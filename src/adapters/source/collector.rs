//! Fixed Linux collector: bounded stdin, trusted config/binary, metadata-only
//! identity and fixed TCP diagnostics. No shell/SQL/GRANT/install hook.
// Linux collectors are also type-checked on Unix controller hosts; the public
// stdio entry refuses non-Linux before any native IO.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{gce_host::*, jwt, process};
use crate::core::{admission::IssuedObservation, evidence::*};
use std::{io::Read, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

pub async fn run_collector_stdio(cancel: CancellationToken) -> Result<(), SourceError> {
    let input = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut bytes = vec![];
        tokio::io::stdin()
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(SourceError::Limit);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| SourceError::TimedOut)??;
    let issued: IssuedObservation =
        serde_json::from_slice(&input).map_err(|_| SourceError::Invalid)?;
    crate::core::admission::validate_issued(&issued).map_err(|_| SourceError::Invalid)?;
    let bytes = match &issued.snapshot {
        crate::core::source::RegisteredSourceSnapshot::Gce(_) => {
            serde_json::to_vec(&response_for_request(&issued, &cancel).await)
        }
        crate::core::source::RegisteredSourceSnapshot::Aws(_) => {
            serde_json::to_vec(&super::aws_host::response_for_request(&issued, &cancel).await)
        }
    }
    .map_err(|_| SourceError::Invalid)?;
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(SourceError::Limit);
    }
    tokio::io::stdout()
        .write_all(&bytes)
        .await
        .map_err(|_| SourceError::Unavailable)?;
    Ok(())
}

async fn response_for_request(
    issued: &IssuedObservation,
    cancel: &CancellationToken,
) -> CollectorResponse {
    #[cfg(not(target_os = "linux"))]
    let result: Result<CollectorReply, SourceError> = {
        let _ = cancel;
        Err(SourceError::Unsupported)
    };
    #[cfg(target_os = "linux")]
    let result = {
        let remaining = issued
            .request
            .expires_at
            .saturating_sub(crate::domain::now())
            .min(MAX_CAPTURE_SECONDS);
        if remaining == 0 {
            Err(SourceError::RequestExpired)
        } else {
            tokio::select! {biased;_=cancel.cancelled()=>Err(SourceError::Cancelled),
            r=tokio::time::timeout(std::time::Duration::from_secs(remaining),collect(issued,cancel))=>r.unwrap_or(Err(SourceError::TimedOut))}
        }
    };
    match result {
        Ok(reply) => CollectorResponse::Success {
            reply: Box::new(reply),
        },
        Err(error) => CollectorResponse::Failure {
            request_digest: issued.request.digest().unwrap_or_default(),
            code: CollectorFailure::from_error(error),
        },
    }
}

/// Read-only bootstrap material for an already trusted operator session. This
/// unsigned preview does not register a source or mint native verified facts.
pub async fn read_local_context(
    allow_read: bool,
    cancel: &CancellationToken,
) -> Result<LinuxHostContext, SourceError> {
    if !allow_read {
        return Err(SourceError::PermissionRequired);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cancel;
        Err(SourceError::Unsupported)
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::geteuid() } != 0 {
            return Err(SourceError::Unsupported);
        }
        tokio::select! {biased;_=cancel.cancelled()=>Err(SourceError::Cancelled),
        r=tokio::time::timeout(std::time::Duration::from_secs(10),host_context(cancel))=>r.unwrap_or(Err(SourceError::TimedOut))}
    }
}

#[cfg(unix)]
async fn collect(
    i: &IssuedObservation,
    cancel: &CancellationToken,
) -> Result<CollectorReply, SourceError> {
    let p = validated_profile(&i.snapshot)?;
    let config_bytes = root_file(Path::new(COLLECTOR_CONFIG_PATH), 65536)?;
    if crate::config::hash_bytes(&config_bytes) != i.snapshot.collector_config_digest() {
        return Err(SourceError::Integrity);
    }
    let config: CollectorConfig =
        serde_json::from_slice(&config_bytes).map_err(|_| SourceError::Invalid)?;
    config.validate_request(i)?;
    let executable = std::env::current_exe().map_err(|_| SourceError::Unavailable)?;
    super::gce_host::trusted_program(&executable)?;
    let binary_digest = file_digest(&executable, 128 * 1024 * 1024)?;
    if binary_digest != p.collector_binary_digest
        || crate::BUILD_ID != i.snapshot.collector_build_id()
    {
        return Err(SourceError::Integrity);
    }
    let started = crate::domain::now();
    let before = host_context(cancel).await?;
    if before != config.context || before.uid != p.execution_uid {
        return Err(SourceError::ContextUnverified);
    }
    let token = metadata_identity(&jwt::audience(i)?, cancel).await?;
    let mut diagnostics = vec![];
    let mut route_denials = vec![];
    let mut kernel_probes = vec![];
    let mut unix_probes = vec![];
    for c in &i.request.cases {
        if cancel.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        let start = crate::domain::now();
        let mut d = CaseDiagnostic {
            runtime_capture: None,
            runtime_failure: None,
            iam_inventory: None,
            case_id: c.id.clone(),
            started_at: start,
            finished_at: start,
            outcome: DiagnosticOutcome::UnsupportedCase,
            connection: None,
            postgres: None,
        };
        let budget = i
            .request
            .expires_at
            .min(started + MAX_CAPTURE_SECONDS)
            .saturating_sub(crate::domain::now())
            .saturating_sub(12);
        if budget == 0 {
            if let Some(pg) = &config.postgres {
                let mut observation = super::postgres::PgObservation::failed(i, &pg.proxy_sha256);
                observation.stage = super::postgres::PgStage::Deadline;
                if !matches!(
                    c.kind,
                    FixedObservationCase::DirectPath | FixedObservationCase::RuntimeBinding
                ) {
                    d.postgres = Some(observation);
                    d.outcome = DiagnosticOutcome::PostgresObserved;
                }
            }
            d.finished_at = crate::domain::now();
            diagnostics.push(d);
            continue;
        }
        if c.kind == FixedObservationCase::RuntimeBinding {
            d.outcome = DiagnosticOutcome::RuntimeObserved;
            if let Some(binding) = config.runtime_unix.iter().find(|b| b.matches(&c.address)) {
                let context =
                    crate::core::runtime_binding::RuntimeCaptureContext::from_issued(i, c)
                        .map_err(|_| SourceError::Invalid)?;
                match super::runtime_unix::collect(&binding.selection, cancel) {
                    Ok(capture) => {
                        d.outcome = DiagnosticOutcome::RuntimeUnixObserved;
                        unix_probes.push(RuntimeUnixRecord {
                            context,
                            capture: capture.wire().clone(),
                        });
                    }
                    Err(SourceError::Cancelled) => return Err(SourceError::Cancelled),
                    Err(error) => d.runtime_failure = Some(CollectorFailure::from_error(error)),
                }
                d.finished_at = crate::domain::now();
                diagnostics.push(d);
                continue;
            }
            let result = match &config.runtime {
                Some(runtime) => {
                    let endpoint = config
                        .endpoints
                        .iter()
                        .find(|e| {
                            e.target_id == c.address.target_id
                                && e.endpoint == c.endpoint
                                && e.port == c.port
                        })
                        .ok_or(SourceError::Invalid)?;
                    super::runtime::collect(i, c, endpoint, runtime, cancel)
                }
                None => Err(SourceError::Unsupported),
            };
            match result {
                Ok(capture) => {
                    d.connection = Some(capture.before.connection.clone());
                    d.runtime_capture = Some(capture);
                }
                Err(SourceError::Cancelled) => return Err(SourceError::Cancelled),
                Err(error) => d.runtime_failure = Some(CollectorFailure::from_error(error)),
            }
            d.finished_at = crate::domain::now();
            diagnostics.push(d);
            continue;
        }
        if c.kind == FixedObservationCase::DirectPath {
            let endpoints: Vec<_> = config
                .endpoints
                .iter()
                .filter(|e| {
                    e.target_id == c.address.target_id
                        && e.native_id == c.address.target.native_ref.native_id
                        && e.endpoint == c.endpoint
                        && e.port == c.port
                        && Some(e.generation_digest.as_str())
                            == c.address
                                .target
                                .native_ref
                                .generation_fingerprint
                                .as_deref()
                        && e.ip.is_ipv4() == (c.address_family == AddressFamily::Ipv4)
                })
                .collect();
            if endpoints.len() != 1 {
                return Err(SourceError::Invalid);
            }
            let e = endpoints[0];
            d = tokio::time::timeout(
                std::time::Duration::from_secs(if config.route_denial.is_some() {
                    budget
                } else {
                    budget.min(10)
                }),
                async {
                    if let Some(origin) = &config.kernel_origin {
                        let (diagnostic, probe) =
                            super::origin::observe(c, e, origin, cancel).await?;
                        kernel_probes.push(probe);
                        Ok(diagnostic)
                    } else if let Some(route) = &config.route_denial {
                        let (diagnostic, observation) =
                            super::route_denial::observe(i, c, e, route, cancel).await?;
                        if let Some(observation) = observation {
                            route_denials.push(observation);
                        }
                        Ok(diagnostic)
                    } else {
                        tcp_diagnostic(c, e.ip, cancel).await
                    }
                },
            )
            .await
            .unwrap_or_else(|_| {
                Ok(CaseDiagnostic {
                    runtime_capture: None,
                    runtime_failure: None,
                    iam_inventory: None,
                    case_id: c.id.clone(),
                    started_at: start,
                    finished_at: crate::domain::now(),
                    outcome: DiagnosticOutcome::TcpTimedOut,
                    connection: None,
                    postgres: None,
                })
            })?;
        }
        if c.kind != FixedObservationCase::DirectPath
            && matches!(
                c.kind,
                FixedObservationCase::NewConnection
                    | FixedObservationCase::TargetHealth
                    | FixedObservationCase::EffectiveSqlPrivilege
                    | FixedObservationCase::Transport
            )
            && let Some(pg) = &config.postgres
        {
            let endpoint = config
                .endpoints
                .iter()
                .find(|e| {
                    e.target_id == c.address.target_id
                        && e.endpoint == c.endpoint
                        && e.port == c.port
                        && e.native_id == c.address.target.native_ref.native_id
                        && e.database == c.address.target.engine_binding.database
                        && Some(e.generation_digest.as_str())
                            == c.address
                                .target
                                .native_ref
                                .generation_fingerprint
                                .as_deref()
                        && e.ip.is_ipv4() == (c.address_family == AddressFamily::Ipv4)
                })
                .ok_or(SourceError::Invalid)?;
            match super::postgres_native::observe(
                i,
                c,
                endpoint,
                pg,
                diagnostics.len(),
                i.request
                    .expires_at
                    .min(started + MAX_CAPTURE_SECONDS)
                    .saturating_sub(crate::domain::now())
                    .saturating_sub(12),
                cancel,
            )
            .await
            {
                Ok(observation) => {
                    d.postgres = Some(observation);
                    d.outcome = DiagnosticOutcome::PostgresObserved;
                }
                Err(SourceError::Unsupported) => {}
                Err(e) => return Err(e),
            }
            if pg.collect_iam_inventory
                && c.kind == FixedObservationCase::NewConnection
                && d.postgres.is_some()
            {
                d.iam_inventory = super::iam_inventory::observe_gcp(i, c, cancel).await.ok();
            }
            d.finished_at = crate::domain::now();
        }
        diagnostics.push(d);
    }
    let after = host_context(cancel).await?;
    if after != before {
        return Err(SourceError::ContextUnverified);
    }
    Ok(CollectorReply {
        schema_version: 1,
        request_digest: i.request.digest().map_err(|_| SourceError::Invalid)?,
        collector_build_id: crate::BUILD_ID.into(),
        binary_digest,
        config_digest: crate::config::hash_bytes(&config_bytes),
        context_before: before,
        context_after: after,
        identity_token: token,
        started_at: started,
        finished_at: crate::domain::now(),
        diagnostics,
        route_denials,
        kernel_probes,
        unix_probes,
    })
}

#[cfg(unix)]
pub(super) fn root_file(path: &Path, max: usize) -> Result<Vec<u8>, SourceError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| SourceError::Unavailable)?;
    let m = f.metadata().map_err(|_| SourceError::Unavailable)?;
    if !m.is_file()
        || m.uid() != 0
        || m.mode() & 0o022 != 0
        || m.len() > max as u64
        || m.nlink() != 1
    {
        return Err(SourceError::Integrity);
    }
    let mut out = vec![];
    (&mut f)
        .take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| SourceError::Unavailable)?;
    if out.len() > max {
        return Err(SourceError::Limit);
    }
    Ok(out)
}

fn classify_tcp_error(kind: std::io::ErrorKind) -> DiagnosticOutcome {
    match kind {
        std::io::ErrorKind::ConnectionRefused => DiagnosticOutcome::TcpRefused,
        std::io::ErrorKind::TimedOut => DiagnosticOutcome::TcpTimedOut,
        _ => DiagnosticOutcome::TcpUnavailable,
    }
}

pub(super) async fn tcp_diagnostic(
    c: &RequestedCase,
    ip: std::net::IpAddr,
    cancel: &CancellationToken,
) -> Result<CaseDiagnostic, SourceError> {
    if c.kind != FixedObservationCase::DirectPath {
        return Err(SourceError::Invalid);
    }
    let mut d = CaseDiagnostic {
        runtime_capture: None,
        runtime_failure: None,
        iam_inventory: None,
        case_id: c.id.clone(),
        started_at: crate::domain::now(),
        finished_at: 0,
        outcome: DiagnosticOutcome::TcpUnavailable,
        connection: None,
        postgres: None,
    };
    let result = tokio::select! {biased;_=cancel.cancelled()=>return Err(SourceError::Cancelled),
    r=tokio::time::timeout(std::time::Duration::from_secs(10),TcpStream::connect((ip,c.port)))=>r};
    match result {
        Ok(Ok(stream)) => {
            let local = stream.local_addr().map_err(|_| SourceError::Unavailable)?;
            let peer = stream.peer_addr().map_err(|_| SourceError::Unavailable)?;
            d.outcome = DiagnosticOutcome::TcpConnected;
            d.connection = Some(ConnectionTuple {
                endpoint: c.endpoint.clone(),
                local_ip: local.ip(),
                local_port: local.port(),
                peer_ip: peer.ip(),
                peer_port: peer.port(),
            });
        }
        Ok(Err(e)) => d.outcome = classify_tcp_error(e.kind()),
        Err(_) => d.outcome = DiagnosticOutcome::TcpTimedOut,
    }
    d.finished_at = crate::domain::now();
    Ok(d)
}
/// Retain the probe and monitor late completion throughout native acquisition.
/// Some kernels release an explicit bind after a failed connect even while a
/// duplicate descriptor lives. Such captures cannot establish this recipe.
#[cfg(unix)]
pub(super) struct BoundProbe {
    socket: std::net::TcpStream,
    pub pending: Option<tokio::task::JoinHandle<std::io::Result<tokio::net::TcpStream>>>,
    pub reserved_at: u64,
}
#[cfg(unix)]
impl BoundProbe {
    pub fn exclusive(&self, tuple: &ConnectionTuple) -> bool {
        let address = std::net::SocketAddr::new(tuple.local_ip, tuple.local_port);
        if self.socket.local_addr().ok() != Some(address) || self.socket.peer_addr().is_ok() {
            return false;
        }
        let Ok(check) = (if tuple.local_ip.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }) else {
            return false;
        };
        // No reuse flags. Only EADDRINUSE is evidence of retained reservation;
        // permission/resource failures are not treated as successful checks.
        check
            .bind(address)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::AddrInUse)
    }
}
#[cfg(unix)]
impl Drop for BoundProbe {
    fn drop(&mut self) {
        if let Some(task) = &self.pending {
            task.abort();
        }
    }
}
#[cfg(unix)]
pub(super) async fn bound_tcp_diagnostic(
    c: &RequestedCase,
    ip: std::net::IpAddr,
    source_ip: std::net::IpAddr,
    cancel: &CancellationToken,
) -> Result<(CaseDiagnostic, BoundProbe), SourceError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if c.kind != FixedObservationCase::DirectPath || ip.is_ipv4() != source_ip.is_ipv4() {
        return Err(SourceError::Invalid);
    }
    let socket = (if ip.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    })
    .map_err(|_| SourceError::Unavailable)?;
    socket
        .bind(std::net::SocketAddr::new(source_ip, 0))
        .map_err(|_| SourceError::Unavailable)?;
    let local = socket.local_addr().map_err(|_| SourceError::Unavailable)?;
    // SAFETY: duplicate a live borrowed socket; successful result is a new
    // owned descriptor, closed exactly once by OwnedFd/std::net::TcpStream.
    let duplicate = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(SourceError::Unavailable);
    }
    let duplicate = unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) };
    let reserved_at = crate::domain::now();
    // Quarantine the reserved tuple beyond the profile's maximum host/provider
    // clock difference. Strict probe windows remain unchanged.
    let quarantine_start = tokio::time::Instant::now();
    let boundary = async {
        while crate::domain::now() <= reserved_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
            || quarantine_start.elapsed()
                < std::time::Duration::from_secs(MAX_CLOCK_SKEW_SECONDS + 1)
        {
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    };
    tokio::select! { biased;
        _ = cancel.cancelled() => return Err(SourceError::Cancelled),
        result = tokio::time::timeout(std::time::Duration::from_secs(MAX_CLOCK_SKEW_SECONDS + 2), boundary) => result.map_err(|_| SourceError::TimedOut)?,
    }
    let mut d = CaseDiagnostic {
        runtime_capture: None,
        runtime_failure: None,
        iam_inventory: None,
        case_id: c.id.clone(),
        started_at: crate::domain::now(),
        finished_at: 0,
        outcome: DiagnosticOutcome::TcpUnavailable,
        connection: Some(ConnectionTuple {
            endpoint: c.endpoint.clone(),
            local_ip: local.ip(),
            local_port: local.port(),
            peer_ip: ip,
            peer_port: c.port,
        }),
        postgres: None,
    };
    let peer = std::net::SocketAddr::new(ip, c.port);
    let pending = tokio::spawn(async move { socket.connect(peer).await });
    let mut held = BoundProbe {
        socket: std::net::TcpStream::from(duplicate),
        pending: Some(pending),
        reserved_at,
    };
    let result = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(SourceError::Cancelled),
        result = tokio::time::timeout(std::time::Duration::from_secs(3), held.pending.as_mut().expect("started")) => result,
    };
    match result {
        Ok(Ok(Ok(stream))) => {
            held.pending = None;
            d.outcome = DiagnosticOutcome::TcpConnected;
            drop(stream);
        }
        Ok(Ok(Err(e))) => {
            held.pending = None;
            d.outcome = classify_tcp_error(e.kind());
        }
        Ok(Err(_)) => return Err(SourceError::Unavailable),
        Err(_) => d.outcome = DiagnosticOutcome::TcpTimedOut,
    }
    d.finished_at = crate::domain::now();
    if d.outcome != DiagnosticOutcome::TcpConnected
        && !held.exclusive(d.connection.as_ref().expect("bound tuple"))
    {
        return Err(SourceError::Unsupported);
    }
    Ok((d, held))
}
#[cfg(unix)]
pub(super) fn file_digest(path: &Path, max: u64) -> Result<String, SourceError> {
    use sha2::{Digest, Sha256};
    let f = std::fs::File::open(path).map_err(|_| SourceError::Unavailable)?;
    let m = f.metadata().map_err(|_| SourceError::Unavailable)?;
    if !m.is_file() || m.len() > max {
        return Err(SourceError::Limit);
    }
    let mut hash = Sha256::new();
    let mut reader = f.take(max + 1);
    let mut b = [0; 65536];
    let mut count = 0;
    loop {
        let n = Read::read(&mut reader, &mut b).map_err(|_| SourceError::Unavailable)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > max {
            return Err(SourceError::Limit);
        }
        hash.update(&b[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
#[cfg(unix)]
fn proc_file(path: &str, max: usize) -> Result<Vec<u8>, SourceError> {
    let file = std::fs::File::open(path).map_err(|_| SourceError::ContextUnverified)?;
    let mut out = vec![];
    file.take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| SourceError::ContextUnverified)?;
    if out.len() > max {
        return Err(SourceError::Limit);
    }
    Ok(out)
}
#[cfg(unix)]
pub(super) async fn host_context(
    cancel: &CancellationToken,
) -> Result<LinuxHostContext, SourceError> {
    let ns = |name: &str| -> Result<String, SourceError> {
        let own = std::fs::read_link(format!("/proc/self/ns/{name}"))
            .map_err(|_| SourceError::ContextUnverified)?;
        let init = std::fs::read_link(format!("/proc/1/ns/{name}"))
            .map_err(|_| SourceError::ContextUnverified)?;
        if own != init {
            return Err(SourceError::ContextUnverified);
        }
        own.into_os_string()
            .into_string()
            .map_err(|_| SourceError::ContextUnverified)
    };
    if proc_file("/proc/1/comm", 64)? != b"systemd\n" {
        return Err(SourceError::ContextUnverified);
    }
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let cgroup = normalize_cgroup(&proc_file("/proc/self/cgroup", 4096)?, uid)?;
    let interface = normalize_interfaces(&proc_file("/proc/net/dev", 65536)?)?;
    let route4 = normalize_routes(&proc_file("/proc/net/route", 65536)?, false)?;
    let route6 = normalize_routes(&proc_file("/proc/net/ipv6_route", 65536)?, true)?;
    trusted_program(Path::new("/usr/sbin/ip"))?;
    let r4 = process::run(
        Path::new("/usr/sbin/ip"),
        &["-j".into(), "-4".into(), "rule".into(), "show".into()],
        &[],
        65536,
        3,
        cancel,
    )
    .await?;
    let r6 = process::run(
        Path::new("/usr/sbin/ip"),
        &["-j".into(), "-6".into(), "rule".into(), "show".into()],
        &[],
        65536,
        3,
        cancel,
    )
    .await?;
    Ok(LinuxHostContext {
        uid,
        effective_uid: euid,
        network_namespace: ns("net")?,
        mount_namespace: ns("mnt")?,
        user_namespace: ns("user")?,
        boot_id_digest: crate::config::hash_bytes(&proc_file(
            "/proc/sys/kernel/random/boot_id",
            128,
        )?),
        cgroup_class: cgroup,
        route_v4_digest: crate::config::hash_bytes(&route4),
        route_v6_digest: crate::config::hash_bytes(&route6),
        interfaces_digest: crate::config::hash_bytes(&interface),
        rules_v4_digest: crate::config::hash_bytes(&default_rules(&r4)?),
        rules_v6_digest: crate::config::hash_bytes(&default_rules(&r6)?),
    })
}

pub(super) fn normalize_cgroup(bytes: &[u8], uid: u32) -> Result<String, SourceError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| SourceError::ContextUnverified)?
        .trim();
    if matches!(
        s,
        "0::/" | "0::/system.slice/ssh.service" | "0::/system.slice/sshd.service"
    ) {
        return Ok(s.into());
    }
    let prefix = format!("0::/user.slice/user-{uid}.slice/session-");
    if let Some(n) = s
        .strip_prefix(&prefix)
        .and_then(|v| v.strip_suffix(".scope"))
        && !n.is_empty()
        && n.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(format!("0::/user.slice/user-{uid}.slice/session.scope"));
    }
    Err(SourceError::ContextUnverified)
}
fn normalize_interfaces(bytes: &[u8]) -> Result<Vec<u8>, SourceError> {
    let s = std::str::from_utf8(bytes).map_err(|_| SourceError::ContextUnverified)?;
    let mut names = vec![];
    for line in s.lines().skip(2) {
        let name = line
            .split_once(':')
            .ok_or(SourceError::ContextUnverified)?
            .0
            .trim();
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.@".contains(&b))
        {
            return Err(SourceError::ContextUnverified);
        }
        names.push(name);
    }
    if names.is_empty() || names.len() > 64 {
        return Err(SourceError::ContextUnverified);
    }
    names.sort();
    Ok(names.join("\n").into_bytes())
}
fn normalize_routes(bytes: &[u8], v6: bool) -> Result<Vec<u8>, SourceError> {
    let s = std::str::from_utf8(bytes).map_err(|_| SourceError::ContextUnverified)?;
    let mut rows = vec![];
    for line in s.lines().skip(if v6 { 0 } else { 1 }) {
        let cols: Vec<_> = line.split_whitespace().collect();
        let indexes: &[usize] = if v6 {
            &[0, 1, 2, 3, 4, 5, 8, 9]
        } else {
            &[0, 1, 2, 3, 6, 7, 8, 9, 10]
        };
        if cols.len() != if v6 { 10 } else { 11 } {
            return Err(SourceError::ContextUnverified);
        }
        rows.push(
            indexes
                .iter()
                .map(|i| cols[*i])
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if rows.len() > 256 {
        return Err(SourceError::Limit);
    }
    rows.sort();
    Ok(rows.join("\n").into_bytes())
}
fn default_rules(bytes: &[u8]) -> Result<Vec<u8>, SourceError> {
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|_| SourceError::ContextUnverified)?;
    if values.is_empty() || values.len() > 3 {
        return Err(SourceError::ContextUnverified);
    }
    let mut rows = vec![];
    for value in values {
        let o = value.as_object().ok_or(SourceError::ContextUnverified)?;
        if o.keys()
            .any(|k| !["priority", "src", "table", "protocol"].contains(&k.as_str()))
            || o.get("src").and_then(|v| v.as_str()) != Some("all")
        {
            return Err(SourceError::ContextUnverified);
        }
        let p = o
            .get("priority")
            .and_then(|v| v.as_u64())
            .ok_or(SourceError::ContextUnverified)?;
        let table = o
            .get("table")
            .and_then(|v| v.as_str())
            .ok_or(SourceError::ContextUnverified)?;
        if !matches!(
            (p, table),
            (0, "local") | (32766, "main") | (32767, "default")
        ) {
            return Err(SourceError::ContextUnverified);
        }
        rows.push(format!("{p}:{table}"));
    }
    rows.sort();
    rows.dedup();
    Ok(rows.join("\n").into_bytes())
}
#[cfg(unix)]
pub(super) async fn metadata_identity(
    audience: &str,
    cancel: &CancellationToken,
) -> Result<String, SourceError> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("audience", audience)
        .append_pair("format", "full")
        .append_pair("licenses", "FALSE")
        .finish();
    let work = async {
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::new(169, 254, 169, 254), 80))
            .await
            .map_err(|_| SourceError::Unavailable)?;
        let request = format!(
            "GET /computeMetadata/v1/instance/service-accounts/default/identity?{query} HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| SourceError::Unavailable)?;
        let mut bytes = vec![];
        stream
            .take(32769)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        parse_metadata_response(&bytes)
    };
    tokio::select! {biased;_=cancel.cancelled()=>Err(SourceError::Cancelled),r=tokio::time::timeout(std::time::Duration::from_secs(5),work)=>r.unwrap_or(Err(SourceError::TimedOut))}
}
fn parse_metadata_response(bytes: &[u8]) -> Result<String, SourceError> {
    let body = metadata_body(bytes)?;
    let token = std::str::from_utf8(&body).map_err(|_| SourceError::IdentityUnverified)?;
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(SourceError::IdentityUnverified);
    }
    Ok(token.into())
}
pub(super) fn metadata_body(bytes: &[u8]) -> Result<Vec<u8>, SourceError> {
    if bytes.len() > 32768 {
        return Err(SourceError::Limit);
    }
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(SourceError::Invalid)?;
    if split > 8192 {
        return Err(SourceError::Limit);
    }
    let header = std::str::from_utf8(&bytes[..split]).map_err(|_| SourceError::Invalid)?;
    let mut lines = header.split("\r\n");
    if !lines
        .next()
        .is_some_and(|l| l == "HTTP/1.1 200 OK" || l == "HTTP/1.0 200 OK")
    {
        return Err(SourceError::IdentityUnverified);
    }
    let mut length = None;
    let mut flavor = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(SourceError::Invalid)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(SourceError::Invalid);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(SourceError::Invalid);
            }
            length = Some(value.parse::<usize>().map_err(|_| SourceError::Invalid)?);
        }
        if name.eq_ignore_ascii_case("metadata-flavor") {
            if flavor || value != "Google" {
                return Err(SourceError::IdentityUnverified);
            }
            flavor = true;
        }
    }
    let body = &bytes[split + 4..];
    if !flavor || Some(body.len()) != length || body.is_empty() || body.len() > jwt::MAX_TOKEN_BYTES
    {
        return Err(SourceError::IdentityUnverified);
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_bound_probe_requires_real_kernel_reservation_or_fails_closed() {
        let (i, _) = super::super::testsupport::fixture();
        let mut case = i.request.cases[0].clone();
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        case.port = unused.local_addr().unwrap().port();
        drop(unused);
        let loopback = "127.0.0.1".parse().unwrap();
        match bound_tcp_diagnostic(&case, loopback, loopback, &CancellationToken::new()).await {
            Ok((diagnostic, reservation)) => {
                assert_eq!(diagnostic.outcome, DiagnosticOutcome::TcpRefused);
                let tuple = diagnostic.connection.unwrap();
                assert!(reservation.exclusive(&tuple));
                let check = tokio::net::TcpSocket::new_v4().unwrap();
                assert_eq!(
                    check
                        .bind(std::net::SocketAddr::new(loopback, tuple.local_port))
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::AddrInUse
                );
            }
            Err(SourceError::Unsupported) => {
                // Darwin releases a failed connection's bind despite dup. This
                // is an unsupported capture, never successful route evidence.
            }
            Err(other) => panic!("unexpected local probe result: {other:?}"),
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn pure_bound_probe_verifies_reservation_and_detects_release() {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = socket.local_addr().unwrap();
        // SAFETY: take sole ownership of the descriptor consumed from socket.
        let fd = unsafe { OwnedFd::from_raw_fd(socket.into_raw_fd()) };
        let held = BoundProbe {
            socket: std::net::TcpStream::from(fd),
            pending: None,
            reserved_at: crate::domain::now(),
        };
        let tuple = ConnectionTuple {
            endpoint: "local-test".into(),
            local_ip: local.ip(),
            local_port: local.port(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            peer_port: 5432,
        };
        assert!(held.exclusive(&tuple));
        drop(held);
        tokio::net::TcpSocket::new_v4()
            .unwrap()
            .bind(local)
            .unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_bound_probe_does_not_send_a_connection() {
        let (i, _) = super::super::testsupport::fixture();
        let token = CancellationToken::new();
        token.cancel();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut case = i.request.cases[0].clone();
        case.port = listener.local_addr().unwrap().port();
        let loopback = "127.0.0.1".parse().unwrap();
        assert!(matches!(
            bound_tcp_diagnostic(&case, loopback, loopback, &token).await,
            Err(SourceError::Cancelled)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
    #[test]
    fn metadata_protocol_requires_google_header_exact_length_no_redirect_or_transfer_fallback() {
        let body = "header.payload.signature";
        let good = format!(
            "HTTP/1.1 200 OK\r\nMetadata-Flavor: Google\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(parse_metadata_response(good.as_bytes()).unwrap(), body);
        for bad in [
            good.replace("200 OK", "302 Redirect"),
            good.replace("Metadata-Flavor: Google\r\n", ""),
            good.replace("Content-Length:", "Transfer-Encoding:"),
            good.replace("Content-Length:", "Content-Length: 1\r\nContent-Length:"),
            good.replace(body, "PRIVATE-TOKEN-SENTINEL "),
            good + "extra",
        ] {
            let error = parse_metadata_response(bad.as_bytes()).unwrap_err();
            assert!(!format!("{error:?}").contains("PRIVATE-TOKEN-SENTINEL"));
        }
    }
    #[test]
    fn host_context_refuses_containers_uid_routing_and_unregistered_rule_selectors() {
        assert_eq!(
            normalize_cgroup(b"0::/user.slice/user-1000.slice/session-45.scope\n", 1000).unwrap(),
            "0::/user.slice/user-1000.slice/session.scope"
        );
        for cgroup in [
            b"0::/docker/123".as_slice(),
            b"0::/kubepods.slice/test".as_slice(),
            b"0::/user.slice/user-2000.slice/session-45.scope".as_slice(),
        ] {
            assert!(normalize_cgroup(cgroup, 1000).is_err());
        }
        let good=br#"[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"}]"#;
        assert!(default_rules(good).is_ok());
        for bad in [
            br#"[{"priority":0,"src":"all","table":"local","uidrange":"1000-1000"}]"#.as_slice(),
            br#"[{"priority":1,"src":"all","table":"main","fwmark":"1"}]"#.as_slice(),
            br#"[{"priority":32766,"src":"10.0.0.1","table":"main"}]"#.as_slice(),
        ] {
            assert!(default_rules(bad).is_err());
        }
    }
    #[test]
    fn interface_and_route_fingerprints_ignore_counters_but_preserve_real_changes() {
        let first = b"header\nheader\n eth0: 1 2 3 4\n lo: 10 20 30\n";
        let second = b"header\nheader\n eth0: 500 600 700\n lo: 70 80 90\n";
        assert_eq!(
            normalize_interfaces(first).unwrap(),
            normalize_interfaces(second).unwrap()
        );
        let route=b"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n";
        let counter = String::from_utf8(route.to_vec())
            .unwrap()
            .replace("0003 0 0 100", "0003 4 9 100");
        assert_eq!(
            normalize_routes(route, false).unwrap(),
            normalize_routes(counter.as_bytes(), false).unwrap()
        );
        let changed = counter.replace("0100000A", "0200000A");
        assert_ne!(
            normalize_routes(route, false).unwrap(),
            normalize_routes(changed.as_bytes(), false).unwrap()
        );
    }
    #[test]
    fn collector_allowlist_is_exact_and_has_no_credential_shell_sql_or_metadata_override() {
        let (i, config) = super::super::testsupport::fixture();
        config.validate_request(&i).unwrap();
        let mut wrong = config.clone();
        wrong.endpoints[0].endpoint = "attacker.invalid".into();
        assert!(wrong.validate_request(&i).is_err());
        let mut wrong = config.clone();
        wrong.context.effective_uid += 1;
        assert!(wrong.validate_request(&i).is_err());
        for field in ["sql", "shell", "metadata_url", "credential_file", "jwk_url"] {
            let mut value = serde_json::to_value(&config).unwrap();
            value[field] = serde_json::json!("SENSITIVE");
            assert!(serde_json::from_value::<CollectorConfig>(value).is_err());
        }
    }
    #[tokio::test]
    async fn fixed_tcp_diagnostic_captures_actual_loopback_tuple_and_observes_refusal_without_auth_claims()
     {
        let (i, _) = super::super::testsupport::fixture();
        let mut c = i.request.cases[0].clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        c.port = address.port();
        let result = tcp_diagnostic(&c, address.ip(), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(result.outcome, DiagnosticOutcome::TcpConnected);
        assert_eq!(result.connection.unwrap().peer_port, address.port());
        // An unlistened loopback port may be filtered by host policy. Exercise
        // native error classification deterministically without assuming RST.
        assert_eq!(
            classify_tcp_error(std::io::ErrorKind::ConnectionRefused),
            DiagnosticOutcome::TcpRefused
        );
        assert_eq!(
            classify_tcp_error(std::io::ErrorKind::TimedOut),
            DiagnosticOutcome::TcpTimedOut
        );
        assert_eq!(
            classify_tcp_error(std::io::ErrorKind::PermissionDenied),
            DiagnosticOutcome::TcpUnavailable
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert_eq!(
            tcp_diagnostic(&c, address.ip(), &cancel).await.unwrap_err(),
            SourceError::Cancelled
        );
    }
}

#[cfg(test)]
mod pg_config_tests {
    use super::*;
    #[test]
    fn pg_profile_is_explicit_and_v1_config_serialization_stays_unchanged() {
        let (i, mut config) = super::super::testsupport::fixture();
        let old = serde_json::to_vec(&config).unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&old)
                .unwrap()
                .get("postgres")
                .is_none()
        );
        assert_eq!(
            serde_json::to_vec(&serde_json::from_slice::<CollectorConfig>(&old).unwrap()).unwrap(),
            old
        );
        config.postgres = Some(super::super::postgres::PostgresCollectorConfig {
            proxy_sha256: "a".repeat(64),
            collect_connect_denial_audit: false,
            collect_iam_inventory: false,
        });
        assert!(config.validate_request(&i).is_err());
        config.schema_version = 2;
        config.validate_request(&i).unwrap();
        config.endpoints.push(config.endpoints[0].clone());
        assert!(config.validate_request(&i).is_err());
    }
}
