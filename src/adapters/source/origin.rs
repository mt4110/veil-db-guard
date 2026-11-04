//! Protected native producer observations. A kernel denial of the root probe
//! is not a denial of the application; no NewConnectionsDenied is minted here.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::gce_host::*;
use crate::core::{admission::IssuedObservation, evidence::*};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use tokio_util::sync::CancellationToken;

/// Selecting a trust boundary is configuration, not an assertion of a result.
/// The entire root-owned config and collector binary are pinned by registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "contract", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostKernelOriginConfig {
    LinuxRootConnectV1 { source_ip: IpAddr },
}
impl HostKernelOriginConfig {
    pub(super) fn validate(&self) -> Result<(), SourceError> {
        let Self::LinuxRootConnectV1 { source_ip } = self;
        if !matches!(source_ip, IpAddr::V4(ip) if ip.is_private()) {
            return Err(SourceError::Unsupported);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeExecutionContext {
    pub uid: u32,
    pub effective_uid: u32,
    pub gid: u32,
    pub effective_gid: u32,
    pub network_namespace: String,
    pub user_namespace: String,
    pub mount_namespace: String,
    pub cgroup_digest: String,
    pub cgroup_class: String,
    /// Digest of selected process status/LSM label, not of seccomp programs or
    /// LSM/BPF policy. Equality alone cannot establish application scope.
    pub security_context_digest: String,
    pub kernel_release: String,
}
impl ProbeExecutionContext {
    fn matches_host(&self, host: &LinuxHostContext) -> bool {
        self.uid == 0
            && self.effective_uid == 0
            && self.uid == host.uid
            && self.effective_uid == host.effective_uid
            && self.network_namespace == host.network_namespace
            && self.user_namespace == host.user_namespace
            && self.mount_namespace == host.mount_namespace
            && self.cgroup_class == host.cgroup_class
            && crate::core::policy::valid_hash(&self.cgroup_digest)
            && crate::core::policy::valid_hash(&self.security_context_digest)
            && !self.kernel_release.is_empty()
            && self.kernel_release.len() <= 256
            && !self.kernel_release.chars().any(char::is_control)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelSocketOutcome {
    HostKernelProbeDenied,
    Connected,
    Refused,
    TimedOut,
    Unclassified,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostKernelProbeRecord {
    pub case_id: String,
    pub config: HostKernelOriginConfig,
    pub context_before: ProbeExecutionContext,
    pub context_after: ProbeExecutionContext,
    pub started_at: u64,
    pub finished_at: u64,
    pub connection: ConnectionTuple,
    pub outcome: KernelSocketOutcome,
    /// Only the direct, nonblocking connect syscall may set this. SO_ERROR and
    /// later errors are diagnostics and cannot select HostKernelProbeDenied.
    pub synchronous_errno: Option<i32>,
}

/// Capture-authenticated fact, not admitted evidence or application scope proof.
/// No public constructor/Deserialize. K11 must separately recheck admission,
/// freshness, and the application's exact execution/security context.
///
/// ```compile_fail
/// use veil_db_guard::adapters::source::origin::VerifiedHostKernelProbe;
/// let _: VerifiedHostKernelProbe = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedHostKernelProbe {
    request_digest: String,
    source_revision_digest: String,
    proof_digest: String,
    record: HostKernelProbeRecord,
}
impl VerifiedHostKernelProbe {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    pub fn source_revision_digest(&self) -> &str {
        &self.source_revision_digest
    }
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }
    pub fn case_id(&self) -> &str {
        &self.record.case_id
    }
    pub fn context(&self) -> &ProbeExecutionContext {
        &self.record.context_before
    }
    pub fn connection(&self) -> &ConnectionTuple {
        &self.record.connection
    }
    pub fn outcome(&self) -> KernelSocketOutcome {
        self.record.outcome
    }
    pub fn finished_at(&self) -> u64 {
        self.record.finished_at
    }
}

pub(super) fn verify_records(
    i: &IssuedObservation,
    diagnostics: &[CaseDiagnostic],
    records: &[HostKernelProbeRecord],
    host: &LinuxHostContext,
    proof_digest: &str,
) -> Result<Vec<VerifiedHostKernelProbe>, SourceError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut verified = vec![];
    for record in records {
        record.config.validate()?;
        let c = i
            .request
            .cases
            .iter()
            .find(|c| c.id == record.case_id)
            .ok_or(SourceError::Invalid)?;
        let d = diagnostics
            .iter()
            .find(|d| d.case_id == record.case_id)
            .ok_or(SourceError::Invalid)?;
        let HostKernelOriginConfig::LinuxRootConnectV1 { source_ip } = record.config;
        if !seen.insert(&record.case_id)
            || c.kind != FixedObservationCase::DirectPath
            || c.address.route.kind != crate::core::policy::RouteKind::Direct
            || c.address.effect != EffectKindV2::NewConnections
            || record.context_before != record.context_after
            || !record.context_before.matches_host(host)
            || record.started_at != d.started_at
            || record.finished_at != d.finished_at
            || record.started_at > record.finished_at
            || record.connection.local_ip != source_ip
            || record.connection.local_port == 0
            || record.connection.endpoint != c.endpoint
            || record.connection.peer_port != c.port
            || record.connection.peer_ip.is_unspecified()
            || record.connection.peer_ip.is_multicast()
            || !record.connection.peer_ip.is_ipv4()
            || c.address_family != AddressFamily::Ipv4
            || d.connection.as_ref() != Some(&record.connection)
            || d.outcome != diagnostic_outcome(record.outcome)
            || ((record.outcome == KernelSocketOutcome::HostKernelProbeDenied)
                != (record.synchronous_errno == Some(libc::EPERM)))
        {
            return Err(SourceError::ContextUnverified);
        }
        verified.push(VerifiedHostKernelProbe {
            request_digest: i.request.digest().map_err(|_| SourceError::Invalid)?,
            source_revision_digest: i.request.source.revision_digest.clone(),
            proof_digest: proof_digest.into(),
            record: record.clone(),
        });
    }
    Ok(verified)
}
fn diagnostic_outcome(outcome: KernelSocketOutcome) -> DiagnosticOutcome {
    match outcome {
        KernelSocketOutcome::Connected => DiagnosticOutcome::TcpConnected,
        KernelSocketOutcome::Refused => DiagnosticOutcome::TcpRefused,
        KernelSocketOutcome::TimedOut => DiagnosticOutcome::TcpTimedOut,
        KernelSocketOutcome::HostKernelProbeDenied | KernelSocketOutcome::Unclassified => {
            DiagnosticOutcome::TcpUnavailable
        }
    }
}
fn synchronous_outcome(errno: Option<i32>) -> KernelSocketOutcome {
    match errno {
        Some(libc::EPERM) => KernelSocketOutcome::HostKernelProbeDenied,
        Some(libc::ECONNREFUSED) => KernelSocketOutcome::Refused,
        _ => KernelSocketOutcome::Unclassified,
    }
}

#[cfg(unix)]
fn execution_context() -> Result<ProbeExecutionContext, SourceError> {
    fn bounded(path: &str) -> Result<Vec<u8>, SourceError> {
        use std::io::Read;
        let f = std::fs::File::open(path).map_err(|_| SourceError::Unsupported)?;
        let mut b = vec![];
        f.take(16385)
            .read_to_end(&mut b)
            .map_err(|_| SourceError::Unavailable)?;
        if b.is_empty() || b.len() > 16384 {
            return Err(SourceError::Limit);
        }
        Ok(b)
    }
    fn namespace(name: &str) -> Result<String, SourceError> {
        std::fs::read_link(format!("/proc/self/ns/{name}"))
            .map_err(|_| SourceError::Unsupported)?
            .into_os_string()
            .into_string()
            .map_err(|_| SourceError::Invalid)
    }
    let status = bounded("/proc/self/status")?;
    let status = std::str::from_utf8(&status).map_err(|_| SourceError::Invalid)?;
    let mut selected = vec![];
    for key in [
        "Uid:",
        "Gid:",
        "Groups:",
        "CapInh:",
        "CapPrm:",
        "CapEff:",
        "CapBnd:",
        "CapAmb:",
        "NoNewPrivs:",
        "Seccomp:",
    ] {
        let mut matches = status.lines().filter(|l| l.starts_with(key));
        let line = matches.next().ok_or(SourceError::Unsupported)?;
        if matches.next().is_some() {
            return Err(SourceError::Invalid);
        }
        selected.push(line.to_owned());
    }
    let label = bounded("/proc/self/attr/current")?;
    let security = serde_json::to_vec(&(selected, label)).map_err(|_| SourceError::Invalid)?;
    let release = bounded("/proc/sys/kernel/osrelease")?;
    let cgroup = bounded("/proc/self/cgroup")?;
    let uid = unsafe { libc::getuid() };
    Ok(ProbeExecutionContext {
        // SAFETY: identity getters have no preconditions or side effects.
        uid,
        effective_uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getgid() },
        effective_gid: unsafe { libc::getegid() },
        network_namespace: namespace("net")?,
        user_namespace: namespace("user")?,
        mount_namespace: namespace("mnt")?,
        cgroup_digest: crate::config::hash_bytes(&cgroup),
        cgroup_class: super::collector::normalize_cgroup(&cgroup, uid)?,
        security_context_digest: crate::config::hash_bytes(&security),
        kernel_release: std::str::from_utf8(&release)
            .map_err(|_| SourceError::Invalid)?
            .trim()
            .into(),
    })
}

#[cfg(unix)]
pub(super) async fn socket_probe(
    endpoint: &str,
    source: SocketAddr,
    peer: SocketAddr,
    cancel: &CancellationToken,
) -> Result<(ConnectionTuple, KernelSocketOutcome, Option<i32>), SourceError> {
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    let (SocketAddr::V4(source), SocketAddr::V4(peer)) = (source, peer) else {
        return Err(SourceError::Unsupported);
    };
    let socket = tokio::net::TcpSocket::new_v4().map_err(|_| SourceError::Unavailable)?;
    socket
        .bind(SocketAddr::V4(source))
        .map_err(|_| SourceError::Unavailable)?;
    let local = socket.local_addr().map_err(|_| SourceError::Unavailable)?;
    let tuple = ConnectionTuple {
        endpoint: endpoint.into(),
        local_ip: local.ip(),
        local_port: local.port(),
        peer_ip: (*peer.ip()).into(),
        peer_port: peer.port(),
    };
    // SAFETY: initialized IPv4 sockaddr, correct length, live borrowed fd.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as _;
    #[cfg(not(target_os = "linux"))]
    {
        address.sin_len = std::mem::size_of::<libc::sockaddr_in>() as _;
    }
    address.sin_port = peer.port().to_be();
    address.sin_addr.s_addr = u32::from_ne_bytes(peer.ip().octets());
    let rc = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&address) as _,
        )
    };
    let errno = if rc < 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    if rc == 0 {
        return Ok((tuple, KernelSocketOutcome::Connected, None));
    }
    if errno != Some(libc::EINPROGRESS) {
        return Ok((tuple, synchronous_outcome(errno), errno));
    }
    // A pending connect can later succeed; monitor it and preserve success.
    // Later EPERM is deliberately not accepted by this synchronous recipe.
    // SAFETY: ownership transfers out of TcpSocket exactly once.
    let stream = unsafe { std::net::TcpStream::from_raw_fd(socket.into_raw_fd()) };
    let stream = tokio::net::TcpStream::from_std(stream).map_err(|_| SourceError::Unavailable)?;
    let outcome = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(SourceError::Cancelled),
        r = tokio::time::timeout(std::time::Duration::from_secs(3), stream.writable()) => match r {
            Err(_) => KernelSocketOutcome::TimedOut,
            Ok(Err(_)) => KernelSocketOutcome::Unclassified,
            Ok(Ok(())) => match stream.take_error().map_err(|_| SourceError::Unavailable)? {
                None if stream.peer_addr().is_ok() => KernelSocketOutcome::Connected,
                Some(e) if e.raw_os_error() == Some(libc::ECONNREFUSED) => KernelSocketOutcome::Refused,
                _ => KernelSocketOutcome::Unclassified,
            },
        }
    };
    Ok((tuple, outcome, Some(libc::EINPROGRESS)))
}

#[cfg(unix)]
pub(super) async fn observe(
    c: &RequestedCase,
    endpoint: &CollectorEndpoint,
    config: &HostKernelOriginConfig,
    cancel: &CancellationToken,
) -> Result<(CaseDiagnostic, HostKernelProbeRecord), SourceError> {
    config.validate()?;
    if c.kind != FixedObservationCase::DirectPath {
        return Err(SourceError::Invalid);
    }
    // The syscall/context recipe is type-checked on Unix controller hosts;
    // production acquisition still explicitly requires Linux.
    if !cfg!(target_os = "linux") {
        return Err(SourceError::Unsupported);
    }
    {
        let before = execution_context()?;
        if before.uid != 0 || before.effective_uid != 0 {
            return Err(SourceError::Unsupported);
        }
        let started_at = crate::domain::now();
        let HostKernelOriginConfig::LinuxRootConnectV1 { source_ip } = config;
        let (connection, outcome, errno) = socket_probe(
            &c.endpoint,
            SocketAddr::new(*source_ip, 0),
            SocketAddr::new(endpoint.ip, c.port),
            cancel,
        )
        .await?;
        let after = execution_context()?;
        if before != after {
            return Err(SourceError::ContextUnverified);
        }
        let finished_at = crate::domain::now();
        let d = CaseDiagnostic {
            case_id: c.id.clone(),
            started_at,
            finished_at,
            outcome: diagnostic_outcome(outcome),
            connection: Some(connection.clone()),
            postgres: None,
            runtime_capture: None,
            runtime_failure: None,
            iam_inventory: None,
        };
        Ok((
            d,
            HostKernelProbeRecord {
                case_id: c.id.clone(),
                config: config.clone(),
                context_before: before,
                context_after: after,
                started_at,
                finished_at,
                connection,
                outcome,
                synchronous_errno: errno,
            },
        ))
    }
}

#[cfg(test)]
pub(super) fn fixture_record(host: &LinuxHostContext, d: &CaseDiagnostic) -> HostKernelProbeRecord {
    let context = ProbeExecutionContext {
        uid: 0,
        effective_uid: 0,
        gid: 0,
        effective_gid: 0,
        network_namespace: host.network_namespace.clone(),
        user_namespace: host.user_namespace.clone(),
        mount_namespace: host.mount_namespace.clone(),
        cgroup_digest: "a".repeat(64),
        cgroup_class: host.cgroup_class.clone(),
        security_context_digest: "b".repeat(64),
        kernel_release: "6.12-test-fixture".into(),
    };
    HostKernelProbeRecord {
        case_id: d.case_id.clone(),
        config: HostKernelOriginConfig::LinuxRootConnectV1 {
            source_ip: d.connection.as_ref().unwrap().local_ip,
        },
        context_before: context.clone(),
        context_after: context,
        started_at: d.started_at,
        finished_at: d.finished_at,
        connection: d.connection.clone().unwrap(),
        outcome: KernelSocketOutcome::HostKernelProbeDenied,
        synchronous_errno: Some(libc::EPERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_immediate_eperm_is_host_probe_denial() {
        assert_eq!(
            synchronous_outcome(Some(libc::EPERM)),
            KernelSocketOutcome::HostKernelProbeDenied
        );
        for errno in [
            None,
            Some(libc::EACCES),
            Some(libc::ETIMEDOUT),
            Some(libc::EHOSTUNREACH),
            Some(libc::EINPROGRESS),
        ] {
            assert_ne!(
                synchronous_outcome(errno),
                KernelSocketOutcome::HostKernelProbeDenied
            );
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn actual_loopback_success_refusal_and_cancel_are_never_policy_denial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let source = "127.0.0.1:0".parse().unwrap();
        let cancel = CancellationToken::new();
        let (_, outcome, _) = socket_probe("loopback", source, address, &cancel)
            .await
            .unwrap();
        assert_eq!(outcome, KernelSocketOutcome::Connected);
        drop(listener);
        let (_, outcome, _) = socket_probe("loopback", source, address, &cancel)
            .await
            .unwrap();
        assert_eq!(outcome, KernelSocketOutcome::Refused);
        cancel.cancel();
        assert!(matches!(
            socket_probe("loopback", source, address, &cancel).await,
            Err(SourceError::Cancelled)
        ));
    }
}
