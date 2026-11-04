//! Passive, sampled Linux process/socket attribution. This does not establish
//! PostgreSQL identity, authentication, TLS, credential use, or pool generation.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::gce_host::{CollectorEndpoint, SourceError};
use crate::core::{
    admission::IssuedObservation,
    evidence::{AddressFamily, ConnectionTuple, FixedObservationCase, RequestedCase},
    runtime_binding::{
        LinuxProcessSocketSnapshot, LinuxRuntimeCaptureWire, RuntimeProcessSelector,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};
use tokio_util::sync::CancellationToken;

pub(super) const SMALL_LIMIT: usize = 32 * 1024;
const TCP_LIMIT: usize = 1024 * 1024;
const EXECUTABLE_LIMIT: usize = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCollectorConfig {
    pub bindings: Vec<RuntimeProcessBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProcessBinding {
    pub target_id: String,
    pub grant_id: String,
    pub subject_id: String,
    pub selector: RuntimeProcessSelector,
    pub socket_fd: u32,
}
impl RuntimeCollectorConfig {
    pub fn validate(&self) -> Result<(), SourceError> {
        if self.bindings.is_empty() || self.bindings.len() > 256 {
            return Err(SourceError::Invalid);
        }
        let mut seen = BTreeSet::new();
        for binding in &self.bindings {
            binding
                .selector
                .validate()
                .map_err(|_| SourceError::Invalid)?;
            if [&binding.target_id, &binding.grant_id, &binding.subject_id]
                .iter()
                .any(|id| !crate::core::policy::valid_id(id))
                || binding.socket_fd > 1_048_575
                || !seen.insert((&binding.target_id, &binding.grant_id, &binding.subject_id))
            {
                return Err(SourceError::Invalid);
            }
        }
        Ok(())
    }
}

pub(super) fn collect(
    issued: &IssuedObservation,
    case: &RequestedCase,
    endpoint: &CollectorEndpoint,
    config: &RuntimeCollectorConfig,
    cancel: &CancellationToken,
) -> Result<LinuxRuntimeCaptureWire, SourceError> {
    check_cancel(cancel)?;
    if case.kind != FixedObservationCase::RuntimeBinding {
        return Err(SourceError::Invalid);
    }
    config.validate()?;
    let binding = config
        .bindings
        .iter()
        .find(|b| {
            b.target_id == case.address.target_id
                && b.grant_id == case.address.grant_id
                && b.subject_id == case.address.subject_id
        })
        .ok_or(SourceError::ContextUnverified)?;
    if endpoint.endpoint != case.endpoint
        || endpoint.port != case.port
        || !endpoint.ip.is_ipv4()
        || case.address_family != AddressFamily::Ipv4
    {
        return Err(SourceError::Unsupported);
    }
    #[cfg(target_os = "linux")]
    {
        let reader = NativeProcReader::new(binding.selector.pid)?;
        let (before, after) = observe_with_reader(&reader, binding, endpoint, cancel)?;
        let context =
            crate::core::runtime_binding::RuntimeCaptureContext::from_issued(issued, case)
                .map_err(|_| SourceError::Invalid)?;
        Ok(LinuxRuntimeCaptureWire {
            schema_version: 1,
            context,
            before,
            after,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (issued, binding);
        Err(SourceError::Unsupported)
    }
}

pub(super) fn check_cancel(cancel: &CancellationToken) -> Result<(), SourceError> {
    if cancel.is_cancelled() {
        Err(SourceError::Cancelled)
    } else {
        Ok(())
    }
}

/// All target-process paths are relative to one pinned /proc/PID directory.
/// Injection exists only inside this module for deterministic parser/race tests.
pub(super) trait ProcReader {
    fn read(&self, path: &str, limit: usize) -> Result<Vec<u8>, SourceError>;
    fn link(&self, path: &str) -> Result<String, SourceError>;
    fn executable_digest(&self, cancel: &CancellationToken) -> Result<String, SourceError>;
}
pub(super) fn bounded_text<R: ProcReader>(
    reader: &R,
    path: &str,
    limit: usize,
) -> Result<String, SourceError> {
    let data = reader.read(path, limit)?;
    if data.is_empty() || data.len() > limit {
        return Err(SourceError::Limit);
    }
    String::from_utf8(data).map_err(|_| SourceError::Invalid)
}
fn observe_with_reader<R: ProcReader>(
    reader: &R,
    binding: &RuntimeProcessBinding,
    endpoint: &CollectorEndpoint,
    cancel: &CancellationToken,
) -> Result<(LinuxProcessSocketSnapshot, LinuxProcessSocketSnapshot), SourceError> {
    binding
        .selector
        .validate()
        .map_err(|_| SourceError::Invalid)?;
    check_cancel(cancel)?;
    let before = snapshot(reader, binding, endpoint, cancel)?;
    check_cancel(cancel)?;
    let after = snapshot(reader, binding, endpoint, cancel)?;
    check_cancel(cancel)?;
    if before != after {
        return Err(SourceError::ContextUnverified);
    }
    Ok((before, after))
}
fn snapshot<R: ProcReader>(
    reader: &R,
    binding: &RuntimeProcessBinding,
    endpoint: &CollectorEndpoint,
    cancel: &CancellationToken,
) -> Result<LinuxProcessSocketSnapshot, SourceError> {
    let selector = &binding.selector;
    let stat = bounded_text(reader, "stat", SMALL_LIMIT)?;
    let start_ticks = start_ticks(&stat, selector.pid)?;
    let boot_id = bounded_text(reader, "boot_id", 64)?.trim().to_owned();
    if start_ticks != selector.expected_start_ticks || boot_id != selector.expected_boot_id {
        return Err(SourceError::ContextUnverified);
    }
    check_cancel(cancel)?;
    let executable_digest = reader.executable_digest(cancel)?;
    if executable_digest != selector.expected_executable_digest {
        return Err(SourceError::ContextUnverified);
    }
    let status = bounded_text(reader, "status", SMALL_LIMIT)?;
    let (uid, effective_uid, gid, effective_gid, status_security) = parse_status(&status)?;
    let label = bounded_text(reader, "attr/current", SMALL_LIMIT)?;
    let cgroup = bounded_text(reader, "cgroup", SMALL_LIMIT)?;
    let net_namespace = namespace(&reader.link("ns/net")?, "net")?;
    let mount_namespace = namespace(&reader.link("ns/mnt")?, "mnt")?;
    let user_namespace = namespace(&reader.link("ns/user")?, "user")?;
    let fd_path = format!("fd/{}", binding.socket_fd);
    let fd_link = reader.link(&fd_path)?;
    let socket_inode = socket_inode(&fd_link)?;
    check_cancel(cancel)?;
    let table = bounded_text(reader, "net/tcp", TCP_LIMIT)?;
    let connection = tcp_connection(&table, socket_inode, endpoint)?;
    // A socket table is namespace-wide: bracket it with the exact FD and
    // incarnation checks, then compare two complete sampled snapshots.
    if reader.link(&fd_path)? != fd_link
        || start_ticks
            != self::start_ticks(&bounded_text(reader, "stat", SMALL_LIMIT)?, selector.pid)?
    {
        return Err(SourceError::ContextUnverified);
    }
    check_cancel(cancel)?;
    let security_digest = crate::config::hash_bytes(
        &[
            b"veil-db-guard/runtime-security/v1\0".as_slice(),
            status_security.as_bytes(),
            b"\0",
            label.as_bytes(),
        ]
        .concat(),
    );
    Ok(LinuxProcessSocketSnapshot {
        boot_id,
        pid: selector.pid,
        start_ticks,
        executable_digest,
        uid,
        effective_uid,
        gid,
        effective_gid,
        net_namespace,
        mount_namespace,
        user_namespace,
        cgroup_digest: crate::config::hash_bytes(cgroup.as_bytes()),
        security_digest,
        fd: binding.socket_fd,
        socket_inode,
        connection,
        tcp_state: 1,
    })
}
pub(super) fn start_ticks(stat: &str, pid: u32) -> Result<u64, SourceError> {
    let open = stat.find('(').ok_or(SourceError::Invalid)?;
    let close = stat
        .rfind(')')
        .filter(|n| *n > open)
        .ok_or(SourceError::Invalid)?;
    if stat[..open].trim().parse::<u32>().ok() != Some(pid) {
        return Err(SourceError::Invalid);
    }
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .ok_or(SourceError::Invalid)
}
pub(super) fn parse_status(status: &str) -> Result<(u32, u32, u32, u32, String), SourceError> {
    let required = [
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "NoNewPrivs",
        "Seccomp",
    ];
    let mut fields = std::collections::BTreeMap::new();
    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if (required.contains(&key) || ["CapAmb", "Seccomp_filters"].contains(&key))
            && fields.insert(key, value.trim()).is_some()
        {
            return Err(SourceError::Invalid);
        }
    }
    if required.iter().any(|key| !fields.contains_key(key)) {
        return Err(SourceError::ContextUnverified);
    }
    let ids = |key| -> Result<Vec<u32>, SourceError> {
        let values: Vec<_> = fields[key]
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<_, _>>()
            .map_err(|_| SourceError::Invalid)?;
        if values.len() != 4 {
            return Err(SourceError::Invalid);
        }
        Ok(values)
    };
    let uid = ids("Uid")?;
    let gid = ids("Gid")?;
    if fields["Groups"]
        .split_whitespace()
        .any(|n| n.parse::<u32>().is_err())
        || ["CapInh", "CapPrm", "CapEff", "CapBnd"]
            .iter()
            .any(|key| u64::from_str_radix(fields[key], 16).is_err())
        || fields
            .get("CapAmb")
            .is_some_and(|v| u64::from_str_radix(v, 16).is_err())
        || !matches!(fields["NoNewPrivs"], "0" | "1")
        || !matches!(fields["Seccomp"], "0" | "1" | "2")
        || fields
            .get("Seccomp_filters")
            .is_some_and(|v| v.parse::<u32>().is_err())
    {
        return Err(SourceError::Invalid);
    }
    let selected = fields
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect::<String>();
    Ok((uid[0], uid[1], gid[0], gid[1], selected))
}
pub(super) fn namespace(link: &str, kind: &str) -> Result<u64, SourceError> {
    link.strip_prefix(&format!("{kind}:["))
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|n| n.parse().ok())
        .filter(|n| *n > 0)
        .ok_or(SourceError::Invalid)
}
pub(super) fn socket_inode(link: &str) -> Result<u64, SourceError> {
    namespace(link, "socket")
}
fn tcp_endpoint(raw: &str) -> Result<(IpAddr, u16), SourceError> {
    let (ip, port) = raw.split_once(':').ok_or(SourceError::Invalid)?;
    if ip.len() != 8 || port.len() != 4 {
        return Err(SourceError::Invalid);
    }
    let ip = u32::from_str_radix(ip, 16).map_err(|_| SourceError::Invalid)?;
    let port = u16::from_str_radix(port, 16).map_err(|_| SourceError::Invalid)?;
    // proc tcp IPv4 words use host byte order. The fixed profile supports the
    // Linux little-endian machines used by existing GCE/EC2 host collectors.
    Ok((IpAddr::V4(Ipv4Addr::from(ip.to_le_bytes())), port))
}
fn tcp_connection(
    table: &str,
    inode: u64,
    endpoint: &CollectorEndpoint,
) -> Result<ConnectionTuple, SourceError> {
    let header = table.lines().next().ok_or(SourceError::Invalid)?;
    if !header.contains("local_address")
        || !header.contains("rem_address")
        || !header.split_whitespace().any(|field| field == "st")
        || !header.split_whitespace().any(|field| field == "inode")
    {
        return Err(SourceError::Invalid);
    }
    let mut found = None;
    for row in table.lines().skip(1) {
        let fields: Vec<_> = row.split_whitespace().collect();
        if fields.len() < 10 {
            return Err(SourceError::Invalid);
        }
        let row_inode = fields[9].parse::<u64>().map_err(|_| SourceError::Invalid)?;
        if row_inode != inode {
            continue;
        }
        if found.is_some() || fields[3] != "01" {
            return Err(SourceError::ContextUnverified);
        }
        let (local_ip, local_port) = tcp_endpoint(fields[1])?;
        let (peer_ip, peer_port) = tcp_endpoint(fields[2])?;
        if peer_ip != endpoint.ip
            || peer_port != endpoint.port
            || local_port == 0
            || local_ip.is_unspecified()
            || local_ip.is_multicast()
        {
            return Err(SourceError::ContextUnverified);
        }
        found = Some(ConnectionTuple {
            endpoint: endpoint.endpoint.clone(),
            local_ip,
            local_port,
            peer_ip,
            peer_port,
        });
    }
    found.ok_or(SourceError::ContextUnverified)
}

// Type-check the Unix descriptor primitives on controller hosts too. The
// collector entry point above refuses non-Linux before constructing this.
#[cfg(unix)]
pub(super) struct NativeProcReader {
    process: std::fs::File,
}
#[cfg(unix)]
impl NativeProcReader {
    pub(super) fn new(pid: u32) -> Result<Self, SourceError> {
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(SourceError::PermissionRequired);
        }
        Self::open_process(pid)
    }
    #[cfg(target_os = "linux")]
    pub(super) fn for_self(pid: u32) -> Result<Self, SourceError> {
        if pid != std::process::id() {
            return Err(SourceError::PermissionRequired);
        }
        Self::open_process(pid)
    }
    fn open_process(pid: u32) -> Result<Self, SourceError> {
        use std::os::unix::fs::OpenOptionsExt;
        if cfg!(target_endian = "big") {
            return Err(SourceError::Unsupported);
        }
        let process = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))
            .map_err(proc_error)?;
        Ok(Self { process })
    }
    pub(super) fn open(&self, path: &str, follow_exe: bool) -> Result<std::fs::File, SourceError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(path).map_err(|_| SourceError::Invalid)?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if follow_exe { 0 } else { libc::O_NOFOLLOW };
        let fd = unsafe { libc::openat(self.process.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(proc_error(std::io::Error::last_os_error()));
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}
#[cfg(unix)]
pub(super) fn proc_error(error: std::io::Error) -> SourceError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        SourceError::PermissionRequired
    } else {
        SourceError::Unavailable
    }
}
#[cfg(unix)]
impl ProcReader for NativeProcReader {
    fn read(&self, path: &str, limit: usize) -> Result<Vec<u8>, SourceError> {
        use std::io::Read;
        let file = if path == "boot_id" {
            std::fs::File::open("/proc/sys/kernel/random/boot_id").map_err(proc_error)?
        } else {
            self.open(path, false)?
        };
        let mut data = Vec::new();
        file.take(limit as u64 + 1)
            .read_to_end(&mut data)
            .map_err(proc_error)?;
        if data.len() > limit {
            return Err(SourceError::Limit);
        }
        Ok(data)
    }
    fn link(&self, path: &str) -> Result<String, SourceError> {
        use std::os::fd::AsRawFd;
        let name = std::ffi::CString::new(path).map_err(|_| SourceError::Invalid)?;
        let mut bytes = vec![0u8; 257];
        let count = unsafe {
            libc::readlinkat(
                self.process.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(proc_error(std::io::Error::last_os_error()));
        }
        if count as usize > 256 {
            return Err(SourceError::Limit);
        }
        bytes.truncate(count as usize);
        String::from_utf8(bytes).map_err(|_| SourceError::Invalid)
    }
    fn executable_digest(&self, cancel: &CancellationToken) -> Result<String, SourceError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut file = self.open("exe", true)?;
        let mut hash = Sha256::new();
        let mut total = 0usize;
        let mut buffer = [0u8; 16384];
        loop {
            check_cancel(cancel)?;
            let count = file.read(&mut buffer).map_err(proc_error)?;
            if count == 0 {
                break;
            }
            total += count;
            if total > EXECUTABLE_LIMIT {
                return Err(SourceError::Limit);
            }
            hash.update(&buffer[..count]);
        }
        if total == 0 {
            return Err(SourceError::Invalid);
        }
        Ok(format!("{:x}", hash.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::{BTreeMap, VecDeque},
    };

    type FixtureValues<T> = RefCell<BTreeMap<String, VecDeque<Result<T, SourceError>>>>;
    struct Fixture {
        reads: FixtureValues<Vec<u8>>,
        links: FixtureValues<String>,
        digest: String,
        cancel_on_tcp: Option<CancellationToken>,
    }
    fn next<T: Clone>(items: &FixtureValues<T>, path: &str) -> Result<T, SourceError> {
        let mut all = items.borrow_mut();
        let values = all.get_mut(path).ok_or(SourceError::Unavailable)?;
        if values.len() > 1 {
            values.pop_front().unwrap()
        } else {
            values.front().cloned().unwrap()
        }
    }
    impl ProcReader for Fixture {
        fn read(&self, path: &str, _limit: usize) -> Result<Vec<u8>, SourceError> {
            if path == "net/tcp"
                && let Some(c) = &self.cancel_on_tcp
            {
                c.cancel();
            }
            next(&self.reads, path)
        }
        fn link(&self, path: &str) -> Result<String, SourceError> {
            next(&self.links, path)
        }
        fn executable_digest(&self, cancel: &CancellationToken) -> Result<String, SourceError> {
            check_cancel(cancel)?;
            Ok(self.digest.clone())
        }
    }
    fn stat(ticks: u64) -> String {
        let mut fields = vec!["0".to_string(); 20];
        fields[0] = "S".into();
        fields[19] = ticks.to_string();
        format!("123 (worker ) (name) {}\n", fields.join(" "))
    }
    fn status() -> String {
        "Uid:\t1000 1001 1002 1003\nGid:\t2000 2001 2002 2003\nGroups:\t2 3\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n".into()
    }
    fn tcp() -> String {
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 0100000A:C350 0200000A:1538 01 00000000:00000000 00:00000000 00000000 0 0 444 1\n".into()
    }
    fn setup() -> (Fixture, RuntimeProcessBinding, CollectorEndpoint) {
        let boot = "01234567-89ab-cdef-0123-456789abcdef";
        let binding = RuntimeProcessBinding {
            target_id: "target".into(),
            grant_id: "grant".into(),
            subject_id: "subject".into(),
            selector: RuntimeProcessSelector {
                pid: 123,
                expected_boot_id: boot.into(),
                expected_start_ticks: 99,
                expected_executable_digest: "a".repeat(64),
            },
            socket_fd: 8,
        };
        let reads = [
            ("stat", stat(99)),
            ("boot_id", format!("{boot}\n")),
            ("status", status()),
            ("attr/current", "unconfined\n".into()),
            ("cgroup", "0::/app.slice\n".into()),
            ("net/tcp", tcp()),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), VecDeque::from([Ok(v.into_bytes())])))
        .collect();
        let links = [
            ("ns/net", "net:[5]"),
            ("ns/mnt", "mnt:[6]"),
            ("ns/user", "user:[7]"),
            ("fd/8", "socket:[444]"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), VecDeque::from([Ok(v.into())])))
        .collect();
        let reader = Fixture {
            reads: RefCell::new(reads),
            links: RefCell::new(links),
            digest: "a".repeat(64),
            cancel_on_tcp: None,
        };
        let endpoint = CollectorEndpoint {
            target_id: "target".into(),
            native_id: "native".into(),
            generation_digest: "b".repeat(64),
            database: "postgres".into(),
            endpoint: "db.example".into(),
            ip: "10.0.0.2".parse().unwrap(),
            port: 5432,
        };
        (reader, binding, endpoint)
    }
    fn reads(reader: &Fixture, path: &str, values: Vec<String>) {
        reader.reads.borrow_mut().insert(
            path.into(),
            values.into_iter().map(|v| Ok(v.into_bytes())).collect(),
        );
    }
    #[test]
    fn passive_sample_attributes_only_fixed_fd_inode_and_exact_established_tuple() {
        let (reader, binding, endpoint) = setup();
        let (before, after) =
            observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()).unwrap();
        assert_eq!(before, after);
        assert_eq!(before.start_ticks, 99);
        assert_eq!(
            (
                before.uid,
                before.effective_uid,
                before.gid,
                before.effective_gid
            ),
            (1000, 1001, 2000, 2001)
        );
        assert_eq!(
            before.connection.local_ip,
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            (before.connection.local_port, before.connection.peer_port),
            (50000, 5432)
        );
        assert_eq!((before.fd, before.socket_inode), (8, 444));
    }
    #[test]
    fn pid_reuse_boot_change_and_executable_change_are_rejected() {
        for mutation in 0..4 {
            let (mut reader, binding, endpoint) = setup();
            match mutation {
                0 => reads(&reader, "stat", vec![stat(100)]),
                1 => reads(&reader, "stat", vec![stat(99), stat(100)]),
                2 => reads(
                    &reader,
                    "boot_id",
                    vec!["11234567-89ab-cdef-0123-456789abcdef".into()],
                ),
                _ => reader.digest = "b".repeat(64),
            }
            assert_eq!(
                observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()),
                Err(SourceError::ContextUnverified)
            );
        }
    }
    #[test]
    fn replacement_fd_and_context_changes_cannot_survive_before_after_check() {
        for mutation in 0..5 {
            let (reader, binding, endpoint) = setup();
            match mutation {
                0 => {
                    reader.links.borrow_mut().insert(
                        "fd/8".into(),
                        VecDeque::from([Ok("socket:[444]".into()), Ok("socket:[445]".into())]),
                    );
                }
                1 => reads(
                    &reader,
                    "status",
                    vec![status(), status().replace("1002", "9999")],
                ),
                2 => reads(
                    &reader,
                    "cgroup",
                    vec!["0::/app.slice\n".into(), "0::/other.slice\n".into()],
                ),
                3 => reads(
                    &reader,
                    "attr/current",
                    vec!["unconfined\n".into(), "confined\n".into()],
                ),
                _ => {
                    reader.links.borrow_mut().insert(
                        "ns/net".into(),
                        VecDeque::from([Ok("net:[5]".into()), Ok("net:[55]".into())]),
                    );
                }
            }
            assert_eq!(
                observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()),
                Err(SourceError::ContextUnverified)
            );
        }
    }
    #[test]
    fn namespace_inventory_wrong_tuple_non_established_or_duplicate_inode_are_rejected() {
        for table in [
            tcp().replace(" 444 ", " 999 "),
            tcp().replace("0200000A", "0300000A"),
            tcp().replace(":1538", ":1539"),
            tcp().replace(" 01 ", " 0A "),
            format!("{}{}\n", tcp(), tcp().lines().nth(1).unwrap()),
        ] {
            let (reader, binding, endpoint) = setup();
            reads(&reader, "net/tcp", vec![table]);
            assert_eq!(
                observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()),
                Err(SourceError::ContextUnverified)
            );
        }
    }
    #[test]
    fn missing_permission_oversize_malformed_and_cancellation_never_yield_sample() {
        for error in [SourceError::Unavailable, SourceError::PermissionRequired] {
            let (reader, binding, endpoint) = setup();
            reader
                .reads
                .borrow_mut()
                .insert("attr/current".into(), VecDeque::from([Err(error)]));
            assert_eq!(
                observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()),
                Err(error)
            );
        }
        let (reader, binding, endpoint) = setup();
        reads(&reader, "net/tcp", vec!["x".repeat(TCP_LIMIT + 1)]);
        assert_eq!(
            observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()),
            Err(SourceError::Limit)
        );
        let (reader, binding, endpoint) = setup();
        reads(&reader, "status", vec!["Uid: 0 0 0 0".into()]);
        assert_eq!(
            observe_with_reader(&reader, &binding, &endpoint, &CancellationToken::new()),
            Err(SourceError::ContextUnverified)
        );
        let (mut reader, binding, endpoint) = setup();
        let cancel = CancellationToken::new();
        reader.cancel_on_tcp = Some(cancel.clone());
        assert_eq!(
            observe_with_reader(&reader, &binding, &endpoint, &cancel),
            Err(SourceError::Cancelled)
        );
        let (reader, binding, endpoint) = setup();
        cancel.cancel();
        assert_eq!(
            observe_with_reader(&reader, &binding, &endpoint, &cancel),
            Err(SourceError::Cancelled)
        );
    }
    #[test]
    fn malformed_stat_and_namespace_fail_closed() {
        assert_eq!(start_ticks("123 wrong", 123), Err(SourceError::Invalid));
        assert_eq!(start_ticks(&stat(99), 124), Err(SourceError::Invalid));
        assert_eq!(namespace("net:[0]", "net"), Err(SourceError::Invalid));
        assert_eq!(
            socket_inode("socket:[444] trailing"),
            Err(SourceError::Invalid)
        );
        assert_eq!(
            parse_status(&format!("{}Uid: 1 2 3 4\n", status())),
            Err(SourceError::Invalid)
        );
    }
}
