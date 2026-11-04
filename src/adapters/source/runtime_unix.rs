//! Two sampled AF_UNIX endpoints on one Linux host. Socket ownership here means
//! the selected process held the observed FD. PostgreSQL and pool attestation
//! require separate evidence.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{gce_host::SourceError, runtime::check_cancel};
use crate::core::{
    runtime_binding::RuntimeProcessSelector,
    runtime_cutover::{NativeUnixPeerObservation, RuntimeProcessIdentity, UnixProcessEndpoint},
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
pub(crate) use native::sample_connector_endpoint;

const MAX_FD: u32 = 1_048_575;
const ESTABLISHED: u8 = 1;
const MAX_DIAG_REPLY: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnixProcessSelection {
    pub selector: RuntimeProcessSelector,
    pub fd: u32,
    pub expected_uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnixSelection {
    pub app: RuntimeUnixProcessSelection,
    pub connector: RuntimeUnixProcessSelection,
    pub socket_path: String,
    pub path_uid: u32,
    pub path_gid: u32,
    /// Permission bits, excluding the socket file type.
    pub path_mode: u16,
}
impl RuntimeUnixSelection {
    pub fn validate(&self) -> Result<(), SourceError> {
        for endpoint in [&self.app, &self.connector] {
            endpoint
                .selector
                .validate()
                .map_err(|_| SourceError::Invalid)?;
            if endpoint.fd > MAX_FD {
                return Err(SourceError::Invalid);
            }
        }
        if self.app.selector.pid == self.connector.selector.pid
            || self.app.selector.expected_boot_id != self.connector.selector.expected_boot_id
            || !valid_socket_path(&self.socket_path)
            || self.path_mode > 0o777
        {
            return Err(SourceError::Invalid);
        }
        Ok(())
    }
}

fn valid_socket_path(path: &str) -> bool {
    path.len() <= 107
        && !path.chars().any(char::is_control)
        && path
            .strip_prefix('/')
            .is_some_and(|path| path.split('/').all(|part| !matches!(part, "" | "." | "..")))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessSample {
    pid: u32,
    boot_id: String,
    start_ticks: u64,
    executable_digest: String,
    effective_uid: u32,
    net_namespace: u64,
    mount_namespace: u64,
    user_namespace: u64,
    security_digest: String,
    cgroup_digest: String,
    fd: u32,
    socket_inode: u64,
}
impl ProcessSample {
    fn matches(&self, selection: &RuntimeUnixProcessSelection) -> bool {
        self.pid == selection.selector.pid
            && self.boot_id == selection.selector.expected_boot_id
            && self.start_ticks == selection.selector.expected_start_ticks
            && self.executable_digest == selection.selector.expected_executable_digest
            && self.effective_uid == selection.expected_uid
            && self.fd == selection.fd
            && u32::try_from(self.socket_inode).is_ok()
            && self.socket_inode != 0
            && self.net_namespace != 0
            && self.mount_namespace != 0
            && self.user_namespace != 0
            && crate::core::policy::valid_hash(&self.security_digest)
            && crate::core::policy::valid_hash(&self.cgroup_digest)
    }
    fn endpoint(&self, cookie: u64) -> UnixProcessEndpoint {
        UnixProcessEndpoint {
            process: RuntimeProcessIdentity {
                pid: self.pid,
                boot_id: self.boot_id.clone(),
                start_ticks: self.start_ticks,
                executable_digest: self.executable_digest.clone(),
            },
            effective_uid: self.effective_uid,
            socket_fd: self.fd,
            socket_inode: self.socket_inode,
            socket_cookie: cookie,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathSample {
    device: u32,
    inode: u32,
    uid: u32,
    gid: u32,
    mode: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagSample {
    inode: u32,
    peer_inode: u32,
    cookie: u64,
    uid: u32,
    name: Option<String>,
    vfs: Option<(u32, u32)>, // (kernel device encoding, inode)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairSample {
    application: ProcessSample,
    connector: ProcessSample,
    application_diag: DiagSample,
    connector_diag: DiagSample,
    path: PathSample,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxUnixSocketCaptureWire {
    schema_version: u32,
    selection: RuntimeUnixSelection,
    before: PairSample,
    after: PairSample,
}
impl LinuxUnixSocketCaptureWire {
    pub fn selection(&self) -> &RuntimeUnixSelection {
        &self.selection
    }
}

/// Validated shape and correlation to the caller's selection. The existing
/// collector verifier still authenticates source and request provenance.
#[derive(Debug, Clone, Serialize)]
pub struct LinuxUnixSocketCapture(LinuxUnixSocketCaptureWire);
impl LinuxUnixSocketCapture {
    pub fn wire(&self) -> &LinuxUnixSocketCaptureWire {
        &self.0
    }
    pub fn peer_observation(&self) -> NativeUnixPeerObservation {
        let pair = &self.0.before;
        NativeUnixPeerObservation {
            application: pair.application.endpoint(pair.application_diag.cookie),
            connector: pair.connector.endpoint(pair.connector_diag.cookie),
        }
    }
}

pub fn validate_wire(
    wire: &LinuxUnixSocketCaptureWire,
    expected: &RuntimeUnixSelection,
) -> Result<LinuxUnixSocketCapture, SourceError> {
    expected.validate()?;
    if wire.schema_version != 1 || &wire.selection != expected || wire.before != wire.after {
        return Err(SourceError::ContextUnverified);
    }
    let pair = &wire.before;
    let app = &pair.application;
    let connector = &pair.connector;
    let app_diag = &pair.application_diag;
    let connector_diag = &pair.connector_diag;
    let path = pair.path;
    if !app.matches(&expected.app)
        || !connector.matches(&expected.connector)
        || app.net_namespace != connector.net_namespace
        || app.mount_namespace != connector.mount_namespace
        || app.user_namespace != connector.user_namespace
        || app.socket_inode == connector.socket_inode
        || u64::from(app_diag.inode) != app.socket_inode
        || u64::from(connector_diag.inode) != connector.socket_inode
        || app_diag.peer_inode != connector_diag.inode
        || connector_diag.peer_inode != app_diag.inode
        || matches!(app_diag.cookie, 0 | u64::MAX)
        || matches!(connector_diag.cookie, 0 | u64::MAX)
        || app_diag.cookie == connector_diag.cookie
        || app_diag.uid != app.effective_uid
        || connector_diag.uid != connector.effective_uid
        || app_diag.name.is_some()
        || app_diag.vfs.is_some()
        || connector_diag.name.as_deref() != Some(expected.socket_path.as_str())
        || connector_diag.vfs != Some((path.device, path.inode))
        || path.inode == 0
        || path.uid != expected.path_uid
        || path.gid != expected.path_gid
        || path.mode != expected.path_mode
    {
        return Err(SourceError::ContextUnverified);
    }
    Ok(LinuxUnixSocketCapture(wire.clone()))
}

pub fn collect(
    selection: &RuntimeUnixSelection,
    cancel: &CancellationToken,
) -> Result<LinuxUnixSocketCapture, SourceError> {
    check_cancel(cancel)?;
    selection.validate()?;
    #[cfg(target_os = "linux")]
    {
        native::collect(selection, cancel)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(SourceError::Unsupported)
    }
}

// Linux UAPI `unix_diag.h` and `sock_diag.h`; netlink numbers use host order.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const AF_UNIX_WIRE: u8 = 1;
const SOCK_STREAM_WIRE: u8 = 1;
const DIAG_SHOW: u32 = 0x01 | 0x02 | 0x04 | 0x40;

fn request(inode: u32, seq: u32, port: u32) -> [u8; 40] {
    let mut bytes = [0; 40];
    bytes[..4].copy_from_slice(&40_u32.to_ne_bytes());
    bytes[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    bytes[6..8].copy_from_slice(&1_u16.to_ne_bytes()); // NLM_F_REQUEST
    bytes[8..12].copy_from_slice(&seq.to_ne_bytes());
    bytes[12..16].copy_from_slice(&port.to_ne_bytes());
    bytes[16] = AF_UNIX_WIRE;
    bytes[20..24].copy_from_slice(&(1_u32 << ESTABLISHED).to_ne_bytes());
    bytes[24..28].copy_from_slice(&inode.to_ne_bytes());
    bytes[28..32].copy_from_slice(&DIAG_SHOW.to_ne_bytes());
    bytes[32..40].fill(0xff); // INET_DIAG_NOCOOKIE for the first exact lookup
    bytes
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("checked length"),
    )
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked length"),
    )
}

fn parse_reply(bytes: &[u8], inode: u32, seq: u32, port: u32) -> Result<DiagSample, SourceError> {
    if bytes.len() > MAX_DIAG_REPLY {
        return Err(SourceError::Limit);
    }
    if bytes.len() < 16
        || u32_at(bytes, 0) as usize != bytes.len()
        || u32_at(bytes, 8) != seq
        || u32_at(bytes, 12) != port
    {
        return Err(SourceError::Invalid);
    }
    match u16_at(bytes, 4) {
        SOCK_DIAG_BY_FAMILY if u16_at(bytes, 6) == 0 => {}
        2 if bytes.len() >= 20 => {
            // NLMSG_ERROR contains a negative errno for the exact request.
            let errno = u32_at(bytes, 16) as i32;
            return Err(match errno.checked_neg() {
                Some(libc::EOPNOTSUPP | libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT) => {
                    SourceError::Unsupported
                }
                Some(libc::EACCES | libc::EPERM) => SourceError::PermissionRequired,
                Some(libc::ENOENT) => SourceError::ContextUnverified,
                _ => SourceError::Unavailable,
            });
        }
        _ => return Err(SourceError::Invalid),
    }
    if bytes.len() < 32
        || bytes[16..20] != [AF_UNIX_WIRE, SOCK_STREAM_WIRE, ESTABLISHED, 0]
        || u32_at(bytes, 20) != inode
    {
        return Err(SourceError::ContextUnverified);
    }
    let cookie = u64::from(u32_at(bytes, 24)) | (u64::from(u32_at(bytes, 28)) << 32);
    let mut name = None;
    let mut vfs = None;
    let mut peer_inode = None;
    let mut uid = None;
    let mut shutdown = None;
    let mut attrs = &bytes[32..];
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(SourceError::Invalid);
        }
        let len = usize::from(u16_at(attrs, 0));
        let aligned = (len + 3) & !3;
        if len < 4 || aligned > attrs.len() {
            return Err(SourceError::Invalid);
        }
        let body = &attrs[4..len];
        match u16_at(attrs, 2) {
            0 if name.is_none() => {
                let path = body.strip_suffix(&[0]).ok_or(SourceError::Unsupported)?;
                let path = std::str::from_utf8(path).map_err(|_| SourceError::Unsupported)?;
                if !valid_socket_path(path) {
                    return Err(SourceError::Unsupported);
                }
                name = Some(path.to_owned());
            }
            1 if vfs.is_none() && body.len() == 8 => {
                vfs = Some((u32_at(body, 4), u32_at(body, 0)));
            }
            2 if peer_inode.is_none() && body.len() == 4 => peer_inode = Some(u32_at(body, 0)),
            6 if shutdown.is_none() && body.len() == 1 => shutdown = Some(body[0]),
            7 if uid.is_none() && body.len() == 4 => uid = Some(u32_at(body, 0)),
            _ => return Err(SourceError::Invalid),
        }
        attrs = &attrs[aligned..];
    }
    if shutdown != Some(0) {
        return Err(SourceError::ContextUnverified);
    }
    Ok(DiagSample {
        inode,
        peer_inode: peer_inode
            .filter(|n| *n != 0)
            .ok_or(SourceError::ContextUnverified)?,
        cookie,
        uid: uid.ok_or(SourceError::Unsupported)?,
        name,
        vfs,
    })
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use crate::adapters::source::runtime::{
        NativeProcReader, ProcReader, SMALL_LIMIT, bounded_text, namespace, parse_status,
        proc_error, socket_inode, start_ticks,
    };
    use std::{
        ffi::CString,
        fs::File,
        mem::{size_of, zeroed},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::fs::{FileTypeExt, MetadataExt},
        },
        time::{Duration, Instant},
    };

    pub(super) fn collect(
        selection: &RuntimeUnixSelection,
        cancel: &CancellationToken,
    ) -> Result<LinuxUnixSocketCapture, SourceError> {
        let app = NativeProcReader::new(selection.app.selector.pid)?;
        let connector = NativeProcReader::new(selection.connector.selector.pid)?;
        // Avoid deliberately requesting module autoload on an unprepared host.
        // No module-management operation is performed by the collector.
        if !std::path::Path::new("/sys/module/unix_diag").is_dir() {
            return Err(SourceError::Unsupported);
        }
        let mut diag = DiagSocket::open()?;
        let before = sample(selection, &app, &connector, &mut diag, cancel)?;
        check_cancel(cancel)?;
        let after = sample(selection, &app, &connector, &mut diag, cancel)?;
        check_cancel(cancel)?;
        validate_wire(
            &LinuxUnixSocketCaptureWire {
                schema_version: 1,
                selection: selection.clone(),
                before,
                after,
            },
            selection,
        )
    }

    pub(crate) fn sample_connector_endpoint(
        fd: std::os::fd::BorrowedFd<'_>,
        selection: &RuntimeUnixProcessSelection,
        cancel: &CancellationToken,
    ) -> Result<UnixProcessEndpoint, SourceError> {
        if selection.selector.pid != std::process::id()
            || i32::try_from(selection.fd).ok() != Some(fd.as_raw_fd())
        {
            return Err(SourceError::ContextUnverified);
        }
        let proc = NativeProcReader::for_self(selection.selector.pid)?;
        let sample = process(&proc, selection, cancel)?;
        let mut cookie = 0u64;
        let mut len = size_of::<u64>() as libc::socklen_t;
        // The borrowed descriptor stays open across both procfs samples.
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut len,
            )
        };
        if rc != 0 || len as usize != size_of::<u64>() || cookie == 0 {
            return Err(SourceError::ContextUnverified);
        }
        recheck_process(&proc, &sample)?;
        Ok(sample.endpoint(cookie))
    }

    fn process(
        proc: &NativeProcReader,
        selection: &RuntimeUnixProcessSelection,
        cancel: &CancellationToken,
    ) -> Result<ProcessSample, SourceError> {
        check_cancel(cancel)?;
        let pid = selection.selector.pid;
        let start_ticks = start_ticks(&bounded_text(proc, "stat", SMALL_LIMIT)?, pid)?;
        let boot_id = bounded_text(proc, "boot_id", 64)?.trim().to_owned();
        if start_ticks != selection.selector.expected_start_ticks
            || boot_id != selection.selector.expected_boot_id
        {
            return Err(SourceError::ContextUnverified);
        }
        let executable_digest = proc.executable_digest(cancel)?;
        let (_, effective_uid, _, _, selected_status) =
            parse_status(&bounded_text(proc, "status", SMALL_LIMIT)?)?;
        let security_label = bounded_text(proc, "attr/current", SMALL_LIMIT)?;
        let cgroup = bounded_text(proc, "cgroup", SMALL_LIMIT)?;
        let read_namespace = |name| namespace(&proc.link(&format!("ns/{name}"))?, name);
        let sample = ProcessSample {
            pid,
            boot_id,
            start_ticks,
            executable_digest,
            effective_uid,
            net_namespace: read_namespace("net")?,
            mount_namespace: read_namespace("mnt")?,
            user_namespace: read_namespace("user")?,
            security_digest: crate::config::hash_bytes(
                &[
                    b"veil-db-guard/runtime-unix-security/v1\0".as_slice(),
                    selected_status.as_bytes(),
                    b"\0",
                    security_label.as_bytes(),
                ]
                .concat(),
            ),
            cgroup_digest: crate::config::hash_bytes(cgroup.as_bytes()),
            fd: selection.fd,
            socket_inode: read_fd(proc, selection.fd)?,
        };
        if !sample.matches(selection) {
            return Err(SourceError::ContextUnverified);
        }
        Ok(sample)
    }

    fn read_fd(proc: &NativeProcReader, fd: u32) -> Result<u64, SourceError> {
        socket_inode(&proc.link(&format!("fd/{fd}"))?)
    }

    fn recheck_process(proc: &NativeProcReader, sample: &ProcessSample) -> Result<(), SourceError> {
        if read_fd(proc, sample.fd)? != sample.socket_inode
            || start_ticks(&bounded_text(proc, "stat", SMALL_LIMIT)?, sample.pid)?
                != sample.start_ticks
        {
            return Err(SourceError::ContextUnverified);
        }
        Ok(())
    }

    fn check_namespaces(sample: &ProcessSample) -> Result<(), SourceError> {
        // The netlink socket queries the collector's net namespace. Matching
        // user namespaces keeps the reported UID mapping consistent.
        for (kind, expected) in [
            ("net", sample.net_namespace),
            ("mnt", sample.mount_namespace),
            ("user", sample.user_namespace),
        ] {
            let link = std::fs::read_link(format!("/proc/self/ns/{kind}")).map_err(proc_error)?;
            let link = link.to_str().ok_or(SourceError::Invalid)?;
            if namespace(link, kind)? != expected {
                return Err(SourceError::Unsupported);
            }
        }
        Ok(())
    }

    fn sample(
        selection: &RuntimeUnixSelection,
        app_proc: &NativeProcReader,
        connector_proc: &NativeProcReader,
        diag: &mut DiagSocket,
        cancel: &CancellationToken,
    ) -> Result<PairSample, SourceError> {
        let application = process(app_proc, &selection.app, cancel)?;
        let connector = process(connector_proc, &selection.connector, cancel)?;
        check_namespaces(&application)?;
        check_namespaces(&connector)?;
        let path = stat_path(connector_proc, &selection.socket_path)?;
        if path != stat_path(app_proc, &selection.socket_path)? {
            return Err(SourceError::ContextUnverified);
        }
        let application_diag = diag.query(application.socket_inode, cancel)?;
        let connector_diag = diag.query(connector.socket_inode, cancel)?;
        recheck_process(app_proc, &application)?;
        recheck_process(connector_proc, &connector)?;
        Ok(PairSample {
            application,
            connector,
            application_diag,
            connector_diag,
            path,
        })
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn stat_path(proc: &NativeProcReader, path: &str) -> Result<PathSample, SourceError> {
        // The selected process may be chrooted even in our mount namespace.
        // Resolve from its actual root and forbid symlinks at every component.
        let root = proc.open("root", true)?;
        let path = CString::new(path).map_err(|_| SourceError::Invalid)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0x10 | 0x04, // RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS
        };
        // SAFETY: root and path remain valid; openat2 receives the UAPI layout.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                path.as_ptr(),
                &how,
                size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(libc::ENOSYS) => SourceError::Unsupported,
                Some(libc::ELOOP) => SourceError::ContextUnverified,
                _ => proc_error(error),
            });
        }
        // SAFETY: a successful openat2 returns one owned FD.
        let file = unsafe { File::from_raw_fd(fd as i32) };
        let stat = file.metadata().map_err(proc_error)?;
        if !stat.file_type().is_socket() || stat.mode() & 0o7000 != 0 {
            return Err(SourceError::ContextUnverified);
        }
        let major = libc::major(stat.dev());
        let minor = libc::minor(stat.dev());
        if major > 0xfff || minor > 0xfffff {
            return Err(SourceError::Unsupported);
        }
        Ok(PathSample {
            device: (major << 20) | minor,
            inode: u32::try_from(stat.ino()).map_err(|_| SourceError::Unsupported)?,
            uid: stat.uid(),
            gid: stat.gid(),
            mode: (stat.mode() & 0o777) as u16,
        })
    }

    struct DiagSocket {
        fd: OwnedFd,
        port: u32,
        seq: u32,
    }
    impl DiagSocket {
        fn open() -> Result<Self, SourceError> {
            // SAFETY: socket arguments are fixed Linux UAPI constants.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_SOCK_DIAG,
                )
            };
            if fd < 0 {
                return Err(netlink_error());
            }
            // SAFETY: successful socket returns one owned FD.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut addr = kernel_addr();
            let addr_size = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: addr is a valid sockaddr_nl of exactly addr_size bytes.
            if unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), addr_size) } < 0 {
                return Err(netlink_error());
            }
            let mut len = addr_size;
            // SAFETY: mutable addr is writable for addr_size bytes.
            if unsafe { libc::getsockname(fd.as_raw_fd(), (&raw mut addr).cast(), &mut len) } < 0 {
                return Err(netlink_error());
            }
            if len != addr_size
                || addr.nl_family != libc::AF_NETLINK as u16
                || addr.nl_pid == 0
                || addr.nl_groups != 0
            {
                return Err(SourceError::Invalid);
            }
            Ok(Self {
                fd,
                port: addr.nl_pid,
                seq: 0,
            })
        }

        fn query(
            &mut self,
            inode: u64,
            cancel: &CancellationToken,
        ) -> Result<DiagSample, SourceError> {
            check_cancel(cancel)?;
            let inode = u32::try_from(inode).map_err(|_| SourceError::Unsupported)?;
            self.seq += 1;
            let request = request(inode, self.seq, self.port);
            let kernel = kernel_addr();
            let addr_size = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: request and kernel address are alive and sized exactly.
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    request.as_ptr().cast(),
                    request.len(),
                    0,
                    (&raw const kernel).cast(),
                    addr_size,
                )
            };
            if sent < 0 {
                return Err(netlink_error());
            }
            if sent as usize != request.len() {
                return Err(SourceError::Unavailable);
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut ready = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                check_cancel(cancel)?;
                if Instant::now() >= deadline {
                    return Err(SourceError::TimedOut);
                }
                // SAFETY: one initialized pollfd is valid for the fixed poll.
                let result = unsafe { libc::poll(&mut ready, 1, 25) };
                if result < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(proc_error(error));
                }
                if result > 0 && ready.revents & libc::POLLIN != 0 {
                    break;
                }
                if result > 0 {
                    return Err(SourceError::Unavailable);
                }
            }
            check_cancel(cancel)?;
            let mut reply = [0_u8; MAX_DIAG_REPLY];
            let mut sender = kernel_addr();
            let mut len = addr_size;
            // SAFETY: reply and sender are writable to the supplied lengths.
            let count = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    reply.as_mut_ptr().cast(),
                    reply.len(),
                    libc::MSG_TRUNC,
                    (&raw mut sender).cast(),
                    &mut len,
                )
            };
            if count < 0 {
                return Err(netlink_error());
            }
            if count as usize > reply.len() {
                return Err(SourceError::Limit);
            }
            if len != addr_size
                || sender.nl_family != libc::AF_NETLINK as u16
                || sender.nl_pid != 0
                || sender.nl_groups != 0
            {
                return Err(SourceError::ContextUnverified);
            }
            parse_reply(&reply[..count as usize], inode, self.seq, self.port)
        }
    }

    fn kernel_addr() -> libc::sockaddr_nl {
        // SAFETY: sockaddr_nl is a plain integer UAPI struct, zero fills padding.
        let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr
    }

    fn netlink_error() -> SourceError {
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT | libc::EOPNOTSUPP) => {
                SourceError::Unsupported
            }
            _ => proc_error(error),
        }
    }
}

#[cfg(test)]
pub(super) fn fixture() -> (RuntimeUnixSelection, LinuxUnixSocketCaptureWire) {
    tests::fixture()
}

#[cfg(test)]
pub(super) fn fixture_separate_users() -> (RuntimeUnixSelection, LinuxUnixSocketCaptureWire) {
    let (mut selection, mut wire) = tests::fixture();
    selection.connector.expected_uid = 1001;
    selection.path_uid = 1001;
    wire.selection = selection.clone();
    for pair in [&mut wire.before, &mut wire.after] {
        pair.connector.effective_uid = 1001;
        pair.connector_diag.uid = 1001;
        pair.path.uid = 1001;
    }
    (selection, wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(bytes: &mut Vec<u8>, kind: u16, body: &[u8]) {
        let len = 4 + body.len();
        bytes.extend((len as u16).to_ne_bytes());
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(body);
        bytes.resize(bytes.len() + ((4 - (len % 4)) % 4), 0);
    }

    fn packet(inode: u32, peer: u32, cookie: u64, path: Option<&str>) -> Vec<u8> {
        let mut bytes = vec![0; 16];
        bytes[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        bytes[8..12].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&99_u32.to_ne_bytes());
        bytes.extend([AF_UNIX_WIRE, SOCK_STREAM_WIRE, ESTABLISHED, 0]);
        bytes.extend(inode.to_ne_bytes());
        bytes.extend((cookie as u32).to_ne_bytes());
        bytes.extend(((cookie >> 32) as u32).to_ne_bytes());
        if let Some(path) = path {
            let mut name = path.as_bytes().to_vec();
            name.push(0);
            attr(&mut bytes, 0, &name);
            let mut vfs = 88_u32.to_ne_bytes().to_vec();
            vfs.extend(77_u32.to_ne_bytes());
            attr(&mut bytes, 1, &vfs);
        }
        attr(&mut bytes, 2, &peer.to_ne_bytes());
        attr(&mut bytes, 6, &[0]);
        attr(&mut bytes, 7, &1000_u32.to_ne_bytes());
        set_len(&mut bytes);
        bytes
    }

    fn set_len(bytes: &mut [u8]) {
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_ne_bytes());
    }

    #[test]
    fn exact_diag_reply_parses_reciprocal_inodes_cookie_uid_and_path() {
        let path = "/run/veil/proxy.sock";
        let app = parse_reply(&packet(10, 11, 1, None), 10, 3, 99).unwrap();
        let peer = parse_reply(&packet(11, 10, (1 << 40) | 2, Some(path)), 11, 3, 99).unwrap();
        assert_eq!((app.inode, app.peer_inode), (10, 11));
        assert_eq!((peer.inode, peer.peer_inode), (11, 10));
        assert_eq!(peer.cookie, (1 << 40) | 2);
        assert_eq!(peer.uid, 1000);
        assert_eq!(peer.name.as_deref(), Some(path));
        assert_eq!(peer.vfs, Some((77, 88)));
        let query = request(10, 3, 99);
        assert_eq!(u32_at(&query, 24), 10);
        assert_eq!(u32_at(&query, 28), DIAG_SHOW);
        assert_eq!(&query[32..], &[0xff; 8]);
    }

    #[test]
    fn diag_rejects_wrong_sender_header_shutdown_and_malformed_attributes() {
        let packet = packet(10, 11, 1, None);
        assert_eq!(parse_reply(&packet, 10, 3, 98), Err(SourceError::Invalid));
        assert_eq!(parse_reply(&packet, 10, 4, 99), Err(SourceError::Invalid));
        assert_eq!(
            parse_reply(&packet, 12, 3, 99),
            Err(SourceError::ContextUnverified)
        );
        for end in 0..packet.len() {
            assert!(parse_reply(&packet[..end], 10, 3, 99).is_err());
        }
        let mut state = packet.clone();
        state[18] = 10;
        assert_eq!(
            parse_reply(&state, 10, 3, 99),
            Err(SourceError::ContextUnverified)
        );
        let mut shutdown = packet.clone();
        shutdown[44] = 1;
        assert_eq!(
            parse_reply(&shutdown, 10, 3, 99),
            Err(SourceError::ContextUnverified)
        );
        let mut duplicate = packet;
        attr(&mut duplicate, 2, &11_u32.to_ne_bytes());
        set_len(&mut duplicate);
        assert_eq!(
            parse_reply(&duplicate, 10, 3, 99),
            Err(SourceError::Invalid)
        );
    }

    pub(super) fn fixture() -> (RuntimeUnixSelection, LinuxUnixSocketCaptureWire) {
        let process = |pid, fd, inode| ProcessSample {
            pid,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            start_ticks: 100,
            executable_digest: "a".repeat(64),
            effective_uid: 1000,
            net_namespace: 1,
            mount_namespace: 2,
            user_namespace: 3,
            security_digest: "b".repeat(64),
            cgroup_digest: "c".repeat(64),
            fd,
            socket_inode: inode,
        };
        let selection = |process: &ProcessSample| RuntimeUnixProcessSelection {
            selector: RuntimeProcessSelector {
                pid: process.pid,
                expected_boot_id: process.boot_id.clone(),
                expected_start_ticks: process.start_ticks,
                expected_executable_digest: process.executable_digest.clone(),
            },
            fd: process.fd,
            expected_uid: process.effective_uid,
        };
        let application = process(100, 5, 10);
        let connector = process(200, 6, 11);
        let selection = RuntimeUnixSelection {
            app: selection(&application),
            connector: selection(&connector),
            socket_path: "/run/veil/proxy.sock".into(),
            path_uid: 1000,
            path_gid: 1001,
            path_mode: 0o660,
        };
        let before = PairSample {
            application,
            connector,
            application_diag: parse_reply(&packet(10, 11, 1, None), 10, 3, 99).unwrap(),
            connector_diag: parse_reply(
                &packet(11, 10, 2, Some(&selection.socket_path)),
                11,
                3,
                99,
            )
            .unwrap(),
            path: PathSample {
                device: 77,
                inode: 88,
                uid: 1000,
                gid: 1001,
                mode: 0o660,
            },
        };
        let wire = LinuxUnixSocketCaptureWire {
            schema_version: 1,
            selection: selection.clone(),
            before: before.clone(),
            after: before,
        };
        (selection, wire)
    }

    #[test]
    fn validation_checks_pinned_scope_and_both_samples() {
        let (selection, wire) = fixture();
        let round_trip: LinuxUnixSocketCaptureWire =
            serde_json::from_slice(&serde_json::to_vec(&wire).unwrap()).unwrap();
        let capture = validate_wire(&round_trip, &selection).unwrap();
        let observation = capture.peer_observation();
        assert_eq!(observation.application.process.pid, 100);
        assert_eq!(observation.connector.process.pid, 200);
        assert_eq!(observation.connector.socket_fd, 6);
        assert_eq!(observation.connector.socket_cookie, 2);

        let mut replaced = wire.clone();
        replaced.after.application_diag.cookie = 99;
        assert!(validate_wire(&replaced, &selection).is_err());
        let mut changed = selection.clone();
        changed.connector.selector.expected_start_ticks += 1;
        assert!(validate_wire(&wire, &changed).is_err());

        let mut unexpected_key = serde_json::to_value(wire).unwrap();
        unexpected_key["runtime_binding_verified"] = serde_json::json!(true);
        assert!(serde_json::from_value::<LinuxUnixSocketCaptureWire>(unexpected_key).is_err());
    }

    #[test]
    fn stable_but_unpaired_or_wrong_owner_socket_never_validates() {
        type Mutation = fn(&mut PairSample);
        let mutations: [Mutation; 9] = [
            |p| p.application_diag.peer_inode = 12,
            |p| p.connector_diag.peer_inode = 12,
            |p| p.connector.socket_inode = 13,
            |p| p.connector.effective_uid = 0,
            |p| p.connector.user_namespace += 1,
            |p| p.path.inode += 1,
            |p| p.path.uid += 1,
            |p| p.path.mode = 0o777,
            |p| p.connector_diag.name = Some("/run/wrong.sock".into()),
        ];
        for mutation in mutations {
            let (selection, mut wire) = fixture();
            mutation(&mut wire.before);
            wire.after = wire.before.clone();
            assert!(validate_wire(&wire, &selection).is_err());
        }
    }

    #[test]
    fn rejects_relative_abstract_or_traversing_paths_and_cancelled_capture() {
        let (mut selection, _) = fixture();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            collect(&selection, &cancel),
            Err(SourceError::Cancelled)
        ));
        for path in [
            "@",
            "proxy.sock",
            "/run/../proxy.sock",
            "/run//proxy.sock",
            "/run/\0x",
        ] {
            selection.socket_path = path.into();
            assert_eq!(selection.validate(), Err(SourceError::Invalid));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "explicit Linux kernel test: requires preloaded unix_diag and cross-UID procfs access"]
fn native_observer_correlates_distinct_uid_socket_peers() {
    use super::runtime::{NativeProcReader, ProcReader, start_ticks};
    use std::{
        io::{BufRead, BufReader},
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
        process::{Child, Command, Stdio},
    };

    struct Worker(Child);
    impl Drop for Worker {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    impl Worker {
        fn start(code: &str, path: &std::path::Path, uid: u32) -> Self {
            Self(
                Command::new("/usr/bin/python3")
                    .args(["-I", "-u", "-c", code])
                    .arg(path)
                    .uid(uid)
                    .gid(61000)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("start isolated socket fixture"),
            )
        }
        fn read(&mut self) -> String {
            let mut line = String::new();
            BufReader::new(self.0.stdout.as_mut().unwrap())
                .read_line(&mut line)
                .unwrap();
            line.trim().to_owned()
        }
        fn selection(&self, fd: u32, uid: u32) -> RuntimeUnixProcessSelection {
            let pid = self.0.id();
            let proc = NativeProcReader::new(pid).unwrap();
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
            RuntimeUnixProcessSelection {
                selector: RuntimeProcessSelector {
                    pid,
                    expected_boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                        .unwrap()
                        .trim()
                        .to_owned(),
                    expected_start_ticks: start_ticks(&stat, pid).unwrap(),
                    expected_executable_digest: proc
                        .executable_digest(&CancellationToken::new())
                        .unwrap(),
                },
                fd,
                expected_uid: uid,
            }
        }
    }

    assert!(
        std::path::Path::new("/sys/module/unix_diag").is_dir(),
        "unix_diag must be loaded before the test"
    );
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::chown(dir.path(), Some(61001), Some(61000)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    let socket = dir.path().join("peer.sock");
    let mut connector = Worker::start(
        "import os,socket,sys\ns=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);os.chmod(sys.argv[1],0o660);s.listen();print('ready');c,_=s.accept();print(c.fileno());sys.stdin.buffer.read(1)",
        &socket,
        61001,
    );
    assert_eq!(connector.read(), "ready");
    let mut app = Worker::start(
        "import socket,sys\ns=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);print(s.fileno());sys.stdin.buffer.read(1)",
        &socket,
        61002,
    );
    let app_fd = app.read().parse().unwrap();
    let connector_fd = connector.read().parse().unwrap();
    let metadata = std::fs::symlink_metadata(&socket).unwrap();
    let selection = RuntimeUnixSelection {
        app: app.selection(app_fd, 61002),
        connector: connector.selection(connector_fd, 61001),
        socket_path: socket.to_str().unwrap().to_owned(),
        path_uid: metadata.uid(),
        path_gid: metadata.gid(),
        path_mode: (metadata.mode() & 0o777) as u16,
    };
    let capture = collect(&selection, &CancellationToken::new()).unwrap();
    let peer = capture.peer_observation();
    assert_eq!(
        (peer.application.effective_uid, peer.connector.effective_uid),
        (61002, 61001)
    );
    assert_ne!(peer.application.socket_cookie, peer.connector.socket_cookie);
    // Exercise the production corroborator using native kernel evidence.
    // The connector and pool statements are synthetic; this is not a full
    // application checkout test.
    super::gce_host::tests::assert_registered_witness_join(
        selection.clone(),
        capture.wire().clone(),
    );
    let mut wrong = selection;
    wrong.app.fd = 0;
    assert!(collect(&wrong, &CancellationToken::new()).is_err());
}
