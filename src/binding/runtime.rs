//! Application-side PostgreSQL connection and diagnostic session sampling.
use super::{AppConnectionProfile, BindingError, BindingRoute, connection_profile};
use crate::core::{
    change::PreparedChange,
    policy::{EngineFamily, RouteKind, valid_hash},
    source::{SourceBoundaryKind, SourcePurpose, SourceSnapshotRef},
};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionBundle {
    contract: &'static str,
    change_hash: String,
    profile: AppConnectionProfile,
    source: SourceSnapshotRef,
    route_id: String,
    target_generation: String,
    pool_generation: u64,
}

impl ConnectionBundle {
    pub fn prepare(
        change: &PreparedChange,
        grant_id: &str,
        source_id: &str,
        route_id: &str,
        pool_generation: u64,
    ) -> Result<Self, BindingError> {
        change.verify().map_err(|_| BindingError::Invalid)?;
        if change.policy.schema_version != 2 || pool_generation == 0 {
            return Err(BindingError::Invalid);
        }
        let policy = &change.policy;
        let profile = connection_profile(policy, grant_id)?;
        let target = policy
            .targets
            .iter()
            .find(|t| t.id == profile.target_id)
            .ok_or(BindingError::Invalid)?;
        if profile.route != BindingRoute::CloudSqlConnector
            || target.engine.family != EngineFamily::PostgreSql
        {
            return Err(BindingError::Unsupported);
        }
        let grant = policy
            .grants
            .iter()
            .find(|g| g.id == grant_id)
            .ok_or(BindingError::Invalid)?;
        let protection = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(BindingError::Invalid)?;
        if !profile.workload_sources.iter().any(|id| id == source_id)
            || !protection.allowed_routes.iter().any(|r| {
                r.id == route_id
                    && r.kind == RouteKind::NativeConnector
                    && r.source_ids.iter().any(|id| id == source_id)
            })
        {
            return Err(BindingError::Invalid);
        }
        let source = policy
            .source_bindings
            .iter()
            .find(|s| {
                s.source_id == source_id
                    && s.boundary == SourceBoundaryKind::GceHostNetwork
                    && s.allowed_uses.iter().any(|u| {
                        u.subject_id == profile.subject_id
                            && u.purpose == SourcePurpose::Application
                    })
            })
            .ok_or(BindingError::Invalid)?;
        let target_generation = target
            .resource
            .generation_fingerprint
            .as_ref()
            .filter(|g| valid_hash(g))
            .ok_or(BindingError::Pending)?;
        Ok(Self {
            contract: "gcp-postgres-app-connection-v1",
            change_hash: change.change_hash.clone(),
            profile,
            source: source.snapshot_ref(),
            route_id: route_id.into(),
            target_generation: target_generation.clone(),
            pool_generation,
        })
    }

    pub fn digest(&self) -> String {
        super::hash(self)
    }

    /// The registered witness configuration pins this scope before the source
    /// snapshot and prepared change exist. Exact revision checks happen at
    /// checkout; including either revision here would make registration cyclic.
    pub fn witness_scope_digest(&self) -> String {
        super::hash(&(
            "k11-gcp-witness-scope-v1",
            &self.profile.target_id,
            &self.profile.target_hash,
            &self.profile.grant_id,
            &self.profile.subject_id,
            &self.profile.database,
            &self.profile.database_identity,
            &self.profile.workload_identity_reference,
            &self.source.source_id,
            &self.source.registration_id,
            &self.route_id,
            &self.target_generation,
            self.pool_generation,
        ))
    }

    /// Reload an exported bundle against the application's trusted change and
    /// locally selected grant, route, source and generation.
    pub fn verify_export(&self, bytes: &[u8]) -> Result<(), BindingError> {
        if bytes.len() > 64 * 1024 {
            return Err(BindingError::Invalid);
        }
        let expected = serde_json::to_value(self).map_err(|_| BindingError::Invalid)?;
        let actual: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| BindingError::Invalid)?;
        if expected != actual {
            return Err(BindingError::Invalid);
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::{
    AppSession, PoolCheckout, ServerSessionSample, SessionPool, SessionSample, UnixConnectorAccess,
    inspect_session_from_recovery,
};

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        os::unix::fs::{FileTypeExt, MetadataExt},
        path::Path,
        sync::{Arc, Mutex, Weak},
        time::Duration,
    };
    use tokio::{
        net::UnixStream,
        sync::{Mutex as SessionLock, OwnedMutexGuard},
        task::JoinHandle,
    };
    use tokio_postgres::{Client, NoTls};
    use tokio_util::sync::CancellationToken;

    // Use simple protocol so no arbitrary application input enters this query.
    const SESSION_SQL: &str = "SELECT pg_catalog.current_database(), session_user, current_user, pg_catalog.pg_backend_pid()::text, (SELECT ((extract(epoch FROM backend_start) * 1000000)::bigint)::text FROM pg_catalog.pg_stat_activity WHERE pid = pg_catalog.pg_backend_pid())";

    /// Distinct connector account with controlled group access to its socket.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UnixConnectorAccess {
        pub peer_uid: u32,
        pub socket_gid: u32,
    }

    /// This sample describes the connection returned to the app. The connector
    /// peer and DB reply still need independent verification before admission.
    #[derive(Debug, Serialize)]
    pub struct SessionSample {
        bundle_digest: String,
        pool_generation: u64,
        process_id: u32,
        socket_fd: i32,
        socket_inode: u64,
        #[cfg(target_os = "linux")]
        socket_cookie: Option<u64>,
        connector_uid: u32,
        connection_marker: String,
        database: String,
        session_user: String,
        backend_pid: u32,
        backend_started_at_micros: i64,
    }

    pub struct AppSession {
        client: Client,
        task: JoinHandle<()>,
        sample: SessionSample,
    }

    impl Drop for AppSession {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl AppSession {
        /// The application owns the socket directory and runs its configured
        /// IAM connector there. The connector handles credentials in memory.
        pub async fn connect(
            bundle: &ConnectionBundle,
            private_directory: &Path,
            cancel: &CancellationToken,
        ) -> Result<Self, BindingError> {
            Self::connect_with_access(bundle, private_directory, None, cancel).await
        }

        async fn connect_with_access(
            bundle: &ConnectionBundle,
            private_directory: &Path,
            access: Option<UnixConnectorAccess>,
            cancel: &CancellationToken,
        ) -> Result<Self, BindingError> {
            let work = async {
                let uid = unsafe { libc::geteuid() };
                let directory = std::fs::symlink_metadata(private_directory)
                    .map_err(|_| BindingError::Pending)?;
                if !private_directory.is_absolute() || !directory.is_dir() {
                    return Err(BindingError::Invalid);
                }
                let socket = private_directory.join(".s.PGSQL.5432");
                let meta = std::fs::symlink_metadata(&socket).map_err(|_| BindingError::Pending)?;
                if !meta.file_type().is_socket() {
                    return Err(BindingError::Invalid);
                }
                let peer_uid = match access {
                    None if directory.uid() == uid
                        && directory.mode() & 0o077 == 0
                        && meta.uid() == uid =>
                    {
                        uid
                    }
                    Some(access)
                        if access.peer_uid != uid
                            && directory.uid() == access.peer_uid
                            && meta.uid() == access.peer_uid
                            && directory.gid() == access.socket_gid
                            && meta.gid() == access.socket_gid
                            && directory.mode() & 0o027 == 0
                            && directory.mode() & 0o010 != 0
                            && meta.mode() & 0o007 == 0
                            && meta.mode() & 0o020 != 0 =>
                    {
                        access.peer_uid
                    }
                    _ => return Err(BindingError::Invalid),
                };
                let stream = UnixStream::connect(socket)
                    .await
                    .map_err(|_| BindingError::Pending)?;
                let peer = stream.peer_cred().map_err(|_| BindingError::Pending)?;
                if peer.uid() != peer_uid {
                    return Err(BindingError::Invalid);
                }
                Self::connect_stream(bundle, stream, peer.uid()).await
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(BindingError::Pending),
                result = tokio::time::timeout(Duration::from_secs(10), work) =>
                    result.unwrap_or(Err(BindingError::Pending)),
            }
        }

        async fn connect_stream(
            bundle: &ConnectionBundle,
            stream: UnixStream,
            connector_uid: u32,
        ) -> Result<Self, BindingError> {
            use std::os::fd::AsRawFd;
            let socket_fd = stream.as_raw_fd();
            let socket_inode = live_socket_inode(socket_fd)?;
            #[cfg(target_os = "linux")]
            let socket_cookie = linux_socket_option::<8>(socket_fd, libc::SO_COOKIE)
                .ok()
                .map(u64::from_ne_bytes)
                .filter(|cookie| *cookie != 0);
            use ring::rand::{SecureRandom, SystemRandom};
            let mut marker = [0u8; 16];
            SystemRandom::new()
                .fill(&mut marker)
                .map_err(|_| BindingError::Pending)?;
            let connection_marker = format!(
                "vdg-{}",
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, marker,)
            );
            let (client, connection) = tokio_postgres::Config::new()
                .user(&bundle.profile.database_identity)
                .dbname(&bundle.profile.database)
                .application_name(&connection_marker)
                .connect_raw(stream, NoTls)
                .await
                .map_err(|_| BindingError::Pending)?;
            // Abort on cancellation during sampling as well as after a successful handoff.
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut session = Self {
                client,
                task,
                sample: SessionSample {
                    bundle_digest: bundle.digest(),
                    pool_generation: bundle.pool_generation,
                    process_id: std::process::id(),
                    socket_fd,
                    socket_inode,
                    #[cfg(target_os = "linux")]
                    socket_cookie,
                    connector_uid,
                    connection_marker,
                    database: bundle.profile.database.clone(),
                    session_user: bundle.profile.database_identity.clone(),
                    backend_pid: 0,
                    backend_started_at_micros: 0,
                },
            };
            let messages = session
                .client
                .simple_query(SESSION_SQL)
                .await
                .map_err(|_| BindingError::Pending)?;
            let [
                tokio_postgres::SimpleQueryMessage::RowDescription(columns),
                tokio_postgres::SimpleQueryMessage::Row(row),
                tokio_postgres::SimpleQueryMessage::CommandComplete(1),
            ] = messages.as_slice()
            else {
                return Err(BindingError::Invalid);
            };
            if columns.len() != 5
                || row.try_get(0).ok().flatten() != Some(bundle.profile.database.as_str())
                || [1, 2].into_iter().any(|i| {
                    row.try_get(i).ok().flatten() != Some(bundle.profile.database_identity.as_str())
                })
            {
                return Err(BindingError::Invalid);
            }
            session.sample.backend_pid = row
                .try_get(3)
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .filter(|pid| *pid > 0)
                .ok_or(BindingError::Invalid)?;
            session.sample.backend_started_at_micros = row
                .try_get(4)
                .ok()
                .flatten()
                .and_then(|v| v.parse().ok())
                .filter(|v| *v > 0)
                .ok_or(BindingError::Invalid)?;
            Ok(session)
        }

        pub fn client(&self) -> &Client {
            &self.client
        }

        pub fn sample(&self) -> Option<&SessionSample> {
            (!self.client.is_closed() && !self.task.is_finished()).then_some(&self.sample)
        }
    }

    const INSPECT_SESSION_SQL: &str = "SELECT session_user::text, pg_catalog.current_database()::text, a.datname::text, a.usename::text, ((extract(epoch FROM a.backend_start) * 1000000)::bigint), s.ssl FROM pg_catalog.pg_stat_activity AS a LEFT JOIN pg_catalog.pg_stat_ssl AS s ON s.pid = a.pid WHERE a.pid = $1 AND a.application_name = $2 AND a.pid <> pg_catalog.pg_backend_pid()";

    #[derive(Debug, Serialize)]
    pub struct ServerSessionSample {
        bundle_digest: String,
        recovery_user: String,
        backend_pid: u32,
        backend_started_at_micros: i64,
        postgres_ssl: Option<bool>,
    }

    /// Cross-check a live checkout through a separately supplied recovery
    /// connection. PostgreSQL's SSL flag describes the backend's view. It
    /// supplies neither a connector-to-DB peer identity nor an IAM verdict.
    pub async fn inspect_session_from_recovery(
        recovery: &Client,
        expected_recovery_user: &str,
        checkout: &PoolCheckout,
        cancel: &CancellationToken,
    ) -> Result<ServerSessionSample, BindingError> {
        let sample = checkout.session.sample().ok_or(BindingError::Pending)?;
        if expected_recovery_user.is_empty() || expected_recovery_user == sample.session_user {
            return Err(BindingError::Invalid);
        }
        let backend_pid = i32::try_from(sample.backend_pid).map_err(|_| BindingError::Invalid)?;
        let marker = &sample.connection_marker;
        let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[&backend_pid, marker];
        let work = recovery.query_opt(INSPECT_SESSION_SQL, params);
        let row = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(BindingError::Pending),
            result = tokio::time::timeout(Duration::from_secs(5), work) =>
                result.map_err(|_| BindingError::Pending)?
                    .map_err(|_| BindingError::Pending)?.ok_or(BindingError::Pending)?,
        };
        let text = |n| row.try_get::<_, &str>(n).map_err(|_| BindingError::Pending);
        let started_at = row
            .try_get::<_, i64>(4)
            .map_err(|_| BindingError::Pending)?;
        if text(0)? != expected_recovery_user
            || text(1)? != sample.database
            || text(2)? != sample.database
            || text(3)? != sample.session_user
            || started_at != sample.backend_started_at_micros
            || checkout.session.sample().is_none()
        {
            return Err(BindingError::Invalid);
        }
        Ok(ServerSessionSample {
            bundle_digest: sample.bundle_digest.clone(),
            recovery_user: expected_recovery_user.to_owned(),
            backend_pid: sample.backend_pid,
            backend_started_at_micros: started_at,
            postgres_ssl: row.try_get(5).map_err(|_| BindingError::Pending)?,
        })
    }

    type PoolSessions = Vec<Arc<SessionLock<AppSession>>>;

    struct ActivePool {
        bundle: ConnectionBundle,
        sessions: PoolSessions,
        checkout_sequence: u64,
        switched_at: u64,
        previous_generation: Option<u64>,
        connector_access: Option<UnixConnectorAccess>,
    }

    /// Managed pool for the fixed PostgreSQL application connector. Idle old
    /// connections close at switch, while active leases retain their sockets
    /// until returned. Checkout is nonblocking and reports Pending when busy.
    pub struct SessionPool {
        active: Arc<Mutex<ActivePool>>,
    }

    #[derive(Debug, Serialize)]
    struct CheckoutRecord {
        generation: u64,
        sequence: u64,
        switched_at: u64,
        checked_out_at: u64,
        previous_generation: Option<u64>,
    }

    pub struct PoolCheckout {
        session: OwnedMutexGuard<AppSession>,
        record: CheckoutRecord,
        pool: Weak<Mutex<ActivePool>>,
    }

    impl PoolCheckout {
        pub fn client(&self) -> &Client {
            self.session.client()
        }

        pub fn generation(&self) -> u64 {
            self.record.generation
        }

        /// Diagnostic only. A caller must correlate this with independent
        /// observations before it can enter the policy evidence ledger.
        pub fn sample(&self) -> Option<impl Serialize + '_> {
            self.session.sample().map(|sample| (&self.record, sample))
        }

        /// Build a request-bound candidate from a live checkout. The pinned
        /// process selector must still be corroborated by the root observer.
        pub fn cutover_candidate(
            &self,
            intent: &crate::core::runtime_cutover::RuntimeCutoverIntent,
        ) -> Result<crate::core::runtime_cutover::RuntimeCutoverCandidate, BindingError> {
            let pool = self.pool.upgrade().ok_or(BindingError::Pending)?;
            let active = pool.lock().map_err(|_| BindingError::Pending)?;
            self.candidate_for_active_pool(intent, &active)
        }

        fn candidate_for_active_pool(
            &self,
            intent: &crate::core::runtime_cutover::RuntimeCutoverIntent,
            active: &ActivePool,
        ) -> Result<crate::core::runtime_cutover::RuntimeCutoverCandidate, BindingError> {
            use crate::core::runtime_cutover::*;
            let sample = self.session.sample().ok_or(BindingError::Pending)?;
            let selection = intent.selection();
            let context = intent.context();
            let address = &context.address;
            let bundle = &active.bundle;
            if self.record.generation != bundle.pool_generation {
                return Err(BindingError::Pending);
            }
            if self.record.previous_generation != Some(selection.previous_generation)
                || self.record.generation != selection.active_generation
                || sample.bundle_digest != bundle.digest()
                || bundle.witness_scope_digest() != selection.bundle_digest
                || sample.process_id != selection.application.pid
                || sample.socket_inode == 0
                || bundle.change_hash != context.change_hash
                || bundle.profile.policy_revision_hash != context.policy_revision_hash
                || bundle.profile.target_id != address.target_id
                || bundle.profile.grant_id != address.grant_id
                || bundle.profile.subject_id != address.subject_id
                || bundle.profile.database_identity != address.db_identity
                || bundle.profile.database != address.target.engine_binding.database
                || bundle.source != address.source
                || bundle.route_id != address.route.id
                || address.target.native_ref.generation_fingerprint.as_ref()
                    != Some(&bundle.target_generation)
            {
                return Err(BindingError::Invalid);
            }
            Ok(RuntimeCutoverCandidate {
                context: intent.context().clone(),
                bundle_digest: selection.bundle_digest.clone(),
                app: AppSessionLink {
                    process: RuntimeProcessIdentity {
                        pid: sample.process_id,
                        boot_id: selection.application.expected_boot_id.clone(),
                        start_ticks: selection.application.expected_start_ticks,
                        executable_digest: selection.application.expected_executable_digest.clone(),
                    },
                    socket_fd: u32::try_from(sample.socket_fd)
                        .map_err(|_| BindingError::Invalid)?,
                    socket_inode: sample.socket_inode,
                    session: PostgresSessionIdentity {
                        database: sample.database.clone(),
                        session_user: sample.session_user.clone(),
                        backend_pid: sample.backend_pid,
                        backend_started_at_micros: sample.backend_started_at_micros as u64,
                    },
                },
                switch: PoolSwitchLink {
                    previous_generation: selection.previous_generation,
                    active_generation: self.record.generation,
                    checkout_sequence: self.record.sequence,
                    switched_at: self.record.switched_at,
                    checked_out_at: self.record.checked_out_at,
                },
            })
        }

        /// Measure the live checkout owned by this pool and sign its statement.
        /// The trusted process owning this pool supplies the registered signer.
        /// Collector admission still checks the independently measured peer.
        #[cfg(target_os = "linux")]
        pub fn sign_pool_witness(
            &self,
            intent: &crate::core::runtime_cutover::RuntimeCutoverIntent,
            signer: &crate::adapters::source::runtime_witness::RuntimeWitnessSigner,
            cancel: &CancellationToken,
        ) -> Result<
            (
                crate::core::runtime_cutover::RuntimeCutoverCandidate,
                crate::adapters::source::runtime_witness::SignedStatement,
            ),
            BindingError,
        > {
            use crate::core::{evidence::DEFAULT_FRESHNESS_SECONDS, runtime_cutover::*};
            let pool = self.pool.upgrade().ok_or(BindingError::Pending)?;
            // Hash the executable outside the pool lock. A process cannot
            // continue this call across exec, and the socket is checked below.
            let process = linux_self_identity(cancel)?;
            let active = pool.lock().map_err(|_| BindingError::Pending)?;
            let candidate = self.candidate_for_active_pool(intent, &active)?;
            let access = active.connector_access.ok_or(BindingError::Unsupported)?;
            let sample = self.session.sample().ok_or(BindingError::Pending)?;
            let fd = sample.socket_fd;
            let cookie = u64::from_ne_bytes(linux_socket_option::<8>(fd, libc::SO_COOKIE)?);
            // Linux SO_PEERCRED returns struct ucred: pid, uid and gid as
            // three native-endian 32-bit values.
            let [p0, p1, p2, p3, u0, u1, u2, u3, ..] =
                linux_socket_option::<12>(fd, libc::SO_PEERCRED)?;
            let peer_pid = i32::from_ne_bytes([p0, p1, p2, p3]);
            let peer_uid = u32::from_ne_bytes([u0, u1, u2, u3]);
            let effective_uid = unsafe { libc::geteuid() };
            if process != candidate.app.process
                || effective_uid == access.peer_uid
                || peer_uid != access.peer_uid
                || peer_uid != sample.connector_uid
                || u32::try_from(peer_pid).ok() != Some(intent.selection().connector.pid)
                || Some(cookie) != sample.socket_cookie
                || live_socket_inode(fd)? != candidate.app.socket_inode
                || self.session.sample().is_none()
            {
                return Err(BindingError::Invalid);
            }
            let observed_at = crate::domain::now();
            let valid_until = intent.expires_at().min(
                candidate
                    .switch
                    .checked_out_at
                    .saturating_add(DEFAULT_FRESHNESS_SECONDS),
            );
            if cancel.is_cancelled()
                || candidate.switch.switched_at <= intent.not_before()
                || candidate.switch.checked_out_at < intent.issued_at()
                || candidate.switch.checked_out_at > observed_at
                || observed_at >= valid_until
            {
                return Err(BindingError::Pending);
            }
            let statement = signer
                .sign_pool(
                    intent.context(),
                    observed_at,
                    valid_until,
                    &NativePoolUseObservation {
                        application: UnixProcessEndpoint {
                            process,
                            effective_uid,
                            socket_fd: candidate.app.socket_fd,
                            socket_inode: candidate.app.socket_inode,
                            socket_cookie: cookie,
                        },
                        bundle_digest: candidate.bundle_digest.clone(),
                        switch: candidate.switch.clone(),
                    },
                )
                .map_err(|_| BindingError::Invalid)?;
            drop(active);
            Ok((candidate, statement))
        }
    }

    fn live_socket_inode(fd: i32) -> Result<u64, BindingError> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(BindingError::Pending);
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_ino == 0 {
            return Err(BindingError::Invalid);
        }
        Ok(stat.st_ino)
    }

    #[cfg(target_os = "linux")]
    fn linux_socket_option<const N: usize>(fd: i32, option: i32) -> Result<[u8; N], BindingError> {
        let mut value = [0; N];
        let expected_len = N as libc::socklen_t;
        let mut len = expected_len;
        // SAFETY: both output buffers are initialized and valid through the call.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                value.as_mut_ptr().cast(),
                &mut len,
            )
        } != 0
            || len != expected_len
        {
            return Err(BindingError::Pending);
        }
        Ok(value)
    }

    #[cfg(target_os = "linux")]
    fn linux_self_identity(
        cancel: &CancellationToken,
    ) -> Result<crate::core::runtime_cutover::RuntimeProcessIdentity, BindingError> {
        use sha2::{Digest, Sha256};
        use std::{fs::File, io::Read};
        let read_text = |path, limit| -> Result<String, BindingError> {
            let mut value = String::new();
            File::open(path)
                .and_then(|file| file.take(limit).read_to_string(&mut value))
                .map_err(|_| BindingError::Pending)?;
            if value.is_empty() || value.len() as u64 >= limit {
                return Err(BindingError::Invalid);
            }
            Ok(value)
        };
        let pid = std::process::id();
        let boot_id = read_text("/proc/sys/kernel/random/boot_id", 64)?
            .trim()
            .to_owned();
        let stat = read_text("/proc/self/stat", 4096)?;
        let (process, fields) = stat.rsplit_once(')').ok_or(BindingError::Invalid)?;
        if process
            .split_once('(')
            .and_then(|(id, _)| id.trim().parse::<u32>().ok())
            != Some(pid)
        {
            return Err(BindingError::Invalid);
        }
        let start_ticks = fields
            .split_whitespace()
            .nth(19)
            .and_then(|field| field.parse::<u64>().ok())
            .filter(|ticks| *ticks != 0)
            .ok_or(BindingError::Invalid)?;
        let mut executable = File::open("/proc/self/exe").map_err(|_| BindingError::Pending)?;
        let mut hash = Sha256::new();
        let mut bytes = [0u8; 16 * 1024];
        let mut total = 0;
        loop {
            if cancel.is_cancelled() {
                return Err(BindingError::Pending);
            }
            let read = executable
                .read(&mut bytes)
                .map_err(|_| BindingError::Pending)?;
            if read == 0 {
                break;
            }
            total += read;
            if total > 128 * 1024 * 1024 {
                return Err(BindingError::Invalid);
            }
            hash.update(&bytes[..read]);
        }
        if total == 0 {
            return Err(BindingError::Invalid);
        }
        Ok(crate::core::runtime_cutover::RuntimeProcessIdentity {
            pid,
            boot_id,
            start_ticks,
            executable_digest: format!("{:x}", hash.finalize()),
        })
    }

    async fn open_pool(
        bundle: &ConnectionBundle,
        directory: &Path,
        capacity: usize,
        connector_access: Option<UnixConnectorAccess>,
        cancel: &CancellationToken,
    ) -> Result<PoolSessions, BindingError> {
        if !(1..=16).contains(&capacity) {
            return Err(BindingError::Invalid);
        }
        let work = async {
            let mut sessions = Vec::with_capacity(capacity);
            for _ in 0..capacity {
                let session =
                    AppSession::connect_with_access(bundle, directory, connector_access, cancel)
                        .await?;
                sessions.push(Arc::new(SessionLock::new(session)));
            }
            Ok(sessions)
        };
        tokio::time::timeout(Duration::from_secs(30), work)
            .await
            .map_err(|_| BindingError::Pending)?
    }

    impl SessionPool {
        pub async fn open(
            bundle: ConnectionBundle,
            directory: &Path,
            capacity: usize,
            cancel: &CancellationToken,
        ) -> Result<Self, BindingError> {
            Self::open_with_access(bundle, directory, capacity, None, cancel).await
        }

        pub async fn open_with_connector_access(
            bundle: ConnectionBundle,
            directory: &Path,
            capacity: usize,
            connector_access: UnixConnectorAccess,
            cancel: &CancellationToken,
        ) -> Result<Self, BindingError> {
            Self::open_with_access(bundle, directory, capacity, Some(connector_access), cancel)
                .await
        }

        async fn open_with_access(
            bundle: ConnectionBundle,
            directory: &Path,
            capacity: usize,
            connector_access: Option<UnixConnectorAccess>,
            cancel: &CancellationToken,
        ) -> Result<Self, BindingError> {
            let sessions =
                open_pool(&bundle, directory, capacity, connector_access, cancel).await?;
            if cancel.is_cancelled() {
                return Err(BindingError::Pending);
            }
            Ok(Self {
                active: Arc::new(Mutex::new(ActivePool {
                    bundle,
                    sessions,
                    checkout_sequence: 0,
                    switched_at: crate::domain::now(),
                    previous_generation: None,
                    connector_access,
                })),
            })
        }

        /// A replacement must belong to the same immutable scope. Concurrent
        /// rotations compare the original generation again after opening.
        pub async fn switch(
            &self,
            expected_generation: u64,
            bundle: ConnectionBundle,
            directory: &Path,
            cancel: &CancellationToken,
        ) -> Result<(), BindingError> {
            let (capacity, connector_access) = {
                let active = self.active.lock().map_err(|_| BindingError::Pending)?;
                if active.bundle.pool_generation != expected_generation
                    || bundle.pool_generation <= expected_generation
                {
                    return Err(BindingError::Pending);
                }
                let mut expected = active.bundle.clone();
                expected.pool_generation = bundle.pool_generation;
                if expected != bundle {
                    return Err(BindingError::Invalid);
                }
                (active.sessions.len(), active.connector_access)
            };
            let sessions =
                open_pool(&bundle, directory, capacity, connector_access, cancel).await?;
            let mut active = self.active.lock().map_err(|_| BindingError::Pending)?;
            if cancel.is_cancelled() || active.bundle.pool_generation != expected_generation {
                return Err(BindingError::Pending);
            }
            let retired = std::mem::replace(&mut active.sessions, sessions);
            active.bundle = bundle;
            active.switched_at = crate::domain::now();
            active.previous_generation = Some(expected_generation);
            drop(active);
            drop(retired);
            Ok(())
        }

        pub fn checkout(&self) -> Result<PoolCheckout, BindingError> {
            let mut active = self.active.lock().map_err(|_| BindingError::Pending)?;
            let session = active
                .sessions
                .iter()
                .find_map(|session| {
                    let guard = Arc::clone(session).try_lock_owned().ok()?;
                    guard.sample()?;
                    Some(guard)
                })
                .ok_or(BindingError::Pending)?;
            active.checkout_sequence = active
                .checkout_sequence
                .checked_add(1)
                .ok_or(BindingError::Pending)?;
            Ok(PoolCheckout {
                session,
                pool: Arc::downgrade(&self.active),
                record: CheckoutRecord {
                    generation: active.bundle.pool_generation,
                    sequence: active.checkout_sequence,
                    switched_at: active.switched_at,
                    checked_out_at: crate::domain::now(),
                    previous_generation: active.previous_generation,
                },
            })
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    #[test]
    fn linux_witness_reads_the_held_socket_identity() {
        use std::os::fd::AsRawFd;
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let cookie =
            |fd| u64::from_ne_bytes(linux_socket_option::<8>(fd, libc::SO_COOKIE).unwrap());
        assert_ne!(cookie(socket.as_raw_fd()), 0);
        assert_ne!(cookie(socket.as_raw_fd()), cookie(peer.as_raw_fd()));
        assert_ne!(
            live_socket_inode(socket.as_raw_fd()).unwrap(),
            live_socket_inode(peer.as_raw_fd()).unwrap()
        );
        assert!(linux_socket_option::<8>(-1, libc::SO_COOKIE).is_err());
        let process = linux_self_identity(&CancellationToken::new()).unwrap();
        assert_eq!(process.pid, std::process::id());
        assert!(process.start_ticks > 0);
        assert!(valid_hash(&process.executable_digest));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_app_checkout_worker() {
        use crate::{
            adapters::source::runtime_witness::{
                RuntimeWitnessPolicy, RuntimeWitnessRole, RuntimeWitnessSigner,
            },
            core::{
                admission::IssuedObservation,
                runtime_binding::RuntimeProcessSelector,
                runtime_cutover::{RuntimeCutoverIntent, RuntimeCutoverSelection},
            },
        };
        use base64::{Engine, engine::general_purpose::STANDARD};
        use serde::Deserialize;
        use std::{
            io::{BufRead, Write},
            path::PathBuf,
        };

        if std::env::var_os("VDG_K11_APP_WORKER").as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OpenPool {
            change: PreparedChange,
            grant_id: String,
            source_id: String,
            route_id: String,
            previous_generation: u64,
            active_generation: u64,
            old_directory: PathBuf,
            socket_directory: PathBuf,
            connector_uid: u32,
            connector_gid: u32,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SignCheckout {
            issued: IssuedObservation,
            case_id: String,
            not_before: u64,
            policy: RuntimeWitnessPolicy,
            pool_pkcs8_base64: String,
            application: RuntimeProcessSelector,
            connector: RuntimeProcessSelector,
        }

        fn receive<T: serde::de::DeserializeOwned>(reader: &mut impl BufRead) -> T {
            let mut line = String::new();
            assert!(
                reader.read_line(&mut line).unwrap() > 0,
                "worker input closed"
            );
            // Avoid echoing a fixture that may carry the private signing key.
            serde_json::from_str(&line)
                .ok()
                .expect("invalid worker input")
        }

        fn emit(value: serde_json::Value) {
            let mut output = std::io::stdout().lock();
            writeln!(output, "VDG_K11_APP {value}").unwrap();
            output.flush().unwrap();
        }

        let mut input = std::io::stdin().lock();
        let second_free_fd = (3..1024)
            .filter(|&fd| {
                let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
                result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
            })
            .nth(1)
            .expect("two available worker fds") as u32;
        emit(serde_json::json!({ "fd": second_free_fd }));
        let open: OpenPool = receive(&mut input);
        let sign: SignCheckout = receive(&mut input);
        drop(input);

        let prepare = |generation| {
            ConnectionBundle::prepare(
                &open.change,
                &open.grant_id,
                &open.source_id,
                &open.route_id,
                generation,
            )
            .unwrap()
        };
        let old_bundle = prepare(open.previous_generation);
        let active_bundle = prepare(open.active_generation);
        let case = sign
            .issued
            .request
            .cases
            .iter()
            .find(|case| case.id == sign.case_id)
            .unwrap();
        let intent = RuntimeCutoverIntent::for_case(
            &sign.issued,
            case,
            RuntimeCutoverSelection {
                bundle_digest: sign.policy.bundle_digest.clone(),
                previous_generation: sign.policy.previous_generation,
                active_generation: sign.policy.active_generation,
                application: sign.application,
                connector: sign.connector,
                cloud_iam_principal: sign
                    .issued
                    .snapshot
                    .gce()
                    .unwrap()
                    .native_identity
                    .service_account
                    .clone(),
                credential_binding_digest: sign.policy.credential_binding_digest.clone(),
            },
            sign.not_before,
        )
        .unwrap();
        let signer = RuntimeWitnessSigner::from_pkcs8(
            &STANDARD
                .decode(sign.pool_pkcs8_base64)
                .ok()
                .expect("invalid fixture key"),
            &sign.policy,
            RuntimeWitnessRole::Pool,
        )
        .unwrap();
        let cancel = CancellationToken::new();
        let pool = SessionPool::open_with_connector_access(
            old_bundle,
            &open.old_directory,
            1,
            UnixConnectorAccess {
                peer_uid: open.connector_uid,
                socket_gid: open.connector_gid,
            },
            &cancel,
        )
        .await
        .unwrap();
        pool.switch(
            open.previous_generation,
            active_bundle,
            &open.socket_directory,
            &cancel,
        )
        .await
        .unwrap();
        let checkout = pool.checkout().unwrap();
        let (candidate, statement) = checkout
            .sign_pool_witness(&intent, &signer, &cancel)
            .unwrap();
        assert_eq!(candidate.app.socket_fd, second_free_fd);
        emit(serde_json::json!({ "candidate": candidate, "pool": statement }));

        tokio::task::spawn_blocking(|| {
            let mut release = String::new();
            std::io::stdin().read_line(&mut release).unwrap();
        })
        .await
        .unwrap();
        drop(checkout);
    }

    fn bundle() -> ConnectionBundle {
        let change = crate::core::source_execution::tests::change();
        ConnectionBundle::prepare(
            &change,
            "billing-access",
            "billing-runtime",
            "app-connector",
            2,
        )
        .unwrap()
    }

    fn frame(tag: u8, bytes: &[u8], output: &mut Vec<u8>) {
        output.push(tag);
        output.extend(((bytes.len() + 4) as u32).to_be_bytes());
        output.extend(bytes);
    }

    fn serve_session(
        listener: tokio::net::UnixListener,
        bundle: &ConnectionBundle,
        correct_user: bool,
    ) -> tokio::task::JoinHandle<()> {
        let user = bundle.profile.database_identity.clone();
        let db = bundle.profile.database.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let len = stream.read_u32().await.unwrap();
            let mut startup = vec![0; len as usize - 4];
            stream.read_exact(&mut startup).await.unwrap();
            assert!(startup.windows(user.len()).any(|v| v == user.as_bytes()));
            let mut output = vec![];
            frame(b'R', &0u32.to_be_bytes(), &mut output);
            frame(b'Z', b"I", &mut output);
            stream.write_all(&output).await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), b'Q');
            let len = stream.read_u32().await.unwrap();
            let mut sql = vec![0; len as usize - 4];
            stream.read_exact(&mut sql).await.unwrap();
            assert!(sql.starts_with(b"SELECT pg_catalog.current_database()"));
            let mut description = 5u16.to_be_bytes().to_vec();
            for _ in 0..5 {
                description.extend(b"value\0");
                description.extend(0u32.to_be_bytes());
                description.extend(0u16.to_be_bytes());
                description.extend(25u32.to_be_bytes());
                description.extend((-1i16).to_be_bytes());
                description.extend((-1i32).to_be_bytes());
                description.extend(0u16.to_be_bytes());
            }
            let mut row = 5u16.to_be_bytes().to_vec();
            for field in [
                db.as_str(),
                if correct_user { &user } else { "foreign" },
                &user,
                "42",
                "1793750400000000",
            ] {
                row.extend((field.len() as u32).to_be_bytes());
                row.extend(field.as_bytes());
            }
            output.clear();
            frame(b'T', &description, &mut output);
            frame(b'D', &row, &mut output);
            frame(b'C', b"SELECT 1\0", &mut output);
            frame(b'Z', b"I", &mut output);
            stream.write_all(&output).await.unwrap();
            let _ = stream.read_u8().await;
        })
    }

    fn private_directory() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    #[tokio::test]
    async fn isolated_connector_access_rejects_an_app_owned_socket() {
        use std::os::unix::fs::MetadataExt;
        let directory = private_directory();
        let _listener =
            tokio::net::UnixListener::bind(directory.path().join(".s.PGSQL.5432")).unwrap();
        let metadata = std::fs::metadata(directory.path()).unwrap();
        for peer_uid in [metadata.uid(), metadata.uid() ^ 1] {
            let result = SessionPool::open_with_connector_access(
                bundle(),
                directory.path(),
                1,
                UnixConnectorAccess {
                    peer_uid,
                    socket_gid: metadata.gid(),
                },
                &CancellationToken::new(),
            )
            .await;
            assert!(matches!(result, Err(BindingError::Invalid)));
        }
    }

    #[tokio::test]
    async fn pool_switch_redirects_new_leases_and_leaves_old_borrowers_alive() {
        let old = bundle();
        let old_dir = private_directory();
        let old_listener =
            tokio::net::UnixListener::bind(old_dir.path().join(".s.PGSQL.5432")).unwrap();
        let old_server = serve_session(old_listener, &old, true);
        let cancel = CancellationToken::new();
        let pool = SessionPool::open(old.clone(), old_dir.path(), 1, &cancel)
            .await
            .unwrap();
        let old_lease = pool.checkout().unwrap();
        assert_eq!(old_lease.generation(), 2);
        assert!(matches!(pool.checkout(), Err(BindingError::Pending)));

        let mut new = old.clone();
        new.pool_generation = 3;
        assert!(
            pool.switch(2, new.clone(), old_dir.path(), &{
                let cancelled = CancellationToken::new();
                cancelled.cancel();
                cancelled
            })
            .await
            .is_err()
        );
        let new_dir = private_directory();
        let new_listener =
            tokio::net::UnixListener::bind(new_dir.path().join(".s.PGSQL.5432")).unwrap();
        let new_server = serve_session(new_listener, &new, true);
        pool.switch(2, new.clone(), new_dir.path(), &cancel)
            .await
            .unwrap();
        let new_lease = pool.checkout().unwrap();
        assert_eq!(new_lease.generation(), 3);
        assert_eq!(old_lease.generation(), 2);
        assert!(old_lease.sample().is_some());
        assert!(!old_server.is_finished());
        let (unrelated_intent, _, _) = crate::core::runtime_cutover::tests::fixture();
        assert!(matches!(
            old_lease.cutover_candidate(&unrelated_intent),
            Err(BindingError::Pending)
        ));
        assert!(matches!(
            new_lease.cutover_candidate(&unrelated_intent),
            Err(BindingError::Invalid)
        ));
        assert!(pool.switch(2, new, new_dir.path(), &cancel).await.is_err());
        drop(old_lease);
        tokio::time::timeout(std::time::Duration::from_secs(2), old_server)
            .await
            .unwrap()
            .unwrap();
        drop(new_lease);
        drop(pool);
        tokio::time::timeout(std::time::Duration::from_secs(2), new_server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn application_driver_samples_the_returned_session_and_rejects_wrong_principal() {
        let bundle = bundle();
        for correct_user in [true, false] {
            let dir = private_directory();
            let listener =
                tokio::net::UnixListener::bind(dir.path().join(".s.PGSQL.5432")).unwrap();
            let server = serve_session(listener, &bundle, correct_user);
            let result = AppSession::connect(&bundle, dir.path(), &CancellationToken::new()).await;
            if correct_user {
                let session = result.unwrap();
                let sample = serde_json::to_value(session.sample().unwrap()).unwrap();
                assert_eq!(sample["backend_pid"], 42);
                assert_eq!(sample["pool_generation"], 2);
                assert_eq!(sample["bundle_digest"], bundle.digest());
                drop(session);
            } else {
                assert!(matches!(result, Err(BindingError::Invalid)));
            }
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn witness_scope_can_be_pinned_before_source_registration() {
        let draft = bundle();
        let mut registered = draft.clone();
        registered.source.revision_digest = "c".repeat(64);
        registered.profile.policy_revision_hash = "d".repeat(64);
        registered.change_hash = "e".repeat(64);
        assert_ne!(draft.digest(), registered.digest());
        assert_eq!(
            draft.witness_scope_digest(),
            registered.witness_scope_digest()
        );

        registered.pool_generation += 1;
        assert_ne!(
            draft.witness_scope_digest(),
            registered.witness_scope_digest()
        );
    }

    #[test]
    fn connection_bundle_rejects_unrelated_route_or_source_and_zero_generation() {
        let change = crate::core::source_execution::tests::change();
        for (source, route, generation) in [
            ("recovery-runtime", "app-connector", 2),
            ("billing-runtime", "recovery-connector", 2),
            ("billing-runtime", "app-connector", 0),
        ] {
            assert!(
                ConnectionBundle::prepare(&change, "billing-access", source, route, generation)
                    .is_err()
            );
        }
        assert_eq!(bundle().digest(), bundle().digest());
    }
}
