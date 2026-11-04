//! One authenticated PostgreSQL connection through the managed Cloud SQL connector.
use crate::adapters::source::gce_host::SourceError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;

/// Material acquired only by the fixed metadata and SQL Admin bootstrap.
pub(crate) struct NativeConnectorBootstrap {
    pub(crate) peer: SocketAddr,
    pub(crate) server_name: String,
    pub(crate) server_ca: Vec<CertificateDer<'static>>,
    pub(crate) client_certificate: Vec<CertificateDer<'static>>,
    pub(crate) client_key: PrivateKeyDer<'static>,
    pub(crate) target_generation: String,
    pub(crate) native_iam_principal: String,
    pub(crate) credential_binding_digest: String,
    pub(crate) valid_until: u64,
}

#[cfg(unix)]
pub use unix::{ConnectorWitnessConfig, ConnectorWitnessControl, PreparedConnectorWitness};

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::{
        adapters::source::{
            bootstrap_runtime_connector, recheck_runtime_connector,
            runtime_unix::RuntimeUnixSelection,
            runtime_witness::{RuntimeWitnessPolicy, RuntimeWitnessSigner, SignedStatement},
        },
        core::{
            admission::IssuedObservation,
            evidence::{DEFAULT_FRESHNESS_SECONDS, RequestedCase},
            runtime_binding::RuntimeCaptureContext,
            runtime_cutover::{
                NativePostgresSessionObservation, PostgresSessionIdentity, UnixProcessEndpoint,
            },
        },
    };
    use rustls::pki_types::ServerName;
    use std::{
        os::fd::{AsFd, BorrowedFd},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{TcpStream, UnixListener, UnixStream},
        sync::oneshot,
    };
    use tokio_util::sync::CancellationToken;

    const MAX_STARTUP: usize = 8192;
    const MAX_FRAME: usize = 16 * 1024;
    const MAX_STARTUP_REPLY: usize = 64 * 1024;
    const SESSION_SQL: &str = "SELECT pg_catalog.current_database()::text, session_user::text, current_user::text, pg_catalog.current_setting('server_version_num')::text, pg_catalog.pg_backend_pid()::text, (SELECT ((extract(epoch FROM backend_start) * 1000000)::bigint)::text FROM pg_catalog.pg_stat_activity WHERE pid = pg_catalog.pg_backend_pid())";

    /// This capability stays in the registered connector's control plane. It
    /// requests one fresh socket sample and supplies no observation data.
    pub struct ConnectorWitnessControl {
        request: oneshot::Sender<()>,
        reply: oneshot::Receiver<Result<SignedStatement, SourceError>>,
    }
    impl ConnectorWitnessControl {
        pub async fn observe_after_checkout(self) -> Result<SignedStatement, SourceError> {
            self.request
                .send(())
                .map_err(|_| SourceError::Unavailable)?;
            self.reply.await.map_err(|_| SourceError::Unavailable)?
        }
    }

    pub struct ConnectorWitnessConfig<'a> {
        pub issued: &'a IssuedObservation,
        pub case: &'a RequestedCase,
        pub selection: &'a RuntimeUnixSelection,
        pub policy: &'a RuntimeWitnessPolicy,
        pub signer: &'a RuntimeWitnessSigner,
        pub rsa_key_pkcs8: &'a [u8],
    }

    pub struct PreparedConnectorWitness<'a> {
        issued: &'a IssuedObservation,
        case: &'a RequestedCase,
        context: RuntimeCaptureContext,
        material: NativeConnectorBootstrap,
        selection: &'a RuntimeUnixSelection,
        policy: &'a RuntimeWitnessPolicy,
        signer: &'a RuntimeWitnessSigner,
        expires_at: u64,
        request: oneshot::Receiver<()>,
        reply: oneshot::Sender<Result<SignedStatement, SourceError>>,
    }

    impl<'a> ConnectorWitnessConfig<'a> {
        /// Fetch short-lived mTLS material before the app starts its connection.
        pub async fn prepare(
            self,
            cancel: &CancellationToken,
        ) -> Result<(PreparedConnectorWitness<'a>, ConnectorWitnessControl), SourceError> {
            if !cfg!(target_os = "linux") {
                return Err(SourceError::Unsupported);
            }
            let context = RuntimeCaptureContext::for_case(self.issued, self.case)
                .map_err(|_| SourceError::Invalid)?;
            self.selection.validate()?;
            if self.selection.app.expected_uid == self.selection.connector.expected_uid
                || self.selection.connector.expected_uid != self.selection.path_uid
                || self.selection.connector.selector.pid != std::process::id()
                || self.selection.connector.expected_uid != unsafe { libc::geteuid() }
            {
                return Err(SourceError::ContextUnverified);
            }
            let expires_at = self.issued.request.expires_at;
            let seconds = expires_at.saturating_sub(crate::domain::now()).min(45);
            if seconds == 0 {
                return Err(SourceError::RequestExpired);
            }
            let material = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(SourceError::Cancelled),
                result = tokio::time::timeout(Duration::from_secs(seconds),
                    bootstrap_runtime_connector(self.issued, self.case, self.rsa_key_pkcs8, cancel)) =>
                    result.map_err(|_| SourceError::TimedOut)??,
            };
            if material.credential_binding_digest != self.policy.credential_binding_digest
                || Some(material.target_generation.as_str())
                    != context
                        .address
                        .target
                        .native_ref
                        .generation_fingerprint
                        .as_deref()
                || material.valid_until <= crate::domain::now()
                || material.peer.port() != 3307
            {
                return Err(SourceError::ContextUnverified);
            }
            let (request_tx, request) = oneshot::channel();
            let (reply, reply_rx) = oneshot::channel();
            Ok((
                PreparedConnectorWitness {
                    issued: self.issued,
                    case: self.case,
                    context,
                    material,
                    selection: self.selection,
                    policy: self.policy,
                    signer: self.signer,
                    expires_at,
                    request,
                    reply,
                },
                ConnectorWitnessControl {
                    request: request_tx,
                    reply: reply_rx,
                },
            ))
        }
    }

    impl PreparedConnectorWitness<'_> {
        /// Serve one connection from the selected application. It receives
        /// the upstream startup frames unchanged after the fixed identity query.
        pub async fn serve_once(
            self,
            listener: &UnixListener,
            cancel: &CancellationToken,
        ) -> Result<(), SourceError> {
            self.check_listener(listener)?;
            let accept = async {
                listener
                    .accept()
                    .await
                    .map(|(stream, _)| stream)
                    .map_err(|_| SourceError::Unavailable)
            };
            let recheck = recheck_runtime_connector(self.issued, self.case, cancel);
            self.serve_connection(accept, endpoint, recheck, cancel)
                .await
        }

        async fn serve_connection(
            mut self,
            accept: impl Future<Output = Result<UnixStream, SourceError>>,
            sample: impl Fn(
                BorrowedFd<'_>,
                &RuntimeUnixSelection,
                &CancellationToken,
            ) -> Result<UnixProcessEndpoint, SourceError>,
            recheck: impl Future<Output = Result<(), SourceError>>,
            cancel: &CancellationToken,
        ) -> Result<(), SourceError> {
            let deadline = self.expires_at.min(self.material.valid_until);
            let setup_seconds = deadline.saturating_sub(crate::domain::now()).min(10);
            if setup_seconds == 0 {
                return Err(SourceError::RequestExpired);
            }
            let setup = async {
                let mut local = accept.await?;
                self.check_peer(&local)?;
                let selected = sample(local.as_fd(), self.selection, cancel)?;
                let start = startup_request(
                    &mut local,
                    &self.context.address.target.engine_binding.database,
                    &self.context.address.db_identity,
                )
                .await?;
                let (tls, certificate_signed) = tls_config(&self.material)?;
                let dns_name = ServerName::try_from(self.material.server_name.clone())
                    .map_err(|_| SourceError::Invalid)?;
                if !matches!(dns_name, ServerName::DnsName(_)) {
                    return Err(SourceError::Unsupported);
                }
                let tcp = TcpStream::connect(self.material.peer)
                    .await
                    .map_err(|_| SourceError::Unavailable)?;
                let mut upstream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                    .connect(dns_name, tcp)
                    .await
                    .map_err(|_| SourceError::IdentityUnverified)?;
                let tls_session = upstream.get_ref().1;
                if tls_session.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
                    || !matches!(
                        tls_session.handshake_kind(),
                        Some(
                            rustls::HandshakeKind::Full
                                | rustls::HandshakeKind::FullWithHelloRetryRequest
                        )
                    )
                    || !certificate_signed.load(Ordering::Acquire)
                {
                    return Err(SourceError::IdentityUnverified);
                }
                let certificate = tls_session
                    .peer_certificates()
                    .and_then(|certs| certs.first())
                    .ok_or(SourceError::IdentityUnverified)?;
                let certificate_digest = crate::config::hash_bytes(certificate.as_ref());
                upstream
                    .write_all(&start)
                    .await
                    .map_err(|_| SourceError::Unavailable)?;
                let (startup, backend_pid) = startup_reply(&mut upstream).await?;
                let session = inspect_startup_session(
                    &mut upstream,
                    backend_pid,
                    &self.context.address.target.engine_binding.database,
                    &self.context.address.db_identity,
                )
                .await?;
                recheck.await?;
                local
                    .write_all(&startup)
                    .await
                    .map_err(|_| SourceError::Unavailable)?;
                Ok::<_, SourceError>((local, upstream, selected, session, certificate_digest))
            };
            let (mut local, mut upstream, selected, session, certificate_digest) = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(SourceError::Cancelled),
                result = tokio::time::timeout(Duration::from_secs(setup_seconds), setup) =>
                    result.map_err(|_| SourceError::TimedOut)??,
            };
            let observation = NativePostgresSessionObservation {
                connector: selected,
                current_user: session.session_user.clone(),
                session,
                tls_peer_native_id: self.context.address.target.native_ref.native_id.clone(),
                tls_peer_target_generation: self.material.target_generation,
                tls_peer_certificate_digest: certificate_digest,
                native_iam_principal: self.material.native_iam_principal,
                credential_binding_digest: self.material.credential_binding_digest,
            };
            // The bridge owns both sockets until the copy future ends. Keep the
            // raw descriptors only for non-consuming status reads in that scope.
            use std::os::fd::AsRawFd;
            let local_fd = local.as_raw_fd();
            let tcp_fd = upstream.get_ref().0.as_raw_fd();
            let bridge = tokio::io::copy_bidirectional(&mut local, &mut upstream);
            tokio::pin!(bridge);
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(SourceError::Cancelled),
                result = &mut bridge => return result.map(|_| ()).map_err(|_| SourceError::Unavailable),
                request = &mut self.request => {
                    if request.is_ok() {
                        let result = (|| {
                            // Both descriptors are still owned by the pending bridge.
                            let local = unsafe { BorrowedFd::borrow_raw(local_fd) };
                            let tcp = unsafe { BorrowedFd::borrow_raw(tcp_fd) };
                            if !socket_live(local) || !socket_live(tcp)
                                || sample(local, self.selection, cancel)? != observation.connector
                                || !socket_live(local) || !socket_live(tcp)
                            {
                                return Err(SourceError::ContextUnverified);
                            }
                            let now = crate::domain::now();
                            let valid_until = deadline.min(now.saturating_add(DEFAULT_FRESHNESS_SECONDS / 2));
                            if now <= self.policy.not_before || now >= valid_until {
                                return Err(SourceError::RequestExpired);
                            }
                            self.signer.sign_connector(&self.context, now, valid_until, &observation)
                        })();
                        let _ = self.reply.send(result);
                    }
                }
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(SourceError::Cancelled),
                result = &mut bridge => result.map(|_| ()).map_err(|_| SourceError::Unavailable),
            }
        }

        fn check_listener(&self, listener: &UnixListener) -> Result<(), SourceError> {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let addr = listener
                .local_addr()
                .map_err(|_| SourceError::Unavailable)?;
            let path = std::path::Path::new(&self.selection.socket_path);
            let meta = std::fs::symlink_metadata(path).map_err(|_| SourceError::Unavailable)?;
            if addr.as_pathname() != Some(path)
                || !meta.file_type().is_socket()
                || meta.uid() != self.selection.path_uid
                || meta.gid() != self.selection.path_gid
                || meta.mode() & 0o777 != u32::from(self.selection.path_mode)
            {
                return Err(SourceError::ContextUnverified);
            }
            Ok(())
        }

        fn check_peer(&self, stream: &UnixStream) -> Result<(), SourceError> {
            let peer = stream
                .peer_cred()
                .map_err(|_| SourceError::ContextUnverified)?;
            if peer.uid() != self.selection.app.expected_uid
                || peer.pid().and_then(|pid| u32::try_from(pid).ok())
                    != Some(self.selection.app.selector.pid)
            {
                return Err(SourceError::ContextUnverified);
            }
            Ok(())
        }
    }

    fn endpoint(
        fd: BorrowedFd<'_>,
        selection: &RuntimeUnixSelection,
        cancel: &CancellationToken,
    ) -> Result<UnixProcessEndpoint, SourceError> {
        #[cfg(target_os = "linux")]
        return crate::adapters::source::runtime_unix::sample_connector_endpoint(
            fd,
            &selection.connector,
            cancel,
        );
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (fd, selection, cancel);
            Err(SourceError::Unsupported)
        }
    }

    fn socket_live(fd: BorrowedFd<'_>) -> bool {
        use std::os::fd::AsRawFd;
        #[cfg(target_os = "linux")]
        {
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLRDHUP,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 0) } < 0
                || poll.revents & (libc::POLLRDHUP | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                    != 0
            {
                return false;
            }
        }
        // Read readiness without consuming either side's protocol bytes.
        let mut byte = 0u8;
        let result = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        result > 0
            || (result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock)
    }

    fn tls_config(
        material: &NativeConnectorBootstrap,
    ) -> Result<(rustls::ClientConfig, Arc<AtomicBool>), SourceError> {
        let mut roots = rustls::RootCertStore::empty();
        if material.server_ca.is_empty() || material.client_certificate.is_empty() {
            return Err(SourceError::IdentityUnverified);
        }
        for cert in &material.server_ca {
            roots
                .add(cert.clone())
                .map_err(|_| SourceError::IdentityUnverified)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cert = rustls::sign::CertifiedKey::from_der(
            material.client_certificate.clone(),
            material.client_key.clone_key(),
            &provider,
        )
        .map_err(|_| SourceError::IdentityUnverified)?;
        cert.keys_match()
            .map_err(|_| SourceError::IdentityUnverified)?;
        let signed = Arc::new(AtomicBool::new(false));
        cert.key = Arc::new(ObservedSigningKey {
            inner: cert.key,
            signed: signed.clone(),
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| SourceError::Unsupported)?
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(cert)));
        tls.resumption = rustls::client::Resumption::disabled();
        Ok((tls, signed))
    }

    struct ObservedSigningKey {
        inner: Arc<dyn rustls::sign::SigningKey>,
        signed: Arc<AtomicBool>,
    }

    impl std::fmt::Debug for ObservedSigningKey {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("ObservedSigningKey")
        }
    }

    impl rustls::sign::SigningKey for ObservedSigningKey {
        fn choose_scheme(
            &self,
            offered: &[rustls::SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            Some(Box::new(ObservedSigner {
                inner: self.inner.choose_scheme(offered)?,
                signed: self.signed.clone(),
            }))
        }

        fn algorithm(&self) -> rustls::SignatureAlgorithm {
            self.inner.algorithm()
        }
    }

    struct ObservedSigner {
        inner: Box<dyn rustls::sign::Signer>,
        signed: Arc<AtomicBool>,
    }

    impl std::fmt::Debug for ObservedSigner {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("ObservedSigner")
        }
    }

    impl rustls::sign::Signer for ObservedSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            let signature = self.inner.sign(message)?;
            self.signed.store(true, Ordering::Release);
            Ok(signature)
        }

        fn scheme(&self) -> rustls::SignatureScheme {
            self.inner.scheme()
        }
    }

    async fn startup_request(
        stream: &mut (impl AsyncRead + Unpin),
        database: &str,
        user: &str,
    ) -> Result<Vec<u8>, SourceError> {
        let len = stream
            .read_u32()
            .await
            .map_err(|_| SourceError::Unavailable)? as usize;
        if !(9..=MAX_STARTUP).contains(&len) {
            return Err(SourceError::Invalid);
        }
        let mut message = vec![0; len];
        message[..4].copy_from_slice(&(len as u32).to_be_bytes());
        stream
            .read_exact(&mut message[4..])
            .await
            .map_err(|_| SourceError::Unavailable)?;
        if message[4..8] != 196_608u32.to_be_bytes() || !message.ends_with(&[0, 0]) {
            return Err(SourceError::Unsupported);
        }
        let fields = std::str::from_utf8(&message[8..len - 1]).map_err(|_| SourceError::Invalid)?;
        let mut fields = fields.split_terminator('\0');
        let mut seen = std::collections::BTreeSet::new();
        while let Some(key) = fields.next() {
            let value = fields.next().ok_or(SourceError::Invalid)?;
            if !seen.insert(key)
                || !match key {
                    "user" => value == user,
                    "database" => value == database,
                    "client_encoding" => value == "UTF8",
                    "application_name" => {
                        !value.is_empty()
                            && value.len() <= 63
                            && !value.chars().any(char::is_control)
                    }
                    _ => false,
                }
            {
                return Err(SourceError::Invalid);
            }
        }
        if !seen.contains("user") || !seen.contains("database") {
            return Err(SourceError::Invalid);
        }
        Ok(message)
    }

    async fn frame(stream: &mut (impl AsyncRead + Unpin)) -> Result<(u8, Vec<u8>), SourceError> {
        let tag = stream
            .read_u8()
            .await
            .map_err(|_| SourceError::Unavailable)?;
        let len = stream
            .read_u32()
            .await
            .map_err(|_| SourceError::Unavailable)? as usize;
        if !(4..=MAX_FRAME).contains(&len) {
            return Err(SourceError::Limit);
        }
        let mut body = vec![0; len - 4];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        Ok((tag, body))
    }

    fn append_frame(output: &mut Vec<u8>, tag: u8, body: &[u8]) {
        output.push(tag);
        output.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        output.extend_from_slice(body);
    }

    async fn startup_reply(
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<(Vec<u8>, u32), SourceError> {
        let mut output = Vec::new();
        let mut authenticated = false;
        let mut pid = None;
        loop {
            let (tag, body) = frame(stream).await?;
            if output.len() + 5 + body.len() > MAX_STARTUP_REPLY {
                return Err(SourceError::Limit);
            }
            append_frame(&mut output, tag, &body);
            match tag {
                b'R' if !authenticated && body == [0; 4] => authenticated = true,
                b'S' | b'N' if authenticated => (),
                b'K' if authenticated && pid.is_none() && body.len() == 8 => {
                    pid = Some(u32::from_be_bytes(
                        body[..4].try_into().map_err(|_| SourceError::Invalid)?,
                    ));
                }
                b'Z' if authenticated && body == b"I" => {
                    return Ok((
                        output,
                        pid.filter(|pid| *pid != 0 && *pid <= i32::MAX as u32)
                            .ok_or(SourceError::IdentityUnverified)?,
                    ));
                }
                _ => return Err(SourceError::IdentityUnverified),
            }
        }
    }

    async fn inspect_startup_session(
        stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
        backend_pid: u32,
        database: &str,
        user: &str,
    ) -> Result<PostgresSessionIdentity, SourceError> {
        let mut sql = SESSION_SQL.as_bytes().to_vec();
        sql.push(0);
        let mut query = Vec::new();
        append_frame(&mut query, b'Q', &sql);
        stream
            .write_all(&query)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        let (tag, description) = frame(stream).await?;
        if tag != b'T' || !description.starts_with(&[0, 6]) {
            return Err(SourceError::IdentityUnverified);
        }
        let (tag, values) = frame(stream).await?;
        if tag != b'D' {
            return Err(SourceError::IdentityUnverified);
        }
        let [db, session_user, current_user, version, pid, started] = row(&values)?;
        if db != database
            || session_user != user
            || current_user != user
            || version != "160015"
            || pid.parse::<u32>().ok() != Some(backend_pid)
        {
            return Err(SourceError::IdentityUnverified);
        }
        let backend_started_at_micros = started
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or(SourceError::IdentityUnverified)?;
        if frame(stream).await? != (b'C', b"SELECT 1\0".to_vec())
            || frame(stream).await? != (b'Z', b"I".to_vec())
        {
            return Err(SourceError::IdentityUnverified);
        }
        Ok(PostgresSessionIdentity {
            database: database.into(),
            session_user: user.into(),
            backend_pid,
            backend_started_at_micros,
        })
    }

    fn row(body: &[u8]) -> Result<[&str; 6], SourceError> {
        let mut body = body.strip_prefix(&[0, 6]).ok_or(SourceError::Invalid)?;
        let mut values = [""; 6];
        for value in &mut values {
            let len = body.get(..4).ok_or(SourceError::Invalid)?;
            let len =
                u32::from_be_bytes(len.try_into().map_err(|_| SourceError::Invalid)?) as usize;
            if !(1..=256).contains(&len) {
                return Err(SourceError::Invalid);
            }
            let bytes = body.get(4..4 + len).ok_or(SourceError::Invalid)?;
            *value = std::str::from_utf8(bytes).map_err(|_| SourceError::Invalid)?;
            body = &body[4 + len..];
        }
        if !body.is_empty() {
            return Err(SourceError::Invalid);
        }
        Ok(values)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rustls::pki_types::pem::PemObject;

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WorkerInput {
            issued: IssuedObservation,
            case_id: String,
            selection: RuntimeUnixSelection,
            policy: RuntimeWitnessPolicy,
            connector_pkcs8_base64: String,
        }

        /// Entry for the Linux separate-process test. No production entry
        /// point can select the loopback bootstrap or omit the cloud recheck.
        #[tokio::test]
        async fn linux_connector_witness_worker() {
            if std::env::var_os("VDG_K11_CONNECTOR_WORKER").as_deref()
                != Some(std::ffi::OsStr::new("1"))
            {
                return;
            }
            use base64::{Engine, engine::general_purpose::STANDARD};
            use std::io::{Read, Write};

            let directory = std::path::PathBuf::from(std::env::var_os("VDG_K11_TEST_DIR").unwrap());
            let old = worker_listener(&directory.join("old"));
            let active = worker_listener(&directory.join("active"));
            let tls_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let upstream_address = tls_listener.local_addr().unwrap();
            // Between this report and the selected accept we open only the old
            // accepted FD. The loopback dial happens after the selected accept.
            let expected_fd = (3..1024)
                .filter(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } == -1)
                .nth(1)
                .expect("two free descriptors for connector worker");
            worker_report(serde_json::json!({"fd": expected_fd}));
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let input: WorkerInput = serde_json::from_str(&input).unwrap();
            let case = input
                .issued
                .request
                .cases
                .iter()
                .find(|case| case.id == input.case_id)
                .unwrap();
            let context = RuntimeCaptureContext::for_case(&input.issued, case).unwrap();
            input.selection.validate().unwrap();
            assert_eq!(input.selection.connector.fd, expected_fd as u32);
            let signer = RuntimeWitnessSigner::from_pkcs8(
                &STANDARD.decode(input.connector_pkcs8_base64).unwrap(),
                &input.policy,
                crate::adapters::source::runtime_witness::RuntimeWitnessRole::Connector,
            )
            .unwrap();
            let cancel = CancellationToken::new();
            let cancel_on_eof = cancel.clone();
            let (request_tx, request) = oneshot::channel();
            let (reply, reply_rx) = oneshot::channel();
            std::thread::spawn(move || {
                let mut line = String::new();
                let mut stdin = std::io::stdin().lock();
                use std::io::BufRead;
                if stdin.read_line(&mut line).is_ok_and(|bytes| bytes != 0)
                    && line.trim().is_empty()
                {
                    let _ = request_tx.send(());
                }
                let mut discard = [0u8; 256];
                while stdin.read(&mut discard).is_ok_and(|bytes| bytes != 0) {}
                cancel_on_eof.cancel();
            });

            let database = case.address.target.engine_binding.database.clone();
            let user = case.address.db_identity.clone();
            let (old_socket, _) = tokio::time::timeout(Duration::from_secs(15), old.accept())
                .await
                .unwrap()
                .unwrap();
            let old_task = tokio::spawn(mock_postgres(
                old_socket,
                database.clone(),
                user.clone(),
                301,
            ));
            let certificate = CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap();
            let private_key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
            let upstream_task = tokio::spawn(async move {
                let (stream, _) = tls_listener.accept().await.unwrap();
                let upstream = fixture_tls_server(certificate, private_key, true)
                    .accept(stream)
                    .await
                    .unwrap();
                mock_postgres(upstream, database, user, 302).await.unwrap();
            });
            let expires_at = input.issued.request.expires_at;
            let witness = PreparedConnectorWitness {
                issued: &input.issued,
                case,
                context,
                material: NativeConnectorBootstrap {
                    peer: upstream_address,
                    server_name: "mysql-test.invalid".into(),
                    server_ca: vec![CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap()],
                    client_certificate: vec![
                        CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap(),
                    ],
                    client_key: PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap(),
                    target_generation: case
                        .address
                        .target
                        .native_ref
                        .generation_fingerprint
                        .clone()
                        .unwrap(),
                    native_iam_principal: input
                        .issued
                        .snapshot
                        .gce()
                        .unwrap()
                        .native_identity
                        .service_account
                        .clone(),
                    credential_binding_digest: input.policy.credential_binding_digest.clone(),
                    valid_until: expires_at,
                },
                selection: &input.selection,
                policy: &input.policy,
                signer: &signer,
                expires_at,
                request,
                reply,
            };
            witness.check_listener(&active).unwrap();
            let accept = async {
                active
                    .accept()
                    .await
                    .map(|(stream, _)| stream)
                    .map_err(|_| SourceError::Unavailable)
            };
            let output = async {
                let statement = reply_rx.await.unwrap().unwrap();
                worker_report(serde_json::json!({"connector": statement}));
                std::io::stdout().flush().unwrap();
            };
            let (serve, ()) = tokio::join!(
                witness.serve_connection(accept, endpoint, std::future::ready(Ok(())), &cancel),
                output,
            );
            assert!(
                matches!(serve, Ok(()) | Err(SourceError::Cancelled)),
                "{serve:?}"
            );
            upstream_task.abort();
            old_task.abort();
        }

        fn worker_report(value: serde_json::Value) {
            use std::io::Write;
            let mut output = std::io::stdout().lock();
            writeln!(output, "VDG_K11_CONNECTOR {value}").unwrap();
            output.flush().unwrap();
        }

        fn worker_listener(directory: &std::path::Path) -> UnixListener {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            std::fs::DirBuilder::new()
                .mode(0o750)
                .create(directory)
                .unwrap();
            let path = directory.join(".s.PGSQL.5432");
            let listener = UnixListener::bind(&path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).unwrap();
            listener
        }

        fn fixture_tls_server(
            certificate: CertificateDer<'static>,
            private_key: PrivateKeyDer<'static>,
            require_client_auth: bool,
        ) -> tokio_rustls::TlsAcceptor {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server = rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap();
            let server = if require_client_auth {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(certificate.clone()).unwrap();
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    provider,
                )
                .build()
                .unwrap();
                server.with_client_cert_verifier(verifier)
            } else {
                server.with_no_client_auth()
            };
            tokio_rustls::TlsAcceptor::from(Arc::new(
                server
                    .with_single_cert(vec![certificate], private_key)
                    .unwrap(),
            ))
        }

        async fn mock_postgres(
            mut stream: impl AsyncRead + AsyncWrite + Unpin,
            database: String,
            user: String,
            backend_pid: u32,
        ) -> Result<(), SourceError> {
            startup_request(&mut stream, &database, &user).await?;
            let started = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SourceError::Invalid)?
                .as_micros()
                .to_string();
            let mut output = Vec::new();
            append_frame(&mut output, b'R', &[0; 4]);
            let mut cancel_key = backend_pid.to_be_bytes().to_vec();
            cancel_key.extend_from_slice(&[0x91, 0x77, 0x65, 0x01]);
            append_frame(&mut output, b'K', &cancel_key);
            append_frame(&mut output, b'Z', b"I");
            stream
                .write_all(&output)
                .await
                .map_err(|_| SourceError::Unavailable)?;
            loop {
                let (tag, query) = match frame(&mut stream).await {
                    Ok(value) => value,
                    Err(SourceError::Unavailable) => return Ok(()),
                    Err(error) => return Err(error),
                };
                if tag == b'X' && query.is_empty() {
                    return Ok(());
                }
                if tag != b'Q' {
                    return Err(SourceError::Invalid);
                }
                let query = query.strip_suffix(&[0]).ok_or(SourceError::Invalid)?;
                let pid = backend_pid.to_string();
                let values = if query == SESSION_SQL.as_bytes() {
                    vec![database.as_str(), &user, &user, "160015", &pid, &started]
                } else if query == b"SELECT pg_catalog.current_database(), session_user, current_user, pg_catalog.pg_backend_pid()::text, (SELECT ((extract(epoch FROM backend_start) * 1000000)::bigint)::text FROM pg_catalog.pg_stat_activity WHERE pid = pg_catalog.pg_backend_pid())" {
                    vec![database.as_str(), &user, &user, &pid, &started]
                } else {
                    return Err(SourceError::Invalid);
                };
                output.clear();
                append_row(&mut output, &values);
                stream
                    .write_all(&output)
                    .await
                    .map_err(|_| SourceError::Unavailable)?;
            }
        }

        fn append_row(output: &mut Vec<u8>, values: &[&str]) {
            let count = (values.len() as u16).to_be_bytes();
            let mut description = count.to_vec();
            for _ in values {
                description.extend_from_slice(b"column\0");
                description.extend_from_slice(&[0; 6]); // table oid, column index
                description.extend_from_slice(&25u32.to_be_bytes()); // text type
                description.extend_from_slice(&(-1i16).to_be_bytes());
                description.extend_from_slice(&(-1i32).to_be_bytes());
                description.extend_from_slice(&[0; 2]); // text format
            }
            append_frame(output, b'T', &description);
            let mut row = count.to_vec();
            for value in values {
                row.extend_from_slice(&(value.len() as u32).to_be_bytes());
                row.extend_from_slice(value.as_bytes());
            }
            append_frame(output, b'D', &row);
            append_frame(output, b'C', b"SELECT 1\0");
            append_frame(output, b'Z', b"I");
        }

        #[tokio::test]
        async fn startup_is_scoped_and_preserved_byte_for_byte() {
            for (database, extra, expected) in [
                ("billing", "application_name\0app-1\0", true),
                ("foreign", "", false),
                ("billing", "options\0-c role=admin\0", false),
                ("billing", "user\0app\0", false),
            ] {
                let mut startup = vec![0; 4];
                startup.extend(196_608u32.to_be_bytes());
                startup.extend(format!("user\0app\0database\0{database}\0{extra}\0").bytes());
                let len = startup.len() as u32;
                startup[..4].copy_from_slice(&len.to_be_bytes());
                let mut stream = startup.as_slice();
                let actual = startup_request(&mut stream, "billing", "app").await;
                if expected {
                    assert_eq!(actual.unwrap(), startup);
                } else {
                    assert!(actual.is_err());
                }
            }
        }

        #[tokio::test]
        async fn same_backend_must_authenticate_and_match_fixed_query_before_replay() {
            for principal in ["app", "foreign"] {
                let (mut connector, mut backend) = tokio::io::duplex(4096);
                let mut expected_startup = Vec::new();
                append_frame(&mut expected_startup, b'R', &[0; 4]);
                append_frame(&mut expected_startup, b'S', b"client_encoding\0UTF8\0");
                append_frame(
                    &mut expected_startup,
                    b'K',
                    &[0, 0, 0, 23, 0x91, 0x77, 0x65, 0x01],
                );
                append_frame(&mut expected_startup, b'Z', b"I");
                let native = async {
                    backend.write_all(&expected_startup).await.unwrap();
                    let (tag, query) = frame(&mut backend).await.unwrap();
                    assert_eq!(tag, b'Q');
                    assert_eq!(query.strip_suffix(&[0]), Some(SESSION_SQL.as_bytes()));
                    let mut response = Vec::new();
                    let mut description = vec![0, 6];
                    for _ in 0..6 {
                        description.extend_from_slice(b"column\0");
                        description.extend_from_slice(&[0; 18]);
                    }
                    append_frame(&mut response, b'T', &description);
                    let mut values = vec![0, 6];
                    for value in [
                        "billing",
                        "app",
                        principal,
                        "160015",
                        "23",
                        "1800000000000000",
                    ] {
                        values.extend_from_slice(&(value.len() as u32).to_be_bytes());
                        values.extend_from_slice(value.as_bytes());
                    }
                    append_frame(&mut response, b'D', &values);
                    append_frame(&mut response, b'C', b"SELECT 1\0");
                    append_frame(&mut response, b'Z', b"I");
                    backend.write_all(&response).await.unwrap();
                };
                let producer = async {
                    let (replay, pid) = startup_reply(&mut connector).await.unwrap();
                    assert_eq!(replay, expected_startup);
                    assert_eq!(pid, 23);
                    inspect_startup_session(&mut connector, pid, "billing", "app").await
                };
                let ((), result) = tokio::join!(native, producer);
                if principal == "app" {
                    assert_eq!(
                        result.unwrap().backend_started_at_micros,
                        1_800_000_000_000_000
                    );
                } else {
                    assert!(matches!(result, Err(SourceError::IdentityUnverified)));
                }
            }
            // An upstream request for a password cannot silently become IAM.
            let mut password_challenge = Vec::new();
            append_frame(&mut password_challenge, b'R', &3u32.to_be_bytes());
            assert!(
                startup_reply(&mut password_challenge.as_slice())
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn tls_connecting_without_client_auth_does_not_mark_key_use() {
            for require_client_auth in [false, true] {
                let certificate = CertificateDer::from_pem_slice(TEST_CERT.as_bytes()).unwrap();
                let private_key = PrivateKeyDer::from_pem_slice(TEST_KEY.as_bytes()).unwrap();
                let material = NativeConnectorBootstrap {
                    peer: "127.0.0.1:3307".parse().unwrap(),
                    server_name: "mysql-test.invalid".into(),
                    server_ca: vec![certificate.clone()],
                    client_certificate: vec![certificate.clone()],
                    client_key: private_key.clone_key(),
                    target_generation: "".into(),
                    native_iam_principal: "".into(),
                    credential_binding_digest: "".into(),
                    valid_until: 0,
                };
                let (client, signed) = tls_config(&material).unwrap();
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let server = rustls::ServerConfig::builder_with_provider(provider.clone())
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap();
                let server = if require_client_auth {
                    let mut roots = rustls::RootCertStore::empty();
                    roots.add(certificate.clone()).unwrap();
                    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                        Arc::new(roots),
                        provider,
                    )
                    .build()
                    .unwrap();
                    server.with_client_cert_verifier(verifier)
                } else {
                    server.with_no_client_auth()
                };
                let server = server
                    .with_single_cert(vec![certificate], private_key)
                    .unwrap();
                let (one, two) = tokio::io::duplex(8192);
                let client = tokio_rustls::TlsConnector::from(Arc::new(client));
                let server = tokio_rustls::TlsAcceptor::from(Arc::new(server));
                let (client, server) = tokio::join!(
                    client.connect(ServerName::try_from("mysql-test.invalid").unwrap(), one),
                    server.accept(two)
                );
                assert!(client.is_ok());
                assert_eq!(
                    server.unwrap().get_ref().1.peer_certificates().is_some(),
                    require_client_auth
                );
                assert_eq!(signed.load(Ordering::Acquire), require_client_auth);
            }
        }

        // Existing synthetic loopback key/certificate from aws_mysql_transport.rs.
        const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBUjCB+KADAgECAgkAt3w4DrTJVIMwCgYIKoZIzj0EAwIwHTEbMBkGA1UEAwwS
bXlzcWwtdGVzdC5pbnZhbGlkMB4XDTI2MTEwMjA5NTkwMVoXDTM2MTAzMDA5NTkw
MVowHTEbMBkGA1UEAwwSbXlzcWwtdGVzdC5pbnZhbGlkMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAECaRTpk3UnK9OYpVW+HBHasjQr3JFFn/qUSBSQqMhZ38/doxV
H6nHZxbNrWfme1WhEoqCWbjGwnHCB4qDh+XF3aMhMB8wHQYDVR0RBBYwFIISbXlz
cWwtdGVzdC5pbnZhbGlkMAoGCCqGSM49BAMCA0kAMEYCIQClQhjF2bRVpnqJa/DT
cqWfvckSYxIN8/4b87ZkRusJpwIhAKK8T4yO2NrND4fO93apDIdx7fpgGbDQrUK9
LThYzxE/
-----END CERTIFICATE-----
";
        const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWnu4VVZnVJpw3zOV
qyjbULNzPqfHo7YXRhJOYaNELkKhRANCAAQJpFOmTdScr05ilVb4cEdqyNCvckUW
f+pRIFJCoyFnfz92jFUfqcdnFs2tZ+Z7VaESioJZuMbCccIHioOH5cXd
-----END PRIVATE KEY-----
";
    }
}
