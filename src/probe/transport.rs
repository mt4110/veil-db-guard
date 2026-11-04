use super::auth::{TokenMode, TokenProvider};
use crate::domain::*;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{
    error::Error,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpStream, lookup_host},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_postgres::{
    Client, Config,
    config::SslMode,
    tls::{MakeTlsConnect, TlsConnect},
};
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub enum TlsMode {
    Verified,
    Disabled,
    UntrustedCa,
    WrongHostname,
}
#[derive(Clone, Debug)]
pub struct ProbeFailure {
    pub reason: ReasonCode,
    pub stages: PathStages,
    pub execution: Execution,
}
impl ProbeFailure {
    pub fn new(reason: ReasonCode, stages: PathStages) -> Self {
        let execution = match reason {
            ReasonCode::Cancelled => Execution::Cancelled,
            ReasonCode::ConnectTimeout | ReasonCode::QueryTimeout => Execution::Timeout,
            _ => Execution::Error,
        };
        Self {
            reason,
            stages,
            execution,
        }
    }
}
pub struct Session {
    pub client: Client,
    pub stages: PathStages,
    pub addresses: Vec<String>,
    driver: JoinHandle<()>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Session {
    pub fn close(self) {
        drop(self);
    }
}

pub async fn bounded<F, T>(
    future: F,
    deadline: Instant,
    cancel: &CancellationToken,
    timeout_reason: ReasonCode,
) -> Result<T, ReasonCode>
where
    F: Future<Output = T>,
{
    if cancel.is_cancelled() {
        return Err(ReasonCode::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(timeout_reason);
    }
    tokio::select! { biased;
        _ = cancel.cancelled() => Err(ReasonCode::Cancelled),
        value = timeout_at(deadline, future) => value.map_err(|_| timeout_reason),
    }
}

pub fn roots(config: &TargetConfig, mode: TlsMode) -> Result<rustls::ClientConfig, ReasonCode> {
    let mut roots = rustls::RootCertStore::empty();
    if !matches!(mode, TlsMode::UntrustedCa) {
        if let Some(path) = &config.tls.ca_file {
            let bytes = crate::config::read_bounded(path, 1_048_576)
                .map_err(|_| ReasonCode::ConfigInvalid)?;
            let certs = CertificateDer::pem_slice_iter(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ReasonCode::ConfigInvalid)?;
            if certs.is_empty() {
                return Err(ReasonCode::ConfigInvalid);
            }
            for certificate in certs {
                roots
                    .add(certificate)
                    .map_err(|_| ReasonCode::ConfigInvalid)?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| ReasonCode::Unknown)
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

pub async fn resolve(
    endpoint: &Endpoint,
    family: AddressFamily,
    local: bool,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Vec<SocketAddr>, ReasonCode> {
    let addresses = bounded(
        lookup_host((endpoint.host.as_str(), endpoint.port)),
        deadline,
        cancel,
        ReasonCode::ConnectTimeout,
    )
    .await?
    .map_err(|_| ReasonCode::NetworkUnreachable)?;
    let addresses: Vec<_> = addresses
        .filter(|address| match family {
            AddressFamily::Ipv4 => address.is_ipv4(),
            AddressFamily::Ipv6 => address.is_ipv6(),
        })
        .collect();
    if addresses.is_empty() || addresses.len() > 32 {
        return Err(ReasonCode::TargetMismatch);
    }
    // Validate the complete chosen family before any socket is opened. Never fall back to a non-loopback address.
    if local && addresses.iter().any(|address| !address.ip().is_loopback()) {
        return Err(ReasonCode::TargetMismatch);
    }
    Ok(addresses)
}

pub async fn tcp_probe(
    endpoint: &Endpoint,
    family: AddressFamily,
    local: bool,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Vec<String>, ProbeFailure> {
    let stages = PathStages::default();
    let addresses = resolve(endpoint, family, local, deadline, cancel)
        .await
        .map_err(|reason| ProbeFailure::new(reason, stages.clone()))?;
    for address in &addresses {
        match bounded(
            TcpStream::connect(address),
            deadline,
            cancel,
            ReasonCode::ConnectTimeout,
        )
        .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                return Ok(addresses.iter().map(ToString::to_string).collect());
            }
            Ok(Err(_)) => continue,
            Err(reason) => return Err(ProbeFailure::new(reason, stages)),
        }
    }
    Err(ProbeFailure::new(
        ReasonCode::NetworkUnreachable,
        PathStages {
            transport_reachable: Stage::ObservedFalse,
            ..stages
        },
    ))
}

pub struct ConnectOptions<'a> {
    pub token_mode: TokenMode,
    pub tls_mode: TlsMode,
    pub user: &'a str,
    pub local: bool,
    pub total_deadline: Instant,
    pub cancel: &'a CancellationToken,
}

pub async fn connect(
    config: &TargetConfig,
    endpoint: &Endpoint,
    path: &PathSpec,
    provider: &dyn TokenProvider,
    options: ConnectOptions<'_>,
) -> Result<Session, ProbeFailure> {
    let ConnectOptions {
        token_mode,
        tls_mode,
        user,
        local,
        total_deadline,
        cancel,
    } = options;
    let deadline = total_deadline
        .min(Instant::now() + Duration::from_millis(config.limits.connect_timeout_ms));
    let mut stages = PathStages::default();
    if local
        && endpoint.host != "localhost"
        && !endpoint
            .host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        return Err(ProbeFailure::new(ReasonCode::TargetMismatch, stages));
    }
    // Acquire/age the token before opening TCP. An expiry trial must use a new connection,
    // rather than leave an unauthenticated socket open for 15 minutes.
    let token_deadline = if token_mode == TokenMode::Expired {
        total_deadline
    } else {
        deadline
    };
    let token = if matches!(tls_mode, TlsMode::Disabled) {
        super::auth::SecretToken::new(String::new())
    } else {
        bounded(
            provider.token(endpoint, user, token_mode),
            token_deadline,
            cancel,
            ReasonCode::ConnectTimeout,
        )
        .await
        .and_then(|v| v)
        .map_err(|r| ProbeFailure::new(r, stages.clone()))?
    };
    let deadline = if token_mode == TokenMode::Expired {
        total_deadline.min(Instant::now() + Duration::from_millis(config.limits.connect_timeout_ms))
    } else {
        deadline
    };
    let addresses = resolve(endpoint, path.address_family, local, deadline, cancel)
        .await
        .map_err(|r| ProbeFailure::new(r, stages.clone()))?;
    let mut socket = None;
    for address in &addresses {
        match bounded(
            TcpStream::connect(address),
            deadline,
            cancel,
            ReasonCode::ConnectTimeout,
        )
        .await
        {
            Ok(Ok(stream)) => {
                socket = Some(stream);
                break;
            }
            Ok(Err(_)) => continue,
            Err(r) => return Err(ProbeFailure::new(r, stages)),
        }
    }
    let socket = socket.ok_or_else(|| {
        ProbeFailure::new(
            ReasonCode::NetworkUnreachable,
            PathStages {
                transport_reachable: Stage::ObservedFalse,
                ..stages.clone()
            },
        )
    })?;
    stages.transport_reachable = Stage::ObservedTrue;
    let mut pg = Config::new();
    pg.user(user).dbname(
        config
            .test_scope
            .as_ref()
            .map(|s| s.database.as_str())
            .unwrap_or("postgres"),
    );
    pg.password(token.expose());
    // Do not put options into the startup packet: RDS Proxy has protocol-specific restrictions.
    let tls_state = Arc::new(AtomicU8::new(0));
    let result = if matches!(tls_mode, TlsMode::Disabled) {
        pg.ssl_mode(SslMode::Disable);
        let result = bounded(
            pg.connect_raw(socket, tokio_postgres::NoTls),
            deadline,
            cancel,
            ReasonCode::ConnectTimeout,
        )
        .await;
        match result {
            Ok(Ok((client, connection))) => Ok((
                client,
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            )),
            Ok(Err(error)) => Err(classify(&error, true)),
            Err(reason) => Err(reason),
        }
    } else {
        pg.ssl_mode(SslMode::Require);
        let tls_config =
            roots(config, tls_mode).map_err(|r| ProbeFailure::new(r, stages.clone()))?;
        let mut maker = MakeRustlsConnect::new(tls_config);
        let hostname = if matches!(tls_mode, TlsMode::WrongHostname) {
            "invalid-hostname.veil-db-guard.invalid"
        } else {
            endpoint.host.as_str()
        };
        let inner = <MakeRustlsConnect as MakeTlsConnect<TcpStream>>::make_tls_connect(
            &mut maker, hostname,
        )
        .map_err(|_| ProbeFailure::new(ReasonCode::Unknown, stages.clone()))?;
        let tls = ObservedTls {
            inner,
            state: tls_state.clone(),
        };
        let result = bounded(
            pg.connect_raw(socket, tls),
            deadline,
            cancel,
            ReasonCode::ConnectTimeout,
        )
        .await;
        match result {
            Ok(Ok((client, connection))) => Ok((
                client,
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            )),
            Ok(Err(error)) => Err(classify(&error, false)),
            Err(reason) => Err(reason),
        }
    };
    stages.tls_established = match tls_state.load(Ordering::Acquire) {
        1 => Stage::ObservedTrue,
        2 => Stage::ObservedFalse,
        _ if matches!(tls_mode, TlsMode::Disabled) => Stage::ObservedFalse,
        _ => Stage::Unknown,
    };
    match result {
        Ok((client, driver)) => {
            stages.db_authenticated = Stage::ObservedTrue;
            let session = Session {
                client,
                stages,
                addresses: addresses.iter().map(ToString::to_string).collect(),
                driver,
            };
            let setting = config.limits.query_timeout_ms.to_string();
            let query_deadline = total_deadline
                .min(Instant::now() + Duration::from_millis(config.limits.query_timeout_ms));
            bounded(
                session.client.query_one(
                    "SELECT set_config('statement_timeout', $1, false)",
                    &[&setting],
                ),
                query_deadline,
                cancel,
                ReasonCode::QueryTimeout,
            )
            .await
            .and_then(|r| r.map_err(|error| classify(&error, false)))
            .map_err(|r| ProbeFailure::new(r, session.stages.clone()))?;
            Ok(session)
        }
        Err(mut reason) => {
            if tls_state.load(Ordering::Acquire) == 2 {
                reason = ReasonCode::TlsRejected;
            }
            if reason == ReasonCode::DbAuthFailed {
                stages.db_authenticated = Stage::ObservedFalse;
            }
            Err(ProbeFailure::new(reason, stages))
        }
    }
}

pub fn classify(error: &tokio_postgres::Error, plaintext: bool) -> ReasonCode {
    if let Some(db) = error.as_db_error() {
        return match db.code().code() {
            "28P01" => ReasonCode::DbAuthFailed,
            "28000"
                if plaintext
                    && (db.message().contains("no encryption")
                        || db.message().contains("SSL off")) =>
            {
                ReasonCode::TlsRejected
            }
            "28000" => ReasonCode::DbAuthFailed,
            "42501" => ReasonCode::DbPermissionDenied,
            "57014" => ReasonCode::QueryTimeout,
            _ => ReasonCode::Unknown,
        };
    }
    ReasonCode::Unknown
}

struct ObservedTls<T> {
    inner: T,
    state: Arc<AtomicU8>,
}
impl<T> TlsConnect<TcpStream> for ObservedTls<T>
where
    T: TlsConnect<TcpStream> + Send + 'static,
    T::Future: Send,
    T::Stream: Send,
    T::Error: Error + Send + Sync + 'static,
{
    type Stream = T::Stream;
    type Error = T::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;
    fn connect(self, stream: TcpStream) -> Self::Future {
        Box::pin(async move {
            let result = self.inner.connect(stream).await;
            match &result {
                Ok(_) => self.state.store(1, Ordering::Release),
                Err(error) => {
                    let mut source: Option<&(dyn Error + 'static)> = Some(error);
                    while let Some(error) = source {
                        let tls_error = error.downcast_ref::<rustls::Error>().or_else(|| {
                            error
                                .downcast_ref::<std::io::Error>()
                                .and_then(std::io::Error::get_ref)
                                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                        });
                        if matches!(
                            tls_error,
                            Some(
                                rustls::Error::InvalidCertificate(_)
                                    | rustls::Error::NoCertificatesPresented
                            )
                        ) {
                            self.state.store(2, Ordering::Release);
                            break;
                        }
                        source = error.source();
                    }
                }
            }
            result
        })
    }
}
