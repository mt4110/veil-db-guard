mod common;
use common::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use veil_db_guard::{
    config::*,
    domain::*,
    probe::{
        self, ProbeOptions,
        auth::*,
        performance,
        transport::{self, TlsMode},
    },
};

#[test]
fn sigv4_is_offline_encoded_time_limited_and_redacted() {
    let endpoint = Endpoint {
        host: "db.synthetic.rds.amazonaws.com".into(),
        port: 5432,
    };
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let credentials = aws_credential_types::Credentials::new(
        "DUMMY_ACCESS_KEY",
        "SENTINEL_DUMMY_SECRET",
        Some("SENTINEL_DUMMY_SESSION".into()),
        None,
        "local-fixture",
    );
    let token = sign_iam_token(
        credentials.clone(),
        &endpoint,
        "User + & ?",
        "ap-northeast-1",
        time,
    )
    .unwrap();
    let debug = format!("{token:?}");
    assert_eq!(debug, "SecretToken([REDACTED])");
    // Secret material cannot enter Debug, config serialization, or a propagated driver error.
    for secret in [
        "DUMMY_ACCESS_KEY",
        "SENTINEL_DUMMY_SECRET",
        "SENTINEL_DUMMY_SESSION",
    ] {
        assert!(!debug.contains(secret));
    }
    let expired = aws_credential_types::Credentials::new(
        "DUMMY",
        "DUMMY",
        None,
        Some(time - Duration::from_secs(1)),
        "fixture",
    );
    assert_eq!(
        sign_iam_token(expired, &endpoint, "vdg_probe", "ap-northeast-1", time).unwrap_err(),
        ReasonCode::IamDenied
    );
    // The opaque token's exact signed URL is intentionally not publicly exposed.
    assert!(sign_iam_token(credentials, &endpoint, "vdg_probe", "ap-northeast-1", time).is_ok());
}

#[test]
fn empirical_quantiles_require_tail_samples_and_keep_raw_values() {
    let details =
        performance::summarize((1..=30).collect(), 2, Destination::Proxy, "fixed-select-v1");
    assert_eq!(details.sample_count, 32);
    assert_eq!(details.samples_ms.len(), 30);
    assert_eq!(details.p50_ms, Some(15));
    assert_eq!(details.p95_ms, Some(29));
    assert_eq!(details.p99_ms, None);
    assert_eq!(
        performance::summarize(
            (1..=100).collect(),
            0,
            Destination::Database,
            "fixed-select-v1"
        )
        .p99_ms,
        Some(99)
    );
}

struct CountingProvider(Arc<AtomicUsize>);
impl TokenProvider for CountingProvider {
    fn token<'a>(&'a self, _: &'a Endpoint, _: &'a str, _: TokenMode) -> TokenFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(SecretToken::new("SENTINEL_NEVER_SENT".into())) })
    }
}
fn options() -> ProbeOptions {
    ProbeOptions {
        run_id: "local-probe-test".into(),
        source_id: "application".into(),
        allow_network: true,
        allow_test_writes: false,
        local_lab: true,
        aws_profile: None,
    }
}

#[tokio::test]
async fn local_boundary_rejects_non_loopback_before_credentials_or_dns() {
    let c = config();
    let mut s = snapshot();
    s.config_hash = config_hash(&c);
    s.evidence_kind = EvidenceKind::LocalFixture;
    s.proxy.as_mut().unwrap().endpoint.host = "example.com".into();
    let count = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider(count.clone());
    assert_eq!(
        probe::run_with_provider(
            &c,
            &s,
            Suite::Positive,
            &options(),
            CancellationToken::new(),
            &provider
        )
        .await
        .unwrap_err(),
        GuardError::TargetMismatch
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_prevents_credential_acquisition_and_new_connections() {
    let mut c = config();
    c.limits.total_timeout_ms = 100;
    c.limits.connect_timeout_ms = 100;
    c.limits.query_timeout_ms = 100;
    let mut s = snapshot();
    s.config_hash = config_hash(&c);
    s.evidence_kind = EvidenceKind::LocalFixture;
    s.proxy.as_mut().unwrap().endpoint.host = "localhost".into();
    s.db.as_mut().unwrap().endpoint.host = "localhost".into();
    let count = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider(count.clone());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let observations =
        probe::run_with_provider(&c, &s, Suite::Positive, &options(), cancel, &provider)
            .await
            .unwrap();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].execution, Execution::Cancelled);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_reachability_is_kept_even_when_postgres_handshake_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let mut c = config();
    c.limits.connect_timeout_ms = 30;
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: address.port(),
    };
    let result = transport::connect(
        &c,
        &endpoint,
        &c.paths[0],
        &LocalPasswordProvider::new("DUMMY".into()),
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: Instant::now() + Duration::from_secs(1),
            cancel: &CancellationToken::new(),
        },
    )
    .await;
    let failure = match result {
        Ok(_) => panic!("unexpected connection"),
        Err(failure) => failure,
    };
    assert_eq!(failure.reason, ReasonCode::ConnectTimeout);
    assert_eq!(failure.stages.transport_reachable, Stage::ObservedTrue);
    assert_eq!(failure.stages.tls_established, Stage::Unknown);
    assert_eq!(failure.stages.db_authenticated, Stage::Unknown);
    server.abort();
}

#[tokio::test]
async fn tls_disabled_probe_never_fetches_or_transmits_real_credentials() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let length = socket.read_u32().await.unwrap();
        let mut startup = vec![0; (length - 4) as usize];
        socket.read_exact(&mut startup).await.unwrap();
        // Ask for cleartext password, then inspect only the empty local negative response.
        socket
            .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 3])
            .await
            .unwrap();
        let tag = socket.read_u8().await.unwrap();
        let length = socket.read_u32().await.unwrap();
        let mut body = vec![0; (length - 4) as usize];
        socket.read_exact(&mut body).await.unwrap();
        (tag, body)
    });
    let c = config();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: address.port(),
    };
    let count = Arc::new(AtomicUsize::new(0));
    let _ = transport::connect(
        &c,
        &endpoint,
        &c.paths[0],
        &CountingProvider(count.clone()),
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Disabled,
            user: &c.auth.db_user,
            local: true,
            total_deadline: Instant::now() + Duration::from_secs(1),
            cancel: &CancellationToken::new(),
        },
    )
    .await;
    let (tag, body) = server.await.unwrap();
    assert_eq!(tag, b'p');
    assert_eq!(body, vec![0]);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn refused_loopback_tcp_is_never_labeled_an_authentication_rejection() {
    let reserved = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let c = config();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: address.port(),
    };
    let cancel = CancellationToken::new();
    let result = transport::connect(
        &c,
        &endpoint,
        &c.paths[0],
        &LocalPasswordProvider::new("DUMMY".into()),
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: Instant::now() + Duration::from_secs(1),
            cancel: &cancel,
        },
    )
    .await;
    let error = match result {
        Ok(_) => panic!("unexpected accepted TCP connection"),
        Err(error) => error,
    };
    assert_eq!(error.reason, ReasonCode::NetworkUnreachable);
    assert_eq!(error.stages.transport_reachable, Stage::ObservedFalse);
    assert_eq!(error.stages.db_authenticated, Stage::Unknown);
    assert_eq!(error.stages.tls_established, Stage::Unknown);
}

#[tokio::test]
async fn expired_aws_credential_fixture_is_refused_without_opening_any_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = Endpoint {
        host: "127.0.0.1".into(),
        port: address.port(),
    };
    let c = config();
    let cancel = CancellationToken::new();
    let expired = aws_credential_types::Credentials::new(
        "DUMMY",
        "DUMMY",
        None,
        Some(SystemTime::now() - Duration::from_secs(1)),
        "fixture",
    );
    let provider = SigningTokenProvider {
        credentials: expired,
        region: c.target.region.clone(),
    };
    let result = transport::connect(
        &c,
        &endpoint,
        &c.paths[0],
        &provider,
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: Instant::now() + Duration::from_secs(1),
            cancel: &cancel,
        },
    )
    .await;
    let error = match result {
        Ok(_) => panic!("unexpected connection using expired credentials"),
        Err(error) => error,
    };
    assert_eq!(error.reason, ReasonCode::IamDenied);
    assert_eq!(error.stages.transport_reachable, Stage::Unknown);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn shared_parent_deadline_stops_the_probe_without_rewriting_configuration() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let c = config();
    let original_hash = config_hash(&c);
    let mut s = snapshot();
    s.evidence_kind = EvidenceKind::LocalFixture;
    for endpoint in [
        &mut s.db.as_mut().unwrap().endpoint,
        &mut s.proxy.as_mut().unwrap().endpoint,
    ] {
        *endpoint = Endpoint {
            host: "127.0.0.1".into(),
            port,
        };
    }
    s.config_hash = original_hash.clone();
    let accepted = Arc::new(AtomicUsize::new(0));
    let server_count = accepted.clone();
    let server = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            server_count.fetch_add(1, Ordering::SeqCst);
            sockets.push(socket);
        }
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider(calls.clone());
    let started = Instant::now();
    let deadline = started + Duration::from_millis(40);
    let observations = probe::run_with_provider_until(
        &c,
        &s,
        Suite::Positive,
        &options(),
        CancellationToken::new(),
        &provider,
        deadline,
    )
    .await
    .unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(observations[0].reason_code, ReasonCode::ConnectTimeout);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(config_hash(&c), original_hash);
    assert!(
        observations
            .iter()
            .all(|observation| observation.config_hash == original_hash)
    );
    server.abort();
}
