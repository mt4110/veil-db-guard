//! Explicit integration lab. PG_BIN points at PostgreSQL binaries; no existing cluster is reused.
mod common;
use common::*;
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use veil_db_guard::{
    config::*,
    domain::*,
    probe::{
        self, ProbeOptions,
        auth::{LocalPasswordProvider, TokenMode},
        transport::{self, TlsMode},
    },
};

struct Lab {
    root: PathBuf,
    bin: PathBuf,
    port: u16,
    started: bool,
}
impl Lab {
    fn command(&self, name: &str, args: &[&str]) {
        let result = Command::new(self.bin.join(name))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("local executable");
        assert!(result.success(), "local fixture command failed");
    }
    fn new() -> Self {
        let bin = PathBuf::from(
            std::env::var_os("PG_BIN")
                .expect("PG_BIN required for ignored local PostgreSQL integration test"),
        );
        let root = tempfile::Builder::new()
            .prefix("vdg-pg-lab-")
            .tempdir_in("/tmp")
            .unwrap()
            .keep();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let mut lab = Self {
            root,
            bin,
            port,
            started: false,
        };
        eprintln!("Preserving local PostgreSQL lab at {}", lab.root.display());
        let cluster = lab.root.join("cluster");
        lab.command(
            "initdb",
            &[
                "-D",
                cluster.to_str().unwrap(),
                "-U",
                "vdg_admin",
                "--auth-local=trust",
                "--auth-host=scram-sha-256",
                "--no-instructions",
            ],
        );
        let openssl = |args: &[&str]| {
            assert!(
                Command::new("openssl")
                    .current_dir(&lab.root)
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success(),
                "local fixture certificate generation failed"
            );
        };
        openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=VDG Local Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        openssl(&[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=localhost",
        ]);
        fs::write(lab.root.join("server.ext"),"subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
        openssl(&[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "server.pem",
            "-days",
            "1",
            "-extfile",
            "server.ext",
        ]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                lab.root.join("server.key"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        fs::write(cluster.join("pg_hba.conf"),"local all all trust\nhostnossl all all 127.0.0.1/32 reject\nhostssl all all 127.0.0.1/32 scram-sha-256\n").unwrap();
        let mut config = fs::OpenOptions::new()
            .append(true)
            .open(cluster.join("postgresql.conf"))
            .unwrap();
        writeln!(config,"\nlisten_addresses='127.0.0.1'\nport={}\nunix_socket_directories='{}'\nssl=on\nssl_cert_file='{}'\nssl_key_file='{}'\nmax_connections=12\nlog_statement='none'\nlog_min_error_statement='panic'\nlog_error_verbosity='terse'",lab.port,lab.root.display(),lab.root.join("server.pem").display(),lab.root.join("server.key").display()).unwrap();
        lab.command(
            "pg_ctl",
            &[
                "-D",
                cluster.to_str().unwrap(),
                "-l",
                lab.root.join("postgres.log").to_str().unwrap(),
                "-w",
                "start",
            ],
        );
        lab.started = true;
        let mut psql = Command::new(lab.bin.join("psql"))
            .args([
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                lab.root.to_str().unwrap(),
                "-p",
                &lab.port.to_string(),
                "-U",
                "vdg_admin",
                "-d",
                "postgres",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        psql.stdin.take().unwrap().write_all(b"CREATE USER vdg_probe LOGIN PASSWORD 'LOCAL_SYNTHETIC_PASSWORD_ONLY';\nCREATE DATABASE vdg_lab OWNER vdg_probe;\n").unwrap();
        assert!(psql.wait().unwrap().success());
        lab
    }
    fn config(&self) -> (TargetConfig, InventorySnapshot, ProbeOptions) {
        let mut c = config();
        c.tls.ca_file = Some(self.root.join("ca.pem"));
        c.limits.total_timeout_ms = 30_000;
        c.recovery_profile = Some(RecoveryProfile {
            allow_token_expiry_wait: false,
            long_transaction_ms: 50,
        });
        c.auth_negative = Some(AuthNegativeConfig {
            unauthorized_aws_profile: None,
            unauthorized_db_user: Some("vdg_explicitly_forbidden".into()),
        });
        let mut s = snapshot();
        s.config_hash = config_hash(&c);
        s.evidence_kind = EvidenceKind::LocalFixture;
        let endpoint = Endpoint {
            host: "localhost".into(),
            port: self.port,
        };
        s.db.as_mut().unwrap().endpoint = endpoint.clone();
        s.proxy.as_mut().unwrap().endpoint = endpoint;
        let o = ProbeOptions {
            run_id: "local-pg-validation".into(),
            source_id: "application".into(),
            allow_network: true,
            allow_test_writes: true,
            local_lab: true,
            aws_profile: None,
        };
        (c, s, o)
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        if self.started {
            let _ = Command::new(self.bin.join("pg_ctl"))
                .args([
                    "-D",
                    self.root.join("cluster").to_str().unwrap(),
                    "-m",
                    "fast",
                    "-w",
                    "stop",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

fn save(root: &Path, name: &str, observations: &[Observation]) {
    let serialized = serde_json::to_vec_pretty(observations).unwrap();
    assert!(!String::from_utf8_lossy(&serialized).contains("LOCAL_SYNTHETIC_PASSWORD_ONLY"));
    fs::write(root.join(name), serialized).unwrap();
}

#[tokio::test]
#[ignore = "explicit local-only PostgreSQL lab: PG_BIN=<bin-directory> cargo test --test probes_postgres -- --ignored --nocapture"]
async fn postgres_tls_sql_negative_reconnect_and_measurement() {
    let lab = Lab::new();
    let (c, s, o) = lab.config();
    let provider = LocalPasswordProvider::new("LOCAL_SYNTHETIC_PASSWORD_ONLY".into());
    let positive = probe::run_with_provider(
        &c,
        &s,
        Suite::Positive,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    save(&lab.root, "positive.json", &positive);
    for case in [
        "V08.verified_client_tls",
        "V06.insert_read",
        "V06.update_read",
        "V06.delete_read",
        "V06.commit",
        "V06.rollback",
        "V06.error_rollback",
        "V06.session_isolation",
        "V16.prepared_statement",
        "V16.session_state",
        "V16.pool_reset",
        "V16.long_transaction",
    ] {
        let observed = positive
            .iter()
            .find(|observed| observed.case_id == case)
            .expect("required local case");
        assert!(
            matches!(
                observed.outcome,
                Outcome::Authenticated | Outcome::PostconditionMatched
            ),
            "local case {case}"
        );
        assert_eq!(observed.evidence_kind, EvidenceKind::LocalConnection);
    }
    // Exercise the desktop/CLI entry point with the same isolated lab and a new run area.
    let cli_config = lab.root.join("cli-config.yaml");
    let cli_snapshot = lab.root.join("cli-snapshot.json");
    let cli_out = lab.root.join("cli-positive-run");
    // JSON is a YAML 1.2 subset and carries exactly the validated typed configuration.
    fs::write(&cli_config, serde_json::to_vec_pretty(&c).unwrap()).unwrap();
    fs::write(&cli_snapshot, serde_json::to_vec_pretty(&s).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .arg("probe")
        .arg("--config")
        .arg(&cli_config)
        .arg("--snapshot")
        .arg(&cli_snapshot)
        .args([
            "--suite",
            "positive",
            "--source-id",
            "application",
            "--allow-network",
            "--local-lab",
            "--local-password-stdin",
            "--allow-test-writes",
        ])
        .arg("--out")
        .arg(&cli_out)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"LOCAL_SYNTHETIC_PASSWORD_ONLY\n")
        .unwrap();
    let cli_result = child.wait_with_output().unwrap();
    assert!(
        matches!(cli_result.status.code(), Some(0 | 3)),
        "local CLI probe failed instead of capturing observations"
    );
    let contains_secret = |bytes: &[u8]| {
        bytes
            .windows(b"LOCAL_SYNTHETIC_PASSWORD_ONLY".len())
            .any(|window| window == b"LOCAL_SYNTHETIC_PASSWORD_ONLY")
    };
    assert!(!contains_secret(&cli_result.stdout));
    assert!(!contains_secret(&cli_result.stderr));
    let manifest = veil_db_guard::store::verify_run(&cli_out, c.limits.max_bytes).unwrap();
    assert_eq!(manifest.operation, "probe");
    assert!(manifest.operation_only);
    assert_eq!(manifest.config_hash, config_hash(&c));
    assert!(matches!(
        manifest.status,
        veil_db_guard::store::RunStatus::Complete | veil_db_guard::store::RunStatus::Partial
    ));
    let cli_observations: Vec<Observation> =
        read_json(&cli_out.join("observations.json"), c.limits.max_bytes).unwrap();
    assert!(!cli_observations.is_empty());
    assert!(
        cli_observations
            .iter()
            .all(|observation| observation.evidence_kind == EvidenceKind::LocalConnection)
    );
    assert_eq!(
        cli_observations
            .iter()
            .find(|observation| observation.case_id == "V06.commit")
            .unwrap()
            .outcome,
        Outcome::PostconditionMatched
    );
    for entry in fs::read_dir(&cli_out).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert!(!contains_secret(&fs::read(path).unwrap()));
        }
    }
    let negatives = probe::run_with_provider(
        &c,
        &s,
        Suite::TlsNegative,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    save(&lab.root, "tls-negative.json", &negatives);
    for case in ["V08.tls_disabled", "V08.untrusted_ca", "V08.wrong_hostname"] {
        let observed = negatives
            .iter()
            .find(|observed| observed.case_id == case)
            .unwrap();
        assert_eq!(
            observed.reason_code,
            ReasonCode::TlsRejected,
            "TLS negative {case}"
        );
        assert_eq!(
            observed.path_stages.transport_reachable,
            Stage::ObservedTrue
        );
        assert_eq!(observed.execution, Execution::Completed);
    }
    // An AWS assessment profile cannot promote local probes into AWS connection evidence.
    let mut aws_profile_config = c.clone();
    aws_profile_config.assessment_profile = Profile::AwsSandboxCoreV1;
    let mut aws_profile_snapshot = s.clone();
    aws_profile_snapshot.config_hash = config_hash(&aws_profile_config);
    let local_only = probe::run_with_provider(
        &aws_profile_config,
        &aws_profile_snapshot,
        Suite::TlsNegative,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    assert!(
        local_only
            .iter()
            .all(|observation| observation.evidence_kind == EvidenceKind::LocalConnection)
    );
    let assessment =
        veil_db_guard::evaluator::evaluate(&aws_profile_config, &local_only, None, now());
    for case in [
        "V08.verified_client_tls",
        "V08.tls_disabled",
        "V08.untrusted_ca",
        "V08.wrong_hostname",
    ] {
        assert_eq!(
            assessment
                .cases
                .iter()
                .find(|row| row.case_id == case && row.path_id == "application-proxy")
                .unwrap()
                .verdict,
            Verdict::Unknown
        );
    }
    let negatives = probe::run_with_provider(
        &c,
        &s,
        Suite::AuthNegative,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    save(&lab.root, "auth-negative.json", &negatives);
    assert_eq!(
        negatives
            .iter()
            .find(|o| o.case_id == "V07.missing_auth")
            .unwrap()
            .reason_code,
        ReasonCode::DbAuthFailed
    );
    assert_eq!(
        negatives
            .iter()
            .find(|o| o.case_id == "V07.missing_auth")
            .unwrap()
            .execution,
        Execution::Completed
    );
    assert_eq!(
        negatives
            .iter()
            .find(|o| o.case_id == "V07.unauthorized_user")
            .unwrap()
            .reason_code,
        ReasonCode::DbAuthFailed
    );
    let direct = probe::run_with_provider(
        &c,
        &s,
        Suite::DirectPath,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    save(&lab.root, "direct.json", &direct);
    assert_eq!(direct[0].outcome, Outcome::TcpReachable); // A listening local DB is a known network-policy violation, never a pass.
    let recovery = probe::run_with_provider(
        &c,
        &s,
        Suite::Recovery,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    save(&lab.root, "recovery.json", &recovery);
    assert_eq!(
        recovery
            .iter()
            .find(|o| o.case_id == "V11.disconnect")
            .unwrap()
            .outcome,
        Outcome::PostconditionMatched
    );
    for case in ["V11.deadline", "V11.cancellation"] {
        assert_eq!(
            recovery.iter().find(|o| o.case_id == case).unwrap().outcome,
            Outcome::PostconditionMatched
        );
    }
    let measurement = probe::run_with_provider(
        &c,
        &s,
        Suite::Performance,
        &o,
        CancellationToken::new(),
        &provider,
    )
    .await
    .unwrap();
    save(&lab.root, "performance.json", &measurement);
    for case in ["V13.connection_setup", "V13.pooled_query"] {
        let details = measurement
            .iter()
            .find(|o| o.case_id == case)
            .unwrap()
            .details
            .as_ref()
            .unwrap();
        assert_eq!(details.sample_count, 30);
        assert_eq!(details.error_count, 0);
        assert!(details.p95_ms.is_some());
        assert!(details.p99_ms.is_none());
    }

    // Server statement_timeout and client deadline are separate; neither uses CancelRequest.
    let mut short = c.clone();
    short.limits.query_timeout_ms = 30;
    let deadline = Instant::now() + Duration::from_secs(2);
    let session = transport::connect(
        &short,
        &s.proxy.as_ref().unwrap().endpoint,
        &c.paths[0],
        &provider,
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: deadline,
            cancel: &CancellationToken::new(),
        },
    )
    .await
    .unwrap();
    let result = transport::bounded(
        session.client.query_one("SELECT pg_sleep(0.2)", &[]),
        deadline,
        &CancellationToken::new(),
        ReasonCode::QueryTimeout,
    )
    .await
    .unwrap();
    assert_eq!(
        transport::classify(&result.unwrap_err(), false),
        ReasonCode::QueryTimeout
    );
    drop(session);
    let fresh = transport::connect(
        &c,
        &s.proxy.as_ref().unwrap().endpoint,
        &c.paths[0],
        &provider,
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: deadline,
            cancel: &CancellationToken::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        fresh
            .client
            .query_one("SELECT 1::integer", &[])
            .await
            .unwrap()
            .get::<_, i32>(0),
        1
    );
}

#[tokio::test]
#[ignore = "explicit local PostgreSQL COMMIT-response-loss lab; retains its newly created cluster"]
async fn lost_commit_reply_is_reconciled_without_replaying_the_write() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener as AsyncListener, TcpStream},
    };
    let lab = Lab::new();
    let (c, s, _) = lab.config();
    let provider = LocalPasswordProvider::new("LOCAL_SYNTHETIC_PASSWORD_ONLY".into());
    let listener = AsyncListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let armed = Arc::new(AtomicBool::new(false));
    let proxy_armed = armed.clone();
    let backend_port = lab.port;
    let proxy = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(("127.0.0.1", backend_port))
            .await
            .unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let upstream = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
        });
        let mut buffer = [0; 16_384];
        loop {
            let count = match server_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            // Fault after the server has generated a reply, while its TLS ciphertext is still opaque.
            if proxy_armed.load(Ordering::SeqCst) {
                break;
            }
            if client_write.write_all(&buffer[..count]).await.is_err() {
                break;
            }
        }
        upstream.abort();
        let _ = client_write.shutdown().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancel = CancellationToken::new();
    let endpoint = Endpoint {
        host: "localhost".into(),
        port,
    };
    let session = transport::connect(
        &c,
        &endpoint,
        &c.paths[0],
        &provider,
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: deadline,
            cancel: &cancel,
        },
    )
    .await
    .unwrap();
    let schema = probe::sql::owned_schema(
        "vdg_fault",
        lab.root.file_name().unwrap().to_str().unwrap(),
        "commit-response-loss",
    )
    .unwrap();
    session.client.batch_execute(&format!("CREATE SCHEMA \"{schema}\"; CREATE TABLE \"{schema}\".operations(operation_id text PRIMARY KEY,value integer NOT NULL)")).await.unwrap();
    session.client.batch_execute("BEGIN").await.unwrap();
    session
        .client
        .execute(
            &format!("INSERT INTO \"{schema}\".operations(operation_id,value) VALUES($1,$2)"),
            &[&"committed-operation", &11_i32],
        )
        .await
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    assert_eq!(
        probe::sql::commit_once(&session, &c, deadline, &cancel)
            .await
            .unwrap_err(),
        ReasonCode::WriteOutcomeUnknown
    );
    drop(session);
    proxy.await.unwrap();
    let fresh = transport::connect(
        &c,
        &s.db.as_ref().unwrap().endpoint,
        &c.paths[0],
        &provider,
        transport::ConnectOptions {
            token_mode: TokenMode::Valid,
            tls_mode: TlsMode::Verified,
            user: &c.auth.db_user,
            local: true,
            total_deadline: deadline,
            cancel: &cancel,
        },
    )
    .await
    .unwrap();
    assert!(
        probe::sql::reconcile_commit(&fresh, &schema, &c, deadline, &cancel)
            .await
            .unwrap()
    );
    let count = fresh
        .client
        .query_one(
            &format!("SELECT count(*)::bigint FROM \"{schema}\".operations"),
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(count, 1);
    let mut observation = Observation::new(
        &c,
        "local-commit-fault",
        "V11",
        "V11.ambiguous_commit",
        "application",
        "application-proxy",
        EvidenceKind::LocalConnection,
    );
    observation.snapshot_hash = snapshot_hash(&s);
    observation.execution = Execution::Completed;
    observation.outcome = Outcome::PostconditionMatched;
    observation.reason_code = ReasonCode::None;
    observation.path_stages = fresh.stages.clone();
    observation.facts = vec![
        Fact::NoWriteReplay,
        Fact::PostconditionVerified,
        Fact::ChainVerified,
        Fact::HostnameVerified,
    ];
    observation.details = Some(ProbeDetails {
        retained_schema: Some(schema),
        ..Default::default()
    });
    save(&lab.root, "commit-response-loss.json", &[observation]);
}
