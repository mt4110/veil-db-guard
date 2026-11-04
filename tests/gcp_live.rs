//! Adapter tests use newly-created local mock executables; installed gcloud is never invoked.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use veil_db_guard::{
    config::GuardError,
    domain::Limits,
    gcp::{
        config,
        live::{self, LiveTools},
        model::*,
    },
};

struct Fixture {
    root: PathBuf,
    tools: LiveTools,
    config: GcpConfig,
    instance: Value,
    policy: Value,
    users: Value,
}
fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}
fn script(path: &Path, source: &str) {
    fs::write(path, source).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("vdg-gcp-adapter-")
            .tempdir_in("/tmp")
            .unwrap()
            .keep();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let work = root.join("transport");
        fs::create_dir(&work).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(
            Command::new("openssl")
                .current_dir(&root)
                .args([
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
                    "/CN=VDG Local GCP Adapter Fixture",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE"
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let config = GcpConfig {
            schema_version: 1,
            target: GcpTarget {
                project_id: "vdg-fixture".into(),
                instance_id: "guarded-postgres".into(),
                region: "asia-northeast1".into(),
                engine_version: "POSTGRES_16_15".into(),
                database: "vdg_lab".into(),
            },
            principals: vec![
                GcpPrincipal {
                    id: "allowed".into(),
                    service_account: "allowed-probe@vdg-fixture.iam.gserviceaccount.com".into(),
                },
                GcpPrincipal {
                    id: "connect-denied".into(),
                    service_account: "denied-connect-probe@vdg-fixture.iam.gserviceaccount.com"
                        .into(),
                },
                GcpPrincipal {
                    id: "login-denied".into(),
                    service_account: "denied-login-probe@vdg-fixture.iam.gserviceaccount.com"
                        .into(),
                },
            ],
            cases: vec![
                GcpCase {
                    id: "positive-proxy".into(),
                    principal_id: "allowed".into(),
                    route: GcpRoute::Proxy,
                    expected: GcpExpectation::Allow,
                    expected_denial: None,
                },
                GcpCase {
                    id: "denied-connect".into(),
                    principal_id: "connect-denied".into(),
                    route: GcpRoute::Proxy,
                    expected: GcpExpectation::Deny,
                    expected_denial: Some(GcpDenial::ConnectIam),
                },
                GcpCase {
                    id: "denied-login".into(),
                    principal_id: "login-denied".into(),
                    route: GcpRoute::Proxy,
                    expected: GcpExpectation::Deny,
                    expected_denial: Some(GcpDenial::LoginIam),
                },
            ],
            permission_changes: vec![],
            limits: Limits {
                connect_timeout_ms: 2000,
                query_timeout_ms: 1000,
                total_timeout_ms: 15000,
                ..Default::default()
            },
            max_age_seconds: 3600,
            pending_window_seconds: 600,
        };
        config::validate_config(&config).unwrap();
        let instance = json!({"name":config.target.instance_id,"project":config.target.project_id,"region":config.target.region,"databaseVersion":"POSTGRES_16","databaseInstalledVersion":"POSTGRES_16_15","connectionName":"vdg-fixture:asia-northeast1:guarded-postgres","ipAddresses":[{"type":"PRIMARY","ipAddress":"203.0.113.10"}],"serverCaCert":{"cert":fs::read_to_string(root.join("ca.pem")).unwrap()},"settings":{"connectorEnforcement":"REQUIRED","ipConfiguration":{"sslMode":"ENCRYPTED_ONLY","authorizedNetworks":[],"serverCaMode":"GOOGLE_MANAGED_INTERNAL_CA"},"databaseFlags":[{"name":"cloudsql.iam_authentication","value":"on"}]}});
        let mut bindings = Vec::new();
        for (role, ids) in [
            ("roles/cloudsql.client", vec![0, 2]),
            ("roles/cloudsql.instanceUser", vec![0, 1]),
            ("roles/serviceusage.serviceUsageConsumer", vec![0, 1, 2]),
        ] {
            bindings.push(json!({"role":role,"members":ids.into_iter().map(|id|format!("serviceAccount:{}",config.principals[id].service_account)).collect::<Vec<_>>()}));
        }
        let policy = json!({"bindings":bindings});
        let users = json!(
            config
                .principals
                .iter()
                .map(|p| json!({"name":p.db_user(),"type":"CLOUD_IAM_SERVICE_ACCOUNT"}))
                .collect::<Vec<_>>()
        );
        write_json(&root.join("instance.json"), &instance);
        write_json(&root.join("policy.json"), &policy);
        write_json(&root.join("users.json"), &users);
        write_json(&root.join("properties.json"), &json!({}));
        let tools = LiveTools {
            gcloud: root.join("gcloud"),
            proxy: root.join("cloud-sql-proxy"),
            psql: root.join("psql"),
            work_dir: work,
        };
        script(
            &tools.gcloud,
            r#"#!/usr/bin/env python3
import json, os, pathlib, sys, time
r=pathlib.Path(__file__).parent
a=sys.argv[1:]
assert '--project=vdg-fixture' in a
assert not any(k.startswith('PG') or k.startswith('CSQL_PROXY_') for k in os.environ)
assert os.environ.get('CLOUDSDK_AUTH_DISABLE_SSL_VALIDATION')=='false'
assert os.environ.get('CLOUDSDK_CORE_LOG_HTTP')=='false'
assert os.environ.get('CLOUDSDK_CORE_LOG_HTTP_REDACT_TOKEN')=='true'
assert os.environ.get('CLOUDSDK_CORE_DISABLE_FILE_LOGGING')=='true'
assert os.environ.get('CLOUDSDK_API_ENDPOINT_OVERRIDES_SQL')=='https://sqladmin.googleapis.com/'
with (r/'commands.jsonl').open('a') as f: f.write(json.dumps(a)+'\n')
with (r/'pids').open('a') as f: f.write(str(os.getpid())+'\n')
if a[:2]==['config','list']: print((r/'properties.json').read_text())
elif a[:3]==['sql','instances','describe']:
    count=sum('"describe"' in line for line in (r/'commands.jsonl').read_text().splitlines())
    if (r/'fail-after').exists() and count>1: sys.exit(2)
    print((r/'instance.json').read_text())
elif a[:2]==['projects','get-iam-policy']: print((r/'policy.json').read_text())
elif a[:3]==['sql','users','list']: print((r/'users.json').read_text())
elif a[:2]==['sql','generate-login-token']:
    assert '--instance=guarded-postgres' in a
    assert any(x.startswith('--impersonate-service-account=') for x in a)
    if (r/'hang-token').exists():
        pid=os.fork()
        if pid==0:
            with (r/'pids').open('a') as f: f.write(str(os.getpid())+'\n')
            time.sleep(20);sys.exit(0)
        time.sleep(20)
    print('DUMMY_GCP_ACCESS_TOKEN_DO_NOT_PERSIST')
else: sys.exit(91)
"#,
        );
        script(
            &tools.proxy,
            r#"#!/usr/bin/env python3
import json, os, pathlib, socket, sys, time
r=pathlib.Path(__file__).parent
if '--version' in sys.argv: print('cloud-sql-proxy version 2.26.3+fixture');sys.exit(0)
a=sys.argv[1:]
assert '--gcloud-auth' in a and '--auto-iam-authn' not in a
assert '--address=127.0.0.1' in a
assert a[-1]=='vdg-fixture:asia-northeast1:guarded-postgres'
assert not any(k.startswith('CSQL_PROXY_') or k.startswith('PG') for k in os.environ)
assert not any('DUMMY_GCP_ACCESS_TOKEN' in x for x in a)
port=int(next(x.split('=',1)[1] for x in a if x.startswith('--port=')))
s=socket.socket();s.bind(('127.0.0.1',port));s.listen()
with (r/'pids').open('a') as f: f.write(str(os.getpid())+'\n')
print(json.dumps({'message':'Listening on 127.0.0.1:'+str(port)}),flush=True)
if any('denied-connect-probe@' in x for x in a):
    message='403 cloudsql.instances.connect permission denied' if not (r/'unknown-403').exists() else '403 quota unavailable'
    print(json.dumps({'message':message}),flush=True)
while True: time.sleep(1)
"#,
        );
        script(
            &tools.psql,
            r#"#!/usr/bin/env python3
import json, os, pathlib, sys, time
r=pathlib.Path(__file__).parent
if '--version' in sys.argv: print('psql (PostgreSQL) 17.7');sys.exit(0)
with (r/'pids').open('a') as f: f.write(str(os.getpid())+'\n')
assert '--no-psqlrc' in sys.argv and '--no-password' in sys.argv and '--file=-' in sys.argv
assert not any('DUMMY_GCP_ACCESS_TOKEN' in x for x in sys.argv)
assert os.environ['PGHOST']=='127.0.0.1' and int(os.environ['PGPORT'])>0
assert os.environ['PGPASSWORD']=='DUMMY_GCP_ACCESS_TOKEN_DO_NOT_PERSIST'
assert os.environ['PGSSLMODE']=='disable' and os.environ['PGGSSENCMODE']=='disable'
assert os.environ['PGSSLCERTMODE']=='disable' and os.environ['PGPASSFILE']=='/dev/null'
assert 'PGSERVICE' not in os.environ
assert 'default_transaction_read_only=on' in os.environ['PGOPTIONS']
sql=sys.stdin.read()
assert 'current_user' in sql and 'pg_stat_ssl' in sql
assert all(word not in sql.upper() for word in ['INSERT','UPDATE','DELETE','CREATE','DROP'])
if (r/'hang-psql').exists():
    (r/'psql-started').write_text('started')
    time.sleep(20)
if 'denied-connect-probe@' in os.environ['PGUSER']: print('connection closed',file=sys.stderr);sys.exit(2)
if 'denied-login-probe@' in os.environ['PGUSER']: print('FATAL: Cloud SQL IAM service account authentication failed',file=sys.stderr);sys.exit(2)
print(json.dumps({'current_user':'SENTINEL_UNEXPECTED_USER_DO_NOT_SAVE' if (r/'wrong-user').exists() else os.environ['PGUSER'],'database':'SENTINEL_UNEXPECTED_DATABASE_DO_NOT_SAVE' if (r/'wrong-database').exists() else os.environ['PGDATABASE'],'engine_version':'15.12' if (r/'wrong-engine').exists() else '16.15','backend_ssl':False}))
"#,
        );
        Self {
            root,
            tools,
            config,
            instance,
            policy,
            users,
        }
    }
    fn pids_absent(&self) {
        if let Ok(pids) = fs::read_to_string(self.root.join("pids")) {
            for pid in pids.lines() {
                assert!(
                    !Command::new("/bin/kill")
                        .args(["-0", pid])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap()
                        .success(),
                    "adapter-owned child survived capture"
                );
            }
        }
    }
}

#[test]
fn environment_is_minimal_and_rejects_implicit_configuration_switches() {
    let tools = LiveTools {
        gcloud: "/explicit/gcloud".into(),
        proxy: "/explicit/proxy".into(),
        psql: "/explicit/psql".into(),
        work_dir: "/private/work".into(),
    };
    let inherited = BTreeMap::from([
        (OsString::from("HOME"), OsString::from("/home/operator")),
        ("PGSERVICE".into(), "evil".into()),
        ("PGPASSWORD".into(), "DUMMY_PRIVATE".into()),
        ("CSQL_PROXY_ADDRESS".into(), "0.0.0.0".into()),
        (
            "GOOGLE_APPLICATION_CREDENTIALS".into(),
            "/unrequested/key.json".into(),
        ),
        (
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_SQL".into(),
            "https://untrusted.invalid".into(),
        ),
        ("HTTPS_PROXY".into(), "http://untrusted.invalid".into()),
    ]);
    let cleaned = live::sanitized_environment(&tools, &inherited).unwrap();
    for key in [
        "PGSERVICE",
        "PGPASSWORD",
        "CSQL_PROXY_ADDRESS",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "HTTPS_PROXY",
    ] {
        assert!(!cleaned.contains_key(OsStr::new(key)));
    }
    assert_eq!(
        cleaned
            .get(OsStr::new("CLOUDSDK_API_ENDPOINT_OVERRIDES_SQL"))
            .unwrap(),
        "https://sqladmin.googleapis.com/"
    );
    let mut switched = inherited;
    switched.insert("CLOUDSDK_CONFIG".into(), "/alternate/credentials".into());
    assert_eq!(
        live::sanitized_environment(&tools, &switched).unwrap_err(),
        GuardError::ConfigInvalid
    );
}

#[test]
fn failure_classification_requires_the_known_permission_and_keeps_iam_layers_separate() {
    let connect = live::classify_failure(
        br#"{"message":"HTTP 403: missing cloudsql.instances.connect"}"#,
        b"connection closed",
    );
    assert_eq!(
        connect.denied_permission,
        Some(GcpPermission::InstanceConnect)
    );
    assert!(!connect.transport_positive);
    for diagnostic in [
        b"IAM service account authentication failed".as_slice(),
        b"Cloud SQL IAM user authentication failed",
    ] {
        let login = live::classify_failure(b"", diagnostic);
        assert!(login.iam_login_rejected);
        assert!(!login.transport_positive);
        assert_eq!(login.denied_permission, None);
    }
    let unknown = live::classify_failure(b"403 quota unavailable", b"timeout");
    assert_eq!(unknown.denied_permission, None);
    assert!(!unknown.network_rejection_explicit);
    assert!(!unknown.iam_login_rejected);
}

#[test]
fn configured_endpoint_and_credential_overrides_are_refused_without_echo() {
    for value in [
        json!({"auth":{"access_token_file":"SENTINEL_PRIVATE_PATH"}}),
        json!({"auth":{"credential_file_override":"SENTINEL_PRIVATE_PATH"}}),
        json!({"auth":{"impersonate_service_account":"unrequested@project.iam.gserviceaccount.com"}}),
        json!({"api_endpoint_overrides":{"sql":"https://untrusted.invalid/"}}),
        json!({"auth":{"disable_ssl_validation":true}}),
    ] {
        let error = live::validate_sdk_properties(&value).unwrap_err();
        assert_eq!(error, GuardError::ConfigInvalid);
        assert!(!error.to_string().contains("SENTINEL_PRIVATE_PATH"));
    }
}

#[tokio::test]
async fn fixed_mock_adapter_captures_fresh_snapshots_and_distinguishes_two_denial_layers() {
    let fixture = Fixture::new();
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "gcp-adapter-local",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    assert!(capture.before.complete && capture.after.complete);
    assert_eq!(capture.execution, GcpExecution::Completed);
    assert_eq!(capture.before.registered_principal_ids.len(), 3);
    assert_eq!(capture.before.ca_fingerprint.len(), 64);
    let allowed = &capture.observations[0];
    assert_eq!(allowed.observed, GcpAccess::Allowed);
    assert!(allowed.proof.sql_ok && allowed.proof.sql_authenticated);
    assert_eq!(allowed.proof.tls_established, Some(false));
    assert!(!allowed.proof.ca_verified);
    let denied = &capture.observations[1];
    assert_eq!(denied.observed, GcpAccess::Denied);
    assert_eq!(
        denied.proof.denied_permission,
        Some(GcpPermission::InstanceConnect)
    );
    assert_eq!(denied.execution, GcpExecution::Completed);
    let login = &capture.observations[2];
    assert_eq!(login.observed, GcpAccess::Denied);
    assert!(login.proof.iam_login_rejected && login.proof.transport_positive);
    assert_eq!(
        login.proof.transport_control_case_id.as_deref(),
        Some("positive-proxy")
    );
    assert_eq!(login.proof.denied_permission, None);
    let serialized = serde_json::to_vec(&capture).unwrap();
    assert!(!String::from_utf8_lossy(&serialized).contains("DUMMY_GCP_ACCESS_TOKEN"));
    let commands = fs::read_to_string(fixture.root.join("commands.jsonl")).unwrap();
    assert_eq!(
        commands
            .lines()
            .filter(|line| line.contains("\"describe\""))
            .count(),
        2
    );
    assert_eq!(
        commands
            .lines()
            .filter(|line| line.contains("\"get-iam-policy\""))
            .count(),
        2
    );
    assert_eq!(
        commands
            .lines()
            .filter(|line| line.contains("\"users\""))
            .count(),
        2
    );
    assert_eq!(capture.config_hash, config::config_hash(&fixture.config));
    fixture.pids_absent();
}

#[tokio::test]
async fn sql_success_with_identity_or_version_mismatch_keeps_observed_allowed() {
    let mut fixture = Fixture::new();
    fixture.config.cases.truncate(1);
    fs::write(fixture.root.join("wrong-engine"), b"1").unwrap();
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "wrong-engine",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    let observed = &capture.observations[0];
    assert_eq!(observed.observed, GcpAccess::Allowed);
    assert!(observed.proof.sql_authenticated);
    assert!(!observed.proof.sql_ok);
    fixture.pids_absent();
}

#[tokio::test]
async fn plain_403_is_not_reported_as_connect_permission_rejection() {
    let mut fixture = Fixture::new();
    fixture.config.cases.remove(2);
    fixture.config.cases.remove(0);
    fs::write(fixture.root.join("unknown-403"), b"1").unwrap();
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "unclassified-403",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    let observed = &capture.observations[0];
    assert_eq!(observed.observed, GcpAccess::Unknown);
    assert_eq!(observed.proof.denied_permission, None);
    fixture.pids_absent();
}

#[tokio::test]
async fn token_timeout_reaps_the_entire_created_process_group() {
    let mut fixture = Fixture::new();
    fixture.config.cases.truncate(1);
    // Allow ordinary mock-interpreter startup under parallel test load. The token
    // command and its fork still hang for 20 seconds and must be killed at 2 seconds.
    fixture.config.limits.connect_timeout_ms = 2_000;
    fs::write(fixture.root.join("hang-token"), b"1").unwrap();
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "token-deadline",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    let observed = &capture.observations[0];
    assert_eq!(observed.execution, GcpExecution::Timeout);
    assert_eq!(observed.observed, GcpAccess::Unknown);
    assert!(!observed.proof.credential_issued);
    assert!(!observed.proof.network_rejection_explicit);
    tokio::time::sleep(Duration::from_millis(30)).await;
    fixture.pids_absent();
}

#[test]
fn inventory_checks_target_user_registration_conditions_and_certificate_fingerprint() {
    let fixture = Fixture::new();
    let snapshot = live::normalize_inventory(
        &fixture.config,
        &fixture.instance,
        &fixture.policy,
        &fixture.users,
    )
    .unwrap();
    assert_eq!(snapshot.ca_fingerprint.len(), 64);
    assert_eq!(snapshot.registered_principal_ids.len(), 3);
    let mut wrong = fixture.instance.clone();
    wrong["project"] = json!("another-project");
    assert!(matches!(
        live::normalize_inventory(&fixture.config, &wrong, &fixture.policy, &fixture.users),
        Err(GuardError::TargetMismatch)
    ));
    let mut conditional = fixture.policy.clone();
    conditional["bindings"][0]["condition"] = json!({"expression":"true"});
    let snapshot = live::normalize_inventory(
        &fixture.config,
        &fixture.instance,
        &conditional,
        &fixture.users,
    )
    .unwrap();
    assert!(
        snapshot
            .principal_roles
            .iter()
            .find(|roles| roles.principal_id == "allowed")
            .unwrap()
            .roles
            .contains(&GcpRole::Other)
    );
    let absent = live::normalize_inventory(
        &fixture.config,
        &fixture.instance,
        &fixture.policy,
        &json!([]),
    )
    .unwrap();
    assert!(absent.registered_principal_ids.is_empty());
}

#[tokio::test]
async fn iam_rejection_without_a_successful_independent_sql_control_stays_unconfirmed() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("wrong-engine"), b"1").unwrap();
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "missing-sql-control",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    let login = &capture.observations[2];
    assert_eq!(login.observed, GcpAccess::Denied);
    assert!(login.proof.iam_login_rejected);
    assert!(!login.proof.transport_positive);
    assert!(login.proof.transport_control_case_id.is_none());
    let assessment = veil_db_guard::gcp::evaluate::evaluate(
        &fixture.config,
        &[capture],
        &[],
        veil_db_guard::domain::now(),
    );
    assert_eq!(
        assessment
            .cases
            .iter()
            .find(|case| case.case_id == "denied-login")
            .unwrap()
            .verdict,
        GcpVerdict::Unknown
    );
    fixture.pids_absent();
}

#[tokio::test]
async fn after_inventory_failure_preserves_the_actual_allowed_observation() {
    let mut fixture = Fixture::new();
    fixture.config.cases.truncate(1);
    fs::write(fixture.root.join("fail-after"), b"1").unwrap();
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "after-read-failed",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    assert!(capture.before.complete);
    assert!(!capture.after.complete);
    assert_eq!(capture.execution, GcpExecution::Error);
    assert_eq!(capture.observations[0].observed, GcpAccess::Allowed);
    let assessment = veil_db_guard::gcp::evaluate::evaluate(
        &fixture.config,
        &[capture],
        &[],
        veil_db_guard::domain::now(),
    );
    assert_eq!(assessment.cases[0].observed, GcpAccess::Allowed);
    assert_eq!(assessment.cases[0].verdict, GcpVerdict::Unknown);
    fixture.pids_absent();
}

#[tokio::test]
async fn cancellation_stops_owned_proxy_and_sql_children_and_does_not_start_another_case() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("hang-psql"), b"1").unwrap();
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    let marker = fixture.root.join("psql-started");
    let task = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && !marker.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        trigger.cancel();
    });
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "cancelled-capture",
        cancel,
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    task.await.unwrap();
    assert_eq!(capture.execution, GcpExecution::Cancelled);
    assert!(!capture.after.complete);
    assert!(
        capture
            .observations
            .iter()
            .all(|observation| observation.execution == GcpExecution::Cancelled)
    );
    let commands = fs::read_to_string(fixture.root.join("commands.jsonl")).unwrap();
    assert_eq!(
        commands
            .lines()
            .filter(|line| line.contains("generate-login-token"))
            .count(),
        1
    );
    fixture.pids_absent();
}

#[tokio::test]
async fn direct_shared_ca_mode_is_not_silently_downgraded_to_unbound_verify_ca() {
    let mut fixture = Fixture::new();
    fixture.config.cases.truncate(1);
    fixture.config.cases.push(GcpCase {
        id: "direct-blocked".into(),
        principal_id: "allowed".into(),
        route: GcpRoute::Direct,
        expected: GcpExpectation::Deny,
        expected_denial: Some(GcpDenial::NetworkBlocked),
    });
    fixture.instance["settings"]["ipConfiguration"]["serverCaMode"] =
        json!("GOOGLE_MANAGED_CAS_CA");
    write_json(&fixture.root.join("instance.json"), &fixture.instance);
    let capture = live::probe(
        &fixture.config,
        &fixture.tools,
        "shared-ca-refused",
        CancellationToken::new(),
        Instant::now() + Duration::from_secs(15),
    )
    .await
    .unwrap();
    let direct = &capture.observations[1];
    assert_eq!(direct.execution, GcpExecution::NotRun);
    assert_eq!(direct.observed, GcpAccess::Unknown);
    assert!(!direct.proof.credential_issued);
    assert!(!direct.proof.network_rejection_explicit);
    assert!(!direct.proof.ca_verified);
    assert_eq!(fs::read_dir(&fixture.tools.work_dir).unwrap().count(), 0);
    fixture.pids_absent();
}

#[tokio::test]
async fn unexpected_sql_user_or_database_keeps_allowed_without_persisting_freeform_identity() {
    for marker in ["wrong-user", "wrong-database"] {
        let mut fixture = Fixture::new();
        fixture.config.cases.truncate(1);
        fs::write(fixture.root.join(marker), b"1").unwrap();
        let capture = live::probe(
            &fixture.config,
            &fixture.tools,
            marker,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(15),
        )
        .await
        .unwrap();
        let observation = &capture.observations[0];
        assert_eq!(observation.observed, GcpAccess::Allowed);
        assert!(observation.proof.sql_authenticated);
        assert!(!observation.proof.sql_ok);
        if marker == "wrong-user" {
            assert!(observation.proof.db_user.is_none());
        } else {
            assert!(observation.proof.database.is_none());
        }
        config::validate_evidence(&fixture.config, &capture).unwrap();
        let serialized = serde_json::to_string(&capture).unwrap();
        assert!(!serialized.contains("SENTINEL_UNEXPECTED_"));
        let assessment = veil_db_guard::gcp::evaluate::evaluate(
            &fixture.config,
            &[capture],
            &[],
            veil_db_guard::domain::now(),
        );
        assert_eq!(assessment.cases[0].observed, GcpAccess::Allowed);
        assert_eq!(assessment.cases[0].verdict, GcpVerdict::Unknown);
        assert_eq!(assessment.cases[0].reason, GcpReason::IdentityMismatch);
        assert!(!assessment.protected);
        fixture.pids_absent();
    }
}
