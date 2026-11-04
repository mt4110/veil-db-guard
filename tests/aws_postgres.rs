use aws_credential_types::Credentials;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio_util::sync::CancellationToken;
use veil_db_guard::{
    adapters::{
        deployment::aws::generation_fingerprint,
        engine::postgres::{aws::*, *},
    },
    core::policy::*,
    domain::Endpoint,
};

const ACCOUNT: &str = "123456789012";
const REGION: &str = "ap-northeast-1";
const RECOVERY_ARN: &str = "arn:aws:iam::123456789012:role/operators/recovery";
const RECOVERY_ID: &str = "AROARECOVERY000000000";
const PROXY_ROLE: &str = "arn:aws:iam::123456789012:role/proxy";
const PROXY_ROLE_ID: &str = "AROAPROXY000000000000";
const DB_ARN: &str = "arn:aws:rds:ap-northeast-1:123456789012:db:billing";
const PROXY_ARN: &str = "arn:aws:rds:ap-northeast-1:123456789012:db-proxy:prx-REGISTERED";
const DB_HOST: &str = "billing.abcd.ap-northeast-1.rds.amazonaws.com";
const PROXY_HOST: &str = "billing.proxy-abcd.ap-northeast-1.rds.amazonaws.com";

fn policy() -> PolicyRevision {
    let mut p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    p.subjects[0].identity.provider = IdentityProvider::Aws;
    p.subjects[0].identity.principal = "arn:aws:iam::123456789012:role/app".into();
    p.subjects[0].identity.immutable_id = Some("AROAAPP00000000000000".into());
    p.subjects[1].identity.provider = IdentityProvider::Aws;
    p.subjects[1].identity.principal = RECOVERY_ARN.into();
    p.subjects[1].identity.immutable_id = Some(RECOVERY_ID.into());
    let t = &mut p.targets[0];
    t.placement = PlacementRef {
        kind: PlacementKind::AwsRds,
        account_id: ACCOUNT.into(),
        region: REGION.into(),
    };
    t.resource.native_id = DB_ARN.into();
    t.resource.generation_fingerprint = Some(generation_fingerprint(
        ACCOUNT,
        REGION,
        DB_ARN,
        "db-IMMUTABLE",
    ));
    t.managed_surface.fields = vec![
        ManagedField::AwsIamBinding,
        ManagedField::AwsProxy,
        ManagedField::AwsSecurityGroupRule,
        ManagedField::DbLogin,
        ManagedField::DbRole,
        ManagedField::DbObjectPrivilege,
        ManagedField::ApplicationBinding,
    ];
    t.managed_surface.db_identities[0] = "billing_app".into();
    t.aws = Some(AwsRdsBinding {
        db_resource_id: "db-IMMUTABLE".into(),
        db_endpoint: DB_HOST.into(),
        proxy_name: "billing-proxy".into(),
        proxy_arn: PROXY_ARN.into(),
        proxy_endpoint: PROXY_HOST.into(),
        proxy_role_arn: PROXY_ROLE.into(),
        proxy_role_id: PROXY_ROLE_ID.into(),
        proxy_policy_name: "vdg-proxy".into(),
        proxy_security_group_id: "sg-proxy".into(),
        db_security_group_id: "sg-database".into(),
        managed_policy_name: "vdg-app".into(),
        management_db_identity: "recovery_login".into(),
        owned_direct_rules: vec![],
    });
    p.grants[0].db_identity = "billing_app".into();
    p.protection_profiles[0].kind = ProfileKind::AwsRdsPostgresProxyV1;
    for route in &mut p.protection_profiles[0].allowed_routes {
        route.kind = RouteKind::NativeProxy;
    }
    p.validate().unwrap();
    p
}

fn binding() -> AwsPgTargetBinding {
    AwsPgTargetBinding {
        db_instance_arn: DB_ARN.into(),
        dbi_resource_id: "db-IMMUTABLE".into(),
        db_endpoint: Endpoint {
            host: DB_HOST.into(),
            port: 5432,
        },
        database: "billing".into(),
        management_endpoint: Endpoint {
            host: PROXY_HOST.into(),
            port: 5432,
        },
        proxy_arn: Some(PROXY_ARN.into()),
        proxy_name: Some("billing-proxy".into()),
        proxy_role_arn: Some(PROXY_ROLE.into()),
        proxy_role_id: Some(PROXY_ROLE_ID.into()),
    }
}
fn management() -> AwsPgManagementIdentity {
    AwsPgManagementIdentity {
        role_arn: RECOVERY_ARN.into(),
        role_id: RECOVERY_ID.into(),
        db_username: "recovery_login".into(),
    }
}

struct FakeIssuer {
    calls: AtomicUsize,
    wrong_role: bool,
    wrong_target: bool,
    expired: bool,
}
impl AwsPgAuthProvider for FakeIssuer {
    fn authenticate<'a>(&'a self, target: &'a AwsPgTargetBinding) -> AwsPgAuthenticationFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut target = target.clone();
            if self.wrong_target {
                target.dbi_resource_id = "db-RECREATED".into();
            }
            Ok(AwsPgAuthentication {
                credentials: Credentials::new(
                    "TESTACCESS",
                    "test-secret",
                    Some("test-session".into()),
                    self.expired.then_some(SystemTime::UNIX_EPOCH),
                    "local-fake",
                ),
                role_arn: RECOVERY_ARN.into(),
                role_id: if self.wrong_role {
                    "AROARECREATED000000000".into()
                } else {
                    RECOVERY_ID.into()
                },
                target,
            })
        })
    }
}
fn issuer() -> Arc<FakeIssuer> {
    Arc::new(FakeIssuer {
        calls: AtomicUsize::new(0),
        wrong_role: false,
        wrong_target: false,
        expired: false,
    })
}
fn transport(
    p: &PolicyRevision,
    b: AwsPgTargetBinding,
    auth: Arc<dyn AwsPgAuthProvider>,
) -> Result<AwsRdsPgTransport, PgError> {
    AwsRdsPgTransport::new(
        p.targets[0].clone(),
        b,
        management(),
        auth,
        TEST_CA.as_bytes(),
        Duration::from_secs(2),
    )
}

#[test]
fn construction_is_local_and_tls_settings_preserve_registered_hostname_and_login() {
    let auth = issuer();
    let transport = transport(&policy(), binding(), auth.clone()).unwrap();
    assert_eq!(auth.calls.load(Ordering::SeqCst), 0);
    let config = transport.connection_settings();
    assert_eq!(
        config.get_hosts(),
        &[tokio_postgres::config::Host::Tcp(PROXY_HOST.into())]
    );
    assert_eq!(
        config.get_ssl_mode(),
        tokio_postgres::config::SslMode::Require
    );
    assert_eq!(config.get_user(), Some("recovery_login"));
    assert_eq!(config.get_dbname(), Some("billing"));
    assert!(config.get_password().is_none());
}

#[test]
fn constructor_rejects_recreated_database_foreign_endpoint_and_untrusted_ca() {
    let p = policy();
    let mut wrong = binding();
    wrong.dbi_resource_id = "db-RECREATED".into();
    assert!(matches!(
        transport(&p, wrong, issuer()),
        Err(PgError::Precondition)
    ));
    let mut wrong = binding();
    wrong.management_endpoint.host = "other.example.com".into();
    assert!(matches!(
        transport(&p, wrong, issuer()),
        Err(PgError::Precondition)
    ));
    let mut wrong = p.clone();
    wrong.targets[0].resource.generation_fingerprint = Some("0".repeat(64));
    assert!(matches!(
        transport(&wrong, binding(), issuer()),
        Err(PgError::Precondition)
    ));
    assert!(matches!(
        AwsRdsPgTransport::new(
            p.targets[0].clone(),
            binding(),
            management(),
            issuer(),
            b"not a certificate",
            Duration::from_secs(1)
        ),
        Err(PgError::Precondition)
    ));
    assert!(matches!(
        AwsRdsPgTransport::new(
            p.targets[0].clone(),
            binding(),
            management(),
            issuer(),
            &vec![0; 1_048_577],
            Duration::from_secs(1)
        ),
        Err(PgError::Precondition)
    ));
}

#[test]
fn aws_registration_grants_only_native_iam_membership_to_existing_scoped_login() {
    let p = policy();
    let registration = compile(
        &p,
        "billing-db",
        "billing-access",
        PgAction::RegisterNativeDbIdentity,
    )
    .unwrap();
    assert_eq!(
        registration.statements(),
        &["GRANT \"rds_iam\" TO \"billing_app\" WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"]
    );
    let mut wrong = p.clone();
    wrong.targets[0]
        .managed_surface
        .fields
        .retain(|f| *f != ManagedField::DbLogin);
    assert_eq!(
        compile(
            &wrong,
            "billing-db",
            "billing-access",
            PgAction::RegisterNativeDbIdentity
        ),
        Err(PgError::Scope)
    );
    let mut wrong = p.clone();
    wrong.grants[0].admission = AdmissionIntent::Deny;
    assert!(
        compile(
            &wrong,
            "billing-db",
            "billing-access",
            PgAction::RegisterNativeDbIdentity
        )
        .is_err()
    );
}

#[test]
fn stale_identity_expired_credentials_and_cancel_fail_before_network() {
    let p = policy();
    let batch = compile(
        &p,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    for (wrong_role, wrong_target, expired) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let auth = Arc::new(FakeIssuer {
            calls: AtomicUsize::new(0),
            wrong_role,
            wrong_target,
            expired,
        });
        let mut transport = transport(&p, binding(), auth.clone()).unwrap();
        assert_eq!(transport.execute_atomic(&batch), Err(PgError::Precondition));
        assert_eq!(auth.calls.load(Ordering::SeqCst), 1);
        assert!(transport.owned_receipt().is_none());
    }
    let auth = issuer();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut transport = transport(&p, binding(), auth.clone())
        .unwrap()
        .with_cancel(cancel);
    assert_eq!(transport.query(&batch), Err(PgError::Unavailable));
    assert_eq!(auth.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn batch_from_other_database_is_refused_without_requesting_credentials() {
    let p = policy();
    let batch = compile(
        &p,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let mut other = p.clone();
    other.targets[0].engine.database = "other".into();
    let mut b = binding();
    b.database = "other".into();
    let auth = issuer();
    let mut transport = transport(&other, b, auth.clone()).unwrap();
    assert_eq!(transport.execute_atomic(&batch), Err(PgError::Precondition));
    assert_eq!(auth.calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
fn fake_cli(role_id: &str, dbi: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fake-aws");
    let response = |v: serde_json::Value| format!("printf '%s' '{v}'");
    let export = response(
        json!({"Version":1,"AccessKeyId":"TESTACCESS","SecretAccessKey":"test-secret","SessionToken":"test-session"}),
    );
    let sts = response(
        json!({"Account":ACCOUNT,"Arn":"arn:aws:sts::123456789012:assumed-role/recovery/test-session","UserId":format!("{role_id}:test-session")}),
    );
    let recovery = response(json!({"Role":{"Arn":RECOVERY_ARN,"RoleId":RECOVERY_ID}}));
    let proxy_role = response(json!({"Role":{"Arn":PROXY_ROLE,"RoleId":PROXY_ROLE_ID}}));
    let db = response(
        json!({"DBInstances":[{"DBInstanceArn":DB_ARN,"DbiResourceId":dbi,"Endpoint":{"Address":DB_HOST,"Port":5432},"Engine":"postgres","IAMDatabaseAuthenticationEnabled":true}]}),
    );
    let proxy = response(
        json!({"DBProxies":[{"DBProxyArn":PROXY_ARN,"DBProxyName":"billing-proxy","Endpoint":PROXY_HOST,"RoleArn":PROXY_ROLE,"DefaultAuthScheme":"IAM_AUTH","EngineFamily":"POSTGRESQL","Status":"available","RequireTLS":true}]}),
    );
    let targets = response(
        json!({"Targets":[{"RdsResourceId":"billing","Endpoint":DB_HOST,"Port":5432,"Type":"RDS_INSTANCE","TargetHealth":{"State":"AVAILABLE"}}]}),
    );
    let script = format!(
        r##"#!/bin/sh
set -eu
case "$1 $2" in
  'configure export-credentials')
    [ "$3" = '--profile' ] && [ "$4" = 'explicit-recovery' ]
    [ -z "${{AWS_ACCESS_KEY_ID+x}}" ]
    {export}; exit 0 ;;
esac
[ "$AWS_ACCESS_KEY_ID" = 'TESTACCESS' ]
[ "$AWS_SECRET_ACCESS_KEY" = 'test-secret' ]
[ "$AWS_SESSION_TOKEN" = 'test-session' ]
[ "$AWS_CONFIG_FILE" = '/dev/null' ]
[ "$AWS_SHARED_CREDENTIALS_FILE" = '/dev/null' ]
case "$1 $2" in
  'sts get-caller-identity') {sts} ;;
  'iam get-role') case "$4" in recovery) {recovery} ;; proxy) {proxy_role} ;; *) exit 90 ;; esac ;;
  'rds describe-db-instances') {db} ;;
  'rds describe-db-proxies') {proxy} ;;
  'rds describe-db-proxy-targets') {targets} ;;
  *) exit 91 ;;
esac
"##
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (directory, path)
}

#[cfg(unix)]
#[tokio::test]
async fn fake_cli_authenticates_exact_exported_credentials_and_native_target() {
    let (_dir, path) = fake_cli(RECOVERY_ID, "db-IMMUTABLE");
    let source = AwsCliPgAuthProvider::new(
        path,
        "explicit-recovery".into(),
        RECOVERY_ARN.into(),
        RECOVERY_ID.into(),
        CancellationToken::new(),
    )
    .unwrap();
    let auth = source.authenticate(&binding()).await.unwrap();
    assert_eq!(auth.role_id, RECOVERY_ID);
    assert_eq!(auth.target, binding());
    assert_eq!(auth.credentials.access_key_id(), "TESTACCESS");
    for (role, dbi) in [
        ("AROARECREATED000000000", "db-IMMUTABLE"),
        (RECOVERY_ID, "db-RECREATED"),
    ] {
        let (_dir, path) = fake_cli(role, dbi);
        let source = AwsCliPgAuthProvider::new(
            path,
            "explicit-recovery".into(),
            RECOVERY_ARN.into(),
            RECOVERY_ID.into(),
            CancellationToken::new(),
        )
        .unwrap();
        assert!(matches!(
            source.authenticate(&binding()).await,
            Err(PgError::Precondition)
        ));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn role_credentials_uses_exact_sts_credentials_without_iam_or_rds_permissions() {
    let (_dir, path) = fake_cli(RECOVERY_ID, "db-IMMUTABLE");
    let script = std::fs::read_to_string(&path).unwrap();
    let marker = "case \"$1 $2\" in\n  'sts get-caller-identity')";
    let restricted =
        "case \"$1\" in iam|rds) exit 95;; esac\ncase \"$1 $2\" in\n  'sts get-caller-identity')";
    assert!(script.contains(marker));
    std::fs::write(&path, script.replace(marker, restricted)).unwrap();
    let source = AwsCliPgAuthProvider::new(
        path,
        "explicit-recovery".into(),
        RECOVERY_ARN.into(),
        RECOVERY_ID.into(),
        CancellationToken::new(),
    )
    .unwrap();
    let credentials = source.role_credentials(REGION).await.unwrap();
    assert_eq!(credentials.access_key_id(), "TESTACCESS");
    assert_eq!(credentials.session_token(), Some("test-session"));
    assert!(matches!(
        source.authenticated_credentials(REGION).await,
        Err(PgError::Precondition)
    ));
    assert!(matches!(
        source.authenticate(&binding()).await,
        Err(PgError::Precondition)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn fake_cli_rejects_a_different_sts_session_even_for_the_expected_role() {
    let (_dir, path) = fake_cli(RECOVERY_ID, "db-IMMUTABLE");
    let script = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        script.replace(
            &format!("{RECOVERY_ID}:test-session"),
            &format!("{RECOVERY_ID}:other-session"),
        ),
    )
    .unwrap();
    let source = AwsCliPgAuthProvider::new(
        path,
        "explicit-recovery".into(),
        RECOVERY_ARN.into(),
        RECOVERY_ID.into(),
        CancellationToken::new(),
    )
    .unwrap();
    assert!(matches!(
        source.authenticate(&binding()).await,
        Err(PgError::Precondition)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn fake_cli_rejects_secret_auth_fallback_and_malformed_auth_configuration() {
    for auth in [
        serde_json::json!([{"AuthScheme":"SECRETS","IAMAuth":"DISABLED","SecretArn":"arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:foreign"}]),
        serde_json::json!({}),
        serde_json::json!(null),
        serde_json::json!("invalid"),
    ] {
        let (_dir, path) = fake_cli(RECOVERY_ID, "db-IMMUTABLE");
        let script = std::fs::read_to_string(&path).unwrap();
        let marker = "\"DefaultAuthScheme\":\"IAM_AUTH\"";
        let replacement = format!("{marker},\"Auth\":{auth}");
        assert!(script.contains(marker));
        std::fs::write(&path, script.replace(marker, &replacement)).unwrap();
        let source = AwsCliPgAuthProvider::new(
            path,
            "explicit-recovery".into(),
            RECOVERY_ARN.into(),
            RECOVERY_ID.into(),
            CancellationToken::new(),
        )
        .unwrap();
        assert!(matches!(
            source.authenticate(&binding()).await,
            Err(PgError::Precondition)
        ));
    }
    let (_dir, path) = fake_cli(RECOVERY_ID, "db-IMMUTABLE");
    let script = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        script.replace(
            "\"DefaultAuthScheme\":\"IAM_AUTH\"",
            "\"DefaultAuthScheme\":\"IAM_AUTH\",\"Auth\":[]",
        ),
    )
    .unwrap();
    let source = AwsCliPgAuthProvider::new(
        path,
        "explicit-recovery".into(),
        RECOVERY_ARN.into(),
        RECOVERY_ID.into(),
        CancellationToken::new(),
    )
    .unwrap();
    assert!(source.authenticate(&binding()).await.is_ok());
}

struct PendingAuth;
impl AwsPgAuthProvider for PendingAuth {
    fn authenticate<'a>(&'a self, _: &'a AwsPgTargetBinding) -> AwsPgAuthenticationFuture<'a> {
        Box::pin(std::future::pending())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn cancelled_credential_export_kills_descendants_and_reaps_parent() {
    assert_export_processes_stop(false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn dropped_credential_future_kills_descendants_and_reaps_without_async_cleanup() {
    assert_export_processes_stop(true).await;
}

#[cfg(unix)]
async fn assert_export_processes_stop(drop_future: bool) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-aws");
    let pid_file = directory.path().join("pids");
    // The descendant inherits stdout, reproducing credential_process pipes
    // that remain open while the immediate AWS CLI waits for its subprocess.
    let script = format!(
        "#!/bin/sh\n/bin/sleep 60 &\nchild=$!\nprintf '%s %s\\n' \"$$\" \"$child\" > '{}'\nwait \"$child\"\n",
        pid_file.display()
    );
    std::fs::write(&executable, script).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cancel = CancellationToken::new();
    let source = AwsCliPgAuthProvider::new(
        executable,
        "explicit-recovery".into(),
        RECOVERY_ARN.into(),
        RECOVERY_ID.into(),
        cancel.clone(),
    )
    .unwrap();
    let task = tokio::spawn(async move { source.role_credentials(REGION).await });
    let pids = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(value) = std::fs::read_to_string(&pid_file) {
                let pids = value
                    .split_whitespace()
                    .map(|pid| pid.parse::<i32>().unwrap())
                    .collect::<Vec<_>>();
                if pids.len() == 2 {
                    break pids;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    if drop_future {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    } else {
        cancel.cancel();
        let result = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(PgError::Unavailable)));
        // Explicit async cancellation reaps the direct parent before return.
        assert_eq!(unsafe { libc::kill(pids[0], 0) }, -1);
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while unsafe { libc::kill(pids[0], 0) } != -1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if unsafe { libc::kill(pids[1], 0) } == -1 {
                break;
            }
            // Some Linux container init processes retain orphan zombies. They
            // cannot execute or retain credentials; only init can reap them.
            #[cfg(target_os = "linux")]
            if std::fs::read_to_string(format!("/proc/{}/stat", pids[1])).is_ok_and(|s| {
                s.split_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with('Z'))
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn native_request_deadline_also_bounds_a_pending_credential_source() {
    let p = policy();
    let batch = compile(
        &p,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let mut transport = AwsRdsPgTransport::new(
        p.targets[0].clone(),
        binding(),
        management(),
        Arc::new(PendingAuth),
        TEST_CA.as_bytes(),
        Duration::from_millis(20),
    )
    .unwrap();
    assert_eq!(transport.query(&batch), Err(PgError::Unknown));
    assert!(transport.owned_receipt().is_none());
}

const TEST_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUQ0Ts0fvXpMAvrIbLv8MZpkbFSTIwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPbG9jYWwtdGVzdC1yb290MB4XDTI2MTEwMjA5MDM0MFoX
DTM2MTAzMDA5MDM0MFowGjEYMBYGA1UEAwwPbG9jYWwtdGVzdC1yb290MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzT6G33JCMGwAd3+FJPtL+bqmpnd+
fWr20oBC4yOPFd87bsxuaD4a4ifd/B+W/dUOrbQJ4kx/QjNOG3r9nyF46RUc3+Gb
sxJXGAna1v6ZmqcNOARCzjNN7ORROZ41Wg0UXuLTcA5sp2KFK8kRRwR/lCHQ23rf
TTgc4YNHrYU1bP/Phed8D80McN3Mo6c4WVyGrmek73jcDbxR1o/G/oEByEoEeqCp
47ymEqbzIyxq+lxtmI5hPlF6UXgo9G5WR6UJhKJ4etPdwxObUar0v/iJg4FBLTG3
Tr9lGJ/PPmyyJS3ZsKbD7lGfEF2rUxj+nUM42LJ6mRPTWSgzFLjCDPLQlQIDAQAB
o1MwUTAdBgNVHQ4EFgQUt+YoIBUADh00wfm2XDpY6a5bp5QwHwYDVR0jBBgwFoAU
t+YoIBUADh00wfm2XDpY6a5bp5QwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAputaS4tu+oPFxcWFRLGGMdtITtRVVKQVxjt4RwB9b9p17KdOJzya
Kv2Za75HTQIjzvYOnNBZ+/rslVXaOoYLdBS4fUkC4C5a7onCA2I6ynmxyZtLKBXN
urhbc7+jNBXiLvKPRDCe9RqLk2GhQ31oF/tTKx+DLF0eJY/IgD+YvYOUyVwDo/Fb
HWUv+PypSS0mgg153fhMbDs3xNa36EILOBG/CO8lhnBX0SZOqZ6qGWIqm2IuMrwS
/72z56i6lxmGl4fsBQZgWB/zLs/W8SYjHPDEsxu9i9OZ2lnoHl3rW3Ll/xvq0R9P
TdwEmjO8LuAKefPAncTdBFZ8w8SuESW5Wg==
-----END CERTIFICATE-----
"#;
