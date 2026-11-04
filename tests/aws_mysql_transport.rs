//! Local-only transport checks. No AWS executable, DNS lookup, or DB is used.
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
        engine::mysql::{aws::*, *},
    },
    core::policy::*,
    domain::Endpoint,
};

fn policy() -> PolicyRevision {
    let mut p = parse_policy(include_str!("../examples/core-aws-policy.yaml")).unwrap();
    let t = &mut p.targets[0];
    t.engine.family = EngineFamily::MySql;
    t.engine.version = "8.0.43".into();
    t.mysql = Some(MysqlTargetBinding {
        account_host: "%".into(),
        management_account_host: "%".into(),
    });
    t.managed_surface
        .fields
        .retain(|f| *f != ManagedField::DbRole);
    t.managed_surface.db_identities = vec!["billing_app".into()];
    t.managed_surface.sql_scopes[0].kind = SqlObjectKind::Table;
    t.managed_surface.sql_scopes[0].object = Some("invoices".into());
    let aws = t.aws.as_mut().unwrap();
    aws.owned_direct_rules.clear();
    t.resource.generation_fingerprint = Some(generation_fingerprint(
        &t.placement.account_id,
        &t.placement.region,
        &t.resource.native_id,
        &aws.db_resource_id,
    ));
    p.grants[0].sql_access.existing_roles.clear();
    p.protection_profiles[0].kind = ProfileKind::AwsRdsMysqlProxyV1;
    p.validate().unwrap();
    p
}
fn binding(p: &PolicyRevision) -> AwsMysqlTargetBinding {
    let t = &p.targets[0];
    let a = t.aws.as_ref().unwrap();
    AwsMysqlTargetBinding {
        db_instance_arn: t.resource.native_id.clone(),
        dbi_resource_id: a.db_resource_id.clone(),
        db_endpoint: Endpoint {
            host: a.db_endpoint.clone(),
            port: 3306,
        },
        database: t.engine.database.clone(),
        management_endpoint: Endpoint {
            host: a.proxy_endpoint.clone(),
            port: 3306,
        },
        proxy_arn: Some(a.proxy_arn.clone()),
        proxy_name: Some(a.proxy_name.clone()),
        proxy_role_arn: Some(a.proxy_role_arn.clone()),
        proxy_role_id: Some(a.proxy_role_id.clone()),
    }
}
fn management() -> AwsMysqlManagementIdentity {
    AwsMysqlManagementIdentity {
        role_arn: "arn:aws:iam::123456789012:role/veil-recovery".into(),
        role_id: "AROA00000000000000002".into(),
        db_username: "veil_recovery".into(),
    }
}
struct FakeAuth {
    calls: AtomicUsize,
    wrong_role: bool,
    wrong_target: bool,
    expired: bool,
    pending: bool,
}
impl AwsMysqlAuthProvider for FakeAuth {
    fn authenticate<'a>(
        &'a self,
        target: &'a AwsMysqlTargetBinding,
    ) -> AwsMysqlAuthenticationFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.pending {
                std::future::pending::<()>().await;
            }
            let mut b = target.clone();
            if self.wrong_target {
                b.dbi_resource_id = "db-RECREATED".into();
            }
            let m = management();
            Ok(AwsMysqlAuthentication {
                credentials: Credentials::new(
                    "LOCALACCESS",
                    "local-secret",
                    Some("local-session".into()),
                    self.expired.then_some(SystemTime::UNIX_EPOCH),
                    "local-test",
                ),
                role_arn: m.role_arn,
                role_id: if self.wrong_role {
                    "AROARECREATED000000000".into()
                } else {
                    m.role_id
                },
                target: b,
            })
        })
    }
}
fn auth() -> Arc<FakeAuth> {
    Arc::new(FakeAuth {
        calls: AtomicUsize::new(0),
        wrong_role: false,
        wrong_target: false,
        expired: false,
        pending: false,
    })
}
fn transport(
    p: &PolicyRevision,
    b: AwsMysqlTargetBinding,
    a: Arc<dyn AwsMysqlAuthProvider>,
    timeout: Duration,
) -> Result<AwsRdsMysqlTransport, MysqlError> {
    AwsRdsMysqlTransport::new(
        p.targets[0].clone(),
        b,
        management(),
        a,
        CA.as_bytes(),
        timeout,
    )
}
fn batch(p: &PolicyRevision) -> SqlBatch {
    compile(
        p,
        "billing-db",
        "billing-access",
        MysqlAction::ConfigureSqlPrivileges,
    )
    .unwrap()
}

#[test]
fn construction_is_local_and_exposes_only_strict_secret_free_options() {
    let p = policy();
    let a = auth();
    let t = transport(&p, binding(&p), a.clone(), Duration::from_secs(1)).unwrap();
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    let opts = t.connection_settings();
    let ssl = opts.ssl_opts().unwrap();
    assert_eq!(
        opts.ip_or_hostname(),
        p.targets[0].aws.as_ref().unwrap().proxy_endpoint
    );
    assert_eq!(opts.tcp_port(), 3306);
    assert_eq!(opts.user(), Some("veil_recovery"));
    assert_eq!(opts.db_name(), Some("billing"));
    assert_eq!(opts.pass(), None);
    assert!(!opts.prefer_socket());
    assert!(opts.socket().is_none());
    assert!(opts.local_infile_handler().is_none());
    assert!(opts.enable_cleartext_plugin());
    assert_eq!(opts.max_allowed_packet(), Some(1024 * 1024));
    assert!(ssl.disable_built_in_roots());
    assert!(!ssl.accept_invalid_certs());
    assert!(!ssl.skip_domain_validation());
    assert!(ssl.tls_hostname_override().is_none());
    assert_eq!(ssl.root_certs().len(), 1);
}

#[test]
fn rejects_unapproved_route_engine_generation_ca_and_deadline_locally() {
    let p = policy();
    for b in [
        {
            let mut b = binding(&p);
            b.management_endpoint = b.db_endpoint.clone();
            b
        },
        {
            let mut b = binding(&p);
            b.db_endpoint.port = 5432;
            b
        },
        {
            let mut b = binding(&p);
            b.proxy_role_id = Some("AROAREPLACED000000000".into());
            b
        },
        {
            let mut b = binding(&p);
            b.management_endpoint.host = "127.0.0.1".into();
            b
        },
    ] {
        assert!(matches!(
            transport(&p, b, auth(), Duration::from_secs(1)),
            Err(MysqlError::Precondition)
        ));
    }
    let mut changed = p.clone();
    changed.targets[0].engine.version = "8.0.42".into();
    assert!(matches!(
        transport(&changed, binding(&p), auth(), Duration::from_secs(1)),
        Err(MysqlError::Precondition)
    ));
    changed = p.clone();
    changed.targets[0].resource.generation_fingerprint = Some("recreated".into());
    assert!(matches!(
        transport(&changed, binding(&p), auth(), Duration::from_secs(1)),
        Err(MysqlError::Precondition)
    ));
    for ca in [&b""[..], &b"not-a-certificate"[..]] {
        assert!(matches!(
            AwsRdsMysqlTransport::new(
                p.targets[0].clone(),
                binding(&p),
                management(),
                auth(),
                ca,
                Duration::from_secs(1)
            ),
            Err(MysqlError::Precondition)
        ));
    }
    assert!(matches!(
        transport(&p, binding(&p), auth(), Duration::ZERO),
        Err(MysqlError::Precondition)
    ));
    assert!(matches!(
        transport(&p, binding(&p), auth(), Duration::from_secs(121)),
        Err(MysqlError::Precondition)
    ));
}

#[test]
fn rejects_frozen_role_resource_and_expiry_mismatch_before_network() {
    let p = policy();
    let batch = batch(&p);
    for (wrong_role, wrong_target, expired) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let a = Arc::new(FakeAuth {
            calls: AtomicUsize::new(0),
            wrong_role,
            wrong_target,
            expired,
            pending: false,
        });
        let mut t = transport(&p, binding(&p), a.clone(), Duration::from_secs(1)).unwrap();
        assert_eq!(t.execute(&batch), Err(MysqlError::Precondition));
        assert_eq!(a.calls.load(Ordering::SeqCst), 1);
        assert!(t.owned_receipt().is_none());
    }
}

#[test]
fn cancellation_and_pending_auth_are_bounded_and_produce_no_ownership() {
    let p = policy();
    let batch = batch(&p);
    let a = auth();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut t = transport(&p, binding(&p), a.clone(), Duration::from_secs(1))
        .unwrap()
        .with_cancel(cancel);
    assert_eq!(t.execute(&batch), Err(MysqlError::Unavailable));
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    let a = Arc::new(FakeAuth {
        calls: AtomicUsize::new(0),
        wrong_role: false,
        wrong_target: false,
        expired: false,
        pending: true,
    });
    let mut t = transport(&p, binding(&p), a, Duration::from_millis(20)).unwrap();
    assert_eq!(t.execute(&batch), Err(MysqlError::Unknown));
    assert!(t.owned_receipt().is_none());
}

#[tokio::test]
async fn real_driver_refuses_plaintext_server_before_sending_any_iam_secret() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = vec![10];
        hello.extend_from_slice(b"8.0.43\0");
        hello.extend_from_slice(&1u32.to_le_bytes());
        hello.extend_from_slice(b"12345678\0");
        hello.extend_from_slice(&0x8201u16.to_le_bytes());
        hello.push(45);
        hello.extend_from_slice(&2u16.to_le_bytes());
        hello.extend_from_slice(&8u16.to_le_bytes());
        hello.push(21);
        hello.extend_from_slice(&[0; 10]);
        hello.extend_from_slice(b"abcdefghijkl\0mysql_clear_password\0");
        let len = hello.len();
        let mut packet = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, 0];
        packet.extend_from_slice(&hello);
        stream.write_all(&packet).await.unwrap();
        let mut received = vec![];
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        received
    });
    let p = policy();
    let t = transport(&p, binding(&p), auth(), Duration::from_secs(1)).unwrap();
    // The override exists only in this test, on secret-free review options.
    let opts = mysql_async::OptsBuilder::from_opts(t.connection_settings())
        .resolved_ips(Some(vec!["127.0.0.1".parse().unwrap()]))
        .tcp_port(port)
        .pass(Some("IAM_SECRET_SENTINEL"));
    assert!(mysql_async::Conn::new(opts).await.is_err());
    assert!(
        server.await.unwrap().is_empty(),
        "no authentication response before TLS"
    );
}

#[tokio::test]
async fn read_only_probe_cancellation_and_invalid_target_stay_unknown() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = probe_mysql_iam(
        &Endpoint {
            host: "mysql.example.test".into(),
            port: 3306,
        },
        "billing",
        "8.0.43",
        "billing_app",
        "%",
        "ap-northeast-1",
        Credentials::new(
            "LOCAL",
            "secret",
            Some("session".into()),
            None,
            "local-test",
        ),
        CA.as_bytes(),
        Duration::from_secs(1),
        cancel,
    )
    .await;
    assert_eq!(result, MysqlAccessProbe::Unknown);
}

#[cfg(unix)]
#[tokio::test]
async fn fake_cli_binds_one_frozen_sts_role_to_exact_mysql_metadata() {
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use veil_db_guard::adapters::engine::postgres::aws::AwsCliPgAuthProvider;
    let p = policy();
    let b = binding(&p);
    let a = p.targets[0].aws.as_ref().unwrap();
    let m = management();
    for (engine, version, proxy_engine, role_id, success) in [
        ("mysql", "8.0.43", "MYSQL", m.role_id.as_str(), true),
        ("postgres", "8.0.43", "MYSQL", m.role_id.as_str(), false),
        ("mysql", "8.0.42", "MYSQL", m.role_id.as_str(), false),
        ("mysql", "8.0.43", "POSTGRESQL", m.role_id.as_str(), false),
        ("mysql", "8.0.43", "MYSQL", "AROARECREATED000000000", false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("fake-aws");
        let export = json!({"Version":1,"AccessKeyId":"LOCALACCESS","SecretAccessKey":"local-secret","SessionToken":"local-session"});
        let sts = json!({"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/veil-recovery/local-session","UserId":format!("{role_id}:local-session")});
        let recovery = json!({"Role":{"Arn":m.role_arn,"RoleId":m.role_id}});
        let proxy_role = json!({"Role":{"Arn":a.proxy_role_arn,"RoleId":a.proxy_role_id}});
        let db = json!({"DBInstances":[{"DBInstanceArn":b.db_instance_arn,"DbiResourceId":b.dbi_resource_id,"Endpoint":{"Address":b.db_endpoint.host,"Port":3306},"Engine":engine,"EngineVersion":version,"IAMDatabaseAuthenticationEnabled":true}]});
        let proxy = json!({"DBProxies":[{"DBProxyArn":a.proxy_arn,"DBProxyName":a.proxy_name,"Endpoint":a.proxy_endpoint,"RoleArn":a.proxy_role_arn,"DefaultAuthScheme":"IAM_AUTH","EngineFamily":proxy_engine,"Status":"available","RequireTLS":true}]});
        let targets = json!({"Targets":[{"RdsResourceId":"billing-postgres","Endpoint":b.db_endpoint.host,"Port":3306,"Type":"RDS_INSTANCE","TargetHealth":{"State":"AVAILABLE"}}]});
        // All fixture strings are fixed local data, quoted as POSIX shell
        // literals. The fake executable cannot invoke an actual AWS CLI.
        let emit = |v: serde_json::Value| {
            format!("printf '%s' '{}'", v.to_string().replace('\'', "'\\''"))
        };
        let script = format!(
            r#"#!/bin/sh
set -eu
case "$1 $2" in
 'configure export-credentials') {}; exit 0;;
esac
[ "$AWS_ACCESS_KEY_ID" = LOCALACCESS ]
[ "$AWS_SECRET_ACCESS_KEY" = local-secret ]
[ "$AWS_SESSION_TOKEN" = local-session ]
case "$1 $2" in
 'sts get-caller-identity') {};;
 'iam get-role') case "$4" in veil-recovery) {};; veil-proxy-backend) {};; *) exit 90;; esac;;
 'rds describe-db-instances') {};;
 'rds describe-db-proxies') {};;
 'rds describe-db-proxy-targets') {};;
 *) exit 91;;
esac
"#,
            emit(export),
            emit(sts),
            emit(recovery),
            emit(proxy_role),
            emit(db),
            emit(proxy),
            emit(targets)
        );
        std::fs::write(&executable, script).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let auth = AwsCliPgAuthProvider::new(
            executable,
            "explicit-local-fixture".into(),
            m.role_arn.clone(),
            m.role_id.clone(),
            CancellationToken::new(),
        )
        .unwrap();
        let result = AwsMysqlAuthProvider::authenticate(&auth, &b).await;
        assert_eq!(result.is_ok(), success);
        if let Ok(result) = result {
            assert_eq!(result.role_id, m.role_id);
            assert_eq!(result.target, b);
            assert_eq!(result.credentials.access_key_id(), "LOCALACCESS");
        }
    }
}

#[tokio::test]
async fn real_driver_rejects_untrusted_ca_and_wrong_hostname_before_authentication() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::io::{Read, Write};
    for (trusted, expected) in [(true, "NotValidForName"), (false, "UnknownIssuer")] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = vec![10];
            hello.extend_from_slice(b"8.0.43\0");
            hello.extend_from_slice(&1u32.to_le_bytes());
            hello.extend_from_slice(b"12345678\0");
            hello.extend_from_slice(&0x8a01u16.to_le_bytes());
            hello.push(45);
            hello.extend_from_slice(&2u16.to_le_bytes());
            hello.extend_from_slice(&8u16.to_le_bytes());
            hello.push(21);
            hello.extend_from_slice(&[0; 10]);
            hello.extend_from_slice(b"abcdefghijkl\0mysql_clear_password\0");
            let len = hello.len();
            let mut packet = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, 0];
            packet.extend_from_slice(&hello);
            stream.write_all(&packet).unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let size =
                header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
            assert_eq!(size, 32);
            let mut ssl_request = vec![0; size];
            stream.read_exact(&mut ssl_request).unwrap();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from_pem_slice(TLS_CERT.as_bytes()).unwrap()],
                    PrivateKeyDer::from_pem_slice(TLS_KEY.as_bytes()).unwrap(),
                )
                .unwrap();
            let session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(session, stream);
            let mut application = [0; 1024];
            // Certificate rejection must prevent MySQL auth application data.
            assert!(tls.read(&mut application).is_err());
        });
        let p = policy();
        let t = transport(&p, binding(&p), auth(), Duration::from_secs(1)).unwrap();
        let roots = if trusted { TLS_CERT } else { CA };
        let ssl = mysql_async::SslOpts::default()
            .with_disable_built_in_roots(true)
            .with_root_certs(vec![roots.as_bytes().to_vec().into()]);
        let opts = mysql_async::OptsBuilder::from_opts(t.connection_settings())
            .resolved_ips(Some(vec!["127.0.0.1".parse().unwrap()]))
            .tcp_port(port)
            .ssl_opts(Some(ssl))
            .pass(Some("IAM_SECRET_SENTINEL"));
        let error = mysql_async::Conn::new(opts).await.unwrap_err();
        assert!(format!("{error:?}").contains(expected));
        server.join().unwrap();
    }
}

// A public, non-production test fixture key, used only by the loopback server.
const TLS_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIBUjCB+KADAgECAgkAt3w4DrTJVIMwCgYIKoZIzj0EAwIwHTEbMBkGA1UEAwwS
bXlzcWwtdGVzdC5pbnZhbGlkMB4XDTI2MTEwMjA5NTkwMVoXDTM2MTAzMDA5NTkw
MVowHTEbMBkGA1UEAwwSbXlzcWwtdGVzdC5pbnZhbGlkMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAECaRTpk3UnK9OYpVW+HBHasjQr3JFFn/qUSBSQqMhZ38/doxV
H6nHZxbNrWfme1WhEoqCWbjGwnHCB4qDh+XF3aMhMB8wHQYDVR0RBBYwFIISbXlz
cWwtdGVzdC5pbnZhbGlkMAoGCCqGSM49BAMCA0kAMEYCIQClQhjF2bRVpnqJa/DT
cqWfvckSYxIN8/4b87ZkRusJpwIhAKK8T4yO2NrND4fO93apDIdx7fpgGbDQrUK9
LThYzxE/
-----END CERTIFICATE-----
"#;
const TLS_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWnu4VVZnVJpw3zOV
qyjbULNzPqfHo7YXRhJOYaNELkKhRANCAAQJpFOmTdScr05ilVb4cEdqyNCvckUW
f+pRIFJCoyFnfz92jFUfqcdnFs2tZ+Z7VaESioJZuMbCccIHioOH5cXd
-----END PRIVATE KEY-----
"#;

const CA: &str = r#"-----BEGIN CERTIFICATE-----
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
