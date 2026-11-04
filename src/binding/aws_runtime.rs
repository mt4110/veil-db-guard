//! Application connection bundles for the AWS RDS Proxy profiles.
use super::{AppConnectionProfile, BindingError, BindingRoute, connection_profile};
use crate::{
    core::{
        change::PreparedChange,
        policy::{EngineFamily, GrantLifetime, RouteKind, aws_generation_fingerprint, valid_hash},
        source::{
            AwsEc2Identity, AwsMetadataCredential, RegisteredSourceSnapshot, SourcePurpose,
            SourceSnapshotRef,
        },
    },
    domain::Endpoint,
    probe::auth::{SecretToken, sign_iam_token},
};
use aws_credential_types::Credentials;
use mysql_async::prelude::{FromRow, Queryable};
use serde::Serialize;
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;

mod pool;
pub use pool::{
    AwsPoolCheckout, AwsPoolCheckoutSample, AwsPostgresBackendSample,
    AwsPostgresCheckoutObservation, AwsSessionPool, inspect_aws_postgres_transaction,
};

const TOKEN_TTL: Duration = Duration::from_secs(900);
const MIN_CREDENTIAL_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AwsConnectionBundle {
    contract: &'static str,
    change_hash: String,
    profile: AppConnectionProfile,
    engine: EngineFamily,
    source: SourceSnapshotRef,
    source_trust_epoch: u64,
    expected_instance: AwsEc2Identity,
    route_id: String,
    target_generation: String,
    pool_generation: u64,
    lease_expires_at_unix: Option<u64>,
    proxy_ca_sha256: String,
}

impl AwsConnectionBundle {
    pub fn prepare(
        change: &PreparedChange,
        grant_id: &str,
        source_id: &str,
        route_id: &str,
        pool_generation: u64,
        snapshot: &RegisteredSourceSnapshot,
        proxy_ca_sha256: &str,
    ) -> Result<Self, BindingError> {
        change.verify().map_err(|_| BindingError::Invalid)?;
        if change.policy.schema_version != 2 || pool_generation == 0 || !valid_hash(proxy_ca_sha256)
        {
            return Err(BindingError::Invalid);
        }
        let policy = &change.policy;
        let profile = connection_profile(policy, grant_id)?;
        if profile.route != BindingRoute::RdsProxy {
            return Err(BindingError::Unsupported);
        }
        let aws = profile.aws.as_ref().ok_or(BindingError::Invalid)?;
        let target = policy
            .targets
            .iter()
            .find(|t| t.id == profile.target_id)
            .ok_or(BindingError::Invalid)?;
        if !matches!(
            (target.engine.family, target.engine.version.as_str()),
            (EngineFamily::PostgreSql, "16.15") | (EngineFamily::MySql, "8.0.43")
        ) || target.placement.region != "ap-northeast-1"
        {
            return Err(BindingError::Unsupported);
        }
        let native = target.aws.as_ref().ok_or(BindingError::Invalid)?;
        let target_generation = aws_generation_fingerprint(
            &target.placement.account_id,
            &target.placement.region,
            &target.resource.native_id,
            &native.db_resource_id,
        );
        if target.resource.generation_fingerprint.as_deref() != Some(target_generation.as_str()) {
            return Err(BindingError::Pending);
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
                    && r.kind == RouteKind::NativeProxy
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
                    && s.allowed_uses.iter().any(|u| {
                        u.subject_id == profile.subject_id
                            && u.purpose == SourcePurpose::Application
                    })
            })
            .ok_or(BindingError::Invalid)?;
        if !snapshot
            .matches_binding(source)
            .map_err(|_| BindingError::Invalid)?
        {
            return Err(BindingError::Invalid);
        }
        let snapshot = snapshot.aws().ok_or(BindingError::Unsupported)?;
        let actor = snapshot
            .metadata_credential
            .as_ref()
            .ok_or(BindingError::Unsupported)?;
        if actor.role_arn != aws.role_arn
            || actor.role_id != aws.role_id
            || actor.credential_reference != profile.workload_identity_reference
            || snapshot.native_identity.account_id != target.placement.account_id
            || snapshot.native_identity.region != aws.region
        {
            return Err(BindingError::Invalid);
        }
        let lease_expires_at_unix = match grant.lifetime {
            GrantLifetime::Standing => None,
            GrantLifetime::Lease {
                expires_at_unix, ..
            } => Some(expires_at_unix),
        };
        Ok(Self {
            contract: "aws-rds-proxy-app-connection-v1",
            change_hash: change.change_hash.clone(),
            profile,
            engine: target.engine.family,
            source: source.snapshot_ref(),
            source_trust_epoch: snapshot.trust_epoch,
            expected_instance: snapshot.native_identity.clone(),
            route_id: route_id.into(),
            target_generation,
            pool_generation,
            lease_expires_at_unix,
            proxy_ca_sha256: proxy_ca_sha256.into(),
        })
    }

    pub fn digest(&self) -> String {
        super::hash(self)
    }

    /// Match an exported handoff to a bundle reconstructed from trusted inputs.
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

    pub fn profile(&self) -> &AppConnectionProfile {
        &self.profile
    }

    pub fn engine(&self) -> EngineFamily {
        self.engine
    }

    /// Mint a fresh password for a new physical connection using this EC2
    /// instance's credentials. This method performs IMDSv2 and regional STS reads.
    pub async fn mint_native_token(
        &self,
        cancel: &CancellationToken,
    ) -> Result<AwsConnectionToken, BindingError> {
        if cancel.is_cancelled() {
            return Err(BindingError::Pending);
        }
        if !cfg!(target_os = "linux") {
            return Err(BindingError::Unsupported);
        }
        self.check_token_window(SystemTime::now())?;
        let aws = self.profile.aws.as_ref().ok_or(BindingError::Invalid)?;
        let actor = AwsMetadataCredential {
            role_arn: aws.role_arn.clone(),
            role_id: aws.role_id.clone(),
            credential_reference: self.profile.workload_identity_reference.clone(),
        };
        let work = crate::adapters::source::aws_native::authenticate_application(
            &actor,
            &self.expected_instance,
            cancel,
        );
        let credentials = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(BindingError::Pending),
            result = tokio::time::timeout(Duration::from_secs(20), work) =>
                result.map_err(|_| BindingError::Pending)?.map_err(|_| BindingError::Pending)?,
        };
        self.sign_for_connection(credentials, SystemTime::now())
    }

    fn check_token_window(&self, now: SystemTime) -> Result<SystemTime, BindingError> {
        let expires = now.checked_add(TOKEN_TTL).ok_or(BindingError::Invalid)?;
        let expires_at_unix = expires
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| BindingError::Invalid)?
            .as_secs();
        // The fixed signer emits a 15-minute token. Refuse to issue one that
        // would extend beyond the local grant window.
        if self
            .lease_expires_at_unix
            .is_some_and(|lease| expires_at_unix >= lease)
        {
            return Err(BindingError::Pending);
        }
        Ok(expires)
    }

    fn sign_for_connection(
        &self,
        credentials: Credentials,
        now: SystemTime,
    ) -> Result<AwsConnectionToken, BindingError> {
        let expires = self.check_token_window(now)?;
        let credential_expiry = credentials
            .expiry()
            .filter(|expiry| {
                expiry
                    .duration_since(now)
                    .is_ok_and(|remaining| remaining >= MIN_CREDENTIAL_LIFETIME)
            })
            .ok_or(BindingError::Pending)?;
        let aws = self.profile.aws.as_ref().ok_or(BindingError::Invalid)?;
        let token = sign_iam_token(
            credentials,
            &Endpoint {
                host: aws.hostname.clone(),
                port: aws.port,
            },
            &self.profile.database_identity,
            &aws.region,
            now,
        )
        .map_err(|_| BindingError::Pending)?;
        Ok(AwsConnectionToken {
            token,
            expires: expires.min(credential_expiry),
        })
    }

    /// Validate the exact CA bytes selected at bundle construction. The pin is
    /// for the proxy's public-facing certificate chain.
    pub fn proxy_tls_config(&self, ca_pem: &[u8]) -> Result<rustls::ClientConfig, BindingError> {
        self.check_proxy_ca(ca_pem)?;
        crate::adapters::engine::postgres::aws::verified_tls(ca_pem)
            .map_err(|_| BindingError::Invalid)
    }

    fn check_proxy_ca(&self, ca_pem: &[u8]) -> Result<(), BindingError> {
        if ca_pem.is_empty()
            || ca_pem.len() > 1_048_576
            || crate::config::hash_bytes(ca_pem) != self.proxy_ca_sha256
        {
            return Err(BindingError::Invalid);
        }
        Ok(())
    }

    /// Open the selected PostgreSQL proxy endpoint with required hostname and
    /// CA verification and check the database, users, and version on that session.
    pub async fn connect_postgres(
        &self,
        ca_pem: &[u8],
        cancel: &CancellationToken,
    ) -> Result<AwsPostgresSession, BindingError> {
        if self.engine != EngineFamily::PostgreSql {
            return Err(BindingError::Unsupported);
        }
        let tls = self.proxy_tls_config(ca_pem)?;
        let token = self.mint_native_token(cancel).await?;
        let aws = self.profile.aws.as_ref().ok_or(BindingError::Invalid)?;
        let password = token.password().ok_or(BindingError::Pending)?;
        let mut pg = tokio_postgres::Config::new();
        pg.host(&aws.hostname)
            .port(aws.port)
            .dbname(&self.profile.database)
            .user(&self.profile.database_identity)
            .password(password)
            .ssl_mode(tokio_postgres::config::SslMode::Require)
            .connect_timeout(Duration::from_secs(8));
        let work = async {
            let (client, connection) = pg
                .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
                .await
                .map_err(|_| BindingError::Pending)?;
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut session = AwsPostgresSession {
                client,
                task,
                startup_backend_pid: None,
            };
            let row = session.client.query_one(
                "SELECT pg_catalog.current_database()::text, session_user::text, current_user::text, pg_catalog.current_setting('server_version_num')::int, pg_catalog.pg_backend_pid()",
                &[],
            ).await.map_err(|_| BindingError::Pending)?;
            if row.try_get::<_, &str>(0).ok() != Some(self.profile.database.as_str())
                || [1, 2].into_iter().any(|column| {
                    row.try_get::<_, &str>(column).ok()
                        != Some(self.profile.database_identity.as_str())
                })
                || row.try_get::<_, i32>(3).ok() != Some(160015)
            {
                return Err(BindingError::Invalid);
            }
            session.startup_backend_pid = row
                .try_get::<_, i32>(4)
                .ok()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0);
            Ok(session)
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(BindingError::Pending),
            result = tokio::time::timeout(Duration::from_secs(8), work) =>
                result.unwrap_or(Err(BindingError::Pending)),
        }
    }

    /// Open the selected MySQL proxy endpoint with required hostname and CA
    /// verification and check the returned database and account on that session.
    pub async fn connect_mysql(
        &self,
        ca_pem: &[u8],
        cancel: &CancellationToken,
    ) -> Result<AwsMysqlSession, BindingError> {
        use crate::adapters::engine::mysql::aws::{
            connection_options, verified_tls, verify_session_identity,
        };
        if self.engine != EngineFamily::MySql {
            return Err(BindingError::Unsupported);
        }
        self.check_proxy_ca(ca_pem)?;
        let ssl = verified_tls(ca_pem).map_err(|_| BindingError::Invalid)?;
        let aws = self.profile.aws.as_ref().ok_or(BindingError::Invalid)?;
        let account_host = self
            .profile
            .mysql_account_host
            .as_deref()
            .ok_or(BindingError::Invalid)?;
        let token = self.mint_native_token(cancel).await?;
        let password = token.password().ok_or(BindingError::Pending)?;
        let options = connection_options(
            &Endpoint {
                host: aws.hostname.clone(),
                port: aws.port,
            },
            &self.profile.database,
            &self.profile.database_identity,
            ssl,
        );
        let options = mysql_async::OptsBuilder::from_opts(options).pass(Some(password));
        let work = async {
            let mut connection = mysql_async::Conn::new(options)
                .await
                .map_err(|_| BindingError::Pending)?;
            // Required driver TLS covers the client hop. RDS Proxy can omit
            // SSL status variables, which are not a frontend handshake report.
            verify_session_identity(
                &mut connection,
                &self.profile.database,
                "8.0.43",
                &self.profile.database_identity,
                account_host,
            )
            .await
            .map_err(|_| BindingError::Invalid)?;
            Ok(AwsMysqlSession { connection })
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(BindingError::Pending),
            result = tokio::time::timeout(Duration::from_secs(8), work) =>
                result.unwrap_or(Err(BindingError::Pending)),
        }
    }
}

/// The application can supply this password to a driver with verified TLS.
/// Debug stays redacted and the type has no Serialize or Clone implementation.
#[derive(Debug)]
pub struct AwsConnectionToken {
    token: SecretToken,
    expires: SystemTime,
}

impl AwsConnectionToken {
    pub fn expires_at(&self) -> SystemTime {
        self.expires
    }

    pub fn password(&self) -> Option<&str> {
        (SystemTime::now() < self.expires).then(|| self.token.expose())
    }
}

pub struct AwsPostgresSession {
    client: tokio_postgres::Client,
    task: tokio::task::JoinHandle<()>,
    startup_backend_pid: Option<u32>,
}

impl AwsPostgresSession {
    pub fn client(&self) -> &tokio_postgres::Client {
        &self.client
    }
}

impl Drop for AwsPostgresSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `mysql_async::Conn` retains its password-bearing options. Keep the driver
/// private because its Debug output and `opts()` expose those options.
///
/// ```compile_fail
/// use veil_db_guard::binding::aws_runtime::AwsMysqlSession;
/// fn require_debug<T: std::fmt::Debug>() {}
/// require_debug::<AwsMysqlSession>();
/// ```
pub struct AwsMysqlSession {
    connection: mysql_async::Conn,
}

impl AwsMysqlSession {
    pub async fn exec<T: FromRow + Send + 'static>(
        &mut self,
        statement: &str,
        parameters: mysql_async::Params,
    ) -> Result<Vec<T>, BindingError> {
        self.connection
            .exec(statement, parameters)
            .await
            .map_err(|_| BindingError::Pending)
    }

    pub async fn exec_drop(
        &mut self,
        statement: &str,
        parameters: mysql_async::Params,
    ) -> Result<(), BindingError> {
        self.connection
            .exec_drop(statement, parameters)
            .await
            .map_err(|_| BindingError::Pending)
    }

    pub async fn disconnect(self) -> Result<(), BindingError> {
        self.connection
            .disconnect()
            .await
            .map_err(|_| BindingError::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        change::{OperationLimits, prepare_change},
        plan::build_plan,
        policy::{PolicyRevision, parse_policy},
        source::{AwsHostProfile, AwsSourceRegistrationSnapshot, SourceBoundaryKind},
    };

    fn policy(engine: EngineFamily) -> PolicyRevision {
        let mut policy = parse_policy(match engine {
            EngineFamily::PostgreSql => include_str!("../../examples/core-aws-policy.yaml"),
            EngineFamily::MySql => include_str!("../../examples/core-aws-mysql-policy.yaml"),
            _ => unreachable!(),
        })
        .unwrap();
        let v2 = parse_policy(include_str!("../../examples/core-policy-v2.yaml")).unwrap();
        policy.schema_version = 2;
        policy.source_bindings = v2.source_bindings;
        for source in &mut policy.source_bindings {
            source.boundary = SourceBoundaryKind::AwsHostNetwork;
        }
        policy.evaluation = v2.evaluation;
        policy.evaluation.as_mut().unwrap().denial_requirements[0].profile_id =
            policy.protection_profiles[0].id.clone();
        let target = &mut policy.targets[0];
        target.resource.generation_fingerprint = Some(aws_generation_fingerprint(
            &target.placement.account_id,
            &target.placement.region,
            &target.resource.native_id,
            &target.aws.as_ref().unwrap().db_resource_id,
        ));
        policy
    }

    fn snapshot(policy: &PolicyRevision) -> AwsSourceRegistrationSnapshot {
        let app = &policy.subjects[0];
        AwsSourceRegistrationSnapshot {
            schema_version: 1,
            registration_id: policy.source_bindings[0].registration_id.clone(),
            trust_epoch: 2,
            native_identity: AwsEc2Identity {
                account_id: policy.targets[0].placement.account_id.clone(),
                region: "ap-northeast-1".into(),
                availability_zone: "ap-northeast-1a".into(),
                instance_id: "i-0123456789abcdef0".into(),
                image_id: "ami-0123456789abcdef0".into(),
                pending_time: "2026-11-03T00:00:00Z".into(),
                private_ip: "10.0.0.10".parse().unwrap(),
            },
            ssh_host_key_digest: "b".repeat(64),
            collector_build_id: "c".repeat(64),
            collector_config_digest: "d".repeat(64),
            network_context_digest: "e".repeat(64),
            execution_user: "root".into(),
            aws_host: AwsHostProfile {
                ssh_ip: "192.0.2.10".parse().unwrap(),
                ssh_port: 22,
                host_key_ed25519_base64: "fixture".into(),
                collector_binary_digest: "f".repeat(64),
                execution_uid: 0,
            },
            metadata_credential: Some(AwsMetadataCredential {
                role_arn: app.identity.principal.clone(),
                role_id: app.identity.immutable_id.clone().unwrap(),
                credential_reference: app.identity.credential_source.reference.clone(),
            }),
        }
    }

    fn change(mut policy: PolicyRevision, snapshot: &RegisteredSourceSnapshot) -> PreparedChange {
        policy.source_bindings[0].revision_digest = snapshot.revision_digest().unwrap();
        let plan = build_plan(
            &policy,
            crate::adapters::capabilities_for_policy(&policy).unwrap(),
            vec![],
            100,
        )
        .unwrap();
        prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap()
    }

    pub(super) fn bundle_for(engine: EngineFamily) -> AwsConnectionBundle {
        let policy = policy(engine);
        let snapshot = snapshot(&policy).into();
        AwsConnectionBundle::prepare(
            &change(policy, &snapshot),
            "billing-access",
            "billing-runtime",
            "app-proxy",
            7,
            &snapshot,
            &"a".repeat(64),
        )
        .unwrap()
    }

    #[test]
    fn both_engines_export_bound_non_secret_profiles() {
        for (engine, port) in [
            (EngineFamily::PostgreSql, 5432),
            (EngineFamily::MySql, 3306),
        ] {
            let bundle = bundle_for(engine);
            let export = serde_json::to_vec(&bundle).unwrap();
            bundle.verify_export(&export).unwrap();
            assert_eq!(bundle.engine(), engine);
            assert_eq!(bundle.profile().aws.as_ref().unwrap().port, port);
            assert_eq!(bundle.digest(), bundle_for(engine).digest());
            let mut altered: serde_json::Value = serde_json::from_slice(&export).unwrap();
            altered["profile"]["aws"]["hostname"] = "unrelated.invalid".into();
            assert!(
                bundle
                    .verify_export(&serde_json::to_vec(&altered).unwrap())
                    .is_err()
            );
            assert!(!String::from_utf8(export).unwrap().contains("X-Amz-"));
        }
    }

    #[test]
    fn foreign_role_and_source_revision_cannot_prepare_a_bundle() {
        let policy = policy(EngineFamily::PostgreSql);
        let snapshot = snapshot(&policy);
        let original = snapshot.clone().into();
        let planned = change(policy.clone(), &original);
        let prepare = |change: &PreparedChange, source: &RegisteredSourceSnapshot| {
            AwsConnectionBundle::prepare(
                change,
                "billing-access",
                "billing-runtime",
                "app-proxy",
                1,
                source,
                &"a".repeat(64),
            )
        };
        let mut foreign = snapshot.clone();
        foreign.metadata_credential.as_mut().unwrap().role_id = "AROA00000000000000008".into();
        let foreign = foreign.into();
        assert!(prepare(&planned, &foreign).is_err());
        assert!(prepare(&change(policy, &foreign), &foreign).is_err());
        assert!(matches!(
            AwsConnectionBundle::prepare(
                &planned,
                "billing-access",
                "billing-runtime",
                "recovery-proxy",
                1,
                &original,
                &"a".repeat(64)
            ),
            Err(BindingError::Invalid)
        ));
    }

    #[test]
    fn token_signing_uses_pinned_proxy_scope_and_stays_within_credential_window() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let credentials = |remaining: u64| {
            Credentials::new(
                "ASIAEXAMPLE0000000001",
                "fixture-secret",
                Some("fixture-session".into()),
                Some(now + Duration::from_secs(remaining)),
                "offline-fixture",
            )
        };
        for engine in [EngineFamily::PostgreSql, EngineFamily::MySql] {
            let mut bundle = bundle_for(engine);
            let token = bundle.sign_for_connection(credentials(120), now).unwrap();
            let url = url::Url::parse(&format!("https://{}", token.token.expose())).unwrap();
            let aws = bundle.profile().aws.as_ref().unwrap();
            assert_eq!(url.host_str(), Some(aws.hostname.as_str()));
            assert_eq!(url.port(), Some(aws.port));
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "DBUser"
                        && value == bundle.profile().database_identity)
            );
            assert!(
                url.query_pairs()
                    .any(|(key, value)| key == "X-Amz-Credential"
                        && value.contains("/ap-northeast-1/rds-db/"))
            );
            assert_eq!(token.expires_at(), now + Duration::from_secs(120));
            assert!(!format!("{token:?}").contains("fixture-session"));
            assert!(bundle.sign_for_connection(credentials(59), now).is_err());
            bundle.lease_expires_at_unix = Some(1_800_000_899);
            assert!(bundle.sign_for_connection(credentials(1200), now).is_err());
        }
    }

    #[tokio::test]
    async fn rejected_tls_or_cancelled_token_request_stops_before_native_io() {
        let pg = bundle_for(EngineFamily::PostgreSql);
        let mysql = bundle_for(EngineFamily::MySql);
        let cancel = CancellationToken::new();
        assert!(matches!(
            pg.connect_postgres(b"untrusted", &cancel).await,
            Err(BindingError::Invalid)
        ));
        assert!(matches!(
            mysql.connect_postgres(b"untrusted", &cancel).await,
            Err(BindingError::Unsupported)
        ));
        assert!(matches!(
            mysql.connect_mysql(b"untrusted", &cancel).await,
            Err(BindingError::Invalid)
        ));
        assert!(matches!(
            pg.connect_mysql(b"untrusted", &cancel).await,
            Err(BindingError::Unsupported)
        ));
        cancel.cancel();
        assert!(matches!(
            pg.mint_native_token(&cancel).await,
            Err(BindingError::Pending)
        ));
    }
}
