//! Opt-in EC2 metadata-only MySQL observations. A fresh IAM connection uses a
//! pinned IP/hostname and CA; only fixed read-only catalog queries are issued.
//! Negative information-schema lookups alone are never absence evidence. A
//! bounded, repeated SHOW GRANTS role closure can prove named-action absence.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[path = "aws_mysql_inventory.rs"]
mod inventory;
pub use super::aws_native::{AwsDatabaseTarget as AwsMysqlTarget, CA_PATH};
use super::{
    aws_native::*,
    gce_host::{CollectorEndpoint, SourceError},
};
use crate::{
    core::{
        admission::IssuedObservation, evidence::*, policy::*, source::AwsMetadataCredential,
        state::*,
    },
    domain::Endpoint,
};
use mysql_async::{Conn, Opts, OptsBuilder, SslOpts, prelude::Queryable};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsMysqlConfig {
    pub ca_sha256: String,
    pub targets: Vec<AwsMysqlTarget>,
    /// Optional current-backend status read, separately pinned by config hash.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collect_backend_tls: bool,
}
impl AwsMysqlConfig {
    pub(super) fn validate(&self, i: &IssuedObservation) -> Result<(), SourceError> {
        validate_config(i, &self.ca_sha256, &self.targets, EngineFamily::MySql)?;
        if i.request.cases.iter().any(|c| {
            c.address.target.engine_binding.family == EngineFamily::MySql
                && !c
                    .mysql_account_host
                    .as_deref()
                    .is_some_and(mysql_account_host)
        }) {
            return Err(SourceError::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MysqlCatalog {
    login_user: String,
    current_account: String,
    database: String,
    version: String,
    lower_case_table_names: u64,
    tls_cipher_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend_tls_cipher: Option<String>,
    partial_revokes: bool,
    active_roles: Vec<MysqlRole>,
    roles_complete: bool,
    /// Positive matching static privilege only. Absence stays unconfirmed.
    privilege_present: Option<bool>,
    object_exists: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inventory: Option<inventory::Inventory>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MysqlRole {
    user: String,
    host: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AwsMysqlObservation {
    pub case_id: String,
    stage: Stage,
    connected: bool,
    error_code: Option<u16>,
    actor: Option<AwsMetadataCredential>,
    before: Option<Metadata>,
    after: Option<Metadata>,
    catalog: Option<MysqlCatalog>,
}
fn safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && !s.chars().any(char::is_control)
        && !s.contains("://")
        && !s.contains("${")
        && !s.contains("{{")
        && !["password=", "pwd=", "token=", "secret="]
            .iter()
            .any(|x| s.to_ascii_lowercase().contains(x))
}
fn verified_tls(ca: &[u8]) -> Result<SslOpts, SourceError> {
    let certs = CertificateDer::pem_slice_iter(ca)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SourceError::Invalid)?;
    if certs.is_empty() {
        return Err(SourceError::Invalid);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|_| SourceError::Invalid)?;
    }
    Ok(SslOpts::default()
        .with_root_certs(vec![ca.to_vec().into()])
        .with_disable_built_in_roots(true))
}
fn options(c: &RequestedCase, e: &CollectorEndpoint, ssl: SslOpts) -> Opts {
    OptsBuilder::default()
        .ip_or_hostname(&c.endpoint)
        .resolved_ips(Some(vec![e.ip]))
        .tcp_port(c.port)
        .user(Some(c.address.db_identity.clone()))
        .db_name(Some(c.address.target.engine_binding.database.clone()))
        .ssl_opts(Some(ssl))
        .prefer_socket(false)
        .socket::<String>(None)
        .enable_cleartext_plugin(true)
        .max_allowed_packet(Some(1024 * 1024))
        .wait_timeout(Some(15))
        .stmt_cache_size(0)
        .connect_attributes(std::collections::HashMap::<String, String>::new())
        .into()
}
fn error_code(error: &mysql_async::Error) -> Option<u16> {
    if let mysql_async::Error::Server(e) = error {
        Some(e.code)
    } else {
        None
    }
}
#[cfg(unix)]
pub(super) async fn observe(
    i: &IssuedObservation,
    c: &RequestedCase,
    e: &CollectorEndpoint,
    config: &AwsMysqlConfig,
    cancel: &CancellationToken,
) -> Result<AwsMysqlObservation, SourceError> {
    config.validate(i)?;
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    let actor = s.metadata_credential.as_ref().ok_or(SourceError::Invalid)?;
    let t = config
        .targets
        .iter()
        .find(|t| t.target_id == c.address.target_id)
        .ok_or(SourceError::Invalid)?;
    let mut out = AwsMysqlObservation {
        case_id: c.id.clone(),
        stage: Stage::Credential,
        connected: false,
        error_code: None,
        actor: None,
        before: None,
        after: None,
        catalog: None,
    };
    let budget = i
        .request
        .expires_at
        .saturating_sub(crate::domain::now())
        .saturating_sub(12)
        .min(35);
    if budget == 0 {
        out.stage = Stage::Deadline;
        return Ok(out);
    }
    let work = async {
        let creds = authenticate(actor, &s.native_identity.account_id, cancel).await?;
        out.actor = Some(actor.clone());
        out.stage = Stage::TargetMetadata;
        out.before = Some(metadata(&creds, t, EngineFamily::MySql, cancel).await?);
        let ca = pinned_ca(&config.ca_sha256)?;
        let ssl = verified_tls(&ca)?;
        let token = crate::probe::auth::sign_iam_token(
            creds.clone(),
            &Endpoint {
                host: c.endpoint.clone(),
                port: c.port,
            },
            &c.address.db_identity,
            "ap-northeast-1",
            SystemTime::now(),
        )
        .map_err(|_| SourceError::IdentityUnverified)?;
        let opts = OptsBuilder::from_opts(options(c, e, ssl)).pass(Some(token.expose().to_owned()));
        out.stage = Stage::Connect;
        match tokio::time::timeout(Duration::from_secs(8), Conn::new(opts)).await {
            Ok(Ok(mut conn)) => {
                out.connected = true;
                out.stage = Stage::Catalog;
                match catalog_with_backend(&mut conn, c, config.collect_backend_tls).await {
                    Ok(cat) => {
                        out.catalog = Some(cat);
                        out.stage = Stage::Completed;
                    }
                    Err(error) => {
                        out.error_code = error_code(&error);
                    }
                }
                let _ = conn.disconnect().await;
            }
            Ok(Err(error)) => out.error_code = error_code(&error),
            Err(_) => out.stage = Stage::Deadline,
        }
        out.after = metadata(&creds, t, EngineFamily::MySql, cancel).await.ok();
        Ok(())
    };
    let result = tokio::select! {biased;_=cancel.cancelled()=>return Err(SourceError::Cancelled),r=tokio::time::timeout(Duration::from_secs(budget),work)=>r};
    match result {
        Err(_) => out.stage = Stage::Deadline,
        Ok(Err(SourceError::Integrity)) => return Err(SourceError::Integrity),
        _ => {}
    }
    Ok(out)
}
const SESSION_SQL: &str = "SELECT USER(), CURRENT_USER(), DATABASE(), VERSION(), @@lower_case_table_names, @@partial_revokes";
const TLS_SQL: &str = "SHOW SESSION STATUS LIKE 'Ssl_cipher'";
const ROLES_SQL: &str = "SELECT ROLE_NAME, ROLE_HOST FROM information_schema.ENABLED_ROLES ORDER BY ROLE_NAME, ROLE_HOST LIMIT 129";
const GLOBAL_PRIVILEGE_SQL: &str = "SELECT 1 FROM information_schema.USER_PRIVILEGES WHERE BINARY GRANTEE = BINARY ? AND PRIVILEGE_TYPE = ? LIMIT 1";
const SCHEMA_PRIVILEGE_SQL: &str = "SELECT 1 FROM information_schema.SCHEMA_PRIVILEGES WHERE BINARY GRANTEE = BINARY ? AND BINARY TABLE_SCHEMA = BINARY ? AND PRIVILEGE_TYPE = ? LIMIT 1";
const TABLE_PRIVILEGE_SQL: &str = "SELECT 1 FROM information_schema.TABLE_PRIVILEGES WHERE BINARY GRANTEE = BINARY ? AND BINARY TABLE_SCHEMA = BINARY ? AND BINARY TABLE_NAME = BINARY ? AND PRIVILEGE_TYPE = ? LIMIT 1";
const TABLE_EXISTS_SQL: &str = "SELECT 1 FROM information_schema.TABLES WHERE BINARY TABLE_SCHEMA = BINARY ? AND BINARY TABLE_NAME = BINARY ? AND TABLE_TYPE = 'BASE TABLE' LIMIT 1";
#[cfg(test)]
async fn catalog(conn: &mut Conn, c: &RequestedCase) -> Result<MysqlCatalog, mysql_async::Error> {
    catalog_with_backend(conn, c, false).await
}
async fn catalog_with_backend(
    conn: &mut Conn,
    c: &RequestedCase,
    collect_backend: bool,
) -> Result<MysqlCatalog, mysql_async::Error> {
    conn.query_drop("SET SESSION MAX_EXECUTION_TIME=3000")
        .await?;
    let mut opts = mysql_async::TxOpts::default();
    opts.with_readonly(true);
    let mut tx = conn.start_transaction(opts).await?;
    let (login, current, db, version, case, partial_revokes): (
        String,
        String,
        String,
        String,
        u64,
        bool,
    ) = tx
        .query_first(SESSION_SQL)
        .await?
        .ok_or(mysql_async::Error::Driver(
            mysql_async::DriverError::ConnectionClosed,
        ))?;
    let tls: Option<(String, String)> = tx.query_first(TLS_SQL).await?;
    let roles: Vec<(String, String)> = tx.query(ROLES_SQL).await?;
    let backend_tls_cipher = if collect_backend {
        tx.query_first::<mysql_async::Row,_>("SELECT s.VARIABLE_VALUE FROM performance_schema.status_by_thread s JOIN performance_schema.threads t ON t.THREAD_ID=s.THREAD_ID WHERE t.PROCESSLIST_ID=CONNECTION_ID() AND s.VARIABLE_NAME='Ssl_cipher' LIMIT 1").await.ok().flatten().and_then(|row| mysql_async::from_row_opt::<Option<String>>(row).ok().flatten())
    } else {
        None
    };
    let mut selected = MysqlCatalog {
        backend_tls_cipher,
        login_user: login,
        current_account: current,
        database: db,
        version,
        lower_case_table_names: case,
        partial_revokes,
        tls_cipher_present: tls.is_some_and(|(k, v)| k == "Ssl_cipher" && !v.is_empty()),
        roles_complete: roles.len() <= 128,
        active_roles: roles
            .into_iter()
            .take(128)
            .map(|(user, host)| MysqlRole { user, host })
            .collect(),
        privilege_present: None,
        object_exists: None,
        inventory: None,
    };
    if let EffectKindV2::EffectiveSqlPrivilege { scope, action } = &c.address.effect {
        let privilege = match action {
            SqlAction::Read => Some("SELECT"),
            SqlAction::Insert => Some("INSERT"),
            SqlAction::Update => Some("UPDATE"),
            SqlAction::Delete => Some("DELETE"),
            _ => None,
        };
        if !partial_revokes
            && scope.kind == SqlObjectKind::Table
            && scope.database == c.address.target.engine_binding.database
            && scope.schema.as_deref() == Some(scope.database.as_str())
            && let (Some(object), Some(privilege)) = (&scope.object, privilege)
        {
            selected.object_exists = Some(
                tx.exec_first::<u8, _, _>(TABLE_EXISTS_SQL, (&scope.database, object))
                    .await?
                    .is_some(),
            );
            let host = c.mysql_account_host.as_deref().unwrap_or("");
            let mut grantees = vec![format!("'{}'@'{}'", c.address.db_identity, host)];
            for role in &selected.active_roles {
                if mysql_db_user(&role.user) && mysql_account_host(&role.host) {
                    grantees.push(format!("'{}'@'{}'", role.user, role.host));
                }
            }
            for grantee in grantees {
                let global: Option<u8> = tx
                    .exec_first(GLOBAL_PRIVILEGE_SQL, (&grantee, privilege))
                    .await?;
                let schema: Option<u8> = tx
                    .exec_first(SCHEMA_PRIVILEGE_SQL, (&grantee, &scope.database, privilege))
                    .await?;
                let table: Option<u8> = tx
                    .exec_first(
                        TABLE_PRIVILEGE_SQL,
                        (&grantee, &scope.database, object, privilege),
                    )
                    .await?;
                if global.is_some() || schema.is_some() || table.is_some() {
                    selected.privilege_present = Some(true);
                    break;
                }
            }
            // The negative I_S result is deliberately ignored. SHOW GRANTS
            // must independently cover current, mandatory and inactive roles.
            if selected.object_exists == Some(true) && selected.privilege_present != Some(true) {
                selected.inventory = inventory::capture(
                    &mut tx,
                    &MysqlRole {
                        user: c.address.db_identity.clone(),
                        host: host.into(),
                    },
                )
                .await;
            }
        }
    }
    tx.rollback().await?;
    Ok(selected)
}
pub(super) fn normalize(
    i: &IssuedObservation,
    c: &RequestedCase,
    start: u64,
    finish: u64,
    p: &AwsMysqlObservation,
    proof: &str,
) -> Result<(ObservationClaim, ClaimAssurance), SourceError> {
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    let host = c
        .mysql_account_host
        .as_deref()
        .filter(|h| mysql_account_host(h))
        .ok_or(SourceError::Invalid)?;
    if p.case_id != c.id
        || c.kind == FixedObservationCase::DirectPath
        || c.address.target.engine_binding.family != EngineFamily::MySql
        || c.address.target.engine_binding.version != "8.0.43"
        || (p.catalog.is_some() && !p.connected)
        || p.actor
            .as_ref()
            .is_some_and(|a| Some(a) != s.metadata_credential.as_ref())
    {
        return Err(SourceError::Invalid);
    }
    if p.before.iter().chain(p.after.iter()).any(|m| {
        [
            &m.db_arn,
            &m.db_resource_id,
            &m.db_endpoint,
            &m.engine_version,
            &m.proxy_arn,
            &m.proxy_endpoint,
            &m.target_resource_name,
            &m.target_endpoint,
        ]
        .iter()
        .any(|v| !safe(v))
    }) {
        return Err(SourceError::Invalid);
    }
    if p.catalog.as_ref().is_some_and(|r| {
        ![&r.login_user, &r.current_account, &r.database, &r.version]
            .iter()
            .all(|v| safe(v))
            || r.backend_tls_cipher.as_ref().is_some_and(|v| {
                v.len() > 128
                    || !v
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            })
            || r.active_roles.len() > 128
            || r.active_roles
                .iter()
                .any(|r| !mysql_db_user(&r.user) || !mysql_account_host(&r.host))
            || r.inventory.as_ref().is_some_and(|v| {
                !v.valid(&MysqlRole {
                    user: c.address.db_identity.clone(),
                    host: host.into(),
                })
            })
    }) {
        return Err(SourceError::Invalid);
    }
    let target = p.before.as_ref().is_some_and(|b| {
        p.after.as_ref() == Some(b)
            && b.db_arn == c.address.target.native_ref.native_id
            && b.engine_version == "8.0.43"
            && b.proxy_endpoint == c.endpoint
            && Some(
                aws_generation_fingerprint(
                    &s.native_identity.account_id,
                    "ap-northeast-1",
                    &b.db_arn,
                    &b.db_resource_id,
                )
                .as_str(),
            ) == c
                .address
                .target
                .native_ref
                .generation_fingerprint
                .as_deref()
    });
    let expected = format!("{}@{host}", c.address.db_identity);
    let session = p.catalog.as_ref().is_some_and(|r| {
        r.login_user
            .rsplit_once('@')
            .is_some_and(|(u, h)| u == c.address.db_identity && !h.is_empty())
            && r.current_account == expected
            && r.database == c.address.target.engine_binding.database
            && r.version == "8.0.43"
            && r.lower_case_table_names == 0
    });
    let principal = p.actor.is_some() && session;
    let channel = target && principal && p.connected;
    let tls = channel && p.catalog.as_ref().is_some_and(|r| r.tls_cipher_present);
    let mut claim = ObservationClaim {
        runtime_capture: None,
        postgres_login_failure: None,
        login_catalog: vec![],
        id: format!("aws-mysql-{}", c.id),
        case_id: c.id.clone(),
        policy_revision_hash: i.request.policy_revision_hash.clone(),
        address: c.address.clone(),
        started_at: start,
        finished_at: finish,
        observed: StateValue::Unknown,
        layer: StateLayer::Authentication,
        denial_cause: None,
        connection: None,
        controls: vec![],
        transport: vec![],
        sql_context: None,
        evidence_refs: vec![proof.into()],
        permission_inventory: None,
    };
    let inventory_absent = p.catalog.as_ref().is_some_and(|r| {
        if let EffectKindV2::EffectiveSqlPrivilege { scope, action } = &c.address.effect {
            !r.partial_revokes
                && r.roles_complete
                && r.object_exists == Some(true)
                && scope.kind == SqlObjectKind::Table
                && scope.database == c.address.target.engine_binding.database
                && scope.schema.as_deref() == Some(scope.database.as_str())
                && scope.object.as_deref().is_some_and(|object| {
                    r.inventory.as_ref().is_some_and(|v| {
                        v.absent(
                            &MysqlRole {
                                user: c.address.db_identity.clone(),
                                host: host.into(),
                            },
                            &scope.database,
                            object,
                            *action,
                            &r.active_roles,
                        )
                    })
                })
        } else {
            false
        }
    });
    if p.connected {
        match &c.address.effect {
            EffectKindV2::NewConnections => claim.observed = StateValue::Allowed,
            EffectKindV2::Transport {
                segment: TransportSegment::ClientToNativeRoute,
            } if tls => {
                claim.observed = StateValue::Present;
                claim.transport = vec![TransportFact {
                    validation_basis: None,
                    segment: TransportSegment::ClientToNativeRoute,
                    encrypted: Some(true),
                    ca_verified: Some(true),
                    hostname_verified: Some(true),
                    ipc_boundary_verified: None,
                    evidence_refs: vec![proof.into()],
                }];
            }
            EffectKindV2::EffectiveSqlPrivilege { .. } => {
                claim.layer = StateLayer::SqlAuthorization;
                if p.catalog.as_ref().is_some_and(|r| {
                    r.privilege_present == Some(true)
                        && r.object_exists == Some(true)
                        && !r.partial_revokes
                }) {
                    claim.observed = StateValue::Present;
                } else if inventory_absent {
                    claim.observed = StateValue::Absent;
                }
            }
            // MySQL role names lack an approved role-host selector in this
            // profile; retain active roles as context without proving this effect.
            EffectKindV2::EffectiveSqlRole { .. } => {
                claim.layer = StateLayer::SqlAuthorization;
            }
            _ => {}
        }
    } else {
        claim.denial_cause = Some(if p.stage == Stage::Deadline {
            DenialCause::Timeout
        } else {
            DenialCause::Unclassified
        });
    }
    if let Some(cat) = &p.catalog {
        // Names scoped to the approved policy and immutable DB generation,
        // never PostgreSQL OIDs or proof of account/table incarnation/removal.
        let identity = |kind: &str, value: &str| {
            format!(
                "mysql-{kind}-{}",
                crate::config::hash_bytes(
                    format!(
                        "{}:{}:{value}",
                        i.request.policy_revision_hash,
                        c.address
                            .target
                            .native_ref
                            .generation_fingerprint
                            .as_deref()
                            .unwrap_or("")
                    )
                    .as_bytes()
                )
            )
        };
        let object = match &c.address.effect {
            EffectKindV2::EffectiveSqlPrivilege { scope, .. }
                if cat.object_exists == Some(true) =>
            {
                Some(identity(
                    "object",
                    &serde_json::to_string(scope).map_err(|_| SourceError::Invalid)?,
                ))
            }
            EffectKindV2::EffectiveSqlRole { role } => Some(identity("role", role)),
            _ => None,
        };
        claim.sql_context = Some(SqlAuthorizationContext {
            session_user: cat.login_user.clone(),
            current_user: cat.current_account.clone(),
            active_roles: cat
                .active_roles
                .iter()
                .map(|r| format!("{}@{}", r.user, r.host))
                .collect(),
            login_catalog_identity: session.then(|| identity("account", &cat.current_account)),
            object_catalog_identity: object,
            permission_inventory_complete: inventory_absent,
        });
    }
    let yes = || Assurance::Verified {
        evidence_refs: vec![proof.into()],
    };
    let facet = |ok, reason| {
        if ok {
            yes()
        } else {
            Assurance::Unconfirmed { reason }
        }
    };
    let mut a = ClaimAssurance {
        claim_id: claim.id.clone(),
        coverage: AssuranceCoverage {
            source: yes(),
            temporal: yes(),
            target: facet(target, EvidenceReason::TargetUnconfirmed),
            principal: facet(principal, EvidenceReason::PrincipalUnconfirmed),
            route: facet(channel, EvidenceReason::RouteUnconfirmed),
            transport: facet(tls, EvidenceReason::TransportUnconfirmed),
            completeness: facet(
                channel && p.stage == Stage::Completed,
                EvidenceReason::IncompleteCapture,
            ),
        },
    };
    if tls {
        super::backend_tls::attach(
            &mut claim,
            &mut a,
            p.catalog
                .as_ref()
                .and_then(|cat| cat.backend_tls_cipher.as_ref().map(|s| !s.is_empty())),
            proof,
            c.backend_tls_trust,
        );
    }
    Ok((claim, a))
}
#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn sample() -> (
        IssuedObservation,
        super::super::aws_host::AwsCollectorConfig,
        AwsMysqlObservation,
    ) {
        let (mut i, mut config, _) = super::super::aws_postgres::tests::sample();
        let policy =
            parse_policy(include_str!("../../../examples/core-aws-mysql-policy.yaml")).unwrap();
        let target = &policy.targets[0];
        let aws = target.aws.as_ref().unwrap();
        let t = AwsMysqlTarget {
            target_id: target.id.clone(),
            db_arn: target.resource.native_id.clone(),
            db_resource_id: aws.db_resource_id.clone(),
            db_endpoint: aws.db_endpoint.clone(),
            proxy_name: aws.proxy_name.clone(),
            proxy_arn: aws.proxy_arn.clone(),
            proxy_endpoint: aws.proxy_endpoint.clone(),
        };
        let c = &mut i.request.cases[0];
        c.mysql_account_host = Some("%".into());
        c.port = 3306;
        c.endpoint = aws.proxy_endpoint.clone();
        c.address.target.registration_id = target.registration_id.clone();
        c.address.target.native_ref = target.resource.clone();
        c.address.target.native_ref.generation_fingerprint = Some(aws_generation_fingerprint(
            &target.placement.account_id,
            &target.placement.region,
            &target.resource.native_id,
            &aws.db_resource_id,
        ));
        c.address.target.engine_binding = target.engine.clone();
        config.postgres = None;
        config.mysql = Some(AwsMysqlConfig {
            collect_backend_tls: false,
            ca_sha256: "a".repeat(64),
            targets: vec![t.clone()],
        });
        config.endpoints[0].native_id = t.db_arn.clone();
        config.endpoints[0].generation_digest = c
            .address
            .target
            .native_ref
            .generation_fingerprint
            .clone()
            .unwrap();
        config.endpoints[0].endpoint = t.proxy_endpoint.clone();
        config.endpoints[0].port = 3306;
        let snapshot = match &mut i.snapshot {
            crate::core::source::RegisteredSourceSnapshot::Aws(s) => s,
            _ => unreachable!(),
        };
        snapshot.collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        i.request.cases[0].address.source = i.request.source.snapshot_ref();
        let meta = Metadata {
            db_arn: t.db_arn,
            db_resource_id: t.db_resource_id,
            db_endpoint: t.db_endpoint.clone(),
            engine_version: "8.0.43".into(),
            proxy_arn: t.proxy_arn,
            proxy_endpoint: t.proxy_endpoint,
            target_resource_name: "billing-mysql".into(),
            target_endpoint: t.db_endpoint,
        };
        let observation = AwsMysqlObservation {
            case_id: i.request.cases[0].id.clone(),
            stage: Stage::Completed,
            connected: true,
            error_code: None,
            actor: i.snapshot.aws().unwrap().metadata_credential.clone(),
            before: Some(meta.clone()),
            after: Some(meta),
            catalog: Some(MysqlCatalog {
                backend_tls_cipher: None,
                login_user: "billing_app@10.0.0.10".into(),
                current_account: "billing_app@%".into(),
                database: "billing".into(),
                version: "8.0.43".into(),
                lower_case_table_names: 0,
                tls_cipher_present: true,
                partial_revokes: false,
                active_roles: vec![],
                roles_complete: true,
                privilege_present: Some(true),
                object_exists: Some(true),
                inventory: None,
            }),
        };
        (i, config, observation)
    }
    pub(crate) fn absence_sample() -> (
        IssuedObservation,
        super::super::aws_host::AwsCollectorConfig,
        AwsMysqlObservation,
    ) {
        let (mut i, config, mut p) = sample();
        let policy =
            parse_policy(include_str!("../../../examples/core-aws-mysql-policy.yaml")).unwrap();
        i.request.cases[0].kind = FixedObservationCase::EffectiveSqlPrivilege;
        i.request.cases[0].address.effect = EffectKindV2::EffectiveSqlPrivilege {
            scope: policy.grants[0].sql_access.privileges[0].scope.clone(),
            action: SqlAction::Read,
        };
        let catalog = p.catalog.as_mut().unwrap();
        catalog.privilege_present = None;
        catalog.inventory = Some(inventory::tests::sample());
        (i, config, p)
    }
    #[test]
    fn complete_named_action_inventory_proves_absence_with_exact_scope_but_not_incarnation() {
        let (mut i, _, mut p) = absence_sample();
        let (claim, assurance) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Absent);
        assert!(claim.sql_context.unwrap().permission_inventory_complete);
        assert!(matches!(
            assurance.coverage.completeness,
            Assurance::Verified { .. }
        ));
        for n in 0..6 {
            let mut p = p.clone();
            let cat = p.catalog.as_mut().unwrap();
            match n {
                0 => cat.inventory = None,
                1 => cat.object_exists = None,
                2 => cat.object_exists = Some(false),
                3 => cat.roles_complete = false,
                4 => cat.partial_revokes = true,
                _ => cat.active_roles.push(MysqlRole {
                    user: "uncovered_role".into(),
                    host: "%".into(),
                }),
            }
            let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
            assert_eq!(claim.observed, StateValue::Unknown, "{n}");
            assert!(
                !claim.sql_context.unwrap().permission_inventory_complete,
                "{n}"
            );
        }
        if let EffectKindV2::EffectiveSqlPrivilege { scope, .. } =
            &mut i.request.cases[0].address.effect
        {
            scope.schema = Some("different".into());
        }
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        i.request.cases[0].address.effect = EffectKindV2::EffectiveSqlRole {
            role: "reader".into(),
        };
        p.catalog.as_mut().unwrap().active_roles.push(MysqlRole {
            user: "reader".into(),
            host: "%".into(),
        });
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
    }
    #[test]
    fn fresh_mysql_success_binds_account_host_identity_tls_and_keeps_backend_tls_unknown() {
        let (mut i, config, p) = sample();
        config.validate_request(&i).unwrap();
        let (claim, a) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Allowed);
        assert!(matches!(a.coverage.principal, Assurance::Verified { .. }));
        assert!(matches!(a.coverage.target, Assurance::Verified { .. }));
        assert!(matches!(a.coverage.route, Assurance::Verified { .. }));
        assert!(matches!(a.coverage.transport, Assurance::Verified { .. }));
        for n in 0..7 {
            let mut p = p.clone();
            match n {
                0 => p.after = None,
                1 => p.after.as_mut().unwrap().db_resource_id = "replaced".into(),
                2 => p.catalog = None,
                3 => p.catalog.as_mut().unwrap().current_account = "billing_app@localhost".into(),
                4 => p.catalog.as_mut().unwrap().login_user = "anonymous@10.0.0.10".into(),
                5 => p.catalog.as_mut().unwrap().version = "8.0.42".into(),
                _ => p.actor = None,
            };
            let (claim, a) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
            assert_eq!(claim.observed, StateValue::Allowed);
            assert!(
                !matches!(a.coverage.route, Assurance::Verified { .. }),
                "{n}"
            );
        }
        i.request.cases[0].kind = FixedObservationCase::Transport;
        i.request.cases[0].address.effect = EffectKindV2::Transport {
            segment: TransportSegment::ClientToNativeRoute,
        };
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Present);
        assert_eq!(claim.transport[0].hostname_verified, Some(true));
        i.request.cases[0].address.effect = EffectKindV2::Transport {
            segment: TransportSegment::NativeRouteToDatabase,
        };
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        assert_eq!(claim.transport[0].hostname_verified, None);
    }
    #[test]
    fn table_privilege_presence_has_named_mysql_identity_but_absence_is_never_removal_proof() {
        let (mut i, _, mut p) = sample();
        let policy =
            parse_policy(include_str!("../../../examples/core-aws-mysql-policy.yaml")).unwrap();
        let privilege = &policy.grants[0].sql_access.privileges[0];
        i.request.cases[0].kind = FixedObservationCase::EffectiveSqlPrivilege;
        i.request.cases[0].address.effect = EffectKindV2::EffectiveSqlPrivilege {
            scope: privilege.scope.clone(),
            action: SqlAction::Read,
        };
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Present);
        let sql = claim.sql_context.unwrap();
        assert!(
            sql.login_catalog_identity
                .unwrap()
                .starts_with("mysql-account-")
        );
        assert!(
            sql.object_catalog_identity
                .unwrap()
                .starts_with("mysql-object-")
        );
        assert!(!sql.permission_inventory_complete);
        p.catalog.as_mut().unwrap().partial_revokes = true;
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        p.catalog.as_mut().unwrap().partial_revokes = false;
        p.catalog.as_mut().unwrap().privilege_present = Some(false);
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        p.connected = false;
        p.catalog = None;
        p.error_code = Some(1045);
        p.stage = Stage::Connect;
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        assert_eq!(claim.denial_cause, Some(DenialCause::Unclassified));
    }
    #[test]
    fn mysql_profile_and_selected_records_reject_missing_host_pg_objects_and_secret_fields() {
        let (mut i, config, mut p) = sample();
        i.request.cases[0].mysql_account_host = None;
        assert!(config.validate_request(&i).is_err());
        assert!(normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").is_err());
        i.request.cases[0].mysql_account_host = Some("%".into());
        p.catalog.as_mut().unwrap().current_account = "token=PRIVATE_SENTINEL".into();
        assert!(normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").is_err());
        let (mut i, _, _) = sample();
        i.request.cases[0].address.target.engine_binding.family = EngineFamily::PostgreSql;
        assert!(i.request.validate().is_err());
    }
    #[test]
    fn native_mysql_options_pin_ip_hostname_ca_and_no_socket_or_ambient_settings() {
        let (i, config, _) = sample();
        let opts = options(
            &i.request.cases[0],
            &config.endpoints[0],
            SslOpts::default().with_disable_built_in_roots(true),
        );
        assert_eq!(opts.ip_or_hostname(), i.request.cases[0].endpoint);
        assert_eq!(opts.resolved_ips(), &Some(vec![config.endpoints[0].ip]));
        assert!(!opts.prefer_socket());
        assert!(opts.socket().is_none());
        assert!(opts.pass().is_none());
        assert!(opts.enable_cleartext_plugin());
        let ssl = opts.ssl_opts().unwrap();
        assert!(!ssl.accept_invalid_certs());
        assert!(!ssl.skip_domain_validation());
        assert!(ssl.disable_built_in_roots());
        assert!(ssl.tls_hostname_override().is_none());
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    async fn packet(stream: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut h = [0; 4];
        stream.read_exact(&mut h).await.unwrap();
        let n = usize::from(h[0]) | (usize::from(h[1]) << 8) | (usize::from(h[2]) << 16);
        assert!(n <= 16384);
        let mut body = vec![0; n];
        stream.read_exact(&mut body).await.unwrap();
        (h[3], body)
    }
    async fn send(stream: &mut TcpStream, seq: u8, body: &[u8]) {
        let n = body.len();
        stream
            .write_all(&[n as u8, (n >> 8) as u8, (n >> 16) as u8, seq])
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
    }
    fn handshake(ssl: bool) -> Vec<u8> {
        use mysql_async::consts::CapabilityFlags as C;
        let mut flags = C::CLIENT_LONG_PASSWORD
            | C::CLIENT_LONG_FLAG
            | C::CLIENT_CONNECT_WITH_DB
            | C::CLIENT_PROTOCOL_41
            | C::CLIENT_TRANSACTIONS
            | C::CLIENT_SECURE_CONNECTION
            | C::CLIENT_PLUGIN_AUTH;
        if ssl {
            flags |= C::CLIENT_SSL;
        }
        let flags = flags.bits();
        let mut b = vec![10];
        b.extend(b"8.0.43\0");
        b.extend(1u32.to_le_bytes());
        b.extend(b"12345678\0");
        b.extend((flags as u16).to_le_bytes());
        b.push(45);
        b.extend(2u16.to_le_bytes());
        b.extend(((flags >> 16) as u16).to_le_bytes());
        b.push(21);
        b.extend([0; 10]);
        b.extend(b"123456789012\0");
        b.extend(b"mysql_native_password\0");
        b
    }
    fn lenenc(bytes: &[u8], out: &mut Vec<u8>) {
        assert!(bytes.len() < 251);
        out.push(bytes.len() as u8);
        out.extend(bytes);
    }
    async fn rows(stream: &mut TcpStream, names: &[&str], values: &[Vec<&str>]) {
        let values: Vec<Vec<Option<&[u8]>>> = values
            .iter()
            .map(|row| row.iter().map(|value| Some(value.as_bytes())).collect())
            .collect();
        raw_rows(stream, names, &values).await;
    }
    async fn raw_rows(stream: &mut TcpStream, names: &[&str], values: &[Vec<Option<&[u8]>>]) {
        let mut seq = 1;
        send(stream, seq, &[names.len() as u8]).await;
        seq += 1;
        for name in names {
            let mut c = vec![];
            for s in ["def", "", "", "", name, ""] {
                lenenc(s.as_bytes(), &mut c);
            }
            c.push(12);
            c.extend(45u16.to_le_bytes());
            c.extend(512u32.to_le_bytes());
            c.push(0xfd);
            c.extend(0u16.to_le_bytes());
            c.extend([0, 0, 0]);
            send(stream, seq, &c).await;
            seq += 1;
        }
        let eof = [0xfe, 0, 0, 2, 0];
        send(stream, seq, &eof).await;
        seq += 1;
        for row in values {
            let mut b = vec![];
            for v in row {
                if let Some(v) = v {
                    lenenc(v, &mut b);
                } else {
                    b.push(0xfb);
                }
            }
            send(stream, seq, &b).await;
            seq += 1;
        }
        send(stream, seq, &eof).await;
    }
    struct InventoryScenario {
        root: Vec<String>,
        root_second: Option<Vec<String>>,
        role: Vec<String>,
        deny_role: bool,
        skip_grant_tables: bool,
        partial_revokes: bool,
    }
    impl Default for InventoryScenario {
        fn default() -> Self {
            Self {
                root: vec![
                    "GRANT USAGE ON *.* TO `billing_app`@`%`".into(),
                    "GRANT INSERT ON `billing`.`invoices` TO `billing_app`@`%`".into(),
                    "GRANT `reader`@`%` TO `billing_app`@`%`".into(),
                ],
                root_second: None,
                role: vec!["GRANT USAGE ON *.* TO `reader`@`%`".into()],
                deny_role: false,
                skip_grant_tables: false,
                partial_revokes: false,
            }
        }
    }
    async fn inventory_from_fake(
        s: InventoryScenario,
    ) -> (Option<inventory::Inventory>, Vec<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            send(&mut stream, 0, &handshake(false)).await;
            let (seq, _) = packet(&mut stream).await;
            assert_eq!(seq, 1);
            send(&mut stream, 2, &[0, 0, 0, 2, 0, 0, 0]).await;
            let mut queries = Vec::new();
            let mut roots = 0;
            loop {
                let (_, body) = packet(&mut stream).await;
                if body == [1] {
                    break;
                }
                assert_eq!(body[0], 3);
                let sql = std::str::from_utf8(&body[1..]).unwrap();
                queries.push(sql.to_owned());
                match sql {
                    "SET TRANSACTION READ ONLY" | "START TRANSACTION" | "ROLLBACK" => {
                        send(&mut stream, 1, &[0, 0, 0, 2, 0, 0, 0]).await;
                    }
                    inventory::ENV_SQL => {
                        rows(
                            &mut stream,
                            &[
                                "@@skip_grant_tables",
                                "@@mandatory_roles",
                                "@@partial_revokes",
                            ],
                            &[vec![
                                if s.skip_grant_tables { "1" } else { "0" },
                                "`reader`@`%`",
                                if s.partial_revokes { "1" } else { "0" },
                            ]],
                        )
                        .await;
                    }
                    inventory::CURRENT_GRANTS_SQL => {
                        roots += 1;
                        let grants = if roots > 1 {
                            s.root_second.as_ref().unwrap_or(&s.root)
                        } else {
                            &s.root
                        };
                        let values: Vec<_> = grants.iter().map(|g| vec![g.as_str()]).collect();
                        rows(&mut stream, &["Grants for billing_app@%"], &values).await;
                    }
                    "SHOW GRANTS FOR `reader`@`%`" if s.deny_role => {
                        let mut error = vec![0xff];
                        error.extend(1142u16.to_le_bytes());
                        error.extend(b"#42000catalog access denied (local fake)");
                        send(&mut stream, 1, &error).await;
                    }
                    "SHOW GRANTS FOR `reader`@`%`" => {
                        let values: Vec<_> = s.role.iter().map(|g| vec![g.as_str()]).collect();
                        rows(&mut stream, &["Grants for reader@%"], &values).await;
                    }
                    _ => panic!("unexpected inventory query {sql}"),
                }
            }
            queries
        });
        let mut conn = Conn::new(
            OptsBuilder::default()
                .ip_or_hostname("127.0.0.1")
                .tcp_port(address.port())
                .user(Some("billing_app"))
                .pass(Some("local-fake-only"))
                .prefer_socket(false)
                .max_allowed_packet(Some(1024 * 1024))
                .wait_timeout(Some(15)),
        )
        .await
        .unwrap();
        let work = async {
            let mut opts = mysql_async::TxOpts::default();
            opts.with_readonly(true);
            let mut tx = conn.start_transaction(opts).await.unwrap();
            let inventory = inventory::capture(
                &mut tx,
                &MysqlRole {
                    user: "billing_app".into(),
                    host: "%".into(),
                },
            )
            .await;
            tx.rollback().await.unwrap();
            inventory
        };
        let inventory = tokio::time::timeout(Duration::from_secs(5), work)
            .await
            .unwrap();
        conn.disconnect().await.unwrap();
        (inventory, server.await.unwrap())
    }
    #[tokio::test]
    async fn mysql_wire_inventory_reads_complete_role_closure_twice_and_rolls_back() {
        let (capture, queries) = inventory_from_fake(InventoryScenario::default()).await;
        let capture = capture.unwrap();
        let account = MysqlRole {
            user: "billing_app".into(),
            host: "%".into(),
        };
        assert!(capture.valid(&account));
        assert!(capture.absent(&account, "billing", "invoices", SqlAction::Read, &[]));
        assert_eq!(
            queries
                .iter()
                .filter(|q| q.as_str() == "SHOW GRANTS")
                .count(),
            2
        );
        assert_eq!(
            queries
                .iter()
                .filter(|q| q.as_str() == "SHOW GRANTS FOR `reader`@`%`")
                .count(),
            2
        );
        assert_eq!(queries.last().unwrap(), "ROLLBACK");
        assert!(queries.iter().all(|q| q.starts_with("SELECT @@")
            || q.starts_with("SHOW GRANTS")
            || matches!(
                q.as_str(),
                "SET TRANSACTION READ ONLY" | "START TRANSACTION" | "ROLLBACK"
            )));
    }
    #[tokio::test]
    async fn mysql_wire_catalog_visibility_denial_empty_unknown_and_limit_never_mean_absent() {
        for n in 0..6 {
            let mut scenario = InventoryScenario::default();
            match n {
                0 => scenario.deny_role = true,
                1 => scenario.root.clear(),
                2 => scenario.root = vec!["GRANT ROLE_ADMIN ON *.* TO `billing_app`@`%`".into()],
                3 => scenario.root = vec!["GRANT USAGE ON *.* TO `billing_app`@`%`".into(); 129],
                4 => scenario.skip_grant_tables = true,
                _ => scenario.partial_revokes = true,
            }
            let (capture, queries) = inventory_from_fake(scenario).await;
            assert!(capture.is_none(), "{n}");
            assert_eq!(queries.last().unwrap(), "ROLLBACK", "{n}");
        }
    }
    #[tokio::test]
    async fn mysql_wire_role_right_or_changed_capture_blocks_absence() {
        let account = MysqlRole {
            user: "billing_app".into(),
            host: "%".into(),
        };
        let mut role_right = InventoryScenario::default();
        role_right
            .role
            .push("GRANT SELECT (`amount`) ON `billing`.`invoices` TO `reader`@`%`".into());
        let (capture, _) = inventory_from_fake(role_right).await;
        assert!(
            !capture
                .unwrap()
                .absent(&account, "billing", "invoices", SqlAction::Read, &[])
        );
        let mut changed = InventoryScenario::default();
        let mut after = changed.root.clone();
        after.push("GRANT SELECT ON *.* TO `billing_app`@`%`".into());
        changed.root_second = Some(after);
        let (capture, _) = inventory_from_fake(changed).await;
        assert!(
            !capture
                .unwrap()
                .absent(&account, "billing", "invoices", SqlAction::Read, &[])
        );
    }
    #[tokio::test]
    async fn real_mysql_driver_uses_fixed_readonly_catalog_queries_and_rolls_back_with_fake_server()
    {
        let (selected, sql) = catalog_from_fake(None).await;
        assert_eq!(selected.current_account, "billing_app@%");
        assert_eq!(selected.database, "billing");
        assert!(selected.tls_cipher_present);
        assert!(selected.privilege_present.is_none());
        assert!(selected.backend_tls_cipher.is_none());
        assert_eq!(sql.first().unwrap(), "SET SESSION MAX_EXECUTION_TIME=3000");
        assert!(sql.contains(&"SET TRANSACTION READ ONLY".into()));
        assert_eq!(sql.last().unwrap(), "ROLLBACK");
    }
    async fn catalog_from_fake(backend: Option<usize>) -> (MysqlCatalog, Vec<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            send(&mut stream, 0, &handshake(false)).await;
            let (seq, _) = packet(&mut stream).await;
            assert_eq!(seq, 1);
            send(&mut stream, 2, &[0, 0, 0, 2, 0, 0, 0]).await;
            let mut sql = vec![];
            loop {
                let (seq, b) = packet(&mut stream).await;
                assert_eq!(seq, 0);
                if b == [1] {
                    break;
                }
                assert_eq!(b[0], 3);
                let query = std::str::from_utf8(&b[1..]).unwrap();
                sql.push(query.to_owned());
                match query {
                    "SET SESSION MAX_EXECUTION_TIME=3000"
                    | "SET TRANSACTION READ ONLY"
                    | "START TRANSACTION"
                    | "ROLLBACK" => send(&mut stream, 1, &[0, 0, 0, 2, 0, 0, 0]).await,
                    SESSION_SQL => {
                        rows(
                            &mut stream,
                            &[
                                "USER()",
                                "CURRENT_USER()",
                                "DATABASE()",
                                "VERSION()",
                                "@@lower_case_table_names",
                                "@@partial_revokes",
                            ],
                            &[vec![
                                "billing_app@127.0.0.1",
                                "billing_app@%",
                                "billing",
                                "8.0.43",
                                "0",
                                "0",
                            ]],
                        )
                        .await
                    }
                    TLS_SQL => {
                        rows(
                            &mut stream,
                            &["Variable_name", "Value"],
                            &[vec!["Ssl_cipher", "TLS_FAKE_TEST_ONLY"]],
                        )
                        .await
                    }
                    ROLES_SQL => rows(&mut stream, &["ROLE_NAME", "ROLE_HOST"], &[]).await,
                    q if q.starts_with(
                        "SELECT s.VARIABLE_VALUE FROM performance_schema.status_by_thread ",
                    ) =>
                    {
                        let value: Option<&[u8]> = match backend.unwrap() {
                            0 => None,
                            1 => Some(&[0xff]), // A non-UTF8 value cannot convert to String.
                            2 => Some(b""),
                            _ => Some(b"TLS_AES_256_GCM_SHA384"),
                        };
                        raw_rows(&mut stream, &["VARIABLE_VALUE"], &[vec![value]]).await;
                    }
                    _ => panic!("unexpected SQL {query}"),
                }
            }
            sql
        });
        let mut conn = Conn::new(
            OptsBuilder::default()
                .ip_or_hostname("127.0.0.1")
                .tcp_port(address.port())
                .user(Some("billing_app"))
                .pass(Some("fake-only"))
                .db_name(Some("billing"))
                .prefer_socket(false)
                .max_allowed_packet(Some(1024 * 1024))
                .wait_timeout(Some(15)),
        )
        .await
        .unwrap();
        let (i, _, _) = super::tests::sample();
        let selected = tokio::time::timeout(Duration::from_secs(5), async {
            if backend.is_some() {
                catalog_with_backend(&mut conn, &i.request.cases[0], true).await
            } else {
                catalog(&mut conn, &i.request.cases[0]).await
            }
        })
        .await
        .unwrap()
        .unwrap();
        conn.disconnect().await.unwrap();
        let sql = server.await.unwrap();
        (selected, sql)
    }
    #[tokio::test]
    async fn optional_backend_tls_null_bad_value_empty_and_cipher_do_not_break_catalog() {
        for (mode, expected) in [
            (0, None),
            (1, None),
            (2, Some("")),
            (3, Some("TLS_AES_256_GCM_SHA384")),
        ] {
            let (catalog, queries) = catalog_from_fake(Some(mode)).await;
            assert_eq!(catalog.backend_tls_cipher.as_deref(), expected, "{mode}");
            assert_eq!(catalog.current_account, "billing_app@%");
            assert_eq!(queries.last().unwrap(), "ROLLBACK");
            assert_eq!(
                queries
                    .iter()
                    .filter(|q| q.starts_with(
                        "SELECT s.VARIABLE_VALUE FROM performance_schema.status_by_thread "
                    ))
                    .count(),
                1
            );
            let (mut i, _, mut p) = super::tests::sample();
            i.request.cases[0].kind = FixedObservationCase::Transport;
            i.request.cases[0].address.effect = EffectKindV2::Transport {
                segment: TransportSegment::NativeRouteToDatabase,
            };
            p.catalog = Some(catalog);
            let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
            assert_eq!(claim.observed, StateValue::Unknown);
            assert_eq!(
                claim.transport[0].encrypted,
                expected.map(|value| !value.is_empty())
            );
            assert_eq!(claim.transport[0].ca_verified, None);
            assert_eq!(claim.transport[0].hostname_verified, None);
        }
    }
    #[tokio::test]
    async fn required_mysql_tls_refuses_plaintext_server_before_authentication_token_is_sent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            send(&mut stream, 0, &handshake(false)).await;
            let mut captured = vec![];
            stream.read_to_end(&mut captured).await.unwrap();
            captured
        });
        let (mut i, mut config, _) = super::tests::sample();
        i.request.cases[0].port = address.port();
        config.endpoints[0].ip = address.ip();
        let opts = OptsBuilder::from_opts(options(
            &i.request.cases[0],
            &config.endpoints[0],
            SslOpts::default(),
        ))
        .pass(Some("PRIVATE_IAM_TOKEN_SENTINEL"));
        assert!(
            tokio::time::timeout(Duration::from_secs(5), Conn::new(opts))
                .await
                .unwrap()
                .is_err()
        );
        assert!(server.await.unwrap().is_empty());
    }
}

#[cfg(test)]
mod managed_tls_tests {
    use super::*;
    #[test]
    fn managed_backend_requires_selected_cipher_and_verified_client_channel() {
        for mode in 0..5 {
            let (mut i, _, mut raw) = super::tests::sample();
            let c = &mut i.request.cases[0];
            c.kind = FixedObservationCase::Transport;
            c.address.effect = EffectKindV2::Transport {
                segment: TransportSegment::NativeRouteToDatabase,
            };
            c.backend_tls_trust = Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1);
            raw.catalog.as_mut().unwrap().backend_tls_cipher =
                Some("TLS_AES_256_GCM_SHA384".into());
            match mode {
                1 => raw.catalog.as_mut().unwrap().backend_tls_cipher = None,
                2 => raw.catalog.as_mut().unwrap().backend_tls_cipher = Some(String::new()),
                3 => raw.catalog.as_mut().unwrap().tls_cipher_present = false,
                4 => raw.after.as_mut().unwrap().db_resource_id = "db-CHANGED".into(),
                _ => {}
            }
            let (claim, a) = normalize(&i, &i.request.cases[0], 111, 114, &raw, "proof").unwrap();
            assert_eq!(
                claim.observed == StateValue::Present,
                mode == 0,
                "mode {mode}"
            );
            assert!(
                claim
                    .transport
                    .iter()
                    .all(|t| t.ca_verified.is_none() && t.hostname_verified.is_none())
            );
            if mode == 0 {
                assert!(matches!(a.coverage.transport, Assurance::Verified { .. }));
            }
        }
    }
}

#[cfg(test)]
pub(super) fn enable_backend_tls_for_test(
    i: &mut IssuedObservation,
    config: &mut super::aws_host::AwsCollectorConfig,
    raw: &mut AwsMysqlObservation,
) {
    config.mysql.as_mut().unwrap().collect_backend_tls = true;
    raw.catalog.as_mut().unwrap().backend_tls_cipher = Some("TLS_AES_256_GCM_SHA384".into());
    let snapshot = match &mut i.snapshot {
        crate::core::source::RegisteredSourceSnapshot::Aws(s) => s,
        _ => unreachable!(),
    };
    snapshot.collector_config_digest =
        crate::config::hash_bytes(&serde_json::to_vec(config).unwrap());
    i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
    for case in &mut i.request.cases {
        case.address.source = i.request.source.snapshot_ref();
    }
}
