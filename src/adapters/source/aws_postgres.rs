//! Opt-in EC2 metadata-only PostgreSQL observation. No SDK/environment/profile
//! credential fallback; fixed STS/RDS origins and fixed read-only catalog SQL.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub use super::aws_native::{AwsDatabaseTarget as AwsPostgresTarget, CA_PATH};
use super::{
    aws_native::*,
    gce_host::{CollectorEndpoint, SourceError},
    postgres::PgCatalog,
};
use crate::{
    core::{
        admission::IssuedObservation,
        evidence::*,
        policy::*,
        postgres_login::{PostgresLoginFailure, PostgresLoginFailureKind},
        source::AwsMetadataCredential,
        state::*,
    },
    domain::Endpoint,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsPostgresConfig {
    pub ca_sha256: String,
    pub targets: Vec<AwsPostgresTarget>,
}
impl AwsPostgresConfig {
    pub(super) fn validate(&self, i: &IssuedObservation) -> Result<(), SourceError> {
        validate_config(i, &self.ca_sha256, &self.targets, EngineFamily::PostgreSql)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AwsPgObservation {
    pub case_id: String,
    stage: Stage,
    connected: bool,
    sqlstate: Option<String>,
    actor: Option<AwsMetadataCredential>,
    before: Option<Metadata>,
    after: Option<Metadata>,
    catalog: Option<PgCatalog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login_rejection: Option<PostgresLoginFailure>,
}
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[cfg(unix)]
pub(super) async fn observe(
    i: &IssuedObservation,
    c: &RequestedCase,
    e: &CollectorEndpoint,
    config: &AwsPostgresConfig,
    cancel: &CancellationToken,
) -> Result<AwsPgObservation, SourceError> {
    config.validate(i)?;
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    let actor = s.metadata_credential.as_ref().ok_or(SourceError::Invalid)?;
    let t = config
        .targets
        .iter()
        .find(|t| t.target_id == c.address.target_id)
        .ok_or(SourceError::Invalid)?;
    let mut out = AwsPgObservation {
        case_id: c.id.clone(),
        stage: Stage::Credential,
        connected: false,
        sqlstate: None,
        actor: None,
        before: None,
        after: None,
        catalog: None,
        login_rejection: None,
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
        out.before = Some(metadata(&creds, t, EngineFamily::PostgreSql, cancel).await?);
        let ca = pinned_ca(&config.ca_sha256)?;
        let certs = CertificateDer::pem_slice_iter(&ca)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SourceError::Invalid)?;
        if certs.is_empty() {
            return Err(SourceError::Invalid);
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|_| SourceError::Invalid)?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| SourceError::Invalid)?
        .with_root_certificates(roots)
        .with_no_client_auth();
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
        let mut pg = tokio_postgres::Config::new();
        pg.host(&c.endpoint).hostaddr(e.ip).port(c.port).user(&c.address.db_identity).dbname(&c.address.target.engine_binding.database).password(token.expose()).ssl_mode(tokio_postgres::config::SslMode::Require).connect_timeout(Duration::from_secs(8)).application_name("veil-db-guard-observation-v2").options("-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=1000");
        out.stage = Stage::Connect;
        match tokio::time::timeout(
            Duration::from_secs(8),
            pg.connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls)),
        )
        .await
        {
            Ok(Ok((mut client, connection))) => {
                out.connected = true;
                let _driver = Driver(tokio::spawn(async move {
                    let _ = connection.await;
                }));
                out.stage = Stage::Catalog;
                match super::postgres_native::catalog(&mut client, c).await {
                    Ok(cat) => {
                        out.catalog = Some(cat);
                        out.stage = Stage::Completed;
                    }
                    Err(err) => {
                        out.sqlstate = err.code().map(|s| s.code().to_owned());
                    }
                }
            }
            Ok(Err(err)) => {
                out.sqlstate = err.code().map(|s| s.code().to_owned());
                out.login_rejection =
                    super::postgres_login::recognize(&err, &c.address.db_identity);
            }
            Err(_) => out.stage = Stage::Deadline,
        }
        out.after = metadata(&creds, t, EngineFamily::PostgreSql, cancel)
            .await
            .ok();
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
pub(super) fn normalize(
    i: &IssuedObservation,
    c: &RequestedCase,
    start: u64,
    finish: u64,
    p: &AwsPgObservation,
    proof: &str,
) -> Result<(ObservationClaim, ClaimAssurance), SourceError> {
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    if p.case_id != c.id
        || c.kind == FixedObservationCase::DirectPath
        || c.address.target.engine_binding.family != EngineFamily::PostgreSql
        || c.address.target.engine_binding.version != "16.15"
        || p.sqlstate.as_ref().is_some_and(|s| {
            s.len() != 5
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
        || (p.catalog.is_some() && !p.connected)
        || p.actor
            .as_ref()
            .is_some_and(|a| Some(a) != s.metadata_credential.as_ref())
        || p.login_rejection.as_ref().is_some_and(|r| {
            r.db_identity != c.address.db_identity
                || !crate::core::postgres_login::identity(&r.db_identity)
                || r.kind != PostgresLoginFailureKind::AuthenticatedNoLoginV1
        })
    {
        return Err(SourceError::Invalid);
    }
    let safe = |s: &str| {
        !s.is_empty()
            && s.len() <= 512
            && !s.chars().any(char::is_control)
            && !s.contains("://")
            && !s.contains("${")
            && !s.contains("{{")
            && !["password=", "pwd=", "token=", "secret="]
                .iter()
                .any(|x| s.to_ascii_lowercase().contains(x))
    };
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
    }) || p.catalog.as_ref().is_some_and(|r| {
        [&r.session_user, &r.current_user, &r.database]
            .into_iter()
            .chain(r.active_roles.iter())
            .any(|v| !safe(v))
            || r.login_catalog.len() > MAX_CASES_PER_SOURCE
            || r.login_catalog.iter().any(|f| {
                !f.target.valid() || f.role_oid == 0 || !c.login_catalog_targets.contains(&f.target)
            })
            || r.login_catalog
                .iter()
                .map(|f| &f.target)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != r.login_catalog.len()
    }) {
        return Err(SourceError::Invalid);
    }
    let target = p.before.as_ref().is_some_and(|b| {
        p.after.as_ref() == Some(b)
            && b.db_arn == c.address.target.native_ref.native_id
            && b.engine_version == "16.15"
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
    let session = p.catalog.as_ref().is_some_and(|r| {
        r.session_user == c.address.db_identity
            && r.current_user == r.session_user
            && r.database == c.address.target.engine_binding.database
            && r.server_version_num == 160015
            && r.login_oid != 0
            && r.login_can_login
    });
    let login_denial = !p.connected
        && p.stage == Stage::Connect
        && p.sqlstate.as_deref() == Some("28000")
        && c.address.effect == EffectKindV2::NewConnections
        && c.address.route.kind == RouteKind::NativeProxy
        && target
        && p.actor.is_some()
        && p.login_rejection.is_some();
    let principal = (p.actor.is_some() && session) || login_denial;
    let channel = target && principal && p.connected;
    let mut claim = ObservationClaim {
        runtime_capture: None,
        postgres_login_failure: None,
        login_catalog: vec![],
        id: format!("aws-pg-{}", c.id),
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
    if p.connected {
        match &c.address.effect {
            EffectKindV2::NewConnections => claim.observed = StateValue::Allowed,
            EffectKindV2::Transport {
                segment: TransportSegment::ClientToNativeRoute,
            } if channel => {
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
            EffectKindV2::EffectiveSqlPrivilege { .. } | EffectKindV2::EffectiveSqlRole { .. } => {
                claim.layer = StateLayer::SqlAuthorization;
                if let Some(cat) = &p.catalog {
                    if cat.effective_privilege == Some(true) {
                        claim.observed = StateValue::Present;
                    } else if cat.effective_privilege == Some(false)
                        && cat.roles_complete
                        && cat.object_oid.is_some()
                    {
                        claim.observed = StateValue::Absent;
                    }
                }
            }
            _ => {}
        }
    } else {
        claim.denial_cause = Some(if p.stage == Stage::Deadline {
            DenialCause::Timeout
        } else {
            DenialCause::Unclassified
        });
        if login_denial {
            claim.observed = StateValue::Denied;
            claim.denial_cause = Some(DenialCause::LoginRejected);
            claim.postgres_login_failure = p.login_rejection.clone();
        }
    }
    if let Some(cat) = &p.catalog {
        claim.login_catalog = cat.login_catalog.clone();
        if cat.active_roles.len() > 128
            || [&cat.session_user, &cat.current_user]
                .into_iter()
                .chain(cat.active_roles.iter())
                .any(|s| {
                    s.is_empty()
                        || s.len() > 128
                        || s.chars().any(char::is_control)
                        || s.contains("://")
                })
        {
            return Err(SourceError::Invalid);
        }
        claim.sql_context = Some(SqlAuthorizationContext {
            session_user: cat.session_user.clone(),
            current_user: cat.current_user.clone(),
            active_roles: cat.active_roles.clone(),
            login_catalog_identity: Some(format!("pg-role-{}", cat.login_oid)),
            object_catalog_identity: cat.object_oid.map(|o| format!("pg-object-{o}")),
            permission_inventory_complete: cat.roles_complete,
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
    let mut assurance = ClaimAssurance {
        claim_id: claim.id.clone(),
        coverage: AssuranceCoverage {
            source: yes(),
            temporal: yes(),
            target: facet(target, EvidenceReason::TargetUnconfirmed),
            principal: facet(principal, EvidenceReason::PrincipalUnconfirmed),
            route: facet(channel || login_denial, EvidenceReason::RouteUnconfirmed),
            // The native decision was received over verified client-to-proxy
            // TLS. No backend TLS TransportFact is inferred from a refusal.
            transport: facet(
                channel || login_denial,
                EvidenceReason::TransportUnconfirmed,
            ),
            completeness: facet(
                (channel && p.stage == Stage::Completed) || login_denial,
                EvidenceReason::IncompleteCapture,
            ),
        },
    };
    if channel {
        super::backend_tls::attach(
            &mut claim,
            &mut assurance,
            p.catalog.as_ref().and_then(|cat| cat.backend_ssl),
            proof,
            c.backend_tls_trust,
        );
    }
    Ok((claim, assurance))
}
#[cfg(test)]
pub(super) fn set_backend_ssl_for_test(p: &mut AwsPgObservation, value: Option<bool>) {
    p.catalog.as_mut().unwrap().backend_ssl = value;
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn sample() -> (
        IssuedObservation,
        super::super::aws_host::AwsCollectorConfig,
        AwsPgObservation,
    ) {
        let (mut i, mut config) = super::super::aws_host::tests::fixture();
        let p = parse_policy(include_str!("../../../examples/core-aws-policy.yaml")).unwrap();
        let target = &p.targets[0];
        let aws = target.aws.as_ref().unwrap();
        let actor = AwsMetadataCredential {
            role_arn: p.subjects[0].identity.principal.clone(),
            role_id: p.subjects[0].identity.immutable_id.clone().unwrap(),
            credential_reference: p.subjects[0].identity.credential_source.reference.clone(),
        };
        let t = AwsPostgresTarget {
            target_id: target.id.clone(),
            db_arn: target.resource.native_id.clone(),
            db_resource_id: aws.db_resource_id.clone(),
            db_endpoint: aws.db_endpoint.clone(),
            proxy_name: aws.proxy_name.clone(),
            proxy_arn: aws.proxy_arn.clone(),
            proxy_endpoint: aws.proxy_endpoint.clone(),
        };
        config.postgres = Some(AwsPostgresConfig {
            ca_sha256: "a".repeat(64),
            targets: vec![t.clone()],
        });
        config.endpoints[0].endpoint = t.proxy_endpoint.clone();
        let snapshot = match &mut i.snapshot {
            crate::core::source::RegisteredSourceSnapshot::Aws(s) => s,
            _ => unreachable!(),
        };
        snapshot.metadata_credential = Some(actor.clone());
        snapshot.collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        let c = &mut i.request.cases[0];
        c.kind = FixedObservationCase::NewConnection;
        c.endpoint = t.proxy_endpoint.clone();
        c.address.source = i.request.source.snapshot_ref();
        c.address.target.registration_id = target.registration_id.clone();
        c.address.route = StateRoute {
            id: "app-proxy".into(),
            kind: RouteKind::NativeProxy,
        };
        c.address.db_identity = p.grants[0].db_identity.clone();
        let metadata = Metadata {
            db_arn: t.db_arn,
            db_resource_id: t.db_resource_id,
            db_endpoint: t.db_endpoint.clone(),
            engine_version: "16.15".into(),
            proxy_arn: t.proxy_arn,
            proxy_endpoint: t.proxy_endpoint,
            target_resource_name: "billing-postgres".into(),
            target_endpoint: t.db_endpoint,
        };
        let observation = AwsPgObservation {
            login_rejection: None,
            case_id: c.id.clone(),
            stage: Stage::Completed,
            connected: true,
            sqlstate: None,
            actor: Some(actor),
            before: Some(metadata.clone()),
            after: Some(metadata),
            catalog: Some(PgCatalog {
                login_catalog: vec![],
                session_user: c.address.db_identity.clone(),
                current_user: c.address.db_identity.clone(),
                database: "billing".into(),
                server_version_num: 160015,
                login_oid: 100,
                login_can_login: true,
                active_roles: vec!["billing_reader_writer".into()],
                object_oid: Some(200),
                object_kind: Some(SqlObjectKind::Table),
                effective_privilege: Some(true),
                roles_complete: true,
                backend_ssl: Some(true),
            }),
        };
        (i, config, observation)
    }
    #[test]
    fn pg_success_is_preserved_with_separate_target_principal_route_and_transport_facets() {
        let (mut i, config, p) = sample();
        config.validate_request(&i).unwrap();
        let c = &i.request.cases[0];
        let (claim, a) = normalize(&i, c, 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Allowed);
        for facet in [
            &a.coverage.target,
            &a.coverage.principal,
            &a.coverage.source,
            &a.coverage.route,
            &a.coverage.transport,
            &a.coverage.temporal,
            &a.coverage.completeness,
        ] {
            assert!(matches!(facet, Assurance::Verified { .. }));
        }
        for n in 0..4 {
            let mut p = p.clone();
            match n {
                0 => p.after = None,
                1 => p.after.as_mut().unwrap().db_resource_id = "recreated".into(),
                2 => p.catalog = None,
                _ => p.actor = None,
            };
            let (claim, a) = normalize(&i, c, 111, 114, &p, "proof").unwrap();
            assert_eq!(claim.observed, StateValue::Allowed);
            assert!(!matches!(a.coverage.route, Assurance::Verified { .. }));
        }
        i.request.cases[0].address.effect = EffectKindV2::Transport {
            segment: TransportSegment::ClientToNativeRoute,
        };
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Present);
        assert_eq!(claim.transport[0].ca_verified, Some(true));
        i.request.cases[0].address.effect = EffectKindV2::Transport {
            segment: TransportSegment::NativeRouteToDatabase,
        };
        let (claim, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        assert_eq!(claim.transport[0].ca_verified, None);
    }
    #[test]
    fn selected_nologin_failure_is_generation_actor_and_phase_bound_and_never_overrides_success() {
        let (i, _, mut p) = sample();
        let c = &i.request.cases[0];
        p.connected = false;
        p.catalog = None;
        p.stage = Stage::Connect;
        p.sqlstate = Some("28000".into());
        p.login_rejection = Some(PostgresLoginFailure {
            db_identity: c.address.db_identity.clone(),
            kind: PostgresLoginFailureKind::AuthenticatedNoLoginV1,
        });
        let (claim, assurance) = normalize(&i, c, 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Denied);
        assert_eq!(claim.layer, StateLayer::Authentication);
        assert_eq!(claim.denial_cause, Some(DenialCause::LoginRejected));
        assert_eq!(claim.postgres_login_failure, p.login_rejection);
        assert!(claim.sql_context.is_none());
        assert!(claim.transport.is_empty());
        for facet in [
            assurance.coverage.target,
            assurance.coverage.principal,
            assurance.coverage.route,
            assurance.coverage.transport,
            assurance.coverage.completeness,
        ] {
            assert!(matches!(facet, Assurance::Verified { .. }));
        }
        for variant in 0..6 {
            let mut changed = p.clone();
            match variant {
                0 => changed.after = None,
                1 => changed.actor = None,
                2 => changed.sqlstate = Some("28P01".into()),
                3 => changed.stage = Stage::Deadline,
                4 => changed.login_rejection = None,
                _ => changed.after.as_mut().unwrap().db_resource_id = "replacement".into(),
            }
            assert_eq!(
                normalize(&i, c, 111, 114, &changed, "proof")
                    .unwrap()
                    .0
                    .observed,
                StateValue::Unknown
            );
        }
        let mut changed = p.clone();
        changed.login_rejection.as_mut().unwrap().db_identity = "other-role".into();
        assert!(normalize(&i, c, 111, 114, &changed, "proof").is_err());
        p.connected = true;
        let (claim, _) = normalize(&i, c, 111, 114, &p, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Allowed);
        assert!(claim.postgres_login_failure.is_none());
    }
    #[test]
    fn recovery_catalog_facts_require_exact_request_targets_and_valid_unique_oids() {
        let (mut i, _, mut p) = sample();
        let target = crate::core::postgres_login::LoginCatalogTarget {
            grant_id: "app-grant".into(),
            subject_id: "app-subject".into(),
            db_identity: "app-login".into(),
        };
        i.request.cases[0].login_catalog_targets = vec![target.clone()];
        let fact = crate::core::postgres_login::LoginCatalogFact {
            target,
            role_oid: 300,
            can_login: false,
        };
        p.catalog.as_mut().unwrap().login_catalog = vec![fact.clone()];
        let c = &i.request.cases[0];
        assert_eq!(
            normalize(&i, c, 111, 114, &p, "proof")
                .unwrap()
                .0
                .login_catalog,
            vec![fact]
        );
        for variant in 0..3 {
            let mut changed = p.clone();
            let facts = &mut changed.catalog.as_mut().unwrap().login_catalog;
            match variant {
                0 => facts[0].target.db_identity = "other-login".into(),
                1 => facts[0].role_oid = 0,
                _ => facts.push(facts[0].clone()),
            }
            assert!(normalize(&i, c, 111, 114, &changed, "proof").is_err());
        }
    }
    #[test]
    fn failures_and_uncertain_inventory_never_become_layer_attributed_denials_or_removal_proof() {
        let (mut i, _, mut p) = sample();
        p.connected = false;
        p.catalog = None;
        p.sqlstate = Some("28000".into());
        p.stage = Stage::Connect;
        let (c, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(c.observed, StateValue::Unknown);
        assert_eq!(c.denial_cause, Some(DenialCause::Unclassified));
        let (_, _, mut p) = sample();
        i.request.cases[0].kind = FixedObservationCase::EffectiveSqlPrivilege;
        i.request.cases[0].address.effect = EffectKindV2::EffectiveSqlRole {
            role: "billing_reader_writer".into(),
        };
        p.catalog.as_mut().unwrap().effective_privilege = Some(false);
        p.catalog.as_mut().unwrap().roles_complete = false;
        let (c, _) = normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").unwrap();
        assert_eq!(c.observed, StateValue::Unknown);
    }
    #[test]
    fn imdsv2_credentials_and_signed_requests_never_enter_process_args() {
        let now = 1_793_664_000;
        let credentials=MetadataCredentials::parse(br#"{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIA0000000000000000","SecretAccessKey":"PRIVATESECRETSENTINEL00000000000000000000","Token":"PRIVATE_SESSION_SENTINEL","Expiration":"2026-11-04T00:00:00Z"}"#,now).unwrap();
        let input = signed_config(&credentials, "sts", "GetCallerIdentity", &[]).unwrap();
        let input = String::from_utf8(input).unwrap();
        assert!(input.contains("sts.ap-northeast-1.amazonaws.com"));
        assert!(input.contains("X-Amz-Security-Token=PRIVATE_SESSION_SENTINEL"));
        assert!(!input.contains("PRIVATESECRETSENTINEL"));
        let argv = api_args().join(" ");
        assert!(!argv.contains("SENTINEL"));
        assert!(argv.ends_with("--config -"));
        assert!(!argv.contains("--location"));
        assert!(signed_config(&credentials, "iam", "PutRolePolicy", &[]).is_err());
        for time in [
            "2026-02-30T00:00:00Z",
            "２０２６-11-03T00:00:00Z",
            "2026-11-03T24:00:00Z",
        ] {
            assert!(parse_time(time).is_err());
        }
        assert!(MetadataCredentials::parse(br#"{"Code":"Success","Type":"AWS-HMAC","AccessKeyId":"ASIA0000000000000000","SecretAccessKey":"PRIVATESECRETSENTINEL00000000000000000000","Token":"token","Expiration":"2026-11-04T00:00:00Z"}"#,u64::MAX).is_err());
    }
    #[test]
    fn unsafe_selected_metadata_or_catalog_fields_are_rejected_before_archiving() {
        let (i, _, mut p) = sample();
        p.catalog.as_mut().unwrap().database = "password=PRIVATE_SENTINEL".into();
        assert!(normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").is_err());
        let (i, _, mut p) = sample();
        p.after.as_mut().unwrap().proxy_arn = "token=PRIVATE_SENTINEL".into();
        assert!(normalize(&i, &i.request.cases[0], 111, 114, &p, "proof").is_err());
    }
    #[test]
    fn sts_checks_same_credential_role_incarnation_and_query_xml_lists_are_exact() {
        let (i, _, _) = sample();
        let actor = i
            .snapshot
            .aws()
            .unwrap()
            .metadata_credential
            .as_ref()
            .unwrap();
        let xml = format!(
            "<GetCallerIdentityResult><Arn>arn:aws:sts::123456789012:assumed-role/billing-app/i-0123456789abcdef0</Arn><UserId>{}:i-0123456789abcdef0</UserId><Account>123456789012</Account></GetCallerIdentityResult>",
            actor.role_id
        );
        sts(&xml, actor, "123456789012").unwrap();
        assert!(
            sts(
                &xml.replace(&actor.role_id, "AROA00000000000000999"),
                actor,
                "123456789012"
            )
            .is_err()
        );
        assert!(
            sts(
                &xml.replace("billing-app/", "foreign/"),
                actor,
                "123456789012"
            )
            .is_err()
        );
        assert_eq!(single_member("<member><Auth><member><Scheme>IAM</Scheme></member></Auth><DBProxyArn>arn</DBProxyArn></member>").unwrap(),"<Auth><member><Scheme>IAM</Scheme></member></Auth><DBProxyArn>arn</DBProxyArn>");
        assert!(single_member("<member>x</member><member>y</member>").is_err());
        assert!(scalar("<X>a</X><X>b</X>", "X").is_err());
        assert!(scalar("<X><nested>value</nested></X>", "X").is_err());
    }
}
