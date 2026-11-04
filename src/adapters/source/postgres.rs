//! Selected PostgreSQL observations and their fixed GCP connector recipe.
//! No SQL/error text, passwords, access tokens, customer rows, or DSNs on wire.
use super::gce_host::{CaseDiagnostic, SourceError};
use crate::core::postgres_login::{
    LoginCatalogFact, PostgresLoginFailure, PostgresLoginFailureKind,
};
use crate::core::{admission::IssuedObservation, evidence::*, policy::*, state::*};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const PROXY_PATH: &str = "/usr/local/libexec/cloud-sql-proxy";
pub const PROXY_VERSION: &str = "2.26.3";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresCollectorConfig {
    pub proxy_sha256: String,
    /// Additional bounded Cloud Audit Log reads require explicit registration.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collect_connect_denial_audit: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collect_iam_inventory: bool,
}
impl PostgresCollectorConfig {
    pub(super) fn validate(&self) -> Result<(), SourceError> {
        if !crate::core::policy::valid_hash(&self.proxy_sha256) {
            return Err(SourceError::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstanceIdentity {
    pub project: String,
    pub name: String,
    pub region: String,
    pub connection_name: String,
    pub create_time: String,
    pub database_version: String,
    pub private_ip: IpAddr,
}
impl InstanceIdentity {
    pub(super) fn matches(&self, c: &RequestedCase) -> bool {
        let t = &c.address.target;
        t.placement.kind == PlacementKind::GcpCloudSql
            && t.engine_binding.family == EngineFamily::PostgreSql
            && t.engine_binding.version == "16.15"
            && self.database_version == "POSTGRES_16"
            && self.project == t.placement.account_id
            && self.region == t.placement.region
            && t.native_ref.native_id
                == format!("projects/{}/instances/{}", self.project, self.name)
            && self.connection_name == format!("{}:{}:{}", self.project, self.region, self.name)
            && t.native_ref.generation_fingerprint.as_deref()
                == Some(
                    crate::adapters::deployment::gcp::generation_fingerprint(
                        &self.project,
                        &self.name,
                        &self.create_time,
                    )
                    .as_str(),
                )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PgStage {
    Credential,
    InstanceMetadata,
    ProxyStartup,
    Connect,
    Catalog,
    Completed,
    Deadline,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PgCatalog {
    pub session_user: String,
    pub current_user: String,
    pub database: String,
    pub server_version_num: i32,
    pub login_oid: u32,
    pub login_can_login: bool,
    pub active_roles: Vec<String>,
    pub object_oid: Option<u32>,
    pub object_kind: Option<SqlObjectKind>,
    pub effective_privilege: Option<bool>,
    pub roles_complete: bool,
    pub backend_ssl: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_catalog: Vec<LoginCatalogFact>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PgObservation {
    pub stage: PgStage,
    pub sqlstate: Option<String>,
    pub connected: bool,
    pub instance_before: Option<InstanceIdentity>,
    pub instance_after: Option<InstanceIdentity>,
    pub proxy_sha256: String,
    pub proxy_version: String,
    pub credential_identity: String,
    pub catalog: Option<PgCatalog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_denial: Option<super::denial::GcpConnectDenial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_rejection: Option<PostgresLoginFailure>,
}
impl PgObservation {
    pub(super) fn failed(i: &IssuedObservation, digest: &str) -> Self {
        Self {
            stage: PgStage::Credential,
            sqlstate: None,
            connected: false,
            instance_before: None,
            instance_after: None,
            proxy_sha256: digest.into(),
            proxy_version: PROXY_VERSION.into(),
            credential_identity: i
                .snapshot
                .gce()
                .map(|s| s.native_identity.service_account.clone())
                .unwrap_or_default(),
            catalog: None,
            connect_denial: None,
            login_rejection: None,
        }
    }
}

pub(super) fn normalize(
    i: &IssuedObservation,
    c: &RequestedCase,
    d: &CaseDiagnostic,
    proof_id: &str,
) -> Result<(ObservationClaim, ClaimAssurance), SourceError> {
    let p = d.postgres.as_ref().ok_or(SourceError::Invalid)?;
    let expected_user = i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity
        .service_account
        .strip_suffix(".gserviceaccount.com")
        .ok_or(SourceError::Invalid)?;
    if p.credential_identity
        != i.snapshot
            .gce()
            .ok_or(SourceError::Unsupported)?
            .native_identity
            .service_account
        || c.address.db_identity != expected_user
        || p.proxy_version != PROXY_VERSION
        || !crate::core::policy::valid_hash(&p.proxy_sha256)
        || p.sqlstate.as_ref().is_some_and(|s| {
            s.len() != 5
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
        || p.catalog.as_ref().is_some_and(|s| {
            s.active_roles.len() > 128
                || s.session_user.len() > 128
                || s.current_user.len() > 128
                || s.active_roles.iter().any(|r| r.len() > 128)
                || s.login_catalog.len() > MAX_CASES_PER_SOURCE
                || s.login_catalog.iter().any(|f| {
                    !f.target.valid()
                        || f.role_oid == 0
                        || !c.login_catalog_targets.contains(&f.target)
                })
                || s.login_catalog
                    .iter()
                    .map(|f| &f.target)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != s.login_catalog.len()
        })
        || (p.catalog.is_some() && !p.connected)
        || p.login_rejection.as_ref().is_some_and(|r| {
            r.db_identity != c.address.db_identity
                || r.kind != PostgresLoginFailureKind::AuthenticatedNoLoginV1
        })
    {
        return Err(SourceError::Invalid);
    }
    let target = p
        .instance_before
        .as_ref()
        .is_some_and(|a| a.matches(c) && p.instance_after.as_ref() == Some(a));
    let session = p.catalog.as_ref().is_some_and(|s| {
        s.session_user == expected_user
            && s.current_user == expected_user
            && s.database == c.address.target.engine_binding.database
            && s.server_version_num == 160015
            && s.login_oid != 0
            && s.login_can_login
    });
    // A pinned connector's successful private IPC session establishes its remote
    // TLS recipe. pg_stat_ssl alone is never used for CA/hostname assurance.
    let channel = target && session && p.connected;
    let yes = || Assurance::Verified {
        evidence_refs: vec![proof_id.into()],
    };
    let no = |reason| Assurance::Unconfirmed { reason };
    let id = format!("source-{}", c.id);
    let mut claim = ObservationClaim {
        runtime_capture: None,
        postgres_login_failure: None,
        login_catalog: vec![],
        id: id.clone(),
        case_id: c.id.clone(),
        policy_revision_hash: i.request.policy_revision_hash.clone(),
        address: c.address.clone(),
        started_at: d.started_at,
        finished_at: d.finished_at,
        observed: StateValue::Unknown,
        layer: StateLayer::Authentication,
        denial_cause: None,
        connection: None,
        controls: vec![],
        transport: vec![],
        sql_context: None,
        evidence_refs: vec![proof_id.into()],
        permission_inventory: None,
    };
    // This authenticates retrieval and matches selected log fields, not the
    // original producer. No provider-exclusive write boundary is established.
    let connect_candidate = !p.connected
        && p.stage == PgStage::Connect
        && c.address.effect == EffectKindV2::NewConnections
        && c.address.route.kind == RouteKind::NativeConnector
        && target
        && p.connect_denial
            .as_ref()
            .is_some_and(|n| n.matches(i, c, d.started_at, d.finished_at));
    let login_denial = !p.connected
        && p.stage == PgStage::Connect
        && p.sqlstate.as_deref() == Some("28000")
        && c.address.effect == EffectKindV2::NewConnections
        && c.address.route.kind == RouteKind::NativeConnector
        && target
        && p.login_rejection.is_some();
    let mut complete = channel || login_denial;
    if p.connected {
        match &c.address.effect {
            EffectKindV2::NewConnections => claim.observed = StateValue::Allowed,
            EffectKindV2::Transport { segment } => {
                let t = match segment {
                    TransportSegment::LocalIpcBoundary => TransportFact {
                        validation_basis: None,
                        segment: *segment,
                        encrypted: None,
                        ca_verified: None,
                        hostname_verified: None,
                        ipc_boundary_verified: Some(true),
                        evidence_refs: vec![proof_id.into()],
                    },
                    TransportSegment::NativeRouteToDatabase => TransportFact {
                        validation_basis: None,
                        segment: *segment,
                        encrypted: Some(true),
                        ca_verified: Some(true),
                        hostname_verified: Some(true),
                        ipc_boundary_verified: None,
                        evidence_refs: vec![proof_id.into()],
                    },
                    _ => {
                        complete = false;
                        TransportFact {
                            validation_basis: None,
                            segment: *segment,
                            encrypted: None,
                            ca_verified: None,
                            hostname_verified: None,
                            ipc_boundary_verified: None,
                            evidence_refs: vec![proof_id.into()],
                        }
                    }
                };
                claim.transport.push(t);
                if complete {
                    claim.observed = StateValue::Present
                }
            }
            EffectKindV2::EffectiveSqlPrivilege { .. } | EffectKindV2::EffectiveSqlRole { .. } => {
                claim.layer = StateLayer::SqlAuthorization;
                if let Some(s) = &p.catalog {
                    if let Some(present) = s.effective_privilege {
                        if present {
                            claim.observed = StateValue::Present
                        } else if s.roles_complete && s.object_oid.is_some() {
                            claim.observed = StateValue::Absent
                        }
                    }
                    complete = complete && s.roles_complete && s.object_oid.is_some();
                } else {
                    complete = false
                }
            }
            // Ownership receipts do not establish total ACL or incarnation.
            _ => complete = false,
        }
    } else {
        claim.layer = match p.stage {
            PgStage::InstanceMetadata | PgStage::ProxyStartup => {
                StateLayer::ConnectionAuthorization
            }
            _ => StateLayer::Authentication,
        };
        claim.denial_cause = Some(match p.stage {
            PgStage::Deadline => DenialCause::Timeout,
            _ => DenialCause::Unclassified,
        });
        // Generic 28P01/28000 is not IAM attribution or registered NOLOGIN proof.
        if connect_candidate {
            claim.layer = StateLayer::ConnectionAuthorization;
        }
        // Direct authenticated PG startup evidence is independent of a log
        // candidate whose producer origin remains unconfirmed.
        if login_denial {
            claim.observed = StateValue::Denied;
            claim.layer = StateLayer::Authentication;
            claim.denial_cause = Some(DenialCause::LoginRejected);
            claim.postgres_login_failure = p.login_rejection.clone();
        }
    }
    if let Some(s) = &p.catalog {
        claim.login_catalog = s.login_catalog.clone();
        claim.sql_context = Some(SqlAuthorizationContext {
            session_user: s.session_user.clone(),
            current_user: s.current_user.clone(),
            active_roles: s.active_roles.clone(),
            login_catalog_identity: Some(format!("pg-role-{}", s.login_oid)),
            object_catalog_identity: s.object_oid.map(|o| format!("pg-{:?}-{o}", s.object_kind)),
            permission_inventory_complete: s.roles_complete,
        });
    }
    let coverage = AssuranceCoverage {
        target: if target {
            yes()
        } else {
            no(EvidenceReason::TargetUnconfirmed)
        },
        principal: if session || login_denial {
            yes()
        } else if connect_candidate {
            no(EvidenceReason::NativeLogOriginUnconfirmed)
        } else {
            no(EvidenceReason::PrincipalUnconfirmed)
        },
        source: yes(),
        route: if channel || login_denial {
            yes()
        } else if connect_candidate {
            no(EvidenceReason::NativeLogOriginUnconfirmed)
        } else {
            no(EvidenceReason::RouteUnconfirmed)
        },
        // For a rejection, this authenticates the decision transport through the
        // pinned connector. It does not manufacture a backend TLS effect fact.
        transport: if channel || login_denial {
            yes()
        } else if connect_candidate {
            no(EvidenceReason::NativeLogOriginUnconfirmed)
        } else {
            no(EvidenceReason::TransportUnconfirmed)
        },
        temporal: yes(),
        completeness: if complete {
            yes()
        } else if connect_candidate {
            no(EvidenceReason::NativeLogOriginUnconfirmed)
        } else {
            no(EvidenceReason::IncompleteCapture)
        },
    };
    Ok((
        claim,
        ClaimAssurance {
            claim_id: id,
            coverage,
        },
    ))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::adapters::source) fn sample() -> (IssuedObservation, RequestedCase, CaseDiagnostic)
    {
        let (mut i, _) = super::super::testsupport::fixture();
        let mut c = i.request.cases[0].clone();
        c.id = "connection".into();
        c.kind = FixedObservationCase::NewConnection;
        c.address.route = StateRoute {
            id: "app-connector".into(),
            kind: RouteKind::NativeConnector,
        };
        let t = &c.address.target;
        let identity = InstanceIdentity {
            project: t.placement.account_id.clone(),
            name: "billing-postgres".into(),
            region: t.placement.region.clone(),
            connection_name: format!(
                "{}:{}:billing-postgres",
                t.placement.account_id, t.placement.region
            ),
            create_time: "2026-01-01T00:00:00Z".into(),
            database_version: "POSTGRES_16".into(),
            private_ip: "10.0.0.1".parse().unwrap(),
        };
        c.address.target.native_ref.generation_fingerprint =
            Some(crate::adapters::deployment::gcp::generation_fingerprint(
                &identity.project,
                &identity.name,
                &identity.create_time,
            ));
        i.request.cases = vec![c.clone()];
        let p = PgObservation {
            connect_denial: None,
            login_rejection: None,
            stage: PgStage::Completed,
            sqlstate: None,
            connected: true,
            instance_before: Some(identity.clone()),
            instance_after: Some(identity),
            proxy_sha256: "f".repeat(64),
            proxy_version: PROXY_VERSION.into(),
            credential_identity: i
                .snapshot
                .gce()
                .map(|s| s.native_identity.service_account.clone())
                .unwrap_or_default(),
            catalog: Some(PgCatalog {
                session_user: c.address.db_identity.clone(),
                current_user: c.address.db_identity.clone(),
                database: "billing".into(),
                server_version_num: 160015,
                login_oid: 100,
                login_can_login: true,
                active_roles: vec!["reader".into()],
                object_oid: Some(200),
                object_kind: Some(SqlObjectKind::Table),
                effective_privilege: Some(true),
                roles_complete: true,
                backend_ssl: Some(true),
                login_catalog: vec![],
            }),
        };
        let d = CaseDiagnostic {
            runtime_capture: None,
            runtime_failure: None,
            iam_inventory: None,
            case_id: c.id.clone(),
            started_at: 111,
            finished_at: 114,
            outcome: super::super::gce_host::DiagnosticOutcome::PostgresObserved,
            connection: None,
            postgres: Some(p),
        };
        (i, c, d)
    }
    #[test]
    fn selected_authenticated_nologin_requires_target_generation_and_keeps_catalog_unclaimed() {
        let (i, c, mut d) = sample();
        let p = d.postgres.as_mut().unwrap();
        p.connected = false;
        p.catalog = None;
        p.stage = PgStage::Connect;
        p.sqlstate = Some("28000".into());
        p.login_rejection = Some(PostgresLoginFailure {
            db_identity: c.address.db_identity.clone(),
            kind: PostgresLoginFailureKind::AuthenticatedNoLoginV1,
        });
        let (claim, assurance) = normalize(&i, &c, &d, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Denied);
        assert_eq!(claim.layer, StateLayer::Authentication);
        assert_eq!(claim.denial_cause, Some(DenialCause::LoginRejected));
        assert!(claim.postgres_login_failure.is_some());
        assert!(claim.sql_context.is_none());
        assert!(claim.login_catalog.is_empty());
        assert!(claim.transport.is_empty());
        assert!(matches!(
            assurance.coverage.principal,
            Assurance::Verified { .. }
        ));
        assert!(matches!(
            assurance.coverage.transport,
            Assurance::Verified { .. }
        ));
        for variant in 0..4 {
            let mut changed = d.clone();
            let p = changed.postgres.as_mut().unwrap();
            match variant {
                0 => p.instance_after = None,
                1 => p.sqlstate = Some("28P01".into()),
                2 => p.login_rejection = None,
                _ => p.stage = PgStage::Deadline,
            }
            assert_eq!(
                normalize(&i, &c, &changed, "proof").unwrap().0.observed,
                StateValue::Unknown
            );
        }
        let mut changed = d.clone();
        changed
            .postgres
            .as_mut()
            .unwrap()
            .login_rejection
            .as_mut()
            .unwrap()
            .db_identity = "another-role".into();
        assert!(normalize(&i, &c, &changed, "proof").is_err());
        let mut changed = d;
        changed.postgres.as_mut().unwrap().connected = true;
        assert_eq!(
            normalize(&i, &c, &changed, "proof").unwrap().0.observed,
            StateValue::Allowed
        );
    }
    #[test]
    fn recovery_catalog_selections_are_bound_to_request_and_reject_extras_duplicates_and_zero_oid()
    {
        let (i, mut c, mut d) = sample();
        let target = crate::core::postgres_login::LoginCatalogTarget {
            grant_id: "app-grant".into(),
            subject_id: "app-subject".into(),
            db_identity: "app-login".into(),
        };
        c.login_catalog_targets = vec![target.clone()];
        let fact = LoginCatalogFact {
            target,
            role_oid: 300,
            can_login: false,
        };
        d.postgres
            .as_mut()
            .unwrap()
            .catalog
            .as_mut()
            .unwrap()
            .login_catalog = vec![fact.clone()];
        let (claim, _) = normalize(&i, &c, &d, "proof").unwrap();
        assert_eq!(claim.login_catalog, vec![fact]);
        assert_eq!(claim.observed, StateValue::Allowed);
        for variant in 0..3 {
            let mut changed = d.clone();
            let facts = &mut changed
                .postgres
                .as_mut()
                .unwrap()
                .catalog
                .as_mut()
                .unwrap()
                .login_catalog;
            match variant {
                0 => facts[0].target.db_identity = "unauthorized-role".into(),
                1 => facts[0].role_oid = 0,
                _ => facts.push(facts[0].clone()),
            }
            assert!(normalize(&i, &c, &changed, "proof").is_err());
        }
    }
    #[test]
    fn allowed_is_retained_when_generation_after_read_or_catalog_is_missing() {
        let (i, c, d) = sample();
        let (claim, a) = normalize(&i, &c, &d, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Allowed);
        assert!(matches!(a.coverage.target, Assurance::Verified { .. }));
        for n in 0..4 {
            let mut d = d.clone();
            let p = d.postgres.as_mut().unwrap();
            match n {
                0 => p.instance_after = None,
                1 => p.instance_after.as_mut().unwrap().create_time = "replacement".into(),
                2 => p.catalog = None,
                _ => p.catalog.as_mut().unwrap().server_version_num = 160016,
            };
            let (claim, a) = normalize(&i, &c, &d, "proof").unwrap();
            assert_eq!(claim.observed, StateValue::Allowed);
            assert!(!matches!(
                a.coverage.completeness,
                Assurance::Verified { .. }
            ));
        }
    }
    #[test]
    fn generic_login_errors_metadata_failure_and_deadline_are_not_attributed_denials() {
        let (i, c, d) = sample();
        for stage in [
            PgStage::Credential,
            PgStage::InstanceMetadata,
            PgStage::ProxyStartup,
            PgStage::Connect,
            PgStage::Catalog,
            PgStage::Deadline,
        ] {
            for code in ["28000", "28P01", "08006", "57014"] {
                let mut d = d.clone();
                let p = d.postgres.as_mut().unwrap();
                p.stage = stage;
                p.connected = false;
                p.catalog = None;
                p.sqlstate = Some(code.into());
                let (claim, _) = normalize(&i, &c, &d, "proof").unwrap();
                assert_eq!(claim.observed, StateValue::Unknown);
                assert_ne!(claim.denial_cause, Some(DenialCause::PermissionDenied));
                assert_ne!(claim.denial_cause, Some(DenialCause::RouteBlocked));
            }
        }
    }
    #[test]
    fn connector_tls_and_local_ipc_are_separate_from_backend_ssl() {
        let (i, mut c, mut d) = sample();
        d.postgres
            .as_mut()
            .unwrap()
            .catalog
            .as_mut()
            .unwrap()
            .backend_ssl = None;
        for segment in [
            TransportSegment::LocalIpcBoundary,
            TransportSegment::NativeRouteToDatabase,
        ] {
            c.address.effect = EffectKindV2::Transport { segment };
            c.kind = FixedObservationCase::Transport;
            let (claim, a) = normalize(&i, &c, &d, "proof").unwrap();
            assert_eq!(claim.observed, StateValue::Present);
            assert_eq!(claim.transport[0].segment, segment);
            assert!(matches!(a.coverage.transport, Assurance::Verified { .. }));
        }
        c.address.effect = EffectKindV2::Transport {
            segment: TransportSegment::ClientToNativeRoute,
        };
        assert_eq!(
            normalize(&i, &c, &d, "proof").unwrap().0.observed,
            StateValue::Unknown
        );
    }
    #[test]
    fn partial_role_inventory_cannot_prove_absence_and_owned_delta_stays_unknown() {
        let (i, mut c, mut d) = sample();
        c.kind = FixedObservationCase::EffectiveSqlPrivilege;
        c.address.effect = EffectKindV2::EffectiveSqlRole {
            role: "reader".into(),
        };
        for (present, complete, expected) in [
            (true, false, StateValue::Present),
            (false, false, StateValue::Unknown),
            (false, true, StateValue::Absent),
        ] {
            let s = d.postgres.as_mut().unwrap().catalog.as_mut().unwrap();
            s.effective_privilege = Some(present);
            s.roles_complete = complete;
            assert_eq!(normalize(&i, &c, &d, "proof").unwrap().0.observed, expected);
        }
        c.address.effect = EffectKindV2::OwnedSqlDelta {
            receipt_digest: "a".repeat(64),
            delta_digest: "b".repeat(64),
        };
        assert_eq!(
            normalize(&i, &c, &d, "proof").unwrap().0.observed,
            StateValue::Unknown
        );
    }
    #[test]
    fn different_actor_version_and_unsafe_sqlstate_are_rejected() {
        let (i, c, d) = sample();
        for n in 0..3 {
            let mut d = d.clone();
            let p = d.postgres.as_mut().unwrap();
            match n {
                0 => p.credential_identity = "other@project.iam.gserviceaccount.com".into(),
                1 => p.proxy_version = "unfixed".into(),
                _ => p.sqlstate = Some("PRIVATE-SENTINEL".into()),
            };
            assert!(normalize(&i, &c, &d, "proof").is_err());
        }
    }
}
