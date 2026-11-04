//! AWS PostgreSQL/MySQL selected-observation normalization. These are WIRE
//! claims, never an ObservationVerifier or admitted facts. Native EC2 collection
//! lives in aws_host; this importer never upgrades a wire claim into source proof.
use crate::core::{
    admission::{AdmissionError, validate_request_scope},
    change::PreparedChange,
    evidence::*,
    policy::*,
    source::SourceBoundaryKind,
    state::*,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsObservationStage {
    Credential,
    TargetMetadata,
    Tls,
    DatabaseLogin,
    Sql,
    Completed,
    Deadline,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "engine", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwsSqlSelection {
    PostgreSql {
        session_user: String,
        current_user: String,
        login_oid: u32,
        object_oid: Option<u32>,
        active_roles: Vec<String>,
        inventory_complete: bool,
        effective_privilege: Option<bool>,
    },
    MySql {
        login_user: String,
        current_account: String,
        active_roles: Vec<String>,
        inventory_complete: bool,
        effective_privilege: Option<bool>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsCaseSelection {
    pub case_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub stage: AwsObservationStage,
    pub session_established: bool,
    pub sqlstate: Option<String>,
    pub mysql_error_code: Option<u16>,
    pub database: String,
    pub engine_version: String,
    pub proxy_arn: String,
    pub db_resource_id: String,
    pub transport: Vec<TransportFact>,
    pub sql: Option<AwsSqlSelection>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSelectedCapture {
    pub schema_version: u32,
    pub request_digest: String,
    pub cases: Vec<AwsCaseSelection>,
}
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedAwsClaims {
    pub source_verified: bool,
    pub admission_available: bool,
    pub claims: Vec<ObservationClaim>,
    pub assurances: Vec<ClaimAssurance>,
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
impl AwsSelectedCapture {
    pub fn parse_untrusted(bytes: &[u8]) -> Result<Self, AdmissionError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(AdmissionError::Limit);
        }
        let c: Self = serde_json::from_slice(bytes).map_err(|_| AdmissionError::Invalid)?;
        if c.schema_version != 1
            || c.cases.is_empty()
            || c.cases.len() > MAX_CASES_PER_SOURCE
            || !crate::core::policy::valid_hash(&c.request_digest)
            || c.cases
                .iter()
                .map(|c| &c.case_id)
                .collect::<BTreeSet<_>>()
                .len()
                != c.cases.len()
        {
            return Err(AdmissionError::Invalid);
        }
        for row in &c.cases {
            if !crate::core::policy::valid_id(&row.case_id)
                || row.started_at > row.finished_at
                || row.finished_at - row.started_at > MAX_CAPTURE_SECONDS
                || [
                    &row.database,
                    &row.engine_version,
                    &row.proxy_arn,
                    &row.db_resource_id,
                ]
                .iter()
                .any(|s| !safe(s))
                || row.sqlstate.as_ref().is_some_and(|s| {
                    s.len() != 5
                        || !s
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
                })
                || row.transport.len() > 2
                || row.transport.iter().any(|t| !t.evidence_refs.is_empty())
                || (!row.session_established && row.sql.is_some())
            {
                return Err(AdmissionError::Invalid);
            }
            if let Some(s) = &row.sql {
                let (names, roles) = match s {
                    AwsSqlSelection::PostgreSql {
                        session_user,
                        current_user,
                        active_roles,
                        ..
                    } => (vec![session_user, current_user], active_roles),
                    AwsSqlSelection::MySql {
                        login_user,
                        current_account,
                        active_roles,
                        ..
                    } => (vec![login_user, current_account], active_roles),
                };
                if roles.len() > 128 || names.into_iter().chain(roles.iter()).any(|s| !safe(s)) {
                    return Err(AdmissionError::Invalid);
                }
            }
        }
        Ok(c)
    }
}
/// Scope is the approved v2 change/request. The selected capture itself is not
/// authenticated by this function, regardless of its TLS/principal assertions.
pub fn normalize(
    change: &PreparedChange,
    request: &ObservationRequest,
    input: &AwsSelectedCapture,
    artifact: &str,
) -> Result<NormalizedAwsClaims, AdmissionError> {
    request.validate().map_err(|_| AdmissionError::Invalid)?;
    validate_request_scope(request, change)?;
    let checked = AwsSelectedCapture::parse_untrusted(
        &serde_json::to_vec(input).map_err(|_| AdmissionError::Invalid)?,
    )?;
    if request.source.boundary != SourceBoundaryKind::AwsHostNetwork
        || checked.request_digest != request.digest().map_err(|_| AdmissionError::Invalid)?
        || !crate::core::policy::valid_id(artifact)
        || input.cases.len() > request.cases.len()
    {
        return Err(AdmissionError::ScopeMismatch);
    }
    let mut out = NormalizedAwsClaims {
        source_verified: false,
        admission_available: false,
        claims: vec![],
        assurances: vec![],
    };
    for s in &input.cases {
        let c = request
            .cases
            .iter()
            .find(|c| c.id == s.case_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let t = change
            .policy
            .targets
            .iter()
            .find(|t| t.id == c.address.target_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let binding = t.aws.as_ref().ok_or(AdmissionError::ScopeMismatch)?;
        if t.placement.kind != PlacementKind::AwsRds
            || t.placement.region != "ap-northeast-1"
            || !matches!(
                (t.engine.family, t.engine.version.as_str()),
                (EngineFamily::PostgreSql, "16.15") | (EngineFamily::MySql, "8.0.43")
            )
            || s.started_at < request.issued_at
            || s.finished_at >= request.expires_at
            || s.proxy_arn != binding.proxy_arn
            || s.db_resource_id != binding.db_resource_id
            || s.database != t.engine.database
            || s.engine_version != t.engine.version
            || (t.engine.family == EngineFamily::PostgreSql && s.mysql_error_code.is_some())
            || c.address.target.native_ref.generation_fingerprint.as_ref()
                != Some(&crate::core::policy::aws_generation_fingerprint(
                    &t.placement.account_id,
                    &t.placement.region,
                    &t.resource.native_id,
                    &binding.db_resource_id,
                ))
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        let expected_endpoint = if c.kind == FixedObservationCase::DirectPath {
            &binding.db_endpoint
        } else {
            &binding.proxy_endpoint
        };
        let expected_port = if t.engine.family == EngineFamily::PostgreSql {
            5432
        } else {
            3306
        };
        if c.endpoint != *expected_endpoint || c.port != expected_port {
            return Err(AdmissionError::ScopeMismatch);
        }
        let mut claim = ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: format!("aws-{}", s.case_id),
            case_id: s.case_id.clone(),
            policy_revision_hash: request.policy_revision_hash.clone(),
            address: c.address.clone(),
            started_at: s.started_at,
            finished_at: s.finished_at,
            observed: StateValue::Unknown,
            layer: match s.stage {
                AwsObservationStage::Credential | AwsObservationStage::TargetMetadata => {
                    StateLayer::ConnectionAuthorization
                }
                AwsObservationStage::Sql => StateLayer::SqlAuthorization,
                _ => StateLayer::Authentication,
            },
            denial_cause: None,
            connection: None,
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec![artifact.into()],
            permission_inventory: None,
        };
        if c.kind == FixedObservationCase::DirectPath {
            claim.layer = StateLayer::RouteEnforcement;
            // Session success on the actual direct route is a positive access
            // claim, but TCP/TLS/login refusal can never become RouteBlocked.
            if s.session_established {
                claim.observed = StateValue::Allowed;
            }
        } else if s.session_established {
            let mut present = None;
            let mut complete = false;
            if let Some(sql) = &s.sql {
                match (t.engine.family, sql) {
                    (
                        EngineFamily::PostgreSql,
                        AwsSqlSelection::PostgreSql {
                            session_user,
                            current_user,
                            login_oid,
                            object_oid,
                            active_roles,
                            inventory_complete,
                            effective_privilege,
                        },
                    ) => {
                        if session_user != &c.address.db_identity
                            || current_user != session_user
                            || *login_oid == 0
                        {
                            return Err(AdmissionError::ScopeMismatch);
                        }
                        claim.sql_context = Some(SqlAuthorizationContext {
                            session_user: session_user.clone(),
                            current_user: current_user.clone(),
                            active_roles: active_roles.clone(),
                            login_catalog_identity: Some(format!("pg-role-{login_oid}")),
                            object_catalog_identity: object_oid
                                .map(|oid| format!("pg-object-{oid}")),
                            permission_inventory_complete: *inventory_complete,
                        });
                        present = *effective_privilege;
                        complete = *inventory_complete && object_oid.is_some();
                    }
                    (
                        EngineFamily::MySql,
                        AwsSqlSelection::MySql {
                            login_user,
                            current_account,
                            active_roles,
                            inventory_complete,
                            effective_privilege,
                        },
                    ) => {
                        let mysql = t.mysql.as_ref().ok_or(AdmissionError::ScopeMismatch)?;
                        let expected = format!(
                            "{}@{}",
                            c.address.db_identity,
                            if c.purpose == crate::core::source::SourcePurpose::Recovery {
                                &mysql.management_account_host
                            } else {
                                &mysql.account_host
                            }
                        );
                        if login_user != &c.address.db_identity || current_account != &expected {
                            return Err(AdmissionError::ScopeMismatch);
                        }
                        claim.sql_context = Some(SqlAuthorizationContext {
                            session_user: login_user.clone(),
                            current_user: current_account.clone(),
                            active_roles: active_roles.clone(),
                            login_catalog_identity: None,
                            object_catalog_identity: None,
                            permission_inventory_complete: false,
                        });
                        present = *effective_privilege;
                        complete = *inventory_complete;
                        // MySQL account/object incarnation is not represented by
                        // PostgreSQL OIDs. No old receipt is upgraded by its name.
                    }
                    _ => return Err(AdmissionError::ScopeMismatch),
                }
            }
            match c.address.effect {
                EffectKindV2::NewConnections => claim.observed = StateValue::Allowed,
                EffectKindV2::EffectiveSqlPrivilege { .. }
                | EffectKindV2::EffectiveSqlRole { .. } => {
                    claim.layer = StateLayer::SqlAuthorization;
                    if present == Some(true) {
                        claim.observed = StateValue::Present
                    } else if present == Some(false) && complete {
                        claim.observed = StateValue::Absent
                    }
                }
                EffectKindV2::Transport { segment } => {
                    claim.transport = s
                        .transport
                        .iter()
                        .filter(|t| t.segment == segment)
                        .cloned()
                        .map(|mut t| {
                            t.evidence_refs = vec![artifact.into()];
                            t
                        })
                        .collect();
                    if claim.transport.iter().any(|t| {
                        t.encrypted == Some(true)
                            && t.ca_verified == Some(true)
                            && t.hostname_verified == Some(true)
                    }) {
                        claim.observed = StateValue::Present
                    }
                }
                _ => {}
            }
        } else if s.stage == AwsObservationStage::Deadline {
            claim.denial_cause = Some(DenialCause::Timeout)
        } else {
            claim.denial_cause = Some(DenialCause::Unclassified)
        }
        let un = |reason| Assurance::Unconfirmed { reason };
        out.assurances.push(ClaimAssurance {
            claim_id: claim.id.clone(),
            coverage: AssuranceCoverage {
                target: un(EvidenceReason::TargetUnconfirmed),
                principal: un(EvidenceReason::PrincipalUnconfirmed),
                source: Assurance::Unconfirmed {
                    reason: EvidenceReason::SourceUnconfirmed,
                },
                route: un(EvidenceReason::RouteUnconfirmed),
                transport: un(EvidenceReason::TransportUnconfirmed),
                temporal: un(EvidenceReason::TemporalUnconfirmed),
                completeness: un(EvidenceReason::IncompleteCapture),
            },
        });
        out.claims.push(claim);
    }
    Ok(out)
}
