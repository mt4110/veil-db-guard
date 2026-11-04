//! Source-bound evidence protocol types. Wire records are untrusted claims.
//! Admission, collection and evaluation are later K10 units; this module cannot
//! deserialize or construct a confirmed observation from a JSON verdict.
use super::{
    policy::{
        PolicyError, PolicyRevision, SqlAction, SqlScope, TargetHandle, valid_hash, valid_id,
    },
    source::{SourceBinding, SourcePurpose, SourceSnapshotRef},
    state::{ArtifactRef, DenialCause, StateLayer, StateRoute, StateValue},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EVIDENCE_WIRE_SCHEMA_VERSION: u32 = 1;
pub const EVALUATION_SCHEMA_VERSION: u32 = 2;
pub const MAX_CASES_PER_SOURCE: usize = 8;
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_REQUEST_TTL_SECONDS: u64 = 120;
pub const MAX_CAPTURE_SECONDS: u64 = 45;
pub const DEFAULT_FRESHNESS_SECONDS: u64 = 60;
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 5;
pub const SOURCE_BOUND_ADAPTER_CONTRACT: &str = "source-bound-evaluation-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationContract {
    SourceBoundV2,
}

/// Layer choice is an approved requirement. Route denial is an independent
/// direct-path effect, never an alternative to an IAM authorization denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptedDenialLayer {
    ConnectionAuthorization,
    DatabaseLogin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDenialRequirement {
    pub profile_id: String,
    pub accepted_layers: Vec<AcceptedDenialLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationPolicy {
    pub contract: EvaluationContract,
    pub denial_requirements: Vec<ProfileDenialRequirement>,
}
impl EvaluationPolicy {
    pub(crate) fn validate(&self, policy: &PolicyRevision) -> Result<(), PolicyError> {
        if self.denial_requirements.len() != policy.protection_profiles.len()
            || self
                .denial_requirements
                .iter()
                .map(|r| &r.profile_id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.denial_requirements.len()
        {
            return Err(PolicyError::ReferenceInvalid);
        }
        for requirement in &self.denial_requirements {
            if !policy
                .protection_profiles
                .iter()
                .any(|p| p.id == requirement.profile_id)
                || requirement.accepted_layers.is_empty()
                || requirement.accepted_layers.len() > 2
                || requirement
                    .accepted_layers
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != requirement.accepted_layers.len()
            {
                return Err(PolicyError::ReferenceInvalid);
            }
        }
        Ok(())
    }
    pub(crate) fn normalize(&mut self) {
        self.denial_requirements
            .sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
        for requirement in &mut self.denial_requirements {
            requirement.accepted_layers.sort();
        }
    }
}

/// Explicit acceptance of provider-managed backend TLS identity handling. This
/// is not an observation that the provider verified a CA or hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendTlsTrustContract {
    AwsRdsProxyManagedEncryptionV1,
}

/// Actual transport segments and boundary proofs stay distinct from login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportSegment {
    ClientToNativeRoute,
    NativeRouteToDatabase,
    LocalIpcBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectKindV2 {
    NewConnections,
    ExistingSessions,
    EffectiveSqlPrivilege {
        scope: SqlScope,
        action: SqlAction,
    },
    EffectiveSqlRole {
        role: String,
    },
    OwnedSqlDelta {
        receipt_digest: String,
        delta_digest: String,
    },
    RuntimeBinding,
    BindingPublication,
    Transport {
        segment: TransportSegment,
    },
    LeaseExpiry,
}

/// Stable across an approved Allow -> Deny transition. Policy revision and the
/// required denial layer are deliberately NOT part of the effect address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAddress {
    pub target_id: String,
    pub target: TargetHandle,
    pub grant_id: String,
    pub subject_id: String,
    pub db_identity: String,
    pub source: SourceSnapshotRef,
    pub route: StateRoute,
    pub effect: EffectKindV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceFacet {
    Target,
    Principal,
    Source,
    Route,
    Transport,
    Temporal,
    Completeness,
}

/// NotApplicable requires a named, verifier-recognized contract rule. Merely
/// deserializing this type never establishes that the rule or proof is valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Assurance {
    Verified { evidence_refs: Vec<String> },
    Unconfirmed { reason: EvidenceReason },
    Unsupported { reason: EvidenceReason },
    NotApplicable { contract_rule: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceReason {
    MissingEvidence,
    TargetUnconfirmed,
    PrincipalUnconfirmed,
    SourceUnconfirmed,
    ContextUnverified,
    RouteUnconfirmed,
    TransportUnconfirmed,
    ProviderManagedTlsValidationUnobservable,
    NativeLogOriginUnconfirmed,
    TemporalUnconfirmed,
    IncompleteCapture,
    UnsupportedProducer,
    WrongDenialLayer,
    UncorroboratedDenial,
    MissingAdmission,
    IntegrityError,
    ContractMismatch,
    BuildMismatch,
    TrustEpochMismatch,
    StaleEvidence,
    RuntimeBindingUnverified,
    PermissionInventoryIncomplete,
    CatalogIdentityUnconfirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceCoverage {
    // Explicit fields prevent a missing facet from defaulting to Verified.
    pub target: Assurance,
    pub principal: Assurance,
    pub source: Assurance,
    pub route: Assurance,
    pub transport: Assurance,
    pub temporal: Assurance,
    pub completeness: Assurance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPurpose {
    SameSourceRouteReachability,
    TargetHealth,
    CredentialValidity,
    NativeBoundaryDecision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlReference {
    /// None = this bundle. An external digest must resolve to an independently
    /// admitted bundle; cross-bundle control validation belongs to K10-B/D.
    pub bundle_digest: Option<String>,
    pub claim_id: String,
    pub purpose: ControlPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportFact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_basis: Option<BackendTlsTrustContract>,
    pub segment: TransportSegment,
    pub encrypted: Option<bool>,
    pub ca_verified: Option<bool>,
    pub hostname_verified: Option<bool>,
    pub ipc_boundary_verified: Option<bool>,
    pub evidence_refs: Vec<String>,
}

/// These are selected identifiers/context, not a catalog dump or customer rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlAuthorizationContext {
    pub session_user: String,
    pub current_user: String,
    pub active_roles: Vec<String>,
    pub login_catalog_identity: Option<String>,
    pub object_catalog_identity: Option<String>,
    pub permission_inventory_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationClaim {
    /// Partial process/socket observation. It never establishes a PostgreSQL
    /// session, credential provider, pool generation or complete binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_capture: Option<super::runtime_binding::LinuxRuntimeCaptureWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_login_failure: Option<crate::core::postgres_login::PostgresLoginFailure>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_catalog: Vec<crate::core::postgres_login::LoginCatalogFact>,
    pub id: String,
    pub case_id: String,
    pub policy_revision_hash: String,
    pub address: EffectAddress,
    pub started_at: u64,
    pub finished_at: u64,
    pub observed: StateValue,
    pub layer: StateLayer,
    pub denial_cause: Option<DenialCause>,
    pub connection: Option<ConnectionTuple>,
    pub controls: Vec<ControlReference>,
    pub transport: Vec<TransportFact>,
    pub sql_context: Option<SqlAuthorizationContext>,
    pub evidence_refs: Vec<String>,
    /// A trusted producer must cover all relevant native permission paths.
    /// An owned binding deletion alone cannot set complete=true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_inventory: Option<NativePermissionInventory>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePermissionInventory {
    pub complete: bool,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionTuple {
    pub endpoint: String,
    pub local_ip: std::net::IpAddr,
    pub local_port: u16,
    pub peer_ip: std::net::IpAddr,
    pub peer_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedObservationCase {
    NewConnection,
    DirectPath,
    TargetHealth,
    EffectiveSqlPrivilege,
    OwnedSqlDelta,
    Transport,
    RuntimeBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_trust: Option<BackendTlsTrustContract>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub login_catalog_targets: Vec<crate::core::postgres_login::LoginCatalogTarget>,
    /// Approved MySQL account selector, distinct from the connection username.
    /// Omitted in historical GCE/PG and source-only AWS request wire bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql_account_host: Option<String>,
    pub id: String,
    pub kind: FixedObservationCase,
    pub address: EffectAddress,
    pub purpose: SourcePurpose,
    pub endpoint: String,
    pub port: u16,
    pub address_family: AddressFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRequest {
    pub schema_version: u32,
    pub request_id: String,
    /// 256-bit nonce supplied by the application CSPRNG (K10-B). Shape
    /// validation cannot establish entropy or replace atomic nonce admission.
    pub nonce: String,
    pub policy_revision_hash: String,
    pub change_hash: String,
    pub operation_id: String,
    pub source: SourceBinding,
    pub source_trust_epoch: u64,
    pub evaluation_contract: EvaluationContract,
    pub collector_build_id: String,
    pub verifier_build_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub cases: Vec<RequestedCase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("EVIDENCE_INVALID: invalid or incompatible evidence protocol input")]
    Invalid,
    #[error("EVIDENCE_LIMIT: evidence protocol input exceeds the local limit")]
    Limit,
}

impl ObservationRequest {
    pub fn parse_untrusted(input: &[u8]) -> Result<Self, EvidenceError> {
        if input.len() > MAX_REQUEST_BYTES {
            return Err(EvidenceError::Limit);
        }
        let request: Self = serde_json::from_slice(input).map_err(|_| EvidenceError::Invalid)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.cases.is_empty() || self.cases.len() > MAX_CASES_PER_SOURCE {
            return Err(EvidenceError::Limit);
        }
        if self.schema_version != 1
            || !valid_id(&self.request_id)
            || !valid_id(&self.operation_id)
            || self.source_trust_epoch == 0
            || self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_REQUEST_TTL_SECONDS
            || [
                &self.nonce,
                &self.policy_revision_hash,
                &self.change_hash,
                &self.collector_build_id,
                &self.verifier_build_id,
            ]
            .iter()
            .any(|s| !valid_hash(s))
            || self.source.validate().is_err()
            || self
                .cases
                .iter()
                .map(|c| &c.id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.cases.len()
        {
            return Err(EvidenceError::Invalid);
        }
        for case in &self.cases {
            if case.login_catalog_targets.len() > 8
                || case.login_catalog_targets.iter().any(|t| !t.valid())
                || case
                    .login_catalog_targets
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != case.login_catalog_targets.len()
                || (!case.login_catalog_targets.is_empty()
                    && (case.purpose != SourcePurpose::Recovery
                        || !matches!(
                            case.kind,
                            FixedObservationCase::TargetHealth
                                | FixedObservationCase::NewConnection
                        )
                        || case.address.effect != EffectKindV2::NewConnections
                        || case.address.route.kind == super::policy::RouteKind::Direct
                        || case.address.target.engine_binding.family
                            != super::policy::EngineFamily::PostgreSql))
            {
                return Err(EvidenceError::Invalid);
            }
            if case.backend_tls_trust.is_some()
                && (case.kind != FixedObservationCase::Transport
                    || case.address.effect
                        != (EffectKindV2::Transport {
                            segment: TransportSegment::NativeRouteToDatabase,
                        })
                    || case.address.route.kind != super::policy::RouteKind::NativeProxy
                    || case.address.target.placement.kind != super::policy::PlacementKind::AwsRds
                    || self.source.boundary != super::source::SourceBoundaryKind::AwsHostNetwork
                    || !matches!(
                        case.address.target.engine_binding.family,
                        super::policy::EngineFamily::PostgreSql
                            | super::policy::EngineFamily::MySql
                    ))
            {
                return Err(EvidenceError::Invalid);
            }
            if case.mysql_account_host.as_ref().is_some_and(|host| {
                case.address.target.engine_binding.family != super::policy::EngineFamily::MySql
                    || !super::policy::mysql_account_host(host)
            }) {
                return Err(EvidenceError::Invalid);
            }
            if !valid_id(&case.id)
                || case.port == 0
                || !endpoint_name(&case.endpoint)
                || case.address.source != self.source.snapshot_ref()
                || !self
                    .source
                    .allowed_uses
                    .iter()
                    .any(|u| u.subject_id == case.address.subject_id && u.purpose == case.purpose)
                || !valid_address(&case.address)
                || !case_matches_effect(case.kind, &case.address.effect)
            {
                return Err(EvidenceError::Invalid);
            }
        }
        Ok(())
    }

    /// Request identity, not an audience URL and never an instruction to fetch.
    pub fn digest(&self) -> Result<String, EvidenceError> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.cases.sort_by(|a, b| a.id.cmp(&b.id));
        canonical.source.allowed_uses.sort();
        let mut bytes = b"veil-db-guard/observation-request/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&canonical).map_err(|_| EvidenceError::Invalid)?);
        Ok(super::hash_bytes(&bytes))
    }
}

fn endpoint_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
        && !value.contains("..")
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.chars().any(char::is_control)
        && !value.contains("://")
        && !value.contains("${")
        && !value.contains("{{")
        && !["password=", "pwd=", "token=", "secret="]
            .iter()
            .any(|s| value.to_ascii_lowercase().contains(s))
}

pub(super) fn valid_address(address: &EffectAddress) -> bool {
    [
        &address.target_id,
        &address.grant_id,
        &address.subject_id,
        &address.route.id,
        &address.target.registration_id,
    ]
    .iter()
    .all(|s| valid_id(s))
        && safe_identifier(&address.db_identity)
        && safe_identifier(&address.target.native_ref.native_id)
        && safe_identifier(&address.target.placement.account_id)
        && valid_id(&address.target.placement.region)
        && safe_identifier(&address.target.engine_binding.database)
        && safe_identifier(&address.target.engine_binding.version)
        && address
            .target
            .native_ref
            .generation_fingerprint
            .as_ref()
            .is_some_and(|s| valid_hash(s))
        && address.source.validate().is_ok()
        && match &address.effect {
            EffectKindV2::EffectiveSqlPrivilege { scope, .. } => super::policy::valid_scope(scope),
            EffectKindV2::EffectiveSqlRole { role } => safe_identifier(role),
            EffectKindV2::OwnedSqlDelta {
                receipt_digest,
                delta_digest,
            } => valid_hash(receipt_digest) && valid_hash(delta_digest),
            _ => true,
        }
}

fn case_matches_effect(case: FixedObservationCase, effect: &EffectKindV2) -> bool {
    matches!(
        (case, effect),
        (
            FixedObservationCase::NewConnection
                | FixedObservationCase::DirectPath
                | FixedObservationCase::TargetHealth,
            EffectKindV2::NewConnections
        ) | (
            FixedObservationCase::EffectiveSqlPrivilege,
            EffectKindV2::EffectiveSqlPrivilege { .. } | EffectKindV2::EffectiveSqlRole { .. }
        ) | (
            FixedObservationCase::OwnedSqlDelta,
            EffectKindV2::OwnedSqlDelta { .. }
        ) | (
            FixedObservationCase::Transport,
            EffectKindV2::Transport { .. }
        ) | (
            FixedObservationCase::RuntimeBinding,
            EffectKindV2::RuntimeBinding
        )
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationBundleWire {
    pub schema_version: u32,
    pub request_digest: String,
    pub collector_build_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub capture_complete: bool,
    pub claims: Vec<ObservationClaim>,
    pub artifacts: Vec<ArtifactRef>,
}

impl ObservationBundleWire {
    /// Strict bounded syntax + shape validation only. This MUST NOT produce
    /// verified facts; channel, identity and admission are not checked here.
    pub fn parse_untrusted(input: &[u8]) -> Result<Self, EvidenceError> {
        if input.len() > MAX_BUNDLE_BYTES {
            return Err(EvidenceError::Limit);
        }
        let bundle: Self = serde_json::from_slice(input).map_err(|_| EvidenceError::Invalid)?;
        bundle.validate_shape()?;
        Ok(bundle)
    }

    pub fn validate_shape(&self) -> Result<(), EvidenceError> {
        if self.claims.len() > 64 || self.artifacts.len() > 128 {
            return Err(EvidenceError::Limit);
        }
        if self.schema_version != EVIDENCE_WIRE_SCHEMA_VERSION
            || !valid_hash(&self.request_digest)
            || !valid_hash(&self.collector_build_id)
            || self.started_at == 0
            || self.finished_at < self.started_at
            || self.finished_at - self.started_at > MAX_CAPTURE_SECONDS
            || self
                .claims
                .iter()
                .map(|c| &c.id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.claims.len()
            || self
                .artifacts
                .iter()
                .map(|a| &a.id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.artifacts.len()
            || self
                .artifacts
                .iter()
                .any(|a| !valid_id(&a.id) || !valid_hash(&a.sha256))
        {
            return Err(EvidenceError::Invalid);
        }
        for claim in &self.claims {
            if claim.runtime_capture.is_some()
                && (claim.address.effect != EffectKindV2::RuntimeBinding
                    || claim.observed != StateValue::Unknown
                    || claim.layer != StateLayer::Configuration
                    || claim.denial_cause.is_some()
                    || claim.sql_context.is_some()
                    || !claim.transport.is_empty()
                    || !claim.controls.is_empty())
            {
                return Err(EvidenceError::Invalid);
            }
            if claim.login_catalog.len() > 8
                || claim
                    .login_catalog
                    .iter()
                    .any(|f| !f.target.valid() || f.role_oid == 0)
                || claim
                    .login_catalog
                    .iter()
                    .map(|f| &f.target)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != claim.login_catalog.len()
                || (!claim.login_catalog.is_empty()
                    && (claim.address.effect != EffectKindV2::NewConnections
                        || claim.observed != StateValue::Allowed
                        || claim.address.route.kind == super::policy::RouteKind::Direct
                        || claim.address.target.engine_binding.family
                            != super::policy::EngineFamily::PostgreSql))
                || claim.postgres_login_failure.as_ref().is_some_and(|f| {
                    !crate::core::postgres_login::identity(&f.db_identity)
                        || f.db_identity != claim.address.db_identity
                        || claim.address.effect != EffectKindV2::NewConnections
                        || claim.observed != StateValue::Denied
                        || claim.layer != StateLayer::Authentication
                        || claim.denial_cause != Some(DenialCause::LoginRejected)
                        || claim.address.route.kind == super::policy::RouteKind::Direct
                        || claim.address.target.engine_binding.family
                            != super::policy::EngineFamily::PostgreSql
                })
            {
                return Err(EvidenceError::Invalid);
            }
            if !valid_id(&claim.id)
                || !valid_id(&claim.case_id)
                || !valid_hash(&claim.policy_revision_hash)
                || !valid_address(&claim.address)
                || claim.started_at < self.started_at
                || claim.finished_at > self.finished_at
                || claim.finished_at < claim.started_at
                || claim.controls.len() > MAX_CASES_PER_SOURCE
                || claim.transport.len() > 3
                || claim.transport.iter().enumerate().any(|(index, t)| {
                    claim.transport[..index]
                        .iter()
                        .any(|prior| prior.segment == t.segment)
                })
                || claim.evidence_refs.len() > 128
                || claim
                    .evidence_refs
                    .iter()
                    .any(|r| !self.artifacts.iter().any(|a| a.id == *r))
                || claim.controls.iter().any(|r| {
                    !valid_id(&r.claim_id)
                        || match &r.bundle_digest {
                            Some(digest) => !valid_hash(digest),
                            None => {
                                r.claim_id == claim.id
                                    || !self.claims.iter().any(|c| c.id == r.claim_id)
                            }
                        }
                })
                || claim.connection.as_ref().is_some_and(|c| {
                    !endpoint_name(&c.endpoint)
                        || c.local_port == 0
                        || c.peer_port == 0
                        || c.local_ip.is_ipv4() != c.peer_ip.is_ipv4()
                })
                || claim.transport.iter().any(|t| {
                    (t.validation_basis.is_some()
                        && (t.segment != TransportSegment::NativeRouteToDatabase
                            || t.ca_verified.is_some()
                            || t.hostname_verified.is_some()))
                        || t.evidence_refs.len() > 128
                        || t.evidence_refs
                            .iter()
                            .any(|r| !self.artifacts.iter().any(|a| a.id == *r))
                })
                || claim.permission_inventory.as_ref().is_some_and(|p| {
                    claim.address.effect != EffectKindV2::NewConnections
                        || claim.observed != StateValue::Unknown
                        || p.permissions.len() > 512
                        || p.permissions.iter().any(|v| !safe_identifier(v))
                        || p.permissions.iter().collect::<BTreeSet<_>>().len()
                            != p.permissions.len()
                })
                || claim.sql_context.as_ref().is_some_and(|c| {
                    !safe_identifier(&c.session_user)
                        || !safe_identifier(&c.current_user)
                        || c.active_roles.len() > 128
                        || c.active_roles.iter().any(|s| !safe_identifier(s))
                        || [&c.login_catalog_identity, &c.object_catalog_identity]
                            .iter()
                            .any(|s| s.as_ref().is_some_and(|s| !safe_identifier(s)))
                })
            {
                return Err(EvidenceError::Invalid);
            }
        }
        // The graph is tiny and bounded. Reject cycles, including indirect ones.
        fn cycle(
            bundle: &ObservationBundleWire,
            id: &str,
            path: &mut Vec<String>,
            done: &mut BTreeSet<String>,
        ) -> bool {
            if done.contains(id) {
                return false;
            }
            if path.iter().any(|p| p == id) {
                return true;
            }
            path.push(id.to_owned());
            let found = bundle.claims.iter().find(|c| c.id == id).is_some_and(|c| {
                c.controls
                    .iter()
                    .filter(|r| r.bundle_digest.is_none())
                    .any(|r| cycle(bundle, &r.claim_id, path, done))
            });
            path.pop();
            done.insert(id.to_owned());
            found
        }
        if self
            .claims
            .iter()
            .any(|c| cycle(self, &c.id, &mut Vec::new(), &mut BTreeSet::new()))
        {
            return Err(EvidenceError::Invalid);
        }
        Ok(())
    }
}

/// Deliberately not Deserialize and no public constructor. K10-B's trusted
/// verifier/admission assembly will be the only creation path. A wire claim,
/// v1 identity_confirmed bool or copied bundle cannot enter this type.
///
/// ```compile_fail
/// use veil_db_guard::core::evidence::VerifiedObservationFacts;
/// let _: VerifiedObservationFacts = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedObservationFacts {
    request_digest: String,
    bundle_digest: String,
    admission_id: String,
    claims: Vec<ObservationClaim>,
    assurances: Vec<ClaimAssurance>,
    admission: super::admission::EvidenceAdmission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimAssurance {
    pub claim_id: String,
    pub coverage: AssuranceCoverage,
}

impl VerifiedObservationFacts {
    pub(super) fn admitted(
        request_digest: String,
        bundle_digest: String,
        admission_id: String,
        claims: Vec<ObservationClaim>,
        assurances: Vec<ClaimAssurance>,
        admission: super::admission::EvidenceAdmission,
    ) -> Self {
        Self {
            request_digest,
            bundle_digest,
            admission_id,
            claims,
            assurances,
            admission,
        }
    }
    pub fn admission(&self) -> &super::admission::EvidenceAdmission {
        &self.admission
    }
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    pub fn bundle_digest(&self) -> &str {
        &self.bundle_digest
    }
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }
    pub fn claims(&self) -> &[ObservationClaim] {
        &self.claims
    }
    pub fn assurances(&self) -> &[ClaimAssurance] {
        &self.assurances
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredEffectV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_trust: Option<BackendTlsTrustContract>,
    pub id: String,
    pub policy_revision_hash: String,
    pub address: EffectAddress,
    pub expected: StateValue,
    pub accepted_denial_layers: Vec<AcceptedDenialLayer>,
    pub required_assurance: Vec<AssuranceFacet>,
}

/// Pure evaluation input. Only admitted facts enter v2; v1 wire records are
/// never upgraded. Reload with admission::evaluate_admitted_change for status.
#[derive(Debug, Clone, Serialize)]
pub struct StateEvaluationInputV2 {
    pub contract: EvaluationContract,
    pub now: u64,
    pub max_age_seconds: u64,
    pub desired: Vec<RequiredEffectV2>,
    pub evidence: Vec<VerifiedObservationFacts>,
    pub permission_removals: Vec<super::state_v2::PermissionRemovalV2>,
}

#[cfg(test)]
impl VerifiedObservationFacts {
    pub(super) fn test_claims(&mut self) -> &mut Vec<ObservationClaim> {
        &mut self.claims
    }
    pub(super) fn test_assurances(&mut self) -> &mut Vec<ClaimAssurance> {
        &mut self.assurances
    }
    pub(super) fn test_admission(&mut self) -> &mut super::admission::EvidenceAdmission {
        &mut self.admission
    }
}
