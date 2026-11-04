//! Pure source-bound evaluation. Only locally admitted facts enter this module.
//! No network, filesystem, adapter, or operation-store dependency.
use super::{
    approval::ApprovalGrant,
    change::PreparedChange,
    evidence::*,
    operation::Operation,
    policy::{self, AdmissionIntent, PolicyRevision, RouteKind, TargetHandle},
    state::{self, DenialCause, StateAssessment, StateError, StateLayer, StateReason, StateValue},
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct ObservationV2 {
    pub bundle_digest: String,
    pub claim: ObservationClaim,
    pub eligible: bool,
    pub reason: Option<EvidenceReason>,
    pub missing_assurance: Vec<AssuranceFacet>,
}
#[derive(Debug, Clone, Serialize)]
pub struct StateRowV2 {
    pub desired: RequiredEffectV2,
    pub observed: StateValue,
    pub assessment: StateAssessment,
    pub reasons: Vec<StateReason>,
    pub history: Vec<ObservationV2>,
    pub current_claims: Vec<String>,
    pub missing_assurance: Vec<AssuranceFacet>,
    pub propagation_deadline: Option<u64>,
    pub protection_evaluated: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct StateReportV2 {
    pub schema_version: u32,
    pub evaluated_at: u64,
    pub assessment: StateAssessment,
    pub rows: Vec<StateRowV2>,
    pub protection_evaluated: bool,
    pub all_required_effects_satisfied: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub derived_controls: Vec<DerivedControlLink>,
}
/// Evaluation annotation derived from CURRENT admitted facts. Original bundle
/// bytes/claims/receipts remain unchanged and keep their original digest.
#[derive(Debug, Clone, Serialize)]
pub struct DerivedControlLink {
    pub owner_bundle_digest: String,
    pub owner_claim_id: String,
    pub control: ControlReference,
}

fn all_facets() -> Vec<AssuranceFacet> {
    vec![
        AssuranceFacet::Target,
        AssuranceFacet::Principal,
        AssuranceFacet::Source,
        AssuranceFacet::Route,
        AssuranceFacet::Transport,
        AssuranceFacet::Temporal,
        AssuranceFacet::Completeness,
    ]
}
fn facet(c: &AssuranceCoverage, f: AssuranceFacet) -> &Assurance {
    match f {
        AssuranceFacet::Target => &c.target,
        AssuranceFacet::Principal => &c.principal,
        AssuranceFacet::Source => &c.source,
        AssuranceFacet::Route => &c.route,
        AssuranceFacet::Transport => &c.transport,
        AssuranceFacet::Temporal => &c.temporal,
        AssuranceFacet::Completeness => &c.completeness,
    }
}
fn coverage<'a>(
    f: &'a VerifiedObservationFacts,
    c: &ObservationClaim,
) -> Option<&'a AssuranceCoverage> {
    f.assurances()
        .iter()
        .find(|a| a.claim_id == c.id)
        .map(|a| &a.coverage)
}
fn missing(
    f: &VerifiedObservationFacts,
    c: &ObservationClaim,
    required: &[AssuranceFacet],
) -> Vec<AssuranceFacet> {
    required
        .iter()
        .copied()
        .filter(|k| {
            coverage(f, c).is_none_or(|a| !matches!(facet(a, *k), Assurance::Verified { .. }))
        })
        .collect()
}
fn fresh(
    input: &StateEvaluationInputV2,
    f: &VerifiedObservationFacts,
    c: &ObservationClaim,
) -> bool {
    let a = f.admission();
    a.evaluation_contract == input.contract
        && a.accepted_at <= input.now
        && input.now < a.valid_until
        && c.started_at <= c.finished_at
        && c.finished_at <= input.now.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        && input.now.saturating_sub(c.started_at) <= input.max_age_seconds
        && c.started_at >= a.capture_started_at
        && c.finished_at <= a.capture_finished_at
        && a.source_snapshot_digest == c.address.source.revision_digest
}
fn same_effect(a: &EffectAddress, b: &EffectAddress) -> bool {
    a.target_id == b.target_id
        && a.grant_id == b.grant_id
        && a.subject_id == b.subject_id
        && a.db_identity == b.db_identity
        && a.source.source_id == b.source.source_id
        && a.route == b.route
        && a.effect == b.effect
}
fn base_reason(
    input: &StateEvaluationInputV2,
    f: &VerifiedObservationFacts,
    c: &ObservationClaim,
    d: &RequiredEffectV2,
) -> Option<EvidenceReason> {
    if c.policy_revision_hash != d.policy_revision_hash || c.address != d.address {
        return Some(EvidenceReason::ContractMismatch);
    }
    if !fresh(input, f, c) {
        return Some(EvidenceReason::StaleEvidence);
    }
    if f.admission().policy_revision_hash != d.policy_revision_hash {
        return Some(EvidenceReason::ContractMismatch);
    }
    None
}
fn control(
    input: &StateEvaluationInputV2,
    owner: &VerifiedObservationFacts,
    c: &ObservationClaim,
    purpose: ControlPurpose,
    automatic_health: bool,
) -> bool {
    let explicit = c.controls.iter().filter(|r| r.purpose == purpose).any(|r| {
        let digest = r.bundle_digest.as_deref().unwrap_or(owner.bundle_digest());
        input
            .evidence
            .iter()
            .find(|f| f.bundle_digest() == digest)
            .is_some_and(|f| {
                f.claims()
                    .iter()
                    .find(|other| other.id == r.claim_id)
                    .is_some_and(|other| {
                        if other.id == c.id && digest == owner.bundle_digest() {
                            return false;
                        }
                        if !fresh(input, f, other)
                            || !missing(f, other, &all_facets()).is_empty()
                            || other.address.target != c.address.target
                            || other.policy_revision_hash != c.policy_revision_hash
                            || other.started_at
                                > c.finished_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
                            || c.started_at
                                > other.finished_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
                        {
                            return false;
                        }
                        match purpose {
                            ControlPurpose::TargetHealth => {
                                other.observed == StateValue::Allowed
                                    && other.address.effect == EffectKindV2::NewConnections
                            }
                            ControlPurpose::SameSourceRouteReachability
                            | ControlPurpose::CredentialValidity => {
                                other.address.source == c.address.source
                                    && other.address.route == c.address.route
                                    && other.address.subject_id == c.address.subject_id
                                    && other.address.db_identity == c.address.db_identity
                                    && other.observed == StateValue::Allowed
                                    && other.address.effect == EffectKindV2::NewConnections
                            }
                            ControlPurpose::NativeBoundaryDecision => {
                                other.address == c.address
                                    && other.observed == StateValue::Denied
                                    && other.layer == c.layer
                                    && other.denial_cause == c.denial_cause
                            }
                        }
                    })
            })
    });
    explicit
        || (automatic_health
            && purpose == ControlPurpose::TargetHealth
            && !c
                .controls
                .iter()
                .any(|r| r.purpose == ControlPurpose::TargetHealth)
            && native_health(input, owner, c).is_some())
        || (automatic_health
            && purpose == ControlPurpose::CredentialValidity
            && !c
                .controls
                .iter()
                .any(|r| r.purpose == ControlPurpose::CredentialValidity)
            && login::corroboration(input, owner, c).is_some())
}
fn native_health<'a>(
    input: &'a StateEvaluationInputV2,
    owner: &VerifiedObservationFacts,
    c: &ObservationClaim,
) -> Option<(&'a VerifiedObservationFacts, &'a ObservationClaim)> {
    if c.postgres_login_failure.is_some() {
        return login::corroboration(input, owner, c);
    }
    if owner.admission().verification_recipe != "gce-host-network-root-v1"
        || c.observed != StateValue::Denied
        || c.layer != StateLayer::ConnectionAuthorization
        || c.denial_cause != Some(DenialCause::PermissionDenied)
        || c.address.source.boundary != super::source::SourceBoundaryKind::GceHostNetwork
        || c.address.route.kind != RouteKind::NativeConnector
        || !fresh(input, owner, c)
        || !missing(owner, c, &all_facets()).is_empty()
        || !control(
            input,
            owner,
            c,
            ControlPurpose::NativeBoundaryDecision,
            false,
        )
    {
        return None;
    }
    input
        .evidence
        .iter()
        .flat_map(|f| f.claims().iter().map(move |other| (f, other)))
        .find(|(f, other)| {
            f.admission().operation_id == owner.admission().operation_id
                && f.admission().change_hash == owner.admission().change_hash
                && other.address.source != c.address.source
                && other.address.subject_id != c.address.subject_id
                && other.address.target == c.address.target
                && other.policy_revision_hash == c.policy_revision_hash
                && other.observed == StateValue::Allowed
                && other.layer == StateLayer::Authentication
                && other.address.effect == EffectKindV2::NewConnections
                && other.address.route.kind != RouteKind::Direct
                && fresh(input, f, other)
                && missing(f, other, &all_facets()).is_empty()
                && other.started_at <= c.finished_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
                && c.started_at <= other.finished_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
                && health_is_current(input, f, other)
                && input.desired.iter().any(|d| {
                    d.address == other.address
                        && d.policy_revision_hash == other.policy_revision_hash
                        && d.expected == StateValue::Allowed
                })
        })
}

// A historical Allowed must not corroborate a more recent failed/unknown
// recovery observation. Use the same non-overlapping current frontier as rows.
fn health_is_current(
    input: &StateEvaluationInputV2,
    owner: &VerifiedObservationFacts,
    c: &ObservationClaim,
) -> bool {
    let Some(d) = input.desired.iter().find(|d| {
        d.address == c.address
            && d.policy_revision_hash == c.policy_revision_hash
            && d.expected == StateValue::Allowed
    }) else {
        return false;
    };
    let candidates: Vec<_> = input
        .evidence
        .iter()
        .flat_map(|f| f.claims().iter().map(move |c| (f, c)))
        .filter(|(f, c)| {
            c.permission_inventory.is_none()
                && same_effect(&c.address, &d.address)
                && base_reason(input, f, c, d).is_none()
        })
        .collect();
    let times: Vec<_> = candidates
        .iter()
        .map(|(_, c)| (c.started_at, c.finished_at))
        .collect();
    let current = state::current_indices(&times);
    current.iter().any(|n| {
        candidates[*n].0.bundle_digest() == owner.bundle_digest() && candidates[*n].1.id == c.id
    }) && current.iter().all(|n| {
        let (f, c) = candidates[*n];
        c.observed == StateValue::Allowed && quality(input, f, c, d, false).is_none()
    })
}

fn quality(
    input: &StateEvaluationInputV2,
    f: &VerifiedObservationFacts,
    c: &ObservationClaim,
    d: &RequiredEffectV2,
    automatic_health: bool,
) -> Option<StateReason> {
    if !missing(f, c, &d.required_assurance).is_empty() {
        return Some(StateReason::IdentityUnconfirmed);
    }
    if c.observed != StateValue::Unknown && c.observed != StateValue::Denied {
        let expected = match c.address.effect {
            EffectKindV2::NewConnections | EffectKindV2::Transport { .. } => {
                StateLayer::Authentication
            }
            EffectKindV2::EffectiveSqlPrivilege { .. }
            | EffectKindV2::EffectiveSqlRole { .. }
            | EffectKindV2::OwnedSqlDelta { .. } => StateLayer::SqlAuthorization,
            EffectKindV2::ExistingSessions => StateLayer::SessionControl,
            EffectKindV2::RuntimeBinding | EffectKindV2::BindingPublication => {
                StateLayer::Configuration
            }
            EffectKindV2::LeaseExpiry => StateLayer::LeaseControl,
        };
        if c.layer != expected {
            return Some(StateReason::WrongDenialLayer);
        }
    }
    if c.observed == StateValue::Denied {
        if c.address.effect != EffectKindV2::NewConnections {
            return Some(StateReason::WrongDenialLayer);
        }
        if c.address.route.kind == RouteKind::Direct {
            if c.layer != StateLayer::RouteEnforcement
                || c.denial_cause != Some(DenialCause::RouteBlocked)
            {
                return Some(StateReason::WrongDenialLayer);
            }
            if !control(
                input,
                f,
                c,
                ControlPurpose::NativeBoundaryDecision,
                automatic_health,
            ) {
                return Some(StateReason::UncorroboratedDenial);
            }
        } else {
            let accepted = match c.layer {
                StateLayer::ConnectionAuthorization
                    if c.denial_cause == Some(DenialCause::PermissionDenied) =>
                {
                    Some(AcceptedDenialLayer::ConnectionAuthorization)
                }
                StateLayer::Authentication
                    if c.denial_cause == Some(DenialCause::LoginRejected) =>
                {
                    Some(AcceptedDenialLayer::DatabaseLogin)
                }
                _ => None,
            };
            if accepted.is_none_or(|a| !d.accepted_denial_layers.contains(&a)) {
                return Some(StateReason::WrongDenialLayer);
            }
            if !control(
                input,
                f,
                c,
                ControlPurpose::NativeBoundaryDecision,
                automatic_health,
            ) || !control(input, f, c, ControlPurpose::TargetHealth, automatic_health)
                || (c.layer == StateLayer::Authentication
                    && (!control(
                        input,
                        f,
                        c,
                        ControlPurpose::CredentialValidity,
                        automatic_health,
                    ) || (c
                        .sql_context
                        .as_ref()
                        .is_none_or(|s| s.login_catalog_identity.is_none())
                        && !(automatic_health && login::corroboration(input, f, c).is_some()))))
            {
                return Some(StateReason::UncorroboratedDenial);
            }
        }
    } else if c.denial_cause.is_some() && c.observed != StateValue::Unknown {
        return Some(StateReason::ContradictoryEvidence);
    }
    if matches!(
        c.address.effect,
        EffectKindV2::EffectiveSqlPrivilege { .. } | EffectKindV2::EffectiveSqlRole { .. }
    ) && c.sql_context.as_ref().is_none_or(|s| {
        s.login_catalog_identity.is_none()
            || s.object_catalog_identity.is_none()
            || (c.observed == StateValue::Absent && !s.permission_inventory_complete)
    }) {
        return Some(StateReason::IncompleteCapture);
    }
    if let EffectKindV2::Transport { segment } = c.address.effect {
        let valid = c.transport.iter().any(|t| {
            t.segment == segment
                && match segment {
                    TransportSegment::LocalIpcBoundary => t.ipc_boundary_verified == Some(true),
                    TransportSegment::NativeRouteToDatabase if d.backend_tls_trust.is_some() => {
                        c.transport.iter().filter(|v| v.segment == segment).count() == 1
                            && t.encrypted == Some(true)
                            && t.validation_basis == d.backend_tls_trust
                            && t.ca_verified.is_none()
                            && t.hostname_verified.is_none()
                            && c.address.route.kind == RouteKind::NativeProxy
                            && c.address.target.placement.kind == policy::PlacementKind::AwsRds
                            && c.address.source.boundary
                                == super::source::SourceBoundaryKind::AwsHostNetwork
                            && matches!(
                                c.address.target.engine_binding.family,
                                policy::EngineFamily::PostgreSql | policy::EngineFamily::MySql
                            )
                            && f.admission().verification_recipe == "aws-ec2-host-network-root-v1"
                    }
                    _ => {
                        t.validation_basis.is_none()
                            && t.encrypted == Some(true)
                            && t.ca_verified == Some(true)
                            && t.hostname_verified == Some(true)
                    }
                }
        });
        if !valid {
            return Some(StateReason::IncompleteCapture);
        }
    }
    None
}

/// The reference values are untrusted until checked against admitted facts and
/// the exact immutable change/approval/operation. No wire boolean grants Pending.
#[derive(Debug, Clone)]
pub struct RemovalReferencesV2 {
    pub before_inventory: (String, String),
    pub after_inventory: (String, String),
    pub prior_allowed: (String, String),
    pub changed_at: u64,
    pub deadline: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct PermissionRemovalV2 {
    address: EffectAddress,
    policy_revision_hash: String,
    before_policy_revision_hash: String,
    change_hash: String,
    operation_id: String,
    references: RemovalReferencesWire,
    partial_failure: bool,
}
#[derive(Debug, Clone, Serialize)]
struct RemovalReferencesWire {
    before_inventory: (String, String),
    after_inventory: (String, String),
    prior_allowed: (String, String),
    changed_at: u64,
    deadline: u64,
}
impl PermissionRemovalV2 {
    pub fn from_approved_change(
        change: &PreparedChange,
        approval: &ApprovalGrant,
        op: &Operation,
        address: &EffectAddress,
        r: RemovalReferencesV2,
    ) -> Result<Self, StateError> {
        change.verify().map_err(|_| StateError::Invalid)?;
        approval
            .validate(change, &op.execution_identity, r.changed_at, false)
            .map_err(|_| StateError::Invalid)?;
        let previous = change.previous_policy.as_ref().ok_or(StateError::Invalid)?;
        let current = change
            .policy
            .grants
            .iter()
            .find(|g| g.id == address.grant_id)
            .ok_or(StateError::Invalid)?;
        let old = previous
            .grants
            .iter()
            .find(|g| g.id == address.grant_id)
            .ok_or(StateError::Invalid)?;
        if change.policy.schema_version != 2
            || current.admission != AdmissionIntent::Deny
            || old.admission != AdmissionIntent::Allow
            || current.subject != old.subject
            || current.target != old.target
            || current.db_identity != old.db_identity
            || address.effect != EffectKindV2::NewConnections
            || address.route.kind == RouteKind::Direct
            || op.change_hash != change.change_hash
            || op.approval_id != approval.id
            || op.policy_revision_hash != change.plan.policy_revision_hash
            || r.changed_at < op.created_at
            || r.deadline
                .checked_sub(r.changed_at)
                .is_none_or(|v| v == 0 || v > state::MAX_PROPAGATION_SECONDS)
        {
            return Err(StateError::Invalid);
        }
        let desired = desired_for_change_v2(
            &change.policy,
            Some(previous),
            std::slice::from_ref(&address.target),
            r.changed_at,
        )?;
        if !desired
            .iter()
            .any(|d| d.address == *address && d.expected == StateValue::Denied)
        {
            return Err(StateError::Invalid);
        }
        Ok(Self {
            address: address.clone(),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            before_policy_revision_hash: previous
                .revision_hash()
                .map_err(|_| StateError::Invalid)?,
            change_hash: change.change_hash.clone(),
            operation_id: op.id.clone(),
            references: RemovalReferencesWire {
                before_inventory: r.before_inventory,
                after_inventory: r.after_inventory,
                prior_allowed: r.prior_allowed,
                changed_at: r.changed_at,
                deadline: r.deadline,
            },
            partial_failure: matches!(op.state, super::operation::ExecutionState::FailedPartial),
        })
    }
}
fn reference<'a>(
    input: &'a StateEvaluationInputV2,
    r: &(String, String),
) -> Option<(&'a VerifiedObservationFacts, &'a ObservationClaim)> {
    let f = input.evidence.iter().find(|f| f.bundle_digest() == r.0)?;
    let c = f.claims().iter().find(|c| c.id == r.1)?;
    Some((f, c))
}
fn removal_valid(
    input: &StateEvaluationInputV2,
    r: &PermissionRemovalV2,
    current: &ObservationClaim,
    before_pool: &[VerifiedObservationFacts],
) -> bool {
    let refs = &r.references;
    let Some((bf, b)) = reference(input, &refs.before_inventory)
        .or_else(|| reference_in(before_pool, &refs.before_inventory))
    else {
        return false;
    };
    let Some((af, a)) = reference(input, &refs.after_inventory) else {
        return false;
    };
    let Some((pf, p)) = reference(input, &refs.prior_allowed)
        .or_else(|| reference_in(before_pool, &refs.prior_allowed))
    else {
        return false;
    };
    let old = |c: &ObservationClaim| {
        c.address == r.address && c.policy_revision_hash == r.before_policy_revision_hash
    };
    let Some(bi) = &b.permission_inventory else {
        return false;
    };
    let Some(ai) = &a.permission_inventory else {
        return false;
    };
    let before: BTreeSet<_> = bi.permissions.iter().collect();
    let after: BTreeSet<_> = ai.permissions.iter().collect();
    old(b)
        && old(p)
        && a.address == r.address
        && a.policy_revision_hash == r.policy_revision_hash
        && af.admission().change_hash == r.change_hash
        && af.admission().operation_id == r.operation_id
        && p.observed == StateValue::Allowed
        && b.finished_at <= refs.changed_at
        && p.finished_at <= refs.changed_at
        && a.started_at >= refs.changed_at
        && a.finished_at <= current.started_at
        && refs.changed_at <= input.now
        && bi.complete
        && ai.complete
        && after.is_subset(&before)
        && after.len() < before.len()
        && [(bf, b), (af, a), (pf, p)]
            .iter()
            .all(|(f, c)| fresh(input, f, c) && missing(f, c, &all_facets()).is_empty())
}

fn reference_in<'a>(
    pool: &'a [VerifiedObservationFacts],
    r: &(String, String),
) -> Option<(&'a VerifiedObservationFacts, &'a ObservationClaim)> {
    let f = pool.iter().find(|f| f.bundle_digest() == r.0)?;
    Some((f, f.claims().iter().find(|c| c.id == r.1)?))
}
pub fn evaluate_source_state_v2(
    input: &StateEvaluationInputV2,
) -> Result<StateReportV2, StateError> {
    evaluate_impl(input, true, &[])
}
/// Old-operation facts are ONLY before-inventory/prior-Allowed references for
/// independently approved PermissionRemovalV2. Never observation candidates,
/// after-inventory, current health, or current protection.
pub fn evaluate_source_state_v2_with_removal_evidence(
    input: &StateEvaluationInputV2,
    before_pool: &[VerifiedObservationFacts],
) -> Result<StateReportV2, StateError> {
    if before_pool.len() > 32768
        || before_pool.iter().map(|f| f.claims().len()).sum::<usize>() > 32768
    {
        return Err(StateError::Limit);
    }
    if before_pool
        .iter()
        .map(|f| f.bundle_digest())
        .collect::<BTreeSet<_>>()
        .len()
        != before_pool.len()
    {
        return Err(StateError::Invalid);
    }
    evaluate_impl(input, true, before_pool)
}
pub fn evaluate_state_v2(input: &StateEvaluationInputV2) -> Result<StateReportV2, StateError> {
    evaluate_impl(input, false, &[])
}
fn evaluate_impl(
    input: &StateEvaluationInputV2,
    automatic_health: bool,
    before_pool: &[VerifiedObservationFacts],
) -> Result<StateReportV2, StateError> {
    if input
        .evidence
        .iter()
        .map(|f| f.claims().len())
        .sum::<usize>()
        > 32768
        || input.desired.len() > 8192
        || input.evidence.len() > 32768
        || input.permission_removals.len() > 8192
    {
        return Err(StateError::Limit);
    }
    if input.max_age_seconds == 0
        || input.max_age_seconds > DEFAULT_FRESHNESS_SECONDS
        || input
            .desired
            .iter()
            .map(|d| &d.id)
            .collect::<BTreeSet<_>>()
            .len()
            != input.desired.len()
        || input
            .evidence
            .iter()
            .map(|f| f.bundle_digest())
            .collect::<BTreeSet<_>>()
            .len()
            != input.evidence.len()
        || input.desired.iter().any(|d| {
            !policy::valid_id(&d.id)
                || !policy::valid_hash(&d.policy_revision_hash)
                || !desired_address_valid(&d.address)
                || !expected_valid(d)
                || d.required_assurance != all_facets()
                || (d.backend_tls_trust.is_some()
                    && (d.address.effect
                        != (EffectKindV2::Transport {
                            segment: TransportSegment::NativeRouteToDatabase,
                        })
                        || d.address.route.kind != RouteKind::NativeProxy
                        || d.address.target.placement.kind != policy::PlacementKind::AwsRds
                        || d.address.source.boundary
                            != super::source::SourceBoundaryKind::AwsHostNetwork
                        || !matches!(
                            d.address.target.engine_binding.family,
                            policy::EngineFamily::PostgreSql | policy::EngineFamily::MySql
                        )))
        })
    {
        return Err(StateError::Invalid);
    }
    let mut rows = vec![];
    for d in &input.desired {
        let mut row = StateRowV2 {
            desired: d.clone(),
            observed: StateValue::Unknown,
            assessment: StateAssessment::Unknown,
            reasons: vec![],
            history: vec![],
            current_claims: vec![],
            missing_assurance: vec![],
            propagation_deadline: None,
            protection_evaluated: false,
        };
        let mut candidates = vec![];
        for f in &input.evidence {
            for c in f
                .claims()
                .iter()
                .filter(|c| same_effect(&c.address, &d.address) && c.permission_inventory.is_none())
            {
                let reason = base_reason(input, f, c, d);
                row.history.push(ObservationV2 {
                    bundle_digest: f.bundle_digest().into(),
                    claim: c.clone(),
                    eligible: reason.is_none(),
                    reason,
                    missing_assurance: missing(f, c, &d.required_assurance),
                });
                if reason.is_none() {
                    candidates.push((f, c))
                }
            }
        }
        if candidates
            .iter()
            .any(|(_, c)| c.observed == StateValue::Allowed)
            && candidates
                .iter()
                .any(|(_, c)| c.observed == StateValue::Denied)
        {
            row.reasons.push(StateReason::MixedHistory)
        }
        let times: Vec<_> = candidates
            .iter()
            .map(|(_, c)| (c.started_at, c.finished_at))
            .collect();
        let current: Vec<_> = state::current_indices(&times)
            .into_iter()
            .map(|i| candidates[i])
            .collect();
        // Controls retain their native layers/history, but an incomplete raw
        // decision must not hide a fully corroborated observation of that value.
        let chosen = current
            .iter()
            .filter(|(f, c)| {
                c.observed == StateValue::Allowed
                    && quality(input, f, c, d, automatic_health).is_none()
            })
            .max_by_key(|(_, c)| (c.finished_at, &c.id))
            .or_else(|| {
                current
                    .iter()
                    .find(|(_, c)| c.observed == StateValue::Allowed)
            })
            .or_else(|| {
                current
                    .iter()
                    .filter(|(f, c)| quality(input, f, c, d, automatic_health).is_none())
                    .max_by_key(|(_, c)| (c.finished_at, &c.id))
            })
            .or_else(|| current.iter().max_by_key(|(_, c)| (c.finished_at, &c.id)));
        if let Some((f, c)) = chosen {
            row.observed = c.observed;
            row.protection_evaluated = true;
            row.missing_assurance = missing(f, c, &d.required_assurance);
            row.current_claims = current
                .iter()
                .map(|(f, c)| format!("{}:{}", f.bundle_digest(), c.id))
                .collect();
            let contradiction = current
                .iter()
                .any(|(_, o)| o.observed != StateValue::Unknown && o.observed != c.observed);
            let q = quality(input, f, c, d, automatic_health);
            if contradiction {
                row.reasons.push(StateReason::ContradictoryEvidence)
            }
            if let Some(q) = q {
                row.reasons.push(q)
            }
            if !contradiction && q.is_none() && c.observed == d.expected {
                row.assessment = StateAssessment::Satisfied;
                row.reasons.push(StateReason::EffectObserved)
            } else if matches!(c.observed, StateValue::Allowed | StateValue::Present)
                && c.observed != d.expected
            {
                row.assessment = StateAssessment::NeedsAction;
                row.reasons.push(StateReason::AccessStillAllowed);
            } else if q.is_none() && !contradiction && c.observed != StateValue::Unknown {
                row.assessment = StateAssessment::NeedsAction;
                row.reasons.push(StateReason::EffectNotSatisfied)
            }
            if c.observed == StateValue::Allowed
                && d.expected == StateValue::Denied
                && q.is_none()
                && !contradiction
                && let Some(r) = input
                    .permission_removals
                    .iter()
                    .filter(|r| {
                        r.address == d.address
                            && r.policy_revision_hash == d.policy_revision_hash
                            && removal_valid(input, r, c, before_pool)
                    })
                    .max_by_key(|r| r.references.changed_at)
            {
                row.propagation_deadline = Some(r.references.deadline);
                if r.partial_failure {
                    row.assessment = StateAssessment::FailedPartial
                } else if input.now < r.references.deadline {
                    row.assessment = StateAssessment::Pending;
                    row.reasons.push(StateReason::PropagationPending)
                }
            }
        } else {
            row.reasons.push(
                if row
                    .history
                    .iter()
                    .any(|h| h.reason == Some(EvidenceReason::StaleEvidence))
                {
                    StateReason::StaleEvidence
                } else {
                    StateReason::MissingEvidence
                },
            )
        }
        for r in input.permission_removals.iter().filter(|r| {
            r.address == d.address
                && r.policy_revision_hash == d.policy_revision_hash
                && input.now >= r.references.deadline
        }) {
            if row.assessment != StateAssessment::Satisfied {
                row.assessment = if r.partial_failure {
                    StateAssessment::FailedPartial
                } else {
                    StateAssessment::NeedsAction
                };
                row.propagation_deadline = Some(r.references.deadline);
                row.reasons.push(StateReason::PropagationDeadlineExceeded)
            }
        }
        rows.push(row);
    }
    let all = !rows.is_empty()
        && rows
            .iter()
            .all(|r| r.assessment == StateAssessment::Satisfied);
    let assessment = state::aggregate_assessment(rows.iter().map(|r| r.assessment), all);
    Ok(StateReportV2 {
        schema_version: EVALUATION_SCHEMA_VERSION,
        evaluated_at: input.now,
        assessment,
        protection_evaluated: rows.iter().any(|r| r.protection_evaluated),
        all_required_effects_satisfied: all,
        derived_controls: if automatic_health {
            derived_controls(input)
        } else {
            vec![]
        },
        rows,
    })
}

fn derived_controls(input: &StateEvaluationInputV2) -> Vec<DerivedControlLink> {
    let mut links = vec![];
    for f in &input.evidence {
        for c in f.claims() {
            if !c
                .controls
                .iter()
                .any(|r| r.purpose == ControlPurpose::TargetHealth)
                && let Some((health, other)) = native_health(input, f, c)
            {
                links.push(DerivedControlLink {
                    owner_bundle_digest: f.bundle_digest().into(),
                    owner_claim_id: c.id.clone(),
                    control: ControlReference {
                        bundle_digest: Some(health.bundle_digest().into()),
                        claim_id: other.id.clone(),
                        purpose: ControlPurpose::TargetHealth,
                    },
                });
            }
            if !c
                .controls
                .iter()
                .any(|r| r.purpose == ControlPurpose::CredentialValidity)
                && login::corroboration(input, f, c).is_some()
                && let Some(native) = c
                    .controls
                    .iter()
                    .find(|r| r.purpose == ControlPurpose::NativeBoundaryDecision)
            {
                let mut control = native.clone();
                control
                    .bundle_digest
                    .get_or_insert_with(|| f.bundle_digest().into());
                control.purpose = ControlPurpose::CredentialValidity;
                links.push(DerivedControlLink {
                    owner_bundle_digest: f.bundle_digest().into(),
                    owner_claim_id: c.id.clone(),
                    control,
                });
            }
        }
    }
    links
}

/// Reuse the v1 policy-universe rules, including exact previous-grant revocation
/// checks. This projects requirements only; no v1 evidence is ever promoted.
pub fn desired_for_change_v2(
    policy: &PolicyRevision,
    previous: Option<&PolicyRevision>,
    handles: &[TargetHandle],
    now: u64,
) -> Result<Vec<RequiredEffectV2>, StateError> {
    policy.validate().map_err(|_| StateError::Invalid)?;
    if let Some(old) = previous {
        old.validate().map_err(|_| StateError::Invalid)?;
        if policy.parent_revision_hash.as_ref()
            != Some(&old.revision_hash().map_err(|_| StateError::Invalid)?)
            || old.revision.checked_add(1) != Some(policy.revision)
            || old.policy_id != policy.policy_id
        {
            return Err(StateError::Invalid);
        }
    }
    if policy.schema_version != 2 || previous.is_some_and(|p| p.schema_version != 2) {
        return Err(StateError::Invalid);
    }
    let hash = policy.revision_hash().map_err(|_| StateError::Invalid)?;
    let mut legacy = policy.clone();
    legacy.schema_version = 1;
    legacy.source_bindings.clear();
    legacy.evaluation = None;
    for profile in &mut legacy.protection_profiles {
        profile.encryption = policy::EncryptionRequirement::VerifiedTls;
    }
    let old = previous.map(|p| {
        let mut p = p.clone();
        p.schema_version = 1;
        p.source_bindings.clear();
        p.evaluation = None;
        for profile in &mut p.protection_profiles {
            profile.encryption = policy::EncryptionRequirement::VerifiedTls;
        }
        p
    });
    if let Some(old) = &old {
        legacy.parent_revision_hash = Some(old.revision_hash().map_err(|_| StateError::Invalid)?)
    }
    let base = state::desired_for_change(&legacy, old.as_ref(), handles, now)?;
    let mut rows = vec![];
    for d in base {
        let binding = policy
            .source_bindings
            .iter()
            .find(|b| b.source_id == d.scope.source_id)
            .ok_or(StateError::Invalid)?;
        let effect = match d.scope.effect {
            state::StateEffect::NewConnections => EffectKindV2::NewConnections,
            state::StateEffect::ExistingSessions => EffectKindV2::ExistingSessions,
            state::StateEffect::SqlPrivilege { scope, action } => {
                EffectKindV2::EffectiveSqlPrivilege { scope, action }
            }
            state::StateEffect::SqlRole { role } => EffectKindV2::EffectiveSqlRole { role },
            state::StateEffect::Binding => EffectKindV2::BindingPublication,
            state::StateEffect::LeaseExpiry => EffectKindV2::LeaseExpiry,
        };
        let grant = policy
            .grants
            .iter()
            .find(|g| g.id == d.scope.grant_id)
            .ok_or(StateError::Invalid)?;
        let backend_trust = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(StateError::Invalid)?
            .encryption
            .backend_tls_trust();
        let layers = policy
            .evaluation
            .as_ref()
            .and_then(|e| {
                e.denial_requirements
                    .iter()
                    .find(|r| r.profile_id == grant.profile)
            })
            .ok_or(StateError::Invalid)?
            .accepted_layers
            .clone();
        let address = EffectAddress {
            target_id: d.scope.target_id,
            target: d.scope.target,
            grant_id: d.scope.grant_id,
            subject_id: d.scope.subject_id,
            db_identity: d.scope.db_identity,
            source: binding.snapshot_ref(),
            route: d.scope.route,
            effect,
        };
        let mut append = |address: EffectAddress, expected| {
            rows.push(RequiredEffectV2 {
                backend_tls_trust: if address.effect
                    == (EffectKindV2::Transport {
                        segment: TransportSegment::NativeRouteToDatabase,
                    }) {
                    backend_trust
                } else {
                    None
                },
                id: format!("effect-v2-{}", rows.len() + 1),
                policy_revision_hash: hash.clone(),
                address,
                expected,
                accepted_denial_layers: layers.clone(),
                required_assurance: all_facets(),
            })
        };
        append(address.clone(), d.expected);
        if address.effect == EffectKindV2::NewConnections && address.route.kind != RouteKind::Direct
        {
            let mut a = address.clone();
            a.effect = EffectKindV2::RuntimeBinding;
            append(a, StateValue::Present);
            let segments = if address.route.kind == RouteKind::NativeConnector {
                vec![
                    TransportSegment::LocalIpcBoundary,
                    TransportSegment::NativeRouteToDatabase,
                ]
            } else {
                vec![
                    TransportSegment::ClientToNativeRoute,
                    TransportSegment::NativeRouteToDatabase,
                ]
            };
            for segment in segments {
                let mut a = address.clone();
                a.effect = EffectKindV2::Transport { segment };
                append(a, StateValue::Present)
            }
        }
    }
    // Recovery is an independent mandatory source, not an inferred success
    // from the application's connection. Keep missing health/TLS rows visible.
    for grant in &policy.grants {
        let profile = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(StateError::Invalid)?;
        let base = rows
            .iter()
            .find(|r| r.address.grant_id == grant.id)
            .ok_or(StateError::Invalid)?
            .clone();
        let target = policy
            .targets
            .iter()
            .find(|t| t.id == grant.target)
            .ok_or(StateError::Invalid)?;
        for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
            let subject = policy
                .subjects
                .iter()
                .find(|s| s.id == exception.subject)
                .ok_or(StateError::Invalid)?;
            let route = profile
                .allowed_routes
                .iter()
                .find(|r| r.id == exception.route_id)
                .ok_or(StateError::Invalid)?;
            let db_identity = match subject.identity.provider {
                policy::IdentityProvider::Gcp => subject
                    .identity
                    .principal
                    .strip_suffix(".gserviceaccount.com")
                    .ok_or(StateError::Invalid)?
                    .to_owned(),
                policy::IdentityProvider::Aws => target
                    .aws
                    .as_ref()
                    .ok_or(StateError::Invalid)?
                    .management_db_identity
                    .clone(),
                _ => return Err(StateError::Invalid),
            };
            for source in &exception.source_ids {
                let binding = policy
                    .source_bindings
                    .iter()
                    .find(|b| b.source_id == *source)
                    .ok_or(StateError::Invalid)?;
                let mut address = base.address.clone();
                address.source = binding.snapshot_ref();
                address.subject_id = subject.id.clone();
                address.db_identity = db_identity.clone();
                address.route = state::StateRoute {
                    id: route.id.clone(),
                    kind: route.kind,
                };
                let expected = if matches!(exception.lifetime,policy::GrantLifetime::Lease{expires_at_unix,..}if now>=expires_at_unix)
                {
                    StateValue::Denied
                } else {
                    StateValue::Allowed
                };
                for (effect, expected) in [
                    (EffectKindV2::NewConnections, expected),
                    (
                        EffectKindV2::Transport {
                            segment: if route.kind == RouteKind::NativeConnector {
                                TransportSegment::LocalIpcBoundary
                            } else {
                                TransportSegment::ClientToNativeRoute
                            },
                        },
                        StateValue::Present,
                    ),
                    (
                        EffectKindV2::Transport {
                            segment: TransportSegment::NativeRouteToDatabase,
                        },
                        StateValue::Present,
                    ),
                ] {
                    let mut address = address.clone();
                    address.effect = effect;
                    rows.push(RequiredEffectV2 {
                        backend_tls_trust: if address.effect
                            == (EffectKindV2::Transport {
                                segment: TransportSegment::NativeRouteToDatabase,
                            }) {
                            profile.encryption.backend_tls_trust()
                        } else {
                            None
                        },
                        id: format!("effect-v2-{}", rows.len() + 1),
                        policy_revision_hash: hash.clone(),
                        address,
                        expected,
                        accepted_denial_layers: base.accepted_denial_layers.clone(),
                        required_assurance: all_facets(),
                    });
                }
            }
        }
    }
    if rows.len() > 8192 {
        return Err(StateError::Limit);
    }
    Ok(rows)
}

fn desired_address_valid(a: &EffectAddress) -> bool {
    let mut a = a.clone();
    if a.target.native_ref.generation_fingerprint.is_none() {
        a.target.native_ref.generation_fingerprint = Some("0".repeat(64));
    }
    valid_address(&a)
}
fn expected_valid(d: &RequiredEffectV2) -> bool {
    match d.address.effect {
        EffectKindV2::NewConnections => {
            matches!(d.expected, StateValue::Allowed | StateValue::Denied)
        }
        EffectKindV2::ExistingSessions => d.expected == StateValue::Terminated,
        EffectKindV2::LeaseExpiry => d.expected == StateValue::Expired,
        _ => matches!(d.expected, StateValue::Present | StateValue::Absent),
    }
}

mod login;
#[cfg(test)]
mod tests;
