//! Pure desired/observed/effective evaluation. These records are adapter claims,
//! not authenticated attestations. Artifact hashes identify supplied provenance;
//! this module never opens artifacts, contacts a provider, or changes protection.
use super::policy::{
    AdmissionIntent, DirectPathPolicy, EffectKind, GenerationAssurance, GrantLifetime,
    PolicyRevision, RouteKind, SqlAction, SqlScope, SubjectKind, TargetHandle, valid_hash,
    valid_id,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const STATE_SCHEMA_VERSION: u32 = 1;
/// A propagation claim cannot keep a row Pending beyond one day.
pub const MAX_PROPAGATION_SECONDS: u64 = 86_400;
const MAX_ROWS: usize = 8192;
const MAX_EVIDENCE: usize = 32768;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StateError {
    #[error("STATE_INVALID: invalid or incompatible local state input")]
    Invalid,
    #[error("STATE_LIMIT: local state evaluation input limit exceeded")]
    Limit,
}
macro_rules! choice {
    ($name:ident {$($variant:ident),+ $(,)?}) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {$($variant),+}
    };
}
choice!(StateLayer {
    RouteEnforcement,
    ConnectionAuthorization,
    Authentication,
    SqlAuthorization,
    SessionControl,
    Configuration,
    LeaseControl
});
choice!(StateValue {
    Unknown,
    Allowed,
    Denied,
    Present,
    Absent,
    Terminated,
    Expired
});
choice!(StateAssessment {
    Unknown,
    Satisfied,
    Pending,
    NeedsAction,
    FailedPartial
});
choice!(EvidenceOrigin {
    Fixture,
    AdapterValidated,
    OperatorAttestation
});
choice!(DenialCause {
    RouteBlocked,
    PermissionDenied,
    LoginRejected,
    SqlPermissionDenied,
    TokenCreationDenied,
    ServiceUsageDenied,
    InstanceMetadataDenied,
    ServiceUnavailable,
    Timeout,
    Unclassified
});
choice!(StateReason {
    MissingEvidence,
    TargetGenerationUnconfirmed,
    ScopeMismatch,
    BuildMismatch,
    StaleEvidence,
    FixtureOnly,
    AttestationOnly,
    InvalidEvidence,
    IncompleteCapture,
    IdentityUnconfirmed,
    WrongDenialLayer,
    UncorroboratedDenial,
    AccessStillAllowed,
    EffectNotSatisfied,
    PropagationPending,
    PropagationDeadlineExceeded,
    RemovalUncorroborated,
    MixedHistory,
    ContradictoryEvidence,
    SessionsUnattributed,
    LeaseRequiresReconciliation,
    EffectObserved
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRoute {
    pub id: String,
    pub kind: RouteKind,
}

/// Effects have disjoint scopes: a new-connection refusal cannot establish that
/// old sessions ended or that any SQL privilege was removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StateEffect {
    NewConnections,
    ExistingSessions,
    SqlPrivilege { scope: SqlScope, action: SqlAction },
    SqlRole { role: String },
    Binding,
    LeaseExpiry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceScope {
    pub policy_revision_hash: String,
    pub target_id: String,
    pub target: TargetHandle,
    pub grant_id: String,
    pub subject_id: String,
    pub db_identity: String,
    pub source_id: String,
    pub route: StateRoute,
    pub layer: StateLayer,
    pub effect: StateEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredEffect {
    pub id: String,
    pub scope: EvidenceScope,
    pub expected: StateValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub id: String,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub origin: EvidenceOrigin,
    pub build_id: String,
    pub artifacts: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenialProof {
    pub layer: StateLayer,
    pub cause: DenialCause,
    pub credential_issued: bool,
    pub identity_registered: bool,
    /// A separate, contemporaneous successful transport/connection control.
    /// Required for a login rejection; self-reference is never a control.
    pub transport_control_ref: Option<String>,
}

/// Timestamps cover the whole capture. A long/partial capture is not made fresh
/// by stamping its end. Successful access remains visible in a partial capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateEvidence {
    pub id: String,
    pub scope: EvidenceScope,
    pub started_at: u64,
    pub finished_at: u64,
    pub valid_until: u64,
    pub provenance: EvidenceProvenance,
    pub complete: bool,
    pub identity_confirmed: bool,
    pub observed: StateValue,
    pub denial: Option<DenialProof>,
    /// Session ownership must be attributable to this exact grant/subject.
    pub sessions_attributed: bool,
}

/// Selected permission inventory, not a provider payload. IDs are opaque,
/// non-secret permission identifiers interpreted only by the producing adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub id: String,
    pub scope: EvidenceScope,
    pub observed_at: u64,
    pub complete: bool,
    pub permissions: Vec<String>,
    pub provenance: EvidenceProvenance,
}

/// A bounded propagation explanation. Mere API acceptance is insufficient:
/// complete before/after inventories and successful pre-change access are linked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionRemoval {
    pub id: String,
    pub scope: EvidenceScope,
    pub before_policy_revision_hash: String,
    pub changed_at: u64,
    pub deadline: u64,
    pub removed_permissions: Vec<String>,
    pub before: PermissionSnapshot,
    pub after: PermissionSnapshot,
    pub prior_allowed_evidence_id: String,
    pub partial_failure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateEvaluationInput {
    pub schema_version: u32,
    pub now: u64,
    pub max_age_seconds: u64,
    pub expected_build_id: String,
    pub desired: Vec<DesiredEffect>,
    pub evidence: Vec<StateEvidence>,
    pub permission_removals: Vec<PermissionRemoval>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateObservation {
    pub evidence_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub observed: StateValue,
    pub denial: Option<DenialProof>,
    pub provenance: EvidenceProvenance,
    pub eligible: bool,
    pub reason: Option<StateReason>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateRow {
    pub desired: DesiredEffect,
    pub observed: StateValue,
    pub assessment: StateAssessment,
    pub reasons: Vec<StateReason>,
    pub current_evidence_ids: Vec<String>,
    pub history: Vec<StateObservation>,
    pub removal_id: Option<String>,
    pub propagation_deadline: Option<u64>,
    /// Whether fresh non-fixture evidence was evaluated, not universal protection.
    pub protection_evaluated: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateReport {
    pub schema_version: u32,
    pub evaluated_at: u64,
    pub assessment: StateAssessment,
    pub rows: Vec<StateRow>,
    pub protection_evaluated: bool,
    pub all_required_effects_satisfied: bool,
}

fn bounded_text(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    !v.is_empty()
        && v.len() <= 512
        && !v.chars().any(char::is_control)
        && !v.contains("://")
        && !v.contains("${")
        && !v.contains("{{")
        && !["password=", "pwd=", "token=", "secret="]
            .iter()
            .any(|part| lower.contains(part))
}
fn provenance_valid(p: &EvidenceProvenance) -> bool {
    valid_id(&p.build_id)
        && !p.artifacts.is_empty()
        && p.artifacts.len() <= 64
        && p.artifacts
            .iter()
            .all(|a| valid_id(&a.id) && valid_hash(&a.sha256))
        && unique(p.artifacts.iter().map(|a| &a.id))
}
fn unique<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|v| seen.insert(v))
}
fn scope_valid(s: &EvidenceScope) -> bool {
    valid_hash(&s.policy_revision_hash)
        && [
            &s.target_id,
            &s.target.registration_id,
            &s.grant_id,
            &s.subject_id,
            &s.source_id,
            &s.route.id,
        ]
        .iter()
        .all(|v| valid_id(v))
        && bounded_text(&s.db_identity)
        && bounded_text(&s.target.native_ref.native_id)
        && bounded_text(&s.target.placement.account_id)
        && valid_id(&s.target.placement.region)
        && bounded_text(&s.target.engine_binding.version)
        && bounded_text(&s.target.engine_binding.database)
        && s.target
            .native_ref
            .generation_fingerprint
            .as_ref()
            .is_none_or(|v| valid_hash(v))
        && match &s.effect {
            StateEffect::SqlRole { role } => bounded_text(role),
            StateEffect::SqlPrivilege { scope, .. } => {
                bounded_text(&scope.database)
                    && scope.schema.as_ref().is_none_or(|v| bounded_text(v))
                    && scope.object.as_ref().is_none_or(|v| bounded_text(v))
            }
            _ => true,
        }
}
fn expected_valid(d: &DesiredEffect) -> bool {
    match d.scope.effect {
        StateEffect::NewConnections => {
            matches!(d.expected, StateValue::Allowed | StateValue::Denied)
        }
        StateEffect::ExistingSessions => d.expected == StateValue::Terminated,
        StateEffect::SqlPrivilege { .. } | StateEffect::SqlRole { .. } | StateEffect::Binding => {
            matches!(d.expected, StateValue::Present | StateValue::Absent)
        }
        StateEffect::LeaseExpiry => d.expected == StateValue::Expired,
    }
}
fn same_subject_scope(a: &EvidenceScope, b: &EvidenceScope) -> bool {
    // Different revisions/generations/registrations remain report history but
    // never participate in the current effective-state calculation.
    a.target_id == b.target_id
        && a.grant_id == b.grant_id
        && a.subject_id == b.subject_id
        && a.source_id == b.source_id
        && a.route == b.route
        && a.layer == b.layer
        && a.effect == b.effect
}
fn base_reason(
    input: &StateEvaluationInput,
    e: &StateEvidence,
    desired: &DesiredEffect,
) -> Option<StateReason> {
    if e.scope != desired.scope {
        return Some(StateReason::ScopeMismatch);
    }
    if e.provenance.build_id != input.expected_build_id {
        return Some(StateReason::BuildMismatch);
    }
    if e.started_at > e.finished_at
        || e.finished_at > input.now
        || e.valid_until < e.finished_at
        || input.now > e.valid_until
        || input.now.saturating_sub(e.started_at) > input.max_age_seconds
    {
        return Some(StateReason::StaleEvidence);
    }
    match e.provenance.origin {
        EvidenceOrigin::Fixture => Some(StateReason::FixtureOnly),
        EvidenceOrigin::OperatorAttestation => Some(StateReason::AttestationOnly),
        EvidenceOrigin::AdapterValidated => {
            if e.scope.target.generation_assurance != GenerationAssurance::Confirmed
                || e.scope.target.native_ref.generation_fingerprint.is_none()
            {
                Some(StateReason::TargetGenerationUnconfirmed)
            } else {
                None
            }
        }
    }
}
fn denial_reason(input: &StateEvaluationInput, e: &StateEvidence) -> Option<StateReason> {
    let Some(proof) = &e.denial else {
        return Some(StateReason::UncorroboratedDenial);
    };
    if proof.layer != e.scope.layer {
        return Some(StateReason::WrongDenialLayer);
    }
    let supported = matches!(
        (proof.layer, proof.cause),
        (StateLayer::RouteEnforcement, DenialCause::RouteBlocked)
            | (
                StateLayer::ConnectionAuthorization,
                DenialCause::PermissionDenied
            )
            | (StateLayer::Authentication, DenialCause::LoginRejected)
            | (
                StateLayer::SqlAuthorization,
                DenialCause::SqlPermissionDenied
            )
    );
    if !supported {
        return Some(StateReason::WrongDenialLayer);
    }
    if matches!(
        proof.layer,
        StateLayer::ConnectionAuthorization | StateLayer::Authentication
    ) && !proof.credential_issued
    {
        return Some(StateReason::UncorroboratedDenial);
    }
    if proof.layer == StateLayer::Authentication {
        if !proof.identity_registered {
            return Some(StateReason::UncorroboratedDenial);
        }
        let control = proof
            .transport_control_ref
            .as_ref()
            .and_then(|id| input.evidence.iter().find(|c| &c.id == id && c.id != e.id));
        let valid = control.is_some_and(|c| {
            let mut expected_scope = e.scope.clone();
            expected_scope.subject_id = c.scope.subject_id.clone();
            expected_scope.grant_id = c.scope.grant_id.clone();
            expected_scope.db_identity = c.scope.db_identity.clone();
            c.scope == expected_scope
                && c.scope.subject_id != e.scope.subject_id
                && c.observed == StateValue::Allowed
                && c.identity_confirmed
                && c.complete
                && c.started_at <= e.finished_at
                && c.finished_at >= e.started_at
                && base_reason(
                    input,
                    c,
                    &DesiredEffect {
                        id: "control".into(),
                        scope: c.scope.clone(),
                        expected: StateValue::Allowed,
                    },
                )
                .is_none()
        });
        if !valid {
            return Some(StateReason::UncorroboratedDenial);
        }
    }
    None
}
fn quality_reason(input: &StateEvaluationInput, e: &StateEvidence) -> Option<StateReason> {
    if !e.complete {
        return Some(StateReason::IncompleteCapture);
    }
    if !e.identity_confirmed {
        return Some(StateReason::IdentityUnconfirmed);
    }
    if e.scope.effect == StateEffect::ExistingSessions && !e.sessions_attributed {
        return Some(StateReason::SessionsUnattributed);
    }
    if e.observed == StateValue::Denied {
        return denial_reason(input, e);
    }
    if e.denial.is_some() {
        return Some(StateReason::ContradictoryEvidence);
    }
    None
}
fn snapshot_valid(
    input: &StateEvaluationInput,
    s: &PermissionSnapshot,
    scope: &EvidenceScope,
) -> bool {
    s.scope == *scope
        && s.complete
        && s.observed_at <= input.now
        && input.now.saturating_sub(s.observed_at) <= input.max_age_seconds
        && s.provenance.origin == EvidenceOrigin::AdapterValidated
        && s.provenance.build_id == input.expected_build_id
}
fn corroborated_removal(
    input: &StateEvaluationInput,
    r: &PermissionRemoval,
    desired: &DesiredEffect,
    current: &StateEvidence,
) -> bool {
    if r.scope != desired.scope
        || desired.expected != StateValue::Denied
        || desired.scope.effect != StateEffect::NewConnections
        || r.changed_at > current.started_at
        || r.changed_at > input.now
        || r.deadline <= r.changed_at
        || r.before.id == r.after.id
        || r.before.observed_at > r.changed_at
        || r.after.observed_at < r.changed_at
        || r.after.observed_at > current.started_at
        || r.removed_permissions.is_empty()
    {
        return false;
    }
    let mut old_scope = desired.scope.clone();
    old_scope.policy_revision_hash = r.before_policy_revision_hash.clone();
    if !snapshot_valid(input, &r.before, &old_scope)
        || !snapshot_valid(input, &r.after, &desired.scope)
    {
        return false;
    }
    let before: BTreeSet<_> = r.before.permissions.iter().collect();
    let after: BTreeSet<_> = r.after.permissions.iter().collect();
    let removed: BTreeSet<_> = r.removed_permissions.iter().collect();
    if !after.is_subset(&before)
        || before.difference(&after).copied().collect::<BTreeSet<_>>() != removed
    {
        return false;
    }
    input.evidence.iter().any(|e| {
        e.id == r.prior_allowed_evidence_id
            && e.scope == old_scope
            && e.id != current.id
            && e.observed == StateValue::Allowed
            && e.finished_at <= r.changed_at
            && base_reason(
                input,
                e,
                &DesiredEffect {
                    id: "prior".into(),
                    scope: old_scope.clone(),
                    expected: StateValue::Allowed,
                },
            )
            .is_none()
            && quality_reason(input, e).is_none()
    })
}
fn add_reason(reasons: &mut Vec<StateReason>, r: StateReason) {
    if !reasons.contains(&r) {
        reasons.push(r);
    }
}

pub fn evaluate_state(input: &StateEvaluationInput) -> Result<StateReport, StateError> {
    if input.desired.len() > MAX_ROWS
        || input.evidence.len() > MAX_EVIDENCE
        || input.permission_removals.len() > MAX_ROWS
    {
        return Err(StateError::Limit);
    }
    if input.schema_version != STATE_SCHEMA_VERSION
        || input.max_age_seconds == 0
        || !valid_id(&input.expected_build_id)
        || !unique(input.desired.iter().map(|v| &v.id))
        || !unique(input.evidence.iter().map(|v| &v.id))
        || !unique(input.permission_removals.iter().map(|v| &v.id))
        || input
            .desired
            .iter()
            .any(|d| !valid_id(&d.id) || !scope_valid(&d.scope) || !expected_valid(d))
        || input.evidence.iter().any(|e| {
            !valid_id(&e.id)
                || !scope_valid(&e.scope)
                || !provenance_valid(&e.provenance)
                || e.denial
                    .as_ref()
                    .and_then(|d| d.transport_control_ref.as_ref())
                    .is_some_and(|id| !valid_id(id))
        })
        || input.permission_removals.iter().any(|r| {
            !valid_id(&r.id)
                || !scope_valid(&r.scope)
                || !valid_hash(&r.before_policy_revision_hash)
                || r.deadline
                    .checked_sub(r.changed_at)
                    .is_none_or(|window| window == 0 || window > MAX_PROPAGATION_SECONDS)
                || !valid_id(&r.before.id)
                || !valid_id(&r.after.id)
                || !valid_id(&r.prior_allowed_evidence_id)
                || !scope_valid(&r.before.scope)
                || !scope_valid(&r.after.scope)
                || !provenance_valid(&r.before.provenance)
                || !provenance_valid(&r.after.provenance)
                || r.removed_permissions.len() > 512
                || r.before.permissions.len() > 512
                || r.after.permissions.len() > 512
                || [
                    &r.removed_permissions,
                    &r.before.permissions,
                    &r.after.permissions,
                ]
                .iter()
                .any(|v| !unique(v.iter()) || v.iter().any(|p| !valid_id(p)))
        })
    {
        return Err(StateError::Invalid);
    }
    let mut rows = Vec::with_capacity(input.desired.len());
    for d in &input.desired {
        let mut row = StateRow {
            desired: d.clone(),
            observed: StateValue::Unknown,
            assessment: StateAssessment::Unknown,
            reasons: vec![],
            current_evidence_ids: vec![],
            history: vec![],
            removal_id: None,
            propagation_deadline: None,
            protection_evaluated: false,
        };
        let mut candidates = Vec::new();
        for e in &input.evidence {
            if !same_subject_scope(&e.scope, &d.scope) {
                continue;
            }
            let reason = base_reason(input, e, d);
            row.history.push(StateObservation {
                evidence_id: e.id.clone(),
                started_at: e.started_at,
                finished_at: e.finished_at,
                observed: e.observed,
                denial: e.denial.clone(),
                provenance: e.provenance.clone(),
                eligible: reason.is_none(),
                reason: reason.or_else(|| quality_reason(input, e)),
            });
            if let Some(reason) = reason {
                add_reason(&mut row.reasons, reason);
            } else {
                candidates.push(e);
            }
        }
        row.history
            .sort_by(|a, b| (a.finished_at, &a.evidence_id).cmp(&(b.finished_at, &b.evidence_id)));
        if candidates.iter().any(|e| e.observed == StateValue::Allowed)
            && candidates.iter().any(|e| e.observed == StateValue::Denied)
        {
            add_reason(&mut row.reasons, StateReason::MixedHistory);
        }
        // Overlapping captures represent simultaneous contradictory evidence.
        // Preserve a positive access result instead of hiding it behind denial.
        if !candidates.is_empty() {
            let times: Vec<_> = candidates
                .iter()
                .map(|e| (e.started_at, e.finished_at))
                .collect();
            let current: Vec<_> = current_indices(&times)
                .into_iter()
                .map(|i| candidates[i])
                .collect();
            row.current_evidence_ids = current.iter().map(|e| e.id.clone()).collect();
            row.protection_evaluated = true;
            let chosen = current
                .iter()
                .copied()
                .find(|e| e.observed == StateValue::Allowed)
                .or_else(|| {
                    current
                        .iter()
                        .copied()
                        .max_by_key(|e| (e.finished_at, &e.id))
                })
                .unwrap();
            row.observed = chosen.observed;
            let contradiction = current
                .iter()
                .any(|e| e.observed != chosen.observed && e.observed != StateValue::Unknown);
            if contradiction {
                add_reason(&mut row.reasons, StateReason::ContradictoryEvidence);
            }
            if let Some(reason) = quality_reason(input, chosen) {
                add_reason(&mut row.reasons, reason);
            } else if !contradiction && row.observed == d.expected {
                row.assessment = StateAssessment::Satisfied;
                add_reason(&mut row.reasons, StateReason::EffectObserved);
            } else if row.observed != StateValue::Unknown {
                row.assessment = StateAssessment::NeedsAction;
                add_reason(
                    &mut row.reasons,
                    if row.observed == StateValue::Allowed {
                        StateReason::AccessStillAllowed
                    } else {
                        StateReason::EffectNotSatisfied
                    },
                );
            }
            if d.expected == StateValue::Denied && row.observed == StateValue::Allowed {
                let matching: Vec<_> = input
                    .permission_removals
                    .iter()
                    .filter(|r| r.scope == d.scope)
                    .collect();
                let removal = matching
                    .iter()
                    .copied()
                    .filter(|r| corroborated_removal(input, r, d, chosen))
                    .max_by_key(|r| r.changed_at);
                if let Some(r) = removal {
                    row.removal_id = Some(r.id.clone());
                    row.propagation_deadline = Some(r.deadline);
                    if input.now >= r.deadline {
                        row.assessment = if r.partial_failure {
                            StateAssessment::FailedPartial
                        } else {
                            StateAssessment::NeedsAction
                        };
                        add_reason(&mut row.reasons, StateReason::PropagationDeadlineExceeded);
                    } else if !contradiction && quality_reason(input, chosen).is_none() {
                        row.assessment = if r.partial_failure {
                            StateAssessment::FailedPartial
                        } else {
                            StateAssessment::Pending
                        };
                        add_reason(&mut row.reasons, StateReason::PropagationPending);
                    }
                } else if !matching.is_empty() {
                    add_reason(&mut row.reasons, StateReason::RemovalUncorroborated);
                }
            }
        } else {
            // A fresh successful sample is still an observed fact when its
            // target incarnation has not been authenticated. It cannot satisfy
            // protection, and fixtures/stale/foreign scopes never enter here.
            let visible: Vec<_> = input
                .evidence
                .iter()
                .filter(|e| {
                    base_reason(input, e, d) == Some(StateReason::TargetGenerationUnconfirmed)
                })
                .collect();
            if let Some(end) = visible.iter().map(|e| e.finished_at).max() {
                let start = visible
                    .iter()
                    .filter(|e| e.finished_at == end)
                    .map(|e| e.started_at)
                    .min()
                    .unwrap_or(end);
                let current: Vec<_> = visible
                    .iter()
                    .copied()
                    .filter(|e| e.finished_at >= start)
                    .collect();
                let chosen = current
                    .iter()
                    .copied()
                    .find(|e| e.observed == StateValue::Allowed)
                    .or_else(|| {
                        current
                            .iter()
                            .copied()
                            .max_by_key(|e| (e.finished_at, &e.id))
                    })
                    .unwrap();
                row.observed = chosen.observed;
                row.current_evidence_ids = current.iter().map(|e| e.id.clone()).collect();
                if let Some(reason) = quality_reason(input, chosen) {
                    add_reason(&mut row.reasons, reason);
                }
                if visible.iter().any(|e| e.observed == StateValue::Allowed)
                    && visible.iter().any(|e| e.observed == StateValue::Denied)
                {
                    add_reason(&mut row.reasons, StateReason::MixedHistory);
                }
                if current
                    .iter()
                    .any(|e| e.observed != chosen.observed && e.observed != StateValue::Unknown)
                {
                    add_reason(&mut row.reasons, StateReason::ContradictoryEvidence);
                }
            } else {
                add_reason(&mut row.reasons, StateReason::MissingEvidence);
            }
            if d.scope.target.generation_assurance != GenerationAssurance::Confirmed
                || d.scope.target.native_ref.generation_fingerprint.is_none()
            {
                add_reason(&mut row.reasons, StateReason::TargetGenerationUnconfirmed);
            }
        }
        // Deadlines never disappear into perpetual Unknown/Pending when a
        // previously supplied propagation explanation loses fresh evidence.
        for removal in input.permission_removals.iter().filter(|r| {
            r.scope == d.scope
                && r.changed_at <= input.now
                && r.deadline > r.changed_at
                && input.now >= r.deadline
        }) {
            if row.assessment != StateAssessment::Satisfied {
                row.assessment = if removal.partial_failure {
                    StateAssessment::FailedPartial
                } else {
                    StateAssessment::NeedsAction
                };
                row.removal_id = Some(removal.id.clone());
                row.propagation_deadline = Some(removal.deadline);
                add_reason(&mut row.reasons, StateReason::PropagationDeadlineExceeded);
            }
        }
        rows.push(row);
    }
    let all_required_effects_satisfied = !rows.is_empty()
        && rows
            .iter()
            .all(|r| r.assessment == StateAssessment::Satisfied);
    let assessment = aggregate_assessment(
        rows.iter().map(|r| r.assessment),
        all_required_effects_satisfied,
    );
    Ok(StateReport {
        schema_version: STATE_SCHEMA_VERSION,
        evaluated_at: input.now,
        assessment,
        protection_evaluated: rows.iter().any(|r| r.protection_evaluated),
        all_required_effects_satisfied,
        rows,
    })
}

/// Build a fixed required-effect universe from policy, never from available
/// observations. Missing evidence therefore remains a visible Unknown row.
/// Confirmed handles must bind registration/native resource/placement/engine;
/// generation fingerprints supplied by the policy must also agree.
pub fn desired_for_policy(
    policy: &PolicyRevision,
    handles: &[TargetHandle],
    now: u64,
) -> Result<Vec<DesiredEffect>, StateError> {
    desired_for_change(policy, None, handles, now)
}

/// SQL revocation is evaluated against exact privileges from the parent policy.
/// An empty current grant is never treated as proof of removing its old access.
pub fn desired_for_change(
    policy: &PolicyRevision,
    previous: Option<&PolicyRevision>,
    handles: &[TargetHandle],
    now: u64,
) -> Result<Vec<DesiredEffect>, StateError> {
    // Never discard v2 source snapshots, independent assurance or denial-layer
    // requirements by feeding a source-bound policy to the legacy evaluator.
    if policy.schema_version != 1 || previous.is_some_and(|p| p.schema_version != 1) {
        return Err(StateError::Invalid);
    }
    policy.validate().map_err(|_| StateError::Invalid)?;
    let revision_hash = policy.revision_hash().map_err(|_| StateError::Invalid)?;
    let mut result = Vec::new();
    for grant in &policy.grants {
        let target = policy
            .targets
            .iter()
            .find(|t| t.id == grant.target)
            .ok_or(StateError::Invalid)?;
        let subject = policy
            .subjects
            .iter()
            .find(|s| s.id == grant.subject)
            .ok_or(StateError::Invalid)?;
        let profile = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(StateError::Invalid)?;
        let matching: Vec<_> = handles
            .iter()
            .filter(|h| h.registration_id == target.registration_id)
            .collect();
        if matching.len() > 1 {
            return Err(StateError::Invalid);
        }
        let handle = if let Some(h) = matching.first() {
            if h.native_ref.native_id != target.resource.native_id
                || h.placement != target.placement
                || h.engine_binding != target.engine
                || target
                    .resource
                    .generation_fingerprint
                    .as_ref()
                    .is_some_and(|g| h.native_ref.generation_fingerprint.as_ref() != Some(g))
            {
                return Err(StateError::Invalid);
            }
            (*h).clone()
        } else {
            TargetHandle {
                registration_id: target.registration_id.clone(),
                native_ref: target.resource.clone(),
                placement: target.placement.clone(),
                engine_binding: target.engine.clone(),
                generation_assurance: GenerationAssurance::Unconfirmed,
            }
        };
        let expired = matches!(grant.lifetime, GrantLifetime::Lease { expires_at_unix, .. } if now >= expires_at_unix);
        let revoke_sql = profile
            .required_effects
            .contains(&EffectKind::SqlPrivilegesRevoked);
        let sql_access = if revoke_sql {
            let old = previous.ok_or(StateError::Invalid)?;
            old.validate().map_err(|_| StateError::Invalid)?;
            if grant.admission != AdmissionIntent::Deny
                || policy.parent_revision_hash.as_ref()
                    != Some(&old.revision_hash().map_err(|_| StateError::Invalid)?)
                || old.revision.checked_add(1) != Some(policy.revision)
                || old.policy_id != policy.policy_id
            {
                return Err(StateError::Invalid);
            }
            let old_grant = old
                .grants
                .iter()
                .find(|g| g.id == grant.id)
                .ok_or(StateError::Invalid)?;
            let old_target = old
                .targets
                .iter()
                .find(|t| t.id == old_grant.target)
                .ok_or(StateError::Invalid)?;
            let old_subject = old
                .subjects
                .iter()
                .find(|s| s.id == old_grant.subject)
                .ok_or(StateError::Invalid)?;
            if old_grant.admission != AdmissionIntent::Allow
                || old_grant.target != grant.target
                || old_grant.subject != grant.subject
                || old_grant.db_identity != grant.db_identity
                || old_target.registration_id != target.registration_id
                || old_target.resource != target.resource
                || old_target.placement != target.placement
                || old_target.engine != target.engine
                || old_subject != subject
            {
                return Err(StateError::Invalid);
            }
            &old_grant.sql_access
        } else {
            &grant.sql_access
        };
        let admission = if grant.admission == AdmissionIntent::Deny || expired {
            StateValue::Denied
        } else {
            StateValue::Allowed
        };
        for source in &subject.workload_sources {
            let mut routes: Vec<_> = profile
                .allowed_routes
                .iter()
                .filter(|r| r.source_ids.contains(source))
                .map(|r| StateRoute {
                    id: r.id.clone(),
                    kind: r.kind,
                })
                .collect();
            if subject.kind == SubjectKind::Application
                && matches!(profile.application_direct_path, DirectPathPolicy::Deny)
            {
                if routes.iter().any(|r| r.id == "application-direct") {
                    return Err(StateError::Invalid);
                }
                routes.push(StateRoute {
                    id: "application-direct".into(),
                    kind: RouteKind::Direct,
                });
            }
            for route in routes {
                let direct_denied = route.id == "application-direct";
                let expected = if direct_denied {
                    StateValue::Denied
                } else {
                    admission
                };
                let scope = EvidenceScope {
                    policy_revision_hash: revision_hash.clone(),
                    target_id: target.id.clone(),
                    target: handle.clone(),
                    grant_id: grant.id.clone(),
                    subject_id: subject.id.clone(),
                    db_identity: grant.db_identity.clone(),
                    source_id: source.clone(),
                    route: route.clone(),
                    layer: if direct_denied {
                        StateLayer::RouteEnforcement
                    } else if expected == StateValue::Denied {
                        StateLayer::ConnectionAuthorization
                    } else {
                        StateLayer::Authentication
                    },
                    effect: StateEffect::NewConnections,
                };
                let mut append = |effect: StateEffect, layer: StateLayer, expected: StateValue| {
                    let mut scope = scope.clone();
                    scope.layer = layer;
                    scope.effect = effect;
                    result.push(DesiredEffect {
                        id: format!("effect-{}", result.len() + 1),
                        scope,
                        expected,
                    });
                };
                append(StateEffect::NewConnections, scope.layer, expected);
                if direct_denied {
                    continue;
                }
                if profile
                    .required_effects
                    .contains(&EffectKind::BindingApplied)
                {
                    append(
                        StateEffect::Binding,
                        StateLayer::Configuration,
                        StateValue::Present,
                    );
                }
                if profile
                    .required_effects
                    .contains(&EffectKind::SessionsTerminated)
                {
                    append(
                        StateEffect::ExistingSessions,
                        StateLayer::SessionControl,
                        StateValue::Terminated,
                    );
                }
                if revoke_sql
                    || profile
                        .required_effects
                        .contains(&EffectKind::SqlPrivilegesApplied)
                {
                    let sql_expected = if admission == StateValue::Denied {
                        StateValue::Absent
                    } else {
                        StateValue::Present
                    };
                    for role in &sql_access.existing_roles {
                        append(
                            StateEffect::SqlRole { role: role.clone() },
                            StateLayer::SqlAuthorization,
                            sql_expected,
                        );
                    }
                    for privilege in &sql_access.privileges {
                        for action in &privilege.actions {
                            append(
                                StateEffect::SqlPrivilege {
                                    scope: privilege.scope.clone(),
                                    action: *action,
                                },
                                StateLayer::SqlAuthorization,
                                sql_expected,
                            );
                        }
                    }
                }
                if expired || profile.required_effects.contains(&EffectKind::LeaseExpired) {
                    append(
                        StateEffect::LeaseExpiry,
                        StateLayer::LeaseControl,
                        StateValue::Expired,
                    );
                }
            }
        }
    }
    if result.len() > MAX_ROWS {
        return Err(StateError::Limit);
    }
    Ok(result)
}

/// Shared overlap rule: simultaneous Allowed evidence must remain visible.
pub(super) fn current_indices(times: &[(u64, u64)]) -> Vec<usize> {
    let Some(end) = times.iter().map(|(_, e)| *e).max() else {
        return vec![];
    };
    let start = times
        .iter()
        .filter(|(_, e)| *e == end)
        .map(|(s, _)| *s)
        .min()
        .unwrap_or(end);
    times
        .iter()
        .enumerate()
        .filter(|(_, (_, e))| *e >= start)
        .map(|(i, _)| i)
        .collect()
}
pub(super) fn aggregate_assessment(
    values: impl Iterator<Item = StateAssessment>,
    all: bool,
) -> StateAssessment {
    let values: Vec<_> = values.collect();
    [
        StateAssessment::FailedPartial,
        StateAssessment::NeedsAction,
        StateAssessment::Unknown,
        StateAssessment::Pending,
    ]
    .into_iter()
    .find(|v| values.contains(v))
    .unwrap_or(if all {
        StateAssessment::Satisfied
    } else {
        StateAssessment::Unknown
    })
}
