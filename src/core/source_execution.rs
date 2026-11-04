//! Stage-specific execution evidence. Only locally admitted facts are inputs;
//! reports and operator handoff declarations cannot construct a positive check.
use super::{
    change::PreparedChange,
    evidence::*,
    orchestrator::ExecutorError,
    plan::PlanStep,
    policy::{AdmissionIntent, RouteKind},
    state::{StateAssessment, StateValue},
    state_v2::{StateReportV2, desired_for_change_v2, evaluate_source_state_v2},
};
use serde::Serialize;

/// New executable contract. Evaluation-only v2 plans keep their original hash
/// and reader, but must be replanned/reapproved to dispatch under this contract.
pub const SOURCE_BOUND_EXECUTION_CONTRACT: &str = "source-bound-execution-v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStepPhase {
    BeforeDispatch,
    AfterConfiguration { not_before: u64 },
}

/// No Deserialize or public fields: a saved JSON assessment is not authority.
#[derive(Debug, Clone, Serialize)]
pub struct SourceStepCheck {
    satisfied: bool,
    required_effect_ids: Vec<String>,
    unsatisfied_effect_ids: Vec<String>,
    evidence_refs: Vec<String>,
}
impl SourceStepCheck {
    pub fn satisfied(&self) -> bool {
        self.satisfied
    }
    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }
}

/// Trusted local evidence reader. Implementations must reload registry, archive,
/// original admission, context and current clock at EACH call (including submit).
pub trait SourceStepGate: Send {
    /// Resolve current immutable declarations before even preparatory writes.
    /// Collector/credential profiles known to be unsupported are a hard stop;
    /// this check does not claim that a source or DB was observed at runtime.
    fn validate_sources(&mut self, _: &PreparedChange) -> Result<(), ExecutorError> {
        Err(ExecutorError::Unavailable)
    }
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    fn check(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        phase: SourceStepPhase,
    ) -> Result<SourceStepCheck, ExecutorError>;
}

pub fn execution_contract_matches(change: &PreparedChange, step: &PlanStep, legacy: &str) -> bool {
    step.adapter_contract
        == if change.policy.schema_version == 2 {
            SOURCE_BOUND_EXECUTION_CONTRACT
        } else {
            legacy
        }
}

/// Select stage prerequisites from the COMPLETE mandatory universe, then
/// evaluate admitted facts using the same evaluator as state/status.
pub fn check_source_step(
    change: &PreparedChange,
    step: &PlanStep,
    phase: SourceStepPhase,
    now: u64,
    mut facts: Vec<VerifiedObservationFacts>,
) -> Result<SourceStepCheck, ExecutorError> {
    change
        .verify()
        .map_err(|_| ExecutorError::PreconditionsNotMet)?;
    if change.policy.schema_version != 2
        || !change.plan.steps.contains(step)
        || step.adapter_contract != SOURCE_BOUND_EXECUTION_CONTRACT
    {
        return Err(ExecutorError::Unavailable);
    }
    if facts.iter().any(|f| {
        f.admission().change_hash != change.change_hash
            || f.admission().policy_revision_hash != change.plan.policy_revision_hash
    }) {
        return Err(ExecutorError::PreconditionsNotMet);
    }
    if let SourceStepPhase::AfterConfiguration { not_before } = phase {
        // Controller capture-start seconds must be STRICTLY later than the
        // durable dispatch seconds. A same-second/old remote timestamp cannot
        // establish causal order, even with a fresh admission receipt.
        facts.retain(|f| f.admission().capture_started_at > not_before);
    }
    let desired = desired_for_change_v2(&change.policy, change.previous_policy.as_ref(), &[], now)
        .map_err(|_| ExecutorError::PreconditionsNotMet)?;
    let report = evaluate_source_state_v2(&StateEvaluationInputV2 {
        contract: EvaluationContract::SourceBoundV2,
        now,
        max_age_seconds: DEFAULT_FRESHNESS_SECONDS,
        desired,
        evidence: facts,
        permission_removals: vec![],
    })
    .map_err(|_| ExecutorError::PreconditionsNotMet)?;
    stage_check(change, step, phase, &report)
}

/// Diagnostic projection only. Callers requiring authority must use
/// check_source_step through a trusted SourceStepGate, never a saved report.
pub(crate) fn stage_check(
    change: &PreparedChange,
    step: &PlanStep,
    phase: SourceStepPhase,
    report: &StateReportV2,
) -> Result<SourceStepCheck, ExecutorError> {
    use super::capability::ActionKind::*;
    let profiles = &change.policy.protection_profiles;
    let grants = &change.policy.grants;
    let closing = matches!(
        step.action,
        ConstrainDirectPath
            | DisableNativeIdentity
            | DisableNewConnections
            | RevokeSqlPrivileges
            | ObserveRevocation
    );
    let mut rows = Vec::new();
    for row in &report.rows {
        let d = &row.desired;
        if d.policy_revision_hash != change.plan.policy_revision_hash
            || d.address.target_id != step.target_id
        {
            continue;
        }
        let grant = grants
            .iter()
            .find(|g| g.id == d.address.grant_id)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let profile = profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let recovery = profile.management_exceptions.iter().any(|e| {
            e.recovery
                && e.subject == d.address.subject_id
                && e.source_ids.contains(&d.address.source.source_id)
                && e.route_id == d.address.route.id
        });
        let native = d.address.route.kind != RouteKind::Direct;
        let connectivity = matches!(
            d.address.effect,
            EffectKindV2::NewConnections | EffectKindV2::Transport { .. }
        );
        let relevant = match (step.action, phase) {
            (ConfirmRecoveryReadiness, _) => recovery && native && connectivity,
            (ObserveAccess, _) => {
                d.address.grant_id == step.grant_id && !recovery && native && connectivity
            }
            (ConstrainDirectPath, SourceStepPhase::BeforeDispatch) => {
                native
                    && ((recovery && connectivity)
                        || (!recovery
                            && grant.admission == AdmissionIntent::Allow
                            && (connectivity || d.address.effect == EffectKindV2::RuntimeBinding)))
            }
            (ConstrainDirectPath, SourceStepPhase::AfterConfiguration { .. }) => {
                (native && connectivity && (recovery || grant.admission == AdmissionIntent::Allow))
                    || (!native && d.address.effect == EffectKindV2::NewConnections)
            }
            (
                DisableNewConnections | ObserveRevocation,
                SourceStepPhase::AfterConfiguration { .. },
            ) => {
                (recovery && native && connectivity)
                    || (d.address.grant_id == step.grant_id
                        && !recovery
                        && d.address.effect == EffectKindV2::NewConnections)
            }
            (_, SourceStepPhase::BeforeDispatch) if closing => recovery && native && connectivity,
            _ => false,
        };
        if relevant {
            rows.push(row);
        }
    }
    // Every affected grant needs an INDEPENDENT recovery connection and each
    // mandatory transport segment. Missing recovery is not an empty success.
    let affected: Vec<_> = grants
        .iter()
        .filter(|g| {
            g.target == step.target_id
                && (step.action == ConstrainDirectPath || g.id == step.grant_id)
        })
        .collect();
    let recovery_covered = affected.iter().all(|g| {
        let Some(app) = change.policy.subjects.iter().find(|s| s.id == g.subject) else {
            return false;
        };
        rows.iter().any(|r| {
            let recovery_source = &r.desired.address.source;
            r.desired.address.grant_id == g.id
                && r.desired.address.subject_id != g.subject
                && !change.policy.source_bindings.iter().any(|source| {
                    app.workload_sources.contains(&source.source_id)
                        && (source.source_id == recovery_source.source_id
                            || source.registration_id == recovery_source.registration_id
                            || source.revision_digest == recovery_source.revision_digest)
                })
                && r.desired.address.effect == EffectKindV2::NewConnections
                && r.desired.expected == StateValue::Allowed
        })
    });
    let need_recovery = closing || step.action == ConfirmRecoveryReadiness;
    let mut unsatisfied = Vec::new();
    let mut refs = Vec::new();
    for row in &rows {
        let lower = match phase {
            SourceStepPhase::BeforeDispatch => None,
            SourceStepPhase::AfterConfiguration { not_before } => Some(not_before),
        };
        let fresh_after = lower.is_none_or(|floor| {
            !row.current_claims.is_empty()
                && row.current_claims.iter().all(|id| {
                    row.history.iter().any(|h| {
                        h.eligible
                            && format!("{}:{}", h.bundle_digest, h.claim.id) == *id
                            && h.claim.started_at >= floor
                    })
                })
        });
        if row.assessment != StateAssessment::Satisfied || !fresh_after {
            unsatisfied.push(row.desired.id.clone());
        } else {
            for h in &row.history {
                if h.eligible
                    && row
                        .current_claims
                        .contains(&format!("{}:{}", h.bundle_digest, h.claim.id))
                {
                    refs.push(h.bundle_digest.clone());
                    for derived in &report.derived_controls {
                        if derived.owner_bundle_digest == h.bundle_digest
                            && derived.owner_claim_id == h.claim.id
                            && let Some(digest) = &derived.control.bundle_digest
                        {
                            refs.push(digest.clone());
                        }
                    }
                }
            }
        }
    }
    refs.sort();
    refs.dedup();
    Ok(SourceStepCheck {
        satisfied: !rows.is_empty()
            && unsatisfied.is_empty()
            && (!need_recovery || recovery_covered),
        required_effect_ids: rows.iter().map(|r| r.desired.id.clone()).collect(),
        unsatisfied_effect_ids: unsatisfied,
        evidence_refs: refs,
    })
}

#[cfg(test)]
pub(crate) mod tests;
