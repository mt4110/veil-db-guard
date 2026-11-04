//! Planning contract for the next implementation slice. It grants no native
//! authority and cannot deserialize a claimed readiness into trusted facts.
use super::{
    change::PreparedChange,
    evidence::*,
    policy::{EngineFamily, PlacementKind},
    source::SourceBoundaryKind,
    source_execution::SOURCE_BOUND_EXECUTION_CONTRACT,
    state::{StateAssessment, StateError},
    state_v2::{StateReportV2, desired_for_change_v2},
};
use serde::Serialize;

pub const K11_INPUT_CONTRACT: &str = "k11-runtime-evidence-input-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffBlocker {
    StaticIntentUnsupported,
    ExecutionContractMismatch,
    UnsupportedSourceProfile,
    UnsupportedTargetProfile,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCheck {
    ProcessIncarnation,
    UserAndGroup,
    NetworkMountUserNamespaces,
    CgroupAndSecurityContext,
    SourceSnapshotAndCurrentTrust,
    TargetGeneration,
    ActualSessionIdentity,
    ActualRouteAndTransport,
    NativeCredentialProviderWithoutSecret,
    PoolAndConnectionGeneration,
    IndependentRecoveryAndCutover,
}
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeBindingRequirement {
    pub required_effect: RequiredEffectV2,
    pub checks: Vec<RuntimeCheck>,
}
#[derive(Debug, Clone, Serialize)]
pub struct ClosureGap {
    pub required_effect_id: String,
    pub address: EffectAddress,
    pub assessment: StateAssessment,
}
#[derive(Debug, Clone, Serialize)]
pub struct K11Handoff {
    pub schema_version: u32,
    pub input_contract: String,
    pub policy_revision_hash: String,
    pub change_hash: String,
    pub evaluation_contract: EvaluationContract,
    pub execution_contract: String,
    pub evaluated_at: u64,
    /// Compatibility for starting implementation, never deployment readiness.
    pub k11_implementation_can_start: bool,
    pub implementation_blockers: Vec<HandoffBlocker>,
    pub runtime_requirements: Vec<RuntimeBindingRequirement>,
    pub native_closure_gaps: Vec<ClosureGap>,
    pub current_protection_evaluated: bool,
    pub all_required_effects_satisfied: bool,
    pub native_dispatch_available: bool,
    pub native_queries_performed: bool,
}

/// `state` is produced by the common local evaluator. Reject mixed, missing,
/// duplicate or forged desired rows before projecting the K11 work package.
pub fn prepare(
    change: &PreparedChange,
    state: &StateReportV2,
    now: u64,
) -> Result<K11Handoff, StateError> {
    change.verify().map_err(|_| StateError::Invalid)?;
    if change.policy.schema_version != 2 || state.evaluated_at != now {
        return Err(StateError::Invalid);
    }
    let desired = desired_for_change_v2(&change.policy, change.previous_policy.as_ref(), &[], now)?;
    if state.rows.len() != desired.len()
        || desired
            .iter()
            .any(|d| state.rows.iter().filter(|r| r.desired == *d).count() != 1)
    {
        return Err(StateError::Invalid);
    }
    let mut blockers = vec![];
    if change
        .plan
        .steps
        .iter()
        .any(|s| s.adapter_contract != SOURCE_BOUND_EXECUTION_CONTRACT)
    {
        blockers.push(HandoffBlocker::ExecutionContractMismatch);
    }
    for target in &change.policy.targets {
        if !matches!(
            (
                target.placement.kind,
                target.engine.family,
                target.engine.version.as_str(),
                target.placement.region.as_str()
            ),
            (
                PlacementKind::GcpCloudSql,
                EngineFamily::PostgreSql,
                "16.15",
                "asia-northeast1"
            ) | (
                PlacementKind::AwsRds,
                EngineFamily::PostgreSql,
                "16.15",
                "ap-northeast-1"
            ) | (
                PlacementKind::AwsRds,
                EngineFamily::MySql,
                "8.0.43",
                "ap-northeast-1"
            )
        ) && !blockers.contains(&HandoffBlocker::UnsupportedTargetProfile)
        {
            blockers.push(HandoffBlocker::UnsupportedTargetProfile);
        }
    }
    for d in &desired {
        if !matches!(
            (d.address.target.placement.kind, d.address.source.boundary),
            (
                PlacementKind::GcpCloudSql,
                SourceBoundaryKind::GceHostNetwork
            ) | (PlacementKind::AwsRds, SourceBoundaryKind::AwsHostNetwork)
        ) && !blockers.contains(&HandoffBlocker::UnsupportedSourceProfile)
        {
            blockers.push(HandoffBlocker::UnsupportedSourceProfile);
        }
    }
    let runtime_requirements = desired
        .into_iter()
        .filter(|d| d.address.effect == EffectKindV2::RuntimeBinding)
        .map(|required_effect| RuntimeBindingRequirement {
            required_effect,
            checks: vec![
                RuntimeCheck::ProcessIncarnation,
                RuntimeCheck::UserAndGroup,
                RuntimeCheck::NetworkMountUserNamespaces,
                RuntimeCheck::CgroupAndSecurityContext,
                RuntimeCheck::SourceSnapshotAndCurrentTrust,
                RuntimeCheck::TargetGeneration,
                RuntimeCheck::ActualSessionIdentity,
                RuntimeCheck::ActualRouteAndTransport,
                RuntimeCheck::NativeCredentialProviderWithoutSecret,
                RuntimeCheck::PoolAndConnectionGeneration,
                RuntimeCheck::IndependentRecoveryAndCutover,
            ],
        })
        .collect();
    Ok(K11Handoff {
        schema_version: 1,
        input_contract: K11_INPUT_CONTRACT.into(),
        policy_revision_hash: change.plan.policy_revision_hash.clone(),
        change_hash: change.change_hash.clone(),
        evaluation_contract: EvaluationContract::SourceBoundV2,
        execution_contract: SOURCE_BOUND_EXECUTION_CONTRACT.into(),
        evaluated_at: now,
        k11_implementation_can_start: blockers.is_empty(),
        implementation_blockers: blockers,
        runtime_requirements,
        native_closure_gaps: state
            .rows
            .iter()
            .filter(|r| r.assessment != StateAssessment::Satisfied)
            .map(|r| ClosureGap {
                required_effect_id: r.desired.id.clone(),
                address: r.desired.address.clone(),
                assessment: r.assessment,
            })
            .collect(),
        current_protection_evaluated: state.protection_evaluated,
        all_required_effects_satisfied: state.all_required_effects_satisfied,
        native_dispatch_available: false,
        native_queries_performed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{source_execution::tests::change, state_v2::*};
    fn empty(c: &PreparedChange) -> StateReportV2 {
        evaluate_source_state_v2(&StateEvaluationInputV2 {
            contract: EvaluationContract::SourceBoundV2,
            now: 130,
            max_age_seconds: 60,
            desired: desired_for_change_v2(&c.policy, c.previous_policy.as_ref(), &[], 130)
                .unwrap(),
            evidence: vec![],
            permission_removals: vec![],
        })
        .unwrap()
    }
    #[test]
    fn integration_can_start_with_unknown_effects_without_weakening_native_gate() {
        let c = change();
        let state = empty(&c);
        let handoff = prepare(&c, &state, 130).unwrap();
        assert!(handoff.k11_implementation_can_start);
        assert!(!handoff.native_dispatch_available);
        assert!(!handoff.current_protection_evaluated);
        assert!(!handoff.all_required_effects_satisfied);
        assert!(!handoff.native_closure_gaps.is_empty());
        assert!(!handoff.runtime_requirements.is_empty());
        let close = c
            .plan
            .steps
            .iter()
            .find(|s| s.action == crate::core::capability::ActionKind::ConstrainDirectPath)
            .unwrap();
        assert!(
            !crate::core::source_execution::check_source_step(
                &c,
                close,
                crate::core::source_execution::SourceStepPhase::BeforeDispatch,
                130,
                vec![]
            )
            .unwrap()
            .satisfied()
        );
        assert!(
            handoff
                .runtime_requirements
                .iter()
                .all(|r| r.checks.contains(&RuntimeCheck::CgroupAndSecurityContext))
        );
    }
    #[test]
    fn incomplete_foreign_duplicate_or_stale_state_cannot_be_a_handoff_input() {
        let c = change();
        for n in 0..4 {
            let mut state = empty(&c);
            match n {
                0 => {
                    state.rows.pop();
                }
                1 => state.rows[0].desired.policy_revision_hash = "f".repeat(64),
                2 => state.rows[1] = state.rows[0].clone(),
                _ => state.evaluated_at = 129,
            }
            assert!(prepare(&c, &state, 130).is_err(), "{n}");
        }
    }
}
