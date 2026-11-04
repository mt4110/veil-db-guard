//! Diagnostic projection of source-bound native prerequisites. Execution-v3
//! uses trusted current SourceStepGate checks; this saved report grants no
//! dispatch authority and never substitutes for those checks.
use crate::core::{
    capability::{ActionKind, requires_source_evidence},
    change::PreparedChange,
    evidence::SOURCE_BOUND_ADAPTER_CONTRACT,
    source_execution::{
        SOURCE_BOUND_EXECUTION_CONTRACT, SourceStepCheck, SourceStepPhase, stage_check,
    },
    state::StateAssessment,
    state_v2::StateReportV2,
};
use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
pub struct NativeStepEvidence {
    pub step_id: String,
    pub dependencies: Vec<String>,
    pub action: ActionKind,
    pub source_contract_matches: bool,
    pub required_effect_ids: Vec<String>,
    pub unsatisfied_effect_ids: Vec<String>,
    pub observed_effects_satisfied: bool,
    pub native_dispatch_available: bool,
    pub reason: NativeGateReason,
    pub before_dispatch: Option<SourceStepCheck>,
    pub after_configuration: Option<SourceStepCheck>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeGateReason {
    SourceEvidenceIncomplete,
    SourceAwareExecutorUnavailable,
    RuntimeChecksRequired,
    ContractMismatch,
}
pub fn evaluate(change: &PreparedChange, state: &StateReportV2) -> Vec<NativeStepEvidence> {
    change
        .plan
        .steps
        .iter()
        .filter(|s| {
            requires_source_evidence(s.action)
                || s.action == ActionKind::CompensateOwnedIam
                || (s.adapter_contract == SOURCE_BOUND_EXECUTION_CONTRACT
                    && matches!(
                        s.action,
                        ActionKind::DisableNativeIdentity | ActionKind::RevokeSqlPrivileges
                    ))
        })
        .map(|s| {
            let recovery = change
                .policy
                .protection_profiles
                .iter()
                .find(|p| p.id == s.profile_id)
                .map(|p| {
                    p.management_exceptions
                        .iter()
                        .filter(|e| e.recovery)
                        .map(|e| e.subject.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let required: Vec<_> = state
                .rows
                .iter()
                .filter(|r| {
                    r.desired.policy_revision_hash == change.plan.policy_revision_hash
                        && r.desired.address.target_id == s.target_id
                        && r.desired.address.grant_id == s.grant_id
                        && (s.action != ActionKind::ConfirmRecoveryReadiness
                            || recovery.contains(&r.desired.address.subject_id.as_str()))
                })
                .collect();
            let unsatisfied = required
                .iter()
                .filter(|r| r.assessment != StateAssessment::Satisfied)
                .map(|r| r.desired.id.clone())
                .collect::<Vec<_>>();
            let compensation = s.action == ActionKind::CompensateOwnedIam
                && s.adapter_contract == crate::core::plan::OWNED_IAM_COMPENSATION_CONTRACT;
            let executable = s.adapter_contract == SOURCE_BOUND_EXECUTION_CONTRACT || compensation;
            let contract = s.adapter_contract == SOURCE_BOUND_ADAPTER_CONTRACT || executable;
            let satisfied = !required.is_empty() && unsatisfied.is_empty();
            NativeStepEvidence {
                step_id: s.id.clone(),
                dependencies: s.dependencies.clone(),
                action: s.action,
                source_contract_matches: contract,
                required_effect_ids: required.iter().map(|r| r.desired.id.clone()).collect(),
                unsatisfied_effect_ids: unsatisfied,
                observed_effects_satisfied: satisfied,
                native_dispatch_available: false,
                before_dispatch: if executable {
                    stage_check(change, s, SourceStepPhase::BeforeDispatch, state).ok()
                } else {
                    None
                },
                after_configuration: if executable && !compensation {
                    stage_check(
                        change,
                        s,
                        SourceStepPhase::AfterConfiguration { not_before: 0 },
                        state,
                    )
                    .ok()
                } else {
                    None
                },
                reason: if !contract {
                    NativeGateReason::ContractMismatch
                } else if executable {
                    NativeGateReason::RuntimeChecksRequired
                } else if !satisfied {
                    NativeGateReason::SourceEvidenceIncomplete
                } else {
                    NativeGateReason::SourceAwareExecutorUnavailable
                },
            }
        })
        .collect()
}
