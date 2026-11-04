//! Shared presentation/gates at the CLI edge. Static qualification never grants
//! approval and never replaces runtime identity, ownership or handoff checks.
use crate::{
    adapters::qualification::{QualificationDisposition, QualificationReport, qualify_change},
    config::GuardError,
    core::{
        change::PreparedChange,
        operation::{ExecutionState, Operation, StepRecord, StepState},
    },
};

pub(crate) fn report(change: &PreparedChange) -> Result<QualificationReport, GuardError> {
    qualify_change(change).map_err(|_| GuardError::EvidenceIncompatible)
}

pub(crate) fn gap_count(report: &QualificationReport) -> usize {
    report
        .findings
        .iter()
        .filter(|f| f.disposition == QualificationDisposition::Unsupported)
        .count()
}

pub(crate) fn require(report: &QualificationReport) -> Result<(), GuardError> {
    if report.is_qualified() {
        return Ok(());
    }
    reject(report)
}

fn reject(report: &QualificationReport) -> Result<(), GuardError> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "operation_only":true,"native_dispatch_available":false,
            "protection_evaluated":false,"intent_qualification":report
        }))
        .map_err(|_| GuardError::StorageFailed)?
    );
    Err(GuardError::IntentNotQualified)
}

/// Accepted work remains queryable even if current code discovers a static
/// incompatibility elsewhere in the old plan. Composed executors separately
/// prevent every new dispatch, preflight and submit in that case.
pub(crate) fn require_before_native(
    report: &QualificationReport,
    records: &[StepRecord],
) -> Result<(), GuardError> {
    if has_unresolved(records) || report.is_dispatch_qualified() {
        Ok(())
    } else {
        reject(report)
    }
}

/// Local evidence presentation before any native configuration/tool/credential
/// lookup. Evidence never overrides the current adapter qualification contract.
pub(crate) fn require_before_native_with_source(
    report: &QualificationReport,
    records: &[StepRecord],
    source: Option<&crate::adapters::source::state::SourceStateReport>,
) -> Result<(), GuardError> {
    if has_unresolved(records) || report.is_dispatch_qualified() {
        return Ok(());
    }
    if let Some(source) = source {
        println!("{}",serde_json::to_string_pretty(&serde_json::json!({"operation_only":true,"native_dispatch_available":false,"protection_evaluated":source.effective.protection_evaluated,"native_queries_performed":false,"intent_qualification":report,"source_evidence":source})).map_err(|_|GuardError::StorageFailed)?);
        Err(GuardError::IntentNotQualified)
    } else {
        require_before_native(report, records)
    }
}

pub(crate) fn has_unresolved(records: &[StepRecord]) -> bool {
    records.iter().any(|r| {
        matches!(
            r.state,
            StepState::Dispatching
                | StepState::Submitted
                | StepState::ConfigApplied
                | StepState::OutcomeUnknown
        )
    })
}

/// A recorded completed operation needs no credential/tool/DB access. Its past
/// completion still cannot assert present policy protection.
pub(crate) fn completed_without_native(
    operation: &Operation,
    records: &[StepRecord],
    report: &QualificationReport,
) -> Result<Option<i32>, GuardError> {
    if operation.state != ExecutionState::Completed || has_unresolved(records) {
        return Ok(None);
    }
    let mut output = serde_json::json!({"operation_only":true,"native_dispatch_available":false,
        "native_queries_performed":false,"operation":operation,"steps":records,
        "intent_qualification":report,"forward_dispatch_blocked":!report.is_dispatch_qualified()});
    for (key, value) in completion(operation.state)
        .as_object()
        .ok_or(GuardError::StorageFailed)?
    {
        output[key] = value.clone();
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|_| GuardError::StorageFailed)?
    );
    Ok(Some(0))
}

/// Completion is scoped to the operation. Native collectors currently cannot
/// evaluate every common-policy source/effect; K10 must supply that evidence.
pub(crate) fn completion(state: ExecutionState) -> serde_json::Value {
    serde_json::json!({"operation_scope_completed":state==ExecutionState::Completed,
        "protection_evaluated":false,"current_protection_rechecked":false})
}

pub(crate) fn append_report(
    text: &mut String,
    report: &QualificationReport,
) -> Result<(), GuardError> {
    text.push_str(&format!("\n## 要求別の事前判定\n\n静的な非対応: {}件。実構成・実効・将来のhandoffは未確認です。\n\n```json\n{}\n```\n",
        gap_count(report), serde_json::to_string_pretty(report).map_err(|_| GuardError::StorageFailed)?));
    Ok(())
}

/// Fail before native config/tool/credential lookup if the currently runnable
/// source step lacks evidence. Earlier setup steps may proceed under their own
/// immutable approval; accepted queries remain available despite source loss.
pub(crate) fn require_source_ready_for_next(
    records: &[StepRecord],
    source: &crate::adapters::source::state::SourceStateReport,
) -> Result<(), GuardError> {
    if has_unresolved(records) {
        return Ok(());
    }
    let blocker = source.native_step_evidence.iter().find(|s| {
        records.iter().any(|r| {
            r.step_id == s.step_id && matches!(r.state, StepState::Prepared | StepState::NotApplied)
        }) && s.dependencies.iter().all(|id| {
            records.iter().any(|r| {
                &r.step_id == id
                    && matches!(
                        r.state,
                        StepState::EffectSatisfied | StepState::NoOpSatisfied
                    )
            })
        }) && s.before_dispatch.as_ref().is_some_and(|c| !c.satisfied())
    });
    if let Some(step) = blocker {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "native_dispatch_available":false,"reason":"source_evidence_not_ready",
                "blocked_step":step,"source_evidence":source
            }))
            .map_err(|_| GuardError::StorageFailed)?
        );
        return Err(GuardError::SourceEvidenceNotReady);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_operation_never_substitutes_for_policy_protection_evaluation() {
        for state in [
            ExecutionState::Completed,
            ExecutionState::WaitingEffect,
            ExecutionState::FailedPartial,
            ExecutionState::Cancelled,
        ] {
            let output = completion(state);
            assert_eq!(
                output["operation_scope_completed"],
                state == ExecutionState::Completed
            );
            assert_eq!(output["protection_evaluated"], false);
            assert_eq!(output["current_protection_rechecked"], false);
        }
    }
}
