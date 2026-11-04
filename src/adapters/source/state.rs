//! Offline current-state composition. Expired/revoked/corrupt records are not
//! admitted anew. Integrity-checked original history is visibly ineligible.
use super::support::{self, SourceCoverage};
use crate::{
    core::{
        admission::*,
        change::PreparedChange,
        evidence::*,
        ports::{EvidenceArchive, EvidenceLedger},
        state::StateAssessment,
        state_v2::*,
    },
    evidence_store::EvidenceStore,
};
use serde::Serialize;
use std::collections::BTreeSet;
mod pending;
#[derive(Debug, Clone, Serialize)]
pub struct AdmissionRead {
    pub request_id: String,
    pub current: bool,
    pub error: Option<AdmissionErrorCode>,
    pub original_admission: Option<EvidenceAdmission>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionErrorCode {
    Expired,
    TrustChanged,
    BuildChanged,
    IntegrityError,
    NotAdmitted,
    Unavailable,
}
#[derive(Debug, Clone, Serialize)]
pub struct SourceStateReport {
    pub schema_version: u32,
    pub context_id: String,
    pub effective: StateReportV2,
    pub source_coverage: Vec<SourceCoverage>,
    pub admission_reads: Vec<AdmissionRead>,
    pub native_step_evidence: Vec<super::native_gate::NativeStepEvidence>,
    pub native_queries_performed: bool,
    pub native_dispatch_available: bool,
}
pub fn empty(
    change: &PreparedChange,
    context: &str,
    now: u64,
) -> Result<SourceStateReport, AdmissionError> {
    let desired = desired_for_change_v2(&change.policy, change.previous_policy.as_ref(), &[], now)
        .map_err(|_| AdmissionError::Invalid)?;
    let effective = evaluate_source_state_v2(&StateEvaluationInputV2 {
        contract: EvaluationContract::SourceBoundV2,
        now,
        max_age_seconds: DEFAULT_FRESHNESS_SECONDS,
        desired,
        evidence: vec![],
        permission_removals: vec![],
    })
    .map_err(|_| AdmissionError::Invalid)?;
    Ok(SourceStateReport {
        schema_version: 2,
        context_id: context.into(),
        native_step_evidence: super::native_gate::evaluate(change, &effective),
        effective,
        source_coverage: support::for_policy(&change.policy)
            .map_err(|_| AdmissionError::Invalid)?,
        admission_reads: vec![],
        native_queries_performed: false,
        native_dispatch_available: false,
    })
}
fn classification(error: AdmissionError, old_build: bool) -> (AdmissionErrorCode, EvidenceReason) {
    match error {
        AdmissionError::Expired => (AdmissionErrorCode::Expired, EvidenceReason::StaleEvidence),
        AdmissionError::TrustChanged if old_build => (
            AdmissionErrorCode::BuildChanged,
            EvidenceReason::BuildMismatch,
        ),
        AdmissionError::TrustChanged => (
            AdmissionErrorCode::TrustChanged,
            EvidenceReason::TrustEpochMismatch,
        ),
        AdmissionError::Integrity => (
            AdmissionErrorCode::IntegrityError,
            EvidenceReason::IntegrityError,
        ),
        AdmissionError::NotFound => (
            AdmissionErrorCode::NotAdmitted,
            EvidenceReason::MissingAdmission,
        ),
        _ => (
            AdmissionErrorCode::Unavailable,
            EvidenceReason::MissingEvidence,
        ),
    }
}
pub fn evaluate<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &A,
    change: &PreparedChange,
    context: &str,
    ids: &[String],
    now: u64,
) -> Result<SourceStateReport, AdmissionError> {
    evaluate_with_pending(ledger, archive, change, context, ids, now, None)
}
fn evaluate_with_pending<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &A,
    change: &PreparedChange,
    context: &str,
    ids: &[String],
    now: u64,
    removal_context: Option<&pending::PendingContext>,
) -> Result<SourceStateReport, AdmissionError> {
    if ids.len() > 32768 || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(AdmissionError::Limit);
    }
    let mut report = empty(change, context, now)?;
    let mut facts = vec![];
    let mut history = vec![];
    for id in ids {
        let issued = ledger.issued(id)?;
        if issued.request.operation_id != context
            || issued.request.change_hash != change.change_hash
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        match load_admitted(ledger, archive, id, now) {
            Ok(f) => {
                report.admission_reads.push(AdmissionRead {
                    request_id: id.clone(),
                    current: true,
                    error: None,
                    original_admission: Some(f.admission().clone()),
                });
                facts.push(f)
            }
            Err(error) => {
                let (mut code, reason) =
                    classification(error, issued.request.verifier_build_id != crate::BUILD_ID);
                let original = match read_admitted_history(ledger, archive, id) {
                    Ok(h) => {
                        history.push((h.clone(), reason));
                        Some(h.admission)
                    }
                    Err(e) => {
                        code = classification(e, false).0;
                        None
                    }
                };
                report.admission_reads.push(AdmissionRead {
                    request_id: id.clone(),
                    current: false,
                    error: Some(code),
                    original_admission: original,
                });
            }
        }
    }
    // Do not keep a previously loaded current object if its source trust changes
    // while another archive is read. No fallback to a serialized verdict.
    let mut current = vec![];
    for f in facts {
        let read = report
            .admission_reads
            .iter_mut()
            .find(|r| {
                r.original_admission
                    .as_ref()
                    .is_some_and(|a| a.id == f.admission_id())
            })
            .ok_or(AdmissionError::Integrity)?;
        let issued = ledger.issued(&read.request_id)?;
        match ledger.ensure_current(&issued, now) {
            Ok(()) => current.push(f),
            Err(e) => {
                let (code, reason) =
                    classification(e, issued.request.verifier_build_id != crate::BUILD_ID);
                read.current = false;
                read.error = Some(code);
                history.push((
                    StoredObservationHistory {
                        admission: f.admission().clone(),
                        claims: f.claims().to_vec(),
                    },
                    reason,
                ));
            }
        }
    }
    let derived = if let Some(context) = removal_context {
        pending::derive(ledger, archive, change, context, &current, now)?
    } else {
        pending::DerivedRemovals {
            removals: vec![],
            before_evidence: vec![],
        }
    };
    // A prior-archive read must not leave a previously verified current source
    // alive after its trust head changed. This closes the additional read window.
    if removal_context.is_some() {
        for read in report.admission_reads.iter().filter(|r| r.current) {
            let issued = ledger.issued(&read.request_id)?;
            ledger.ensure_current(&issued, now)?;
        }
    }
    report.effective = evaluate_source_state_v2_with_removal_evidence(
        &StateEvaluationInputV2 {
            contract: EvaluationContract::SourceBoundV2,
            now,
            max_age_seconds: DEFAULT_FRESHNESS_SECONDS,
            desired: report
                .effective
                .rows
                .iter()
                .map(|r| r.desired.clone())
                .collect(),
            evidence: current,
            permission_removals: derived.removals,
        },
        &derived.before_evidence,
    )
    .map_err(|_| AdmissionError::Invalid)?;
    for (old, reason) in history {
        for claim in old.claims {
            for row in &mut report.effective.rows {
                let a = &row.desired.address;
                let b = &claim.address;
                if a.target_id == b.target_id
                    && a.grant_id == b.grant_id
                    && a.subject_id == b.subject_id
                    && a.source.source_id == b.source.source_id
                    && a.route == b.route
                    && a.effect == b.effect
                {
                    row.history.push(ObservationV2 {
                        bundle_digest: old.admission.bundle_digest.clone(),
                        claim: claim.clone(),
                        eligible: false,
                        reason: Some(reason),
                        missing_assurance: row.desired.required_assurance.clone(),
                    });
                }
            }
        }
    }
    for row in &mut report.effective.rows {
        row.history.sort_by(|a, b| {
            (a.claim.finished_at, &a.bundle_digest, &a.claim.id).cmp(&(
                b.claim.finished_at,
                &b.bundle_digest,
                &b.claim.id,
            ))
        });
    }
    // Corrupt/unreadable requested evidence is explicit incomplete coverage.
    // Ordinary older expired history does not override fresh complete evidence.
    if report.admission_reads.iter().any(|r| {
        matches!(
            r.error,
            Some(AdmissionErrorCode::IntegrityError | AdmissionErrorCode::Unavailable)
        )
    }) {
        report.effective.all_required_effects_satisfied = false;
        if report.effective.assessment == StateAssessment::Satisfied {
            report.effective.assessment = StateAssessment::Unknown
        }
    }
    report.native_step_evidence = super::native_gate::evaluate(change, &report.effective);
    Ok(report)
}
pub fn read_local(
    ledger: &mut EvidenceStore,
    archive: &impl EvidenceArchive,
    change: &PreparedChange,
    context: &str,
    ids: &[String],
    now: u64,
) -> Result<SourceStateReport, AdmissionError> {
    let ids = if ids.is_empty() {
        ledger.request_ids(context)?
    } else {
        ids.to_vec()
    };
    let mut pending = pending::context(ledger.operation_store(), change, context, now)?;
    if let Some(p) = &mut pending {
        p.request_ids = ledger.request_ids(&p.before_operation_id)?;
    }
    let report = evaluate_with_pending(
        ledger,
        archive,
        change,
        context,
        &ids,
        now,
        pending.as_ref(),
    )?;
    if report
        .effective
        .rows
        .iter()
        .any(|r| r.assessment == StateAssessment::Pending)
    {
        let refreshed = pending::context(ledger.operation_store(), change, context, now)?;
        if refreshed.as_ref().map(|p| &p.fingerprint) != pending.as_ref().map(|p| &p.fingerprint) {
            // A concurrent receipt, cancellation or desired-head change cannot
            // preserve a propagation verdict from the earlier operation view.
            return evaluate(ledger, archive, change, context, &ids, now);
        }
    }
    Ok(report)
}
