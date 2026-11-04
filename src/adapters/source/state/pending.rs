//! Derive narrowly scoped propagation references from trusted local operations.
//! No JSON removal references, prior-context controls, or guessed IAM deadline.
use crate::{
    core::{
        admission::*,
        approval::ApprovalGrant,
        capability::ActionKind,
        change::PreparedChange,
        evidence::*,
        lifecycle::LifecycleKind,
        operation::*,
        policy::*,
        ports::{EvidenceArchive, EvidenceLedger},
        state::{StateLayer, StateValue},
        state_v2::*,
    },
    operation_store::OperationStore,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub(super) struct PendingContext {
    operation: Operation,
    approval: ApprovalGrant,
    pub(super) before_operation_id: String,
    before_change_hash: String,
    before_policy_hash: String,
    windows: Vec<Window>,
    pub(super) request_ids: Vec<String>,
    pub(super) fingerprint: String,
}
#[derive(Debug, Clone)]
struct Window {
    grant_id: String,
    target_id: String,
    dispatched_at: u64,
    changed_at: u64,
    deadline: u64,
}

fn storage(error: StoreError) -> AdmissionError {
    match error {
        StoreError::NotFound => AdmissionError::NotFound,
        StoreError::Limit => AdmissionError::Limit,
        _ => AdmissionError::Storage,
    }
}

pub(super) fn context(
    store: &OperationStore,
    change: &PreparedChange,
    operation_id: &str,
    now: u64,
) -> Result<Option<PendingContext>, AdmissionError> {
    let operation = match store.get(operation_id) {
        Ok(o) => o,
        // Read-only observation sessions never authorize a removal.
        Err(StoreError::NotFound) => return Ok(None),
        Err(e) => return Err(storage(e)),
    };
    change.verify().map_err(|_| AdmissionError::Integrity)?;
    if operation.change_hash != change.change_hash
        || operation.policy_revision_hash != change.plan.policy_revision_hash
    {
        return Err(AdmissionError::ScopeMismatch);
    }
    let Some(lineage) = &change.lifecycle else {
        return Ok(None);
    };
    if lineage.kind != LifecycleKind::Revoke
        || matches!(
            operation.state,
            ExecutionState::FailedPartial
                | ExecutionState::Cancelled
                | ExecutionState::Recovering
                | ExecutionState::Completed
        )
    {
        return Ok(None);
    }
    let before = store.get(&lineage.source_operation_id).map_err(storage)?;
    let before_change = store.load_change(&before.change_hash).map_err(storage)?;
    if before.id == operation.id
        || before.change_hash != lineage.source_change_hash
        || before.policy_revision_hash != lineage.source_policy_revision_hash
        || before.state != ExecutionState::Completed
        || crate::core::lifecycle::validate_source(change, &before_change).is_err()
    {
        return Ok(None);
    }
    let Some(previous) = &change.previous_policy else {
        return Ok(None);
    };
    let before_hash = previous
        .revision_hash()
        .map_err(|_| AdmissionError::Integrity)?;
    if before_hash != before.policy_revision_hash {
        return Ok(None);
    }
    let approval = store
        .load_approval(&operation.approval_id)
        .map_err(storage)?;
    let before_approval = store.load_approval(&before.approval_id).map_err(storage)?;
    if before_approval
        .validate(
            &before_change,
            &before.execution_identity,
            before.created_at,
            false,
        )
        .is_err()
    {
        return Ok(None);
    }
    let events = store.events(&operation.id).map_err(storage)?;
    let before_events = store.events(&before.id).map_err(storage)?;
    if events
        .iter()
        .chain(&before_events)
        .any(|e| e.event == EventKind::ApprovalCancelled)
    {
        return Ok(None);
    }
    let steps = store.steps(&operation.id).map_err(storage)?;
    if steps.iter().any(|s| {
        matches!(
            s.state,
            StepState::Failed
                | StepState::OutcomeUnknown
                | StepState::Compensating
                | StepState::Compensated
        )
    }) {
        return Ok(None);
    }
    if store
        .desired_head(&change.policy.policy_id)
        .map_err(storage)?
        .as_deref()
        != Some(change.plan.policy_revision_hash.as_str())
    {
        return Ok(None);
    }
    let approved_end = operation
        .created_at
        .checked_add(change.limits.max_operation_seconds)
        .ok_or(AdmissionError::Invalid)?
        .min(approval.forward_valid_until);
    let mut windows = Vec::new();
    for plan in change
        .plan
        .steps
        .iter()
        .filter(|s| s.action == ActionKind::DisableNativeIdentity)
    {
        let Some(target) = change
            .policy
            .targets
            .iter()
            .find(|t| t.id == plan.target_id)
        else {
            continue;
        };
        if target.placement.kind != PlacementKind::GcpCloudSql
            || target.engine.family != EngineFamily::PostgreSql
            || plan.adapter_contract
                != crate::core::source_execution::SOURCE_BOUND_EXECUTION_CONTRACT
        {
            continue;
        }
        let Some(record) = steps.iter().find(|s| s.step_id == plan.id) else {
            continue;
        };
        if record.attempt != 1 || record.state != StepState::EffectSatisfied {
            continue;
        }
        let Some(receipt) = &record.receipt else {
            continue;
        };
        let native_ref = format!(
            "gcp-readback-{}",
            crate::config::hash_bytes(
                &serde_json::to_vec(&(&change.change_hash, &plan.id, &plan.parameters_hash))
                    .map_err(|_| AdmissionError::Invalid)?
            )
        );
        let evidence = crate::config::hash_bytes(
            &serde_json::to_vec(&(
                "native-postcondition-v1",
                &change.change_hash,
                &plan.id,
                &native_ref,
            ))
            .map_err(|_| AdmissionError::Invalid)?,
        );
        if receipt.state != StepState::EffectSatisfied
            || receipt.effect != EffectState::Enforced
            || receipt.native_operation_ref.as_deref() != Some(native_ref.as_str())
            || !receipt.evidence_refs.contains(&evidence)
        {
            continue;
        }
        let dispatched = events
            .iter()
            .filter(|e| {
                e.step_id.as_deref() == Some(plan.id.as_str()) && e.event == EventKind::Dispatched
            })
            .collect::<Vec<_>>();
        let recorded = events
            .iter()
            .filter(|e| {
                e.step_id.as_deref() == Some(plan.id.as_str())
                    && matches!(e.event, EventKind::ReceiptRecorded | EventKind::Resolved)
            })
            .collect::<Vec<_>>();
        if dispatched.len() != 1 || recorded.len() != 1 {
            continue;
        }
        let (dispatch, changed) = (dispatched[0], recorded[0]);
        if dispatch.sequence >= changed.sequence
            || dispatch.at > changed.at
            || dispatch.at < operation.created_at
            || changed.at > now
            || approval
                .validate(change, &operation.execution_identity, changed.at, false)
                .is_err()
        {
            continue;
        }
        // This is the approved observation-wait budget, never a provider SLA.
        let deadline = approved_end.min(
            changed
                .at
                .saturating_add(crate::core::state::MAX_PROPAGATION_SECONDS),
        );
        if deadline <= changed.at || now >= deadline {
            continue;
        }
        windows.push(Window {
            grant_id: plan.grant_id.clone(),
            target_id: plan.target_id.clone(),
            dispatched_at: dispatch.at,
            changed_at: changed.at,
            deadline,
        });
    }
    if windows.is_empty() {
        return Ok(None);
    }
    let fingerprint = crate::config::hash_bytes(
        &serde_json::to_vec(&(
            &operation,
            &approval,
            &before,
            &before_approval,
            &steps,
            &events,
            &before_events,
        ))
        .map_err(|_| AdmissionError::Invalid)?,
    );
    Ok(Some(PendingContext {
        operation,
        approval,
        before_operation_id: before.id,
        before_change_hash: before.change_hash,
        before_policy_hash: before_hash,
        windows,
        request_ids: vec![],
        fingerprint,
    }))
}

fn complete(f: &VerifiedObservationFacts, c: &ObservationClaim, now: u64) -> bool {
    let a = f.admission();
    let Some(coverage) = f
        .assurances()
        .iter()
        .find(|a| a.claim_id == c.id)
        .map(|a| &a.coverage)
    else {
        return false;
    };
    a.verification_recipe == "gce-host-network-root-v1"
        && c.finished_at >= c.started_at
        && c.finished_at <= now
        && c.started_at >= a.capture_started_at
        && c.finished_at <= a.capture_finished_at
        && now < a.valid_until
        && a.accepted_at <= now
        && now.saturating_sub(c.started_at) <= DEFAULT_FRESHNESS_SECONDS
        && [
            &coverage.target,
            &coverage.principal,
            &coverage.source,
            &coverage.route,
            &coverage.transport,
            &coverage.temporal,
            &coverage.completeness,
        ]
        .iter()
        .all(|a| matches!(a, Assurance::Verified { .. }))
}

fn native_inventory(c: &ObservationClaim) -> bool {
    c.id == format!("iam-{}", c.case_id)
        && c.observed == StateValue::Unknown
        && c.layer == StateLayer::ConnectionAuthorization
        && c.permission_inventory.as_ref().is_some_and(|i| {
            i.complete
                && i.permissions.iter().all(|p| {
                    matches!(
                        p.as_str(),
                        "cloudsql.instances.connect"
                            | "cloudsql.instances.get"
                            | "cloudsql.instances.login"
                    )
                })
        })
}

pub(super) struct DerivedRemovals {
    pub(super) removals: Vec<PermissionRemovalV2>,
    pub(super) before_evidence: Vec<VerifiedObservationFacts>,
}
pub(super) fn derive<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &A,
    change: &PreparedChange,
    context: &PendingContext,
    current: &[VerifiedObservationFacts],
    now: u64,
) -> Result<DerivedRemovals, AdmissionError> {
    let mut old = Vec::new();
    let mut issued = Vec::new();
    if context.request_ids.len() > 32768 {
        return Err(AdmissionError::Limit);
    }
    for id in &context.request_ids {
        let i = ledger.issued(id)?;
        if i.request.operation_id != context.before_operation_id
            || i.request.change_hash != context.before_change_hash
            || i.request.policy_revision_hash != context.before_policy_hash
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        match load_admitted(ledger, archive, id, now) {
            Ok(f) => {
                old.push(f);
                issued.push(i);
            }
            // An unavailable prior proof cannot grant Pending. It is not a
            // current-context failure and does not overwrite actual Allowed.
            Err(_) => continue,
        }
    }
    let mut removals = Vec::new();
    let mut used = BTreeSet::new();
    for window in &context.windows {
        for after in current {
            if after.admission().operation_id != context.operation.id
                || after.admission().change_hash != change.change_hash
                || after.admission().capture_started_at <= window.changed_at
            {
                continue;
            }
            for a in after.claims().iter().filter(|a| {
                a.address.grant_id == window.grant_id
                    && a.address.target_id == window.target_id
                    && a.address.effect == EffectKindV2::NewConnections
                    && a.started_at > window.changed_at
                    && native_inventory(a)
                    && complete(after, a, now)
            }) {
                // Native PG precedes IAM in a capture. Require a later actual
                // Allowed capture, and reject a later incomplete/changed set.
                if current.iter().any(|f| {
                    f.claims().iter().any(|c| {
                        c.address == a.address
                            && c.permission_inventory.is_some()
                            && (
                                c.finished_at,
                                c.started_at,
                                f.bundle_digest(),
                                c.id.as_str(),
                            ) > (
                                a.finished_at,
                                a.started_at,
                                after.bundle_digest(),
                                a.id.as_str(),
                            )
                            && (!native_inventory(c)
                                || !complete(f, c, now)
                                || c.permission_inventory != a.permission_inventory)
                    })
                }) {
                    continue;
                }
                let latest = current
                    .iter()
                    .flat_map(|f| f.claims().iter().map(move |p| (f, p)))
                    .filter(|(_, p)| {
                        p.address == a.address
                            && p.id == format!("source-{}", p.case_id)
                            && p.permission_inventory.is_none()
                    })
                    .max_by_key(|(f, p)| {
                        (
                            p.finished_at,
                            p.started_at,
                            f.bundle_digest(),
                            p.id.as_str(),
                        )
                    });
                let Some((latest_f, p)) = latest else {
                    continue;
                };
                if p.observed != StateValue::Allowed
                    || p.layer != StateLayer::Authentication
                    || p.started_at < a.finished_at
                    || !complete(latest_f, p, now)
                    || !latest_f.claims().iter().any(|corroborating| {
                        corroborating.case_id == p.case_id
                            && corroborating.address == p.address
                            && native_inventory(corroborating)
                            && complete(latest_f, corroborating, now)
                            && corroborating.permission_inventory == a.permission_inventory
                    })
                {
                    continue;
                }
                let before = old
                    .iter()
                    .flat_map(|f| f.claims().iter().map(move |c| (f, c)))
                    .filter(|(_, b)| {
                        b.address == a.address
                            && b.finished_at < window.dispatched_at
                            && b.policy_revision_hash == context.before_policy_hash
                            && b.permission_inventory.is_some()
                    })
                    .max_by_key(|(_, c)| c.finished_at);
                let prior = old
                    .iter()
                    .flat_map(|f| f.claims().iter().map(move |c| (f, c)))
                    .filter(|(_, p)| {
                        p.address == a.address
                            && p.finished_at < window.dispatched_at
                            && p.policy_revision_hash == context.before_policy_hash
                            && p.id == format!("source-{}", p.case_id)
                            && p.permission_inventory.is_none()
                    })
                    .max_by_key(|(_, c)| c.finished_at);
                let (Some((bf, b)), Some((pf, p))) = (before, prior) else {
                    continue;
                };
                if !native_inventory(b)
                    || !complete(bf, b, now)
                    || p.observed != StateValue::Allowed
                    || p.layer != StateLayer::Authentication
                    || !complete(pf, p, now)
                {
                    continue;
                }
                let previous: BTreeSet<_> = b
                    .permission_inventory
                    .as_ref()
                    .unwrap()
                    .permissions
                    .iter()
                    .collect();
                let present: BTreeSet<_> = a
                    .permission_inventory
                    .as_ref()
                    .unwrap()
                    .permissions
                    .iter()
                    .collect();
                if !present.is_subset(&previous) || present.len() >= previous.len() {
                    continue;
                }
                let references = RemovalReferencesV2 {
                    before_inventory: (bf.bundle_digest().into(), b.id.clone()),
                    after_inventory: (after.bundle_digest().into(), a.id.clone()),
                    prior_allowed: (pf.bundle_digest().into(), p.id.clone()),
                    changed_at: window.changed_at,
                    deadline: window.deadline,
                };
                let Ok(removal) = PermissionRemovalV2::from_approved_change(
                    change,
                    &context.approval,
                    &context.operation,
                    &a.address,
                    references,
                ) else {
                    continue;
                };
                used.insert(bf.bundle_digest().to_owned());
                used.insert(pf.bundle_digest().to_owned());
                removals.push(removal);
                if removals.len() > 8192 {
                    return Err(AdmissionError::Limit);
                }
            }
        }
    }
    // Close the multi-archive read window against current source heads. Never
    // revive a stale historical fact at its original admission time.
    for i in issued {
        if ledger.ensure_current(&i, now).is_err() {
            return Ok(DerivedRemovals {
                removals: vec![],
                before_evidence: vec![],
            });
        }
    }
    Ok(DerivedRemovals {
        removals,
        before_evidence: old
            .into_iter()
            .filter(|f| used.contains(f.bundle_digest()))
            .collect(),
    })
}

#[cfg(test)]
mod tests;
