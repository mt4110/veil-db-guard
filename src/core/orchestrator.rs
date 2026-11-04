//! Durable dispatch/resume kernel. Native implementations are supplied by K05.
use super::{
    change::PreparedChange,
    operation::{
        DispatchTicket, EffectState, ExecutionState, Operation, StepReceipt, StepRecord, StepState,
        StoreError,
    },
    plan::PlanStep,
    ports::OperationLedger,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorError {
    Unavailable,
    PreconditionsNotMet,
    OutcomeUnknown,
    NotApplied,
}

/// Trusted adapter code, not an interface for deserializing user-supplied
/// receipts. A preflight must revalidate native identity/configuration and all
/// step preconditions. Operator handoff declarations alone are not SQL effects.
pub trait StepExecutor {
    /// Lease budget for one query or one preflight/submit sequence, including
    /// adapter overhead. Adapters must bound that work below this duration. The
    /// ledger still rejects a late receipt; a longer lease never authorizes a
    /// stale worker to commit.
    fn lease_duration_seconds(&self) -> u64 {
        30
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn identity(&self) -> &str;
    fn available(&self, change: &PreparedChange, step: &PlanStep) -> bool;
    fn preflight(&mut self, change: &PreparedChange, step: &PlanStep) -> Result<(), ExecutorError>;
    fn submit(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError>;
    /// The compensation adapter calls the ledger check immediately before its
    /// conditional native write, after its final provider reads.
    fn submit_with_dispatch_check(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
        _check: &mut dyn FnMut() -> Result<(), ExecutorError>,
    ) -> Result<StepReceipt, ExecutorError> {
        if step.action == super::capability::ActionKind::CompensateOwnedIam {
            return Err(ExecutorError::NotApplied);
        }
        self.submit(change, step, ticket)
    }
    /// A typed ownership record from the immediately preceding successful submit.
    fn take_gcp_iam_owned_delta(&mut self) -> Option<super::owned_iam::OwnedIamDeltaReceipt> {
        None
    }
    fn query(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        record: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError>;
}

pub trait Clock {
    fn now(&mut self) -> u64;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// CLI production default until a reviewed native executor is installed.
/// It cannot dispatch, acknowledge a handoff or invent a successful receipt.
pub struct UnavailableExecutor {
    pub execution_identity: String,
}
impl StepExecutor for UnavailableExecutor {
    fn identity(&self) -> &str {
        &self.execution_identity
    }
    fn available(&self, _: &PreparedChange, _: &PlanStep) -> bool {
        false
    }
    fn preflight(&mut self, _: &PreparedChange, _: &PlanStep) -> Result<(), ExecutorError> {
        Err(ExecutorError::Unavailable)
    }
    fn submit(
        &mut self,
        _: &PreparedChange,
        _: &PlanStep,
        _: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        Err(ExecutorError::Unavailable)
    }
    fn query(
        &mut self,
        _: &PreparedChange,
        _: &PlanStep,
        _: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        Err(ExecutorError::Unavailable)
    }
}

fn unresolved(state: StepState) -> bool {
    matches!(
        state,
        StepState::Dispatching
            | StepState::Submitted
            | StepState::ConfigApplied
            | StepState::OutcomeUnknown
    )
}
fn satisfied(state: StepState) -> bool {
    matches!(state, StepState::EffectSatisfied | StepState::NoOpSatisfied)
}
fn unknown_receipt() -> StepReceipt {
    StepReceipt {
        state: StepState::OutcomeUnknown,
        effect: EffectState::Unknown,
        native_operation_ref: None,
        evidence_refs: vec![],
    }
}

/// Takes one bounded pass over the graph. Every provider call occurs outside
/// ledger transactions; every dispatch first receives a durable ticket. A crash
/// after dispatch is therefore queried on the next invocation, never replayed.
pub fn resume(
    store: &mut (impl OperationLedger + ?Sized),
    operation_id: &str,
    expected_version: u64,
    holder: &str,
    executor: &mut impl StepExecutor,
) -> Result<Operation, StoreError> {
    resume_with_clock(
        store,
        operation_id,
        expected_version,
        holder,
        &mut SystemClock,
        executor,
    )
}

pub fn resume_with_clock(
    store: &mut (impl OperationLedger + ?Sized),
    operation_id: &str,
    expected_version: u64,
    holder: &str,
    clock: &mut impl Clock,
    executor: &mut impl StepExecutor,
) -> Result<Operation, StoreError> {
    let mut operation = store.get(operation_id)?;
    if operation.version != expected_version {
        return Err(StoreError::Stale);
    }
    if operation.execution_identity != executor.identity() {
        return Err(StoreError::Approval);
    }
    let change = store.load_change(&operation.change_hash)?;
    change.verify().map_err(|_| StoreError::Invalid)?;
    let compensation = change
        .lifecycle
        .as_ref()
        .is_some_and(|context| context.kind == super::lifecycle::LifecycleKind::CompensateOwnedIam);
    let stopped = matches!(
        operation.state,
        ExecutionState::Cancelled | ExecutionState::FailedPartial | ExecutionState::Recovering
    );
    if operation.state == ExecutionState::Completed {
        return Ok(operation);
    }
    let lease_duration = executor.lease_duration_seconds();
    if !(1..=3600).contains(&lease_duration) {
        return Err(StoreError::Invalid);
    }
    let mut leases = store.acquire_leases(operation_id, holder, clock.now(), lease_duration)?;
    let result = (|| {
        // The pass starts with reconciliation regardless of the forward grant's
        // current validity. A revoked grant does not erase an accepted request.
        for record in store.steps(operation_id)? {
            if !unresolved(record.state) {
                continue;
            }
            let step = change
                .plan
                .steps
                .iter()
                .find(|s| s.id == record.step_id)
                .ok_or(StoreError::Invalid)?;
            leases = store.renew_leases(&leases, clock.now(), lease_duration)?;
            let receipt = match executor.query(&change, step, &record) {
                Ok(receipt) => receipt,
                Err(_) if compensation && record.state == StepState::ConfigApplied => continue,
                Err(_) => {
                    let mut receipt = unknown_receipt();
                    receipt.native_operation_ref = record
                        .receipt
                        .as_ref()
                        .and_then(|r| r.native_operation_ref.clone());
                    receipt.evidence_refs = record
                        .receipt
                        .as_ref()
                        .map(|r| r.evidence_refs.clone())
                        .unwrap_or_default();
                    receipt
                }
            };
            operation = store.resolve(
                operation_id,
                &record.step_id,
                operation.version,
                &leases,
                &receipt,
                executor.identity(),
                clock.now(),
            )?;
        }
        if stopped {
            return Ok(operation);
        }
        if compensation
            && store
                .steps(operation_id)?
                .iter()
                .all(|r| r.state == StepState::Compensated)
        {
            return store.set_state(
                operation_id,
                operation.version,
                ExecutionState::Completed,
                clock.now(),
            );
        }
        if clock.now().saturating_sub(operation.created_at) >= change.limits.max_operation_seconds
            && store
                .steps(operation_id)?
                .iter()
                .any(|r| !satisfied(r.state))
        {
            return store.set_state(
                operation_id,
                operation.version,
                ExecutionState::FailedPartial,
                clock.now(),
            );
        }
        if !compensation && !change.plan.required_effect_gaps.is_empty() {
            return store.set_state(
                operation_id,
                operation.version,
                ExecutionState::NeedsAction,
                clock.now(),
            );
        }
        let records = store.steps(operation_id)?;
        if records.iter().any(|r| unresolved(r.state)) {
            let state = if records
                .iter()
                .any(|r| r.state == StepState::OutcomeUnknown || r.state == StepState::Dispatching)
            {
                ExecutionState::NeedsAction
            } else if records.iter().any(|r| r.state == StepState::Submitted) {
                ExecutionState::WaitingProvider
            } else {
                ExecutionState::WaitingEffect
            };
            return store.set_state(operation_id, operation.version, state, clock.now());
        }
        if records.iter().any(|r| {
            matches!(
                r.state,
                StepState::Failed | StepState::Compensating | StepState::Compensated
            )
        }) {
            return store.set_state(
                operation_id,
                operation.version,
                ExecutionState::FailedPartial,
                clock.now(),
            );
        }
        // A dependency may appear later in serialized graph order. Iterate a
        // bounded number of passes rather than implicitly requiring array order.
        for _ in 0..=change.plan.steps.len() {
            let mut progressed = false;
            for step in &change.plan.steps {
                let records = store.steps(operation_id)?;
                let record = records
                    .iter()
                    .find(|r| r.step_id == step.id)
                    .ok_or(StoreError::Invalid)?;
                if satisfied(record.state) {
                    continue;
                }
                if !matches!(record.state, StepState::Prepared | StepState::NotApplied)
                    || step.dependencies.iter().any(|id| {
                        !records
                            .iter()
                            .any(|r| &r.step_id == id && satisfied(r.state))
                    })
                {
                    continue;
                }
                if executor.cancelled() {
                    return store.set_state(
                        operation_id,
                        operation.version,
                        ExecutionState::Cancelled,
                        clock.now(),
                    );
                }
                leases = store.renew_leases(&leases, clock.now(), lease_duration)?;
                let capability_ready = change.plan.capabilities.iter().any(|capability| {
                    capability.target_id.as_deref() == Some(step.target_id.as_str())
                        && capability.action == step.action
                        && capability.has_implementation()
                });
                if !capability_ready
                    || !executor.available(&change, step)
                    || executor.preflight(&change, step).is_err()
                {
                    return store.set_state(
                        operation_id,
                        operation.version,
                        ExecutionState::NeedsAction,
                        clock.now(),
                    );
                }
                if executor.cancelled() {
                    return store.set_state(
                        operation_id,
                        operation.version,
                        ExecutionState::Cancelled,
                        clock.now(),
                    );
                }
                let ticket = store.dispatch(
                    operation_id,
                    &step.id,
                    operation.version,
                    &leases,
                    executor.identity(),
                    clock.now(),
                )?;
                let submitted = if compensation {
                    let identity = executor.identity().to_owned();
                    executor.submit_with_dispatch_check(&change, step, &ticket, &mut || {
                        store
                            .validate_owned_iam_dispatch(&ticket, &identity, clock.now())
                            .map_err(|_| ExecutorError::NotApplied)
                    })
                } else {
                    executor.submit(&change, step, &ticket)
                };
                let successful_submit = submitted.is_ok();
                let owned_delta = executor.take_gcp_iam_owned_delta();
                let receipt = match submitted {
                    Ok(receipt) => receipt,
                    Err(ExecutorError::NotApplied) => StepReceipt {
                        state: StepState::NotApplied,
                        effect: EffectState::Unknown,
                        native_operation_ref: None,
                        evidence_refs: vec![],
                    },
                    Err(_) => unknown_receipt(),
                };
                operation = match owned_delta {
                    Some(delta) if successful_submit => {
                        store.record_owned_iam_receipt(&ticket, &receipt, &delta, clock.now())?
                    }
                    _ => store.record_receipt(&ticket, &receipt, clock.now())?,
                };
                progressed = true;
                if !satisfied(receipt.state) {
                    let state = match receipt.state {
                        StepState::Submitted => ExecutionState::WaitingProvider,
                        StepState::ConfigApplied => ExecutionState::WaitingEffect,
                        StepState::Failed => ExecutionState::FailedPartial,
                        _ => ExecutionState::NeedsAction,
                    };
                    return store.set_state(operation_id, operation.version, state, clock.now());
                }
            }
            if !progressed {
                break;
            }
        }
        if store
            .steps(operation_id)?
            .iter()
            .all(|r| satisfied(r.state))
        {
            store.set_state(
                operation_id,
                operation.version,
                ExecutionState::Completed,
                clock.now(),
            )
        } else {
            store.set_state(
                operation_id,
                operation.version,
                ExecutionState::NeedsAction,
                clock.now(),
            )
        }
    })();
    // Preserve the original failure; releasing a local lease cannot undo a
    // dispatched remote operation. An expired lease is safe to reclaim later.
    let released = store.release_leases(&leases);
    match (result, released) {
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Ok(op), Ok(())) => Ok(op),
    }
}
