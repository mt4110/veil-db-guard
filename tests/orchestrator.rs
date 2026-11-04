//! Local injected adapters only. These receipts are not native/cloud evidence.
use std::{cell::Cell, collections::VecDeque, rc::Rc};
use veil_db_guard::{
    adapters::capabilities_for,
    core::{
        approval,
        capability::{Implementation, Support},
        change::{OperationLimits, PreparedChange, prepare_change},
        operation::*,
        orchestrator::{self, Clock, ExecutorError, StepExecutor, UnavailableExecutor},
        plan::{PlanStep, build_plan},
        policy::{PolicyRevision, parse_policy},
        ports::OperationLedger,
    },
    operation_store::OperationStore,
};

fn prepared(policy: &PolicyRevision) -> PreparedChange {
    let mut capabilities = policy
        .targets
        .iter()
        .flat_map(capabilities_for)
        .collect::<Vec<_>>();
    // Test-only registered implementations. Production CLI has no such driver.
    for c in &mut capabilities {
        c.support = Support::Supported;
        c.implementation = Implementation::Implemented;
        c.constraints.clear();
    }
    let plan = build_plan(policy, capabilities, vec![], 100).unwrap();
    prepare_change(policy, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn setup(store: &mut OperationStore, change: &PreparedChange) -> Operation {
    let grant =
        approval::issue(change, "approval-1", "operator", "runner", 900, 1000, 100).unwrap();
    store.register_change(change).unwrap();
    store.register_approval(change, &grant).unwrap();
    store
        .begin(&BeginRequest {
            request_id: "request-1".into(),
            operation_id: "op-1".into(),
            change_hash: change.change_hash.clone(),
            approval_id: grant.id,
            expected_desired_head: None,
            execution_identity: "runner".into(),
            now: 100,
        })
        .unwrap()
}
#[derive(Clone)]
struct TestClock(Rc<Cell<u64>>);
impl Clock for TestClock {
    fn now(&mut self) -> u64 {
        self.0.get()
    }
}
fn receipt(state: StepState) -> StepReceipt {
    StepReceipt {
        state,
        effect: if matches!(state, StepState::EffectSatisfied | StepState::NoOpSatisfied) {
            EffectState::Enforced
        } else {
            EffectState::Unknown
        },
        native_operation_ref: None,
        evidence_refs: vec![],
    }
}
struct LocalDriver {
    submitted: Vec<(String, String)>,
    queried: Vec<String>,
    responses: VecDeque<Result<StepReceipt, ExecutorError>>,
    query_response: StepReceipt,
    panic_submit: bool,
    advance_preflight: Option<(Rc<Cell<u64>>, u64)>,
    advance_submit: Option<(Rc<Cell<u64>>, u64)>,
    advance_query: Option<(Rc<Cell<u64>>, u64)>,
    lease_duration: u64,
}
impl Default for LocalDriver {
    fn default() -> Self {
        Self {
            submitted: vec![],
            queried: vec![],
            responses: VecDeque::new(),
            query_response: receipt(StepState::EffectSatisfied),
            panic_submit: false,
            advance_preflight: None,
            advance_submit: None,
            advance_query: None,
            lease_duration: 30,
        }
    }
}
impl StepExecutor for LocalDriver {
    fn lease_duration_seconds(&self) -> u64 {
        self.lease_duration
    }
    fn identity(&self) -> &str {
        "runner"
    }
    fn available(&self, _: &PreparedChange, _: &PlanStep) -> bool {
        true
    }
    fn preflight(&mut self, _: &PreparedChange, _: &PlanStep) -> Result<(), ExecutorError> {
        if let Some((clock, at)) = &self.advance_preflight {
            clock.set(*at);
        }
        Ok(())
    }
    fn submit(
        &mut self,
        _: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        self.submitted
            .push((step.id.clone(), ticket.idempotency_key.clone()));
        assert!(
            !self.panic_submit,
            "simulated worker crash after durable dispatch"
        );
        if let Some((clock, at)) = &self.advance_submit {
            clock.set(*at);
        }
        self.responses
            .pop_front()
            .unwrap_or_else(|| Ok(receipt(StepState::EffectSatisfied)))
    }
    fn query(
        &mut self,
        _: &PreparedChange,
        step: &PlanStep,
        _: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        self.queried.push(step.id.clone());
        if let Some((clock, at)) = &self.advance_query {
            clock.set(*at);
        }
        Ok(self.query_response.clone())
    }
}
fn sample() -> PreparedChange {
    prepared(&parse_policy(include_str!("../examples/core-policy.yaml")).unwrap())
}

#[test]
fn full_graph_completes_with_bounded_registered_local_driver() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let change = sample();
    let op = setup(&mut store, &change);
    let mut driver = LocalDriver::default();
    let ledger: &mut dyn OperationLedger = &mut store;
    let result = orchestrator::resume_with_clock(
        ledger,
        &op.id,
        op.version,
        "worker-1",
        &mut TestClock(Rc::new(Cell::new(100))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(result.state, ExecutionState::Completed);
    assert_eq!(driver.submitted.len(), change.plan.steps.len());
    assert_eq!(result.attempts as usize, change.plan.steps.len());
}

#[test]
fn crashed_dispatch_is_queried_after_reopen_and_never_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let mut store = OperationStore::open(&path).unwrap();
    let change = sample();
    let op = setup(&mut store, &change);
    let mut crash = LocalDriver {
        panic_submit: true,
        ..Default::default()
    };
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = orchestrator::resume_with_clock(
            &mut store,
            &op.id,
            op.version,
            "old-worker",
            &mut TestClock(Rc::new(Cell::new(100))),
            &mut crash,
        );
    }));
    assert!(panic.is_err());
    assert_eq!(
        store.steps(&op.id).unwrap()[0].state,
        StepState::Dispatching
    );
    drop(store);
    let mut reopened = OperationStore::open_existing(&path).unwrap();
    let op = reopened.get(&op.id).unwrap();
    let mut driver = LocalDriver::default();
    let done = orchestrator::resume_with_clock(
        &mut reopened,
        &op.id,
        op.version,
        "new-worker",
        &mut TestClock(Rc::new(Cell::new(131))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(done.state, ExecutionState::Completed);
    assert_eq!(driver.queried, vec![change.plan.steps[0].id.clone()]);
    assert_eq!(driver.submitted.len(), change.plan.steps.len() - 1);
    assert!(
        driver
            .submitted
            .iter()
            .all(|(id, _)| id != &change.plan.steps[0].id)
    );
}

#[test]
fn unknown_result_waits_and_definitive_not_applied_retry_keeps_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let mut driver = LocalDriver::default();
    driver
        .responses
        .push_back(Err(ExecutorError::OutcomeUnknown));
    let op = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(100))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::NeedsAction);
    let original = driver.submitted[0].clone();
    driver.query_response = receipt(StepState::OutcomeUnknown);
    let op = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(101))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(driver.submitted.len(), 1);
    assert_eq!(op.state, ExecutionState::NeedsAction);
    driver.query_response = receipt(StepState::NotApplied);
    let done = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(102))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(done.state, ExecutionState::Completed);
    assert_eq!(driver.submitted[1], original);
}

#[test]
fn cancelled_approval_does_not_erase_an_accepted_request() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let mut driver = LocalDriver::default();
    driver
        .responses
        .push_back(Ok(receipt(StepState::Submitted)));
    let op = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(100))),
        &mut driver,
    )
    .unwrap();
    store.cancel_approval("approval-1", 101).unwrap();
    let op = store
        .set_state(&op.id, op.version, ExecutionState::Cancelled, 101)
        .unwrap();
    let done = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(1100))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(done.state, ExecutionState::Cancelled);
    assert_eq!(driver.queried.len(), 1);
    assert_eq!(driver.submitted.len(), 1);
    assert_eq!(
        store.steps(&op.id).unwrap()[0].state,
        StepState::EffectSatisfied
    );
}

#[test]
fn approval_expiring_during_preflight_blocks_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let time = Rc::new(Cell::new(100));
    let mut driver = LocalDriver {
        advance_preflight: Some((time.clone(), 901)),
        ..Default::default()
    };
    assert_eq!(
        orchestrator::resume_with_clock(
            &mut store,
            &op.id,
            op.version,
            "worker",
            &mut TestClock(time),
            &mut driver
        )
        .unwrap_err(),
        StoreError::Approval
    );
    assert!(driver.submitted.is_empty());
    assert_eq!(store.get(&op.id).unwrap().attempts, 0);
}

#[test]
fn expired_worker_cannot_commit_receipt_after_slow_submit() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let time = Rc::new(Cell::new(100));
    let mut driver = LocalDriver {
        advance_submit: Some((time.clone(), 131)),
        ..Default::default()
    };
    assert_eq!(
        orchestrator::resume_with_clock(
            &mut store,
            &op.id,
            op.version,
            "worker",
            &mut TestClock(time),
            &mut driver
        )
        .unwrap_err(),
        StoreError::Stale
    );
    assert_eq!(
        store.steps(&op.id).unwrap()[0].state,
        StepState::Dispatching
    );
}

#[test]
fn production_default_cannot_turn_local_approval_into_native_success() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let mut driver = UnavailableExecutor {
        execution_identity: "runner".into(),
    };
    let done = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(100))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(done.state, ExecutionState::NeedsAction);
    assert_eq!(done.attempts, 0);
}

/// A deliberately narrow ledger adapter: it can reconcile an already accepted
/// step after cancellation, but any new dispatch is a test failure. It exercises
/// the kernel through the inner port without constructing a SQLite store.
struct ReconciliationLedger {
    operation: Operation,
    change: PreparedChange,
    record: StepRecord,
    resolve_error: Option<StoreError>,
    release_error: Option<StoreError>,
    released: bool,
    renewals: usize,
}
impl ReconciliationLedger {
    fn new() -> Self {
        let change = sample();
        Self {
            operation: Operation {
                id: "op-port".into(),
                request_id: "request-port".into(),
                input_hash: "local-test-input".into(),
                change_hash: change.change_hash.clone(),
                approval_id: "revoked-approval".into(),
                policy_id: change.policy.policy_id.clone(),
                policy_revision_hash: "local-test-revision".into(),
                execution_identity: "runner".into(),
                version: 3,
                state: ExecutionState::Cancelled,
                attempts: 1,
                created_at: 100,
                updated_at: 100,
            },
            record: StepRecord {
                step_id: change.plan.steps[0].id.clone(),
                state: StepState::Dispatching,
                attempt: 1,
                idempotency_key: "stable-key".into(),
                receipt: None,
            },
            change,
            resolve_error: None,
            release_error: None,
            released: false,
            renewals: 0,
        }
    }
}
impl OperationLedger for ReconciliationLedger {
    fn get(&self, id: &str) -> Result<Operation, StoreError> {
        assert_eq!(id, self.operation.id);
        Ok(self.operation.clone())
    }
    fn load_change(&self, hash: &str) -> Result<PreparedChange, StoreError> {
        assert_eq!(hash, self.change.change_hash);
        Ok(self.change.clone())
    }
    fn steps(&self, id: &str) -> Result<Vec<StepRecord>, StoreError> {
        assert_eq!(id, self.operation.id);
        Ok(vec![self.record.clone()])
    }
    fn acquire_leases(
        &mut self,
        id: &str,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError> {
        assert_eq!(id, self.operation.id);
        Ok(LeaseSet {
            holder: holder.into(),
            token: 8,
            keys: vec!["local-resource".into()],
            expires_at: now + ttl,
        })
    }
    fn renew_leases(
        &mut self,
        lease: &LeaseSet,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError> {
        assert_eq!(lease.token, 8);
        assert!(now < lease.expires_at);
        self.renewals += 1;
        Ok(LeaseSet {
            expires_at: now + ttl,
            ..lease.clone()
        })
    }
    fn release_leases(&mut self, lease: &LeaseSet) -> Result<(), StoreError> {
        assert_eq!(lease.token, 8);
        self.released = true;
        self.release_error.map_or(Ok(()), Err)
    }
    fn dispatch(
        &mut self,
        _: &str,
        _: &str,
        _: u64,
        _: &LeaseSet,
        _: &str,
        _: u64,
    ) -> Result<DispatchTicket, StoreError> {
        panic!("accepted step must be queried, never replayed")
    }
    fn record_receipt(
        &mut self,
        _: &DispatchTicket,
        _: &StepReceipt,
        _: u64,
    ) -> Result<Operation, StoreError> {
        panic!("reconciliation must use fenced resolve")
    }
    fn resolve(
        &mut self,
        id: &str,
        step: &str,
        expected: u64,
        lease: &LeaseSet,
        receipt: &StepReceipt,
        identity: &str,
        now: u64,
    ) -> Result<Operation, StoreError> {
        assert_eq!(id, self.operation.id);
        assert_eq!(step, self.record.step_id);
        assert_eq!(expected, self.operation.version);
        assert_eq!(lease.token, 8);
        assert_eq!(identity, "runner");
        if let Some(error) = self.resolve_error {
            return Err(error);
        }
        self.record.state = receipt.state;
        self.record.receipt = Some(receipt.clone());
        self.operation.version += 1;
        self.operation.updated_at = now;
        Ok(self.operation.clone())
    }
    fn set_state(
        &mut self,
        _: &str,
        _: u64,
        _: ExecutionState,
        _: u64,
    ) -> Result<Operation, StoreError> {
        panic!("reconciliation must preserve cancellation")
    }
}

#[test]
fn independent_ledger_port_reconciles_cancelled_operation_without_replay() {
    let mut ledger = ReconciliationLedger::new();
    let mut driver = LocalDriver::default();
    let result = orchestrator::resume_with_clock(
        &mut ledger as &mut dyn OperationLedger,
        "op-port",
        3,
        "worker",
        &mut TestClock(Rc::new(Cell::new(101))),
        &mut driver,
    )
    .unwrap();
    assert_eq!(result.state, ExecutionState::Cancelled);
    assert_eq!(result.version, 4);
    assert_eq!(ledger.record.state, StepState::EffectSatisfied);
    assert!(ledger.released);
    assert_eq!(ledger.renewals, 1);
    assert_eq!(driver.queried, vec![ledger.record.step_id]);
    assert!(driver.submitted.is_empty());
}

#[test]
fn independent_ledger_port_releases_on_fenced_resolve_failure_and_preserves_error() {
    let mut ledger = ReconciliationLedger::new();
    ledger.resolve_error = Some(StoreError::Stale);
    ledger.release_error = Some(StoreError::Storage);
    let result = orchestrator::resume_with_clock(
        &mut ledger as &mut dyn OperationLedger,
        "op-port",
        3,
        "worker",
        &mut TestClock(Rc::new(Cell::new(101))),
        &mut LocalDriver::default(),
    );
    assert_eq!(result.unwrap_err(), StoreError::Stale);
    assert_eq!(ledger.record.state, StepState::Dispatching);
    assert!(ledger.released);
}

#[test]
fn bounded_extended_lease_allows_a_native_call_longer_than_default() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let change = sample();
    let op = setup(&mut store, &change);
    let time = Rc::new(Cell::new(100));
    let mut driver = LocalDriver {
        lease_duration: 300,
        advance_submit: Some((time.clone(), 260)),
        ..Default::default()
    };
    let result = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(time),
        &mut driver,
    )
    .unwrap();
    assert_eq!(result.state, ExecutionState::Completed);
    assert_eq!(result.attempts as usize, change.plan.steps.len());
}

#[test]
fn lease_duration_outside_ledger_bounds_is_rejected_before_dispatch() {
    for duration in [0, 3601] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
        let op = setup(&mut store, &sample());
        let mut driver = LocalDriver {
            lease_duration: duration,
            ..Default::default()
        };
        let result = orchestrator::resume_with_clock(
            &mut store,
            &op.id,
            op.version,
            "worker",
            &mut TestClock(Rc::new(Cell::new(100))),
            &mut driver,
        );
        assert_eq!(result.unwrap_err(), StoreError::Invalid);
        assert!(driver.submitted.is_empty());
        assert_eq!(store.get(&op.id).unwrap(), op);
    }
}

struct SequenceClock(VecDeque<u64>);
impl Clock for SequenceClock {
    fn now(&mut self) -> u64 {
        self.0.pop_front().expect("unexpected clock read")
    }
}

#[test]
fn reconciliation_refreshes_lease_before_query_and_preserves_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let mut driver = LocalDriver::default();
    driver
        .responses
        .push_back(Ok(receipt(StepState::Submitted)));
    let op = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(100))),
        &mut driver,
    )
    .unwrap();
    let op = store
        .set_state(&op.id, op.version, ExecutionState::Cancelled, 100)
        .unwrap();
    // Initial lease expires at 130. Refresh immediately before query extends it
    // to 150, allowing the receipt at 131 without weakening any fence check.
    let mut clock = SequenceClock(VecDeque::from([100, 120, 131]));
    let result = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut clock,
        &mut driver,
    )
    .unwrap();
    assert_eq!(result.state, ExecutionState::Cancelled);
    assert_eq!(
        store.steps(&op.id).unwrap()[0].state,
        StepState::EffectSatisfied
    );
    assert_eq!(driver.submitted.len(), 1);
    assert!(clock.0.is_empty());
}

#[test]
fn query_exceeding_refreshed_lease_cannot_commit_or_trigger_replay() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.db")).unwrap();
    let op = setup(&mut store, &sample());
    let mut driver = LocalDriver::default();
    driver
        .responses
        .push_back(Err(ExecutorError::OutcomeUnknown));
    let op = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(Rc::new(Cell::new(100))),
        &mut driver,
    )
    .unwrap();
    let time = Rc::new(Cell::new(101));
    driver.advance_query = Some((time.clone(), 132));
    let result = orchestrator::resume_with_clock(
        &mut store,
        &op.id,
        op.version,
        "worker",
        &mut TestClock(time),
        &mut driver,
    );
    assert_eq!(result.unwrap_err(), StoreError::Stale);
    assert_eq!(
        store.steps(&op.id).unwrap()[0].state,
        StepState::OutcomeUnknown
    );
    assert_eq!(driver.submitted.len(), 1);
    assert_eq!(driver.queried.len(), 1);
}
