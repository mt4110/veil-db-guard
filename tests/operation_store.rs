use std::path::Path;
use veil_db_guard::{
    adapters::capabilities_for,
    core::{
        approval::{ApprovalGrant, issue},
        capability::ActionKind,
        change::{OperationLimits, PreparedChange, prepare_change},
        lifecycle::prepare_owned_iam_compensation,
        operation::*,
        owned_iam::{OwnedIamBinding, OwnedIamDeltaReceipt},
        plan::build_plan,
        policy::parse_policy,
    },
    operation_store::OperationStore,
};

fn change() -> PreparedChange {
    let policy = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    let plan = build_plan(
        &policy,
        policy.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn setup(path: &Path) -> (OperationStore, PreparedChange, ApprovalGrant, Operation) {
    let mut store = OperationStore::open(path).unwrap();
    let change = change();
    let approval = issue(&change, "approval-1", "operator", "runner", 1000, 2000, 100).unwrap();
    store.register_change(&change).unwrap();
    store.register_approval(&change, &approval).unwrap();
    let op = store
        .begin(&request(&change, "request-1", "operation-1", None, 101))
        .unwrap();
    (store, change, approval, op)
}
fn request(
    change: &PreparedChange,
    request: &str,
    operation: &str,
    head: Option<String>,
    now: u64,
) -> BeginRequest {
    BeginRequest {
        request_id: request.into(),
        operation_id: operation.into(),
        change_hash: change.change_hash.clone(),
        approval_id: "approval-1".into(),
        expected_desired_head: head,
        execution_identity: "runner".into(),
        now,
    }
}
fn effect() -> StepReceipt {
    StepReceipt {
        state: StepState::EffectSatisfied,
        effect: EffectState::Enforced,
        native_operation_ref: None,
        evidence_refs: vec![],
    }
}
fn unknown() -> StepReceipt {
    StepReceipt {
        state: StepState::OutcomeUnknown,
        effect: EffectState::Unknown,
        native_operation_ref: None,
        evidence_refs: vec![],
    }
}

fn owned_iam_attempt(
    path: &Path,
) -> (
    OperationStore,
    PreparedChange,
    DispatchTicket,
    OwnedIamDeltaReceipt,
) {
    let mut store = OperationStore::open(path).unwrap();
    let mut policy = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
    policy.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    for (index, subject) in policy.subjects.iter_mut().enumerate() {
        subject.identity.immutable_id = Some(format!("10000000000000000000{index}"));
    }
    let plan = build_plan(
        &policy,
        veil_db_guard::adapters::capabilities_for_policy(&policy).unwrap(),
        vec![],
        100,
    )
    .unwrap();
    let change = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
    let approval = issue(&change, "approval-1", "operator", "runner", 1000, 2000, 100).unwrap();
    store.register_change(&change).unwrap();
    store.register_approval(&change, &approval).unwrap();
    let mut operation = store
        .begin(&request(&change, "request-1", "operation-1", None, 101))
        .unwrap();
    let leases = store
        .acquire_leases(&operation.id, "worker", 102, 30)
        .unwrap();
    let mut ticket = None;
    for step in &change.plan.steps {
        let attempt = store
            .dispatch(
                &operation.id,
                &step.id,
                operation.version,
                &leases,
                "runner",
                103,
            )
            .unwrap();
        if step.action == ActionKind::ConfigureIdentity {
            ticket = Some(attempt);
            break;
        }
        operation = store.record_receipt(&attempt, &effect(), 103).unwrap();
    }
    let ticket = ticket.unwrap();
    let target = &policy.targets[0];
    let grant = &policy.grants[0];
    let subject = &policy.subjects[0];
    let owned = OwnedIamDeltaReceipt {
        source_operation_id: operation.id,
        source_change_hash: change.change_hash.clone(),
        source_policy_revision_hash: change.plan.policy_revision_hash.clone(),
        source_step_id: ticket.step_id.clone(),
        attempt: ticket.attempt,
        idempotency_key: ticket.idempotency_key.clone(),
        execution_identity: "runner".into(),
        step_receipt_hash: OwnedIamDeltaReceipt::step_receipt_hash(&effect()),
        project_id: target.placement.account_id.clone(),
        project_number: "123456789012".into(),
        native_resource_id: target.resource.native_id.clone(),
        registration_id: target.registration_id.clone(),
        generation_fingerprint: target.resource.generation_fingerprint.clone().unwrap(),
        engine_version: target.engine.version.clone(),
        grant_id: grant.id.clone(),
        service_account_email: subject.identity.principal.clone(),
        service_account_unique_id: subject.identity.immutable_id.clone().unwrap(),
        db_login: grant.db_identity.clone(),
        before_etag: "before".into(),
        before_digest: "b".repeat(64),
        before_read_at: 103,
        after_etag: "after".into(),
        after_digest: "c".repeat(64),
        after_read_at: 104,
        bindings: OwnedIamBinding::for_grant(&policy.policy_id, target, grant, subject),
    };
    (store, change, ticket, owned)
}

fn owned_iam_source(
    path: &Path,
) -> (
    OperationStore,
    PreparedChange,
    Operation,
    OwnedIamDeltaReceipt,
) {
    let (mut store, change, ticket, owned) = owned_iam_attempt(path);
    let operation = store
        .record_owned_iam_receipt(&ticket, &effect(), &owned, 104)
        .unwrap();
    let operation = store
        .set_state(
            &operation.id,
            operation.version,
            ExecutionState::Cancelled,
            105,
        )
        .unwrap();
    store.cancel_approval(&operation.approval_id, 106).unwrap();
    store.release_leases(&ticket.leases).unwrap();
    (store, change, operation, owned)
}

#[test]
fn ownership_receipt_requires_exact_attempt_and_rolls_back_with_step_result() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, _, ticket, owned) = owned_iam_attempt(&dir.path().join("ledger.sqlite"));
    let events = store.events(&ticket.operation_id).unwrap();
    let steps = store.steps(&ticket.operation_id).unwrap();
    let mut wrong_attempt = owned.clone();
    wrong_attempt.attempt += 1;
    assert_eq!(
        store.record_owned_iam_receipt(&ticket, &effect(), &wrong_attempt, 104),
        Err(StoreError::Invalid)
    );
    let no_op = StepReceipt {
        state: StepState::NoOpSatisfied,
        ..effect()
    };
    let mut alleged_no_op = owned.clone();
    alleged_no_op.step_receipt_hash = OwnedIamDeltaReceipt::step_receipt_hash(&no_op);
    assert_eq!(
        store.record_owned_iam_receipt(&ticket, &no_op, &alleged_no_op, 104),
        Err(StoreError::Invalid)
    );
    assert_eq!(store.events(&ticket.operation_id).unwrap(), events);
    assert_eq!(store.steps(&ticket.operation_id).unwrap(), steps);
    assert_eq!(
        store.get(&ticket.operation_id).unwrap().version,
        ticket.operation_version
    );
    let operation = store.record_receipt(&ticket, &effect(), 104).unwrap();
    let operation = store
        .set_state(
            &operation.id,
            operation.version,
            ExecutionState::Cancelled,
            105,
        )
        .unwrap();
    store.cancel_approval(&operation.approval_id, 106).unwrap();
    assert_eq!(
        store.owned_iam_compensation_source(&operation.id, &owned.grant_id),
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store.record_owned_iam_receipt(&ticket, &effect(), &owned, 107),
        Err(StoreError::Stale)
    );
}

#[test]
fn cancelled_source_still_requires_revocation_and_resolution_of_pending_write() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, _, ticket, owned) = owned_iam_attempt(&dir.path().join("ledger.sqlite"));
    let operation = store
        .set_state(
            &ticket.operation_id,
            ticket.operation_version,
            ExecutionState::Cancelled,
            105,
        )
        .unwrap();
    assert_eq!(
        store.owned_iam_compensation_source(&operation.id, &owned.grant_id),
        Err(StoreError::Approval)
    );
    store.cancel_approval(&operation.approval_id, 106).unwrap();
    assert_eq!(
        store.owned_iam_compensation_source(&operation.id, &owned.grant_id),
        Err(StoreError::Unresolved)
    );
}

fn competing_begin(store: &mut OperationStore, source: &PreparedChange) -> BeginRequest {
    let mut competing = source.policy.clone();
    competing.policy_id = "different-policy".into();
    let plan = build_plan(
        &competing,
        veil_db_guard::adapters::capabilities_for_policy(&competing).unwrap(),
        vec![],
        110,
    )
    .unwrap();
    let change = prepare_change(&competing, &plan, &[], None, OperationLimits::default()).unwrap();
    let approval = issue(
        &change,
        "peer-approval",
        "operator",
        "runner",
        1000,
        2000,
        110,
    )
    .unwrap();
    store.register_change(&change).unwrap();
    store.register_approval(&change, &approval).unwrap();
    let mut peer = request(&change, "peer-request", "peer-operation", None, 111);
    peer.approval_id = approval.id;
    peer
}

#[test]
fn compensation_source_checks_other_desired_policies_for_same_native_iam_use() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, source, operation, owned) = owned_iam_source(&dir.path().join("ledger.sqlite"));
    let peer = competing_begin(&mut store, &source);
    store.begin(&peer).unwrap();
    assert_eq!(
        store.owned_iam_compensation_source(&operation.id, &owned.grant_id),
        Err(StoreError::Conflict)
    );
}

#[test]
fn compensation_reserves_owned_receipt_and_checks_head_in_begin_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let (mut store, source, operation, owned) = owned_iam_source(&path);
    let mut other = OperationStore::open_existing(&path).unwrap();
    assert_eq!(
        other
            .owned_iam_compensation_source(&operation.id, &owned.grant_id)
            .unwrap(),
        owned
    );
    let limits = OperationLimits {
        max_repair_executions: 0,
        ..source.limits.clone()
    };
    let mut invented = owned.clone();
    invented.after_etag = "invented".into();
    let invented_change =
        prepare_owned_iam_compensation(&source, &invented, &owned.grant_id, 110, limits.clone())
            .unwrap();
    assert_eq!(
        store.register_change(&invented_change),
        Err(StoreError::Conflict)
    );
    let compensation =
        prepare_owned_iam_compensation(&source, &owned, &owned.grant_id, 110, limits).unwrap();
    let approval = issue(
        &compensation,
        "comp-approval",
        "operator",
        "runner",
        1000,
        2000,
        110,
    )
    .unwrap();
    store.register_change(&compensation).unwrap();
    store.register_approval(&compensation, &approval).unwrap();
    let mut begin = request(&compensation, "comp-request", "comp-operation", None, 111);
    begin.approval_id = approval.id;
    assert_eq!(other.begin(&begin), Err(StoreError::Conflict));
    assert_eq!(other.get(&begin.operation_id), Err(StoreError::NotFound));
    begin.expected_desired_head = Some(source.plan.policy_revision_hash.clone());
    let gate = std::sync::Barrier::new(2);
    let result = std::thread::scope(|scope| {
        // Open the competing connection inside its worker. Both transactions
        // observe one request identity and can commit at most one operation.
        let peer = scope.spawn(|| {
            let peer = OperationStore::open_existing(&path);
            gate.wait();
            peer.unwrap().begin(&begin)
        });
        gate.wait();
        let result = store.begin(&begin).unwrap();
        assert_eq!(peer.join().unwrap().unwrap(), result);
        result
    });
    begin.now += 1;
    assert_eq!(other.begin(&begin).unwrap(), result);
    begin.request_id = "comp-request-other".into();
    begin.operation_id = "comp-operation-other".into();
    begin.expected_desired_head = Some(compensation.plan.policy_revision_hash.clone());
    assert_eq!(other.begin(&begin), Err(StoreError::Conflict));
    assert_eq!(store.get(&operation.id).unwrap(), operation);
    assert_eq!(
        store.owned_iam_compensation_source(&operation.id, &owned.grant_id),
        Err(StoreError::Conflict)
    );

    let leases = store.acquire_leases(&result.id, "worker", 113, 30).unwrap();
    let ticket = store
        .dispatch(
            &result.id,
            &compensation.plan.steps[0].id,
            result.version,
            &leases,
            "runner",
            114,
        )
        .unwrap();
    assert_eq!(
        store.validate_owned_iam_dispatch(&ticket, "runner", 115),
        Ok(())
    );
    let mut competing = competing_begin(&mut other, &source);
    competing.now = 115;
    assert_eq!(other.begin(&competing), Err(StoreError::Lease));
    assert_eq!(
        store.validate_owned_iam_dispatch(&ticket, "wrong-runner", 115),
        Err(StoreError::Approval)
    );
    assert_eq!(
        store.validate_owned_iam_dispatch(&ticket, "runner", leases.expires_at),
        Err(StoreError::Stale)
    );
    let mut forged_ticket = ticket.clone();
    forged_ticket.leases.expires_at += 1;
    assert_eq!(
        store.validate_owned_iam_dispatch(&forged_ticket, "runner", 115),
        Err(StoreError::Stale)
    );
    let compensated = StepReceipt {
        state: StepState::Compensated,
        ..unknown()
    };
    let not_applied = StepReceipt {
        state: StepState::NotApplied,
        ..unknown()
    };
    for receipt in [&compensated, &not_applied] {
        assert_eq!(
            store.resolve(
                &result.id,
                &ticket.step_id,
                ticket.operation_version,
                &leases,
                receipt,
                "runner",
                116
            ),
            Err(StoreError::Transition)
        );
    }
    let accepted = StepReceipt {
        state: StepState::ConfigApplied,
        native_operation_ref: Some("iam-acceptance".into()),
        ..unknown()
    };
    let waiting = store.record_receipt(&ticket, &accepted, 117).unwrap();
    let failed = StepReceipt {
        state: StepState::Failed,
        ..unknown()
    };
    assert_eq!(
        store.resolve(
            &result.id,
            &ticket.step_id,
            waiting.version,
            &leases,
            &failed,
            "runner",
            118
        ),
        Err(StoreError::Transition)
    );
    assert_eq!(
        store
            .resolve(
                &result.id,
                &ticket.step_id,
                waiting.version,
                &leases,
                &unknown(),
                "runner",
                118
            )
            .unwrap(),
        waiting
    );
    assert_eq!(
        store.steps(&result.id).unwrap()[0].receipt.as_ref(),
        Some(&accepted)
    );
    let observed = store
        .resolve(
            &result.id,
            &ticket.step_id,
            waiting.version,
            &leases,
            &compensated,
            "runner",
            119,
        )
        .unwrap();
    let done = store
        .set_state(&result.id, observed.version, ExecutionState::Completed, 120)
        .unwrap();
    assert_eq!(done.state, ExecutionState::Completed);
    assert_eq!(
        store.steps(&result.id).unwrap()[0]
            .receipt
            .as_ref()
            .unwrap()
            .effect,
        EffectState::Unknown
    );
    assert!(!compensation.plan.required_effect_gaps.is_empty());
}

#[test]
fn request_idempotency_and_desired_head_cas_are_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, change, _, op) = setup(&dir.path().join("ledger.sqlite"));
    let repeated = store
        .begin(&request(&change, "request-1", "operation-1", None, 120))
        .unwrap();
    assert_eq!(repeated.id, op.id);
    assert_eq!(store.events(&op.id).unwrap().len(), 1);
    let altered = request(&change, "request-1", "different-operation", None, 120);
    assert_eq!(store.begin(&altered).unwrap_err(), StoreError::Conflict);
    let stale = request(&change, "request-2", "operation-2", None, 120);
    assert_eq!(store.begin(&stale).unwrap_err(), StoreError::Conflict);
    assert_eq!(store.get("operation-2").unwrap_err(), StoreError::NotFound);
    assert_eq!(
        store.desired_head(&change.policy.policy_id).unwrap(),
        Some(change.plan.policy_revision_hash)
    );
}

#[test]
fn immutable_change_and_approval_do_not_accept_replacements() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, change, approval, _) = setup(&dir.path().join("ledger.sqlite"));
    store.register_change(&change).unwrap();
    store.register_approval(&change, &approval).unwrap();
    let mut corrupt = change.clone();
    corrupt.plan.created_at += 1;
    assert_eq!(
        store.register_change(&corrupt).unwrap_err(),
        StoreError::Invalid
    );
    let mut edited = approval;
    edited.execution_identity = "other-runner".into();
    assert_eq!(
        store.register_approval(&change, &edited).unwrap_err(),
        StoreError::Approval
    );
}

#[test]
fn dispatch_is_durable_and_a_restart_queries_before_any_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let (mut store, change, _, op) = setup(&path);
    let first = &change.plan.steps[0].id;
    let leases = store.acquire_leases(&op.id, "worker-a", 102, 10).unwrap();
    let ticket = store
        .dispatch(&op.id, first, op.version, &leases, "runner", 103)
        .unwrap();
    drop(store);
    let mut store = OperationStore::open_existing(&path).unwrap();
    assert_eq!(
        store.steps(&op.id).unwrap()[0].state,
        StepState::Dispatching
    );
    let next = store.acquire_leases(&op.id, "worker-b", 113, 30).unwrap();
    assert_ne!(next.token, leases.token);
    assert_eq!(
        store.record_receipt(&ticket, &effect(), 114).unwrap_err(),
        StoreError::Stale
    );
    assert_eq!(
        store
            .dispatch(
                &op.id,
                first,
                ticket.operation_version,
                &next,
                "runner",
                114
            )
            .unwrap_err(),
        StoreError::Unresolved
    );
    let unresolved = store
        .resolve(
            &op.id,
            first,
            ticket.operation_version,
            &next,
            &unknown(),
            "runner",
            114,
        )
        .unwrap();
    let not_applied = StepReceipt {
        state: StepState::NotApplied,
        effect: EffectState::Unknown,
        native_operation_ref: None,
        evidence_refs: vec![],
    };
    let resolved = store
        .resolve(
            &op.id,
            first,
            unresolved.version,
            &next,
            &not_applied,
            "runner",
            115,
        )
        .unwrap();
    let retried = store
        .dispatch(&op.id, first, resolved.version, &next, "runner", 116)
        .unwrap();
    assert_eq!(retried.idempotency_key, ticket.idempotency_key);
    assert_eq!(retried.attempt, 2);
    assert!(
        store
            .events(&op.id)
            .unwrap()
            .iter()
            .any(|e| e.event == EventKind::Resolved)
    );
}

#[test]
fn approval_cancel_or_expiry_stops_dispatch_but_not_recording_accepted_results() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, change, _, op) = setup(&dir.path().join("ledger.sqlite"));
    let leases = store.acquire_leases(&op.id, "worker-a", 102, 30).unwrap();
    let ticket = store
        .dispatch(
            &op.id,
            &change.plan.steps[0].id,
            op.version,
            &leases,
            "runner",
            103,
        )
        .unwrap();
    let accepted = StepReceipt {
        state: StepState::Submitted,
        effect: EffectState::Pending,
        native_operation_ref: Some("provider-operation-1".into()),
        evidence_refs: vec![],
    };
    let waiting = store.record_receipt(&ticket, &accepted, 104).unwrap();
    store.cancel_approval("approval-1", 105).unwrap();
    let resolved = store
        .resolve(
            &op.id,
            &change.plan.steps[0].id,
            waiting.version,
            &leases,
            &effect(),
            "runner",
            106,
        )
        .unwrap();
    assert_eq!(
        store
            .dispatch(
                &op.id,
                &change.plan.steps[1].id,
                resolved.version,
                &leases,
                "runner",
                107
            )
            .unwrap_err(),
        StoreError::Approval
    );
    assert_eq!(
        store.steps(&op.id).unwrap()[0]
            .receipt
            .as_ref()
            .unwrap()
            .native_operation_ref
            .as_deref(),
        Some("provider-operation-1")
    );
    assert_eq!(
        store
            .set_state(&op.id, resolved.version, ExecutionState::Completed, 108)
            .unwrap_err(),
        StoreError::Transition
    );
}

#[test]
fn expired_forward_scope_does_not_prevent_readonly_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, change, _, op) = setup(&dir.path().join("ledger.sqlite"));
    let leases = store.acquire_leases(&op.id, "worker-a", 102, 2000).unwrap();
    let ticket = store
        .dispatch(
            &op.id,
            &change.plan.steps[0].id,
            op.version,
            &leases,
            "runner",
            103,
        )
        .unwrap();
    let waiting = store
        .record_receipt(
            &ticket,
            &StepReceipt {
                state: StepState::Submitted,
                effect: EffectState::Pending,
                native_operation_ref: Some("provider-operation-1".into()),
                evidence_refs: vec![],
            },
            104,
        )
        .unwrap();
    let resolved = store
        .resolve(
            &op.id,
            &change.plan.steps[0].id,
            waiting.version,
            &leases,
            &effect(),
            "runner",
            1001,
        )
        .unwrap();
    assert_eq!(
        store
            .dispatch(
                &op.id,
                &change.plan.steps[1].id,
                resolved.version,
                &leases,
                "runner",
                1002
            )
            .unwrap_err(),
        StoreError::Approval
    );
}

#[test]
fn shared_resource_leases_and_stale_worker_updates_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let (mut store, change, _, op) = setup(&path);
    let second = store
        .begin(&request(
            &change,
            "request-2",
            "operation-2",
            Some(change.plan.policy_revision_hash.clone()),
            102,
        ))
        .unwrap();
    let old = store.acquire_leases(&op.id, "worker-a", 103, 10).unwrap();
    let mut other = OperationStore::open_existing(&path).unwrap();
    assert_eq!(
        other
            .acquire_leases(&second.id, "worker-b", 104, 10)
            .unwrap_err(),
        StoreError::Lease
    );
    let replaced = other
        .acquire_leases(&second.id, "worker-b", 114, 30)
        .unwrap();
    assert!(replaced.token > old.token);
    assert_eq!(
        store
            .dispatch(
                &op.id,
                &change.plan.steps[0].id,
                op.version,
                &old,
                "runner",
                115
            )
            .unwrap_err(),
        StoreError::Stale
    );
    assert_eq!(
        store.renew_leases(&old, 115, 10).unwrap_err(),
        StoreError::Stale
    );
}

#[test]
fn submitted_effects_and_cancellation_cannot_be_rewritten_as_success() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, change, _, op) = setup(&dir.path().join("ledger.sqlite"));
    let leases = store.acquire_leases(&op.id, "worker", 102, 30).unwrap();
    let ticket = store
        .dispatch(
            &op.id,
            &change.plan.steps[0].id,
            op.version,
            &leases,
            "runner",
            103,
        )
        .unwrap();
    let invalid = StepReceipt {
        state: StepState::Submitted,
        effect: EffectState::Enforced,
        native_operation_ref: None,
        evidence_refs: vec![],
    };
    assert_eq!(
        store.record_receipt(&ticket, &invalid, 104).unwrap_err(),
        StoreError::Invalid
    );
    let cancelled = store
        .set_state(
            &op.id,
            ticket.operation_version,
            ExecutionState::Cancelled,
            104,
        )
        .unwrap();
    let resolved = store
        .resolve(
            &op.id,
            &change.plan.steps[0].id,
            cancelled.version,
            &leases,
            &effect(),
            "runner",
            105,
        )
        .unwrap();
    assert_eq!(resolved.state, ExecutionState::Cancelled);
    assert_eq!(
        store
            .dispatch(
                &op.id,
                &change.plan.steps[1].id,
                resolved.version,
                &leases,
                "runner",
                106
            )
            .unwrap_err(),
        StoreError::Transition
    );
    assert_eq!(
        store
            .set_state(&op.id, resolved.version, ExecutionState::Running, 106)
            .unwrap_err(),
        StoreError::Transition
    );
}

#[test]
fn completed_requires_every_dependency_and_effect_not_only_provider_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let (mut store, change, _, mut op) = setup(&dir.path().join("ledger.sqlite"));
    let leases = store.acquire_leases(&op.id, "worker", 102, 100).unwrap();
    assert_eq!(
        store
            .dispatch(
                &op.id,
                &change.plan.steps[2].id,
                op.version,
                &leases,
                "runner",
                103
            )
            .unwrap_err(),
        StoreError::Transition
    );
    for step in &change.plan.steps {
        let ticket = store
            .dispatch(&op.id, &step.id, op.version, &leases, "runner", 104)
            .unwrap();
        op = store.record_receipt(&ticket, &effect(), 104).unwrap();
    }
    let done = store
        .set_state(&op.id, op.version, ExecutionState::Completed, 105)
        .unwrap();
    assert_eq!(done.state, ExecutionState::Completed);
    assert_eq!(done.attempts, change.plan.steps.len() as u32);
}

#[test]
fn open_existing_does_not_initialize_missing_or_follow_symlinks_and_uri_names_are_files() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.sqlite");
    assert!(matches!(
        OperationStore::open_existing(&missing),
        Err(StoreError::NotFound)
    ));
    assert!(!missing.exists());
    let uri = dir.path().join("file:ledger?mode=memory");
    drop(OperationStore::open(&uri).unwrap());
    assert!(uri.is_file());
    assert!(OperationStore::open_existing(&uri).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(
            std::fs::metadata(&uri).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = dir.path().join("link.sqlite");
        symlink(&uri, &link).unwrap();
        assert!(matches!(
            OperationStore::open(&link),
            Err(StoreError::Invalid)
        ));
        let victim = dir.path().join("private-victim");
        std::fs::write(&victim, b"preserve-private-content").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
        let journal = std::path::PathBuf::from(format!("{}-journal", uri.to_str().unwrap()));
        std::fs::hard_link(&victim, &journal).unwrap();
        assert!(matches!(
            OperationStore::open_existing(&uri),
            Err(StoreError::Invalid)
        ));
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve-private-content");
    }
}

#[test]
fn ledger_size_and_event_reads_are_bounded_without_deleting_history() {
    use veil_db_guard::operation_store::{MAX_LEDGER_BYTES, MAX_OPERATION_EVENTS};
    let dir = tempfile::tempdir().unwrap();
    let oversized = dir.path().join("oversized.sqlite");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&oversized)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    file.set_len(MAX_LEDGER_BYTES + 1).unwrap();
    assert!(matches!(
        OperationStore::open_existing(&oversized),
        Err(StoreError::Limit)
    ));
    let path = dir.path().join("ledger.sqlite");
    let (store, _, _, op) = setup(&path);
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO operation_events(operation_id,kind,step_id,at) SELECT ?2,'\"state_changed\"',NULL,104 FROM n",rusqlite::params![MAX_OPERATION_EVENTS,op.id]).unwrap();
    drop(connection);
    let store = OperationStore::open_existing(&path).unwrap();
    assert_eq!(store.events(&op.id).unwrap_err(), StoreError::Limit);
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let count: usize = connection
        .query_row("SELECT COUNT(*) FROM operation_events", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, MAX_OPERATION_EVENTS + 1);
}

#[test]
fn a_foreign_sqlite_v1_database_is_rejected_without_modification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign.sqlite");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TABLE keep(value TEXT); INSERT INTO keep VALUES('untouched'); PRAGMA user_version=1;").unwrap();
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        OperationStore::open_existing(&path),
        Err(StoreError::Invalid)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn owned_iam_recover_cli_creates_an_approved_but_undispatched_operation() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.sqlite");
    let out = dir.path().join("compensation-plan");
    let (store, source, operation, owned) = owned_iam_source(&ledger);
    drop(store);
    let ledger_arg = ledger.to_str().unwrap();
    let out_arg = out.to_str().unwrap();
    let guard = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
            .arg("guard")
            .args(args)
            .output()
            .unwrap()
    };
    let planned = guard(&[
        "recover",
        "--compensate-owned-iam",
        "--ledger",
        ledger_arg,
        "--source-operation",
        &operation.id,
        "--grant",
        &owned.grant_id,
        "--out",
        out_arg,
    ]);
    assert_eq!(planned.status.code(), Some(3), "{:?}", planned);
    let change: PreparedChange =
        serde_json::from_slice(&std::fs::read(out.join("prepared-change.json")).unwrap()).unwrap();
    assert_eq!(change.plan.steps.len(), 1);
    assert_eq!(change.plan.steps[0].action, ActionKind::CompensateOwnedIam);
    assert!(!change.plan.required_effect_gaps.is_empty());
    assert_eq!(change.lifecycle.unwrap().owned_iam.as_ref(), Some(&owned));

    let approved = guard(&[
        "approve",
        "--ledger",
        ledger_arg,
        "--plan-run",
        out_arg,
        "--approval-id",
        "approval-compensation",
        "--approver",
        "operator",
        "--execution-identity",
        "runner",
    ]);
    assert!(approved.status.success(), "{:?}", approved);
    let begun = guard(&[
        "begin",
        "--ledger",
        ledger_arg,
        "--approval-id",
        "approval-compensation",
        "--operation-id",
        "compensation",
        "--request-id",
        "compensation-request",
        "--execution-identity",
        "runner",
        "--expected-desired-head",
        &source.plan.policy_revision_hash,
    ]);
    assert_eq!(begun.status.code(), Some(3), "{:?}", begun);
    let store = OperationStore::open_existing(&ledger).unwrap();
    let version = store.get("compensation").unwrap().version.to_string();
    let blocked = guard(&[
        "apply-gcp",
        "--allow-native-changes",
        "--ledger",
        ledger_arg,
        "--operation",
        "compensation",
        "--expected-version",
        &version,
        "--execution-identity",
        "runner",
        "--native-config",
        "/missing-k12-native-config.json",
    ]);
    assert!(!blocked.status.success());
    let output: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(output["reason"], "source_evidence_not_ready");
    assert_eq!(
        store.steps("compensation").unwrap()[0].state,
        StepState::Prepared
    );
}
