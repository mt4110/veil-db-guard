use std::path::Path;
use veil_db_guard::{
    adapters::capabilities_for,
    core::{
        approval::{ApprovalGrant, issue},
        change::{OperationLimits, PreparedChange, prepare_change},
        operation::*,
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
