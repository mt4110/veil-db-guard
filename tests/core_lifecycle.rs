//! Ledger-backed scoped lifecycle tests use a fake executor, never native proof.
use veil_db_guard::{
    adapters::capabilities_for,
    binding::{CheckpointKind, ManualCheckpoint},
    core::{
        approval,
        capability::*,
        change::*,
        lifecycle::*,
        operation::*,
        orchestrator::{self, Clock, ExecutorError, StepExecutor},
        plan::{PlanStep, build_plan},
        policy::*,
    },
    operation_store::OperationStore,
};
fn source() -> PreparedChange {
    let mut p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    p.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    let plan = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn maintenance(s: &PreparedChange, kind: LifecycleKind, sql: bool) -> PreparedChange {
    prepare_maintenance(
        s,
        "source",
        kind,
        "billing-access",
        &[],
        s.policy.targets.iter().flat_map(capabilities_for).collect(),
        110,
        s.limits.clone(),
        sql,
    )
    .unwrap()
}
fn begin(
    store: &mut OperationStore,
    c: &PreparedChange,
    name: &str,
    head: Option<String>,
) -> Result<Operation, StoreError> {
    let a = approval::issue(
        c,
        &format!("approval-{name}"),
        "operator",
        "runner",
        900,
        1000,
        110,
    )
    .unwrap();
    store.register_change(c)?;
    store.register_approval(c, &a)?;
    store.begin(&BeginRequest {
        request_id: format!("request-{name}"),
        operation_id: name.into(),
        change_hash: c.change_hash.clone(),
        approval_id: a.id,
        expected_desired_head: head,
        execution_identity: "runner".into(),
        now: 110,
    })
}
struct Time(u64);
impl Clock for Time {
    fn now(&mut self) -> u64 {
        self.0
    }
}
struct Fake {
    pending: bool,
    writes: usize,
}
impl StepExecutor for Fake {
    fn identity(&self) -> &str {
        "runner"
    }
    fn available(&self, _: &PreparedChange, _: &PlanStep) -> bool {
        true
    }
    fn preflight(&mut self, _: &PreparedChange, _: &PlanStep) -> Result<(), ExecutorError> {
        Ok(())
    }
    fn submit(
        &mut self,
        _: &PreparedChange,
        _: &PlanStep,
        _: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        self.writes += 1;
        Ok(self.receipt())
    }
    fn query(
        &mut self,
        _: &PreparedChange,
        _: &PlanStep,
        _: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        Ok(self.receipt())
    }
}
impl Fake {
    fn receipt(&self) -> StepReceipt {
        StepReceipt {
            state: if self.pending {
                StepState::ConfigApplied
            } else {
                StepState::EffectSatisfied
            },
            effect: if self.pending {
                EffectState::Pending
            } else {
                EffectState::Enforced
            },
            native_operation_ref: None,
            evidence_refs: vec![],
        }
    }
}
fn store() -> (tempfile::TempDir, OperationStore) {
    let d = tempfile::tempdir().unwrap();
    let s = OperationStore::open(&d.path().join("ledger.sqlite")).unwrap();
    (d, s)
}
#[test]
fn revoke_advances_only_selected_grant_and_preserves_denied_recovery() {
    let s = source();
    let r = maintenance(&s, LifecycleKind::Revoke, false);
    r.verify().unwrap();
    validate_source(&r, &s).unwrap();
    assert_eq!(r.policy.revision, 2);
    assert_eq!(r.policy.grants[0].admission, AdmissionIntent::Deny);
    assert!(r.policy.grants[0].sql_access.privileges.is_empty());
    assert_eq!(
        r.plan.steps.iter().map(|s| s.action).collect::<Vec<_>>(),
        vec![
            ActionKind::DisableNativeIdentity,
            ActionKind::DisableNewConnections,
            ActionKind::ObserveRevocation
        ]
    );
    assert!(r.plan.required_effect_gaps.is_empty());
    for c in &r.recovery.compensations {
        if c.forward_step_id != r.plan.steps.last().unwrap().id {
            assert_eq!(c.method, RecoveryMethod::NoAutomaticAllowRestoration);
            assert!(c.security_weakening_requires_separate_approval);
        }
    }
    let window = ManualCheckpoint::attest(
        &r,
        "billing-db",
        CheckpointKind::ExclusiveNativeChangeWindow,
        "recovery-operator",
        110,
        410,
    )
    .unwrap();
    window.validate(&r, "billing-db", 120).unwrap();
    assert!(
        ManualCheckpoint::attest(
            &r,
            "billing-db",
            CheckpointKind::BindingPublished,
            "recovery-operator",
            110,
            410
        )
        .is_err()
    );
    let repair = maintenance(&r, LifecycleKind::Reconcile, false);
    assert_eq!(repair.policy.grants[0].admission, AdmissionIntent::Deny);
    validate_source(&repair, &r).unwrap();
}
#[test]
fn sql_revoke_profile_can_be_reconciled_without_turning_it_into_allow() {
    let s = source();
    let r = maintenance(&s, LifecycleKind::Revoke, true);
    let repair = maintenance(&r, LifecycleKind::Reconcile, false);
    validate_source(&repair, &r).unwrap();
    assert!(
        repair
            .plan
            .steps
            .iter()
            .any(|s| s.action == ActionKind::RevokeSqlPrivileges)
    );
    assert_eq!(repair.policy.grants[0].admission, AdmissionIntent::Deny);
}
#[test]
fn source_operation_and_new_approval_are_required() {
    let s = source();
    let r = maintenance(&s, LifecycleKind::Reconcile, false);
    let (_d, mut ledger) = store();
    assert_eq!(ledger.register_change(&r), Err(StoreError::NotFound));
    let parent = begin(&mut ledger, &s, "source", None).unwrap();
    let head = Some(parent.policy_revision_hash);
    assert!(begin(&mut ledger, &r, "repair", head).is_ok());
    let op = ledger.get("repair").unwrap();
    assert_ne!(op.change_hash, s.change_hash);
    assert_eq!(op.approval_id, "approval-repair");
}
#[test]
fn maintenance_lineage_cannot_reset_budget_or_raise_limits() {
    let s = source();
    let r = maintenance(&s, LifecycleKind::Reconcile, false);
    assert!(
        prepare_maintenance(
            &r,
            "repair",
            LifecycleKind::Reconcile,
            "billing-access",
            &[],
            r.plan.capabilities.clone(),
            120,
            r.limits.clone(),
            false
        )
        .is_err()
    );
    let mut limits = s.limits.clone();
    limits.max_attempts += 1;
    assert!(
        prepare_maintenance(
            &s,
            "source",
            LifecycleKind::Recover,
            "billing-access",
            &[],
            s.plan.capabilities.clone(),
            120,
            limits,
            false
        )
        .is_err()
    );
    let (_d, mut ledger) = store();
    let parent = begin(&mut ledger, &s, "source", None).unwrap();
    let head = Some(parent.policy_revision_hash);
    assert!(begin(&mut ledger, &r, "repair-1", head.clone()).is_ok());
    assert!(begin(&mut ledger, &r, "repair-2", head.clone()).is_ok());
    assert_eq!(
        begin(&mut ledger, &r, "repair-3", head),
        Err(StoreError::Limit)
    );
}
#[test]
fn recover_of_old_allow_cannot_replace_active_deny() {
    let s = source();
    let (_d, mut ledger) = store();
    let op = begin(&mut ledger, &s, "source", None).unwrap();
    ledger
        .set_state("source", op.version, ExecutionState::Cancelled, 111)
        .unwrap();
    let revoke = maintenance(&s, LifecycleKind::Revoke, false);
    let deny = begin(
        &mut ledger,
        &revoke,
        "revoke",
        Some(s.plan.policy_revision_hash.clone()),
    )
    .unwrap();
    let recovery = maintenance(&s, LifecycleKind::Recover, false);
    assert_eq!(
        begin(
            &mut ledger,
            &recovery,
            "recover",
            Some(deny.policy_revision_hash)
        ),
        Err(StoreError::Conflict)
    );
    assert_eq!(
        ledger.desired_head(&s.policy.policy_id).unwrap(),
        Some(revoke.plan.policy_revision_hash)
    );
}
#[test]
fn effect_wait_deadline_stops_finitely_without_resending_or_restoring_allow() {
    let mut s = source();
    let limits = OperationLimits {
        max_operation_seconds: 30,
        ..s.limits.clone()
    };
    s = prepare_change(&s.policy, &s.plan, &[], None, limits).unwrap();
    let (_d, mut ledger) = store();
    let a = approval::issue(&s, "approval", "operator", "runner", 120, 130, 100).unwrap();
    ledger.register_change(&s).unwrap();
    ledger.register_approval(&s, &a).unwrap();
    let op = ledger
        .begin(&BeginRequest {
            request_id: "request".into(),
            operation_id: "source".into(),
            change_hash: s.change_hash.clone(),
            approval_id: a.id,
            expected_desired_head: None,
            execution_identity: "runner".into(),
            now: 100,
        })
        .unwrap();
    let mut driver = Fake {
        pending: true,
        writes: 0,
    };
    let waiting = orchestrator::resume_with_clock(
        &mut ledger,
        "source",
        op.version,
        "worker",
        &mut Time(110),
        &mut driver,
    )
    .unwrap();
    assert_eq!(waiting.state, ExecutionState::WaitingEffect);
    let failed = orchestrator::resume_with_clock(
        &mut ledger,
        "source",
        waiting.version,
        "worker",
        &mut Time(131),
        &mut driver,
    )
    .unwrap();
    assert_eq!(failed.state, ExecutionState::FailedPartial);
    assert_eq!(driver.writes, 1);
    assert_eq!(
        ledger.steps("source").unwrap()[0]
            .receipt
            .as_ref()
            .unwrap()
            .effect,
        EffectState::Pending
    );
}

#[test]
fn native_allowed_partial_record_roundtrips_without_becoming_protection_pass() {
    use std::collections::BTreeSet;
    use veil_db_guard::{
        adapters::deployment::gcp::RevocationEvidence,
        gcp::model::GcpAccess,
        native_cli::{NativeStateRecord, load_state_record},
        store::{RunStatus, RunWriter},
    };
    let revoke = maintenance(&source(), LifecycleKind::Revoke, false);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state-run");
    let observation = RevocationEvidence {
        complete: false,
        generation: "a".repeat(64),
        observed_at: 110,
        denied_principal: revoke
            .policy
            .subjects
            .iter()
            .find(|s| s.id == revoke.policy.grants[0].subject)
            .unwrap()
            .identity
            .principal
            .clone(),
        access: GcpAccess::Allowed,
        denied_permission: None,
        connector_allowed_principals: BTreeSet::new(),
        direct_denied_principals: BTreeSet::new(),
        evidence_refs: vec!["b".repeat(64)],
    };
    let record = NativeStateRecord {
        schema_version: 1,
        operation_id: "revoke".into(),
        change_hash: revoke.change_hash.clone(),
        policy_revision_hash: revoke.plan.policy_revision_hash.clone(),
        observation,
    };
    let mut writer = RunWriter::create_for_config(
        &path,
        &revoke.policy.policy_id,
        &revoke.policy,
        "guard-state",
        8 * 1024 * 1024,
        false,
    )
    .unwrap();
    writer.write_json("effective-state.json", &record).unwrap();
    writer.finish(RunStatus::Partial).unwrap();
    let loaded = load_state_record(&revoke, "revoke", &path).unwrap();
    assert_eq!(loaded.observation.access, GcpAccess::Allowed);
    assert!(!loaded.observation.complete);
    assert!(load_state_record(&revoke, "another-operation", &path).is_err());
    std::fs::write(path.join("effective-state.json"), b"{}\n").unwrap();
    assert!(load_state_record(&revoke, "revoke", &path).is_err());
}

#[test]
fn native_factory_resolves_sql_owner_ancestor_and_keeps_immediate_deny_parent_bound() {
    use veil_db_guard::{
        adapters::engine::postgres::{PgAction, PgOwnershipReceipt, compile},
        native_cli::build_sql_lifecycle_context,
        store::{RunStatus, RunWriter},
    };
    let s = source();
    let batch = compile(
        &s.policy,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let batch_json = serde_json::to_value(&batch).unwrap();
    let ownership:PgOwnershipReceipt=serde_json::from_value(serde_json::json!({"policy_hash":s.plan.policy_revision_hash,"apply_batch_hash":batch.hash(),"management_role":"management","before_roles":[],"before_privileges":[],"after_roles":[],"after_privileges":[batch_json["checks"][0].clone()],"added_roles":[],"added_privileges":[batch_json["checks"][0].clone()]})).unwrap();
    let (dir, mut ledger) = store();
    let path = dir.path().join("ownership-run");
    let mut writer = RunWriter::create_for_config(
        &path,
        "billing-db",
        &batch,
        "postgres-ownership",
        2 * 1024 * 1024,
        false,
    )
    .unwrap();
    writer
        .write_json("postgres-ownership.json", &ownership)
        .unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    struct Applied {
        batch: String,
        owned: String,
    }
    impl StepExecutor for Applied {
        fn identity(&self) -> &str {
            "runner"
        }
        fn available(&self, _: &PreparedChange, _: &PlanStep) -> bool {
            true
        }
        fn preflight(&mut self, _: &PreparedChange, _: &PlanStep) -> Result<(), ExecutorError> {
            Ok(())
        }
        fn submit(
            &mut self,
            _: &PreparedChange,
            step: &PlanStep,
            _: &DispatchTicket,
        ) -> Result<StepReceipt, ExecutorError> {
            Ok(StepReceipt {
                state: StepState::EffectSatisfied,
                effect: EffectState::Enforced,
                native_operation_ref: None,
                evidence_refs: if step.action == ActionKind::ConfigureSqlPrivileges {
                    vec![self.batch.clone(), self.owned.clone()]
                } else {
                    vec![]
                },
            })
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
    let op = begin(&mut ledger, &s, "source", None).unwrap();
    let complete = orchestrator::resume_with_clock(
        &mut ledger,
        "source",
        op.version,
        "worker",
        &mut Time(111),
        &mut Applied {
            batch: batch.hash(),
            owned: ownership.hash(),
        },
    )
    .unwrap();
    assert_eq!(complete.state, ExecutionState::Completed);
    let revoke = maintenance(&s, LifecycleKind::Revoke, true);
    let op = begin(
        &mut ledger,
        &revoke,
        "revoke",
        Some(s.plan.policy_revision_hash.clone()),
    )
    .unwrap();
    ledger
        .set_state("revoke", op.version, ExecutionState::Cancelled, 111)
        .unwrap();
    for kind in [LifecycleKind::Reconcile, LifecycleKind::Recover] {
        let change = prepare_maintenance(
            &revoke,
            "revoke",
            kind,
            "billing-access",
            &[],
            revoke.plan.capabilities.clone(),
            112,
            revoke.limits.clone(),
            false,
        )
        .unwrap();
        let context = build_sql_lifecycle_context(&ledger, &change, Some(&path))
            .unwrap()
            .unwrap();
        assert_eq!(context.prior_operation_id, "source");
        assert_eq!(context.prior_policy, s.policy);
        assert_eq!(
            context.authorization_source,
            Some(("revoke".into(), revoke.change_hash.clone()))
        );
        assert!(build_sql_lifecycle_context(&ledger, &change, None).is_err());
    }
}

#[test]
fn v2_revoke_carries_approved_denial_layers_into_the_new_profile() {
    let mut p = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
    p.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    let plan = build_plan(
        &p,
        veil_db_guard::adapters::capabilities_for_policy(&p).unwrap(),
        vec![],
        100,
    )
    .unwrap();
    let source = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let revoke = prepare_maintenance(
        &source,
        "source",
        LifecycleKind::Revoke,
        "billing-access",
        &[],
        source.plan.capabilities.clone(),
        110,
        source.limits.clone(),
        false,
    )
    .unwrap();
    revoke.verify().unwrap();
    validate_source(&revoke, &source).unwrap();
    let grant = &revoke.policy.grants[0];
    let old_id = &source.policy.grants[0].profile;
    let old = source
        .policy
        .evaluation
        .as_ref()
        .unwrap()
        .denial_requirements
        .iter()
        .find(|r| &r.profile_id == old_id)
        .unwrap();
    let new = revoke
        .policy
        .evaluation
        .as_ref()
        .unwrap()
        .denial_requirements
        .iter()
        .find(|r| r.profile_id == grant.profile)
        .unwrap();
    assert_eq!(new.accepted_layers, old.accepted_layers);
    assert_ne!(revoke.change_hash, source.change_hash);
    assert_eq!(revoke.previous_policy.as_ref().unwrap(), &source.policy);
}
