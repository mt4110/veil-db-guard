//! Local fake provider/SQL with the REAL source phase evaluator. No network.
use super::*;
use crate::{
    adapters::{capabilities_for_policy, deployment::gcp::*, engine::postgres::*},
    binding::*,
    core::{
        change::*,
        evidence::VerifiedObservationFacts,
        operation::*,
        plan::build_plan,
        policy::*,
        source_execution::{tests as fixture, *},
    },
};
use std::{cell::Cell, rc::Rc};
const ID: &str = "runner";
struct Gate {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    expire_on: usize,
    facts: Vec<VerifiedObservationFacts>,
    advance_clock: Option<(std::sync::Arc<std::sync::atomic::AtomicU64>, usize, u64)>,
}
impl SourceStepGate for Gate {
    fn validate_sources(&mut self, _: &PreparedChange) -> Result<(), ExecutorError> {
        Ok(())
    }
    fn now(&self) -> u64 {
        130
    }
    fn check(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        p: SourceStepPhase,
    ) -> Result<SourceStepCheck, ExecutorError> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let proof = check_source_step(
            c,
            s,
            p,
            if n >= self.expire_on { 170 } else { 130 },
            self.facts.clone(),
        );
        if let Some((clock, at, value)) = &self.advance_clock
            && n == *at
        {
            clock.store(*value, std::sync::atomic::Ordering::SeqCst);
        }
        proof
    }
}
struct Provider {
    calls: Rc<Cell<usize>>,
    writes: usize,
    instance: CloudSqlInstance,
    clock: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
impl CloudSqlProvider for Provider {
    fn now(&self) -> u64 {
        self.clock.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        self.calls.set(self.calls.get() + 1);
        Ok(ID.into())
    }
    fn instance(&mut self, _: &Target) -> Result<CloudSqlInstance, ProviderError> {
        Ok(self.instance.clone())
    }
    fn service_account_id(&mut self, email: &str) -> Result<String, ProviderError> {
        Ok(if email.starts_with("billing-app@") {
            "1"
        } else {
            "2"
        }
        .into())
    }
    fn iam_policy(&mut self, _: &str) -> Result<serde_json::Value, ProviderError> {
        Ok(serde_json::json!({"version":3,"etag":"local","bindings":[]}))
    }
    fn set_iam_policy(&mut self, _: &str, _: &serde_json::Value) -> Result<(), ProviderError> {
        self.writes += 1;
        Ok(())
    }
    fn users(&mut self, _: &Target) -> Result<Vec<CloudSqlUser>, ProviderError> {
        Ok(vec![])
    }
    fn patch(
        &mut self,
        t: &Target,
        _: &CloudSqlInstance,
        _: NativePatch,
    ) -> Result<NativeOperation, ProviderError> {
        self.writes += 1;
        self.instance.connector_required = true;
        Ok(op(t))
    }
    fn register_user(&mut self, t: &Target, _: &str) -> Result<NativeOperation, ProviderError> {
        self.writes += 1;
        Ok(op(t))
    }
    fn operation(&mut self, t: &Target, _: &str) -> Result<NativeOperation, ProviderError> {
        Ok(op(t))
    }
    fn observe_connections(
        &mut self,
        _: &PreparedChange,
        _: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        panic!("v1 CLI-host observer cannot supply v3 evidence")
    }
}
fn op(t: &Target) -> NativeOperation {
    NativeOperation {
        name: "local-native-op".into(),
        project: t.placement.account_id.clone(),
        instance: "billing-postgres".into(),
        done: true,
        failed: false,
    }
}
#[derive(Default)]
struct Sql {
    writes: usize,
}
impl PgTransport for Sql {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn preflight(&mut self, _: &SqlBatch) -> Result<(), PgError> {
        Ok(())
    }
    fn execute_atomic(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.writes += 1;
        Ok(PgOutcome::Applied)
    }
    fn execute_atomic_guarded(
        &mut self,
        batch: &SqlBatch,
        guard: &mut BeforeSqlWrite<'_>,
    ) -> Result<PgOutcome, PgError> {
        guard()?;
        self.execute_atomic(batch)
    }
    fn query(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        Ok(PgOutcome::Applied)
    }
}
fn setup(
    expire_on: usize,
) -> (
    PreparedChange,
    GcpProtectionExecutor<Provider, ManualCheckpoints, Sql>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut p = fixture::change().policy;
    p.targets[0].resource.generation_fingerprint = Some(generation_fingerprint(
        &p.targets[0].placement.account_id,
        "billing-postgres",
        "fixed-create-time",
    ));
    let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
    let c = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let cp = ManualCheckpoints {
        receipts: [
            CheckpointKind::BindingPublished,
            CheckpointKind::RecoveryReady,
            CheckpointKind::ApplicationCutover,
            CheckpointKind::ExclusiveNativeChangeWindow,
        ]
        .into_iter()
        .map(|k| {
            ManualCheckpoint::attest(&c, "billing-db", k, "recovery-operator", 100, 600).unwrap()
        })
        .collect(),
    };
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let gate = Gate {
        calls: calls.clone(),
        expire_on,
        advance_clock: None,
        facts: fixture::facts(&c, true, true),
    };
    let instance = CloudSqlInstance {
        project: p.targets[0].placement.account_id.clone(),
        name: "billing-postgres".into(),
        region: p.targets[0].placement.region.clone(),
        create_time: "fixed-create-time".into(),
        installed_version: "POSTGRES_16_15".into(),
        settings_version: "1".into(),
        database_flags: vec![DatabaseFlag {
            name: "cloudsql.iam_authentication".into(),
            value: "on".into(),
        }],
        connector_required: false,
        runnable: true,
    };
    let e = GcpProtectionExecutor {
        query_only: false,
        cloud: GcpExecutor::new(
            Provider {
                calls: Rc::new(Cell::new(0)),
                writes: 0,
                clock: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(130)),
                instance,
            },
            ID.into(),
            cp.clone(),
        ),
        postgres: PostgresStepExecutor::new(
            ID.into(),
            PostgresEngine {
                transport: Sql::default(),
            },
        ),
        binding: BindingStepExecutor::new(ID.into(), cp, 130),
        source: Some(Box::new(gate)),
    };
    (c, e, calls)
}
fn close(c: &PreparedChange) -> PlanStep {
    c.plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConstrainDirectPath)
        .unwrap()
        .clone()
}
fn ticket(s: &PlanStep) -> DispatchTicket {
    DispatchTicket {
        operation_id: "operation".into(),
        step_id: s.id.clone(),
        attempt: 1,
        operation_version: 1,
        idempotency_key: "local-key".into(),
        leases: LeaseSet {
            holder: "worker".into(),
            token: 1,
            keys: vec![],
            expires_at: 500,
        },
    }
}
#[test]
fn composite_rechecks_after_preflight_and_stale_proof_stops_before_provider() {
    let (c, mut e, calls) = setup(2);
    let s = close(&c);
    e.preflight(&c, &s).unwrap();
    let provider_calls = e.cloud.provider.calls.get();
    assert_eq!(
        e.submit(&c, &s, &ticket(&s)),
        Err(ExecutorError::NotApplied)
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(e.cloud.provider.calls.get(), provider_calls);
    assert_eq!(e.cloud.provider.writes, 0);
}
#[test]
fn configuration_ack_stays_separate_and_query_can_finish_with_fresh_source_proof() {
    let (c, mut e, calls) = setup(usize::MAX);
    let s = close(&c);
    e.preflight(&c, &s).unwrap();
    let submitted = e.submit(&c, &s, &ticket(&s)).unwrap();
    assert_eq!(submitted.state, StepState::Submitted);
    assert_eq!(e.cloud.provider.writes, 1);
    let record = StepRecord {
        step_id: s.id.clone(),
        state: submitted.state,
        attempt: 1,
        idempotency_key: "key".into(),
        receipt: Some(submitted),
    };
    let complete = e.query(&c, &s, &record).unwrap();
    assert_eq!(complete.state, StepState::EffectSatisfied);
    assert!(complete.evidence_refs.len() >= 2);
    assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 3);
    // Missing source data after an accepted patch preserves query-only config
    // readback and its native reference; it never makes the step redispatchable.
    e.source = None;
    let incomplete = e.query(&c, &s, &record).unwrap();
    assert_eq!(incomplete.state, StepState::ConfigApplied);
    assert_eq!(incomplete.effect, EffectState::Unknown);
    assert_eq!(
        incomplete.native_operation_ref,
        complete.native_operation_ref
    );
    assert_eq!(e.cloud.provider.writes, 1);
}
#[test]
fn uncomposed_adapters_and_manual_recovery_cannot_write_or_satisfy_v3() {
    let (c, mut e, _) = setup(usize::MAX);
    let s = close(&c);
    assert!(e.cloud.preflight(&c, &s).is_err());
    assert!(e.cloud.submit(&c, &s, &ticket(&s)).is_err());
    let sql = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    assert!(!e.postgres.available(&c, sql));
    assert!(e.postgres.submit(&c, sql, &ticket(sql)).is_err());
    let rec = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfirmRecoveryReadiness)
        .unwrap();
    assert!(e.binding.submit(&c, rec, &ticket(rec)).is_err());
    assert_eq!(e.cloud.provider.writes, 0);
    assert_eq!(e.postgres.engine.transport.writes, 0);
    e.source = None;
    assert!(!e.available(&c, &s));
}

#[test]
fn expiry_during_provider_reads_is_rechecked_at_patch_boundary() {
    let (c, mut e, calls) = setup(3);
    let s = close(&c);
    e.preflight(&c, &s).unwrap();
    assert_eq!(
        e.submit(&c, &s, &ticket(&s)),
        Err(ExecutorError::NotApplied)
    );
    assert!(e.cloud.provider.calls.get() >= 2);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(e.cloud.provider.writes, 0);
}

#[test]
fn query_only_latch_cannot_unlock_forward_when_readback_finishes() {
    let (c, mut e, _) = setup(usize::MAX);
    e.query_only = true;
    e.source = None;
    let step = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::PrepareNativeRoute)
        .unwrap();
    let record = StepRecord {
        step_id: step.id.clone(),
        state: StepState::Submitted,
        attempt: 1,
        idempotency_key: "key".into(),
        receipt: Some(StepReceipt {
            state: StepState::Submitted,
            effect: EffectState::Pending,
            native_operation_ref: Some("local-native-op".into()),
            evidence_refs: vec![],
        }),
    };
    assert_eq!(
        e.query(&c, step, &record).unwrap().state,
        StepState::EffectSatisfied
    );
    let next = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureIdentity)
        .unwrap();
    assert!(!e.available(&c, next));
    assert!(e.submit(&c, next, &ticket(next)).is_err());
    assert_eq!(e.cloud.provider.writes, 0);
}
#[test]
fn sql_source_guard_failure_is_known_uncommitted_and_stops_at_transport_hook() {
    let (allow, mut e, _) = setup(usize::MAX);
    let mut p = allow.policy.clone();
    p.revision += 1;
    p.parent_revision_hash = Some(allow.policy.revision_hash().unwrap());
    p.grants[0].admission = AdmissionIntent::Deny;
    p.grants[0].sql_access = SqlAccessIntent::default();
    p.protection_profiles[0].required_effects = vec![EffectKind::NewConnectionsDenied];
    let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
    let c = prepare_change(
        &p,
        &plan,
        &[],
        Some(&allow.policy),
        OperationLimits::default(),
    )
    .unwrap();
    e.binding.checkpoints = ManualCheckpoints {
        receipts: vec![
            ManualCheckpoint::attest(
                &c,
                "billing-db",
                CheckpointKind::ExclusiveNativeChangeWindow,
                "recovery-operator",
                100,
                600,
            )
            .unwrap(),
        ],
    };
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    e.source = Some(Box::new(Gate {
        calls: calls.clone(),
        expire_on: 2,
        advance_clock: None,
        facts: fixture::facts(&c, false, false),
    }));
    let s = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::DisableNewConnections)
        .unwrap();
    assert_eq!(e.submit(&c, s, &ticket(s)), Err(ExecutorError::NotApplied));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(e.postgres.engine.transport.writes, 0);
}

#[test]
fn checkpoint_expiry_during_source_read_blocks_patch_after_the_hook() {
    let (c, mut e, calls) = setup(usize::MAX);
    let s = close(&c);
    e.source = Some(Box::new(Gate {
        calls,
        expire_on: usize::MAX,
        facts: fixture::facts(&c, true, true),
        advance_clock: Some((e.cloud.provider.clock.clone(), 3, 601)),
    }));
    e.preflight(&c, &s).unwrap();
    assert_eq!(
        e.submit(&c, &s, &ticket(&s)),
        Err(ExecutorError::NotApplied)
    );
    assert_eq!(e.cloud.provider.writes, 0);
}

#[test]
fn known_unsupported_source_profile_stops_even_preparatory_native_reads() {
    struct Unsupported;
    impl SourceStepGate for Unsupported {
        fn check(
            &mut self,
            _: &PreparedChange,
            _: &PlanStep,
            _: SourceStepPhase,
        ) -> Result<SourceStepCheck, ExecutorError> {
            panic!("unsupported declaration cannot reach observations")
        }
    }
    let (c, mut e, _) = setup(usize::MAX);
    e.source = Some(Box::new(Unsupported));
    let first = &c.plan.steps[0];
    assert!(e.preflight(&c, first).is_err());
    assert_eq!(e.cloud.provider.calls.get(), 0);
    assert_eq!(e.cloud.provider.writes, 0);
}

#[test]
fn source_registration_rotated_during_setup_reads_blocks_the_actual_iam_write() {
    struct Rotating {
        checks: usize,
    }
    impl SourceStepGate for Rotating {
        fn validate_sources(&mut self, _: &PreparedChange) -> Result<(), ExecutorError> {
            self.checks += 1;
            if self.checks >= 3 {
                Err(ExecutorError::PreconditionsNotMet)
            } else {
                Ok(())
            }
        }
        fn check(
            &mut self,
            _: &PreparedChange,
            _: &PlanStep,
            _: SourceStepPhase,
        ) -> Result<SourceStepCheck, ExecutorError> {
            panic!("preparatory IAM needs declaration validity, not future runtime access")
        }
    }
    let (c, mut e, _) = setup(usize::MAX);
    e.source = Some(Box::new(Rotating { checks: 0 }));
    let s = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureIdentity)
        .unwrap();
    e.preflight(&c, s).unwrap();
    assert_eq!(e.submit(&c, s, &ticket(s)), Err(ExecutorError::NotApplied));
    assert_eq!(e.cloud.provider.writes, 0);
}
