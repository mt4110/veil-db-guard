//! Local fakes exercise the real adapter composition and durable SQLite kernel.
//! No provider executable, network connection or database server is used.
use serde_json::{Value, json};
use std::{cell::Cell, collections::BTreeSet, rc::Rc};
use veil_db_guard::{
    adapters::{
        capabilities_for, deployment::gcp::*, engine::postgres::*, executor::GcpProtectionExecutor,
    },
    binding::*,
    core::{
        approval,
        change::{OperationLimits, PreparedChange, prepare_change},
        operation::*,
        orchestrator::{self, Clock},
        plan::build_plan,
        policy::*,
    },
    operation_store::OperationStore,
};
const ID: &str =
    "gcp-service-account:runner@vdg-example-000000.iam.gserviceaccount.com:100000000000000000009";
fn change() -> PreparedChange {
    let mut p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    for (i, s) in p.subjects.iter_mut().enumerate() {
        s.identity.immutable_id = Some(format!("10000000000000000000{i}"));
    }
    p.targets[0].resource.generation_fingerprint = Some(generation_fingerprint(
        "vdg-example-000000",
        "billing-postgres",
        "2026-11-01T10:00:00Z",
    ));
    let plan = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    assert!(plan.capability_gaps.is_empty());
    prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn checkpoints(c: &PreparedChange) -> ManualCheckpoints {
    ManualCheckpoints {
        receipts: [
            CheckpointKind::BindingPublished,
            CheckpointKind::RecoveryReady,
            CheckpointKind::ApplicationCutover,
            CheckpointKind::ExclusiveNativeChangeWindow,
        ]
        .into_iter()
        .map(|kind| {
            ManualCheckpoint::attest(c, "billing-db", kind, "recovery-operator", 100, 600).unwrap()
        })
        .collect(),
    }
}
struct FakeCloud {
    instance: CloudSqlInstance,
    iam: Value,
    users: Vec<CloudSqlUser>,
    writes: Vec<&'static str>,
    principals: BTreeSet<String>,
    direct_denied: bool,
    revocation_access: veil_db_guard::gcp::model::GcpAccess,
    time: Rc<Cell<u64>>,
}
impl FakeCloud {
    fn new(c: &PreparedChange, time: Rc<Cell<u64>>) -> Self {
        Self {
            instance: CloudSqlInstance {
                project: "vdg-example-000000".into(),
                name: "billing-postgres".into(),
                region: "asia-northeast1".into(),
                create_time: "2026-11-01T10:00:00Z".into(),
                installed_version: "POSTGRES_16_15".into(),
                settings_version: "1".into(),
                database_flags: vec![],
                connector_required: false,
                runnable: true,
            },
            iam: json!({"version":3,"etag":"local-etag","bindings":[]}),
            users: vec![],
            writes: vec![],
            principals: c
                .policy
                .subjects
                .iter()
                .map(|s| s.identity.principal.clone())
                .collect(),
            direct_denied: false,
            revocation_access: veil_db_guard::gcp::model::GcpAccess::Allowed,
            time,
        }
    }
    fn operation() -> NativeOperation {
        NativeOperation {
            name: "local-native-1".into(),
            project: "vdg-example-000000".into(),
            instance: "billing-postgres".into(),
            done: true,
            failed: false,
        }
    }
}
impl CloudSqlProvider for FakeCloud {
    fn now(&self) -> u64 {
        self.time.get()
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        Ok(ID.into())
    }
    fn instance(&mut self, _: &Target) -> Result<CloudSqlInstance, ProviderError> {
        Ok(self.instance.clone())
    }
    fn service_account_id(&mut self, email: &str) -> Result<String, ProviderError> {
        Ok(if email.starts_with("billing-app@") {
            "100000000000000000000"
        } else {
            "100000000000000000001"
        }
        .into())
    }
    fn iam_policy(&mut self, _: &str) -> Result<Value, ProviderError> {
        Ok(self.iam.clone())
    }
    fn set_iam_policy(&mut self, _: &str, p: &Value) -> Result<(), ProviderError> {
        self.writes.push("iam");
        self.iam = p.clone();
        Ok(())
    }
    fn users(&mut self, _: &Target) -> Result<Vec<CloudSqlUser>, ProviderError> {
        Ok(self.users.clone())
    }
    fn patch(
        &mut self,
        _: &Target,
        _: &CloudSqlInstance,
        p: NativePatch,
    ) -> Result<NativeOperation, ProviderError> {
        match p {
            NativePatch::EnableIamAuthentication => {
                self.writes.push("iam-flag");
                self.instance.database_flags.push(DatabaseFlag {
                    name: "cloudsql.iam_authentication".into(),
                    value: "on".into(),
                });
            }
            NativePatch::RequireConnector => {
                self.writes.push("connector-required");
                self.instance.connector_required = true;
            }
        }
        self.instance.settings_version =
            (self.instance.settings_version.parse::<u64>().unwrap() + 1).to_string();
        Ok(Self::operation())
    }
    fn register_user(&mut self, _: &Target, name: &str) -> Result<NativeOperation, ProviderError> {
        self.writes.push("db-login");
        self.users.push(CloudSqlUser {
            name: name.into(),
            iam_service_account: true,
        });
        Ok(Self::operation())
    }
    fn operation(&mut self, _: &Target, _: &str) -> Result<NativeOperation, ProviderError> {
        Ok(Self::operation())
    }
    fn observe_revocation(
        &mut self,
        change: &PreparedChange,
        target: &Target,
        grant: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        use veil_db_guard::gcp::model::{GcpAccess, GcpPermission};
        let principal = change
            .policy
            .subjects
            .iter()
            .find(|s| s.id == grant.subject)
            .unwrap()
            .identity
            .principal
            .clone();
        Ok(Some(RevocationEvidence {
            complete: true,
            generation: target.resource.generation_fingerprint.clone().unwrap(),
            observed_at: self.time.get(),
            denied_principal: principal,
            access: self.revocation_access,
            denied_permission: if self.revocation_access == GcpAccess::Denied {
                Some(GcpPermission::InstanceConnect)
            } else {
                None
            },
            connector_allowed_principals: self.principals.clone(),
            direct_denied_principals: if self.direct_denied {
                self.principals.clone()
            } else {
                BTreeSet::new()
            },
            evidence_refs: vec!["b".repeat(64)],
        }))
    }
    fn observe_connections(
        &mut self,
        _: &PreparedChange,
        t: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        Ok(Some(ConnectionEvidence {
            generation: t.resource.generation_fingerprint.clone().unwrap(),
            observed_at: self.time.get(),
            connector_principals: self.principals.clone(),
            direct_denied_principals: if self.direct_denied {
                self.principals.clone()
            } else {
                BTreeSet::new()
            },
            evidence_refs: vec!["a".repeat(64)],
        }))
    }
}
#[derive(Default)]
struct FakeSql {
    writes: usize,
    queries: usize,
}
impl PgTransport for FakeSql {
    fn preflight(&mut self, _: &SqlBatch) -> Result<(), PgError> {
        Ok(())
    }
    fn execute_atomic(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.writes += 1;
        Ok(PgOutcome::Applied)
    }
    fn query(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.queries += 1;
        Ok(PgOutcome::Applied)
    }
}
struct Time(Rc<Cell<u64>>);
impl Clock for Time {
    fn now(&mut self) -> u64 {
        self.0.get()
    }
}
fn begin(store: &mut OperationStore, c: &PreparedChange) -> Operation {
    let approval = approval::issue(c, "approval", "operator", ID, 900, 1000, 100).unwrap();
    store.register_change(c).unwrap();
    store.register_approval(c, &approval).unwrap();
    store
        .begin(&BeginRequest {
            request_id: "request".into(),
            operation_id: "operation".into(),
            change_hash: c.change_hash.clone(),
            approval_id: approval.id,
            expected_desired_head: None,
            execution_identity: ID.into(),
            now: 100,
        })
        .unwrap()
}
fn driver(
    c: &PreparedChange,
    time: Rc<Cell<u64>>,
) -> GcpProtectionExecutor<FakeCloud, ManualCheckpoints, FakeSql> {
    let cp = checkpoints(c);
    GcpProtectionExecutor {
        query_only: false,
        source: None,
        cloud: GcpExecutor::new(FakeCloud::new(c, time), ID.into(), cp.clone()),
        postgres: PostgresStepExecutor::new(
            ID.into(),
            PostgresEngine {
                transport: FakeSql::default(),
            },
        ),
        binding: BindingStepExecutor::new(ID.into(), cp, 100),
    }
}
#[test]
fn full_native_graph_resumes_and_preserves_pending_until_direct_denial() {
    let c = change();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let mut store = OperationStore::open(&path).unwrap();
    let mut op = begin(&mut store, &c);
    let time = Rc::new(Cell::new(100));
    let mut exec = driver(&c, time.clone());
    let mut clock = Time(time.clone());
    for pass in 0..8 {
        op = orchestrator::resume_with_clock(
            &mut store,
            "operation",
            op.version,
            "worker",
            &mut clock,
            &mut exec,
        )
        .unwrap();
        drop(store);
        store = OperationStore::open_existing(&path).unwrap(); // actual process-boundary persistence
        if op.state == ExecutionState::WaitingEffect {
            break;
        }
        assert!(pass < 7, "graph never reached scoped effect wait");
    }
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(
        exec.cloud.provider.writes,
        vec!["iam-flag", "iam", "db-login", "connector-required"]
    );
    assert_eq!(exec.postgres.engine.transport.writes, 1);
    let attempts = op.attempts;
    // Re-reading a pending refusal cannot repeat the accepted native mutation.
    op = orchestrator::resume_with_clock(
        &mut store,
        "operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(op.attempts, attempts);
    // Expired approval/window does not block read-only reconciliation.
    time.set(1100);
    exec.cloud.provider.direct_denied = true;
    op = orchestrator::resume_with_clock(
        &mut store,
        "operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::Completed);
    assert_eq!(op.attempts, 8);
    assert_eq!(exec.cloud.provider.writes.len(), 4);
    assert_eq!(exec.postgres.engine.transport.writes, 1);
    assert!(store.steps("operation").unwrap().iter().all(|r| matches!(
        r.state,
        StepState::EffectSatisfied | StepState::NoOpSatisfied
    )));
}
#[test]
fn missing_one_registered_client_handoff_prevents_instance_closure() {
    let c = change();
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("ledger.sqlite")).unwrap();
    let mut op = begin(&mut store, &c);
    let time = Rc::new(Cell::new(100));
    let mut exec = driver(&c, time.clone());
    exec.binding
        .checkpoints
        .receipts
        .retain(|r| r.kind != CheckpointKind::ApplicationCutover);
    for _ in 0..5 {
        op = orchestrator::resume_with_clock(
            &mut store,
            "operation",
            op.version,
            "worker",
            &mut Time(time.clone()),
            &mut exec,
        )
        .unwrap();
        if op.state == ExecutionState::NeedsAction {
            break;
        }
    }
    assert_eq!(op.state, ExecutionState::NeedsAction);
    assert!(!exec.cloud.provider.writes.contains(&"connector-required"));
}
#[test]
fn recreated_target_blocks_sql_even_when_database_and_version_match() {
    let c = change();
    let time = Rc::new(Cell::new(100));
    let mut exec = driver(&c, time);
    let sql = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == veil_db_guard::core::capability::ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    exec.cloud.provider.instance.create_time = "2026-11-02T10:00:00Z".into();
    use veil_db_guard::core::orchestrator::StepExecutor;
    assert!(exec.preflight(&c, sql).is_err());
    assert_eq!(exec.postgres.engine.transport.writes, 0);
}

#[test]
fn native_observation_artifacts_are_manifested_and_tampering_is_detected() {
    use veil_db_guard::store::{RunStatus, RunWriter, verify_manifest};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("native-evidence");
    let config =
        veil_db_guard::gcp::config::parse_config(include_bytes!("../examples/gcp.yaml")).unwrap();
    let mut writer = RunWriter::create_for_config(
        &path,
        "billing-db",
        &config,
        "gcp-check",
        config.limits.max_bytes,
        false,
    )
    .unwrap();
    writer
        .write_json(
            "native-direct-transport.json",
            &json!({"status":"timeout","cause":"unknown"}),
        )
        .unwrap();
    writer
        .write_json(
            "probe-error.json",
            &json!({"status":"unavailable","raw_output_retained":false}),
        )
        .unwrap();
    writer.finish(RunStatus::Partial).unwrap();
    let manifest = verify_manifest(&path, config.limits.max_bytes).unwrap();
    assert_eq!(manifest.status, RunStatus::Partial);
    assert!(
        manifest
            .artifacts
            .iter()
            .any(|a| a.name == "native-direct-transport.json")
    );
    std::fs::write(path.join("native-direct-transport.json"), b"{}\n").unwrap();
    assert!(verify_manifest(&path, config.limits.max_bytes).is_err());
}

#[test]
fn native_revoke_preserves_allowed_pending_and_cancelled_query_never_restores_allow() {
    use veil_db_guard::core::lifecycle::{LifecycleKind, prepare_maintenance};
    use veil_db_guard::gcp::model::GcpAccess;
    let c = change();
    let dir = tempfile::tempdir().unwrap();
    let mut store = OperationStore::open(&dir.path().join("lifecycle.sqlite")).unwrap();
    let mut source = begin(&mut store, &c);
    let time = Rc::new(Cell::new(100));
    let mut exec = driver(&c, time.clone());
    exec.cloud.provider.direct_denied = true;
    for _ in 0..5 {
        source = orchestrator::resume_with_clock(
            &mut store,
            "operation",
            source.version,
            "worker",
            &mut Time(time.clone()),
            &mut exec,
        )
        .unwrap();
        if source.state == ExecutionState::Completed {
            break;
        }
    }
    assert_eq!(source.state, ExecutionState::Completed);
    let revoke = prepare_maintenance(
        &c,
        "operation",
        LifecycleKind::Revoke,
        "billing-access",
        &[],
        c.policy.targets.iter().flat_map(capabilities_for).collect(),
        110,
        c.limits.clone(),
        false,
    )
    .unwrap();
    let approval =
        approval::issue(&revoke, "revoke-approval", "operator", ID, 900, 1000, 110).unwrap();
    store.register_change(&revoke).unwrap();
    store.register_approval(&revoke, &approval).unwrap();
    let mut op = store
        .begin(&BeginRequest {
            request_id: "revoke-request".into(),
            operation_id: "revoke-operation".into(),
            change_hash: revoke.change_hash.clone(),
            approval_id: approval.id,
            expected_desired_head: Some(c.plan.policy_revision_hash.clone()),
            execution_identity: ID.into(),
            now: 110,
        })
        .unwrap();
    time.set(110);
    let cp = ManualCheckpoints {
        receipts: vec![
            ManualCheckpoint::attest(
                &revoke,
                "billing-db",
                CheckpointKind::ExclusiveNativeChangeWindow,
                "recovery-operator",
                110,
                600,
            )
            .unwrap(),
        ],
    };
    let mut revoke_exec = GcpProtectionExecutor {
        query_only: false,
        source: None,
        cloud: GcpExecutor::new(exec.cloud.provider, ID.into(), cp.clone()),
        postgres: PostgresStepExecutor::new(
            ID.into(),
            PostgresEngine {
                transport: FakeSql::default(),
            },
        ),
        binding: BindingStepExecutor::new(ID.into(), cp, 110),
    };
    op = orchestrator::resume_with_clock(
        &mut store,
        "revoke-operation",
        op.version,
        "worker",
        &mut Time(time.clone()),
        &mut revoke_exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(
        revoke_exec.cloud.last_revocation_evidence().unwrap().access,
        GcpAccess::Allowed
    );
    assert!(
        revoke_exec.cloud.provider.iam["bindings"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(revoke_exec.postgres.engine.transport.writes, 1);
    let count = revoke_exec.cloud.provider.writes.len();
    op = store
        .set_state(
            "revoke-operation",
            op.version,
            ExecutionState::Cancelled,
            111,
        )
        .unwrap();
    revoke_exec.cloud.provider.revocation_access = GcpAccess::Denied;
    time.set(1100);
    op = orchestrator::resume_with_clock(
        &mut store,
        "revoke-operation",
        op.version,
        "worker",
        &mut Time(time.clone()),
        &mut revoke_exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::Cancelled);
    assert_eq!(revoke_exec.cloud.provider.writes.len(), count);
    assert_eq!(revoke_exec.postgres.engine.transport.writes, 1);
    assert_eq!(
        store.desired_head(&c.policy.policy_id).unwrap(),
        Some(revoke.plan.policy_revision_hash)
    );
    let last = store.steps("revoke-operation").unwrap().pop().unwrap();
    assert_eq!(last.state, StepState::EffectSatisfied);
}
