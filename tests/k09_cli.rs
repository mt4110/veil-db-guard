//! Offline process boundaries and upgrade gates. All provider executables are
//! replaced by local traps; no cloud account, network or database is used.
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use veil_db_guard::{
    adapters::capabilities_for,
    core::{
        approval,
        change::{OperationLimits, PreparedChange, prepare_change},
        operation::BeginRequest,
        plan::build_plan,
        policy::{ManagedField, PolicyRevision, SqlAction, SqlObjectKind, parse_policy},
    },
    operation_store::OperationStore,
    store,
};

const CASES: &[(&str, &str)] = &[
    ("gcp", include_str!("../examples/core-policy.yaml")),
    ("aws-pg", include_str!("../examples/core-aws-policy.yaml")),
    (
        "aws-mysql",
        include_str!("../examples/core-aws-mysql-policy.yaml"),
    ),
];
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args(args)
        .env("PATH", root)
        .env("VDG_TOOL_MARKER", root.join("tool-called"))
        .output()
        .unwrap()
}
fn traps(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["aws", "gcloud", "curl", "psql", "mysql", "cloud-sql-proxy"] {
            let path = root.join(name);
            fs::write(
                &path,
                "#!/bin/sh\nprintf called >> \"$VDG_TOOL_MARKER\"\nexit 97\n",
            )
            .unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
fn unsupported(case: &str, source: &str) -> PolicyRevision {
    let mut policy = parse_policy(source).unwrap();
    if case == "aws-mysql" {
        policy.grants[0]
            .sql_access
            .existing_roles
            .push("billing-reader-writer".into());
        policy.targets[0]
            .managed_surface
            .fields
            .push(ManagedField::DbRole);
        policy.targets[0]
            .managed_surface
            .db_identities
            .push("billing-reader-writer".into());
    } else {
        let privilege = &mut policy.grants[0].sql_access.privileges[0];
        privilege.scope.kind = SqlObjectKind::Routine;
        privilege.scope.object = Some("calculate_invoice".into());
        privilege.actions = vec![SqlAction::Execute];
    }
    policy.validate().unwrap();
    policy
}
fn plan(root: &Path, policy: &PolicyRevision) -> std::path::PathBuf {
    let input = root.join("policy.json");
    let output = root.join("plan");
    fs::write(&input, serde_json::to_vec(policy).unwrap()).unwrap();
    let result = cli(
        root,
        &["guard", "plan", "--policy", p(&input), "--out", p(&output)],
    );
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("static_qualified=false"));
    output
}
fn approve(root: &Path, run: &Path, ledger: &Path) -> Output {
    cli(
        root,
        &[
            "guard",
            "approve",
            "--plan-run",
            p(run),
            "--ledger",
            p(ledger),
            "--approval-id",
            "approval-1",
            "--approver",
            "operator",
            "--execution-identity",
            "runner",
        ],
    )
}
fn report(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("INTENT_NOT_QUALIFIED"));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["native_dispatch_available"], false);
    assert_eq!(value["protection_evaluated"], false);
    value["intent_qualification"].clone()
}

#[test]
fn unsupported_intents_are_saved_with_exact_scope_but_cannot_create_an_approval_ledger() {
    for &(case, source) in CASES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        traps(root);
        let policy = unsupported(case, source);
        let run = plan(root, &policy);
        let manifest = store::verify_manifest(&run, 8 * 1024 * 1024).unwrap();
        let saved: Value = store::read_artifact(
            &run,
            &manifest,
            "intent-qualification.json",
            8 * 1024 * 1024,
        )
        .unwrap();
        assert_eq!(saved["readiness_only"], true);
        assert_eq!(saved["runtime_verified"], false);
        let scope_kind = if case == "aws-mysql" {
            "existing_roles"
        } else {
            "sql_scope"
        };
        let finding = saved["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| {
                f["disposition"] == "unsupported"
                    && f["target_id"] == "billing-db"
                    && f["grant_id"] == "billing-access"
                    && f["scope"]["kind"] == scope_kind
            })
            .unwrap_or_else(|| panic!("{case}: missing scoped finding: {saved}"));
        if case != "aws-mysql" {
            assert_eq!(finding["scope"]["scope"]["object"], "calculate_invoice");
            assert_eq!(finding["action"], "configure_sql_privileges");
        }
        let ledger = root.join("must-not-exist.sqlite");
        assert_eq!(report(&approve(root, &run, &ledger)), saved);
        assert!(
            !ledger.exists(),
            "{case}: unsupported intent created a ledger"
        );
        assert!(!root.join("tool-called").exists());
    }
}

fn legacy_operation(root: &Path, policy: &PolicyRevision) -> (std::path::PathBuf, PreparedChange) {
    // Simulate a pre-K09 local approval: core integrity/approval APIs remain
    // independent of adapters and therefore do not perform qualification.
    let at = veil_db_guard::domain::now();
    let graph = build_plan(
        policy,
        policy.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        at,
    )
    .unwrap();
    let change = prepare_change(policy, &graph, &[], None, OperationLimits::default()).unwrap();
    let grant = approval::issue(
        &change,
        "approval-1",
        "operator",
        "runner",
        at + 300,
        at + 900,
        at,
    )
    .unwrap();
    let path = root.join("legacy.sqlite");
    let mut ledger = OperationStore::open(&path).unwrap();
    ledger.register_change(&change).unwrap();
    ledger.register_approval(&change, &grant).unwrap();
    ledger
        .begin(&BeginRequest {
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
            change_hash: change.change_hash.clone(),
            approval_id: grant.id,
            expected_desired_head: None,
            execution_identity: "runner".into(),
            now: at,
        })
        .unwrap();
    (path, change)
}

#[test]
fn legacy_approved_intent_is_requalified_before_native_paths_or_tools_and_opt_in_still_comes_first()
{
    for &(case, source) in CASES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        traps(root);
        let policy = unsupported(case, source);
        let (path, _) = legacy_operation(root, &policy);
        let ledger = OperationStore::open_existing(&path).unwrap();
        let before = ledger.get("operation-1").unwrap();
        let before_steps = ledger.steps("operation-1").unwrap();
        drop(ledger);
        let missing_config = root.join("missing-native.json");
        let missing_ownership = root.join("missing-ownership");
        let missing_checkpoint = root.join("missing-checkpoint.json");
        let mut args = vec![
            "guard",
            if case == "gcp" {
                "apply-gcp"
            } else {
                "apply-aws"
            },
            "--ledger",
            p(&path),
            "--operation",
            "operation-1",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
            "--native-config",
            p(&missing_config),
            "--ownership-run",
            p(&missing_ownership),
            "--checkpoint",
            p(&missing_checkpoint),
        ];
        let denied = cli(root, &args);
        assert_eq!(denied.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&denied.stderr).contains("PERMISSION_REQUIRED"));
        args.push("--allow-native-changes");
        let qualification = report(&cli(root, &args));
        assert!(
            qualification["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["disposition"] == "unsupported")
        );
        let after = OperationStore::open_existing(&path).unwrap();
        assert_eq!(after.get("operation-1").unwrap(), before);
        assert_eq!(after.steps("operation-1").unwrap(), before_steps);
        assert!(
            !root.join("tool-called").exists(),
            "{case}: native executable invoked"
        );
    }
}

#[test]
fn a_forged_positive_report_does_not_authorize_approval_or_legacy_begin() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let policy = unsupported(CASES[0].0, CASES[0].1);
    let (legacy, change) = legacy_operation(root, &policy);
    let run = root.join("forged-report-plan");
    let mut writer = store::RunWriter::create_for_config(
        &run,
        &policy.policy_id,
        &policy,
        "guard-plan",
        8 * 1024 * 1024,
        true,
    )
    .unwrap();
    writer.write_json("plan.json", &change.plan).unwrap();
    writer.write_json("prepared-change.json", &change).unwrap();
    writer
        .write_json(
            "intent-qualification.json",
            &serde_json::json!({
                "schema_version":1,"policy_revision_hash":change.plan.policy_revision_hash,
                "change_hash":change.change_hash,"readiness_only":true,"runtime_verified":false,
                "findings":[]
            }),
        )
        .unwrap();
    writer.finish(store::RunStatus::Complete).unwrap();
    let target = root.join("must-not-exist.sqlite");
    let recomputed = report(&approve(root, &run, &target));
    assert!(
        recomputed["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["disposition"] == "unsupported")
    );
    assert!(!target.exists());
    let begin = cli(
        root,
        &[
            "guard",
            "begin",
            "--ledger",
            p(&legacy),
            "--approval-id",
            "approval-1",
            "--operation-id",
            "operation-1",
            "--request-id",
            "request-1",
            "--execution-identity",
            "runner",
        ],
    );
    assert_eq!(report(&begin), recomputed);
    assert!(!root.join("tool-called").exists());
}

#[test]
fn missing_pinned_references_block_native_configuration_lookup_without_claiming_static_unsupported()
{
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let policy = parse_policy(CASES[0].1).unwrap();
    let (path, _) = legacy_operation(root, &policy);
    let missing = root.join("must-not-be-read-native.json");
    let output = cli(
        root,
        &[
            "guard",
            "apply-gcp",
            "--ledger",
            p(&path),
            "--operation",
            "operation-1",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
            "--native-config",
            p(&missing),
            "--allow-native-changes",
        ],
    );
    let report = report(&output);
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .all(|f| f["disposition"] == "runtime_prerequisite")
    );
    assert!(
        findings
            .iter()
            .any(|f| f["reason"] == "identity_reference_required")
    );
    assert!(
        findings
            .iter()
            .any(|f| f["reason"] == "target_generation_reference_required")
    );
    assert_eq!(
        OperationStore::open_existing(&path)
            .unwrap()
            .get("operation-1")
            .unwrap()
            .attempts,
        0
    );
    assert!(!root.join("tool-called").exists());
}

#[test]
fn recorded_completion_needs_no_native_config_and_cannot_claim_current_protection() {
    use veil_db_guard::core::operation::{EffectState, ExecutionState, StepReceipt, StepState};
    for &(case, source) in CASES {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        traps(root);
        // Trusted local receipts simulate historical completion; they provide no
        // current native evidence, and current code rejects this old SQL intent.
        let (path, change) = legacy_operation(root, &unsupported(case, source));
        let mut ledger = OperationStore::open_existing(&path).unwrap();
        let mut op = ledger.get("operation-1").unwrap();
        let at = veil_db_guard::domain::now();
        let lease = ledger
            .acquire_leases(&op.id, "legacy-worker", at, 30)
            .unwrap();
        for step in &change.plan.steps {
            let ticket = ledger
                .dispatch(&op.id, &step.id, op.version, &lease, "runner", at)
                .unwrap();
            op = ledger
                .record_receipt(
                    &ticket,
                    &StepReceipt {
                        state: StepState::EffectSatisfied,
                        effect: EffectState::Enforced,
                        native_operation_ref: None,
                        evidence_refs: vec![],
                    },
                    at,
                )
                .unwrap();
        }
        let completed = ledger
            .set_state(&op.id, op.version, ExecutionState::Completed, at)
            .unwrap();
        ledger.release_leases(&lease).unwrap();
        drop(ledger);
        let version = completed.version.to_string();
        let missing = root.join("must-not-be-read-native.json");
        let output = cli(
            root,
            &[
                "guard",
                if case == "gcp" {
                    "apply-gcp"
                } else {
                    "apply-aws"
                },
                "--ledger",
                p(&path),
                "--operation",
                "operation-1",
                "--expected-version",
                &version,
                "--execution-identity",
                "runner",
                "--native-config",
                p(&missing),
                "--allow-native-changes",
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["operation_scope_completed"], true);
        assert_eq!(value["protection_evaluated"], false);
        assert_eq!(value["current_protection_rechecked"], false);
        assert_eq!(value["native_queries_performed"], false);
        assert_eq!(value["forward_dispatch_blocked"], true);
        assert!(!root.join("tool-called").exists());
    }
}

mod composed_gate {
    use super::*;
    use veil_db_guard::{
        adapters::{
            deployment::gcp::*,
            engine::postgres::{
                PgError, PgOutcome, PgTransport, PostgresEngine, PostgresStepExecutor, SqlBatch,
            },
            executor::GcpProtectionExecutor,
        },
        binding::{BindingStepExecutor, ManualCheckpoints},
        core::{
            capability::ActionKind,
            operation::{EffectState, StepReceipt, StepState},
            orchestrator::{self, ExecutorError, StepExecutor},
            policy::Target,
        },
    };

    // Reads are counted, and every mutation panics. The pending request is an
    // already accepted operation, independent of unsupported later SQL intent.
    struct ReadOnlyCloud {
        reads: usize,
        queries: usize,
        done: bool,
    }
    impl CloudSqlProvider for ReadOnlyCloud {
        fn execution_identity(&mut self) -> Result<String, ProviderError> {
            self.reads += 1;
            Ok("runner".into())
        }
        fn instance(&mut self, _: &Target) -> Result<CloudSqlInstance, ProviderError> {
            self.reads += 1;
            Ok(CloudSqlInstance {
                project: "vdg-example-000000".into(),
                name: "billing-postgres".into(),
                region: "asia-northeast1".into(),
                create_time: "2026-11-01T10:00:00Z".into(),
                installed_version: "POSTGRES_16_15".into(),
                settings_version: "1".into(),
                database_flags: vec![DatabaseFlag {
                    name: "cloudsql.iam_authentication".into(),
                    value: "on".into(),
                }],
                connector_required: false,
                runnable: true,
            })
        }
        fn service_account_id(&mut self, _: &str) -> Result<String, ProviderError> {
            self.reads += 1;
            Ok("100000000000000000001".into())
        }
        fn iam_policy(&mut self, _: &str) -> Result<Value, ProviderError> {
            panic!("qualification gate allowed later identity read")
        }
        fn set_iam_policy(&mut self, _: &str, _: &Value) -> Result<(), ProviderError> {
            panic!("unexpected IAM mutation")
        }
        fn users(&mut self, _: &Target) -> Result<Vec<CloudSqlUser>, ProviderError> {
            panic!("unexpected users read")
        }
        fn patch(
            &mut self,
            _: &Target,
            _: &CloudSqlInstance,
            _: NativePatch,
        ) -> Result<NativeOperation, ProviderError> {
            panic!("unexpected instance mutation")
        }
        fn register_user(&mut self, _: &Target, _: &str) -> Result<NativeOperation, ProviderError> {
            panic!("unexpected DB login mutation")
        }
        fn operation(&mut self, _: &Target, _: &str) -> Result<NativeOperation, ProviderError> {
            self.reads += 1;
            self.queries += 1;
            Ok(NativeOperation {
                name: "native-one".into(),
                project: "vdg-example-000000".into(),
                instance: "billing-postgres".into(),
                done: self.done,
                failed: false,
            })
        }
    }
    struct NoSql;
    impl PgTransport for NoSql {
        fn preflight(&mut self, _: &SqlBatch) -> Result<(), PgError> {
            panic!("unexpected SQL preflight")
        }
        fn execute_atomic(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
            panic!("unexpected SQL write")
        }
        fn query(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
            panic!("unexpected SQL query")
        }
    }
    fn executor(done: bool) -> GcpProtectionExecutor<ReadOnlyCloud, ManualCheckpoints, NoSql> {
        GcpProtectionExecutor {
            query_only: false,
            source: None,
            cloud: GcpExecutor::new(
                ReadOnlyCloud {
                    reads: 0,
                    queries: 0,
                    done,
                },
                "runner".into(),
                ManualCheckpoints::default(),
            ),
            postgres: PostgresStepExecutor::new(
                "runner".into(),
                PostgresEngine { transport: NoSql },
            ),
            binding: BindingStepExecutor::new(
                "runner".into(),
                ManualCheckpoints::default(),
                veil_db_guard::domain::now(),
            ),
        }
    }
    fn policy() -> PolicyRevision {
        let mut policy = unsupported(CASES[0].0, CASES[0].1);
        policy.subjects[0].identity.immutable_id = Some("100000000000000000001".into());
        policy.subjects[1].identity.immutable_id = Some("100000000000000000002".into());
        policy.targets[0].resource.generation_fingerprint = Some(generation_fingerprint(
            "vdg-example-000000",
            "billing-postgres",
            "2026-11-01T10:00:00Z",
        ));
        policy
    }

    #[test]
    fn composite_gate_stops_the_first_native_step_before_reads_and_direct_submit() {
        let dir = tempfile::tempdir().unwrap();
        let (path, change) = legacy_operation(dir.path(), &policy());
        let mut ledger = OperationStore::open_existing(&path).unwrap();
        let op = ledger.get("operation-1").unwrap();
        let step = change
            .plan
            .steps
            .iter()
            .find(|s| s.action == ActionKind::PrepareNativeRoute)
            .unwrap();
        let mut executor = executor(false);
        assert!(!executor.available(&change, step));
        assert_eq!(
            executor.preflight(&change, step),
            Err(ExecutorError::Unavailable)
        );
        let at = veil_db_guard::domain::now();
        let lease = ledger
            .acquire_leases(&op.id, "legacy-worker", at, 30)
            .unwrap();
        let ticket = ledger
            .dispatch(&op.id, &step.id, op.version, &lease, "runner", at)
            .unwrap();
        assert!(executor.submit(&change, step, &ticket).is_err());
        assert_eq!(executor.cloud.provider.reads, 0);
    }

    #[test]
    fn accepted_or_unknown_native_request_can_be_read_back_without_unlocking_later_writes() {
        for state in [StepState::Submitted, StepState::OutcomeUnknown] {
            for done in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let (path, change) = legacy_operation(dir.path(), &policy());
                let mut ledger = OperationStore::open_existing(&path).unwrap();
                let op = ledger.get("operation-1").unwrap();
                let step = change
                    .plan
                    .steps
                    .iter()
                    .find(|s| s.action == ActionKind::PrepareNativeRoute)
                    .unwrap();
                let at = veil_db_guard::domain::now();
                let lease = ledger
                    .acquire_leases(&op.id, "legacy-worker", at, 30)
                    .unwrap();
                let ticket = ledger
                    .dispatch(&op.id, &step.id, op.version, &lease, "runner", at)
                    .unwrap();
                let pending = ledger
                    .record_receipt(
                        &ticket,
                        &StepReceipt {
                            state,
                            effect: if state == StepState::OutcomeUnknown {
                                EffectState::Unknown
                            } else {
                                EffectState::Pending
                            },
                            native_operation_ref: Some("native-one".into()),
                            evidence_refs: vec![],
                        },
                        at,
                    )
                    .unwrap();
                ledger.release_leases(&lease).unwrap();
                let mut executor = executor(done);
                let after = orchestrator::resume(
                    &mut ledger,
                    &op.id,
                    pending.version,
                    "new-worker",
                    &mut executor,
                )
                .unwrap();
                assert_eq!(
                    executor.cloud.provider.queries, 1,
                    "accepted query blocked: {state:?}, done={done}"
                );
                assert_eq!(after.attempts, 1, "a new native step was dispatched");
                let recorded = ledger
                    .steps(&op.id)
                    .unwrap()
                    .into_iter()
                    .find(|r| r.step_id == step.id)
                    .unwrap();
                assert_eq!(
                    recorded.state,
                    if done {
                        StepState::EffectSatisfied
                    } else {
                        StepState::Submitted
                    }
                );
            }
        }
    }
}
