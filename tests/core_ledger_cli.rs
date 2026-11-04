use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn command(root: &Path, args: &[&str]) -> Output {
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
        for tool in ["aws", "gcloud", "psql", "cloud-sql-proxy"] {
            let path = root.join(tool);
            fs::write(
                &path,
                "#!/bin/sh\nprintf called >> \"$VDG_TOOL_MARKER\"\nexit 97\n",
            )
            .unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
fn plan(root: &Path) -> std::path::PathBuf {
    let input = root.join("policy.yaml");
    fs::write(&input, include_str!("../examples/core-policy.yaml")).unwrap();
    let out = root.join("plan");
    let result = command(
        root,
        &["guard", "plan", "--policy", p(&input), "--out", p(&out)],
    );
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    out
}
fn approval(root: &Path, out: &Path, ledger: &Path) -> Output {
    command(
        root,
        &[
            "guard",
            "approve",
            "--plan-run",
            p(out),
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
fn begin(root: &Path, ledger: &Path, identity: &str) -> Output {
    command(
        root,
        &[
            "guard",
            "begin",
            "--ledger",
            p(ledger),
            "--approval-id",
            "approval-1",
            "--operation-id",
            "op-1",
            "--request-id",
            "request-1",
            "--execution-identity",
            identity,
        ],
    )
}
fn status(root: &Path, ledger: &Path) -> Value {
    let result = command(
        root,
        &[
            "guard",
            "status",
            "--ledger",
            p(ledger),
            "--operation",
            "op-1",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
fn separate_cli_processes_persist_approval_begin_resume_and_cancel_without_native_tools() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let out = plan(root);
    let ledger = root.join("ledger.db");
    let approved = approval(root, &out, &ledger);
    assert_eq!(
        approved.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    assert_eq!(begin(root, &ledger, "runner").status.code(), Some(3));
    let initial = status(root, &ledger);
    assert_eq!(initial["operation"]["version"], 0);
    assert_eq!(initial["operation"]["state"], "prepared");
    let resumed = command(
        root,
        &[
            "guard",
            "resume",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
        ],
    );
    assert_eq!(
        resumed.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let after = status(root, &ledger);
    assert_eq!(after["operation"]["state"], "needs_action");
    assert_eq!(after["operation"]["attempts"], 0);
    assert_eq!(after["native_dispatch_available"], false);
    let version = after["operation"]["version"].as_u64().unwrap().to_string();
    let stale = command(
        root,
        &[
            "guard",
            "resume",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
        ],
    );
    assert_eq!(stale.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&stale.stderr).contains("LEDGER_STALE"));
    assert_eq!(begin(root, &ledger, "runner").status.code(), Some(3));
    assert_eq!(
        status(root, &ledger)["operation"]["version"],
        after["operation"]["version"]
    );
    let revoked = command(
        root,
        &[
            "guard",
            "revoke-approval",
            "--ledger",
            p(&ledger),
            "--approval-id",
            "approval-1",
        ],
    );
    assert_eq!(revoked.status.code(), Some(0));
    assert_eq!(status(root, &ledger)["approval_revoked"], true);
    let cancelled = command(
        root,
        &[
            "guard",
            "cancel",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--expected-version",
            &version,
        ],
    );
    assert_eq!(cancelled.status.code(), Some(3));
    assert_eq!(status(root, &ledger)["operation"]["state"], "cancelled");
    assert!(!root.join("tool-called").exists());
}

#[test]
fn expiry_scope_and_tampered_artifacts_are_rejected_before_native_work() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let out = plan(root);
    let ledger = root.join("ledger.db");
    let expired = command(
        root,
        &[
            "guard",
            "approve",
            "--plan-run",
            p(&out),
            "--ledger",
            p(&ledger),
            "--approval-id",
            "bad",
            "--approver",
            "operator",
            "--execution-identity",
            "runner",
            "--valid-for",
            "0",
        ],
    );
    assert_eq!(expired.status.code(), Some(2));
    assert!(!ledger.exists());
    assert_eq!(approval(root, &out, &ledger).status.code(), Some(0));
    let wrong = begin(root, &ledger, "other-runner");
    assert_eq!(wrong.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("LEDGER_APPROVAL"));
    fs::write(out.join("prepared-change.json"), b"{}\n").unwrap();
    assert_eq!(approval(root, &out, &ledger).status.code(), Some(2));
    assert!(!root.join("tool-called").exists());
}

#[test]
fn status_typo_does_not_create_or_initialize_a_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.db");
    let result = command(
        dir.path(),
        &[
            "guard",
            "status",
            "--ledger",
            p(&path),
            "--operation",
            "op-1",
        ],
    );
    assert_eq!(result.status.code(), Some(2));
    assert!(!path.exists());
}

#[test]
fn explicit_native_command_cannot_contact_tools_without_opt_in() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let missing = root.join("does-not-exist.sqlite");
    let result = command(
        root,
        &[
            "guard",
            "apply-gcp",
            "--ledger",
            p(&missing),
            "--operation",
            "op-1",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
            "--native-config",
            p(&root.join("missing.json")),
        ],
    );
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("PERMISSION_REQUIRED"));
    assert!(!missing.exists());
    assert!(!root.join("tool-called").exists());
}

#[test]
fn native_principal_approval_binding_and_attestation_are_offline_and_scope_bound() {
    use veil_db_guard::{
        binding::{AppConnectionProfile, CheckpointKind, ManualCheckpoint},
        core::policy::parse_policy,
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let mut policy = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    policy.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    let input = root.join("native-policy.json");
    fs::write(&input, serde_json::to_vec(&policy).unwrap()).unwrap();
    let plan = root.join("native-plan");
    assert_eq!(
        command(
            root,
            &["guard", "plan", "--policy", p(&input), "--out", p(&plan)]
        )
        .status
        .code(),
        Some(3)
    );
    let ledger = root.join("native.sqlite");
    let identity = "gcp-service-account:runner@vdg-example-000000.iam.gserviceaccount.com:100000000000000000001";
    let approve = command(
        root,
        &[
            "guard",
            "approve",
            "--plan-run",
            p(&plan),
            "--ledger",
            p(&ledger),
            "--approval-id",
            "approval-1",
            "--approver",
            "operator",
            "--execution-identity",
            identity,
        ],
    );
    assert_eq!(
        approve.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&approve.stderr)
    );
    assert_eq!(begin(root, &ledger, identity).status.code(), Some(3));
    let binding = command(
        root,
        &[
            "guard",
            "binding",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--grant",
            "billing-access",
        ],
    );
    assert_eq!(binding.status.code(), Some(0));
    let profile: AppConnectionProfile = serde_json::from_slice(&binding.stdout).unwrap();
    assert_eq!(profile.database_identity, policy.grants[0].db_identity);
    assert_eq!(profile.workload_sources, vec!["billing-runtime"]);
    let attested = command(
        root,
        &[
            "guard",
            "attest",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--target",
            "billing-db",
            "--kind",
            "application-cutover",
            "--operator-subject",
            "recovery-operator",
        ],
    );
    assert_eq!(
        attested.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&attested.stderr)
    );
    let receipt: ManualCheckpoint = serde_json::from_slice(&attested.stdout).unwrap();
    assert_eq!(receipt.kind, CheckpointKind::ApplicationCutover);
    assert_eq!(
        receipt.application_bindings[0].connection_profile_hash,
        profile.hash()
    );
    let store = veil_db_guard::operation_store::OperationStore::open_existing(&ledger).unwrap();
    let op = store.get("op-1").unwrap();
    let change = store.load_change(&op.change_hash).unwrap();
    receipt
        .validate(&change, "billing-db", receipt.attested_at)
        .unwrap();
    assert_eq!(op.attempts, 0);
    assert_eq!(
        op.state,
        veil_db_guard::core::operation::ExecutionState::Prepared
    );
    assert!(!root.join("tool-called").exists());
}

#[test]
fn maintenance_cli_plans_new_scope_and_status_keeps_missing_effects_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let source_plan = plan(root);
    let ledger = root.join("lifecycle.sqlite");
    assert_eq!(approval(root, &source_plan, &ledger).status.code(), Some(0));
    assert_eq!(begin(root, &ledger, "runner").status.code(), Some(3));
    let out = root.join("revoke-plan");
    let result = command(
        root,
        &[
            "guard",
            "revoke",
            "--ledger",
            p(&ledger),
            "--source-operation",
            "op-1",
            "--grant",
            "billing-access",
            "--out",
            p(&out),
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let change: veil_db_guard::core::change::PreparedChange =
        serde_json::from_slice(&fs::read(out.join("prepared-change.json")).unwrap()).unwrap();
    change.verify().unwrap();
    assert_eq!(
        change.policy.grants[0].admission,
        veil_db_guard::core::policy::AdmissionIntent::Deny
    );
    let state = command(
        root,
        &[
            "guard",
            "state",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
        ],
    );
    assert_eq!(state.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&state.stdout).unwrap();
    assert_eq!(report["all_required_effects_satisfied"], false);
    let summary = status(root, &ledger);
    assert_eq!(
        summary["effective"]["all_required_effects_satisfied"],
        false
    );
    assert_eq!(summary["operation"]["attempts"], 0);
    let recover = command(
        root,
        &[
            "guard",
            "recover",
            "--ledger",
            p(&ledger),
            "--source-operation",
            "op-1",
            "--grant",
            "billing-access",
            "--out",
            p(&root.join("bad-recover")),
        ],
    );
    assert_eq!(recover.status.code(), Some(2));
    assert!(!root.join("bad-recover").exists());
    assert!(!root.join("tool-called").exists());
}

#[test]
fn aws_native_commands_require_opt_in_before_files_or_tools() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let missing = root.join("missing.sqlite");
    for args in [
        vec![
            "guard",
            "apply-aws",
            "--ledger",
            p(&missing),
            "--operation",
            "op-1",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
            "--native-config",
            p(&root.join("missing.json")),
        ],
        vec![
            "guard",
            "inspect-aws",
            "--ledger",
            p(&missing),
            "--operation",
            "op-1",
            "--execution-identity",
            "runner",
            "--native-config",
            p(&root.join("missing.json")),
            "--out",
            p(&root.join("native-inspect")),
        ],
    ] {
        let result = command(root, &args);
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("PERMISSION_REQUIRED"));
    }
    assert!(!missing.exists());
    assert!(!root.join("tool-called").exists());
    assert!(!root.join("native-inspect").exists());
}
#[test]
fn aws_plan_binding_and_preparation_declaration_are_offline() {
    use veil_db_guard::{
        binding::{AppConnectionProfile, CheckpointKind, ManualCheckpoint},
        core::policy::parse_policy,
    };
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let mut policy = parse_policy(include_str!("../examples/core-aws-policy.yaml")).unwrap();
    policy.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    let input = root.join("aws.json");
    fs::write(&input, serde_json::to_vec(&policy).unwrap()).unwrap();
    let plan = root.join("aws-plan");
    assert_eq!(
        command(
            root,
            &["guard", "plan", "--policy", p(&input), "--out", p(&plan)]
        )
        .status
        .code(),
        Some(3)
    );
    let ledger = root.join("aws.sqlite");
    assert_eq!(approval(root, &plan, &ledger).status.code(), Some(0));
    assert_eq!(begin(root, &ledger, "runner").status.code(), Some(3));
    let profile = command(
        root,
        &[
            "guard",
            "binding",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--grant",
            "billing-access",
        ],
    );
    assert_eq!(profile.status.code(), Some(0));
    let profile: AppConnectionProfile = serde_json::from_slice(&profile.stdout).unwrap();
    assert!(profile.aws.is_some());
    assert_eq!(profile.database_identity, "billing_app");
    let hash = "b".repeat(64);
    let declare = command(
        root,
        &[
            "guard",
            "attest",
            "--ledger",
            p(&ledger),
            "--operation",
            "op-1",
            "--target",
            "billing-db",
            "--kind",
            "native-preparation-ready",
            "--configuration-hash",
            &hash,
            "--operator-subject",
            "recovery-operator",
        ],
    );
    assert_eq!(
        declare.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&declare.stderr)
    );
    let record: ManualCheckpoint = serde_json::from_slice(&declare.stdout).unwrap();
    assert_eq!(record.kind, CheckpointKind::NativePreparationReady);
    assert_eq!(
        record.expected_configuration_hash.as_deref(),
        Some(hash.as_str())
    );
    assert!(!root.join("tool-called").exists());
    assert_eq!(status(root, &ledger)["operation"]["attempts"], 0);
}
