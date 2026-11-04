//! Offline handoff command; trap provider executables to detect accidental IO.
use std::{fs, path::Path, process::Command};
use veil_db_guard::{
    adapters::capabilities_for_policy,
    core::{
        change::{OperationLimits, prepare_change},
        plan::build_plan,
        policy::*,
    },
    store::{RunStatus, RunWriter},
};
fn plan(root: &Path) -> std::path::PathBuf {
    let mut p = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
    p.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    let graph = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
    let change = prepare_change(&p, &graph, &[], None, OperationLimits::default()).unwrap();
    let out = root.join("plan");
    let mut run =
        RunWriter::create_for_config(&out, &p.policy_id, &p, "guard-plan", 8 * 1024 * 1024, true)
            .unwrap();
    run.write_json("prepared-change.json", &change).unwrap();
    run.write_json("plan.json", &change.plan).unwrap();
    run.finish(RunStatus::Complete).unwrap();
    out
}
#[test]
fn handoff_emits_runtime_work_with_unknown_protection_and_never_calls_native_tools() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in [
            "aws",
            "gcloud",
            "ssh",
            "curl",
            "psql",
            "mysql",
            "cloud-sql-proxy",
        ] {
            let p = root.join(name);
            fs::write(&p, "#!/bin/sh\nprintf called >> \"$MARKER\"\nexit 99\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let plan = plan(root);
    let out = root.join("handoff");
    let result = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args([
            "guard",
            "k11-readiness",
            "--plan-run",
            plan.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .env_clear()
        .env("PATH", root)
        .env("MARKER", root.join("native-called"))
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(v["handoff"]["k11_implementation_can_start"], true);
    assert_eq!(v["handoff"]["all_required_effects_satisfied"], false);
    assert_eq!(v["handoff"]["native_dispatch_available"], false);
    assert!(
        !v["handoff"]["runtime_requirements"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(out.join("k11-handoff.json").is_file());
    assert!(!root.join("native-called").exists());
    assert!(!root.join("ledger.sqlite").exists());
    let denied_ledger = root.join("must-not-create.sqlite");
    let reject = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args([
            "guard",
            "approve",
            "--plan-run",
            out.to_str().unwrap(),
            "--ledger",
            denied_ledger.to_str().unwrap(),
            "--approval-id",
            "handoff-is-not-approval",
            "--approver",
            "operator",
            "--execution-identity",
            "runner",
        ])
        .env_clear()
        .env("PATH", root)
        .output()
        .unwrap();
    assert_eq!(reject.status.code(), Some(2));
    assert!(!denied_ledger.exists());
}
#[test]
fn incomplete_optional_ledger_inputs_are_rejected_before_output_or_creation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let plan = plan(root);
    let out = root.join("out");
    let ledger = root.join("missing.sqlite");
    let result = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args([
            "guard",
            "k11-readiness",
            "--plan-run",
            plan.to_str().unwrap(),
            "--ledger",
            ledger.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.exists());
    assert!(!ledger.exists());
}
