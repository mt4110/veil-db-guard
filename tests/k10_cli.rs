//! New source contracts must stop before native configuration/tool lookup.
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use veil_db_guard::{
    adapters::capabilities_for_policy,
    core::{
        approval,
        change::{OperationLimits, prepare_change},
        operation::BeginRequest,
        plan::build_plan,
        policy::parse_policy,
    },
    operation_store::OperationStore,
};

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
        for name in [
            "gcloud",
            "aws",
            "ssh",
            "curl",
            "psql",
            "mysql",
            "cloud-sql-proxy",
        ] {
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
fn assert_blocked(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("INTENT_NOT_QUALIFIED"));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["native_dispatch_available"], false);
    assert_eq!(json["protection_evaluated"], false);
    assert!(
        json["intent_qualification"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["reason"] == "contract_mismatch")
    );
}

#[test]
fn v3_plan_is_reviewable_and_approval_does_not_claim_source_verification_or_call_tools() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let policy = root.join("policy.yaml");
    let run = root.join("plan");
    let ledger = root.join("must-not-exist.sqlite");
    fs::write(&policy, include_str!("../examples/core-policy-v2.yaml")).unwrap();
    let output = cli(
        root,
        &["guard", "plan", "--policy", p(&policy), "--out", p(&run)],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("static_qualified=true"));
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("prepared-change.json")).unwrap()).unwrap();
    assert_eq!(saved["policy"]["schema_version"], 2);
    assert_eq!(
        saved["policy"]["source_bindings"].as_array().unwrap().len(),
        2
    );
    let approved = cli(
        root,
        &[
            "guard",
            "approve",
            "--plan-run",
            p(&run),
            "--ledger",
            p(&ledger),
            "--approval-id",
            "approval-1",
            "--approver",
            "reviewer",
            "--execution-identity",
            "runner",
        ],
    );
    assert_eq!(
        approved.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    assert!(ledger.exists());
    assert!(!root.join("tool-called").exists());
}

#[test]
fn library_created_v2_approval_cannot_bypass_native_gate_and_leaves_operation_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut policy = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
    policy.targets[0].resource.generation_fingerprint = Some("c".repeat(64));
    for (i, subject) in policy.subjects.iter_mut().enumerate() {
        subject.identity.immutable_id = Some(format!("{}", i + 1));
    }
    let mut capabilities = capabilities_for_policy(&policy).unwrap();
    // Persist the OLD evaluation-only contract with a forged implementation
    // verdict. Updating the executable registry must not enable this approval.
    for capability in &mut capabilities {
        capability.implementation = veil_db_guard::core::capability::Implementation::Implemented;
        capability.contract_revision =
            if veil_db_guard::core::capability::requires_source_evidence(capability.action) {
                veil_db_guard::core::evidence::SOURCE_BOUND_ADAPTER_CONTRACT
            } else {
                "core-adapter-v2"
            }
            .into();
    }
    let plan = build_plan(&policy, capabilities, vec![], at).unwrap();
    let change = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
    let a = approval::issue(
        &change,
        "approval-1",
        "reviewer",
        "runner",
        at + 300,
        at + 900,
        at,
    )
    .unwrap();
    let path = root.join("library.sqlite");
    let mut store = OperationStore::open(&path).unwrap();
    store.register_change(&change).unwrap();
    store.register_approval(&change, &a).unwrap();
    store
        .begin(&BeginRequest {
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
            change_hash: change.change_hash.clone(),
            approval_id: a.id,
            expected_desired_head: None,
            execution_identity: "runner".into(),
            now: at,
        })
        .unwrap();
    let before = store.get("operation-1").unwrap();
    let steps = store.steps("operation-1").unwrap();
    drop(store);
    let absent = root.join("missing-native-config.json");
    for command in ["apply-gcp", "apply-aws"] {
        assert_blocked(cli(
            root,
            &[
                "guard",
                command,
                "--ledger",
                p(&path),
                "--operation",
                "operation-1",
                "--expected-version",
                "0",
                "--execution-identity",
                "runner",
                "--native-config",
                p(&absent),
                "--allow-native-changes",
            ],
        ));
    }
    let after = OperationStore::open_existing(&path).unwrap();
    assert_eq!(after.get("operation-1").unwrap(), before);
    assert_eq!(after.steps("operation-1").unwrap(), steps);
    assert!(!root.join("tool-called").exists());
}

#[test]
fn executable_v3_without_source_archive_stops_before_native_config_and_tools() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    traps(root);
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut p2 = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
    p2.targets[0].resource.generation_fingerprint = Some("c".repeat(64));
    for (i, s) in p2.subjects.iter_mut().enumerate() {
        s.identity.immutable_id = Some(format!("{}", i + 1));
    }
    let plan = build_plan(&p2, capabilities_for_policy(&p2).unwrap(), vec![], at).unwrap();
    let change = prepare_change(&p2, &plan, &[], None, OperationLimits::default()).unwrap();
    assert!(
        veil_db_guard::adapters::qualification::qualify_change(&change)
            .unwrap()
            .is_dispatch_qualified()
    );
    let approval = approval::issue(
        &change,
        "v3-approval",
        "reviewer",
        "runner",
        at + 300,
        at + 900,
        at,
    )
    .unwrap();
    let path = root.join("v3.sqlite");
    let mut store = OperationStore::open(&path).unwrap();
    store.register_change(&change).unwrap();
    store.register_approval(&change, &approval).unwrap();
    let op = store
        .begin(&BeginRequest {
            request_id: "v3-request".into(),
            operation_id: "v3-operation".into(),
            change_hash: change.change_hash.clone(),
            approval_id: approval.id,
            expected_desired_head: None,
            execution_identity: "runner".into(),
            now: at,
        })
        .unwrap();
    let steps = store.steps(&op.id).unwrap();
    drop(store);
    let output = cli(
        root,
        &[
            "guard",
            "apply-gcp",
            "--ledger",
            p(&path),
            "--operation",
            &op.id,
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
            "--native-config",
            p(&root.join("absent-native.json")),
            "--allow-native-changes",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("SOURCE_EVIDENCE_NOT_READY"));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["reason"], "source_archive_required");
    assert_eq!(result["native_dispatch_available"], false);
    assert!(!root.join("tool-called").exists());
    let store = OperationStore::open_existing(&path).unwrap();
    assert_eq!(store.get(&op.id).unwrap(), op);
    assert_eq!(store.steps(&op.id).unwrap(), steps);
}
