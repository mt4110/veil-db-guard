use std::{fs, path::Path, process::Command};
use veil_db_guard::{config::hash_bytes, core::plan::ChangePlan, store};

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args(args)
        .output()
        .unwrap()
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn guard_plan_is_offline_private_new_run_and_never_a_protection_pass() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("policy.yaml");
    let out = dir.path().join("plan");
    fs::write(&input, include_str!("../examples/core-policy.yaml")).unwrap();
    let marker = dir.path().join("unexpected-tool-call");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for tool in ["gcloud", "aws", "psql", "cloud-sql-proxy"] {
            let stub = dir.path().join(tool);
            fs::write(
                &stub,
                "#!/bin/sh\nprintf called >> \"$VDG_TOOL_MARKER\"\nexit 97\n",
            )
            .unwrap();
            fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let result = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args(["guard", "plan", "--policy", p(&input), "--out", p(&out)])
        .env("PATH", dir.path())
        .env("VDG_TOOL_MARKER", &marker)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("execution_available=false"));
    assert!(!marker.exists());
    let manifest = store::verify_manifest(&out, 8 * 1024 * 1024).unwrap();
    assert_eq!(manifest.operation, "guard-plan");
    assert!(manifest.operation_only);
    let plan: ChangePlan =
        store::read_artifact(&out, &manifest, "plan.json", 8 * 1024 * 1024).unwrap();
    assert!(!plan.execution_available && !plan.protection_evaluated);
    let normalized = fs::read(out.join("config.normalized.json")).unwrap();
    let parsed: veil_db_guard::core::policy::PolicyRevision =
        serde_json::from_slice(&normalized).unwrap();
    assert_eq!(
        manifest.config_hash,
        hash_bytes(&serde_json::to_vec(&parsed).unwrap_or_default())
    );
    // The semantic revision digest is separately versioned; neither is a signature.
    assert_ne!(manifest.config_hash, plan.policy_revision_hash);
    let original = fs::read(out.join("manifest.json")).unwrap();
    let repeat = cli(&["guard", "plan", "--policy", p(&input), "--out", p(&out)]);
    assert_eq!(repeat.status.code(), Some(2));
    assert_eq!(fs::read(out.join("manifest.json")).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(out.join("plan.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn malformed_or_secret_fields_do_not_echo_or_create_output() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("policy.yaml");
    let out = dir.path().join("plan");
    let sentinel = "not-a-real-token-SENTINEL";
    fs::write(
        &input,
        format!(
            "{}\npassword: {sentinel}\n",
            include_str!("../examples/core-policy.yaml")
        ),
    )
    .unwrap();
    let result = cli(&["guard", "plan", "--policy", p(&input), "--out", p(&out)]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(sentinel));
    assert!(!String::from_utf8_lossy(&result.stdout).contains(sentinel));
    assert!(!out.exists());
}

#[test]
fn evidence_target_must_be_explicit_before_import() {
    let result = cli(&[
        "guard",
        "plan",
        "--policy",
        "unused",
        "--out",
        "unused",
        "--evidence",
        "unused",
    ]);
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn imported_observation_ref_resolves_to_the_saved_artifact() {
    use veil_db_guard::{
        core::policy::parse_policy,
        gcp::config,
        store::{RunStatus, RunWriter},
    };
    let dir = tempfile::tempdir().unwrap();
    let mut observer = config::parse_config(include_bytes!("../examples/gcp.yaml")).unwrap();
    observer.target.instance_id = "billing-postgres".into();
    observer.target.database = "billing".into();
    let source = dir.path().join("source");
    let target_id = format!(
        "gcp-{}",
        hash_bytes(&serde_json::to_vec(&observer.target).unwrap())
    );
    let mut capture = RunWriter::create_for_config(
        &source,
        &target_id,
        &observer,
        "gcp-check",
        8 * 1024 * 1024,
        false,
    )
    .unwrap();
    capture.finish(RunStatus::Partial).unwrap();
    let input = dir.path().join("policy.json");
    let policy = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    fs::write(&input, serde_json::to_vec(&policy).unwrap()).unwrap();
    let out = dir.path().join("plan");
    let result = cli(&[
        "guard",
        "plan",
        "--policy",
        p(&input),
        "--out",
        p(&out),
        "--evidence",
        p(&source),
        "--evidence-target",
        "billing-db",
    ]);
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest = store::verify_manifest(&out, 8 * 1024 * 1024).unwrap();
    let plan: ChangePlan =
        store::read_artifact(&out, &manifest, "plan.json", 8 * 1024 * 1024).unwrap();
    let snapshot_hash = &manifest
        .artifacts
        .iter()
        .find(|a| a.name == "snapshot.json")
        .unwrap()
        .sha256;
    assert_eq!(plan.observation_refs, vec![snapshot_hash.clone()]);
    assert!(!plan.execution_available && !plan.protection_evaluated);
    assert!(store::verify_run(&out, 8 * 1024 * 1024).is_err());
    assert_eq!(
        store::verify_manifest(&source, 8 * 1024 * 1024)
            .unwrap()
            .status,
        RunStatus::Partial
    );
}
