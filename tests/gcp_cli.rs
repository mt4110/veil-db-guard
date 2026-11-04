mod common;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use veil_db_guard::{
    config::hash_bytes,
    gcp::{config, model::*},
    store::{RunStatus, RunWriter},
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args(args)
        .output()
        .unwrap()
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn config_fixture() -> GcpConfig {
    serde_json::from_value(serde_json::json!({
        "schema_version":1,"target":{"project_id":"vdg-example-123456","instance_id":"vdg-db","region":"asia-northeast1","engine_version":"POSTGRES_16_15","database":"vdg_lab"},
        "principals":[{"id":"allowed","service_account":"vdg-allowed@vdg-example-123456.iam.gserviceaccount.com"},{"id":"blocked","service_account":"vdg-blocked@vdg-example-123456.iam.gserviceaccount.com"}],
        "cases":[{"id":"normal","principal_id":"allowed","route":"proxy","expected":"allow"},{"id":"refused","principal_id":"blocked","route":"proxy","expected":"deny","expected_denial":"connect_iam"}]
    })).unwrap()
}
fn snapshot(c: &GcpConfig, at: u64, blocked_roles: Vec<GcpRole>) -> GcpSnapshot {
    serde_json::from_value(serde_json::json!({
        "target":c.target,"observed_at":at,"complete":true,"engine_version":c.target.engine_version,
        "connection_name":format!("{}:{}:{}",c.target.project_id,c.target.region,c.target.instance_id),"public_ip":"198.51.100.10","ca_mode":"GOOGLE_MANAGED_INTERNAL_CA","ca_fingerprint":"a".repeat(64),
        "iam_auth_enabled":true,"connector_enforcement":"required","ssl_mode":"encrypted_only","authorized_networks":[],
        "principal_roles":[{"principal_id":"allowed","roles":["cloud_sql_client","cloud_sql_instance_user","service_usage_consumer"]},{"principal_id":"blocked","roles":blocked_roles}],"registered_principal_ids":["allowed","blocked"]
    })).unwrap()
}
fn capture(
    c: &GcpConfig,
    at: u64,
    blocked_allowed: bool,
    blocked_roles: Vec<GcpRole>,
) -> GcpRunEvidence {
    let observations = c.cases.iter().enumerate().map(|(i, case)| {
        let actor = c.principals.iter().find(|p|p.id==case.principal_id).unwrap();
        let allowed = actor.id=="allowed" || blocked_allowed;
        let proof = if allowed { GcpProof {sql_authenticated:true,sql_ok:true,db_user:Some(actor.db_user()),database:Some(c.target.database.clone()),credential_issued:true,tcp_reachable:Some(true),..Default::default()} }
            else { GcpProof {denied_permission:Some(GcpPermission::InstanceConnect),credential_issued:true,tcp_reachable:Some(true),..Default::default()} };
        serde_json::json!({"case_id":case.id,"attempt_id":format!("attempt-{i}"),"principal_id":actor.id,"route":case.route,"started_at":at+1,"finished_at":at+1,"execution":"completed","observed":if allowed{"allowed"}else{"denied"},"proof":proof})
    }).collect::<Vec<_>>();
    serde_json::from_value(serde_json::json!({"schema_version":1,"run_id":"example-run","build_id":veil_db_guard::BUILD_ID,"config_hash":config::config_hash(c),"history_compatibility_hash":config::history_compatibility_hash(c),"evidence_kind":"live","target":c.target,"started_at":at,"finished_at":at+2,"execution":"completed","before":snapshot(c,at,blocked_roles.clone()),"after":snapshot(c,at+2,blocked_roles),"observations":observations})).unwrap()
}
fn config_path(root: &Path, name: &str, c: &GcpConfig) -> std::path::PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec(c).unwrap()).unwrap();
    path
}
fn save_run(path: &Path, c: &GcpConfig, mut evidence: GcpRunEvidence, status: RunStatus) {
    let target = format!(
        "gcp-{}",
        hash_bytes(&serde_json::to_vec(&c.target).unwrap())
    );
    let mut writer =
        RunWriter::create_for_config(path, &target, c, "gcp-check", c.limits.max_bytes, false)
            .unwrap();
    writer.manifest.created_at = evidence.started_at;
    evidence.run_id = writer.manifest.run_id.clone();
    writer
        .write_json("snapshot.before.json", &evidence.before)
        .unwrap();
    writer
        .write_json("snapshot.after.json", &evidence.after)
        .unwrap();
    writer.write_json("observations.json", &evidence).unwrap();
    writer.finish(status).unwrap();
}

#[test]
fn fixture_cannot_claim_live_protection_and_offline_report_needs_no_tools() {
    let root = common::workspace();
    let c = config_fixture();
    let path = config_path(&root, "gcp.yaml", &c);
    let fixture = root.join("fixture.json");
    let sample = capture(
        &c,
        veil_db_guard::domain::now() - 5,
        false,
        vec![GcpRole::CloudSqlInstanceUser, GcpRole::ServiceUsageConsumer],
    );
    fs::write(&fixture, serde_json::to_vec(&sample).unwrap()).unwrap();
    let out = root.join("fixture-run");
    let result = cli(&[
        "gcp",
        "check",
        "--config",
        p(&path),
        "--fixture",
        p(&fixture),
        "--gcloud-bin",
        "/no/such/gcloud",
        "--proxy-bin",
        "/no/such/proxy",
        "--psql-bin",
        "/no/such/psql",
        "--out",
        p(&out),
    ]);
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stored: GcpRunEvidence =
        serde_json::from_slice(&fs::read(out.join("observations.json")).unwrap()).unwrap();
    assert_eq!(stored.evidence_kind, GcpEvidenceKind::Fixture);
    let assessment: GcpAssessment =
        serde_json::from_slice(&fs::read(out.join("assessment.json")).unwrap()).unwrap();
    assert!(!assessment.protected);
    let report = root.join("report");
    let result = cli(&[
        "gcp",
        "report",
        "--config",
        p(&path),
        "--evidence",
        p(&out),
        "--out",
        p(&report),
    ]);
    assert_eq!(result.status.code(), Some(3));
    fs::write(out.join("observations.json"), b"{}").unwrap();
    let rejected = root.join("tampered");
    let result = cli(&[
        "gcp",
        "report",
        "--config",
        p(&path),
        "--evidence",
        p(&out),
        "--out",
        p(&rejected),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!rejected.exists());
}

#[test]
fn live_permission_gate_precedes_any_output_or_external_command() {
    let root = common::workspace();
    let c = config_fixture();
    let path = config_path(&root, "gcp.yaml", &c);
    let out = root.join("never-created");
    let result = cli(&["gcp", "check", "--config", p(&path), "--out", p(&out)]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.exists());
}

#[test]
fn published_example_target_is_rejected_before_live_credentials() {
    let root = common::workspace();
    let cfg = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/gcp.yaml");
    let out = root.join("example-live");
    let result = cli(&[
        "gcp",
        "check",
        "--config",
        p(&cfg),
        "--allow-gcp-read",
        "--allow-network",
        "--gcloud-bin",
        "/not/a/tool",
        "--out",
        p(&out),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("CONFIG_INVALID"));
    assert!(!out.exists());
}

#[test]
fn malformed_fixture_values_are_not_persisted_or_echoed() {
    let root = common::workspace();
    let c = config_fixture();
    let cfg = config_path(&root, "gcp.yaml", &c);
    let mut fixture = serde_json::to_value(capture(
        &c,
        veil_db_guard::domain::now() - 5,
        false,
        vec![GcpRole::CloudSqlInstanceUser, GcpRole::ServiceUsageConsumer],
    ))
    .unwrap();
    let secret = "DUMMY_TOKEN_MUST_NOT_BE_SAVED";
    fixture["observations"][0]["proof"]["db_user"] = serde_json::json!(secret);
    let input = root.join("bad-fixture.json");
    fs::write(&input, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let out = root.join("rejected-fixture");
    let result = cli(&[
        "gcp",
        "check",
        "--config",
        p(&cfg),
        "--fixture",
        p(&input),
        "--out",
        p(&out),
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
    if out.exists() {
        for entry in fs::read_dir(out).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                assert!(!String::from_utf8_lossy(&fs::read(path).unwrap()).contains(secret));
            }
        }
    }
}

#[test]
fn incomplete_manifest_cannot_certify_completed_observations() {
    let root = common::workspace();
    let c = config_fixture();
    let path = config_path(&root, "gcp.yaml", &c);
    let source = root.join("partial");
    save_run(
        &source,
        &c,
        capture(
            &c,
            veil_db_guard::domain::now() - 5,
            false,
            vec![GcpRole::CloudSqlInstanceUser, GcpRole::ServiceUsageConsumer],
        ),
        RunStatus::Partial,
    );
    let out = root.join("report");
    let result = cli(&[
        "gcp",
        "report",
        "--config",
        p(&path),
        "--evidence",
        p(&source),
        "--out",
        p(&out),
    ]);
    assert_eq!(result.status.code(), Some(3));
    let a: GcpAssessment =
        serde_json::from_slice(&fs::read(out.join("assessment.json")).unwrap()).unwrap();
    assert!(!a.protected);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
}

#[test]
fn missing_current_capture_cannot_fall_back_to_an_older_pass() {
    let root = common::workspace();
    let c = config_fixture();
    let path = config_path(&root, "gcp.yaml", &c);
    let prior = root.join("prior");
    save_run(
        &prior,
        &c,
        capture(
            &c,
            veil_db_guard::domain::now() - 20,
            false,
            vec![GcpRole::CloudSqlInstanceUser, GcpRole::ServiceUsageConsumer],
        ),
        RunStatus::Complete,
    );
    let first = root.join("prior-report");
    let result = cli(&[
        "gcp",
        "report",
        "--config",
        p(&path),
        "--evidence",
        p(&prior),
        "--out",
        p(&first),
    ]);
    assert_eq!(result.status.code(), Some(0));
    let partial = root.join("failed-before-capture");
    let target = format!(
        "gcp-{}",
        hash_bytes(&serde_json::to_vec(&c.target).unwrap())
    );
    let mut writer = RunWriter::create_for_config(
        &partial,
        &target,
        &c,
        "gcp-check",
        c.limits.max_bytes,
        false,
    )
    .unwrap();
    // Even a failed overlapping run that started before the old run finished
    // cannot be silently discarded from explicit current inputs.
    writer.manifest.created_at = veil_db_guard::domain::now() - 25;
    writer
        .write_json(
            "operation-error.json",
            &serde_json::json!({"error":"OPERATION_FAILED"}),
        )
        .unwrap();
    writer.finish(RunStatus::Partial).unwrap();
    let out = root.join("gap-report");
    let result = cli(&[
        "gcp",
        "report",
        "--config",
        p(&path),
        "--evidence",
        p(&prior),
        p(&partial),
        "--out",
        p(&out),
    ]);
    assert_eq!(result.status.code(), Some(3));
    let a: GcpAssessment =
        serde_json::from_slice(&fs::read(out.join("assessment.json")).unwrap()).unwrap();
    assert!(!a.protected);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
}

#[test]
fn role_history_import_links_changed_config_without_hiding_current_allowed_access() {
    let root = common::workspace();
    let mut before = config_fixture();
    before.cases[1].expected_denial = Some(GcpDenial::LoginIam);
    let t = veil_db_guard::domain::now();
    let all = vec![
        GcpRole::CloudSqlClient,
        GcpRole::CloudSqlInstanceUser,
        GcpRole::ServiceUsageConsumer,
    ];
    let reduced = vec![GcpRole::CloudSqlClient, GcpRole::ServiceUsageConsumer];
    let baseline = root.join("before");
    save_run(
        &baseline,
        &before,
        capture(&before, t - 15, true, all.clone()),
        RunStatus::Complete,
    );
    let mut current = before.clone();
    current.permission_changes.push(GcpPermissionChange {
        principal_id: "blocked".into(),
        layer: GcpDenial::LoginIam,
        changed_at: t - 8,
        before_roles: all,
        after_roles: reduced.clone(),
    });
    assert_ne!(config::config_hash(&before), config::config_hash(&current));
    assert_eq!(
        config::history_compatibility_hash(&before),
        config::history_compatibility_hash(&current)
    );
    let evidence = root.join("after");
    save_run(
        &evidence,
        &current,
        capture(&current, t - 5, true, reduced),
        RunStatus::Complete,
    );
    let path = config_path(&root, "current.yaml", &current);
    let out = root.join("pending-report");
    let result = cli(&[
        "gcp",
        "report",
        "--config",
        p(&path),
        "--evidence",
        p(&evidence),
        "--history",
        p(&baseline),
        "--out",
        p(&out),
    ]);
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let a: GcpAssessment =
        serde_json::from_slice(&fs::read(out.join("assessment.json")).unwrap()).unwrap();
    let blocked = &a.cases[1];
    assert_eq!(blocked.verdict, GcpVerdict::Pending);
    assert_eq!(blocked.observed, GcpAccess::Allowed);
    assert!(!blocked.protected);
    assert!(!a.protected);
    let text = fs::read_to_string(out.join("report.md")).unwrap();
    assert!(text.contains("反映確認待ち") && text.contains("現在は接続できる"));
}
