//! All captures here are synthetic local records, including records whose origin
//! is labelled Live to test provenance handling. No cloud or DB is contacted.
use std::path::PathBuf;
use veil_db_guard::{
    adapters::{capabilities_for, state::evaluate_run},
    config::{GuardError, hash_bytes},
    core::{
        change::{OperationLimits, PreparedChange, prepare_change},
        plan::build_plan,
        policy::parse_policy,
        state::{StateAssessment, StateEffect, StateReason, StateValue},
    },
    gcp::{config, model::*},
    store::{RunStatus, RunWriter},
};

fn change() -> PreparedChange {
    let mut p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    p.targets[0].resource.generation_fingerprint = Some("c".repeat(64));
    let plan = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        90,
    )
    .unwrap();
    prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn config() -> GcpConfig {
    serde_json::from_value(serde_json::json!({
        "schema_version":1,
        "target":{"project_id":"vdg-example-000000","instance_id":"billing-postgres",
            "region":"asia-northeast1","engine_version":"POSTGRES_16_15","database":"billing"},
        "principals":[{"id":"app","service_account":"billing-app@vdg-example-000000.iam.gserviceaccount.com"}],
        "cases":[{"id":"normal","principal_id":"app","route":"proxy","expected":"allow"},
            {"id":"direct","principal_id":"app","route":"direct","expected":"deny","expected_denial":"network_blocked"}]
    })).unwrap()
}
fn snapshot(c: &GcpConfig, at: u64) -> GcpSnapshot {
    serde_json::from_value(serde_json::json!({
        "target":c.target,"observed_at":at,"complete":true,"engine_version":c.target.engine_version,
        "connection_name":format!("{}:{}:{}",c.target.project_id,c.target.region,c.target.instance_id),
        "public_ip":"198.51.100.10","ca_mode":"GOOGLE_MANAGED_INTERNAL_CA","ca_fingerprint":"a".repeat(64),
        "iam_auth_enabled":true,"connector_enforcement":"required","ssl_mode":"encrypted_only",
        "authorized_networks":[],"principal_roles":[{"principal_id":"app","roles":["cloud_sql_client","cloud_sql_instance_user","service_usage_consumer"]}],
        "registered_principal_ids":["app"]
    })).unwrap()
}
fn capture(c: &GcpConfig, kind: GcpEvidenceKind) -> GcpRunEvidence {
    let allowed = GcpProof {
        sql_authenticated: true,
        sql_ok: true,
        db_user: Some(c.principals[0].db_user()),
        database: Some(c.target.database.clone()),
        credential_issued: true,
        tcp_reachable: Some(true),
        ..Default::default()
    };
    let direct = GcpProof {
        network_rejection_explicit: true,
        tcp_reachable: Some(false),
        ..Default::default()
    };
    GcpRunEvidence {
        schema_version: 1,
        run_id: "local-record".into(),
        build_id: veil_db_guard::BUILD_ID.into(),
        config_hash: config::config_hash(c),
        history_compatibility_hash: config::history_compatibility_hash(c),
        evidence_kind: kind,
        target: c.target.clone(),
        started_at: 100,
        finished_at: 104,
        execution: GcpExecution::Completed,
        before: snapshot(c, 100),
        after: snapshot(c, 104),
        observations: vec![
            GcpObservation {
                case_id: "normal".into(),
                attempt_id: "attempt-allow".into(),
                principal_id: "app".into(),
                route: GcpRoute::Proxy,
                started_at: 101,
                finished_at: 102,
                execution: GcpExecution::Completed,
                observed: GcpAccess::Allowed,
                proof: allowed,
            },
            GcpObservation {
                case_id: "direct".into(),
                attempt_id: "attempt-direct".into(),
                principal_id: "app".into(),
                route: GcpRoute::Direct,
                started_at: 103,
                finished_at: 103,
                execution: GcpExecution::Completed,
                observed: GcpAccess::Denied,
                proof: direct,
            },
        ],
    }
}
fn save(c: &GcpConfig, mut capture: GcpRunEvidence, status: RunStatus) -> PathBuf {
    let root = tempfile::Builder::new()
        .prefix("vdg-preserved-state-")
        .tempdir()
        .unwrap()
        .keep();
    let path = root.join("run");
    let target = format!(
        "gcp-{}",
        hash_bytes(&serde_json::to_vec(&c.target).unwrap())
    );
    let mut writer =
        RunWriter::create_for_config(&path, &target, c, "gcp-check", c.limits.max_bytes, false)
            .unwrap();
    writer.manifest.created_at = capture.started_at;
    writer.manifest.build_id = capture.build_id.clone();
    capture.run_id = writer.manifest.run_id.clone();
    writer
        .write_json("snapshot.before.json", &capture.before)
        .unwrap();
    writer
        .write_json("snapshot.after.json", &capture.after)
        .unwrap();
    writer.write_json("observations.json", &capture).unwrap();
    // Deliberately forged cached verdict: evaluation must ignore it.
    writer
        .write_json("assessment.json", &serde_json::json!({"protected":true}))
        .unwrap();
    writer.finish(status).unwrap();
    path
}
fn new_connection(
    report: &veil_db_guard::core::state::StateReport,
) -> &veil_db_guard::core::state::StateRow {
    report
        .rows
        .iter()
        .find(|r| {
            r.desired.scope.effect == StateEffect::NewConnections
                && r.desired.expected == StateValue::Allowed
        })
        .unwrap()
}

#[test]
fn verified_local_capture_preserves_access_without_inventing_generation_or_sql_protection() {
    let c = config();
    let path = save(&c, capture(&c, GcpEvidenceKind::Live), RunStatus::Complete);
    let report = evaluate_run(&change(), &path, 110).unwrap();
    assert_eq!(report.assessment, StateAssessment::Unknown);
    assert!(!report.protection_evaluated);
    assert!(!report.all_required_effects_satisfied);
    let row = new_connection(&report);
    assert_eq!(row.observed, StateValue::Allowed);
    assert_eq!(row.assessment, StateAssessment::Unknown);
    assert!(
        row.reasons
            .contains(&StateReason::TargetGenerationUnconfirmed)
    );
    assert!(row.reasons.contains(&StateReason::IdentityUnconfirmed));
    assert!(!row.history[0].eligible);
    assert!(
        row.history[0]
            .provenance
            .artifacts
            .iter()
            .any(|a| a.id == "observations.json" && a.sha256.len() == 64)
    );
    assert!(
        report
            .rows
            .iter()
            .filter(|r| matches!(
                r.desired.scope.effect,
                StateEffect::SqlRole { .. } | StateEffect::SqlPrivilege { .. }
            ))
            .all(|r| r.observed == StateValue::Unknown)
    );
}

#[test]
fn fixture_and_stale_or_wrong_build_capture_cannot_become_current_protection() {
    let c = config();
    for mode in 0..3 {
        let mut cap = capture(
            &c,
            if mode == 0 {
                GcpEvidenceKind::Fixture
            } else {
                GcpEvidenceKind::Live
            },
        );
        if mode == 2 {
            cap.build_id = "d".repeat(64);
        }
        let path = save(&c, cap, RunStatus::Complete);
        let report = evaluate_run(&change(), &path, if mode == 1 { 5000 } else { 110 }).unwrap();
        let row = new_connection(&report);
        assert_eq!(row.observed, StateValue::Unknown);
        assert_eq!(row.history[0].observed, StateValue::Allowed);
        let reason = match mode {
            0 => StateReason::FixtureOnly,
            1 => StateReason::StaleEvidence,
            _ => StateReason::BuildMismatch,
        };
        assert!(row.reasons.contains(&reason));
        assert!(!report.protection_evaluated);
        assert!(!report.all_required_effects_satisfied);
    }
}

#[test]
fn partial_manifest_retains_success_and_does_not_trust_cached_verdict() {
    let c = config();
    let path = save(&c, capture(&c, GcpEvidenceKind::Live), RunStatus::Partial);
    let report = evaluate_run(&change(), &path, 110).unwrap();
    let row = new_connection(&report);
    assert_eq!(row.observed, StateValue::Allowed);
    assert_eq!(row.assessment, StateAssessment::Unknown);
    assert!(row.reasons.contains(&StateReason::IncompleteCapture));
    assert!(!report.protection_evaluated);
}

#[test]
fn foreign_target_and_modified_original_artifacts_are_rejected() {
    let mut c = config();
    c.target.instance_id = "foreign-instance".into();
    let path = save(&c, capture(&c, GcpEvidenceKind::Live), RunStatus::Complete);
    assert!(matches!(
        evaluate_run(&change(), &path, 110),
        Err(GuardError::TargetMismatch)
    ));
    let c = config();
    let path = save(&c, capture(&c, GcpEvidenceKind::Live), RunStatus::Complete);
    std::fs::write(path.join("observations.json"), b"{}").unwrap();
    assert!(evaluate_run(&change(), &path, 110).is_err());
}

#[test]
fn future_capture_and_unbounded_permission_declaration_cannot_create_pending() {
    let mut c = config();
    c.permission_changes = vec![GcpPermissionChange {
        principal_id: "app".into(),
        layer: GcpDenial::ConnectIam,
        changed_at: 99,
        before_roles: vec![GcpRole::CloudSqlClient],
        after_roles: vec![],
    }];
    let path = save(&c, capture(&c, GcpEvidenceKind::Live), RunStatus::Complete);
    let report = evaluate_run(&change(), &path, 110).unwrap();
    assert!(
        report
            .rows
            .iter()
            .all(|r| r.assessment != StateAssessment::Pending)
    );
    let report = evaluate_run(&change(), &path, 102).unwrap();
    assert_eq!(new_connection(&report).observed, StateValue::Unknown);
    assert!(!report.protection_evaluated);
}
