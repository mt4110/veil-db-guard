mod common;
use common::*;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use veil_db_guard::{config::config_hash, domain::*, store};
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args(args)
        .output()
        .unwrap()
}
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
#[test]
fn offline_plan_inspect_replay_report_pipeline_is_unknown_without_required_tests() {
    let parent = workspace();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cfg = root.join("examples/local.yaml");
    let plan = parent.join("plan");
    let result = cli(&["plan", "--config", p(&cfg), "--sandbox", "--out", p(&plan)]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(plan.join("sandbox.yaml").is_file());
    assert!(plan.join("bootstrap.sql").is_file());
    assert!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["operation_only"]
            .as_bool()
            .unwrap()
    );
    let inspect = parent.join("inspect");
    let result = cli(&[
        "inspect",
        "--config",
        p(&cfg),
        "--fixture",
        p(&root.join("examples/aws-responses.json")),
        "--out",
        p(&inspect),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let snapshot: InventorySnapshot =
        serde_json::from_slice(&fs::read(inspect.join("snapshot.json")).unwrap()).unwrap();
    assert_eq!(snapshot.evidence_kind, EvidenceKind::LocalFixture);
    let observations = parent.join("empty.json");
    fs::write(&observations, b"[]").unwrap();
    let probe = parent.join("probe");
    let result = cli(&[
        "probe",
        "--config",
        p(&cfg),
        "--snapshot",
        p(&inspect.join("snapshot.json")),
        "--suite",
        "positive",
        "--source-id",
        "application",
        "--fixture",
        p(&observations),
        "--out",
        p(&probe),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = parent.join("report");
    let result = cli(&[
        "report",
        "--config",
        p(&cfg),
        "--evidence",
        p(&probe),
        "--out",
        p(&report),
    ]);
    assert_eq!(result.status.code(), Some(3));
    let assessment: Assessment =
        serde_json::from_slice(&fs::read(report.join("assessment.json")).unwrap()).unwrap();
    assert_eq!(assessment.verdict, Verdict::Unknown);
    assert!(!assessment.cases.is_empty());
    assert!(
        assessment
            .cases
            .iter()
            .all(|x| x.verdict == Verdict::Unknown)
    );
    store::verify_run(&report, config().limits.max_bytes).unwrap();
}
#[test]
fn imported_fixture_claims_can_never_become_aws_connection_evidence() {
    let parent = workspace();
    let mut c = config();
    c.assessment_profile = Profile::AwsSandboxCoreV1;
    let cfg = parent.join("config.yaml");
    fs::write(&cfg, serde_saphyr::to_string(&c).unwrap()).unwrap();
    let mut s = snapshot();
    s.config_hash = config_hash(&c);
    let snap = parent.join("snapshot.json");
    fs::write(&snap, serde_json::to_vec(&s).unwrap()).unwrap();
    let mut forged = Observation::new(
        &c,
        "old-run",
        "V08",
        "V08.verified_client_tls",
        "application",
        "application-proxy",
        EvidenceKind::AwsConnection,
    );
    forged.execution = Execution::Completed;
    forged.outcome = Outcome::Authenticated;
    forged.reason_code = ReasonCode::None;
    forged.source_verification = SourceVerification::Corroborated;
    forged.path_stages = PathStages {
        transport_reachable: Stage::ObservedTrue,
        tls_established: Stage::ObservedTrue,
        db_authenticated: Stage::ObservedTrue,
    };
    forged.facts = vec![
        Fact::ChainVerified,
        Fact::HostnameVerified,
        Fact::TargetMatched,
        Fact::ConfigBeforeAfterMatched,
        Fact::NoChangesAttested,
    ];
    forged.details = Some(ProbeDetails {
        protocol: Some(ObservationProtocol {
            identity: Some(IdentityEvidence {
                iam_principal_arn: "SENTINEL_UNTRUSTED_IDENTITY".into(),
                requested_db_user: "vdg_probe".into(),
                authenticated_db_user: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    let input = parent.join("claimed-aws.json");
    fs::write(&input, serde_json::to_vec(&vec![forged]).unwrap()).unwrap();
    let probe = parent.join("replay");
    let result = cli(&[
        "probe",
        "--config",
        p(&cfg),
        "--snapshot",
        p(&snap),
        "--suite",
        "positive",
        "--source-id",
        "application",
        "--fixture",
        p(&input),
        "--out",
        p(&probe),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let observations: Vec<Observation> =
        serde_json::from_slice(&fs::read(probe.join("observations.json")).unwrap()).unwrap();
    assert!(
        !String::from_utf8(fs::read(probe.join("observations.json")).unwrap())
            .unwrap()
            .contains("SENTINEL_UNTRUSTED_IDENTITY")
    );
    assert_eq!(observations[0].evidence_kind, EvidenceKind::LocalFixture);
    assert_eq!(
        observations[0].source_verification,
        SourceVerification::Declared
    );
    let manifest = store::verify_run(&probe, c.limits.max_bytes).unwrap();
    assert_eq!(
        observations[0].evidence_refs,
        vec![
            manifest
                .artifacts
                .iter()
                .find(|a| a.name == "snapshot.json")
                .unwrap()
                .sha256
                .clone()
        ]
    );
    let report = parent.join("report");
    let result = cli(&[
        "report",
        "--config",
        p(&cfg),
        "--evidence",
        p(&probe),
        "--out",
        p(&report),
    ]);
    assert_eq!(result.status.code(), Some(3));
    let assessment: Assessment =
        serde_json::from_slice(&fs::read(report.join("assessment.json")).unwrap()).unwrap();
    assert_eq!(assessment.connection_verdict, Verdict::Unknown);
}
#[test]
fn cli_does_not_echo_secret_sentinels_from_invalid_arguments_or_yaml() {
    let secret = "SENTINEL_SECRET_298237";
    let invalid = cli(&["plan", "--unknown-secret", secret]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains(secret));
    let parent = workspace();
    let cfg = parent.join("invalid.yaml");
    fs::write(
        &cfg,
        format!(
            "{}\npassword: {secret}\n",
            include_str!("../examples/local.yaml")
        ),
    )
    .unwrap();
    let result = cli(&["plan", "--config", p(&cfg), "--out", p(&parent.join("out"))]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
    assert!(!String::from_utf8_lossy(&result.stdout).contains(secret));
}
#[test]
fn live_operations_require_permission_and_plan_never_overwrites() {
    let parent = workspace();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cfg = root.join("examples/local.yaml");
    let out = parent.join("no-permission");
    let result = cli(&["inspect", "--config", p(&cfg), "--out", p(&out)]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.exists());
    let out = parent.join("plan");
    let args = ["plan", "--config", p(&cfg), "--out", p(&out)];
    assert!(cli(&args).status.success());
    let before = fs::read(out.join("manifest.json")).unwrap();
    assert_eq!(cli(&args).status.code(), Some(2));
    assert_eq!(fs::read(out.join("manifest.json")).unwrap(), before);
}
#[test]
fn sandbox_generation_rejects_missing_dedicated_scope_before_creating_output() {
    let parent = workspace();
    let mut c = config();
    c.test_scope = None;
    let cfg = parent.join("no-scope.yaml");
    fs::write(&cfg, serde_saphyr::to_string(&c).unwrap()).unwrap();
    let out = parent.join("no-output");
    let result = cli(&["plan", "--config", p(&cfg), "--sandbox", "--out", p(&out)]);
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.exists());
}
#[test]
fn fixture_and_local_lab_cannot_enable_aws_reads() {
    let parent = workspace();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cfg = root.join("examples/local.yaml");
    for mode in ["--fixture", "--local-lab"] {
        let out = parent.join(if mode == "--fixture" {
            "fixture-refused"
        } else {
            "lab-refused"
        });
        let mut args = vec![
            "probe",
            "--config",
            p(&cfg),
            "--snapshot",
            "unused.json",
            "--suite",
            "positive",
            "--source-id",
            "application",
            "--allow-aws-read",
            "--allow-network",
            mode,
        ];
        if mode == "--fixture" {
            args.push("unused-observations.json");
        }
        args.extend(["--out", p(&out)]);
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(!out.exists());
    }
}
#[test]
fn report_rejects_nonexistent_refs_and_nested_snapshot_substitution() {
    for nested in [false, true] {
        let parent = workspace();
        let c = config();
        let s = snapshot();
        let input = parent.join("input");
        let mut run = store::RunWriter::create(&input, &c, "probe", true).unwrap();
        run.write_json("snapshot.json", &s).unwrap();
        let actual = run
            .manifest
            .artifacts
            .iter()
            .find(|a| a.name == "snapshot.json")
            .unwrap()
            .sha256
            .clone();
        let mut o = Observation::new(
            &c,
            &run.manifest.run_id,
            "V01",
            "V01.reject_missing",
            "global",
            "global",
            EvidenceKind::LocalFixture,
        );
        o.snapshot_hash = veil_db_guard::config::snapshot_hash(&s);
        o.execution = Execution::Completed;
        o.outcome = Outcome::CheckSatisfied;
        o.reason_code = ReasonCode::None;
        o.evidence_refs = vec![if nested {
            actual.clone()
        } else {
            "9".repeat(64)
        }];
        if nested {
            let mut changed = s.clone();
            changed.db.as_mut().unwrap().publicly_accessible = true;
            o.details = Some(ProbeDetails {
                protocol: Some(ObservationProtocol {
                    plan_hash: "a".repeat(64),
                    before: Some(SnapshotEvidence {
                        reference_id: "before".into(),
                        artifact_hash: actual,
                        snapshot: changed,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        run.write_json("observations.json", &vec![o]).unwrap();
        run.finish(store::RunStatus::Complete).unwrap();
        let cfg = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/local.yaml");
        let out = parent.join("rejected");
        let result = cli(&[
            "report",
            "--config",
            p(&cfg),
            "--evidence",
            p(&input),
            "--out",
            p(&out),
        ]);
        assert_eq!(result.status.code(), Some(2));
        assert!(!out.exists());
    }
}
