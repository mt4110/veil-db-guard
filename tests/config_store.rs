mod common;
use common::*;
use std::{fs, path::Path};
use veil_db_guard::{config::*, domain::*, store::*};

#[test]
fn strict_yaml_rejects_missing_duplicate_unknown_and_interpolation_without_echo() {
    let yaml = include_str!("../examples/local.yaml");
    let secret = "SENTINEL_DO_NOT_PRINT_492093";
    let variants = [
        yaml.replacen("schema_version: 1\n", "", 1),
        format!("{yaml}\nschema_version: 1\n"),
        format!("{yaml}\npassword: {secret}\n"),
        yaml.replace("local-demo", "${SECRET}"),
        yaml.replace(
            "region: ap-northeast-1",
            "region: ap-northeast-1\n  region: ap-northeast-1",
        ),
        format!("{yaml}\n---\n{{}}"),
        yaml.replace("local-demo", "&anchor local-demo"),
    ];
    for value in variants {
        let e = parse_config(value.as_bytes()).unwrap_err();
        assert!(!e.to_string().contains(secret));
    }
}
#[test]
fn target_auth_path_and_resource_limits_are_checked() {
    let c = config();
    let mut variants = vec![];
    let mut v = c.clone();
    v.target.region = "us-east-1".into();
    variants.push(v);
    let mut v = c.clone();
    v.target.db_instance_arn = v
        .target
        .db_instance_arn
        .replace("000000000000", "111111111111");
    variants.push(v);
    let mut v = c.clone();
    v.auth.mode = AuthMode::StandardIam;
    variants.push(v);
    let mut v = c.clone();
    v.paths.retain(|p| p.destination != Destination::Database);
    variants.push(v);
    let mut v = c.clone();
    v.paths[1].expected = Expectation::Allow;
    variants.push(v);
    let mut v = c.clone();
    v.sources.push(v.sources[0].clone());
    variants.push(v);
    let mut v = c.clone();
    v.limits.max_concurrency = 0;
    variants.push(v);
    let mut v = c.clone();
    v.test_scope.as_mut().unwrap().schema_prefix = "public".into();
    variants.push(v);
    for v in variants {
        assert!(validate_config(&v).is_err());
    }
}
#[test]
fn descriptions_are_not_saved_or_hashed() {
    let c = config();
    let mut described = c.clone();
    described.sources[0].description = Some("SENTINEL_PRIVATE_NOTE".into());
    assert_eq!(config_hash(&c), config_hash(&described));
    assert!(
        !serde_json::to_string(&described)
            .unwrap()
            .contains("SENTINEL_PRIVATE_NOTE")
    );
}
#[test]
fn new_run_is_private_hash_verified_and_never_overwrites_existing_output() {
    let parent = workspace();
    let out = parent.join("run");
    let c = config();
    let mut writer = RunWriter::create(&out, &c, "plan", true).unwrap();
    writer
        .write_json("plan.json", &serde_json::json!({"test":true}))
        .unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    let m = verify_run(&out, c.limits.max_bytes).unwrap();
    assert_eq!(m.status, RunStatus::Complete);
    assert!(RunWriter::create(&out, &c, "plan", true).is_err());
    assert!(writer.write_bytes("../escape", b"bad").is_err());
    assert!(writer.write_bytes("plan.json", b"overwrite").is_err());
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
    fs::write(out.join("plan.json"), b"modified by test").unwrap();
    assert!(verify_run(&out, c.limits.max_bytes).is_err());
}
#[test]
fn dropping_partial_run_records_partial_state_and_keeps_evidence() {
    let parent = workspace();
    let out = parent.join("partial");
    let c = config();
    {
        let mut run = RunWriter::create(&out, &c, "probe", true).unwrap();
        run.write_json("observations.json", &Vec::<Observation>::new())
            .unwrap();
    }
    assert_eq!(
        verify_run(&out, c.limits.max_bytes).unwrap().status,
        RunStatus::Partial
    );
    assert!(out.join("observations.json").exists());
}
#[test]
fn oversized_or_symlink_inputs_and_output_links_are_rejected() {
    let parent = workspace();
    let file = parent.join("oversized");
    fs::write(&file, [0u8; 1025]).unwrap();
    assert_eq!(read_bounded(&file, 1024), Err(GuardError::LimitExceeded));
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let linked = parent.join("link");
        symlink(&file, &linked).unwrap();
        assert!(read_bounded(&linked, 2048).is_err());
        let dir = parent.join("actual");
        fs::create_dir(&dir).unwrap();
        let output = parent.join("output");
        symlink(&dir, &output).unwrap();
        assert!(RunWriter::create(&output, &config(), "plan", true).is_err());
    }
}
#[test]
fn artifact_limits_and_missing_storage_are_errors() {
    let parent = workspace();
    let c = config();
    let out = parent.join("bounded");
    let mut run = RunWriter::create(&out, &c, "plan", true).unwrap();
    assert_eq!(
        run.write_bytes("sandbox.yaml", &vec![0; c.limits.max_bytes + 1]),
        Err(GuardError::LimitExceeded)
    );
    assert!(RunWriter::create(Path::new("/nonexistent-vdg-parent/new"), &c, "plan", true).is_err());
}
#[test]
fn snapshot_foreign_identity_staleness_and_target_pair_are_rejected() {
    let c = config();
    let s = snapshot();
    validate_snapshot(&c, &s).unwrap();
    let mut v = s.clone();
    v.target.account_id = "111111111111".into();
    assert!(validate_snapshot(&c, &v).is_err());
    let mut v = s.clone();
    v.observed_at = 0;
    assert!(validate_snapshot(&c, &v).is_err());
    let mut v = s.clone();
    v.observed_at = now() + 3600;
    assert!(validate_snapshot(&c, &v).is_err());
    let mut v = s;
    v.proxy.as_mut().unwrap().target_db_resource_id = Some("db-OTHER".into());
    assert!(validate_snapshot(&c, &v).is_err());
}
#[test]
fn writer_and_verifier_share_total_manifest_and_artifact_budget() {
    let parent = workspace();
    let c = config();
    let mut run = RunWriter::create(&parent.join("boundary"), &c, "plan", true).unwrap();
    let used = run
        .manifest
        .artifacts
        .iter()
        .map(|a| a.bytes)
        .sum::<usize>();
    assert_eq!(
        run.write_bytes("sandbox.yaml", &vec![b'x'; c.limits.max_bytes - used]),
        Err(GuardError::LimitExceeded)
    );
    run.finish(RunStatus::Complete).unwrap();
    verify_run(run.path(), c.limits.max_bytes).unwrap();
}
#[cfg(unix)]
#[test]
fn renamed_run_directory_cannot_redirect_writes_or_replace_foreign_manifest() {
    use std::os::unix::fs::symlink;
    let parent = workspace();
    let original = parent.join("run");
    let retained = parent.join("retained");
    let foreign = parent.join("foreign");
    let mut run = RunWriter::create(&original, &config(), "plan", true).unwrap();
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("manifest.json"), b"KEEP_FOREIGN").unwrap();
    fs::rename(&original, &retained).unwrap();
    symlink(&foreign, &original).unwrap();
    run.write_bytes("sandbox.yaml", b"owned run only").unwrap();
    run.finish(RunStatus::Complete).unwrap();
    assert!(retained.join("sandbox.yaml").exists());
    assert!(!foreign.join("sandbox.yaml").exists());
    assert_eq!(
        fs::read(foreign.join("manifest.json")).unwrap(),
        b"KEEP_FOREIGN"
    );
}
