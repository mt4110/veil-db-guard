mod common;

use veil_db_guard::{
    config::GuardError,
    store::{self, RunStatus, RunWriter},
};

#[test]
fn provider_artifacts_share_integrity_storage_but_cannot_be_imported_as_aws() {
    let root = common::workspace();
    let path = root.join("gcp");
    let config = serde_json::json!({"schema_version":1,"provider":"gcp","target_id":"gcp-lab"});
    let mut writer =
        RunWriter::create_for_config(&path, "gcp-lab", &config, "gcp-check", 8192, false).unwrap();
    writer
        .write_json("observations.json", &serde_json::json!([]))
        .unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    let manifest = store::verify_manifest(&path, 8192).unwrap();
    assert_eq!(manifest.target_id, "gcp-lab");
    assert_eq!(manifest.operation, "gcp-check");
    assert_eq!(
        store::verify_run(&path, 8192).unwrap_err(),
        GuardError::EvidenceIncompatible
    );

    std::fs::write(path.join("observations.json"), b"[1]").unwrap();
    assert_eq!(
        store::verify_manifest(&path, 8192).unwrap_err(),
        GuardError::EvidenceIncompatible
    );
}

#[test]
fn malformed_provider_identity_is_rejected_before_creating_output() {
    let root = common::workspace();
    let output = root.join("invalid");
    let config = serde_json::json!({"schema_version":1});
    assert!(
        RunWriter::create_for_config(&output, "../outside", &config, "gcp-check", 8192, false,)
            .is_err()
    );
    assert!(!output.exists());
}
