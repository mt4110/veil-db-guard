//! Fixed collector entry only; malformed input never reaches native IO.
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn execute(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .arg("source-collector-v1")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}
#[test]
fn fixed_collector_rejects_malformed_and_oversized_stdin_without_echoing_secrets() {
    for input in [
        b"PRIVATE_TOKEN_SENTINEL".to_vec(),
        vec![b'x'; veil_db_guard::core::evidence::MAX_REQUEST_BYTES + 1],
    ] {
        let output = execute(&input);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("PRIVATE_TOKEN_SENTINEL"));
        assert!(stderr.contains("SOURCE_INVALID") || stderr.contains("SOURCE_LIMIT"));
    }
}
#[test]
fn fixed_collector_cannot_take_arbitrary_sql_shell_metadata_or_key_source_arguments() {
    for flag in ["--sql", "--shell", "--metadata-url", "--jwk-url"] {
        let output = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
            .args(["source-collector-v1", flag, "PRIVATE_TOKEN_SENTINEL"])
            .env_clear()
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_TOKEN_SENTINEL"));
    }
}
#[test]
fn offline_build_info_identifies_the_artifact_without_source_verification() {
    let output = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .arg("source-build-info")
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(veil_db_guard::core::policy::valid_hash(
        info["build_id"].as_str().unwrap()
    ));
    assert_eq!(info["collector_supported"], cfg!(target_os = "linux"));
    assert_eq!(info["source_registration_schema"], 2);
}
#[test]
fn bootstrap_context_requires_explicit_local_read_and_never_auto_registers() {
    let output = Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .arg("source-context-v1")
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SOURCE_PERMISSION_REQUIRED"));
}
