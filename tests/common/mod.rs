#![allow(dead_code)]
use veil_db_guard::{config::parse_config, domain::*};
pub fn config() -> TargetConfig {
    parse_config(include_bytes!("../../examples/local.yaml")).expect("valid synthetic config")
}
pub fn workspace() -> std::path::PathBuf {
    tempfile::Builder::new()
        .prefix("vdg-preserved-test-")
        .tempdir()
        .expect("temp dir")
        .keep()
}
pub fn snapshot() -> InventorySnapshot {
    let c = config();
    let responses = serde_json::from_str(include_str!("../../examples/aws-responses.json"))
        .expect("fixture JSON");
    veil_db_guard::aws_inventory::normalize(&c, &responses).expect("fixture snapshot")
}
