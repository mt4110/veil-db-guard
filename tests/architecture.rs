//! Compile the actual kernel as an isolated module graph. This integration-test
//! crate intentionally has no adapters, CLI, provider clients or SQLite module:
//! any dependency from core onto one of them becomes a compiler error here.
#![allow(dead_code)]

#[path = "../src/core/mod.rs"]
mod core;

const BUILD_ID: &str = env!("VDG_BUILD_ID");

#[test]
fn kernel_policy_compiles_and_runs_without_infrastructure_modules() {
    let policy = core::policy::parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    let original = policy.revision_hash().unwrap();
    assert!(core::policy::valid_hash(&original));
    assert_eq!(policy.normalized().revision_hash().unwrap(), original);
}
