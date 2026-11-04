use veil_db_guard::{
    binding::*,
    core::{
        change::{OperationLimits, PreparedChange, prepare_change},
        plan::build_plan,
        policy::*,
    },
};
fn policy() -> PolicyRevision {
    let mut policy = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    policy.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    policy
}
fn prepare(policy: &PolicyRevision) -> PreparedChange {
    let plan = build_plan(
        policy,
        policy
            .targets
            .iter()
            .flat_map(veil_db_guard::adapters::capabilities_for)
            .collect(),
        vec![],
        100,
    )
    .unwrap();
    prepare_change(policy, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn checkpoint(change: &PreparedChange, kind: CheckpointKind) -> ManualCheckpoint {
    ManualCheckpoint::attest(change, "billing-db", kind, "recovery-operator", 100, 200).unwrap()
}
#[test]
fn profile_is_secret_free_and_uses_workload_iam_connector_contract() {
    let profile = connection_profile(&policy(), "billing-access").unwrap();
    assert_eq!(
        profile.instance_connection_name,
        "vdg-example-000000:asia-northeast1:billing-postgres"
    );
    assert_eq!(
        profile.authentication,
        BindingAuthentication::WorkloadIdentityAutomaticIam
    );
    assert_eq!(profile.route, BindingRoute::CloudSqlConnector);
    assert_eq!(profile.allowed_route_ids, vec!["app-connector"]);
    let serialized = serde_json::to_string(&profile).unwrap();
    assert!(
        !["password", "token", "credential_file", "postgres://"]
            .iter()
            .any(|s| serialized.contains(s))
    );
    let mut policy = policy();
    policy.subjects[0].identity.credential_source.kind = CredentialSourceKind::NativeSdk;
    assert_eq!(
        connection_profile(&policy, "billing-access"),
        Err(BindingError::Invalid)
    );
}
#[test]
fn all_three_fresh_manual_checkpoints_are_required_but_are_not_native_proof() {
    let change = prepare(&policy());
    let mut gate = ManualCheckpoints::default();
    for kind in [
        CheckpointKind::BindingPublished,
        CheckpointKind::RecoveryReady,
        CheckpointKind::ApplicationCutover,
    ] {
        assert!(gate.validate(&change, "billing-db", 110).is_err());
        gate.receipts.push(checkpoint(&change, kind));
    }
    assert_eq!(gate.validate(&change, "billing-db", 110).unwrap().len(), 3);
    assert!(gate.validate(&change, "billing-db", 99).is_err());
    assert!(gate.validate(&change, "billing-db", 200).is_err());
    assert!(
        !serde_json::to_string(&gate)
            .unwrap()
            .contains("sql_authenticated")
    );
}
#[test]
fn stale_revision_generation_and_tampered_coverage_cannot_authorize_cutover() {
    let policy = policy();
    let change = prepare(&policy);
    let mut receipt = checkpoint(&change, CheckpointKind::ApplicationCutover);
    receipt.application_bindings.clear();
    assert!(receipt.validate(&change, "billing-db", 110).is_err());
    let receipt = checkpoint(&change, CheckpointKind::ApplicationCutover);
    let mut other = policy.clone();
    other.targets[0].resource.generation_fingerprint = Some("b".repeat(64));
    assert!(
        receipt
            .validate(&prepare(&other), "billing-db", 110)
            .is_err()
    );
    other = policy.clone();
    other.revision = 2;
    other.parent_revision_hash = Some(policy.revision_hash().unwrap());
    let plan = build_plan(
        &other,
        other
            .targets
            .iter()
            .flat_map(veil_db_guard::adapters::capabilities_for)
            .collect(),
        vec![],
        100,
    )
    .unwrap();
    let revised = prepare_change(
        &other,
        &plan,
        &[],
        Some(&policy),
        OperationLimits::default(),
    )
    .unwrap();
    assert!(receipt.validate(&revised, "billing-db", 110).is_err());
}
#[test]
fn adding_second_application_invalidates_old_target_wide_acknowledgement() {
    let mut policy = policy();
    let previous = prepare(&policy);
    let old = checkpoint(&previous, CheckpointKind::ApplicationCutover);
    let mut subject = policy.subjects[0].clone();
    subject.id = "second-app".into();
    subject.identity.principal = "second@vdg-example-000000.iam.gserviceaccount.com".into();
    subject.workload_sources = vec!["second-runtime".into()];
    policy.subjects.push(subject);
    let mut grant = policy.grants[0].clone();
    grant.id = "second-access".into();
    grant.subject = "second-app".into();
    grant.db_identity = "second@vdg-example-000000.iam".into();
    policy.targets[0]
        .managed_surface
        .db_identities
        .push(grant.db_identity.clone());
    policy.grants.push(grant);
    policy.protection_profiles[0].allowed_routes[0]
        .source_ids
        .push("second-runtime".into());
    let current = prepare(&policy);
    assert!(old.validate(&current, "billing-db", 110).is_err());
    let new = checkpoint(&current, CheckpointKind::ApplicationCutover);
    assert_eq!(new.application_bindings.len(), 2);
    assert_eq!(new.application_bindings[1].grant_id, "second-access");
}
#[test]
fn unconfirmed_target_or_nonoperator_cannot_issue_checkpoint() {
    let mut policy = policy();
    policy.targets[0].resource.generation_fingerprint = None;
    assert!(
        ManualCheckpoint::attest(
            &prepare(&policy),
            "billing-db",
            CheckpointKind::RecoveryReady,
            "recovery-operator",
            100,
            200
        )
        .is_err()
    );
    assert!(
        ManualCheckpoint::attest(
            &prepare(&self::policy()),
            "billing-db",
            CheckpointKind::RecoveryReady,
            "billing-app",
            100,
            200
        )
        .is_err()
    );
}

#[test]
fn exclusive_native_window_is_separate_short_lived_and_exactly_bound() {
    let change = prepare(&policy());
    let mut gate = ManualCheckpoints::default();
    assert_eq!(
        gate.validate_change_window(&change, "billing-db", 110),
        Err(BindingError::Pending)
    );
    assert!(
        ManualCheckpoint::attest(
            &change,
            "billing-db",
            CheckpointKind::ExclusiveNativeChangeWindow,
            "recovery-operator",
            100,
            3701
        )
        .is_err()
    );
    gate.receipts.push(checkpoint(
        &change,
        CheckpointKind::ExclusiveNativeChangeWindow,
    ));
    assert!(
        gate.validate_change_window(&change, "billing-db", 110)
            .is_ok()
    );
    assert!(
        gate.validate_change_window(&change, "billing-db", 200)
            .is_err()
    );
    assert!(gate.validate(&change, "billing-db", 110).is_err());
}
