use veil_db_guard::{
    adapters,
    config::hash_bytes,
    core::{
        approval::{self, ApprovalError},
        change::{
            self, ChangeError, ConflictKey, DifferenceField, DifferenceKind, DifferenceValue,
            OperationLimits, PreparedChange, RecoveryMethod,
        },
        observation::{ChangeObservation as ObservedState, ConfigurationFacts, ObservationOrigin},
        plan::build_plan,
        policy::{
            self, AdmissionIntent, AuthenticationRequirement, GenerationAssurance, Grant,
            GrantLifetime, ProfileKind, SqlAccessIntent,
        },
    },
};

fn policy() -> policy::PolicyRevision {
    policy::parse_policy(include_str!("../examples/core-policy.yaml")).unwrap()
}
fn prepare(
    policy: &policy::PolicyRevision,
    states: &[ObservedState],
    previous: Option<&policy::PolicyRevision>,
) -> Result<PreparedChange, ChangeError> {
    let refs = states
        .iter()
        .map(|state| {
            let mut bytes = serde_json::to_vec_pretty(state).unwrap();
            bytes.push(b'\n');
            hash_bytes(&bytes)
        })
        .collect();
    let plan = build_plan(
        policy,
        policy
            .targets
            .iter()
            .flat_map(adapters::capabilities_for)
            .collect(),
        refs,
        100,
    )
    .unwrap();
    change::prepare_change(policy, &plan, states, previous, OperationLimits::default())
}
fn current(policy: &policy::PolicyRevision) -> ObservedState {
    let mut state = ObservedState::missing(&policy.targets[0], 100);
    state.configuration_epoch = Some("a".repeat(64));
    state.configuration_observed_at = Some(90);
    state.valid_until = Some(150);
    state.inventory_complete = true;
    state.origins = vec![ObservationOrigin::GcpLive];
    state.notices.clear();
    state.configuration = Some(ConfigurationFacts {
        target: state.target.clone(),
        observed_at: 90,
        complete: true,
        native_iam_enabled: Some(true),
        connector_required: Some(true),
        identities: vec![],
    });
    state
}

#[test]
fn immutable_change_keeps_unknown_sql_and_declared_generation_unknown() {
    let policy = policy();
    let change = prepare(&policy, &[], None).unwrap();
    change.verify().unwrap();
    assert!(
        change
            .differences
            .iter()
            .filter(|row| row.field == DifferenceField::SqlPrivileges)
            .all(|row| row.kind == DifferenceKind::Unknown && row.before.is_none())
    );
    assert!(change.repair_recipes.is_empty());
    assert!(
        change
            .differences
            .iter()
            .any(|row| row.field == DifferenceField::TargetGeneration
                && row.kind == DifferenceKind::Unknown)
    );
    let mut changed = change.clone();
    changed.limits.max_attempts += 1;
    assert!(changed.verify().is_err());
}

#[test]
fn a_rehashed_forged_graph_is_not_an_approvable_policy_change() {
    let policy = policy();
    let mut plan = build_plan(
        &policy,
        policy
            .targets
            .iter()
            .flat_map(adapters::capabilities_for)
            .collect(),
        vec![],
        100,
    )
    .unwrap();
    plan.steps.last_mut().unwrap().dependencies.clear();
    plan.plan_hash.clear();
    plan.plan_hash = hash_bytes(&serde_json::to_vec(&plan).unwrap());
    assert_eq!(
        change::prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap_err(),
        ChangeError::Tampered
    );
}

#[test]
fn creator_build_is_historical_metadata_under_an_unchanged_graph_contract() {
    let policy = policy();
    let mut plan = build_plan(
        &policy,
        policy
            .targets
            .iter()
            .flat_map(adapters::capabilities_for)
            .collect(),
        vec![],
        100,
    )
    .unwrap();
    plan.build_id = "e".repeat(64);
    plan.plan_hash.clear();
    plan.plan_hash = hash_bytes(&serde_json::to_vec(&plan).unwrap());
    let change =
        change::prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
    change.verify().unwrap();
    assert_eq!(change.plan.build_id, "e".repeat(64));
}

#[test]
fn generic_profiles_never_request_implicit_iam_or_connector_weakening() {
    let mut policy = policy();
    policy.protection_profiles[0].kind = ProfileKind::NativePathV1;
    policy.protection_profiles[0].authentication = AuthenticationRequirement::NativeDatabase;
    let state = current(&policy);
    let change = prepare(&policy, &[state], None).unwrap();
    for field in [
        DifferenceField::NativeIamEnabled,
        DifferenceField::ConnectorRequired,
    ] {
        let row = change
            .differences
            .iter()
            .find(|row| row.field == field)
            .unwrap();
        assert_eq!(row.kind, DifferenceKind::Unknown);
        assert_eq!(row.desired, None);
    }
}

#[test]
fn observed_config_diff_has_freshness_bound_and_does_not_prove_sql_or_tls() {
    let policy = policy();
    let mut state = current(&policy);
    let change = prepare(&policy, &[state.clone()], None).unwrap();
    assert!(
        change
            .differences
            .iter()
            .any(|row| row.field == DifferenceField::ConnectorRequired
                && row.kind == DifferenceKind::Unchanged
                && row.before == Some(DifferenceValue::Boolean(true)))
    );
    assert!(
        change
            .differences
            .iter()
            .filter(|row| matches!(
                row.field,
                DifferenceField::SqlPrivileges | DifferenceField::VerifiedTls
            ))
            .all(|row| row.kind == DifferenceKind::Unknown)
    );
    state.valid_until = Some(99);
    let stale = prepare(&policy, &[state], None).unwrap();
    assert!(
        stale
            .differences
            .iter()
            .filter(|row| row.field == DifferenceField::ConnectorRequired)
            .all(|row| row.kind == DifferenceKind::Unknown)
    );
}

#[test]
fn observations_must_match_saved_refs_and_registered_native_scope() {
    let policy = policy();
    let mut state = current(&policy);
    let plan = build_plan(
        &policy,
        policy
            .targets
            .iter()
            .flat_map(adapters::capabilities_for)
            .collect(),
        vec![],
        100,
    )
    .unwrap();
    assert_eq!(
        change::prepare_change(
            &policy,
            &plan,
            &[state.clone()],
            None,
            OperationLimits::default()
        )
        .unwrap_err(),
        ChangeError::Tampered
    );
    if let Some(snapshot) = &mut state.configuration {
        snapshot.target.placement.account_id = "another-project".into();
    }
    assert_eq!(
        prepare(&policy, &[state], None).unwrap_err(),
        ChangeError::TargetMismatch
    );
}

#[test]
fn different_databases_in_a_project_share_the_iam_conflict_scope() {
    let a = prepare(&policy(), &[], None).unwrap();
    let mut second = policy();
    second.targets[0].resource.native_id = "projects/vdg-example-000000/instances/second-db".into();
    let b = prepare(&second, &[], None).unwrap();
    assert!(
        a.conflict_keys
            .iter()
            .any(|a| a.field_or_domain == "iam" && b.conflict_keys.iter().any(|b| a.conflicts(b)))
    );
    let broad = ConflictKey {
        resource_identity: "resource".into(),
        field_or_domain: "iam".into(),
    };
    let member = ConflictKey {
        resource_identity: "resource".into(),
        field_or_domain: "iam/member".into(),
    };
    assert!(broad.conflicts(&member));
    assert_ne!(broad.canonical_key(), member.canonical_key());
}

#[test]
fn previous_revision_is_bound_and_removal_requires_explicit_revoke_plan() {
    let mut old = policy();
    let mut next = old.clone();
    next.revision = 2;
    next.parent_revision_hash = Some(old.revision_hash().unwrap());
    next.grants[0].sql_access.privileges[0].actions.pop();
    let changed = prepare(&next, &[], Some(&old)).unwrap();
    assert!(changed.differences.iter().any(
        |row| row.field == DifferenceField::PolicyGrant && row.kind == DifferenceKind::Changed
    ));
    old.targets[0]
        .managed_surface
        .db_identities
        .push("recovery@vdg-example-000000.iam".into());
    old.grants.push(Grant {
        id: "recovery-grant".into(),
        subject: "recovery-operator".into(),
        target: "billing-db".into(),
        db_identity: "recovery@vdg-example-000000.iam".into(),
        admission: AdmissionIntent::Allow,
        sql_access: SqlAccessIntent::default(),
        profile: "gcp-protected".into(),
        lifetime: GrantLifetime::Standing,
    });
    let mut removed = old.clone();
    removed.revision = 2;
    removed.parent_revision_hash = Some(old.revision_hash().unwrap());
    removed.grants.pop();
    assert_eq!(
        prepare(&removed, &[], Some(&old)).unwrap_err(),
        ChangeError::RevokePlanRequired
    );
}

#[test]
fn approval_binds_exact_change_identity_limits_and_separate_deadlines() {
    let change = prepare(&policy(), &[], None).unwrap();
    let approval = approval::issue(
        &change,
        "approval-1",
        "operator-1",
        "executor-1",
        120,
        140,
        100,
    )
    .unwrap();
    approval
        .validate(&change, "executor-1", 119, false)
        .unwrap();
    assert_eq!(
        approval.validate(&change, "executor-1", 120, false),
        Err(ApprovalError::Expired)
    );
    approval.validate(&change, "executor-1", 120, true).unwrap();
    assert_eq!(
        approval.validate(&change, "executor-1", 140, true),
        Err(ApprovalError::Expired)
    );
    assert_eq!(
        approval.validate(&change, "other-executor", 101, false),
        Err(ApprovalError::ScopeMismatch)
    );
    assert_eq!(
        approval.validate(&change, "executor-1", 99, false),
        Err(ApprovalError::ScopeMismatch)
    );
    let mut forged = approval.clone();
    forged.allowed_step_ids.clear();
    assert!(forged.validate(&change, "executor-1", 101, false).is_err());
}

#[test]
fn repair_is_generation_epoch_and_budget_bound_and_never_inferred_from_a_name() {
    let mut policy = policy();
    policy.targets[0].resource.generation_fingerprint = Some("c".repeat(64));
    let mut state = current(&policy);
    assert!(
        prepare(&policy, &[state.clone()], None)
            .unwrap()
            .repair_recipes
            .is_empty()
    );
    state.target.native_ref.generation_fingerprint = Some("c".repeat(64));
    state.target.generation_assurance = GenerationAssurance::Confirmed;
    let change = prepare(&policy, &[state], None).unwrap();
    assert!(!change.repair_recipes.is_empty());
    for recipe in &change.repair_recipes {
        assert_eq!(recipe.max_executions, 2);
        assert_eq!(recipe.target_generation, "c".repeat(64));
        assert_eq!(recipe.permitted_prior_epoch, "a".repeat(64));
        assert_eq!(recipe.minimum_interval_seconds, 60);
    }
    let approval = approval::issue(
        &change,
        "approval-1",
        "operator-1",
        "executor-1",
        120,
        140,
        100,
    )
    .unwrap();
    assert!(
        change
            .repair_recipes
            .iter()
            .all(|recipe| approval.permits_repair(&recipe.recipe_hash))
    );
}

#[test]
fn revoke_compensation_never_reopens_an_old_allow_automatically() {
    let mut policy = policy();
    policy.grants[0].admission = AdmissionIntent::Deny;
    policy.grants[0].sql_access = SqlAccessIntent::default();
    let change = prepare(&policy, &[], None).unwrap();
    assert_eq!(
        change.recovery.compensations[0].method,
        RecoveryMethod::NoAutomaticAllowRestoration
    );
    assert!(change.recovery.compensations[0].security_weakening_requires_separate_approval);
}

#[test]
fn a_retained_grant_id_cannot_hide_rebinding_to_another_native_identity_or_resource() {
    let old = policy();
    let mut next = old.clone();
    next.revision = 2;
    next.parent_revision_hash = Some(old.revision_hash().unwrap());
    let app = next
        .subjects
        .iter_mut()
        .find(|subject| subject.id == "billing-app")
        .unwrap();
    app.identity.principal = "another-app@vdg-example-000000.iam.gserviceaccount.com".into();
    next.grants[0].db_identity = "another-app@vdg-example-000000.iam".into();
    next.targets[0]
        .managed_surface
        .db_identities
        .push(next.grants[0].db_identity.clone());
    assert_eq!(
        prepare(&next, &[], Some(&old)).unwrap_err(),
        ChangeError::RevokePlanRequired
    );
    let mut moved = old.clone();
    moved.revision = 2;
    moved.parent_revision_hash = Some(old.revision_hash().unwrap());
    moved.targets[0].resource.native_id =
        "projects/vdg-example-000000/instances/another-instance".into();
    assert_eq!(
        prepare(&moved, &[], Some(&old)).unwrap_err(),
        ChangeError::RevokePlanRequired
    );
}

#[test]
fn referenced_profile_changes_are_visible_even_when_grant_fields_are_unchanged() {
    let old = policy();
    let mut next = old.clone();
    next.revision = 2;
    next.parent_revision_hash = Some(old.revision_hash().unwrap());
    next.protection_profiles[0].management_exceptions[0].reason_code =
        "updated-recovery-purpose".into();
    let change = prepare(&next, &[], Some(&old)).unwrap();
    assert!(change.differences.iter().any(
        |row| row.field == DifferenceField::PolicyGrant && row.kind == DifferenceKind::Changed
    ));
}

#[test]
fn a_parent_digest_alone_cannot_hide_unplanned_revocation_in_a_later_revision() {
    let old = policy();
    let mut next = old.clone();
    next.revision = 2;
    next.parent_revision_hash = Some(old.revision_hash().unwrap());
    assert_eq!(
        prepare(&next, &[], None).unwrap_err(),
        ChangeError::PreviousPolicyRequired
    );
    prepare(&next, &[], Some(&old)).unwrap();
}
