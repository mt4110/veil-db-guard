use veil_db_guard::core::policy::*;

const EXAMPLE: &str = include_str!("../examples/core-policy.yaml");

#[test]
fn policy_is_normalized_and_hash_tracks_meaning_not_collection_order() {
    let policy = parse_policy(EXAMPLE).unwrap();
    let hash = policy.revision_hash().unwrap();
    let mut reordered = policy.clone();
    reordered.subjects.reverse();
    reordered.protection_profiles[0].allowed_routes.reverse();
    reordered.targets[0].managed_surface.fields.reverse();
    reordered.grants[0].sql_access.privileges[0]
        .actions
        .reverse();
    assert_eq!(hash, reordered.revision_hash().unwrap());
    reordered.grants[0].sql_access.privileges[0].actions.pop();
    assert_ne!(hash, reordered.revision_hash().unwrap());
    assert!(valid_hash(&hash));
}

#[test]
fn strict_parser_rejects_unknown_duplicate_alias_and_interpolation_without_echo() {
    for input in [
        format!("{EXAMPLE}\npassword: SUPER_SECRET_VALUE\n"),
        format!("{EXAMPLE}\nrevision: 8\n"),
        EXAMPLE.replace("billing-protection", "&anchor billing-protection"),
        EXAMPLE.replace("billing-protection", "${SECRET}"),
        EXAMPLE.replace(
            "billing-workload",
            "postgres://user:SUPER_SECRET_VALUE@example.invalid/db",
        ),
        EXAMPLE.replace(
            "projects/vdg-example-000000/instances/billing-postgres",
            "host=db password=SUPER_SECRET_VALUE",
        ),
    ] {
        let error = parse_policy(&input).unwrap_err();
        assert!(!error.to_string().contains("SUPER_SECRET_VALUE"));
        assert!(!format!("{error:?}").contains("SUPER_SECRET_VALUE"));
    }
    assert_eq!(
        parse_policy(&"x".repeat(MAX_POLICY_BYTES + 1)),
        Err(PolicyError::LimitExceeded)
    );
}

#[test]
fn reference_and_conflicting_admission_are_rejected() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.grants[0].subject = "missing-subject".into();
    assert_eq!(policy.validate(), Err(PolicyError::ReferenceInvalid));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    let mut conflicting = policy.grants[0].clone();
    conflicting.id = "deny-app".into();
    conflicting.admission = AdmissionIntent::Deny;
    conflicting.sql_access = SqlAccessIntent::default();
    policy.grants.push(conflicting);
    assert_eq!(policy.validate(), Err(PolicyError::ReferenceInvalid));
}

#[test]
fn exact_managed_scope_and_role_are_not_widened() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.grants[0]
        .sql_access
        .existing_roles
        .push("unmanaged-admin".into());
    assert_eq!(policy.validate(), Err(PolicyError::ScopeViolation));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.grants[0].sql_access.privileges[0].scope.schema = Some("other-schema".into());
    assert_eq!(policy.validate(), Err(PolicyError::ScopeViolation));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.targets[0]
        .managed_surface
        .fields
        .retain(|f| *f != ManagedField::DbObjectPrivilege);
    assert_eq!(policy.validate(), Err(PolicyError::ScopeViolation));
}

#[test]
fn connector_profile_requires_separate_recovery_and_forbids_direct_exception() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.protection_profiles[0].management_exceptions.clear();
    assert_eq!(policy.validate(), Err(PolicyError::ProfileInvalid));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.protection_profiles[0].allowed_routes[1].kind = RouteKind::Direct;
    assert_eq!(policy.validate(), Err(PolicyError::ProfileInvalid));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.subjects[0].identity.credential_source.kind = CredentialSourceKind::NativeSdk;
    assert_eq!(policy.validate(), Err(PolicyError::ProfileInvalid));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.targets[0]
        .managed_surface
        .db_identities
        .push("arbitrary-login".into());
    policy.grants[0].db_identity = "arbitrary-login".into();
    assert_eq!(policy.validate(), Err(PolicyError::ProfileInvalid));
}

#[test]
fn jit_requires_an_explicit_native_or_controller_expiry_contract() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.grants[0].lifetime = GrantLifetime::Lease {
        expires_at_unix: 1_900_000_000,
        expiry_mode: ExpiryMode::ControllerReconciled,
        reconciler_ref: None,
    };
    assert_eq!(policy.validate(), Err(PolicyError::ReferenceInvalid));
    if let GrantLifetime::Lease { reconciler_ref, .. } = &mut policy.grants[0].lifetime {
        *reconciler_ref = Some("explicit-reconciler".into());
    }
    policy.validate().unwrap();
}

#[test]
fn revision_chain_is_explicit_and_native_identifiers_keep_case_and_unicode() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.revision = 2;
    assert_eq!(policy.validate(), Err(PolicyError::Invalid));
    policy.parent_revision_hash = Some("a".repeat(64));
    let role = policy.targets[0]
        .managed_surface
        .db_identities
        .iter_mut()
        .find(|v| **v == "billing-reader-writer")
        .unwrap();
    *role = "売上-ReadWrite".into();
    policy.grants[0].sql_access.existing_roles[0] = "売上-ReadWrite".into();
    policy.validate().unwrap();
    assert!(
        serde_json::to_string(&policy)
            .unwrap()
            .contains("売上-ReadWrite")
    );
}

#[test]
fn standing_grant_cannot_require_an_undefined_lease_expiry_effect() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.protection_profiles[0]
        .required_effects
        .push(EffectKind::LeaseExpired);
    assert_eq!(policy.validate(), Err(PolicyError::ProfileInvalid));
}

#[test]
fn engine_and_placement_are_independent_policy_axes() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.protection_profiles[0].kind = ProfileKind::NativePathV1;
    policy.targets[0].engine.family = EngineFamily::MySql;
    policy.validate().unwrap();
    policy.targets[0].placement.kind = PlacementKind::SelfManaged;
    policy.validate().unwrap();
    // Policy expression is not adapter support or permission to mutate.
    assert_ne!(
        policy.revision_hash().unwrap(),
        parse_policy(EXAMPLE).unwrap().revision_hash().unwrap()
    );
}

#[test]
fn native_resource_cannot_point_outside_declared_cloud_scope() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    policy.targets[0].resource.native_id = "projects/other-project/instances/db".into();
    assert_eq!(policy.validate(), Err(PolicyError::Invalid));
    let mut policy = parse_policy(EXAMPLE).unwrap();
    let target = &mut policy.targets[0];
    target.placement.kind = PlacementKind::AwsRds;
    target.placement.account_id = "123456789012".into();
    target.placement.region = "ap-northeast-1".into();
    target.resource.native_id = "arn:aws:rds:us-east-1:123456789012:db:billing".into();
    assert_eq!(policy.validate(), Err(PolicyError::Invalid));
}

#[test]
fn physical_resource_aliases_cannot_split_target_barriers() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    let mut duplicate = policy.targets[0].clone();
    duplicate.id = "other-logical-target".into();
    duplicate.registration_id = "other-registration".into();
    policy.targets.push(duplicate);
    assert_eq!(policy.validate(), Err(PolicyError::ReferenceInvalid));
}

#[test]
fn recovery_can_have_its_own_managed_grant_without_reusing_app_identity() {
    let mut policy = parse_policy(EXAMPLE).unwrap();
    let login = "recovery@vdg-example-000000.iam".to_string();
    policy.targets[0]
        .managed_surface
        .db_identities
        .push(login.clone());
    policy.grants.push(Grant {
        id: "recovery-access".into(),
        subject: "recovery-operator".into(),
        target: "billing-db".into(),
        db_identity: login,
        admission: AdmissionIntent::Allow,
        sql_access: SqlAccessIntent::default(),
        profile: "gcp-protected".into(),
        lifetime: GrantLifetime::Standing,
    });
    policy.validate().unwrap();
}
