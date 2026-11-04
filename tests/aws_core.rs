//! Synthetic policy/local artifact checks; no AWS process or database connection.
use veil_db_guard::{
    adapters::capabilities_for,
    binding::*,
    core::{change::*, plan::build_plan, policy::*},
};
fn policy() -> PolicyRevision {
    parse_policy(include_str!("../examples/core-aws-policy.yaml")).unwrap()
}
fn prepared(mut p: PolicyRevision) -> PreparedChange {
    p.targets[0].resource.generation_fingerprint = Some(
        veil_db_guard::adapters::deployment::aws::generation_fingerprint(
            &p.targets[0].placement.account_id,
            &p.targets[0].placement.region,
            &p.targets[0].resource.native_id,
            &p.targets[0].aws.as_ref().unwrap().db_resource_id,
        ),
    );
    let graph = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    prepare_change(&p, &graph, &[], None, OperationLimits::default()).unwrap()
}
#[test]
fn aws_profile_binds_native_refs_and_uses_exact_aws_user_not_gcp_mapping() {
    let parsed = policy();
    assert!(parsed.targets[0].resource.generation_fingerprint.is_some());
    let c = prepared(parsed);
    c.verify().unwrap();
    assert_eq!(c.plan.steps.len(), 8);
    assert!(c.plan.capability_gaps.is_empty());
    let profile = connection_profile(&c.policy, "billing-access").unwrap();
    assert_eq!(profile.schema_version, 2);
    assert_eq!(profile.route, BindingRoute::RdsProxy);
    assert_eq!(profile.database_identity, "billing_app");
    assert!(
        profile
            .aws
            .as_ref()
            .unwrap()
            .refresh_token_on_new_connection
    );
    assert_eq!(
        profile.aws.as_ref().unwrap().hostname,
        c.policy.targets[0].aws.as_ref().unwrap().proxy_endpoint
    );
    let sql = veil_db_guard::adapters::engine::postgres::compile(
        &c.policy,
        "billing-db",
        "billing-access",
        veil_db_guard::adapters::engine::postgres::PgAction::RegisterNativeDbIdentity,
    )
    .unwrap();
    assert_eq!(
        sql.statements(),
        &["GRANT \"rds_iam\" TO \"billing_app\" WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"]
    );
}
#[test]
fn cross_account_roles_proxy_rule_and_unsafe_user_are_rejected() {
    let p = policy();
    let mut cross = p.clone();
    cross.targets[0].aws.as_mut().unwrap().proxy_role_arn =
        "arn:aws:iam::999999999999:role/proxy".into();
    assert!(cross.validate().is_err());
    let mut rule = p.clone();
    let account = rule.targets[0].placement.account_id.clone();
    let native = rule.targets[0].aws.as_mut().unwrap();
    native.owned_direct_rules[0].source = AwsRuleSource::SecurityGroup {
        group_id: native.proxy_security_group_id.clone(),
        account_id: account,
    };
    assert!(rule.validate().is_err());
    let mut user = p.clone();
    user.grants[0].db_identity = "rds-db:connect access denied".into();
    user.targets[0]
        .managed_surface
        .db_identities
        .push(user.grants[0].db_identity.clone());
    assert!(user.validate().is_err());
    let mut shared = p;
    shared.subjects[1].identity.principal = shared.subjects[0].identity.principal.clone();
    assert!(shared.validate().is_err());
}
#[test]
fn proxy_rebinding_requires_explicit_retirement_and_shared_proxy_is_locked() {
    let c = prepared(policy());
    let mut next = c.policy.clone();
    next.revision = 2;
    next.parent_revision_hash = Some(c.plan.policy_revision_hash.clone());
    next.targets[0].aws.as_mut().unwrap().proxy_arn =
        "arn:aws:rds:ap-northeast-1:123456789012:db-proxy:prx-other".into();
    let graph = build_plan(
        &next,
        next.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        110,
    )
    .unwrap();
    assert_eq!(
        prepare_change(&next, &graph, &[], Some(&c.policy), c.limits.clone()).unwrap_err(),
        ChangeError::RevokePlanRequired
    );
    assert!(
        c.conflict_keys
            .iter()
            .any(|k| k.field_or_domain == "ingress")
    );
    assert!(
        c.conflict_keys
            .iter()
            .filter(|k| k.field_or_domain == "*")
            .count()
            >= 2
    );
}
#[test]
fn preparation_declaration_is_baseline_bound_and_separate_from_cutover() {
    let c = prepared(policy());
    let receipt = ManualCheckpoint::attest_preparation(
        &c,
        "billing-db",
        "recovery-operator",
        &"a".repeat(64),
        100,
        400,
    )
    .unwrap();
    let gate = ManualCheckpoints {
        receipts: vec![receipt],
    };
    assert!(
        gate.validate_preparation(&c, "billing-db", &"a".repeat(64), 101)
            .is_ok()
    );
    assert!(
        gate.validate_preparation(&c, "billing-db", &"b".repeat(64), 101)
            .is_err()
    );
    assert!(gate.validate_native_cutover(&c, "billing-db", 101).is_err());
    assert!(
        ManualCheckpoint::attest(
            &c,
            "billing-db",
            CheckpointKind::NativePreparationReady,
            "recovery-operator",
            100,
            400
        )
        .is_err()
    );
}
#[test]
fn current_cli_host_allowed_capture_never_proves_all_workload_sources() {
    use veil_db_guard::{
        adapters::{
            aws_observation::{AccessRecord, AwsAccessCapture, DirectOutcome},
            deployment::aws::Access,
            state::evaluate_run,
        },
        core::state::{StateAssessment, StateValue},
        store::{RunStatus, RunWriter},
    };
    let c = prepared(policy());
    let target = &c.policy.targets[0];
    let native = target.aws.as_ref().unwrap();
    let capture = AwsAccessCapture {
        schema_version: 1,
        policy_revision_hash: c.plan.policy_revision_hash.clone(),
        target_id: target.id.clone(),
        generation: target.resource.generation_fingerprint.clone().unwrap(),
        proxy_arn: native.proxy_arn.clone(),
        started_at: 100,
        finished_at: 105,
        complete: true,
        direct: DirectOutcome::Refused,
        observations: vec![AccessRecord {
            subject_id: "billing-app".into(),
            principal: c
                .policy
                .subjects
                .iter()
                .find(|s| s.id == "billing-app")
                .unwrap()
                .identity
                .principal
                .clone(),
            db_user: "billing_app".into(),
            identity_verified: true,
            tls_verified: true,
            access: Access::Allowed,
            iam_denial: false,
            reason: "verified_proxy_sql".into(),
        }],
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aws-capture");
    let mut writer = RunWriter::create_for_config(
        &path,
        &target.id,
        &c.policy,
        "aws-guard-check",
        8 * 1024 * 1024,
        false,
    )
    .unwrap();
    writer.write_json("aws-access.json", &capture).unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    let report = evaluate_run(&c, &path, 106).unwrap();
    assert!(!report.all_required_effects_satisfied);
    assert!(!report.protection_evaluated);
    assert!(
        report
            .rows
            .iter()
            .filter(|r| r.desired.scope.route.kind == RouteKind::Direct)
            .all(|r| r.observed == StateValue::Unknown)
    );
    assert!(
        report
            .rows
            .iter()
            .any(|r| r.observed == StateValue::Allowed && r.assessment == StateAssessment::Unknown)
    );
    std::fs::write(path.join("aws-access.json"), b"{}\n").unwrap();
    assert!(evaluate_run(&c, &path, 106).is_err());
}

#[test]
fn saved_aws_allowed_observation_is_scope_bound_and_keeps_partial_state() {
    use std::collections::BTreeSet;
    use veil_db_guard::{
        adapters::deployment::aws::{Access, RevocationEvidence},
        aws_native_cli::{AwsNativeStateRecord, load_state_record},
        core::lifecycle::{LifecycleKind, prepare_maintenance},
        store::{RunStatus, RunWriter},
    };
    let source = prepared(policy());
    let change = prepare_maintenance(
        &source,
        "source",
        LifecycleKind::Revoke,
        "billing-access",
        &[],
        source.plan.capabilities.clone(),
        110,
        source.limits.clone(),
        false,
    )
    .unwrap();
    let observation = RevocationEvidence {
        complete: false,
        generation: change.policy.targets[0]
            .resource
            .generation_fingerprint
            .clone()
            .unwrap(),
        observed_at: 110,
        denied_principal: change
            .policy
            .subjects
            .iter()
            .find(|s| s.id == "billing-app")
            .unwrap()
            .identity
            .principal
            .clone(),
        access: Access::Allowed,
        iam_connect_denied: false,
        proxy_allowed_principals: BTreeSet::new(),
        direct_denied_principals: BTreeSet::new(),
        evidence_refs: vec!["b".repeat(64)],
    };
    let record = AwsNativeStateRecord {
        schema_version: 1,
        operation_id: "revoke".into(),
        change_hash: change.change_hash.clone(),
        policy_revision_hash: change.plan.policy_revision_hash.clone(),
        observation,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aws-state");
    let mut writer = RunWriter::create_for_config(
        &path,
        &change.policy.policy_id,
        &change.policy,
        "aws-guard-state",
        8 * 1024 * 1024,
        false,
    )
    .unwrap();
    writer.write_json("effective-state.json", &record).unwrap();
    writer.finish(RunStatus::Partial).unwrap();
    assert_eq!(
        load_state_record(&change, "revoke", &path)
            .unwrap()
            .observation
            .access,
        Access::Allowed
    );
    assert!(load_state_record(&change, "another-operation", &path).is_err());
    let generic =
        veil_db_guard::native_cli::load_any_state_record(&change, "revoke", &path).unwrap();
    assert_eq!(generic["observation"]["access"], "allowed");
    std::fs::write(path.join("effective-state.json"), b"{}\n").unwrap();
    assert!(load_state_record(&change, "revoke", &path).is_err());
}
