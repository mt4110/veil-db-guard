//! Offline compatibility checks; no process, cloud, DB or future handoff proof.
use veil_db_guard::{
    adapters::{capabilities_for, qualification::*},
    core::{capability::ActionKind, change::*, lifecycle::*, plan::build_plan, policy::*},
};

fn policy(input: &str) -> PolicyRevision {
    parse_policy(input).unwrap()
}
fn gcp() -> PolicyRevision {
    policy(include_str!("../examples/core-policy.yaml"))
}
fn aws() -> PolicyRevision {
    policy(include_str!("../examples/core-aws-policy.yaml"))
}
fn mysql() -> PolicyRevision {
    policy(include_str!("../examples/core-aws-mysql-policy.yaml"))
}
fn prepared(p: &PolicyRevision) -> PreparedChange {
    let plan = build_plan(
        p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    prepare_change(p, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn reasons(report: &QualificationReport, reason: QualificationReason) -> bool {
    report.findings.iter().any(|f| f.reason == reason)
}
fn pin_references(p: &mut PolicyRevision) {
    p.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    for (index, subject) in p.subjects.iter_mut().enumerate() {
        if subject.identity.immutable_id.is_none() {
            subject.identity.immutable_id = Some(format!("{}", index + 1));
        }
    }
}

#[test]
fn known_subsets_qualify_without_future_checkpoints_or_live_generation() {
    for mut p in [gcp(), aws(), mysql()] {
        let c = prepared(&p);
        let report = qualify_change(&c).unwrap();
        assert!(report.is_qualified(), "{:?}", report.findings);
        assert_eq!(report.change_hash, c.change_hash);
        assert_eq!(report.policy_revision_hash, c.plan.policy_revision_hash);
        assert!(report.readiness_only);
        assert!(!report.runtime_verified);
        if p.targets[0].placement.kind == PlacementKind::GcpCloudSql {
            assert!(
                !report.is_dispatch_qualified(),
                "GCP example has unpinned references"
            );
        }
        assert!(reasons(
            &report,
            QualificationReason::RuntimeStateNotVerified
        ));
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains("GRANT "));
        assert_eq!(report, qualify_change(&c).unwrap());
        assert!(report.findings.windows(2).all(|w| w[0] < w[1]));
        pin_references(&mut p);
        assert!(
            qualify_change(&prepared(&p))
                .unwrap()
                .is_dispatch_qualified(),
            "pinned inputs require no future checkpoint or runtime success to pass static qualification"
        );
    }
}

#[test]
fn pg_routine_is_reported_with_exact_object_before_any_action_dispatch() {
    for mut p in [gcp(), aws()] {
        let privilege = &mut p.grants[0].sql_access.privileges[0];
        privilege.scope.kind = SqlObjectKind::Routine;
        privilege.scope.object = Some("calculate_invoice".into());
        privilege.actions = vec![SqlAction::Execute];
        let report = qualify_change(&prepared(&p)).unwrap();
        assert!(!report.is_qualified());
        let f = report
            .findings
            .iter()
            .find(|f| f.reason == QualificationReason::PostgresSqlUnsupported)
            .unwrap();
        assert_eq!(f.target_id.as_deref(), Some("billing-db"));
        assert_eq!(f.grant_id.as_deref(), Some("billing-access"));
        assert!(f.step_id.is_some());
        assert_eq!(f.action, Some(ActionKind::ConfigureSqlPrivileges));
        assert!(
            matches!(&f.scope, QualificationScope::SqlScope {scope} if scope.kind == SqlObjectKind::Routine && scope.object.as_deref() == Some("calculate_invoice"))
        );
    }
}

#[test]
fn mysql_roles_and_non_table_and_foreign_schema_remain_separate_gaps() {
    let mut p = mysql();
    p.grants[0].sql_access.existing_roles = vec!["billing_reader_writer".into()];
    p.targets[0]
        .managed_surface
        .db_identities
        .push("billing_reader_writer".into());
    p.targets[0]
        .managed_surface
        .fields
        .push(ManagedField::DbRole);
    let report = qualify_change(&prepared(&p)).unwrap();
    assert!(!report.is_qualified());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.reason == QualificationReason::MysqlSqlScope
                && f.scope == QualificationScope::ExistingRoles)
    );

    let mut p = mysql();
    p.grants[0].sql_access.privileges[0].scope.kind = SqlObjectKind::Schema;
    p.grants[0].sql_access.privileges[0].scope.object = None;
    p.grants[0].sql_access.privileges[0].actions = vec![SqlAction::Usage];
    assert!(reasons(
        &qualify_change(&prepared(&p)).unwrap(),
        QualificationReason::MysqlSqlUnsupported
    ));

    let mut p = mysql();
    p.targets[0].managed_surface.sql_scopes[0].schema = Some("foreign".into());
    p.grants[0].sql_access.privileges[0].scope.schema = Some("foreign".into());
    assert!(reasons(
        &qualify_change(&prepared(&p)).unwrap(),
        QualificationReason::MysqlSqlScope
    ));
}

#[test]
fn compiler_identifier_and_database_bounds_are_not_diluted() {
    let mut p = gcp();
    p.grants[0].sql_access.privileges[0].scope.object = Some("x".repeat(64));
    assert!(reasons(
        &qualify_change(&prepared(&p)).unwrap(),
        QualificationReason::PostgresSqlScope
    ));
    let mut p = gcp();
    p.targets[0].managed_surface.sql_scopes[0].database = "other".into();
    p.grants[0].sql_access.privileges[0].scope.database = "other".into();
    assert!(
        p.validate().is_err(),
        "core rejects the cross-database managed surface before qualification"
    );
}

#[test]
fn shared_logins_are_static_gaps() {
    let mut p = aws();
    let mut other = p.grants[0].clone();
    other.id = "other-access".into();
    let mut subject = p.subjects[0].clone();
    subject.id = "other-app".into();
    subject.identity.principal = "arn:aws:iam::123456789012:role/other-app".into();
    subject.identity.immutable_id = Some("AROA00000000000000004".into());
    other.subject = subject.id.clone();
    p.subjects.push(subject);
    p.grants.push(other);
    let report = qualify_change(&prepared(&p)).unwrap();
    assert!(!report.is_qualified());
    assert!(reasons(
        &report,
        QualificationReason::SharedLoginUnsupported
    ));
}

#[test]
fn aws_principal_limit_and_single_recovery_are_checked_without_native_metadata() {
    let mut p = aws();
    for index in 1..8 {
        let mut subject = p.subjects[0].clone();
        subject.id = format!("app-{index}");
        subject.identity.principal = format!("arn:aws:iam::123456789012:role/app-{index}");
        subject.identity.immutable_id = Some(format!("AROA{:017}", index + 10));
        let mut grant = p.grants[0].clone();
        grant.id = format!("access-{index}");
        grant.subject = subject.id.clone();
        grant.db_identity = format!("app_{index}");
        p.targets[0]
            .managed_surface
            .db_identities
            .push(grant.db_identity.clone());
        p.subjects.push(subject);
        p.grants.push(grant);
    }
    let report = qualify_change(&prepared(&p)).unwrap();
    assert!(!report.is_qualified());
    assert!(reasons(
        &report,
        QualificationReason::PrincipalLimitExceeded
    ));

    let mut p = aws();
    let mut second = p.subjects[1].clone();
    second.id = "other-recovery".into();
    second.identity.principal = "arn:aws:iam::123456789012:role/other-recovery".into();
    second.identity.immutable_id = Some("AROA00000000000000004".into());
    let mut exception = p.protection_profiles[0].management_exceptions[0].clone();
    exception.id = "other-recovery".into();
    exception.subject = second.id.clone();
    p.subjects.push(second);
    p.protection_profiles[0]
        .management_exceptions
        .push(exception);
    let report = qualify_change(&prepared(&p)).unwrap();
    assert!(!report.is_qualified());
    assert!(reasons(
        &report,
        QualificationReason::ExactlyOneRecoveryRequired
    ));
}

#[test]
fn current_registry_rejects_old_stored_contract_claims() {
    let p = aws();
    let mut descriptors: Vec<_> = p.targets.iter().flat_map(capabilities_for).collect();
    for descriptor in &mut descriptors {
        descriptor.contract_revision = "old-contract".into();
    }
    let graph = build_plan(&p, descriptors, vec![], 100).unwrap();
    let c = prepare_change(&p, &graph, &[], None, OperationLimits::default()).unwrap();
    assert!(
        c.plan.capability_gaps.is_empty(),
        "stored claims alone still say implemented"
    );
    let report = qualify_change(&c).unwrap();
    assert!(!report.is_qualified());
    assert!(reasons(&report, QualificationReason::ContractMismatch));
}

#[test]
fn claimed_implementations_cannot_register_an_unimplemented_action() {
    let mut p = aws();
    p.protection_profiles[0]
        .required_effects
        .push(EffectKind::SessionsTerminated);
    let mut descriptors: Vec<_> = p.targets.iter().flat_map(capabilities_for).collect();
    for descriptor in &mut descriptors {
        descriptor.support = veil_db_guard::core::capability::Support::Supported;
        descriptor.implementation = veil_db_guard::core::capability::Implementation::Implemented;
    }
    let graph = build_plan(&p, descriptors, vec![], 100).unwrap();
    let c = prepare_change(&p, &graph, &[], None, OperationLimits::default()).unwrap();
    let report = qualify_change(&c).unwrap();
    assert!(!report.is_qualified());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.action == Some(ActionKind::TerminateSelectedSessions)
                && f.reason == QualificationReason::ActionNotImplemented)
    );
}

#[test]
fn revoke_defers_ownership_to_runtime_factory_and_keeps_source_validation() {
    for mut p in [gcp(), aws(), mysql()] {
        if !p.targets[0]
            .managed_surface
            .fields
            .contains(&ManagedField::DbRole)
        {
            p.targets[0]
                .managed_surface
                .fields
                .push(ManagedField::DbRole);
        }
        pin_references(&mut p);
        let source = prepared(&p);
        let c = prepare_maintenance(
            &source,
            "source-operation",
            LifecycleKind::Revoke,
            "billing-access",
            &[],
            p.targets.iter().flat_map(capabilities_for).collect(),
            110,
            source.limits.clone(),
            true,
        )
        .unwrap_or_else(|e| panic!("{:?}: {e:?}", p.targets[0].engine.family));
        let report = qualify_change(&c).unwrap();
        assert!(report.is_qualified(), "{:?}", report.findings);
        assert!(
            report.is_dispatch_qualified(),
            "ownership must be checked at its runtime stage"
        );
        assert!(reasons(
            &report,
            QualificationReason::OwnedSqlReceiptRequired
        ));
        let mut altered = c;
        altered.lifecycle.as_mut().unwrap().source_change_hash = "not-a-hash".into();
        assert_eq!(
            qualify_change(&altered),
            Err(QualificationError::InvalidChange)
        );
    }
}

#[test]
fn maintenance_qualifies_only_selected_sql_actions() {
    let mut p = gcp();
    let mut unrelated_subject = p
        .subjects
        .iter()
        .find(|s| s.kind == SubjectKind::Application)
        .unwrap()
        .clone();
    unrelated_subject.id = "unrelated-app".into();
    unrelated_subject.identity.principal =
        "unrelated@vdg-example-000000.iam.gserviceaccount.com".into();
    unrelated_subject.identity.immutable_id = Some("333333333333333333333".into());
    p.subjects.push(unrelated_subject);
    let mut unrelated = p.grants[0].clone();
    unrelated.id = "unrelated-access".into();
    unrelated.subject = "unrelated-app".into();
    unrelated.db_identity = "unrelated@vdg-example-000000.iam".into();
    unrelated.sql_access.privileges[0].scope.kind = SqlObjectKind::Routine;
    unrelated.sql_access.privileges[0].actions = vec![SqlAction::Execute];
    p.targets[0]
        .managed_surface
        .db_identities
        .push(unrelated.db_identity.clone());
    p.grants.push(unrelated);
    let source = prepared(&p);
    assert!(!qualify_change(&source).unwrap().is_qualified());
    let c = prepare_maintenance(
        &source,
        "source-operation",
        LifecycleKind::Recover,
        "billing-access",
        &[],
        p.targets.iter().flat_map(capabilities_for).collect(),
        110,
        source.limits.clone(),
        false,
    )
    .unwrap();
    assert!(c.plan.steps.iter().all(|s| s.grant_id == "billing-access"));
    assert!(qualify_change(&c).unwrap().is_qualified());
}
