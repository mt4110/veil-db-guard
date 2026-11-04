//! Synthetic policy and adapter composition checks. No native connections.
use veil_db_guard::{
    adapters::{
        capabilities_for,
        engine::{mysql, postgres},
    },
    binding::connection_profile,
    core::{change::*, plan::build_plan, policy::*},
};

fn policy() -> PolicyRevision {
    parse_policy(include_str!("../examples/core-aws-mysql-policy.yaml")).unwrap()
}
fn prepared(p: &PolicyRevision) -> PreparedChange {
    let graph = build_plan(
        p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    prepare_change(p, &graph, &[], None, OperationLimits::default()).unwrap()
}

#[test]
fn mysql_uses_common_eight_steps_but_exact_mysql_account_and_transport() {
    let c = prepared(&policy());
    c.verify().unwrap();
    assert_eq!(c.plan.steps.len(), 8);
    assert!(c.plan.capability_gaps.is_empty());
    assert!(
        c.plan
            .steps
            .iter()
            .all(|s| s.adapter_contract == "core-adapter-v3")
    );
    let profile = connection_profile(&c.policy, "billing-access").unwrap();
    assert_eq!(profile.schema_version, 3);
    assert_eq!(profile.database_identity, "billing_app");
    assert_eq!(profile.mysql_account_host.as_deref(), Some("%"));
    assert_eq!(profile.aws.as_ref().unwrap().port, 3306);
    let sql = mysql::compile(
        &c.policy,
        "billing-db",
        "billing-access",
        mysql::MysqlAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    assert!(
        sql.statements()
            .iter()
            .all(|s| s.contains("`billing`.`invoices`")
                && s.contains("'billing_app'@'%'")
                && !s.contains("rds_iam"))
    );
    assert!(
        postgres::compile(
            &c.policy,
            "billing-db",
            "billing-access",
            postgres::PgAction::ConfigureSqlPrivileges
        )
        .is_err()
    );
    let native = mysql::compile(
        &c.policy,
        "billing-db",
        "billing-access",
        mysql::MysqlAction::RegisterNativeDbIdentity,
    )
    .unwrap();
    assert!(
        native.statements().is_empty(),
        "preconfigured plugin is verified without changing a password login"
    );
}

#[test]
fn profile_engine_account_host_and_native_port_cannot_be_substituted() {
    let p = policy();
    let mut wrong = p.clone();
    wrong.protection_profiles[0].kind = ProfileKind::AwsRdsPostgresProxyV1;
    assert!(wrong.validate().is_err());
    wrong = p.clone();
    wrong.targets[0].mysql.as_mut().unwrap().account_host = "bad' OR 1=1".into();
    assert!(wrong.validate().is_err());
    wrong = p.clone();
    wrong.targets[0].aws.as_mut().unwrap().owned_direct_rules[0].from_port = 5432;
    assert!(wrong.validate().is_err());
    wrong = p.clone();
    wrong.targets[0].mysql = None;
    assert!(wrong.validate().is_err());
    wrong = p.clone();
    wrong.grants[0].db_identity = "a".repeat(33);
    wrong.targets[0].managed_surface.db_identities = vec![wrong.grants[0].db_identity.clone()];
    assert!(wrong.validate().is_err());
    wrong = p;
    wrong.targets[0].engine.version = "8.4.7".into();
    assert!(prepared(&wrong).plan.capability_gaps.len() >= 8);
}

#[test]
fn mysql_host_rebinding_requires_an_explicit_revocation_plan() {
    let c = prepared(&policy());
    let mut next = c.policy.clone();
    next.revision += 1;
    next.parent_revision_hash = Some(c.plan.policy_revision_hash.clone());
    next.targets[0].mysql.as_mut().unwrap().account_host = "10.0.0.5".into();
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
}

#[test]
fn postgres_remains_a_separate_implemented_path_with_stable_optional_fields() {
    for input in [
        include_str!("../examples/core-aws-policy.yaml"),
        include_str!("../examples/core-policy.yaml"),
    ] {
        let p = parse_policy(input).unwrap();
        let c = prepared(&p);
        assert!(c.plan.capability_gaps.is_empty());
        let json = serde_json::to_value(&c.policy).unwrap();
        assert!(json["targets"][0].get("mysql").is_none());
        let binding = connection_profile(&c.policy, "billing-access").unwrap();
        assert!(binding.mysql_account_host.is_none());
        assert!(
            serde_json::to_value(&binding)
                .unwrap()
                .get("mysql_account_host")
                .is_none()
        );
        if let Some(aws) = binding.aws {
            assert_eq!(aws.port, 5432);
        }
        assert!(
            mysql::compile(
                &p,
                "billing-db",
                "billing-access",
                mysql::MysqlAction::ConfigureSqlPrivileges
            )
            .is_err()
        );
        assert!(
            postgres::compile(
                &p,
                "billing-db",
                "billing-access",
                postgres::PgAction::ConfigureSqlPrivileges
            )
            .is_ok()
        );
    }
}
