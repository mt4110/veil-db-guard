mod common;
use serde_json::Value;
use veil_db_guard::{config::GuardError, domain::*, planner::*};
#[test]
fn plan_without_snapshot_stays_operation_only_and_requires_evidence() {
    let p = plan(&common::config(), None).unwrap();
    assert!(p.operation_only);
    assert!(!p.snapshot_available);
    assert!(p.bootstrap_required);
    assert!(p.unknowns.contains(&ReasonCode::SnapshotIncomplete));
    assert!(p.unknowns.contains(&ReasonCode::MissingEvidence));
    assert!(
        p.changes
            .iter()
            .any(|x| x.code == "INVENTORY_REQUIRED_BEFORE_EXISTING_DB_CHANGE" && x.required)
    );
}
#[test]
fn plan_rejects_other_targets_and_marks_pending_parameters_for_review() {
    let c = common::config();
    let mut s = common::snapshot();
    s.target.id = "other".into();
    assert_eq!(plan(&c, Some(&s)).unwrap_err(), GuardError::TargetMismatch);
    let mut s = common::snapshot();
    s.db.as_mut().unwrap().parameters_in_sync = false;
    let p = plan(&c, Some(&s)).unwrap();
    assert!(
        p.changes
            .iter()
            .any(|x| x.code == "REVIEW_DB_TLS_AND_PARAMETER_APPLICATION"
                && x.required
                && x.verification_ids == ["V08"])
    );
    assert!(
        p.changes
            .iter()
            .any(|x| x.code == "REVIEW_PUBLIC_AND_ALL_SECURITY_GROUP_PATHS" && x.required)
    );
}
#[test]
fn sandbox_is_parseable_dedicated_new_resources_with_separate_roles_and_no_existing_db_import() {
    let c = common::config();
    let text = sandbox_template(&c);
    let v: Value = serde_saphyr::from_str(&text).unwrap();
    let resources = v["Resources"].as_object().unwrap();
    for key in [
        "Vpc",
        "SubnetA",
        "SubnetB",
        "Database",
        "Proxy",
        "ProxyTargetGroup",
        "ApplicationRunner",
        "DeniedRunner",
        "AdminRunner",
        "SsmEndpoint",
        "SsmMessagesEndpoint",
        "SecretsEndpoint",
    ] {
        assert!(resources.contains_key(key), "{key}");
    }
    assert_eq!(
        v["Resources"]["Proxy"]["Properties"]["DefaultAuthScheme"].as_str(),
        Some("IAM_AUTH")
    );
    assert_eq!(
        v["Resources"]["Proxy"]["Properties"]["RequireTLS"].as_bool(),
        Some(true)
    );
    assert_eq!(
        v["Resources"]["Database"]["Properties"]["EngineVersion"].as_str(),
        Some("16.15")
    );
    assert_eq!(
        v["Resources"]["Database"]["Properties"]["PubliclyAccessible"].as_bool(),
        Some(false)
    );
    assert_eq!(
        v["Resources"]["Database"]["DeletionPolicy"].as_str(),
        Some("Snapshot")
    );
    assert!(v["Resources"]["DeniedRole"]["Properties"]["Policies"].is_null());
    assert_eq!(
        v["Resources"]["DbSecurityGroup"]["Properties"]["SecurityGroupIngress"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(!text.contains(&c.target.db_instance_arn));
    assert!(!text.contains(&c.target.proxy_arn));
    assert!(!text.contains("DBSnapshotIdentifier"));
    assert!(v["Resources"]["Database"]["Properties"]["MasterUserPassword"].is_null());
    assert!(!text.contains("UserData:"));
    assert!(!text.contains("@DBUSER@"));
    assert!(!text.contains("@VERSION@"));
    // JSON normalization does not preserve YAML tags: verify the emitted intrinsic
    // syntax separately, so parsing cannot hide accidentally removed CFN references.
    assert!(text.contains("VpcId: !Ref Vpc"));
    assert!(text.contains("DBProxyName: !Ref Proxy"));
    assert!(text.contains("!GetAtt Database.Endpoint.Address"));
    assert!(text.contains("Resource: !Sub arn:${AWS::Partition}:rds-db:"));
    assert!(text.contains("UNAPPLIED"));
    assert!(text.contains("retains a charged final DB snapshot"));
}
#[test]
fn bootstrap_is_separate_secret_free_non_destructive_sql() {
    let c = common::config();
    let sql = bootstrap_sql(&c);
    assert!(sql.contains("GRANT rds_iam"));
    assert!(sql.contains("GRANT CONNECT, CREATE ON DATABASE \"vdg_lab\" TO \"vdg_probe\""));
    assert!(sql.contains("current_database() <> 'vdg_lab'"));
    assert!(sql.contains("current_user <> 'bootstrap_admin'"));
    assert!(sql.contains("Do not run on an existing/customer DB"));
    assert!(sql.contains("CREATE SCHEMA"));
    assert!(sql.contains("BEGIN;"));
    assert!(sql.contains("COMMIT;"));
    assert!(!sql.contains("PASSWORD"));
    assert!(!sql.contains("DROP "));
    assert!(!sql.contains("DELETE "));
    assert!(!sql.contains("IF NOT EXISTS"));
    let mut no_scope = c.clone();
    no_scope.test_scope = None;
    assert!(bootstrap_sql(&no_scope).contains("CONFIG_INVALID"));
    let mut existing = c.clone();
    existing.assessment_profile = Profile::ExistingDbCoreV1;
    assert!(bootstrap_sql(&existing).starts_with("-- CONFIG_INVALID"));
    assert!(sandbox_template(&existing).starts_with("# CONFIG_INVALID"));
    let mut system_database = c.clone();
    system_database.test_scope.as_mut().unwrap().database = "postgres".into();
    assert!(bootstrap_sql(&system_database).starts_with("-- CONFIG_INVALID"));
    let mut invalid = c;
    invalid.auth.db_user = "injected; DROP ROLE x;".into();
    assert!(sandbox_template(&invalid).starts_with("# CONFIG_INVALID"));
    assert!(bootstrap_sql(&invalid).starts_with("-- CONFIG_INVALID"));
}
