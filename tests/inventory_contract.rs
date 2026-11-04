use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex, time::Duration};
use tokio_util::sync::CancellationToken;
use veil_db_guard::{
    aws_inventory::*,
    config::{GuardError, validate_config},
    domain::*,
};
fn config() -> TargetConfig {
    serde_json::from_value(json!({"schema_version":1,"assessment_profile":"local_contract_v1","experiment_id":"fixture","phase_id":"baseline","configuration_epoch":"one",
        "target":{"id":"fixture","account_id":"111111111111","region":"ap-northeast-1","db_instance_arn":"arn:aws:rds:ap-northeast-1:111111111111:db:vdg-db","proxy_arn":"arn:aws:rds:ap-northeast-1:111111111111:db-proxy:prx-fixture","proxy_name":"vdg-proxy","engine":"postgres","engine_version":"16.15"},
        "auth":{"mode":"end_to_end_iam","db_user":"vdg_user"},"sources":[{"id":"app","kind":"local_lab"}],
        "paths":[{"id":"proxy","source_id":"app","actor":"application","destination":"proxy","expected":"allow","address_family":"ipv4"},{"id":"direct","source_id":"app","actor":"application","destination":"database","expected":"deny","address_family":"ipv4"}]})).unwrap()
}
fn fixture() -> BTreeMap<String, Value> {
    let c = config();
    BTreeMap::from([
        (
            "describe-db-proxies".into(),
            json!({"DBProxies":[{"DBProxyArn":c.target.proxy_arn,"DBProxyName":"vdg-proxy","DefaultAuthScheme":"IAM_AUTH","EngineFamily":"POSTGRESQL","Endpoint":"vdg-proxy.proxy-abcd.ap-northeast-1.rds.amazonaws.com","RequireTLS":true,"VpcSecurityGroupIds":["sg-12345678"],"RoleArn":"arn:aws:iam::111111111111:role/ProxyRole","Description":"sensitive-not-preserved"}]}),
        ),
        (
            "describe-db-instances".into(),
            json!({"DBInstances":[{"DBInstanceArn":c.target.db_instance_arn,"DBInstanceIdentifier":"vdg-db","DbiResourceId":"db-IMMUTABLE","Endpoint":{"Address":"vdg-db.abcd.ap-northeast-1.rds.amazonaws.com","Port":5432},"Engine":"postgres","EngineVersion":"16.15","DBInstanceClass":"db.t4g.medium","AvailabilityZone":"ap-northeast-1a","IAMDatabaseAuthenticationEnabled":true,"PubliclyAccessible":false,"VpcSecurityGroups":[{"VpcSecurityGroupId":"sg-87654321"},{"VpcSecurityGroupId":"sg-abcdef01"}],"DBParameterGroups":[{"DBParameterGroupName":"default.postgres16","ParameterApplyStatus":"in-sync"}]}]}),
        ),
        (
            "describe-db-proxy-targets".into(),
            json!({"Targets":[{"RdsResourceId":"vdg-db","Endpoint":"vdg-db.abcd.ap-northeast-1.rds.amazonaws.com","Port":5432,"Type":"RDS_INSTANCE","Role":"READ_WRITE","TargetHealth":{"State":"AVAILABLE","Description":"secret-detail-not-preserved"}}]}),
        ),
        (
            "describe-db-proxy-target-groups".into(),
            json!({"TargetGroups":[{"DBProxyName":"vdg-proxy","TargetGroupName":"default","ConnectionPoolConfig":{"InitQuery":"sensitive-init-not-preserved"}}]}),
        ),
        (
            "describe-db-parameters".into(),
            json!({"Parameters":[{"ParameterName":"rds.force_ssl","ParameterValue":"1"}]}),
        ),
        (
            "describe-security-groups".into(),
            json!({"SecurityGroups":[
                {"GroupId":"sg-12345678","OwnerId":"111111111111","VpcId":"vpc-12345678","IpPermissions":[]},
                {"GroupId":"sg-87654321","OwnerId":"111111111111","VpcId":"vpc-12345678","IpPermissions":[{"IpProtocol":"tcp","FromPort":5432,"ToPort":5432,"UserIdGroupPairs":[{"GroupId":"sg-12345678"}]}]},
                {"GroupId":"sg-abcdef01","OwnerId":"111111111111","VpcId":"vpc-12345678","IpPermissions":[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"sensitive-rule-not-preserved"}],"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]}
            ]}),
        ),
    ])
}
#[test]
fn normalizes_official_target_name_and_preserves_all_sg_rules_without_free_text() {
    let c = config();
    validate_config(&c).unwrap();
    let s = normalize(&c, &fixture()).unwrap();
    assert_eq!(s.evidence_kind, EvidenceKind::LocalFixture);
    assert_eq!(
        s.proxy.unwrap().target_db_resource_id.as_deref(),
        Some("db-IMMUTABLE")
    );
    assert_eq!(s.security_groups.len(), 3);
    assert_eq!(s.security_groups[2].ingress.len(), 2);
    assert!(s.db.unwrap().force_ssl.unwrap());
    let text = serde_json::to_string(&normalize(&c, &fixture()).unwrap()).unwrap();
    assert!(!text.contains("sensitive"));
    assert!(!text.contains("secret-detail"));
}
#[test]
fn pending_reboot_is_not_runtime_ssl_evidence() {
    let mut data = fixture();
    data.get_mut("describe-db-instances").unwrap()["DBInstances"][0]["DBParameterGroups"][0]["ParameterApplyStatus"] =
        json!("pending-reboot");
    let s = normalize(&config(), &data).unwrap();
    assert_eq!(s.db.as_ref().unwrap().force_ssl, Some(true));
    assert!(!s.db.unwrap().parameters_in_sync);
}
#[test]
fn partial_denied_missing_and_unsupported_sg_sources_do_not_become_complete() {
    let mut data = fixture();
    data.get_mut("describe-security-groups").unwrap()["NextToken"] =
        json!("private-pagination-not-saved");
    data.insert(
        "describe-db-parameters".into(),
        json!({"_error":"access_denied"}),
    );
    let s = normalize(&config(), &data).unwrap();
    assert_eq!(s.retrievals[4].status, RetrievalStatus::AccessDenied);
    assert_eq!(s.retrievals[5].status, RetrievalStatus::Partial);
    assert_eq!(s.db.unwrap().force_ssl, None);
    data.get_mut("describe-security-groups")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("NextToken");
    data.get_mut("describe-security-groups").unwrap()["SecurityGroups"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert_eq!(
        normalize(&config(), &data).unwrap().retrievals[5].status,
        RetrievalStatus::Partial
    );
}
#[test]
fn mismatched_arn_or_target_name_is_rejected() {
    for (op, pointer, value) in [
        (
            "describe-db-proxies",
            "/DBProxies/0/DBProxyArn",
            "arn:aws:rds:ap-northeast-1:222222222222:db-proxy:other",
        ),
        (
            "describe-db-proxy-targets",
            "/Targets/0/RdsResourceId",
            "other-db",
        ),
        (
            "describe-db-proxy-targets",
            "/Targets/0/Endpoint",
            "other.abcd.ap-northeast-1.rds.amazonaws.com",
        ),
    ] {
        let mut d = fixture();
        *d.get_mut(op).unwrap().pointer_mut(pointer).unwrap() = json!(value);
        assert_eq!(
            normalize(&config(), &d).unwrap_err(),
            GuardError::TargetMismatch
        );
    }
}
#[test]
fn invalid_selected_strings_are_never_saved() {
    for (op, pointer, value) in [
        (
            "describe-db-proxies",
            "/DBProxies/0/RoleArn",
            "password-secret",
        ),
        (
            "describe-db-instances",
            "/DBInstances/0/DBParameterGroups/0/DBParameterGroupName",
            "secret\nvalue",
        ),
        (
            "describe-security-groups",
            "/SecurityGroups/2/IpPermissions/0/IpRanges/0/CidrIp",
            "password-secret",
        ),
        (
            "describe-security-groups",
            "/SecurityGroups/2/IpPermissions/0/IpProtocol",
            "password-secret",
        ),
    ] {
        let mut d = fixture();
        *d.get_mut(op).unwrap().pointer_mut(pointer).unwrap() = json!(value);
        assert_eq!(
            normalize(&config(), &d).unwrap_err(),
            GuardError::EvidenceIncompatible
        );
    }
}
struct Fake {
    data: BTreeMap<String, Value>,
    calls: Mutex<Vec<CommandRequest>>,
    delay: bool,
    oversize: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            data: fixture(),
            calls: Mutex::new(vec![]),
            delay: false,
            oversize: false,
        }
    }
}
impl CommandRunner for Fake {
    async fn run(
        &self,
        r: CommandRequest,
        _: CancellationToken,
    ) -> Result<CommandOutput, GuardError> {
        let op = r.args[1].clone();
        self.calls.lock().unwrap().push(r);
        if self.delay {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let stdout = if self.oversize {
            vec![b'x'; 9 * 1024 * 1024]
        } else {
            serde_json::to_vec(&self.data[&op]).unwrap()
        };
        Ok(CommandOutput {
            success: true,
            stdout,
            stderr: vec![],
        })
    }
}
#[tokio::test]
async fn fake_runner_checks_fixed_read_only_selectors_and_no_aws_is_spawned() {
    let f = Fake::new();
    let c = config();
    let s = inspect_with_runner(
        &c,
        &InspectOptions {
            allow_aws_read: true,
            aws_profile: Some("sandbox".into()),
        },
        CancellationToken::new(),
        &f,
    )
    .await
    .unwrap();
    assert_eq!(s.evidence_kind, EvidenceKind::AwsConfiguration);
    let calls = f.calls.lock().unwrap();
    assert_eq!(calls.len(), 6);
    for r in calls.iter() {
        assert!(r.args[1].starts_with("describe-"));
        for required in [
            "--region",
            "--output",
            "--no-cli-pager",
            "--no-cli-auto-prompt",
            "--max-items",
        ] {
            assert!(r.args.iter().any(|a| a == required));
        }
        assert!(
            !r.args
                .iter()
                .any(|a| a == "--debug" || a == "--endpoint-url" || a == "--no-verify-ssl")
        );
        assert!(r.timeout_ms > 0 && r.timeout_ms <= c.limits.total_timeout_ms);
        assert_eq!(r.max_bytes, c.limits.max_bytes);
    }
    assert!(
        calls[0]
            .args
            .windows(2)
            .any(|p| p == ["--db-proxy-name", "vdg-proxy"])
    );
    assert!(
        calls[1]
            .args
            .windows(2)
            .any(|p| p[0] == "--db-instance-identifier" && p[1] == c.target.db_instance_arn)
    );
    assert!(
        calls[4]
            .args
            .iter()
            .any(|a| a == "Name=parameter-name,Values=rds.force_ssl")
    );
    assert_eq!(
        calls[5]
            .args
            .iter()
            .filter(|a| a.starts_with("sg-"))
            .count(),
        3
    );
}
#[tokio::test]
async fn permission_cancellation_size_and_total_deadline_are_enforced_without_live_calls() {
    let f = Fake::new();
    let c = config();
    assert_eq!(
        inspect_with_runner(&c, &InspectOptions::default(), CancellationToken::new(), &f)
            .await
            .unwrap_err(),
        GuardError::PermissionRequired
    );
    assert!(f.calls.lock().unwrap().is_empty());
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        inspect_with_runner(
            &c,
            &InspectOptions {
                allow_aws_read: true,
                aws_profile: None
            },
            cancel,
            &f
        )
        .await
        .unwrap_err(),
        GuardError::Cancelled
    );
    let mut f = Fake::new();
    f.oversize = true;
    assert_eq!(
        inspect_with_runner(
            &c,
            &InspectOptions {
                allow_aws_read: true,
                aws_profile: None
            },
            CancellationToken::new(),
            &f
        )
        .await
        .unwrap_err(),
        GuardError::LimitExceeded
    );
    let mut f = Fake::new();
    f.delay = true;
    let mut c = config();
    c.limits.total_timeout_ms = 20;
    c.limits.connect_timeout_ms = 10;
    c.limits.query_timeout_ms = 10;
    let start = std::time::Instant::now();
    assert!(
        inspect_with_runner(
            &c,
            &InspectOptions {
                allow_aws_read: true,
                aws_profile: None
            },
            CancellationToken::new(),
            &f
        )
        .await
        .is_err()
    );
    assert!(start.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn public_live_wrapper_refuses_documentation_account_before_spawning_aws() {
    let mut c = config();
    c.target.account_id = "000000000000".into();
    c.target.db_instance_arn = c
        .target
        .db_instance_arn
        .replace("111111111111", "000000000000");
    c.target.proxy_arn = c.target.proxy_arn.replace("111111111111", "000000000000");
    assert_eq!(
        inspect(
            &c,
            &InspectOptions {
                allow_aws_read: true,
                aws_profile: None
            },
            CancellationToken::new()
        )
        .await
        .unwrap_err(),
        GuardError::ConfigInvalid
    );
}

#[test]
fn class_and_zone_are_observed_without_inference_and_invalid_values_are_rejected() {
    let c = config();
    let data = fixture();
    let snapshot = normalize(&c, &data).unwrap();
    let db = snapshot.db.unwrap();
    assert_eq!(db.instance_class.as_deref(), Some("db.t4g.medium"));
    assert_eq!(db.availability_zone.as_deref(), Some("ap-northeast-1a"));
    for field in ["DBInstanceClass", "AvailabilityZone"] {
        let mut missing = data.clone();
        missing.get_mut("describe-db-instances").unwrap()["DBInstances"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        let absent = normalize(&c, &missing).unwrap().db.unwrap();
        if field == "DBInstanceClass" {
            assert_eq!(absent.instance_class, None);
        } else {
            assert_eq!(absent.availability_zone, None);
        }
        missing.get_mut("describe-db-instances").unwrap()["DBInstances"][0][field] = Value::Null;
        let absent = normalize(&c, &missing).unwrap().db.unwrap();
        if field == "DBInstanceClass" {
            assert_eq!(absent.instance_class, None);
        } else {
            assert_eq!(absent.availability_zone, None);
        }
        for invalid in [json!("SENTINEL\nSECRET"), json!(false), json!("")] {
            let mut malformed = data.clone();
            malformed.get_mut("describe-db-instances").unwrap()["DBInstances"][0][field] = invalid;
            assert_eq!(
                normalize(&c, &malformed).unwrap_err(),
                GuardError::EvidenceIncompatible
            );
        }
    }
    for (field, value) in [
        ("DBInstanceClass", "db.t4g.medium;echo"),
        ("AvailabilityZone", "us-east-1a"),
        ("AvailabilityZone", "ap-northeast-1"),
    ] {
        let mut malformed = data.clone();
        malformed.get_mut("describe-db-instances").unwrap()["DBInstances"][0][field] = json!(value);
        assert_eq!(
            normalize(&c, &malformed).unwrap_err(),
            GuardError::EvidenceIncompatible
        );
    }
}
