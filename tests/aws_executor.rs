//! Local injected provider evidence only. This test never invokes AWS or a DB.
use serde_json::{Value, json};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};
use veil_db_guard::{
    adapters::{capabilities_for, deployment::aws::*},
    binding::{BindingError, CheckpointGate},
    core::{
        capability::{ActionKind, Implementation, Support},
        change::{OperationLimits, PreparedChange, prepare_change},
        operation::{DispatchTicket, EffectState, LeaseSet, StepReceipt, StepRecord, StepState},
        orchestrator::{ExecutorError, StepExecutor},
        plan::{PlanStep, build_plan},
        policy::*,
    },
};

const ACCOUNT: &str = "111122223333";
const APP: &str = "arn:aws:iam::111122223333:role/billing-app";
const RECOVERY: &str = "arn:aws:iam::111122223333:role/recovery";
const PROXY_ROLE: &str = "arn:aws:iam::111122223333:role/proxy-backend";
const APP_ID: &str = "AROA11111111111111111";
const RECOVERY_ID: &str = "AROA22222222222222222";
const PROXY_ID: &str = "AROA33333333333333333";
const EXECUTION: &str = "aws-role:arn:aws:iam::111122223333:role/runner:AROA44444444444444444";
fn prepared(deny: bool) -> PreparedChange {
    prepared_engine(deny, EngineFamily::PostgreSql)
}
fn prepared_engine(deny: bool, engine: EngineFamily) -> PreparedChange {
    let mut p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    {
        let (s, arn, id) = (&mut p.subjects[0], APP, APP_ID);
        s.identity.provider = IdentityProvider::Aws;
        s.identity.principal = arn.into();
        s.identity.immutable_id = Some(id.into());
    }
    p.subjects[1].identity.provider = IdentityProvider::Aws;
    p.subjects[1].identity.principal = RECOVERY.into();
    p.subjects[1].identity.immutable_id = Some(RECOVERY_ID.into());
    let t = &mut p.targets[0];
    t.placement = PlacementRef {
        kind: PlacementKind::AwsRds,
        account_id: ACCOUNT.into(),
        region: "ap-northeast-1".into(),
    };
    t.resource.native_id = "arn:aws:rds:ap-northeast-1:111122223333:db:billing-postgres".into();
    t.resource.generation_fingerprint = Some(generation_fingerprint(
        ACCOUNT,
        "ap-northeast-1",
        &t.resource.native_id,
        "db-IMMUTABLE",
    ));
    t.managed_surface.fields = vec![
        ManagedField::AwsProxy,
        ManagedField::AwsIamBinding,
        ManagedField::AwsSecurityGroupRule,
        ManagedField::DbLogin,
        ManagedField::DbRole,
        ManagedField::DbObjectPrivilege,
        ManagedField::ApplicationBinding,
    ];
    t.managed_surface.db_identities = vec!["billing_app".into(), "billing-reader-writer".into()];
    t.aws = Some(AwsRdsBinding {
        db_resource_id: "db-IMMUTABLE".into(),
        db_endpoint: "billing.ap-northeast-1.rds.amazonaws.com".into(),
        proxy_name: "billing-proxy".into(),
        proxy_arn: "arn:aws:rds:ap-northeast-1:111122223333:db-proxy:prx-IMMUTABLE".into(),
        proxy_endpoint: "billing.proxy.ap-northeast-1.rds.amazonaws.com".into(),
        proxy_role_arn: PROXY_ROLE.into(),
        proxy_role_id: PROXY_ID.into(),
        proxy_policy_name: "existing-backend".into(),
        proxy_security_group_id: "sg-proxy".into(),
        db_security_group_id: "sg-db".into(),
        managed_policy_name: "veil-billing".into(),
        management_db_identity: "recovery_user".into(),
        owned_direct_rules: vec![AwsSecurityGroupRuleBinding {
            rule_id: "sgr-owned".into(),
            protocol: "tcp".into(),
            from_port: 5432,
            to_port: 5432,
            source: AwsRuleSource::CidrV4 {
                cidr: "10.0.0.0/24".into(),
            },
            ownership_tag_key: "VeilOwner".into(),
            ownership_tag_value: "billing-registration".into(),
        }],
    });
    if engine == EngineFamily::MySql {
        t.engine.family = EngineFamily::MySql;
        t.engine.version = "8.0.43".into();
        t.mysql = Some(MysqlTargetBinding {
            account_host: "%".into(),
            management_account_host: "%".into(),
        });
        for rule in &mut t.aws.as_mut().unwrap().owned_direct_rules {
            rule.from_port = 3306;
            rule.to_port = 3306;
        }
        p.grants[0].sql_access.existing_roles.clear();
    }
    p.grants[0].db_identity = "billing_app".into();
    p.protection_profiles[0].kind = if engine == EngineFamily::MySql {
        ProfileKind::AwsRdsMysqlProxyV1
    } else {
        ProfileKind::AwsRdsPostgresProxyV1
    };
    for r in &mut p.protection_profiles[0].allowed_routes {
        r.kind = RouteKind::NativeProxy;
    }
    if deny {
        p.grants[0].admission = AdmissionIntent::Deny;
        p.grants[0].sql_access.existing_roles.clear();
        p.grants[0].sql_access.privileges.clear();
        p.protection_profiles[0].required_effects =
            vec![EffectKind::BindingApplied, EffectKind::NewConnectionsDenied];
    }
    let mut capabilities = p
        .targets
        .iter()
        .flat_map(capabilities_for)
        .collect::<Vec<_>>();
    for c in &mut capabilities {
        c.support = Support::Supported;
        c.implementation = Implementation::Implemented;
        c.contract_revision = if engine == EngineFamily::MySql {
            "core-adapter-v3"
        } else {
            "core-adapter-v2"
        }
        .into();
        c.constraints.clear();
    }
    let plan = build_plan(&p, capabilities, vec![], 100).unwrap();
    prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn step(c: &PreparedChange, a: ActionKind) -> &PlanStep {
    c.plan.steps.iter().find(|s| s.action == a).unwrap()
}
fn ticket(s: &PlanStep) -> DispatchTicket {
    DispatchTicket {
        operation_id: "operation-1".into(),
        step_id: s.id.clone(),
        attempt: 1,
        operation_version: 1,
        idempotency_key: "request-1".into(),
        leases: LeaseSet {
            holder: "holder".into(),
            token: 1,
            keys: vec!["owned".into()],
            expires_at: 4000,
        },
    }
}
fn record(s: &PlanStep, r: StepReceipt) -> StepRecord {
    StepRecord {
        step_id: s.id.clone(),
        state: r.state,
        attempt: 1,
        idempotency_key: "request-1".into(),
        receipt: Some(r),
    }
}
#[derive(Clone)]
struct Gate(Rc<Cell<bool>>);
impl CheckpointGate for Gate {
    fn validate_preparation(
        &self,
        _: &PreparedChange,
        _: &str,
        _: &str,
        _: u64,
    ) -> Result<String, BindingError> {
        if self.0.get() {
            Ok("f".repeat(64))
        } else {
            Err(BindingError::Pending)
        }
    }
    fn validate(&self, _: &PreparedChange, _: &str, _: u64) -> Result<Vec<String>, BindingError> {
        if self.0.get() {
            Ok(vec!["b".repeat(64)])
        } else {
            Err(BindingError::Pending)
        }
    }
    fn validate_change_window(
        &self,
        _: &PreparedChange,
        _: &str,
        _: u64,
    ) -> Result<String, BindingError> {
        if self.0.get() {
            Ok("c".repeat(64))
        } else {
            Err(BindingError::Pending)
        }
    }
}
struct Fake {
    now: u64,
    identity: String,
    roles: BTreeMap<String, String>,
    db: RdsInstance,
    proxy: RdsProxy,
    backend: Value,
    policy: Option<Value>,
    rules: Vec<SecurityGroupRule>,
    evidence: Option<ConnectionEvidence>,
    revoke: Option<RevocationEvidence>,
    writes: Vec<String>,
    ambiguous: bool,
}
impl Fake {
    fn new(c: &PreparedChange) -> Self {
        let t = &c.policy.targets[0];
        let b = t.aws.as_ref().unwrap();
        let port = if t.engine.family == EngineFamily::MySql {
            3306
        } else {
            5432
        };
        let path = SecurityGroupRule {
            id: "sgr-proxy".into(),
            group_id: b.db_security_group_id.clone(),
            owner_account: ACCOUNT.into(),
            ingress: true,
            protocol: "tcp".into(),
            from_port: port,
            to_port: port,
            source: Some(AwsRuleSource::SecurityGroup {
                group_id: b.proxy_security_group_id.clone(),
                account_id: ACCOUNT.into(),
            }),
            tags: BTreeMap::new(),
        };
        let direct = SecurityGroupRule {
            id: "sgr-owned".into(),
            group_id: b.db_security_group_id.clone(),
            owner_account: ACCOUNT.into(),
            ingress: true,
            protocol: "tcp".into(),
            from_port: port,
            to_port: port,
            source: Some(b.owned_direct_rules[0].source.clone()),
            tags: BTreeMap::from([("VeilOwner".into(), "billing-registration".into())]),
        };
        Self {
            now: 100,
            identity: EXECUTION.into(),
            roles: BTreeMap::from([
                (APP.into(), APP_ID.into()),
                (RECOVERY.into(), RECOVERY_ID.into()),
                (PROXY_ROLE.into(), PROXY_ID.into()),
            ]),
            db: RdsInstance {
                arn: t.resource.native_id.clone(),
                resource_id: b.db_resource_id.clone(),
                endpoint: b.db_endpoint.clone(),
                version: t.engine.version.clone(),
                engine_family: t.engine.family,
                available: true,
                iam_authentication: true,
                security_group_ids: BTreeSet::from([b.db_security_group_id.clone()]),
                port: u16::try_from(port).unwrap(),
            },
            proxy: RdsProxy {
                arn: b.proxy_arn.clone(),
                name: b.proxy_name.clone(),
                endpoint: b.proxy_endpoint.clone(),
                role_arn: PROXY_ROLE.into(),
                available: true,
                engine_family: t.engine.family,
                require_tls: true,
                iam_authentication: true,
                auth_entries: 0,
                security_group_ids: BTreeSet::from([b.proxy_security_group_id.clone()]),
                target_resource_ids: BTreeSet::from([b.db_resource_id.clone()]),
            },
            backend: required_proxy_policy(c, t).unwrap(),
            policy: None,
            rules: vec![path, direct],
            evidence: Some(ConnectionEvidence {
                generation: t.resource.generation_fingerprint.clone().unwrap(),
                observed_at: 100,
                proxy_allowed_principals: BTreeSet::from([APP.into(), RECOVERY.into()]),
                direct_denied_principals: BTreeSet::from([APP.into(), RECOVERY.into()]),
                evidence_refs: vec!["d".repeat(64)],
            }),
            revoke: None,
            writes: vec![],
            ambiguous: false,
        }
    }
    fn write(&mut self, name: &str) -> Result<(), ProviderError> {
        self.writes.push(name.into());
        if self.ambiguous {
            Err(ProviderError::Unknown)
        } else {
            Ok(())
        }
    }
}
impl AwsProvider for Fake {
    fn now(&self) -> u64 {
        self.now
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        Ok(self.identity.clone())
    }
    fn instance(&mut self, _: &Target) -> Result<RdsInstance, ProviderError> {
        Ok(self.db.clone())
    }
    fn proxy(&mut self, _: &Target) -> Result<RdsProxy, ProviderError> {
        Ok(self.proxy.clone())
    }
    fn role_id(&mut self, arn: &str) -> Result<String, ProviderError> {
        self.roles
            .get(arn)
            .cloned()
            .ok_or(ProviderError::Precondition)
    }
    fn inline_policy(&mut self, arn: &str, _: &str) -> Result<Option<Value>, ProviderError> {
        Ok(if arn == PROXY_ROLE {
            Some(self.backend.clone())
        } else {
            self.policy.clone()
        })
    }
    fn put_inline_policy(&mut self, _: &str, _: &str, v: &Value) -> Result<(), ProviderError> {
        self.write("put-policy")?;
        self.policy = Some(v.clone());
        Ok(())
    }
    fn delete_inline_policy(&mut self, _: &str, _: &str, v: &Value) -> Result<(), ProviderError> {
        assert_eq!(self.policy.as_ref(), Some(v));
        self.write("delete-policy")?;
        self.policy = None;
        Ok(())
    }
    fn prepare_proxy(&mut self, _: &Target, p: &RdsProxy) -> Result<(), ProviderError> {
        assert_eq!(p, &self.proxy);
        self.write("proxy")?;
        self.proxy.iam_authentication = true;
        self.proxy.require_tls = true;
        Ok(())
    }
    fn rules(&mut self, _: &Target) -> Result<Vec<SecurityGroupRule>, ProviderError> {
        Ok(self.rules.clone())
    }
    fn revoke_rule(&mut self, _: &Target, r: &SecurityGroupRule) -> Result<(), ProviderError> {
        self.write("revoke-rule")?;
        self.rules.retain(|v| v.id != r.id);
        Ok(())
    }
    fn observe_connections(
        &mut self,
        _: &PreparedChange,
        _: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        Ok(self.evidence.clone())
    }
    fn observe_revocation(
        &mut self,
        _: &PreparedChange,
        _: &Target,
        _: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        Ok(self.revoke.clone())
    }
}
fn executor(c: &PreparedChange) -> AwsExecutor<Fake, Gate> {
    AwsExecutor::new(
        Fake::new(c),
        EXECUTION.into(),
        Gate(Rc::new(Cell::new(true))),
    )
}

#[test]
fn setup_writes_once_and_query_only_reads_config() {
    let c = prepared(false);
    let s = step(&c, ActionKind::PrepareNativeRoute);
    let mut e = executor(&c);
    e.provider.proxy.require_tls = false;
    e.provider.proxy.iam_authentication = false;
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    assert_eq!(r.state, StepState::Submitted);
    assert_eq!(r.effect, EffectState::Pending);
    let r = record(s, r);
    assert_eq!(
        e.query(&c, s, &r).unwrap().state,
        StepState::EffectSatisfied
    );
    assert_eq!(e.provider.writes, vec!["proxy"]);
}
#[test]
fn password_proxy_switch_requires_a_current_exact_preparation_declaration() {
    use veil_db_guard::binding::{CheckpointKind, ManualCheckpoint, ManualCheckpoints};
    let c = prepared(false);
    let s = step(&c, ActionKind::PrepareNativeRoute);
    let window = ManualCheckpoint::attest(
        &c,
        "billing-db",
        CheckpointKind::ExclusiveNativeChangeWindow,
        "recovery-operator",
        100,
        600,
    )
    .unwrap();
    let gate = ManualCheckpoints {
        receipts: vec![window.clone()],
    };
    let mut e = AwsExecutor::new(Fake::new(&c), EXECUTION.into(), gate);
    // Existing compliant routes need no new native preparation declaration.
    assert_eq!(
        e.submit(&c, s, &ticket(s)).unwrap().state,
        StepState::NoOpSatisfied
    );
    e.provider.proxy.iam_authentication = false;
    assert!(e.preflight(&c, s).is_err());
    assert!(e.provider.writes.is_empty());
    let fingerprint = preparation_fingerprint(&e.provider.db, &e.provider.proxy);
    let declaration = ManualCheckpoint::attest_preparation(
        &c,
        "billing-db",
        "recovery-operator",
        &fingerprint,
        100,
        600,
    )
    .unwrap();
    let gate = ManualCheckpoints {
        receipts: vec![window, declaration],
    };
    let mut e = AwsExecutor::new(e.provider, EXECUTION.into(), gate);
    e.preflight(&c, s).unwrap();
    e.provider.proxy.require_tls = false;
    assert!(
        e.submit(&c, s, &ticket(s)).is_err(),
        "a changed native baseline invalidates preparation"
    );
    assert!(e.provider.writes.is_empty());
}
#[test]
fn identity_grant_is_exact_and_collision_is_never_overwritten() {
    let c = prepared(false);
    let s = step(&c, ActionKind::ConfigureIdentity);
    let mut e = executor(&c);
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    let policy = e.provider.policy.clone().unwrap();
    assert_eq!(policy["Statement"][0]["Action"], "rds-db:connect");
    assert_eq!(
        policy["Statement"][0]["Resource"],
        "arn:aws:rds-db:ap-northeast-1:111122223333:dbuser:prx-IMMUTABLE/billing_app"
    );
    assert_eq!(
        e.query(&c, s, &record(s, r)).unwrap().state,
        StepState::EffectSatisfied
    );
    assert_eq!(
        e.submit(&c, s, &ticket(s)).unwrap().state,
        StepState::NoOpSatisfied
    );
    assert_eq!(e.provider.writes.len(), 1);
    e.provider.policy = Some(json!({"Statement":[{"Action":"*","Resource":"*","Effect":"Allow"}]}));
    assert!(e.preflight(&c, s).is_err());
    assert_eq!(e.provider.writes.len(), 1);
}
#[test]
fn immutable_incarnation_execution_role_and_backend_are_preconditions() {
    let c = prepared(false);
    let s = step(&c, ActionKind::PrepareNativeRoute);
    for fault in [
        "db",
        "proxy",
        "role",
        "proxy-role",
        "backend",
        "execution",
        "version",
        "db-iam",
        "legacy-auth",
        "extra-sg",
        "endpoint",
    ] {
        let mut e = executor(&c);
        match fault {
            "db" => e.provider.db.resource_id = "db-RECREATED".into(),
            "proxy" => e.provider.proxy.arn.push_str("recreated"),
            "role" => {
                e.provider
                    .roles
                    .insert(APP.into(), "AROA99999999999999999".into());
            }
            "proxy-role" => {
                e.provider
                    .roles
                    .insert(PROXY_ROLE.into(), "AROA99999999999999999".into());
            }
            "backend" => e.provider.backend = json!({"Statement":[]}),
            "execution" => e.provider.identity = "other".into(),
            "version" => e.provider.db.version = "16.14".into(),
            "db-iam" => e.provider.db.iam_authentication = false,
            "legacy-auth" => e.provider.proxy.auth_entries = 1,
            "extra-sg" => {
                e.provider
                    .db
                    .security_group_ids
                    .insert("sg-unreviewed".into());
            }
            _ => e.provider.db.endpoint = "other.ap-northeast-1.rds.amazonaws.com".into(),
        }
        assert!(e.submit(&c, s, &ticket(s)).is_err(), "{fault}");
        assert!(e.provider.writes.is_empty());
    }
}
#[test]
fn closure_needs_positive_app_and_recovery_then_explicit_current_denial() {
    let c = prepared(false);
    let s = step(&c, ActionKind::ConstrainDirectPath);
    let mut e = executor(&c);
    e.provider
        .evidence
        .as_mut()
        .unwrap()
        .proxy_allowed_principals
        .remove(RECOVERY);
    assert!(e.preflight(&c, s).is_err());
    assert!(e.provider.writes.is_empty());
    e.provider.evidence = Fake::new(&c).evidence;
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    assert_eq!(e.provider.rules.len(), 1);
    assert_eq!(e.provider.rules[0].id, "sgr-proxy");
    let r = record(s, r);
    e.provider
        .evidence
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .clear();
    let pending = e.query(&c, s, &r).unwrap();
    assert_eq!(pending.state, StepState::ConfigApplied);
    assert_eq!(pending.effect, EffectState::Pending);
    e.provider.evidence = Fake::new(&c).evidence;
    assert_eq!(
        e.query(&c, s, &r).unwrap().state,
        StepState::EffectSatisfied
    );
    assert_eq!(e.provider.writes, vec!["revoke-rule"]);
}
#[test]
fn closure_rejects_changed_rule_tuple_owner_tag_and_missing_proxy_path() {
    let c = prepared(false);
    let s = step(&c, ActionKind::ConstrainDirectPath);
    for fault in [
        "owner",
        "source",
        "port",
        "protocol",
        "tag",
        "direction",
        "proxy-path",
    ] {
        let mut e = executor(&c);
        match fault {
            "owner" => e.provider.rules[1].owner_account = "999999999999".into(),
            "source" => {
                e.provider.rules[1].source = Some(AwsRuleSource::CidrV4 {
                    cidr: "0.0.0.0/0".into(),
                })
            }
            "port" => e.provider.rules[1].to_port = 5433,
            "protocol" => e.provider.rules[1].protocol = "-1".into(),
            "tag" => e.provider.rules[1].tags.clear(),
            "direction" => e.provider.rules[1].ingress = false,
            _ => {
                e.provider.rules.remove(0);
            }
        }
        assert!(e.submit(&c, s, &ticket(s)).is_err(), "{fault}");
        assert!(e.provider.writes.is_empty());
    }
}
#[test]
fn closure_never_turns_stale_foreign_or_unattributed_evidence_into_effect() {
    let c = prepared(false);
    let s = step(&c, ActionKind::ConstrainDirectPath);
    let mut e = executor(&c);
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    let r = record(s, r);
    for fault in ["stale", "generation", "future", "recovery", "hash", "none"] {
        e.provider.evidence = Fake::new(&c).evidence;
        let v = e.provider.evidence.as_mut().unwrap();
        match fault {
            "stale" => v.observed_at = 1,
            "generation" => v.generation = "f".repeat(64),
            "future" => v.observed_at = 101,
            "recovery" => {
                v.direct_denied_principals.remove(RECOVERY);
            }
            "hash" => v.evidence_refs = vec!["fake".into()],
            _ => e.provider.evidence = None,
        }
        assert_eq!(
            e.query(&c, s, &r).unwrap().effect,
            EffectState::Pending,
            "{fault}"
        );
    }
    assert_eq!(e.provider.writes.len(), 1);
}
#[test]
fn mixed_allow_and_deny_never_requires_a_revoked_app_to_pass_positive_control() {
    let mut p = prepared(false).policy;
    let mut u = p.subjects[0].clone();
    u.id = "revoked-app".into();
    u.identity.principal = "arn:aws:iam::111122223333:role/revoked-app".into();
    u.identity.immutable_id = Some("AROA55555555555555555".into());
    let mut grant = p.grants[0].clone();
    grant.id = "revoked-grant".into();
    grant.subject = u.id.clone();
    grant.db_identity = "revoked_user".into();
    grant.admission = AdmissionIntent::Deny;
    grant.sql_access.existing_roles.clear();
    grant.sql_access.privileges.clear();
    p.subjects.push(u.clone());
    p.grants.push(grant);
    p.targets[0]
        .managed_surface
        .db_identities
        .push("revoked_user".into());
    let mut caps = p
        .targets
        .iter()
        .flat_map(capabilities_for)
        .collect::<Vec<_>>();
    for cap in &mut caps {
        cap.support = Support::Supported;
        cap.implementation = Implementation::Implemented;
        cap.contract_revision = "core-adapter-v2".into();
        cap.constraints.clear();
    }
    let plan = build_plan(&p, caps, vec![], 100).unwrap();
    let c = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let s = step(&c, ActionKind::ConstrainDirectPath);
    let mut e = executor(&c);
    e.provider.roles.insert(
        u.identity.principal.clone(),
        u.identity.immutable_id.unwrap(),
    );
    e.provider
        .evidence
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .insert(u.identity.principal);
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    assert_eq!(
        e.query(&c, s, &record(s, r)).unwrap().effect,
        EffectState::Enforced
    );
    assert_eq!(e.provider.writes, vec!["revoke-rule"]);
}
#[test]
fn expired_window_blocks_new_writes_but_reconciliation_remains_read_only() {
    let c = prepared(false);
    let s = step(&c, ActionKind::PrepareNativeRoute);
    let gate = Gate(Rc::new(Cell::new(true)));
    let shared = gate.0.clone();
    let mut e = AwsExecutor::new(Fake::new(&c), EXECUTION.into(), gate);
    e.provider.proxy.require_tls = false;
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    shared.set(false);
    assert!(e.preflight(&c, s).is_err());
    assert_eq!(
        e.query(&c, s, &record(s, r)).unwrap().effect,
        EffectState::Enforced
    );
    assert_eq!(e.provider.writes.len(), 1);
}
#[test]
fn ambiguous_write_is_never_replayed_by_query() {
    let c = prepared(false);
    let s = step(&c, ActionKind::ConfigureIdentity);
    let mut e = executor(&c);
    e.provider.ambiguous = true;
    assert_eq!(
        e.submit(&c, s, &ticket(s)),
        Err(ExecutorError::OutcomeUnknown)
    );
    assert_eq!(e.provider.writes.len(), 1);
    let mut r = record(
        s,
        StepReceipt {
            state: StepState::Submitted,
            effect: EffectState::Pending,
            native_operation_ref: Some("foreign".into()),
            evidence_refs: vec![],
        },
    );
    assert_eq!(e.query(&c, s, &r), Err(ExecutorError::OutcomeUnknown));
    r.step_id = "wrong".into();
    assert!(e.query(&c, s, &r).is_err());
    assert_eq!(e.provider.writes.len(), 1);
}
#[test]
fn sql_and_handoff_composition_revalidates_without_native_action() {
    let c = prepared(false);
    let s = step(&c, ActionKind::ConfigureSqlPrivileges);
    let mut e = executor(&c);
    e.revalidate_target(&c, s).unwrap();
    e.provider.db.resource_id = "db-replaced".into();
    assert!(e.revalidate_target(&c, s).is_err());
    assert!(e.provider.writes.is_empty());
}
#[test]
fn owned_revocation_never_deletes_unrelated_policy() {
    let allow = prepared(false);
    let deny = prepared(true);
    let mut e = executor(&allow);
    let setup = step(&allow, ActionKind::ConfigureIdentity);
    e.submit(&allow, setup, &ticket(setup)).unwrap();
    let revoke = step(&deny, ActionKind::DisableNativeIdentity);
    let r = e.submit(&deny, revoke, &ticket(revoke)).unwrap();
    assert_eq!(
        e.query(&deny, revoke, &record(revoke, r)).unwrap().effect,
        EffectState::Enforced
    );
    assert!(e.provider.policy.is_none());
    assert_eq!(e.provider.writes, vec!["put-policy", "delete-policy"]);
    e.provider.policy = Some(json!({"foreign":"policy"}));
    assert!(e.preflight(&deny, revoke).is_err());
    assert_eq!(e.provider.writes.len(), 2);
}
fn revocation(c: &PreparedChange) -> RevocationEvidence {
    RevocationEvidence {
        complete: true,
        generation: c.policy.targets[0]
            .resource
            .generation_fingerprint
            .clone()
            .unwrap(),
        observed_at: 100,
        denied_principal: APP.into(),
        access: Access::Denied,
        iam_connect_denied: true,
        proxy_allowed_principals: BTreeSet::from([RECOVERY.into()]),
        direct_denied_principals: BTreeSet::from([APP.into(), RECOVERY.into()]),
        evidence_refs: vec!["e".repeat(64)],
    }
}
#[test]
fn current_revocation_retains_allowed_and_requires_correct_iam_layer_and_control() {
    let c = prepared(true);
    let s = step(&c, ActionKind::ObserveRevocation);
    let mut e = executor(&c);
    e.provider.revoke = Some(revocation(&c));
    assert_eq!(
        e.submit(&c, s, &ticket(s)).unwrap().effect,
        EffectState::Enforced
    );
    for fault in [
        "allowed",
        "unknown",
        "layer",
        "partial",
        "recovery",
        "direct",
        "stale",
        "generation",
    ] {
        e.provider.revoke = Some(revocation(&c));
        let v = e.provider.revoke.as_mut().unwrap();
        match fault {
            "allowed" => v.access = Access::Allowed,
            "unknown" => v.access = Access::Unknown,
            "layer" => v.iam_connect_denied = false,
            "partial" => v.complete = false,
            "recovery" => v.proxy_allowed_principals.clear(),
            "direct" => v.direct_denied_principals.clear(),
            "stale" => v.observed_at = 1,
            _ => v.generation = "f".repeat(64),
        }
        assert_eq!(
            e.submit(&c, s, &ticket(s)).unwrap().effect,
            EffectState::Pending,
            "{fault}"
        );
        if fault == "allowed" {
            assert_eq!(
                e.last_revocation_evidence().unwrap().access,
                Access::Allowed
            );
        }
    }
    assert!(e.provider.writes.is_empty());
}
#[test]
fn construction_is_offline_and_requires_pinned_absolute_executable_and_role() {
    use tokio_util::sync::CancellationToken;
    let create = |path: &str, role: &str| {
        AwsCliProvider::new(
            path.into(),
            "approved".into(),
            ACCOUNT.into(),
            "arn:aws:iam::111122223333:role/runner".into(),
            role.into(),
            CancellationToken::new(),
        )
    };
    assert!(create("/usr/bin/true", "AROA44444444444444444").is_ok());
    assert!(create("aws", "AROA44444444444444444").is_err());
    assert!(create("/missing/aws", "AROA44444444444444444").is_err());
    assert!(create("/usr/bin/true", "mutable-name").is_err());
    assert!(create("/usr/bin/true", "AROA").is_err());
    assert_ne!(
        generation_fingerprint(ACCOUNT, "ap-northeast-1", "same-name", "db-old"),
        generation_fingerprint(ACCOUNT, "ap-northeast-1", "same-name", "db-new")
    );
}

#[cfg(unix)]
#[test]
fn production_process_uses_frozen_credentials_and_never_retries_ambiguous_writes() {
    use std::os::unix::fs::PermissionsExt;
    use tokio_util::sync::CancellationToken;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("local-fake-aws");
    let log = temp.path().join("calls");
    let script = format!(
        r##"#!/bin/sh
printf '%s\n' "$*" >> '{}'
if [ "$1 $2" = 'configure export-credentials' ]; then
  printf '%s' '{{"Version":1,"AccessKeyId":"LOCAL_EXAMPLE_KEY","SecretAccessKey":"LOCAL_EXAMPLE_SECRET","SessionToken":"LOCAL_EXAMPLE_SESSION"}}'
  exit 0
fi
[ "$AWS_ACCESS_KEY_ID" = LOCAL_EXAMPLE_KEY ] || exit 42
[ "$AWS_SECRET_ACCESS_KEY" = LOCAL_EXAMPLE_SECRET ] || exit 43
[ "$AWS_SESSION_TOKEN" = LOCAL_EXAMPLE_SESSION ] || exit 44
[ "$AWS_CONFIG_FILE" = /dev/null ] || exit 45
[ "$AWS_SHARED_CREDENTIALS_FILE" = /dev/null ] || exit 46
[ "$AWS_MAX_ATTEMPTS" = 1 ] || exit 47
case "$1 $2" in
  'sts get-caller-identity') printf '%s' '{{"Account":"111122223333","Arn":"arn:aws:sts::111122223333:assumed-role/runner/local-session","UserId":"AROA44444444444444444:local-session"}}' ;;
  'iam list-role-policies') printf '%s' '{{"PolicyNames":["test-policy"]}}' ;;
  'iam get-role-policy') printf '%s' '{{"PolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D"}}' ;;
  'iam put-role-policy') printf '%s' '{{' ;;
  'rds describe-db-proxies') printf '%s' '{{"DBProxies":[{{"DBProxyArn":"arn:aws:rds:ap-northeast-1:111122223333:db-proxy:prx-IMMUTABLE","DBProxyName":"billing-proxy","Endpoint":"billing.proxy.ap-northeast-1.rds.amazonaws.com","RoleArn":"arn:aws:iam::111122223333:role/proxy-backend","Status":"available","EngineFamily":"POSTGRESQL","RequireTLS":true,"DefaultAuthScheme":"IAM_AUTH","VpcSecurityGroupIds":["sg-proxy"]}}]}}' ;;
  'rds describe-db-proxy-targets') printf '%s' '{{"Targets":[{{"TargetArn":"arn:aws:rds:ap-northeast-1:111122223333:db:billing-postgres","RdsResourceId":"billing-postgres","Type":"RDS_INSTANCE","Endpoint":"billing.ap-northeast-1.rds.amazonaws.com","Port":5432,"TargetHealth":{{"State":"UNAVAILABLE"}}}}]}}' ;;
  'ec2 describe-security-group-rules') printf '%s' '{{"SecurityGroupRules":[{{"SecurityGroupRuleId":"sgr-owned","GroupId":"sg-db","GroupOwnerId":"111122223333","IsEgress":false,"IpProtocol":"tcp","FromPort":5432,"ToPort":5432,"CidrIpv4":"10.0.0.0/24","PrefixListId":"pl-unexpected"}}]}}' ;;
  *) exit 48 ;;
esac
"##,
        log.display()
    );
    std::fs::write(&executable, script).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let cancel = CancellationToken::new();
    let mut p = AwsCliProvider::new(
        executable,
        "approved".into(),
        ACCOUNT.into(),
        "arn:aws:iam::111122223333:role/runner".into(),
        "AROA44444444444444444".into(),
        cancel.clone(),
    )
    .unwrap();
    assert!(!log.exists(), "constructor must not execute the fake tool");
    assert_eq!(p.execution_identity().unwrap(), EXECUTION);
    let c = prepared(false);
    assert_eq!(
        p.proxy(&c.policy.targets[0]).unwrap().target_resource_ids,
        BTreeSet::from(["db-IMMUTABLE".into()])
    );
    assert_eq!(
        p.rules(&c.policy.targets[0]),
        Err(ProviderError::Unavailable)
    );
    assert_eq!(
        p.inline_policy(APP, "test-policy").unwrap(),
        Some(json!({"Version":"2012-10-17","Statement":[]}))
    );
    assert_eq!(
        p.put_inline_policy(
            APP,
            "owned-policy",
            &json!({"Version":"2012-10-17","Statement":[]})
        ),
        Err(ProviderError::Unknown)
    );
    let calls = std::fs::read_to_string(&log).unwrap();
    let lines = calls.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 9);
    assert!(lines[0].contains("--profile approved"));
    assert!(
        lines[1..]
            .iter()
            .all(|v| !v.contains("--profile") && v.contains("--region ap-northeast-1"))
    );
    assert!(!calls.contains("LOCAL_EXAMPLE_"));
    assert_eq!(
        lines
            .iter()
            .filter(|v| v.contains("put-role-policy"))
            .count(),
        1
    );
    cancel.cancel();
    assert_eq!(p.execution_identity(), Err(ProviderError::Unavailable));
    assert_eq!(std::fs::read_to_string(&log).unwrap(), calls);
}

#[cfg(unix)]
#[test]
fn active_cancellation_stops_and_reaps_the_local_cli_process() {
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    use tokio_util::sync::CancellationToken;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("blocking-fake-cli");
    let marker = temp.path().join("started");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\n/bin/sleep 20\n",
            marker.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = CancellationToken::new();
    let worker_token = token.clone();
    let started = Instant::now();
    let worker = std::thread::spawn(move || {
        let mut p = AwsCliProvider::new(
            executable,
            "approved".into(),
            ACCOUNT.into(),
            "arn:aws:iam::111122223333:role/runner".into(),
            "AROA44444444444444444".into(),
            worker_token,
        )
        .unwrap();
        p.execution_identity()
    });
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
        {
            break pid;
        }
        if started.elapsed() >= Duration::from_secs(2) {
            token.cancel();
            let _ = worker.join();
            panic!("local child failed to start");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    token.cancel();
    assert_eq!(worker.join().unwrap(), Err(ProviderError::Unavailable));
    assert!(started.elapsed() < Duration::from_secs(3));
    // The direct child is reaped before the synchronous boundary returns.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
}

#[test]
fn real_sqlite_orchestrator_resumes_all_eight_aws_steps_and_a_fresh_revoke() {
    use veil_db_guard::{
        adapters::{engine::postgres::*, executor::AwsProtectionExecutor},
        binding::*,
        core::{
            approval,
            lifecycle::{LifecycleKind, prepare_maintenance},
            operation::*,
            orchestrator::{self, Clock},
        },
        operation_store::OperationStore,
    };
    #[derive(Default)]
    struct Sql {
        writes: usize,
    }
    impl PgTransport for Sql {
        fn preflight(&mut self, _: &SqlBatch) -> Result<(), PgError> {
            Ok(())
        }
        fn execute_atomic(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
            self.writes += 1;
            Ok(PgOutcome::Applied)
        }
        fn query(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
            Ok(PgOutcome::Applied)
        }
    }
    struct Time(u64);
    impl Clock for Time {
        fn now(&mut self) -> u64 {
            self.0
        }
    }
    let p = prepared(false).policy;
    let plan = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    assert!(plan.capability_gaps.is_empty());
    assert_eq!(plan.steps.len(), 8);
    let c = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let mut cp = ManualCheckpoints {
        receipts: [
            CheckpointKind::BindingPublished,
            CheckpointKind::RecoveryReady,
            CheckpointKind::ApplicationCutover,
            CheckpointKind::ExclusiveNativeChangeWindow,
        ]
        .into_iter()
        .map(|k| {
            ManualCheckpoint::attest(&c, "billing-db", k, "recovery-operator", 100, 600).unwrap()
        })
        .collect(),
    };
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("actual.sqlite");
    let mut store = OperationStore::open(&ledger).unwrap();
    let permit =
        approval::issue(&c, "allow-approval", "operator", EXECUTION, 900, 1000, 100).unwrap();
    store.register_change(&c).unwrap();
    store.register_approval(&c, &permit).unwrap();
    let mut op = store
        .begin(&BeginRequest {
            request_id: "allow-request".into(),
            operation_id: "allow-operation".into(),
            change_hash: c.change_hash.clone(),
            approval_id: permit.id,
            expected_desired_head: None,
            execution_identity: EXECUTION.into(),
            now: 100,
        })
        .unwrap();
    let mut native = Fake::new(&c);
    native.proxy.require_tls = false;
    native.proxy.iam_authentication = false;
    cp.receipts.push(
        ManualCheckpoint::attest_preparation(
            &c,
            "billing-db",
            "recovery-operator",
            &preparation_fingerprint(&native.db, &native.proxy),
            100,
            600,
        )
        .unwrap(),
    );
    native
        .evidence
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .clear();
    let mut exec = AwsProtectionExecutor {
        source: None,
        query_only: false,
        cloud: AwsExecutor::new(native, EXECUTION.into(), cp.clone()),
        engine: PostgresStepExecutor::new(
            EXECUTION.into(),
            PostgresEngine {
                transport: Sql::default(),
            },
        ),
        binding: BindingStepExecutor::new(EXECUTION.into(), cp, 100),
    };
    let mut clock = Time(100);
    for _ in 0..12 {
        op = orchestrator::resume_with_clock(
            &mut store,
            "allow-operation",
            op.version,
            "worker",
            &mut clock,
            &mut exec,
        )
        .unwrap();
        drop(store);
        store = OperationStore::open_existing(&ledger).unwrap();
        if op.state == ExecutionState::WaitingEffect {
            break;
        }
    }
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(op.attempts, 8);
    assert_eq!(
        exec.cloud.provider.writes,
        vec!["proxy", "put-policy", "revoke-rule"]
    );
    assert_eq!(exec.engine.engine.transport.writes, 2);
    let attempts = op.attempts;
    op = orchestrator::resume_with_clock(
        &mut store,
        "allow-operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(op.attempts, attempts);
    assert_eq!(exec.cloud.provider.writes.len(), 3);
    clock.0 = 1100;
    exec.cloud.provider.now = 1100;
    let e = exec.cloud.provider.evidence.as_mut().unwrap();
    e.observed_at = 1100;
    e.direct_denied_principals = BTreeSet::from([APP.into(), RECOVERY.into()]);
    op = orchestrator::resume_with_clock(
        &mut store,
        "allow-operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::Completed);
    assert_eq!(op.attempts, 8);
    assert_eq!(exec.cloud.provider.writes.len(), 3);
    assert!(
        store
            .steps("allow-operation")
            .unwrap()
            .iter()
            .all(|r| matches!(
                r.state,
                StepState::EffectSatisfied | StepState::NoOpSatisfied
            ))
    );

    let revoke = prepare_maintenance(
        &c,
        "allow-operation",
        LifecycleKind::Revoke,
        "billing-access",
        &[],
        c.policy.targets.iter().flat_map(capabilities_for).collect(),
        1110,
        c.limits.clone(),
        false,
    )
    .unwrap();
    let permit = approval::issue(
        &revoke,
        "revoke-approval",
        "operator",
        EXECUTION,
        1900,
        2000,
        1110,
    )
    .unwrap();
    store.register_change(&revoke).unwrap();
    store.register_approval(&revoke, &permit).unwrap();
    let mut op = store
        .begin(&BeginRequest {
            request_id: "revoke-request".into(),
            operation_id: "revoke-operation".into(),
            change_hash: revoke.change_hash.clone(),
            approval_id: permit.id,
            expected_desired_head: Some(c.plan.policy_revision_hash.clone()),
            execution_identity: EXECUTION.into(),
            now: 1110,
        })
        .unwrap();
    let cp = ManualCheckpoints {
        receipts: vec![
            ManualCheckpoint::attest(
                &revoke,
                "billing-db",
                CheckpointKind::ExclusiveNativeChangeWindow,
                "recovery-operator",
                1110,
                1600,
            )
            .unwrap(),
        ],
    };
    let mut native = exec.cloud.provider;
    native.now = 1110;
    let mut observation = revocation(&revoke);
    observation.observed_at = 1110;
    observation.access = Access::Allowed;
    observation.iam_connect_denied = false;
    native.revoke = Some(observation);
    let mut exec = AwsProtectionExecutor {
        source: None,
        query_only: false,
        cloud: AwsExecutor::new(native, EXECUTION.into(), cp.clone()),
        engine: PostgresStepExecutor::new(
            EXECUTION.into(),
            PostgresEngine {
                transport: Sql::default(),
            },
        ),
        binding: BindingStepExecutor::new(EXECUTION.into(), cp, 1110),
    };
    clock.0 = 1110;
    for _ in 0..6 {
        op = orchestrator::resume_with_clock(
            &mut store,
            "revoke-operation",
            op.version,
            "worker",
            &mut clock,
            &mut exec,
        )
        .unwrap();
        if op.state == ExecutionState::WaitingEffect {
            break;
        }
    }
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(
        exec.cloud.last_revocation_evidence().unwrap().access,
        Access::Allowed
    );
    assert!(exec.cloud.provider.policy.is_none());
    assert_eq!(exec.engine.engine.transport.writes, 1);
    assert_eq!(
        exec.cloud.provider.writes,
        vec!["proxy", "put-policy", "revoke-rule", "delete-policy"]
    );
    let attempts = op.attempts;
    clock.0 = 2100;
    exec.cloud.provider.now = 2100;
    let e = exec.cloud.provider.revoke.as_mut().unwrap();
    e.observed_at = 2100;
    e.access = Access::Denied;
    e.iam_connect_denied = true;
    op = orchestrator::resume_with_clock(
        &mut store,
        "revoke-operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::Completed);
    assert_eq!(op.attempts, attempts);
    assert_eq!(
        exec.cloud.last_revocation_evidence().unwrap().access,
        Access::Denied
    );
    assert_eq!(exec.cloud.provider.writes.len(), 4);
    assert_eq!(exec.engine.engine.transport.writes, 1);
}

#[test]
fn mysql_native_route_iam_and_owned_3306_rule_apply_and_revoke() {
    let c = prepared_engine(false, EngineFamily::MySql);
    let mut e = executor(&c);
    e.provider.proxy.require_tls = false;
    e.provider.proxy.iam_authentication = false;
    for action in [
        ActionKind::PrepareNativeRoute,
        ActionKind::ConfigureIdentity,
        ActionKind::ConstrainDirectPath,
    ] {
        let s = step(&c, action);
        let r = e.submit(&c, s, &ticket(s)).unwrap();
        assert_eq!(
            e.query(&c, s, &record(s, r)).unwrap().effect,
            EffectState::Enforced
        );
    }
    assert_eq!(e.provider.writes, ["proxy", "put-policy", "revoke-rule"]);
    assert_eq!(e.provider.rules.len(), 1);
    assert_eq!(e.provider.rules[0].from_port, 3306);
    assert_eq!(e.provider.rules[0].id, "sgr-proxy");
    assert_eq!(
        e.provider.policy.as_ref().unwrap()["Statement"][0]["Resource"],
        "arn:aws:rds-db:ap-northeast-1:111122223333:dbuser:prx-IMMUTABLE/billing_app"
    );
    assert!(
        e.provider.backend["Statement"][0]["Resource"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r
                == "arn:aws:rds-db:ap-northeast-1:111122223333:dbuser:db-IMMUTABLE/recovery_user")
    );

    let deny = prepared_engine(true, EngineFamily::MySql);
    let s = step(&deny, ActionKind::DisableNativeIdentity);
    let r = e.submit(&deny, s, &ticket(s)).unwrap();
    assert_eq!(
        e.query(&deny, s, &record(s, r)).unwrap().effect,
        EffectState::Enforced
    );
    assert!(e.provider.policy.is_none());
    e.provider.revoke = Some(revocation(&deny));
    let s = step(&deny, ActionKind::ObserveRevocation);
    assert_eq!(
        e.submit(&deny, s, &ticket(s)).unwrap().effect,
        EffectState::Enforced
    );
    e.provider.revoke.as_mut().unwrap().access = Access::Unknown;
    assert_eq!(
        e.submit(&deny, s, &ticket(s)).unwrap().effect,
        EffectState::Pending
    );
    assert_eq!(e.provider.writes.len(), 4);
}

#[test]
fn mysql_rejects_engine_port_generation_policy_auth_and_rule_drift_before_any_write() {
    let c = prepared_engine(false, EngineFamily::MySql);
    for fault in [
        "db-engine",
        "proxy-engine",
        "db-version",
        "db-port",
        "db-generation",
        "backend",
        "legacy-auth",
        "direct-rule-port",
        "proxy-path-port",
        "owner-tag",
    ] {
        let mut e = executor(&c);
        let action = match fault {
            "direct-rule-port" | "proxy-path-port" | "owner-tag" => ActionKind::ConstrainDirectPath,
            _ => ActionKind::ConfigureIdentity,
        };
        match fault {
            "db-engine" => e.provider.db.engine_family = EngineFamily::MariaDb,
            "proxy-engine" => e.provider.proxy.engine_family = EngineFamily::SqlServer,
            "db-version" => e.provider.db.version = "8.0.42".into(),
            "db-port" => e.provider.db.port = 5432,
            "db-generation" => e.provider.db.resource_id = "db-RECREATED".into(),
            "backend" => e.provider.backend["Statement"][0]["Resource"] = json!(["*"]),
            "legacy-auth" => e.provider.proxy.auth_entries = 1,
            "direct-rule-port" => e.provider.rules[1].to_port = 5432,
            "proxy-path-port" => e.provider.rules[0].to_port = 5432,
            _ => e.provider.rules[1].tags.clear(),
        }
        let s = step(&c, action);
        assert!(e.submit(&c, s, &ticket(s)).is_err(), "{fault}");
        assert!(e.provider.writes.is_empty(), "{fault}");
    }
}

#[test]
fn mysql_ambiguous_native_write_and_source_gap_remain_pending_without_replay() {
    let c = prepared_engine(false, EngineFamily::MySql);
    let mut e = executor(&c);
    let s = step(&c, ActionKind::ConfigureIdentity);
    e.provider.ambiguous = true;
    assert_eq!(
        e.submit(&c, s, &ticket(s)),
        Err(ExecutorError::OutcomeUnknown)
    );
    let unknown = record(
        s,
        StepReceipt {
            state: StepState::Submitted,
            effect: EffectState::Pending,
            native_operation_ref: None,
            evidence_refs: vec![],
        },
    );
    for _ in 0..2 {
        assert!(e.query(&c, s, &unknown).is_err());
    }
    assert_eq!(e.provider.writes, ["put-policy"]);

    let mut e = executor(&c);
    e.provider
        .evidence
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .clear();
    let s = step(&c, ActionKind::ConstrainDirectPath);
    let r = e.submit(&c, s, &ticket(s)).unwrap();
    let r = record(s, r);
    for _ in 0..2 {
        assert_eq!(e.query(&c, s, &r).unwrap().effect, EffectState::Pending);
    }
    assert_eq!(e.provider.writes, ["revoke-rule"]);
}

#[test]
fn mysql_preparation_and_exclusive_window_guards_apply_before_native_changes() {
    let c = prepared_engine(false, EngineFamily::MySql);
    let s = step(&c, ActionKind::PrepareNativeRoute);
    let mut e = AwsExecutor::new(
        Fake::new(&c),
        EXECUTION.into(),
        Gate(Rc::new(Cell::new(false))),
    );
    e.provider.proxy.iam_authentication = false;
    assert!(e.submit(&c, s, &ticket(s)).is_err());
    assert!(e.provider.writes.is_empty());
    let mut e = executor(&c);
    let before = preparation_fingerprint(&e.provider.db, &e.provider.proxy);
    e.provider.db.engine_family = EngineFamily::PostgreSql;
    assert_ne!(
        before,
        preparation_fingerprint(&e.provider.db, &e.provider.proxy)
    );
    e.provider.db.engine_family = EngineFamily::MySql;
    e.provider.proxy.engine_family = EngineFamily::PostgreSql;
    assert_ne!(
        before,
        preparation_fingerprint(&e.provider.db, &e.provider.proxy)
    );
}

#[cfg(unix)]
#[test]
fn local_mysql_cli_strictly_binds_native_engine_proxy_family_and_exact_target() {
    use std::os::unix::fs::PermissionsExt;
    use tokio_util::sync::CancellationToken;
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("local-fake-aws");
    let instances = temp.path().join("instances.json");
    let proxies = temp.path().join("proxies.json");
    let targets = temp.path().join("targets.json");
    let script = format!(
        r##"#!/bin/sh
case "$1 $2" in
 'configure export-credentials') printf '%s' '{{"AccessKeyId":"LOCAL_KEY","SecretAccessKey":"LOCAL_SECRET","SessionToken":"LOCAL_SESSION"}}' ;;
 'sts get-caller-identity') printf '%s' '{{"Account":"111122223333","Arn":"arn:aws:sts::111122223333:assumed-role/runner/local","UserId":"AROA44444444444444444:local"}}' ;;
 'rds describe-db-instances') cat '{}' ;;
 'rds describe-db-proxies') cat '{}' ;;
 'rds describe-db-proxy-targets') cat '{}' ;;
 *) exit 48 ;;
esac
"##,
        instances.display(),
        proxies.display(),
        targets.display()
    );
    std::fs::write(&executable, script).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let c = prepared_engine(false, EngineFamily::MySql);
    let t = &c.policy.targets[0];
    let b = t.aws.as_ref().unwrap();
    let db = json!({"DBInstanceArn":t.resource.native_id,"DbiResourceId":b.db_resource_id,
        "Endpoint":{"Address":b.db_endpoint,"Port":3306},"Engine":"mysql","EngineVersion":"8.0.43",
        "DBInstanceStatus":"available","IAMDatabaseAuthenticationEnabled":true,
        "VpcSecurityGroups":[{"VpcSecurityGroupId":b.db_security_group_id}]});
    let proxy = json!({"DBProxyArn":b.proxy_arn,"DBProxyName":b.proxy_name,"Endpoint":b.proxy_endpoint,
        "RoleArn":PROXY_ROLE,"Status":"available","EngineFamily":"MYSQL","RequireTLS":true,
        "DefaultAuthScheme":"IAM_AUTH","Auth":[],"VpcSecurityGroupIds":[b.proxy_security_group_id]});
    let target = json!({"TargetArn":t.resource.native_id,"RdsResourceId":"billing-postgres",
        "Type":"RDS_INSTANCE","Endpoint":b.db_endpoint,"Port":3306});
    let write = |path: &std::path::Path, key: &str, value: &Value| {
        std::fs::write(path, json!({key:[value]}).to_string()).unwrap();
    };
    write(&instances, "DBInstances", &db);
    write(&proxies, "DBProxies", &proxy);
    write(&targets, "Targets", &target);
    let mut p = AwsCliProvider::new(
        executable,
        "approved".into(),
        ACCOUNT.into(),
        "arn:aws:iam::111122223333:role/runner".into(),
        "AROA44444444444444444".into(),
        CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(p.execution_identity().unwrap(), EXECUTION);
    assert_eq!(p.instance(t).unwrap().engine_family, EngineFamily::MySql);
    assert_eq!(p.proxy(t).unwrap().engine_family, EngineFamily::MySql);
    for engine in ["postgres", "mariadb", "sqlserver-ex", "unknown", "MYSQL"] {
        let mut wrong = db.clone();
        wrong["Engine"] = json!(engine);
        write(&instances, "DBInstances", &wrong);
        assert_eq!(p.instance(t), Err(ProviderError::Precondition), "{engine}");
    }
    for family in ["POSTGRESQL", "SQLSERVER", "unknown", "mysql"] {
        let mut wrong = proxy.clone();
        wrong["EngineFamily"] = json!(family);
        write(&proxies, "DBProxies", &wrong);
        assert_eq!(p.proxy(t), Err(ProviderError::Precondition), "{family}");
    }
    write(&proxies, "DBProxies", &proxy);
    for (key, value) in [
        ("Port", json!(5432)),
        ("TargetArn", json!("foreign-db")),
        ("RdsResourceId", json!("db-IMMUTABLE")),
        ("Endpoint", json!("other-endpoint")),
        ("Type", json!("TRACKED_CLUSTER")),
        ("TrackedClusterId", json!("cluster-foreign")),
    ] {
        let mut wrong = target.clone();
        wrong[key] = value;
        write(&targets, "Targets", &wrong);
        assert_eq!(p.proxy(t), Err(ProviderError::Precondition), "{key}");
    }
}

#[test]
fn sqlite_orchestrator_integrates_mysql_all_eight_steps_and_fresh_revoke() {
    use veil_db_guard::{
        adapters::{
            engine::mysql::{
                MysqlEngine, MysqlError, MysqlOutcome, MysqlStepExecutor, MysqlTransport, SqlBatch,
            },
            executor::AwsProtectionExecutor,
        },
        binding::*,
        core::{
            approval,
            lifecycle::{LifecycleKind, prepare_maintenance},
            operation::*,
            orchestrator::{self, Clock},
        },
        operation_store::OperationStore,
    };
    #[derive(Default)]
    struct Sql {
        writes: usize,
    }
    impl MysqlTransport for Sql {
        fn preflight(&mut self, _: &SqlBatch) -> Result<(), MysqlError> {
            Ok(())
        }
        fn execute(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
            self.writes += usize::from(!batch.statements().is_empty());
            Ok(MysqlOutcome::Applied)
        }
        fn query(&mut self, _: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
            Ok(MysqlOutcome::Applied)
        }
    }
    struct Time(u64);
    impl Clock for Time {
        fn now(&mut self) -> u64 {
            self.0
        }
    }
    let policy = prepared_engine(false, EngineFamily::MySql).policy;
    let plan = build_plan(
        &policy,
        policy.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    assert!(plan.capability_gaps.is_empty());
    assert_eq!(plan.steps.len(), 8);
    let allow = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
    let checkpoints = |c: &PreparedChange, now: u64| ManualCheckpoints {
        receipts: [
            CheckpointKind::BindingPublished,
            CheckpointKind::RecoveryReady,
            CheckpointKind::ApplicationCutover,
            CheckpointKind::ExclusiveNativeChangeWindow,
        ]
        .into_iter()
        .filter(|k| {
            *k == CheckpointKind::ExclusiveNativeChangeWindow
                || c.policy
                    .grants
                    .iter()
                    .any(|g| g.admission == AdmissionIntent::Allow)
        })
        .map(|k| {
            ManualCheckpoint::attest(c, "billing-db", k, "recovery-operator", now, now + 600)
                .unwrap()
        })
        .collect(),
    };
    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("mysql.sqlite");
    let mut store = OperationStore::open(&ledger).unwrap();
    let permit = approval::issue(
        &allow,
        "allow-approval",
        "operator",
        EXECUTION,
        900,
        1000,
        100,
    )
    .unwrap();
    store.register_change(&allow).unwrap();
    store.register_approval(&allow, &permit).unwrap();
    let mut op = store
        .begin(&BeginRequest {
            request_id: "allow-request".into(),
            operation_id: "allow-operation".into(),
            change_hash: allow.change_hash.clone(),
            approval_id: permit.id,
            expected_desired_head: None,
            execution_identity: EXECUTION.into(),
            now: 100,
        })
        .unwrap();
    let cp = checkpoints(&allow, 100);
    let mut native = Fake::new(&allow);
    native
        .evidence
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .clear();
    let mut exec = AwsProtectionExecutor {
        source: None,
        query_only: false,
        cloud: AwsExecutor::new(native, EXECUTION.into(), cp.clone()),
        engine: MysqlStepExecutor::new(
            EXECUTION.into(),
            MysqlEngine {
                transport: Sql::default(),
            },
        ),
        binding: BindingStepExecutor::new(EXECUTION.into(), cp, 100),
    };
    for s in &allow.plan.steps {
        assert!(exec.available(&allow, s), "unavailable {:?}", s.action);
    }
    let mut clock = Time(100);
    for _ in 0..12 {
        op = orchestrator::resume_with_clock(
            &mut store,
            "allow-operation",
            op.version,
            "worker",
            &mut clock,
            &mut exec,
        )
        .unwrap();
        drop(store);
        store = OperationStore::open_existing(&ledger).unwrap();
        if op.state == ExecutionState::WaitingEffect {
            break;
        }
    }
    assert_eq!(
        op.state,
        ExecutionState::WaitingEffect,
        "steps: {:?}",
        store.steps("allow-operation").unwrap()
    );
    assert_eq!(op.attempts, 8);
    assert_eq!(
        exec.engine.engine.transport.writes, 1,
        "account registration only verifies the existing IAM account"
    );
    assert_eq!(exec.cloud.provider.writes, ["put-policy", "revoke-rule"]);
    clock.0 = 1100;
    exec.cloud.provider.now = 1100;
    let e = exec.cloud.provider.evidence.as_mut().unwrap();
    e.observed_at = 1100;
    e.direct_denied_principals = BTreeSet::from([APP.into(), RECOVERY.into()]);
    op = orchestrator::resume_with_clock(
        &mut store,
        "allow-operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::Completed);
    assert_eq!(op.attempts, 8);
    assert_eq!(exec.engine.engine.transport.writes, 1);
    assert_eq!(exec.cloud.provider.writes.len(), 2);

    let deny = prepare_maintenance(
        &allow,
        "allow-operation",
        LifecycleKind::Revoke,
        "billing-access",
        &[],
        allow
            .policy
            .targets
            .iter()
            .flat_map(capabilities_for)
            .collect(),
        1110,
        allow.limits.clone(),
        false,
    )
    .unwrap();
    let permit = approval::issue(
        &deny,
        "deny-approval",
        "operator",
        EXECUTION,
        1900,
        2000,
        1110,
    )
    .unwrap();
    store.register_change(&deny).unwrap();
    store.register_approval(&deny, &permit).unwrap();
    let mut op = store
        .begin(&BeginRequest {
            request_id: "deny-request".into(),
            operation_id: "deny-operation".into(),
            change_hash: deny.change_hash.clone(),
            approval_id: permit.id,
            expected_desired_head: Some(allow.plan.policy_revision_hash.clone()),
            execution_identity: EXECUTION.into(),
            now: 1110,
        })
        .unwrap();
    let cp = checkpoints(&deny, 1110);
    let mut native = exec.cloud.provider;
    native.now = 1110;
    let mut observation = revocation(&deny);
    observation.observed_at = 1110;
    observation.access = Access::Allowed;
    observation.iam_connect_denied = false;
    native.revoke = Some(observation);
    let mut exec = AwsProtectionExecutor {
        source: None,
        query_only: false,
        cloud: AwsExecutor::new(native, EXECUTION.into(), cp.clone()),
        engine: MysqlStepExecutor::new(
            EXECUTION.into(),
            MysqlEngine {
                transport: Sql::default(),
            },
        ),
        binding: BindingStepExecutor::new(EXECUTION.into(), cp, 1110),
    };
    clock.0 = 1110;
    for _ in 0..6 {
        op = orchestrator::resume_with_clock(
            &mut store,
            "deny-operation",
            op.version,
            "worker",
            &mut clock,
            &mut exec,
        )
        .unwrap();
        if op.state == ExecutionState::WaitingEffect {
            break;
        }
    }
    assert_eq!(op.state, ExecutionState::WaitingEffect);
    assert_eq!(
        exec.cloud.last_revocation_evidence().unwrap().access,
        Access::Allowed
    );
    assert_eq!(
        exec.cloud.provider.writes,
        ["put-policy", "revoke-rule", "delete-policy"]
    );
    assert_eq!(exec.engine.engine.transport.writes, 1);
    let attempts = op.attempts;
    clock.0 = 2100;
    exec.cloud.provider.now = 2100;
    let e = exec.cloud.provider.revoke.as_mut().unwrap();
    e.observed_at = 2100;
    e.access = Access::Denied;
    e.iam_connect_denied = true;
    op = orchestrator::resume_with_clock(
        &mut store,
        "deny-operation",
        op.version,
        "worker",
        &mut clock,
        &mut exec,
    )
    .unwrap();
    assert_eq!(op.state, ExecutionState::Completed);
    assert_eq!(op.attempts, attempts);
    assert_eq!(exec.cloud.provider.writes.len(), 3);
    assert_eq!(exec.engine.engine.transport.writes, 1);
}
