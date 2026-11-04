//! Source-aware AWS composition with typed synthetic facts and local fakes.
//! No AWS process, source SSH collector or database is invoked.
use super::*;
use crate::adapters::engine::postgres::{PgError, PgOutcome, PostgresEngine, SqlBatch as PgBatch};
use crate::{
    adapters::{capabilities_for_policy, deployment::aws::*, engine::mysql::*},
    binding::*,
    core::{
        change::*,
        evidence::VerifiedObservationFacts,
        operation::*,
        policy::*,
        source::SourceBoundaryKind,
        source_execution::{tests as fixture, *},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
const RUNNER: &str = "local-aws-runner";
fn change(mysql: bool) -> PreparedChange {
    let mut p = parse_policy(if mysql {
        include_str!("../../../examples/core-aws-mysql-policy.yaml")
    } else {
        include_str!("../../../examples/core-aws-policy.yaml")
    })
    .unwrap();
    let v2 = fixture::change().policy;
    p.schema_version = 2;
    p.source_bindings = v2.source_bindings;
    for s in &mut p.source_bindings {
        s.boundary = SourceBoundaryKind::AwsHostNetwork;
    }
    p.evaluation = v2.evaluation;
    p.evaluation.as_mut().unwrap().denial_requirements[0].profile_id =
        p.protection_profiles[0].id.clone();
    let t = &mut p.targets[0];
    t.resource.generation_fingerprint = Some(generation_fingerprint(
        &t.placement.account_id,
        &t.placement.region,
        &t.resource.native_id,
        &t.aws.as_ref().unwrap().db_resource_id,
    ));
    let plan = crate::core::plan::build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100)
        .unwrap();
    prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap()
}
struct Gate {
    now: Arc<AtomicU64>,
    facts: Vec<VerifiedObservationFacts>,
}
impl SourceStepGate for Gate {
    fn validate_sources(&mut self, _: &PreparedChange) -> Result<(), ExecutorError> {
        Ok(())
    }
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn check(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        p: SourceStepPhase,
    ) -> Result<SourceStepCheck, ExecutorError> {
        check_source_step(c, s, p, self.now(), self.facts.clone())
    }
}
struct Provider {
    c: PreparedChange,
    db: RdsInstance,
    proxy: RdsProxy,
    rules: Vec<SecurityGroupRule>,
    writes: usize,
    clock: Arc<AtomicU64>,
    last_read_time: Option<u64>,
}
impl Provider {
    fn new(c: &PreparedChange, clock: Arc<AtomicU64>) -> Self {
        let t = &c.policy.targets[0];
        let b = t.aws.as_ref().unwrap();
        let port = if t.engine.family == EngineFamily::MySql {
            3306
        } else {
            5432
        };
        let owned = &b.owned_direct_rules[0];
        Self {
            c: c.clone(),
            db: RdsInstance {
                arn: t.resource.native_id.clone(),
                resource_id: b.db_resource_id.clone(),
                endpoint: b.db_endpoint.clone(),
                version: t.engine.version.clone(),
                engine_family: t.engine.family,
                available: true,
                iam_authentication: true,
                security_group_ids: BTreeSet::from([b.db_security_group_id.clone()]),
                port,
            },
            proxy: RdsProxy {
                arn: b.proxy_arn.clone(),
                name: b.proxy_name.clone(),
                endpoint: b.proxy_endpoint.clone(),
                role_arn: b.proxy_role_arn.clone(),
                available: true,
                engine_family: t.engine.family,
                require_tls: true,
                iam_authentication: true,
                auth_entries: 0,
                security_group_ids: BTreeSet::from([b.proxy_security_group_id.clone()]),
                target_resource_ids: BTreeSet::from([b.db_resource_id.clone()]),
            },
            rules: vec![
                SecurityGroupRule {
                    id: owned.rule_id.clone(),
                    group_id: b.db_security_group_id.clone(),
                    ingress: true,
                    protocol: owned.protocol.clone(),
                    from_port: i64::from(port),
                    to_port: i64::from(port),
                    source: Some(owned.source.clone()),
                    owner_account: t.placement.account_id.clone(),
                    tags: BTreeMap::from([(
                        owned.ownership_tag_key.clone(),
                        owned.ownership_tag_value.clone(),
                    )]),
                },
                SecurityGroupRule {
                    id: "sgr-proxy".into(),
                    group_id: b.db_security_group_id.clone(),
                    ingress: true,
                    protocol: "tcp".into(),
                    from_port: i64::from(port),
                    to_port: i64::from(port),
                    source: Some(AwsRuleSource::SecurityGroup {
                        group_id: b.proxy_security_group_id.clone(),
                        account_id: t.placement.account_id.clone(),
                    }),
                    owner_account: t.placement.account_id.clone(),
                    tags: BTreeMap::new(),
                },
            ],
            writes: 0,
            clock,
            last_read_time: None,
        }
    }
}
impl AwsProvider for Provider {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        Ok(RUNNER.into())
    }
    fn instance(&mut self, _: &Target) -> Result<RdsInstance, ProviderError> {
        Ok(self.db.clone())
    }
    fn proxy(&mut self, _: &Target) -> Result<RdsProxy, ProviderError> {
        Ok(self.proxy.clone())
    }
    fn role_id(&mut self, arn: &str) -> Result<String, ProviderError> {
        let b = self.c.policy.targets[0].aws.as_ref().unwrap();
        if arn == b.proxy_role_arn {
            return Ok(b.proxy_role_id.clone());
        }
        self.c
            .policy
            .subjects
            .iter()
            .find(|u| u.identity.principal == arn)
            .and_then(|u| u.identity.immutable_id.clone())
            .ok_or(ProviderError::Precondition)
    }
    fn inline_policy(
        &mut self,
        arn: &str,
        _: &str,
    ) -> Result<Option<serde_json::Value>, ProviderError> {
        let t = &self.c.policy.targets[0];
        if arn == t.aws.as_ref().unwrap().proxy_role_arn {
            Ok(Some(required_proxy_policy(&self.c, t)?))
        } else {
            Ok(None)
        }
    }
    fn put_inline_policy(
        &mut self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<(), ProviderError> {
        self.writes += 1;
        Ok(())
    }
    fn delete_inline_policy(
        &mut self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<(), ProviderError> {
        self.writes += 1;
        Ok(())
    }
    fn prepare_proxy(&mut self, _: &Target, _: &RdsProxy) -> Result<(), ProviderError> {
        self.writes += 1;
        Ok(())
    }
    fn rules(&mut self, _: &Target) -> Result<Vec<SecurityGroupRule>, ProviderError> {
        Ok(self.rules.clone())
    }
    fn revoke_rule(&mut self, _: &Target, r: &SecurityGroupRule) -> Result<(), ProviderError> {
        self.writes += 1;
        self.rules.retain(|v| v.id != r.id);
        Ok(())
    }
    fn revoke_rule_guarded(
        &mut self,
        t: &Target,
        r: &SecurityGroupRule,
        g: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        // Model a source revoke/expiry during the provider's final native read.
        assert!(self.rules(t)?.contains(r));
        if let Some(at) = self.last_read_time {
            self.clock.store(at, Ordering::SeqCst);
        }
        g()?;
        self.revoke_rule(t, r)
    }
    fn observe_connections(
        &mut self,
        _: &PreparedChange,
        _: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        panic!("CLI-host observer cannot supply source-bound proof")
    }
}
#[derive(Default)]
struct Sql {
    writes: usize,
}
impl PgTransport for Sql {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn preflight(&mut self, _: &PgBatch) -> Result<(), PgError> {
        Ok(())
    }
    fn execute_atomic(&mut self, _: &PgBatch) -> Result<PgOutcome, PgError> {
        self.writes += 1;
        Ok(PgOutcome::Applied)
    }
    fn execute_atomic_guarded(
        &mut self,
        b: &PgBatch,
        g: &mut crate::adapters::engine::postgres::BeforeSqlWrite<'_>,
    ) -> Result<PgOutcome, PgError> {
        g()?;
        self.execute_atomic(b)
    }
    fn query(&mut self, _: &PgBatch) -> Result<PgOutcome, PgError> {
        Ok(PgOutcome::Applied)
    }
}
fn setup(
    mysql: bool,
    runtime: bool,
) -> (
    PreparedChange,
    AwsProtectionExecutor<Provider, ManualCheckpoints, PostgresStepExecutor<Sql>>,
    Arc<AtomicU64>,
) {
    let c = change(mysql);
    let clock = Arc::new(AtomicU64::new(130));
    let cp = ManualCheckpoints {
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
    let exec = AwsProtectionExecutor {
        source: Some(Box::new(Gate {
            now: clock.clone(),
            facts: fixture::facts(&c, runtime, true),
        })),
        query_only: false,
        cloud: AwsExecutor::new(Provider::new(&c, clock.clone()), RUNNER.into(), cp.clone()),
        engine: PostgresStepExecutor::new(
            RUNNER.into(),
            PostgresEngine {
                transport: Sql::default(),
            },
        ),
        binding: BindingStepExecutor::new(RUNNER.into(), cp, 130),
    };
    (c, exec, clock)
}
fn close(c: &PreparedChange) -> &PlanStep {
    c.plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConstrainDirectPath)
        .unwrap()
}
fn ticket(s: &PlanStep) -> DispatchTicket {
    DispatchTicket {
        operation_id: "operation".into(),
        step_id: s.id.clone(),
        attempt: 1,
        operation_version: 1,
        idempotency_key: "key".into(),
        leases: LeaseSet {
            holder: "holder".into(),
            token: 1,
            keys: vec!["key".into()],
            expires_at: 4000,
        },
    }
}
#[test]
fn pg_and_mysql_preclose_missing_runtime_stops_before_native_read() {
    for mysql in [false, true] {
        let (c, mut e, _) = setup(mysql, false);
        assert!(e.preflight(&c, close(&c)).is_err());
        assert_eq!(e.cloud.provider.writes, 0);
    }
}
#[test]
fn pg_and_mysql_late_source_expiry_blocks_sg_mutation() {
    for mysql in [false, true] {
        let (c, mut e, _) = setup(mysql, true);
        e.preflight(&c, close(&c)).unwrap();
        e.cloud.provider.last_read_time = Some(1000);
        assert_eq!(
            e.submit(&c, close(&c), &ticket(close(&c))).unwrap_err(),
            ExecutorError::NotApplied
        );
        assert_eq!(e.cloud.provider.writes, 0);
    }
}
#[test]
fn pg_and_mysql_configuration_acceptance_and_source_completion_are_separate() {
    for mysql in [false, true] {
        let (c, mut e, clock) = setup(mysql, true);
        let s = close(&c);
        let submitted = e.submit(&c, s, &ticket(s)).unwrap();
        assert_eq!(submitted.state, StepState::Submitted);
        assert_eq!(e.cloud.provider.writes, 1);
        clock.store(1000, Ordering::SeqCst);
        let r = StepRecord {
            step_id: s.id.clone(),
            state: submitted.state,
            attempt: 1,
            idempotency_key: "key".into(),
            receipt: Some(submitted),
        };
        e.query_only = true;
        assert!(!e.available(&c, s));
        let receipt = e.query(&c, s, &r).unwrap();
        assert_eq!(receipt.state, StepState::ConfigApplied);
        assert_eq!(receipt.effect, EffectState::Unknown);
        assert_eq!(e.cloud.provider.writes, 1);
    }
}
#[test]
fn bare_aws_cloud_and_mysql_step_executors_cannot_dispatch_v3() {
    for mysql in [false, true] {
        let (c, mut e, _) = setup(mysql, true);
        let s = close(&c);
        assert!(e.cloud.submit(&c, s, &ticket(s)).is_err());
        assert_eq!(e.cloud.provider.writes, 0);
    }
    struct MySql;
    impl MysqlTransport for MySql {
        fn preflight(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<(), MysqlError> {
            panic!("bare transport called")
        }
        fn execute(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<MysqlOutcome, MysqlError> {
            panic!("bare transport called")
        }
        fn query(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<MysqlOutcome, MysqlError> {
            Ok(MysqlOutcome::Applied)
        }
    }
    let c = change(true);
    let s = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    let mut e = MysqlStepExecutor::new(RUNNER.into(), MysqlEngine { transport: MySql });
    assert!(!e.available(&c, s));
    assert!(e.submit(&c, s, &ticket(s)).is_err());
}
#[test]
fn old_evaluation_only_aws_approvals_never_gain_dispatch_qualification() {
    for mysql in [false, true] {
        let c = change(mysql);
        let mut caps = capabilities_for_policy(&c.policy).unwrap();
        for cap in &mut caps {
            cap.contract_revision = if crate::core::capability::requires_source_evidence(cap.action)
            {
                crate::core::evidence::SOURCE_BOUND_ADAPTER_CONTRACT.into()
            } else if mysql {
                "core-adapter-v3".into()
            } else {
                "core-adapter-v2".into()
            };
        }
        let plan = crate::core::plan::build_plan(&c.policy, caps, vec![], 100).unwrap();
        let old = prepare_change(&c.policy, &plan, &[], None, OperationLimits::default()).unwrap();
        assert_ne!(old.change_hash, c.change_hash);
        assert!(
            !crate::adapters::qualification::qualify_change(&old)
                .unwrap()
                .is_dispatch_qualified()
        );
        assert!(
            crate::adapters::qualification::qualify_change(&c)
                .unwrap()
                .is_dispatch_qualified()
        );
    }
}
#[test]
fn mysql_v3_requires_a_guard_capable_transport_even_inside_composition() {
    struct Legacy;
    impl MysqlTransport for Legacy {
        fn preflight(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<(), MysqlError> {
            panic!("unsupported source transport reached")
        }
        fn execute(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<MysqlOutcome, MysqlError> {
            panic!("unsupported source transport reached")
        }
        fn query(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<MysqlOutcome, MysqlError> {
            Ok(MysqlOutcome::Applied)
        }
    }
    let c = change(true);
    let s = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    let e = MysqlStepExecutor::new(RUNNER.into(), MysqlEngine { transport: Legacy });
    assert!(!SourceEngineExecutor::source_available(&e, &c, s));
}
#[test]
fn mysql_source_guard_rejection_before_first_write_is_not_applied() {
    struct Guarded {
        writes: usize,
    }
    impl MysqlTransport for Guarded {
        fn supports_source_guard(&self) -> bool {
            true
        }
        fn preflight(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<(), MysqlError> {
            Ok(())
        }
        fn execute(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<MysqlOutcome, MysqlError> {
            panic!("unguarded source dispatch")
        }
        fn execute_guarded(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
            g: &mut BeforeMysqlWrite<'_>,
        ) -> Result<MysqlOutcome, MysqlError> {
            g()?;
            self.writes += 1;
            Ok(MysqlOutcome::Applied)
        }
        fn query(
            &mut self,
            _: &crate::adapters::engine::mysql::SqlBatch,
        ) -> Result<MysqlOutcome, MysqlError> {
            Ok(MysqlOutcome::Applied)
        }
    }
    let (c, e, clock) = setup(true, true);
    let s = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    let mut engine = MysqlStepExecutor::new(
        RUNNER.into(),
        MysqlEngine {
            transport: Guarded { writes: 0 },
        },
    );
    let mut gate = Gate {
        now: clock.clone(),
        facts: fixture::facts(&c, true, true),
    };
    assert!(SourceEngineExecutor::source_available(&engine, &c, s));
    clock.store(1000, Ordering::SeqCst);
    assert_eq!(
        SourceEngineExecutor::submit_source(&mut engine, &c, s, &mut gate, &e.binding.checkpoints)
            .unwrap_err(),
        ExecutorError::NotApplied
    );
    assert_eq!(engine.engine.transport.writes, 0);
}

#[test]
fn late_checkpoint_expiry_blocks_even_while_source_facts_remain_fresh() {
    for mysql in [false, true] {
        let (c, mut e, clock) = setup(mysql, true);
        let s = close(&c);
        let cp = ManualCheckpoints {
            receipts: [
                CheckpointKind::BindingPublished,
                CheckpointKind::RecoveryReady,
                CheckpointKind::ApplicationCutover,
                CheckpointKind::ExclusiveNativeChangeWindow,
            ]
            .into_iter()
            .map(|k| {
                ManualCheckpoint::attest(&c, "billing-db", k, "recovery-operator", 100, 150)
                    .unwrap()
            })
            .collect(),
        };
        let mut provider = Provider::new(&c, clock);
        provider.last_read_time = Some(160);
        e.cloud = AwsExecutor::new(provider, RUNNER.into(), cp);
        // The source evaluator still accepts the same facts at t=160.
        assert!(
            check_source_step(
                &c,
                s,
                SourceStepPhase::BeforeDispatch,
                160,
                fixture::facts(&c, true, true)
            )
            .unwrap()
            .satisfied()
        );
        e.preflight(&c, s).unwrap();
        assert_eq!(
            e.submit(&c, s, &ticket(s)).unwrap_err(),
            ExecutorError::NotApplied
        );
        assert_eq!(e.cloud.provider.writes, 0);
    }
}
