use veil_db_guard::{
    adapters::engine::mysql::*,
    core::{
        capability::ActionKind,
        change::{OperationLimits, prepare_change},
        operation::{DispatchTicket, EffectState, LeaseSet, StepReceipt, StepRecord, StepState},
        orchestrator::StepExecutor,
        plan::build_plan,
        policy::*,
    },
};

fn policy() -> PolicyRevision {
    parse_policy(include_str!("../examples/core-aws-mysql-policy.yaml")).unwrap()
}

#[test]
fn mysql_table_sql_uses_explicit_account_and_independent_exact_privileges() {
    let mut p = policy();
    p.grants[0].sql_access.privileges[0].scope.object =
        Some("invoices`; DROP TABLE other;--".into());
    let batch = compile(
        &p,
        "billing-db",
        "billing-access",
        MysqlAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    assert_eq!(batch.statements().len(), 3);
    assert_eq!(
        batch.statements()[0],
        "GRANT SELECT ON TABLE `billing`.`invoices``; DROP TABLE other;--` TO 'billing_app'@'%'"
    );
    assert!(
        batch.statements().iter().all(|s| !s.contains("GRANT ALL")
            && !s.contains("GRANT OPTION")
            && !s.contains("BEGIN"))
    );
    let hash = batch.hash();
    p.targets[0].mysql.as_mut().unwrap().account_host = "127.0.0.1".into();
    assert_ne!(
        hash,
        compile(
            &p,
            "billing-db",
            "billing-access",
            MysqlAction::ConfigureSqlPrivileges
        )
        .unwrap()
        .hash()
    );
}

#[test]
fn registration_verifies_existing_auth_without_mutating_or_creating_accounts() {
    let p = policy();
    let batch = compile(
        &p,
        "billing-db",
        "billing-access",
        MysqlAction::RegisterNativeDbIdentity,
    )
    .unwrap();
    assert!(batch.statements().is_empty());
    assert_eq!(batch.version(), "8.0.43");
    let mut deny = p.clone();
    deny.grants[0].admission = AdmissionIntent::Deny;
    deny.grants[0].sql_access = SqlAccessIntent::default();
    assert!(
        compile(
            &deny,
            "billing-db",
            "billing-access",
            MysqlAction::RegisterNativeDbIdentity
        )
        .is_err()
    );
    let lock = compile(
        &deny,
        "billing-db",
        "billing-access",
        MysqlAction::DisableNewConnections,
    )
    .unwrap();
    assert_eq!(
        lock.statements(),
        &["ALTER USER 'billing_app'@'%' ACCOUNT LOCK"]
    );
}

#[test]
fn mysql_refuses_roles_pg_schema_semantics_and_ambiguous_accounts() {
    assert!(quote_account("billing_app", "").is_err());
    assert!(quote_account("billing_app", "%'; DROP USER x;--").is_err());
    assert!(quote_account("user@host", "%").is_err());
    assert!(quote_account(&"a".repeat(33), "%").is_err());
    assert!(quote_identifier("x\0y").is_err());
    let mut p = policy();
    p.targets[0]
        .managed_surface
        .db_identities
        .push("existing_reader".into());
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
    p.grants[0].sql_access.existing_roles = vec!["existing_reader".into()];
    assert!(
        compile(
            &p,
            "billing-db",
            "billing-access",
            MysqlAction::ConfigureSqlPrivileges
        )
        .is_err()
    );
    let mut p = policy();
    p.targets[0].managed_surface.sql_scopes[0].schema = Some("pg_schema".into());
    p.grants[0].sql_access.privileges[0].scope.schema = Some("pg_schema".into());
    assert!(
        compile(
            &p,
            "billing-db",
            "billing-access",
            MysqlAction::ConfigureSqlPrivileges
        )
        .is_err()
    );
    let mut p = policy();
    p.grants[0].sql_access.privileges[0].scope = SqlScope {
        database: "billing".into(),
        kind: SqlObjectKind::Database,
        schema: None,
        object: None,
    };
    p.targets[0].managed_surface.sql_scopes =
        vec![p.grants[0].sql_access.privileges[0].scope.clone()];
    p.grants[0].sql_access.privileges[0].actions = vec![SqlAction::Connect];
    assert!(
        compile(
            &p,
            "billing-db",
            "billing-access",
            MysqlAction::ConfigureSqlPrivileges
        )
        .is_err()
    );
}

fn ownership(p: &PolicyRevision) -> (SqlBatch, MysqlLifecycleContext, PolicyRevision) {
    let batch = compile(
        p,
        "billing-db",
        "billing-access",
        MysqlAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let value = serde_json::to_value(&batch).unwrap();
    let checks = value["checks"].as_array().unwrap();
    // First privilege existed before adoption. It must remain after revoke.
    let owned: MysqlOwnershipReceipt = serde_json::from_value(serde_json::json!({
        "policy_hash": value["policy_hash"], "apply_batch_hash": batch.hash(),
        "management_identity": "'veil_recovery'@'%'",
        "before_privileges": [checks[0].clone()], "after_privileges": checks,
        "added_privileges": &checks[1..], "acknowledged_statements": [0,1,2],
        "uncertain_statement": null, "outcome": "Applied"
    }))
    .unwrap();
    let plan = build_plan(p, vec![], vec![], 0).unwrap();
    let sql = plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    let context = MysqlLifecycleContext {
        prior_policy: p.clone(),
        prior_operation_id: "prior-operation".into(),
        prior_change_hash: "a".repeat(64),
        authorization_source: None,
        prior_sql_step: StepRecord {
            step_id: sql.id.clone(),
            state: StepState::EffectSatisfied,
            attempt: 1,
            idempotency_key: "b".repeat(64),
            receipt: Some(StepReceipt {
                state: StepState::EffectSatisfied,
                effect: EffectState::Enforced,
                native_operation_ref: None,
                evidence_refs: vec![batch.hash(), owned.hash()],
            }),
        },
        ownership: Some(owned),
    };
    let mut deny = p.clone();
    deny.revision += 1;
    deny.parent_revision_hash = Some(p.revision_hash().unwrap());
    deny.grants[0].admission = AdmissionIntent::Deny;
    deny.grants[0].sql_access = SqlAccessIntent::default();
    (batch, context, deny)
}

#[test]
fn revoke_preserves_preexisting_rights_and_requires_exact_successful_delta() {
    let p = policy();
    let (_, context, deny) = ownership(&p);
    let revoke = compile_owned_revoke(&deny, &p, "billing-db", "billing-access", &context).unwrap();
    assert_eq!(
        revoke.statements(),
        &[
            "REVOKE INSERT ON TABLE `billing`.`invoices` FROM 'billing_app'@'%'",
            "REVOKE UPDATE ON TABLE `billing`.`invoices` FROM 'billing_app'@'%'",
        ]
    );
    let mut forged = context.clone();
    let mut value = serde_json::to_value(forged.ownership.as_ref().unwrap()).unwrap();
    value["added_privileges"] = value["after_privileges"].clone();
    forged.ownership = Some(serde_json::from_value(value).unwrap());
    assert!(compile_owned_revoke(&deny, &p, "billing-db", "billing-access", &forged).is_err());
    let mut missing = context;
    missing
        .prior_sql_step
        .receipt
        .as_mut()
        .unwrap()
        .evidence_refs
        .pop();
    assert!(compile_owned_revoke(&deny, &p, "billing-db", "billing-access", &missing).is_err());
}

#[test]
fn partial_and_unknown_durable_proofs_never_authorize_revoke() {
    let p = policy();
    for outcome in ["Partial", "Unknown", "NotApplied"] {
        let (_, mut context, deny) = ownership(&p);
        let mut value = serde_json::to_value(context.ownership.as_ref().unwrap()).unwrap();
        value["outcome"] = outcome.into();
        value["acknowledged_statements"] = serde_json::json!([0]);
        value["uncertain_statement"] = 1.into();
        let owned: MysqlOwnershipReceipt = serde_json::from_value(value).unwrap();
        context
            .prior_sql_step
            .receipt
            .as_mut()
            .unwrap()
            .evidence_refs[1] = owned.hash();
        context.ownership = Some(owned);
        assert!(compile_owned_revoke(&deny, &p, "billing-db", "billing-access", &context).is_err());
    }
}

#[test]
fn durable_partial_receipt_is_preserved_without_becoming_revoke_authority() {
    let p = policy();
    let (batch, mut context, deny) = ownership(&p);
    let mut value = serde_json::to_value(context.ownership.as_ref().unwrap()).unwrap();
    value["outcome"] = "Unknown".into();
    value["acknowledged_statements"] = serde_json::json!([0]);
    value["uncertain_statement"] = 1.into();
    let owned: MysqlOwnershipReceipt = serde_json::from_value(value).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let run = directory.path().join("mysql-partial");
    let mut writer = veil_db_guard::store::RunWriter::create_for_config(
        &run,
        "billing-db",
        &batch,
        "mysql-ownership",
        2 * 1024 * 1024,
        true,
    )
    .unwrap();
    writer.write_json("mysql-ownership.json", &owned).unwrap();
    writer
        .finish(veil_db_guard::store::RunStatus::Complete)
        .unwrap();
    let loaded = MysqlOwnershipReceipt::load_verified_run(&run).unwrap();
    assert_eq!(loaded.hash(), owned.hash());
    context
        .prior_sql_step
        .receipt
        .as_mut()
        .unwrap()
        .evidence_refs[1] = loaded.hash();
    context.ownership = Some(loaded);
    assert!(compile_owned_revoke(&deny, &p, "billing-db", "billing-access", &context).is_err());
}

struct PartialWrite {
    writes: usize,
    reads: usize,
    observed: MysqlOutcome,
    owned: Option<MysqlOwnershipReceipt>,
}
impl MysqlTransport for PartialWrite {
    fn owned_receipt(&self) -> Option<MysqlOwnershipReceipt> {
        self.owned.clone()
    }
    fn preflight(&mut self, _: &SqlBatch) -> Result<(), MysqlError> {
        Ok(())
    }
    fn execute(&mut self, _: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
        self.writes += 1;
        Ok(MysqlOutcome::Partial)
    }
    fn query(&mut self, _: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
        self.reads += 1;
        Ok(self.observed)
    }
}

#[test]
fn partial_resume_is_read_only_even_when_observed_privileges_are_absent() {
    let p = policy();
    let capabilities = p
        .targets
        .iter()
        .flat_map(veil_db_guard::adapters::capabilities_for)
        .collect();
    let plan = build_plan(&p, capabilities, vec![], 100).unwrap();
    let change = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    let batch = compile(
        &p,
        "billing-db",
        "billing-access",
        MysqlAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let mut executor = MysqlStepExecutor::new(
        "operator".into(),
        MysqlEngine {
            transport: PartialWrite {
                writes: 0,
                reads: 0,
                observed: MysqlOutcome::NotApplied,
                owned: None,
            },
        },
    );
    let (_, context, _) = ownership(&p);
    let mut value = serde_json::to_value(context.ownership.unwrap()).unwrap();
    value["outcome"] = "Partial".into();
    value["acknowledged_statements"] = serde_json::json!([0]);
    value["uncertain_statement"] = 1.into();
    executor.engine.transport.owned = Some(serde_json::from_value(value).unwrap());
    let ticket = DispatchTicket {
        operation_id: "operation".into(),
        step_id: step.id.clone(),
        attempt: 1,
        operation_version: 1,
        idempotency_key: "b".repeat(64),
        leases: LeaseSet {
            holder: "worker".into(),
            token: 1,
            keys: vec![],
            expires_at: 200,
        },
    };
    let receipt = executor.submit(&change, step, &ticket).unwrap();
    assert_eq!(receipt.state, StepState::OutcomeUnknown);
    assert!(receipt.evidence_refs.contains(&batch.hash()));
    assert!(
        receipt
            .evidence_refs
            .contains(&executor.engine.transport.owned.as_ref().unwrap().hash())
    );
    let record = StepRecord {
        step_id: step.id.clone(),
        state: StepState::OutcomeUnknown,
        attempt: 1,
        idempotency_key: "b".repeat(64),
        receipt: None,
    };
    let receipt = executor.query(&change, step, &record).unwrap();
    assert_eq!(receipt.state, StepState::OutcomeUnknown);
    assert_eq!(receipt.effect, EffectState::Unknown);
    assert_eq!(executor.engine.transport.writes, 1);
    assert_eq!(executor.engine.transport.reads, 1);
    executor.engine.transport.observed = MysqlOutcome::Applied;
    assert_eq!(
        executor.query(&change, step, &record).unwrap().state,
        StepState::EffectSatisfied
    );
    assert_eq!(executor.engine.transport.writes, 1);
}
