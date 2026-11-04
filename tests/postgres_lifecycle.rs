//! Local typed compilation and injected-transport tests. No database is opened.
use veil_db_guard::{
    adapters::engine::postgres::*,
    core::{
        operation::{EffectState, StepReceipt, StepRecord, StepState},
        policy::*,
    },
};

fn source() -> PolicyRevision {
    parse_policy(include_str!("../examples/core-policy.yaml"))
        .unwrap()
        .normalized()
}
fn revoke(prior: &PolicyRevision) -> PolicyRevision {
    let mut policy = prior.clone();
    policy.revision += 1;
    policy.parent_revision_hash = Some(prior.revision_hash().unwrap());
    policy.grants[0].admission = AdmissionIntent::Deny;
    policy.grants[0].sql_access = SqlAccessIntent::default();
    policy
}
fn context(prior: &PolicyRevision, include_role: bool) -> PgLifecycleContext {
    let batch = compile(
        prior,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let value = serde_json::to_value(&batch).unwrap();
    // Test fixture for a trusted native artifact. Production artifacts originate
    // only from the transaction's before/after catalog readback.
    let ownership: PgOwnershipReceipt = serde_json::from_value(serde_json::json!({
        "policy_hash": prior.revision_hash().unwrap(),
        "apply_batch_hash": batch.hash(),
        "management_role": "management",
        "before_roles": [], "before_privileges": [],
        "after_roles": if include_role { value["roles"].clone() } else { serde_json::json!([]) },
        "after_privileges": [value["checks"][0].clone()],
        "added_roles": if include_role { value["roles"].clone() } else { serde_json::json!([]) },
        "added_privileges": [value["checks"][0].clone()]
    }))
    .unwrap();
    PgLifecycleContext {
        prior_policy: prior.clone(),
        prior_operation_id: "prior-apply".into(),
        prior_change_hash: "a".repeat(64),
        authorization_source: None,
        prior_sql_step: StepRecord {
            step_id: veil_db_guard::core::plan::build_plan(prior, vec![], vec![], 0)
                .unwrap()
                .steps
                .into_iter()
                .find(|s| {
                    s.action == veil_db_guard::core::capability::ActionKind::ConfigureSqlPrivileges
                })
                .unwrap()
                .id,
            state: StepState::EffectSatisfied,
            attempt: 1,
            idempotency_key: "b".repeat(64),
            receipt: Some(StepReceipt {
                state: StepState::EffectSatisfied,
                effect: EffectState::Enforced,
                native_operation_ref: None,
                evidence_refs: vec![batch.hash(), ownership.hash()],
            }),
        },
        ownership: Some(ownership),
    }
}
#[test]
fn revoke_compiles_only_owned_delta_with_exact_grantor_and_restrict() {
    let prior = source();
    let policy = revoke(&prior);
    let batch = compile_owned_revoke(
        &policy,
        &prior,
        "billing-db",
        "billing-access",
        &context(&prior, false),
    )
    .unwrap();
    assert_eq!(batch.statements().len(), 1);
    assert!(
        batch.statements()[0].starts_with("REVOKE SELECT ON TABLE \"billing\".\"invoices\" FROM ")
    );
    assert!(batch.statements()[0].ends_with(" GRANTED BY \"management\" RESTRICT"));
    // This preexisting role relationship and the unowned UPDATE privilege are
    // retained, even though the old intent included them.
    assert!(
        !batch
            .statements()
            .iter()
            .any(|s| s.contains("billing-reader-writer") || s.contains("UPDATE"))
    );
    assert!(
        batch
            .statements()
            .iter()
            .all(|s| !s.contains("CASCADE") && !s.contains("GRANT ") && !s.contains("LOGIN"))
    );
    let role = compile_owned_revoke(
        &policy,
        &prior,
        "billing-db",
        "billing-access",
        &context(&prior, true),
    )
    .unwrap();
    assert_eq!(role.statements().len(), 2);
    assert!(role.statements()[0].starts_with("REVOKE \"billing-reader-writer\" FROM "));
}
#[test]
fn missing_unknown_or_tampered_ownership_never_authorizes_removal() {
    let prior = source();
    let policy = revoke(&prior);
    let mut proof = context(&prior, false);
    proof.ownership = None;
    assert_eq!(
        compile_owned_revoke(&policy, &prior, "billing-db", "billing-access", &proof),
        Err(PgError::Unsupported)
    );
    let mut proof = context(&prior, false);
    proof.prior_sql_step.state = StepState::OutcomeUnknown;
    assert_eq!(
        compile_owned_revoke(&policy, &prior, "billing-db", "billing-access", &proof),
        Err(PgError::Precondition)
    );
    let mut proof = context(&prior, false);
    proof
        .prior_sql_step
        .receipt
        .as_mut()
        .unwrap()
        .evidence_refs
        .pop();
    assert_eq!(
        compile_owned_revoke(&policy, &prior, "billing-db", "billing-access", &proof),
        Err(PgError::Precondition)
    );
    // The legacy batch hash alone does not prove a newly introduced delta.
    let batch = compile(
        &prior,
        "billing-db",
        "billing-access",
        PgAction::RevokeSqlPrivileges,
    );
    assert_eq!(batch, Err(PgError::Precondition));
}
#[test]
fn wrong_prior_policy_and_forged_out_of_scope_delta_are_rejected() {
    let prior = source();
    let policy = revoke(&prior);
    let mut proof = context(&prior, false);
    let mut artifact = serde_json::to_value(proof.ownership.as_ref().unwrap()).unwrap();
    artifact["added_roles"] = serde_json::json!(["foreign_reader"]);
    artifact["after_roles"] = serde_json::json!(["foreign_reader"]);
    let forged: PgOwnershipReceipt = serde_json::from_value(artifact).unwrap();
    // Even a matching artifact digest cannot broaden the original typed batch.
    proof.prior_sql_step.receipt.as_mut().unwrap().evidence_refs[1] = forged.hash();
    proof.ownership = Some(forged);
    assert_eq!(
        compile_owned_revoke(&policy, &prior, "billing-db", "billing-access", &proof),
        Err(PgError::Precondition)
    );
    let mut wrong = policy;
    wrong.parent_revision_hash = Some("c".repeat(64));
    assert_eq!(
        compile_owned_revoke(
            &wrong,
            &prior,
            "billing-db",
            "billing-access",
            &context(&prior, false)
        ),
        Err(PgError::Precondition)
    );
}

#[test]
fn source_step_identity_and_empty_owned_delta_fail_closed() {
    let prior = source();
    let policy = revoke(&prior);
    let mut proof = context(&prior, false);
    proof.prior_sql_step.step_id = "another-grant-step-3".into();
    assert_eq!(
        compile_owned_revoke(&policy, &prior, "billing-db", "billing-access", &proof),
        Err(PgError::Precondition)
    );
    let mut proof = context(&prior, false);
    let mut value = serde_json::to_value(proof.ownership.as_ref().unwrap()).unwrap();
    value["added_privileges"] = serde_json::json!([]);
    value["after_privileges"] = serde_json::json!([]);
    let owned: PgOwnershipReceipt = serde_json::from_value(value).unwrap();
    proof.prior_sql_step.receipt.as_mut().unwrap().evidence_refs[1] = owned.hash();
    proof.ownership = Some(owned);
    assert_eq!(
        compile_owned_revoke(&policy, &prior, "billing-db", "billing-access", &proof),
        Err(PgError::Unsupported)
    );
}

#[test]
fn ownership_run_is_retrievable_and_tampering_is_detected_locally() {
    use veil_db_guard::store::{RunStatus, RunWriter};
    let prior = source();
    let owned = context(&prior, false).ownership.unwrap();
    let batch = compile(
        &prior,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ownership");
    let mut writer = RunWriter::create_for_config(
        &path,
        "billing-db",
        &batch,
        "postgres-ownership",
        2 * 1024 * 1024,
        true,
    )
    .unwrap();
    writer
        .write_json("postgres-ownership.json", &owned)
        .unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    assert_eq!(PgOwnershipReceipt::load_verified_run(&path).unwrap(), owned);
    std::fs::write(path.join("postgres-ownership.json"), b"{}\n").unwrap();
    assert_eq!(
        PgOwnershipReceipt::load_verified_run(&path),
        Err(PgError::Precondition)
    );
}

struct FailedRevoke {
    context: PgLifecycleContext,
    sent: Vec<String>,
    queries: usize,
}
impl PgTransport for FailedRevoke {
    fn lifecycle_context(&self) -> Option<&PgLifecycleContext> {
        Some(&self.context)
    }
    fn preflight(&mut self, _: &SqlBatch) -> Result<(), PgError> {
        Ok(())
    }
    fn execute_atomic(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.sent.extend_from_slice(batch.statements());
        Ok(PgOutcome::Unknown)
    }
    fn query(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.queries += 1;
        Ok(PgOutcome::NotApplied)
    }
}
#[test]
fn unknown_revoke_only_reads_on_resume_and_never_restores_allow() {
    use veil_db_guard::core::{
        capability::ActionKind,
        change::{OperationLimits, prepare_change},
        orchestrator::StepExecutor,
        plan::build_plan,
    };
    let prior = source();
    let capabilities = prior
        .targets
        .iter()
        .flat_map(veil_db_guard::adapters::capabilities_for)
        .collect();
    let plan = build_plan(&prior, capabilities, vec![], 100).unwrap();
    let source = prepare_change(&prior, &plan, &[], None, OperationLimits::default()).unwrap();
    let capabilities = prior
        .targets
        .iter()
        .flat_map(veil_db_guard::adapters::capabilities_for)
        .collect();
    let change = veil_db_guard::core::lifecycle::prepare_maintenance(
        &source,
        "prior-apply",
        veil_db_guard::core::lifecycle::LifecycleKind::Revoke,
        "billing-access",
        &[],
        capabilities,
        101,
        OperationLimits::default(),
        true,
    )
    .unwrap();
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::RevokeSqlPrivileges)
        .unwrap();
    let mut proof = context(&prior, true);
    proof.prior_change_hash = source.change_hash.clone();
    let batch = compile_owned_revoke(
        &change.policy,
        &prior,
        "billing-db",
        "billing-access",
        &proof,
    )
    .unwrap();
    let mut executor = PostgresStepExecutor::new(
        "operator".into(),
        PostgresEngine {
            transport: FailedRevoke {
                context: proof,
                sent: vec![],
                queries: 0,
            },
        },
    );
    assert!(executor.available(&change, step));
    assert_eq!(executor.engine.submit(&batch).unwrap(), PgOutcome::Unknown);
    let record = StepRecord {
        step_id: step.id.clone(),
        state: StepState::OutcomeUnknown,
        attempt: 1,
        idempotency_key: "c".repeat(64),
        receipt: None,
    };
    let result = executor.query(&change, step, &record).unwrap();
    assert_eq!(result.state, StepState::OutcomeUnknown);
    assert_eq!(executor.engine.transport.queries, 1);
    assert_eq!(executor.engine.transport.sent.len(), 2);
    assert!(
        executor
            .engine
            .transport
            .sent
            .iter()
            .all(|s| s.starts_with("REVOKE "))
    );
}

#[test]
fn nologin_refuses_shared_allow_role_in_same_native_instance_across_databases() {
    let prior = source();
    let mut policy = revoke(&prior);
    // A distinct subject reference can still resolve to the same database role.
    let mut subject = policy
        .subjects
        .iter()
        .find(|s| s.id == "billing-app")
        .unwrap()
        .clone();
    subject.id = "second-billing-app".into();
    policy.subjects.push(subject);
    let mut other = prior.grants[0].clone();
    other.id = "second-billing-access".into();
    other.subject = "second-billing-app".into();
    policy.grants.push(other);
    policy.validate().unwrap();
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::DisableNewConnections
        ),
        Err(PgError::Scope)
    );

    let mut other_target = policy.targets[0].clone();
    other_target.id = "analytics-db".into();
    other_target.registration_id = "analytics-registration".into();
    other_target.engine.database = "analytics".into();
    other_target.managed_surface.sql_scopes[0].database = "analytics".into();
    // Current validation disallows duplicate native targets with the same
    // region. Even a differing region label cannot make the native role local
    // to the second database; the native ID and account still name one cluster.
    other_target.placement.region = "asia-northeast2".into();
    policy.targets.push(other_target);
    policy.grants[1].target = "analytics-db".into();
    policy.grants[1].sql_access.privileges[0].scope.database = "analytics".into();
    policy.validate().unwrap();
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::DisableNewConnections
        ),
        Err(PgError::Scope)
    );

    // The same role name on a distinct native instance has independent LOGIN.
    policy.targets[1].resource.native_id =
        "projects/vdg-example-000000/instances/analytics-postgres".into();
    policy.validate().unwrap();
    assert!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::DisableNewConnections
        )
        .is_ok()
    );
}

#[test]
fn deny_maintenance_binds_immediate_approval_parent_and_keeps_original_ownership() {
    use veil_db_guard::core::{
        capability::ActionKind,
        change::{OperationLimits, prepare_change},
        lifecycle::{LifecycleKind, prepare_maintenance},
        orchestrator::StepExecutor,
        plan::build_plan,
    };
    let prior = source();
    let capabilities = || {
        prior
            .targets
            .iter()
            .flat_map(veil_db_guard::adapters::capabilities_for)
            .collect()
    };
    let plan = build_plan(&prior, capabilities(), vec![], 100).unwrap();
    let applied = prepare_change(&prior, &plan, &[], None, OperationLimits::default()).unwrap();
    let revoked = prepare_maintenance(
        &applied,
        "prior-apply",
        LifecycleKind::Revoke,
        "billing-access",
        &[],
        capabilities(),
        101,
        OperationLimits::default(),
        true,
    )
    .unwrap();
    for kind in [LifecycleKind::Reconcile, LifecycleKind::Recover] {
        let maintenance = prepare_maintenance(
            &revoked,
            "completed-revoke",
            kind,
            "billing-access",
            &[],
            capabilities(),
            102,
            OperationLimits::default(),
            false,
        )
        .unwrap();
        let step = maintenance
            .plan
            .steps
            .iter()
            .find(|s| s.action == ActionKind::RevokeSqlPrivileges)
            .unwrap();
        let mut proof = context(&prior, true);
        proof.prior_change_hash = applied.change_hash.clone();
        let mut executor = PostgresStepExecutor::new(
            "operator".into(),
            PostgresEngine {
                transport: FailedRevoke {
                    context: proof,
                    sent: vec![],
                    queries: 0,
                },
            },
        );
        // Original ownership alone cannot substitute for the immediate parent
        // that this fresh Reconcile/Recover approval names.
        assert!(!executor.available(&maintenance, step));
        executor.engine.transport.context.authorization_source =
            Some(("completed-revoke".into(), "f".repeat(64)));
        assert!(!executor.available(&maintenance, step));
        executor.engine.transport.context.authorization_source =
            Some(("completed-revoke".into(), revoked.change_hash.clone()));
        assert!(executor.available(&maintenance, step));
        // Matching the immediate parent does not weaken the original ownership
        // batch/receipt binding or permit replacing its Allow ancestor policy.
        executor.engine.transport.context.prior_policy = revoked.policy.clone();
        assert!(!executor.available(&maintenance, step));
    }
}
