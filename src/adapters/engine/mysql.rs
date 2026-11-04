//! Bounded MySQL 8.0.43 account/table privileges. Account-management statements
//! implicitly commit: a batch is never a transaction and cannot be replayed
//! after a partial result, transport loss, timeout or process restart.
use crate::core::{
    capability::ActionKind,
    change::PreparedChange,
    operation::{DispatchTicket, EffectState, StepReceipt, StepRecord, StepState},
    orchestrator::{ExecutorError, StepExecutor},
    plan::PlanStep,
    policy::*,
};
use serde::{Deserialize, Serialize};

pub mod aws;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MysqlError {
    #[error("MYSQL_SCOPE: SQL intent is outside the managed surface")]
    Scope,
    #[error("MYSQL_SOURCE_GUARD_REJECTED: no statement was dispatched")]
    SourceGuardRejected,
    #[error("MYSQL_UNSUPPORTED: SQL intent is not supported by this adapter")]
    Unsupported,
    #[error("MYSQL_PRECONDITION: account or privilege precondition failed")]
    Precondition,
    #[error("MYSQL_UNAVAILABLE: database transport is unavailable")]
    Unavailable,
    #[error("MYSQL_UNKNOWN: independently committed writes require read-only reconciliation")]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MysqlAction {
    RegisterNativeDbIdentity,
    ConfigureSqlPrivileges,
    DisableNewConnections,
    RevokeSqlPrivileges,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrivilegeCheck {
    pub(super) kind: SqlObjectKind,
    pub(super) database: String,
    pub(super) object: Option<String>,
    pub(super) action: String,
}

/// Only typed policy compilation constructs SQL. No arbitrary SQL or forged
/// deserialized batch can enter the native transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SqlBatch {
    pub(super) policy_hash: String,
    pub(super) target_id: String,
    pub(super) target_hash: String,
    pub(super) database: String,
    pub(super) version: String,
    pub(super) login: String,
    pub(super) account_host: String,
    pub(super) management_account_host: String,
    pub(super) action: MysqlAction,
    pub(super) checks: Vec<PrivilegeCheck>,
    pub(super) statements: Vec<String>,
    pub(super) management_identity: Option<String>,
}
impl SqlBatch {
    pub fn statements(&self) -> &[String] {
        &self.statements
    }
    pub fn database(&self) -> &str {
        &self.database
    }
    pub fn action(&self) -> MysqlAction {
        self.action
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn hash(&self) -> String {
        crate::config::hash_bytes(&serde_json::to_vec(self).expect("typed SQL batch"))
    }
}

pub fn valid_login(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
pub fn valid_account_host(value: &str) -> bool {
    value == "%"
        || (!value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-".contains(&b)))
}
pub fn quote_account(login: &str, host: &str) -> Result<String, MysqlError> {
    if !valid_login(login) || !valid_account_host(host) {
        return Err(MysqlError::Scope);
    }
    Ok(format!("'{login}'@'{host}'"))
}
pub fn quote_identifier(value: &str) -> Result<String, MysqlError> {
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_control) {
        return Err(MysqlError::Scope);
    }
    Ok(format!("`{}`", value.replace('`', "``")))
}

pub fn compile(
    policy: &PolicyRevision,
    target_id: &str,
    grant_id: &str,
    action: MysqlAction,
) -> Result<SqlBatch, MysqlError> {
    policy.validate().map_err(|_| MysqlError::Scope)?;
    let stable = policy.normalized();
    let target = stable
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or(MysqlError::Scope)?;
    let grant = stable
        .grants
        .iter()
        .find(|g| g.id == grant_id && g.target == target_id)
        .ok_or(MysqlError::Scope)?;
    let binding = target.mysql.as_ref().ok_or(MysqlError::Unsupported)?;
    let aws = target.aws.as_ref().ok_or(MysqlError::Unsupported)?;
    let profile = stable
        .protection_profiles
        .iter()
        .find(|p| p.id == grant.profile)
        .ok_or(MysqlError::Scope)?;
    if target.engine.family != EngineFamily::MySql
        || target.engine.version != "8.0.43"
        || target.placement.kind != PlacementKind::AwsRds
        || target.placement.region != "ap-northeast-1"
        || profile.kind != ProfileKind::AwsRdsMysqlProxyV1
    {
        return Err(MysqlError::Unsupported);
    }
    if !target
        .managed_surface
        .db_identities
        .contains(&grant.db_identity)
        || grant.db_identity == aws.management_db_identity
        || !mysql_db_user(&grant.db_identity)
        || !mysql_db_user(&aws.management_db_identity)
        || !mysql_database(&target.engine.database)
        || !grant.sql_access.existing_roles.is_empty()
    {
        return Err(MysqlError::Scope);
    }
    let account = quote_account(&grant.db_identity, &binding.account_host)?;
    quote_account(
        &aws.management_db_identity,
        &binding.management_account_host,
    )?;
    quote_identifier(&target.engine.database)?;
    // MySQL cannot identify a policy owner/grantor for a table privilege. The
    // initial subset requires exclusive application-account ownership across
    // all databases on the same native instance, even under another target ID.
    if stable.grants.iter().any(|other| {
        other.id != grant.id
            && other.db_identity == grant.db_identity
            && other.admission == AdmissionIntent::Allow
            && stable.targets.iter().any(|t| {
                t.id == other.target
                    && t.placement.kind == target.placement.kind
                    && t.placement.account_id == target.placement.account_id
                    && t.resource.native_id == target.resource.native_id
            })
    }) {
        return Err(MysqlError::Scope);
    }
    let mut batch = SqlBatch {
        policy_hash: stable.revision_hash().map_err(|_| MysqlError::Scope)?,
        target_id: target.id.clone(),
        target_hash: crate::config::hash_bytes(
            &serde_json::to_vec(target).map_err(|_| MysqlError::Scope)?,
        ),
        database: target.engine.database.clone(),
        version: target.engine.version.clone(),
        login: grant.db_identity.clone(),
        account_host: binding.account_host.clone(),
        management_account_host: binding.management_account_host.clone(),
        action,
        checks: vec![],
        statements: vec![],
        management_identity: None,
    };
    match action {
        MysqlAction::RegisterNativeDbIdentity => {
            if grant.admission != AdmissionIntent::Allow
                || !target
                    .managed_surface
                    .fields
                    .contains(&ManagedField::DbLogin)
            {
                return Err(MysqlError::Scope);
            }
            // Verify preconfigured AWSAuthenticationPlugin + REQUIRE SSL and
            // unlocked account; no CREATE USER or destructive plugin migration.
        }
        MysqlAction::DisableNewConnections => {
            if grant.admission != AdmissionIntent::Deny
                || !target
                    .managed_surface
                    .fields
                    .contains(&ManagedField::DbLogin)
            {
                return Err(MysqlError::Scope);
            }
            batch
                .statements
                .push(format!("ALTER USER {account} ACCOUNT LOCK"));
        }
        MysqlAction::RevokeSqlPrivileges => return Err(MysqlError::Precondition),
        MysqlAction::ConfigureSqlPrivileges => {
            if grant.admission != AdmissionIntent::Allow {
                return Err(MysqlError::Scope);
            }
            for privilege in &grant.sql_access.privileges {
                if privilege.scope.kind != SqlObjectKind::Table {
                    return Err(MysqlError::Unsupported);
                }
                if privilege.scope.database != batch.database
                    || privilege.scope.schema.as_deref() != Some(batch.database.as_str())
                {
                    return Err(MysqlError::Scope);
                }
                let object = privilege.scope.object.as_ref().ok_or(MysqlError::Scope)?;
                let qualified = format!(
                    "{}.{}",
                    quote_identifier(&batch.database)?,
                    quote_identifier(object)?
                );
                // One independently committed statement per exact privilege:
                // receipts can preserve the acknowledged prefix without
                // describing a failed multi-statement batch as rolled back.
                for action in &privilege.actions {
                    let action = match action {
                        SqlAction::Read => "SELECT",
                        SqlAction::Insert => "INSERT",
                        SqlAction::Update => "UPDATE",
                        SqlAction::Delete => "DELETE",
                        _ => return Err(MysqlError::Unsupported),
                    };
                    batch
                        .statements
                        .push(format!("GRANT {action} ON TABLE {qualified} TO {account}"));
                    batch.checks.push(PrivilegeCheck {
                        kind: SqlObjectKind::Table,
                        database: batch.database.clone(),
                        object: Some(object.clone()),
                        action: action.into(),
                    });
                }
            }
        }
    }
    Ok(batch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MysqlOutcome {
    Applied,
    NotApplied,
    Partial,
    Unknown,
}

/// Evidence of independent statements, including partial/unknown application.
/// A complete artifact is not proof that the SQL batch was fully applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlOwnershipReceipt {
    pub(super) policy_hash: String,
    pub(super) apply_batch_hash: String,
    pub(super) management_identity: String,
    pub(super) before_privileges: Vec<PrivilegeCheck>,
    pub(super) after_privileges: Vec<PrivilegeCheck>,
    pub(super) added_privileges: Vec<PrivilegeCheck>,
    pub(super) acknowledged_statements: Vec<usize>,
    pub(super) uncertain_statement: Option<usize>,
    pub(super) outcome: MysqlOutcome,
}
impl MysqlOwnershipReceipt {
    pub fn hash(&self) -> String {
        let mut bytes = serde_json::to_vec_pretty(self).expect("typed ownership receipt");
        bytes.push(b'\n');
        crate::config::hash_bytes(&bytes)
    }
    pub fn load_verified_run(path: &std::path::Path) -> Result<Self, MysqlError> {
        let manifest = crate::store::verify_manifest(path, 2 * 1024 * 1024)
            .map_err(|_| MysqlError::Precondition)?;
        if manifest.operation != "mysql-ownership"
            || manifest.status != crate::store::RunStatus::Complete
        {
            return Err(MysqlError::Precondition);
        }
        let owned: Self =
            crate::store::read_artifact(path, &manifest, "mysql-ownership.json", 2 * 1024 * 1024)
                .map_err(|_| MysqlError::Precondition)?;
        let batch: serde_json::Value =
            crate::store::read_artifact(path, &manifest, "config.normalized.json", 2 * 1024 * 1024)
                .map_err(|_| MysqlError::Precondition)?;
        if batch.get("target_id").and_then(|v| v.as_str()) != Some(manifest.target_id.as_str())
            || manifest.config_hash != owned.apply_batch_hash
            || batch.get("policy_hash").and_then(|v| v.as_str()) != Some(owned.policy_hash.as_str())
            || !manifest
                .artifacts
                .iter()
                .any(|a| a.name == "mysql-ownership.json" && a.sha256 == owned.hash())
        {
            return Err(MysqlError::Precondition);
        }
        Ok(owned)
    }
}

#[derive(Debug, Clone)]
pub struct MysqlLifecycleContext {
    pub prior_policy: PolicyRevision,
    pub prior_operation_id: String,
    pub prior_change_hash: String,
    pub authorization_source: Option<(String, String)>,
    pub prior_sql_step: StepRecord,
    pub ownership: Option<MysqlOwnershipReceipt>,
}

/// Revoke only the previously absent direct table privileges introduced by a
/// fully evidenced successful operation. MySQL has no GRANTED BY ownership;
/// native execution must additionally verify the exclusive mutation window.
pub fn compile_owned_revoke(
    policy: &PolicyRevision,
    previous: &PolicyRevision,
    target_id: &str,
    grant_id: &str,
    context: &MysqlLifecycleContext,
) -> Result<SqlBatch, MysqlError> {
    let owned = context.ownership.as_ref().ok_or(MysqlError::Unsupported)?;
    policy.validate().map_err(|_| MysqlError::Scope)?;
    previous.validate().map_err(|_| MysqlError::Scope)?;
    let policy = policy.normalized();
    let previous = previous.normalized();
    let current = policy
        .grants
        .iter()
        .find(|g| g.id == grant_id && g.target == target_id)
        .ok_or(MysqlError::Scope)?;
    let prior = previous
        .grants
        .iter()
        .find(|g| g.id == grant_id && g.target == target_id)
        .ok_or(MysqlError::Scope)?;
    let target = policy
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or(MysqlError::Scope)?;
    if policy.policy_id != previous.policy_id
        || previous.revision.checked_add(1) != Some(policy.revision)
        || policy.parent_revision_hash.as_ref()
            != Some(&previous.revision_hash().map_err(|_| MysqlError::Scope)?)
        || current.admission != AdmissionIntent::Deny
        || prior.admission != AdmissionIntent::Allow
        || current.sql_access != SqlAccessIntent::default()
        || current.subject != prior.subject
        || current.db_identity != prior.db_identity
        || context.prior_policy.normalized() != previous
        || context.prior_operation_id.is_empty()
        || !valid_hash(&context.prior_change_hash)
        || previous.targets.iter().find(|t| t.id == target_id) != Some(target)
    {
        return Err(MysqlError::Precondition);
    }
    let mut batch = compile(
        &previous,
        target_id,
        grant_id,
        MysqlAction::ConfigureSqlPrivileges,
    )?;
    let proof = context
        .prior_sql_step
        .receipt
        .as_ref()
        .ok_or(MysqlError::Precondition)?;
    let source_plan = crate::core::plan::build_plan(&previous, vec![], vec![], 0)
        .map_err(|_| MysqlError::Precondition)?;
    let management = quote_account(
        &target
            .aws
            .as_ref()
            .ok_or(MysqlError::Scope)?
            .management_db_identity,
        &batch.management_account_host,
    )?;
    let delta: Vec<_> = owned
        .after_privileges
        .iter()
        .filter(|p| !owned.before_privileges.contains(p))
        .cloned()
        .collect();
    if !source_plan.steps.iter().any(|s| {
        s.id == context.prior_sql_step.step_id
            && s.target_id == target_id
            && s.grant_id == grant_id
            && s.action == ActionKind::ConfigureSqlPrivileges
    }) || context.prior_sql_step.state != StepState::EffectSatisfied
        || context.prior_sql_step.attempt == 0
        || proof.state != StepState::EffectSatisfied
        || proof.effect != EffectState::Enforced
        || !proof.evidence_refs.contains(&batch.hash())
        || !proof.evidence_refs.contains(&owned.hash())
        || owned.apply_batch_hash != batch.hash()
        || owned.policy_hash != batch.policy_hash
        || owned.management_identity != management
        || owned.outcome != MysqlOutcome::Applied
        || owned.uncertain_statement.is_some()
        || owned.acknowledged_statements != (0..batch.statements.len()).collect::<Vec<_>>()
        || owned.added_privileges != delta
        || owned.after_privileges != batch.checks
        || owned
            .before_privileges
            .iter()
            .any(|p| !batch.checks.contains(p))
    {
        return Err(MysqlError::Precondition);
    }
    batch.checks = owned.added_privileges.clone();
    batch.action = MysqlAction::RevokeSqlPrivileges;
    batch.policy_hash = policy.revision_hash().map_err(|_| MysqlError::Scope)?;
    batch.management_identity = Some(management);
    let account = quote_account(&batch.login, &batch.account_host)?;
    batch.statements = batch
        .checks
        .iter()
        .map(|p| {
            Ok(format!(
                "REVOKE {} ON TABLE {}.{} FROM {account}",
                p.action,
                quote_identifier(&p.database)?,
                quote_identifier(p.object.as_deref().ok_or(MysqlError::Scope)?)?
            ))
        })
        .collect::<Result<_, MysqlError>>()?;
    Ok(batch)
}

/// Trusted transport: `execute` is sequential and non-atomic. `query` may only
/// observe; absence after unknown submission never authorizes another write.
pub type BeforeMysqlWrite<'a> = dyn FnMut() -> Result<(), MysqlError> + Send + 'a;
pub trait MysqlTransport {
    fn supports_source_guard(&self) -> bool {
        false
    }
    /// Must check after slow reads, before each independently committed SQL
    /// statement. SourceGuardRejected / NotApplied may be returned ONLY before
    /// any statement is sent. After any prior statement dispatch, a later guard
    /// rejection MUST remain Unknown; implicit COMMIT cannot be rolled back.
    fn execute_guarded(
        &mut self,
        _: &SqlBatch,
        _: &mut BeforeMysqlWrite<'_>,
    ) -> Result<MysqlOutcome, MysqlError> {
        Err(MysqlError::Unsupported)
    }
    fn lifecycle_context(&self) -> Option<&MysqlLifecycleContext> {
        None
    }
    fn owned_receipt(&self) -> Option<MysqlOwnershipReceipt> {
        None
    }
    fn evidence_refs(&self) -> Vec<String> {
        vec![]
    }
    fn preflight(&mut self, batch: &SqlBatch) -> Result<(), MysqlError>;
    fn execute(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError>;
    fn query(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError>;
}
pub struct MysqlEngine<T> {
    pub transport: T,
}
impl<T: MysqlTransport> MysqlEngine<T> {
    pub fn submit(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
        self.transport.execute(batch)
    }
    pub fn query(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
        self.transport.query(batch)
    }
}
pub struct MysqlStepExecutor<T> {
    pub execution_identity: String,
    pub engine: MysqlEngine<T>,
    source_contract_scope: bool,
}
impl<T: MysqlTransport> MysqlStepExecutor<T> {
    pub fn new(execution_identity: String, engine: MysqlEngine<T>) -> Self {
        Self {
            execution_identity,
            engine,
            source_contract_scope: false,
        }
    }
    pub(crate) fn with_source_contract<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        self.source_contract_scope = true;
        let result = f(self);
        self.source_contract_scope = false;
        result
    }
    pub(crate) fn source_available(&self, change: &PreparedChange, step: &PlanStep) -> bool {
        self.engine.transport.supports_source_guard()
            && self.batch_with_scope(change, step, true).is_ok()
    }
    pub(crate) fn submit_source(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
        checkpoints: &crate::binding::ManualCheckpoints,
    ) -> Result<StepReceipt, ExecutorError> {
        self.with_source_contract(|this| {
            let batch = this.batch(change, step)?;
            let mut guard = || {
                gate.validate_sources(change)
                    .map_err(|_| MysqlError::SourceGuardRejected)?;
                if matches!(
                    step.action,
                    ActionKind::DisableNewConnections | ActionKind::RevokeSqlPrivileges
                ) {
                    let check = gate
                        .check(
                            change,
                            step,
                            crate::core::source_execution::SourceStepPhase::BeforeDispatch,
                        )
                        .map_err(|_| MysqlError::SourceGuardRejected)?;
                    if !check.satisfied() {
                        return Err(MysqlError::SourceGuardRejected);
                    }
                }
                use crate::binding::CheckpointGate;
                checkpoints
                    .validate_change_window(change, &step.target_id, gate.now())
                    .map_err(|_| MysqlError::SourceGuardRejected)?;
                Ok(())
            };
            let outcome = this
                .engine
                .transport
                .execute_guarded(&batch, &mut guard)
                .map_err(map_error)?;
            Ok(this.receipt(&batch, outcome))
        })
    }
    fn batch(&self, change: &PreparedChange, step: &PlanStep) -> Result<SqlBatch, ExecutorError> {
        self.batch_with_scope(change, step, self.source_contract_scope)
    }
    fn batch_with_scope(
        &self,
        change: &PreparedChange,
        step: &PlanStep,
        scope: bool,
    ) -> Result<SqlBatch, ExecutorError> {
        change
            .verify()
            .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        if !change.plan.steps.contains(step)
            || !crate::core::source_execution::execution_contract_matches(
                change,
                step,
                "core-adapter-v3",
            )
            || (change.policy.schema_version == 2 && !scope)
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let action = match step.action {
            ActionKind::RegisterNativeDbIdentity => MysqlAction::RegisterNativeDbIdentity,
            ActionKind::ConfigureSqlPrivileges => MysqlAction::ConfigureSqlPrivileges,
            ActionKind::DisableNewConnections => MysqlAction::DisableNewConnections,
            ActionKind::RevokeSqlPrivileges => MysqlAction::RevokeSqlPrivileges,
            _ => return Err(ExecutorError::Unavailable),
        };
        if action == MysqlAction::RevokeSqlPrivileges {
            let ctx = self
                .engine
                .transport
                .lifecycle_context()
                .ok_or(ExecutorError::Unavailable)?;
            let bound = change
                .lifecycle
                .as_ref()
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            let (operation, hash) = ctx
                .authorization_source
                .as_ref()
                .map(|(o, h)| (o, h))
                .unwrap_or((&ctx.prior_operation_id, &ctx.prior_change_hash));
            if &bound.source_operation_id != operation || &bound.source_change_hash != hash {
                return Err(ExecutorError::PreconditionsNotMet);
            }
            compile_owned_revoke(
                &change.policy,
                change
                    .previous_policy
                    .as_ref()
                    .ok_or(ExecutorError::PreconditionsNotMet)?,
                &step.target_id,
                &step.grant_id,
                ctx,
            )
            .map_err(map_error)
        } else {
            compile(&change.policy, &step.target_id, &step.grant_id, action).map_err(map_error)
        }
    }
    fn receipt(&self, batch: &SqlBatch, outcome: MysqlOutcome) -> StepReceipt {
        let mut evidence_refs = vec![batch.hash()];
        evidence_refs.extend(self.engine.transport.evidence_refs());
        if let Some(owned) = self.engine.transport.owned_receipt()
            && owned.apply_batch_hash == batch.hash()
        {
            evidence_refs.push(owned.hash());
        }
        evidence_refs.sort();
        evidence_refs.dedup();
        StepReceipt {
            state: match outcome {
                MysqlOutcome::Applied if batch.action == MysqlAction::RegisterNativeDbIdentity => {
                    StepState::NoOpSatisfied
                }
                MysqlOutcome::Applied => StepState::EffectSatisfied,
                MysqlOutcome::NotApplied => StepState::NotApplied,
                MysqlOutcome::Partial | MysqlOutcome::Unknown => StepState::OutcomeUnknown,
            },
            effect: match outcome {
                MysqlOutcome::Applied => EffectState::Enforced,
                MysqlOutcome::NotApplied => EffectState::NotSatisfied,
                MysqlOutcome::Partial | MysqlOutcome::Unknown => EffectState::Unknown,
            },
            native_operation_ref: None,
            evidence_refs,
        }
    }
}
fn map_error(error: MysqlError) -> ExecutorError {
    match error {
        MysqlError::Unknown => ExecutorError::OutcomeUnknown,
        MysqlError::SourceGuardRejected => ExecutorError::NotApplied,
        MysqlError::Unavailable | MysqlError::Unsupported => ExecutorError::Unavailable,
        _ => ExecutorError::PreconditionsNotMet,
    }
}
impl<T: MysqlTransport> StepExecutor for MysqlStepExecutor<T> {
    fn identity(&self) -> &str {
        &self.execution_identity
    }
    fn available(&self, change: &PreparedChange, step: &PlanStep) -> bool {
        self.batch(change, step).is_ok()
    }
    fn preflight(&mut self, change: &PreparedChange, step: &PlanStep) -> Result<(), ExecutorError> {
        self.engine
            .transport
            .preflight(&self.batch(change, step)?)
            .map_err(map_error)
    }
    fn submit(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        _: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        let batch = self.batch(change, step)?;
        let outcome = self.engine.submit(&batch).map_err(map_error)?;
        Ok(self.receipt(&batch, outcome))
    }
    fn query(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        _: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        let batch = self.batch(change, step)?;
        let outcome = self.engine.query(&batch).map_err(map_error)?;
        // A complete desired readback can resolve the effect. An absent or
        // partially present grant never proves previously submitted SQL absent.
        Ok(self.receipt(
            &batch,
            if outcome == MysqlOutcome::Applied {
                outcome
            } else {
                MysqlOutcome::Unknown
            },
        ))
    }
}
