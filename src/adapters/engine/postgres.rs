//! Bounded PostgreSQL 16 grants. No password/login creation, GRANT ALL,
//! ownership changes, default privileges, session termination or automatic restoration.
use crate::core::{
    capability::ActionKind,
    change::PreparedChange,
    operation::{DispatchTicket, EffectState, StepReceipt, StepRecord, StepState},
    orchestrator::{ExecutorError, StepExecutor},
    plan::PlanStep,
    policy::*,
};
use serde::{Deserialize, Serialize};
use std::{sync::Mutex, time::Duration};
pub mod aws;
pub mod connector;
pub use connector::ConnectorPgTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PgError {
    #[error("POSTGRES_SCOPE: SQL intent is outside the managed surface")]
    Scope,
    #[error("POSTGRES_UNSUPPORTED: SQL intent is not supported by this adapter")]
    Unsupported,
    #[error("POSTGRES_PRECONDITION: database identity or role precondition failed")]
    Precondition,
    #[error("POSTGRES_UNAVAILABLE: database transport is unavailable")]
    Unavailable,
    #[error("POSTGRES_UNKNOWN: transaction outcome requires read-only reconciliation")]
    Unknown,
    #[error("POSTGRES_SOURCE_GUARD: current source evidence rejected before COMMIT")]
    SourceGuardRejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PgAction {
    RegisterNativeDbIdentity,
    ConfigureSqlPrivileges,
    DisableNewConnections,
    RevokeSqlPrivileges,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrivilegeCheck {
    kind: SqlObjectKind,
    object: String,
    action: String,
}

/// Only `compile` constructs this value. Consumers can inspect generated SQL,
/// but cannot supply SQL or deserialise a forged batch into the native driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SqlBatch {
    policy_hash: String,
    target_id: String,
    target_hash: String,
    database: String,
    version: String,
    login: String,
    action: PgAction,
    roles: Vec<String>,
    checks: Vec<PrivilegeCheck>,
    statements: Vec<String>,
    management_role: Option<String>,
}
impl SqlBatch {
    pub fn statements(&self) -> &[String] {
        &self.statements
    }
    pub fn hash(&self) -> String {
        crate::config::hash_bytes(&serde_json::to_vec(self).expect("serializable typed SQL"))
    }
    pub fn database(&self) -> &str {
        &self.database
    }
}

/// PostgreSQL's default identifier limit is 63 bytes; refuse truncation and
/// special PUBLIC semantics instead of silently applying to a different role.
pub fn quote_identifier(value: &str) -> Result<String, PgError> {
    if value.is_empty() || value.len() > 63 || value.chars().any(char::is_control) {
        return Err(PgError::Scope);
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}

pub fn compile(
    policy: &PolicyRevision,
    target_id: &str,
    grant_id: &str,
    action: PgAction,
) -> Result<SqlBatch, PgError> {
    policy.validate().map_err(|_| PgError::Scope)?;
    let stable = policy.normalized();
    let target = stable
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or(PgError::Scope)?;
    let grant = stable
        .grants
        .iter()
        .find(|g| g.id == grant_id && g.target == target_id)
        .ok_or(PgError::Scope)?;
    if target.engine.family != EngineFamily::PostgreSql || !target.engine.version.starts_with("16.")
    {
        return Err(PgError::Unsupported);
    }
    if !target
        .managed_surface
        .db_identities
        .contains(&grant.db_identity)
        || grant.db_identity.eq_ignore_ascii_case("public")
    {
        return Err(PgError::Scope);
    }
    let login = quote_identifier(&grant.db_identity)?;
    quote_identifier(&target.engine.database)?;
    let mut batch = SqlBatch {
        policy_hash: stable.revision_hash().map_err(|_| PgError::Scope)?,
        target_id: target.id.clone(),
        target_hash: crate::config::hash_bytes(
            &serde_json::to_vec(target).map_err(|_| PgError::Scope)?,
        ),
        database: target.engine.database.clone(),
        version: target.engine.version.clone(),
        login: grant.db_identity.clone(),
        action,
        roles: vec![],
        checks: vec![],
        statements: vec![],
        management_role: None,
    };
    match action {
        PgAction::RegisterNativeDbIdentity => {
            if target.placement.kind != PlacementKind::AwsRds
                || target.aws.is_none()
                || grant.admission != AdmissionIntent::Allow
                || !target
                    .managed_surface
                    .fields
                    .contains(&ManagedField::DbLogin)
            {
                return Err(PgError::Scope);
            }
            if stable.grants.iter().any(|other| {
                other.id != grant.id
                    && other.admission == AdmissionIntent::Allow
                    && other.db_identity == grant.db_identity
                    && stable.targets.iter().any(|t| {
                        t.id == other.target
                            && t.placement.kind == target.placement.kind
                            && t.placement.account_id == target.placement.account_id
                            && t.resource.native_id == target.resource.native_id
                    })
            }) {
                return Err(PgError::Scope);
            }
            batch.roles.push("rds_iam".into());
            batch.statements.push(format!(
                "GRANT \"rds_iam\" TO {login} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
            ));
        }
        // Revocation must use compile_owned_revoke and its prior apply proof.
        PgAction::RevokeSqlPrivileges => return Err(PgError::Precondition),
        PgAction::DisableNewConnections => {
            if grant.admission != AdmissionIntent::Deny
                || !target
                    .managed_surface
                    .fields
                    .contains(&ManagedField::DbLogin)
            {
                return Err(PgError::Scope);
            }
            // PostgreSQL login attributes belong to the cluster-wide role,
            // not this database. Refuse collateral denial of another Allow
            // grant, including another logical database on the same instance.
            // Region labels do not narrow a native instance's role namespace.
            if stable.grants.iter().any(|other| {
                other.id != grant.id
                    && other.admission == AdmissionIntent::Allow
                    && other.db_identity == grant.db_identity
                    && stable.targets.iter().any(|other_target| {
                        other_target.id == other.target
                            && other_target.placement.kind == target.placement.kind
                            && other_target.placement.account_id == target.placement.account_id
                            && other_target.resource.native_id == target.resource.native_id
                    })
            }) {
                return Err(PgError::Scope);
            }
            batch.statements.push(format!("ALTER ROLE {login} NOLOGIN"));
        }
        PgAction::ConfigureSqlPrivileges => {
            if grant.admission != AdmissionIntent::Allow {
                return Err(PgError::Scope);
            }
            for role in &grant.sql_access.existing_roles {
                if role.eq_ignore_ascii_case("public") || role == &grant.db_identity {
                    return Err(PgError::Scope);
                }
                batch.statements.push(format!(
                    "GRANT {} TO {login} WITH ADMIN FALSE, INHERIT TRUE, SET FALSE",
                    quote_identifier(role)?
                ));
                batch.roles.push(role.clone());
            }
            for privilege in &grant.sql_access.privileges {
                if privilege.scope.database != target.engine.database {
                    return Err(PgError::Scope);
                }
                let (kind, object) = match privilege.scope.kind {
                    SqlObjectKind::Database => {
                        ("DATABASE", quote_identifier(&privilege.scope.database)?)
                    }
                    SqlObjectKind::Schema => (
                        "SCHEMA",
                        quote_identifier(privilege.scope.schema.as_deref().ok_or(PgError::Scope)?)?,
                    ),
                    SqlObjectKind::Table => (
                        "TABLE",
                        format!(
                            "{}.{}",
                            quote_identifier(
                                privilege.scope.schema.as_deref().ok_or(PgError::Scope)?
                            )?,
                            quote_identifier(
                                privilege.scope.object.as_deref().ok_or(PgError::Scope)?
                            )?
                        ),
                    ),
                    // The current policy has no routine signature. Never guess
                    // an overload or broaden to ALL FUNCTIONS IN SCHEMA.
                    SqlObjectKind::Routine => return Err(PgError::Unsupported),
                };
                let actions: Vec<_> = privilege
                    .actions
                    .iter()
                    .map(|a| match a {
                        SqlAction::Read => "SELECT",
                        SqlAction::Insert => "INSERT",
                        SqlAction::Update => "UPDATE",
                        SqlAction::Delete => "DELETE",
                        SqlAction::Usage => "USAGE",
                        SqlAction::Connect => "CONNECT",
                        SqlAction::Execute => "EXECUTE",
                    })
                    .collect();
                batch.statements.push(format!(
                    "GRANT {} ON {kind} {object} TO {login}",
                    actions.join(", ")
                ));
                for action in actions {
                    batch.checks.push(PrivilegeCheck {
                        kind: privilege.scope.kind,
                        object: match privilege.scope.kind {
                            SqlObjectKind::Database => privilege.scope.database.clone(),
                            SqlObjectKind::Schema => {
                                privilege.scope.schema.clone().ok_or(PgError::Scope)?
                            }
                            _ => object.clone(),
                        },
                        action: action.into(),
                    });
                }
            }
        }
    }
    Ok(batch)
}

/// Exact direct grants newly introduced by one successful native transaction.
/// A caller-supplied object is not authority: its digest must match the trusted
/// successful prior step receipt before it can authorize removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PgOwnershipReceipt {
    policy_hash: String,
    apply_batch_hash: String,
    management_role: String,
    before_roles: Vec<String>,
    before_privileges: Vec<PrivilegeCheck>,
    after_roles: Vec<String>,
    after_privileges: Vec<PrivilegeCheck>,
    added_roles: Vec<String>,
    added_privileges: Vec<PrivilegeCheck>,
}
impl PgOwnershipReceipt {
    pub fn load_verified_run(path: &std::path::Path) -> Result<Self, PgError> {
        let manifest = crate::store::verify_manifest(path, 2 * 1024 * 1024)
            .map_err(|_| PgError::Precondition)?;
        if manifest.operation != "postgres-ownership"
            || manifest.status != crate::store::RunStatus::Complete
        {
            return Err(PgError::Precondition);
        }
        let owned: Self = crate::store::read_artifact(
            path,
            &manifest,
            "postgres-ownership.json",
            2 * 1024 * 1024,
        )
        .map_err(|_| PgError::Precondition)?;
        let batch: serde_json::Value =
            crate::store::read_artifact(path, &manifest, "config.normalized.json", 2 * 1024 * 1024)
                .map_err(|_| PgError::Precondition)?;
        if batch.get("target_id").and_then(|v| v.as_str()) != Some(manifest.target_id.as_str())
            || manifest.config_hash != owned.apply_batch_hash
            || batch.get("policy_hash").and_then(|v| v.as_str()) != Some(owned.policy_hash.as_str())
            || !manifest
                .artifacts
                .iter()
                .any(|a| a.name == "postgres-ownership.json" && a.sha256 == owned.hash())
        {
            return Err(PgError::Precondition);
        }
        Ok(owned)
    }
    pub fn hash(&self) -> String {
        let mut bytes = serde_json::to_vec_pretty(self).expect("typed ownership receipt");
        bytes.push(b'\n');
        crate::config::hash_bytes(&bytes)
    }
}

/// The composing adapter loads this from a verified, approved source operation.
/// This context never authorizes widening the new approved change's scope.
#[derive(Debug, Clone)]
pub struct PgLifecycleContext {
    pub prior_policy: PolicyRevision,
    pub prior_operation_id: String,
    pub prior_change_hash: String,
    /// Immediate lifecycle parent authorized by the fresh maintenance approval.
    /// The composing adapter separately verifies its relationship to the true
    /// ownership ancestor identified by prior_operation_id/prior_change_hash.
    pub authorization_source: Option<(String, String)>,
    pub prior_sql_step: StepRecord,
    pub ownership: Option<PgOwnershipReceipt>,
}

/// Compile removal of only the identical, formerly applied SQL intent. This is
/// not an inverse snapshot: foreign grantors, PUBLIC and inherited rights remain.
pub fn compile_owned_revoke(
    policy: &PolicyRevision,
    previous: &PolicyRevision,
    target_id: &str,
    grant_id: &str,
    context: &PgLifecycleContext,
) -> Result<SqlBatch, PgError> {
    let ownership = context.ownership.as_ref().ok_or(PgError::Unsupported)?;
    policy.validate().map_err(|_| PgError::Scope)?;
    previous.validate().map_err(|_| PgError::Scope)?;
    let policy = policy.normalized();
    let previous = previous.normalized();
    let current = policy
        .grants
        .iter()
        .find(|g| g.id == grant_id && g.target == target_id)
        .ok_or(PgError::Scope)?;
    let prior = previous
        .grants
        .iter()
        .find(|g| g.id == grant_id && g.target == target_id)
        .ok_or(PgError::Scope)?;
    if policy.policy_id != previous.policy_id
        || previous.revision.checked_add(1) != Some(policy.revision)
        || policy.parent_revision_hash.as_ref()
            != Some(&previous.revision_hash().map_err(|_| PgError::Scope)?)
        || current.admission != AdmissionIntent::Deny
        || prior.admission != AdmissionIntent::Allow
        || current.sql_access != SqlAccessIntent::default()
        || current.subject != prior.subject
        || current.db_identity != prior.db_identity
        || ownership.policy_hash != previous.revision_hash().map_err(|_| PgError::Scope)?
        || context.prior_policy.normalized() != previous
        || context.prior_operation_id.is_empty()
        || !valid_hash(&context.prior_change_hash)
    {
        return Err(PgError::Precondition);
    }
    let old_target = previous
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or(PgError::Scope)?;
    let target = policy
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or(PgError::Scope)?;
    if old_target != target {
        return Err(PgError::Precondition);
    }
    let mut batch = compile(
        &previous,
        target_id,
        grant_id,
        PgAction::ConfigureSqlPrivileges,
    )?;
    let source_plan = crate::core::plan::build_plan(&previous, vec![], vec![], 0)
        .map_err(|_| PgError::Precondition)?;
    if !source_plan.steps.iter().any(|step| {
        step.id == context.prior_sql_step.step_id
            && step.target_id == target_id
            && step.grant_id == grant_id
            && step.action == ActionKind::ConfigureSqlPrivileges
    }) {
        return Err(PgError::Precondition);
    }
    let proof = context
        .prior_sql_step
        .receipt
        .as_ref()
        .ok_or(PgError::Precondition)?;
    if batch.hash() != ownership.apply_batch_hash
        || context.prior_sql_step.state != StepState::EffectSatisfied
        || context.prior_sql_step.attempt == 0
        || proof.state != StepState::EffectSatisfied
        || proof.effect != EffectState::Enforced
        || !proof.evidence_refs.contains(&batch.hash())
        || !proof.evidence_refs.contains(&ownership.hash())
        || ownership.added_roles
            != ownership
                .after_roles
                .iter()
                .filter(|r| !ownership.before_roles.contains(r))
                .cloned()
                .collect::<Vec<_>>()
        || ownership.added_privileges
            != ownership
                .after_privileges
                .iter()
                .filter(|p| !ownership.before_privileges.contains(p))
                .cloned()
                .collect::<Vec<_>>()
        || ownership
            .before_roles
            .iter()
            .chain(&ownership.after_roles)
            .any(|r| !batch.roles.contains(r))
        || ownership
            .before_privileges
            .iter()
            .chain(&ownership.after_privileges)
            .any(|p| !batch.checks.contains(p))
        || ownership
            .added_roles
            .iter()
            .any(|role| !batch.roles.contains(role))
        || ownership
            .added_privileges
            .iter()
            .any(|check| !batch.checks.contains(check))
    {
        return Err(PgError::Precondition);
    }
    // Another grant for the same DB principal can share the exact ACL entry.
    // PostgreSQL records a grantor/grantee pair, not the policy grant ID.
    for other_policy in [&previous, &policy] {
        for other in other_policy.grants.iter().filter(|g| {
            g.id != grant_id
                && g.target == target_id
                && g.db_identity == prior.db_identity
                && g.admission == AdmissionIntent::Allow
        }) {
            let other_batch = compile(
                other_policy,
                target_id,
                &other.id,
                PgAction::ConfigureSqlPrivileges,
            )?;
            if ownership
                .added_roles
                .iter()
                .any(|r| other_batch.roles.contains(r))
                || ownership
                    .added_privileges
                    .iter()
                    .any(|p| other_batch.checks.contains(p))
            {
                return Err(PgError::Precondition);
            }
        }
    }
    // Only delta entries can be removed, never pre-existing identical grants.
    batch.roles = ownership.added_roles.clone();
    batch.checks = ownership.added_privileges.clone();
    batch.policy_hash = policy.revision_hash().map_err(|_| PgError::Scope)?;
    batch.action = PgAction::RevokeSqlPrivileges;
    batch.management_role = Some(ownership.management_role.clone());
    let login = quote_identifier(&batch.login)?;
    if ownership.management_role.eq_ignore_ascii_case("public")
        || ownership.management_role == batch.login
    {
        return Err(PgError::Precondition);
    }
    let grantor = quote_identifier(&ownership.management_role)?;
    if batch.roles.is_empty() && batch.checks.is_empty() {
        return Err(PgError::Unsupported);
    }
    batch.statements = vec![];
    for role in &batch.roles {
        batch.statements.push(format!(
            "REVOKE {} FROM {login} GRANTED BY {grantor} RESTRICT",
            quote_identifier(role)?
        ));
    }
    for check in &batch.checks {
        let (kind, object) = match check.kind {
            SqlObjectKind::Database => ("DATABASE", quote_identifier(&check.object)?),
            SqlObjectKind::Schema => ("SCHEMA", quote_identifier(&check.object)?),
            // The table object was produced by compile with both identifiers quoted.
            SqlObjectKind::Table => ("TABLE", check.object.clone()),
            SqlObjectKind::Routine => return Err(PgError::Unsupported),
        };
        batch.statements.push(format!(
            "REVOKE {} ON {kind} {object} FROM {login} GRANTED BY {grantor} RESTRICT",
            check.action
        ));
    }
    Ok(batch)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgOutcome {
    Applied,
    NotApplied,
    Unknown,
}

/// Trusted, injected transport. `query` must remain read-only: neither a lost
/// commit acknowledgement nor a process restart authorizes resending SQL.
pub type BeforeSqlWrite<'a> = dyn FnMut() -> Result<(), PgError> + Send + 'a;
pub trait PgTransport {
    fn supports_source_guard(&self) -> bool {
        false
    }
    fn lifecycle_context(&self) -> Option<&PgLifecycleContext> {
        None
    }
    fn owned_receipt(&self) -> Option<PgOwnershipReceipt> {
        None
    }
    fn preflight(&mut self, batch: &SqlBatch) -> Result<(), PgError>;
    fn execute_atomic(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError>;
    /// V3 requires a transport that rechecks AFTER slow connection/catalog
    /// reads, before each write and COMMIT. Legacy transports fail closed.
    fn execute_atomic_guarded(
        &mut self,
        _: &SqlBatch,
        _: &mut BeforeSqlWrite<'_>,
    ) -> Result<PgOutcome, PgError> {
        Err(PgError::Unsupported)
    }
    fn query(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError>;
}
pub struct PostgresEngine<T> {
    pub transport: T,
}
impl<T: PgTransport> PostgresEngine<T> {
    pub fn submit(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.transport.execute_atomic(batch)
    }
    pub fn query(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.transport.query(batch)
    }
}

/// Native backend over an explicitly supplied, TLS-verified management
/// connection. Credentials stay in memory and are never Debug/Serialize output.
/// Each bounded request owns a worker thread/runtime, so synchronous CLI calls
/// are safe both inside and outside an existing Tokio runtime.
pub struct TokioPgTransport {
    config: tokio_postgres::Config,
    tls: rustls::ClientConfig,
    timeout: Duration,
    target_hash: String,
    lifecycle: Option<PgLifecycleContext>,
    ownership: Mutex<Option<PgOwnershipReceipt>>,
}
impl TokioPgTransport {
    /// `target` is the configuration binding, not remote identity evidence.
    /// The composing deployment adapter must independently establish that the
    /// management connector/TLS endpoint reaches this exact native target.
    /// Do not expose this expert constructor as an arbitrary-DSN CLI option.
    pub fn for_target(
        config: tokio_postgres::Config,
        tls: rustls::ClientConfig,
        timeout: Duration,
        target: &Target,
    ) -> Result<Self, PgError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(120)
            || config.get_dbname() != Some(target.engine.database.as_str())
            || target.resource.generation_fingerprint.is_none()
        {
            return Err(PgError::Precondition);
        }
        let target_hash =
            crate::config::hash_bytes(&serde_json::to_vec(target).map_err(|_| PgError::Scope)?);
        Ok(Self {
            config,
            tls,
            timeout,
            target_hash,
            lifecycle: None,
            ownership: Mutex::new(None),
        })
    }
    pub fn with_lifecycle_context(mut self, context: PgLifecycleContext) -> Self {
        self.lifecycle = Some(context);
        self
    }
    fn run(
        &self,
        batch: &SqlBatch,
        mode: u8,
        mut guard: Option<&mut BeforeSqlWrite<'_>>,
    ) -> Result<PgOutcome, PgError> {
        if self.config.get_dbname() != Some(batch.database.as_str())
            || self.target_hash != batch.target_hash
        {
            return Err(PgError::Precondition);
        }
        std::thread::scope(|scope| {
            scope.spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| PgError::Unavailable)?;
            runtime.block_on(async {
                let work = async {
                    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(self.tls.clone());
                    let (mut client, connection) = self.config.connect(tls).await.map_err(|_| PgError::Unavailable)?;
                    let handle = tokio::spawn(async move { let _ = connection.await; });
                    let result = async {
                        let transaction = client.transaction().await.map_err(|_| PgError::Unavailable)?;
                        transaction.batch_execute("SET LOCAL search_path = pg_catalog; SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '30s'").await.map_err(|_| PgError::Precondition)?;
                        if mode != 1 { transaction.batch_execute("SET TRANSACTION READ ONLY").await.map_err(|_| PgError::Precondition)?; }
                        verify_identity(&transaction, batch).await?;
                        verify_revoke_preconditions(&transaction, batch).await?;
                        if mode == 0 { return Ok(PgOutcome::NotApplied); }
                        if mode == 1 { *self.ownership.lock().map_err(|_| PgError::Unavailable)? = None; }
                        let before = if mode == 1 && matches!(batch.action,PgAction::ConfigureSqlPrivileges|PgAction::RegisterNativeDbIdentity) { Some(capture_ownership(&transaction, batch).await?) } else { None };
                        if mode == 1 {
                            for sql in &batch.statements {
                                if let Some(g)=guard.as_mut() {g()?;}
                                transaction.batch_execute(sql).await.map_err(|_| PgError::Precondition)?;
                            }
                        }
                        let applied = readback(&transaction, batch).await?;
                        if mode == 1 && !applied {
                            // Never COMMIT a batch whose complete desired
                            // readback was not satisfied.
                            transaction.rollback().await.map_err(|_| PgError::Unknown)?;
                            return Ok(PgOutcome::NotApplied);
                        }
                        let owned = if let Some(before) = before { Some(ownership_delta(&before, capture_ownership(&transaction, batch).await?)) } else { None };
                        if mode == 1 {
                            // Everything before COMMIT is transactional; any
                            // error/timeout at COMMIT remains unknown.
                            if let Some(g)=guard.as_mut() {g()?;}
                            transaction.commit().await.map_err(|_| PgError::Unknown)?;
                            *self.ownership.lock().map_err(|_| PgError::Unknown)? = owned;
                        }
                        Ok(if applied { PgOutcome::Applied } else { PgOutcome::NotApplied })
                    }.await;
                    handle.abort();
                    result
                };
                tokio::time::timeout(self.timeout, work).await.map_err(|_| PgError::Unknown)?
            })
        }).join().map_err(|_| PgError::Unknown)?
        })
    }
}
impl PgTransport for TokioPgTransport {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn lifecycle_context(&self) -> Option<&PgLifecycleContext> {
        self.lifecycle.as_ref()
    }
    fn owned_receipt(&self) -> Option<PgOwnershipReceipt> {
        self.ownership.lock().ok()?.clone()
    }

    fn preflight(&mut self, batch: &SqlBatch) -> Result<(), PgError> {
        self.run(batch, 0, None).map(|_| ())
    }
    fn execute_atomic(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.run(batch, 1, None)
    }
    fn execute_atomic_guarded(
        &mut self,
        batch: &SqlBatch,
        guard: &mut BeforeSqlWrite<'_>,
    ) -> Result<PgOutcome, PgError> {
        self.run(batch, 1, Some(guard))
    }
    fn query(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.run(batch, 2, None)
    }
}
/// Direct ACL membership, scoped to the transaction's authenticated grantor.
/// Effective rights inherited from PUBLIC/other grantors are never ownership.
async fn direct_privilege(
    tx: &tokio_postgres::Transaction<'_>,
    batch: &SqlBatch,
    check: &PrivilegeCheck,
) -> Result<bool, PgError> {
    let catalog = match check.kind {
        SqlObjectKind::Database => {
            "SELECT d.datacl AS acl, d.datdba AS owner FROM pg_catalog.pg_database d WHERE d.datname=$2"
        }
        SqlObjectKind::Schema => {
            "SELECT n.nspacl AS acl, n.nspowner AS owner FROM pg_catalog.pg_namespace n WHERE n.nspname=$2"
        }
        SqlObjectKind::Table => {
            "SELECT c.relacl AS acl, c.relowner AS owner FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass($2)"
        }
        SqlObjectKind::Routine => return Err(PgError::Unsupported),
    };
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM ({catalog}) o CROSS JOIN LATERAL pg_catalog.aclexplode(o.acl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee JOIN pg_catalog.pg_roles g ON g.oid=a.grantor WHERE u.rolname=$1 AND g.rolname=current_user AND a.privilege_type=$3)"
    );
    let row = tx
        .query_one(&sql, &[&batch.login, &check.object, &check.action])
        .await
        .map_err(|_| PgError::Precondition)?;
    Ok(row.get(0))
}
async fn direct_role(
    tx: &tokio_postgres::Transaction<'_>,
    batch: &SqlBatch,
    role: &str,
) -> Result<bool, PgError> {
    let row = tx.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member JOIN pg_catalog.pg_roles g ON g.oid=m.grantor WHERE u.rolname=$1 AND r.rolname=$2 AND g.rolname=current_user)", &[&batch.login, &role]).await.map_err(|_| PgError::Precondition)?;
    Ok(row.get(0))
}
async fn capture_ownership(
    tx: &tokio_postgres::Transaction<'_>,
    batch: &SqlBatch,
) -> Result<PgOwnershipReceipt, PgError> {
    let row = tx
        .query_one("SELECT current_user::text", &[])
        .await
        .map_err(|_| PgError::Precondition)?;
    let mut owned = PgOwnershipReceipt {
        policy_hash: batch.policy_hash.clone(),
        apply_batch_hash: batch.hash(),
        management_role: row.get(0),
        before_roles: vec![],
        before_privileges: vec![],
        after_roles: vec![],
        after_privileges: vec![],
        added_roles: vec![],
        added_privileges: vec![],
    };
    for role in &batch.roles {
        if direct_role(tx, batch, role).await? {
            owned.added_roles.push(role.clone());
        }
    }
    for check in &batch.checks {
        if direct_privilege(tx, batch, check).await? {
            owned.added_privileges.push(check.clone());
        }
    }
    Ok(owned)
}
fn ownership_delta(
    before: &PgOwnershipReceipt,
    mut after: PgOwnershipReceipt,
) -> PgOwnershipReceipt {
    after.before_roles = before.added_roles.clone();
    after.before_privileges = before.added_privileges.clone();
    after.after_roles = after.added_roles.clone();
    after.after_privileges = after.added_privileges.clone();
    after
        .added_roles
        .retain(|role| !before.added_roles.contains(role));
    after
        .added_privileges
        .retain(|check| !before.added_privileges.contains(check));
    after
}
async fn verify_revoke_preconditions(
    tx: &tokio_postgres::Transaction<'_>,
    batch: &SqlBatch,
) -> Result<(), PgError> {
    if batch.action != PgAction::RevokeSqlPrivileges {
        return Ok(());
    }
    let role = batch
        .management_role
        .as_ref()
        .ok_or(PgError::Precondition)?;
    let row = tx.query_one("SELECT current_user::text, session_user::text, rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user", &[]).await.map_err(|_| PgError::Precondition)?;
    if row.get::<_, String>(0) != *role
        || row.get::<_, String>(1) != *role
        || row.get::<_, bool>(2)
        || role == &batch.login
    {
        return Err(PgError::Precondition);
    }
    for check in &batch.checks {
        // PostgreSQL may select an inherited grantor. Require direct authority
        // so a revoke cannot silently act on a different grantor's ACL.
        let catalog = match check.kind {
            SqlObjectKind::Database => {
                "SELECT d.datacl AS acl, d.datdba AS owner FROM pg_catalog.pg_database d WHERE d.datname=$1"
            }
            SqlObjectKind::Schema => {
                "SELECT n.nspacl AS acl, n.nspowner AS owner FROM pg_catalog.pg_namespace n WHERE n.nspname=$1"
            }
            SqlObjectKind::Table => {
                "SELECT c.relacl AS acl, c.relowner AS owner FROM pg_catalog.pg_class c WHERE c.oid=pg_catalog.to_regclass($1)"
            }
            SqlObjectKind::Routine => return Err(PgError::Unsupported),
        };
        let sql = format!(
            "SELECT EXISTS (SELECT 1 FROM ({catalog}) o JOIN pg_catalog.pg_roles g ON g.rolname=current_user WHERE o.owner=g.oid OR EXISTS (SELECT 1 FROM pg_catalog.aclexplode(o.acl) a WHERE a.grantee=g.oid AND a.privilege_type=$2 AND a.is_grantable))"
        );
        let authority = tx
            .query_one(&sql, &[&check.object, &check.action])
            .await
            .map_err(|_| PgError::Precondition)?;
        if !authority.get::<_, bool>(0) {
            return Err(PgError::Precondition);
        }
        if check.kind == SqlObjectKind::Table {
            // Table REVOKE can remove column ACLs implicitly. Such columns were
            // never in our grant intent: refuse rather than destroy them.
            let columns = tx.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute c CROSS JOIN LATERAL pg_catalog.aclexplode(c.attacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE c.attrelid=pg_catalog.to_regclass($1) AND u.rolname=$2 AND a.privilege_type=$3)", &[&check.object, &batch.login, &check.action]).await.map_err(|_| PgError::Precondition)?;
            if columns.get::<_, bool>(0) {
                return Err(PgError::Precondition);
            }
        }
    }
    Ok(())
}

async fn verify_identity(
    tx: &tokio_postgres::Transaction<'_>,
    batch: &SqlBatch,
) -> Result<(), PgError> {
    let row = tx
        .query_one(
            "SELECT current_database(), current_setting('server_version')",
            &[],
        )
        .await
        .map_err(|_| PgError::Precondition)?;
    let version: String = row.get(1);
    if row.get::<_, String>(0) != batch.database
        || version.split_whitespace().next() != Some(batch.version.as_str())
    {
        return Err(PgError::Precondition);
    }
    for name in std::iter::once(&batch.login).chain(batch.roles.iter()) {
        let row = tx.query_opt("SELECT rolcanlogin, rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=$1", &[name]).await.map_err(|_| PgError::Precondition)?.ok_or(PgError::Precondition)?;
        if row.get::<_, bool>(1)
            || (name == &batch.login
                && matches!(
                    batch.action,
                    PgAction::ConfigureSqlPrivileges | PgAction::RegisterNativeDbIdentity
                )
                && !row.get::<_, bool>(0))
        {
            return Err(PgError::Precondition);
        }
        let elevated = tx.query_one("WITH RECURSIVE memberships(oid) AS (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1 UNION SELECT m.roleid FROM pg_catalog.pg_auth_members m JOIN memberships p ON m.member=p.oid) SELECT EXISTS (SELECT 1 FROM memberships m JOIN pg_catalog.pg_roles r ON r.oid=m.oid WHERE r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls)", &[name]).await.map_err(|_| PgError::Precondition)?;
        if elevated.get::<_, bool>(0) {
            return Err(PgError::Precondition);
        }
    }
    for role in &batch.roles {
        let unsafe_membership = tx.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE u.rolname=$1 AND r.rolname=$2 AND (m.set_option OR m.admin_option))", &[&batch.login, role]).await.map_err(|_| PgError::Precondition)?;
        if unsafe_membership.get::<_, bool>(0) {
            return Err(PgError::Precondition);
        }
    }
    Ok(())
}
async fn readback(tx: &tokio_postgres::Transaction<'_>, batch: &SqlBatch) -> Result<bool, PgError> {
    if batch.action == PgAction::DisableNewConnections {
        let row = tx
            .query_one(
                "SELECT NOT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=$1",
                &[&batch.login],
            )
            .await
            .map_err(|_| PgError::Unknown)?;
        return Ok(row.get(0));
    }
    if batch.action == PgAction::RevokeSqlPrivileges {
        for role in &batch.roles {
            if direct_role(tx, batch, role).await? {
                return Ok(false);
            }
        }
        for check in &batch.checks {
            if direct_privilege(tx, batch, check).await? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    for role in &batch.roles {
        let row = tx.query_one("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member WHERE u.rolname=$1 AND r.rolname=$2 AND m.inherit_option AND NOT m.set_option AND NOT m.admin_option)", &[&batch.login, role]).await.map_err(|_| PgError::Unknown)?;
        if !row.get::<_, bool>(0) {
            return Ok(false);
        }
    }
    for check in &batch.checks {
        let sql = match check.kind {
            SqlObjectKind::Database => {
                "SELECT pg_catalog.has_database_privilege($1::name, $2::text, $3::text)"
            }
            SqlObjectKind::Schema => {
                "SELECT pg_catalog.has_schema_privilege($1::name, $2::text, $3::text)"
            }
            SqlObjectKind::Table => {
                "SELECT pg_catalog.has_table_privilege($1::name, $2::text, $3::text)"
            }
            SqlObjectKind::Routine => return Err(PgError::Unsupported),
        };
        let row = tx
            .query_one(sql, &[&batch.login, &check.object, &check.action])
            .await
            .map_err(|_| PgError::Unknown)?;
        if !row.get::<_, bool>(0) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub struct PostgresStepExecutor<T> {
    pub execution_identity: String,
    pub engine: PostgresEngine<T>,
    source_contract_scope: bool,
}
impl<T: PgTransport> PostgresStepExecutor<T> {
    pub fn new(execution_identity: String, engine: PostgresEngine<T>) -> Self {
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
                    .map_err(|_| PgError::SourceGuardRejected)?;
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
                        .map_err(|_| PgError::SourceGuardRejected)?;
                    if !check.satisfied() {
                        return Err(PgError::SourceGuardRejected);
                    }
                }
                use crate::binding::CheckpointGate;
                checkpoints
                    .validate_change_window(change, &step.target_id, gate.now())
                    .map_err(|_| PgError::SourceGuardRejected)?;
                Ok(())
            };
            let outcome = this
                .engine
                .transport
                .execute_atomic_guarded(&batch, &mut guard)
                .map_err(map_error)?;
            Ok(this.finish_receipt(&batch, outcome))
        })
    }
    fn finish_receipt(&self, batch: &SqlBatch, outcome: PgOutcome) -> StepReceipt {
        let mut r = receipt(batch, outcome);
        if batch.action == PgAction::ConfigureSqlPrivileges
            && outcome == PgOutcome::Applied
            && let Some(ownership) = self.engine.transport.owned_receipt()
            && ownership.apply_batch_hash == batch.hash()
        {
            r.evidence_refs.push(ownership.hash());
        }
        r
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
                "core-adapter-v2",
            )
            || (change.policy.schema_version == 2 && !scope)
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let action = match step.action {
            ActionKind::RegisterNativeDbIdentity => PgAction::RegisterNativeDbIdentity,
            ActionKind::ConfigureSqlPrivileges => PgAction::ConfigureSqlPrivileges,
            ActionKind::DisableNewConnections => PgAction::DisableNewConnections,
            ActionKind::RevokeSqlPrivileges => PgAction::RevokeSqlPrivileges,
            _ => return Err(ExecutorError::Unavailable),
        };
        if action == PgAction::RevokeSqlPrivileges {
            let context = self
                .engine
                .transport
                .lifecycle_context()
                .ok_or(ExecutorError::Unavailable)?;
            let bound = change
                .lifecycle
                .as_ref()
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            let (source_operation, source_change) = context
                .authorization_source
                .as_ref()
                .map(|(operation, change)| (operation, change))
                .unwrap_or((&context.prior_operation_id, &context.prior_change_hash));
            if &bound.source_operation_id != source_operation
                || &bound.source_change_hash != source_change
            {
                return Err(ExecutorError::PreconditionsNotMet);
            }
            let previous = change
                .previous_policy
                .as_ref()
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            compile_owned_revoke(
                &change.policy,
                previous,
                &step.target_id,
                &step.grant_id,
                context,
            )
            .map_err(map_error)
        } else {
            compile(&change.policy, &step.target_id, &step.grant_id, action).map_err(map_error)
        }
    }
}
fn map_error(error: PgError) -> ExecutorError {
    match error {
        PgError::Unknown => ExecutorError::OutcomeUnknown,
        PgError::SourceGuardRejected => ExecutorError::NotApplied,
        PgError::Unavailable | PgError::Unsupported => ExecutorError::Unavailable,
        _ => ExecutorError::PreconditionsNotMet,
    }
}
fn receipt(batch: &SqlBatch, outcome: PgOutcome) -> StepReceipt {
    StepReceipt {
        state: match outcome {
            PgOutcome::Applied => StepState::EffectSatisfied,
            PgOutcome::NotApplied => StepState::NotApplied,
            PgOutcome::Unknown => StepState::OutcomeUnknown,
        },
        effect: match outcome {
            PgOutcome::Applied => EffectState::Enforced,
            PgOutcome::NotApplied => EffectState::NotSatisfied,
            PgOutcome::Unknown => EffectState::Unknown,
        },
        native_operation_ref: None,
        evidence_refs: vec![batch.hash()],
    }
}
impl<T: PgTransport> StepExecutor for PostgresStepExecutor<T> {
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
        Ok(self.finish_receipt(&batch, outcome))
    }
    fn query(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        _: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        let batch = self.batch(change, step)?;
        // Absence on a read cannot prove that an uncertain transaction did not
        // commit (a concurrent actor may have revoked it). Never enable resend.
        self.engine
            .query(&batch)
            .map(|outcome| {
                receipt(
                    &batch,
                    if outcome == PgOutcome::NotApplied {
                        PgOutcome::Unknown
                    } else {
                        outcome
                    },
                )
            })
            .map_err(map_error)
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    #[test]
    fn ownership_delta_retains_preexisting_and_foreign_grants() {
        let check = PrivilegeCheck {
            kind: SqlObjectKind::Table,
            object: "\"billing\".\"invoices\"".into(),
            action: "SELECT".into(),
        };
        let before = PgOwnershipReceipt {
            policy_hash: "a".repeat(64),
            apply_batch_hash: "b".repeat(64),
            management_role: "management".into(),
            before_roles: vec![],
            before_privileges: vec![],
            after_roles: vec![],
            after_privileges: vec![],
            added_roles: vec!["existing-reader".into()],
            added_privileges: vec![check.clone()],
        };
        let mut after = before.clone();
        after.added_roles.push("new-reader".into());
        let delta = ownership_delta(&before, after);
        assert_eq!(delta.added_roles, vec!["new-reader"]);
        assert!(delta.added_privileges.is_empty());
        assert!(
            ownership_delta(&before, before.clone())
                .added_roles
                .is_empty()
        );
    }
}
