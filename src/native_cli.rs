//! Explicit opt-in composition root for GCP native execution. Reading this
//! configuration and constructing adapters performs no provider operation.
use crate::{
    adapters::{
        deployment::gcp::{GcloudProvider, GcpExecutor},
        engine::postgres::{ConnectorPgTransport, PostgresEngine, PostgresStepExecutor},
        executor::GcpProtectionExecutor,
    },
    binding::{BindingStepExecutor, ManualCheckpoint, ManualCheckpoints},
    config::{GuardError, read_json},
    core::{operation::ExecutionState, orchestrator},
    gcp::{self, live::LiveTools},
    operation_store::OperationStore,
    store,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Args)]
pub struct NativeGcpArgs {
    /// Read current local source evidence for the v3 execution contract. Native changes still require explicit opt-in and approval.
    #[arg(long)]
    pub source_archive: Option<PathBuf>,
    #[arg(long = "source-request", requires = "source_archive")]
    pub source_requests: Vec<String>,

    #[arg(long)]
    pub ledger: PathBuf,
    #[arg(long)]
    pub operation: String,
    #[arg(long)]
    pub expected_version: u64,
    #[arg(long)]
    pub execution_identity: String,
    /// Secret-free executable paths and current probe configuration.
    #[arg(long)]
    pub native_config: PathBuf,
    /// Hash-bound operator attestations. Repeat for each required kind.
    #[arg(long = "checkpoint")]
    pub checkpoints: Vec<PathBuf>,
    /// Explicitly permit this invocation to contact GCP and mutate approved fields.
    #[arg(long)]
    pub allow_native_changes: bool,
    /// Verified SQL ownership artifact from the source apply, required for SQL revocation.
    #[arg(long)]
    pub ownership_run: Option<PathBuf>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeToolsConfig {
    pub schema_version: u32,
    pub gcloud: PathBuf,
    pub curl: PathBuf,
    pub proxy: PathBuf,
    pub psql: PathBuf,
    pub work_dir: PathBuf,
    pub probe_config: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStateRecord {
    pub schema_version: u32,
    pub operation_id: String,
    pub change_hash: String,
    pub policy_revision_hash: String,
    pub observation: crate::adapters::deployment::gcp::RevocationEvidence,
}
pub fn load_any_state_record(
    change: &crate::core::change::PreparedChange,
    operation: &str,
    path: &std::path::Path,
) -> Result<serde_json::Value, GuardError> {
    let manifest = store::verify_manifest(path, 8 * 1024 * 1024)?;
    if manifest.operation == "aws-guard-state" {
        serde_json::to_value(crate::aws_native_cli::load_state_record(
            change, operation, path,
        )?)
        .map_err(|_| GuardError::EvidenceIncompatible)
    } else {
        serde_json::to_value(load_state_record(change, operation, path)?)
            .map_err(|_| GuardError::EvidenceIncompatible)
    }
}
pub fn load_state_record(
    change: &crate::core::change::PreparedChange,
    operation: &str,
    path: &std::path::Path,
) -> Result<NativeStateRecord, GuardError> {
    let manifest = store::verify_manifest(path, 8 * 1024 * 1024)?;
    if manifest.operation != "guard-state" || manifest.target_id != change.policy.policy_id {
        return Err(GuardError::EvidenceIncompatible);
    }
    let policy: crate::core::policy::PolicyRevision =
        store::read_artifact(path, &manifest, "config.normalized.json", 8 * 1024 * 1024)?;
    let record: NativeStateRecord =
        store::read_artifact(path, &manifest, "effective-state.json", 8 * 1024 * 1024)?;
    if policy != change.policy
        || manifest.config_hash
            != crate::config::hash_bytes(
                &serde_json::to_vec(&policy).map_err(|_| GuardError::EvidenceIncompatible)?,
            )
        || record.schema_version != 1
        || record.operation_id != operation
        || record.change_hash != change.change_hash
        || record.policy_revision_hash != change.plan.policy_revision_hash
        || !change.policy.grants.iter().any(|g| {
            g.admission == crate::core::policy::AdmissionIntent::Deny
                && change.policy.subjects.iter().any(|s| {
                    s.id == g.subject && s.identity.principal == record.observation.denied_principal
                })
                && change.policy.targets.iter().any(|t| {
                    t.id == g.target
                        && t.resource.generation_fingerprint.as_deref()
                            == Some(record.observation.generation.as_str())
                })
        })
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    Ok(record)
}
/// Resolve the approved immediate lifecycle source separately from the
/// successful ancestor that owns the SQL delta. This function performs only
/// ledger/artifact reads; no credential, executable or network access.
/// Immutable ledger ancestry shared by engine-specific ownership verifiers.
pub struct SqlOwnershipSource {
    pub prior_policy: crate::core::policy::PolicyRevision,
    pub prior_operation_id: String,
    pub prior_change_hash: String,
    pub prior_sql_step: crate::core::operation::StepRecord,
    pub authorization_source: Option<(String, String)>,
}
pub fn load_sql_ownership_source(
    ledger: &OperationStore,
    change: &crate::core::change::PreparedChange,
) -> Result<Option<SqlOwnershipSource>, GuardError> {
    use crate::core::{
        capability::ActionKind,
        lifecycle::{LifecycleKind, validate_source},
    };
    if !change
        .plan
        .steps
        .iter()
        .any(|s| s.action == ActionKind::RevokeSqlPrivileges)
    {
        return Ok(None);
    }
    let context = change
        .lifecycle
        .as_ref()
        .ok_or(GuardError::EvidenceIncompatible)?;
    let immediate_op = ledger.get(&context.source_operation_id)?;
    if immediate_op.change_hash != context.source_change_hash {
        return Err(GuardError::EvidenceIncompatible);
    }
    let immediate = ledger.load_change(&immediate_op.change_hash)?;
    validate_source(change, &immediate)?;
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::RevokeSqlPrivileges)
        .ok_or(GuardError::EvidenceIncompatible)?;
    let (owner_op, owner) = if immediate
        .plan
        .steps
        .iter()
        .any(|s| s.grant_id == step.grant_id && s.action == ActionKind::ConfigureSqlPrivileges)
    {
        (immediate_op.clone(), immediate)
    } else {
        let parent = immediate
            .lifecycle
            .as_ref()
            .filter(|c| c.kind == LifecycleKind::Revoke)
            .ok_or(GuardError::EvidenceIncompatible)?;
        let operation = ledger.get(&parent.source_operation_id)?;
        if operation.change_hash != parent.source_change_hash {
            return Err(GuardError::EvidenceIncompatible);
        }
        let ancestor = ledger.load_change(&operation.change_hash)?;
        validate_source(&immediate, &ancestor)?;
        (operation, ancestor)
    };
    if change.previous_policy.as_ref() != Some(&owner.policy) {
        return Err(GuardError::EvidenceIncompatible);
    }
    let sql = owner
        .plan
        .steps
        .iter()
        .find(|s| s.grant_id == step.grant_id && s.action == ActionKind::ConfigureSqlPrivileges)
        .ok_or(GuardError::EvidenceIncompatible)?;
    let record = ledger
        .steps(&owner_op.id)?
        .into_iter()
        .find(|s| s.step_id == sql.id)
        .ok_or(GuardError::EvidenceIncompatible)?;
    Ok(Some(SqlOwnershipSource {
        prior_policy: owner.policy,
        prior_operation_id: owner_op.id,
        prior_change_hash: owner_op.change_hash,
        prior_sql_step: record,
        authorization_source: Some((immediate_op.id, immediate_op.change_hash)),
    }))
}

pub fn build_sql_lifecycle_context(
    ledger: &OperationStore,
    change: &crate::core::change::PreparedChange,
    ownership_run: Option<&std::path::Path>,
) -> Result<Option<crate::adapters::engine::postgres::PgLifecycleContext>, GuardError> {
    use crate::{
        adapters::engine::postgres::{
            PgLifecycleContext, PgOwnershipReceipt, compile_owned_revoke,
        },
        core::capability::ActionKind,
    };
    let Some(source) = load_sql_ownership_source(ledger, change)? else {
        return Ok(None);
    };
    let ownership = PgOwnershipReceipt::load_verified_run(
        ownership_run.ok_or(GuardError::EvidenceIncompatible)?,
    )
    .map_err(|_| GuardError::EvidenceIncompatible)?;
    let result = PgLifecycleContext {
        prior_policy: source.prior_policy,
        prior_operation_id: source.prior_operation_id,
        prior_change_hash: source.prior_change_hash,
        prior_sql_step: source.prior_sql_step,
        authorization_source: source.authorization_source,
        ownership: Some(ownership),
    };
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::RevokeSqlPrivileges)
        .ok_or(GuardError::EvidenceIncompatible)?;
    compile_owned_revoke(
        &change.policy,
        change
            .previous_policy
            .as_ref()
            .ok_or(GuardError::EvidenceIncompatible)?,
        &step.target_id,
        &step.grant_id,
        &result,
    )
    .map_err(|_| GuardError::EvidenceIncompatible)?;
    Ok(Some(result))
}

fn private_directory(path: &std::path::Path) -> Result<(), GuardError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| GuardError::StorageFailed)?;
    if !path.is_absolute() || !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(GuardError::ConfigInvalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(GuardError::ConfigInvalid);
        }
    }
    Ok(())
}
pub fn execute(args: NativeGcpArgs, cancel: CancellationToken) -> Result<i32, GuardError> {
    // The opt-in gate is checked before opening config or launching anything.
    if !args.allow_native_changes {
        return Err(GuardError::PermissionRequired);
    }
    let mut ledger = OperationStore::open_existing(&args.ledger)?;
    let operation = ledger.get(&args.operation)?;
    if operation.version != args.expected_version {
        return Err(crate::core::operation::StoreError::Stale.into());
    }
    if operation.execution_identity != args.execution_identity {
        return Err(crate::core::operation::StoreError::Approval.into());
    }
    let change = ledger.load_change(&operation.change_hash)?;
    change.verify()?;
    let intent_qualification = crate::qualification_cli::report(&change)?;
    let existing_steps = ledger.steps(&args.operation)?;
    if let Some(code) = crate::qualification_cli::completed_without_native(
        &operation,
        &existing_steps,
        &intent_qualification,
    )? {
        return Ok(code);
    }
    let mut source_evidence_read_failed = false;
    let source_evidence = if change.policy.schema_version == 2 {
        Some(
            match crate::observation_cli::state(
                &args.ledger,
                &args.operation,
                args.source_archive.as_deref(),
                &args.source_requests,
            ) {
                Ok(s) => s,
                Err(_) if crate::qualification_cli::has_unresolved(&existing_steps) => {
                    source_evidence_read_failed = true;
                    // A broken archive must not stop read-only reconciliation of
                    // accepted provider work. It still cannot enable new dispatch.
                    crate::adapters::source::state::empty(
                        &change,
                        &args.operation,
                        crate::domain::now(),
                    )?
                }
                Err(e) => return Err(e),
            },
        )
    } else {
        if args.source_archive.is_some() || !args.source_requests.is_empty() {
            return Err(GuardError::EvidenceIncompatible);
        }
        None
    };
    crate::qualification_cli::require_before_native_with_source(
        &intent_qualification,
        &existing_steps,
        source_evidence.as_ref(),
    )?;
    if let Some(source) = &source_evidence {
        crate::qualification_cli::require_source_ready_for_next(&existing_steps, source)?;
    }
    if change.policy.schema_version == 2
        && args.source_archive.is_none()
        && !existing_steps.iter().any(|r| {
            matches!(
                r.state,
                crate::core::operation::StepState::Dispatching
                    | crate::core::operation::StepState::Submitted
                    | crate::core::operation::StepState::ConfigApplied
                    | crate::core::operation::StepState::OutcomeUnknown
            )
        })
    {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "native_dispatch_available":false,"reason":"source_archive_required",
                "source_evidence":source_evidence,"intent_qualification":intent_qualification
            }))
            .map_err(|_| GuardError::StorageFailed)?
        );
        return Err(GuardError::SourceEvidenceNotReady);
    }
    if change.policy.targets.len() != 1
        || change.policy.targets[0].placement.kind
            != crate::core::policy::PlacementKind::GcpCloudSql
    {
        return Err(GuardError::UnsupportedTarget);
    }
    let target = change.policy.targets[0].clone();
    let config: NativeToolsConfig = read_json(&args.native_config, 64 * 1024)?;
    if config.schema_version != 1 {
        return Err(GuardError::ConfigInvalid);
    }
    private_directory(&config.work_dir)?;
    let probe = gcp::config::load_config(&config.probe_config)?;
    if args.checkpoints.len() > 16 {
        return Err(GuardError::LimitExceeded);
    }
    let checkpoints = ManualCheckpoints {
        receipts: args
            .checkpoints
            .iter()
            .map(|path| read_json::<ManualCheckpoint>(path, 1024 * 1024))
            .collect::<Result<Vec<_>, _>>()?,
    };
    if checkpoints.receipts.len() > 16 {
        return Err(GuardError::LimitExceeded);
    }
    let management_email = args
        .execution_identity
        .strip_prefix("gcp-service-account:")
        .and_then(|v| v.split_once(':'))
        .map(|(email, _)| email.to_string())
        .ok_or(GuardError::ConfigInvalid)?;
    let config_work_dir = config.work_dir.clone();
    let tools = LiveTools {
        gcloud: config.gcloud.clone(),
        proxy: config.proxy,
        psql: config.psql,
        work_dir: config.work_dir,
    };
    let provider = GcloudProvider::new(
        config.gcloud,
        config.curl,
        &args.execution_identity,
        cancel.clone(),
    )
    .and_then(|p| p.with_probe(probe.clone(), tools.clone()))
    .map_err(|_| GuardError::ConfigInvalid)?;
    let mut transport = ConnectorPgTransport::new(
        target,
        probe,
        tools,
        management_email,
        Duration::from_secs(120),
    )
    .map_err(|_| GuardError::ConfigInvalid)?
    .with_cancel(cancel.clone());
    // An incompatible old plan may only reconcile accepted work. Future SQL
    // ownership prerequisites must not prevent an already accepted cloud query.
    let mut ownership_context_failed = false;
    if intent_qualification.is_dispatch_qualified() {
        match build_sql_lifecycle_context(&ledger, &change, args.ownership_run.as_deref()) {
            Ok(Some(context)) => transport = transport.with_lifecycle_context(context),
            Ok(None) => {}
            Err(_) if crate::qualification_cli::has_unresolved(&existing_steps) => {
                ownership_context_failed = true
            }
            Err(e) => return Err(e),
        }
    }
    let mut executor = GcpProtectionExecutor {
        query_only: ownership_context_failed
            || (change.policy.schema_version == 2
                && (source_evidence_read_failed || args.source_archive.is_none())),
        source: args.source_archive.as_ref().map(|archive| {
            Box::new(crate::adapters::source::execution::LocalSourceGate::new(
                args.ledger.clone(),
                archive.clone(),
                args.operation.clone(),
                args.source_requests.clone(),
            )) as Box<dyn crate::core::source_execution::SourceStepGate>
        }),
        cloud: GcpExecutor::new(
            provider,
            args.execution_identity.clone(),
            checkpoints.clone(),
        ),
        postgres: PostgresStepExecutor::new(
            args.execution_identity.clone(),
            PostgresEngine { transport },
        ),
        binding: BindingStepExecutor::new(
            args.execution_identity,
            checkpoints,
            crate::domain::now(),
        ),
    };
    let result = orchestrator::resume(
        &mut ledger,
        &args.operation,
        args.expected_version,
        &store::new_run_id(),
        &mut executor,
    )?;
    let steps = ledger.steps(&args.operation)?;
    if let Some(observation) = executor.cloud.last_revocation_evidence() {
        let evidence_dir = std::path::PathBuf::from(&config_work_dir)
            .join(format!("guard-state-{}", store::new_run_id()));
        let mut writer = store::RunWriter::create_for_config(
            &evidence_dir,
            &change.policy.policy_id,
            &change.policy,
            "guard-state",
            8 * 1024 * 1024,
            false,
        )?;
        let record = NativeStateRecord {
            schema_version: 1,
            operation_id: args.operation.clone(),
            change_hash: change.change_hash.clone(),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            observation: observation.clone(),
        };
        writer.write_json("effective-state.json", &record)?;
        writer.finish(if observation.complete {
            store::RunStatus::Complete
        } else {
            store::RunStatus::Partial
        })?;
    }

    let mut output = serde_json::json!({"operation_only":false,"native_dispatch_available":intent_qualification.is_dispatch_qualified(),"protection_evaluated":false,"operation_scope_completed":result.state==ExecutionState::Completed,"revocation_observation":executor.cloud.last_revocation_evidence(),
        "current_protection_rechecked":false,"operation":result,"steps":steps});
    crate::qualification_cli::annotate_owned_iam(&change, &steps, &mut output);
    output["intent_qualification"] =
        serde_json::to_value(&intent_qualification).map_err(|_| GuardError::StorageFailed)?;
    output["ownership_context_failed"] = serde_json::json!(ownership_context_failed);
    output["source_evidence_read_failed"] = serde_json::json!(source_evidence_read_failed);
    output["forward_dispatch_blocked"] =
        serde_json::json!(!intent_qualification.is_dispatch_qualified() || executor.query_only);
    output["native_dispatch_available"] =
        serde_json::json!(intent_qualification.is_dispatch_qualified() && !executor.query_only);
    for (key, value) in crate::qualification_cli::completion(result.state)
        .as_object()
        .ok_or(GuardError::StorageFailed)?
    {
        output[key] = value.clone();
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|_| GuardError::StorageFailed)?
    );
    Ok(if cancel.is_cancelled() {
        130
    } else if result.state == ExecutionState::Completed {
        0
    } else {
        3
    })
}
