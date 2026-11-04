//! AWS opt-in composition root. Offline commands never enter this module.
use crate::{
    adapters::{
        aws_observation::{AwsLiveObserver, AwsProfileBinding, target_binding},
        deployment::aws::{AwsCliProvider, AwsExecutor},
        engine::postgres::{
            PostgresEngine, PostgresStepExecutor,
            aws::{AwsCliPgAuthProvider, AwsPgManagementIdentity, AwsRdsPgTransport},
        },
        executor::AwsProtectionExecutor,
    },
    binding::{BindingStepExecutor, ManualCheckpoint, ManualCheckpoints},
    config::{GuardError, read_bounded, read_json},
    core::{
        operation::{ExecutionState, StoreError},
        orchestrator,
        policy::{EngineFamily, PlacementKind, ProfileKind},
    },
    operation_store::OperationStore,
    store,
};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Args)]
pub struct NativeAwsArgs {
    /// Read current local source evidence for the v3 native contract. Changes still require explicit opt-in and immutable approval.
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
    #[arg(long)]
    pub native_config: PathBuf,
    #[arg(long = "checkpoint")]
    pub checkpoints: Vec<PathBuf>,
    #[arg(long)]
    pub allow_native_changes: bool,
    #[arg(long)]
    pub ownership_run: Option<PathBuf>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAwsTools {
    pub schema_version: u32,
    pub aws_cli: PathBuf,
    pub management_profile: String,
    pub profiles: Vec<AwsProfileBinding>,
    pub ca_file: PathBuf,
    pub work_dir: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsNativeStateRecord {
    pub schema_version: u32,
    pub operation_id: String,
    pub change_hash: String,
    pub policy_revision_hash: String,
    pub observation: crate::adapters::deployment::aws::RevocationEvidence,
}
pub fn load_state_record(
    change: &crate::core::change::PreparedChange,
    operation: &str,
    path: &std::path::Path,
) -> Result<AwsNativeStateRecord, GuardError> {
    let manifest = store::verify_manifest(path, 8 * 1024 * 1024)?;
    if manifest.operation != "aws-guard-state" || manifest.target_id != change.policy.policy_id {
        return Err(GuardError::EvidenceIncompatible);
    }
    let policy: crate::core::policy::PolicyRevision =
        store::read_artifact(path, &manifest, "config.normalized.json", 8 * 1024 * 1024)?;
    let record: AwsNativeStateRecord =
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
pub fn execute(args: NativeAwsArgs, cancel: CancellationToken) -> Result<i32, GuardError> {
    if !args.allow_native_changes {
        return Err(GuardError::PermissionRequired);
    }
    let mut ledger = OperationStore::open_existing(&args.ledger)?;
    let op = ledger.get(&args.operation)?;
    if op.version != args.expected_version {
        return Err(StoreError::Stale.into());
    }
    if op.execution_identity != args.execution_identity {
        return Err(StoreError::Approval.into());
    }
    let change = ledger.load_change(&op.change_hash)?;
    change.verify()?;
    let intent_qualification = crate::qualification_cli::report(&change)?;
    let existing_steps = ledger.steps(&args.operation)?;
    if let Some(code) = crate::qualification_cli::completed_without_native(
        &op,
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
    if change.policy.targets.len() != 1 {
        return Err(GuardError::UnsupportedTarget);
    }
    let target = change.policy.targets[0].clone();
    let native = target.aws.as_ref().ok_or(GuardError::ConfigInvalid)?;
    if target.placement.kind != PlacementKind::AwsRds {
        return Err(GuardError::UnsupportedTarget);
    }
    let mut recovery = BTreeSet::new();
    for grant in change
        .policy
        .grants
        .iter()
        .filter(|g| g.target == target.id)
    {
        let profile = change
            .policy
            .protection_profiles
            .iter()
            .find(|p| {
                p.id == grant.profile
                    && matches!(
                        p.kind,
                        ProfileKind::AwsRdsPostgresProxyV1 | ProfileKind::AwsRdsMysqlProxyV1
                    )
            })
            .ok_or(GuardError::ConfigInvalid)?;
        for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
            recovery.insert(exception.subject.clone());
        }
    }
    if recovery.len() != 1 {
        return Err(GuardError::UnsupportedTarget);
    }
    let operator = change
        .policy
        .subjects
        .iter()
        .find(|s| Some(&s.id) == recovery.first())
        .ok_or(GuardError::ConfigInvalid)?;
    let role_id = operator
        .identity
        .immutable_id
        .clone()
        .ok_or(GuardError::ConfigInvalid)?;
    if args.execution_identity != format!("aws-role:{}:{}", operator.identity.principal, role_id) {
        return Err(StoreError::Approval.into());
    }
    let tools: NativeAwsTools = read_json(&args.native_config, 64 * 1024)?;
    if tools.schema_version != 1 || tools.profiles.len() > 16 || args.checkpoints.len() > 16 {
        return Err(GuardError::ConfigInvalid);
    }
    private_directory(&tools.work_dir)?;
    let ca = read_bounded(&tools.ca_file, 1024 * 1024)?;
    let checkpoints = ManualCheckpoints {
        receipts: args
            .checkpoints
            .iter()
            .map(|path| read_json::<ManualCheckpoint>(path, 1024 * 1024))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let observer = AwsLiveObserver {
        aws: tools.aws_cli.clone(),
        profiles: tools.profiles,
        root_ca: ca.clone(),
        work_dir: tools.work_dir.clone(),
        cancel: cancel.clone(),
    };
    let provider = AwsCliProvider::new(
        tools.aws_cli.clone(),
        tools.management_profile.clone(),
        target.placement.account_id.clone(),
        operator.identity.principal.clone(),
        role_id.clone(),
        cancel.clone(),
    )
    .map_err(|_| GuardError::ConfigInvalid)?
    .with_observer(Box::new(observer));
    let auth = AwsCliPgAuthProvider::new(
        tools.aws_cli,
        tools.management_profile,
        operator.identity.principal.clone(),
        role_id.clone(),
        cancel.clone(),
    )
    .map_err(|_| GuardError::ConfigInvalid)?;
    let binding = target_binding(&target).map_err(|_| GuardError::ConfigInvalid)?;
    let management = AwsPgManagementIdentity {
        role_arn: operator.identity.principal.clone(),
        role_id,
        db_username: native.management_db_identity.clone(),
    };
    let mut ownership_context_failed = false;
    let engine: Box<dyn crate::adapters::executor::SourceEngineExecutor> = match target
        .engine
        .family
    {
        EngineFamily::PostgreSql => {
            let mut transport = AwsRdsPgTransport::new(
                target.clone(),
                binding,
                management,
                Arc::new(auth),
                &ca,
                Duration::from_secs(120),
            )
            .map_err(|_| GuardError::ConfigInvalid)?
            .with_cancel(cancel.clone())
            .with_ownership_directory(tools.work_dir.clone());
            if intent_qualification.is_dispatch_qualified() {
                match crate::native_cli::build_sql_lifecycle_context(
                    &ledger,
                    &change,
                    args.ownership_run.as_deref(),
                ) {
                    Ok(Some(context)) => transport = transport.with_lifecycle_context(context),
                    Ok(None) => {}
                    Err(_) if crate::qualification_cli::has_unresolved(&existing_steps) => {
                        ownership_context_failed = true
                    }
                    Err(e) => return Err(e),
                }
            }
            Box::new(PostgresStepExecutor::new(
                args.execution_identity.clone(),
                PostgresEngine { transport },
            ))
        }
        EngineFamily::MySql => {
            use crate::adapters::engine::mysql::{
                MysqlEngine, MysqlStepExecutor, aws::AwsRdsMysqlTransport,
            };
            let mut transport = AwsRdsMysqlTransport::new(
                target.clone(),
                binding,
                management,
                Arc::new(auth),
                &ca,
                Duration::from_secs(120),
            )
            .map_err(|_| GuardError::ConfigInvalid)?
            .with_cancel(cancel.clone())
            .with_ownership_directory(tools.work_dir.clone());
            if intent_qualification.is_dispatch_qualified() {
                match build_mysql_lifecycle_context(&ledger, &change, args.ownership_run.as_deref())
                {
                    Ok(Some(context)) => transport = transport.with_lifecycle_context(context),
                    Ok(None) => {}
                    Err(_) if crate::qualification_cli::has_unresolved(&existing_steps) => {
                        ownership_context_failed = true
                    }
                    Err(e) => return Err(e),
                }
            }
            Box::new(MysqlStepExecutor::new(
                args.execution_identity.clone(),
                MysqlEngine { transport },
            ))
        }
        _ => return Err(GuardError::UnsupportedTarget),
    };
    let mut executor = AwsProtectionExecutor {
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
        cloud: AwsExecutor::new(
            provider,
            args.execution_identity.clone(),
            checkpoints.clone(),
        ),
        engine,
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
    let mut output = serde_json::json!({"operation_only":false,"native_dispatch_available":intent_qualification.is_dispatch_qualified(),"protection_evaluated":false,"operation_scope_completed":result.state==ExecutionState::Completed,"current_protection_rechecked":false,"operation":result,"steps":steps,"revocation_observation":executor.cloud.last_revocation_evidence()});
    if executor.cloud.last_revocation_evidence().is_some() {
        let mut writer = store::RunWriter::create_for_config(
            &tools
                .work_dir
                .join(format!("aws-state-{}", store::new_run_id())),
            &change.policy.policy_id,
            &change.policy,
            "aws-guard-state",
            8 * 1024 * 1024,
            false,
        )?;
        let record = AwsNativeStateRecord {
            schema_version: 1,
            operation_id: args.operation.clone(),
            change_hash: change.change_hash.clone(),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            observation: executor
                .cloud
                .last_revocation_evidence()
                .cloned()
                .ok_or(GuardError::EvidenceIncompatible)?,
        };
        writer.write_json("effective-state.json", &record)?;
        writer.finish(if result.state == ExecutionState::Completed {
            store::RunStatus::Complete
        } else {
            store::RunStatus::Partial
        })?;
    }
    output["intent_qualification"] =
        serde_json::to_value(&intent_qualification).map_err(|_| GuardError::StorageFailed)?;
    output["source_evidence_read_failed"] = serde_json::json!(source_evidence_read_failed);
    output["ownership_context_failed"] = serde_json::json!(ownership_context_failed);
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
fn build_mysql_lifecycle_context(
    ledger: &OperationStore,
    change: &crate::core::change::PreparedChange,
    ownership_run: Option<&std::path::Path>,
) -> Result<Option<crate::adapters::engine::mysql::MysqlLifecycleContext>, GuardError> {
    use crate::{
        adapters::engine::mysql::{
            MysqlLifecycleContext, MysqlOwnershipReceipt, compile_owned_revoke,
        },
        core::capability::ActionKind,
    };
    let Some(source) = crate::native_cli::load_sql_ownership_source(ledger, change)? else {
        return Ok(None);
    };
    let owned = MysqlOwnershipReceipt::load_verified_run(
        ownership_run.ok_or(GuardError::EvidenceIncompatible)?,
    )
    .map_err(|_| GuardError::EvidenceIncompatible)?;
    let result = MysqlLifecycleContext {
        prior_policy: source.prior_policy,
        prior_operation_id: source.prior_operation_id,
        prior_change_hash: source.prior_change_hash,
        prior_sql_step: source.prior_sql_step,
        authorization_source: source.authorization_source,
        ownership: Some(owned),
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
#[derive(Debug, Args)]
pub struct InspectAwsArgs {
    #[arg(long)]
    pub ledger: PathBuf,
    #[arg(long)]
    pub operation: String,
    #[arg(long)]
    pub execution_identity: String,
    #[arg(long)]
    pub native_config: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long)]
    pub allow_aws_read: bool,
}
/// Read selected native metadata and emit a reviewable preparation hash. This
/// is a read-only explicit command, never invoked by plan/attest or by tests.
pub fn inspect(args: InspectAwsArgs, cancel: CancellationToken) -> Result<i32, GuardError> {
    use crate::adapters::deployment::aws::{
        AwsProvider, generation_fingerprint, preparation_fingerprint,
    };
    if !args.allow_aws_read {
        return Err(GuardError::PermissionRequired);
    }
    let ledger = OperationStore::open_existing(&args.ledger)?;
    let operation = ledger.get(&args.operation)?;
    if operation.execution_identity != args.execution_identity {
        return Err(StoreError::Approval.into());
    }
    let change = ledger.load_change(&operation.change_hash)?;
    change.verify()?;
    if change.policy.targets.len() != 1 {
        return Err(GuardError::UnsupportedTarget);
    }
    let target = &change.policy.targets[0];
    let binding = target.aws.as_ref().ok_or(GuardError::UnsupportedTarget)?;
    let roles = change
        .policy
        .protection_profiles
        .iter()
        .flat_map(|p| p.management_exceptions.iter())
        .filter(|e| e.recovery)
        .map(|e| e.subject.clone())
        .collect::<BTreeSet<_>>();
    if roles.len() != 1 {
        return Err(GuardError::UnsupportedTarget);
    }
    let subject = change
        .policy
        .subjects
        .iter()
        .find(|s| Some(&s.id) == roles.first())
        .ok_or(GuardError::ConfigInvalid)?;
    let role_id = subject
        .identity
        .immutable_id
        .clone()
        .ok_or(GuardError::ConfigInvalid)?;
    if args.execution_identity != format!("aws-role:{}:{}", subject.identity.principal, role_id) {
        return Err(StoreError::Approval.into());
    }
    let tools: NativeAwsTools = read_json(&args.native_config, 64 * 1024)?;
    if tools.schema_version != 1 {
        return Err(GuardError::ConfigInvalid);
    }
    let mut provider = AwsCliProvider::new(
        tools.aws_cli,
        tools.management_profile,
        target.placement.account_id.clone(),
        subject.identity.principal.clone(),
        role_id,
        cancel,
    )
    .map_err(|_| GuardError::ConfigInvalid)?;
    if provider
        .execution_identity()
        .map_err(|_| GuardError::OperationFailed)?
        != args.execution_identity
    {
        return Err(StoreError::Approval.into());
    }
    let db = provider
        .instance(target)
        .map_err(|_| GuardError::OperationFailed)?;
    let proxy = provider
        .proxy(target)
        .map_err(|_| GuardError::OperationFailed)?;
    if db.arn != target.resource.native_id
        || db.resource_id != binding.db_resource_id
        || proxy.arn != binding.proxy_arn
        || proxy.auth_entries != 0
        || provider
            .role_id(&binding.proxy_role_arn)
            .map_err(|_| GuardError::OperationFailed)?
            != binding.proxy_role_id
    {
        return Err(GuardError::TargetMismatch);
    }
    let fingerprint = preparation_fingerprint(&db, &proxy);
    let snapshot = serde_json::json!({"target_id":target.id,"generation":generation_fingerprint(&target.placement.account_id,&target.placement.region,&db.arn,&db.resource_id),"preparation_configuration_hash":fingerprint,
        "db":{"arn":db.arn,"resource_id":db.resource_id,"endpoint":db.endpoint,"engine_family":db.engine_family,"version":db.version,"iam_authentication":db.iam_authentication,"security_group_ids":db.security_group_ids,"port":db.port},
        "proxy":{"arn":proxy.arn,"name":proxy.name,"endpoint":proxy.endpoint,"role_arn":proxy.role_arn,"engine_family":proxy.engine_family,"require_tls":proxy.require_tls,"iam_authentication":proxy.iam_authentication,"auth_entries":proxy.auth_entries,"security_group_ids":proxy.security_group_ids,"target_resource_ids":proxy.target_resource_ids}});
    let mut run = store::RunWriter::create_for_config(
        &args.out,
        &target.id,
        &change.policy,
        "aws-guard-inspect",
        8 * 1024 * 1024,
        true,
    )?;
    run.write_json("snapshot.json", &snapshot)?;
    run.finish(store::RunStatus::Complete)?;
    println!(
        "{}",
        serde_json::json!({"operation_only":true,"native_changes":false,"protection_evaluated":false,"preparation_configuration_hash":fingerprint,"run_id":run.manifest.run_id})
    );
    Ok(0)
}
