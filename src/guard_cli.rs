//! CLI presentation and composition. Only explicit native opt-in commands contact providers.
use crate::core::{
    approval,
    change::{self, OperationLimits, PreparedChange},
    operation::{BeginRequest, EventKind, ExecutionState},
    orchestrator::{self, UnavailableExecutor},
    plan, policy,
};
use crate::{
    adapters,
    config::{GuardError, hash_bytes, read_bounded},
    domain::now,
    operation_store::OperationStore,
    store::{self, RunStatus, RunWriter},
};
use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CheckpointArg {
    BindingPublished,
    RecoveryReady,
    ApplicationCutover,
    ExclusiveNativeChangeWindow,
    NativePreparationReady,
}
impl From<CheckpointArg> for crate::binding::CheckpointKind {
    fn from(value: CheckpointArg) -> Self {
        match value {
            CheckpointArg::BindingPublished => Self::BindingPublished,
            CheckpointArg::RecoveryReady => Self::RecoveryReady,
            CheckpointArg::ApplicationCutover => Self::ApplicationCutover,
            CheckpointArg::ExclusiveNativeChangeWindow => Self::ExclusiveNativeChangeWindow,
            CheckpointArg::NativePreparationReady => Self::NativePreparationReady,
        }
    }
}
#[derive(Debug, clap::Args)]
pub struct MaintenanceArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    source_operation: String,
    #[arg(long)]
    grant: String,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    evidence: Option<PathBuf>,
    #[arg(long)]
    revoke_sql: bool,
}
fn maintenance(
    args: MaintenanceArgs,
    kind: crate::core::lifecycle::LifecycleKind,
) -> Result<i32, GuardError> {
    let ledger = OperationStore::open_existing(&args.ledger)?;
    let source_op = ledger.get(&args.source_operation)?;
    let source = ledger.load_change(&source_op.change_hash)?;
    if kind == crate::core::lifecycle::LifecycleKind::Recover
        && !matches!(
            source_op.state,
            ExecutionState::Cancelled | ExecutionState::NeedsAction | ExecutionState::FailedPartial
        )
    {
        return Err(crate::core::operation::StoreError::Transition.into());
    }
    if ledger.desired_head(&source.policy.policy_id)?.as_deref()
        != Some(&source.plan.policy_revision_hash)
    {
        return Err(crate::core::operation::StoreError::Conflict.into());
    }
    let at = now();
    let grant = source
        .policy
        .grants
        .iter()
        .find(|g| g.id == args.grant)
        .ok_or(GuardError::ConfigInvalid)?;
    let target = source
        .policy
        .targets
        .iter()
        .find(|t| t.id == grant.target)
        .ok_or(GuardError::ConfigInvalid)?;
    let observed = args
        .evidence
        .as_deref()
        .map(|path| adapters::import::import_verified_run(target, path, at)?.for_change(target))
        .transpose()?;
    let capabilities =
        adapters::capabilities_for_policy(&source.policy).map_err(|_| GuardError::ConfigInvalid)?;
    let change = crate::core::lifecycle::prepare_maintenance(
        &source,
        &args.source_operation,
        kind,
        &args.grant,
        observed.as_slice(),
        capabilities,
        at,
        source.limits.clone(),
        args.revoke_sql,
    )?;
    let intent_qualification = crate::qualification_cli::report(&change)?;
    let mut run = RunWriter::create_for_config(
        &args.out,
        &change.policy.policy_id,
        &change.policy,
        "guard-plan",
        8 * 1024 * 1024,
        true,
    )?;
    run.write_json("plan.json", &change.plan)?;
    run.write_json("prepared-change.json", &change)?;
    run.write_json("intent-qualification.json", &intent_qualification)?;
    if let Some(observed) = observed {
        run.write_json("snapshot.json", &observed)?;
    }
    let mut report = "# Scoped lifecycle plan\n\nNo native changes performed. New bounded approval required. Reconcile/recover preserve current desired policy; revoke never restores Allow.\n".to_string();
    crate::qualification_cli::append_report(&mut report, &intent_qualification)?;
    run.write_bytes("report.md", report.as_bytes())?;
    run.finish(RunStatus::Complete)?;
    println!(
        "{}",
        serde_json::json!({"operation_only":true,"native_dispatch_available":false,"protection_evaluated":false,"lifecycle":change.lifecycle,"change_hash":change.change_hash,"policy_revision_hash":change.plan.policy_revision_hash,"required_effect_gaps":change.plan.required_effect_gaps,"static_qualified":intent_qualification.is_qualified(),"intent_qualification":intent_qualification})
    );
    Ok(3)
}
#[derive(Debug, Subcommand)]
pub enum GuardCommand {
    /// Prepare a K11 implementation handoff offline; never authorizes native changes.
    K11Readiness(crate::k11_cli::K11ReadinessArgs),
    /// Register a pinned local source snapshot; no installation or native read.
    SourceRegister(crate::observation_cli::SourceRegisterArgs),
    /// Open a read-only observation context, without forward approval or dispatch.
    ObservationStart(crate::observation_cli::ObservationStartArgs),
    /// Report collection/normalization coverage without contacting a source.
    ObservationCoverage(crate::observation_cli::ObservationCoverageArgs),
    /// Plan bounded fixed cases from the immutable policy and pinned collector config.
    ObservePlan(crate::observation_cli::ObservePlanArgs),
    /// Issue a bounded source challenge for external witness production.
    ObservationIssue(crate::observation_cli::ObservationIssueArgs),
    /// Capture and admit one fixed source batch (explicit native read opt-in).
    Observe(crate::observation_cli::ObserveArgs),
    /// Plan a bounded repair of current desired protection; no native I/O.
    Reconcile(MaintenanceArgs),
    /// Plan recovery of current desired protection from a stopped/failed operation.
    Recover(MaintenanceArgs),
    /// Advance the selected grant to Deny and plan narrow revocation.
    Revoke(MaintenanceArgs),
    /// Evaluate a verified local observation run against the exact policy.
    State {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, alias = "context")]
        operation: String,
        #[arg(long)]
        evidence: Option<PathBuf>,
        #[arg(long, conflicts_with = "evidence")]
        archive: Option<PathBuf>,
        #[arg(long = "request", requires = "archive", conflicts_with = "evidence")]
        requests: Vec<String>,
    },
    /// Resume approved GCP/PG changes through the native adapters (explicit opt-in).
    ApplyGcp(crate::native_cli::NativeGcpArgs),
    /// Resume approved AWS RDS PostgreSQL/MySQL changes through native adapters.
    ApplyAws(crate::aws_native_cli::NativeAwsArgs),
    /// Read native AWS metadata for a baseline-bound preparation declaration.
    InspectAws(crate::aws_native_cli::InspectAwsArgs),
    /// Print a secret-free workload connection profile from the immutable policy.
    Binding {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        grant: String,
    },
    /// Print a secret-free connection bundle for a selected application route.
    ConnectionBundle {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        grant: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        route: String,
        #[arg(long)]
        pool_generation: u64,
        /// SHA-256 of the configured client-to-RDS-Proxy CA PEM.
        #[arg(long)]
        aws_proxy_ca_sha256: Option<String>,
    },
    /// Record an explicit operator declaration; this performs no connection test.
    Attest {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        target: String,
        #[arg(long, value_enum)]
        kind: CheckpointArg,
        #[arg(long)]
        operator_subject: String,
        #[arg(long, default_value_t = 300)]
        valid_for: u64,
        #[arg(long)]
        configuration_hash: Option<String>,
    },
    /// Build a policy-bound desired protection graph locally. Does not apply changes.
    Plan {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, requires = "evidence_target")]
        evidence: Option<PathBuf>,
        #[arg(long, requires = "evidence")]
        evidence_target: Option<String>,
        #[arg(long)]
        previous_policy: Option<PathBuf>,
        #[arg(long, default_value_t = 128)]
        max_attempts: u32,
        #[arg(long, default_value_t = 3600)]
        max_operation_seconds: u64,
        #[arg(long, default_value_t = 2)]
        max_repair_executions: u32,
    },
    /// Record a bounded local approval; never contacts a provider.
    Approve {
        #[arg(long)]
        plan_run: PathBuf,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        approval_id: String,
        #[arg(long)]
        approver: String,
        #[arg(long)]
        execution_identity: String,
        #[arg(long, default_value_t = 300)]
        valid_for: u64,
        #[arg(long, default_value_t = 900)]
        recovery_for: u64,
    },
    /// Atomically register an operation and its desired revision. No native apply.
    Begin {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        approval_id: String,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        execution_identity: String,
        #[arg(long)]
        expected_desired_head: Option<String>,
    },
    /// Reconcile local operation state without contacting native systems; use apply-gcp/apply-aws for native execution.
    Resume {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        expected_version: u64,
        #[arg(long)]
        execution_identity: String,
    },
    /// Read an existing local ledger without creating a new one.
    Status {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long, alias = "context")]
        operation: String,
        #[arg(long)]
        native_state_run: Option<PathBuf>,
        #[arg(long)]
        archive: Option<PathBuf>,
        #[arg(long = "request", requires = "archive")]
        requests: Vec<String>,
    },
    /// Stop future dispatch; accepted/in-flight steps remain in the ledger.
    Cancel {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        expected_version: u64,
    },
    /// Revoke future use of an approval without erasing accepted work.
    RevokeApproval {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        approval_id: String,
    },
}

pub(crate) fn load_policy(path: &std::path::Path) -> Result<policy::PolicyRevision, GuardError> {
    let bytes = read_bounded(path, policy::MAX_POLICY_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GuardError::ConfigInvalid)?;
    policy::parse_policy(text).map_err(|_| GuardError::ConfigInvalid)
}

pub(crate) fn load_change_run(path: &std::path::Path) -> Result<PreparedChange, GuardError> {
    let manifest = store::verify_manifest(path, 8 * 1024 * 1024)?;
    if manifest.operation != "guard-plan"
        || manifest.status != RunStatus::Complete
        || !manifest.operation_only
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let policy: policy::PolicyRevision =
        store::read_artifact(path, &manifest, "config.normalized.json", 8 * 1024 * 1024)?;
    policy.validate().map_err(|_| GuardError::ConfigInvalid)?;
    if manifest.target_id != policy.policy_id
        || manifest.config_hash
            != hash_bytes(&serde_json::to_vec(&policy).map_err(|_| GuardError::ConfigInvalid)?)
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let change: PreparedChange =
        store::read_artifact(path, &manifest, "prepared-change.json", 8 * 1024 * 1024)?;
    let plan: plan::ChangePlan =
        store::read_artifact(path, &manifest, "plan.json", 8 * 1024 * 1024)?;
    change.verify()?;
    let saved_refs = manifest
        .artifacts
        .iter()
        .filter(|a| a.name == "snapshot.json")
        .map(|a| a.sha256.clone())
        .collect::<Vec<_>>();
    if manifest.build_id != plan.build_id
        || plan.observation_refs != saved_refs
        || change.policy != policy
        || serde_json::to_vec(&change.plan).map_err(|_| GuardError::EvidenceIncompatible)?
            != serde_json::to_vec(&plan).map_err(|_| GuardError::EvidenceIncompatible)?
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    Ok(change)
}

pub(crate) fn unknown_state(
    change: &PreparedChange,
) -> Result<crate::core::state::StateReport, GuardError> {
    use crate::core::state::*;
    let desired = desired_for_change(&change.policy, change.previous_policy.as_ref(), &[], now())
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    evaluate_state(&StateEvaluationInput {
        schema_version: STATE_SCHEMA_VERSION,
        now: now(),
        max_age_seconds: 60,
        expected_build_id: crate::BUILD_ID.into(),
        desired,
        evidence: vec![],
        permission_removals: vec![],
    })
    .map_err(|_| GuardError::EvidenceIncompatible)
}
fn show_operation(operation: &crate::core::operation::Operation) -> Result<i32, GuardError> {
    let output = serde_json::json!({"operation_only":true,"native_dispatch_available":false,"protection_evaluated":false,"operation":operation});
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|_| GuardError::StorageFailed)?
    );
    Ok(if operation.state == ExecutionState::Completed {
        0
    } else {
        3
    })
}

pub fn execute(command: GuardCommand) -> Result<i32, GuardError> {
    execute_with_cancel(command, CancellationToken::new())
}
pub fn execute_with_cancel(
    command: GuardCommand,
    cancel: CancellationToken,
) -> Result<i32, GuardError> {
    match command {
        GuardCommand::K11Readiness(args) => crate::k11_cli::execute(args),
        GuardCommand::SourceRegister(args) => crate::observation_cli::register(args),
        GuardCommand::ObservationStart(args) => crate::observation_cli::start(args),
        GuardCommand::ObservationCoverage(args) => crate::observation_cli::coverage(args),
        GuardCommand::ObservePlan(args) => crate::observation_cli::plan(args),
        GuardCommand::ObservationIssue(args) => crate::observation_cli::issue(args),
        GuardCommand::Observe(args) => crate::observation_cli::observe(args, cancel),
        GuardCommand::Reconcile(args) => {
            maintenance(args, crate::core::lifecycle::LifecycleKind::Reconcile)
        }
        GuardCommand::Recover(args) => {
            maintenance(args, crate::core::lifecycle::LifecycleKind::Recover)
        }
        GuardCommand::Revoke(args) => {
            maintenance(args, crate::core::lifecycle::LifecycleKind::Revoke)
        }
        GuardCommand::State {
            ledger,
            operation,
            evidence,
            archive,
            requests,
        } => {
            let change = crate::observation_cli::load_context(&ledger, &operation)?;
            if change.policy.schema_version == 2 {
                if evidence.is_some() {
                    return Err(GuardError::EvidenceIncompatible);
                }
                let report = crate::observation_cli::state(
                    &ledger,
                    &operation,
                    archive.as_deref(),
                    &requests,
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|_| GuardError::StorageFailed)?
                );
                return Ok(if report.effective.all_required_effects_satisfied {
                    0
                } else {
                    3
                });
            }
            if archive.is_some() || !requests.is_empty() {
                return Err(GuardError::EvidenceIncompatible);
            }
            let report = if let Some(path) = evidence {
                adapters::state::evaluate_run(&change, &path, now())?
            } else {
                unknown_state(&change)?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|_| GuardError::StorageFailed)?
            );
            Ok(if report.all_required_effects_satisfied {
                0
            } else {
                3
            })
        }
        GuardCommand::InspectAws(args) => crate::aws_native_cli::inspect(args, cancel),
        GuardCommand::ApplyAws(args) => crate::aws_native_cli::execute(args, cancel),
        GuardCommand::ApplyGcp(args) => crate::native_cli::execute(args, cancel),
        GuardCommand::Binding {
            ledger,
            operation,
            grant,
        } => {
            let ledger = OperationStore::open_existing(&ledger)?;
            let operation = ledger.get(&operation)?;
            let change = ledger.load_change(&operation.change_hash)?;
            let profile = crate::binding::connection_profile(&change.policy, &grant)
                .map_err(|_| GuardError::ConfigInvalid)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&profile).map_err(|_| GuardError::StorageFailed)?
            );
            Ok(0)
        }
        GuardCommand::ConnectionBundle {
            ledger,
            operation,
            grant,
            source,
            route,
            pool_generation,
            aws_proxy_ca_sha256,
        } => {
            let operations = OperationStore::open_existing(&ledger)?;
            let operation = operations.get(&operation)?;
            let change = operations.load_change(&operation.change_hash)?;
            if let Some(ca) = aws_proxy_ca_sha256 {
                let source_binding = change
                    .policy
                    .source_bindings
                    .iter()
                    .find(|binding| binding.source_id == source)
                    .ok_or(GuardError::ConfigInvalid)?;
                let snapshot = crate::evidence_store::EvidenceStore::open_existing(&ledger)?
                    .source_snapshot(&source_binding.registration_id)?;
                let bundle = crate::binding::aws_runtime::AwsConnectionBundle::prepare(
                    &change,
                    &grant,
                    &source,
                    &route,
                    pool_generation,
                    &snapshot,
                    &ca,
                )
                .map_err(|_| GuardError::ConfigInvalid)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&bundle).map_err(|_| GuardError::StorageFailed)?
                );
                return Ok(0);
            }
            let bundle = crate::binding::runtime::ConnectionBundle::prepare(
                &change,
                &grant,
                &source,
                &route,
                pool_generation,
            )
            .map_err(|_| GuardError::ConfigInvalid)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&bundle).map_err(|_| GuardError::StorageFailed)?
            );
            Ok(0)
        }
        GuardCommand::Attest {
            ledger,
            operation,
            target,
            kind,
            operator_subject,
            valid_for,
            configuration_hash,
        } => {
            let ledger = OperationStore::open_existing(&ledger)?;
            let operation = ledger.get(&operation)?;
            let change = ledger.load_change(&operation.change_hash)?;
            let at = now();
            let kind: crate::binding::CheckpointKind = kind.into();
            let until = at.checked_add(valid_for).ok_or(GuardError::ConfigInvalid)?;
            let receipt = if kind == crate::binding::CheckpointKind::NativePreparationReady {
                crate::binding::ManualCheckpoint::attest_preparation(
                    &change,
                    &target,
                    &operator_subject,
                    configuration_hash
                        .as_deref()
                        .ok_or(GuardError::ConfigInvalid)?,
                    at,
                    until,
                )
            } else {
                if configuration_hash.is_some() {
                    return Err(GuardError::ConfigInvalid);
                }
                crate::binding::ManualCheckpoint::attest(
                    &change,
                    &target,
                    kind,
                    &operator_subject,
                    at,
                    until,
                )
            }
            .map_err(|_| GuardError::ConfigInvalid)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt).map_err(|_| GuardError::StorageFailed)?
            );
            Ok(0)
        }
        GuardCommand::Plan {
            policy: path,
            out,
            evidence,
            evidence_target,
            previous_policy,
            max_attempts,
            max_operation_seconds,
            max_repair_executions,
        } => {
            let policy = load_policy(&path)?.normalized();
            let previous = previous_policy.as_deref().map(load_policy).transpose()?;
            let at = now();
            // Import/validate before creating output, including target/config/build
            // and provider-specific checks; a manifest is not a signature.
            let observed = if let Some(path) = evidence {
                let target = policy
                    .targets
                    .iter()
                    .find(|target| Some(&target.id) == evidence_target.as_ref())
                    .ok_or(GuardError::TargetMismatch)?;
                Some(adapters::import::import_verified_run(target, &path, at)?.for_change(target)?)
            } else {
                None
            };
            let refs = observed
                .as_ref()
                .map(|o| {
                    serde_json::to_vec_pretty(o)
                        .map(|mut bytes| {
                            bytes.push(b'\n'); // Exactly RunWriter::write_json's artifact bytes.
                            vec![hash_bytes(&bytes)]
                        })
                        .map_err(|_| GuardError::EvidenceIncompatible)
                })
                .transpose()?
                .unwrap_or_default();
            let capabilities = adapters::capabilities_for_policy(&policy)
                .map_err(|_| GuardError::ConfigInvalid)?;
            let plan = plan::build_plan(&policy, capabilities, refs, at).map_err(|e| match e {
                plan::PlanError::PolicyInvalid | plan::PlanError::ScopeViolation => {
                    GuardError::ConfigInvalid
                }
                plan::PlanError::CapabilityInvalid => GuardError::EvidenceIncompatible,
            })?;
            let change = change::prepare_change(
                &policy,
                &plan,
                observed.as_slice(),
                previous.as_ref(),
                OperationLimits {
                    max_attempts,
                    max_operation_seconds,
                    max_repair_executions,
                    max_parallel_steps: 1,
                },
            )?;
            let intent_qualification = crate::qualification_cli::report(&change)?;
            let mut run = RunWriter::create_for_config(
                &out,
                &policy.policy_id,
                &policy,
                "guard-plan",
                8 * 1024 * 1024,
                true,
            )?;
            run.write_json("plan.json", &plan)?;
            run.write_json("prepared-change.json", &change)?;
            run.write_json("intent-qualification.json", &intent_qualification)?;
            if let Some(observed) = observed {
                run.write_json("snapshot.json", &observed)?;
            }
            let mut report = format!(
                "# 接続保護の変更計画\n\nポリシーrevision: `{}`\n\n計画hash: `{}`\n\n導入step: {}件。Capability不足: {}件。\n\n差分・承認範囲・復旧計画はprepared-change.jsonに保存しています。未取得の実構成はUnknownです。GCP PostgreSQL、AWS PostgreSQL/MySQLの限定native executorを実装しています。この計画生成は外部変更を実行しません。recoverは現在desiredを保つ限定修復です。旧Allowの復元や任意の差分補償は未実装です。適用・保護成立を表しません。\n\n順序はplan.jsonへ記録しています。復旧経路の準備を確認し、アプリ・pool・jobを切り替える前に旧経路を閉じません。\n",
                plan.policy_revision_hash,
                plan.plan_hash,
                plan.steps.len(),
                plan.capability_gaps.len()
            );
            report.push_str(&format!(
                "\n対応stepのない必須効果: {}件。\n",
                plan.required_effect_gaps.len()
            ));
            crate::qualification_cli::append_report(&mut report, &intent_qualification)?;
            run.write_bytes("report.md", report.as_bytes())?;
            run.finish(RunStatus::Complete)?;
            println!(
                "operation_only=true protection_evaluated=false execution_available=false static_qualified={} intent_gaps={} steps={} capability_gaps={} required_effect_gaps={}",
                intent_qualification.is_qualified(),
                crate::qualification_cli::gap_count(&intent_qualification),
                plan.steps.len(),
                plan.capability_gaps.len(),
                plan.required_effect_gaps.len()
            );
            // Three is incomplete readiness, not a provider failure or protection pass.
            Ok(3)
        }
        GuardCommand::Approve {
            plan_run,
            ledger,
            approval_id,
            approver,
            execution_identity,
            valid_for,
            recovery_for,
        } => {
            let change = load_change_run(&plan_run)?;
            let intent_qualification = crate::qualification_cli::report(&change)?;
            crate::qualification_cli::require(&intent_qualification)?;
            let at = now();
            let grant = approval::issue(
                &change,
                &approval_id,
                &approver,
                &execution_identity,
                at.checked_add(valid_for).ok_or(GuardError::ConfigInvalid)?,
                at.checked_add(recovery_for)
                    .ok_or(GuardError::ConfigInvalid)?,
                at,
            )?;
            let mut store = OperationStore::open(&ledger)?;
            store.register_change(&change)?;
            store.register_approval(&change, &grant)?;
            println!("{}",serde_json::to_string_pretty(&serde_json::json!({"operation_only":true,"native_dispatch_available":false,"approval":grant})).map_err(|_|GuardError::StorageFailed)?);
            Ok(0)
        }
        GuardCommand::Begin {
            ledger,
            approval_id,
            operation_id,
            request_id,
            execution_identity,
            expected_desired_head,
        } => {
            let mut store = OperationStore::open_existing(&ledger)?;
            let grant = store.load_approval(&approval_id)?;
            let change = store.load_change(&grant.change_hash)?;
            let intent_qualification = crate::qualification_cli::report(&change)?;
            crate::qualification_cli::require(&intent_qualification)?;
            let operation = store.begin(&BeginRequest {
                request_id,
                operation_id,
                change_hash: grant.change_hash,
                approval_id,
                expected_desired_head,
                execution_identity,
                now: now(),
            })?;
            show_operation(&operation)
        }
        GuardCommand::Resume {
            ledger,
            operation,
            expected_version,
            execution_identity,
        } => {
            let mut store = OperationStore::open_existing(&ledger)?;
            let mut executor = UnavailableExecutor { execution_identity };
            let result = orchestrator::resume(
                &mut store,
                &operation,
                expected_version,
                &store::new_run_id(),
                &mut executor,
            )?;
            show_operation(&result)
        }
        GuardCommand::Status {
            ledger,
            operation,
            native_state_run,
            archive,
            requests,
        } => {
            let context_change = crate::observation_cli::load_context(&ledger, &operation)?;
            if context_change.policy.schema_version == 2 {
                let source = crate::observation_cli::state(
                    &ledger,
                    &operation,
                    archive.as_deref(),
                    &requests,
                )?;
                let store = OperationStore::open_existing(&ledger)?;
                let op = match store.get(&operation) {
                    Ok(op) => Some(op),
                    Err(crate::core::operation::StoreError::NotFound) => None,
                    Err(e) => return Err(e.into()),
                };
                let native_observation = native_state_run
                    .as_deref()
                    .map(|p| {
                        crate::native_cli::load_any_state_record(&context_change, &operation, p)
                    })
                    .transpose()?;
                let output = if let Some(op) = op {
                    serde_json::json!({"operation_only":!source.effective.protection_evaluated,"native_dispatch_available":false,"operation_scope_completed":op.state==ExecutionState::Completed,"protection_evaluated":source.effective.protection_evaluated,"native_queries_performed":false,"local_evidence_rechecked":true,"operation":op,"desired":context_change.policy,"effective":source.effective,"source_coverage":source.source_coverage,"native_step_evidence":source.native_step_evidence,"admission_reads":source.admission_reads,"native_observation":native_observation,"steps":store.steps(&operation)?,"events":store.events(&operation)?})
                } else {
                    if native_observation.is_some() {
                        return Err(GuardError::EvidenceIncompatible);
                    }
                    let session = crate::evidence_store::EvidenceStore::open_existing(&ledger)?
                        .session(&operation)?;
                    serde_json::json!({"context_kind":"observation_only","native_dispatch_available":false,"operation_scope_completed":false,"protection_evaluated":source.effective.protection_evaluated,"native_queries_performed":false,"local_evidence_rechecked":true,"session":session,"desired":context_change.policy,"effective":source.effective,"source_coverage":source.source_coverage,"native_step_evidence":source.native_step_evidence,"admission_reads":source.admission_reads})
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).map_err(|_| GuardError::StorageFailed)?
                );
                return Ok(0);
            }
            if archive.is_some() || !requests.is_empty() {
                return Err(GuardError::EvidenceIncompatible);
            }
            let store = OperationStore::open_existing(&ledger)?;
            let result = store.get(&operation)?;
            let events = store.events(&operation)?;
            let change = store.load_change(&result.change_hash)?;
            let effective = unknown_state(&change)?;
            let native_observation = native_state_run
                .as_deref()
                .map(|path| crate::native_cli::load_any_state_record(&change, &operation, path))
                .transpose()?;
            let native_observation_fresh = native_observation.as_ref().is_some_and(|v| {
                v.pointer("/observation/observed_at")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|at| at <= now() && now().saturating_sub(at) <= 60)
            });
            let output = serde_json::json!({"operation_only":true,"native_dispatch_available":false,"protection_evaluated":false,"operation":result,"desired":change.policy,"effective":effective,"native_observation":native_observation,"native_observation_fresh":native_observation_fresh,"lifecycle":change.lifecycle,"steps":store.steps(&operation)?,"events":events,"approval_revoked":events.iter().any(|e|e.event==EventKind::ApprovalCancelled)});
            println!(
                "{}",
                serde_json::to_string_pretty(&output).map_err(|_| GuardError::StorageFailed)?
            );
            Ok(0)
        }
        GuardCommand::Cancel {
            ledger,
            operation,
            expected_version,
        } => {
            let mut store = OperationStore::open_existing(&ledger)?;
            show_operation(&store.set_state(
                &operation,
                expected_version,
                ExecutionState::Cancelled,
                now(),
            )?)
        }
        GuardCommand::RevokeApproval {
            ledger,
            approval_id,
        } => {
            OperationStore::open_existing(&ledger)?.cancel_approval(&approval_id, now())?;
            println!("operation_only=true approval_revoked=true native_dispatch_available=false");
            Ok(0)
        }
    }
}
