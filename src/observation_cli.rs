//! Source-bound CLI composition. Read-only sessions cannot become operations or
//! approvals. Only observe's explicit opt-in may start native source reads.
use crate::{
    adapters::{
        evidence::RunEvidenceArchive,
        source::{
            self,
            gce_host::{CollectorConfig, SshAccess},
        },
    },
    config::{GuardError, read_bounded, read_json},
    core::{admission::*, evidence::*, ports::EvidenceLedger, source::RegisteredSourceSnapshot},
    domain::now,
    evidence_store::{EvidenceStore, ObservationRequestSpec},
    operation_store::OperationStore,
    store::{RunStatus, RunWriter},
};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

#[derive(Debug, clap::Args)]
pub struct SourceRegisterArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    snapshot: PathBuf,
    #[arg(long)]
    expected_digest: Option<String>,
}
#[derive(Debug, clap::Args)]
pub struct ObservationStartArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    plan_run: PathBuf,
    #[arg(long)]
    context: String,
}
#[derive(Debug, clap::Args)]
pub struct ObservePlanArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    context: String,
    #[arg(long)]
    source: String,
    #[arg(long)]
    collector_config: PathBuf,
    #[arg(long)]
    out: PathBuf,
}
#[derive(Debug, clap::Args)]
pub struct ObserveArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    context: String,
    #[arg(long)]
    source: String,
    #[arg(long)]
    request_id: String,
    #[arg(long)]
    cases: PathBuf,
    #[arg(long)]
    archive: PathBuf,
    #[arg(long, required_unless_present = "aws_runtime_pool_witness")]
    identity_file: Option<PathBuf>,
    #[arg(long, required_unless_present = "aws_runtime_pool_witness")]
    work_directory: Option<PathBuf>,
    #[arg(long)]
    allow_native_read: bool,
    #[arg(long, requires = "runtime_collector_config")]
    runtime_witnesses: Option<PathBuf>,
    #[arg(long)]
    runtime_collector_config: Option<PathBuf>,
    #[arg(long, requires_all = ["aws_runtime_database_witness", "runtime_collector_config"],
        conflicts_with_all = ["runtime_witnesses", "allow_native_read", "identity_file", "work_directory"])]
    aws_runtime_pool_witness: Option<PathBuf>,
    #[arg(long, requires = "aws_runtime_pool_witness")]
    aws_runtime_database_witness: Option<PathBuf>,
}
#[derive(Debug, clap::Args)]
pub struct ObservationIssueArgs {
    #[arg(long)]
    ledger: PathBuf,
    #[arg(long)]
    context: String,
    #[arg(long)]
    source: String,
    #[arg(long)]
    request_id: String,
    #[arg(long)]
    cases: PathBuf,
}
#[derive(Debug, clap::Args)]
pub struct ObservationCoverageArgs {
    #[arg(long)]
    policy: PathBuf,
}
fn print(value: &impl serde::Serialize) -> Result<(), GuardError> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|_| GuardError::StorageFailed)?
    );
    Ok(())
}
pub(crate) fn register(args: SourceRegisterArgs) -> Result<i32, GuardError> {
    let snapshot: RegisteredSourceSnapshot = read_json(&args.snapshot, 65536)?;
    snapshot.validate().map_err(|_| GuardError::ConfigInvalid)?;
    let digest = EvidenceStore::open(&args.ledger)?
        .register_source(&snapshot, args.expected_digest.as_deref())?;
    print(
        &serde_json::json!({"registered_snapshot_digest":digest,"registration_id":snapshot.registration_id(),"source_verified":false,"native_queries_performed":false,"native_dispatch_available":false,"policy_updated":false}),
    )?;
    Ok(0)
}
pub(crate) fn start(args: ObservationStartArgs) -> Result<i32, GuardError> {
    let change = crate::guard_cli::load_change_run(&args.plan_run)?;
    if change.policy.schema_version != 2 {
        return Err(GuardError::EvidenceIncompatible);
    }
    let session =
        EvidenceStore::open(&args.ledger)?.start_session(&change, &args.context, now())?;
    print(
        &serde_json::json!({"context_kind":"observation_only","session":session,"native_queries_performed":false,"native_dispatch_available":false,"forward_approval_created":false,"desired_head_updated":false}),
    )?;
    Ok(0)
}
pub(crate) fn coverage(args: ObservationCoverageArgs) -> Result<i32, GuardError> {
    let p = crate::guard_cli::load_policy(&args.policy)?;
    let coverage = source::support::for_policy(&p).map_err(|_| GuardError::EvidenceIncompatible)?;
    print(
        &serde_json::json!({"schema_version":2,"source_coverage":coverage,"source_verified":false,"native_queries_performed":false,"native_dispatch_available":false}),
    )?;
    Ok(0)
}
pub(crate) fn plan(args: ObservePlanArgs) -> Result<i32, GuardError> {
    let mut ledger = EvidenceStore::open_existing(&args.ledger)?;
    let change = ledger.context_change(&args.context)?;
    let source = change
        .policy
        .source_bindings
        .iter()
        .find(|s| s.source_id == args.source)
        .ok_or(AdmissionError::ScopeMismatch)?;
    let coverage = source::support::for_policy(&change.policy)
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    if !coverage
        .iter()
        .any(|r| r.source_id == args.source && r.collector_implemented)
    {
        print(
            &serde_json::json!({"source_coverage":coverage,"native_queries_performed":false,"admitted":false}),
        )?;
        return Err(GuardError::UnsupportedTarget);
    }
    let snapshot = ledger.source_snapshot(&source.registration_id)?;
    if !snapshot
        .matches_binding(source)
        .map_err(|_| GuardError::ConfigInvalid)?
    {
        return Err(AdmissionError::TrustChanged.into());
    }
    match &snapshot {
        RegisteredSourceSnapshot::Gce(_) => source::gce_host::validate_registration(&snapshot)?,
        RegisteredSourceSnapshot::Aws(s) => source::aws_host::validate_registration(s)?,
    }
    let bytes = read_bounded(&args.collector_config, 65536)?;
    if crate::config::hash_bytes(&bytes) != snapshot.collector_config_digest() {
        return Err(AdmissionError::Integrity.into());
    }
    enum Config {
        Gce(CollectorConfig),
        Aws(source::aws_host::AwsCollectorConfig),
    }
    let config = match &snapshot {
        RegisteredSourceSnapshot::Gce(_) => {
            Config::Gce(serde_json::from_slice(&bytes).map_err(|_| GuardError::ConfigInvalid)?)
        }
        RegisteredSourceSnapshot::Aws(_) => {
            Config::Aws(serde_json::from_slice(&bytes).map_err(|_| GuardError::ConfigInvalid)?)
        }
    };
    let plan = match &config {
        Config::Gce(c) => source::requests::plan(&change, &args.source, c, now())?,
        Config::Aws(c) => source::requests::plan_aws(&change, &args.source, c, now())?,
    };
    // Validate fixed cases using the same collector allowlist, without issuing
    // a nonce or writing a request. This synthetic request is never persisted,
    // admitted, exported as an issued request, or sent to a source.
    for cases in &plan.batches {
        let request = ObservationRequest {
            schema_version: 1,
            request_id: "offline-validation".into(),
            nonce: "0".repeat(64),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            change_hash: change.change_hash.clone(),
            operation_id: args.context.clone(),
            source: source.clone(),
            source_trust_epoch: snapshot.trust_epoch(),
            evaluation_contract: EvaluationContract::SourceBoundV2,
            collector_build_id: snapshot.collector_build_id().to_owned(),
            verifier_build_id: crate::BUILD_ID.into(),
            issued_at: 1,
            expires_at: 121,
            cases: cases.clone(),
        };
        validate_request_scope(&request, &change)?;
        let issued = IssuedObservation {
            request,
            snapshot: snapshot.clone(),
        };
        validate_source_actor_binding(&issued, &change)?;
        match &config {
            Config::Gce(c) => c.validate_request(&issued)?,
            Config::Aws(c) => c.validate_request(&issued)?,
        }
    }
    let mut out = RunWriter::create_for_config(
        &args.out,
        &change.policy.policy_id,
        &change.policy,
        "guard-observation-plan",
        8 * 1024 * 1024,
        true,
    )?;
    out.write_json("case-plan.json", &plan)?;
    out.write_json("source-coverage.json", &coverage)?;
    for (index, batch) in plan.batches.iter().enumerate() {
        out.write_json(&format!("cases-{}.json", index + 1), batch)?;
    }
    out.finish(RunStatus::Complete)?;
    print(
        &serde_json::json!({"batches":plan.batches.len(),"uncollected_required_effects":plan.uncollected_required_effects,"source_verified":false,"native_queries_performed":false,"native_dispatch_available":false,"config_mysql_producer_enabled":matches!(&config,Config::Aws(c) if c.mysql.is_some()),"config_postgres_producer_enabled":(matches!(&config,Config::Gce(c) if c.postgres.is_some()) || matches!(&config,Config::Aws(c) if c.postgres.is_some()))}),
    )?;
    Ok(0)
}
fn private_directory(path: &Path) -> Result<(), GuardError> {
    if path.try_exists().map_err(|_| GuardError::StorageFailed)? {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| GuardError::StorageFailed)
}
pub(crate) fn observe(args: ObserveArgs, cancel: CancellationToken) -> Result<i32, GuardError> {
    // The existing guard API is synchronous and is also called from Tokio main.
    // Keep its bounded native read on an owned runtime, without nested block_on.
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| GuardError::OperationFailed)?
            .block_on(observe_async(args, cancel))
    })
    .join()
    .map_err(|_| GuardError::OperationFailed)?
}

/// Allocate the challenge before app checkout and witness production.
pub(crate) fn issue(args: ObservationIssueArgs) -> Result<i32, GuardError> {
    let mut ledger = EvidenceStore::open_existing(&args.ledger)?;
    let spec = ObservationRequestSpec {
        request_id: args.request_id,
        operation_id: args.context,
        source_id: args.source,
        ttl_seconds: MAX_REQUEST_TTL_SECONDS,
        cases: read_json(&args.cases, MAX_REQUEST_BYTES)?,
    };
    if spec.cases.is_empty() || spec.cases.len() > MAX_CASES_PER_SOURCE {
        return Err(GuardError::LimitExceeded);
    }
    let issued = ledger.issue_request(&spec, now())?;
    print(&issued)?;
    Ok(0)
}
async fn observe_async(args: ObserveArgs, cancel: CancellationToken) -> Result<i32, GuardError> {
    // This check precedes ledger/archive/key/tool IO and nonce allocation.
    let aws_runtime = args.aws_runtime_pool_witness.is_some();
    if !args.allow_native_read && !aws_runtime {
        return Err(GuardError::PermissionRequired);
    }
    if args.runtime_collector_config.is_some() != (aws_runtime || args.runtime_witnesses.is_some())
    {
        return Err(GuardError::ConfigInvalid);
    }
    if cancel.is_cancelled() {
        return Err(GuardError::Cancelled);
    }
    let mut ledger = EvidenceStore::open_existing(&args.ledger)?;
    let change = ledger.context_change(&args.context)?;
    let coverage =
        source::support::for_policy(&change.policy).map_err(|_| GuardError::ConfigInvalid)?;
    if !coverage
        .iter()
        .any(|r| r.source_id == args.source && r.collector_implemented)
    {
        print(
            &serde_json::json!({"source_coverage":coverage,"native_queries_performed":false,"admitted":false,"native_dispatch_available":false}),
        )?;
        return Err(GuardError::UnsupportedTarget);
    }
    let cases: Vec<RequestedCase> = read_json(&args.cases, MAX_REQUEST_BYTES)?;
    if cases.is_empty() || cases.len() > MAX_CASES_PER_SOURCE {
        return Err(GuardError::LimitExceeded);
    }
    let existing = match ledger.issued(&args.request_id) {
        Ok(i) => Some(i),
        Err(AdmissionError::NotFound) => None,
        Err(e) => return Err(e.into()),
    };
    let issued = if let Some(i) = existing {
        if i.request.operation_id != args.context
            || i.request.source.source_id != args.source
            || i.request.cases != cases
            || i.request.change_hash != change.change_hash
        {
            return Err(AdmissionError::Conflict.into());
        }
        ledger.ensure_current(&i, now())?;
        i
    } else if aws_runtime {
        return Err(AdmissionError::NotFound.into());
    } else {
        ledger.issue_request(
            &ObservationRequestSpec {
                request_id: args.request_id.clone(),
                operation_id: args.context.clone(),
                source_id: args.source.clone(),
                ttl_seconds: MAX_REQUEST_TTL_SECONDS,
                cases,
            },
            now(),
        )?
    };
    match ledger.admission(&args.request_id) {
        Ok(receipt) => {
            validate_receipt(&issued, &receipt, now())?;
            let archive = RunEvidenceArchive::open(&args.archive)?;
            let state = source::state::read_local(
                &mut ledger,
                &archive,
                &change,
                &args.context,
                std::slice::from_ref(&args.request_id),
                now(),
            )?;
            let current = state.admission_reads.iter().all(|r| r.current);
            print(
                &serde_json::json!({"admitted":true,"current_evidence_usable":current,"reused_original_admission":true,"native_queries_performed":false,"native_dispatch_available":false,"admission":receipt,"state":state}),
            )?;
            return Ok(
                if current && state.effective.all_required_effects_satisfied {
                    0
                } else {
                    3
                },
            );
        }
        Err(AdmissionError::NotFound) => {}
        Err(e) => return Err(e.into()),
    }
    private_directory(&args.archive)?;
    let mut archive = RunEvidenceArchive::open(&args.archive)?;
    let receipt = if let (Some(pool), Some(database)) = (
        args.aws_runtime_pool_witness.as_deref(),
        args.aws_runtime_database_witness.as_deref(),
    ) {
        let config = args
            .runtime_collector_config
            .as_deref()
            .ok_or(GuardError::ConfigInvalid)?;
        let received_at = now();
        let sent_at = issued
            .request
            .issued_at
            .max(received_at.saturating_sub(MAX_CAPTURE_SECONDS));
        let window = CaptureWindow {
            sent_at,
            received_at,
            elapsed_millis: received_at.saturating_sub(sent_at) * 1000,
        };
        let mut capture = source::aws_runtime_cutover::AwsPostgresRuntimeCapture::corroborate(
            &issued,
            &change,
            &read_bounded(config, 65536)?,
            &read_bounded(pool, 65536)?,
            &read_bounded(database, 65536)?,
            window,
            received_at,
        )?;
        if cancel.is_cancelled() {
            return Err(GuardError::Cancelled);
        }
        accept_evidence(
            &mut ledger,
            &mut archive,
            &mut capture.verifier,
            &args.request_id,
            &capture.bundle,
            &capture.payloads,
            capture.window,
            &crate::adapters::evidence::SystemEvidenceClock,
        )?
    } else {
        let work_directory = args.work_directory.ok_or(GuardError::ConfigInvalid)?;
        private_directory(&work_directory)?;
        let access = SshAccess {
            identity_file: args.identity_file.ok_or(GuardError::ConfigInvalid)?,
            work_directory,
        };
        match &issued.snapshot {
            RegisteredSourceSnapshot::Gce(_) if args.runtime_witnesses.is_some() => {
                let config = read_bounded(
                    args.runtime_collector_config
                        .as_deref()
                        .ok_or(GuardError::ConfigInvalid)?,
                    65536,
                )?;
                let witnesses = read_bounded(
                    args.runtime_witnesses
                        .as_deref()
                        .ok_or(GuardError::ConfigInvalid)?,
                    65536,
                )?;
                let capture = source::gce_host::capture_gce_source(&issued, &access, &cancel, true)
                    .await?
                    .corroborate_runtime(&issued, &config, &witnesses, now())?;
                if cancel.is_cancelled() {
                    return Err(GuardError::Cancelled);
                }
                source::gce_host::admit_gce_capture(
                    &mut ledger,
                    &mut archive,
                    &args.request_id,
                    capture,
                )?
            }
            RegisteredSourceSnapshot::Gce(_) => {
                source::gce_host::capture_and_admit_gce(
                    &mut ledger,
                    &mut archive,
                    &args.request_id,
                    &access,
                    &cancel,
                    true,
                )
                .await?
            }
            RegisteredSourceSnapshot::Aws(_) => {
                if args.runtime_witnesses.is_some() {
                    return Err(GuardError::UnsupportedTarget);
                }
                source::aws_host::capture_and_admit_aws(
                    &mut ledger,
                    &mut archive,
                    &args.request_id,
                    &access,
                    &cancel,
                    true,
                )
                .await?
            }
        }
    };
    let state = source::state::read_local(
        &mut ledger,
        &archive,
        &change,
        &args.context,
        std::slice::from_ref(&args.request_id),
        now(),
    )?;
    print(
        &serde_json::json!({"admitted":true,"reused_original_admission":false,"native_queries_performed":!aws_runtime,"native_dispatch_available":false,"admission":receipt,"state":state}),
    )?;
    Ok(if state.effective.all_required_effects_satisfied {
        0
    } else {
        3
    })
}
pub(crate) fn load_context(
    path: &Path,
    id: &str,
) -> Result<crate::core::change::PreparedChange, GuardError> {
    let ops = OperationStore::open_existing(path)?;
    match ops.get(id) {
        Ok(op) => Ok(ops.load_change(&op.change_hash)?),
        Err(crate::core::operation::StoreError::NotFound) => {
            drop(ops);
            Ok(EvidenceStore::open_existing(path)?.context_change(id)?)
        }
        Err(e) => Err(e.into()),
    }
}
pub(crate) fn state(
    path: &Path,
    context: &str,
    archive: Option<&Path>,
    requests: &[String],
) -> Result<source::state::SourceStateReport, GuardError> {
    let change = load_context(path, context)?;
    if change.policy.schema_version != 2 {
        return Err(GuardError::EvidenceIncompatible);
    }
    if let Some(root) = archive {
        let mut ledger = EvidenceStore::open_existing(path)?;
        let archive = RunEvidenceArchive::open(root)?;
        Ok(source::state::read_local(
            &mut ledger,
            &archive,
            &change,
            context,
            requests,
            now(),
        )?)
    } else {
        if !requests.is_empty() {
            return Err(GuardError::ConfigInvalid);
        }
        Ok(source::state::empty(&change, context, now())?)
    }
}
