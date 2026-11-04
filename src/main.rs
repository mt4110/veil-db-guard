use clap::{Parser, Subcommand, ValueEnum};
use std::{collections::BTreeMap, path::PathBuf};
use tokio_util::sync::CancellationToken;
use veil_db_guard::{
    config::*,
    domain::*,
    store::{self, RunStatus, RunWriter},
};

#[derive(Parser)]
#[command(
    version,
    about = "Database access protection with approved, opt-in native changes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Fixed single-run collector protocol; installation is an operator action.
    #[command(hide = true)]
    SourceCollectorV1,
    /// Offline build/protocol information for a collector artifact.
    #[command(hide = true)]
    SourceBuildInfo,
    /// Unsigned bootstrap preview in an operator's already trusted local session.
    #[command(hide = true)]
    SourceContextV1 {
        #[arg(long)]
        allow_local_context_read: bool,
    },
    /// Plan protection for an existing database from a common policy, offline.
    Guard {
        #[command(subcommand)]
        command: veil_db_guard::guard_cli::GuardCommand,
    },
    /// Verify declared GCP Cloud SQL PostgreSQL protection conditions.
    Gcp {
        #[command(subcommand)]
        command: veil_db_guard::gcp::cli::GcpCommand,
    },
    /// Build a local change plan; never contacts AWS or a database.
    Plan {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        snapshot: Option<PathBuf>,
        #[arg(long)]
        sandbox: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Read explicitly declared AWS targets, or normalize an offline CLI response fixture.
    Inspect {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, conflicts_with = "allow_aws_read")]
        fixture: Option<PathBuf>,
        #[arg(long)]
        aws_profile: Option<String>,
        #[arg(long)]
        allow_aws_read: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Run only an explicitly selected suite. Fixture replay cannot produce AWS evidence.
    Probe {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        experiment_plan: Option<PathBuf>,
        #[arg(long, value_enum)]
        suite: SuiteArg,
        #[arg(long)]
        source_id: String,
        #[arg(long)]
        allow_network: bool,
        #[arg(long)]
        allow_test_writes: bool,
        #[arg(long, conflicts_with_all=["local_lab", "fixture"], requires="allow_network")]
        allow_aws_read: bool,
        #[arg(long, conflicts_with = "fixture")]
        local_lab: bool,
        #[arg(long, conflicts_with = "allow_network")]
        fixture: Option<PathBuf>,
        #[arg(long, requires = "local_lab", conflicts_with = "fixture")]
        local_password_stdin: bool,
        #[arg(long)]
        aws_profile: Option<String>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Evaluate hash-verified local run directories. No network access.
    Report {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, num_args=1..)]
        evidence: Vec<PathBuf>,
        #[arg(long)]
        experiment_plan: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(Clone, ValueEnum)]
enum SuiteArg {
    Positive,
    AuthNegative,
    TlsNegative,
    DirectPath,
    Recovery,
    Performance,
}
impl From<SuiteArg> for Suite {
    fn from(v: SuiteArg) -> Self {
        match v {
            SuiteArg::Positive => Self::Positive,
            SuiteArg::AuthNegative => Self::AuthNegative,
            SuiteArg::TlsNegative => Self::TlsNegative,
            SuiteArg::DirectPath => Self::DirectPath,
            SuiteArg::Recovery => Self::Recovery,
            SuiteArg::Performance => Self::Performance,
        }
    }
}
fn validate_observation(
    o: &Observation,
    c: &TargetConfig,
    run: &store::Manifest,
) -> Result<(), GuardError> {
    let hash = |s: &str| s.len() == 64 && s.bytes().all(|x| x.is_ascii_hexdigit());
    if o.schema_version != 1
        || o.run_id != run.run_id
        || o.target_id != run.target_id
        || o.config_hash != run.config_hash
        || o.build_id != run.build_id
        || !hash(&o.build_id)
        || !safe_id(&o.case_id)
        || !safe_id(&o.attempt_id)
        || !safe_id(&o.verification_id)
        || !safe_id(&o.experiment_id)
        || !safe_id(&o.phase_id)
        || !safe_id(&o.configuration_epoch)
        || !safe_id(&o.path_id)
        || !safe_id(&o.source_id)
        || !hash(&o.config_hash)
        || (!o.snapshot_hash.is_empty() && !hash(&o.snapshot_hash))
        || o.requirement_ids.iter().any(|x| !safe_id(x))
        || o.evidence_refs.iter().any(|x| !hash(x))
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if o.path_id != "global"
        && !c
            .paths
            .iter()
            .any(|p| p.id == o.path_id && p.source_id == o.source_id)
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if let Some(d) = &o.details
        && (d.samples_ms.len() > c.limits.max_results
            || d.resolved_addresses.len() > 128
            || d.resolved_addresses
                .iter()
                .any(|s| s.parse::<std::net::SocketAddr>().is_err())
            || d.retained_schema.as_ref().is_some_and(|s| !sql_id(s))
            || d.workload_id.as_ref().is_some_and(|s| !safe_id(s)))
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    veil_db_guard::evaluator::validate_observation_protocol(o, c)
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    Ok(())
}
fn print_summary(writer: &RunWriter, code: i32) {
    println!(
        "{}",
        serde_json::json!({"run_id":writer.manifest.run_id,"operation":writer.manifest.operation,
        "operation_only":writer.manifest.operation_only,"exit_code":code,"build_id":veil_db_guard::BUILD_ID})
    );
}
async fn inventory_until(
    c: &TargetConfig,
    profile: Option<String>,
    cancel: CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<InventorySnapshot, GuardError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(GuardError::TimedOut);
    }
    tokio::time::timeout_at(
        deadline,
        veil_db_guard::aws_inventory::inspect(
            c,
            &veil_db_guard::aws_inventory::InspectOptions {
                aws_profile: profile,
                allow_aws_read: true,
            },
            cancel,
        ),
    )
    .await
    .map_err(|_| GuardError::TimedOut)?
}
async fn execute(cli: Cli, cancel: CancellationToken) -> Result<i32, GuardError> {
    match cli.command {
        Command::SourceCollectorV1 => {
            match veil_db_guard::adapters::source::run_collector_stdio(cancel).await {
                Ok(()) => Ok(0),
                Err(error) => {
                    eprintln!("{error}");
                    Ok(2)
                }
            }
        }
        Command::SourceBuildInfo => {
            println!(
                "{}",
                serde_json::json!({"build_id":veil_db_guard::BUILD_ID,"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
                "source_profile":"gce-host-network-root-v1","source_profiles":["gce-host-network-root-v1","aws-ec2-host-network-root-v1"],"source_registration_schemas":{"gce":2,"aws":1},"collector_supported":cfg!(target_os="linux"),"source_registration_schema":2,"collector_protocol":1,"observation_wire":1})
            );
            Ok(0)
        }
        Command::SourceContextV1 {
            allow_local_context_read,
        } => {
            match veil_db_guard::adapters::source::read_local_context(
                allow_local_context_read,
                &cancel,
            )
            .await
            {
                Ok(context) => {
                    let digest = context
                        .digest()
                        .map_err(|_| GuardError::EvidenceIncompatible)?;
                    println!(
                        "{}",
                        serde_json::json!({"source_verified":false,"bootstrap_only":true,"context":context,"context_digest":digest,"aws_context_digest":context.aws_digest().map_err(|_| GuardError::EvidenceIncompatible)?})
                    );
                    Ok(0)
                }
                Err(error) => {
                    eprintln!("{error}");
                    Ok(2)
                }
            }
        }
        Command::Guard { command } => {
            veil_db_guard::guard_cli::execute_with_cancel(command, cancel)
        }
        Command::Gcp { command } => veil_db_guard::gcp::cli::execute(command, cancel).await,
        Command::Plan {
            config,
            snapshot,
            sandbox,
            out,
        } => {
            let c = load_config(&config)?;
            if sandbox {
                veil_db_guard::planner::validate_sandbox(&c)?;
            }
            let s: Option<InventorySnapshot> = snapshot
                .as_ref()
                .map(|p| read_json(p, c.limits.max_bytes))
                .transpose()?;
            let plan = veil_db_guard::planner::plan(&c, s.as_ref())?;
            let mut run = RunWriter::create(&out, &c, "plan", true)?;
            run.write_json("plan.json", &plan)?;
            if sandbox {
                run.write_bytes(
                    "sandbox.yaml",
                    veil_db_guard::planner::sandbox_template(&c).as_bytes(),
                )?;
                run.write_bytes(
                    "bootstrap.sql",
                    veil_db_guard::planner::bootstrap_sql(&c).as_bytes(),
                )?;
            }
            run.finish(RunStatus::Complete)?;
            print_summary(&run, 0);
            Ok(0)
        }
        Command::Inspect {
            config,
            fixture,
            aws_profile,
            allow_aws_read,
            out,
        } => {
            let c = load_config(&config)?;
            if fixture.is_none() && !allow_aws_read {
                return Err(GuardError::PermissionRequired);
            }
            let mut run = RunWriter::create(&out, &c, "inspect", true)?;
            let s = if let Some(path) = fixture {
                let responses: BTreeMap<String, serde_json::Value> =
                    read_json(&path, c.limits.max_bytes)?;
                veil_db_guard::aws_inventory::normalize(&c, &responses)?
            } else {
                veil_db_guard::aws_inventory::inspect(
                    &c,
                    &veil_db_guard::aws_inventory::InspectOptions {
                        aws_profile,
                        allow_aws_read,
                    },
                    cancel.clone(),
                )
                .await?
            };
            run.write_json("snapshot.json", &s)?;
            run.finish(if cancel.is_cancelled() {
                RunStatus::Cancelled
            } else {
                RunStatus::Complete
            })?;
            let code = if cancel.is_cancelled() { 130 } else { 0 };
            print_summary(&run, code);
            Ok(code)
        }
        Command::Probe {
            config,
            snapshot,
            experiment_plan,
            suite,
            source_id,
            allow_network,
            allow_test_writes,
            allow_aws_read,
            local_lab,
            local_password_stdin,
            fixture,
            aws_profile,
            out,
        } => {
            let c = load_config(&config)?;
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(c.limits.total_timeout_ms);
            let offline_replay = fixture.is_some();
            let mut s: InventorySnapshot = read_json(&snapshot, c.limits.max_bytes)?;
            validate_snapshot(&c, &s)?;
            let capture_plan: Option<ExperimentPlan> = experiment_plan
                .as_ref()
                .map(|p| read_json(p, c.limits.max_bytes))
                .transpose()?;
            if let Some(plan) = &capture_plan {
                veil_db_guard::evaluator::validate_experiment_plan(&c, plan)
                    .map_err(|_| GuardError::ConfigInvalid)?;
                let protocol = plan.protocol.as_ref().ok_or(GuardError::ConfigInvalid)?;
                let phase = protocol
                    .phase_contracts
                    .iter()
                    .find(|p| p.phase_id == c.phase_id)
                    .ok_or(GuardError::ConfigInvalid)?;
                if plan.schema_version != 1
                    || plan.experiment_id != c.experiment_id
                    || plan.profile != c.assessment_profile
                    || config_hash(&phase.config) != config_hash(&c)
                    || phase.configuration_epoch != c.configuration_epoch
                    || protocol.planned_at > now()
                    || now() < phase.starts_at
                    || now() > phase.ends_at
                {
                    return Err(GuardError::ConfigInvalid);
                }
            }
            if !c.sources.iter().any(|x| x.id == source_id) {
                return Err(GuardError::ConfigInvalid);
            }
            if fixture.is_none() && !allow_network {
                return Err(GuardError::PermissionRequired);
            }
            if fixture.is_none() && !local_lab && !allow_aws_read {
                return Err(GuardError::PermissionRequired);
            }
            if local_lab && !local_password_stdin {
                return Err(GuardError::PermissionRequired);
            }
            let mut run = RunWriter::create(&out, &c, "probe", true)?;
            if fixture.is_none() && !local_lab {
                // A file checksum does not authenticate AWS endpoint ownership. Refresh
                // declared targets through the authenticated read adapter before signing.
                let fresh =
                    inventory_until(&c, aws_profile.clone(), cancel.clone(), deadline).await?;
                validate_snapshot(&c, &fresh)?;
                if fresh
                    .retrievals
                    .iter()
                    .any(|r| r.status != RetrievalStatus::Complete)
                    || fresh.db.as_ref().map(|x| &x.endpoint) != s.db.as_ref().map(|x| &x.endpoint)
                    || fresh.proxy.as_ref().map(|x| &x.endpoint)
                        != s.proxy.as_ref().map(|x| &x.endpoint)
                {
                    return Err(GuardError::TargetMismatch);
                }
                s = fresh;
            }
            run.write_json("snapshot.json", &s)?;
            if let Some(plan) = &capture_plan {
                run.write_json("experiment-plan.json", plan)?;
                run.write_json("snapshot.before.json", &s)?;
            }
            let mut observations = if let Some(path) = fixture {
                let mut data: Vec<Observation> = read_json(&path, c.limits.max_bytes)?;
                if data.len() > c.limits.max_results {
                    return Err(GuardError::LimitExceeded);
                }
                for o in &mut data {
                    // Offline replay is always fixture evidence, independent of labels in input.
                    o.evidence_kind = EvidenceKind::LocalFixture;
                    o.run_id = run.manifest.run_id.clone();
                    o.attempt_id = format!("{}-{}", run.manifest.run_id, o.case_id);
                    o.build_id = veil_db_guard::BUILD_ID.into();
                    o.config_hash = config_hash(&c);
                    o.snapshot_hash = snapshot_hash(&s);
                    o.observed_at = now();
                    o.target_id = c.target.id.clone();
                    o.experiment_id = c.experiment_id.clone();
                    o.phase_id = c.phase_id.clone();
                    o.configuration_epoch = c.configuration_epoch.clone();
                    o.assessment_profile = c.assessment_profile;
                    o.evidence_refs.clear();
                    o.source_verification = SourceVerification::Declared;
                    if let Some(details) = &mut o.details {
                        details.protocol = None;
                    }
                    validate_observation(o, &c, &run.manifest)?;
                }
                data
            } else {
                let options = veil_db_guard::probe::ProbeOptions {
                    run_id: run.manifest.run_id.clone(),
                    source_id,
                    allow_network,
                    allow_test_writes,
                    local_lab,
                    aws_profile: aws_profile.clone(),
                };
                if local_lab {
                    use tokio::io::AsyncReadExt;
                    let mut secret = Vec::new();
                    let mut stdin = tokio::io::stdin().take(1025);
                    tokio::select! {
                        _ = cancel.cancelled() => return Err(GuardError::Cancelled),
                        result = tokio::time::timeout_at(deadline.min(tokio::time::Instant::now()+std::time::Duration::from_millis(c.limits.connect_timeout_ms)),stdin.read_to_end(&mut secret)) => {
                            result.map_err(|_| GuardError::TimedOut)?.map_err(|_| GuardError::OperationFailed)?;
                        }
                    }
                    if secret.is_empty() || secret.len() > 1024 {
                        return Err(GuardError::ConfigInvalid);
                    }
                    let secret =
                        String::from_utf8(secret).map_err(|_| GuardError::ConfigInvalid)?;
                    let provider = veil_db_guard::probe::auth::LocalPasswordProvider::new(
                        secret.trim_end_matches(['\r', '\n']).to_owned(),
                    );
                    veil_db_guard::probe::run_with_provider_until(
                        &c,
                        &s,
                        suite.into(),
                        &options,
                        cancel.clone(),
                        &provider,
                        deadline,
                    )
                    .await?
                } else {
                    veil_db_guard::probe::run_until(
                        &c,
                        &s,
                        suite.into(),
                        &options,
                        cancel.clone(),
                        deadline,
                    )
                    .await?
                }
            };
            let mut capture_incomplete = false;
            let mut after_capture = None;
            if capture_plan.is_some()
                && allow_aws_read
                && !local_lab
                && !offline_replay
                && !cancel.is_cancelled()
            {
                match inventory_until(&c, aws_profile.clone(), cancel.clone(), deadline).await {
                    Ok(after) => {
                        validate_snapshot(&c, &after)?;
                        run.write_json("snapshot.after.json", &after)?;
                        after_capture = Some(after);
                    }
                    Err(_) => capture_incomplete = true,
                }
            } else if capture_plan.is_some() {
                capture_incomplete = true;
            }
            let snapshot_ref = run
                .manifest
                .artifacts
                .iter()
                .find(|a| a.name == "snapshot.json")
                .ok_or(GuardError::StorageFailed)?
                .sha256
                .clone();
            for observation in &mut observations {
                observation.evidence_refs.push(snapshot_ref.clone());
                if let Some(plan) = &capture_plan {
                    let phase = plan
                        .protocol
                        .as_ref()
                        .and_then(|p| p.phase_contracts.iter().find(|p| p.phase_id == c.phase_id))
                        .ok_or(GuardError::ConfigInvalid)?;
                    let before_hash = run
                        .manifest
                        .artifacts
                        .iter()
                        .find(|a| a.name == "snapshot.before.json")
                        .ok_or(GuardError::StorageFailed)?
                        .sha256
                        .clone();
                    observation.evidence_refs.push(before_hash.clone());
                    let after = after_capture.as_ref().map(|snapshot| {
                        let hash = run
                            .manifest
                            .artifacts
                            .iter()
                            .find(|a| a.name == "snapshot.after.json")
                            .expect("saved after snapshot")
                            .sha256
                            .clone();
                        observation.evidence_refs.push(hash.clone());
                        SnapshotEvidence {
                            reference_id: phase.after_snapshot_ref.clone(),
                            artifact_hash: hash,
                            snapshot: snapshot.clone(),
                        }
                    });
                    let protocol = observation
                        .details
                        .get_or_insert_with(ProbeDetails::default)
                        .protocol
                        .get_or_insert_with(ObservationProtocol::default);
                    protocol.plan_hash = veil_db_guard::evaluator::plan_hash(plan);
                    protocol.before = Some(SnapshotEvidence {
                        reference_id: phase.before_snapshot_ref.clone(),
                        artifact_hash: before_hash,
                        snapshot: s.clone(),
                    });
                    protocol.after = after;
                }
                observation.evidence_refs.sort();
                observation.evidence_refs.dedup();
                validate_observation(observation, &c, &run.manifest)?;
            }
            run.write_json("observations.json", &observations)?;
            let code = if cancel.is_cancelled() {
                130
            } else if capture_incomplete
                || observations
                    .iter()
                    .any(|o| o.execution != Execution::Completed)
            {
                3
            } else {
                0
            };
            run.finish(if code == 130 {
                RunStatus::Cancelled
            } else if code == 3 {
                RunStatus::Partial
            } else {
                RunStatus::Complete
            })?;
            print_summary(&run, code);
            Ok(code)
        }
        Command::Report {
            config,
            evidence,
            experiment_plan,
            out,
        } => {
            let c = load_config(&config)?;
            if evidence.len() > 128 {
                return Err(GuardError::LimitExceeded);
            }
            let plan: Option<ExperimentPlan> = experiment_plan
                .as_ref()
                .map(|p| read_json(p, c.limits.max_bytes))
                .transpose()?;
            if let Some(p) = &plan
                && p.protocol.is_some()
            {
                veil_db_guard::evaluator::validate_experiment_plan(&c, p)
                    .map_err(|_| GuardError::EvidenceIncompatible)?;
            }
            let mut observations: Vec<Observation> = vec![];
            let mut total_bytes = 0usize;
            let mut artifacts = std::collections::BTreeSet::new();
            let mut snapshots = std::collections::BTreeSet::new();
            let mut imported_snapshots = Vec::new();
            for path in evidence {
                let manifest = store::verify_run(&path, c.limits.max_bytes)?;
                if manifest.target_id != c.target.id {
                    return Err(GuardError::TargetMismatch);
                }
                total_bytes = total_bytes
                    .saturating_add(manifest.artifacts.iter().map(|a| a.bytes).sum::<usize>());
                if total_bytes > c.limits.max_bytes {
                    return Err(GuardError::LimitExceeded);
                }
                artifacts.extend(manifest.artifacts.iter().map(|a| a.sha256.clone()));
                for artifact in manifest.artifacts.iter().filter(|a| {
                    [
                        "snapshot.json",
                        "snapshot.before.json",
                        "snapshot.after.json",
                    ]
                    .contains(&a.name.as_str())
                }) {
                    let snapshot: InventorySnapshot =
                        store::read_artifact(&path, &manifest, &artifact.name, c.limits.max_bytes)?;
                    snapshots.insert(snapshot_hash(&snapshot));
                    imported_snapshots.push((artifact.sha256.clone(), snapshot));
                }
                if manifest
                    .artifacts
                    .iter()
                    .any(|a| a.name == "observations.json")
                {
                    let local_c: TargetConfig = store::read_artifact(
                        &path,
                        &manifest,
                        "config.normalized.json",
                        c.limits.max_bytes,
                    )?;
                    let data: Vec<Observation> = store::read_artifact(
                        &path,
                        &manifest,
                        "observations.json",
                        c.limits.max_bytes,
                    )?;
                    if observations.len().saturating_add(data.len()) > c.limits.max_results {
                        return Err(GuardError::LimitExceeded);
                    }
                    for o in &data {
                        validate_observation(o, &local_c, &manifest)?;
                    }
                    observations.extend(data);
                }
            }
            if observations.iter().any(|o| {
                o.evidence_refs.iter().any(|r| !artifacts.contains(r))
                    || (!o.snapshot_hash.is_empty() && !snapshots.contains(&o.snapshot_hash))
                    || !veil_db_guard::evaluator::validate_protocol_links(o, &imported_snapshots)
            }) {
                return Err(GuardError::EvidenceIncompatible);
            }
            let assessment =
                veil_db_guard::evaluator::evaluate(&c, &observations, plan.as_ref(), now());
            let mut run = RunWriter::create(&out, &c, "report", false)?;
            run.write_json("assessment.json", &assessment)?;
            run.write_bytes(
                "report.md",
                veil_db_guard::report::render_markdown(&assessment).as_bytes(),
            )?;
            run.finish(RunStatus::Complete)?;
            let code = veil_db_guard::report::exit_code(&assessment);
            print_summary(&run, code);
            Ok(code)
        }
    }
}
#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e)
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            let _ = e.print();
            return;
        }
        Err(_) => {
            eprintln!("{}", GuardError::ConfigInvalid);
            std::process::exit(2);
        }
    };
    let cancel = CancellationToken::new();
    let handler = cancel.clone();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            handler.cancel();
        }
    });
    let result = execute(cli, cancel).await;
    signal.abort();
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(if e == GuardError::Cancelled {
                130
            } else if e == GuardError::TimedOut {
                3
            } else {
                2
            });
        }
    }
}
