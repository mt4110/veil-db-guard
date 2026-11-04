//! GCP entry points share the private run store, not AWS target/configuration semantics.
use super::{config, evaluate, live, model::*, report};
use crate::{
    config::{GuardError, hash_bytes, read_json},
    domain::now,
    store::{self, Manifest, RunStatus, RunWriter},
};
use clap::Subcommand;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Subcommand)]
pub enum GcpCommand {
    /// Check declared Cloud SQL PostgreSQL access paths; never changes cloud/DB settings.
    Check {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, conflicts_with_all=["allow_gcp_read", "allow_network"])]
        fixture: Option<PathBuf>,
        #[arg(long)]
        allow_gcp_read: bool,
        #[arg(long)]
        allow_network: bool,
        #[arg(long)]
        baseline: Vec<PathBuf>,
        #[arg(long, default_value = "gcloud")]
        gcloud_bin: PathBuf,
        #[arg(long, default_value = "cloud-sql-proxy")]
        proxy_bin: PathBuf,
        #[arg(long, default_value = "psql")]
        psql_bin: PathBuf,
    },
    /// Re-evaluate integrity-checked GCP evidence locally, without credentials or network.
    Report {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, num_args=1..)]
        evidence: Vec<PathBuf>,
        #[arg(long)]
        history: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

fn target_id(c: &GcpConfig) -> String {
    format!(
        "gcp-{}",
        hash_bytes(&serde_json::to_vec(&c.target).expect("typed GCP target"))
    )
}

fn executable(path: &Path) -> Result<PathBuf, GuardError> {
    let candidates = if path.components().count() == 1 {
        std::env::var_os("PATH")
            .map(|paths| {
                std::env::split_paths(&paths)
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| p.join(path))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    } else {
        vec![path.to_path_buf()]
    };
    for candidate in candidates {
        if let Ok(real) = candidate.canonicalize()
            && let Ok(meta) = real.metadata()
            && meta.is_file()
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return Ok(real);
        }
    }
    Err(GuardError::OperationFailed)
}

fn imported_run(
    path: &Path,
    remaining: &mut usize,
) -> Result<(GcpConfig, Option<GcpRunEvidence>, Manifest), GuardError> {
    let manifest = store::verify_manifest(path, *remaining)?;
    if manifest.operation != "gcp-check" {
        return Err(GuardError::EvidenceIncompatible);
    }
    let c: GcpConfig = store::read_artifact(path, &manifest, "config.normalized.json", *remaining)?;
    config::validate_config(&c)?;
    if config::config_hash(&c) != manifest.config_hash || target_id(&c) != manifest.target_id {
        return Err(GuardError::EvidenceIncompatible);
    }
    let manifest_bytes = std::fs::metadata(path.join("manifest.json"))
        .map_err(|_| GuardError::StorageFailed)?
        .len();
    let size = manifest
        .artifacts
        .iter()
        .map(|a| a.bytes)
        .sum::<usize>()
        .checked_add(usize::try_from(manifest_bytes).map_err(|_| GuardError::LimitExceeded)?)
        .ok_or(GuardError::LimitExceeded)?;
    *remaining = remaining
        .checked_sub(size)
        .ok_or(GuardError::LimitExceeded)?;
    if !manifest
        .artifacts
        .iter()
        .any(|a| a.name == "observations.json")
    {
        if matches!(manifest.status, RunStatus::Complete) {
            return Err(GuardError::EvidenceIncompatible);
        }
        return Ok((c, None, manifest));
    }
    let mut capture: GcpRunEvidence =
        store::read_artifact(path, &manifest, "observations.json", c.limits.max_bytes)?;
    if capture.config_hash != manifest.config_hash
        || capture.build_id != manifest.build_id
        || capture.run_id != manifest.run_id
        || capture.target != c.target
        || capture.history_compatibility_hash != config::history_compatibility_hash(&c)
        || (capture.evidence_kind == GcpEvidenceKind::Live
            && capture.started_at < manifest.created_at)
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let before: GcpSnapshot =
        store::read_artifact(path, &manifest, "snapshot.before.json", c.limits.max_bytes)?;
    let after: GcpSnapshot =
        store::read_artifact(path, &manifest, "snapshot.after.json", c.limits.max_bytes)?;
    if before != capture.before || after != capture.after {
        return Err(GuardError::EvidenceIncompatible);
    }
    if !matches!(manifest.status, RunStatus::Complete) {
        capture.execution = if matches!(manifest.status, RunStatus::Cancelled) {
            GcpExecution::Cancelled
        } else {
            GcpExecution::Error
        };
    }
    Ok((c, Some(capture), manifest))
}

fn history(
    c: &GcpConfig,
    paths: &[PathBuf],
    remaining: &mut usize,
    seen: &mut BTreeSet<String>,
) -> Result<Vec<GcpHistoricalRun>, GuardError> {
    if paths.len() > 16 {
        return Err(GuardError::LimitExceeded);
    }
    let mut history = Vec::new();
    for path in paths {
        let (source, capture, manifest) = imported_run(path, remaining)?;
        if !seen.insert(manifest.run_id) {
            return Err(GuardError::EvidenceIncompatible);
        }
        if config::history_compatibility_hash(&source) != config::history_compatibility_hash(c) {
            return Err(GuardError::TargetMismatch);
        }
        if let Some(evidence) = capture {
            history.push(GcpHistoricalRun {
                config: source,
                evidence,
            });
        }
    }
    Ok(history)
}

fn save_assessment(writer: &mut RunWriter, assessment: &GcpAssessment) -> Result<(), GuardError> {
    writer.write_json("assessment.json", assessment)?;
    writer.write_bytes("report.md", report::render_markdown(assessment).as_bytes())
}
fn summary(writer: &RunWriter, assessment: &GcpAssessment, code: i32) {
    println!(
        "{}",
        serde_json::json!({"run_id":writer.manifest.run_id,"operation":writer.manifest.operation,"exit_code":code,"build_id":crate::BUILD_ID,"verdict":assessment.verdict,"protected":assessment.protected,"scope":"configured_cases_only"})
    );
}

pub async fn execute(command: GcpCommand, cancel: CancellationToken) -> Result<i32, GuardError> {
    match command {
        GcpCommand::Check {
            config: path,
            out,
            fixture,
            allow_gcp_read,
            allow_network,
            baseline,
            gcloud_bin,
            proxy_bin,
            psql_bin,
        } => {
            let c = config::load_config(&path)?;
            if fixture.is_none() && (!allow_gcp_read || !allow_network) {
                return Err(GuardError::PermissionRequired);
            }
            if fixture.is_none() && c.target.project_id == "vdg-example-000000" {
                return Err(GuardError::ConfigInvalid);
            }
            let mut remaining = c.limits.max_bytes;
            let prior = history(&c, &baseline, &mut remaining, &mut BTreeSet::new())?;
            let tools = if fixture.is_none() {
                Some((
                    executable(&gcloud_bin)?,
                    executable(&proxy_bin)?,
                    executable(&psql_bin)?,
                ))
            } else {
                None
            };
            let mut writer = RunWriter::create_for_config(
                &out,
                &target_id(&c),
                &c,
                "gcp-check",
                c.limits.max_bytes,
                false,
            )?;
            let deadline =
                tokio::time::Instant::now() + Duration::from_millis(c.limits.total_timeout_ms);
            let result = if let Some(path) = fixture {
                let mut capture: GcpRunEvidence = read_json(&path, c.limits.max_bytes)?;
                capture.run_id = writer.manifest.run_id.clone();
                capture.build_id = crate::BUILD_ID.into();
                capture.config_hash = config::config_hash(&c);
                capture.history_compatibility_hash = config::history_compatibility_hash(&c);
                capture.evidence_kind = GcpEvidenceKind::Fixture;
                // Reject free-form or foreign values before persisting a replay.
                // Provenance is always Fixture regardless of its input label.
                config::validate_evidence(&c, &capture)?;
                Ok(capture)
            } else {
                let (gcloud, proxy, psql) = tools.expect("live tools checked");
                let work_dir = writer.path().join("transport");
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(&work_dir)
                    .map_err(|_| GuardError::StorageFailed)?;
                let tools = live::LiveTools {
                    gcloud,
                    proxy,
                    psql,
                    work_dir,
                };
                live::probe(
                    &c,
                    &tools,
                    &writer.manifest.run_id,
                    cancel.clone(),
                    deadline,
                )
                .await
            };
            let (captures, mut status, operation_error) = match result {
                Ok(capture) => {
                    writer.write_json("snapshot.before.json", &capture.before)?;
                    writer.write_json("snapshot.after.json", &capture.after)?;
                    writer.write_json("observations.json", &capture)?;
                    let status = if capture.execution == GcpExecution::Cancelled {
                        RunStatus::Cancelled
                    } else if capture.execution != GcpExecution::Completed {
                        RunStatus::Partial
                    } else {
                        RunStatus::Complete
                    };
                    (vec![capture], status, None)
                }
                Err(error) => {
                    writer.write_json(
                        "operation-error.json",
                        &serde_json::json!({"error":error.to_string()}),
                    )?;
                    (
                        vec![],
                        if error == GuardError::Cancelled {
                            RunStatus::Cancelled
                        } else {
                            RunStatus::Partial
                        },
                        Some(error),
                    )
                }
            };
            let assessment = evaluate::evaluate(&c, &captures, &prior, now());
            save_assessment(&mut writer, &assessment)?;
            let code = if cancel.is_cancelled() || operation_error == Some(GuardError::Cancelled) {
                status = RunStatus::Cancelled;
                130
            } else {
                report::exit_code(&assessment)
            };
            writer.finish(status)?;
            summary(&writer, &assessment, code);
            Ok(code)
        }
        GcpCommand::Report {
            config: path,
            evidence,
            history: paths,
            out,
        } => {
            let c = config::load_config(&path)?;
            if evidence.is_empty() || evidence.len() > 16 {
                return Err(GuardError::LimitExceeded);
            }
            let mut remaining = c.limits.max_bytes;
            let mut seen = BTreeSet::new();
            let mut current = Vec::new();
            let mut missing = Vec::new();
            for path in evidence {
                let (source, capture, manifest) = imported_run(&path, &mut remaining)?;
                if !seen.insert(manifest.run_id.clone()) {
                    return Err(GuardError::EvidenceIncompatible);
                }
                if config::config_hash(&source) != config::config_hash(&c) {
                    return Err(GuardError::TargetMismatch);
                }
                if let Some(capture) = capture {
                    current.push(capture);
                } else {
                    missing.push((manifest.created_at, manifest.run_id));
                }
            }
            let prior = history(&c, &paths, &mut remaining, &mut seen)?;
            // A run with no capture has no observed finish time. It cannot be
            // ordered against a successful overlapping run using its start time.
            // Explicit current inputs containing such a gap stay unconfirmed.
            let missing_latest = !missing.is_empty();
            let mut assessment = evaluate::evaluate(
                &c,
                if missing_latest { &[] } else { &current },
                &prior,
                now(),
            );
            if missing_latest {
                for case in &mut assessment.cases {
                    case.evidence_runs = seen.iter().cloned().collect();
                }
            }
            let mut writer = RunWriter::create_for_config(
                &out,
                &target_id(&c),
                &c,
                "gcp-report",
                c.limits.max_bytes,
                false,
            )?;
            save_assessment(&mut writer, &assessment)?;
            writer.finish(RunStatus::Complete)?;
            let code = report::exit_code(&assessment);
            summary(&writer, &assessment, code);
            Ok(code)
        }
    }
}
