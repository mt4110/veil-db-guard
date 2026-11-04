//! Bounded, hash-verified local imports. No provider APIs or cached credentials.
use super::{ObservedState, bridge_aws, bridge_gcp};
use crate::{
    config::{self, GuardError, MAX_INPUT_BYTES},
    core::policy::{PlacementKind, Target},
    domain as aws,
    gcp::{self, model::*},
    store::{self, Manifest, RunStatus},
};
use std::{collections::BTreeSet, path::Path};

fn has(manifest: &Manifest, name: &str) -> bool {
    manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.name == name)
}

/// Loads one existing observer run. Plans and reports are intentionally not
/// observation inputs; assessment.json is never trusted or copied as a verdict.
/// The hash verifies local integrity and does not authenticate a provider.
pub fn import_verified_run(
    target: &Target,
    path: &Path,
    evaluated_at: u64,
) -> Result<ObservedState, GuardError> {
    let manifest = store::verify_manifest(path, MAX_INPUT_BYTES)?;
    let mut state = match (target.placement.kind, manifest.operation.as_str()) {
        (PlacementKind::GcpCloudSql, "gcp-check") => {
            import_gcp(target, path, &manifest, evaluated_at)?
        }
        (PlacementKind::AwsRds, "inspect" | "probe") => {
            import_aws(target, path, &manifest, evaluated_at)?
        }
        _ => return Err(GuardError::EvidenceIncompatible),
    };
    state.evidence_refs = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.sha256.clone())
        .collect();
    Ok(state)
}

fn import_gcp(
    target: &Target,
    path: &Path,
    manifest: &Manifest,
    evaluated_at: u64,
) -> Result<ObservedState, GuardError> {
    let config: GcpConfig =
        store::read_artifact(path, manifest, "config.normalized.json", MAX_INPUT_BYTES)?;
    gcp::config::validate_config(&config)?;
    super::check_gcp_target(target, &config)?;
    if gcp::config::config_hash(&config) != manifest.config_hash
        || manifest.target_id
            != format!(
                "gcp-{}",
                config::hash_bytes(
                    &serde_json::to_vec(&config.target)
                        .map_err(|_| GuardError::EvidenceIncompatible)?
                )
            )
        || manifest.created_at > evaluated_at
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if !has(manifest, "observations.json") {
        if manifest.status == RunStatus::Complete {
            return Err(GuardError::EvidenceIncompatible);
        }
        return Ok(ObservedState::missing(target, evaluated_at));
    }
    let mut capture: GcpRunEvidence =
        store::read_artifact(path, manifest, "observations.json", MAX_INPUT_BYTES)?;
    gcp::config::validate_evidence(&config, &capture)?;
    if capture.config_hash != manifest.config_hash
        || capture.build_id != manifest.build_id
        || capture.run_id != manifest.run_id
        || capture.target != config.target
        || (capture.evidence_kind == GcpEvidenceKind::Live
            && capture.started_at < manifest.created_at)
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let before: GcpSnapshot =
        store::read_artifact(path, manifest, "snapshot.before.json", MAX_INPUT_BYTES)?;
    let after: GcpSnapshot =
        store::read_artifact(path, manifest, "snapshot.after.json", MAX_INPUT_BYTES)?;
    if before != capture.before || after != capture.after {
        return Err(GuardError::EvidenceIncompatible);
    }
    if manifest.status != RunStatus::Complete {
        capture.execution = if manifest.status == RunStatus::Cancelled {
            GcpExecution::Cancelled
        } else {
            GcpExecution::Error
        };
    }
    // A single run carries no independently verified pre-removal baseline. The
    // evaluator will therefore not manufacture a Pending from its declaration.
    bridge_gcp(target, &config, &[capture], &[], evaluated_at)
}

fn import_aws(
    target: &Target,
    path: &Path,
    manifest: &Manifest,
    evaluated_at: u64,
) -> Result<ObservedState, GuardError> {
    let config: aws::TargetConfig =
        store::read_artifact(path, manifest, "config.normalized.json", MAX_INPUT_BYTES)?;
    config::validate_config(&config)?;
    super::check_aws_target(target, &config)?;
    if config::config_hash(&config) != manifest.config_hash
        || manifest.target_id != config.target.id
        || manifest.created_at > evaluated_at
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if !has(manifest, "snapshot.json") {
        if manifest.status == RunStatus::Complete {
            return Err(GuardError::EvidenceIncompatible);
        }
        return Ok(ObservedState::missing(target, evaluated_at));
    }
    let snapshot: aws::InventorySnapshot =
        store::read_artifact(path, manifest, "snapshot.json", MAX_INPUT_BYTES)?;
    config::validate_snapshot(&config, &snapshot)?;
    let mut linked_snapshots = vec![];
    for artifact in &manifest.artifacts {
        if [
            "snapshot.json",
            "snapshot.before.json",
            "snapshot.after.json",
        ]
        .contains(&artifact.name.as_str())
        {
            let snapshot: aws::InventorySnapshot =
                store::read_artifact(path, manifest, &artifact.name, MAX_INPUT_BYTES)?;
            config::validate_snapshot(&config, &snapshot)?;
            linked_snapshots.push((artifact.sha256.clone(), snapshot));
        }
    }
    let plan: Option<aws::ExperimentPlan> = if has(manifest, "experiment-plan.json") {
        let plan = store::read_artifact(path, manifest, "experiment-plan.json", MAX_INPUT_BYTES)?;
        crate::evaluator::validate_experiment_plan(&config, &plan)
            .map_err(|_| GuardError::EvidenceIncompatible)?;
        Some(plan)
    } else {
        None
    };
    let mut observations: Vec<aws::Observation> = if has(manifest, "observations.json") {
        store::read_artifact(path, manifest, "observations.json", MAX_INPUT_BYTES)?
    } else {
        vec![]
    };
    if observations.len() > config.limits.max_results {
        return Err(GuardError::LimitExceeded);
    }
    let artifact_hashes: BTreeSet<_> = manifest
        .artifacts
        .iter()
        .map(|artifact| &artifact.sha256)
        .collect();
    let snapshot_hashes: BTreeSet<_> = linked_snapshots
        .iter()
        .map(|(_, snapshot)| config::snapshot_hash(snapshot))
        .collect();
    for observation in &observations {
        super::validate_aws_observation(&config, observation)?;
        if observation.run_id != manifest.run_id
            || observation.build_id != manifest.build_id
            || observation.config_hash != manifest.config_hash
            || observation
                .evidence_refs
                .iter()
                .any(|reference| !artifact_hashes.contains(reference))
            || (!observation.snapshot_hash.is_empty()
                && !snapshot_hashes.contains(&observation.snapshot_hash))
            || !crate::evaluator::validate_protocol_links(observation, &linked_snapshots)
            || (observation.evidence_kind == aws::EvidenceKind::AwsConnection
                && observation.observed_at < manifest.created_at)
        {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    if manifest.status != RunStatus::Complete {
        for observation in &mut observations {
            // Positive facts remain historical samples, while a partial capture
            // cannot complete the surrounding requirements.
            if observation.execution == aws::Execution::Completed {
                observation.execution = if manifest.status == RunStatus::Cancelled {
                    aws::Execution::Cancelled
                } else {
                    aws::Execution::Error
                };
            }
        }
    }
    bridge_aws(
        target,
        &config,
        &snapshot,
        &observations,
        plan.as_ref(),
        evaluated_at,
    )
}
