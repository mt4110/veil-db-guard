//! Verified local AWS native captures remain observations of the CLI source,
//! never proof for every workload source declared in a policy.
use super::{aws_observation::AwsAccessCapture, deployment::aws::Access};
use crate::{
    config::{GuardError, MAX_INPUT_BYTES, hash_bytes},
    core::{change::PreparedChange, policy::RouteKind, state::*},
    store::{self, RunStatus},
};
use std::path::Path;
pub fn evaluate_run(
    change: &PreparedChange,
    path: &Path,
    now: u64,
) -> Result<StateReport, GuardError> {
    change.verify()?;
    let manifest = store::verify_manifest(path, MAX_INPUT_BYTES)?;
    if manifest.operation != "aws-guard-check" {
        return Err(GuardError::EvidenceIncompatible);
    }
    let policy: crate::core::policy::PolicyRevision =
        store::read_artifact(path, &manifest, "config.normalized.json", MAX_INPUT_BYTES)?;
    if policy != change.policy
        || manifest.config_hash
            != hash_bytes(
                &serde_json::to_vec(&policy).map_err(|_| GuardError::EvidenceIncompatible)?,
            )
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let capture: AwsAccessCapture =
        store::read_artifact(path, &manifest, "aws-access.json", MAX_INPUT_BYTES)?;
    let target = policy
        .targets
        .iter()
        .find(|t| t.id == capture.target_id)
        .ok_or(GuardError::TargetMismatch)?;
    let binding = target.aws.as_ref().ok_or(GuardError::TargetMismatch)?;
    if capture.schema_version != 1
        || capture.policy_revision_hash != change.plan.policy_revision_hash
        || capture.proxy_arn != binding.proxy_arn
        || target.resource.generation_fingerprint.as_deref() != Some(capture.generation.as_str())
        || manifest.target_id != target.id
        || capture.observations.len() > 16
        || capture.finished_at < capture.started_at
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let desired = desired_for_change(&policy, change.previous_policy.as_ref(), &[], now)
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    let mut input = StateEvaluationInput {
        schema_version: STATE_SCHEMA_VERSION,
        now,
        max_age_seconds: 60,
        expected_build_id: crate::BUILD_ID.into(),
        desired,
        evidence: vec![],
        permission_removals: vec![],
    };
    let provenance = EvidenceProvenance {
        origin: EvidenceOrigin::AdapterValidated,
        build_id: manifest.build_id.clone(),
        artifacts: manifest
            .artifacts
            .iter()
            .map(|a| ArtifactRef {
                id: a.name.clone(),
                sha256: a.sha256.clone(),
            })
            .collect(),
    };
    for row in &capture.observations {
        let subject = policy
            .subjects
            .iter()
            .find(|s| s.id == row.subject_id && s.identity.principal == row.principal)
            .ok_or(GuardError::EvidenceIncompatible)?;
        let matching = input
            .desired
            .iter()
            .filter(|d| {
                d.scope.target_id == target.id
                    && d.scope.subject_id == subject.id
                    && d.scope.db_identity == row.db_user
                    && d.scope.route.kind == RouteKind::NativeProxy
                    && d.scope.effect == StateEffect::NewConnections
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            continue;
        }
        input.evidence.push(StateEvidence {
            id: format!("aws-observation-{}", input.evidence.len() + 1),
            scope: matching[0].scope.clone(),
            started_at: capture.started_at,
            finished_at: capture.finished_at,
            valid_until: if capture.finished_at > now {
                0
            } else {
                capture.started_at.saturating_add(60)
            },
            provenance: provenance.clone(),
            complete: manifest.status == RunStatus::Complete && capture.complete,
            // STS identity is real in the native observer, but this artifact has
            // no independently authenticated workload/source binding.
            identity_confirmed: false,
            observed: match row.access {
                Access::Allowed => StateValue::Allowed,
                Access::Denied => StateValue::Denied,
                Access::Unknown => StateValue::Unknown,
            },
            denial: None,
            sessions_attributed: false,
        });
    }
    evaluate_state(&input).map_err(|_| GuardError::EvidenceIncompatible)
}
