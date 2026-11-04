//! Read-only K06 state reports from existing verified local GCP captures.
//! Local manifests establish integrity, never provider authenticity. Legacy GCP
//! captures cannot authenticate a resource generation, workload source, native
//! route ID, or immutable service-account identity. They remain scoped observed
//! samples with Unknown effective protection, including successful access.
use crate::{
    config::{GuardError, MAX_INPUT_BYTES},
    core::{
        change::PreparedChange,
        policy::{PlacementKind, RouteKind},
        state::{
            self, ArtifactRef, DenialCause, DenialProof, EvidenceOrigin, EvidenceProvenance,
            StateEffect, StateEvaluationInput, StateEvidence, StateLayer, StateReport, StateValue,
        },
    },
    gcp::model::*,
    store::{self, RunStatus},
};
use std::path::Path;

/// Verify original artifacts and recompute provider assessment. A stored
/// assessment.json/effective-state.json is never accepted as a verdict.
/// This operation reads local files only and does not write or dispatch anything.
pub fn evaluate_run(
    change: &PreparedChange,
    path: &Path,
    now: u64,
) -> Result<StateReport, GuardError> {
    change
        .verify()
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    let manifest = store::verify_manifest(path, MAX_INPUT_BYTES)?;
    if manifest.operation == "aws-guard-check" {
        return super::aws_state::evaluate_run(change, path, now);
    }
    if manifest.operation != "gcp-check" {
        return Err(GuardError::EvidenceIncompatible);
    }
    let config: GcpConfig =
        store::read_artifact(path, &manifest, "config.normalized.json", MAX_INPUT_BYTES)?;
    crate::gcp::config::validate_config(&config)?;
    let targets: Vec<_> = change
        .policy
        .targets
        .iter()
        .filter(|target| {
            target.placement.kind == PlacementKind::GcpCloudSql
                && super::check_gcp_target(target, &config).is_ok()
        })
        .collect();
    if targets.len() != 1 {
        return Err(GuardError::TargetMismatch);
    }
    let target = targets[0];
    // Reuse the established import boundary: target/config/run/build linkage,
    // before/after artifacts, observation protocol and complete manifest status.
    let imported = super::import::import_verified_run(target, path, now)?;
    let desired =
        state::desired_for_change(&change.policy, change.previous_policy.as_ref(), &[], now)
            .map_err(|_| GuardError::EvidenceIncompatible)?;
    let mut input = StateEvaluationInput {
        schema_version: state::STATE_SCHEMA_VERSION,
        now,
        max_age_seconds: config.max_age_seconds,
        expected_build_id: crate::BUILD_ID.into(),
        desired,
        evidence: vec![],
        permission_removals: vec![],
    };
    if !manifest
        .artifacts
        .iter()
        .any(|a| a.name == "observations.json")
    {
        return state::evaluate_state(&input).map_err(|_| GuardError::EvidenceIncompatible);
    }
    let capture: GcpRunEvidence =
        store::read_artifact(path, &manifest, "observations.json", MAX_INPUT_BYTES)?;
    // The importer already validated these exact bytes against the manifest.
    // A second typed read is hash checked too, so path replacement cannot supply
    // a different capture between import and normalization.
    let provenance = EvidenceProvenance {
        origin: if capture.evidence_kind == GcpEvidenceKind::Fixture {
            EvidenceOrigin::Fixture
        } else {
            EvidenceOrigin::AdapterValidated
        },
        build_id: capture.build_id.clone(),
        artifacts: manifest
            .artifacts
            .iter()
            .map(|a| ArtifactRef {
                id: a.name.clone(),
                sha256: a.sha256.clone(),
            })
            .collect(),
    };
    for observation in &capture.observations {
        let principal = config
            .principals
            .iter()
            .find(|p| p.id == observation.principal_id)
            .ok_or(GuardError::EvidenceIncompatible)?;
        // The observer contract lacks source and native route identifiers. Only
        // an unambiguous policy declaration can associate this historical sample
        // with a row; identity_confirmed remains false below.
        let matching: Vec<_> = input
            .desired
            .iter()
            .filter(|d| {
                d.scope.target_id == target.id
                    && d.scope.effect == StateEffect::NewConnections
                    && change.policy.subjects.iter().any(|s| {
                        s.id == d.scope.subject_id
                            && s.identity.principal == principal.service_account
                    })
                    && d.scope.db_identity == principal.db_user()
                    && match observation.route {
                        GcpRoute::Proxy => matches!(
                            d.scope.route.kind,
                            RouteKind::NativeConnector | RouteKind::NativeProxy
                        ),
                        GcpRoute::Direct => d.scope.route.kind == RouteKind::Direct,
                    }
            })
            .collect();
        if matching.len() != 1 {
            continue;
        }
        let d = matching[0];
        let observed = observed_access(observation);
        let denial = denial_proof(observation, &capture.before);
        let assessed = imported
            .access
            .iter()
            .find(|a| a.case_id == observation.case_id);
        let provider_checked = assessed.is_some_and(|a| {
            !matches!(
                a.verdict,
                super::ObservedVerdict::Unknown | super::ObservedVerdict::NotApplicable
            )
        });
        input.evidence.push(StateEvidence {
            id: format!("capture-{}", input.evidence.len() + 1),
            scope: d.scope.clone(),
            // Preserve individual attempt intervals for contradictory/mixed history.
            started_at: observation.started_at,
            finished_at: observation.finished_at,
            // The validity bound still starts at the whole capture's start.
            valid_until: if capture.finished_at > now
                || capture.before.observed_at > now
                || capture.after.observed_at > now
            {
                0
            } else {
                capture.started_at.saturating_add(config.max_age_seconds)
            },
            provenance: provenance.clone(),
            complete: manifest.status == RunStatus::Complete
                && capture.execution == GcpExecution::Completed
                && observation.execution == GcpExecution::Completed
                && imported.inventory_complete
                && provider_checked,
            // A declared mutable principal + an observer-side impersonation does
            // not establish the policy workload source or immutable SA identity.
            identity_confirmed: false,
            observed,
            denial,
            sessions_attributed: false,
        });
    }
    // A single imported run has no independently verified pre-removal access
    // baseline. Its permission_changes declaration cannot manufacture Pending.
    state::evaluate_state(&input).map_err(|_| GuardError::EvidenceIncompatible)
}

fn observed_access(o: &GcpObservation) -> StateValue {
    if o.proof.sql_authenticated || o.proof.sql_ok {
        return StateValue::Allowed;
    }
    if o.execution != GcpExecution::Completed {
        return StateValue::Unknown;
    }
    if o.proof.denied_permission.is_some()
        || (o.proof.iam_login_rejected && o.proof.credential_issued && o.proof.transport_positive)
        || (o.proof.network_rejection_explicit && o.proof.tcp_reachable == Some(false))
    {
        StateValue::Denied
    } else {
        StateValue::Unknown
    }
}
fn denial_proof(o: &GcpObservation, before: &GcpSnapshot) -> Option<DenialProof> {
    let (layer, cause) = match o.proof.denied_permission {
        Some(GcpPermission::InstanceConnect) => (
            StateLayer::ConnectionAuthorization,
            DenialCause::PermissionDenied,
        ),
        Some(GcpPermission::InstanceLogin) => {
            (StateLayer::Authentication, DenialCause::LoginRejected)
        }
        Some(GcpPermission::TokenCreation) => {
            (StateLayer::Authentication, DenialCause::TokenCreationDenied)
        }
        Some(GcpPermission::ServiceUsage) => {
            (StateLayer::Configuration, DenialCause::ServiceUsageDenied)
        }
        Some(GcpPermission::InstanceGet) => (
            StateLayer::Configuration,
            DenialCause::InstanceMetadataDenied,
        ),
        None if o.proof.iam_login_rejected => {
            (StateLayer::Authentication, DenialCause::LoginRejected)
        }
        None if o.proof.network_rejection_explicit => {
            (StateLayer::RouteEnforcement, DenialCause::RouteBlocked)
        }
        None => return None,
    };
    Some(DenialProof {
        layer,
        cause,
        credential_issued: o.proof.credential_issued,
        identity_registered: before.registered_principal_ids.contains(&o.principal_id),
        // A legacy case ID alone is not an independently scoped core control.
        transport_control_ref: None,
    })
}
