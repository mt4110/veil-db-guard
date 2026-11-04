//! Provider/engine boundaries and offline bridges into the protection core.
//!
//! Import bridges are offline; explicit native executors may change approved
//! cloud/DB configuration. Imported local manifests establish integrity,
//! not the authenticity of a provider response or resource generation.
mod control_observation;
pub mod deployment;
pub mod engine;
pub mod evidence;
pub mod executor;
pub mod import;
pub mod qualification;
pub mod source;
pub mod state;
pub use crate::core::observation::{ObservationNotice, ObservationOrigin};
mod registry;

pub use registry::{
    AwsRdsAdapter, DeploymentAdapter, EngineAdapter, GcpCloudSqlAdapter, PostgreSqlAdapter,
    capabilities_for, capabilities_for_policy,
};

use crate::{
    config::{self, GuardError},
    core::policy::{EngineFamily, GenerationAssurance, PlacementKind, Target, TargetHandle},
    domain as aws,
    gcp::{self, model as gcp_model},
};
use serde::{Deserialize, Serialize};

macro_rules! choice {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

choice!(ObservedAccess {
    Allowed,
    Denied,
    Unknown
});
choice!(ExpectedAccess { Allow, Deny });
choice!(ObservedVerdict {
    Pass,
    Fail,
    Pending,
    Unknown,
    NotApplicable
});

choice!(AccessRoute {
    Connector,
    Proxy,
    Direct,
    Other
});

/// A provider-local declaration, never proof of a common Policy Subject's
/// immutable identity. AWS source corroboration is not IAM identity validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActorReference {
    GcpDeclaredServiceAccount {
        principal_id: String,
        service_account: String,
    },
    AwsDeclaredSource {
        source_id: String,
        source_verification: Option<aws::SourceVerification>,
    },
    Unattributed,
}

/// A historical access sample. This is never an assertion of current protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessSample {
    pub case_id: String,
    pub actor: ActorReference,
    pub route: AccessRoute,
    pub expected: ExpectedAccess,
    pub actual: ObservedAccess,
    pub origin: ObservationOrigin,
    pub observed_at: u64,
    pub run_id: String,
    pub build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "provider",
    content = "code",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AssessmentReason {
    Gcp(gcp_model::GcpReason),
    Aws(aws::ReasonCode),
}

/// A provider evaluator's scoped assessment, not a policy grant or native effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessAssessment {
    pub case_id: String,
    pub actor: ActorReference,
    pub route: AccessRoute,
    pub expected: Option<ExpectedAccess>,
    pub actual: ObservedAccess,
    pub verdict: ObservedVerdict,
    pub reason: AssessmentReason,
    pub observed_at: Option<u64>,
    pub mixed_history: bool,
    pub consecutive_denials: usize,
    pub evidence_runs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "provider",
    content = "snapshot",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum NativeConfiguration {
    Gcp(Box<gcp_model::GcpSnapshot>),
    Aws(Box<aws::InventorySnapshot>),
}

/// Separates the observed incarnation from mutable configuration and freshness.
/// `generation_assurance` remains unconfirmed: the existing observer contracts do
/// not authenticate an incarnation against a registered target generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedState {
    pub schema_version: u32,
    pub target_id: String,
    pub target: TargetHandle,
    pub configuration_epoch: Option<String>,
    pub native_configuration: Option<NativeConfiguration>,
    pub inventory_complete: bool,
    pub evaluated_at: u64,
    pub configuration_observed_at: Option<u64>,
    pub valid_until: Option<u64>,
    pub origins: Vec<ObservationOrigin>,
    pub samples: Vec<AccessSample>,
    pub access: Vec<AccessAssessment>,
    pub notices: Vec<ObservationNotice>,
    pub evidence_refs: Vec<String>,
}

impl ObservedState {
    pub fn missing(target: &Target, evaluated_at: u64) -> Self {
        let mut resource = target.resource.clone();
        resource.generation_fingerprint = None;
        Self {
            schema_version: 1,
            target_id: target.id.clone(),
            target: TargetHandle {
                registration_id: target.registration_id.clone(),
                native_ref: resource,
                placement: target.placement.clone(),
                engine_binding: target.engine.clone(),
                generation_assurance: GenerationAssurance::Unconfirmed,
            },
            configuration_epoch: None,
            native_configuration: None,
            inventory_complete: false,
            evaluated_at,
            configuration_observed_at: None,
            valid_until: None,
            origins: vec![],
            samples: vec![],
            access: vec![],
            notices: vec![
                ObservationNotice::TargetGenerationUnconfirmed,
                ObservationNotice::MissingEvidence,
                ObservationNotice::ReadOnlyBridge,
            ],
            evidence_refs: vec![],
        }
    }
}

fn json_hash<T: Serialize>(value: &T) -> Result<String, GuardError> {
    serde_json::to_vec(value)
        .map(|bytes| config::hash_bytes(&bytes))
        .map_err(|_| GuardError::EvidenceIncompatible)
}

fn gcp_configuration_hash(snapshot: &gcp_model::GcpSnapshot) -> Result<String, GuardError> {
    let mut stable = snapshot.clone();
    stable.observed_at = 0;
    stable.authorized_networks.sort();
    stable.registered_principal_ids.sort();
    stable
        .principal_roles
        .sort_by(|a, b| a.principal_id.cmp(&b.principal_id));
    for principal in &mut stable.principal_roles {
        principal.roles.sort();
    }
    json_hash(&stable)
}

fn gcp_access(observation: &gcp_model::GcpObservation) -> ObservedAccess {
    use gcp_model::{GcpExecution, GcpPermission};
    // A positive SQL result survives partial capture. An untyped failure does not
    // become a denial just because the supplied `observed` field says Denied.
    if observation.proof.sql_authenticated || observation.proof.sql_ok {
        ObservedAccess::Allowed
    } else if observation.execution == GcpExecution::Completed
        && (observation
            .proof
            .denied_permission
            .is_some_and(|permission| {
                matches!(
                    permission,
                    GcpPermission::InstanceConnect | GcpPermission::InstanceLogin
                )
            })
            || (observation.proof.iam_login_rejected
                && observation.proof.credential_issued
                && observation.proof.transport_positive)
            || (observation.proof.network_rejection_explicit
                && observation.proof.tcp_reachable == Some(false)))
    {
        ObservedAccess::Denied
    } else {
        ObservedAccess::Unknown
    }
}

pub fn gcp_native_id(config: &gcp_model::GcpConfig) -> String {
    format!(
        "projects/{}/instances/{}",
        config.target.project_id, config.target.instance_id
    )
}

fn check_gcp_target(target: &Target, config: &gcp_model::GcpConfig) -> Result<(), GuardError> {
    if target.placement.kind != PlacementKind::GcpCloudSql
        || target.engine.family != EngineFamily::PostgreSql
        || target.placement.account_id != config.target.project_id
        || target.placement.region != config.target.region
        || target.resource.native_id != gcp_native_id(config)
        || target.engine.database != config.target.database
        || target.engine.version != "16.15"
    {
        return Err(GuardError::TargetMismatch);
    }
    Ok(())
}

/// Validates and normalizes already loaded, selected evidence. Callers importing
/// local files must verify their manifests first (`import_verified_run`). This
/// pure bridge never treats a hash as a provider signature.
pub fn bridge_gcp(
    target: &Target,
    config: &gcp_model::GcpConfig,
    current: &[gcp_model::GcpRunEvidence],
    history: &[gcp_model::GcpHistoricalRun],
    evaluated_at: u64,
) -> Result<ObservedState, GuardError> {
    gcp::config::validate_config(config)?;
    check_gcp_target(target, config)?;
    if current.len() > 16 || history.len() > 16 {
        return Err(GuardError::LimitExceeded);
    }
    let mut ids = std::collections::BTreeSet::new();
    for run in current {
        gcp::config::validate_evidence(config, run)?;
        if !ids.insert(run.run_id.as_str()) {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    for prior in history {
        gcp::config::validate_evidence(&prior.config, &prior.evidence)?;
        if gcp::config::history_compatibility_hash(&prior.config)
            != gcp::config::history_compatibility_hash(config)
            || !ids.insert(prior.evidence.run_id.as_str())
        {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    let assessment = gcp::evaluate::evaluate(config, current, history, evaluated_at);
    let mut state = ObservedState::missing(target, evaluated_at);
    state.access = assessment
        .cases
        .into_iter()
        .map(|row| AccessAssessment {
            case_id: row.case_id,
            actor: config
                .principals
                .iter()
                .find(|principal| principal.id == row.principal_id)
                .map_or(ActorReference::Unattributed, |principal| {
                    ActorReference::GcpDeclaredServiceAccount {
                        principal_id: principal.id.clone(),
                        service_account: principal.service_account.clone(),
                    }
                }),
            route: match row.route {
                gcp_model::GcpRoute::Proxy => AccessRoute::Connector,
                gcp_model::GcpRoute::Direct => AccessRoute::Direct,
            },
            expected: Some(match row.expected {
                gcp_model::GcpExpectation::Allow => ExpectedAccess::Allow,
                gcp_model::GcpExpectation::Deny => ExpectedAccess::Deny,
            }),
            actual: match row.observed {
                gcp_model::GcpAccess::Allowed => ObservedAccess::Allowed,
                gcp_model::GcpAccess::Denied => ObservedAccess::Denied,
                gcp_model::GcpAccess::Unknown => ObservedAccess::Unknown,
            },
            verdict: match row.verdict {
                gcp_model::GcpVerdict::Pass => ObservedVerdict::Pass,
                gcp_model::GcpVerdict::Fail => ObservedVerdict::Fail,
                gcp_model::GcpVerdict::Pending => ObservedVerdict::Pending,
                gcp_model::GcpVerdict::Unknown => ObservedVerdict::Unknown,
            },
            reason: AssessmentReason::Gcp(row.reason),
            observed_at: row.observed_at,
            mixed_history: row.mixed_history,
            consecutive_denials: row.consecutive_denials,
            evidence_runs: row.evidence_runs,
        })
        .collect();
    for run in current {
        let origin = match run.evidence_kind {
            gcp_model::GcpEvidenceKind::Live => ObservationOrigin::GcpLive,
            gcp_model::GcpEvidenceKind::Fixture => ObservationOrigin::Fixture,
        };
        if !state.origins.contains(&origin) {
            state.origins.push(origin);
        }
        if origin == ObservationOrigin::Fixture
            && !state.notices.contains(&ObservationNotice::FixtureOnly)
        {
            state.notices.push(ObservationNotice::FixtureOnly);
        }
        if run.build_id != crate::BUILD_ID
            && !state.notices.contains(&ObservationNotice::BuildMismatch)
        {
            state.notices.push(ObservationNotice::BuildMismatch);
        }
        if run.execution != gcp_model::GcpExecution::Completed
            && !state
                .notices
                .contains(&ObservationNotice::ExecutionIncomplete)
        {
            state.notices.push(ObservationNotice::ExecutionIncomplete);
        }
        if (run.finished_at > evaluated_at
            || evaluated_at.saturating_sub(run.started_at) > config.max_age_seconds)
            && !state.notices.contains(&ObservationNotice::StaleEvidence)
        {
            state.notices.push(ObservationNotice::StaleEvidence);
        }
        for observation in &run.observations {
            let case = config
                .cases
                .iter()
                .find(|case| case.id == observation.case_id)
                .ok_or(GuardError::EvidenceIncompatible)?;
            state.samples.push(AccessSample {
                case_id: observation.case_id.clone(),
                actor: config
                    .principals
                    .iter()
                    .find(|principal| principal.id == observation.principal_id)
                    .map_or(ActorReference::Unattributed, |principal| {
                        ActorReference::GcpDeclaredServiceAccount {
                            principal_id: principal.id.clone(),
                            service_account: principal.service_account.clone(),
                        }
                    }),
                route: match observation.route {
                    gcp_model::GcpRoute::Proxy => AccessRoute::Connector,
                    gcp_model::GcpRoute::Direct => AccessRoute::Direct,
                },
                expected: match case.expected {
                    gcp_model::GcpExpectation::Allow => ExpectedAccess::Allow,
                    gcp_model::GcpExpectation::Deny => ExpectedAccess::Deny,
                },
                actual: gcp_access(observation),
                origin,
                observed_at: observation.finished_at,
                run_id: run.run_id.clone(),
                build_id: run.build_id.clone(),
            });
        }
    }
    if let Some(latest) = current.iter().max_by_key(|run| run.finished_at) {
        let before = gcp_configuration_hash(&latest.before)?;
        let after = gcp_configuration_hash(&latest.after)?;
        state.configuration_epoch = Some(after.clone());
        state.configuration_observed_at = Some(latest.after.observed_at);
        state.valid_until = Some(latest.started_at.saturating_add(config.max_age_seconds));
        state.inventory_complete =
            latest.before.complete && latest.after.complete && before == after;
        state.native_configuration = Some(NativeConfiguration::Gcp(Box::new(latest.after.clone())));
        state
            .notices
            .retain(|notice| *notice != ObservationNotice::MissingEvidence);
        if !state.inventory_complete {
            state.notices.push(ObservationNotice::IncompleteInventory);
        }
        if before != after {
            state.notices.push(ObservationNotice::ConfigurationChanged);
        }
    }
    Ok(state)
}

fn aws_origin(kind: aws::EvidenceKind) -> ObservationOrigin {
    match kind {
        aws::EvidenceKind::LocalFixture => ObservationOrigin::Fixture,
        aws::EvidenceKind::AwsConfiguration => ObservationOrigin::AwsConfiguration,
        aws::EvidenceKind::AwsConnection => ObservationOrigin::AwsConnection,
        aws::EvidenceKind::LocalConnection => ObservationOrigin::LocalConnection,
        aws::EvidenceKind::OperatorAttestation => ObservationOrigin::OperatorAttestation,
    }
}

fn validate_aws_observation(
    config: &aws::TargetConfig,
    observation: &aws::Observation,
) -> Result<(), GuardError> {
    let hash =
        |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if observation.schema_version != 1
        || observation.target_id != config.target.id
        || observation.config_hash != config::config_hash(config)
        || !hash(&observation.build_id)
        || (!observation.snapshot_hash.is_empty() && !hash(&observation.snapshot_hash))
        || [
            &observation.run_id,
            &observation.experiment_id,
            &observation.phase_id,
            &observation.configuration_epoch,
            &observation.verification_id,
            &observation.case_id,
            &observation.attempt_id,
            &observation.path_id,
            &observation.source_id,
        ]
        .iter()
        .any(|value| !config::safe_id(value))
        || observation
            .requirement_ids
            .iter()
            .any(|value| !config::safe_id(value))
        || observation.evidence_refs.iter().any(|value| !hash(value))
        || (observation.path_id != "global"
            && !config.paths.iter().any(|path| {
                path.id == observation.path_id && path.source_id == observation.source_id
            }))
        || observation.details.as_ref().is_some_and(|details| {
            details.samples_ms.len() > config.limits.max_results
                || details.resolved_addresses.len() > 128
                || details
                    .resolved_addresses
                    .iter()
                    .any(|address| address.parse::<std::net::SocketAddr>().is_err())
                || details
                    .retained_schema
                    .as_ref()
                    .is_some_and(|name| !config::sql_id(name))
                || details
                    .workload_id
                    .as_ref()
                    .is_some_and(|name| !config::safe_id(name))
        })
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    crate::evaluator::validate_observation_protocol(observation, config)
        .map_err(|_| GuardError::EvidenceIncompatible)
}

/// Imports inventory and optional connection samples without invoking the AWS
/// CLI or a driver. Snapshot validation retains its existing strict bounds.
fn check_aws_target(target: &Target, config: &aws::TargetConfig) -> Result<(), GuardError> {
    if target.placement.kind != PlacementKind::AwsRds
        || target.engine.family != EngineFamily::PostgreSql
        || target.placement.account_id != config.target.account_id
        || target.placement.region != config.target.region
        || target.resource.native_id != config.target.db_instance_arn
        || target.engine.version != config.target.engine_version
        || config
            .test_scope
            .as_ref()
            .is_some_and(|scope| scope.database != target.engine.database)
    {
        return Err(GuardError::TargetMismatch);
    }
    Ok(())
}

pub fn bridge_aws(
    target: &Target,
    config: &aws::TargetConfig,
    snapshot: &aws::InventorySnapshot,
    observations: &[aws::Observation],
    plan: Option<&aws::ExperimentPlan>,
    evaluated_at: u64,
) -> Result<ObservedState, GuardError> {
    config::validate_config(config)?;
    config::validate_snapshot(config, snapshot)?;
    check_aws_target(target, config)?;
    if observations.len() > config.limits.max_results {
        return Err(GuardError::LimitExceeded);
    }
    for observation in observations {
        validate_aws_observation(config, observation)?;
    }
    let assessment = crate::evaluator::evaluate(config, observations, plan, evaluated_at);
    let mut state = ObservedState::missing(target, evaluated_at);
    let mut stable = snapshot.clone();
    stable.observed_at = 0;
    state.configuration_epoch = Some(json_hash(&stable)?);
    state.configuration_observed_at = Some(snapshot.observed_at);
    state.valid_until = Some(
        snapshot
            .observed_at
            .saturating_add(config.evidence_policy.max_age_seconds),
    );
    state.inventory_complete = snapshot.db.is_some()
        && snapshot.proxy.is_some()
        && snapshot.retrievals.len() == 6
        && snapshot
            .retrievals
            .iter()
            .all(|row| row.status == aws::RetrievalStatus::Complete);
    state.native_configuration = Some(NativeConfiguration::Aws(Box::new(snapshot.clone())));
    state.origins.push(aws_origin(snapshot.evidence_kind));
    state
        .notices
        .retain(|notice| *notice != ObservationNotice::MissingEvidence);
    if !state.inventory_complete {
        state.notices.push(ObservationNotice::IncompleteInventory);
    }
    if snapshot.evidence_kind == aws::EvidenceKind::LocalFixture {
        state.notices.push(ObservationNotice::FixtureOnly);
    }
    if snapshot.observed_at > evaluated_at
        || evaluated_at.saturating_sub(snapshot.observed_at)
            > config.evidence_policy.max_age_seconds
    {
        state.notices.push(ObservationNotice::StaleEvidence);
    }
    for row in assessment.cases {
        let path = config.paths.iter().find(|path| path.id == row.path_id);
        state.access.push(AccessAssessment {
            case_id: row.case_id,
            actor: path.map_or(ActorReference::Unattributed, |path| {
                ActorReference::AwsDeclaredSource {
                    source_id: path.source_id.clone(),
                    source_verification: row
                        .source_ids
                        .iter()
                        .position(|source| source == &path.source_id)
                        .and_then(|index| row.source_verifications.get(index).copied()),
                }
            }),
            route: path.map_or(AccessRoute::Other, |path| match path.destination {
                aws::Destination::Proxy => AccessRoute::Proxy,
                aws::Destination::Database => AccessRoute::Direct,
            }),
            expected: path.map(|path| match path.expected {
                aws::Expectation::Allow => ExpectedAccess::Allow,
                aws::Expectation::Deny => ExpectedAccess::Deny,
            }),
            // The AWS evaluator includes requirements other than access. A Pass
            // must not be converted into an Allowed or Denied connection.
            actual: ObservedAccess::Unknown,
            verdict: match row.verdict {
                aws::Verdict::Pass => ObservedVerdict::Pass,
                aws::Verdict::Fail => ObservedVerdict::Fail,
                aws::Verdict::Unknown => ObservedVerdict::Unknown,
                aws::Verdict::NotApplicable => ObservedVerdict::NotApplicable,
            },
            reason: AssessmentReason::Aws(row.reason_code),
            observed_at: None,
            mixed_history: false,
            consecutive_denials: 0,
            evidence_runs: row.evidence_runs,
        });
    }
    for observation in observations {
        let Some(path) = config
            .paths
            .iter()
            .find(|path| path.id == observation.path_id)
        else {
            continue;
        };
        let actual = if observation.path_stages.db_authenticated == aws::Stage::ObservedTrue {
            ObservedAccess::Allowed
        } else if observation.execution == aws::Execution::Completed
            && observation.outcome == aws::Outcome::AuthenticationRejected
        {
            ObservedAccess::Denied
        } else {
            ObservedAccess::Unknown
        };
        let origin = aws_origin(observation.evidence_kind);
        if !state.origins.contains(&origin) {
            state.origins.push(origin);
        }
        state.samples.push(AccessSample {
            case_id: observation.case_id.clone(),
            actor: ActorReference::AwsDeclaredSource {
                source_id: observation.source_id.clone(),
                source_verification: Some(observation.source_verification),
            },
            route: match path.destination {
                aws::Destination::Proxy => AccessRoute::Proxy,
                aws::Destination::Database => AccessRoute::Direct,
            },
            expected: match path.expected {
                aws::Expectation::Allow => ExpectedAccess::Allow,
                aws::Expectation::Deny => ExpectedAccess::Deny,
            },
            actual,
            origin,
            observed_at: observation.observed_at,
            run_id: observation.run_id.clone(),
            build_id: observation.build_id.clone(),
        });
    }
    Ok(state)
}

pub mod aws_observation;

pub mod aws_state;
