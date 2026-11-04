//! Provider-neutral facts consumed by change planning. Raw provider payloads and
//! their validation belong to adapters; a fact is not authenticated evidence.
use super::policy::{GenerationAssurance, Target, TargetHandle};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOrigin {
    Fixture,
    AwsConfiguration,
    AwsConnection,
    LocalConnection,
    GcpLive,
    OperatorAttestation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationNotice {
    TargetGenerationUnconfirmed,
    FixtureOnly,
    IncompleteInventory,
    ConfigurationChanged,
    StaleEvidence,
    BuildMismatch,
    MissingEvidence,
    ExecutionIncomplete,
    ReadOnlyBridge,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRegistration {
    pub principal: String,
    pub registered: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationFacts {
    pub target: TargetHandle,
    pub observed_at: u64,
    pub complete: bool,
    pub native_iam_enabled: Option<bool>,
    pub connector_required: Option<bool>,
    pub identities: Vec<IdentityRegistration>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeObservation {
    pub schema_version: u32,
    pub target_id: String,
    pub target: TargetHandle,
    pub configuration_epoch: Option<String>,
    pub configuration: Option<ConfigurationFacts>,
    pub inventory_complete: bool,
    pub evaluated_at: u64,
    pub configuration_observed_at: Option<u64>,
    pub valid_until: Option<u64>,
    pub origins: Vec<ObservationOrigin>,
    pub notices: Vec<ObservationNotice>,
    pub evidence_refs: Vec<String>,
}
impl ChangeObservation {
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
            configuration: None,
            inventory_complete: false,
            evaluated_at,
            configuration_observed_at: None,
            valid_until: None,
            origins: vec![],
            notices: vec![
                ObservationNotice::TargetGenerationUnconfirmed,
                ObservationNotice::MissingEvidence,
            ],
            evidence_refs: vec![],
        }
    }
}
