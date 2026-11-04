//! Validate provider payload scope before projecting facts into the inner model.
use super::{ActorReference, NativeConfiguration, ObservationOrigin, ObservedState};
use crate::{
    config::GuardError,
    core::{
        observation::{ChangeObservation, ConfigurationFacts, IdentityRegistration},
        policy::{EngineFamily, PlacementKind, Target},
    },
    domain::RetrievalStatus,
    gcp::model::GcpConnectorEnforcement,
};
use std::collections::BTreeMap;

impl ObservedState {
    pub fn for_change(&self, target: &Target) -> Result<ChangeObservation, GuardError> {
        if self.target_id != target.id
            || self.target.registration_id != target.registration_id
            || self.target.native_ref.native_id != target.resource.native_id
            || self.target.placement != target.placement
            || self.target.engine_binding != target.engine
        {
            return Err(GuardError::TargetMismatch);
        }
        let configuration = match &self.native_configuration {
            None => None,
            Some(NativeConfiguration::Gcp(snapshot)) => {
                if target.placement.kind != PlacementKind::GcpCloudSql
                    || target.resource.native_id
                        != format!(
                            "projects/{}/instances/{}",
                            snapshot.target.project_id, snapshot.target.instance_id
                        )
                    || target.placement.account_id != snapshot.target.project_id
                    || target.placement.region != snapshot.target.region
                    || target.engine.database != snapshot.target.database
                    || target.engine.family != EngineFamily::PostgreSql
                    || snapshot.engine_version != snapshot.target.engine_version
                    || snapshot
                        .target
                        .engine_version
                        .strip_prefix("POSTGRES_")
                        .map(|v| v.replace('_', "."))
                        .as_deref()
                        != Some(target.engine.version.as_str())
                    || self.configuration_observed_at != Some(snapshot.observed_at)
                    || self.origins.iter().any(|origin| {
                        !matches!(
                            origin,
                            ObservationOrigin::GcpLive | ObservationOrigin::Fixture
                        )
                    })
                {
                    return Err(GuardError::TargetMismatch);
                }
                let mut identities = BTreeMap::new();
                for access in &self.access {
                    if let ActorReference::GcpDeclaredServiceAccount {
                        principal_id,
                        service_account,
                    } = &access.actor
                    {
                        let registered = snapshot.registered_principal_ids.contains(principal_id);
                        if identities
                            .insert(service_account.clone(), registered)
                            .is_some_and(|old| old != registered)
                        {
                            return Err(GuardError::EvidenceIncompatible);
                        }
                    }
                }
                Some(ConfigurationFacts {
                    target: self.target.clone(),
                    observed_at: snapshot.observed_at,
                    complete: snapshot.complete,
                    native_iam_enabled: Some(snapshot.iam_auth_enabled),
                    connector_required: match snapshot.connector_enforcement {
                        GcpConnectorEnforcement::Required => Some(true),
                        GcpConnectorEnforcement::NotRequired => Some(false),
                        GcpConnectorEnforcement::Unknown => None,
                    },
                    identities: identities
                        .into_iter()
                        .map(|(principal, registered)| IdentityRegistration {
                            principal,
                            registered,
                        })
                        .collect(),
                })
            }
            Some(NativeConfiguration::Aws(snapshot)) => {
                if target.placement.kind != PlacementKind::AwsRds
                    || snapshot.target.account_id != target.placement.account_id
                    || snapshot.target.region != target.placement.region
                    || snapshot.target.db_instance_arn != target.resource.native_id
                    || snapshot.target.engine_version != target.engine.version
                    || snapshot.target.engine != "postgres"
                    || target.engine.family != EngineFamily::PostgreSql
                    || self.configuration_observed_at != Some(snapshot.observed_at)
                    || self.origins.contains(&ObservationOrigin::GcpLive)
                    || snapshot
                        .db
                        .as_ref()
                        .is_some_and(|db| db.arn != target.resource.native_id)
                {
                    return Err(GuardError::TargetMismatch);
                }
                Some(ConfigurationFacts {
                    target: self.target.clone(),
                    observed_at: snapshot.observed_at,
                    complete: snapshot.db.is_some()
                        && snapshot.proxy.is_some()
                        && snapshot.retrievals.len() == 6
                        && snapshot
                            .retrievals
                            .iter()
                            .all(|r| r.status == RetrievalStatus::Complete),
                    native_iam_enabled: None,
                    connector_required: None,
                    identities: vec![],
                })
            }
        };
        Ok(ChangeObservation {
            schema_version: self.schema_version,
            target_id: self.target_id.clone(),
            target: self.target.clone(),
            configuration_epoch: self.configuration_epoch.clone(),
            configuration,
            inventory_complete: self.inventory_complete,
            evaluated_at: self.evaluated_at,
            configuration_observed_at: self.configuration_observed_at,
            valid_until: self.valid_until,
            origins: self.origins.clone(),
            notices: self.notices.clone(),
            evidence_refs: self.evidence_refs.clone(),
        })
    }
}
