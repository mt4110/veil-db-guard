//! Fixed case planning. No nonce, source verification, credential, or network IO.
use super::gce_host::CollectorConfig;
use crate::core::{
    admission::AdmissionError, change::PreparedChange, evidence::*, policy::*, source::*,
    state_v2::desired_for_change_v2,
};
use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
pub struct CasePlan {
    pub schema_version: u32,
    pub source_id: String,
    pub batches: Vec<Vec<RequestedCase>>,
    pub uncollected_required_effects: Vec<String>,
    pub source_verified: bool,
}
pub fn plan(
    change: &PreparedChange,
    source_id: &str,
    config: &CollectorConfig,
    now: u64,
) -> Result<CasePlan, AdmissionError> {
    config
        .validate_runtime_unix()
        .map_err(|_| AdmissionError::Invalid)?;
    if let Some(runtime) = &config.runtime {
        runtime.validate().map_err(|_| AdmissionError::Invalid)?;
    }
    plan_endpoints(
        change,
        source_id,
        &config.registration_id,
        &config.endpoints,
        |address| {
            address.target.placement.kind == PlacementKind::GcpCloudSql
                && (config
                    .runtime_unix
                    .iter()
                    .any(|binding| binding.matches(address))
                    || config.runtime.as_ref().is_some_and(|runtime| {
                        runtime.bindings.iter().any(|binding| {
                            binding.target_id == address.target_id
                                && binding.grant_id == address.grant_id
                                && binding.subject_id == address.subject_id
                        })
                    }))
        },
        now,
    )
}
pub fn plan_aws(
    change: &PreparedChange,
    source_id: &str,
    config: &super::aws_host::AwsCollectorConfig,
    now: u64,
) -> Result<CasePlan, AdmissionError> {
    if let Some(runtime) = &config.postgres_runtime {
        runtime.validate().map_err(|_| AdmissionError::Invalid)?;
    }
    plan_endpoints(
        change,
        source_id,
        &config.registration_id,
        &config.endpoints,
        |address| {
            address.target.placement.kind == PlacementKind::AwsRds
                && address.target.engine_binding.version == "16.15"
                && config
                    .postgres_runtime
                    .as_ref()
                    .is_some_and(|runtime| runtime.matches(address))
        },
        now,
    )
}
fn plan_endpoints(
    change: &PreparedChange,
    source_id: &str,
    registration_id: &str,
    endpoints: &[super::gce_host::CollectorEndpoint],
    runtime_matches: impl Fn(&EffectAddress) -> bool,
    now: u64,
) -> Result<CasePlan, AdmissionError> {
    change.verify().map_err(|_| AdmissionError::Invalid)?;
    let source = change
        .policy
        .source_bindings
        .iter()
        .find(|s| s.source_id == source_id)
        .ok_or(AdmissionError::ScopeMismatch)?;
    if source.registration_id != registration_id {
        return Err(AdmissionError::ScopeMismatch);
    }
    let desired = desired_for_change_v2(&change.policy, change.previous_policy.as_ref(), &[], now)
        .map_err(|_| AdmissionError::Invalid)?;
    let mut cases = vec![];
    let mut uncollected = vec![];
    for d in desired
        .iter()
        .filter(|d| d.address.source.source_id == source_id)
    {
        let purpose = source
            .allowed_uses
            .iter()
            .find(|u| u.subject_id == d.address.subject_id)
            .ok_or(AdmissionError::ScopeMismatch)?
            .purpose;
        let kind = match d.address.effect {
            EffectKindV2::NewConnections if d.address.route.kind == RouteKind::Direct => {
                Some(FixedObservationCase::DirectPath)
            }
            EffectKindV2::NewConnections if purpose == SourcePurpose::Recovery => {
                Some(FixedObservationCase::TargetHealth)
            }
            EffectKindV2::NewConnections => Some(FixedObservationCase::NewConnection),
            EffectKindV2::EffectiveSqlPrivilege { .. } | EffectKindV2::EffectiveSqlRole { .. } => {
                Some(FixedObservationCase::EffectiveSqlPrivilege)
            }
            EffectKindV2::Transport { .. } => Some(FixedObservationCase::Transport),
            EffectKindV2::RuntimeBinding
                if purpose == SourcePurpose::Application
                    && d.address.target.engine_binding.family == EngineFamily::PostgreSql
                    && runtime_matches(&d.address) =>
            {
                Some(FixedObservationCase::RuntimeBinding)
            }
            _ => None,
        };
        let Some(kind) = kind else {
            uncollected.push(d.id.clone());
            continue;
        };
        for e in endpoints.iter().filter(|e| {
            e.target_id == d.address.target_id
                && e.native_id == d.address.target.native_ref.native_id
                && e.database == d.address.target.engine_binding.database
                && change
                    .policy
                    .targets
                    .iter()
                    .find(|t| t.id == d.address.target_id)
                    .and_then(|t| t.aws.as_ref())
                    .is_none_or(|aws| {
                        e.endpoint
                            == if kind == FixedObservationCase::DirectPath {
                                aws.db_endpoint.as_str()
                            } else {
                                aws.proxy_endpoint.as_str()
                            }
                    })
                && Some(e.generation_digest.as_str())
                    == d.address
                        .target
                        .native_ref
                        .generation_fingerprint
                        .as_deref()
        }) {
            let mut case = RequestedCase {
                backend_tls_trust: d.backend_tls_trust,
                login_catalog_targets: vec![],
                mysql_account_host: change
                    .policy
                    .targets
                    .iter()
                    .find(|t| t.id == d.address.target_id)
                    .and_then(|t| t.mysql.as_ref())
                    .map(|m| {
                        if purpose == SourcePurpose::Recovery {
                            m.management_account_host.clone()
                        } else {
                            m.account_host.clone()
                        }
                    }),
                id: format!("case-{}", cases.len() + 1),
                kind,
                address: d.address.clone(),
                purpose,
                endpoint: e.endpoint.clone(),
                port: e.port,
                address_family: if e.ip.is_ipv4() {
                    AddressFamily::Ipv4
                } else {
                    AddressFamily::Ipv6
                },
            };
            if d.accepted_denial_layers
                .contains(&AcceptedDenialLayer::DatabaseLogin)
            {
                case.login_catalog_targets =
                    crate::core::postgres_login::authorized_targets(&change.policy, &case);
            }
            cases.push(case);
        }
        if !cases.iter().any(|c| c.address == d.address) {
            return Err(AdmissionError::ScopeMismatch);
        }
    }
    if cases.is_empty() || cases.len() > 32768 {
        return Err(AdmissionError::Limit);
    }
    // AWS witness captures accept one issued RuntimeBinding case. Keep these
    // cases separate from ordinary SSH probe batches.
    let (detached, regular): (Vec<_>, Vec<_>) = cases.into_iter().partition(|case| {
        case.address.source.boundary == SourceBoundaryKind::AwsHostNetwork
            && case.kind == FixedObservationCase::RuntimeBinding
    });
    Ok(CasePlan {
        schema_version: 1,
        source_id: source_id.into(),
        batches: regular
            .chunks(MAX_CASES_PER_SOURCE)
            .map(|c| c.to_vec())
            .chain(detached.into_iter().map(|case| vec![case]))
            .collect(),
        uncollected_required_effects: uncollected,
        source_verified: false,
    })
}
