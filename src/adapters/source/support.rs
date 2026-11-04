//! Source collection and engine normalization are independent capabilities.
//! This report never proves that a registered runtime is available or protected.
use crate::core::{policy::*, source::*};
use serde::Serialize;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSupportReason {
    GceRootHostProfile,
    AwsEc2RootHostProfile,
    AwsMysqlMetadataProfileOptIn,
    AwsPostgresMetadataProfileOptIn,
    SourceBoundaryUnsupported,
    TargetProfileUnsupported,
    RuntimeBindingProducerUnavailable,
    RuntimeProcessSocketProfileOptIn,
    RuntimeUnixPeerProfileOptIn,
    RuntimeSessionAndPoolUnverified,
    NativeBoundaryDecisionUnavailable,
    ProviderManagedBackendTlsValidationUnobservable,
    PermissionInventoryProducerUnavailable,
    AwsBoundedIamInventoryProfileOptIn,
    HostKernelOriginRequiresRuntimeBinding,
    AwsDeferredRouteHistoryOnly,
    GcpConnectAuditCandidateProfileOptIn,
    GcpAuditLogOriginUnconfirmed,
    NativePostgresNoLoginProfile,
    GcpCompleteEffectiveIamProfileOptIn,
    MysqlNamedAclAbsenceProfile,
    OtherDenialLayersUnavailable,
    GcpFirewallRouteDenialProfileOptIn,
    GcpFirewallLogOriginUnconfirmed,
    AwsFlowLogWindowExceedsCaptureContract,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceCoverage {
    pub target_id: String,
    pub source_id: String,
    pub engine: EngineFamily,
    pub boundary: SourceBoundaryKind,
    pub collector_implemented: bool,
    pub normalizer_implemented: bool,
    pub native_verified: bool,
    pub reasons: Vec<SourceSupportReason>,
}
pub fn for_policy(p: &PolicyRevision) -> Result<Vec<SourceCoverage>, PolicyError> {
    p.validate()?;
    if p.schema_version != 2 {
        return Err(PolicyError::Invalid);
    }
    let mut rows = vec![];
    for g in &p.grants {
        let t = p
            .targets
            .iter()
            .find(|t| t.id == g.target)
            .ok_or(PolicyError::ReferenceInvalid)?;
        let subject = p
            .subjects
            .iter()
            .find(|s| s.id == g.subject)
            .ok_or(PolicyError::ReferenceInvalid)?;
        let profile = p
            .protection_profiles
            .iter()
            .find(|r| r.id == g.profile)
            .ok_or(PolicyError::ReferenceInvalid)?;
        let sources = subject.workload_sources.iter().chain(
            profile
                .management_exceptions
                .iter()
                .filter(|e| e.recovery)
                .flat_map(|e| &e.source_ids),
        );
        for id in sources {
            if rows
                .iter()
                .any(|r: &SourceCoverage| r.target_id == t.id && r.source_id == *id)
            {
                continue;
            }
            let binding = p
                .source_bindings
                .iter()
                .find(|b| b.source_id == *id)
                .ok_or(PolicyError::ReferenceInvalid)?;
            let gcp = t.placement.kind == PlacementKind::GcpCloudSql
                && t.engine.family == EngineFamily::PostgreSql
                && t.engine.version == "16.15"
                && t.placement.region == "asia-northeast1";
            let aws = t.placement.kind == PlacementKind::AwsRds
                && t.placement.region == "ap-northeast-1"
                && matches!(
                    (t.engine.family, t.engine.version.as_str()),
                    (EngineFamily::PostgreSql, "16.15") | (EngineFamily::MySql, "8.0.43")
                );
            let implemented = (gcp && binding.boundary == SourceBoundaryKind::GceHostNetwork)
                || (aws && binding.boundary == SourceBoundaryKind::AwsHostNetwork);
            let normalizer =
                implemented || (aws && binding.boundary == SourceBoundaryKind::AwsHostNetwork);
            let reason = if gcp && binding.boundary == SourceBoundaryKind::GceHostNetwork {
                SourceSupportReason::GceRootHostProfile
            } else if aws && binding.boundary == SourceBoundaryKind::AwsHostNetwork {
                SourceSupportReason::AwsEc2RootHostProfile
            } else if gcp || aws {
                SourceSupportReason::SourceBoundaryUnsupported
            } else {
                SourceSupportReason::TargetProfileUnsupported
            };
            let mut reasons = vec![reason, SourceSupportReason::OtherDenialLayersUnavailable];
            if gcp && binding.boundary == SourceBoundaryKind::GceHostNetwork {
                reasons.push(SourceSupportReason::RuntimeProcessSocketProfileOptIn);
                reasons.push(SourceSupportReason::RuntimeUnixPeerProfileOptIn);
                reasons.push(SourceSupportReason::RuntimeSessionAndPoolUnverified);
                reasons.push(SourceSupportReason::GcpConnectAuditCandidateProfileOptIn);
                reasons.push(SourceSupportReason::GcpAuditLogOriginUnconfirmed);
                reasons.push(SourceSupportReason::NativePostgresNoLoginProfile);
                reasons.push(SourceSupportReason::GcpFirewallRouteDenialProfileOptIn);
                reasons.push(SourceSupportReason::GcpFirewallLogOriginUnconfirmed);
                reasons.push(SourceSupportReason::GcpCompleteEffectiveIamProfileOptIn);
                reasons.push(SourceSupportReason::HostKernelOriginRequiresRuntimeBinding);
            } else {
                reasons.push(SourceSupportReason::RuntimeBindingProducerUnavailable);
                if aws && t.engine.family == EngineFamily::PostgreSql {
                    reasons.push(SourceSupportReason::NativePostgresNoLoginProfile);
                } else {
                    reasons.push(SourceSupportReason::NativeBoundaryDecisionUnavailable);
                }
                if aws && binding.boundary == SourceBoundaryKind::AwsHostNetwork {
                    reasons.push(SourceSupportReason::AwsBoundedIamInventoryProfileOptIn);
                } else {
                    reasons.push(SourceSupportReason::PermissionInventoryProducerUnavailable);
                }
            }
            if aws && binding.boundary == SourceBoundaryKind::AwsHostNetwork {
                if t.engine.family == EngineFamily::MySql {
                    reasons.push(SourceSupportReason::MysqlNamedAclAbsenceProfile);
                }
                reasons.push(if t.engine.family == EngineFamily::PostgreSql {
                    SourceSupportReason::AwsPostgresMetadataProfileOptIn
                } else {
                    SourceSupportReason::AwsMysqlMetadataProfileOptIn
                });
            }
            if aws {
                reasons.push(SourceSupportReason::AwsFlowLogWindowExceedsCaptureContract);
                reasons.push(SourceSupportReason::AwsDeferredRouteHistoryOnly);
                reasons.push(SourceSupportReason::ProviderManagedBackendTlsValidationUnobservable);
            }
            rows.push(SourceCoverage {
                target_id: t.id.clone(),
                source_id: id.clone(),
                engine: t.engine.family,
                boundary: binding.boundary,
                collector_implemented: implemented,
                normalizer_implemented: normalizer,
                native_verified: false,
                reasons,
            });
        }
    }
    Ok(rows)
}
