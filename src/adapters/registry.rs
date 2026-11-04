//! Explicit registration: implemented code is distinct from target qualification.
use crate::core::{
    capability::{
        ActionKind, CapabilityConstraint, CapabilityDescriptor, Coverage, Implementation, Support,
    },
    policy::{EngineFamily, PlacementKind, Target},
};

pub trait DeploymentAdapter {
    fn placement(&self) -> PlacementKind;
    fn capabilities(&self, target: &Target) -> Vec<CapabilityDescriptor>;
}
pub trait EngineAdapter {
    fn engine(&self) -> EngineFamily;
    fn capabilities(&self, target: &Target) -> Vec<CapabilityDescriptor>;
}

pub struct GcpCloudSqlAdapter;
pub struct AwsRdsAdapter;
pub struct PostgreSqlAdapter;
pub struct MySqlAdapter;

fn qualified_aws_engine(target: &Target) -> bool {
    match target.engine.family {
        EngineFamily::PostgreSql => target.engine.version == "16.15",
        EngineFamily::MySql => target.engine.version == "8.0.43" && target.mysql.is_some(),
        _ => false,
    }
}

const DEPLOYMENT_ACTIONS: &[ActionKind] = &[
    ActionKind::ObserveConfiguration,
    ActionKind::ObserveAccess,
    ActionKind::PrepareNativeRoute,
    ActionKind::ConfigureIdentity,
    ActionKind::RegisterNativeDbIdentity,
    ActionKind::PublishBinding,
    ActionKind::AwaitApplicationCutover,
    ActionKind::ConfirmRecoveryReadiness,
    ActionKind::ConstrainDirectPath,
    ActionKind::DisableNativeIdentity,
    ActionKind::ObserveRevocation,
    ActionKind::EnforceLeaseExpiry,
];
const ENGINE_ACTIONS: &[ActionKind] = &[
    ActionKind::ConfigureSqlPrivileges,
    ActionKind::DisableNewConnections,
    ActionKind::RevokeSqlPrivileges,
    ActionKind::DrainExistingSessions,
    ActionKind::TerminateSelectedSessions,
];

fn deployment_capabilities(target: &Target, placement: PlacementKind) -> Vec<CapabilityDescriptor> {
    DEPLOYMENT_ACTIONS
        .iter()
        .map(|action| {
            let mut capability =
                CapabilityDescriptor::planned(placement, target.engine.family, *action)
                    .for_target(target);
            if target.placement.kind == placement
                && target.engine.family == EngineFamily::PostgreSql
                && target.engine.version == "16.15"
                && match placement {
                    PlacementKind::GcpCloudSql => target.placement.region == "asia-northeast1",
                    PlacementKind::AwsRds => target.placement.region == "ap-northeast-1",
                    PlacementKind::SelfManaged => false,
                }
                && matches!(
                    action,
                    ActionKind::ObserveConfiguration | ActionKind::ObserveAccess
                )
            {
                capability.support = Support::Supported;
                capability.implementation = Implementation::Implemented;
                capability.coverage = Coverage::LocalCovered;
                capability.constraints = vec![
                    CapabilityConstraint::ReadOnlyBridge,
                    CapabilityConstraint::TargetGenerationUnconfirmed,
                ];
            } else {
                capability
                    .constraints
                    .push(CapabilityConstraint::TargetScopeNotQualified);
                if target.engine.version != "16.15" {
                    capability
                        .constraints
                        .push(CapabilityConstraint::VersionNotQualified);
                }
            }
            if placement == PlacementKind::GcpCloudSql
                && target.placement.kind == placement
                && target.engine.family == EngineFamily::PostgreSql
                && target.engine.version == "16.15"
                && target.placement.region == "asia-northeast1"
                && matches!(
                    action,
                    ActionKind::PrepareNativeRoute
                        | ActionKind::ConfigureIdentity
                        | ActionKind::RegisterNativeDbIdentity
                        | ActionKind::PublishBinding
                        | ActionKind::ConfirmRecoveryReadiness
                        | ActionKind::AwaitApplicationCutover
                        | ActionKind::ConstrainDirectPath
                        | ActionKind::DisableNativeIdentity
                        | ActionKind::ObserveRevocation
                )
            {
                capability.contract_revision = "core-adapter-v2".into();
                capability.support = Support::Supported;
                capability.implementation = Implementation::Implemented;
                capability.coverage = Coverage::LocalCovered;
                capability.constraints = vec![
                    CapabilityConstraint::TargetGenerationUnconfirmed,
                    CapabilityConstraint::ExternalConcurrencyUnprotected,
                    CapabilityConstraint::ManualHandoffRequired,
                ];
            }
            if placement == PlacementKind::AwsRds
                && target.placement.kind == placement
                && target.aws.is_some()
                && qualified_aws_engine(target)
                && target.placement.region == "ap-northeast-1"
                && matches!(
                    action,
                    ActionKind::PrepareNativeRoute
                        | ActionKind::ConfigureIdentity
                        | ActionKind::RegisterNativeDbIdentity
                        | ActionKind::PublishBinding
                        | ActionKind::ConfirmRecoveryReadiness
                        | ActionKind::AwaitApplicationCutover
                        | ActionKind::ConstrainDirectPath
                        | ActionKind::DisableNativeIdentity
                        | ActionKind::ObserveRevocation
                )
            {
                capability.contract_revision = if target.engine.family == EngineFamily::MySql {
                    "core-adapter-v3"
                } else {
                    "core-adapter-v2"
                }
                .into();
                capability.support = Support::Supported;
                capability.implementation = Implementation::Implemented;
                capability.coverage = Coverage::LocalCovered;
                capability.constraints = vec![
                    CapabilityConstraint::TargetGenerationUnconfirmed,
                    CapabilityConstraint::ExternalConcurrencyUnprotected,
                    CapabilityConstraint::ManualHandoffRequired,
                ];
            }
            if placement == PlacementKind::AwsRds
                && target.placement.kind == placement
                && target.aws.is_some()
                && qualified_aws_engine(target)
                && target.engine.family == EngineFamily::MySql
                && target.placement.region == "ap-northeast-1"
                && matches!(
                    action,
                    ActionKind::ObserveConfiguration | ActionKind::ObserveAccess
                )
            {
                capability.contract_revision = "core-adapter-v3".into();
                capability.support = Support::Supported;
                capability.implementation = Implementation::Implemented;
                capability.coverage = Coverage::LocalCovered;
                capability.constraints = vec![
                    CapabilityConstraint::ReadOnlyBridge,
                    CapabilityConstraint::TargetGenerationUnconfirmed,
                ];
            }
            capability
        })
        .collect()
}

impl DeploymentAdapter for GcpCloudSqlAdapter {
    fn placement(&self) -> PlacementKind {
        PlacementKind::GcpCloudSql
    }
    fn capabilities(&self, target: &Target) -> Vec<CapabilityDescriptor> {
        deployment_capabilities(target, self.placement())
    }
}
impl DeploymentAdapter for AwsRdsAdapter {
    fn placement(&self) -> PlacementKind {
        PlacementKind::AwsRds
    }
    fn capabilities(&self, target: &Target) -> Vec<CapabilityDescriptor> {
        deployment_capabilities(target, self.placement())
    }
}
impl EngineAdapter for PostgreSqlAdapter {
    fn engine(&self) -> EngineFamily {
        EngineFamily::PostgreSql
    }
    fn capabilities(&self, target: &Target) -> Vec<CapabilityDescriptor> {
        ENGINE_ACTIONS
            .iter()
            .map(|action| {
                let mut capability =
                    CapabilityDescriptor::planned(target.placement.kind, self.engine(), *action)
                        .for_target(target);
                if ((target.placement.kind == PlacementKind::GcpCloudSql
                    && target.placement.region == "asia-northeast1")
                    || (target.placement.kind == PlacementKind::AwsRds
                        && target.placement.region == "ap-northeast-1"
                        && target.aws.is_some()))
                    && target.engine.family == EngineFamily::PostgreSql
                    && target.engine.version == "16.15"
                    && matches!(
                        action,
                        ActionKind::ConfigureSqlPrivileges
                            | ActionKind::DisableNewConnections
                            | ActionKind::RevokeSqlPrivileges
                    )
                {
                    capability.contract_revision = "core-adapter-v2".into();
                    capability.support = Support::Supported;
                    capability.implementation = Implementation::Implemented;
                    capability.coverage = Coverage::LocalCovered;
                    capability.constraints = vec![
                        CapabilityConstraint::TargetGenerationUnconfirmed,
                        CapabilityConstraint::ExternalConcurrencyUnprotected,
                    ];
                }
                capability
            })
            .collect()
    }
}

impl EngineAdapter for MySqlAdapter {
    fn engine(&self) -> EngineFamily {
        EngineFamily::MySql
    }
    fn capabilities(&self, target: &Target) -> Vec<CapabilityDescriptor> {
        ENGINE_ACTIONS
            .iter()
            .map(|action| {
                let mut capability =
                    CapabilityDescriptor::planned(target.placement.kind, self.engine(), *action)
                        .for_target(target);
                if target.placement.kind == PlacementKind::AwsRds
                    && target.placement.region == "ap-northeast-1"
                    && target.aws.is_some()
                    && target.engine.family == EngineFamily::MySql
                    && qualified_aws_engine(target)
                    && matches!(
                        action,
                        ActionKind::ConfigureSqlPrivileges
                            | ActionKind::DisableNewConnections
                            | ActionKind::RevokeSqlPrivileges
                    )
                {
                    capability.contract_revision = "core-adapter-v3".into();
                    capability.support = Support::Supported;
                    capability.implementation = Implementation::Implemented;
                    capability.coverage = Coverage::LocalCovered;
                    capability.constraints = vec![
                        CapabilityConstraint::TargetGenerationUnconfirmed,
                        CapabilityConstraint::ExternalConcurrencyUnprotected,
                    ];
                }
                capability
            })
            .collect()
    }
}

/// Returns descriptors for the requested pair; a provider's name never implies
/// support for another engine, or for an unimplemented mutation.
pub fn capabilities_for(target: &Target) -> Vec<CapabilityDescriptor> {
    let mut capabilities = match target.placement.kind {
        PlacementKind::GcpCloudSql => GcpCloudSqlAdapter.capabilities(target),
        PlacementKind::AwsRds => AwsRdsAdapter.capabilities(target),
        PlacementKind::SelfManaged => DEPLOYMENT_ACTIONS
            .iter()
            .map(|action| {
                CapabilityDescriptor::planned(target.placement.kind, target.engine.family, *action)
                    .for_target(target)
            })
            .collect(),
    };
    capabilities.extend(if target.engine.family == EngineFamily::PostgreSql {
        PostgreSqlAdapter.capabilities(target)
    } else if target.engine.family == EngineFamily::MySql {
        MySqlAdapter.capabilities(target)
    } else {
        ENGINE_ACTIONS
            .iter()
            .map(|action| {
                CapabilityDescriptor::planned(target.placement.kind, target.engine.family, *action)
                    .for_target(target)
            })
            .collect()
    });
    capabilities
}

/// Current executable v2 scope. Runtime source identity, evidence and approval
/// are separately required by the composed executor, never inferred here.
pub fn source_execution_supported(policy: &crate::core::policy::PolicyRevision) -> bool {
    use crate::core::source::SourceBoundaryKind;
    policy.schema_version == 2
        && policy.targets.len() == 1
        && !policy.source_bindings.is_empty()
        && policy.targets.iter().all(|t| match t.placement.kind {
            PlacementKind::GcpCloudSql => {
                t.placement.region == "asia-northeast1"
                    && t.engine.family == EngineFamily::PostgreSql
                    && t.engine.version == "16.15"
                    && policy
                        .source_bindings
                        .iter()
                        .all(|s| s.boundary == SourceBoundaryKind::GceHostNetwork)
            }
            PlacementKind::AwsRds => {
                t.placement.region == "ap-northeast-1"
                    && t.aws.is_some()
                    && qualified_aws_engine(t)
                    && policy
                        .source_bindings
                        .iter()
                        .all(|s| s.boundary == SourceBoundaryKind::AwsHostNetwork)
            }
            _ => false,
        })
}

/// V1 registry is unchanged. Executable v2 uses a NEW contract for every action,
/// so evaluation-only v2 approvals are not silently enabled by this code update.
pub fn capabilities_for_policy(
    policy: &crate::core::policy::PolicyRevision,
) -> Result<Vec<CapabilityDescriptor>, crate::core::policy::PolicyError> {
    policy.validate()?;
    let executable = source_execution_supported(policy);
    Ok(policy
        .targets
        .iter()
        .flat_map(capabilities_for)
        .map(|mut c| {
            if executable && c.has_implementation() {
                c.contract_revision =
                    crate::core::source_execution::SOURCE_BOUND_EXECUTION_CONTRACT.into();
            } else if policy.schema_version == 2
                && crate::core::capability::requires_source_evidence(c.action)
            {
                c.contract_revision = crate::core::evidence::SOURCE_BOUND_ADAPTER_CONTRACT.into();
                c.implementation = Implementation::Planned;
                c.coverage = Coverage::None;
                c.constraints
                    .push(CapabilityConstraint::SourceEvidencePipelineMissing);
            }
            c
        })
        .collect())
}
