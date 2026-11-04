//! A native feature, implemented operation and observed effect are different facts.
use super::policy::{EngineFamily, PlacementKind, Target};
use serde::{Deserialize, Serialize};

macro_rules! choice {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}
choice!(ActionKind {
    ObserveConfiguration,
    ObserveAccess,
    PrepareNativeRoute,
    ConfigureIdentity,
    RegisterNativeDbIdentity,
    ConfigureSqlPrivileges,
    PublishBinding,
    ConfirmRecoveryReadiness,
    AwaitApplicationCutover,
    ConstrainDirectPath,
    DisableNativeIdentity,
    DisableNewConnections,
    RevokeSqlPrivileges,
    ObserveRevocation,
    DrainExistingSessions,
    TerminateSelectedSessions,
    EnforceLeaseExpiry,
    CompensateOwnedIam
});
choice!(Support {
    Supported,
    Unsupported,
    Unknown
});
choice!(Implementation {
    Planned,
    Implemented
});
choice!(Coverage {
    None,
    LocalCovered,
    PlatformObserved,
    TargetObserved
});
choice!(CapabilityConstraint {
    VersionNotQualified,
    TargetGenerationUnconfirmed,
    ExternalConcurrencyUnprotected,
    ManualHandoffRequired,
    SharedIdentityUnattributed,
    NativeExpiryUnavailable,
    ExplicitReconcilerRequired,
    NoEvidence,
    ReadOnlyBridge,
    TargetScopeNotQualified,
    SourceEvidencePipelineMissing
});

/// Actions whose completion depends on source-bound observation in policy v2.
pub fn requires_source_evidence(action: ActionKind) -> bool {
    matches!(
        action,
        ActionKind::ObserveAccess
            | ActionKind::ConfirmRecoveryReadiness
            | ActionKind::ConstrainDirectPath
            | ActionKind::DisableNewConnections
            | ActionKind::ObserveRevocation
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescriptor {
    pub target_id: Option<String>,
    pub engine_version: Option<String>,
    pub placement: PlacementKind,
    pub engine: EngineFamily,
    pub action: ActionKind,
    pub contract_revision: String,
    pub support: Support,
    pub implementation: Implementation,
    pub coverage: Coverage,
    pub constraints: Vec<CapabilityConstraint>,
    pub evidence_refs: Vec<String>,
}
impl CapabilityDescriptor {
    /// No provider feature or operational qualification is inferred from its name.
    pub fn planned(placement: PlacementKind, engine: EngineFamily, action: ActionKind) -> Self {
        Self {
            target_id: None,
            engine_version: None,
            placement,
            engine,
            action,
            contract_revision: "core-adapter-v1".into(),
            support: Support::Unknown,
            implementation: Implementation::Planned,
            coverage: Coverage::None,
            constraints: vec![CapabilityConstraint::NoEvidence],
            evidence_refs: vec![],
        }
    }

    pub fn for_target(mut self, target: &Target) -> Self {
        self.target_id = Some(target.id.clone());
        self.engine_version = Some(target.engine.version.clone());
        self
    }

    /// This does not check target identity, freshness, ownership, approval or
    /// concurrency preconditions and must never authorize an execution.
    pub fn has_implementation(&self) -> bool {
        self.support == Support::Supported && self.implementation == Implementation::Implemented
    }
}

choice!(GapReason {
    Unsupported,
    NativeSupportUnknown,
    ImplementationMissing
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGap {
    pub target_id: String,
    pub action: ActionKind,
    pub reason: GapReason,
}

pub fn gap_for(target_id: &str, capability: &CapabilityDescriptor) -> Option<CapabilityGap> {
    let reason = match (capability.support, capability.implementation) {
        (Support::Unsupported, _) => GapReason::Unsupported,
        (Support::Unknown, _) => GapReason::NativeSupportUnknown,
        (_, Implementation::Planned) => GapReason::ImplementationMissing,
        _ => return None,
    };
    Some(CapabilityGap {
        target_id: target_id.into(),
        action: capability.action,
        reason,
    })
}
