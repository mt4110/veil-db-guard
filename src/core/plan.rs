//! Immutable, policy-bound desired change graph. This module performs no I/O.
use super::hash_bytes;
use super::{
    capability::{ActionKind, CapabilityDescriptor, CapabilityGap, gap_for},
    policy::{
        AdmissionIntent, EffectKind, GrantLifetime, ManagedField, PlacementKind, PolicyRevision,
        Target,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanLimitation {
    ObservationRequired,
    TargetGenerationUnconfirmed,
    ActualDiffUnresolved,
    ApplicationHandoffRequired,
    NativeWritesNotImplemented,
    OperationJournalNotImplemented,
    RecoveryExecutionNotImplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precondition {
    TargetIdentityRevalidated,
    ManagedSurfaceRevalidated,
    NativeVersionMatches,
    NativeCasOrExclusiveChangeWindow,
    RecoveryRouteReady,
    RegisteredClientsMigrated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub id: String,
    pub target_id: String,
    pub grant_id: String,
    pub profile_id: String,
    pub action: ActionKind,
    /// Every parameter is resolved from the exact embedded policy revision.
    pub parameters_hash: String,
    pub dependencies: Vec<String>,
    pub adapter_contract: String,
    pub preconditions: Vec<Precondition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredEffectGap {
    pub target_id: String,
    pub grant_id: String,
    pub effect: EffectKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePlan {
    pub schema_version: u32,
    pub plan_hash: String,
    pub policy_revision_hash: String,
    pub build_id: String,
    pub created_at: u64,
    /// Declared target generations are preconditions, never verified identities.
    pub targets: Vec<Target>,
    pub steps: Vec<PlanStep>,
    pub capabilities: Vec<CapabilityDescriptor>,
    pub capability_gaps: Vec<CapabilityGap>,
    /// Effects without an action in this draft must remain explicit, even
    /// when the grant/profile combination is not yet executable.
    pub required_effect_gaps: Vec<RequiredEffectGap>,
    pub limitations: Vec<PlanLimitation>,
    pub observation_refs: Vec<String>,
    pub execution_available: bool,
    pub protection_evaluated: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("POLICY_INVALID: policy cannot be planned; input values are not echoed")]
    PolicyInvalid,
    #[error("CAPABILITY_INVALID: adapter capabilities do not match the policy")]
    CapabilityInvalid,
    #[error("PLAN_SCOPE_VIOLATION: a required change is outside the declared managed surface")]
    ScopeViolation,
}

/// No observed change, capability or operator statement becomes a claim that
/// the desired protection is applied. The first version intentionally emits
/// no executable receipt or approval: those require K04's durable executor.
pub fn build_plan(
    policy: &PolicyRevision,
    capabilities: Vec<CapabilityDescriptor>,
    observation_refs: Vec<String>,
    created_at: u64,
) -> Result<ChangePlan, PlanError> {
    build_selected_plan(policy, capabilities, observation_refs, created_at, None)
}

pub(crate) fn build_selected_plan(
    policy: &PolicyRevision,
    mut capabilities: Vec<CapabilityDescriptor>,
    mut observation_refs: Vec<String>,
    created_at: u64,
    selected: Option<&[String]>,
) -> Result<ChangePlan, PlanError> {
    policy.validate().map_err(|_| PlanError::PolicyInvalid)?;
    let normalized = policy.normalized();
    let policy = &normalized;
    let policy_hash = policy
        .revision_hash()
        .map_err(|_| PlanError::PolicyInvalid)?;
    observation_refs.sort();
    observation_refs.dedup();
    if observation_refs.len() > 128 || observation_refs.iter().any(|s| !is_digest(s)) {
        return Err(PlanError::CapabilityInvalid);
    }
    capabilities.sort_by_key(|c| (c.target_id.clone(), c.placement, c.engine, c.action));
    if capabilities.windows(2).any(|w| {
        (&w[0].target_id, w[0].placement, w[0].engine, w[0].action)
            == (&w[1].target_id, w[1].placement, w[1].engine, w[1].action)
    }) {
        return Err(PlanError::CapabilityInvalid);
    }
    for capability in &capabilities {
        if policy.schema_version == 2
            && super::capability::requires_source_evidence(capability.action)
            && !matches!(
                capability.contract_revision.as_str(),
                super::evidence::SOURCE_BOUND_ADAPTER_CONTRACT
                    | super::source_execution::SOURCE_BOUND_EXECUTION_CONTRACT
            )
        {
            return Err(PlanError::CapabilityInvalid);
        }
        if !policy.targets.iter().any(|target| {
            capability.target_id.as_deref() == Some(&target.id)
                && capability.engine_version.as_deref() == Some(&target.engine.version)
                && capability.placement == target.placement.kind
                && capability.engine == target.engine.family
        }) {
            return Err(PlanError::CapabilityInvalid);
        }
    }
    let mut steps = Vec::new();
    let mut gaps = Vec::new();
    let mut effect_gaps = Vec::new();
    let mut grants = policy.grants.iter().collect::<Vec<_>>();
    grants.sort_by(|a, b| a.id.cmp(&b.id));
    for grant in grants {
        let target = policy
            .targets
            .iter()
            .find(|t| t.id == grant.target)
            .ok_or(PlanError::PolicyInvalid)?;
        let profile = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(PlanError::PolicyInvalid)?;
        let mut actions = if grant.admission == AdmissionIntent::Allow {
            vec![
                ActionKind::PrepareNativeRoute,
                ActionKind::ConfigureIdentity,
                ActionKind::ConfigureSqlPrivileges,
                ActionKind::PublishBinding,
                ActionKind::ConfirmRecoveryReadiness,
                ActionKind::AwaitApplicationCutover,
                ActionKind::ConstrainDirectPath,
            ]
        } else {
            if matches!(
                target.placement.kind,
                PlacementKind::GcpCloudSql | PlacementKind::AwsRds
            ) {
                let mut deny = vec![
                    ActionKind::DisableNativeIdentity,
                    ActionKind::DisableNewConnections,
                ];
                if profile
                    .required_effects
                    .contains(&EffectKind::SqlPrivilegesRevoked)
                {
                    deny.push(ActionKind::RevokeSqlPrivileges);
                }
                deny.push(ActionKind::ObserveRevocation);
                deny
            } else {
                vec![ActionKind::DisableNewConnections]
            }
        };
        if grant.admission == AdmissionIntent::Allow
            && (target.placement.kind == PlacementKind::GcpCloudSql
                || (target.placement.kind == PlacementKind::AwsRds && target.aws.is_some()))
        {
            actions.insert(2, ActionKind::RegisterNativeDbIdentity);
        }
        if profile
            .required_effects
            .contains(&EffectKind::SessionsTerminated)
        {
            actions.push(ActionKind::TerminateSelectedSessions);
        }
        if matches!(grant.lifetime, GrantLifetime::Lease { .. }) {
            actions.push(ActionKind::EnforceLeaseExpiry);
        }
        for effect in &profile.required_effects {
            let action = match effect {
                EffectKind::BindingApplied => ActionKind::PublishBinding,
                EffectKind::NewConnectionsAllowed => ActionKind::ConfigureIdentity,
                EffectKind::NewConnectionsDenied => {
                    if grant.admission == AdmissionIntent::Allow {
                        ActionKind::ConstrainDirectPath
                    } else {
                        if matches!(
                            target.placement.kind,
                            PlacementKind::GcpCloudSql | PlacementKind::AwsRds
                        ) {
                            ActionKind::ObserveRevocation
                        } else {
                            ActionKind::DisableNewConnections
                        }
                    }
                }
                EffectKind::SessionsTerminated => ActionKind::TerminateSelectedSessions,
                EffectKind::SqlPrivilegesApplied => ActionKind::ConfigureSqlPrivileges,
                EffectKind::SqlPrivilegesRevoked => ActionKind::RevokeSqlPrivileges,
                EffectKind::LeaseExpired => ActionKind::EnforceLeaseExpiry,
            };
            if !actions.contains(&action) {
                effect_gaps.push(RequiredEffectGap {
                    target_id: target.id.clone(),
                    grant_id: grant.id.clone(),
                    effect: *effect,
                });
            }
        }
        let mut previous = None;
        for (index, action) in actions.into_iter().enumerate() {
            let fields = &target.managed_surface.fields;
            let needs = match action {
                ActionKind::PublishBinding => vec![ManagedField::ApplicationBinding],
                ActionKind::ConfigureIdentity => {
                    let mut f = vec![ManagedField::DbLogin];
                    match target.placement.kind {
                        PlacementKind::GcpCloudSql => f.push(ManagedField::GcpIamBinding),
                        PlacementKind::AwsRds => f.push(ManagedField::AwsIamBinding),
                        PlacementKind::SelfManaged => {}
                    }
                    f
                }
                ActionKind::RegisterNativeDbIdentity | ActionKind::DisableNewConnections => {
                    vec![ManagedField::DbLogin]
                }
                ActionKind::DisableNativeIdentity => match target.placement.kind {
                    PlacementKind::GcpCloudSql => vec![ManagedField::GcpIamBinding],
                    PlacementKind::AwsRds => vec![ManagedField::AwsIamBinding],
                    PlacementKind::SelfManaged => vec![],
                },
                ActionKind::RevokeSqlPrivileges => {
                    vec![ManagedField::DbRole, ManagedField::DbObjectPrivilege]
                }
                ActionKind::PrepareNativeRoute
                    if target.placement.kind == PlacementKind::GcpCloudSql =>
                {
                    vec![ManagedField::GcpDatabaseFlag]
                }
                ActionKind::ConstrainDirectPath => match target.placement.kind {
                    PlacementKind::GcpCloudSql => vec![ManagedField::GcpConnectorEnforcement],
                    PlacementKind::AwsRds => vec![ManagedField::AwsSecurityGroupRule],
                    PlacementKind::SelfManaged => vec![],
                },
                ActionKind::PrepareNativeRoute
                    if target.placement.kind == PlacementKind::AwsRds =>
                {
                    vec![ManagedField::AwsProxy]
                }
                _ => vec![],
            };
            if needs.iter().any(|field| !fields.contains(field))
                || !target
                    .managed_surface
                    .db_identities
                    .contains(&grant.db_identity)
            {
                return Err(PlanError::ScopeViolation);
            }
            let capability = capabilities
                .iter()
                .find(|c| {
                    c.target_id.as_deref() == Some(target.id.as_str())
                        && c.engine_version.as_deref() == Some(target.engine.version.as_str())
                        && c.placement == target.placement.kind
                        && c.engine == target.engine.family
                        && c.action == action
                })
                .cloned()
                .unwrap_or_else(|| {
                    let mut descriptor = CapabilityDescriptor::planned(
                        target.placement.kind,
                        target.engine.family,
                        action,
                    )
                    .for_target(target);
                    if policy.schema_version == 2
                        && super::capability::requires_source_evidence(action)
                    {
                        descriptor.contract_revision =
                            super::evidence::SOURCE_BOUND_ADAPTER_CONTRACT.into();
                        descriptor.constraints.push(
                            super::capability::CapabilityConstraint::SourceEvidencePipelineMissing,
                        );
                    }
                    descriptor
                });
            if let Some(gap) = gap_for(&target.id, &capability)
                && !gaps.contains(&gap)
            {
                gaps.push(gap);
            }
            let id = format!("{}-step-{index}", grant.id);
            let parameters = if policy.schema_version == 1 {
                serde_json::to_vec(&(&policy_hash, grant, profile, action))
            } else {
                serde_json::to_vec(&(
                    &policy_hash,
                    grant,
                    profile,
                    action,
                    &policy.source_bindings,
                    &policy.evaluation,
                ))
            }
            .map_err(|_| PlanError::PolicyInvalid)?;
            let parameters_hash = hash_bytes(&parameters);
            steps.push(PlanStep {
                id: id.clone(),
                target_id: target.id.clone(),
                grant_id: grant.id.clone(),
                profile_id: grant.profile.clone(),
                action,
                parameters_hash,
                dependencies: previous.into_iter().collect(),
                adapter_contract: capability.contract_revision,
                preconditions: {
                    let mut requirements = vec![
                        Precondition::TargetIdentityRevalidated,
                        Precondition::ManagedSurfaceRevalidated,
                        Precondition::NativeVersionMatches,
                        Precondition::NativeCasOrExclusiveChangeWindow,
                    ];
                    if action == ActionKind::ConstrainDirectPath {
                        requirements.extend([
                            Precondition::RecoveryRouteReady,
                            Precondition::RegisteredClientsMigrated,
                        ]);
                    }
                    requirements
                },
            });
            previous = Some(id);
        }
    }
    // A shared instance boundary must wait for EVERY application and recovery
    // handoff on that target, not just whichever grant was visited first.
    let barriers = steps
        .iter()
        .filter(|s| {
            matches!(
                s.action,
                ActionKind::AwaitApplicationCutover | ActionKind::ConfirmRecoveryReadiness
            )
        })
        .map(|s| (s.target_id.clone(), s.id.clone()))
        .collect::<Vec<_>>();
    for step in &mut steps {
        if step.action == ActionKind::ConstrainDirectPath {
            step.dependencies.extend(
                barriers
                    .iter()
                    .filter(|(target, _)| target == &step.target_id)
                    .map(|(_, id)| id.clone()),
            );
            step.dependencies.sort();
            step.dependencies.dedup();
        }
    }
    if let Some(selected) = selected {
        if selected.is_empty()
            || selected.len() > steps.len()
            || selected.iter().any(|id| !steps.iter().any(|s| &s.id == id))
            || selected
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != selected.len()
        {
            return Err(PlanError::CapabilityInvalid);
        }
        let grants = steps
            .iter()
            .filter(|s| selected.contains(&s.id))
            .map(|s| s.grant_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        steps.retain(|s| selected.contains(&s.id));
        for step in &mut steps {
            step.dependencies.retain(|id| selected.contains(id));
        }
        gaps.retain(|gap| {
            steps
                .iter()
                .any(|s| s.target_id == gap.target_id && s.action == gap.action)
        });
        effect_gaps.retain(|gap| grants.contains(&gap.grant_id));
    }
    let mut targets = policy.targets.clone();
    targets.sort_by(|a, b| a.id.cmp(&b.id));
    let mut limitations = vec![
        PlanLimitation::TargetGenerationUnconfirmed,
        PlanLimitation::ActualDiffUnresolved,
        PlanLimitation::ApplicationHandoffRequired,
        PlanLimitation::RecoveryExecutionNotImplemented,
    ];
    if !gaps.is_empty() {
        limitations.push(PlanLimitation::NativeWritesNotImplemented);
    }
    if observation_refs.is_empty() {
        limitations.insert(0, PlanLimitation::ObservationRequired);
    }
    let mut result = ChangePlan {
        schema_version: 1,
        plan_hash: String::new(),
        policy_revision_hash: policy_hash,
        build_id: crate::BUILD_ID.into(),
        created_at,
        targets,
        steps,
        capabilities,
        capability_gaps: gaps,
        required_effect_gaps: effect_gaps,
        limitations,
        observation_refs,
        execution_available: false,
        protection_evaluated: false,
    };
    result.plan_hash =
        hash_bytes(&serde_json::to_vec(&result).map_err(|_| PlanError::PolicyInvalid)?);
    Ok(result)
}

fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Revalidate a stored plan's meaning under this adapter contract. The capture
/// build remains provenance, so an unrelated new executable build does not
/// invalidate a durable operation. Any changed graph/contract/scope still fails.
pub fn verify_plan(policy: &PolicyRevision, plan: &ChangePlan) -> Result<(), PlanError> {
    if !is_digest(&plan.build_id) || !is_digest(&plan.plan_hash) {
        return Err(PlanError::CapabilityInvalid);
    }
    verify_selected_plan(policy, plan, None)
}
pub(crate) fn verify_selected_plan(
    policy: &PolicyRevision,
    plan: &ChangePlan,
    selected: Option<&[String]>,
) -> Result<(), PlanError> {
    let mut rebuilt = build_selected_plan(
        policy,
        plan.capabilities.clone(),
        plan.observation_refs.clone(),
        plan.created_at,
        selected,
    )?;
    rebuilt.build_id = plan.build_id.clone();
    rebuilt.plan_hash.clear();
    rebuilt.plan_hash =
        hash_bytes(&serde_json::to_vec(&rebuilt).map_err(|_| PlanError::PolicyInvalid)?);
    if serde_json::to_vec(&rebuilt).map_err(|_| PlanError::PolicyInvalid)?
        != serde_json::to_vec(plan).map_err(|_| PlanError::PolicyInvalid)?
    {
        return Err(PlanError::CapabilityInvalid);
    }
    Ok(())
}
