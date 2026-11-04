//! Scoped maintenance/revocation plans. They reference the trusted ledger's
//! source operation; hashes alone never establish that the source was executed.
use super::{
    capability::{ActionKind, CapabilityDescriptor},
    change::{self, ChangeError, OperationLimits, PreparedChange},
    observation::ChangeObservation,
    owned_iam::OwnedIamDeltaReceipt,
    plan,
    policy::*,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleKind {
    Reconcile,
    Recover,
    Revoke,
    CompensateOwnedIam,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleContext {
    pub kind: LifecycleKind,
    pub source_operation_id: String,
    pub source_change_hash: String,
    pub source_policy_revision_hash: String,
    pub selected_step_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owned_iam: Option<OwnedIamDeltaReceipt>,
}
impl LifecycleContext {
    pub fn validate(
        &self,
        policy: &PolicyRevision,
        previous: Option<&PolicyRevision>,
        graph: &plan::ChangePlan,
    ) -> Result<(), ChangeError> {
        if !valid_id(&self.source_operation_id)
            || !valid_hash(&self.source_change_hash)
            || !valid_hash(&self.source_policy_revision_hash)
            || self.selected_step_ids.is_empty()
            || self.selected_step_ids.len() > 4096
            || self.selected_step_ids.windows(2).any(|w| w[0] >= w[1])
            || graph.steps.len() != self.selected_step_ids.len()
            || graph
                .steps
                .iter()
                .any(|s| !self.selected_step_ids.contains(&s.id))
        {
            return Err(ChangeError::Invalid);
        }
        if self.kind == LifecycleKind::CompensateOwnedIam {
            let receipt = self.owned_iam.as_ref().ok_or(ChangeError::Invalid)?;
            let previous = previous.ok_or(ChangeError::PreviousPolicyRequired)?;
            if self.source_operation_id != receipt.source_operation_id
                || self.source_change_hash != receipt.source_change_hash
                || self.source_policy_revision_hash != receipt.source_policy_revision_hash
                || graph.created_at < receipt.after_read_at
                || &owned_iam_deny_child(previous, receipt)? != policy
            {
                return Err(ChangeError::TargetMismatch);
            }
            return Ok(());
        }
        if self.owned_iam.is_some() {
            return Err(ChangeError::Invalid);
        }
        let source_hash = if self.kind == LifecycleKind::Revoke {
            previous
                .ok_or(ChangeError::PreviousPolicyRequired)?
                .revision_hash()
        } else {
            policy.revision_hash()
        }
        .map_err(|_| ChangeError::Invalid)?;
        if source_hash != self.source_policy_revision_hash {
            return Err(ChangeError::TargetMismatch);
        }
        for step in &graph.steps {
            let grant = policy
                .grants
                .iter()
                .find(|g| g.id == step.grant_id)
                .ok_or(ChangeError::Invalid)?;
            let permitted = if self.kind == LifecycleKind::Revoke {
                grant.admission == AdmissionIntent::Deny
                    && matches!(
                        step.action,
                        ActionKind::DisableNativeIdentity
                            | ActionKind::DisableNewConnections
                            | ActionKind::RevokeSqlPrivileges
                            | ActionKind::ObserveRevocation
                            | ActionKind::TerminateSelectedSessions
                    )
            } else if grant.admission == AdmissionIntent::Deny {
                matches!(
                    step.action,
                    ActionKind::DisableNativeIdentity
                        | ActionKind::DisableNewConnections
                        | ActionKind::RevokeSqlPrivileges
                        | ActionKind::ObserveRevocation
                )
            } else {
                matches!(
                    step.action,
                    ActionKind::PrepareNativeRoute
                        | ActionKind::ConfigureIdentity
                        | ActionKind::RegisterNativeDbIdentity
                        | ActionKind::ConfigureSqlPrivileges
                        | ActionKind::ConstrainDirectPath
                )
            };
            if !permitted {
                return Err(ChangeError::Invalid);
            }
        }
        Ok(())
    }
}

/// A new bounded approval is required for every returned change. This does not
/// reuse an old forward grant, automatically restore an Allow, or run native I/O.
#[allow(clippy::too_many_arguments)]
pub fn prepare_maintenance(
    source: &PreparedChange,
    source_operation_id: &str,
    kind: LifecycleKind,
    grant_id: &str,
    observations: &[ChangeObservation],
    capabilities: Vec<CapabilityDescriptor>,
    created_at: u64,
    limits: OperationLimits,
    revoke_sql: bool,
) -> Result<PreparedChange, ChangeError> {
    source.verify()?;
    if kind == LifecycleKind::CompensateOwnedIam {
        return Err(ChangeError::Invalid);
    }
    if kind != LifecycleKind::Revoke
        && source
            .lifecycle
            .as_ref()
            .is_some_and(|c| c.kind != LifecycleKind::Revoke)
    {
        return Err(ChangeError::Invalid);
    }
    if limits.max_attempts > source.limits.max_attempts
        || limits.max_operation_seconds > source.limits.max_operation_seconds
        || limits.max_repair_executions > source.limits.max_repair_executions
    {
        return Err(ChangeError::Invalid);
    }
    if created_at < source.plan.created_at {
        return Err(ChangeError::Invalid);
    }
    let mut policy = source.policy.clone();
    let mut previous = source.previous_policy.clone();
    let source_hash = policy.revision_hash().map_err(|_| ChangeError::Invalid)?;
    if kind == LifecycleKind::Revoke {
        previous = Some(policy.clone());
        deny_grant(
            &mut policy,
            grant_id,
            &source_hash,
            revoke_sql,
            format!("{grant_id}-revoke"),
        )?;
    } else if revoke_sql {
        return Err(ChangeError::Invalid);
    }
    policy.validate().map_err(|_| ChangeError::Invalid)?;
    let refs = observations
        .iter()
        .map(|state| {
            let mut bytes = serde_json::to_vec_pretty(state).map_err(|_| ChangeError::Invalid)?;
            bytes.push(b'\n');
            Ok(super::hash_bytes(&bytes))
        })
        .collect::<Result<Vec<_>, ChangeError>>()?;
    let full = plan::build_plan(&policy, capabilities.clone(), refs.clone(), created_at)
        .map_err(|_| ChangeError::Invalid)?;
    let mut selected = full
        .steps
        .iter()
        .filter(|s| {
            s.grant_id == grant_id
                && (kind == LifecycleKind::Revoke
                    || !matches!(
                        s.action,
                        ActionKind::PublishBinding
                            | ActionKind::ConfirmRecoveryReadiness
                            | ActionKind::AwaitApplicationCutover
                    ))
        })
        .map(|s| s.id.clone())
        .collect::<Vec<_>>();
    selected.sort();
    let graph = plan::build_selected_plan(&policy, capabilities, refs, created_at, Some(&selected))
        .map_err(|_| ChangeError::Invalid)?;
    let context = LifecycleContext {
        kind,
        source_operation_id: source_operation_id.into(),
        source_change_hash: source.change_hash.clone(),
        source_policy_revision_hash: source_hash,
        selected_step_ids: selected,
        owned_iam: None,
    };
    context.validate(&policy, previous.as_ref(), &graph)?;
    change::prepare_lifecycle_change(
        &policy,
        &graph,
        observations,
        previous.as_ref(),
        limits,
        context,
    )
}

fn deny_grant(
    policy: &mut PolicyRevision,
    grant_id: &str,
    source_hash: &str,
    revoke_sql: bool,
    profile_id: String,
) -> Result<(), ChangeError> {
    let grant = policy
        .grants
        .iter_mut()
        .find(|g| g.id == grant_id)
        .ok_or(ChangeError::Invalid)?;
    if grant.admission != AdmissionIntent::Allow {
        return Err(ChangeError::Invalid);
    }
    grant.admission = AdmissionIntent::Deny;
    grant.sql_access = SqlAccessIntent {
        existing_roles: vec![],
        privileges: vec![],
    };
    let prior = policy
        .protection_profiles
        .iter()
        .find(|p| p.id == grant.profile)
        .ok_or(ChangeError::Invalid)?
        .clone();
    let prior_profile_id = prior.id.clone();
    let mut profile = prior;
    profile.id = profile_id;
    if !valid_id(&profile.id)
        || policy
            .protection_profiles
            .iter()
            .any(|p| p.id == profile.id)
    {
        return Err(ChangeError::Invalid);
    }
    profile.required_effects = vec![EffectKind::NewConnectionsDenied];
    if revoke_sql {
        profile
            .required_effects
            .push(EffectKind::SqlPrivilegesRevoked);
    }
    grant.profile = profile.id.clone();
    if let Some(evaluation) = &mut policy.evaluation {
        let mut requirement = evaluation
            .denial_requirements
            .iter()
            .find(|r| r.profile_id == prior_profile_id)
            .ok_or(ChangeError::Invalid)?
            .clone();
        requirement.profile_id = profile.id.clone();
        evaluation.denial_requirements.push(requirement);
    }
    policy.protection_profiles.push(profile);
    policy.revision = policy.revision.checked_add(1).ok_or(ChangeError::Invalid)?;
    policy.parent_revision_hash = Some(source_hash.into());
    Ok(())
}

/// Build from a receipt authenticated by the ledger. The caller must check
/// source state, current desired head and duplicate consumption in the ledger.
pub fn prepare_owned_iam_compensation(
    source: &PreparedChange,
    receipt: &OwnedIamDeltaReceipt,
    grant_id: &str,
    created_at: u64,
    limits: OperationLimits,
) -> Result<PreparedChange, ChangeError> {
    source.verify()?;
    if !receipt.matches_change(source)
        || receipt.grant_id != grant_id
        || receipt.before_read_at < source.plan.created_at
        || created_at < receipt.after_read_at
        || limits.max_attempts > source.limits.max_attempts
        || limits.max_operation_seconds > source.limits.max_operation_seconds
        || limits.max_repair_executions != 0
    {
        return Err(ChangeError::Invalid);
    }
    let policy = owned_iam_deny_child(&source.policy, receipt)?;
    let graph = plan::build_owned_iam_plan(&policy, receipt, created_at, crate::BUILD_ID)
        .map_err(|_| ChangeError::Invalid)?;
    let context = LifecycleContext {
        kind: LifecycleKind::CompensateOwnedIam,
        source_operation_id: receipt.source_operation_id.clone(),
        source_change_hash: receipt.source_change_hash.clone(),
        source_policy_revision_hash: receipt.source_policy_revision_hash.clone(),
        selected_step_ids: vec![graph.steps[0].id.clone()],
        owned_iam: Some(receipt.clone()),
    };
    change::prepare_lifecycle_change(&policy, &graph, &[], Some(&source.policy), limits, context)
}

fn owned_iam_deny_child(
    previous: &PolicyRevision,
    receipt: &OwnedIamDeltaReceipt,
) -> Result<PolicyRevision, ChangeError> {
    if previous.schema_version != SOURCE_BOUND_POLICY_SCHEMA_VERSION
        || !receipt.validate()
        || previous.revision_hash().map_err(|_| ChangeError::Invalid)?
            != receipt.source_policy_revision_hash
    {
        return Err(ChangeError::Invalid);
    }
    let grant = previous
        .grants
        .iter()
        .find(|grant| grant.id == receipt.grant_id)
        .ok_or(ChangeError::Invalid)?;
    let target = previous
        .targets
        .iter()
        .find(|target| target.id == grant.target)
        .ok_or(ChangeError::Invalid)?;
    let subject = previous
        .subjects
        .iter()
        .find(|subject| subject.id == grant.subject)
        .ok_or(ChangeError::Invalid)?;
    let profile = previous
        .protection_profiles
        .iter()
        .find(|profile| profile.id == grant.profile)
        .ok_or(ChangeError::Invalid)?;
    if grant.admission != AdmissionIntent::Allow
        || profile.kind != ProfileKind::GcpCloudSqlPostgresConnectorV1
        || !receipt.matches_scope(&previous.policy_id, target, grant, subject)
    {
        return Err(ChangeError::TargetMismatch);
    }
    if owned_iam_conflicts_with_policy(previous, receipt, Some(&grant.id)) {
        return Err(ChangeError::TargetMismatch);
    }
    let mut child = previous.clone();
    let profile_id = format!(
        "owned-iam-deny-{}",
        change::digest("gcp-iam-owned-compensation-profile", &grant.id)?
    );
    deny_grant(
        &mut child,
        &grant.id,
        &receipt.source_policy_revision_hash,
        false,
        profile_id,
    )?;
    child.validate().map_err(|_| ChangeError::Invalid)?;
    Ok(child.normalized())
}

/// Check use of the receipted IAM identity on the same native instance, even
/// when a second policy uses different logical target, subject and grant IDs.
pub(crate) fn owned_iam_conflicts_with_policy(
    policy: &PolicyRevision,
    receipt: &OwnedIamDeltaReceipt,
    ignore_grant_id: Option<&str>,
) -> bool {
    let same_identity = |id: &str| {
        policy.subjects.iter().any(|subject| {
            subject.id == id
                && subject.identity.provider == IdentityProvider::Gcp
                && (subject
                    .identity
                    .principal
                    .eq_ignore_ascii_case(&receipt.service_account_email)
                    || subject.identity.immutable_id.as_ref()
                        == Some(&receipt.service_account_unique_id))
        })
    };
    policy
        .targets
        .iter()
        .filter(|target| {
            target.placement.kind == PlacementKind::GcpCloudSql
                && target.placement.account_id == receipt.project_id
                && target.resource.native_id == receipt.native_resource_id
        })
        .any(|target| {
            policy
                .grants
                .iter()
                .filter(|grant| grant.target == target.id)
                .any(|grant| {
                    (ignore_grant_id != Some(grant.id.as_str())
                        && grant.admission == AdmissionIntent::Allow
                        && (same_identity(&grant.subject) || grant.db_identity == receipt.db_login))
                        || policy.protection_profiles.iter().any(|profile| {
                            profile.id == grant.profile
                                && profile
                                    .management_exceptions
                                    .iter()
                                    .any(|exception| same_identity(&exception.subject))
                        })
                })
        })
}

pub fn validate_source(
    change: &PreparedChange,
    source: &PreparedChange,
) -> Result<(), ChangeError> {
    let Some(context) = &change.lifecycle else {
        return Ok(());
    };
    if source.change_hash != context.source_change_hash
        || source.plan.policy_revision_hash != context.source_policy_revision_hash
    {
        return Err(ChangeError::TargetMismatch);
    }
    let grant = change
        .plan
        .steps
        .first()
        .ok_or(ChangeError::Invalid)?
        .grant_id
        .clone();
    if change.plan.steps.iter().any(|s| s.grant_id != grant) {
        return Err(ChangeError::Invalid);
    }
    let expected = if context.kind == LifecycleKind::CompensateOwnedIam {
        prepare_owned_iam_compensation(
            source,
            context.owned_iam.as_ref().ok_or(ChangeError::Invalid)?,
            &grant,
            change.plan.created_at,
            change.limits.clone(),
        )?
    } else {
        prepare_maintenance(
            source,
            &context.source_operation_id,
            context.kind,
            &grant,
            &change.observations,
            change.plan.capabilities.clone(),
            change.plan.created_at,
            change.limits.clone(),
            context.kind == LifecycleKind::Revoke
                && change.policy.protection_profiles.iter().any(|p| {
                    change
                        .policy
                        .grants
                        .iter()
                        .any(|g| g.id == grant && g.profile == p.id)
                        && p.required_effects
                            .contains(&EffectKind::SqlPrivilegesRevoked)
                }),
        )?
    };
    if expected.policy != change.policy
        || expected.previous_policy != change.previous_policy
        || expected.lifecycle != change.lifecycle
    {
        return Err(ChangeError::TargetMismatch);
    }
    Ok(())
}
