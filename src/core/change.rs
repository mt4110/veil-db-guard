//! Immutable change-control contracts. No provider calls or arbitrary payloads.
use super::{
    capability::ActionKind,
    plan::{ChangePlan, verify_plan},
    policy::{
        AdmissionIntent, GenerationAssurance, Grant, PlacementKind, PolicyRevision, Target,
        valid_hash,
    },
};
use super::{
    hash_bytes,
    observation::{ChangeObservation as ObservedState, ObservationNotice, ObservationOrigin},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChangeError {
    #[error("CHANGE_INVALID: change-control inputs are invalid; values are not echoed")]
    Invalid,
    #[error("CHANGE_TAMPERED: immutable change does not match its canonical inputs")]
    Tampered,
    #[error("CHANGE_TARGET_MISMATCH: observation or prior policy does not match the change")]
    TargetMismatch,
    #[error(
        "CHANGE_REVOKE_PLAN_REQUIRED: removed grants or targets require an explicit revocation plan"
    )]
    RevokePlanRequired,
    #[error(
        "CHANGE_PREVIOUS_POLICY_REQUIRED: later revisions require the complete previous policy"
    )]
    PreviousPolicyRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLimits {
    pub max_attempts: u32,
    pub max_operation_seconds: u64,
    pub max_repair_executions: u32,
    pub max_parallel_steps: u32,
}
impl Default for OperationLimits {
    fn default() -> Self {
        Self {
            max_attempts: 128,
            max_operation_seconds: 3600,
            max_repair_executions: 2,
            max_parallel_steps: 1,
        }
    }
}
impl OperationLimits {
    pub fn validate(&self) -> Result<(), ChangeError> {
        if !(1..=4096).contains(&self.max_attempts)
            || !(1..=86400).contains(&self.max_operation_seconds)
            || self.max_repair_executions > 10
            || self.max_parallel_steps != 1
        {
            return Err(ChangeError::Invalid);
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<String, ChangeError> {
        digest("limits", self)
    }
}

/// Native resource identity and field ownership, independent of logical DB IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictKey {
    pub resource_identity: String,
    pub field_or_domain: String,
}
impl ConflictKey {
    pub fn canonical_key(&self) -> String {
        digest("conflict-key", self).expect("serializable typed conflict key")
    }
    pub fn conflicts(&self, other: &Self) -> bool {
        self.resource_identity == other.resource_identity
            && (self.field_or_domain == "*"
                || other.field_or_domain == "*"
                || self.field_or_domain == other.field_or_domain
                || self
                    .field_or_domain
                    .strip_prefix(&other.field_or_domain)
                    .is_some_and(|tail| tail.starts_with('/'))
                || other
                    .field_or_domain
                    .strip_prefix(&self.field_or_domain)
                    .is_some_and(|tail| tail.starts_with('/')))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceKind {
    Added,
    Removed,
    Changed,
    Unchanged,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceField {
    PolicyGrant,
    TargetGeneration,
    NativeIamEnabled,
    ConnectorRequired,
    RegisteredDbIdentity,
    SqlPrivileges,
    VerifiedTls,
    OwnedGcpIamBindings,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DifferenceValue {
    Boolean(bool),
    Digest(String),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedDifference {
    pub target_id: String,
    pub grant_id: Option<String>,
    pub field: DifferenceField,
    pub kind: DifferenceKind,
    pub before: Option<DifferenceValue>,
    pub desired: Option<DifferenceValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryMethod {
    RestoreOwnedDifference,
    ManualRecovery,
    NotReversible,
    NoAutomaticAllowRestoration,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compensation {
    pub forward_step_id: String,
    pub target_id: String,
    pub method: RecoveryMethod,
    pub requires_owned_receipt: bool,
    pub requires_unchanged_postcondition: bool,
    pub security_weakening_requires_separate_approval: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRoute {
    pub target_id: String,
    pub profile_id: String,
    pub exception_id: String,
    pub subject_id: String,
    pub route_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    pub scope_hash: String,
    pub compensations: Vec<Compensation>,
    pub independent_routes: Vec<RecoveryRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairRecipe {
    pub id: String,
    pub recipe_hash: String,
    pub target_id: String,
    pub target_generation: String,
    pub forward_step_id: String,
    pub action: ActionKind,
    pub desired_parameters_hash: String,
    pub permitted_prior_epoch: String,
    pub max_executions: u32,
    pub minimum_interval_seconds: u64,
    pub valid_until: u64,
}

/// Captures both the source policy and all derived execution scope. Generation
/// and configuration assertions remain preconditions, not newly proven facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedChange {
    pub schema_version: u32,
    pub change_hash: String,
    pub policy: PolicyRevision,
    pub previous_policy: Option<PolicyRevision>,
    pub plan: ChangePlan,
    pub observations: Vec<ObservedState>,
    pub differences: Vec<ScopedDifference>,
    pub conflict_keys: Vec<ConflictKey>,
    pub repair_recipes: Vec<RepairRecipe>,
    pub recovery: RecoveryPlan,
    pub limits: OperationLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<super::lifecycle::LifecycleContext>,
}

pub fn prepare_change(
    policy: &PolicyRevision,
    plan: &ChangePlan,
    observations: &[ObservedState],
    previous_policy: Option<&PolicyRevision>,
    limits: OperationLimits,
) -> Result<PreparedChange, ChangeError> {
    prepare_internal(policy, plan, observations, previous_policy, limits, None)
}
pub(crate) fn prepare_lifecycle_change(
    policy: &PolicyRevision,
    plan: &ChangePlan,
    observations: &[ObservedState],
    previous_policy: Option<&PolicyRevision>,
    limits: OperationLimits,
    lifecycle: super::lifecycle::LifecycleContext,
) -> Result<PreparedChange, ChangeError> {
    prepare_internal(
        policy,
        plan,
        observations,
        previous_policy,
        limits,
        Some(lifecycle),
    )
}
fn prepare_internal(
    policy: &PolicyRevision,
    plan: &ChangePlan,
    observations: &[ObservedState],
    previous_policy: Option<&PolicyRevision>,
    limits: OperationLimits,
    lifecycle: Option<super::lifecycle::LifecycleContext>,
) -> Result<PreparedChange, ChangeError> {
    limits.validate()?;
    policy.validate().map_err(|_| ChangeError::Invalid)?;
    let policy = policy.normalized();
    if policy.revision > 1 && previous_policy.is_none() {
        return Err(ChangeError::PreviousPolicyRequired);
    }
    if let Some(context) = &lifecycle {
        context.validate(&policy, previous_policy, plan)?;
        if let Some(receipt) = &context.owned_iam {
            if limits.max_repair_executions != 0 {
                return Err(ChangeError::Invalid);
            }
            let expected = super::plan::build_owned_iam_plan(
                &policy,
                receipt,
                plan.created_at,
                &plan.build_id,
            )
            .map_err(|_| ChangeError::Tampered)?;
            if json(&expected)? != json(plan)? {
                return Err(ChangeError::Tampered);
            }
        } else {
            super::plan::verify_selected_plan(&policy, plan, Some(&context.selected_step_ids))
                .map_err(|_| ChangeError::Tampered)?;
        }
    } else {
        verify_plan(&policy, plan).map_err(|_| ChangeError::Tampered)?;
    }
    let rebuilt = plan.clone();
    if let Some(previous) = previous_policy {
        previous.validate().map_err(|_| ChangeError::Invalid)?;
        if previous.policy_id != policy.policy_id
            || previous.revision.checked_add(1) != Some(policy.revision)
            || policy.parent_revision_hash.as_ref()
                != Some(&previous.revision_hash().map_err(|_| ChangeError::Invalid)?)
        {
            return Err(ChangeError::TargetMismatch);
        }
        if previous
            .grants
            .iter()
            .any(|prior| !policy.grants.iter().any(|grant| grant.id == prior.id))
            || previous
                .targets
                .iter()
                .any(|prior| !policy.targets.iter().any(|target| target.id == prior.id))
        {
            return Err(ChangeError::RevokePlanRequired);
        }
        for prior in &previous.grants {
            let grant = policy
                .grants
                .iter()
                .find(|grant| grant.id == prior.id)
                .ok_or(ChangeError::RevokePlanRequired)?;
            let old_subject = previous
                .subjects
                .iter()
                .find(|subject| subject.id == prior.subject)
                .ok_or(ChangeError::Invalid)?;
            let subject = policy
                .subjects
                .iter()
                .find(|subject| subject.id == grant.subject)
                .ok_or(ChangeError::Invalid)?;
            let old_target = previous
                .targets
                .iter()
                .find(|target| target.id == prior.target)
                .ok_or(ChangeError::Invalid)?;
            let target = policy
                .targets
                .iter()
                .find(|target| target.id == grant.target)
                .ok_or(ChangeError::Invalid)?;
            if grant.subject != prior.subject
                || grant.target != prior.target
                || grant.db_identity != prior.db_identity
                || subject.identity.provider != old_subject.identity.provider
                || subject.identity.principal != old_subject.identity.principal
                || subject.identity.immutable_id != old_subject.identity.immutable_id
                || target.registration_id != old_target.registration_id
                || target.resource != old_target.resource
                || target.aws != old_target.aws
                || target.mysql != old_target.mysql
                || target.placement != old_target.placement
                || target.engine.family != old_target.engine.family
                || target.engine.database != old_target.engine.database
            {
                return Err(ChangeError::RevokePlanRequired);
            }
        }
    }
    let mut observations = observations.to_vec();
    observations.sort_by(|a, b| a.target_id.cmp(&b.target_id));
    if observations.len() > policy.targets.len()
        || observations
            .windows(2)
            .any(|pair| pair[0].target_id == pair[1].target_id)
    {
        return Err(ChangeError::Invalid);
    }
    let mut observation_refs = observations
        .iter()
        .map(|state| {
            let mut bytes = serde_json::to_vec_pretty(state).map_err(|_| ChangeError::Invalid)?;
            bytes.push(b'\n');
            Ok(hash_bytes(&bytes))
        })
        .collect::<Result<Vec<_>, ChangeError>>()?;
    observation_refs.sort();
    if observation_refs != plan.observation_refs {
        return Err(ChangeError::Tampered);
    }
    for observed in &observations {
        let target = policy
            .targets
            .iter()
            .find(|target| target.id == observed.target_id)
            .ok_or(ChangeError::TargetMismatch)?;
        if observed.schema_version != 1
            || observed.target.registration_id != target.registration_id
            || observed.target.native_ref.native_id != target.resource.native_id
            || observed.target.placement != target.placement
            || observed.target.engine_binding != target.engine
            || observed.evaluated_at > plan.created_at
            || observed.evidence_refs.len() > 128
            || observed
                .evidence_refs
                .iter()
                .any(|reference| !valid_hash(reference))
        {
            return Err(ChangeError::TargetMismatch);
        }
        if let Some(configuration) = &observed.configuration
            && (configuration.target.registration_id != target.registration_id
                || configuration.target.native_ref.native_id != target.resource.native_id
                || configuration.target.placement != target.placement
                || configuration.target.engine_binding != target.engine
                || observed.configuration_observed_at != Some(configuration.observed_at)
                || configuration.identities.len() > 128
                || configuration
                    .identities
                    .iter()
                    .any(|row| row.principal.is_empty() || row.principal.len() > 512)
                || configuration
                    .identities
                    .iter()
                    .map(|row| &row.principal)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != configuration.identities.len())
        {
            return Err(ChangeError::TargetMismatch);
        }
    }

    let previous_policy = previous_policy.map(PolicyRevision::normalized);
    let mut differences = differences(
        &policy,
        previous_policy.as_ref(),
        &observations,
        plan.created_at,
    )?;
    if let Some(receipt) = lifecycle
        .as_ref()
        .and_then(|context| context.owned_iam.as_ref())
    {
        let step = &plan.steps[0];
        differences.retain(|difference| {
            difference.field == DifferenceField::PolicyGrant
                && difference.grant_id.as_ref() == Some(&step.grant_id)
        });
        differences.push(ScopedDifference {
            target_id: step.target_id.clone(),
            grant_id: Some(step.grant_id.clone()),
            field: DifferenceField::OwnedGcpIamBindings,
            kind: DifferenceKind::Removed,
            before: Some(DifferenceValue::Digest(receipt.hash())),
            desired: None,
        });
    }
    let conflict_keys = conflict_keys(if plan.schema_version == 2 {
        &plan.targets
    } else {
        &policy.targets
    })?;
    let recovery = recovery(&policy, plan)?;
    let repair_recipes = repair_recipes(&policy, plan, &observations, &limits)?;
    let mut result = PreparedChange {
        schema_version: if plan.schema_version == 2 { 3 } else { 2 },
        change_hash: String::new(),
        policy,
        previous_policy,
        plan: rebuilt,
        observations,
        differences,
        conflict_keys,
        repair_recipes,
        recovery,
        limits,
        lifecycle,
    };
    result.change_hash = result.computed_hash()?;
    Ok(result)
}

impl PreparedChange {
    fn computed_hash(&self) -> Result<String, ChangeError> {
        let mut copy = self.clone();
        copy.change_hash.clear();
        digest(
            if self.schema_version == 3 {
                "gcp-iam-owned-compensation-change"
            } else {
                "prepared-change"
            },
            &copy,
        )
    }
    pub fn verify(&self) -> Result<(), ChangeError> {
        if !matches!(self.schema_version, 2 | 3) || !valid_hash(&self.change_hash) {
            return Err(ChangeError::Invalid);
        }
        let canonical = prepare_internal(
            &self.policy,
            &self.plan,
            &self.observations,
            self.previous_policy.as_ref(),
            self.limits.clone(),
            self.lifecycle.clone(),
        )?;
        if json(&canonical)? != json(self)? {
            return Err(ChangeError::Tampered);
        }
        Ok(())
    }
    pub fn target_scope_hash(&self) -> Result<String, ChangeError> {
        if self.schema_version == 3 {
            digest(
                "gcp-iam-owned-compensation-target-scope",
                &self.plan.targets,
            )
        } else {
            digest("target-scope", &self.policy.targets)
        }
    }
    pub fn limits_hash(&self) -> Result<String, ChangeError> {
        self.limits.hash()
    }
}

fn observed_current(state: &ObservedState, at: u64) -> bool {
    state.inventory_complete
        && state
            .configuration_observed_at
            .is_some_and(|when| when <= at)
        && state.valid_until.is_some_and(|until| until >= at)
        && state
            .configuration
            .as_ref()
            .is_some_and(|facts| facts.complete)
        && state.origins.iter().any(|origin| {
            matches!(
                origin,
                ObservationOrigin::GcpLive
                    | ObservationOrigin::AwsConfiguration
                    | ObservationOrigin::AwsConnection
            )
        })
        && !state.notices.iter().any(|notice| {
            matches!(
                notice,
                ObservationNotice::FixtureOnly
                    | ObservationNotice::IncompleteInventory
                    | ObservationNotice::ConfigurationChanged
                    | ObservationNotice::StaleEvidence
                    | ObservationNotice::BuildMismatch
                    | ObservationNotice::ExecutionIncomplete
                    | ObservationNotice::MissingEvidence
            )
        })
}
fn boolean_diff(
    target: &str,
    grant: Option<&str>,
    field: DifferenceField,
    before: Option<bool>,
    desired: bool,
) -> ScopedDifference {
    ScopedDifference {
        target_id: target.into(),
        grant_id: grant.map(str::to_string),
        field,
        kind: before.map_or(DifferenceKind::Unknown, |value| {
            if value == desired {
                DifferenceKind::Unchanged
            } else {
                DifferenceKind::Changed
            }
        }),
        before: before.map(DifferenceValue::Boolean),
        desired: Some(DifferenceValue::Boolean(desired)),
    }
}
fn differences(
    policy: &PolicyRevision,
    previous: Option<&PolicyRevision>,
    states: &[ObservedState],
    at: u64,
) -> Result<Vec<ScopedDifference>, ChangeError> {
    let mut result = vec![];
    for grant in &policy.grants {
        let prior = previous.and_then(|p| p.grants.iter().find(|prior| prior.id == grant.id));
        let before = prior
            .map(|v| resolved_grant_digest(previous.ok_or(ChangeError::Invalid)?, v))
            .transpose()?;
        let desired = resolved_grant_digest(policy, grant)?;
        result.push(ScopedDifference {
            target_id: grant.target.clone(),
            grant_id: Some(grant.id.clone()),
            field: DifferenceField::PolicyGrant,
            kind: if previous.is_none() {
                DifferenceKind::Unknown
            } else {
                match &before {
                    None => DifferenceKind::Added,
                    Some(before) if before == &desired => DifferenceKind::Unchanged,
                    _ => DifferenceKind::Changed,
                }
            },
            before: before.map(DifferenceValue::Digest),
            desired: Some(DifferenceValue::Digest(desired)),
        });
        let state = states
            .iter()
            .find(|state| state.target_id == grant.target && observed_current(state, at));
        let profile = policy
            .protection_profiles
            .iter()
            .find(|profile| profile.id == grant.profile)
            .ok_or(ChangeError::Invalid)?;
        let snapshot = state.and_then(|state| state.configuration.as_ref());
        if profile.authentication == super::policy::AuthenticationRequirement::NativeIam {
            result.push(boolean_diff(
                &grant.target,
                Some(&grant.id),
                DifferenceField::NativeIamEnabled,
                snapshot.and_then(|s| s.native_iam_enabled),
                true,
            ));
        } else {
            result.push(ScopedDifference {
                target_id: grant.target.clone(),
                grant_id: Some(grant.id.clone()),
                field: DifferenceField::NativeIamEnabled,
                kind: DifferenceKind::Unknown,
                before: None,
                desired: None,
            });
        }
        if profile.kind == super::policy::ProfileKind::GcpCloudSqlPostgresConnectorV1 {
            result.push(boolean_diff(
                &grant.target,
                Some(&grant.id),
                DifferenceField::ConnectorRequired,
                snapshot.and_then(|s| s.connector_required),
                true,
            ));
        } else {
            result.push(ScopedDifference {
                target_id: grant.target.clone(),
                grant_id: Some(grant.id.clone()),
                field: DifferenceField::ConnectorRequired,
                kind: DifferenceKind::Unknown,
                before: None,
                desired: None,
            });
        }
        let subject = policy
            .subjects
            .iter()
            .find(|subject| subject.id == grant.subject)
            .ok_or(ChangeError::Invalid)?;
        let registered = snapshot.and_then(|facts| {
            facts
                .identities
                .iter()
                .find(|row| row.principal == subject.identity.principal)
                .map(|row| row.registered)
        });
        result.push(boolean_diff(
            &grant.target,
            Some(&grant.id),
            DifferenceField::RegisteredDbIdentity,
            registered,
            grant.admission == AdmissionIntent::Allow,
        ));
        for field in [DifferenceField::SqlPrivileges, DifferenceField::VerifiedTls] {
            result.push(ScopedDifference {
                target_id: grant.target.clone(),
                grant_id: Some(grant.id.clone()),
                field,
                kind: DifferenceKind::Unknown,
                before: None,
                desired: Some(DifferenceValue::Digest(
                    if field == DifferenceField::SqlPrivileges {
                        digest("sql-access", &grant.sql_access)?
                    } else {
                        digest("transport", &profile.encryption)?
                    },
                )),
            });
        }
    }
    if let Some(previous) = previous {
        for prior in &previous.grants {
            if !policy.grants.iter().any(|grant| grant.id == prior.id) {
                result.push(ScopedDifference {
                    target_id: prior.target.clone(),
                    grant_id: Some(prior.id.clone()),
                    field: DifferenceField::PolicyGrant,
                    kind: DifferenceKind::Removed,
                    before: Some(DifferenceValue::Digest(resolved_grant_digest(
                        previous, prior,
                    )?)),
                    desired: None,
                });
            }
        }
    }
    for target in &policy.targets {
        let confirmed = states
            .iter()
            .find(|state| {
                state.target_id == target.id
                    && observed_current(state, at)
                    && state.target.generation_assurance == GenerationAssurance::Confirmed
            })
            .and_then(|state| state.target.native_ref.generation_fingerprint.clone());
        result.push(ScopedDifference {
            target_id: target.id.clone(),
            grant_id: None,
            field: DifferenceField::TargetGeneration,
            kind: if confirmed.is_some() && confirmed == target.resource.generation_fingerprint {
                DifferenceKind::Unchanged
            } else {
                DifferenceKind::Unknown
            },
            before: confirmed.map(DifferenceValue::Digest),
            desired: target
                .resource
                .generation_fingerprint
                .clone()
                .map(DifferenceValue::Digest),
        });
    }
    Ok(result)
}

fn resolved_grant_digest(policy: &PolicyRevision, grant: &Grant) -> Result<String, ChangeError> {
    let subject = policy
        .subjects
        .iter()
        .find(|subject| subject.id == grant.subject)
        .ok_or(ChangeError::Invalid)?;
    let target = policy
        .targets
        .iter()
        .find(|target| target.id == grant.target)
        .ok_or(ChangeError::Invalid)?;
    let profile = policy
        .protection_profiles
        .iter()
        .find(|profile| profile.id == grant.profile)
        .ok_or(ChangeError::Invalid)?;
    if policy.schema_version == 1 {
        digest("resolved-policy-grant", &(grant, subject, target, profile))
    } else {
        // A source/trust or accepted-layer change is visible in the reviewed
        // grant diff as well as the overall policy/plan/approval hashes.
        digest(
            "resolved-policy-grant-v2",
            &(
                grant,
                subject,
                target,
                profile,
                &policy.source_bindings,
                &policy.evaluation,
            ),
        )
    }
}

fn target_resource(target: &Target) -> Result<String, ChangeError> {
    digest(
        "native-resource",
        &(&target.placement, &target.resource.native_id),
    )
}
fn conflict_keys(targets: &[Target]) -> Result<Vec<ConflictKey>, ChangeError> {
    let mut keys = BTreeSet::new();
    for target in targets {
        keys.insert(ConflictKey {
            resource_identity: target_resource(target)?,
            field_or_domain: "*".into(),
        });
        match target.placement.kind {
            PlacementKind::GcpCloudSql => {
                keys.insert(ConflictKey {
                    resource_identity: digest("gcp-project", &target.placement.account_id)?,
                    field_or_domain: "iam".into(),
                });
            }
            PlacementKind::AwsRds => {
                if let Some(binding) = &target.aws {
                    keys.insert(ConflictKey {
                        resource_identity: digest("aws-proxy", &binding.proxy_arn)?,
                        field_or_domain: "*".into(),
                    });
                    keys.insert(ConflictKey {
                        resource_identity: digest(
                            "aws-security-group",
                            &(&target.placement.account_id, &binding.db_security_group_id),
                        )?,
                        field_or_domain: "ingress".into(),
                    });
                }

                keys.insert(ConflictKey {
                    resource_identity: digest("aws-account", &target.placement.account_id)?,
                    field_or_domain: "iam".into(),
                });
                keys.insert(ConflictKey {
                    resource_identity: digest(
                        "aws-network",
                        &(&target.placement.account_id, &target.placement.region),
                    )?,
                    field_or_domain: "network".into(),
                });
            }
            PlacementKind::SelfManaged => {}
        }
    }
    Ok(keys.into_iter().collect())
}

fn recovery(policy: &PolicyRevision, plan: &ChangePlan) -> Result<RecoveryPlan, ChangeError> {
    let compensations = plan
        .steps
        .iter()
        .map(|step| {
            let method = match step.action {
                ActionKind::DisableNewConnections
                | ActionKind::DisableNativeIdentity
                | ActionKind::CompensateOwnedIam
                | ActionKind::RevokeSqlPrivileges => RecoveryMethod::NoAutomaticAllowRestoration,
                ActionKind::ObserveRevocation => RecoveryMethod::ManualRecovery,
                ActionKind::TerminateSelectedSessions => RecoveryMethod::NotReversible,
                ActionKind::PublishBinding
                | ActionKind::AwaitApplicationCutover
                | ActionKind::ConfirmRecoveryReadiness
                | ActionKind::DrainExistingSessions => RecoveryMethod::ManualRecovery,
                _ => RecoveryMethod::RestoreOwnedDifference,
            };
            Compensation {
                forward_step_id: step.id.clone(),
                target_id: step.target_id.clone(),
                method,
                requires_owned_receipt: true,
                requires_unchanged_postcondition: true,
                security_weakening_requires_separate_approval: matches!(
                    step.action,
                    ActionKind::ConstrainDirectPath
                        | ActionKind::DisableNewConnections
                        | ActionKind::DisableNativeIdentity
                        | ActionKind::RevokeSqlPrivileges
                        | ActionKind::ConfigureIdentity
                        | ActionKind::ConfigureSqlPrivileges
                ),
            }
        })
        .collect();
    let mut routes = BTreeSet::new();
    for grant in &policy.grants {
        if plan.schema_version == 2 && !plan.steps.iter().any(|step| step.grant_id == grant.id) {
            continue;
        }
        let profile = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(ChangeError::Invalid)?;
        for exception in &profile.management_exceptions {
            if exception.recovery {
                routes.insert((
                    grant.target.clone(),
                    profile.id.clone(),
                    exception.id.clone(),
                    exception.subject.clone(),
                    exception.route_id.clone(),
                ));
            }
        }
    }
    let independent_routes = routes
        .into_iter()
        .map(
            |(target_id, profile_id, exception_id, subject_id, route_id)| RecoveryRoute {
                target_id,
                profile_id,
                exception_id,
                subject_id,
                route_id,
            },
        )
        .collect();
    let mut result = RecoveryPlan {
        scope_hash: String::new(),
        compensations,
        independent_routes,
    };
    result.scope_hash = digest("recovery", &result)?;
    Ok(result)
}
fn repair_recipes(
    policy: &PolicyRevision,
    plan: &ChangePlan,
    states: &[ObservedState],
    limits: &OperationLimits,
) -> Result<Vec<RepairRecipe>, ChangeError> {
    if limits.max_repair_executions == 0 {
        return Ok(vec![]);
    }
    let mut result = vec![];
    for step in &plan.steps {
        if !matches!(
            step.action,
            ActionKind::ConfigureIdentity
                | ActionKind::ConfigureSqlPrivileges
                | ActionKind::ConstrainDirectPath
        ) {
            continue;
        }
        let target = policy
            .targets
            .iter()
            .find(|target| target.id == step.target_id)
            .ok_or(ChangeError::Invalid)?;
        let Some(generation) = &target.resource.generation_fingerprint else {
            continue;
        };
        let Some(state) = states.iter().find(|state| {
            state.target_id == step.target_id
                && observed_current(state, plan.created_at)
                && state.target.generation_assurance == GenerationAssurance::Confirmed
                && state.target.native_ref.generation_fingerprint.as_ref() == Some(generation)
        }) else {
            continue;
        };
        let Some(epoch) = &state.configuration_epoch else {
            continue;
        };
        if !valid_hash(epoch) {
            return Err(ChangeError::Invalid);
        }
        let mut recipe = RepairRecipe {
            id: format!("repair-{}", step.id),
            recipe_hash: String::new(),
            target_id: step.target_id.clone(),
            target_generation: generation.clone(),
            forward_step_id: step.id.clone(),
            action: step.action,
            desired_parameters_hash: step.parameters_hash.clone(),
            permitted_prior_epoch: epoch.clone(),
            max_executions: limits.max_repair_executions,
            minimum_interval_seconds: 60,
            valid_until: plan
                .created_at
                .checked_add(limits.max_operation_seconds)
                .ok_or(ChangeError::Invalid)?,
        };
        recipe.recipe_hash = digest("repair-recipe", &recipe)?;
        result.push(recipe);
    }
    Ok(result)
}

pub(crate) fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, ChangeError> {
    serde_json::to_vec(value).map_err(|_| ChangeError::Invalid)
}
pub(crate) fn digest<T: Serialize>(domain: &str, value: &T) -> Result<String, ChangeError> {
    let mut bytes = format!("veil-db-guard/{domain}/v1\0").into_bytes();
    bytes.extend(json(value)?);
    Ok(hash_bytes(&bytes))
}
