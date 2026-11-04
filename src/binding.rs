//! Secret-free application handoffs. These records are operator attestations,
//! not connector connections, SQL proof, IAM tokens or provider signatures.
use crate::core::{
    capability::ActionKind,
    change::PreparedChange,
    operation::{DispatchTicket, EffectState, StepReceipt, StepRecord, StepState},
    orchestrator::{ExecutorError, StepExecutor},
    plan::PlanStep,
    policy::*,
};
use serde::{Deserialize, Serialize};

pub mod aws_runtime;
pub mod gcp_connector_witness;
pub mod runtime;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    #[error("BINDING_INVALID: handoff scope or immutable binding is invalid")]
    Invalid,
    #[error("BINDING_PENDING: required operator handoff is missing or stale")]
    Pending,
    #[error("BINDING_UNSUPPORTED: application profile is unsupported")]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingRoute {
    CloudSqlConnector,
    RdsProxy,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingAuthentication {
    WorkloadIdentityAutomaticIam,
    WorkloadIdentityIamToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConnectionProfile {
    pub schema_version: u32,
    pub policy_revision_hash: String,
    pub target_id: String,
    pub target_hash: String,
    pub grant_id: String,
    pub subject_id: String,
    pub instance_connection_name: String,
    pub database: String,
    pub database_identity: String,
    pub route: BindingRoute,
    pub authentication: BindingAuthentication,
    pub workload_identity_reference: String,
    pub workload_sources: Vec<String>,
    pub allowed_route_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsApplicationConnection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql_account_host: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsApplicationConnection {
    pub proxy_arn: String,
    pub hostname: String,
    pub port: u16,
    pub region: String,
    pub role_arn: String,
    pub role_id: String,
    pub refresh_token_on_new_connection: bool,
}
impl AppConnectionProfile {
    pub fn hash(&self) -> String {
        hash(self)
    }
}
fn hash(value: &impl Serialize) -> String {
    crate::config::hash_bytes(&serde_json::to_vec(value).expect("typed handoff is serializable"))
}

pub fn connection_profile(
    policy: &PolicyRevision,
    grant_id: &str,
) -> Result<AppConnectionProfile, BindingError> {
    policy.validate().map_err(|_| BindingError::Invalid)?;
    let stable = policy.normalized();
    let grant = stable
        .grants
        .iter()
        .find(|g| g.id == grant_id)
        .ok_or(BindingError::Invalid)?;
    let subject = stable
        .subjects
        .iter()
        .find(|s| s.id == grant.subject)
        .ok_or(BindingError::Invalid)?;
    let target = stable
        .targets
        .iter()
        .find(|t| t.id == grant.target)
        .ok_or(BindingError::Invalid)?;
    let profile = stable
        .protection_profiles
        .iter()
        .find(|p| p.id == grant.profile)
        .ok_or(BindingError::Invalid)?;
    if grant.admission != AdmissionIntent::Allow
        || subject.kind != SubjectKind::Application
        || !matches!(
            target.placement.kind,
            PlacementKind::GcpCloudSql | PlacementKind::AwsRds
        )
        || !matches!(
            target.engine.family,
            EngineFamily::PostgreSql | EngineFamily::MySql
        )
        || !matches!(
            profile.kind,
            ProfileKind::GcpCloudSqlPostgresConnectorV1
                | ProfileKind::AwsRdsPostgresProxyV1
                | ProfileKind::AwsRdsMysqlProxyV1
        )
        || subject.identity.credential_source.kind != CredentialSourceKind::WorkloadIdentity
        || !target
            .managed_surface
            .fields
            .contains(&ManagedField::ApplicationBinding)
    {
        return Err(BindingError::Unsupported);
    }
    if target.placement.kind == PlacementKind::AwsRds {
        let native = target.aws.as_ref().ok_or(BindingError::Unsupported)?;
        if !matches!(
            profile.kind,
            ProfileKind::AwsRdsPostgresProxyV1 | ProfileKind::AwsRdsMysqlProxyV1
        ) {
            return Err(BindingError::Unsupported);
        }
        return Ok(AppConnectionProfile {
            schema_version: if target.engine.family == EngineFamily::MySql {
                3
            } else {
                2
            },
            policy_revision_hash: stable.revision_hash().map_err(|_| BindingError::Invalid)?,
            target_id: target.id.clone(),
            target_hash: hash(target),
            grant_id: grant.id.clone(),
            subject_id: subject.id.clone(),
            instance_connection_name: native.proxy_arn.clone(),
            database: target.engine.database.clone(),
            database_identity: grant.db_identity.clone(),
            route: BindingRoute::RdsProxy,
            authentication: BindingAuthentication::WorkloadIdentityIamToken,
            workload_identity_reference: subject.identity.credential_source.reference.clone(),
            workload_sources: subject.workload_sources.clone(),
            allowed_route_ids: profile
                .allowed_routes
                .iter()
                .filter(|r| {
                    r.kind == RouteKind::NativeProxy
                        && r.source_ids
                            .iter()
                            .any(|s| subject.workload_sources.contains(s))
                })
                .map(|r| r.id.clone())
                .collect(),
            aws: Some(AwsApplicationConnection {
                proxy_arn: native.proxy_arn.clone(),
                hostname: native.proxy_endpoint.clone(),
                port: native_db_port(target.engine.family).ok_or(BindingError::Unsupported)?,
                region: target.placement.region.clone(),
                role_arn: subject.identity.principal.clone(),
                role_id: subject
                    .identity
                    .immutable_id
                    .clone()
                    .ok_or(BindingError::Invalid)?,
                refresh_token_on_new_connection: true,
            }),
            mysql_account_host: target.mysql.as_ref().map(|b| b.account_host.clone()),
        });
    }
    let instance = target
        .resource
        .native_id
        .rsplit('/')
        .next()
        .ok_or(BindingError::Invalid)?;
    let route_ids = profile
        .allowed_routes
        .iter()
        .filter(|r| {
            r.kind == RouteKind::NativeConnector
                && r.source_ids
                    .iter()
                    .any(|s| subject.workload_sources.contains(s))
        })
        .map(|r| r.id.clone())
        .collect();
    Ok(AppConnectionProfile {
        schema_version: 1,
        policy_revision_hash: stable.revision_hash().map_err(|_| BindingError::Invalid)?,
        target_id: target.id.clone(),
        target_hash: hash(target),
        grant_id: grant.id.clone(),
        subject_id: subject.id.clone(),
        instance_connection_name: format!(
            "{}:{}:{}",
            target.placement.account_id, target.placement.region, instance
        ),
        database: target.engine.database.clone(),
        database_identity: grant.db_identity.clone(),
        route: BindingRoute::CloudSqlConnector,
        authentication: BindingAuthentication::WorkloadIdentityAutomaticIam,
        workload_identity_reference: subject.identity.credential_source.reference.clone(),
        workload_sources: subject.workload_sources.clone(),
        allowed_route_ids: route_ids,
        aws: None,
        mysql_account_host: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointKind {
    BindingPublished,
    RecoveryReady,
    ApplicationCutover,
    ExclusiveNativeChangeWindow,
    NativePreparationReady,
    OwnedIamCompensationReady,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBinding {
    pub grant_id: String,
    pub connection_profile_hash: String,
}

/// Immutable content hashes bind an attestation to its reviewed scope. Hashes
/// detect mutation; they do not authenticate the person making a declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCheckpoint {
    pub schema_version: u32,
    pub checkpoint_hash: String,
    pub kind: CheckpointKind,
    pub change_hash: String,
    pub policy_revision_hash: String,
    pub target_id: String,
    pub target_hash: String,
    pub target_generation: String,
    /// Every currently allowed registered application on the target, including
    /// all workloads within each profile. A single-app acknowledgement fails.
    pub application_bindings: Vec<GrantBinding>,
    pub recovery_exception_ids: Vec<String>,
    pub attested_by: String,
    pub attested_at: u64,
    pub valid_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_configuration_hash: Option<String>,
}

fn scope(
    change: &PreparedChange,
    target_id: &str,
) -> Result<(Target, Vec<GrantBinding>, Vec<String>), BindingError> {
    change.verify().map_err(|_| BindingError::Invalid)?;
    let policy = change.policy.normalized();
    let target = policy
        .targets
        .iter()
        .find(|t| t.id == target_id)
        .ok_or(BindingError::Invalid)?
        .clone();
    if target.resource.generation_fingerprint.is_none() {
        return Err(BindingError::Pending);
    }
    let mut bindings = vec![];
    let mut recovery = BTreeSet::new();
    for grant in policy.grants.iter().filter(|g| g.target == target_id) {
        let subject = policy
            .subjects
            .iter()
            .find(|s| s.id == grant.subject)
            .ok_or(BindingError::Invalid)?;
        if subject.kind != SubjectKind::Application {
            continue;
        }
        if grant.admission == AdmissionIntent::Allow {
            let profile = connection_profile(&policy, &grant.id)?;
            bindings.push(GrantBinding {
                grant_id: grant.id.clone(),
                connection_profile_hash: profile.hash(),
            });
        }
        let protection = policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(BindingError::Invalid)?;
        for exception in protection
            .management_exceptions
            .iter()
            .filter(|e| e.recovery)
        {
            let operator = policy
                .subjects
                .iter()
                .find(|s| s.id == exception.subject)
                .ok_or(BindingError::Invalid)?;
            if operator.kind == SubjectKind::Application
                || operator.identity.principal == subject.identity.principal
                || exception
                    .source_ids
                    .iter()
                    .any(|s| subject.workload_sources.contains(s))
            {
                return Err(BindingError::Invalid);
            }
            recovery.insert(exception.id.clone());
        }
    }
    bindings.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
    if !policy.grants.iter().any(|g| g.target == target_id) || recovery.is_empty() {
        return Err(BindingError::Pending);
    }
    Ok((target, bindings, recovery.into_iter().collect()))
}

impl ManualCheckpoint {
    /// Creates an explicitly declared operator attestation. Caller must present
    /// this description honestly; this method performs no native operation.
    pub fn attest(
        change: &PreparedChange,
        target_id: &str,
        kind: CheckpointKind,
        operator_subject: &str,
        attested_at: u64,
        valid_until: u64,
    ) -> Result<Self, BindingError> {
        if kind == CheckpointKind::NativePreparationReady {
            return Err(BindingError::Invalid);
        }
        Self::attest_inner(
            change,
            target_id,
            kind,
            operator_subject,
            attested_at,
            valid_until,
            None,
        )
    }
    pub fn attest_preparation(
        change: &PreparedChange,
        target_id: &str,
        operator_subject: &str,
        configuration_hash: &str,
        attested_at: u64,
        valid_until: u64,
    ) -> Result<Self, BindingError> {
        Self::attest_inner(
            change,
            target_id,
            CheckpointKind::NativePreparationReady,
            operator_subject,
            attested_at,
            valid_until,
            Some(configuration_hash.into()),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn attest_inner(
        change: &PreparedChange,
        target_id: &str,
        kind: CheckpointKind,
        operator_subject: &str,
        attested_at: u64,
        valid_until: u64,
        expected_configuration_hash: Option<String>,
    ) -> Result<Self, BindingError> {
        let (target, bindings, recovery) = scope(change, target_id)?;
        if kind == CheckpointKind::OwnedIamCompensationReady
            && !change.lifecycle.as_ref().is_some_and(|context| {
                context.kind == crate::core::lifecycle::LifecycleKind::CompensateOwnedIam
            })
        {
            return Err(BindingError::Unsupported);
        }
        if bindings.is_empty()
            && !matches!(
                kind,
                CheckpointKind::ExclusiveNativeChangeWindow
                    | CheckpointKind::OwnedIamCompensationReady
            )
        {
            return Err(BindingError::Unsupported);
        }
        if (kind == CheckpointKind::NativePreparationReady) != expected_configuration_hash.is_some()
            || expected_configuration_hash
                .as_ref()
                .is_some_and(|v| !valid_hash(v))
            || (kind == CheckpointKind::NativePreparationReady && target.aws.is_none())
        {
            return Err(BindingError::Invalid);
        }
        let max_validity = if matches!(
            kind,
            CheckpointKind::ExclusiveNativeChangeWindow
                | CheckpointKind::NativePreparationReady
                | CheckpointKind::OwnedIamCompensationReady
        ) {
            3_600
        } else {
            86_400
        };
        if attested_at == 0
            || valid_until <= attested_at
            || valid_until - attested_at > max_validity
            || !change
                .policy
                .subjects
                .iter()
                .any(|s| s.id == operator_subject && s.kind == SubjectKind::Operator)
        {
            return Err(BindingError::Invalid);
        }
        let mut result = Self {
            schema_version: 1,
            checkpoint_hash: String::new(),
            kind,
            change_hash: change.change_hash.clone(),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            target_id: target_id.into(),
            target_hash: hash(&target),
            target_generation: target
                .resource
                .generation_fingerprint
                .ok_or(BindingError::Pending)?,
            application_bindings: bindings,
            recovery_exception_ids: recovery,
            attested_by: operator_subject.into(),
            attested_at,
            valid_until,
            expected_configuration_hash,
        };
        result.checkpoint_hash = result.content_hash();
        Ok(result)
    }
    fn content_hash(&self) -> String {
        let mut clone = self.clone();
        clone.checkpoint_hash.clear();
        hash(&clone)
    }
    pub fn validate(
        &self,
        change: &PreparedChange,
        target_id: &str,
        now: u64,
    ) -> Result<(), BindingError> {
        if self.schema_version != 1
            || self.checkpoint_hash != self.content_hash()
            || now < self.attested_at
            || now >= self.valid_until
        {
            return Err(BindingError::Pending);
        }
        let expected = Self::attest_inner(
            change,
            target_id,
            self.kind,
            &self.attested_by,
            self.attested_at,
            self.valid_until,
            self.expected_configuration_hash.clone(),
        )?;
        if self != &expected {
            return Err(BindingError::Invalid);
        }
        Ok(())
    }
}

pub trait CheckpointGate {
    fn validate_owned_iam_compensation(
        &self,
        _change: &PreparedChange,
        _target_id: &str,
        _now: u64,
    ) -> Result<String, BindingError> {
        Err(BindingError::Pending)
    }

    fn validate_preparation(
        &self,
        _change: &PreparedChange,
        _target_id: &str,
        _configuration_hash: &str,
        _now: u64,
    ) -> Result<String, BindingError> {
        Err(BindingError::Pending)
    }

    fn validate(
        &self,
        change: &PreparedChange,
        target_id: &str,
        now: u64,
    ) -> Result<Vec<String>, BindingError>;
    fn validate_change_window(
        &self,
        _change: &PreparedChange,
        _target_id: &str,
        _now: u64,
    ) -> Result<String, BindingError> {
        Err(BindingError::Pending)
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualCheckpoints {
    pub receipts: Vec<ManualCheckpoint>,
}
impl ManualCheckpoints {
    pub fn check_kind(
        &self,
        change: &PreparedChange,
        target_id: &str,
        kind: CheckpointKind,
        now: u64,
    ) -> Result<String, BindingError> {
        if self.receipts.len() > 1024 {
            return Err(BindingError::Invalid);
        }
        self.receipts
            .iter()
            .filter(|r| r.kind == kind && r.target_id == target_id)
            .find(|r| r.validate(change, target_id, now).is_ok())
            .map(|r| r.checkpoint_hash.clone())
            .ok_or(BindingError::Pending)
    }
    pub fn validate_native_cutover(
        &self,
        change: &PreparedChange,
        target_id: &str,
        now: u64,
    ) -> Result<Vec<String>, BindingError> {
        self.validate(change, target_id, now)
    }
}
impl CheckpointGate for ManualCheckpoints {
    fn validate_owned_iam_compensation(
        &self,
        change: &PreparedChange,
        target_id: &str,
        now: u64,
    ) -> Result<String, BindingError> {
        if self.receipts.len() > 1024 {
            return Err(BindingError::Invalid);
        }
        let ready = self.receipts.iter().find(|ready| {
            ready.kind == CheckpointKind::OwnedIamCompensationReady
                && ready.validate(change, target_id, now).is_ok()
                && self.receipts.iter().any(|window| {
                    window.kind == CheckpointKind::ExclusiveNativeChangeWindow
                        && window.attested_by == ready.attested_by
                        && window.attested_at <= ready.attested_at
                        && window.validate(change, target_id, now).is_ok()
                })
        });
        ready
            .map(|r| r.checkpoint_hash.clone())
            .ok_or(BindingError::Pending)
    }

    fn validate_preparation(
        &self,
        change: &PreparedChange,
        target_id: &str,
        configuration_hash: &str,
        now: u64,
    ) -> Result<String, BindingError> {
        self.receipts
            .iter()
            .find(|r| {
                r.kind == CheckpointKind::NativePreparationReady
                    && r.target_id == target_id
                    && r.expected_configuration_hash.as_deref() == Some(configuration_hash)
                    && r.validate(change, target_id, now).is_ok()
            })
            .map(|r| r.checkpoint_hash.clone())
            .ok_or(BindingError::Pending)
    }

    fn validate(
        &self,
        change: &PreparedChange,
        target_id: &str,
        now: u64,
    ) -> Result<Vec<String>, BindingError> {
        [
            CheckpointKind::BindingPublished,
            CheckpointKind::RecoveryReady,
            CheckpointKind::ApplicationCutover,
        ]
        .into_iter()
        .map(|kind| self.check_kind(change, target_id, kind, now))
        .collect()
    }
    fn validate_change_window(
        &self,
        change: &PreparedChange,
        target_id: &str,
        now: u64,
    ) -> Result<String, BindingError> {
        self.check_kind(
            change,
            target_id,
            CheckpointKind::ExclusiveNativeChangeWindow,
            now,
        )
    }
}

pub struct BindingStepExecutor {
    pub execution_identity: String,
    pub checkpoints: ManualCheckpoints,
    pub now: u64,
    source_contract_scope: bool,
}
impl BindingStepExecutor {
    pub fn new(execution_identity: String, checkpoints: ManualCheckpoints, now: u64) -> Self {
        Self {
            execution_identity,
            checkpoints,
            now,
            source_contract_scope: false,
        }
    }
    pub(crate) fn with_source_contract<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        self.source_contract_scope = true;
        let r = f(self);
        self.source_contract_scope = false;
        r
    }
    fn receipt(
        &self,
        change: &PreparedChange,
        step: &PlanStep,
    ) -> Result<StepReceipt, ExecutorError> {
        change
            .verify()
            .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        let contract = if change
            .policy
            .targets
            .iter()
            .any(|t| t.id == step.target_id && t.engine.family == EngineFamily::MySql)
        {
            "core-adapter-v3"
        } else {
            "core-adapter-v2"
        };
        if !change.plan.steps.contains(step)
            || !crate::core::source_execution::execution_contract_matches(change, step, contract)
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if change.policy.schema_version == 2 && step.action == ActionKind::ConfirmRecoveryReadiness
        {
            // A manual checkpoint cannot implement source-verified readiness.
            return Err(ExecutorError::Unavailable);
        }
        if change.policy.schema_version == 2 && !self.source_contract_scope {
            return Err(ExecutorError::Unavailable);
        }
        let kind = match step.action {
            ActionKind::PublishBinding => CheckpointKind::BindingPublished,
            ActionKind::ConfirmRecoveryReadiness => CheckpointKind::RecoveryReady,
            ActionKind::AwaitApplicationCutover => CheckpointKind::ApplicationCutover,
            _ => return Err(ExecutorError::Unavailable),
        };
        let reference = self
            .checkpoints
            .check_kind(change, &step.target_id, kind, self.now)
            .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        // Satisfied refers only to the manual plan action. Nothing here emits
        // SQL/network evidence or asserts that protection has been evaluated.
        Ok(StepReceipt {
            state: StepState::EffectSatisfied,
            effect: EffectState::Enforced,
            native_operation_ref: None,
            evidence_refs: vec![reference],
        })
    }
}
impl StepExecutor for BindingStepExecutor {
    fn identity(&self) -> &str {
        &self.execution_identity
    }
    fn available(&self, _: &PreparedChange, step: &PlanStep) -> bool {
        matches!(
            step.action,
            ActionKind::PublishBinding
                | ActionKind::ConfirmRecoveryReadiness
                | ActionKind::AwaitApplicationCutover
        )
    }
    fn preflight(&mut self, change: &PreparedChange, step: &PlanStep) -> Result<(), ExecutorError> {
        self.receipt(change, step).map(|_| ())
    }
    fn submit(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        _: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        self.receipt(change, step)
    }
    fn query(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        _: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        self.receipt(change, step)
    }
}
