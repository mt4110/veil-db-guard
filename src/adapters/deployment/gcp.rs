//! Cloud SQL PostgreSQL native changes, with one write per durable dispatch.
//!
//! Setup receipts certify only the named configuration predicate. They do not
//! certify SQL privileges, application migration, or end-to-end protection.
//! Connector enforcement stays ConfigApplied until fresh positive connector
//! and explicit direct-denial observations cover application and recovery users.
//!
//! REST contracts: Cloud SQL Admin API v1 instances.patch/settingsVersion,
//! users.insert and operations.get; Resource Manager v1 setIamPolicy/etag.
//! https://docs.cloud.google.com/sql/docs/postgres/admin-api/rest/v1/instances
//! https://docs.cloud.google.com/sql/docs/postgres/iam-conditions
//! https://docs.cloud.google.com/resource-manager/reference/rest/v1/projects/setIamPolicy
use crate::{
    binding::CheckpointGate,
    config::hash_bytes,
    core::{
        capability::ActionKind,
        change::PreparedChange,
        operation::{DispatchTicket, EffectState, StepReceipt, StepRecord, StepState},
        orchestrator::{ExecutorError, StepExecutor},
        owned_iam::{OwnedIamBinding, OwnedIamDeltaReceipt, numeric_id, valid_etag},
        plan::PlanStep,
        policy::{
            AdmissionIntent, EngineFamily, Grant, GrantLifetime, IdentityProvider, ManagedField,
            PlacementKind, ProfileKind, Subject, Target,
        },
    },
    gcp::{live::LiveTools, model::*},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

mod owned_iam;
use owned_iam::{IamPolicy, PolicySnapshot, binding_value, has_title};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    Unavailable,
    Precondition,
    Conflict,
    NotApplied,
    Unknown,
}
impl From<ProviderError> for ExecutorError {
    fn from(value: ProviderError) -> Self {
        match value {
            ProviderError::Unavailable => Self::Unavailable,
            ProviderError::Precondition => Self::PreconditionsNotMet,
            ProviderError::Conflict => Self::NotApplied,
            ProviderError::NotApplied => Self::NotApplied,
            ProviderError::Unknown => Self::OutcomeUnknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudSqlInstance {
    pub project: String,
    pub name: String,
    pub region: String,
    /// Exact API createTime; never a mutable settings version.
    pub create_time: String,
    pub installed_version: String,
    pub settings_version: String,
    pub database_flags: Vec<DatabaseFlag>,
    pub connector_required: bool,
    pub runnable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseFlag {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudSqlUser {
    pub name: String,
    pub iam_service_account: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativePatch {
    EnableIamAuthentication,
    RequireConnector,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeOperation {
    pub name: String,
    pub project: String,
    pub instance: String,
    pub done: bool,
    pub failed: bool,
}
/// Produced by a trusted current connection observer, never imported receipts.
#[derive(Debug, Clone)]
pub struct ConnectionEvidence {
    pub generation: String,
    pub observed_at: u64,
    pub connector_principals: BTreeSet<String>,
    pub direct_denied_principals: BTreeSet<String>,
    pub evidence_refs: Vec<String>,
}

/// Fresh observer facts for a dedicated revoked principal. A configuration
/// removal alone never establishes this predicate; broad external grants can
/// legitimately leave access Allowed while the revocation remains pending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvidence {
    /// All observer inventory and execution checks completed coherently.
    pub complete: bool,
    pub generation: String,
    pub observed_at: u64,
    pub denied_principal: String,
    pub access: GcpAccess,
    pub denied_permission: Option<GcpPermission>,
    pub connector_allowed_principals: BTreeSet<String>,
    pub direct_denied_principals: BTreeSet<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectTransportOutcome {
    ExplicitRefusal,
    Connected,
    Timeout,
    OtherFailure,
    Cancelled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectTransportObservation {
    pub target_id: String,
    pub generation: String,
    pub address: std::net::Ipv4Addr,
    pub port: u16,
    pub observed_at: u64,
    pub outcome: DirectTransportOutcome,
}
/// Identify an explicit refusal from the CLI transport diagnostic. This alone
/// never establishes direct denial for a workload source. A timeout, routing
/// failure, missing public address or arbitrary psql failure is not a refusal.
pub fn classify_transport_refusal(kind: std::io::ErrorKind) -> bool {
    kind == std::io::ErrorKind::ConnectionRefused
}

type BeforeIamSend<'a> = dyn FnMut(&dyn Fn() -> u64) -> Result<(), ProviderError> + 'a;

/// An injected provider is trusted adapter implementation code. All mutations
/// must condition on the supplied version, preserve unrelated fields and never
/// retry after an ambiguous response. Tests implement this port without network.
pub trait CloudSqlProvider {
    fn cancelled(&self) -> bool {
        false
    }
    fn now(&self) -> u64 {
        crate::domain::now()
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError>;
    fn instance(&mut self, target: &Target) -> Result<CloudSqlInstance, ProviderError>;
    fn service_account_id(&mut self, email: &str) -> Result<String, ProviderError>;
    fn project_number(&mut self, _project: &str) -> Result<String, ProviderError> {
        Err(ProviderError::Unavailable)
    }
    fn iam_policy(&mut self, project: &str) -> Result<Value, ProviderError>;
    fn iam_policy_with_version(&mut self, project: &str) -> Result<Value, ProviderError> {
        self.iam_policy(project)
    }
    fn set_iam_policy(&mut self, project: &str, policy: &Value) -> Result<(), ProviderError>;
    fn set_iam_policy_receipt(
        &mut self,
        project: &str,
        policy: &Value,
    ) -> Result<Option<Value>, ProviderError> {
        self.set_iam_policy(project, policy)?;
        Ok(None)
    }
    fn set_iam_policy_receipt_checked(
        &mut self,
        project: &str,
        policy: &Value,
        before_send: &mut BeforeIamSend<'_>,
    ) -> Result<Option<Value>, ProviderError> {
        before_send(&|| self.now())?;
        if self.cancelled() {
            return Err(ProviderError::NotApplied);
        }
        self.set_iam_policy_receipt(project, policy)
    }
    fn users(&mut self, target: &Target) -> Result<Vec<CloudSqlUser>, ProviderError>;
    fn patch(
        &mut self,
        target: &Target,
        before: &CloudSqlInstance,
        patch: NativePatch,
    ) -> Result<NativeOperation, ProviderError>;
    fn register_user(
        &mut self,
        target: &Target,
        username: &str,
    ) -> Result<NativeOperation, ProviderError>;
    fn operation(&mut self, target: &Target, name: &str) -> Result<NativeOperation, ProviderError>;
    fn observe_connections(
        &mut self,
        _change: &PreparedChange,
        _target: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        Ok(None)
    }
    fn observe_revocation(
        &mut self,
        _change: &PreparedChange,
        _target: &Target,
        _grant: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        Ok(None)
    }
}

/// Registration fingerprint algorithm. The complete tuple binds createTime to
/// its provider, project, and native name, avoiding cross-target digest reuse.
pub fn generation_fingerprint(project: &str, instance: &str, create_time: &str) -> String {
    hash_bytes(
        &serde_json::to_vec(&(
            "gcp-cloud-sql-generation-v1",
            project,
            instance,
            create_time,
        ))
        .expect("fixed tuple serializes"),
    )
}

fn native_name(target: &Target) -> Result<&str, ProviderError> {
    let prefix = format!("projects/{}/instances/", target.placement.account_id);
    let name = target
        .resource
        .native_id
        .strip_prefix(&prefix)
        .ok_or(ProviderError::Precondition)?;
    if !segment(name) || !segment(&target.placement.account_id) {
        return Err(ProviderError::Precondition);
    }
    Ok(name)
}
fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_".contains(&v))
}
fn service_email(value: &str) -> bool {
    value.len() <= 254
        && value.ends_with(".iam.gserviceaccount.com")
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_.@".contains(&v))
        && value.bytes().filter(|v| *v == b'@').count() == 1
}

pub struct GcpExecutor<P, G> {
    pub provider: P,
    execution_identity: String,
    checkpoints: G,
    last_revocation: Option<RevocationEvidence>,
    last_owned_iam_delta: Option<OwnedIamDeltaReceipt>,
    source_contract_scope: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContextMode {
    Dispatch,
    Reconcile,
    Composite,
}
impl<P: CloudSqlProvider, G: CheckpointGate> GcpExecutor<P, G> {
    /// Only the source-aware composition may enter this scope, after its fresh
    /// evidence gate. Public StepExecutor use cannot write under a v3 contract.
    pub(crate) fn with_source_contract<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        self.source_contract_scope = true;
        let result = f(self);
        self.source_contract_scope = false;
        result
    }

    pub(crate) fn submit_source(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
        dispatch_check: &mut dyn FnMut() -> Result<(), ExecutorError>,
    ) -> Result<StepReceipt, ExecutorError> {
        self.with_source_contract(|this| {
            let mut source_check = || {
                gate.validate_sources(change)
                    .map_err(|_| ExecutorError::NotApplied)?;
                if matches!(
                    step.action,
                    ActionKind::ConstrainDirectPath
                        | ActionKind::DisableNativeIdentity
                        | ActionKind::ObserveRevocation
                        | ActionKind::CompensateOwnedIam
                ) {
                    let proof = gate
                        .check(
                            change,
                            step,
                            crate::core::source_execution::SourceStepPhase::BeforeDispatch,
                        )
                        .map_err(|_| ExecutorError::NotApplied)?;
                    if !proof.satisfied() {
                        return Err(ExecutorError::NotApplied);
                    }
                }
                Ok(())
            };
            this.submit_checked(change, step, ticket, &mut source_check, dispatch_check)
        })
    }
    fn check_before_write(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        before_write: &mut dyn FnMut() -> Result<(), ExecutorError>,
    ) -> Result<(), ExecutorError> {
        before_write()?;
        if self.cancelled() {
            return Err(ExecutorError::NotApplied);
        }
        self.checkpoints
            .validate_change_window(change, &step.target_id, self.provider.now())
            .map_err(|_| ExecutorError::NotApplied)?;
        if step.action == ActionKind::ConstrainDirectPath {
            self.checkpoints
                .validate(change, &step.target_id, self.provider.now())
                .map_err(|_| ExecutorError::NotApplied)?;
        }
        Ok(())
    }
    fn submit_checked(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
        before_write: &mut dyn FnMut() -> Result<(), ExecutorError>,
        dispatch_check: &mut dyn FnMut() -> Result<(), ExecutorError>,
    ) -> Result<StepReceipt, ExecutorError> {
        self.last_owned_iam_delta = None;
        if ticket.step_id != step.id
            || ticket.idempotency_key.is_empty()
            || ticket.attempt == 0
            || self.cancelled()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if step.action == ActionKind::CompensateOwnedIam {
            return self.submit_owned_compensation(
                change,
                step,
                ticket,
                before_write,
                dispatch_check,
            );
        }
        // Repeat all checks immediately before mutation; preflight is not a
        // reusable authorization or generation assertion.
        let (target, grant, subject, instance) =
            self.context(change, step, ContextMode::Dispatch)?;
        if step.action == ActionKind::ObserveRevocation {
            return self.applied(change, step, target, synchronous_ref(change, step), true);
        }
        if self.configured(change, step, target, grant, subject, &instance)? {
            return self.applied(change, step, target, synchronous_ref(change, step), true);
        }
        if change.policy.schema_version == 1 && step.action == ActionKind::ConstrainDirectPath {
            let evidence = self
                .provider
                .observe_connections(change, target)?
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            let needed = required_principals(change, target)?;
            if evidence.generation
                != target
                    .resource
                    .generation_fingerprint
                    .clone()
                    .unwrap_or_default()
                || evidence.observed_at > self.provider.now()
                || self.provider.now().saturating_sub(evidence.observed_at) > 60
                || !needed.is_subset(&evidence.connector_principals)
                || evidence.evidence_refs.is_empty()
            {
                return Err(ExecutorError::PreconditionsNotMet);
            }
            // A readiness probe may take time: obtain a new CAS incarnation
            // immediately before the patch rather than reuse its old version.
            let fresh = self.provider.instance(target)?;
            self.check_instance(target, &fresh)?;
            self.checkpoints
                .validate_change_window(change, &target.id, self.provider.now())
                .map_err(|_| ExecutorError::NotApplied)?;
            self.checkpoints
                .validate(change, &target.id, self.provider.now())
                .map_err(|_| ExecutorError::NotApplied)?;
            if self.provider.now().saturating_sub(evidence.observed_at) > 60 {
                return Err(ExecutorError::NotApplied);
            }
            self.check_before_write(change, step, before_write)?;
            let native = self
                .provider
                .patch(target, &fresh, NativePatch::RequireConnector)?;
            validate_operation(target, &native)?;
            return Ok(StepReceipt {
                state: StepState::Submitted,
                effect: EffectState::Pending,
                native_operation_ref: Some(native.name),
                evidence_refs: evidence.evidence_refs,
            });
        }
        self.checkpoints
            .validate_change_window(change, &target.id, self.provider.now())
            .map_err(|_| ExecutorError::NotApplied)?;
        let native = match step.action {
            ActionKind::ConfigureIdentity => {
                return self.configure_identity(
                    change,
                    step,
                    ticket,
                    before_write,
                    (target, grant, subject, &instance),
                );
            }
            ActionKind::DisableNativeIdentity => {
                let before = self.provider.iam_policy(&target.placement.account_id)?;
                let desired = removed_iam_policy(change, target, grant, subject, &before)?;
                self.checkpoints
                    .validate_change_window(change, &target.id, self.provider.now())
                    .map_err(|_| ExecutorError::NotApplied)?;
                // IAM CAS uses the exact etag read above and preserves every
                // unrelated binding and audit setting byte-for-byte as values.
                self.check_before_write(change, step, before_write)?;
                self.provider
                    .set_iam_policy(&target.placement.account_id, &desired)?;
                if self.configured(change, step, target, grant, subject, &instance)? {
                    return self.applied(
                        change,
                        step,
                        target,
                        synchronous_ref(change, step),
                        false,
                    );
                }
                return Err(ExecutorError::OutcomeUnknown);
            }
            ActionKind::PrepareNativeRoute => {
                self.check_before_write(change, step, before_write)?;
                self.provider
                    .patch(target, &instance, NativePatch::EnableIamAuthentication)?
            }
            ActionKind::RegisterNativeDbIdentity => {
                self.check_before_write(change, step, before_write)?;
                self.provider.register_user(target, &grant.db_identity)?
            }
            ActionKind::ConstrainDirectPath => {
                self.check_before_write(change, step, before_write)?;
                self.provider
                    .patch(target, &instance, NativePatch::RequireConnector)?
            }
            _ => return Err(ExecutorError::Unavailable),
        };
        validate_operation(target, &native)?;
        // Even DONE is reconciled by query. A provider's acceptance is never
        // treated as either a fresh readback or a successful connection.
        Ok(StepReceipt {
            state: StepState::Submitted,
            effect: EffectState::Pending,
            native_operation_ref: Some(native.name),
            evidence_refs: vec![],
        })
    }
    fn configure_identity(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
        before_write: &mut dyn FnMut() -> Result<(), ExecutorError>,
        (target, grant, subject, instance): (&Target, &Grant, &Subject, &CloudSqlInstance),
    ) -> Result<StepReceipt, ExecutorError> {
        let project = &target.placement.account_id;
        let (before, snapshot) = match self.provider.iam_policy_with_version(project) {
            Ok(raw) => {
                let snapshot = PolicySnapshot::parse(&raw).ok();
                (raw, snapshot)
            }
            Err(_) => (self.provider.iam_policy(project)?, None),
        };
        let before_read_at = self.provider.now();
        let desired = desired_iam_policy(change, target, grant, subject, &before)?;
        if desired == before {
            return self.applied(change, step, target, synchronous_ref(change, step), true);
        }
        let bindings = OwnedIamBinding::for_grant(&change.policy.policy_id, target, grant, subject);
        let owned_candidate = snapshot
            .zip(PolicySnapshot::parse(&desired).ok())
            .filter(|_| {
                change.lifecycle.is_none()
                    && change.policy.schema_version == 2
                    && bindings
                        .iter()
                        .all(|binding| !has_title(&before, &binding.condition.title))
            })
            .and_then(|(before, desired)| {
                self.provider
                    .project_number(project)
                    .ok()
                    .filter(|number| numeric_id(number))
                    .map(|number| (before, desired, number))
            });
        self.check_before_write(change, step, before_write)?;
        if let Some((_, _, number)) = &owned_candidate {
            self.revalidate_iam_scope(target, subject, number)
                .map_err(|_| ExecutorError::NotApplied)?;
            // The late incarnation reads can take time. Recheck the write
            // window and cancellation before sending the same CAS etag.
            self.check_before_write(change, step, &mut || Ok(()))?;
        }
        let response = self.provider.set_iam_policy_receipt(project, &desired)?;
        let owned_after = owned_candidate
            .zip(
                response
                    .as_ref()
                    .and_then(|r| PolicySnapshot::parse(r).ok()),
            )
            .and_then(|((before, expected, number), response)| {
                if response.etag == before.etag || response.digest != expected.digest {
                    return None;
                }
                let raw = self.provider.iam_policy_with_version(project).ok()?;
                let after = PolicySnapshot::parse(&raw).ok()?;
                let after_read_at = self.provider.now();
                if after.etag != response.etag
                    || after.digest != response.digest
                    || self.revalidate_iam_scope(target, subject, &number).is_err()
                {
                    return None;
                }
                Some((before, number, after, after_read_at))
            });
        if owned_after.is_none()
            && !self.configured(change, step, target, grant, subject, instance)?
        {
            return Err(ExecutorError::OutcomeUnknown);
        }
        let receipt = self.applied(change, step, target, synchronous_ref(change, step), false)?;
        if let Some((before, project_number, after, after_read_at)) = owned_after {
            let delta = OwnedIamDeltaReceipt {
                source_operation_id: ticket.operation_id.clone(),
                source_change_hash: change.change_hash.clone(),
                source_policy_revision_hash: change.plan.policy_revision_hash.clone(),
                source_step_id: step.id.clone(),
                attempt: ticket.attempt,
                idempotency_key: ticket.idempotency_key.clone(),
                execution_identity: self.execution_identity.clone(),
                step_receipt_hash: OwnedIamDeltaReceipt::step_receipt_hash(&receipt),
                project_id: project.clone(),
                project_number,
                native_resource_id: target.resource.native_id.clone(),
                registration_id: target.registration_id.clone(),
                generation_fingerprint: target
                    .resource
                    .generation_fingerprint
                    .clone()
                    .unwrap_or_default(),
                engine_version: target.engine.version.clone(),
                grant_id: grant.id.clone(),
                service_account_email: subject.identity.principal.clone(),
                service_account_unique_id: subject
                    .identity
                    .immutable_id
                    .clone()
                    .unwrap_or_default(),
                db_login: grant.db_identity.clone(),
                before_etag: before.etag,
                before_digest: before.digest,
                before_read_at,
                after_etag: after.etag,
                after_digest: after.digest,
                after_read_at,
                bindings,
            };
            self.last_owned_iam_delta = delta.matches_change(change).then_some(delta);
        }
        Ok(receipt)
    }
    fn revalidate_iam_scope(
        &mut self,
        target: &Target,
        subject: &Subject,
        project_number: &str,
    ) -> Result<(), ExecutorError> {
        if self.provider.project_number(&target.placement.account_id)? != project_number
            || Some(
                self.provider
                    .service_account_id(&subject.identity.principal)?,
            ) != subject.identity.immutable_id
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let instance = self.provider.instance(target)?;
        self.check_instance(target, &instance)
    }
    fn owned_compensation_context<'a>(
        &mut self,
        change: &'a PreparedChange,
        step: &PlanStep,
        mode: ContextMode,
    ) -> Result<(&'a Target, &'a Subject, &'a OwnedIamDeltaReceipt), ExecutorError> {
        let (target, grant, subject, _) = self.context(change, step, mode)?;
        let owned = change
            .lifecycle
            .as_ref()
            .filter(|context| {
                context.kind == crate::core::lifecycle::LifecycleKind::CompensateOwnedIam
            })
            .and_then(|context| context.owned_iam.as_ref())
            .filter(|owned| {
                owned.validate()
                    && owned.matches_scope(&change.policy.policy_id, target, grant, subject)
            })
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        Ok((target, subject, owned))
    }
    fn owned_compensation_candidate(
        &mut self,
        owned: &OwnedIamDeltaReceipt,
    ) -> Result<(Value, PolicySnapshot), ExecutorError> {
        let mut policy = self.provider.iam_policy_with_version(&owned.project_id)?;
        let current = PolicySnapshot::parse(&policy)?;
        if current.etag != owned.after_etag || current.digest != owned.after_digest {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let rows = policy
            .get_mut("bindings")
            .and_then(Value::as_array_mut)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        for binding in &owned.bindings {
            let exact = binding_value(binding);
            let position = rows
                .iter()
                .position(|row| *row == exact)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            rows.remove(position);
        }
        policy["version"] = json!(3);
        let expected = PolicySnapshot::parse(&policy)?;
        if expected.digest != owned.before_digest {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok((policy, expected))
    }
    fn submit_owned_compensation(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
        before_write: &mut dyn FnMut() -> Result<(), ExecutorError>,
        dispatch_check: &mut dyn FnMut() -> Result<(), ExecutorError>,
    ) -> Result<StepReceipt, ExecutorError> {
        let (target, subject, owned) = self
            .owned_compensation_context(change, step, ContextMode::Dispatch)
            .map_err(|_| ExecutorError::NotApplied)?;
        let (policy, expected) = self.owned_compensation_candidate(owned)?;
        self.revalidate_iam_scope(target, subject, &owned.project_number)
            .map_err(|_| ExecutorError::NotApplied)?;
        let now = self.provider.now();
        if now >= ticket.leases.expires_at {
            return Err(ExecutorError::NotApplied);
        }
        self.checkpoints
            .validate_owned_iam_compensation(change, &target.id, now)
            .map_err(|_| ExecutorError::NotApplied)?;
        let mut readiness_ref = None;
        let response = match self.provider.set_iam_policy_receipt_checked(
            &owned.project_id,
            &policy,
            &mut |now| {
                before_write().map_err(|_| ProviderError::NotApplied)?;
                let now = now();
                if now >= ticket.leases.expires_at {
                    return Err(ProviderError::NotApplied);
                }
                readiness_ref = Some(
                    self.checkpoints
                        .validate_owned_iam_compensation(change, &target.id, now)
                        .map_err(|_| ProviderError::NotApplied)?,
                );
                dispatch_check().map_err(|_| ProviderError::NotApplied)
            },
        ) {
            Ok(Some(response)) => response,
            Ok(None) => return Err(ExecutorError::OutcomeUnknown),
            Err(ProviderError::Conflict) => {
                return Ok(StepReceipt {
                    state: StepState::Failed,
                    effect: EffectState::Unknown,
                    native_operation_ref: None,
                    evidence_refs: vec![],
                });
            }
            Err(error) => return Err(error.into()),
        };
        let applied =
            PolicySnapshot::parse(&response).map_err(|_| ExecutorError::OutcomeUnknown)?;
        if applied.etag == owned.after_etag
            || applied.etag == owned.before_etag
            || applied.digest != expected.digest
        {
            return Err(ExecutorError::OutcomeUnknown);
        }
        // Persist the provider's success before attempting any readback.
        Ok(StepReceipt {
            state: StepState::ConfigApplied,
            effect: EffectState::Unknown,
            native_operation_ref: Some(format!(
                "gcp-owned-iam-removal-v1.{}.{}",
                applied.etag, applied.digest
            )),
            evidence_refs: vec![readiness_ref.ok_or(ExecutorError::OutcomeUnknown)?],
        })
    }
    fn query_owned_compensation(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        record: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        let (target, subject, owned) =
            self.owned_compensation_context(change, step, ContextMode::Reconcile)?;
        let policy = self.provider.iam_policy_with_version(&owned.project_id)?;
        let current = PolicySnapshot::parse(&policy)?;
        self.revalidate_iam_scope(target, subject, &owned.project_number)?;
        let absent = owned
            .bindings
            .iter()
            .all(|binding| !has_title(&policy, &binding.condition.title));
        let reference = record
            .receipt
            .as_ref()
            .and_then(|receipt| receipt.native_operation_ref.as_deref());
        if let Some(reference) = reference {
            let (etag, digest) = reference
                .strip_prefix("gcp-owned-iam-removal-v1.")
                .and_then(|value| value.split_once('.'))
                .filter(|(etag, digest)| valid_etag(etag) && *digest == owned.before_digest)
                .ok_or(ExecutorError::OutcomeUnknown)?;
            if absent && current.etag == etag && current.digest == digest {
                let mut evidence_refs = record
                    .receipt
                    .as_ref()
                    .map(|receipt| receipt.evidence_refs.clone())
                    .unwrap_or_default();
                evidence_refs.push(hash_bytes(
                    &serde_json::to_vec(&(
                        "gcp-owned-iam-readback-v1",
                        &change.change_hash,
                        reference,
                    ))
                    .expect("fixed tuple serializes"),
                ));
                return Ok(StepReceipt {
                    state: StepState::Compensated,
                    effect: EffectState::Unknown,
                    native_operation_ref: Some(reference.into()),
                    evidence_refs,
                });
            }
        } else if absent {
            let absence_ref = hash_bytes(
                &serde_json::to_vec(&(
                    "gcp-owned-iam-unattributed-absence-v1",
                    &change.change_hash,
                    &current.etag,
                    &current.digest,
                ))
                .expect("fixed tuple serializes"),
            );
            return Ok(StepReceipt {
                state: StepState::OutcomeUnknown,
                effect: EffectState::Unknown,
                native_operation_ref: None,
                evidence_refs: vec![
                    owned_iam_unattributed_absence_ref(change, step),
                    absence_ref,
                ],
            });
        }
        Err(ExecutorError::OutcomeUnknown)
    }
    pub fn new(provider: P, execution_identity: String, checkpoints: G) -> Self {
        Self {
            provider,
            execution_identity,
            checkpoints,
            last_revocation: None,
            last_owned_iam_delta: None,
            source_contract_scope: false,
        }
    }
    /// Facts from this executor's latest observation; reading never probes.
    pub fn last_revocation_evidence(&self) -> Option<&RevocationEvidence> {
        self.last_revocation.as_ref()
    }
    /// Shared production boundary for the SQL and handoff adapters. This checks
    /// exact registered principal/incarnation without executing a native action
    /// or requiring a still-valid historical cutover checkpoint.
    pub fn revalidate_target(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
    ) -> Result<(), ExecutorError> {
        self.context(change, step, ContextMode::Composite)
            .map(|_| ())
    }
    /// Read-only current observation; valid after the forward change window
    /// expires. Imported receipts never qualify as current observer evidence.
    /// Incomplete recovery/direct coverage remains in the returned facts, so an
    /// observed Allowed result is retained even while effect proof is pending.
    pub fn collect_revocation_evidence(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
    ) -> Result<Option<RevocationEvidence>, ExecutorError> {
        self.last_revocation = None;
        if step.action != ActionKind::ObserveRevocation {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let (target, grant, subject, instance) =
            self.context(change, step, ContextMode::Reconcile)?;
        let recoveries = recovery_principals(change, target, grant)?;
        for email in &recoveries {
            let recovery = change
                .policy
                .subjects
                .iter()
                .find(|s| s.identity.principal == *email)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            if Some(self.provider.service_account_id(email)?) != recovery.identity.immutable_id {
                return Err(ExecutorError::PreconditionsNotMet);
            }
        }
        let Some(evidence) = self.provider.observe_revocation(change, target, grant)? else {
            return Ok(None);
        };
        let now = self.provider.now();
        if evidence.generation
            != target
                .resource
                .generation_fingerprint
                .clone()
                .unwrap_or_default()
            || evidence.denied_principal != subject.identity.principal
            || evidence.observed_at > now
            || now.saturating_sub(evidence.observed_at) > 60
            || evidence.evidence_refs.is_empty()
            || evidence
                .evidence_refs
                .iter()
                .any(|v| !crate::core::policy::valid_hash(v))
        {
            return Ok(None);
        }
        // Recheck incarnations after potentially slow observations.
        let fresh = self.provider.instance(target)?;
        self.check_instance(target, &fresh)?;
        if fresh != instance {
            return Ok(None);
        }
        for email in recoveries
            .iter()
            .chain(std::iter::once(&subject.identity.principal))
        {
            let registered = change
                .policy
                .subjects
                .iter()
                .find(|s| s.identity.principal == *email)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            if Some(self.provider.service_account_id(email)?) != registered.identity.immutable_id {
                return Err(ExecutorError::PreconditionsNotMet);
            }
        }
        self.last_revocation = Some(evidence.clone());
        Ok(Some(evidence))
    }
    fn context<'a>(
        &mut self,
        change: &'a PreparedChange,
        step: &PlanStep,
        mode: ContextMode,
    ) -> Result<(&'a Target, &'a Grant, &'a Subject, CloudSqlInstance), ExecutorError> {
        if change.verify().is_err()
            || !change.plan.steps.contains(step)
            || (mode != ContextMode::Composite && !self.available(change, step))
            || !crate::core::source_execution::execution_contract_matches(
                change,
                step,
                "core-adapter-v2",
            )
            || (change.policy.schema_version == 2
                && mode == ContextMode::Dispatch
                && !self.source_contract_scope)
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if self.provider.execution_identity()? != self.execution_identity {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let target = change
            .policy
            .targets
            .iter()
            .find(|t| t.id == step.target_id)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let grant = change
            .policy
            .grants
            .iter()
            .find(|g| g.id == step.grant_id && g.target == target.id)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let subject = change
            .policy
            .subjects
            .iter()
            .find(|s| s.id == grant.subject)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let profile = change
            .policy
            .protection_profiles
            .iter()
            .find(|p| p.id == step.profile_id && p.id == grant.profile)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        if target.placement.kind != PlacementKind::GcpCloudSql
            || target.engine.family != EngineFamily::PostgreSql
            || target.engine.version != "16.15"
            || target.placement.region != "asia-northeast1"
            || profile.kind != ProfileKind::GcpCloudSqlPostgresConnectorV1
            || (grant.admission != AdmissionIntent::Allow
                && !matches!(
                    step.action,
                    ActionKind::DisableNativeIdentity
                        | ActionKind::CompensateOwnedIam
                        | ActionKind::ObserveRevocation
                        | ActionKind::DisableNewConnections
                        | ActionKind::RevokeSqlPrivileges
                        | ActionKind::DrainExistingSessions
                        | ActionKind::TerminateSelectedSessions
                ))
            || !matches!(grant.lifetime, GrantLifetime::Standing)
            || subject.identity.provider != IdentityProvider::Gcp
            || !service_email(&subject.identity.principal)
            || !target
                .managed_surface
                .db_identities
                .contains(&grant.db_identity)
            || grant.db_identity
                != subject
                    .identity
                    .principal
                    .trim_end_matches(".gserviceaccount.com")
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if grant.admission == AdmissionIntent::Deny
            && !matches!(
                step.action,
                ActionKind::DisableNativeIdentity
                    | ActionKind::CompensateOwnedIam
                    | ActionKind::ObserveRevocation
                    | ActionKind::DisableNewConnections
                    | ActionKind::RevokeSqlPrivileges
                    | ActionKind::DrainExistingSessions
                    | ActionKind::TerminateSelectedSessions
            )
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let immutable = subject
            .identity
            .immutable_id
            .as_ref()
            .filter(|v| !v.is_empty())
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        if self
            .provider
            .service_account_id(&subject.identity.principal)?
            != *immutable
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if grant.admission == AdmissionIntent::Deny {
            for email in recovery_principals(change, target, grant)? {
                let recovery = change
                    .policy
                    .subjects
                    .iter()
                    .find(|s| s.identity.principal == email)
                    .ok_or(ExecutorError::PreconditionsNotMet)?;
                if Some(self.provider.service_account_id(&email)?) != recovery.identity.immutable_id
                {
                    return Err(ExecutorError::PreconditionsNotMet);
                }
            }
        }
        let instance = self.provider.instance(target)?;
        self.check_instance(target, &instance)?;
        let fields = &target.managed_surface.fields;
        let owned = match step.action {
            ActionKind::PrepareNativeRoute => fields.contains(&ManagedField::GcpDatabaseFlag),
            ActionKind::ConfigureIdentity
            | ActionKind::DisableNativeIdentity
            | ActionKind::CompensateOwnedIam => fields.contains(&ManagedField::GcpIamBinding),
            ActionKind::ObserveRevocation => {
                fields.contains(&ManagedField::GcpIamBinding)
                    && fields.contains(&ManagedField::GcpConnectorEnforcement)
            }
            ActionKind::RegisterNativeDbIdentity => fields.contains(&ManagedField::DbLogin),
            ActionKind::ConstrainDirectPath => {
                fields.contains(&ManagedField::GcpConnectorEnforcement)
            }
            _ => false,
        };
        if mode != ContextMode::Composite && !owned {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if mode == ContextMode::Dispatch && step.action != ActionKind::ObserveRevocation {
            self.checkpoints
                .validate_change_window(change, &target.id, self.provider.now())
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        }
        if step.action == ActionKind::ConstrainDirectPath && mode == ContextMode::Dispatch {
            // Enforcement is instance-wide. Every affected grant must have
            // migration and independent recovery readiness, not just this row.
            self.checkpoints
                .validate(change, &target.id, self.provider.now())
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        }
        Ok((target, grant, subject, instance))
    }
    fn check_instance(
        &self,
        target: &Target,
        instance: &CloudSqlInstance,
    ) -> Result<(), ExecutorError> {
        let expected = target
            .resource
            .generation_fingerprint
            .as_ref()
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let version = instance
            .installed_version
            .strip_prefix("POSTGRES_")
            .unwrap_or(&instance.installed_version)
            .replace('_', ".");
        if instance.project != target.placement.account_id
            || instance.name != native_name(target)?
            || instance.region != target.placement.region
            || instance.create_time.is_empty()
            || generation_fingerprint(&instance.project, &instance.name, &instance.create_time)
                != *expected
            || version != target.engine.version
            || !instance.runnable
            || instance.settings_version.parse::<u64>().is_err()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let mut flags = BTreeSet::new();
        if instance
            .database_flags
            .iter()
            .any(|f| !flags.insert(&f.name))
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(())
    }
    fn configured(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        target: &Target,
        grant: &Grant,
        subject: &Subject,
        instance: &CloudSqlInstance,
    ) -> Result<bool, ExecutorError> {
        Ok(match step.action {
            ActionKind::PrepareNativeRoute => instance
                .database_flags
                .iter()
                .any(|f| f.name == "cloudsql.iam_authentication" && f.value == "on"),
            ActionKind::ConfigureIdentity => {
                let policy = self.provider.iam_policy(&target.placement.account_id)?;
                let desired = desired_iam_policy(change, target, grant, subject, &policy)?;
                desired == policy
            }
            ActionKind::DisableNativeIdentity => {
                let policy = self.provider.iam_policy(&target.placement.account_id)?;
                removed_iam_policy(change, target, grant, subject, &policy)? == policy
            }
            ActionKind::ObserveRevocation => instance.connector_required,
            ActionKind::RegisterNativeDbIdentity => {
                let users = self.provider.users(target)?;
                let rows = users
                    .iter()
                    .filter(|u| u.name == grant.db_identity)
                    .collect::<Vec<_>>();
                if rows.len() > 1 || rows.first().is_some_and(|u| !u.iam_service_account) {
                    return Err(ExecutorError::PreconditionsNotMet);
                }
                rows.len() == 1
            }
            ActionKind::ConstrainDirectPath => instance.connector_required,
            _ => false,
        })
    }
    fn applied(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        target: &Target,
        native_ref: String,
        no_op: bool,
    ) -> Result<StepReceipt, ExecutorError> {
        let mut refs = vec![hash_bytes(
            &serde_json::to_vec(&(
                "native-postcondition-v1",
                &change.change_hash,
                &step.id,
                &native_ref,
            ))
            .expect("fixed tuple serializes"),
        )];
        if step.action == ActionKind::DisableNativeIdentity {
            return Ok(StepReceipt {
                // Only the named configuration predicate is satisfied here.
                // Final ObserveRevocation certifies actual new-connection denial.
                state: if no_op {
                    StepState::NoOpSatisfied
                } else {
                    StepState::EffectSatisfied
                },
                effect: EffectState::Enforced,
                native_operation_ref: Some(native_ref),
                evidence_refs: refs,
            });
        }
        if change.policy.schema_version == 2
            && matches!(
                step.action,
                ActionKind::ConstrainDirectPath | ActionKind::ObserveRevocation
            )
        {
            // Configuration readback is never effect satisfaction in v2.
            // The composition reloads source evidence to finish this receipt.
            return Ok(StepReceipt {
                state: StepState::ConfigApplied,
                effect: EffectState::Unknown,
                native_operation_ref: Some(native_ref),
                evidence_refs: refs,
            });
        }
        if step.action == ActionKind::ObserveRevocation {
            let evidence = self.collect_revocation_evidence(change, step)?;
            let grant = change
                .policy
                .grants
                .iter()
                .find(|g| g.id == step.grant_id)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            let recoveries = recovery_principals(change, target, grant)?;
            let mut direct = recoveries.clone();
            let subject = change
                .policy
                .subjects
                .iter()
                .find(|s| s.id == grant.subject)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            direct.insert(subject.identity.principal.clone());
            let instance = self.provider.instance(target)?;
            self.check_instance(target, &instance)?;
            let satisfied = instance.connector_required
                && evidence.as_ref().is_some_and(|e| {
                    e.complete
                        && e.access == GcpAccess::Denied
                        && matches!(
                            e.denied_permission,
                            Some(GcpPermission::InstanceConnect | GcpPermission::InstanceLogin)
                        )
                        && recoveries.is_subset(&e.connector_allowed_principals)
                        && direct.is_subset(&e.direct_denied_principals)
                });
            if let Some(evidence) = evidence {
                refs.extend(evidence.evidence_refs);
            }
            return Ok(StepReceipt {
                state: if satisfied {
                    StepState::EffectSatisfied
                } else {
                    StepState::ConfigApplied
                },
                effect: if satisfied {
                    EffectState::Enforced
                } else {
                    EffectState::Pending
                },
                native_operation_ref: Some(native_ref),
                evidence_refs: refs,
            });
        }
        if step.action != ActionKind::ConstrainDirectPath {
            return Ok(StepReceipt {
                state: if no_op {
                    StepState::NoOpSatisfied
                } else {
                    StepState::EffectSatisfied
                },
                effect: EffectState::Enforced,
                native_operation_ref: Some(native_ref),
                evidence_refs: refs,
            });
        }
        if let Some(evidence) = self.provider.observe_connections(change, target)? {
            let now = self.provider.now();
            let expected = target
                .resource
                .generation_fingerprint
                .as_deref()
                .unwrap_or("");
            let needed = required_principals(change, target)?;
            if evidence.generation == expected
                && evidence.observed_at <= now
                && now.saturating_sub(evidence.observed_at) <= 60
                && !evidence.evidence_refs.is_empty()
                && evidence
                    .evidence_refs
                    .iter()
                    .all(|v| crate::core::policy::valid_hash(v))
            {
                let satisfied = !needed.is_empty()
                    && needed.is_subset(&evidence.connector_principals)
                    && needed.is_subset(&evidence.direct_denied_principals);
                // Keep scoped current diagnostics even when source coverage is
                // missing. Persistence is not evidence of effect satisfaction.
                refs.extend(evidence.evidence_refs);
                if satisfied {
                    return Ok(StepReceipt {
                        state: StepState::EffectSatisfied,
                        effect: EffectState::Enforced,
                        native_operation_ref: Some(native_ref),
                        evidence_refs: refs,
                    });
                }
            }
        }
        Ok(StepReceipt {
            state: StepState::ConfigApplied,
            effect: EffectState::Pending,
            native_operation_ref: Some(native_ref),
            evidence_refs: refs,
        })
    }
}
impl<P: CloudSqlProvider, G: CheckpointGate> StepExecutor for GcpExecutor<P, G> {
    fn lease_duration_seconds(&self) -> u64 {
        3600
    }
    fn identity(&self) -> &str {
        &self.execution_identity
    }
    fn cancelled(&self) -> bool {
        self.provider.cancelled()
    }
    fn available(&self, _: &PreparedChange, step: &PlanStep) -> bool {
        matches!(
            step.action,
            ActionKind::PrepareNativeRoute
                | ActionKind::ConfigureIdentity
                | ActionKind::RegisterNativeDbIdentity
                | ActionKind::ConstrainDirectPath
                | ActionKind::DisableNativeIdentity
                | ActionKind::CompensateOwnedIam
                | ActionKind::ObserveRevocation
        )
    }
    fn preflight(&mut self, change: &PreparedChange, step: &PlanStep) -> Result<(), ExecutorError> {
        if step.action == ActionKind::CompensateOwnedIam {
            let (target, subject, owned) =
                self.owned_compensation_context(change, step, ContextMode::Dispatch)?;
            self.checkpoints
                .validate_owned_iam_compensation(change, &target.id, self.provider.now())
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
            self.revalidate_iam_scope(target, subject, &owned.project_number)?;
            self.owned_compensation_candidate(owned)?;
            return Ok(());
        }
        let (target, grant, subject, instance) =
            self.context(change, step, ContextMode::Dispatch)?;
        // Read the exact write domain before durable dispatch, detecting invalid
        // IAM ownership collisions and wrong-type existing login accounts.
        self.configured(change, step, target, grant, subject, &instance)?;
        if change.policy.schema_version == 1
            && step.action == ActionKind::ConstrainDirectPath
            && !instance.connector_required
        {
            let evidence = self
                .provider
                .observe_connections(change, target)?
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            let needed = required_principals(change, target)?;
            if evidence.generation
                != target
                    .resource
                    .generation_fingerprint
                    .clone()
                    .unwrap_or_default()
                || evidence.observed_at > self.provider.now()
                || self.provider.now().saturating_sub(evidence.observed_at) > 60
                || !needed.is_subset(&evidence.connector_principals)
                || evidence.evidence_refs.is_empty()
            {
                return Err(ExecutorError::PreconditionsNotMet);
            }
        }
        Ok(())
    }
    fn submit(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        ticket: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        if step.action == ActionKind::CompensateOwnedIam {
            return Err(ExecutorError::Unavailable);
        }
        self.submit_checked(change, step, ticket, &mut || Ok(()), &mut || Ok(()))
    }
    fn take_gcp_iam_owned_delta(&mut self) -> Option<OwnedIamDeltaReceipt> {
        self.last_owned_iam_delta.take()
    }
    fn query(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        record: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        if record.step_id != step.id {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if step.action == ActionKind::CompensateOwnedIam {
            return self.query_owned_compensation(change, step, record);
        }
        let reference = record
            .receipt
            .as_ref()
            .and_then(|r| r.native_operation_ref.as_deref())
            .ok_or(ExecutorError::OutcomeUnknown)?;
        // Missing references (e.g. a crash during submission) stay ambiguous.
        // query never writes and never searches then replays a native request.
        let (target, grant, subject, instance) =
            self.context(change, step, ContextMode::Reconcile)?;
        if reference != synchronous_ref(change, step) {
            let native = self.provider.operation(target, reference)?;
            validate_operation(target, &native)?;
            if native.name != reference {
                return Err(ExecutorError::OutcomeUnknown);
            }
            if !native.done {
                return Ok(StepReceipt {
                    state: StepState::Submitted,
                    effect: EffectState::Pending,
                    native_operation_ref: Some(reference.into()),
                    evidence_refs: vec![],
                });
            }
            if native.failed {
                return Ok(StepReceipt {
                    state: StepState::Failed,
                    effect: EffectState::NotSatisfied,
                    native_operation_ref: Some(reference.into()),
                    evidence_refs: vec![],
                });
            }
        }
        if step.action != ActionKind::ObserveRevocation
            && !self.configured(change, step, target, grant, subject, &instance)?
        {
            return Err(ExecutorError::OutcomeUnknown);
        }
        self.applied(change, step, target, reference.into(), false)
    }
}

fn synchronous_ref(change: &PreparedChange, step: &PlanStep) -> String {
    format!(
        "gcp-readback-{}",
        hash_bytes(
            &serde_json::to_vec(&(&change.change_hash, &step.id, &step.parameters_hash))
                .expect("fixed tuple serializes")
        )
    )
}

/// Marker for a historical, read-only absence observation with no attributable
/// removal response. The companion evidence digest commits to the snapshot.
pub fn owned_iam_unattributed_absence_ref(change: &PreparedChange, step: &PlanStep) -> String {
    hash_bytes(
        &serde_json::to_vec(&(
            "gcp-owned-iam-unattributed-absence-marker-v1",
            &change.change_hash,
            &step.id,
        ))
        .expect("fixed tuple serializes"),
    )
}
fn validate_operation(target: &Target, native: &NativeOperation) -> Result<(), ExecutorError> {
    if !segment(&native.name)
        || native.project != target.placement.account_id
        || native.instance != native_name(target)?
    {
        return Err(ExecutorError::OutcomeUnknown);
    }
    Ok(())
}

/// Adds owned, conditional instance-scoped allow entries; never removes or
/// adopts a pre-existing broad grant. A title collision is an ownership failure.
pub fn desired_iam_policy(
    change: &PreparedChange,
    target: &Target,
    grant: &Grant,
    subject: &Subject,
    before: &Value,
) -> Result<Value, ProviderError> {
    if grant.admission != AdmissionIntent::Allow {
        return Err(ProviderError::Precondition);
    }
    owned_iam_policy(change, target, grant, subject, before, false)
}

/// Removes only exact Veil-owned conditional allow entries. The ownership tuple
/// deliberately excludes revision/admission so a Deny revision identifies the
/// original Allow entries. A changed row is drift and is never adopted/deleted.
pub fn removed_iam_policy(
    change: &PreparedChange,
    target: &Target,
    grant: &Grant,
    subject: &Subject,
    before: &Value,
) -> Result<Value, ProviderError> {
    owned_iam_policy(change, target, grant, subject, before, true)
}
fn owned_iam_policy(
    change: &PreparedChange,
    target: &Target,
    grant: &Grant,
    subject: &Subject,
    before: &Value,
    remove: bool,
) -> Result<Value, ProviderError> {
    if before
        .get("etag")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ProviderError::Precondition);
    }
    let mut next = before.clone();
    let object = next.as_object_mut().ok_or(ProviderError::Precondition)?;
    let bindings = object
        .entry("bindings")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(ProviderError::Precondition)?;
    for binding in OwnedIamBinding::for_grant(&change.policy.policy_id, target, grant, subject) {
        let desired = binding_value(&binding);
        let existing = bindings
            .iter()
            .filter(|b| {
                b.pointer("/condition/title").and_then(Value::as_str)
                    == Some(&binding.condition.title)
            })
            .collect::<Vec<_>>();
        if existing.len() > 1 || existing.first().is_some_and(|b| **b != desired) {
            return Err(ProviderError::Precondition);
        }
        if remove {
            bindings.retain(|b| b != &desired);
        } else if existing.is_empty() {
            bindings.push(desired);
        }
    }
    // IAM conditions require version 3. Existing version 3 must be requested on
    // read or a conditional policy could be silently collapsed to hashed roles.
    if object.get("version").and_then(Value::as_u64) == Some(1)
        && !remove
        && PolicySnapshot::parse(before).is_ok()
    {
        object.insert("version".into(), json!(3));
    } else if object.get("version").and_then(Value::as_u64) != Some(3) {
        return Err(ProviderError::Precondition);
    }
    Ok(next)
}

fn recovery_principals(
    change: &PreparedChange,
    target: &Target,
    grant: &Grant,
) -> Result<BTreeSet<String>, ProviderError> {
    let profile = change
        .policy
        .protection_profiles
        .iter()
        .find(|p| p.id == grant.profile)
        .ok_or(ProviderError::Precondition)?;
    let revoked = change
        .policy
        .subjects
        .iter()
        .find(|s| s.id == grant.subject)
        .ok_or(ProviderError::Precondition)?;
    let mut principals = BTreeSet::new();
    for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
        let subject = change
            .policy
            .subjects
            .iter()
            .find(|s| s.id == exception.subject)
            .ok_or(ProviderError::Precondition)?;
        if subject.identity.provider != IdentityProvider::Gcp
            || !service_email(&subject.identity.principal)
            || subject.identity.principal == revoked.identity.principal
            || subject
                .identity
                .immutable_id
                .as_ref()
                .is_none_or(String::is_empty)
            || subject.identity.immutable_id == revoked.identity.immutable_id
            || !matches!(exception.lifetime, GrantLifetime::Standing)
            || !profile
                .allowed_routes
                .iter()
                .any(|r| r.id == exception.route_id)
            || grant.target != target.id
        {
            return Err(ProviderError::Precondition);
        }
        principals.insert(subject.identity.principal.clone());
    }
    if principals.is_empty() {
        return Err(ProviderError::Precondition);
    }
    Ok(principals)
}

fn required_principals(
    change: &PreparedChange,
    target: &Target,
) -> Result<BTreeSet<String>, ProviderError> {
    let mut ids = BTreeSet::new();
    for grant in change
        .policy
        .grants
        .iter()
        .filter(|g| g.target == target.id && g.admission == AdmissionIntent::Allow)
    {
        ids.insert(grant.subject.clone());
        let profile = change
            .policy
            .protection_profiles
            .iter()
            .find(|p| p.id == grant.profile)
            .ok_or(ProviderError::Precondition)?;
        for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
            ids.insert(exception.subject.clone());
        }
    }
    if ids.is_empty() {
        return Err(ProviderError::Precondition);
    }
    ids.into_iter()
        .map(|id| {
            change
                .policy
                .subjects
                .iter()
                .find(|s| s.id == id)
                .filter(|s| {
                    s.identity.provider == IdentityProvider::Gcp
                        && service_email(&s.identity.principal)
                        && s.identity.immutable_id.is_some()
                })
                .map(|s| s.identity.principal.clone())
                .ok_or(ProviderError::Precondition)
        })
        .collect()
}

/// Opt-in production REST backend. Construction performs no cloud or process
/// calls. Every OAuth token is obtained with explicit SA impersonation. Token
/// headers and bodies go through stdin, never shell strings, argv, files/logs.
pub struct GcloudProvider {
    gcloud: PathBuf,
    curl: PathBuf,
    email: String,
    unique_id: String,
    identity: String,
    cancel: CancellationToken,
    probe: Option<(GcpConfig, LiveTools)>,
}
impl GcloudProvider {
    pub fn new(
        gcloud: PathBuf,
        curl: PathBuf,
        identity: &str,
        cancel: CancellationToken,
    ) -> Result<Self, ProviderError> {
        let rest = identity
            .strip_prefix("gcp-service-account:")
            .ok_or(ProviderError::Precondition)?;
        let (email, unique_id) = rest.split_once(':').ok_or(ProviderError::Precondition)?;
        if !service_email(email)
            || unique_id.is_empty()
            || !unique_id.bytes().all(|v| v.is_ascii_digit())
        {
            return Err(ProviderError::Precondition);
        }
        Ok(Self {
            gcloud: executable(&gcloud)?,
            curl: executable(&curl)?,
            email: email.into(),
            unique_id: unique_id.into(),
            identity: identity.into(),
            cancel,
            probe: None,
        })
    }
    pub fn with_probe(
        mut self,
        config: GcpConfig,
        tools: LiveTools,
    ) -> Result<Self, ProviderError> {
        crate::gcp::config::validate_config(&config).map_err(|_| ProviderError::Precondition)?;
        if config.limits.total_timeout_ms > 120_000 {
            return Err(ProviderError::Precondition);
        }
        if executable(&tools.gcloud)? != self.gcloud {
            return Err(ProviderError::Precondition);
        }
        self.probe = Some((config, tools));
        Ok(self)
    }
    fn token(&self) -> Result<String, ProviderError> {
        let properties_args = ["config", "list", "--all", "--format=json(auth.disable_credentials,auth.disable_ssl_validation,auth.credential_file_override,auth.access_token_file,auth.authorization_token_file,auth.impersonate_service_account,auth.token_host,auth.mtls_token_host,auth.auth_host,core.universe_domain,core.custom_ca_certs_file,api_endpoint_overrides,proxy)", "--quiet", "--verbosity=none"]
            .iter().map(|v| (*v).into()).collect::<Vec<String>>();
        let properties = run_process(&self.gcloud, &properties_args, &[], &self.cancel)?;
        let properties: Value =
            serde_json::from_slice(&properties).map_err(|_| ProviderError::Precondition)?;
        if !properties.is_object() {
            return Err(ProviderError::Precondition);
        }
        crate::gcp::live::validate_sdk_properties(&properties)
            .map_err(|_| ProviderError::Precondition)?;
        let args = vec![
            "auth".into(),
            "print-access-token".into(),
            format!("--impersonate-service-account={}", self.email),
            "--quiet".into(),
            "--verbosity=none".into(),
        ];
        let bytes = run_process(&self.gcloud, &args, &[], &self.cancel)?;
        let token = String::from_utf8(bytes)
            .map_err(|_| ProviderError::Unavailable)?
            .trim()
            .to_string();
        if token.is_empty()
            || token.len() > 16384
            || !token
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-._~+/=".contains(&v))
        {
            return Err(ProviderError::Unavailable);
        }
        Ok(token)
    }
    fn rest(
        &self,
        host: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
        mutation: bool,
    ) -> Result<Value, ProviderError> {
        let output = self.rest_bytes(host, method, path, body, mutation)?;
        serde_json::from_slice(&output).map_err(|_| {
            if mutation {
                ProviderError::Unknown
            } else {
                ProviderError::Unavailable
            }
        })
    }
    fn rest_bytes(
        &self,
        host: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
        mutation: bool,
    ) -> Result<Vec<u8>, ProviderError> {
        self.rest_bytes_checked(host, method, path, body, mutation, &mut |_| Ok(()))
    }
    fn rest_bytes_checked(
        &self,
        host: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
        mutation: bool,
        before_send: &mut BeforeIamSend<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        if ![
            "sqladmin.googleapis.com",
            "cloudresourcemanager.googleapis.com",
            "iam.googleapis.com",
        ]
        .contains(&host)
            || !path.starts_with("/v1/")
            || path.chars().any(char::is_control)
        {
            return Err(ProviderError::Precondition);
        }
        let token = self.token()?;
        let mut config = format!(
            "url = {}\nrequest = {}\nheader = {}\nheader = \"Content-Type: application/json\"\n",
            curl_quote(&format!("https://{host}{path}")),
            curl_quote(method),
            curl_quote(&format!("Authorization: Bearer {token}"))
        );
        if let Some(body) = body {
            config.push_str(&format!("data = {}\n", curl_quote(&body.to_string())));
        }
        let args: Vec<String> = [
            "-q",
            "--silent",
            "--show-error",
            "--max-time",
            "25",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--noproxy",
            "*",
            "--max-filesize",
            "2097152",
            "--write-out",
            "\n%{http_code}",
            "--config",
            "-",
        ]
        .iter()
        .map(|v| (*v).into())
        .collect();
        before_send(&|| self.now())?;
        if self.cancelled() {
            return Err(if mutation {
                ProviderError::NotApplied
            } else {
                ProviderError::Unavailable
            });
        }
        let output =
            run_process(&self.curl, &args, config.as_bytes(), &self.cancel).map_err(|_| {
                if mutation {
                    ProviderError::Unknown
                } else {
                    ProviderError::Unavailable
                }
            })?;
        let split = output
            .iter()
            .rposition(|v| *v == b'\n')
            .ok_or(ProviderError::Unknown)?;
        let status = std::str::from_utf8(&output[split + 1..])
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .ok_or(ProviderError::Unknown)?;
        if !(200..300).contains(&status) {
            return Err(
                if mutation && path.ends_with(":setIamPolicy") && matches!(status, 409 | 412) {
                    ProviderError::Conflict
                } else if matches!(status, 400 | 401 | 403 | 404 | 409 | 412) {
                    ProviderError::NotApplied
                } else if mutation {
                    ProviderError::Unknown
                } else {
                    ProviderError::Unavailable
                },
            );
        }
        Ok(output[..split].to_vec())
    }
    fn read_iam_policy_bytes(&self, project: &str) -> Result<Vec<u8>, ProviderError> {
        if !segment(project) {
            return Err(ProviderError::Precondition);
        }
        self.rest_bytes(
            "cloudresourcemanager.googleapis.com",
            "POST",
            &format!("/v1/projects/{project}:getIamPolicy"),
            Some(&json!({"options":{"requestedPolicyVersion":3}})),
            false,
        )
    }
    fn write_iam_policy_bytes(
        &self,
        project: &str,
        policy: &Value,
        before_send: &mut BeforeIamSend<'_>,
    ) -> Result<Vec<u8>, ProviderError> {
        if !segment(project)
            || policy
                .get("etag")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || policy.get("version") != Some(&json!(3))
        {
            return Err(ProviderError::Precondition);
        }
        self.rest_bytes_checked(
            "cloudresourcemanager.googleapis.com",
            "POST",
            &format!("/v1/projects/{project}:setIamPolicy"),
            Some(&json!({"policy":policy,"updateMask":"bindings,etag,version"})),
            true,
            before_send,
        )
    }
    fn instance_path(target: &Target) -> Result<String, ProviderError> {
        Ok(format!(
            "/v1/projects/{}/instances/{}",
            target.placement.account_id,
            native_name(target)?
        ))
    }
}
fn curl_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
fn string(value: &Value, key: &str) -> Result<String, ProviderError> {
    value
        .pointer(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or(ProviderError::Unavailable)
}
fn executable(path: &Path) -> Result<PathBuf, ProviderError> {
    if !path.is_absolute() {
        return Err(ProviderError::Precondition);
    }
    let real = path
        .canonicalize()
        .map_err(|_| ProviderError::Precondition)?;
    let metadata = real.metadata().map_err(|_| ProviderError::Precondition)?;
    if !metadata.is_file() {
        return Err(ProviderError::Precondition);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ProviderError::Precondition);
        }
    }
    Ok(real)
}
fn parse_operation(value: &Value) -> Result<NativeOperation, ProviderError> {
    Ok(NativeOperation {
        name: string(value, "/name")?,
        project: string(value, "/targetProject")?,
        instance: string(value, "/targetId")?,
        done: value.get("status").and_then(Value::as_str) == Some("DONE"),
        failed: value
            .pointer("/error/errors")
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty()),
    })
}
impl CloudSqlProvider for GcloudProvider {
    fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        let email = self.email.clone();
        if self.service_account_id(&email)? != self.unique_id {
            return Err(ProviderError::Precondition);
        }
        Ok(self.identity.clone())
    }
    fn service_account_id(&mut self, email: &str) -> Result<String, ProviderError> {
        if !service_email(email) {
            return Err(ProviderError::Precondition);
        }
        let value = self.rest(
            "iam.googleapis.com",
            "GET",
            &format!("/v1/projects/-/serviceAccounts/{email}"),
            None,
            false,
        )?;
        if value.get("disabled").and_then(Value::as_bool) == Some(true)
            || string(&value, "/email")? != email
        {
            return Err(ProviderError::Precondition);
        }
        string(&value, "/uniqueId")
    }
    fn project_number(&mut self, project: &str) -> Result<String, ProviderError> {
        if !segment(project) {
            return Err(ProviderError::Precondition);
        }
        let value = self.rest(
            "cloudresourcemanager.googleapis.com",
            "GET",
            &format!("/v1/projects/{project}"),
            None,
            false,
        )?;
        let number = string(&value, "/projectNumber")?;
        if string(&value, "/projectId")? != project
            || string(&value, "/lifecycleState")? != "ACTIVE"
            || !numeric_id(&number)
        {
            return Err(ProviderError::Precondition);
        }
        Ok(number)
    }
    fn instance(&mut self, target: &Target) -> Result<CloudSqlInstance, ProviderError> {
        let value = self.rest(
            "sqladmin.googleapis.com",
            "GET",
            &Self::instance_path(target)?,
            None,
            false,
        )?;
        let database_flags = value
            .pointer("/settings/databaseFlags")
            .cloned()
            .unwrap_or_else(|| json!([]));
        Ok(CloudSqlInstance {
            project: string(&value, "/project")?,
            name: string(&value, "/name")?,
            region: string(&value, "/region")?,
            create_time: string(&value, "/createTime")?,
            installed_version: string(&value, "/databaseInstalledVersion")?,
            settings_version: string(&value, "/settings/settingsVersion")?,
            database_flags: serde_json::from_value(database_flags)
                .map_err(|_| ProviderError::Unavailable)?,
            connector_required: value
                .pointer("/settings/connectorEnforcement")
                .and_then(Value::as_str)
                == Some("REQUIRED"),
            runnable: value.get("state").and_then(Value::as_str) == Some("RUNNABLE"),
        })
    }
    fn iam_policy(&mut self, project: &str) -> Result<Value, ProviderError> {
        let bytes = self.read_iam_policy_bytes(project)?;
        let mut value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ProviderError::Unavailable)?;
        // An unconditional policy can legitimately be returned with version 1.
        // Request version 3 and promote only after ensuring native bindings have
        // no synthetic condition-hash roles from an older version-1 read.
        if value
            .get("bindings")
            .and_then(Value::as_array)
            .is_some_and(|rows| {
                rows.iter().any(|b| {
                    b.get("role")
                        .and_then(Value::as_str)
                        .is_some_and(|r| r.contains("_withcond_"))
                })
            })
        {
            return Err(ProviderError::Precondition);
        }
        value
            .as_object_mut()
            .ok_or(ProviderError::Unavailable)?
            .insert("version".into(), json!(3));
        Ok(value)
    }
    fn iam_policy_with_version(&mut self, project: &str) -> Result<Value, ProviderError> {
        let bytes = self.read_iam_policy_bytes(project)?;
        // Validate the wire representation before converting it to a JSON
        // Value, which would otherwise hide duplicate object keys.
        serde_json::from_slice::<IamPolicy>(&bytes).map_err(|_| ProviderError::Precondition)?;
        serde_json::from_slice(&bytes).map_err(|_| ProviderError::Precondition)
    }
    fn set_iam_policy(&mut self, project: &str, policy: &Value) -> Result<(), ProviderError> {
        self.set_iam_policy_receipt(project, policy)?;
        Ok(())
    }
    fn set_iam_policy_receipt(
        &mut self,
        project: &str,
        policy: &Value,
    ) -> Result<Option<Value>, ProviderError> {
        self.set_iam_policy_receipt_checked(project, policy, &mut |_| Ok(()))
    }
    fn set_iam_policy_receipt_checked(
        &mut self,
        project: &str,
        policy: &Value,
        before_send: &mut BeforeIamSend<'_>,
    ) -> Result<Option<Value>, ProviderError> {
        let bytes = self.write_iam_policy_bytes(project, policy, before_send)?;
        let response = serde_json::from_slice(&bytes).map_err(|_| ProviderError::Unknown)?;
        Ok(serde_json::from_slice::<IamPolicy>(&bytes)
            .ok()
            .map(|_| response))
    }
    fn users(&mut self, target: &Target) -> Result<Vec<CloudSqlUser>, ProviderError> {
        let value = self.rest(
            "sqladmin.googleapis.com",
            "GET",
            &format!("{}/users", Self::instance_path(target)?),
            None,
            false,
        )?;
        if value
            .get("nextPageToken")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return Err(ProviderError::Unavailable);
        }
        value
            .get("items")
            .cloned()
            .unwrap_or_else(|| json!([]))
            .as_array()
            .ok_or(ProviderError::Unavailable)?
            .iter()
            .map(|u| {
                Ok(CloudSqlUser {
                    name: string(u, "/name")?,
                    iam_service_account: u.get("type").and_then(Value::as_str)
                        == Some("CLOUD_IAM_SERVICE_ACCOUNT"),
                })
            })
            .collect()
    }
    fn patch(
        &mut self,
        target: &Target,
        before: &CloudSqlInstance,
        patch: NativePatch,
    ) -> Result<NativeOperation, ProviderError> {
        let current = self.instance(target)?;
        if target.resource.generation_fingerprint.as_deref()
            != Some(&generation_fingerprint(
                &current.project,
                &current.name,
                &current.create_time,
            ))
        {
            return Err(ProviderError::NotApplied);
        }
        // settingsVersion CAS plus immediate incarnation read. The API has no
        // createTime conditional-write parameter; that limitation is explicit.
        if current.create_time != before.create_time
            || current.settings_version != before.settings_version
        {
            return Err(ProviderError::NotApplied);
        }
        let settings = match patch {
            NativePatch::EnableIamAuthentication => {
                let mut flags = before.database_flags.clone();
                flags.retain(|f| f.name != "cloudsql.iam_authentication");
                flags.push(DatabaseFlag {
                    name: "cloudsql.iam_authentication".into(),
                    value: "on".into(),
                });
                json!({"settingsVersion":before.settings_version,"databaseFlags":flags})
            }
            NativePatch::RequireConnector => {
                json!({"settingsVersion":before.settings_version,"connectorEnforcement":"REQUIRED"})
            }
        };
        let value = self.rest(
            "sqladmin.googleapis.com",
            "PATCH",
            &Self::instance_path(target)?,
            Some(&json!({"settings":settings})),
            true,
        )?;
        parse_operation(&value).map_err(|_| ProviderError::Unknown)
    }
    fn register_user(
        &mut self,
        target: &Target,
        username: &str,
    ) -> Result<NativeOperation, ProviderError> {
        let current = self.instance(target)?;
        if target.resource.generation_fingerprint.as_deref()
            != Some(&generation_fingerprint(
                &current.project,
                &current.name,
                &current.create_time,
            ))
        {
            return Err(ProviderError::NotApplied);
        }
        let value = self.rest(
            "sqladmin.googleapis.com",
            "POST",
            &format!("{}/users", Self::instance_path(target)?),
            Some(&json!({"name":username,"type":"CLOUD_IAM_SERVICE_ACCOUNT"})),
            true,
        )?;
        parse_operation(&value).map_err(|_| ProviderError::Unknown)
    }
    fn operation(&mut self, target: &Target, name: &str) -> Result<NativeOperation, ProviderError> {
        if !segment(name) {
            return Err(ProviderError::Precondition);
        }
        let value = self.rest(
            "sqladmin.googleapis.com",
            "GET",
            &format!(
                "/v1/projects/{}/operations/{name}",
                target.placement.account_id
            ),
            None,
            false,
        )?;
        parse_operation(&value)
    }
    fn observe_connections(
        &mut self,
        change: &PreparedChange,
        target: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        let Some((config, tools)) = self.probe.clone() else {
            return Ok(None);
        };
        if config.target.project_id != target.placement.account_id
            || config.target.instance_id != native_name(target)?
            || config.target.region != target.placement.region
            || config.target.database != target.engine.database
            || config
                .target
                .engine_version
                .trim_start_matches("POSTGRES_")
                .replace('_', ".")
                != target.engine.version
        {
            return Err(ProviderError::Precondition);
        }
        let needed = required_principals(change, target)?;
        if needed.len() > 8 {
            return Err(ProviderError::Precondition);
        }
        for email in &needed {
            let subject = change
                .policy
                .subjects
                .iter()
                .find(|s| s.identity.principal == *email)
                .ok_or(ProviderError::Precondition)?;
            if Some(self.service_account_id(email)?) != subject.identity.immutable_id {
                return Err(ProviderError::Precondition);
            }
            let principal = config
                .principals
                .iter()
                .find(|p| p.service_account == *email)
                .ok_or(ProviderError::Precondition)?;
            if !config.cases.iter().any(|c| {
                c.principal_id == principal.id
                    && c.route == GcpRoute::Proxy
                    && c.expected == GcpExpectation::Allow
            }) || !config.cases.iter().any(|c| {
                c.principal_id == principal.id
                    && c.route == GcpRoute::Direct
                    && c.expected == GcpExpectation::Deny
            }) {
                return Err(ProviderError::Precondition);
            }
        }
        let Some(NativeCapture {
            capture,
            generation,
            evidence_refs,
            complete,
        }) = self.capture_connections(target, config.clone(), tools)?
        else {
            return Ok(None);
        };
        if !complete {
            return Ok(None);
        }
        Ok(Some(classify_cli_connection_evidence(
            &capture.observations,
            &config.principals,
            &target.engine.database,
            generation,
            capture.started_at,
            evidence_refs,
        )))
    }

    fn observe_revocation(
        &mut self,
        change: &PreparedChange,
        target: &Target,
        grant: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        let Some((mut config, tools)) = self.probe.clone() else {
            return Ok(None);
        };
        if config.target.project_id != target.placement.account_id
            || config.target.instance_id != native_name(target)?
            || config.target.region != target.placement.region
            || config.target.database != target.engine.database
            || config
                .target
                .engine_version
                .trim_start_matches("POSTGRES_")
                .replace('_', ".")
                != target.engine.version
        {
            return Err(ProviderError::Precondition);
        }
        let subject = change
            .policy
            .subjects
            .iter()
            .find(|s| s.id == grant.subject)
            .ok_or(ProviderError::Precondition)?;
        let recoveries = recovery_principals(change, target, grant)?;
        let mut needed = recoveries.clone();
        needed.insert(subject.identity.principal.clone());
        for email in &needed {
            let registered = change
                .policy
                .subjects
                .iter()
                .find(|s| s.identity.principal == *email)
                .ok_or(ProviderError::Precondition)?;
            if Some(self.service_account_id(email)?) != registered.identity.immutable_id {
                return Err(ProviderError::Precondition);
            }
            let principal = config
                .principals
                .iter()
                .find(|p| p.service_account == *email)
                .ok_or(ProviderError::Precondition)?;
            // Select only the principals approved by this prepared change.
            // Expected outcomes select positive transport controls, not success.
            if !config
                .cases
                .iter()
                .any(|c| c.principal_id == principal.id && c.route == GcpRoute::Proxy)
                || !config
                    .cases
                    .iter()
                    .any(|c| c.principal_id == principal.id && c.route == GcpRoute::Direct)
            {
                return Err(ProviderError::Precondition);
            }
        }
        config
            .principals
            .retain(|p| needed.contains(&p.service_account));
        let principal_ids = config
            .principals
            .iter()
            .map(|p| p.id.clone())
            .collect::<BTreeSet<_>>();
        config
            .cases
            .retain(|c| principal_ids.contains(&c.principal_id));
        config.permission_changes.clear();
        for case in &mut config.cases {
            let principal = config
                .principals
                .iter()
                .find(|p| p.id == case.principal_id)
                .ok_or(ProviderError::Precondition)?;
            case.expected = if case.route == GcpRoute::Proxy
                && recoveries.contains(&principal.service_account)
            {
                GcpExpectation::Allow
            } else {
                GcpExpectation::Deny
            };
            case.expected_denial = if case.route == GcpRoute::Direct {
                Some(GcpDenial::NetworkBlocked)
            } else if principal.service_account == subject.identity.principal {
                Some(GcpDenial::ConnectIam)
            } else {
                None
            };
        }
        crate::gcp::config::validate_config(&config).map_err(|_| ProviderError::Precondition)?;
        let Some(NativeCapture {
            capture,
            generation,
            evidence_refs,
            complete,
        }) = self.capture_connections(target, config.clone(), tools)?
        else {
            return Ok(None);
        };
        let principal_id = &config
            .principals
            .iter()
            .find(|p| p.service_account == subject.identity.principal)
            .ok_or(ProviderError::Precondition)?
            .id;
        let (access, permission) =
            classify_revocation_iam(&capture.observations, principal_id, capture.started_at);
        let connections = classify_cli_connection_evidence(
            &capture.observations,
            &config.principals,
            &target.engine.database,
            generation.clone(),
            capture.started_at,
            evidence_refs,
        );
        Ok(Some(RevocationEvidence {
            complete,
            generation,
            observed_at: capture.started_at,
            denied_principal: subject.identity.principal.clone(),
            access,
            denied_permission: permission,
            connector_allowed_principals: connections.connector_principals,
            direct_denied_principals: connections.direct_denied_principals,
            evidence_refs: connections.evidence_refs,
        }))
    }
}

/// Classify the production CLI collector without expanding its source scope.
/// Connector SQL success establishes the observed authenticated principal. The
/// collector does not verify the workload source for either a declared-principal
/// direct sample or a separate TCP refusal, so neither establishes workload
/// direct denial. Raw observations (including successful direct access) and TCP
/// diagnostics remain in the referenced artifacts; they are not discarded or
/// converted into denial. Source-bound direct proof requires a later producer.
///
/// Called only after the provider's immutable identity, target generation and
/// capture coherence checks. Injected trusted providers can produce broader
/// ConnectionEvidence independently of this production CLI classifier.
pub fn classify_cli_connection_evidence(
    observations: &[GcpObservation],
    principals: &[GcpPrincipal],
    database: &str,
    generation: String,
    started_at: u64,
    evidence_refs: Vec<String>,
) -> ConnectionEvidence {
    let mut positive = BTreeSet::new();
    for sample in observations {
        let Some(principal) = principals.iter().find(|p| p.id == sample.principal_id) else {
            continue;
        };
        if sample.execution == GcpExecution::Completed
            && sample.started_at >= started_at
            && sample.route == GcpRoute::Proxy
            && sample.proof.sql_ok
            && sample.proof.sql_authenticated
            && sample.proof.db_user.as_deref() == Some(&principal.db_user())
            && sample.proof.database.as_deref() == Some(database)
        {
            positive.insert(principal.service_account.clone());
        }
    }
    ConnectionEvidence {
        generation,
        // Freshness starts at the earliest possible connector observation.
        observed_at: started_at,
        connector_principals: positive,
        direct_denied_principals: BTreeSet::new(),
        evidence_refs,
    }
}

/// Pure classification used by the current live collector. Timeout, missing
/// credentials, SQL ACL refusal and unrelated IAM permission failures stay
/// Unknown. A successful connector observation dominates every denial sample.
pub fn classify_revocation_iam(
    observations: &[GcpObservation],
    principal_id: &str,
    started_at: u64,
) -> (GcpAccess, Option<GcpPermission>) {
    let samples = observations
        .iter()
        .filter(|s| {
            s.principal_id == principal_id
                && s.route == GcpRoute::Proxy
                && s.started_at >= started_at
                && s.execution == GcpExecution::Completed
        })
        .collect::<Vec<_>>();
    if samples
        .iter()
        .any(|s| s.proof.sql_authenticated || s.proof.sql_ok || s.observed == GcpAccess::Allowed)
    {
        return (GcpAccess::Allowed, None);
    }
    for sample in samples {
        let proof = &sample.proof;
        if !proof.credential_issued || sample.observed != GcpAccess::Denied {
            continue;
        }
        if proof.denied_permission == Some(GcpPermission::InstanceConnect) {
            return (GcpAccess::Denied, proof.denied_permission);
        }
        if proof.denied_permission == Some(GcpPermission::InstanceLogin)
            && proof.iam_login_rejected
            && proof.transport_positive
            && proof.transport_control_case_id.as_ref().is_some_and(|id| {
                observations.iter().any(|control| {
                    control.case_id == *id
                        && control.principal_id != principal_id
                        && control.execution == GcpExecution::Completed
                        && control.started_at >= started_at
                        && control.route == GcpRoute::Proxy
                        && control.observed == GcpAccess::Allowed
                        && control.proof.credential_issued
                        && control.proof.sql_authenticated
                        && control.proof.sql_ok
                })
            })
        {
            return (GcpAccess::Denied, proof.denied_permission);
        }
    }
    (GcpAccess::Unknown, None)
}

struct NativeCapture {
    complete: bool,
    capture: GcpRunEvidence,
    generation: String,
    evidence_refs: Vec<String>,
}
impl GcloudProvider {
    fn capture_connections(
        &mut self,
        target: &Target,
        config: GcpConfig,
        mut tools: LiveTools,
    ) -> Result<Option<NativeCapture>, ProviderError> {
        let before = self.instance(target)?;
        let started = crate::domain::now();
        let evidence_dir = tools.work_dir.join(format!(
            "native-evidence-{}-{}",
            started,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| ProviderError::Unavailable)?
                .subsec_nanos()
        ));
        let mut writer = crate::store::RunWriter::create_for_config(
            &evidence_dir,
            &target.id,
            &config,
            "gcp-check",
            config.limits.max_bytes,
            false,
        )
        .map_err(|_| ProviderError::Unavailable)?;
        // The existing observer creates CA/proxy files with create_new. Give
        // each observation its own private transport directory so resume never
        // overwrites earlier proof or fails on a prior CA capture.
        let transport_dir = writer.path().join("transport");
        let mut directory = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory
            .create(&transport_dir)
            .map_err(|_| ProviderError::Unavailable)?;
        tools.work_dir = transport_dir;
        let run_id = writer.manifest.run_id.clone();
        let cancel = self.cancel.clone();
        let capture_result = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| ProviderError::Unavailable)?;
                    rt.block_on(async {
                        crate::gcp::live::probe(
                            &config,
                            &tools,
                            &run_id,
                            cancel,
                            tokio::time::Instant::now()
                                + Duration::from_millis(config.limits.total_timeout_ms),
                        )
                        .await
                        .map_err(|_| ProviderError::Unavailable)
                    })
                })
                .join()
                .map_err(|_| ProviderError::Unavailable)
        })?;
        let capture = match capture_result {
            Ok(capture) => capture,
            Err(error) => {
                writer
                    .write_json(
                        "probe-error.json",
                        &json!({"status":"unavailable","raw_output_retained":false}),
                    )
                    .map_err(|_| ProviderError::Unavailable)?;
                writer
                    .finish(crate::store::RunStatus::Partial)
                    .map_err(|_| ProviderError::Unavailable)?;
                return Err(error);
            }
        };
        writer
            .write_json("snapshot.before.json", &capture.before)
            .map_err(|_| ProviderError::Unavailable)?;
        writer
            .write_json("snapshot.after.json", &capture.after)
            .map_err(|_| ProviderError::Unavailable)?;
        writer
            .write_json("observations.json", &capture)
            .map_err(|_| ProviderError::Unavailable)?;
        let generation = generation_fingerprint(&before.project, &before.name, &before.create_time);
        let transport = capture
            .after
            .public_ip
            .map(|address| {
                observe_direct_transport(
                    target.id.clone(),
                    generation.clone(),
                    address,
                    &self.cancel,
                )
            })
            .transpose()?;
        if let Some(transport) = &transport {
            writer
                .write_json("native-direct-transport.json", transport)
                .map_err(|_| ProviderError::Unavailable)?;
        }
        let after_result = self.instance(target);
        let mut a = capture.before.clone();
        a.observed_at = 0;
        let mut b = capture.after.clone();
        b.observed_at = 0;
        let stable_target = after_result.as_ref().is_ok_and(|after| before == *after);
        let coherent = stable_target
            && capture.execution == GcpExecution::Completed
            && capture.evidence_kind == GcpEvidenceKind::Live
            && capture.started_at >= started
            && a.complete
            && b.complete
            && a == b;
        writer
            .finish(if coherent {
                crate::store::RunStatus::Complete
            } else {
                crate::store::RunStatus::Partial
            })
            .map_err(|_| ProviderError::Unavailable)?;
        if !stable_target
            || capture.evidence_kind != GcpEvidenceKind::Live
            || capture.started_at < started
        {
            return Ok(None);
        }
        if target.resource.generation_fingerprint.as_deref() != Some(&generation) {
            return Err(ProviderError::Precondition);
        }
        Ok(Some(NativeCapture {
            complete: coherent,
            capture,
            generation,
            evidence_refs: writer
                .manifest
                .artifacts
                .iter()
                .filter(|a| {
                    a.name == "observations.json" || a.name == "native-direct-transport.json"
                })
                .map(|a| a.sha256.clone())
                .collect(),
        }))
    }
}

fn observe_direct_transport(
    target_id: String,
    generation: String,
    address: std::net::Ipv4Addr,
    cancel: &CancellationToken,
) -> Result<DirectTransportObservation, ProviderError> {
    let outcome = std::thread::scope(|scope| {
        scope.spawn(|| {
        let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|ProviderError::Unavailable)?;
        runtime.block_on(async {
            Ok(tokio::select! { biased; _=cancel.cancelled()=>DirectTransportOutcome::Cancelled,
                result=tokio::time::timeout(Duration::from_secs(5),tokio::net::TcpStream::connect((address,5432)))=> match result {
                    Ok(Ok(stream))=>{drop(stream);DirectTransportOutcome::Connected},
                    Ok(Err(error)) if classify_transport_refusal(error.kind())=>DirectTransportOutcome::ExplicitRefusal,
                    Ok(Err(_))=>DirectTransportOutcome::OtherFailure,
                    Err(_)=>DirectTransportOutcome::Timeout,
                }
            })
        })
    }).join().map_err(|_|ProviderError::Unavailable)
    })??;
    Ok(DirectTransportObservation {
        target_id,
        generation,
        address,
        port: 5432,
        observed_at: crate::domain::now(),
        outcome,
    })
}

/// Bounded private child process. All failures discard raw stdout/stderr. A
/// dedicated runtime thread also permits use from the CLI's Tokio runtime.
fn run_process(
    program: &Path,
    args: &[String],
    input: &[u8],
    cancel: &CancellationToken,
) -> Result<Vec<u8>, ProviderError> {
    if cancel.is_cancelled() {
        return Err(ProviderError::Unavailable);
    }
    std::thread::scope(|scope| {
        scope.spawn(|| {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| ProviderError::Unavailable)?;
        runtime.block_on(async {
            let tools = LiveTools { gcloud: program.to_path_buf(), proxy: program.to_path_buf(), psql: program.to_path_buf(), work_dir: PathBuf::new() };
            let environment = crate::gcp::live::sanitized_environment(&tools, &std::env::vars_os().collect()).map_err(|_| ProviderError::Precondition)?;
            let mut command = tokio::process::Command::new(program);
            command.args(args).env_clear().envs(environment).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.as_std_mut().process_group(0);
            }
            let mut child = command.spawn().map_err(|_| ProviderError::Unavailable)?;
            struct ChildGroup(Option<u32>);
            impl Drop for ChildGroup {
                fn drop(&mut self) {
                    #[cfg(unix)]
                    if let Some(pid)=self.0.and_then(|p|i32::try_from(p).ok()).filter(|p|*p>0) {
                        // SAFETY: spawn assigned the child's pid to a fresh
                        // process group. A positive pid cannot target our group.
                        unsafe { libc::kill(-pid,libc::SIGKILL); }
                    }
                }
            }
            let process_group=ChildGroup(child.id());
            let mut stdin = child.stdin.take().ok_or(ProviderError::Unavailable)?;
            let stdout = child.stdout.take().ok_or(ProviderError::Unavailable)?;
            let stderr = child.stderr.take().ok_or(ProviderError::Unavailable)?;
            async fn read<R: AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>, ProviderError> {
                let mut out = vec![];
                reader.take(2 * 1024 * 1024 + 1).read_to_end(&mut out).await.map_err(|_| ProviderError::Unavailable)?;
                if out.len() > 2 * 1024 * 1024 { return Err(ProviderError::Unavailable); }
                Ok(out)
            }
            let task = async {
                let (status, bytes, _, ()) = tokio::try_join!(
                    async { child.wait().await.map_err(|_| ProviderError::Unavailable) }, read(stdout), read(stderr),
                    async { stdin.write_all(input).await.map_err(|_| ProviderError::Unavailable)?; stdin.shutdown().await.map_err(|_| ProviderError::Unavailable) }
                )?;
                if !status.success() { return Err(ProviderError::Unavailable); }
                Ok(bytes)
            };
            let result = tokio::select! { biased; _ = cancel.cancelled() => Err(ProviderError::Unavailable),
                value = tokio::time::timeout(Duration::from_secs(30), task) => value.unwrap_or(Err(ProviderError::Unavailable)) };
            drop(process_group);
            if result.is_err() { let _ = child.kill().await; let _ = child.wait().await; }
            result
        })
    }).join().map_err(|_| ProviderError::Unavailable)
    })?
}
