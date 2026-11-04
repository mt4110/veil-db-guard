//! All provider responses here are injected local fakes, never cloud evidence.
use serde_json::{Value, json};
use std::{cell::Cell, collections::BTreeSet, rc::Rc};
use veil_db_guard::{
    adapters::{capabilities_for, deployment::gcp::*},
    binding::{BindingError, CheckpointGate},
    core::{
        capability::{ActionKind, Implementation, Support},
        change::{OperationLimits, PreparedChange, prepare_change},
        operation::{DispatchTicket, EffectState, LeaseSet, StepRecord, StepState},
        orchestrator::{ExecutorError, StepExecutor},
        plan::{PlanStep, build_plan},
        policy::{AdmissionIntent, EffectKind, Target, parse_policy},
    },
};

const EXECUTION: &str =
    "gcp-service-account:runner@vdg-example-000000.iam.gserviceaccount.com:100000000000000000001";
const CREATED: &str = "2026-11-01T10:00:00Z";

fn prepared() -> PreparedChange {
    let mut policy = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    for (index, subject) in policy.subjects.iter_mut().enumerate() {
        subject.identity.immutable_id = Some(format!("10000000000000000000{index}"));
    }
    policy.targets[0].resource.generation_fingerprint = Some(generation_fingerprint(
        "vdg-example-000000",
        "billing-postgres",
        CREATED,
    ));
    let mut capabilities = policy
        .targets
        .iter()
        .flat_map(capabilities_for)
        .collect::<Vec<_>>();
    for capability in &mut capabilities {
        capability.support = Support::Supported;
        capability.implementation = Implementation::Implemented;
        capability.contract_revision = "core-adapter-v2".into();
        capability.constraints.clear();
    }
    let plan = build_plan(&policy, capabilities, vec![], 100).unwrap();
    prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn step(change: &PreparedChange, action: ActionKind) -> &PlanStep {
    change
        .plan
        .steps
        .iter()
        .find(|s| s.action == action)
        .unwrap()
}
fn ticket(step: &PlanStep) -> DispatchTicket {
    DispatchTicket {
        operation_id: "operation-1".into(),
        step_id: step.id.clone(),
        attempt: 1,
        operation_version: 1,
        idempotency_key: "request-step-1".into(),
        leases: LeaseSet {
            holder: "holder-1".into(),
            token: 1,
            keys: vec!["owned".into()],
            expires_at: 4000,
        },
    }
}
fn record(step: &PlanStep, receipt: veil_db_guard::core::operation::StepReceipt) -> StepRecord {
    StepRecord {
        step_id: step.id.clone(),
        state: receipt.state,
        attempt: 1,
        idempotency_key: "request-step-1".into(),
        receipt: Some(receipt),
    }
}
#[derive(Clone)]
struct Gate(Rc<Cell<bool>>);
impl CheckpointGate for Gate {
    fn validate(&self, _: &PreparedChange, _: &str, _: u64) -> Result<Vec<String>, BindingError> {
        if self.0.get() {
            Ok(vec!["a".repeat(64)])
        } else {
            Err(BindingError::Pending)
        }
    }
    fn validate_change_window(
        &self,
        _: &PreparedChange,
        _: &str,
        _: u64,
    ) -> Result<String, BindingError> {
        if self.0.get() {
            Ok("b".repeat(64))
        } else {
            Err(BindingError::Pending)
        }
    }
}
struct FakeProvider {
    instance: CloudSqlInstance,
    policy: Value,
    users: Vec<CloudSqlUser>,
    writes: Vec<String>,
    operation: NativeOperation,
    identity: String,
    evidence: Option<ConnectionEvidence>,
    revocation: Option<RevocationEvidence>,
    fail_write: Option<ProviderError>,
    account_id: String,
}
impl FakeProvider {
    fn new(change: &PreparedChange) -> Self {
        let names = change
            .policy
            .subjects
            .iter()
            .map(|s| s.identity.principal.clone())
            .collect::<BTreeSet<_>>();
        Self {
            instance: CloudSqlInstance {
                project: "vdg-example-000000".into(),
                name: "billing-postgres".into(),
                region: "asia-northeast1".into(),
                create_time: CREATED.into(),
                installed_version: "POSTGRES_16_15".into(),
                settings_version: "7".into(),
                database_flags: vec![DatabaseFlag {
                    name: "log_min_duration_statement".into(),
                    value: "500".into(),
                }],
                connector_required: false,
                runnable: true,
            },
            policy: json!({"version":3,"etag":"iam-version-7","auditConfigs":[{"service":"allServices"}],"bindings":[
                {"role":"roles/viewer","members":["user:unrelated@example.com"]}
            ]}),
            users: vec![],
            writes: vec![],
            operation: NativeOperation {
                name: "native-operation-1".into(),
                project: "vdg-example-000000".into(),
                instance: "billing-postgres".into(),
                done: false,
                failed: false,
            },
            identity: EXECUTION.into(),
            evidence: Some(ConnectionEvidence {
                generation: change.policy.targets[0]
                    .resource
                    .generation_fingerprint
                    .clone()
                    .unwrap(),
                observed_at: 100,
                connector_principals: names.clone(),
                direct_denied_principals: names,
                evidence_refs: vec!["d".repeat(64)],
            }),
            revocation: None,
            fail_write: None,
            account_id: "".into(),
        }
    }
}
impl CloudSqlProvider for FakeProvider {
    fn now(&self) -> u64 {
        100
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        Ok(self.identity.clone())
    }
    fn instance(&mut self, _: &Target) -> Result<CloudSqlInstance, ProviderError> {
        Ok(self.instance.clone())
    }
    fn service_account_id(&mut self, email: &str) -> Result<String, ProviderError> {
        if !self.account_id.is_empty() {
            return Ok(self.account_id.clone());
        }
        Ok(if email.starts_with("billing-app@") {
            "100000000000000000000"
        } else {
            "100000000000000000001"
        }
        .into())
    }
    fn iam_policy(&mut self, _: &str) -> Result<Value, ProviderError> {
        Ok(self.policy.clone())
    }
    fn set_iam_policy(&mut self, _: &str, policy: &Value) -> Result<(), ProviderError> {
        self.writes.push("iam".into());
        if let Some(error) = self.fail_write {
            return Err(error);
        }
        assert_eq!(policy.get("etag"), self.policy.get("etag"));
        self.policy = policy.clone();
        Ok(())
    }
    fn users(&mut self, _: &Target) -> Result<Vec<CloudSqlUser>, ProviderError> {
        Ok(self.users.clone())
    }
    fn patch(
        &mut self,
        _: &Target,
        before: &CloudSqlInstance,
        patch: NativePatch,
    ) -> Result<NativeOperation, ProviderError> {
        assert_eq!(before.settings_version, self.instance.settings_version);
        self.writes.push(format!("{patch:?}"));
        if let Some(error) = self.fail_write {
            return Err(error);
        }
        match patch {
            NativePatch::EnableIamAuthentication => {
                self.instance.database_flags.push(DatabaseFlag {
                    name: "cloudsql.iam_authentication".into(),
                    value: "on".into(),
                })
            }
            NativePatch::RequireConnector => self.instance.connector_required = true,
        }
        Ok(self.operation.clone())
    }
    fn register_user(
        &mut self,
        _: &Target,
        username: &str,
    ) -> Result<NativeOperation, ProviderError> {
        self.writes.push("user".into());
        if let Some(error) = self.fail_write {
            return Err(error);
        }
        self.users.push(CloudSqlUser {
            name: username.into(),
            iam_service_account: true,
        });
        Ok(self.operation.clone())
    }
    fn operation(&mut self, _: &Target, _: &str) -> Result<NativeOperation, ProviderError> {
        Ok(self.operation.clone())
    }
    fn observe_connections(
        &mut self,
        _: &PreparedChange,
        _: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        Ok(self.evidence.clone())
    }
    fn observe_revocation(
        &mut self,
        _: &PreparedChange,
        _: &Target,
        _: &veil_db_guard::core::policy::Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        Ok(self.revocation.clone())
    }
}
fn executor(change: &PreparedChange) -> GcpExecutor<FakeProvider, Gate> {
    GcpExecutor::new(
        FakeProvider::new(change),
        EXECUTION.into(),
        Gate(Rc::new(Cell::new(true))),
    )
}

#[test]
fn route_acceptance_is_not_readback_and_unknown_is_never_replayed() {
    let change = prepared();
    let step = step(&change, ActionKind::PrepareNativeRoute);
    let mut executor = executor(&change);
    executor.preflight(&change, step).unwrap();
    let receipt = executor.submit(&change, step, &ticket(step)).unwrap();
    assert_eq!(receipt.state, StepState::Submitted);
    assert_eq!(receipt.effect, EffectState::Pending);
    let mut record = record(step, receipt);
    assert_eq!(
        executor.query(&change, step, &record).unwrap().state,
        StepState::Submitted
    );
    executor.provider.operation.done = true;
    assert_eq!(
        executor.query(&change, step, &record).unwrap().state,
        StepState::EffectSatisfied
    );
    record.receipt = None;
    record.state = StepState::OutcomeUnknown;
    assert_eq!(
        executor.query(&change, step, &record),
        Err(ExecutorError::OutcomeUnknown)
    );
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn reused_native_name_generation_or_subject_identity_blocks_every_write() {
    let change = prepared();
    let step = step(&change, ActionKind::ConfigureIdentity);
    for cause in ["generation", "identity", "subject"] {
        let mut executor = executor(&change);
        match cause {
            "generation" => executor.provider.instance.create_time = "2026-11-02T01:00:00Z".into(),
            "identity" => executor.provider.identity = "different-runner".into(),
            _ => executor.provider.account_id = "recreated-principal".into(),
        }
        assert!(executor.preflight(&change, step).is_err());
        assert!(executor.submit(&change, step, &ticket(step)).is_err());
        assert!(executor.provider.writes.is_empty());
    }
}

#[test]
fn iam_adds_only_owned_instance_conditions_and_preserves_unrelated_policy() {
    let change = prepared();
    let step = step(&change, ActionKind::ConfigureIdentity);
    let mut executor = executor(&change);
    let before = executor.provider.policy.clone();
    let receipt = executor.submit(&change, step, &ticket(step)).unwrap();
    assert_eq!(receipt.state, StepState::EffectSatisfied);
    let after = &executor.provider.policy;
    assert_eq!(after["etag"], before["etag"]);
    assert_eq!(after["auditConfigs"], before["auditConfigs"]);
    assert_eq!(after["bindings"][0], before["bindings"][0]);
    assert_eq!(after["bindings"].as_array().unwrap().len(), 3);
    for binding in after["bindings"].as_array().unwrap().iter().skip(1) {
        assert_eq!(binding["members"].as_array().unwrap().len(), 1);
        assert!(
            binding["condition"]["expression"]
                .as_str()
                .unwrap()
                .contains("projects/vdg-example-000000/instances/billing-postgres")
        );
    }
    let again = executor.submit(&change, step, &ticket(step)).unwrap();
    assert_eq!(again.state, StepState::NoOpSatisfied);
    assert_eq!(executor.provider.writes, vec!["iam"]);
}

#[test]
fn iam_condition_collision_and_missing_etag_are_not_adopted() {
    let change = prepared();
    let step = step(&change, ActionKind::ConfigureIdentity);
    let mut executor = executor(&change);
    executor.submit(&change, step, &ticket(step)).unwrap();
    executor.provider.policy["bindings"][1]["members"] = json!(["allUsers"]);
    assert!(executor.preflight(&change, step).is_err());
    executor
        .provider
        .policy
        .as_object_mut()
        .unwrap()
        .remove("etag");
    assert!(executor.preflight(&change, step).is_err());
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn iam_user_registration_never_adopts_password_login_or_replays_ambiguous_write() {
    let change = prepared();
    let step = step(&change, ActionKind::RegisterNativeDbIdentity);
    let mut executor = executor(&change);
    executor.provider.users.push(CloudSqlUser {
        name: change.policy.grants[0].db_identity.clone(),
        iam_service_account: false,
    });
    assert!(executor.preflight(&change, step).is_err());
    executor.provider.users.clear();
    executor.provider.fail_write = Some(ProviderError::Unknown);
    assert_eq!(
        executor.submit(&change, step, &ticket(step)),
        Err(ExecutorError::OutcomeUnknown)
    );
    let record = StepRecord {
        step_id: step.id.clone(),
        state: StepState::OutcomeUnknown,
        attempt: 1,
        idempotency_key: "unknown".into(),
        receipt: None,
    };
    assert_eq!(
        executor.query(&change, step, &record),
        Err(ExecutorError::OutcomeUnknown)
    );
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn connector_closure_needs_all_clients_and_recovery_before_and_after_write() {
    let change = prepared();
    let step = step(&change, ActionKind::ConstrainDirectPath);
    let mut executor = executor(&change);
    executor.provider.evidence = None;
    assert!(executor.preflight(&change, step).is_err());
    assert!(executor.provider.writes.is_empty());
    executor.provider.evidence = FakeProvider::new(&change).evidence;
    let receipt = executor.submit(&change, step, &ticket(step)).unwrap();
    let record = record(step, receipt);
    executor.provider.operation.done = true;
    executor
        .provider
        .evidence
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .clear();
    let config = executor.query(&change, step, &record).unwrap();
    assert_eq!(config.state, StepState::ConfigApplied);
    assert_eq!(config.effect, EffectState::Pending);
    executor.provider.evidence = FakeProvider::new(&change).evidence;
    let enforced = executor.query(&change, step, &record).unwrap();
    assert_eq!(enforced.state, StepState::EffectSatisfied);
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn accepted_query_survives_expired_checkpoints_but_not_replaced_generation() {
    let change = prepared();
    let step = step(&change, ActionKind::ConstrainDirectPath);
    let gate = Gate(Rc::new(Cell::new(true)));
    let state = gate.0.clone();
    let mut executor = GcpExecutor::new(FakeProvider::new(&change), EXECUTION.into(), gate);
    let receipt = executor.submit(&change, step, &ticket(step)).unwrap();
    let record = record(step, receipt);
    executor.provider.operation.done = true;
    state.set(false);
    assert_eq!(
        executor.query(&change, step, &record).unwrap().state,
        StepState::EffectSatisfied
    );
    assert!(executor.preflight(&change, step).is_err());
    executor.provider.instance.create_time = "replacement".into();
    assert!(executor.query(&change, step, &record).is_err());
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn sql_and_binding_composite_guard_revalidates_generation_without_native_mutation() {
    let change = prepared();
    let step = step(&change, ActionKind::ConfigureSqlPrivileges);
    let mut executor = executor(&change);
    executor.revalidate_target(&change, step).unwrap();
    executor.provider.instance.create_time = "replacement".into();
    assert!(executor.revalidate_target(&change, step).is_err());
    assert!(executor.provider.writes.is_empty());
}

#[test]
fn production_construction_never_executes_tools_and_rejects_unpinned_identity() {
    use tokio_util::sync::CancellationToken;
    assert!(
        GcloudProvider::new(
            "/usr/bin/true".into(),
            "/usr/bin/true".into(),
            EXECUTION,
            CancellationToken::new()
        )
        .is_ok()
    );
    assert!(
        GcloudProvider::new(
            "/does/not/exist".into(),
            "/usr/bin/true".into(),
            EXECUTION,
            CancellationToken::new()
        )
        .is_err()
    );
    assert!(
        GcloudProvider::new(
            "gcloud".into(),
            "/usr/bin/true".into(),
            EXECUTION,
            CancellationToken::new()
        )
        .is_err()
    );
    assert!(
        GcloudProvider::new(
            "gcloud".into(),
            "curl".into(),
            "runner@example.com",
            CancellationToken::new()
        )
        .is_err()
    );
    assert_ne!(
        generation_fingerprint("project-a", "same-name", CREATED),
        generation_fingerprint("project-b", "same-name", CREATED)
    );
}

#[test]
fn external_change_window_and_recovery_coverage_are_required() {
    let change = prepared();
    let gate = Gate(Rc::new(Cell::new(false)));
    let mut executor = GcpExecutor::new(FakeProvider::new(&change), EXECUTION.into(), gate);
    let route = step(&change, ActionKind::PrepareNativeRoute);
    assert!(executor.preflight(&change, route).is_err());
    assert!(executor.provider.writes.is_empty());
    let closure = step(&change, ActionKind::ConstrainDirectPath);
    let mut executor = super_executor(&change);
    executor
        .provider
        .evidence
        .as_mut()
        .unwrap()
        .connector_principals
        .retain(|p| p.starts_with("billing-app@"));
    assert!(executor.preflight(&change, closure).is_err());
    assert!(executor.provider.writes.is_empty());
}

fn super_executor(change: &PreparedChange) -> GcpExecutor<FakeProvider, Gate> {
    executor(change)
}

#[test]
fn foreign_native_operation_cannot_certify_this_target_and_failed_operation_is_retained() {
    let change = prepared();
    let step = step(&change, ActionKind::PrepareNativeRoute);
    let mut executor = executor(&change);
    let receipt = executor.submit(&change, step, &ticket(step)).unwrap();
    let record = record(step, receipt);
    executor.provider.operation.instance = "other-instance".into();
    assert_eq!(
        executor.query(&change, step, &record),
        Err(ExecutorError::OutcomeUnknown)
    );
    executor.provider.operation.instance = "billing-postgres".into();
    executor.provider.operation.done = true;
    executor.provider.operation.failed = true;
    let failed = executor.query(&change, step, &record).unwrap();
    assert_eq!(failed.state, StepState::Failed);
    assert_eq!(
        failed.native_operation_ref.as_deref(),
        Some("native-operation-1")
    );
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn stale_and_foreign_connection_evidence_never_certify_closure() {
    let change = prepared();
    let step = step(&change, ActionKind::ConstrainDirectPath);
    let mut executor = executor(&change);
    let receipt = executor.submit(&change, step, &ticket(step)).unwrap();
    let record = record(step, receipt);
    executor.provider.operation.done = true;
    for fault in ["stale", "generation", "recovery"] {
        executor.provider.evidence = FakeProvider::new(&change).evidence;
        let evidence = executor.provider.evidence.as_mut().unwrap();
        match fault {
            "stale" => evidence.observed_at = 1,
            "generation" => evidence.generation = "f".repeat(64),
            _ => evidence
                .direct_denied_principals
                .retain(|p| p.starts_with("billing-app@")),
        }
        assert_eq!(
            executor.query(&change, step, &record).unwrap().state,
            StepState::ConfigApplied
        );
    }
    assert_eq!(executor.provider.writes.len(), 1);
}

#[test]
fn only_connection_refused_is_an_explicit_transport_refusal_diagnostic() {
    use std::io::ErrorKind;
    assert!(classify_transport_refusal(ErrorKind::ConnectionRefused));
    for kind in [
        ErrorKind::TimedOut,
        ErrorKind::NetworkUnreachable,
        ErrorKind::HostUnreachable,
        ErrorKind::PermissionDenied,
        ErrorKind::ConnectionReset,
        ErrorKind::Other,
    ] {
        assert!(!classify_transport_refusal(kind));
    }
}

fn deny_prepared() -> PreparedChange {
    let mut policy = prepared().policy;
    policy.grants[0].admission = AdmissionIntent::Deny;
    policy.grants[0].sql_access.existing_roles.clear();
    policy.grants[0].sql_access.privileges.clear();
    policy.protection_profiles[0].required_effects =
        vec![EffectKind::BindingApplied, EffectKind::NewConnectionsDenied];
    let mut capabilities = policy
        .targets
        .iter()
        .flat_map(capabilities_for)
        .collect::<Vec<_>>();
    for action in [
        ActionKind::DisableNativeIdentity,
        ActionKind::ObserveRevocation,
    ] {
        if !capabilities.iter().any(|c| c.action == action) {
            capabilities.push(
                veil_db_guard::core::capability::CapabilityDescriptor::planned(
                    policy.targets[0].placement.kind,
                    policy.targets[0].engine.family,
                    action,
                )
                .for_target(&policy.targets[0]),
            );
        }
    }
    for capability in &mut capabilities {
        capability.support = Support::Supported;
        capability.implementation = Implementation::Implemented;
        capability.contract_revision = "core-adapter-v2".into();
        capability.constraints.clear();
    }
    let plan = build_plan(&policy, capabilities, vec![], 100).unwrap();
    prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap()
}
fn revocation_evidence(change: &PreparedChange) -> RevocationEvidence {
    use veil_db_guard::gcp::model::{GcpAccess, GcpPermission};
    let app = change
        .policy
        .subjects
        .iter()
        .find(|s| s.id == change.policy.grants[0].subject)
        .unwrap()
        .identity
        .principal
        .clone();
    let recovery = change
        .policy
        .subjects
        .iter()
        .find(|s| s.id == "recovery-operator")
        .unwrap()
        .identity
        .principal
        .clone();
    RevocationEvidence {
        complete: true,
        generation: change.policy.targets[0]
            .resource
            .generation_fingerprint
            .clone()
            .unwrap(),
        observed_at: 100,
        denied_principal: app.clone(),
        access: GcpAccess::Denied,
        denied_permission: Some(GcpPermission::InstanceConnect),
        connector_allowed_principals: BTreeSet::from([recovery.clone()]),
        direct_denied_principals: BTreeSet::from([app, recovery]),
        evidence_refs: vec!["c".repeat(64)],
    }
}

#[test]
fn revoke_removes_original_owned_bindings_only_and_never_adopts_broad_grants() {
    let allow = prepared();
    let deny = deny_prepared();
    let target = &allow.policy.targets[0];
    let grant = &allow.policy.grants[0];
    let subject = allow
        .policy
        .subjects
        .iter()
        .find(|s| s.id == grant.subject)
        .unwrap();
    let mut native = FakeProvider::new(&allow).policy;
    native["bindings"].as_array_mut().unwrap().push(json!({
        "role":"roles/cloudsql.client", "members":[format!("serviceAccount:{}",subject.identity.principal)]
    }));
    let original = native.clone();
    native = desired_iam_policy(&allow, target, grant, subject, &native).unwrap();
    let removed = removed_iam_policy(
        &deny,
        &deny.policy.targets[0],
        &deny.policy.grants[0],
        subject,
        &native,
    )
    .unwrap();
    assert_eq!(removed, original);
    assert_eq!(
        removed_iam_policy(
            &deny,
            &deny.policy.targets[0],
            &deny.policy.grants[0],
            subject,
            &removed
        )
        .unwrap(),
        original
    );
    assert_eq!(
        desired_iam_policy(
            &deny,
            &deny.policy.targets[0],
            &deny.policy.grants[0],
            subject,
            &removed
        ),
        Err(ProviderError::Precondition)
    );
    native["bindings"][2]["members"]
        .as_array_mut()
        .unwrap()
        .push(json!("user:other@example.com"));
    assert_eq!(
        removed_iam_policy(
            &deny,
            &deny.policy.targets[0],
            &deny.policy.grants[0],
            subject,
            &native
        ),
        Err(ProviderError::Precondition)
    );
}

#[test]
fn revoke_native_readback_certifies_only_configuration_and_query_never_replays() {
    let allow = prepared();
    let deny = deny_prepared();
    let mut executor = executor(&allow);
    let setup = step(&allow, ActionKind::ConfigureIdentity);
    executor.submit(&allow, setup, &ticket(setup)).unwrap();
    let revoke = step(&deny, ActionKind::DisableNativeIdentity);
    let receipt = executor.submit(&deny, revoke, &ticket(revoke)).unwrap();
    assert_eq!(receipt.state, StepState::EffectSatisfied);
    let record = record(revoke, receipt);
    assert_eq!(
        executor.query(&deny, revoke, &record).unwrap().state,
        StepState::EffectSatisfied
    );
    assert_eq!(
        executor
            .submit(&deny, revoke, &ticket(revoke))
            .unwrap()
            .state,
        StepState::NoOpSatisfied
    );
    assert_eq!(executor.provider.writes, vec!["iam", "iam"]);
    assert_eq!(
        executor.provider.policy["bindings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn revocation_observer_is_read_only_after_approval_expiry_and_preserves_allowed_pending() {
    use veil_db_guard::gcp::model::GcpAccess;
    let change = deny_prepared();
    let observe = step(&change, ActionKind::ObserveRevocation);
    let gate = Gate(Rc::new(Cell::new(false)));
    let mut executor = GcpExecutor::new(FakeProvider::new(&change), EXECUTION.into(), gate);
    executor.provider.instance.connector_required = true;
    executor.provider.revocation = Some(revocation_evidence(&change));
    executor.preflight(&change, observe).unwrap();
    let receipt = executor.submit(&change, observe, &ticket(observe)).unwrap();
    assert_eq!(receipt.state, StepState::EffectSatisfied);
    let record = record(observe, receipt);
    executor.provider.revocation.as_mut().unwrap().access = GcpAccess::Allowed;
    let current = executor
        .collect_revocation_evidence(&change, observe)
        .unwrap()
        .unwrap();
    assert_eq!(current.access, GcpAccess::Allowed);
    assert_eq!(
        executor.last_revocation_evidence().unwrap().access,
        GcpAccess::Allowed
    );
    executor.provider.revocation.as_mut().unwrap().complete = false;
    let pending = executor.query(&change, observe, &record).unwrap();
    assert_eq!(pending.state, StepState::ConfigApplied);
    assert_eq!(pending.effect, EffectState::Pending);
    assert!(pending.evidence_refs.contains(&"c".repeat(64)));
    executor
        .provider
        .revocation
        .as_mut()
        .unwrap()
        .direct_denied_principals
        .clear();
    executor
        .provider
        .revocation
        .as_mut()
        .unwrap()
        .connector_allowed_principals
        .clear();
    assert_eq!(
        executor
            .collect_revocation_evidence(&change, observe)
            .unwrap()
            .unwrap()
            .access,
        GcpAccess::Allowed
    );
    assert_eq!(
        executor.query(&change, observe, &record).unwrap().effect,
        EffectState::Pending
    );
    assert!(executor.provider.writes.is_empty());
}

#[test]
fn revocation_needs_fresh_correct_layer_generation_recovery_and_direct_closure() {
    use veil_db_guard::gcp::model::{GcpAccess, GcpPermission};
    let change = deny_prepared();
    let observe = step(&change, ActionKind::ObserveRevocation);
    for fault in [
        "stale",
        "generation",
        "subject",
        "recovery",
        "direct",
        "hash",
        "layer",
        "unknown",
        "connector",
        "partial",
    ] {
        let mut executor = executor(&change);
        executor.provider.instance.connector_required = true;
        executor.provider.revocation = Some(revocation_evidence(&change));
        let evidence = executor.provider.revocation.as_mut().unwrap();
        match fault {
            "stale" => evidence.observed_at = 1,
            "generation" => evidence.generation = "f".repeat(64),
            "subject" => evidence.denied_principal = "different@example.com".into(),
            "recovery" => evidence.connector_allowed_principals.clear(),
            "direct" => evidence.direct_denied_principals.clear(),
            "hash" => evidence.evidence_refs = vec!["invented-artifact".into()],
            "layer" => evidence.denied_permission = Some(GcpPermission::InstanceGet),
            "unknown" => evidence.access = GcpAccess::Unknown,
            "partial" => evidence.complete = false,
            _ => executor.provider.instance.connector_required = false,
        }
        let receipt = executor.submit(&change, observe, &ticket(observe)).unwrap();
        assert_eq!(receipt.state, StepState::ConfigApplied, "{fault}");
        assert_eq!(receipt.effect, EffectState::Pending, "{fault}");
        assert!(executor.provider.writes.is_empty());
    }
    let mut executor = executor(&change);
    executor.provider.account_id = "recreated-principal".into();
    assert!(
        executor
            .collect_revocation_evidence(&change, observe)
            .is_err()
    );
}

#[test]
fn current_iam_revocation_classifier_rejects_timeout_wrong_layer_and_missing_positive_control() {
    use veil_db_guard::gcp::model::*;
    let denied = GcpObservation {
        case_id: "revoked".into(),
        attempt_id: "fresh-attempt".into(),
        principal_id: "app".into(),
        route: GcpRoute::Proxy,
        started_at: 100,
        finished_at: 101,
        execution: GcpExecution::Completed,
        observed: GcpAccess::Denied,
        proof: GcpProof {
            credential_issued: true,
            denied_permission: Some(GcpPermission::InstanceConnect),
            ..Default::default()
        },
    };
    assert_eq!(
        classify_revocation_iam(std::slice::from_ref(&denied), "app", 100),
        (GcpAccess::Denied, Some(GcpPermission::InstanceConnect))
    );
    for fault in [
        "timeout",
        "unrelated-iam",
        "sql-acl",
        "credential",
        "stale",
        "direct",
        "login-no-control",
    ] {
        let mut sample = denied.clone();
        match fault {
            "timeout" => sample.execution = GcpExecution::Timeout,
            "unrelated-iam" => sample.proof.denied_permission = Some(GcpPermission::TokenCreation),
            "sql-acl" => sample.proof.denied_permission = None,
            "credential" => sample.proof.credential_issued = false,
            "stale" => sample.started_at = 99,
            "direct" => sample.route = GcpRoute::Direct,
            _ => {
                sample.proof.denied_permission = Some(GcpPermission::InstanceLogin);
                sample.proof.iam_login_rejected = true;
                sample.proof.transport_positive = true;
                sample.proof.transport_control_case_id = Some("recovery-control".into());
            }
        }
        assert_eq!(
            classify_revocation_iam(&[sample], "app", 100),
            (GcpAccess::Unknown, None),
            "{fault}"
        );
    }
    let mut login = denied.clone();
    login.proof.denied_permission = Some(GcpPermission::InstanceLogin);
    login.proof.iam_login_rejected = true;
    login.proof.transport_positive = true;
    login.proof.transport_control_case_id = Some("recovery-control".into());
    let mut control = denied.clone();
    control.case_id = "recovery-control".into();
    control.principal_id = "recovery".into();
    control.observed = GcpAccess::Allowed;
    control.proof = GcpProof {
        credential_issued: true,
        sql_authenticated: true,
        sql_ok: true,
        ..Default::default()
    };
    assert_eq!(
        classify_revocation_iam(&[login.clone(), control.clone()], "app", 100),
        (GcpAccess::Denied, Some(GcpPermission::InstanceLogin))
    );
    control.principal_id = "app".into();
    assert_eq!(
        classify_revocation_iam(&[login, control], "app", 100),
        (GcpAccess::Allowed, None)
    );
}

#[test]
fn production_cli_scope_cannot_complete_direct_closure_or_revocation() {
    use veil_db_guard::gcp::model::*;
    let change = prepared();
    let principals = change
        .policy
        .subjects
        .iter()
        .map(|s| GcpPrincipal {
            id: s.id.clone(),
            service_account: s.identity.principal.clone(),
        })
        .collect::<Vec<_>>();
    let mut observations = principals
        .iter()
        .map(|p| GcpObservation {
            case_id: format!("{}-connector", p.id),
            attempt_id: "local-synthetic-attempt".into(),
            principal_id: p.id.clone(),
            route: GcpRoute::Proxy,
            started_at: 100,
            finished_at: 100,
            execution: GcpExecution::Completed,
            observed: GcpAccess::Allowed,
            proof: GcpProof {
                sql_authenticated: true,
                sql_ok: true,
                credential_issued: true,
                db_user: Some(p.db_user()),
                database: Some(change.policy.targets[0].engine.database.clone()),
                ..Default::default()
            },
        })
        .collect::<Vec<_>>();
    let mut direct = observations[0].clone();
    direct.route = GcpRoute::Direct;
    direct.observed = GcpAccess::Denied;
    direct.proof = GcpProof {
        credential_issued: true,
        network_rejection_explicit: true,
        ..Default::default()
    };
    observations.push(direct);
    let coverage = classify_cli_connection_evidence(
        &observations,
        &principals,
        &change.policy.targets[0].engine.database,
        change.policy.targets[0]
            .resource
            .generation_fingerprint
            .clone()
            .unwrap(),
        100,
        vec!["d".repeat(64), "e".repeat(64)],
    );
    assert_eq!(coverage.connector_principals.len(), principals.len());
    assert!(coverage.direct_denied_principals.is_empty());
    let closure = step(&change, ActionKind::ConstrainDirectPath);
    let mut executor = executor(&change);
    executor.provider.evidence = Some(coverage.clone());
    let receipt = executor.submit(&change, closure, &ticket(closure)).unwrap();
    let record = record(closure, receipt);
    executor.provider.operation.done = true;
    let pending = executor.query(&change, closure, &record).unwrap();
    assert_eq!(pending.state, StepState::ConfigApplied);
    assert_eq!(pending.effect, EffectState::Pending);
    for evidence_ref in &coverage.evidence_refs {
        assert!(pending.evidence_refs.contains(evidence_ref));
    }
    assert_eq!(executor.provider.writes.len(), 1);

    let revoke = deny_prepared();
    let observe = step(&revoke, ActionKind::ObserveRevocation);
    let mut evidence = revocation_evidence(&revoke);
    // An independently observed IAM denial cannot fill the missing direct
    // workload-source proof produced by the current production CLI collector.
    evidence.direct_denied_principals = coverage.direct_denied_principals;
    evidence.evidence_refs = coverage.evidence_refs;
    executor.provider.revocation = Some(evidence);
    let pending = executor.submit(&revoke, observe, &ticket(observe)).unwrap();
    assert_eq!(pending.state, StepState::ConfigApplied);
    assert_eq!(pending.effect, EffectState::Pending);
    assert_eq!(executor.provider.writes.len(), 1);
}
