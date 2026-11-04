//! Composition of the native deployment, SQL and operator-handoff adapters.
use super::{
    deployment::gcp::{CloudSqlProvider, GcpExecutor},
    engine::postgres::{PgTransport, PostgresStepExecutor},
};
use crate::{
    binding::{BindingStepExecutor, CheckpointGate},
    core::{
        capability::ActionKind,
        change::PreparedChange,
        operation::{DispatchTicket, StepReceipt, StepRecord},
        orchestrator::{ExecutorError, StepExecutor},
        plan::PlanStep,
    },
};

pub struct GcpProtectionExecutor<P, G, T> {
    pub cloud: GcpExecutor<P, G>,
    pub postgres: PostgresStepExecutor<T>,
    pub binding: BindingStepExecutor,
    /// Mandatory for every v2 native composition. Cannot be supplied by JSON.
    pub source: Option<Box<dyn crate::core::source_execution::SourceStepGate>>,
    /// A failed current source read may still reconcile accepted work, but
    /// cannot continue forward even if reconciliation finishes this pass.
    pub query_only: bool,
}
fn sql(step: &PlanStep) -> bool {
    matches!(
        step.action,
        ActionKind::ConfigureSqlPrivileges
            | ActionKind::DisableNewConnections
            | ActionKind::RevokeSqlPrivileges
    )
}
fn handoff(step: &PlanStep) -> bool {
    matches!(
        step.action,
        ActionKind::PublishBinding
            | ActionKind::ConfirmRecoveryReadiness
            | ActionKind::AwaitApplicationCutover
    )
}
fn source_guarded(step: &PlanStep) -> bool {
    matches!(
        step.action,
        ActionKind::ObserveAccess
            | ActionKind::ConfirmRecoveryReadiness
            | ActionKind::ConstrainDirectPath
            | ActionKind::DisableNativeIdentity
            | ActionKind::CompensateOwnedIam
            | ActionKind::DisableNewConnections
            | ActionKind::RevokeSqlPrivileges
            | ActionKind::ObserveRevocation
    )
}
fn source_finished(step: &PlanStep) -> bool {
    matches!(
        step.action,
        ActionKind::ConstrainDirectPath
            | ActionKind::DisableNewConnections
            | ActionKind::ObserveRevocation
    )
}
impl<P: CloudSqlProvider, G: CheckpointGate, T: PgTransport> GcpProtectionExecutor<P, G, T> {
    fn source_precondition(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<(), ExecutorError> {
        if c.policy.schema_version != 2 {
            return Ok(());
        }
        let gate = self.source.as_mut().ok_or(ExecutorError::Unavailable)?;
        gate.validate_sources(c)?;
        if source_guarded(s)
            && !gate
                .check(
                    c,
                    s,
                    crate::core::source_execution::SourceStepPhase::BeforeDispatch,
                )?
                .satisfied()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(())
    }
    fn finish_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        mut receipt: StepReceipt,
    ) -> Result<StepReceipt, ExecutorError> {
        use crate::core::{
            operation::{EffectState, StepState},
            source_execution::SourceStepPhase,
        };
        if c.policy.schema_version != 2
            || !source_finished(s)
            || !matches!(
                receipt.state,
                StepState::EffectSatisfied | StepState::NoOpSatisfied | StepState::ConfigApplied
            )
        {
            return Ok(receipt);
        }
        // Configuration/SQL commit may be confirmed while effective access is
        // still unknown. This is not a license to resend the accepted action.
        let checked = match self.source.as_mut() {
            Some(gate) => gate.check(c, s, SourceStepPhase::AfterConfiguration { not_before: 0 }),
            None => Err(ExecutorError::Unavailable),
        };
        receipt.state = StepState::ConfigApplied;
        receipt.effect = EffectState::Unknown;
        if let Ok(proof) = checked
            && proof.satisfied()
        {
            receipt.state = StepState::EffectSatisfied;
            receipt.effect = EffectState::Enforced;
            receipt
                .evidence_refs
                .extend(proof.evidence_refs().iter().cloned());
            receipt.evidence_refs.sort();
            receipt.evidence_refs.dedup();
        }
        Ok(receipt)
    }
    fn recovery_receipt(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<StepReceipt, ExecutorError> {
        let proof = self
            .source
            .as_mut()
            .ok_or(ExecutorError::Unavailable)?
            .check(
                c,
                s,
                crate::core::source_execution::SourceStepPhase::BeforeDispatch,
            )?;
        if !proof.satisfied() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(StepReceipt {
            state: crate::core::operation::StepState::EffectSatisfied,
            effect: crate::core::operation::EffectState::Enforced,
            native_operation_ref: None,
            evidence_refs: proof.evidence_refs().to_vec(),
        })
    }
}
impl<P: CloudSqlProvider, G: CheckpointGate, T: PgTransport> StepExecutor
    for GcpProtectionExecutor<P, G, T>
{
    fn identity(&self) -> &str {
        self.cloud.identity()
    }
    fn cancelled(&self) -> bool {
        self.cloud.cancelled()
    }
    fn lease_duration_seconds(&self) -> u64 {
        self.cloud.lease_duration_seconds()
    }
    fn available(&self, c: &PreparedChange, s: &PlanStep) -> bool {
        !self.query_only
            && super::qualification::qualify_change(c).is_ok_and(|r| r.is_dispatch_qualified())
            && self.postgres.identity() == self.identity()
            && self.binding.identity() == self.identity()
            && (c.policy.schema_version != 2 || self.source.is_some())
            && if sql(s) {
                if c.policy.schema_version == 2 {
                    self.postgres.source_available(c, s)
                } else {
                    self.postgres.available(c, s)
                }
            } else if handoff(s) {
                self.binding.available(c, s)
            } else {
                self.cloud.available(c, s)
            }
    }
    fn preflight(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        if !self.available(c, s) {
            return Err(ExecutorError::Unavailable);
        }
        self.source_precondition(c, s)?;
        if sql(s) || handoff(s) {
            self.cloud.revalidate_target(c, s)?;
        }
        self.binding.now = self.cloud.provider.now();
        if sql(s) {
            self.binding
                .checkpoints
                .validate_change_window(c, &s.target_id, self.binding.now)
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        }
        if c.policy.schema_version == 2 && s.action == ActionKind::ConfirmRecoveryReadiness {
            self.recovery_receipt(c, s).map(|_| ())
        } else if sql(s) {
            self.postgres.with_source_contract(|e| e.preflight(c, s))
        } else if handoff(s) {
            self.binding.with_source_contract(|e| e.preflight(c, s))
        } else {
            self.cloud.with_source_contract(|e| e.preflight(c, s))
        }
    }
    fn submit(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        t: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        if s.action == ActionKind::CompensateOwnedIam {
            return Err(ExecutorError::Unavailable);
        }
        if !self.available(c, s) || self.cancelled() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        // Repeat, after preflight and durable dispatch, before ANY provider/SQL
        // call. Stale/changed evidence cannot be reused from an earlier check.
        self.source_precondition(c, s)
            .map_err(|_| ExecutorError::NotApplied)?;
        if sql(s) || handoff(s) {
            self.cloud.revalidate_target(c, s)?;
        }
        self.binding.now = self.cloud.provider.now();
        if sql(s) {
            self.binding
                .checkpoints
                .validate_change_window(c, &s.target_id, self.binding.now)
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
        }
        let receipt =
            if c.policy.schema_version == 2 && s.action == ActionKind::ConfirmRecoveryReadiness {
                self.recovery_receipt(c, s)
            } else if sql(s) && c.policy.schema_version == 2 {
                self.postgres.submit_source(
                    c,
                    s,
                    self.source
                        .as_mut()
                        .ok_or(ExecutorError::Unavailable)?
                        .as_mut(),
                    &self.binding.checkpoints,
                )
            } else if sql(s) {
                self.postgres.submit(c, s, t)
            } else if handoff(s) {
                self.binding.with_source_contract(|e| e.submit(c, s, t))
            } else {
                if c.policy.schema_version == 2 {
                    self.cloud.submit_source(
                        c,
                        s,
                        t,
                        self.source
                            .as_mut()
                            .ok_or(ExecutorError::Unavailable)?
                            .as_mut(),
                        &mut || Ok(()),
                    )
                } else {
                    self.cloud.submit(c, s, t)
                }
            }?;
        self.finish_source(c, s, receipt)
    }
    fn submit_with_dispatch_check(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        t: &DispatchTicket,
        check: &mut dyn FnMut() -> Result<(), ExecutorError>,
    ) -> Result<StepReceipt, ExecutorError> {
        if s.action != ActionKind::CompensateOwnedIam {
            return self.submit(c, s, t);
        }
        if !self.available(c, s) || self.cancelled() {
            return Err(ExecutorError::NotApplied);
        }
        self.source_precondition(c, s)
            .map_err(|_| ExecutorError::NotApplied)?;
        self.cloud.submit_source(
            c,
            s,
            t,
            self.source
                .as_mut()
                .ok_or(ExecutorError::Unavailable)?
                .as_mut(),
            check,
        )
    }
    fn take_gcp_iam_owned_delta(&mut self) -> Option<crate::core::owned_iam::OwnedIamDeltaReceipt> {
        self.cloud.take_gcp_iam_owned_delta()
    }
    fn query(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        if self.postgres.identity() != self.identity() || self.binding.identity() != self.identity()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        // Reconciliation remains read-only even if current qualification or
        // source evidence is missing. Never gate it on a new forward approval.
        if sql(s) || handoff(s) {
            self.cloud.revalidate_target(c, s)?;
        }
        self.binding.now = self.cloud.provider.now();
        let receipt =
            if c.policy.schema_version == 2 && s.action == ActionKind::ConfirmRecoveryReadiness {
                self.recovery_receipt(c, s)
            } else if sql(s) {
                self.postgres.with_source_contract(|e| e.query(c, s, r))
            } else if handoff(s) {
                self.binding.with_source_contract(|e| e.query(c, s, r))
            } else {
                self.cloud.query(c, s, r)
            }?;
        self.finish_source(c, s, receipt)
    }
}

/// SQL engine port for the source-aware composition. Bare StepExecutor
/// dispatch remains unavailable for v3; implementations enter private scopes.
pub trait SourceEngineExecutor: StepExecutor {
    fn source_available(&self, c: &PreparedChange, s: &PlanStep) -> bool;
    fn preflight_source(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError>;
    fn submit_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
        checkpoints: &crate::binding::ManualCheckpoints,
    ) -> Result<StepReceipt, ExecutorError>;
    fn query_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError>;
}
impl<T: PgTransport> SourceEngineExecutor for PostgresStepExecutor<T> {
    fn source_available(&self, c: &PreparedChange, s: &PlanStep) -> bool {
        self.source_available(c, s)
    }
    fn preflight_source(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        self.with_source_contract(|e| e.preflight(c, s))
    }
    fn submit_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
        checkpoints: &crate::binding::ManualCheckpoints,
    ) -> Result<StepReceipt, ExecutorError> {
        self.submit_source(c, s, gate, checkpoints)
    }
    fn query_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        self.with_source_contract(|e| e.query(c, s, r))
    }
}
impl<T: super::engine::mysql::MysqlTransport> SourceEngineExecutor
    for super::engine::mysql::MysqlStepExecutor<T>
{
    fn source_available(&self, c: &PreparedChange, s: &PlanStep) -> bool {
        self.source_available(c, s)
    }
    fn preflight_source(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        self.with_source_contract(|e| e.preflight(c, s))
    }
    fn submit_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
        checkpoints: &crate::binding::ManualCheckpoints,
    ) -> Result<StepReceipt, ExecutorError> {
        self.submit_source(c, s, gate, checkpoints)
    }
    fn query_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        self.with_source_contract(|e| e.query(c, s, r))
    }
}
impl<T: SourceEngineExecutor + ?Sized> SourceEngineExecutor for Box<T> {
    fn source_available(&self, c: &PreparedChange, s: &PlanStep) -> bool {
        (**self).source_available(c, s)
    }
    fn preflight_source(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        (**self).preflight_source(c, s)
    }
    fn submit_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
        checkpoints: &crate::binding::ManualCheckpoints,
    ) -> Result<StepReceipt, ExecutorError> {
        (**self).submit_source(c, s, gate, checkpoints)
    }
    fn query_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        (**self).query_source(c, s, r)
    }
}

pub struct AwsProtectionExecutor<P, G, E> {
    pub cloud: super::deployment::aws::AwsExecutor<P, G>,
    pub engine: E,
    pub binding: BindingStepExecutor,
    pub source: Option<Box<dyn crate::core::source_execution::SourceStepGate>>,
    /// A broken/missing archive permits accepted query work only in this pass.
    pub query_only: bool,
}
impl<P: super::deployment::aws::AwsProvider, G: CheckpointGate, E: SourceEngineExecutor>
    AwsProtectionExecutor<P, G, E>
{
    fn source_precondition(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<(), ExecutorError> {
        if c.policy.schema_version != 2 {
            return Ok(());
        }
        let gate = self.source.as_mut().ok_or(ExecutorError::Unavailable)?;
        gate.validate_sources(c)?;
        if source_guarded(s)
            && !gate
                .check(
                    c,
                    s,
                    crate::core::source_execution::SourceStepPhase::BeforeDispatch,
                )?
                .satisfied()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(())
    }
    fn finish_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        mut receipt: StepReceipt,
    ) -> Result<StepReceipt, ExecutorError> {
        use crate::core::{
            operation::{EffectState, StepState},
            source_execution::SourceStepPhase,
        };
        if c.policy.schema_version != 2
            || !source_finished(s)
            || !matches!(
                receipt.state,
                StepState::EffectSatisfied | StepState::NoOpSatisfied | StepState::ConfigApplied
            )
        {
            return Ok(receipt);
        }
        // Configuration/SQL commit may be confirmed while effective access is
        // still unknown. This is not a license to resend the accepted action.
        let checked = match self.source.as_mut() {
            Some(gate) => gate.check(c, s, SourceStepPhase::AfterConfiguration { not_before: 0 }),
            None => Err(ExecutorError::Unavailable),
        };
        receipt.state = StepState::ConfigApplied;
        receipt.effect = EffectState::Unknown;
        if let Ok(proof) = checked
            && proof.satisfied()
        {
            receipt.state = StepState::EffectSatisfied;
            receipt.effect = EffectState::Enforced;
            receipt
                .evidence_refs
                .extend(proof.evidence_refs().iter().cloned());
            receipt.evidence_refs.sort();
            receipt.evidence_refs.dedup();
        }
        Ok(receipt)
    }
    fn recovery_receipt(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<StepReceipt, ExecutorError> {
        let proof = self
            .source
            .as_mut()
            .ok_or(ExecutorError::Unavailable)?
            .check(
                c,
                s,
                crate::core::source_execution::SourceStepPhase::BeforeDispatch,
            )?;
        if !proof.satisfied() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(StepReceipt {
            state: crate::core::operation::StepState::EffectSatisfied,
            effect: crate::core::operation::EffectState::Enforced,
            native_operation_ref: None,
            evidence_refs: proof.evidence_refs().to_vec(),
        })
    }
}
impl<P: super::deployment::aws::AwsProvider, G: CheckpointGate, E: SourceEngineExecutor>
    StepExecutor for AwsProtectionExecutor<P, G, E>
{
    fn identity(&self) -> &str {
        self.cloud.identity()
    }
    fn cancelled(&self) -> bool {
        self.cloud.cancelled()
    }
    fn lease_duration_seconds(&self) -> u64 {
        self.cloud.lease_duration_seconds()
    }
    fn available(&self, c: &PreparedChange, s: &PlanStep) -> bool {
        !self.query_only
            && super::qualification::qualify_change(c).is_ok_and(|r| r.is_dispatch_qualified())
            && self.engine.identity() == self.identity()
            && self.binding.identity() == self.identity()
            && (c.policy.schema_version != 2
                || (self.source.is_some() && self.cloud.source_available()))
            && if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity {
                if c.policy.schema_version == 2 {
                    self.engine.source_available(c, s)
                } else {
                    self.engine.available(c, s)
                }
            } else if handoff(s) {
                self.binding.available(c, s)
            } else {
                self.cloud.available(c, s)
            }
    }
    fn preflight(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        if !self.available(c, s) {
            return Err(ExecutorError::Unavailable);
        }
        self.source_precondition(c, s)?;
        if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity || handoff(s) {
            self.cloud.revalidate_target(c, s)?;
        }
        self.binding.now = self.cloud.provider.now();
        if c.policy.schema_version == 2 && s.action == ActionKind::ConfirmRecoveryReadiness {
            self.recovery_receipt(c, s).map(|_| ())
        } else if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity {
            self.binding
                .checkpoints
                .validate_change_window(c, &s.target_id, self.binding.now)
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
            if c.policy.schema_version == 2 {
                self.engine.preflight_source(c, s)
            } else {
                self.engine.preflight(c, s)
            }
        } else if handoff(s) {
            self.binding.with_source_contract(|e| e.preflight(c, s))
        } else if c.policy.schema_version == 2 {
            self.cloud.preflight_source(c, s)
        } else {
            self.cloud.preflight(c, s)
        }
    }
    fn submit(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        t: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        if !self.available(c, s) || self.cancelled() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        self.source_precondition(c, s)
            .map_err(|_| ExecutorError::NotApplied)?;
        if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity || handoff(s) {
            self.cloud.revalidate_target(c, s)?;
        }
        self.binding.now = self.cloud.provider.now();
        let receipt =
            if c.policy.schema_version == 2 && s.action == ActionKind::ConfirmRecoveryReadiness {
                self.recovery_receipt(c, s)
            } else if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity {
                self.binding
                    .checkpoints
                    .validate_change_window(c, &s.target_id, self.binding.now)
                    .map_err(|_| ExecutorError::NotApplied)?;
                if c.policy.schema_version == 2 {
                    self.engine.submit_source(
                        c,
                        s,
                        self.source
                            .as_mut()
                            .ok_or(ExecutorError::Unavailable)?
                            .as_mut(),
                        &self.binding.checkpoints,
                    )
                } else {
                    self.engine.submit(c, s, t)
                }
            } else if handoff(s) {
                self.binding.with_source_contract(|e| e.submit(c, s, t))
            } else if c.policy.schema_version == 2 {
                self.cloud.submit_source(
                    c,
                    s,
                    t,
                    self.source
                        .as_mut()
                        .ok_or(ExecutorError::Unavailable)?
                        .as_mut(),
                )
            } else {
                self.cloud.submit(c, s, t)
            }?;
        self.finish_source(c, s, receipt)
    }
    fn query(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        if self.engine.identity() != self.identity() || self.binding.identity() != self.identity() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity || handoff(s) {
            self.cloud.revalidate_target(c, s)?;
        }
        self.binding.now = self.cloud.provider.now();
        let receipt =
            if c.policy.schema_version == 2 && s.action == ActionKind::ConfirmRecoveryReadiness {
                self.recovery_receipt(c, s)
            } else if sql(s) || s.action == ActionKind::RegisterNativeDbIdentity {
                if c.policy.schema_version == 2 {
                    self.engine.query_source(c, s, r)
                } else {
                    self.engine.query(c, s, r)
                }
            } else if handoff(s) {
                self.binding.with_source_contract(|e| e.query(c, s, r))
            } else {
                self.cloud.query(c, s, r)
            }?;
        self.finish_source(c, s, receipt)
    }
}

// Engine choice belongs to the composition root. Box forwards the existing
// port without introducing provider types into the core or duplicating AWS flow.
impl<T: StepExecutor + ?Sized> StepExecutor for Box<T> {
    fn identity(&self) -> &str {
        (**self).identity()
    }
    fn cancelled(&self) -> bool {
        (**self).cancelled()
    }
    fn lease_duration_seconds(&self) -> u64 {
        (**self).lease_duration_seconds()
    }
    fn available(&self, c: &PreparedChange, s: &PlanStep) -> bool {
        (**self).available(c, s)
    }
    fn preflight(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        (**self).preflight(c, s)
    }
    fn submit(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        t: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        (**self).submit(c, s, t)
    }
    fn query(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        (**self).query(c, s, r)
    }
}

#[cfg(test)]
mod source_tests;

#[cfg(test)]
mod aws_source_tests;
