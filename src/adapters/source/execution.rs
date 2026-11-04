//! Native composition's local, read-only source gate. Each check reloads exact
//! original admissions and current source heads. No native refresh or verdict import.
use crate::{
    adapters::evidence::RunEvidenceArchive,
    core::{
        admission::{AdmissionError, load_admitted},
        change::PreparedChange,
        operation::EventKind,
        orchestrator::ExecutorError,
        plan::PlanStep,
        ports::EvidenceLedger,
        source_execution::*,
    },
    evidence_store::EvidenceStore,
    operation_store::OperationStore,
};
use std::path::PathBuf;

pub struct LocalSourceGate {
    ledger: PathBuf,
    archive: PathBuf,
    operation: String,
    requests: Vec<String>,
}
impl LocalSourceGate {
    /// Construction performs no IO and creates no authority/receipt.
    pub fn new(
        ledger: PathBuf,
        archive: PathBuf,
        operation: String,
        requests: Vec<String>,
    ) -> Self {
        Self {
            ledger,
            archive,
            operation,
            requests,
        }
    }
}
fn unavailable<T>(_: T) -> ExecutorError {
    ExecutorError::PreconditionsNotMet
}
impl SourceStepGate for LocalSourceGate {
    fn validate_sources(&mut self, change: &PreparedChange) -> Result<(), ExecutorError> {
        use crate::core::{
            policy::{CredentialSourceKind, IdentityProvider},
            source::RegisteredSourceSnapshot,
        };
        change.verify().map_err(unavailable)?;
        let mut ledger = EvidenceStore::open_existing(&self.ledger).map_err(unavailable)?;
        for binding in &change.policy.source_bindings {
            let snapshot = ledger
                .source_snapshot(&binding.registration_id)
                .map_err(unavailable)?;
            if !snapshot.matches_binding(binding).map_err(unavailable)? {
                return Err(ExecutorError::PreconditionsNotMet);
            }
            let (provider, principal, immutable, reference) = match &snapshot {
                RegisteredSourceSnapshot::Gce(s) => {
                    super::gce_host::validate_registration(&snapshot).map_err(unavailable)?;
                    (
                        IdentityProvider::Gcp,
                        s.native_identity.service_account.as_str(),
                        s.native_identity.service_account_id.as_str(),
                        s.credential_reference.as_str(),
                    )
                }
                RegisteredSourceSnapshot::Aws(s) => {
                    super::aws_host::validate_registration(s).map_err(unavailable)?;
                    let cred = s
                        .metadata_credential
                        .as_ref()
                        .ok_or(ExecutorError::Unavailable)?;
                    (
                        IdentityProvider::Aws,
                        cred.role_arn.as_str(),
                        cred.role_id.as_str(),
                        cred.credential_reference.as_str(),
                    )
                }
            };
            for usage in &binding.allowed_uses {
                let subject = change
                    .policy
                    .subjects
                    .iter()
                    .find(|s| s.id == usage.subject_id)
                    .ok_or(ExecutorError::PreconditionsNotMet)?;
                if subject.identity.provider != provider
                    || subject.identity.principal != principal
                    || subject.identity.immutable_id.as_deref() != Some(immutable)
                    || subject.identity.credential_source.kind
                        != CredentialSourceKind::WorkloadIdentity
                    || subject.identity.credential_source.reference != reference
                {
                    return Err(ExecutorError::Unavailable);
                }
            }
        }
        Ok(())
    }
    fn check(
        &mut self,
        change: &PreparedChange,
        step: &PlanStep,
        phase: SourceStepPhase,
    ) -> Result<SourceStepCheck, ExecutorError> {
        let operations = OperationStore::open_existing(&self.ledger).map_err(unavailable)?;
        let operation = operations.get(&self.operation).map_err(unavailable)?;
        if operation.change_hash != change.change_hash {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let phase = match phase {
            SourceStepPhase::AfterConfiguration { not_before } => {
                // A read-only observation session cannot substitute for the
                // real operation's durable dispatch event. Never backdate from
                // a remote timestamp or reconstruct a ticket after a crash.
                let dispatched = operations
                    .events(&self.operation)
                    .map_err(unavailable)?
                    .into_iter()
                    .filter(|e| {
                        e.event == EventKind::Dispatched
                            && e.step_id.as_deref() == Some(step.id.as_str())
                    })
                    .map(|e| e.at)
                    .max()
                    .ok_or(ExecutorError::PreconditionsNotMet)?;
                SourceStepPhase::AfterConfiguration {
                    not_before: not_before.max(dispatched),
                }
            }
            p => p,
        };
        let mut ledger = EvidenceStore::open_existing(&self.ledger).map_err(unavailable)?;
        let archive = RunEvidenceArchive::open(&self.archive).map_err(unavailable)?;
        let ids = if self.requests.is_empty() {
            ledger.request_ids(&self.operation).map_err(unavailable)?
        } else {
            self.requests.clone()
        };
        if ids.len() > 32768
            || ids.iter().collect::<std::collections::BTreeSet<_>>().len() != ids.len()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let started = std::time::Instant::now();
        let mut facts = vec![];
        let mut issued = vec![];
        for id in ids {
            if started.elapsed() > std::time::Duration::from_secs(5) {
                return Err(ExecutorError::PreconditionsNotMet);
            }
            let i = ledger.issued(&id).map_err(unavailable)?;
            if i.request.operation_id != self.operation
                || i.request.change_hash != change.change_hash
            {
                return Err(ExecutorError::PreconditionsNotMet);
            }
            match load_admitted(&mut ledger, &archive, &id, crate::domain::now()) {
                Ok(f) => {
                    facts.push(f);
                    issued.push(i);
                }
                Err(
                    AdmissionError::NotFound
                    | AdmissionError::Expired
                    | AdmissionError::TrustChanged,
                ) => {}
                Err(e) => return Err(unavailable(e)),
            }
        }
        if started.elapsed() > std::time::Duration::from_secs(5) {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let now = crate::domain::now();
        // Close the multi-archive read window. A head revoked while reading a
        // later archive makes the whole check fail rather than reuse a cache.
        for i in &issued {
            ledger.ensure_current(i, now).map_err(unavailable)?;
        }
        check_source_step(change, step, phase, now, facts)
    }
}
