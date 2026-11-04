//! Infrastructure contracts required by the change-control kernel.
use super::{admission::*, evidence::ObservationBundleWire};
use super::{change::PreparedChange, operation::*};

/// Local trusted storage, not portable attestation. admit must atomically bind
/// one issued nonce to one digest, rechecking source trust and original expiry.
pub trait EvidenceLedger {
    fn issued(&mut self, request_id: &str) -> Result<IssuedObservation, AdmissionError>;
    fn ensure_current(
        &mut self,
        issued: &IssuedObservation,
        now: u64,
    ) -> Result<(), AdmissionError>;
    fn admit(
        &mut self,
        candidate: &VerifiedCandidate,
        now: u64,
    ) -> Result<EvidenceAdmission, AdmissionError>;
    fn admission(&mut self, request_id: &str) -> Result<EvidenceAdmission, AdmissionError>;
}

/// Production composition must verify channel/native source/context with
/// ephemeral credentials. A JSON verdict cannot implement this Rust port.
pub trait ObservationVerifier {
    fn verify(
        &mut self,
        issued: &IssuedObservation,
        bundle: &ObservationBundleWire,
        payloads: &[EvidencePayload],
        window: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError>;

    /// Available only from the verifier that performed independent runtime
    /// corroboration for this capture. A wire claim cannot fill this port.
    fn runtime_cutover(
        &self,
        _case_id: &str,
    ) -> Option<&super::runtime_cutover::CorroboratedRuntimeCutover> {
        None
    }

    /// Verified by the registered AWS pool and database measurement producers.
    fn aws_runtime_cutover(
        &self,
        _case_id: &str,
    ) -> Option<&super::aws_runtime_cutover::CorroboratedAwsPostgresCutover> {
        None
    }
}

pub trait EvidenceClock {
    fn now(&self) -> u64;
}

pub trait EvidenceArchive {
    /// Return only after all exact bytes and the final manifest are durable.
    fn persist(
        &mut self,
        issued: &IssuedObservation,
        bundle: &[u8],
        payloads: &[EvidencePayload],
    ) -> Result<EvidenceArchiveRef, AdmissionError>;
    /// No native calls. Check every saved file against the admitted manifest.
    fn read(
        &self,
        issued: &IssuedObservation,
        archive: &EvidenceArchiveRef,
    ) -> Result<(Vec<u8>, Vec<EvidencePayload>), AdmissionError>;
}

/// Durable operation ledger used by the orchestrator.
///
/// Implementations must atomically enforce operation version comparisons,
/// approval scope, lease fencing and dispatch/receipt transitions. A dispatch
/// ticket is returned only after the attempt is durable. No ledger transaction
/// may remain open when one of these calls returns: provider calls occur between
/// calls, and an ambiguous provider result must remain available for query rather
/// than being made eligible for dispatch again.
///
/// Registration, approval issuance and begin are intentionally outside this port:
/// they belong to the application flow that prepares an operation for resume.
pub trait OperationLedger {
    fn get(&self, id: &str) -> Result<Operation, StoreError>;
    fn load_change(&self, hash: &str) -> Result<PreparedChange, StoreError>;
    fn steps(&self, id: &str) -> Result<Vec<StepRecord>, StoreError>;
    fn acquire_leases(
        &mut self,
        operation_id: &str,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError>;
    fn renew_leases(
        &mut self,
        lease: &LeaseSet,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError>;
    fn release_leases(&mut self, lease: &LeaseSet) -> Result<(), StoreError>;
    fn dispatch(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        identity: &str,
        now: u64,
    ) -> Result<DispatchTicket, StoreError>;
    fn record_receipt(
        &mut self,
        ticket: &DispatchTicket,
        receipt: &StepReceipt,
        now: u64,
    ) -> Result<Operation, StoreError>;
    #[allow(clippy::too_many_arguments)]
    fn resolve(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        receipt: &StepReceipt,
        identity: &str,
        now: u64,
    ) -> Result<Operation, StoreError>;
    fn set_state(
        &mut self,
        id: &str,
        expected_version: u64,
        state: ExecutionState,
        now: u64,
    ) -> Result<Operation, StoreError>;
}
