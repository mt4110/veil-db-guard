//! Secret-free operation ledger contracts. Native acceptance and effect differ.
use serde::{Deserialize, Serialize};

/// An opaque non-secret principal reference, distinct from short local IDs.
/// Provider adapters authenticate and interpret the reference at dispatch.
pub fn valid_execution_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/@".contains(&byte))
        && !value.contains("..")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("LEDGER_STORAGE: local ledger access failed")]
    Storage,
    #[error("LEDGER_INVALID: invalid or incompatible ledger input")]
    Invalid,
    #[error("LEDGER_NOT_FOUND: requested record does not exist")]
    NotFound,
    #[error("LEDGER_CONFLICT: immutable input or desired revision conflicts")]
    Conflict,
    #[error("LEDGER_STALE: operation version or worker fence is stale")]
    Stale,
    #[error("LEDGER_APPROVAL: approval scope, identity or validity does not permit dispatch")]
    Approval,
    #[error("LEDGER_LEASE: required local resource leases are unavailable")]
    Lease,
    #[error("LEDGER_UNRESOLVED: prior native result must be resolved before dispatch")]
    Unresolved,
    #[error("LEDGER_LIMIT: operation budget is exhausted")]
    Limit,
    #[error("LEDGER_TRANSITION: operation transition is not permitted")]
    Transition,
}

macro_rules! choice {
    ($name:ident {$($variant:ident),+ $(,)?}) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all="snake_case")]
        pub enum $name {$($variant),+}
    };
}
choice!(ExecutionState {
    Prepared,
    Running,
    WaitingProvider,
    WaitingEffect,
    NeedsAction,
    Recovering,
    Completed,
    FailedPartial,
    Cancelled
});
choice!(StepState {
    Prepared,
    Dispatching,
    Submitted,
    ConfigApplied,
    EffectSatisfied,
    OutcomeUnknown,
    NotApplied,
    Failed,
    Compensating,
    Compensated,
    NoOpSatisfied
});
choice!(EffectState {
    Unknown,
    Pending,
    Enforced,
    NotSatisfied
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub request_id: String,
    pub input_hash: String,
    pub change_hash: String,
    pub approval_id: String,
    pub policy_id: String,
    pub policy_revision_hash: String,
    pub execution_identity: String,
    pub version: u64,
    pub state: ExecutionState,
    pub attempts: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    pub request_id: String,
    pub operation_id: String,
    pub change_hash: String,
    pub approval_id: String,
    pub expected_desired_head: Option<String>,
    pub execution_identity: String,
    pub now: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepReceipt {
    pub state: StepState,
    pub effect: EffectState,
    pub native_operation_ref: Option<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepRecord {
    pub step_id: String,
    pub state: StepState,
    pub attempt: u32,
    pub idempotency_key: String,
    pub receipt: Option<StepReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSet {
    pub holder: String,
    pub token: u64,
    pub keys: Vec<String>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchTicket {
    pub operation_id: String,
    pub step_id: String,
    pub attempt: u32,
    pub operation_version: u64,
    pub idempotency_key: String,
    pub leases: LeaseSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEvent {
    pub sequence: u64,
    pub operation_id: String,
    pub event: EventKind,
    pub step_id: Option<String>,
    pub at: u64,
}
choice!(EventKind {
    Begun,
    Dispatched,
    ReceiptRecorded,
    Resolved,
    StateChanged,
    ApprovalCancelled
});
