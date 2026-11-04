//! Protection policy and change-control kernel. No credentials or network operations.
pub mod admission;
pub mod approval;
pub mod aws_runtime_cutover;
pub mod capability;
pub mod change;
pub mod deferred_route;
pub mod evidence;
pub mod k11_handoff;
pub mod lifecycle;
pub mod observation;
pub mod operation;
pub mod orchestrator;
pub mod plan;
pub mod policy;
pub mod ports;
pub mod postgres_login;
pub mod runtime_binding;
pub mod runtime_cutover;
pub mod source;
pub mod source_execution;
pub mod state;
pub mod state_v2;

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
