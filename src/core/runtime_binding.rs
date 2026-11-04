//! K11-A process/socket samples, not PostgreSQL session or pool attestation.
//!
//! Pure validation establishes shape and correlation with trusted caller inputs.
//! Source authentication, capture freshness and archive admission remain the
//! existing K10 verifier's responsibility. Equality of two samples does not
//! establish continuity between them or independently confirm a database target.
use super::{
    admission::{IssuedObservation, validate_issued},
    evidence::{ConnectionTuple, EffectAddress, EffectKindV2, FixedObservationCase, RequestedCase},
    policy::{EngineFamily, valid_hash, valid_id},
    state::StateValue,
};
use serde::{Deserialize, Serialize};

pub const MAX_RUNTIME_CAPTURE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeBindingError {
    #[error("RUNTIME_BINDING_INVALID: invalid process/socket capture")]
    Invalid,
    #[error("RUNTIME_BINDING_LIMIT: runtime capture exceeds the local limit")]
    Limit,
    #[error("RUNTIME_BINDING_SCOPE_MISMATCH: capture differs from its pinned selection")]
    ScopeMismatch,
    #[error("RUNTIME_BINDING_CHANGED: process/socket samples differ")]
    Changed,
}

/// Must come from the source's pinned collector configuration. Parsing this
/// selector from application JSON does not authorize observing that process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProcessSelector {
    pub pid: u32,
    pub expected_boot_id: String,
    pub expected_start_ticks: u64,
    pub expected_executable_digest: String,
}
impl RuntimeProcessSelector {
    pub fn validate(&self) -> Result<(), RuntimeBindingError> {
        if self.pid == 0
            || self.pid > i32::MAX as u32
            || self.expected_start_ticks == 0
            || !valid_boot_id(&self.expected_boot_id)
            || !valid_hash(&self.expected_executable_digest)
        {
            return Err(RuntimeBindingError::Invalid);
        }
        Ok(())
    }
}

/// Target/source address is request-bound intent, not independently observed
/// PostgreSQL identity. The request digest also binds nonce, expiry and recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCaptureContext {
    pub request_digest: String,
    pub case_id: String,
    pub policy_revision_hash: String,
    pub change_hash: String,
    pub operation_id: String,
    pub source_snapshot_digest: String,
    pub source_trust_epoch: u64,
    pub collector_build_id: String,
    pub address: EffectAddress,
}
impl RuntimeCaptureContext {
    pub fn from_issued(
        issued: &IssuedObservation,
        case: &RequestedCase,
    ) -> Result<Self, RuntimeBindingError> {
        Self::for_case(issued, case)
    }

    pub fn for_case(
        issued: &IssuedObservation,
        case: &RequestedCase,
    ) -> Result<Self, RuntimeBindingError> {
        validate_issued(issued).map_err(|_| RuntimeBindingError::Invalid)?;
        if case.kind != FixedObservationCase::RuntimeBinding
            || case.purpose != super::source::SourcePurpose::Application
            || !issued.request.cases.contains(case)
        {
            return Err(RuntimeBindingError::ScopeMismatch);
        }
        let request = &issued.request;
        let context = Self {
            request_digest: request.digest().map_err(|_| RuntimeBindingError::Invalid)?,
            case_id: case.id.clone(),
            policy_revision_hash: request.policy_revision_hash.clone(),
            change_hash: request.change_hash.clone(),
            operation_id: request.operation_id.clone(),
            source_snapshot_digest: issued
                .snapshot
                .revision_digest()
                .map_err(|_| RuntimeBindingError::Invalid)?,
            source_trust_epoch: request.source_trust_epoch,
            collector_build_id: request.collector_build_id.clone(),
            address: case.address.clone(),
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), RuntimeBindingError> {
        if !valid_id(&self.case_id)
            || !valid_id(&self.operation_id)
            || self.source_trust_epoch == 0
            || self.source_snapshot_digest != self.address.source.revision_digest
            || [
                &self.request_digest,
                &self.policy_revision_hash,
                &self.change_hash,
                &self.source_snapshot_digest,
                &self.collector_build_id,
            ]
            .iter()
            .any(|s| !valid_hash(s))
            || !super::evidence::valid_address(&self.address)
            || self.address.effect != EffectKindV2::RuntimeBinding
            || self.address.target.engine_binding.family != EngineFamily::PostgreSql
        {
            return Err(RuntimeBindingError::Invalid);
        }
        Ok(())
    }
}

/// Selected kernel facts. `security_digest` covers the observer's fixed status
/// selection (all UID/GID slots, groups, capabilities, no-new-privileges,
/// seccomp) and attr/current; it does not model every Linux permission path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxProcessSocketSnapshot {
    pub boot_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub executable_digest: String,
    pub uid: u32,
    pub effective_uid: u32,
    pub gid: u32,
    pub effective_gid: u32,
    pub net_namespace: u64,
    pub mount_namespace: u64,
    pub user_namespace: u64,
    pub cgroup_digest: String,
    pub security_digest: String,
    pub fd: u32,
    pub socket_inode: u64,
    /// Linux /proc TCP state; only 1 (ESTABLISHED) is supported in K11-A.
    pub tcp_state: u8,
    pub connection: ConnectionTuple,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRuntimeCaptureWire {
    pub schema_version: u32,
    pub context: RuntimeCaptureContext,
    pub before: LinuxProcessSocketSnapshot,
    pub after: LinuxProcessSocketSnapshot,
}
impl LinuxRuntimeCaptureWire {
    pub fn parse_untrusted(bytes: &[u8]) -> Result<Self, RuntimeBindingError> {
        if bytes.len() > MAX_RUNTIME_CAPTURE_BYTES {
            return Err(RuntimeBindingError::Limit);
        }
        serde_json::from_slice(bytes).map_err(|_| RuntimeBindingError::Invalid)
    }
}

/// Shape/correlation validated samples only; neither authenticated nor admitted
/// current facts. No Deserialize or public field constructor exists.
///
/// ```compile_fail
/// use veil_db_guard::core::runtime_binding::ValidatedProcessSocketCapture;
/// let _: ValidatedProcessSocketCapture = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedProcessSocketCapture {
    capture: LinuxRuntimeCaptureWire,
    native_session: StateValue,
    pool_generation: StateValue,
    credential_linkage: StateValue,
    runtime_binding: StateValue,
}
impl ValidatedProcessSocketCapture {
    pub fn capture(&self) -> &LinuxRuntimeCaptureWire {
        &self.capture
    }
    pub fn runtime_binding(&self) -> StateValue {
        self.runtime_binding
    }
    pub fn native_session(&self) -> StateValue {
        self.native_session
    }
    pub fn pool_generation(&self) -> StateValue {
        self.pool_generation
    }
    pub fn credential_linkage(&self) -> StateValue {
        self.credential_linkage
    }
}

/// Callers supply the independently pinned configuration and issued context.
/// Never use `wire.context` itself as the trusted expected context.
pub fn validate_runtime_capture(
    wire: &LinuxRuntimeCaptureWire,
    expected_context: &RuntimeCaptureContext,
    selector: &RuntimeProcessSelector,
    expected_connection: &ConnectionTuple,
) -> Result<ValidatedProcessSocketCapture, RuntimeBindingError> {
    selector.validate()?;
    expected_context.validate()?;
    wire.context.validate()?;
    if wire.schema_version != 1 {
        return Err(RuntimeBindingError::Invalid);
    }
    if wire.context != *expected_context {
        return Err(RuntimeBindingError::ScopeMismatch);
    }
    for sample in [&wire.before, &wire.after] {
        if !valid_boot_id(&sample.boot_id)
            || !valid_hash(&sample.executable_digest)
            || !valid_hash(&sample.cgroup_digest)
            || !valid_hash(&sample.security_digest)
            || sample.net_namespace == 0
            || sample.mount_namespace == 0
            || sample.user_namespace == 0
            || sample.socket_inode == 0
            || sample.fd > i32::MAX as u32
            || sample.tcp_state != 1
            || !valid_connection(&sample.connection)
        {
            return Err(RuntimeBindingError::Invalid);
        }
        if sample.pid != selector.pid
            || sample.boot_id != selector.expected_boot_id
            || sample.start_ticks != selector.expected_start_ticks
            || sample.executable_digest != selector.expected_executable_digest
            || sample.connection != *expected_connection
        {
            return Err(RuntimeBindingError::ScopeMismatch);
        }
    }
    if wire.before != wire.after {
        return Err(RuntimeBindingError::Changed);
    }
    Ok(ValidatedProcessSocketCapture {
        capture: wire.clone(),
        native_session: StateValue::Unknown,
        pool_generation: StateValue::Unknown,
        credential_linkage: StateValue::Unknown,
        runtime_binding: StateValue::Unknown,
    })
}

fn valid_boot_id(value: &str) -> bool {
    value != "00000000-0000-0000-0000-000000000000"
        && value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

fn valid_connection(connection: &ConnectionTuple) -> bool {
    !connection.endpoint.is_empty()
        && connection.endpoint.len() <= 253
        && connection
            .endpoint
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b))
        && connection.local_port != 0
        && connection.peer_port != 0
        && !connection.local_ip.is_unspecified()
        && !connection.peer_ip.is_unspecified()
        && !connection.local_ip.is_multicast()
        && !connection.peer_ip.is_multicast()
        && connection.local_ip.is_ipv4() == connection.peer_ip.is_ipv4()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        policy::{GenerationAssurance, RouteKind, TargetHandle, parse_policy},
        state::StateRoute,
    };

    fn valid_capture() -> (LinuxRuntimeCaptureWire, RuntimeProcessSelector) {
        let mut policy = parse_policy(include_str!("../../examples/core-policy-v2.yaml")).unwrap();
        policy.targets[0].resource.generation_fingerprint = Some("d".repeat(64));
        let target = &policy.targets[0];
        let address = EffectAddress {
            target_id: target.id.clone(),
            target: TargetHandle {
                registration_id: target.registration_id.clone(),
                native_ref: target.resource.clone(),
                placement: target.placement.clone(),
                engine_binding: target.engine.clone(),
                generation_assurance: GenerationAssurance::Unconfirmed,
            },
            grant_id: policy.grants[0].id.clone(),
            subject_id: "billing-app".into(),
            db_identity: policy.grants[0].db_identity.clone(),
            source: policy.source_bindings[0].snapshot_ref(),
            route: StateRoute {
                id: "app-connector".into(),
                kind: RouteKind::NativeConnector,
            },
            effect: EffectKindV2::RuntimeBinding,
        };
        let context = RuntimeCaptureContext {
            request_digest: "1".repeat(64),
            case_id: "runtime-1".into(),
            policy_revision_hash: "2".repeat(64),
            change_hash: "3".repeat(64),
            operation_id: "operation-1".into(),
            source_snapshot_digest: address.source.revision_digest.clone(),
            source_trust_epoch: 1,
            collector_build_id: "4".repeat(64),
            address,
        };
        let sample = LinuxProcessSocketSnapshot {
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            pid: 51,
            start_ticks: 820,
            executable_digest: "5".repeat(64),
            uid: 1000,
            effective_uid: 1000,
            gid: 1000,
            effective_gid: 1000,
            net_namespace: 10,
            mount_namespace: 11,
            user_namespace: 12,
            cgroup_digest: "6".repeat(64),
            security_digest: "7".repeat(64),
            fd: 7,
            socket_inode: 813,
            tcp_state: 1,
            connection: ConnectionTuple {
                endpoint: "db.example".into(),
                local_ip: "10.0.0.1".parse().unwrap(),
                local_port: 50001,
                peer_ip: "10.0.0.2".parse().unwrap(),
                peer_port: 5432,
            },
        };
        let selector = RuntimeProcessSelector {
            pid: sample.pid,
            expected_boot_id: sample.boot_id.clone(),
            expected_start_ticks: sample.start_ticks,
            expected_executable_digest: sample.executable_digest.clone(),
        };
        (
            LinuxRuntimeCaptureWire {
                schema_version: 1,
                context,
                before: sample.clone(),
                after: sample,
            },
            selector,
        )
    }

    fn validate(
        wire: &LinuxRuntimeCaptureWire,
        selector: &RuntimeProcessSelector,
    ) -> Result<ValidatedProcessSocketCapture, RuntimeBindingError> {
        validate_runtime_capture(wire, &wire.context, selector, &wire.before.connection)
    }

    #[test]
    fn correlated_samples_leave_application_links_unknown() {
        let (wire, selector) = valid_capture();
        let result = validate(&wire, &selector).unwrap();
        assert_eq!(result.capture(), &wire);
        assert_eq!(result.runtime_binding(), StateValue::Unknown);
        assert_eq!(result.native_session(), StateValue::Unknown);
        assert_eq!(result.pool_generation(), StateValue::Unknown);
        assert_eq!(result.credential_linkage(), StateValue::Unknown);
        assert_eq!(
            result.capture.context.address.target.generation_assurance,
            GenerationAssurance::Unconfirmed
        );
    }

    #[test]
    fn pid_reuse_boot_or_executable_changes_fail_against_pinned_selector() {
        let (wire, selector) = valid_capture();
        for change in 0..4 {
            let mut changed = wire.clone();
            for snapshot in [&mut changed.before, &mut changed.after] {
                match change {
                    0 => snapshot.pid += 1,
                    1 => snapshot.start_ticks += 1,
                    2 => snapshot.boot_id = "11234567-89ab-cdef-0123-456789abcdef".into(),
                    _ => snapshot.executable_digest = "8".repeat(64),
                }
            }
            assert_eq!(
                validate(&changed, &selector),
                Err(RuntimeBindingError::ScopeMismatch)
            );
        }
    }

    #[test]
    fn identity_namespace_security_or_socket_changes_between_samples_fail() {
        let (wire, selector) = valid_capture();
        for change in 0..12 {
            let mut changed = wire.clone();
            match change {
                0 => changed.after.uid += 1,
                1 => changed.after.effective_uid += 1,
                2 => changed.after.gid += 1,
                3 => changed.after.effective_gid += 1,
                4 => changed.after.net_namespace += 1,
                5 => changed.after.mount_namespace += 1,
                6 => changed.after.user_namespace += 1,
                7 => changed.after.cgroup_digest = "8".repeat(64),
                8 => changed.after.security_digest = "8".repeat(64),
                9 => changed.after.socket_inode += 1,
                10 => changed.after.fd += 1,
                _ => changed.after.connection.local_port += 1,
            }
            assert!(matches!(
                validate(&changed, &selector),
                Err(RuntimeBindingError::Changed | RuntimeBindingError::ScopeMismatch)
            ));
        }
    }

    #[test]
    fn full_issued_context_must_match_not_only_process_and_tuple() {
        let (wire, selector) = valid_capture();
        for change in 0..12 {
            let mut changed = wire.clone();
            let c = &mut changed.context;
            match change {
                0 => c.request_digest = "9".repeat(64),
                1 => c.case_id = "other-case".into(),
                2 => c.policy_revision_hash = "9".repeat(64),
                3 => c.change_hash = "9".repeat(64),
                4 => c.operation_id = "other-operation".into(),
                5 => {
                    c.source_snapshot_digest = "9".repeat(64);
                    c.address.source.revision_digest = c.source_snapshot_digest.clone();
                }
                6 => c.source_trust_epoch += 1,
                7 => c.collector_build_id = "9".repeat(64),
                8 => c.address.subject_id = "other-subject".into(),
                9 => c.address.target.native_ref.generation_fingerprint = Some("9".repeat(64)),
                10 => c.address.db_identity = "other-db-user".into(),
                _ => c.address.route.id = "other-route".into(),
            }
            assert_eq!(
                validate_runtime_capture(
                    &changed,
                    &wire.context,
                    &selector,
                    &wire.before.connection
                ),
                Err(RuntimeBindingError::ScopeMismatch)
            );
        }
    }

    #[test]
    fn absent_or_invalid_kernel_facts_and_non_established_sockets_fail() {
        let (wire, selector) = valid_capture();
        for change in 0..8 {
            let mut changed = wire.clone();
            match change {
                0 => changed.before.socket_inode = 0,
                1 => changed.before.net_namespace = 0,
                2 => changed.before.tcp_state = 10,
                3 => changed.before.security_digest = "x".repeat(64),
                4 => changed.before.connection.peer_port = 0,
                5 => changed.before.connection.local_ip = "0.0.0.0".parse().unwrap(),
                6 => changed.before.boot_id = "00000000-0000-0000-0000-000000000000".into(),
                _ => changed.before.fd = u32::MAX,
            }
            assert_eq!(
                validate(&changed, &selector),
                Err(RuntimeBindingError::Invalid)
            );
        }
    }

    #[test]
    fn other_effects_or_source_context_cannot_be_runtime_capture() {
        let (wire, selector) = valid_capture();
        let mut changed = wire.clone();
        changed.context.address.effect = EffectKindV2::NewConnections;
        assert_eq!(
            validate(&changed, &selector),
            Err(RuntimeBindingError::Invalid)
        );
        let mut changed = wire;
        changed.context.source_snapshot_digest = "9".repeat(64);
        assert_eq!(
            validate(&changed, &selector),
            Err(RuntimeBindingError::Invalid)
        );
    }

    #[test]
    fn wire_is_bounded_and_rejects_operator_verdict_fields() {
        let (wire, selector) = valid_capture();
        let bytes = serde_json::to_vec(&wire).unwrap();
        let parsed = LinuxRuntimeCaptureWire::parse_untrusted(&bytes).unwrap();
        validate(&parsed, &selector).unwrap();
        let mut json = serde_json::to_value(&wire).unwrap();
        json["runtime_binding_verified"] = serde_json::json!(true);
        assert_eq!(
            LinuxRuntimeCaptureWire::parse_untrusted(&serde_json::to_vec(&json).unwrap()),
            Err(RuntimeBindingError::Invalid)
        );
        assert_eq!(
            LinuxRuntimeCaptureWire::parse_untrusted(&vec![b' '; MAX_RUNTIME_CAPTURE_BYTES + 1]),
            Err(RuntimeBindingError::Limit)
        );
    }
}
