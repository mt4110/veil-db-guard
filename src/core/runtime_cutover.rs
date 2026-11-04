//! K11-C correlation contract for an app checkout through the PostgreSQL connector.
//! This is a verifier result, consumed only inside trusted admission composition.
use super::{
    admission::IssuedObservation,
    evidence::{DEFAULT_FRESHNESS_SECONDS, RequestedCase},
    policy::{PlacementKind, RouteKind, valid_hash},
    runtime_binding::{RuntimeCaptureContext, RuntimeProcessSelector},
    source::{SourceBoundaryKind, SourcePurpose},
};
use serde::{Deserialize, Serialize};

const MAX_CUTOVER_CANDIDATE_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeCutoverError {
    #[error("RUNTIME_CUTOVER_INVALID: invalid or unsupported runtime cutover input")]
    Invalid,
    #[error("RUNTIME_CUTOVER_SCOPE_MISMATCH: runtime observations differ from pinned scope")]
    ScopeMismatch,
    #[error("RUNTIME_CUTOVER_EXPIRED: runtime cutover evidence is outside its validity window")]
    Expired,
    #[error("RUNTIME_CUTOVER_UNAVAILABLE: independent runtime observations are unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProcessIdentity {
    pub pid: u32,
    pub boot_id: String,
    pub start_ticks: u64,
    pub executable_digest: String,
}

impl RuntimeProcessIdentity {
    fn matches(&self, pinned: &RuntimeProcessSelector) -> bool {
        self.pid == pinned.pid
            && self.boot_id == pinned.expected_boot_id
            && self.start_ticks == pinned.expected_start_ticks
            && self.executable_digest == pinned.expected_executable_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresSessionIdentity {
    pub database: String,
    pub session_user: String,
    pub backend_pid: u32,
    /// Unix epoch microseconds; fixes time-zone and textual formatting ambiguity.
    pub backend_started_at_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSessionLink {
    pub process: RuntimeProcessIdentity,
    pub socket_fd: u32,
    pub socket_inode: u64,
    pub session: PostgresSessionIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolSwitchLink {
    pub previous_generation: u64,
    pub active_generation: u64,
    pub checkout_sequence: u64,
    pub switched_at: u64,
    pub checked_out_at: u64,
}

/// A receipt emitted by the app. It selects what needs corroboration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCutoverCandidate {
    pub context: RuntimeCaptureContext,
    pub bundle_digest: String,
    pub app: AppSessionLink,
    pub switch: PoolSwitchLink,
}

impl RuntimeCutoverCandidate {
    pub fn parse_untrusted(bytes: &[u8]) -> Result<Self, RuntimeCutoverError> {
        if bytes.len() > MAX_CUTOVER_CANDIDATE_BYTES {
            return Err(RuntimeCutoverError::Invalid);
        }
        serde_json::from_slice(bytes).map_err(|_| RuntimeCutoverError::Invalid)
    }
}

/// Construct from the pinned collector configuration and prepared bundle.
/// The credential digest identifies a non-secret authorization binding record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCutoverSelection {
    pub bundle_digest: String,
    pub previous_generation: u64,
    pub active_generation: u64,
    pub application: RuntimeProcessSelector,
    pub connector: RuntimeProcessSelector,
    pub cloud_iam_principal: String,
    pub credential_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCutoverIntent {
    context: RuntimeCaptureContext,
    selection: RuntimeCutoverSelection,
    not_before: u64,
    issued_at: u64,
    expires_at: u64,
}

impl RuntimeCutoverIntent {
    pub fn for_case(
        issued: &IssuedObservation,
        case: &RequestedCase,
        selection: RuntimeCutoverSelection,
        not_before: u64,
    ) -> Result<Self, RuntimeCutoverError> {
        let context = RuntimeCaptureContext::for_case(issued, case)
            .map_err(|_| RuntimeCutoverError::Invalid)?;
        if case.purpose != SourcePurpose::Application
            || context.address.route.kind != RouteKind::NativeConnector
            || context.address.source.boundary != SourceBoundaryKind::GceHostNetwork
            || context.address.target.placement.kind != PlacementKind::GcpCloudSql
            || !valid_hash(&selection.bundle_digest)
            || !valid_hash(&selection.credential_binding_digest)
            || selection.previous_generation == 0
            || selection.active_generation <= selection.previous_generation
            || selection.application.validate().is_err()
            || selection.connector.validate().is_err()
            || selection.application.pid == selection.connector.pid
            || selection.application.expected_boot_id != selection.connector.expected_boot_id
            || issued.snapshot.gce().is_none_or(|gce| {
                gce.native_identity.service_account != selection.cloud_iam_principal
                    || gce
                        .gce_host
                        .as_ref()
                        .is_none_or(|host| host.execution_uid != 0)
            })
            || not_before == 0
            || not_before >= issued.request.expires_at
        {
            return Err(RuntimeCutoverError::Invalid);
        }
        Ok(Self {
            context,
            selection,
            not_before,
            issued_at: issued.request.issued_at,
            expires_at: issued.request.expires_at,
        })
    }

    pub fn context(&self) -> &RuntimeCaptureContext {
        &self.context
    }

    pub fn selection(&self) -> &RuntimeCutoverSelection {
        &self.selection
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixProcessEndpoint {
    pub process: RuntimeProcessIdentity,
    pub effective_uid: u32,
    pub socket_fd: u32,
    pub socket_inode: u64,
    pub socket_cookie: u64,
}

/// Reciprocal AF_UNIX peers checked by a pinned kernel observer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeUnixPeerObservation {
    pub application: UnixProcessEndpoint,
    pub connector: UnixProcessEndpoint,
}

/// The independent connector/backend observer binds the exact connector socket
/// to PostgreSQL identity, native IAM and the authenticated TLS peer instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePostgresSessionObservation {
    pub connector: UnixProcessEndpoint,
    pub session: PostgresSessionIdentity,
    pub current_user: String,
    pub tls_peer_native_id: String,
    pub tls_peer_target_generation: String,
    pub tls_peer_certificate_digest: String,
    pub native_iam_principal: String,
    pub credential_binding_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePoolUseObservation {
    pub application: UnixProcessEndpoint,
    pub bundle_digest: String,
    pub switch: PoolSwitchLink,
}

/// Canonical artifact digests for three independently obtained measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeCutoverEvidenceRefs {
    pub kernel_peer: String,
    pub postgres_session: String,
    pub pool_checkout: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeCutoverObservations {
    pub context: RuntimeCaptureContext,
    pub kernel_observed_at: u64,
    pub postgres_observed_at: u64,
    pub pool_observed_at: u64,
    pub valid_until: u64,
    pub kernel: NativeUnixPeerObservation,
    pub postgres: NativePostgresSessionObservation,
    pub pool: NativePoolUseObservation,
    pub evidence_refs: RuntimeCutoverEvidenceRefs,
}

impl NativeCutoverObservations {
    pub fn latest_observed_at(&self) -> u64 {
        self.kernel_observed_at
            .max(self.postgres_observed_at)
            .max(self.pool_observed_at)
    }
}

/// Trusted composition port. Implementations authenticate and bind each native
/// measurement to the request, and never interpret app JSON as a measurement.
/// The candidate is deliberately unavailable to the producer through this API.
pub trait RuntimeCutoverVerifier {
    fn observe(
        &mut self,
        intent: &RuntimeCutoverIntent,
    ) -> Result<NativeCutoverObservations, RuntimeCutoverError>;
}

/// A verifier result, with request-scoped validity. Admission and the execution
/// gate must still establish current registry, archive and independent recovery.
///
/// ```compile_fail
/// use veil_db_guard::core::runtime_cutover::CorroboratedRuntimeCutover;
/// let _: CorroboratedRuntimeCutover = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorroboratedRuntimeCutover {
    candidate: RuntimeCutoverCandidate,
    native: NativeCutoverObservations,
}

impl CorroboratedRuntimeCutover {
    pub fn candidate(&self) -> &RuntimeCutoverCandidate {
        &self.candidate
    }

    pub fn observations(&self) -> &NativeCutoverObservations {
        &self.native
    }
}

pub fn verify_runtime_cutover(
    intent: &RuntimeCutoverIntent,
    candidate: &RuntimeCutoverCandidate,
    verifier: &mut impl RuntimeCutoverVerifier,
    now: u64,
) -> Result<CorroboratedRuntimeCutover, RuntimeCutoverError> {
    let s = &intent.selection;
    let checkout = &candidate.switch;
    let app = &candidate.app;
    let address = &intent.context.address;
    let backend_started_at = app.session.backend_started_at_micros / 1_000_000;
    if candidate.context != intent.context
        || candidate.bundle_digest != s.bundle_digest
        || checkout.previous_generation != s.previous_generation
        || checkout.active_generation != s.active_generation
        || !app.process.matches(&s.application)
        || app.session.database != address.target.engine_binding.database
        || app.session.session_user != address.db_identity
    {
        return Err(RuntimeCutoverError::ScopeMismatch);
    }
    if checkout.checkout_sequence == 0
        || app.socket_fd > i32::MAX as u32
        || app.socket_inode == 0
        || app.session.backend_pid == 0
        || app.session.backend_pid > i32::MAX as u32
    {
        return Err(RuntimeCutoverError::Invalid);
    }
    if now >= intent.expires_at
        || checkout.switched_at <= intent.not_before
        || checkout.checked_out_at < intent.issued_at
        || checkout.checked_out_at < checkout.switched_at
        || checkout.checked_out_at > now
        || backend_started_at <= intent.not_before
        || backend_started_at > checkout.checked_out_at
        || now.saturating_sub(checkout.checked_out_at) >= DEFAULT_FRESHNESS_SECONDS
    {
        return Err(RuntimeCutoverError::Expired);
    }
    let native = verifier.observe(intent)?;
    let unix = &native.kernel;
    let pg = &native.postgres;
    let pool = &native.pool;
    if native.context != intent.context
        || unix.application.process != app.process
        || unix.application.socket_fd != app.socket_fd
        || unix.application.socket_inode != app.socket_inode
        || !unix.connector.process.matches(&s.connector)
        || pg.connector != unix.connector
        || pg.session != app.session
        || pg.current_user != address.db_identity
        || pg.tls_peer_native_id != address.target.native_ref.native_id
        || address.target.native_ref.generation_fingerprint.as_ref()
            != Some(&pg.tls_peer_target_generation)
        || pg.native_iam_principal != s.cloud_iam_principal
        || pg.credential_binding_digest != s.credential_binding_digest
        || pool.application != unix.application
        || pool.bundle_digest != s.bundle_digest
        || pool.switch != *checkout
    {
        return Err(RuntimeCutoverError::ScopeMismatch);
    }
    let refs = [
        &native.evidence_refs.kernel_peer,
        &native.evidence_refs.postgres_session,
        &native.evidence_refs.pool_checkout,
    ];
    if unix.connector.socket_fd > i32::MAX as u32
        || unix.connector.socket_inode == 0
        || unix.connector.socket_inode == unix.application.socket_inode
        || unix.connector.socket_cookie == 0
        || unix.application.socket_cookie == 0
        || unix.connector.socket_cookie == unix.application.socket_cookie
        || !valid_hash(&pg.tls_peer_certificate_digest)
        || refs.iter().any(|digest| !valid_hash(digest))
        || refs[0] == refs[1]
        || refs[0] == refs[2]
        || refs[1] == refs[2]
    {
        return Err(RuntimeCutoverError::Invalid);
    }
    if [
        native.kernel_observed_at,
        native.postgres_observed_at,
        native.pool_observed_at,
    ]
    .into_iter()
    .any(|sampled_at| sampled_at < checkout.checked_out_at || sampled_at > now)
        || native.valid_until <= now
        || native.valid_until > intent.expires_at
        || native.valid_until
            > checkout
                .checked_out_at
                .saturating_add(DEFAULT_FRESHNESS_SECONDS)
    {
        return Err(RuntimeCutoverError::Expired);
    }
    Ok(CorroboratedRuntimeCutover {
        candidate: candidate.clone(),
        native,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::{
        evidence::{
            AddressFamily, EffectKindV2, EvaluationContract, FixedObservationCase,
            ObservationRequest,
        },
        source::{GceHostProfile, GceVmIdentity, SourceCredentialKind, SourceRegistrationSnapshot},
        source_execution::tests::change,
        state_v2::desired_for_change_v2,
    };

    struct SyntheticVerifier(Option<NativeCutoverObservations>);
    impl RuntimeCutoverVerifier for SyntheticVerifier {
        fn observe(
            &mut self,
            _: &RuntimeCutoverIntent,
        ) -> Result<NativeCutoverObservations, RuntimeCutoverError> {
            self.0.take().ok_or(RuntimeCutoverError::Unavailable)
        }
    }

    pub(crate) fn fixture() -> (
        RuntimeCutoverIntent,
        RuntimeCutoverCandidate,
        NativeCutoverObservations,
    ) {
        let change = change();
        let mut address = desired_for_change_v2(&change.policy, None, &[], 130)
            .unwrap()
            .into_iter()
            .find(|row| row.address.effect == EffectKindV2::RuntimeBinding)
            .unwrap()
            .address;
        let principal = "billing-app@vdg-example-000000.iam.gserviceaccount.com".to_owned();
        let snapshot = SourceRegistrationSnapshot {
            schema_version: 2,
            registration_id: address.source.registration_id.clone(),
            trust_epoch: 1,
            native_identity: GceVmIdentity {
                project_id: "vdg-example-000000".into(),
                project_number: "1234567890".into(),
                zone: "asia-northeast1-a".into(),
                instance_id: "9876543210".into(),
                created_at_unix: 1,
                service_account: principal.clone(),
                service_account_id: "123456789012345678901".into(),
            },
            ssh_host_key_digest: "a".repeat(64),
            collector_build_id: "e".repeat(64),
            collector_config_digest: "b".repeat(64),
            network_context_digest: "c".repeat(64),
            execution_user: "collector".into(),
            credential_kind: SourceCredentialKind::GceMetadata,
            credential_reference: "billing-workload".into(),
            gce_host: Some(GceHostProfile {
                ssh_ip: "10.0.0.1".parse().unwrap(),
                ssh_port: 22,
                host_key_ed25519_base64: "dGVzdA==".into(),
                collector_binary_digest: "d".repeat(64),
                execution_uid: 0,
            }),
        };
        let mut source = change.policy.source_bindings[0].clone();
        source.revision_digest = snapshot.revision_digest().unwrap();
        address.source = source.snapshot_ref();
        let case = RequestedCase {
            backend_tls_trust: None,
            login_catalog_targets: vec![],
            mysql_account_host: None,
            id: "app-cutover".into(),
            kind: FixedObservationCase::RuntimeBinding,
            address: address.clone(),
            purpose: SourcePurpose::Application,
            endpoint: "db.example.invalid".into(),
            port: 5432,
            address_family: AddressFamily::Ipv4,
        };
        let issued = IssuedObservation {
            request: ObservationRequest {
                schema_version: 1,
                request_id: "runtime-cutover-1".into(),
                nonce: "1".repeat(64),
                policy_revision_hash: change.plan.policy_revision_hash,
                change_hash: change.change_hash,
                operation_id: "operation-1".into(),
                source,
                source_trust_epoch: snapshot.trust_epoch,
                evaluation_contract: EvaluationContract::SourceBoundV2,
                collector_build_id: snapshot.collector_build_id.clone(),
                verifier_build_id: "2".repeat(64),
                issued_at: 110,
                expires_at: 160,
                cases: vec![case.clone()],
            },
            snapshot: snapshot.into(),
        };
        let endpoint = |pid, inode, cookie, digest: &str| UnixProcessEndpoint {
            process: RuntimeProcessIdentity {
                pid,
                boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
                start_ticks: 820,
                executable_digest: digest.repeat(64),
            },
            effective_uid: 1000,
            socket_fd: 7,
            socket_inode: inode,
            socket_cookie: cookie,
        };
        let application = endpoint(51, 813, 1, "5");
        let connector = endpoint(52, 814, 2, "6");
        let selector = |endpoint: &UnixProcessEndpoint| RuntimeProcessSelector {
            pid: endpoint.process.pid,
            expected_boot_id: endpoint.process.boot_id.clone(),
            expected_start_ticks: endpoint.process.start_ticks,
            expected_executable_digest: endpoint.process.executable_digest.clone(),
        };
        let selection = RuntimeCutoverSelection {
            bundle_digest: "a".repeat(64),
            previous_generation: 4,
            active_generation: 5,
            application: selector(&application),
            connector: selector(&connector),
            cloud_iam_principal: principal,
            credential_binding_digest: "b".repeat(64),
        };
        let intent =
            RuntimeCutoverIntent::for_case(&issued, &case, selection.clone(), 101).unwrap();
        let session = PostgresSessionIdentity {
            database: address.target.engine_binding.database,
            session_user: address.db_identity,
            backend_pid: 7,
            backend_started_at_micros: 113_500_000,
        };
        let switch = PoolSwitchLink {
            previous_generation: 4,
            active_generation: 5,
            checkout_sequence: 8,
            switched_at: 114,
            checked_out_at: 115,
        };
        let candidate = RuntimeCutoverCandidate {
            context: intent.context.clone(),
            bundle_digest: selection.bundle_digest.clone(),
            app: AppSessionLink {
                process: application.process.clone(),
                socket_fd: application.socket_fd,
                socket_inode: application.socket_inode,
                session: session.clone(),
            },
            switch: switch.clone(),
        };
        let native = NativeCutoverObservations {
            context: intent.context.clone(),
            kernel_observed_at: 116,
            postgres_observed_at: 116,
            pool_observed_at: 116,
            valid_until: 160,
            kernel: NativeUnixPeerObservation {
                application: application.clone(),
                connector: connector.clone(),
            },
            postgres: NativePostgresSessionObservation {
                connector,
                session,
                current_user: candidate.app.session.session_user.clone(),
                tls_peer_native_id: address.target.native_ref.native_id,
                tls_peer_target_generation: address
                    .target
                    .native_ref
                    .generation_fingerprint
                    .unwrap(),
                tls_peer_certificate_digest: "9".repeat(64),
                native_iam_principal: selection.cloud_iam_principal,
                credential_binding_digest: selection.credential_binding_digest,
            },
            pool: NativePoolUseObservation {
                application,
                bundle_digest: selection.bundle_digest,
                switch,
            },
            evidence_refs: RuntimeCutoverEvidenceRefs {
                kernel_peer: "c".repeat(64),
                postgres_session: "d".repeat(64),
                pool_checkout: "e".repeat(64),
            },
        };
        (intent, candidate, native)
    }

    #[test]
    fn runtime_cutover_requires_independent_observations_and_retains_exact_checkout() {
        let (intent, candidate, native) = fixture();
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let parsed = RuntimeCutoverCandidate::parse_untrusted(&bytes).unwrap();
        assert_eq!(
            verify_runtime_cutover(&intent, &parsed, &mut SyntheticVerifier(None), 120),
            Err(RuntimeCutoverError::Unavailable)
        );
        let verified = verify_runtime_cutover(
            &intent,
            &parsed,
            &mut SyntheticVerifier(Some(native.clone())),
            120,
        )
        .unwrap();
        assert_eq!(verified.candidate(), &candidate);
        assert_eq!(verified.observations(), &native);
        let mut wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        wire["applied"] = serde_json::Value::Bool(true);
        assert_eq!(
            RuntimeCutoverCandidate::parse_untrusted(&serde_json::to_vec(&wire).unwrap()),
            Err(RuntimeCutoverError::Invalid)
        );
    }

    #[test]
    fn runtime_cutover_rejects_cross_socket_backend_target_credential_and_pool_splicing() {
        let (intent, candidate, native) = fixture();
        for change in 0..10 {
            let mut changed = native.clone();
            match change {
                0 => changed.context.request_digest = "0".repeat(64),
                1 => changed.kernel.application.process.start_ticks += 1,
                2 => changed.kernel.connector.process.executable_digest = "0".repeat(64),
                3 => changed.postgres.connector.socket_cookie += 1,
                4 => changed.postgres.session.backend_started_at_micros += 1,
                5 => changed.postgres.tls_peer_target_generation = "0".repeat(64),
                6 => changed.postgres.native_iam_principal = "foreign-principal".into(),
                7 => changed.postgres.credential_binding_digest = "0".repeat(64),
                8 => changed.pool.switch.checkout_sequence += 1,
                _ => changed.pool.switch.active_generation -= 1,
            }
            assert_eq!(
                verify_runtime_cutover(
                    &intent,
                    &candidate,
                    &mut SyntheticVerifier(Some(changed)),
                    120
                ),
                Err(RuntimeCutoverError::ScopeMismatch)
            );
        }
        let mut duplicated = native;
        duplicated.evidence_refs.pool_checkout = duplicated.evidence_refs.kernel_peer.clone();
        assert_eq!(
            verify_runtime_cutover(
                &intent,
                &candidate,
                &mut SyntheticVerifier(Some(duplicated)),
                120
            ),
            Err(RuntimeCutoverError::Invalid)
        );
    }

    #[test]
    fn runtime_cutover_expires_and_rejects_checkout_or_backend_from_before_cutover_floor() {
        let (intent, candidate, native) = fixture();
        assert_eq!(
            verify_runtime_cutover(
                &intent,
                &candidate,
                &mut SyntheticVerifier(Some(native.clone())),
                160
            ),
            Err(RuntimeCutoverError::Expired)
        );
        let mut premature = candidate.clone();
        premature.switch.switched_at = intent.not_before();
        assert_eq!(
            verify_runtime_cutover(&intent, &premature, &mut SyntheticVerifier(None), 120),
            Err(RuntimeCutoverError::Expired)
        );
        let mut stale = candidate.clone();
        stale.app.session.backend_started_at_micros = 101_999_999;
        assert_eq!(
            verify_runtime_cutover(&intent, &stale, &mut SyntheticVerifier(None), 120),
            Err(RuntimeCutoverError::Expired)
        );
        let mut native_too_old = native;
        native_too_old.postgres_observed_at = candidate.switch.checked_out_at - 1;
        assert_eq!(
            verify_runtime_cutover(
                &intent,
                &candidate,
                &mut SyntheticVerifier(Some(native_too_old)),
                120
            ),
            Err(RuntimeCutoverError::Expired)
        );
    }
}
