//! GCE host-network source collection. The positive verifier is obtainable only
//! from a pinned SSH capture + Google signature verification, never a wire flag.
use super::{jwt::GoogleSigningKeys, process};
use crate::core::{
    admission::*,
    evidence::*,
    ports::{EvidenceArchive, EvidenceLedger, ObservationVerifier},
    source::*,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

pub const COLLECTOR_PATH: &str = "/usr/local/libexec/veil-db-guard";
pub const COLLECTOR_CONFIG_PATH: &str = "/etc/veil-db-guard/collector-v1.json";
pub(super) const MAX_REPLY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    #[error("SOURCE_PERMISSION_REQUIRED: explicit native read permission is required")]
    PermissionRequired,
    #[error("SOURCE_INVALID: invalid or incompatible source input")]
    Invalid,
    #[error("SOURCE_UNAVAILABLE: registered source or fixed tool is unavailable")]
    Unavailable,
    #[error("SOURCE_UNSUPPORTED: this source profile or platform is not implemented")]
    Unsupported,
    #[error("SOURCE_CONTEXT_UNVERIFIED: source execution context does not match registration")]
    ContextUnverified,
    #[error("SOURCE_IDENTITY_UNVERIFIED: signed native identity could not be confirmed")]
    IdentityUnverified,
    #[error("SOURCE_INTEGRITY_ERROR: pinned source or capture integrity differs")]
    Integrity,
    #[error("SOURCE_LIMIT: source capture input or output exceeds its limit")]
    Limit,
    #[error("SOURCE_TIMED_OUT: source capture deadline elapsed")]
    TimedOut,
    #[error("SOURCE_REQUEST_EXPIRED: original source request has expired")]
    RequestExpired,
    #[error("SOURCE_CANCELLED: source capture was cancelled")]
    Cancelled,
    #[error("SOURCE_ADMISSION_FAILED: {0}")]
    AdmissionFailed(AdmissionError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxHostContext {
    pub uid: u32,
    pub effective_uid: u32,
    pub network_namespace: String,
    pub mount_namespace: String,
    pub user_namespace: String,
    pub boot_id_digest: String,
    pub cgroup_class: String,
    pub route_v4_digest: String,
    pub route_v6_digest: String,
    pub interfaces_digest: String,
    pub rules_v4_digest: String,
    pub rules_v6_digest: String,
}
impl LinuxHostContext {
    pub fn digest(&self) -> Result<String, SourceError> {
        if self.uid != self.effective_uid
            || [
                &self.boot_id_digest,
                &self.route_v4_digest,
                &self.route_v6_digest,
                &self.interfaces_digest,
                &self.rules_v4_digest,
                &self.rules_v6_digest,
            ]
            .iter()
            .any(|s| !crate::core::policy::valid_hash(s))
            || [
                &self.network_namespace,
                &self.mount_namespace,
                &self.user_namespace,
                &self.cgroup_class,
            ]
            .iter()
            .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err(SourceError::Invalid);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| SourceError::Invalid)?;
        Ok(crate::config::hash_bytes(
            &[b"veil-db-guard/gce-host-context/v1\0".as_slice(), &bytes].concat(),
        ))
    }
    pub fn aws_digest(&self) -> Result<String, SourceError> {
        self.digest()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SourceError::Invalid)?;
        Ok(crate::config::hash_bytes(
            &[b"veil-db-guard/aws-host-context/v1\0".as_slice(), &bytes].concat(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorEndpoint {
    pub target_id: String,
    pub native_id: String,
    pub generation_digest: String,
    pub database: String,
    pub endpoint: String,
    pub ip: IpAddr,
    pub port: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorConfig {
    pub schema_version: u32,
    pub registration_id: String,
    pub context: LinuxHostContext,
    pub endpoints: Vec<CollectorEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<super::postgres::PostgresCollectorConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_denial: Option<super::route_denial::GcpRouteDenialConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_origin: Option<super::origin::HostKernelOriginConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<super::runtime::RuntimeCollectorConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_unix: Vec<RuntimeUnixBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeUnixBinding {
    pub target_id: String,
    pub grant_id: String,
    pub subject_id: String,
    pub route_id: String,
    pub selection: super::runtime_unix::RuntimeUnixSelection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witnesses: Option<super::runtime_witness::RuntimeWitnessPolicy>,
}
impl RuntimeUnixBinding {
    pub(super) fn matches(&self, address: &EffectAddress) -> bool {
        self.target_id == address.target_id
            && self.grant_id == address.grant_id
            && self.subject_id == address.subject_id
            && self.route_id == address.route.id
            && address.route.kind == crate::core::policy::RouteKind::NativeConnector
    }
}
impl CollectorConfig {
    pub(super) fn validate_runtime_unix(&self) -> Result<(), SourceError> {
        use crate::core::policy::valid_id;
        let mut seen = std::collections::BTreeSet::new();
        if self.runtime_unix.len() > MAX_CASES_PER_SOURCE {
            return Err(SourceError::Limit);
        }
        for entry in &self.runtime_unix {
            let scope = [
                &entry.target_id,
                &entry.grant_id,
                &entry.subject_id,
                &entry.route_id,
            ];
            if scope.iter().any(|id| !valid_id(id)) || !seen.insert(scope) {
                return Err(SourceError::Invalid);
            }
            entry.selection.validate()?;
            if let Some(witnesses) = &entry.witnesses {
                witnesses.validate()?;
                if entry.selection.app.expected_uid == entry.selection.connector.expected_uid {
                    return Err(SourceError::Invalid);
                }
            }
        }
        Ok(())
    }
    pub fn validate_request(&self, i: &IssuedObservation) -> Result<(), SourceError> {
        validate_issued(i).map_err(|_| SourceError::Invalid)?;
        let profile = i
            .snapshot
            .gce()
            .ok_or(SourceError::Unsupported)?
            .gce_host
            .as_ref()
            .ok_or(SourceError::Unsupported)?;
        if !matches!(
            (self.schema_version, self.postgres.is_some()),
            (1, false) | (2, true)
        ) || self.registration_id != i.snapshot.registration_id()
            || self.context.digest()? != i.snapshot.network_context_digest()
            || self.context.uid != profile.execution_uid
            || self.endpoints.is_empty()
            || self.endpoints.len() > 8
        {
            return Err(SourceError::ContextUnverified);
        }
        if let Some(pg) = &self.postgres {
            pg.validate()?;
        }
        if let Some(runtime) = &self.runtime {
            runtime.validate()?;
        }
        self.validate_runtime_unix()?;
        if self.route_denial.is_some() && self.kernel_origin.is_some() {
            return Err(SourceError::Invalid);
        }
        if let Some(origin) = &self.kernel_origin {
            origin.validate()?;
        }
        if let Some(route) = &self.route_denial {
            route.validate(i)?;
        }
        for c in &i.request.cases {
            if self
                .endpoints
                .iter()
                .filter(|e| {
                    e.target_id == c.address.target_id
                        && e.native_id == c.address.target.native_ref.native_id
                        && c.address
                            .target
                            .native_ref
                            .generation_fingerprint
                            .as_deref()
                            == Some(e.generation_digest.as_str())
                        && e.database == c.address.target.engine_binding.database
                        && e.endpoint == c.endpoint
                        && e.port == c.port
                        && !e.ip.is_unspecified()
                        && !e.ip.is_multicast()
                        && e.ip.is_ipv4() == (c.address_family == AddressFamily::Ipv4)
                })
                .count()
                != 1
            {
                return Err(SourceError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DiagnosticOutcome {
    TcpConnected,
    TcpRefused,
    TcpTimedOut,
    TcpUnavailable,
    UnsupportedCase,
    PostgresObserved,
    MysqlObserved,
    RuntimeObserved,
    RuntimeUnixObserved,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaseDiagnostic {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_capture: Option<crate::core::runtime_binding::LinuxRuntimeCaptureWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_failure: Option<CollectorFailure>,
    pub case_id: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub outcome: DiagnosticOutcome,
    pub connection: Option<ConnectionTuple>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<super::postgres::PgObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iam_inventory: Option<super::iam_inventory::GcpIamObservation>,
}
/// This ephemeral SSH response is never written to an artifact/log. Debug omits
/// the token, and the public capture contains only selected verified identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectorReply {
    pub schema_version: u32,
    pub request_digest: String,
    pub collector_build_id: String,
    pub binary_digest: String,
    pub config_digest: String,
    pub context_before: LinuxHostContext,
    pub context_after: LinuxHostContext,
    pub identity_token: String,
    pub started_at: u64,
    pub finished_at: u64,
    pub diagnostics: Vec<CaseDiagnostic>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_denials: Vec<super::route_denial::GcpRouteObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kernel_probes: Vec<super::origin::HostKernelProbeRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix_probes: Vec<RuntimeUnixRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeUnixRecord {
    pub context: crate::core::runtime_binding::RuntimeCaptureContext,
    pub capture: super::runtime_unix::LinuxUnixSocketCaptureWire,
}
impl std::fmt::Debug for CollectorReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectorReply")
            .field("request_digest", &self.request_digest)
            .field("token", &"[redacted]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CollectorResponse {
    Success {
        reply: Box<CollectorReply>,
    },
    Failure {
        request_digest: String,
        code: CollectorFailure,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CollectorFailure {
    Invalid,
    Unavailable,
    Unsupported,
    ContextUnverified,
    IdentityUnverified,
    Integrity,
    Limit,
    TimedOut,
    RequestExpired,
    Cancelled,
}
impl CollectorFailure {
    pub(super) fn from_error(error: SourceError) -> Self {
        match error {
            SourceError::Invalid
            | SourceError::PermissionRequired
            | SourceError::AdmissionFailed(_) => Self::Invalid,
            SourceError::Unavailable => Self::Unavailable,
            SourceError::Unsupported => Self::Unsupported,
            SourceError::ContextUnverified => Self::ContextUnverified,
            SourceError::IdentityUnverified => Self::IdentityUnverified,
            SourceError::Integrity => Self::Integrity,
            SourceError::Limit => Self::Limit,
            SourceError::TimedOut => Self::TimedOut,
            SourceError::RequestExpired => Self::RequestExpired,
            SourceError::Cancelled => Self::Cancelled,
        }
    }
    pub(super) fn error(self) -> SourceError {
        match self {
            Self::Invalid => SourceError::Invalid,
            Self::Unavailable => SourceError::Unavailable,
            Self::Unsupported => SourceError::Unsupported,
            Self::ContextUnverified => SourceError::ContextUnverified,
            Self::IdentityUnverified => SourceError::IdentityUnverified,
            Self::Integrity => SourceError::Integrity,
            Self::Limit => SourceError::Limit,
            Self::TimedOut => SourceError::TimedOut,
            Self::RequestExpired => SourceError::RequestExpired,
            Self::Cancelled => SourceError::Cancelled,
        }
    }
}
pub struct SshAccess {
    pub identity_file: PathBuf,
    pub work_directory: PathBuf,
}
pub struct GceCapture {
    pub bundle: Vec<u8>,
    pub payloads: Vec<EvidencePayload>,
    pub window: CaptureWindow,
    pub verifier: GceSourceVerifier,
    kernel_probes: Vec<super::origin::VerifiedHostKernelProbe>,
    unix_probes: Vec<RuntimeUnixRecord>,
}
impl GceCapture {
    /// Capture-authenticated observations, requiring normal admission and a
    /// separate application scope binding before use by K11.
    pub fn host_kernel_probes(&self) -> &[super::origin::VerifiedHostKernelProbe] {
        &self.kernel_probes
    }

    /// Join authenticated GCE kernel data with the two registered witness
    /// statements. The pinned config is the authority for keys and scope.
    pub fn corroborate_runtime(
        mut self,
        issued: &IssuedObservation,
        pinned_config: &[u8],
        input: &[u8],
        now: u64,
    ) -> Result<Self, SourceError> {
        use super::runtime_witness::{Input, MAX_WITNESS_INPUT};
        use crate::core::runtime_cutover::*;
        use crate::core::state::{ArtifactRef, StateValue};
        let hash = crate::config::hash_bytes;
        if pinned_config.len() > 65536 || input.len() > MAX_WITNESS_INPUT {
            return Err(SourceError::Limit);
        }
        if self.verifier.cutover.is_some() {
            return Err(SourceError::Invalid);
        }
        if hash(pinned_config) != issued.snapshot.collector_config_digest() {
            return Err(SourceError::Integrity);
        }
        let config: CollectorConfig =
            serde_json::from_slice(pinned_config).map_err(|_| SourceError::Invalid)?;
        config.validate_request(issued)?;
        let input: Input = serde_json::from_slice(input).map_err(|_| SourceError::Invalid)?;
        let case = issued
            .request
            .cases
            .iter()
            .find(|case| case.id == input.candidate.context.case_id)
            .ok_or(SourceError::Invalid)?;
        let binding = config
            .runtime_unix
            .iter()
            .find(|entry| entry.matches(&case.address))
            .ok_or(SourceError::Unsupported)?;
        let policy = binding.witnesses.as_ref().ok_or(SourceError::Unsupported)?;
        let intent = RuntimeCutoverIntent::for_case(
            issued,
            case,
            RuntimeCutoverSelection {
                bundle_digest: policy.bundle_digest.clone(),
                previous_generation: policy.previous_generation,
                active_generation: policy.active_generation,
                application: binding.selection.app.selector.clone(),
                connector: binding.selection.connector.selector.clone(),
                cloud_iam_principal: issued
                    .snapshot
                    .gce()
                    .ok_or(SourceError::Unsupported)?
                    .native_identity
                    .service_account
                    .clone(),
                credential_binding_digest: policy.credential_binding_digest.clone(),
            },
            policy.not_before,
        )
        .map_err(|_| SourceError::ContextUnverified)?;
        let mut bundle = ObservationBundleWire::parse_untrusted(&self.bundle)
            .map_err(|_| SourceError::Invalid)?;
        let mut findings = self
            .verifier
            .verify(issued, &bundle, &self.payloads, self.window)
            .map_err(SourceError::AdmissionFailed)?;
        let kernel = self
            .unix_probes
            .iter()
            .find(|r| &r.context == intent.context())
            .ok_or(SourceError::ContextUnverified)?;
        let peer = super::runtime_unix::validate_wire(&kernel.capture, &binding.selection)?
            .peer_observation();
        let connector = input.connector.connector(policy)?;
        let pool = input.pool.pool(policy)?;
        let claim = bundle
            .claims
            .iter_mut()
            .find(|claim| claim.case_id == case.id && claim.observed == StateValue::Unknown)
            .ok_or(SourceError::ContextUnverified)?;
        if &connector.context != intent.context()
            || &pool.context != intent.context()
            || [connector.observed_at, pool.observed_at]
                .into_iter()
                .any(|at| at < intent.issued_at() || at > claim.finished_at)
        {
            return Err(SourceError::ContextUnverified);
        }
        let signed_payloads = [
            EvidencePayload {
                id: "k11-connector-witness".into(),
                bytes: serde_json::to_vec(&input.connector).map_err(|_| SourceError::Invalid)?,
            },
            EvidencePayload {
                id: "k11-pool-witness".into(),
                bytes: serde_json::to_vec(&input.pool).map_err(|_| SourceError::Invalid)?,
            },
        ];
        let digests = RuntimeCutoverEvidenceRefs {
            kernel_peer: self.verifier.proof_digests[0].clone(),
            postgres_session: hash(&signed_payloads[0].bytes),
            pool_checkout: hash(&signed_payloads[1].bytes),
        };
        struct FixedObservations(Option<NativeCutoverObservations>);
        impl RuntimeCutoverVerifier for FixedObservations {
            fn observe(
                &mut self,
                _: &RuntimeCutoverIntent,
            ) -> Result<NativeCutoverObservations, RuntimeCutoverError> {
                self.0.take().ok_or(RuntimeCutoverError::Unavailable)
            }
        }
        let mut verified = FixedObservations(Some(NativeCutoverObservations {
            context: intent.context().clone(),
            kernel_observed_at: claim.finished_at,
            postgres_observed_at: connector.observed_at,
            pool_observed_at: pool.observed_at,
            valid_until: connector.valid_until.min(pool.valid_until),
            kernel: peer,
            postgres: connector.observation,
            pool: pool.observation,
            evidence_refs: digests,
        }));
        let proof = verify_runtime_cutover(&intent, &input.candidate, &mut verified, now)
            .map_err(|_| SourceError::ContextUnverified)?;
        for payload in signed_payloads {
            let sha256 = hash(&payload.bytes);
            bundle.artifacts.push(ArtifactRef {
                id: payload.id.clone(),
                sha256: sha256.clone(),
            });
            findings.source_evidence_refs.push(payload.id.clone());
            claim.evidence_refs.push(payload.id.clone());
            self.verifier.proof_digests.push(sha256);
            self.payloads.push(payload);
        }
        claim.observed = StateValue::Present;
        let assurance = findings
            .assurances
            .iter_mut()
            .find(|a| a.claim_id == claim.id)
            .ok_or(SourceError::Invalid)?;
        let measured = Assurance::Verified {
            evidence_refs: claim.evidence_refs.clone(),
        };
        assurance.coverage = AssuranceCoverage {
            target: measured.clone(),
            principal: measured.clone(),
            source: measured.clone(),
            route: measured.clone(),
            transport: measured.clone(),
            temporal: measured.clone(),
            completeness: measured,
        };
        findings.recipe_id = "k11-runtime-cutover-v1".into();
        bundle.validate_shape().map_err(|_| SourceError::Invalid)?;
        self.bundle = serde_json::to_vec(&bundle).map_err(|_| SourceError::Invalid)?;
        self.verifier.bundle_digest = hash(&self.bundle);
        self.verifier.findings = findings;
        self.verifier.cutover = Some(proof);
        self.verifier.used = false;
        Ok(self)
    }
}
/// No public constructor and no Deserialize: a wire response cannot manufacture
/// the channel/native proof consumed by the admission port.
///
/// ```compile_fail
/// use veil_db_guard::adapters::source::gce_host::GceSourceVerifier;
/// let _: GceSourceVerifier = serde_json::from_str("{}").unwrap();
/// ```
pub struct GceSourceVerifier {
    request_digest: String,
    bundle_digest: String,
    proof_digests: Vec<String>,
    window: CaptureWindow,
    findings: VerifierFindings,
    used: bool,
    cutover: Option<crate::core::runtime_cutover::CorroboratedRuntimeCutover>,
}
impl ObservationVerifier for GceSourceVerifier {
    fn verify(
        &mut self,
        i: &IssuedObservation,
        b: &ObservationBundleWire,
        p: &[EvidencePayload],
        w: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        if self.used
            || i.request.digest().map_err(|_| AdmissionError::Invalid)? != self.request_digest
            || crate::config::hash_bytes(
                &serde_json::to_vec(b).map_err(|_| AdmissionError::Invalid)?,
            ) != self.bundle_digest
            || w.sent_at != self.window.sent_at
            || w.received_at != self.window.received_at
            || w.elapsed_millis != self.window.elapsed_millis
            || p.len() != self.proof_digests.len()
            || p.iter()
                .zip(&self.proof_digests)
                .any(|(payload, digest)| crate::config::hash_bytes(&payload.bytes) != *digest)
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        self.used = true;
        Ok(self.findings.clone())
    }

    fn runtime_cutover(
        &self,
        case_id: &str,
    ) -> Option<&crate::core::runtime_cutover::CorroboratedRuntimeCutover> {
        self.cutover
            .as_ref()
            .filter(|proof| proof.candidate().context.case_id == case_id)
    }
}

pub async fn capture_gce_source(
    i: &IssuedObservation,
    access: &SshAccess,
    cancel: &CancellationToken,
    allow_native_read: bool,
) -> Result<GceCapture, SourceError> {
    if !allow_native_read {
        return Err(SourceError::PermissionRequired);
    }
    validate_issued(i).map_err(|_| SourceError::Invalid)?;
    validated_profile(&i.snapshot)?;
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    if crate::domain::now() >= i.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    trusted_program(Path::new("/usr/bin/ssh"))?;
    private_file(&access.identity_file, 16384)?;
    let known_hosts = prepare_known_hosts(i, access)?;
    let keys = GoogleSigningKeys::fetch(cancel).await?;
    let args = ssh_arguments(&i.snapshot, access, &known_hosts)?;
    let input = serde_json::to_vec(i).map_err(|_| SourceError::Invalid)?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err(SourceError::Limit);
    }
    let sent = crate::domain::now();
    let instant = std::time::Instant::now();
    let remaining = i
        .request
        .expires_at
        .saturating_sub(sent)
        .min(MAX_CAPTURE_SECONDS);
    if remaining == 0 {
        return Err(SourceError::RequestExpired);
    }
    let bytes = process::run(
        Path::new("/usr/bin/ssh"),
        &args,
        &input,
        MAX_REPLY_BYTES,
        remaining,
        cancel,
    )
    .await?;
    let window = CaptureWindow {
        sent_at: sent,
        received_at: crate::domain::now(),
        elapsed_millis: instant
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| SourceError::Limit)?,
    };
    let reply = decode_reply(&bytes, i)?;
    verify_reply(i, reply, window, &keys, crate::domain::now())
}

fn decode_reply(bytes: &[u8], i: &IssuedObservation) -> Result<CollectorReply, SourceError> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(SourceError::Limit);
    }
    match serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)? {
        CollectorResponse::Success { reply } => Ok(*reply),
        CollectorResponse::Failure {
            request_digest,
            code,
        } => {
            if request_digest != i.request.digest().map_err(|_| SourceError::Invalid)? {
                return Err(SourceError::Invalid);
            }
            Err(code.error())
        }
    }
}
pub async fn capture_and_admit_gce<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &mut A,
    request_id: &str,
    access: &SshAccess,
    cancel: &CancellationToken,
    allow_native_read: bool,
) -> Result<EvidenceAdmission, SourceError> {
    if !allow_native_read {
        return Err(SourceError::PermissionRequired);
    }
    let i = ledger
        .issued(request_id)
        .map_err(SourceError::AdmissionFailed)?;
    ledger
        .ensure_current(&i, crate::domain::now())
        .map_err(SourceError::AdmissionFailed)?;
    let capture = capture_gce_source(&i, access, cancel, allow_native_read).await?;
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    admit_gce_capture(ledger, archive, request_id, capture)
}

pub(crate) fn admit_gce_capture<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &mut A,
    request_id: &str,
    mut capture: GceCapture,
) -> Result<EvidenceAdmission, SourceError> {
    crate::core::admission::accept_evidence(
        ledger,
        archive,
        &mut capture.verifier,
        request_id,
        &capture.bundle,
        &capture.payloads,
        capture.window,
        &crate::adapters::evidence::SystemEvidenceClock,
    )
    .map_err(SourceError::AdmissionFailed)
}

/// Local test transport for a real kernel sample and signed witnesses. The
/// synthetic GCE envelope is authenticated with an ephemeral test identity,
/// then passes the same reply, witness, and admission checks as a native reply.
#[cfg(test)]
pub(crate) fn test_corroborate_runtime_capture(
    issued: &IssuedObservation,
    pinned_config: &[u8],
    kernel: &super::runtime_unix::LinuxUnixSocketCapture,
    input: &[u8],
    window: CaptureWindow,
    now: u64,
) -> Result<GceCapture, SourceError> {
    if pinned_config.len() > 65536 {
        return Err(SourceError::Limit);
    }
    if crate::config::hash_bytes(pinned_config) != issued.snapshot.collector_config_digest() {
        return Err(SourceError::Integrity);
    }
    let config: CollectorConfig =
        serde_json::from_slice(pinned_config).map_err(|_| SourceError::Invalid)?;
    config.validate_request(issued)?;
    let [case] = issued.request.cases.as_slice() else {
        return Err(SourceError::Invalid);
    };
    let context = crate::core::runtime_binding::RuntimeCaptureContext::for_case(issued, case)
        .map_err(|_| SourceError::Invalid)?;
    let (keys, identity_token) =
        super::jwt::test_identity_at(issued, window.sent_at, window.received_at, |_| {});
    let reply = CollectorReply {
        schema_version: 1,
        request_digest: context.request_digest.clone(),
        collector_build_id: issued.snapshot.collector_build_id().into(),
        binary_digest: validated_profile(&issued.snapshot)?
            .collector_binary_digest
            .clone(),
        config_digest: issued.snapshot.collector_config_digest().into(),
        context_before: config.context.clone(),
        context_after: config.context,
        identity_token,
        started_at: window.sent_at,
        finished_at: window.received_at,
        route_denials: vec![],
        kernel_probes: vec![],
        unix_probes: vec![RuntimeUnixRecord {
            context,
            capture: kernel.wire().clone(),
        }],
        diagnostics: vec![CaseDiagnostic {
            runtime_capture: None,
            runtime_failure: None,
            iam_inventory: None,
            case_id: case.id.clone(),
            started_at: window.sent_at,
            finished_at: window.received_at,
            outcome: DiagnosticOutcome::RuntimeUnixObserved,
            connection: None,
            postgres: None,
        }],
    };
    verify_reply(issued, reply, window, &keys, now)?.corroborate_runtime(
        issued,
        pinned_config,
        input,
        now,
    )
}

fn verify_reply(
    i: &IssuedObservation,
    reply: CollectorReply,
    window: CaptureWindow,
    keys: &GoogleSigningKeys,
    now: u64,
) -> Result<GceCapture, SourceError> {
    if now >= i.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    let profile = validated_profile(&i.snapshot)?;
    if reply.schema_version != 1
        || reply.request_digest != i.request.digest().map_err(|_| SourceError::Invalid)?
        || reply.collector_build_id != i.snapshot.collector_build_id()
        || reply.binary_digest != profile.collector_binary_digest
        || reply.config_digest != i.snapshot.collector_config_digest()
        || reply.context_before != reply.context_after
        || reply.context_before.digest()? != i.snapshot.network_context_digest()
        || reply.context_before.uid != profile.execution_uid
        || reply.started_at > reply.finished_at
        || reply.started_at.saturating_add(5) < window.sent_at
        || reply.finished_at > window.received_at.saturating_add(5)
        || window.received_at > now
        || reply.finished_at.saturating_sub(reply.started_at) > MAX_CAPTURE_SECONDS
        || reply.diagnostics.len() != i.request.cases.len()
        || reply.unix_probes.len() > i.request.cases.len()
    {
        return Err(SourceError::ContextUnverified);
    }
    let identity = keys.verify(&reply.identity_token, i, now)?;
    super::route_denial::validate_observations(i, &reply.diagnostics, &reply.route_denials)?;
    let mut seen = std::collections::BTreeSet::new();
    for d in &reply.diagnostics {
        let c = i
            .request
            .cases
            .iter()
            .find(|c| c.id == d.case_id)
            .ok_or(SourceError::Invalid)?;
        let mut unix = reply
            .unix_probes
            .iter()
            .filter(|r| r.context.case_id == c.id);
        let unix_record = unix.next();
        if unix.next().is_some()
            || unix_record.is_some() != (d.outcome == DiagnosticOutcome::RuntimeUnixObserved)
        {
            return Err(SourceError::Invalid);
        }
        if let Some(record) = unix_record {
            let expected = crate::core::runtime_binding::RuntimeCaptureContext::from_issued(i, c)
                .map_err(|_| SourceError::Invalid)?;
            if record.context != expected
                || c.address.route.kind != crate::core::policy::RouteKind::NativeConnector
                || d.connection.is_some()
            {
                return Err(SourceError::ContextUnverified);
            }
            // The fixed collector selected the scope from its root-pinned
            // config. At the controller this only rechecks wire consistency.
            super::runtime_unix::validate_wire(&record.capture, record.capture.selection())?;
        }
        if !seen.insert(&d.case_id)
            || d.started_at < reply.started_at
            || d.finished_at > reply.finished_at
            || d.started_at > d.finished_at
            || d.iam_inventory.as_ref().is_some_and(|v| {
                d.postgres.is_none()
                    || c.kind != FixedObservationCase::NewConnection
                    || v.started_at < d.started_at
                    || v.finished_at > d.finished_at
                    || v.started_at > v.finished_at
            })
            || d.outcome == DiagnosticOutcome::MysqlObserved
            || (d.outcome == DiagnosticOutcome::RuntimeObserved
                && (c.kind != FixedObservationCase::RuntimeBinding
                    || d.postgres.is_some()
                    || d.iam_inventory.is_some()
                    || d.runtime_capture.is_some() == d.runtime_failure.is_some()))
            || (d.outcome != DiagnosticOutcome::RuntimeObserved
                && (d.runtime_capture.is_some() || d.runtime_failure.is_some()))
            || (d.postgres.is_some() && d.outcome != DiagnosticOutcome::PostgresObserved)
            || (d.postgres.is_none() && d.outcome == DiagnosticOutcome::PostgresObserved)
            || (d.postgres.is_some()
                && (matches!(
                    c.kind,
                    FixedObservationCase::DirectPath | FixedObservationCase::RuntimeBinding
                ) || d.connection.is_some()))
            || (d.postgres.is_none()
                && c.kind != FixedObservationCase::DirectPath
                && !matches!(
                    d.outcome,
                    DiagnosticOutcome::UnsupportedCase
                        | DiagnosticOutcome::RuntimeObserved
                        | DiagnosticOutcome::RuntimeUnixObserved
                ))
            || d.connection.as_ref().is_some_and(|t| {
                t.endpoint != c.endpoint
                    || t.peer_port != c.port
                    || t.peer_ip.is_ipv4() != (c.address_family == AddressFamily::Ipv4)
            })
        {
            return Err(SourceError::Invalid);
        }
        if let Some(runtime) = &d.runtime_capture {
            let expected = crate::core::runtime_binding::RuntimeCaptureContext::from_issued(i, c)
                .map_err(|_| SourceError::Invalid)?;
            let selector = crate::core::runtime_binding::RuntimeProcessSelector {
                pid: runtime.before.pid,
                expected_boot_id: runtime.before.boot_id.clone(),
                expected_start_ticks: runtime.before.start_ticks,
                expected_executable_digest: runtime.before.executable_digest.clone(),
            };
            if d.connection.as_ref() != Some(&runtime.before.connection) {
                return Err(SourceError::Invalid);
            }
            crate::core::runtime_binding::validate_runtime_capture(
                runtime,
                &expected,
                &selector,
                &runtime.before.connection,
            )
            .map_err(|_| SourceError::ContextUnverified)?;
        } else if d.outcome == DiagnosticOutcome::RuntimeObserved && d.connection.is_some() {
            return Err(SourceError::Invalid);
        }
    }
    if reply
        .unix_probes
        .iter()
        .any(|r| !seen.contains(&r.context.case_id))
    {
        return Err(SourceError::Invalid);
    }
    #[derive(Serialize)]
    struct Selected<'a> {
        schema_version: u32,
        request_digest: &'a str,
        source_snapshot_digest: &'a str,
        identity: &'a GceVmIdentity,
        context: &'a LinuxHostContext,
        collector_build_id: &'a str,
        binary_digest: &'a str,
        config_digest: &'a str,
        token_digest: String,
        token_issued_at: u64,
        token_expires_at: u64,
        signing_key_id: &'a str,
        diagnostics: &'a [CaseDiagnostic],
        #[serde(skip_serializing_if = "Vec::is_empty")]
        route_denials: &'a Vec<super::route_denial::GcpRouteObservation>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        kernel_probes: &'a Vec<super::origin::HostKernelProbeRecord>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        unix_probes: &'a Vec<RuntimeUnixRecord>,
    }
    let proof = serde_json::to_vec(&Selected {
        schema_version: 1,
        request_digest: &reply.request_digest,
        source_snapshot_digest: &i.request.source.revision_digest,
        identity: &identity.identity,
        context: &reply.context_before,
        collector_build_id: &reply.collector_build_id,
        binary_digest: &reply.binary_digest,
        config_digest: &reply.config_digest,
        token_digest: crate::config::hash_bytes(reply.identity_token.as_bytes()),
        token_issued_at: identity.issued_at,
        token_expires_at: identity.expires_at,
        signing_key_id: &identity.signing_key_id,
        diagnostics: &reply.diagnostics,
        route_denials: &reply.route_denials,
        kernel_probes: &reply.kernel_probes,
        unix_probes: &reply.unix_probes,
    })
    .map_err(|_| SourceError::Invalid)?;
    let proof_digest = crate::config::hash_bytes(&proof);
    if reply
        .kernel_probes
        .iter()
        .any(|k| reply.route_denials.iter().any(|r| r.case_id == k.case_id))
    {
        return Err(SourceError::Invalid);
    }
    let kernel_probes = super::origin::verify_records(
        i,
        &reply.diagnostics,
        &reply.kernel_probes,
        &reply.context_before,
        &proof_digest,
    )?;
    let proof_id = "gce-source-context".to_owned();
    let mut claims = vec![];
    let mut assurances = vec![];
    for d in &reply.diagnostics {
        let c = i
            .request
            .cases
            .iter()
            .find(|c| c.id == d.case_id)
            .ok_or(SourceError::Invalid)?;
        if let Some(route) = reply.route_denials.iter().find(|r| r.case_id == c.id) {
            let (claim, assurance, native, native_assurance) =
                super::route_denial::normalize(i, c, d, route, &proof_id)?;
            claims.extend([claim, native]);
            assurances.extend([assurance, native_assurance]);
            continue;
        }
        if d.postgres.is_some() {
            let (claim, assurance) = super::postgres::normalize(i, c, d, &proof_id)?;
            if let Some(inventory) = &d.iam_inventory {
                let (inventory_claim, inventory_assurance) = super::iam_inventory::normalize_gcp(
                    i,
                    c,
                    inventory,
                    &proof_id,
                    assurance.coverage.clone(),
                )?;
                claims.push(inventory_claim);
                assurances.push(inventory_assurance);
            }
            claims.push(claim);
            assurances.push(assurance);
            continue;
        }
        let kernel_probe = reply.kernel_probes.iter().any(|k| k.case_id == d.case_id);
        let id = format!("source-{}", d.case_id);
        claims.push(ObservationClaim {
            runtime_capture: d.runtime_capture.clone(),
            postgres_login_failure: None,
            login_catalog: vec![],
            id: id.clone(),
            case_id: c.id.clone(),
            policy_revision_hash: i.request.policy_revision_hash.clone(),
            address: c.address.clone(),
            started_at: d.started_at,
            finished_at: d.finished_at,
            // TCP success/refusal does not establish DB authentication or an attributed route denial.
            observed: crate::core::state::StateValue::Unknown,
            layer: if c.kind == FixedObservationCase::RuntimeBinding {
                crate::core::state::StateLayer::Configuration
            } else if c.kind == FixedObservationCase::DirectPath {
                crate::core::state::StateLayer::RouteEnforcement
            } else {
                crate::core::state::StateLayer::Authentication
            },
            denial_cause: None,
            connection: d.connection.clone(),
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec![proof_id.clone()],
            permission_inventory: None,
        });
        assurances.push(ClaimAssurance {
            claim_id: id,
            coverage: AssuranceCoverage {
                target: Assurance::Unconfirmed {
                    reason: EvidenceReason::TargetUnconfirmed,
                },
                principal: Assurance::Unconfirmed {
                    reason: EvidenceReason::PrincipalUnconfirmed,
                },
                source: Assurance::Verified {
                    evidence_refs: vec![proof_id.clone()],
                },
                route: Assurance::Unconfirmed {
                    reason: if kernel_probe {
                        EvidenceReason::RuntimeBindingUnverified
                    } else {
                        EvidenceReason::RouteUnconfirmed
                    },
                },
                transport: Assurance::Unconfirmed {
                    reason: EvidenceReason::TransportUnconfirmed,
                },
                temporal: Assurance::Verified {
                    evidence_refs: vec![proof_id.clone()],
                },
                completeness: if kernel_probe || c.kind == FixedObservationCase::RuntimeBinding {
                    Assurance::Unconfirmed {
                        reason: EvidenceReason::RuntimeBindingUnverified,
                    }
                } else if d.outcome == DiagnosticOutcome::UnsupportedCase {
                    Assurance::Unsupported {
                        reason: EvidenceReason::UnsupportedProducer,
                    }
                } else {
                    Assurance::Verified {
                        evidence_refs: vec![proof_id.clone()],
                    }
                },
            },
        });
    }
    super::denial::append_native_decisions(&mut claims, &mut assurances);
    let bundle = ObservationBundleWire {
        schema_version: 1,
        request_digest: reply.request_digest.clone(),
        collector_build_id: reply.collector_build_id,
        started_at: reply.started_at,
        finished_at: reply.finished_at,
        capture_complete: false,
        claims,
        artifacts: vec![crate::core::state::ArtifactRef {
            id: proof_id.clone(),
            sha256: proof_digest.clone(),
        }],
    };
    bundle.validate_shape().map_err(|_| SourceError::Invalid)?;
    let bytes = serde_json::to_vec(&bundle).map_err(|_| SourceError::Invalid)?;
    let verifier = GceSourceVerifier {
        request_digest: reply.request_digest,
        bundle_digest: crate::config::hash_bytes(&bytes),
        proof_digests: vec![proof_digest],
        window,
        findings: VerifierFindings {
            recipe_id: "gce-host-network-root-v1".into(),
            source_evidence_refs: vec![proof_id.clone()],
            assurances,
        },
        used: false,
        cutover: None,
    };
    Ok(GceCapture {
        bundle: bytes,
        payloads: vec![EvidencePayload {
            id: proof_id,
            bytes: proof,
        }],
        window,
        verifier,
        kernel_probes,
        unix_probes: reply.unix_probes,
    })
}

/// Offline validation of the explicitly registered initial source profile.
pub fn validate_registration(snapshot: &RegisteredSourceSnapshot) -> Result<(), SourceError> {
    validated_profile(snapshot).map(|_| ())
}

pub(super) fn validated_profile(
    s: &RegisteredSourceSnapshot,
) -> Result<&GceHostProfile, SourceError> {
    let s = s.gce().ok_or(SourceError::Unsupported)?;
    s.validate().map_err(|_| SourceError::Invalid)?;
    let p = s.gce_host.as_ref().ok_or(SourceError::Unsupported)?;
    let key = STANDARD
        .decode(&p.host_key_ed25519_base64)
        .map_err(|_| SourceError::Invalid)?;
    // SSH wire format: uint32(11), ssh-ed25519, uint32(32), 32 public bytes.
    if key.len() != 51
        || &key[..19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
        || crate::config::hash_bytes(&key) != s.ssh_host_key_digest
        || s.execution_user.is_empty()
        || s.execution_user.len() > 32
        || !s
            .execution_user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || s.execution_user.starts_with('-')
    {
        return Err(SourceError::Integrity);
    }
    // A general user's shell startup/rc/environment may be application-owned.
    // The first profile trusts the source administrator's root session only;
    // a restricted non-root login-shell recipe requires a separate contract.
    if p.execution_uid != 0 || s.execution_user != "root" {
        return Err(SourceError::Unsupported);
    }
    Ok(p)
}
fn plain_path(p: &Path) -> Result<String, SourceError> {
    let s = p.to_str().ok_or(SourceError::Invalid)?;
    if !p.is_absolute()
        || s.len() > 1024
        || s.contains("..")
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    {
        return Err(SourceError::Invalid);
    }
    Ok(s.into())
}
pub(super) fn private_file(path: &Path, max: u64) -> Result<(), SourceError> {
    plain_path(path)?;
    let m = std::fs::symlink_metadata(path).map_err(|_| SourceError::Unavailable)?;
    if !m.is_file() || m.file_type().is_symlink() || m.len() > max {
        return Err(SourceError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 || m.nlink() != 1 {
            return Err(SourceError::Integrity);
        }
    }
    Ok(())
}
pub(super) fn trusted_program(path: &Path) -> Result<(), SourceError> {
    let m = std::fs::metadata(path).map_err(|_| SourceError::Unavailable)?;
    if !m.is_file() {
        return Err(SourceError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(SourceError::Integrity);
        }
    }
    Ok(())
}
fn prepare_known_hosts(i: &IssuedObservation, access: &SshAccess) -> Result<PathBuf, SourceError> {
    let p = validated_profile(&i.snapshot)?;
    prepare_known_hosts_for(
        &i.request.source.revision_digest,
        &p.host_key_ed25519_base64,
        access,
    )
}
pub(super) fn prepare_known_hosts_for(
    digest: &str,
    host_key: &str,
    access: &SshAccess,
) -> Result<PathBuf, SourceError> {
    plain_path(&access.work_directory)?;
    let m =
        std::fs::symlink_metadata(&access.work_directory).map_err(|_| SourceError::Unavailable)?;
    if !m.is_dir() || m.file_type().is_symlink() {
        return Err(SourceError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(SourceError::Integrity);
        }
    }
    let path = access
        .work_directory
        .join(format!("known-hosts-{}", digest));
    let line = format!("veil-source-{} ssh-ed25519 {}\n", digest, host_key);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match options.open(&path) {
        Ok(mut f) => {
            f.write_all(line.as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|_| SourceError::Unavailable)?;
            std::fs::File::open(&access.work_directory)
                .and_then(|f| f.sync_all())
                .map_err(|_| SourceError::Unavailable)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            private_file(&path, 4096)?;
            let mut b = vec![];
            std::fs::File::open(&path)
                .map_err(|_| SourceError::Unavailable)?
                .take(4097)
                .read_to_end(&mut b)
                .map_err(|_| SourceError::Unavailable)?;
            if b != line.as_bytes() {
                return Err(SourceError::Integrity);
            }
        }
        Err(_) => return Err(SourceError::Unavailable),
    }
    Ok(path)
}
fn ssh_arguments(
    s: &RegisteredSourceSnapshot,
    access: &SshAccess,
    known_hosts: &Path,
) -> Result<Vec<String>, SourceError> {
    let p = validated_profile(s)?;
    ssh_arguments_for(
        &s.revision_digest().map_err(|_| SourceError::Invalid)?,
        p.ssh_ip,
        p.ssh_port,
        &s.gce().ok_or(SourceError::Unsupported)?.execution_user,
        access,
        known_hosts,
    )
}
pub(super) fn ssh_arguments_for(
    digest: &str,
    ip: IpAddr,
    port: u16,
    user: &str,
    access: &SshAccess,
    known_hosts: &Path,
) -> Result<Vec<String>, SourceError> {
    let mut args = ["-F", "/dev/null", "-T", "-a", "-x", "-e", "none"]
        .map(str::to_owned)
        .to_vec();
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "CheckHostIP=no",
        "VerifyHostKeyDNS=no",
        "GlobalKnownHostsFile=/dev/null",
        "KnownHostsCommand=none",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ControlMaster=no",
        "ControlPath=none",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
        "ForwardX11=no",
        "PermitLocalCommand=no",
        "LocalCommand=none",
        "RemoteCommand=none",
        "CanonicalizeHostname=no",
        "ConnectionAttempts=1",
        "ConnectTimeout=10",
        "ServerAliveInterval=5",
        "ServerAliveCountMax=2",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "EnableSSHKeysign=no",
        "PKCS11Provider=none",
        "SecurityKeyProvider=none",
        "CertificateFile=none",
        "HostKeyAlgorithms=ssh-ed25519",
        "LogLevel=ERROR",
        "RequestTTY=no",
    ] {
        args.extend(["-o".into(), option.into()]);
    }
    args.extend([
        "-o".into(),
        format!("UserKnownHostsFile={}", plain_path(known_hosts)?),
        "-o".into(),
        format!("HostKeyAlias=veil-source-{}", digest),
        "-i".into(),
        plain_path(&access.identity_file)?,
        "-p".into(),
        port.to_string(),
        "-l".into(),
        user.to_owned(),
        "--".into(),
        ip.to_string(),
        format!("{COLLECTOR_PATH} source-collector-v1"),
    ]);
    Ok(args)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    fn window() -> CaptureWindow {
        CaptureWindow {
            sent_at: 110,
            received_at: 115,
            elapsed_millis: 5000,
        }
    }
    fn reply(
        i: &IssuedObservation,
        config: &CollectorConfig,
        outcome: DiagnosticOutcome,
    ) -> (GoogleSigningKeys, CollectorReply) {
        let (keys, token) = super::super::jwt::test_identity(i, |_| {});
        let reply = CollectorReply {
            schema_version: 1,
            request_digest: i.request.digest().unwrap(),
            collector_build_id: i.snapshot.collector_build_id().to_owned(),
            binary_digest: i
                .snapshot
                .gce()
                .unwrap()
                .gce_host
                .as_ref()
                .unwrap()
                .collector_binary_digest
                .clone(),
            config_digest: i.snapshot.collector_config_digest().to_owned(),
            context_before: config.context.clone(),
            context_after: config.context.clone(),
            identity_token: token,
            started_at: 110,
            finished_at: 115,
            route_denials: vec![],
            kernel_probes: vec![],
            unix_probes: vec![],
            diagnostics: vec![CaseDiagnostic {
                runtime_capture: None,
                runtime_failure: None,
                iam_inventory: None,
                case_id: "direct".into(),
                started_at: 111,
                finished_at: 114,
                outcome,
                connection: None,
                postgres: None,
            }],
        };
        (keys, reply)
    }
    #[test]
    fn runtime_input_rejects_recovery_as_application_attribution() {
        let (mut i, _) = super::super::testsupport::fixture();
        i.request.cases[0].kind = FixedObservationCase::RuntimeBinding;
        i.request.cases[0].address.effect = EffectKindV2::RuntimeBinding;
        i.request.cases[0].purpose = crate::core::source::SourcePurpose::Recovery;
        i.request.source.allowed_uses[0].purpose = crate::core::source::SourcePurpose::Recovery;
        validate_issued(&i).unwrap();
        assert!(
            crate::core::runtime_binding::RuntimeCaptureContext::from_issued(
                &i,
                &i.request.cases[0],
            )
            .is_err()
        );
    }
    #[test]
    fn protected_kernel_probe_is_sealed_but_application_denial_stays_unknown() {
        use super::super::origin::*;
        let (mut i, mut config) = super::super::testsupport::fixture();
        config.kernel_origin = Some(HostKernelOriginConfig::LinuxRootConnectV1 {
            source_ip: "10.0.0.2".parse().unwrap(),
        });
        i.snapshot.gce_mut().unwrap().collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        for case in &mut i.request.cases {
            case.address.source = i.request.source.snapshot_ref();
        }
        config.validate_request(&i).unwrap();
        let (keys, mut r) = reply(&i, &config, DiagnosticOutcome::TcpUnavailable);
        r.diagnostics[0].connection = Some(ConnectionTuple {
            endpoint: i.request.cases[0].endpoint.clone(),
            local_ip: "10.0.0.2".parse().unwrap(),
            local_port: 40001,
            peer_ip: config.endpoints[0].ip,
            peer_port: 5432,
        });
        r.kernel_probes = vec![super::super::origin::fixture_record(
            &config.context,
            &r.diagnostics[0],
        )];
        // Mutations use the same native fixture/checker, never a public trust switch.
        let baseline = serde_json::to_vec(&r).unwrap();
        for n in 0..9 {
            let mut changed: CollectorReply = serde_json::from_slice(&baseline).unwrap();
            let record = &mut changed.kernel_probes[0];
            match n {
                0 => record.synchronous_errno = Some(libc::EACCES),
                1 => record.context_after.security_context_digest = "e".repeat(64),
                2 => {
                    record.context_before.uid = 1000;
                    record.context_after.uid = 1000;
                }
                3 => {
                    record.context_before.network_namespace = "net:[wrong]".into();
                    record.context_after.network_namespace = "net:[wrong]".into();
                }
                4 => record.connection.peer_port = 5433,
                5 => record.started_at += 1,
                6 => record.outcome = KernelSocketOutcome::Connected,
                7 => record.context_before.cgroup_class = "other".into(),
                _ => changed.kernel_probes.push(changed.kernel_probes[0].clone()),
            }
            assert!(
                verify_reply(&i, changed, window(), &keys, 116).is_err(),
                "mutation {n}"
            );
        }
        let mut capture = verify_reply(&i, r, window(), &keys, 116).unwrap();
        assert_eq!(capture.host_kernel_probes().len(), 1);
        let fact = &capture.host_kernel_probes()[0];
        assert_eq!(fact.outcome(), KernelSocketOutcome::HostKernelProbeDenied);
        assert_eq!(fact.request_digest(), i.request.digest().unwrap());
        assert_eq!(
            fact.source_revision_digest(),
            i.request.source.revision_digest
        );
        assert_eq!(
            fact.proof_digest(),
            crate::config::hash_bytes(&capture.payloads[0].bytes)
        );
        let bundle: ObservationBundleWire = serde_json::from_slice(&capture.bundle).unwrap();
        assert!(bundle.claims.iter().all(|c| c.observed
            == crate::core::state::StateValue::Unknown
            && c.controls.is_empty()));
        let findings = capture
            .verifier
            .verify(&i, &bundle, &capture.payloads, capture.window)
            .unwrap();
        assert!(matches!(
            findings.assurances[0].coverage.route,
            Assurance::Unconfirmed {
                reason: EvidenceReason::RuntimeBindingUnverified
            }
        ));
        assert!(matches!(
            findings.assurances[0].coverage.completeness,
            Assurance::Unconfirmed {
                reason: EvidenceReason::RuntimeBindingUnverified
            }
        ));
    }

    #[test]
    fn native_source_proof_is_redacted_and_tcp_results_never_become_db_effects() {
        let (i, config) = super::super::testsupport::fixture();
        for outcome in [
            DiagnosticOutcome::TcpConnected,
            DiagnosticOutcome::TcpRefused,
            DiagnosticOutcome::TcpTimedOut,
        ] {
            let (keys, reply) = reply(&i, &config, outcome);
            let raw = reply.identity_token.clone();
            assert!(!format!("{reply:?}").contains(&raw));
            let mut capture = verify_reply(&i, reply, window(), &keys, 116).unwrap();
            assert!(!std::str::from_utf8(&capture.bundle).unwrap().contains(&raw));
            assert!(
                !std::str::from_utf8(&capture.payloads[0].bytes)
                    .unwrap()
                    .contains(&raw)
            );
            let bundle: ObservationBundleWire = serde_json::from_slice(&capture.bundle).unwrap();
            assert_eq!(
                bundle.claims[0].observed,
                crate::core::state::StateValue::Unknown
            );
            assert!(bundle.claims[0].denial_cause.is_none());
            let findings = capture
                .verifier
                .verify(&i, &bundle, &capture.payloads, window())
                .unwrap();
            assert!(matches!(
                findings.assurances[0].coverage.source,
                Assurance::Verified { .. }
            ));
            assert!(matches!(
                findings.assurances[0].coverage.principal,
                Assurance::Unconfirmed { .. }
            ));
            assert!(
                capture
                    .verifier
                    .verify(&i, &bundle, &capture.payloads, window())
                    .is_err()
            );
        }
    }

    #[test]
    fn unix_peer_capture_is_sealed_without_promoting_runtime_binding() {
        use crate::core::policy::RouteKind;
        use crate::core::runtime_binding::RuntimeCaptureContext;
        use crate::core::state::StateValue;
        let (mut issued, mut config) = super::super::testsupport::fixture();
        let (selection, capture) = super::super::runtime_unix::fixture();
        let case = &mut issued.request.cases[0];
        case.kind = FixedObservationCase::RuntimeBinding;
        case.address.effect = EffectKindV2::RuntimeBinding;
        case.address.route.kind = RouteKind::NativeConnector;
        config.runtime_unix.push(RuntimeUnixBinding {
            target_id: case.address.target_id.clone(),
            grant_id: case.address.grant_id.clone(),
            subject_id: case.address.subject_id.clone(),
            route_id: case.address.route.id.clone(),
            selection,
            witnesses: None,
        });
        issued.snapshot.gce_mut().unwrap().collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
        issued.request.source.revision_digest = issued.snapshot.revision_digest().unwrap();
        issued.request.cases[0].address.source = issued.request.source.snapshot_ref();
        config.validate_request(&issued).unwrap();
        let context = RuntimeCaptureContext::for_case(&issued, &issued.request.cases[0]).unwrap();
        for tamper in [false, true] {
            let (keys, mut reply) = reply(&issued, &config, DiagnosticOutcome::RuntimeUnixObserved);
            let mut record = RuntimeUnixRecord {
                context: context.clone(),
                capture: capture.clone(),
            };
            if tamper {
                record.context.change_hash = "f".repeat(64);
            }
            reply.unix_probes.push(record);
            let result = verify_reply(&issued, reply, window(), &keys, 116);
            if tamper {
                assert!(matches!(result, Err(SourceError::ContextUnverified)));
                continue;
            }
            let mut capture = result.unwrap();
            let bundle = ObservationBundleWire::parse_untrusted(&capture.bundle).unwrap();
            assert_eq!(bundle.claims[0].observed, StateValue::Unknown);
            let proof: serde_json::Value =
                serde_json::from_slice(&capture.payloads[0].bytes).unwrap();
            assert_eq!(proof["unix_probes"].as_array().unwrap().len(), 1);
            let findings = capture
                .verifier
                .verify(&issued, &bundle, &capture.payloads, window())
                .unwrap();
            assert!(matches!(
                findings.assurances[0].coverage.transport,
                Assurance::Unconfirmed { .. }
            ));
        }
    }

    #[test]
    fn registered_witnesses_join_a_sealed_kernel_capture_and_reject_forgery() {
        let (selection, wire) = super::super::runtime_unix::fixture_separate_users();
        assert_registered_witness_join(selection, wire);
    }

    pub(in crate::adapters::source) fn assert_registered_witness_join(
        selection: super::super::runtime_unix::RuntimeUnixSelection,
        wire: super::super::runtime_unix::LinuxUnixSocketCaptureWire,
    ) {
        use super::super::runtime_witness::{RuntimeWitnessPolicy, Statement};
        use crate::core::policy::RouteKind;
        use crate::core::runtime_binding::RuntimeCaptureContext;
        use crate::core::runtime_cutover::*;
        use crate::core::state::StateValue;
        use ring::signature::{Ed25519KeyPair, KeyPair};
        fn signed(
            key: &Ed25519KeyPair,
            domain: &[u8],
            statement: &impl Serialize,
        ) -> serde_json::Value {
            let bytes = serde_json::to_vec(statement).unwrap();
            let signature = key.sign(&[domain, bytes.as_slice()].concat());
            serde_json::json!({
                "statement_base64": STANDARD.encode(bytes),
                "signature_base64": STANDARD.encode(signature.as_ref()),
            })
        }
        let connector_key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
        let pool_key = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
        let (mut issued, mut config) = super::super::testsupport::fixture();
        let kernel = super::super::runtime_unix::validate_wire(&wire, &selection).unwrap();
        let peer = kernel.peer_observation();
        let case = &mut issued.request.cases[0];
        case.kind = FixedObservationCase::RuntimeBinding;
        case.address.effect = EffectKindV2::RuntimeBinding;
        case.address.route.kind = RouteKind::NativeConnector;
        let policy = RuntimeWitnessPolicy {
            connector_key: STANDARD.encode(connector_key.public_key().as_ref()),
            pool_key: STANDARD.encode(pool_key.public_key().as_ref()),
            bundle_digest: "1".repeat(64),
            previous_generation: 1,
            active_generation: 2,
            credential_binding_digest: "2".repeat(64),
            not_before: 101,
        };
        config.runtime_unix.push(RuntimeUnixBinding {
            target_id: case.address.target_id.clone(),
            grant_id: case.address.grant_id.clone(),
            subject_id: case.address.subject_id.clone(),
            route_id: case.address.route.id.clone(),
            selection,
            witnesses: Some(policy.clone()),
        });
        let config_bytes = serde_json::to_vec(&config).unwrap();
        issued.snapshot.gce_mut().unwrap().collector_config_digest =
            crate::config::hash_bytes(&config_bytes);
        issued.request.source.revision_digest = issued.snapshot.revision_digest().unwrap();
        issued.request.cases[0].address.source = issued.request.source.snapshot_ref();
        let case = &issued.request.cases[0];
        let context = RuntimeCaptureContext::for_case(&issued, case).unwrap();
        let session = PostgresSessionIdentity {
            database: case.address.target.engine_binding.database.clone(),
            session_user: case.address.db_identity.clone(),
            backend_pid: 123,
            backend_started_at_micros: 106_000_000,
        };
        let switch = PoolSwitchLink {
            previous_generation: 1,
            active_generation: 2,
            checkout_sequence: 1,
            switched_at: 107,
            checked_out_at: 108,
        };
        let candidate = RuntimeCutoverCandidate {
            context: context.clone(),
            bundle_digest: policy.bundle_digest.clone(),
            app: AppSessionLink {
                process: peer.application.process.clone(),
                socket_fd: peer.application.socket_fd,
                socket_inode: peer.application.socket_inode,
                session: session.clone(),
            },
            switch: switch.clone(),
        };
        let connector = Statement {
            context: context.clone(),
            observed_at: 109,
            valid_until: 140,
            observation: NativePostgresSessionObservation {
                connector: peer.connector,
                session,
                current_user: case.address.db_identity.clone(),
                tls_peer_native_id: case.address.target.native_ref.native_id.clone(),
                tls_peer_target_generation: case
                    .address
                    .target
                    .native_ref
                    .generation_fingerprint
                    .clone()
                    .unwrap(),
                tls_peer_certificate_digest: "3".repeat(64),
                native_iam_principal: issued
                    .snapshot
                    .gce()
                    .unwrap()
                    .native_identity
                    .service_account
                    .clone(),
                credential_binding_digest: policy.credential_binding_digest.clone(),
            },
        };
        let pool = Statement {
            context: context.clone(),
            observed_at: 109,
            valid_until: 139,
            observation: NativePoolUseObservation {
                application: peer.application,
                bundle_digest: policy.bundle_digest,
                switch,
            },
        };
        for bad in [false, true] {
            let input = serde_json::to_vec(&serde_json::json!({
                "candidate": candidate,
                "connector": signed(if bad { &pool_key } else { &connector_key }, b"veil-db-guard/k11/connector/v1\0", &connector),
                "pool": signed(&pool_key, b"veil-db-guard/k11/pool/v1\0", &pool),
            })).unwrap();
            let result = test_corroborate_runtime_capture(
                &issued,
                &config_bytes,
                &kernel,
                &input,
                window(),
                116,
            );
            if bad {
                assert!(matches!(result, Err(SourceError::IdentityUnverified)));
                continue;
            }
            let mut capture = result.unwrap();
            let bundle = ObservationBundleWire::parse_untrusted(&capture.bundle).unwrap();
            assert_eq!(bundle.claims[0].observed, StateValue::Present);
            assert_eq!(bundle.artifacts.len(), 3);
            let findings = capture
                .verifier
                .verify(&issued, &bundle, &capture.payloads, window())
                .unwrap();
            assert_eq!(findings.recipe_id, "k11-runtime-cutover-v1");
            assert_eq!(
                capture
                    .verifier
                    .runtime_cutover(&case.id)
                    .unwrap()
                    .observations()
                    .valid_until,
                139
            );
        }
    }

    fn runtime_reply_fixture() -> (IssuedObservation, GoogleSigningKeys, CollectorReply) {
        use super::super::runtime::{RuntimeCollectorConfig, RuntimeProcessBinding};
        use crate::core::runtime_binding::*;
        let (mut issued, mut config) = super::super::testsupport::fixture();
        let case = &mut issued.request.cases[0];
        case.id = "runtime".into();
        case.kind = FixedObservationCase::RuntimeBinding;
        case.address.effect = EffectKindV2::RuntimeBinding;
        let selector = RuntimeProcessSelector {
            pid: 1234,
            expected_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            expected_start_ticks: 5678,
            expected_executable_digest: "e".repeat(64),
        };
        config.runtime = Some(RuntimeCollectorConfig {
            bindings: vec![RuntimeProcessBinding {
                target_id: case.address.target_id.clone(),
                grant_id: case.address.grant_id.clone(),
                subject_id: case.address.subject_id.clone(),
                selector: selector.clone(),
                socket_fd: 7,
            }],
        });
        issued.snapshot.gce_mut().unwrap().collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
        issued.request.source.revision_digest = issued.snapshot.revision_digest().unwrap();
        issued.request.cases[0].address.source = issued.request.source.snapshot_ref();
        config.validate_request(&issued).unwrap();
        let case = &issued.request.cases[0];
        let connection = ConnectionTuple {
            endpoint: case.endpoint.clone(),
            local_ip: "10.0.0.2".parse().unwrap(),
            local_port: 40001,
            peer_ip: config.endpoints[0].ip,
            peer_port: case.port,
        };
        let snapshot = LinuxProcessSocketSnapshot {
            boot_id: selector.expected_boot_id,
            pid: selector.pid,
            start_ticks: selector.expected_start_ticks,
            executable_digest: selector.expected_executable_digest,
            uid: 1000,
            effective_uid: 1000,
            gid: 1000,
            effective_gid: 1000,
            net_namespace: 4026531992,
            mount_namespace: 4026531841,
            user_namespace: 4026531837,
            cgroup_digest: "d".repeat(64),
            security_digest: "f".repeat(64),
            fd: 7,
            socket_inode: 98765,
            tcp_state: 1,
            connection: connection.clone(),
        };
        let wire = LinuxRuntimeCaptureWire {
            schema_version: 1,
            context: RuntimeCaptureContext::from_issued(&issued, case).unwrap(),
            before: snapshot.clone(),
            after: snapshot,
        };
        let (keys, mut result) = reply(&issued, &config, DiagnosticOutcome::RuntimeObserved);
        result.diagnostics[0].case_id = case.id.clone();
        result.diagnostics[0].connection = Some(connection);
        result.diagnostics[0].runtime_capture = Some(wire);
        (issued, keys, result)
    }

    #[test]
    fn runtime_signed_capture_preserves_useful_samples_without_confirming_binding() {
        use crate::core::state::{StateLayer, StateValue};
        let (issued, keys, reply) = runtime_reply_fixture();
        let token = reply.identity_token.clone();
        let mut capture = verify_reply(&issued, reply, window(), &keys, 116).unwrap();
        let bundle: ObservationBundleWire = serde_json::from_slice(&capture.bundle).unwrap();
        let claim = &bundle.claims[0];
        assert_eq!(claim.observed, StateValue::Unknown);
        assert_eq!(claim.layer, StateLayer::Configuration);
        let runtime = claim.runtime_capture.as_ref().unwrap();
        assert_eq!(runtime.before.pid, 1234);
        assert_eq!(runtime.before.socket_inode, 98765);
        assert_eq!(runtime.before, runtime.after);
        assert!(claim.transport.is_empty());
        assert!(claim.sql_context.is_none());
        let proof: serde_json::Value = serde_json::from_slice(&capture.payloads[0].bytes).unwrap();
        assert_eq!(
            proof["diagnostics"][0]["runtime_capture"]["before"]["fd"],
            7
        );
        assert!(!String::from_utf8_lossy(&capture.payloads[0].bytes).contains(&token));
        let findings = capture
            .verifier
            .verify(&issued, &bundle, &capture.payloads, window())
            .unwrap();
        assert!(matches!(
            findings.assurances[0].coverage.source,
            Assurance::Verified { .. }
        ));
        assert!(matches!(
            findings.assurances[0].coverage.completeness,
            Assurance::Unconfirmed {
                reason: EvidenceReason::RuntimeBindingUnverified
            }
        ));
        assert!(matches!(
            findings.assurances[0].coverage.target,
            Assurance::Unconfirmed { .. }
        ));
        assert!(matches!(
            findings.assurances[0].coverage.principal,
            Assurance::Unconfirmed { .. }
        ));
        assert!(matches!(
            findings.assurances[0].coverage.transport,
            Assurance::Unconfirmed { .. }
        ));
    }

    #[test]
    fn runtime_signed_capture_rejects_context_reuse_drift_and_downgrade() {
        for mutation in 0..10 {
            let (issued, keys, mut reply) = runtime_reply_fixture();
            let diagnostic = &mut reply.diagnostics[0];
            let wire = diagnostic.runtime_capture.as_mut().unwrap();
            match mutation {
                0 => wire.context.change_hash = "a".repeat(64),
                1 => wire.context.source_trust_epoch += 1,
                2 => wire.context.case_id = "foreign".into(),
                3 => wire.after.start_ticks += 1,
                4 => wire.after.pid += 1,
                5 => wire.after.security_digest = "a".repeat(64),
                6 => wire.after.socket_inode += 1,
                7 => wire.after.tcp_state = 10,
                8 => diagnostic.outcome = DiagnosticOutcome::UnsupportedCase,
                _ => {
                    wire.context
                        .address
                        .target
                        .native_ref
                        .generation_fingerprint = Some("a".repeat(64))
                }
            }
            assert!(
                verify_reply(&issued, reply, window(), &keys, 116).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn runtime_partial_capture_is_covered_by_the_sealed_payload_verifier() {
        for mutation in 0..3 {
            let (issued, keys, reply) = runtime_reply_fixture();
            let mut capture = verify_reply(&issued, reply, window(), &keys, 116).unwrap();
            let mut bundle: ObservationBundleWire =
                serde_json::from_slice(&capture.bundle).unwrap();
            match mutation {
                0 => {
                    bundle.claims[0]
                        .runtime_capture
                        .as_mut()
                        .unwrap()
                        .before
                        .pid += 1
                }
                1 => capture.payloads[0].bytes.push(b' '),
                _ => bundle.claims[0].observed = crate::core::state::StateValue::Allowed,
            }
            assert!(
                capture
                    .verifier
                    .verify(&issued, &bundle, &capture.payloads, window())
                    .is_err()
            );
        }
    }

    #[test]
    fn runtime_observation_failure_preserves_unknown_without_socket_success() {
        let (issued, keys, mut reply) = runtime_reply_fixture();
        reply.diagnostics[0].runtime_capture = None;
        reply.diagnostics[0].connection = None;
        reply.diagnostics[0].runtime_failure = Some(CollectorFailure::ContextUnverified);
        let mut capture = verify_reply(&issued, reply, window(), &keys, 116).unwrap();
        let bundle: ObservationBundleWire = serde_json::from_slice(&capture.bundle).unwrap();
        assert_eq!(
            bundle.claims[0].observed,
            crate::core::state::StateValue::Unknown
        );
        assert!(bundle.claims[0].runtime_capture.is_none());
        assert!(bundle.claims[0].connection.is_none());
        let findings = capture
            .verifier
            .verify(&issued, &bundle, &capture.payloads, window())
            .unwrap();
        assert!(matches!(
            findings.assurances[0].coverage.completeness,
            Assurance::Unconfirmed {
                reason: EvidenceReason::RuntimeBindingUnverified
            }
        ));
    }

    #[test]
    fn runtime_case_planning_requires_explicit_matching_process_selection() {
        use super::super::runtime::{RuntimeCollectorConfig, RuntimeProcessBinding};
        use crate::core::runtime_binding::RuntimeProcessSelector;
        let change = crate::core::source_execution::tests::change();
        let (_, mut config) = super::super::testsupport::fixture();
        config.endpoints[0].generation_digest = change.policy.targets[0]
            .resource
            .generation_fingerprint
            .clone()
            .unwrap();
        let source_id = &change.policy.source_bindings[0].source_id;
        let plan = super::super::requests::plan(&change, source_id, &config, 110).unwrap();
        assert!(
            !plan
                .batches
                .iter()
                .flatten()
                .any(|c| c.kind == FixedObservationCase::RuntimeBinding)
        );
        assert!(!plan.source_verified);
        let grant = &change.policy.grants[0];
        config.runtime = Some(RuntimeCollectorConfig {
            bindings: vec![RuntimeProcessBinding {
                target_id: change.policy.targets[0].id.clone(),
                grant_id: grant.id.clone(),
                subject_id: grant.subject.clone(),
                selector: RuntimeProcessSelector {
                    pid: 1234,
                    expected_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
                    expected_start_ticks: 5678,
                    expected_executable_digest: "e".repeat(64),
                },
                socket_fd: 7,
            }],
        });
        let plan = super::super::requests::plan(&change, source_id, &config, 110).unwrap();
        assert_eq!(
            plan.batches
                .iter()
                .flatten()
                .filter(|c| c.kind == FixedObservationCase::RuntimeBinding)
                .count(),
            1
        );
        assert!(!plan.source_verified);
        config.runtime.as_mut().unwrap().bindings[0].subject_id = "foreign-subject".into();
        let plan = super::super::requests::plan(&change, source_id, &config, 110).unwrap();
        assert!(
            !plan
                .batches
                .iter()
                .flatten()
                .any(|c| c.kind == FixedObservationCase::RuntimeBinding)
        );
    }
    #[test]
    fn correct_vm_token_cannot_override_context_drift_wrong_build_or_case_scope() {
        let (i, config) = super::super::testsupport::fixture();
        for n in 0..9 {
            let (keys, mut r) = reply(&i, &config, DiagnosticOutcome::TcpRefused);
            match n {
                0 => r.context_after.effective_uid += 1,
                1 => r.context_before.network_namespace = "net:[other]".into(),
                2 => r.binary_digest = "a".repeat(64),
                3 => r.collector_build_id = "a".repeat(64),
                4 => r.config_digest = "a".repeat(64),
                5 => r.request_digest = "a".repeat(64),
                6 => r.diagnostics[0].case_id = "foreign".into(),
                7 => r.diagnostics.push(r.diagnostics[0].clone()),
                _ => r.finished_at = 300,
            }
            assert!(
                verify_reply(&i, r, window(), &keys, 116).is_err(),
                "case {n}"
            );
        }
    }
    #[test]
    fn sealed_verifier_rejects_rebound_payload_bundle_window_and_nonce() {
        let (i, config) = super::super::testsupport::fixture();
        for n in 0..4 {
            let (keys, r) = reply(&i, &config, DiagnosticOutcome::TcpRefused);
            let mut capture = verify_reply(&i, r, window(), &keys, 116).unwrap();
            let mut issuer = i.clone();
            let mut bundle: ObservationBundleWire =
                serde_json::from_slice(&capture.bundle).unwrap();
            let mut w = window();
            match n {
                0 => issuer.request.nonce = "b".repeat(64),
                1 => bundle.claims[0].observed = crate::core::state::StateValue::Denied,
                2 => capture.payloads[0].bytes.push(0),
                _ => w.received_at += 1,
            }
            assert!(
                capture
                    .verifier
                    .verify(&issuer, &bundle, &capture.payloads, w)
                    .is_err()
            );
        }
    }
    #[test]
    fn legacy_source_registration_does_not_gain_a_native_profile_by_default() {
        let (mut i, _) = super::super::testsupport::fixture();
        i.snapshot.gce_mut().unwrap().schema_version = 1;
        i.snapshot.gce_mut().unwrap().gce_host = None;
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        assert!(matches!(
            validated_profile(&i.snapshot),
            Err(SourceError::Unsupported)
        ));
    }
    #[test]
    fn collector_failure_codes_are_bounded_request_scoped_and_preserve_the_refusal_reason() {
        let (i, _) = super::super::testsupport::fixture();
        for (code, error) in [
            (
                CollectorFailure::ContextUnverified,
                SourceError::ContextUnverified,
            ),
            (CollectorFailure::Unsupported, SourceError::Unsupported),
            (
                CollectorFailure::IdentityUnverified,
                SourceError::IdentityUnverified,
            ),
            (CollectorFailure::TimedOut, SourceError::TimedOut),
            (
                CollectorFailure::RequestExpired,
                SourceError::RequestExpired,
            ),
        ] {
            let bytes = serde_json::to_vec(&CollectorResponse::Failure {
                request_digest: i.request.digest().unwrap(),
                code,
            })
            .unwrap();
            assert!(matches!(decode_reply(&bytes,&i),Err(e) if e==error));
        }
        let bytes = serde_json::to_vec(&CollectorResponse::Failure {
            request_digest: "f".repeat(64),
            code: CollectorFailure::ContextUnverified,
        })
        .unwrap();
        assert!(matches!(
            decode_reply(&bytes, &i),
            Err(SourceError::Invalid)
        ));
    }
    #[test]
    fn ssh_arguments_have_fixed_command_pinned_key_and_no_ambient_auth_or_forwarding() {
        let (i, _) = super::super::testsupport::fixture();
        let d = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let access = SshAccess {
            identity_file: d.path().join("identity"),
            work_directory: d.path().to_path_buf(),
        };
        let path = prepare_known_hosts(&i, &access).unwrap();
        let args = ssh_arguments(&i.snapshot, &access, &path).unwrap();
        assert_eq!(
            args.last().unwrap(),
            &format!("{COLLECTOR_PATH} source-collector-v1")
        );
        for expected in [
            "/dev/null",
            "StrictHostKeyChecking=yes",
            "ProxyCommand=none",
            "IdentityAgent=none",
            "ClearAllForwardings=yes",
            "ControlPath=none",
            "PermitLocalCommand=no",
            "IdentitiesOnly=yes",
        ] {
            assert!(args.iter().any(|a| a == expected), "{expected}");
        }
        assert!(!args.iter().any(|a| a.contains(&i.request.nonce)));
        std::fs::write(&path, b"changed-key\n").unwrap();
        assert!(prepare_known_hosts(&i, &access).is_err());
    }
    #[tokio::test]
    async fn native_opt_in_precedes_tools_key_reads_and_any_network() {
        let (i, _) = super::super::testsupport::fixture();
        let access = SshAccess {
            identity_file: "/does/not/exist".into(),
            work_directory: "/does/not/exist".into(),
        };
        assert!(matches!(
            capture_gce_source(&i, &access, &CancellationToken::new(), false).await,
            Err(SourceError::PermissionRequired)
        ));
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            capture_gce_source(&i, &access, &cancelled, true).await,
            Err(SourceError::Cancelled)
        ));
        assert!(matches!(
            capture_gce_source(&i, &access, &CancellationToken::new(), true).await,
            Err(SourceError::RequestExpired)
        ));
    }
    #[test]
    fn source_profile_rejects_bad_host_key_digest_and_shell_user() {
        let (i, _) = super::super::testsupport::fixture();
        let mut s = i.snapshot.clone();
        s.gce_mut().unwrap().ssh_host_key_digest = "f".repeat(64);
        assert!(validated_profile(&s).is_err());
        let mut s = i.snapshot.clone();
        s.gce_mut().unwrap().execution_user = "user-command".into();
        assert!(matches!(
            validated_profile(&s),
            Err(SourceError::Unsupported)
        ));
        s.gce_mut().unwrap().execution_user = "user;command".into();
        assert!(validated_profile(&s).is_err());
        let mut value = serde_json::to_value(i.snapshot).unwrap();
        value["gce_host"]["jwk_url"] = serde_json::json!("https://attacker.invalid");
        assert!(serde_json::from_value::<SourceRegistrationSnapshot>(value).is_err());
    }
    #[test]
    fn source_crypto_verifier_connects_to_real_local_admission_without_persisting_token() {
        admission_lab(AdmissionMode::Tcp);
    }
    #[test]
    fn postgres_source_producer_connects_signed_capture_admission_and_effective_state_offline() {
        admission_lab(AdmissionMode::PostgresAllowed);
    }
    #[test]
    fn connect_audit_candidate_passes_sealed_admission_without_origin_promotion() {
        admission_lab(AdmissionMode::PostgresDenied);
    }
    #[test]
    fn native_nologin_passes_sealed_durable_admission_and_requires_recovery_catalog() {
        admission_lab(AdmissionMode::PostgresNoLogin);
    }
    #[test]
    fn independent_recovery_login_catalog_passes_sealed_durable_admission() {
        admission_lab(AdmissionMode::PostgresRecoveryCatalog);
    }
    #[test]
    fn complete_iam_inventory_passes_sealed_admission_and_expires_on_source_epoch_change() {
        admission_lab(AdmissionMode::PostgresInventory);
    }
    #[test]
    fn firewall_log_candidate_passes_sealed_admission_without_origin_promotion() {
        admission_lab(AdmissionMode::RouteDenied);
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum AdmissionMode {
        RouteDenied,
        Tcp,
        PostgresAllowed,
        PostgresDenied,
        PostgresNoLogin,
        PostgresRecoveryCatalog,
        PostgresInventory,
    }
    fn admission_lab(mode: AdmissionMode) {
        let pg = !matches!(mode, AdmissionMode::Tcp | AdmissionMode::RouteDenied);
        use crate::{
            adapters::evidence::RunEvidenceArchive,
            core::{
                approval,
                change::{OperationLimits, prepare_change},
                operation::BeginRequest,
                plan::build_plan,
                policy::*,
                ports::EvidenceClock,
            },
            evidence_store::{EvidenceStore, ObservationRequestSpec},
            operation_store::OperationStore,
        };
        let (mut fixture, mut config) = super::super::testsupport::fixture();
        let mut route_observation = None;
        let mut route_diagnostic = None;
        if mode == AdmissionMode::RouteDenied {
            let (issued, collector, diagnostic, observation, _) =
                super::super::route_denial::tests::sample();
            fixture = issued;
            config = collector;
            route_observation = Some(observation);
            route_diagnostic = Some(diagnostic);
        }
        let mut pg_observation = None;
        if pg {
            let (_, case, diagnostic) = super::super::postgres::tests::sample();
            pg_observation = diagnostic.postgres;
            fixture.request.cases = vec![case];
            config.schema_version = 2;
            config.postgres = Some(super::super::postgres::PostgresCollectorConfig {
                proxy_sha256: "f".repeat(64),
                collect_connect_denial_audit: mode == AdmissionMode::PostgresDenied,
                collect_iam_inventory: mode == AdmissionMode::PostgresInventory,
            });
            config.endpoints[0].generation_digest = fixture.request.cases[0]
                .address
                .target
                .native_ref
                .generation_fingerprint
                .clone()
                .unwrap();
            config.endpoints[0].ip = "10.0.0.1".parse().unwrap();
            fixture.snapshot.gce_mut().unwrap().collector_config_digest =
                crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
            fixture.request.source.revision_digest = fixture.snapshot.revision_digest().unwrap();
            fixture.request.cases[0].address.source = fixture.request.source.snapshot_ref();
        }
        if mode == AdmissionMode::PostgresRecoveryCatalog {
            let source = &mut fixture.request.source;
            source.source_id = "recovery-runtime".into();
            source.registration_id = "recovery-source-registration".into();
            source.allowed_uses = vec![crate::core::source::SourceUse {
                subject_id: "recovery-operator".into(),
                purpose: crate::core::source::SourcePurpose::Recovery,
            }];
            config.registration_id = source.registration_id.clone();
            let snapshot = fixture.snapshot.gce_mut().unwrap();
            snapshot.registration_id = source.registration_id.clone();
            snapshot.native_identity.service_account =
                "recovery@vdg-example-000000.iam.gserviceaccount.com".into();
            snapshot.native_identity.service_account_id = "223456789012345678901".into();
            snapshot.native_identity.instance_id = "8876543210".into();
            snapshot.credential_reference = "recovery-workload".into();
            snapshot.collector_config_digest =
                crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
            source.revision_digest = snapshot.revision_digest().unwrap();
            let case = &mut fixture.request.cases[0];
            case.kind = FixedObservationCase::TargetHealth;
            case.purpose = crate::core::source::SourcePurpose::Recovery;
            case.address.subject_id = "recovery-operator".into();
            case.address.db_identity = "recovery@vdg-example-000000.iam".into();
            case.address.route.id = "recovery-connector".into();
            case.address.source = source.snapshot_ref();
            let observation = pg_observation.as_mut().unwrap();
            observation.credential_identity = snapshot.native_identity.service_account.clone();
            let catalog = observation.catalog.as_mut().unwrap();
            catalog.session_user = case.address.db_identity.clone();
            catalog.current_user = case.address.db_identity.clone();
        }
        let mut p = parse_policy(include_str!("../../../examples/core-policy-v2.yaml")).unwrap();
        p.targets[0].resource = fixture.request.cases[0].address.target.native_ref.clone();
        let app = p
            .subjects
            .iter_mut()
            .find(|s| s.id == fixture.request.cases[0].address.subject_id)
            .unwrap();
        app.identity.immutable_id = Some(
            fixture
                .snapshot
                .gce()
                .unwrap()
                .native_identity
                .service_account_id
                .clone(),
        );
        app.identity.credential_source.kind = CredentialSourceKind::WorkloadIdentity;
        app.identity.credential_source.reference =
            fixture.snapshot.gce().unwrap().credential_reference.clone();
        *p.source_bindings
            .iter_mut()
            .find(|s| s.source_id == fixture.request.source.source_id)
            .unwrap() = fixture.request.source.clone();
        if mode == AdmissionMode::PostgresNoLogin {
            p.evaluation.as_mut().unwrap().denial_requirements[0].accepted_layers =
                vec![AcceptedDenialLayer::DatabaseLogin];
        }
        if mode == AdmissionMode::PostgresRecoveryCatalog {
            let case = &mut fixture.request.cases[0];
            case.login_catalog_targets = crate::core::postgres_login::authorized_targets(&p, case);
            assert_eq!(case.login_catalog_targets.len(), 1);
            pg_observation
                .as_mut()
                .unwrap()
                .catalog
                .as_mut()
                .unwrap()
                .login_catalog = vec![crate::core::postgres_login::LoginCatalogFact {
                target: case.login_catalog_targets[0].clone(),
                role_oid: 300,
                can_login: false,
            }];
        }
        let plan = build_plan(
            &p,
            crate::adapters::capabilities_for_policy(&p).unwrap(),
            vec![],
            100,
        )
        .unwrap();
        let change = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
        let approval = approval::issue(
            &change,
            "test-approval",
            "reviewer",
            "runner",
            300,
            900,
            100,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let mut operations = OperationStore::open(&path).unwrap();
        operations.register_change(&change).unwrap();
        operations.register_approval(&change, &approval).unwrap();
        operations
            .begin(&BeginRequest {
                request_id: "operation-request".into(),
                operation_id: "operation-1".into(),
                change_hash: change.change_hash.clone(),
                approval_id: approval.id,
                expected_desired_head: None,
                execution_identity: "runner".into(),
                now: 100,
            })
            .unwrap();
        drop(operations);
        let mut ledger = EvidenceStore::open(&path).unwrap();
        ledger.register_source(&fixture.snapshot, None).unwrap();
        let i = ledger
            .issue_request(
                &ObservationRequestSpec {
                    request_id: fixture.request.request_id.clone(),
                    operation_id: "operation-1".into(),
                    source_id: fixture.request.source.source_id.clone(),
                    ttl_seconds: 120,
                    cases: fixture.request.cases.clone(),
                },
                100,
            )
            .unwrap();
        let (keys, mut r) = reply(&i, &config, DiagnosticOutcome::TcpRefused);
        if pg {
            r.diagnostics[0].case_id = i.request.cases[0].id.clone();
            r.diagnostics[0].outcome = DiagnosticOutcome::PostgresObserved;
            r.diagnostics[0].postgres = pg_observation;
        }
        if mode == AdmissionMode::PostgresDenied {
            let case = &i.request.cases[0];
            let (_, _, mut audit) = super::super::denial::tests::sample();
            audit["entries"][0]["protoPayload"]["requestMetadata"]["callerSuppliedUserAgent"] =
                format!(
                    "cloud-sql-proxy/2.26.3 {}",
                    super::super::denial::marker(&i, case)
                )
                .into();
            let selected = super::super::denial::select(
                &serde_json::to_vec(&audit).unwrap(),
                &i,
                case,
                r.diagnostics[0].started_at,
                r.diagnostics[0].finished_at,
            )
            .unwrap()
            .unwrap();
            let observation = r.diagnostics[0].postgres.as_mut().unwrap();
            observation.connected = false;
            observation.catalog = None;
            observation.stage = super::super::postgres::PgStage::Connect;
            observation.connect_denial = Some(selected);
        }
        if mode == AdmissionMode::PostgresNoLogin {
            let observation = r.diagnostics[0].postgres.as_mut().unwrap();
            observation.connected = false;
            observation.catalog = None;
            observation.stage = super::super::postgres::PgStage::Connect;
            observation.sqlstate = Some("28000".into());
            observation.login_rejection = Some(crate::core::postgres_login::PostgresLoginFailure {
                db_identity: i.request.cases[0].address.db_identity.clone(),
                kind: crate::core::postgres_login::PostgresLoginFailureKind::AuthenticatedNoLoginV1,
            });
        }
        if mode == AdmissionMode::PostgresInventory {
            let diagnostic = &mut r.diagnostics[0];
            diagnostic.iam_inventory = Some(super::super::iam_inventory::fixture_for_capture(
                &i,
                &i.request.cases[0],
                diagnostic
                    .postgres
                    .as_ref()
                    .unwrap()
                    .instance_before
                    .as_ref()
                    .unwrap(),
                diagnostic.started_at,
                diagnostic.finished_at,
            ));
        }
        if let (Some(diagnostic), Some(observation)) = (route_diagnostic, route_observation) {
            r.diagnostics = vec![diagnostic];
            r.route_denials = vec![observation];
            r.finished_at = 124;
        }
        let raw = r.identity_token.clone();
        let mut capture_window = window();
        let capture_now = if mode == AdmissionMode::RouteDenied {
            capture_window.received_at = 125;
            capture_window.elapsed_millis = 15000;
            126
        } else {
            116
        };
        let read_now = if mode == AdmissionMode::RouteDenied {
            130
        } else {
            120
        };
        let mut capture = verify_reply(&i, r, capture_window, &keys, capture_now).unwrap();
        let archives = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(archives.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut archive = RunEvidenceArchive::open(archives.path()).unwrap();
        struct Clock(u64);
        impl EvidenceClock for Clock {
            fn now(&self) -> u64 {
                self.0
            }
        }
        let receipt = accept_evidence(
            &mut ledger,
            &mut archive,
            &mut capture.verifier,
            &i.request.request_id,
            &capture.bundle,
            &capture.payloads,
            capture_window,
            &Clock(capture_now),
        )
        .unwrap();
        let facts = load_admitted(&mut ledger, &archive, &i.request.request_id, read_now).unwrap();
        assert_eq!(facts.admission_id(), receipt.id);
        assert!(matches!(
            facts.assurances()[0].coverage.source,
            Assurance::Verified { .. }
        ));
        let main = facts
            .claims()
            .iter()
            .find(|c| c.id == format!("source-{}", i.request.cases[0].id))
            .unwrap();
        assert_eq!(
            main.observed,
            match mode {
                AdmissionMode::Tcp | AdmissionMode::PostgresDenied | AdmissionMode::RouteDenied =>
                    crate::core::state::StateValue::Unknown,
                AdmissionMode::PostgresNoLogin => crate::core::state::StateValue::Denied,
                _ => crate::core::state::StateValue::Allowed,
            }
        );
        if mode == AdmissionMode::PostgresNoLogin {
            assert_eq!(facts.claims().len(), 2);
            let failure = main.postgres_login_failure.as_ref().unwrap();
            assert_eq!(failure.db_identity, main.address.db_identity);
            assert_eq!(
                failure.kind,
                crate::core::postgres_login::PostgresLoginFailureKind::AuthenticatedNoLoginV1
            );
            assert_eq!(main.layer, crate::core::state::StateLayer::Authentication);
            assert_eq!(
                main.denial_cause,
                Some(crate::core::state::DenialCause::LoginRejected)
            );
            assert!(main.sql_context.is_none());
            assert!(main.login_catalog.is_empty());
            assert!(
                main.controls
                    .iter()
                    .any(|c| c.purpose == ControlPurpose::NativeBoundaryDecision)
            );
        }
        if mode == AdmissionMode::PostgresRecoveryCatalog {
            assert_eq!(
                main.login_catalog,
                vec![crate::core::postgres_login::LoginCatalogFact {
                    target: i.request.cases[0].login_catalog_targets[0].clone(),
                    role_oid: 300,
                    can_login: false,
                }]
            );
            assert!(main.postgres_login_failure.is_none());
            assert_eq!(main.address.subject_id, "recovery-operator");
        }
        if mode == AdmissionMode::RouteDenied {
            assert_eq!(main.layer, crate::core::state::StateLayer::RouteEnforcement);
            assert_eq!(
                main.denial_cause,
                Some(crate::core::state::DenialCause::Unclassified)
            );
            assert!(main.controls.is_empty());
            assert_eq!(facts.claims().len(), 2);
            assert!(facts.assurances().iter().all(|a| matches!(
                a.coverage.route,
                Assurance::Unconfirmed {
                    reason: EvidenceReason::NativeLogOriginUnconfirmed
                }
            )));
        }
        if mode == AdmissionMode::PostgresDenied {
            use crate::core::state::{DenialCause, StateLayer};
            assert_eq!(facts.claims().len(), 1);
            assert_eq!(main.layer, StateLayer::ConnectionAuthorization);
            assert_eq!(main.denial_cause, Some(DenialCause::Unclassified));
            assert!(main.controls.is_empty());
            assert_eq!(
                facts.assurances()[0].coverage.completeness,
                Assurance::Unconfirmed {
                    reason: EvidenceReason::NativeLogOriginUnconfirmed
                }
            );
        }
        if mode == AdmissionMode::PostgresInventory {
            let inventory = facts
                .claims()
                .iter()
                .find(|c| c.permission_inventory.is_some())
                .unwrap();
            let permissions = inventory.permission_inventory.as_ref().unwrap();
            assert!(permissions.complete);
            assert_eq!(
                permissions.permissions,
                vec![
                    "cloudsql.instances.connect",
                    "cloudsql.instances.get",
                    "cloudsql.instances.login"
                ]
            );
            assert_eq!(inventory.observed, crate::core::state::StateValue::Unknown);
            assert!(inventory.denial_cause.is_none());
            let assurance = facts
                .assurances()
                .iter()
                .find(|a| a.claim_id == inventory.id)
                .unwrap();
            assert!(matches!(
                assurance.coverage.completeness,
                Assurance::Verified { .. }
            ));
        }
        let state = evaluate_admitted_change(
            &mut ledger,
            &archive,
            &change,
            std::slice::from_ref(&i.request.request_id),
            read_now,
        )
        .unwrap();
        assert!(!state.all_required_effects_satisfied);
        if pg
            && !matches!(
                mode,
                AdmissionMode::PostgresDenied | AdmissionMode::PostgresNoLogin
            )
        {
            assert!(
                state
                    .rows
                    .iter()
                    .any(|r| r.observed == crate::core::state::StateValue::Allowed
                        && r.assessment == crate::core::state::StateAssessment::Satisfied)
            );
        }
        if mode == AdmissionMode::RouteDenied {
            let row = state
                .rows
                .iter()
                .find(|r| r.desired.address == main.address)
                .unwrap();
            assert_eq!(row.observed, crate::core::state::StateValue::Unknown);
            assert_eq!(row.assessment, crate::core::state::StateAssessment::Unknown);
        }
        if mode == AdmissionMode::PostgresNoLogin {
            use crate::core::state::{StateAssessment, StateReason, StateValue};
            let row = state
                .rows
                .iter()
                .find(|row| row.desired.address == main.address)
                .unwrap();
            assert_eq!(row.observed, StateValue::Denied);
            assert_eq!(row.assessment, StateAssessment::Unknown);
            assert!(row.reasons.contains(&StateReason::UncorroboratedDenial));
        }
        for entry in std::fs::read_dir(archives.path().join(receipt.archive.run_id)).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(&raw));
            assert!(!text.contains("PRIVATE-SENTINEL"));
            assert!(!text.contains("group:database-operators@example.invalid"));
        }
        let database = std::fs::read(&path).unwrap();
        assert!(
            !database
                .windows(raw.len())
                .any(|bytes| bytes == raw.as_bytes())
        );
        assert!(!String::from_utf8_lossy(&database).contains("PRIVATE-SENTINEL"));
        if mode == AdmissionMode::PostgresInventory {
            let old_digest = i.snapshot.revision_digest().unwrap();
            let mut new_snapshot = i.snapshot.clone();
            new_snapshot.gce_mut().unwrap().trust_epoch += 1;
            ledger
                .register_source(&new_snapshot, Some(&old_digest))
                .unwrap();
            assert!(matches!(
                load_admitted(&mut ledger, &archive, &i.request.request_id, 121),
                Err(AdmissionError::TrustChanged)
            ));
            // Original history remains readable without becoming current facts.
            let history =
                read_admitted_history(&mut ledger, &archive, &i.request.request_id).unwrap();
            assert!(
                history
                    .claims
                    .iter()
                    .any(|c| c.permission_inventory.as_ref().is_some_and(|p| p.complete))
            );
        }
    }
}
