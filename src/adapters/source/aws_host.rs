//! AWS EC2 root host-network source recipe. This authenticates a registered
//! host/context, not IAM credentials, a DB target, TLS, login, or a denial layer.
use super::{collector, gce_host::*, process};
use crate::core::{
    admission::*,
    evidence::*,
    ports::{EvidenceArchive, EvidenceLedger, ObservationVerifier},
    source::*,
    state::*,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::Path};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsCollectorConfig {
    pub schema_version: u32,
    pub registration_id: String,
    pub context: LinuxHostContext,
    pub endpoints: Vec<CollectorEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<super::aws_postgres::AwsPostgresConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres_runtime: Option<super::aws_runtime_cutover::AwsPostgresRuntimeWitnessPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql: Option<super::aws_mysql::AwsMysqlConfig>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub collect_iam_inventory: bool,
}
impl AwsCollectorConfig {
    pub fn validate_request(&self, i: &IssuedObservation) -> Result<(), SourceError> {
        validate_issued(i).map_err(|_| SourceError::Invalid)?;
        let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
        validate_registration(s)?;
        if self.schema_version != 1
            || self.registration_id != s.registration_id
            || self.context.aws_digest()? != s.network_context_digest
            || self.context.uid != s.aws_host.execution_uid
            || self.endpoints.is_empty()
            || self.endpoints.len() > 8
        {
            return Err(SourceError::ContextUnverified);
        }
        if let Some(pg) = &self.postgres {
            pg.validate(i)?;
        }
        if let Some(runtime) = &self.postgres_runtime {
            runtime.validate()?;
        }
        if let Some(mysql) = &self.mysql {
            mysql.validate(i)?;
        }
        for c in &i.request.cases {
            if c.address.target.placement.kind != crate::core::policy::PlacementKind::AwsRds
                || c.address.target.placement.region != "ap-northeast-1"
                || !matches!(
                    (
                        c.address.target.engine_binding.family,
                        c.address.target.engine_binding.version.as_str()
                    ),
                    (crate::core::policy::EngineFamily::PostgreSql, "16.15")
                        | (crate::core::policy::EngineFamily::MySql, "8.0.43")
                )
                || self
                    .endpoints
                    .iter()
                    .filter(|e| endpoint_matches(e, c))
                    .count()
                    != 1
            {
                return Err(SourceError::Invalid);
            }
        }
        Ok(())
    }
}
fn endpoint_matches(e: &CollectorEndpoint, c: &RequestedCase) -> bool {
    e.target_id == c.address.target_id
        && e.native_id == c.address.target.native_ref.native_id
        && Some(e.generation_digest.as_str())
            == c.address
                .target
                .native_ref
                .generation_fingerprint
                .as_deref()
        && e.database == c.address.target.engine_binding.database
        && e.endpoint == c.endpoint
        && e.port == c.port
        && !e.ip.is_unspecified()
        && !e.ip.is_multicast()
        && e.ip.is_ipv4() == (c.address_family == AddressFamily::Ipv4)
}
pub fn validate_registration(s: &AwsSourceRegistrationSnapshot) -> Result<(), SourceError> {
    s.validate().map_err(|_| SourceError::Invalid)?;
    let key = STANDARD
        .decode(&s.aws_host.host_key_ed25519_base64)
        .map_err(|_| SourceError::Invalid)?;
    if key.len() != 51
        || &key[..19] != b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
        || crate::config::hash_bytes(&key) != s.ssh_host_key_digest
    {
        return Err(SourceError::Integrity);
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AwsCollectorReply {
    schema_version: u32,
    request_digest: String,
    collector_build_id: String,
    binary_digest: String,
    config_digest: String,
    context_before: LinuxHostContext,
    context_after: LinuxHostContext,
    identity_document: String,
    identity_signature: String,
    started_at: u64,
    finished_at: u64,
    diagnostics: Vec<CaseDiagnostic>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    postgres: Vec<super::aws_postgres::AwsPgObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mysql: Vec<super::aws_mysql::AwsMysqlObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    iam_inventory: Vec<super::aws_iam_inventory::AwsIamObservation>,
}
// IID is public metadata, but keep the raw response ephemeral and diagnostics
// bounded; no metadata session token or IAM credentials are serialized here.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum AwsCollectorResponse {
    Success {
        reply: Box<AwsCollectorReply>,
    },
    Failure {
        request_digest: String,
        code: CollectorFailure,
    },
}
pub struct AwsCapture {
    pub bundle: Vec<u8>,
    pub payloads: Vec<EvidencePayload>,
    pub window: CaptureWindow,
    pub verifier: AwsSourceVerifier,
}
/// Only a pinned live SSH capture can construct this verifier. No Deserialize,
/// constructor, imported verdict, or configurable production verification key.
/// ```compile_fail
/// use veil_db_guard::adapters::source::aws_host::AwsSourceVerifier;
/// let _: AwsSourceVerifier = serde_json::from_str("{}").unwrap();
/// ```
pub struct AwsSourceVerifier {
    request_digest: String,
    bundle_digest: String,
    proof_digest: String,
    window: CaptureWindow,
    findings: VerifierFindings,
    used: bool,
}
impl ObservationVerifier for AwsSourceVerifier {
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
            || p.len() != 1
            || p[0].id != "aws-source-context"
            || crate::config::hash_bytes(&p[0].bytes) != self.proof_digest
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        self.used = true;
        Ok(self.findings.clone())
    }
}
pub async fn capture_aws_source(
    i: &IssuedObservation,
    access: &SshAccess,
    cancel: &CancellationToken,
    allow_native_read: bool,
) -> Result<AwsCapture, SourceError> {
    if !allow_native_read {
        return Err(SourceError::PermissionRequired);
    }
    validate_issued(i).map_err(|_| SourceError::Invalid)?;
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    validate_registration(s)?;
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    if crate::domain::now() >= i.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    trusted_program(Path::new("/usr/bin/ssh"))?;
    private_file(&access.identity_file, 16384)?;
    let known = prepare_known_hosts_for(
        &i.request.source.revision_digest,
        &s.aws_host.host_key_ed25519_base64,
        access,
    )?;
    let args = ssh_arguments_for(
        &i.request.source.revision_digest,
        s.aws_host.ssh_ip,
        s.aws_host.ssh_port,
        &s.execution_user,
        access,
        &known,
    )?;
    let input = serde_json::to_vec(i).map_err(|_| SourceError::Invalid)?;
    if input.len() > MAX_REQUEST_BYTES {
        return Err(SourceError::Limit);
    }
    let sent_at = crate::domain::now();
    let instant = std::time::Instant::now();
    let remaining = i
        .request
        .expires_at
        .saturating_sub(sent_at)
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
    let w = CaptureWindow {
        sent_at,
        received_at: crate::domain::now(),
        elapsed_millis: instant
            .elapsed()
            .as_millis()
            .try_into()
            .map_err(|_| SourceError::Limit)?,
    };
    let reply = decode_reply(&bytes, i)?;
    verify_reply(i, reply, w, crate::domain::now())
}
fn decode_reply(bytes: &[u8], i: &IssuedObservation) -> Result<AwsCollectorReply, SourceError> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(SourceError::Limit);
    }
    match serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)? {
        AwsCollectorResponse::Success { reply } => Ok(*reply),
        AwsCollectorResponse::Failure {
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
pub async fn capture_and_admit_aws<L: EvidenceLedger, A: EvidenceArchive>(
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
    let mut capture = capture_aws_source(&i, access, cancel, true).await?;
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    accept_evidence(
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
fn verify_reply(
    i: &IssuedObservation,
    r: AwsCollectorReply,
    w: CaptureWindow,
    now: u64,
) -> Result<AwsCapture, SourceError> {
    verify_reply_using(i, r, w, now, super::aws_iid::verify)
}
fn verify_reply_using(
    i: &IssuedObservation,
    r: AwsCollectorReply,
    w: CaptureWindow,
    now: u64,
    verify_identity: impl FnOnce(&str, &str, &AwsEc2Identity, u64) -> Result<(), SourceError>,
) -> Result<AwsCapture, SourceError> {
    validate_issued(i).map_err(|_| SourceError::Invalid)?;
    if now >= i.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    validate_registration(s)?;
    if r.schema_version != 1
        || r.request_digest != i.request.digest().map_err(|_| SourceError::Invalid)?
        || r.collector_build_id != s.collector_build_id
        || r.binary_digest != s.aws_host.collector_binary_digest
        || r.config_digest != s.collector_config_digest
        || r.context_before != r.context_after
        || r.context_before.aws_digest()? != s.network_context_digest
        || r.context_before.uid != s.aws_host.execution_uid
        || r.started_at > r.finished_at
        || r.started_at < i.request.issued_at
        || r.finished_at >= i.request.expires_at
        || r.started_at.saturating_add(5) < w.sent_at
        || r.finished_at > w.received_at.saturating_add(5)
        || w.received_at > now
        || w.sent_at > w.received_at
        || r.finished_at.saturating_sub(r.started_at) > MAX_CAPTURE_SECONDS
        || r.diagnostics.len() != i.request.cases.len()
        || r.postgres.len().saturating_add(r.mysql.len()) > r.diagnostics.len()
        || r.iam_inventory.len() > r.diagnostics.len()
        || r.iam_inventory
            .iter()
            .any(|v| v.started_at < r.started_at || v.finished_at > r.finished_at)
        || r.iam_inventory
            .iter()
            .map(|v| &v.case_id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != r.iam_inventory.len()
        || r.iam_inventory.iter().any(|v| {
            !r.diagnostics.iter().any(|d| {
                d.case_id == v.case_id
                    && matches!(
                        d.outcome,
                        DiagnosticOutcome::PostgresObserved | DiagnosticOutcome::MysqlObserved
                    )
            })
        })
    {
        return Err(SourceError::ContextUnverified);
    }
    verify_identity(
        &r.identity_document,
        &r.identity_signature,
        &s.native_identity,
        now,
    )?;
    let proof_id = "aws-source-context".to_owned();
    let mut seen = std::collections::BTreeSet::new();
    for d in &r.diagnostics {
        let c = i
            .request
            .cases
            .iter()
            .find(|c| c.id == d.case_id)
            .ok_or(SourceError::Invalid)?;
        if !seen.insert(&d.case_id)
            || d.started_at < r.started_at
            || d.finished_at > r.finished_at
            || d.started_at > d.finished_at
            || d.iam_inventory.is_some()
            || d.postgres.is_some()
            || (c.kind != FixedObservationCase::DirectPath
                && !matches!(
                    d.outcome,
                    DiagnosticOutcome::UnsupportedCase
                        | DiagnosticOutcome::PostgresObserved
                        | DiagnosticOutcome::MysqlObserved
                ))
            || (r.postgres.iter().filter(|p| p.case_id == d.case_id).count()
                != usize::from(d.outcome == DiagnosticOutcome::PostgresObserved))
            || (r.mysql.iter().filter(|m| m.case_id == d.case_id).count()
                != usize::from(d.outcome == DiagnosticOutcome::MysqlObserved))
            || (c.kind == FixedObservationCase::DirectPath
                && !matches!(
                    d.outcome,
                    DiagnosticOutcome::TcpConnected
                        | DiagnosticOutcome::TcpRefused
                        | DiagnosticOutcome::TcpTimedOut
                        | DiagnosticOutcome::TcpUnavailable
                ))
            || d.connection.as_ref().is_some_and(|t| {
                t.endpoint != c.endpoint
                    || t.peer_port != c.port
                    || t.peer_ip.is_ipv4() != (c.address_family == AddressFamily::Ipv4)
                    || t.local_port == 0
                    || t.peer_ip.is_unspecified()
                    || t.peer_ip.is_multicast()
                    || (t.peer_ip.is_ipv4() && t.local_ip != s.native_identity.private_ip)
                    || !matches!(
                        d.outcome,
                        DiagnosticOutcome::TcpConnected
                            | DiagnosticOutcome::TcpRefused
                            | DiagnosticOutcome::TcpTimedOut
                            | DiagnosticOutcome::TcpUnavailable
                    )
            })
            || (d.outcome == DiagnosticOutcome::TcpConnected && d.connection.is_none())
        {
            return Err(SourceError::Invalid);
        }
    }
    if r.postgres.iter().any(|p| {
        !r.diagnostics
            .iter()
            .any(|d| d.case_id == p.case_id && d.outcome == DiagnosticOutcome::PostgresObserved)
    }) {
        return Err(SourceError::Invalid);
    }
    if r.mysql.iter().any(|m| {
        !r.diagnostics
            .iter()
            .any(|d| d.case_id == m.case_id && d.outcome == DiagnosticOutcome::MysqlObserved)
    }) {
        return Err(SourceError::Invalid);
    }
    // Selected identity only. Neither the raw document/signature nor metadata
    // tokens, IAM credentials, DSNs, SQL, or errors enter durable evidence.
    let mut proof_value = serde_json::json!({"schema_version":1,"request_digest":r.request_digest,"source_snapshot_digest":i.request.source.revision_digest,
        "identity":s.native_identity,"context":r.context_before,"collector_build_id":r.collector_build_id,"binary_digest":r.binary_digest,"config_digest":r.config_digest,
        "identity_document_digest":crate::config::hash_bytes(r.identity_document.as_bytes()),"identity_signature_digest":crate::config::hash_bytes(r.identity_signature.as_bytes()),
        "signing_key_recipe":"aws-tokyo-iid-raw-rsa-sha256-v1","diagnostics":r.diagnostics,"postgres":r.postgres,"mysql":r.mysql});
    if !r.iam_inventory.is_empty() {
        proof_value["iam_inventory"] =
            serde_json::to_value(&r.iam_inventory).map_err(|_| SourceError::Invalid)?;
    }
    let proof = serde_json::to_vec(&proof_value).map_err(|_| SourceError::Invalid)?;
    let proof_digest = crate::config::hash_bytes(&proof);
    let mut claims = vec![];
    let mut assurances = vec![];
    for d in &r.diagnostics {
        let c = i
            .request
            .cases
            .iter()
            .find(|c| c.id == d.case_id)
            .ok_or(SourceError::Invalid)?;
        if let Some(pg) = r.postgres.iter().find(|p| p.case_id == d.case_id) {
            let (claim, assurance) =
                super::aws_postgres::normalize(i, c, d.started_at, d.finished_at, pg, &proof_id)?;
            let coverage = assurance.coverage.clone();
            claims.push(claim);
            assurances.push(assurance);
            if let Some(inventory) = r.iam_inventory.iter().find(|v| v.case_id == c.id) {
                let (inventory_claim, inventory_assurance) =
                    super::aws_iam_inventory::normalize(i, c, inventory, &proof_id, coverage)?;
                claims.push(inventory_claim);
                assurances.push(inventory_assurance);
            }
            continue;
        }
        if let Some(mysql) = r.mysql.iter().find(|m| m.case_id == d.case_id) {
            let (claim, assurance) =
                super::aws_mysql::normalize(i, c, d.started_at, d.finished_at, mysql, &proof_id)?;
            let coverage = assurance.coverage.clone();
            claims.push(claim);
            assurances.push(assurance);
            if let Some(inventory) = r.iam_inventory.iter().find(|v| v.case_id == c.id) {
                let (inventory_claim, inventory_assurance) =
                    super::aws_iam_inventory::normalize(i, c, inventory, &proof_id, coverage)?;
                claims.push(inventory_claim);
                assurances.push(inventory_assurance);
            }
            continue;
        }
        let id = format!("aws-source-{}", c.id);
        claims.push(ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: id.clone(),
            case_id: c.id.clone(),
            policy_revision_hash: i.request.policy_revision_hash.clone(),
            address: c.address.clone(),
            started_at: d.started_at,
            finished_at: d.finished_at,
            observed: StateValue::Unknown,
            layer: if c.kind == FixedObservationCase::DirectPath {
                StateLayer::RouteEnforcement
            } else {
                StateLayer::Authentication
            },
            denial_cause: None,
            connection: d.connection.clone(),
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec![proof_id.clone()],
            permission_inventory: None,
        });
        let yes = || Assurance::Verified {
            evidence_refs: vec![proof_id.clone()],
        };
        let no = |reason| Assurance::Unconfirmed { reason };
        assurances.push(ClaimAssurance {
            claim_id: id,
            coverage: AssuranceCoverage {
                target: no(EvidenceReason::TargetUnconfirmed),
                principal: no(EvidenceReason::PrincipalUnconfirmed),
                source: yes(),
                route: no(EvidenceReason::RouteUnconfirmed),
                transport: no(EvidenceReason::TransportUnconfirmed),
                temporal: yes(),
                completeness: if d.outcome == DiagnosticOutcome::UnsupportedCase {
                    Assurance::Unsupported {
                        reason: EvidenceReason::UnsupportedProducer,
                    }
                } else {
                    yes()
                },
            },
        });
    }
    super::denial::append_native_decisions(&mut claims, &mut assurances);
    let bundle = ObservationBundleWire {
        schema_version: 1,
        request_digest: r.request_digest.clone(),
        collector_build_id: r.collector_build_id,
        started_at: r.started_at,
        finished_at: r.finished_at,
        capture_complete: false,
        claims,
        artifacts: vec![ArtifactRef {
            id: proof_id.clone(),
            sha256: proof_digest.clone(),
        }],
    };
    bundle.validate_shape().map_err(|_| SourceError::Invalid)?;
    let bytes = serde_json::to_vec(&bundle).map_err(|_| SourceError::Invalid)?;
    Ok(AwsCapture {
        verifier: AwsSourceVerifier {
            request_digest: r.request_digest,
            bundle_digest: crate::config::hash_bytes(&bytes),
            proof_digest,
            window: w,
            findings: VerifierFindings {
                recipe_id: "aws-ec2-host-network-root-v1".into(),
                source_evidence_refs: vec![proof_id.clone()],
                assurances,
            },
            used: false,
        },
        bundle: bytes,
        payloads: vec![EvidencePayload {
            id: proof_id,
            bytes: proof,
        }],
        window: w,
    })
}
pub(super) async fn response_for_request(
    i: &IssuedObservation,
    cancel: &CancellationToken,
) -> AwsCollectorResponse {
    #[cfg(not(target_os = "linux"))]
    let result: Result<AwsCollectorReply, SourceError> = {
        let _ = cancel;
        Err(SourceError::Unsupported)
    };
    #[cfg(target_os = "linux")]
    let result = {
        let remaining = i
            .request
            .expires_at
            .saturating_sub(crate::domain::now())
            .min(MAX_CAPTURE_SECONDS);
        if remaining == 0 {
            Err(SourceError::RequestExpired)
        } else {
            tokio::select! {biased;_=cancel.cancelled()=>Err(SourceError::Cancelled),r=tokio::time::timeout(std::time::Duration::from_secs(remaining),collect(i,cancel))=>r.unwrap_or(Err(SourceError::TimedOut))}
        }
    };
    match result {
        Ok(reply) => AwsCollectorResponse::Success {
            reply: Box::new(reply),
        },
        Err(e) => AwsCollectorResponse::Failure {
            request_digest: i.request.digest().unwrap_or_default(),
            code: CollectorFailure::from_error(e),
        },
    }
}
#[cfg(unix)]
async fn collect(
    i: &IssuedObservation,
    cancel: &CancellationToken,
) -> Result<AwsCollectorReply, SourceError> {
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    validate_registration(s)?;
    let bytes = collector::root_file(Path::new(COLLECTOR_CONFIG_PATH), 65536)?;
    if crate::config::hash_bytes(&bytes) != s.collector_config_digest {
        return Err(SourceError::Integrity);
    }
    let config: AwsCollectorConfig =
        serde_json::from_slice(&bytes).map_err(|_| SourceError::Invalid)?;
    config.validate_request(i)?;
    trusted_program(Path::new(COLLECTOR_PATH))?;
    let binary_digest = collector::file_digest(Path::new(COLLECTOR_PATH), 128 * 1024 * 1024)?;
    if binary_digest != s.aws_host.collector_binary_digest
        || crate::BUILD_ID != s.collector_build_id
    {
        return Err(SourceError::Integrity);
    }
    let started_at = crate::domain::now();
    let before = collector::host_context(cancel).await?;
    if before != config.context {
        return Err(SourceError::ContextUnverified);
    }
    let (document, signature) = metadata_identity(cancel).await?;
    let mut diagnostics = vec![];
    let mut postgres = vec![];
    let mut mysql = vec![];
    let mut iam_inventory = vec![];
    for c in &i.request.cases {
        if cancel.is_cancelled() {
            return Err(SourceError::Cancelled);
        }
        if c.kind == FixedObservationCase::DirectPath {
            let e = config
                .endpoints
                .iter()
                .find(|e| endpoint_matches(e, c))
                .ok_or(SourceError::Invalid)?;
            diagnostics.push(if e.ip.is_ipv4() {
                super::deferred_route::probe_diagnostic(
                    c,
                    e.ip,
                    s.native_identity.private_ip,
                    cancel,
                )
                .await?
            } else {
                collector::tcp_diagnostic(c, e.ip, cancel).await?
            });
        } else {
            let start = crate::domain::now();
            let pg = if let Some(pg) = &config.postgres {
                if c.address.target.engine_binding.family
                    == crate::core::policy::EngineFamily::PostgreSql
                    && matches!(
                        c.kind,
                        FixedObservationCase::NewConnection
                            | FixedObservationCase::TargetHealth
                            | FixedObservationCase::EffectiveSqlPrivilege
                            | FixedObservationCase::Transport
                    )
                {
                    Some(
                        super::aws_postgres::observe(
                            i,
                            c,
                            config
                                .endpoints
                                .iter()
                                .find(|e| endpoint_matches(e, c))
                                .ok_or(SourceError::Invalid)?,
                            pg,
                            cancel,
                        )
                        .await?,
                    )
                } else {
                    None
                }
            } else {
                None
            };
            let mysql_observation = if let Some(mysql_config) = &config.mysql {
                if c.address.target.engine_binding.family
                    == crate::core::policy::EngineFamily::MySql
                    && matches!(
                        c.kind,
                        FixedObservationCase::NewConnection
                            | FixedObservationCase::TargetHealth
                            | FixedObservationCase::EffectiveSqlPrivilege
                            | FixedObservationCase::Transport
                    )
                {
                    Some(
                        super::aws_mysql::observe(
                            i,
                            c,
                            config
                                .endpoints
                                .iter()
                                .find(|e| endpoint_matches(e, c))
                                .ok_or(SourceError::Invalid)?,
                            mysql_config,
                            cancel,
                        )
                        .await?,
                    )
                } else {
                    None
                }
            } else {
                None
            };
            let mysql_observed = mysql_observation.is_some();
            if let Some(observation) = mysql_observation {
                mysql.push(observation);
            }
            let observed = pg.is_some();
            if let Some(pg) = pg {
                postgres.push(pg);
            }
            if config.collect_iam_inventory
                && c.kind == FixedObservationCase::NewConnection
                && (observed || mysql_observed)
            {
                let target = config
                    .postgres
                    .as_ref()
                    .into_iter()
                    .flat_map(|p| &p.targets)
                    .chain(config.mysql.as_ref().into_iter().flat_map(|p| &p.targets))
                    .find(|t| t.target_id == c.address.target_id)
                    .ok_or(SourceError::Invalid)?;
                let budget = i
                    .request
                    .expires_at
                    .min(started_at + MAX_CAPTURE_SECONDS)
                    .saturating_sub(crate::domain::now())
                    .saturating_sub(5);
                if budget > 0
                    && let Ok(Ok(inventory)) = tokio::time::timeout(
                        std::time::Duration::from_secs(budget),
                        super::aws_iam_inventory::observe(i, c, target, cancel),
                    )
                    .await
                {
                    iam_inventory.push(inventory);
                }
            }
            let now = crate::domain::now();
            diagnostics.push(CaseDiagnostic {
                runtime_capture: None,
                runtime_failure: None,
                iam_inventory: None,
                case_id: c.id.clone(),
                started_at: start,
                finished_at: now,
                outcome: if observed {
                    DiagnosticOutcome::PostgresObserved
                } else if mysql_observed {
                    DiagnosticOutcome::MysqlObserved
                } else {
                    DiagnosticOutcome::UnsupportedCase
                },
                connection: None,
                postgres: None,
            });
        }
    }
    let after = collector::host_context(cancel).await?;
    if after != before {
        return Err(SourceError::ContextUnverified);
    }
    Ok(AwsCollectorReply {
        schema_version: 1,
        request_digest: i.request.digest().map_err(|_| SourceError::Invalid)?,
        collector_build_id: crate::BUILD_ID.into(),
        binary_digest,
        config_digest: crate::config::hash_bytes(&bytes),
        context_before: before,
        context_after: after,
        identity_document: document,
        identity_signature: signature,
        started_at,
        finished_at: crate::domain::now(),
        diagnostics,
        postgres,
        mysql,
        iam_inventory,
    })
}
pub(super) async fn metadata_identity(
    cancel: &CancellationToken,
) -> Result<(String, String), SourceError> {
    let token = metadata_request(MetadataRequest::Token, None, cancel).await?;
    let token = std::str::from_utf8(&token).map_err(|_| SourceError::IdentityUnverified)?;
    if token.is_empty() || token.len() > 4096 || token.bytes().any(|b| !(0x21..=0x7e).contains(&b))
    {
        return Err(SourceError::IdentityUnverified);
    }
    let doc = metadata_request(MetadataRequest::Document, Some(token), cancel).await?;
    let sig = metadata_request(MetadataRequest::Signature, Some(token), cancel).await?;
    Ok((
        String::from_utf8(doc).map_err(|_| SourceError::Invalid)?,
        String::from_utf8(sig).map_err(|_| SourceError::Invalid)?,
    ))
}
#[derive(Clone, Copy)]
pub(super) enum MetadataRequest<'a> {
    Token,
    Document,
    Signature,
    RoleName,
    RoleCredentials(&'a str),
}
fn metadata_wire(kind: MetadataRequest<'_>, token: Option<&str>) -> Result<String, SourceError> {
    let (method, path, header) = match kind {
        MetadataRequest::Token if token.is_none() => (
            "PUT",
            "/latest/api/token".to_owned(),
            "X-aws-ec2-metadata-token-ttl-seconds: 120\r\n".into(),
        ),
        MetadataRequest::Document
        | MetadataRequest::Signature
        | MetadataRequest::RoleName
        | MetadataRequest::RoleCredentials(_) => {
            let t = token.ok_or(SourceError::IdentityUnverified)?;
            if t.is_empty() || t.len() > 4096 || t.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
                return Err(SourceError::IdentityUnverified);
            }
            (
                "GET",
                match kind {
                    MetadataRequest::Document => {
                        "/latest/dynamic/instance-identity/document".to_owned()
                    }
                    MetadataRequest::Signature => {
                        "/latest/dynamic/instance-identity/signature".to_owned()
                    }
                    MetadataRequest::RoleName => {
                        "/latest/meta-data/iam/security-credentials/".to_owned()
                    }
                    MetadataRequest::RoleCredentials(role) => {
                        if role.is_empty()
                            || role.len() > 64
                            || !role
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
                        {
                            return Err(SourceError::Invalid);
                        }
                        format!("/latest/meta-data/iam/security-credentials/{role}")
                    }
                    _ => return Err(SourceError::Invalid),
                },
                format!("X-aws-ec2-metadata-token: {t}\r\n"),
            )
        }
        _ => return Err(SourceError::Invalid),
    };
    Ok(format!(
        "{method} {path} HTTP/1.1\r\nHost: 169.254.169.254\r\n{header}Content-Length: 0\r\nConnection: close\r\n\r\n"
    ))
}
pub(super) async fn metadata_request(
    kind: MetadataRequest<'_>,
    token: Option<&str>,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, SourceError> {
    let request = metadata_wire(kind, token)?;
    let work = async {
        // Fixed link-local destination; no proxy, DNS, redirects, env/SDK
        // credentials, arbitrary metadata path, or IMDSv1 fallback.
        let mut stream = TcpStream::connect((IpAddr::from([169, 254, 169, 254]), 80))
            .await
            .map_err(|_| SourceError::Unavailable)?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| SourceError::Unavailable)?;
        let mut bytes = vec![];
        stream
            .take(32769)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| SourceError::Unavailable)?;
        metadata_body(&bytes)
    };
    tokio::select! {biased;_=cancel.cancelled()=>Err(SourceError::Cancelled),r=tokio::time::timeout(std::time::Duration::from_secs(5),work)=>r.unwrap_or(Err(SourceError::TimedOut))}
}
fn metadata_body(bytes: &[u8]) -> Result<Vec<u8>, SourceError> {
    if bytes.len() > 32768 {
        return Err(SourceError::Limit);
    }
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(SourceError::Invalid)?;
    if split > 8192 {
        return Err(SourceError::Limit);
    }
    let header = std::str::from_utf8(&bytes[..split]).map_err(|_| SourceError::Invalid)?;
    let mut lines = header.split("\r\n");
    if !lines
        .next()
        .is_some_and(|s| matches!(s, "HTTP/1.1 200 OK" | "HTTP/1.0 200 OK"))
    {
        return Err(SourceError::IdentityUnverified);
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(SourceError::Invalid)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(SourceError::Invalid);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(SourceError::Invalid);
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| SourceError::Invalid)?,
            );
        }
    }
    let body = &bytes[split + 4..];
    if body.is_empty() || Some(body.len()) != length || body.len() > 16384 {
        return Err(SourceError::IdentityUnverified);
    }
    Ok(body.to_vec())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(crate) fn fixture() -> (IssuedObservation, AwsCollectorConfig) {
        let (mut i, c) = super::super::testsupport::fixture();
        let g = i.snapshot.gce().unwrap();
        let s = AwsSourceRegistrationSnapshot {
            schema_version: 1,
            registration_id: g.registration_id.clone(),
            trust_epoch: 1,
            native_identity: AwsEc2Identity {
                account_id: "123456789012".into(),
                region: "ap-northeast-1".into(),
                availability_zone: "ap-northeast-1a".into(),
                instance_id: "i-0123456789abcdef0".into(),
                image_id: "ami-0123456789abcdef0".into(),
                pending_time: "2026-11-03T00:00:00Z".into(),
                private_ip: "10.0.0.10".parse().unwrap(),
            },
            ssh_host_key_digest: g.ssh_host_key_digest.clone(),
            collector_build_id: g.collector_build_id.clone(),
            collector_config_digest: g.collector_config_digest.clone(),
            network_context_digest: c.context.aws_digest().unwrap(),
            execution_user: "root".into(),
            aws_host: AwsHostProfile {
                ssh_ip: "192.0.2.10".parse().unwrap(),
                ssh_port: 22,
                host_key_ed25519_base64: g
                    .gce_host
                    .as_ref()
                    .unwrap()
                    .host_key_ed25519_base64
                    .clone(),
                collector_binary_digest: "f".repeat(64),
                execution_uid: 0,
            },
            metadata_credential: None,
        };
        i.snapshot = s.into();
        i.request.source.boundary = SourceBoundaryKind::AwsHostNetwork;
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        let p = crate::core::policy::parse_policy(include_str!(
            "../../../examples/core-aws-policy.yaml"
        ))
        .unwrap();
        let t = &p.targets[0];
        let a = &mut i.request.cases[0].address;
        a.source = i.request.source.snapshot_ref();
        a.target.native_ref = t.resource.clone();
        a.target.native_ref.generation_fingerprint =
            Some(crate::core::policy::aws_generation_fingerprint(
                &t.placement.account_id,
                &t.placement.region,
                &t.resource.native_id,
                &t.aws.as_ref().unwrap().db_resource_id,
            ));
        a.target.placement = t.placement.clone();
        a.target.engine_binding = t.engine.clone();
        let mut config = AwsCollectorConfig {
            schema_version: 1,
            registration_id: c.registration_id,
            context: c.context,
            endpoints: c.endpoints,
            postgres: None,
            postgres_runtime: None,
            mysql: None,
            collect_iam_inventory: false,
        };
        config.endpoints[0].native_id = a.target.native_ref.native_id.clone();
        config.endpoints[0].generation_digest =
            a.target.native_ref.generation_fingerprint.clone().unwrap();
        let s = match &mut i.snapshot {
            RegisteredSourceSnapshot::Aws(s) => s,
            _ => unreachable!(),
        };
        s.collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        i.request.cases[0].address.source = i.request.source.snapshot_ref();
        (i, config)
    }
    fn reply(i: &IssuedObservation, c: &AwsCollectorConfig) -> (Vec<u8>, AwsCollectorReply) {
        let s = i.snapshot.aws().unwrap();
        let (key, doc, sig) = super::super::aws_iid::test_identity(&s.native_identity);
        (
            key,
            AwsCollectorReply {
                schema_version: 1,
                request_digest: i.request.digest().unwrap(),
                collector_build_id: s.collector_build_id.clone(),
                binary_digest: s.aws_host.collector_binary_digest.clone(),
                config_digest: s.collector_config_digest.clone(),
                context_before: c.context.clone(),
                context_after: c.context.clone(),
                identity_document: doc,
                identity_signature: sig,
                started_at: 110,
                finished_at: 115,
                postgres: vec![],
                mysql: vec![],
                iam_inventory: vec![],
                diagnostics: i
                    .request
                    .cases
                    .iter()
                    .map(|c| CaseDiagnostic {
                        runtime_capture: None,
                        runtime_failure: None,
                        iam_inventory: None,
                        case_id: c.id.clone(),
                        started_at: 111,
                        finished_at: 114,
                        outcome: DiagnosticOutcome::TcpRefused,
                        connection: None,
                        postgres: None,
                    })
                    .collect(),
            },
        )
    }
    fn window() -> CaptureWindow {
        CaptureWindow {
            sent_at: 110,
            received_at: 115,
            elapsed_millis: 5000,
        }
    }
    fn checked(
        i: &IssuedObservation,
        r: AwsCollectorReply,
        key: &[u8],
    ) -> Result<AwsCapture, SourceError> {
        verify_reply_using(i, r, window(), 116, |d, s, e, _| {
            super::super::aws_iid::verify_test_key(d, s, e, key)
        })
    }
    #[test]
    fn ec2_capture_proves_only_source_and_temporal_and_is_one_use_request_bound() {
        let (i, c) = fixture();
        c.validate_request(&i).unwrap();
        let (key, r) = reply(&i, &c);
        let raw_sig = r.identity_signature.clone();
        let mut capture = checked(&i, r, &key).unwrap();
        let bundle = ObservationBundleWire::parse_untrusted(&capture.bundle).unwrap();
        assert_eq!(bundle.claims[0].observed, StateValue::Unknown);
        assert!(bundle.claims[0].denial_cause.is_none());
        let proof = std::str::from_utf8(&capture.payloads[0].bytes).unwrap();
        assert!(!proof.contains(&raw_sig));
        assert!(!proof.contains("identity_document\""));
        assert!(!proof.contains("identity_signature\""));
        let mut other = i.clone();
        other.request.nonce = "d".repeat(64);
        assert!(
            capture
                .verifier
                .verify(&other, &bundle, &capture.payloads, capture.window)
                .is_err()
        );
        let findings = capture
            .verifier
            .verify(&i, &bundle, &capture.payloads, capture.window)
            .unwrap();
        let a = &findings.assurances[0].coverage;
        assert!(matches!(a.source, Assurance::Verified { .. }));
        assert!(matches!(a.temporal, Assurance::Verified { .. }));
        for v in [&a.target, &a.principal, &a.route, &a.transport] {
            assert!(!matches!(v, Assurance::Verified { .. }));
        }
        assert!(
            capture
                .verifier
                .verify(&i, &bundle, &capture.payloads, capture.window)
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(&i.snapshot).unwrap().get("gce_host"),
            None
        );
        assert!(super::super::gce_host::validate_registration(&i.snapshot).is_err());
    }
    #[test]
    fn signed_iid_cannot_override_request_context_binary_times_or_diagnostics() {
        let (i, c) = fixture();
        for n in 0..10 {
            let (key, mut r) = reply(&i, &c);
            match n {
                0 => r.request_digest = "f".repeat(64),
                1 => r.binary_digest = "a".repeat(64),
                2 => r.context_after.route_v4_digest = "f".repeat(64),
                3 => r.context_before.uid = 1,
                4 => r.config_digest = "a".repeat(64),
                5 => r.started_at = 99,
                6 => r.finished_at = 221,
                7 => r.diagnostics[0].case_id = "foreign".into(),
                8 => r.diagnostics[0].outcome = DiagnosticOutcome::TcpConnected,
                _ => r.identity_document.push(' '),
            };
            assert!(checked(&i, r, &key).is_err(), "{n}");
        }
    }
    #[test]
    fn signed_aws_pg_capture_connects_to_durable_admission_without_raw_iid_or_credentials() {
        durable_admission_lab(false, false, false, false);
    }
    #[test]
    fn signed_aws_mysql_capture_connects_to_durable_admission_without_raw_iid_or_credentials() {
        durable_admission_lab(true, false, false, false);
    }
    #[test]
    fn signed_mysql_absence_survives_admission_and_remains_a_failed_requested_grant() {
        durable_admission_lab(true, true, false, false);
    }
    #[test]
    fn signed_managed_backend_pg_capture_satisfies_only_the_explicit_transport_row() {
        durable_admission_lab(false, false, true, false);
    }
    #[test]
    fn signed_managed_backend_mysql_capture_satisfies_only_the_explicit_transport_row() {
        durable_admission_lab(true, false, true, false);
    }
    #[test]
    fn signed_aws_bounded_iam_inventory_survives_durable_admission_without_permission_promotion() {
        durable_admission_lab(false, false, false, true);
        durable_admission_lab(true, false, false, true);
    }
    fn durable_admission_lab(mysql: bool, absence: bool, managed_tls: bool, iam: bool) {
        use crate::{
            adapters::evidence::RunEvidenceArchive,
            core::{
                change::{OperationLimits, prepare_change},
                plan::build_plan,
                policy::*,
                ports::EvidenceClock,
            },
            evidence_store::{EvidenceStore, ObservationRequestSpec},
        };
        let (mut fixture, mut config, pg, mut mysql_observation) = if mysql {
            let (i, c, m) = if absence {
                super::super::aws_mysql::tests::absence_sample()
            } else {
                super::super::aws_mysql::tests::sample()
            };
            (i, c, None, Some(m))
        } else {
            let (i, c, p) = super::super::aws_postgres::tests::sample();
            (i, c, Some(p), None)
        };
        if managed_tls {
            if let Some(raw) = &mut mysql_observation {
                super::super::aws_mysql::enable_backend_tls_for_test(
                    &mut fixture,
                    &mut config,
                    raw,
                );
            }
            let c = &mut fixture.request.cases[0];
            c.kind = FixedObservationCase::Transport;
            c.address.effect = EffectKindV2::Transport {
                segment: TransportSegment::NativeRouteToDatabase,
            };
            c.backend_tls_trust = Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1);
        }
        if iam {
            config.collect_iam_inventory = true;
            let snapshot = match &mut fixture.snapshot {
                RegisteredSourceSnapshot::Aws(s) => s,
                _ => unreachable!(),
            };
            snapshot.collector_config_digest =
                crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap());
            fixture.request.source.revision_digest = fixture.snapshot.revision_digest().unwrap();
            for c in &mut fixture.request.cases {
                c.address.source = fixture.request.source.snapshot_ref();
            }
        }
        let mut policy = parse_policy(if mysql {
            include_str!("../../../examples/core-aws-mysql-policy.yaml")
        } else {
            include_str!("../../../examples/core-aws-policy.yaml")
        })
        .unwrap();
        policy.schema_version = 2;
        if managed_tls {
            policy.protection_profiles[0].encryption =
                EncryptionRequirement::VerifiedTlsWithAwsRdsProxyManagedBackendV1;
        }
        policy.targets[0].resource = fixture.request.cases[0].address.target.native_ref.clone();
        policy.source_bindings = policy
            .subjects
            .iter()
            .enumerate()
            .map(|(n, s)| {
                if n == 0 {
                    fixture.request.source.clone()
                } else {
                    SourceBinding {
                        source_id: s.workload_sources[0].clone(),
                        registration_id: "aws-recovery-source".into(),
                        revision_digest: "b".repeat(64),
                        boundary: SourceBoundaryKind::AwsHostNetwork,
                        allowed_uses: vec![SourceUse {
                            subject_id: s.id.clone(),
                            purpose: SourcePurpose::Recovery,
                        }],
                    }
                }
            })
            .collect();
        policy.evaluation = Some(EvaluationPolicy {
            contract: EvaluationContract::SourceBoundV2,
            denial_requirements: vec![ProfileDenialRequirement {
                profile_id: policy.protection_profiles[0].id.clone(),
                accepted_layers: vec![AcceptedDenialLayer::ConnectionAuthorization],
            }],
        });
        let plan = build_plan(
            &policy,
            crate::adapters::capabilities_for_policy(&policy).unwrap(),
            vec![],
            100,
        )
        .unwrap();
        let change = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = EvidenceStore::open(&dir.path().join("ledger.sqlite3")).unwrap();
        ledger.register_source(&fixture.snapshot, None).unwrap();
        ledger
            .start_session(&change, "observation-session", 100)
            .unwrap();
        let mut wrong_cases = fixture.request.cases.clone();
        wrong_cases[0].endpoint = "alternate.proxy-example.ap-northeast-1.rds.amazonaws.com".into();
        assert!(matches!(
            ledger.issue_request(
                &ObservationRequestSpec {
                    request_id: "alternate".into(),
                    operation_id: "observation-session".into(),
                    source_id: fixture.request.source.source_id.clone(),
                    ttl_seconds: 120,
                    cases: wrong_cases
                },
                100
            ),
            Err(AdmissionError::ScopeMismatch)
        ));
        assert!(matches!(
            ledger.issued("alternate"),
            Err(AdmissionError::NotFound)
        ));
        let i = ledger
            .issue_request(
                &ObservationRequestSpec {
                    request_id: "aws-capture".into(),
                    operation_id: "observation-session".into(),
                    source_id: fixture.request.source.source_id.clone(),
                    ttl_seconds: 120,
                    cases: fixture.request.cases.clone(),
                },
                100,
            )
            .unwrap();
        let (key, mut r) = reply(&i, &config);
        let raw_signature = r.identity_signature.clone();
        r.diagnostics[0].outcome = if mysql {
            DiagnosticOutcome::MysqlObserved
        } else {
            DiagnosticOutcome::PostgresObserved
        };
        r.postgres = pg.into_iter().collect();
        r.mysql = mysql_observation.into_iter().collect();
        if iam {
            let t = if mysql {
                &config.mysql.as_ref().unwrap().targets[0]
            } else {
                &config.postgres.as_ref().unwrap().targets[0]
            };
            r.iam_inventory
                .push(super::super::aws_iam_inventory::fixture_for_capture(
                    &i,
                    &i.request.cases[0],
                    t,
                ));
        }
        let mut capture = checked(&i, r, &key).unwrap();
        let archives = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(archives.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let mut archive = RunEvidenceArchive::open(archives.path()).unwrap();
        struct Clock;
        impl EvidenceClock for Clock {
            fn now(&self) -> u64 {
                116
            }
        }
        let receipt = accept_evidence(
            &mut ledger,
            &mut archive,
            &mut capture.verifier,
            "aws-capture",
            &capture.bundle,
            &capture.payloads,
            capture.window,
            &Clock,
        )
        .unwrap();
        assert_eq!(receipt.verification_recipe, "aws-ec2-host-network-root-v1");
        let facts = load_admitted(&mut ledger, &archive, "aws-capture", 117).unwrap();
        assert_eq!(
            facts.claims()[0].observed,
            if absence {
                StateValue::Absent
            } else if managed_tls {
                StateValue::Present
            } else {
                StateValue::Allowed
            }
        );
        if iam {
            let inventory = facts
                .claims()
                .iter()
                .find(|c| c.permission_inventory.is_some())
                .unwrap();
            assert_eq!(inventory.observed, StateValue::Unknown);
            assert!(inventory.denial_cause.is_none());
            assert_eq!(
                inventory.permission_inventory.as_ref().unwrap(),
                &NativePermissionInventory {
                    complete: true,
                    permissions: vec!["rds-db:connect".into()]
                }
            );
        }
        if absence {
            assert!(
                facts.claims()[0]
                    .sql_context
                    .as_ref()
                    .unwrap()
                    .permission_inventory_complete
            );
        }
        let proof = std::str::from_utf8(&capture.payloads[0].bytes).unwrap();
        assert!(!proof.contains(&raw_signature));
        assert!(!proof.contains("AccessKeyId"));
        assert!(!proof.contains("SecretAccessKey"));
        let report =
            evaluate_admitted_change(&mut ledger, &archive, &change, &["aws-capture".into()], 117)
                .unwrap();
        assert!(!report.all_required_effects_satisfied);
        if managed_tls {
            let row = report
                .rows
                .iter()
                .find(|r| r.desired.address == facts.claims()[0].address)
                .unwrap();
            assert_eq!(
                row.assessment,
                crate::core::state::StateAssessment::Satisfied
            );
            assert_eq!(
                row.desired.backend_tls_trust,
                Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1)
            );
            let transport = &facts.claims()[0].transport[0];
            assert_eq!(transport.ca_verified, None);
            assert_eq!(transport.hostname_verified, None);
            assert_eq!(transport.validation_basis, row.desired.backend_tls_trust);
        }
        if absence {
            let row = report
                .rows
                .iter()
                .find(|r| r.desired.address == facts.claims()[0].address)
                .unwrap();
            assert_eq!(row.observed, StateValue::Absent);
            assert_eq!(
                row.assessment,
                crate::core::state::StateAssessment::NeedsAction
            );
        }
        let mut alias = fixture.snapshot.aws().unwrap().clone();
        alias.registration_id = "recovery-alias".into();
        assert!(matches!(
            ledger.register_source(&alias, None),
            Err(AdmissionError::ScopeMismatch)
        ));
        let mut rotated = fixture.snapshot.aws().unwrap().clone();
        rotated.trust_epoch += 1;
        let digest = fixture.snapshot.revision_digest().unwrap();
        ledger.register_source(&rotated, Some(&digest)).unwrap();
        assert!(matches!(
            load_admitted(&mut ledger, &archive, "aws-capture", 117),
            Err(AdmissionError::TrustChanged)
        ));
    }
    #[test]
    fn registered_union_preserves_gce_wire_hash_and_keeps_provider_specific_identity() {
        let (gce, _) = super::super::testsupport::fixture();
        let legacy = gce.snapshot.gce().unwrap();
        assert_eq!(
            serde_json::to_vec(legacy).unwrap(),
            serde_json::to_vec(&gce.snapshot).unwrap()
        );
        assert_eq!(
            legacy.revision_digest().unwrap(),
            gce.snapshot.revision_digest().unwrap()
        );
        let (aws, _) = fixture();
        let json = serde_json::to_value(&aws.snapshot).unwrap();
        assert!(json.get("gce_host").is_none());
        assert!(json["native_identity"].get("service_account").is_none());
        assert!(serde_json::from_value::<SourceRegistrationSnapshot>(json).is_err());
    }
    #[test]
    fn orphan_postgres_records_cannot_enter_the_selected_source_proof() {
        let (i, c) = fixture();
        let (key, mut r) = reply(&i, &c);
        let (_, _, mut pg) = super::super::aws_postgres::tests::sample();
        pg.case_id = "orphan".into();
        r.postgres = vec![pg];
        assert!(checked(&i, r, &key).is_err());
    }
    #[test]
    fn orphan_mysql_records_and_engine_swapped_diagnostics_cannot_enter_durable_proof() {
        let (i, c) = fixture();
        let (key, mut r) = reply(&i, &c);
        let (_, _, mut mysql) = super::super::aws_mysql::tests::sample();
        mysql.case_id = "orphan".into();
        r.mysql = vec![mysql];
        assert!(checked(&i, r, &key).is_err());
        let (i, c, mysql) = super::super::aws_mysql::tests::sample();
        let (key, mut r) = reply(&i, &c);
        r.mysql = vec![mysql];
        r.diagnostics[0].outcome = DiagnosticOutcome::PostgresObserved;
        assert!(checked(&i, r, &key).is_err());
    }
    #[test]
    fn legacy_mysql_source_only_request_without_account_host_never_upgrades_principal() {
        let (mut i, mut c, _) = super::super::aws_mysql::tests::sample();
        i.request.cases[0].mysql_account_host = None;
        c.mysql = None;
        let snapshot = match &mut i.snapshot {
            RegisteredSourceSnapshot::Aws(s) => s,
            _ => unreachable!(),
        };
        snapshot.metadata_credential = None;
        snapshot.collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&c).unwrap());
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        i.request.cases[0].address.source = i.request.source.snapshot_ref();
        c.validate_request(&i).unwrap();
        let (key, mut r) = reply(&i, &c);
        r.diagnostics[0].outcome = DiagnosticOutcome::UnsupportedCase;
        let mut capture = checked(&i, r, &key).unwrap();
        let bundle = ObservationBundleWire::parse_untrusted(&capture.bundle).unwrap();
        let findings = capture
            .verifier
            .verify(&i, &bundle, &capture.payloads, capture.window)
            .unwrap();
        assert_eq!(bundle.claims[0].observed, StateValue::Unknown);
        assert!(matches!(
            findings.assurances[0].coverage.principal,
            Assurance::Unconfirmed { .. }
        ));
        assert!(matches!(
            findings.assurances[0].coverage.completeness,
            Assurance::Unsupported { .. }
        ));
    }
    #[test]
    fn metadata_v2_has_fixed_origins_no_fallback_and_rejects_http_smuggling() {
        assert!(metadata_wire(MetadataRequest::Document, None).is_err());
        assert!(metadata_wire(MetadataRequest::Token, Some("token")).is_err());
        assert!(metadata_wire(MetadataRequest::Signature, Some("token\r\nheader: value")).is_err());
        let wire = metadata_wire(MetadataRequest::Token, None).unwrap();
        assert!(wire.starts_with("PUT /latest/api/token "));
        assert!(wire.contains("ttl-seconds: 120"));
        let wire =
            metadata_wire(MetadataRequest::Signature, Some("PRIVATE_TOKEN_SENTINEL")).unwrap();
        assert!(wire.starts_with("GET /latest/dynamic/instance-identity/signature "));
        assert!(!wire.contains("rsa2048"));
        let good = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        assert_eq!(metadata_body(good).unwrap(), b"abc");
        for bad in [
            b"HTTP/1.1 302 Found\r\nContent-Length: 3\r\n\r\nabc".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc",
        ] {
            assert!(metadata_body(bad).is_err());
        }
    }
    #[tokio::test]
    async fn permission_cancel_expiry_precede_ssh_io_and_profile_does_not_reuse_gce() {
        let (i, _) = fixture();
        let access = SshAccess {
            identity_file: "/nonexistent/key".into(),
            work_directory: "/nonexistent/work".into(),
        };
        assert!(matches!(
            capture_aws_source(&i, &access, &CancellationToken::new(), false).await,
            Err(SourceError::PermissionRequired)
        ));
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(matches!(
            capture_aws_source(&i, &access, &cancel, true).await,
            Err(SourceError::Cancelled)
        ));
        assert!(matches!(
            capture_aws_source(&i, &access, &CancellationToken::new(), true).await,
            Err(SourceError::RequestExpired)
        ));
    }
}
