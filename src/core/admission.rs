//! Bounded evidence admission. These pure checks and port orchestration do not
//! perform native verification, open files or read credentials themselves.
use super::{
    change::PreparedChange,
    evidence::*,
    policy::{DirectPathPolicy, IdentityProvider, RouteKind, valid_hash, valid_id},
    ports::{EvidenceArchive, EvidenceClock, EvidenceLedger, ObservationVerifier},
    source::{RegisteredSourceSnapshot, SourcePurpose},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_ACTIVE_REQUESTS: usize = 16;
pub const MAX_SOURCE_REGISTRATIONS: usize = 128;
pub const MAX_EVIDENCE_RECORD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    #[error("EVIDENCE_ADMISSION_INVALID: invalid or incompatible admission input")]
    Invalid,
    #[error("EVIDENCE_SCOPE_MISMATCH: request or capture differs from the registered scope")]
    ScopeMismatch,
    #[error("EVIDENCE_ADMISSION_CONFLICT: request, nonce or immutable record already exists")]
    Conflict,
    #[error("EVIDENCE_NOT_ADMITTED: no local admission exists")]
    NotFound,
    #[error("EVIDENCE_EXPIRED: original request or observation validity has elapsed")]
    Expired,
    #[error("EVIDENCE_TRUST_CHANGED: source trust epoch or approved build has changed")]
    TrustChanged,
    #[error("EVIDENCE_INTEGRITY_ERROR: admitted files or ledger references are inconsistent")]
    Integrity,
    #[error("EVIDENCE_ADMISSION_LIMIT: local admission quota exceeded")]
    Limit,
    #[error("EVIDENCE_STORAGE_ERROR: local evidence storage failed")]
    Storage,
    #[error("EVIDENCE_VERIFIER_UNAVAILABLE: native source verification is not implemented")]
    VerifierUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedObservation {
    pub request: ObservationRequest,
    pub snapshot: RegisteredSourceSnapshot,
}

/// Captured by the controller around the actual call, not deserialized from the
/// remote wire. Wall-clock/monotonic agreement constrains remote timestamps.
#[derive(Debug, Clone, Copy)]
pub struct CaptureWindow {
    pub sent_at: u64,
    pub received_at: u64,
    pub elapsed_millis: u64,
}

/// Already selected/redacted artifacts supplied to the trusted verifier. No
/// token/credential payload belongs here. This is not an external import API.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePayload {
    pub id: String,
    pub bytes: Vec<u8>,
}
impl std::fmt::Debug for EvidencePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidencePayload")
            .field("id", &self.id)
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

/// Output only of trusted, statically composed Rust verification code. It is
/// intentionally not Deserialize and is never accepted from a config/verdict.
#[derive(Debug, Clone)]
pub struct VerifierFindings {
    pub recipe_id: String,
    pub source_evidence_refs: Vec<String>,
    pub assurances: Vec<ClaimAssurance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArchiveRef {
    pub run_id: String,
    pub manifest_digest: String,
    pub bundle_digest: String,
    pub request_digest: String,
}

/// A local receipt read through EvidenceLedger, not a portable attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAdmission {
    pub schema_version: u32,
    pub id: String,
    pub request_digest: String,
    pub bundle_digest: String,
    pub policy_revision_hash: String,
    pub change_hash: String,
    pub operation_id: String,
    pub source_snapshot_digest: String,
    pub source_trust_epoch: u64,
    pub collector_build_id: String,
    pub verifier_build_id: String,
    pub evaluation_contract: EvaluationContract,
    pub verification_recipe: String,
    pub source_evidence_refs: Vec<String>,
    pub accepted_at: u64,
    pub valid_until: u64,
    pub capture_started_at: u64,
    pub capture_finished_at: u64,
    pub assurances: Vec<ClaimAssurance>,
    pub archive: EvidenceArchiveRef,
}

/// No public fields, Deserialize or public constructor: this ticket is minted
/// after scope/time/artifact checks and the trusted verifier call. It conveys
/// no authority to modify a DB or to declare all policy effects satisfied.
///
/// ```compile_fail
/// use veil_db_guard::core::admission::VerifiedCandidate;
/// let _: VerifiedCandidate = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedCandidate {
    admission: EvidenceAdmission,
}
impl VerifiedCandidate {
    pub fn admission(&self) -> &EvidenceAdmission {
        &self.admission
    }
}

pub fn validate_issued(issued: &IssuedObservation) -> Result<(), AdmissionError> {
    let r = &issued.request;
    r.validate().map_err(|_| AdmissionError::Invalid)?;
    if !issued
        .snapshot
        .matches_binding(&r.source)
        .map_err(|_| AdmissionError::Invalid)?
        || issued.snapshot.trust_epoch() != r.source_trust_epoch
        || issued.snapshot.collector_build_id() != r.collector_build_id
    {
        return Err(AdmissionError::TrustChanged);
    }
    Ok(())
}

/// Check declaration binding for the initial metadata-only source profile.
/// This does not authenticate the VM, credential, or collector at runtime.
pub fn validate_source_actor_binding(
    issued: &IssuedObservation,
    change: &PreparedChange,
) -> Result<(), AdmissionError> {
    validate_issued(issued)?;
    // EC2 IID attests the instance, never its IAM role or credential actor.
    // Until a separate STS/IMDS credential recipe exists, only the declared
    // provider is checked for AWS; principal assurance remains Unknown.
    for case in &issued.request.cases {
        let subject = change
            .policy
            .subjects
            .iter()
            .find(|s| s.id == case.address.subject_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        match &issued.snapshot {
            RegisteredSourceSnapshot::Gce(snapshot) => {
                if subject.identity.provider != IdentityProvider::Gcp
                    || subject.identity.principal != snapshot.native_identity.service_account
                    || subject.identity.immutable_id.as_deref()
                        != Some(snapshot.native_identity.service_account_id.as_str())
                    || subject.identity.credential_source.kind
                        != super::policy::CredentialSourceKind::WorkloadIdentity
                    || subject.identity.credential_source.reference != snapshot.credential_reference
                {
                    return Err(AdmissionError::ScopeMismatch);
                }
            }
            RegisteredSourceSnapshot::Aws(snapshot) => {
                if subject.identity.provider != IdentityProvider::Aws {
                    return Err(AdmissionError::ScopeMismatch);
                }
                if let Some(c) = &snapshot.metadata_credential
                    && (subject.identity.principal != c.role_arn
                        || subject.identity.immutable_id.as_deref() != Some(c.role_id.as_str())
                        || subject.identity.credential_source.kind
                            != super::policy::CredentialSourceKind::WorkloadIdentity
                        || subject.identity.credential_source.reference != c.credential_reference)
                {
                    return Err(AdmissionError::ScopeMismatch);
                }
            }
        }
    }
    Ok(())
}

/// Bind each fixed case to the exact immutable, reviewed policy. Endpoint
/// authenticity and native denial recipes remain the source verifier's work.
pub fn validate_request_scope(
    r: &ObservationRequest,
    change: &PreparedChange,
) -> Result<(), AdmissionError> {
    r.validate().map_err(|_| AdmissionError::Invalid)?;
    change.verify().map_err(|_| AdmissionError::Invalid)?;
    let p = &change.policy;
    if p.schema_version != 2
        || r.change_hash != change.change_hash
        || r.policy_revision_hash != change.plan.policy_revision_hash
        || !p.source_bindings.contains(&r.source)
        || p.evaluation.as_ref().map(|e| e.contract) != Some(r.evaluation_contract)
    {
        return Err(AdmissionError::ScopeMismatch);
    }
    for c in &r.cases {
        if !super::postgres_login::validate_catalog_request(p, c) {
            return Err(AdmissionError::ScopeMismatch);
        }
        let a = &c.address;
        let grant = p
            .grants
            .iter()
            .find(|g| g.id == a.grant_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let target = p
            .targets
            .iter()
            .find(|t| t.id == grant.target)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let subject = p
            .subjects
            .iter()
            .find(|s| s.id == a.subject_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let profile = p
            .protection_profiles
            .iter()
            .find(|v| v.id == grant.profile)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let expected_backend_trust = if a.effect
            == (EffectKindV2::Transport {
                segment: TransportSegment::NativeRouteToDatabase,
            }) {
            profile.encryption.backend_tls_trust()
        } else {
            None
        };
        if c.backend_tls_trust != expected_backend_trust {
            return Err(AdmissionError::ScopeMismatch);
        }
        if a.target_id != target.id
            || a.target.registration_id != target.registration_id
            || a.target.native_ref != target.resource
            || a.target.placement != target.placement
            || a.target.engine_binding != target.engine
            || target.resource.generation_fingerprint.is_none()
            || subject.identity.immutable_id.is_none()
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        if target.placement.kind == super::policy::PlacementKind::AwsRds {
            let aws = target.aws.as_ref().ok_or(AdmissionError::ScopeMismatch)?;
            let expected = if c.kind == FixedObservationCase::DirectPath {
                &aws.db_endpoint
            } else {
                &aws.proxy_endpoint
            };
            let port = match target.engine.family {
                super::policy::EngineFamily::PostgreSql => 5432,
                super::policy::EngineFamily::MySql => 3306,
                _ => return Err(AdmissionError::ScopeMismatch),
            };
            if target.engine.family == super::policy::EngineFamily::MySql {
                let mysql = target.mysql.as_ref().ok_or(AdmissionError::ScopeMismatch)?;
                let host = if c.purpose == SourcePurpose::Recovery {
                    &mysql.management_account_host
                } else {
                    &mysql.account_host
                };
                if c.mysql_account_host.as_ref() != Some(host) {
                    return Err(AdmissionError::ScopeMismatch);
                }
            } else if c.mysql_account_host.is_some() {
                return Err(AdmissionError::ScopeMismatch);
            }
            if &c.endpoint != expected || c.port != port {
                return Err(AdmissionError::ScopeMismatch);
            }
        }
        let recovery = c.purpose != SourcePurpose::Application
            && matches!(
                c.kind,
                FixedObservationCase::TargetHealth | FixedObservationCase::Transport
            )
            && profile.management_exceptions.iter().any(|e| {
                e.recovery
                    && e.subject == subject.id
                    && e.source_ids.contains(&r.source.source_id)
                    && e.route_id == a.route.id
            });
        if !recovery && (a.subject_id != grant.subject || a.db_identity != grant.db_identity) {
            return Err(AdmissionError::ScopeMismatch);
        }
        if recovery
            && match subject.identity.provider {
                IdentityProvider::Gcp => {
                    subject
                        .identity
                        .principal
                        .strip_suffix(".gserviceaccount.com")
                        != Some(a.db_identity.as_str())
                }
                IdentityProvider::Aws => target
                    .aws
                    .as_ref()
                    .is_none_or(|b| b.management_db_identity != a.db_identity),
                _ => true,
            }
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        let sql_intent = if grant.admission == super::policy::AdmissionIntent::Deny {
            change
                .previous_policy
                .as_ref()
                .and_then(|p| p.grants.iter().find(|g| g.id == grant.id))
                .map(|g| &g.sql_access)
                .unwrap_or(&grant.sql_access)
        } else {
            &grant.sql_access
        };
        match &a.effect {
            EffectKindV2::EffectiveSqlPrivilege { scope, action }
                if !sql_intent
                    .privileges
                    .iter()
                    .any(|p| p.scope == *scope && p.actions.contains(action)) =>
            {
                return Err(AdmissionError::ScopeMismatch);
            }
            EffectKindV2::EffectiveSqlRole { role }
                if !sql_intent.existing_roles.contains(role) =>
            {
                return Err(AdmissionError::ScopeMismatch);
            }
            EffectKindV2::OwnedSqlDelta { .. }
                if grant.admission != super::policy::AdmissionIntent::Deny
                    || !profile
                        .required_effects
                        .contains(&super::policy::EffectKind::SqlPrivilegesRevoked) =>
            {
                return Err(AdmissionError::ScopeMismatch);
            }
            EffectKindV2::RuntimeBinding
                if !profile
                    .required_effects
                    .contains(&super::policy::EffectKind::BindingApplied) =>
            {
                return Err(AdmissionError::ScopeMismatch);
            }
            _ => (),
        }
        // First source registry profile has one metadata principal. Native SDK
        // fallback or using a recovery SA as the application's actor is absent.
        if !matches!(
            (subject.identity.provider, r.source.boundary),
            (
                IdentityProvider::Gcp,
                super::source::SourceBoundaryKind::GceHostNetwork
            ) | (
                IdentityProvider::Aws,
                super::source::SourceBoundaryKind::AwsHostNetwork
            )
        ) || !subject.workload_sources.contains(&r.source.source_id)
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        let route = profile.allowed_routes.iter().any(|route| {
            route.id == a.route.id
                && route.kind == a.route.kind
                && route.source_ids.contains(&r.source.source_id)
        });
        let direct = c.purpose == SourcePurpose::Application
            && c.kind == FixedObservationCase::DirectPath
            && a.route.id == "application-direct"
            && a.route.kind == RouteKind::Direct
            && matches!(profile.application_direct_path, DirectPathPolicy::Deny);
        if !route && !direct {
            return Err(AdmissionError::ScopeMismatch);
        }
        if c.kind == FixedObservationCase::DirectPath && !direct {
            return Err(AdmissionError::ScopeMismatch);
        }
    }
    Ok(())
}

pub fn validate_payloads(
    bundle: &ObservationBundleWire,
    payloads: &[EvidencePayload],
) -> Result<(), AdmissionError> {
    if payloads.len() != bundle.artifacts.len() || payloads.len() > 128 {
        return Err(AdmissionError::Integrity);
    }
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    for p in payloads {
        total = total.saturating_add(p.bytes.len());
        if total > MAX_BUNDLE_BYTES {
            return Err(AdmissionError::Limit);
        }
        if !seen.insert(&p.id)
            || !bundle
                .artifacts
                .iter()
                .any(|a| a.id == p.id && a.sha256 == super::hash_bytes(&p.bytes))
        {
            return Err(AdmissionError::Integrity);
        }
    }
    Ok(())
}

fn validate_findings(
    bundle: &ObservationBundleWire,
    findings: &VerifierFindings,
) -> Result<(), AdmissionError> {
    if bundle.claims.iter().any(|claim| {
        claim.address.effect == EffectKindV2::RuntimeBinding
            && claim.observed != super::state::StateValue::Unknown
            && (claim.observed != super::state::StateValue::Present
                || claim.layer != super::state::StateLayer::Configuration
                || !matches!(
                    (claim.address.source.boundary, findings.recipe_id.as_str()),
                    (
                        super::source::SourceBoundaryKind::GceHostNetwork,
                        "k11-runtime-cutover-v1"
                    ) | (
                        super::source::SourceBoundaryKind::AwsHostNetwork,
                        super::aws_runtime_cutover::RECIPE
                    )
                ))
    }) {
        return Err(AdmissionError::VerifierUnavailable);
    }
    if !valid_id(&findings.recipe_id)
        || findings.source_evidence_refs.is_empty()
        || findings.source_evidence_refs.len() > 128
        || findings
            .source_evidence_refs
            .iter()
            .any(|r| !bundle.artifacts.iter().any(|a| a.id == *r))
        || findings.assurances.len() != bundle.claims.len()
        || findings
            .assurances
            .iter()
            .map(|a| &a.claim_id)
            .collect::<BTreeSet<_>>()
            .len()
            != findings.assurances.len()
    {
        return Err(AdmissionError::Invalid);
    }
    for a in &findings.assurances {
        if !bundle.claims.iter().any(|c| c.id == a.claim_id) {
            return Err(AdmissionError::Invalid);
        }
        let c = &a.coverage;
        for assurance in [
            &c.target,
            &c.principal,
            &c.source,
            &c.route,
            &c.transport,
            &c.temporal,
            &c.completeness,
        ] {
            match assurance {
                Assurance::Verified { evidence_refs } => {
                    if evidence_refs.is_empty()
                        || evidence_refs.len() > 128
                        || evidence_refs
                            .iter()
                            .any(|r| !bundle.artifacts.iter().any(|a| a.id == *r))
                    {
                        return Err(AdmissionError::Invalid);
                    }
                }
                // No generic exemption is admitted yet. Recipe-specific N/A
                // rules will be implemented with the native producer/evaluator.
                Assurance::NotApplicable { .. } => return Err(AdmissionError::Invalid),
                _ => (),
            }
        }
    }
    Ok(())
}

fn validate_capture(
    issued: &IssuedObservation,
    bundle: &ObservationBundleWire,
    window: CaptureWindow,
    now: u64,
) -> Result<u64, AdmissionError> {
    validate_issued(issued)?;
    let r = &issued.request;
    bundle
        .validate_shape()
        .map_err(|_| AdmissionError::Invalid)?;
    if bundle.request_digest != r.digest().map_err(|_| AdmissionError::Invalid)?
        || bundle.collector_build_id != r.collector_build_id
    {
        return Err(AdmissionError::ScopeMismatch);
    }
    if now >= r.expires_at {
        return Err(AdmissionError::Expired);
    }
    if window.sent_at < r.issued_at
        || window.received_at < window.sent_at
        || window.received_at > now
        || window.received_at >= r.expires_at
        || window.elapsed_millis > MAX_CAPTURE_SECONDS * 1000
        || window
            .received_at
            .saturating_sub(window.sent_at)
            .saturating_mul(1000)
            .abs_diff(window.elapsed_millis)
            > MAX_CLOCK_SKEW_SECONDS * 1000
        || bundle.started_at.saturating_add(MAX_CLOCK_SKEW_SECONDS) < window.sent_at
        || bundle.finished_at > window.received_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(AdmissionError::Invalid);
    }
    for claim in &bundle.claims {
        let case = r
            .cases
            .iter()
            .find(|c| c.id == claim.case_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        if claim.policy_revision_hash != r.policy_revision_hash || claim.address != case.address {
            return Err(AdmissionError::ScopeMismatch);
        }
        if let Some(runtime) = &claim.runtime_capture {
            let expected = super::runtime_binding::RuntimeCaptureContext::from_issued(issued, case)
                .map_err(|_| AdmissionError::ScopeMismatch)?;
            // The selector is collector-config pinned at the native producer.
            // At admission, validate immutable correlation and sample shape;
            // neither a wire selector nor this check grants session authority.
            let selector = super::runtime_binding::RuntimeProcessSelector {
                pid: runtime.before.pid,
                expected_boot_id: runtime.before.boot_id.clone(),
                expected_start_ticks: runtime.before.start_ticks,
                expected_executable_digest: runtime.before.executable_digest.clone(),
            };
            if claim.connection.as_ref() != Some(&runtime.before.connection) {
                return Err(AdmissionError::ScopeMismatch);
            }
            super::runtime_binding::validate_runtime_capture(
                runtime,
                &expected,
                &selector,
                &runtime.before.connection,
            )
            .map_err(|_| AdmissionError::ScopeMismatch)?;
        }
        if claim
            .transport
            .iter()
            .any(|t| t.validation_basis != case.backend_tls_trust)
            || claim
                .login_catalog
                .iter()
                .any(|f| !case.login_catalog_targets.contains(&f.target))
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        if let Some(tuple) = &claim.connection
            && (tuple.endpoint != case.endpoint
                || tuple.peer_port != case.port
                || tuple.peer_ip.is_ipv4() != (case.address_family == AddressFamily::Ipv4))
        {
            return Err(AdmissionError::ScopeMismatch);
        }
    }
    let earliest_start = bundle
        .started_at
        .saturating_sub(MAX_CLOCK_SKEW_SECONDS)
        .max(window.sent_at);
    let until = earliest_start
        .saturating_add(DEFAULT_FRESHNESS_SECONDS)
        .min(r.expires_at);
    if now >= until {
        return Err(AdmissionError::Expired);
    }
    Ok(until)
}

/// File-save precedes the ledger transaction; either failure returns no facts.
/// A changed epoch racing the save is checked again in the ledger's transaction.
#[allow(clippy::too_many_arguments)]
pub fn accept_evidence<
    L: EvidenceLedger,
    A: EvidenceArchive,
    V: ObservationVerifier,
    C: EvidenceClock,
>(
    ledger: &mut L,
    archive: &mut A,
    verifier: &mut V,
    request_id: &str,
    bytes: &[u8],
    payloads: &[EvidencePayload],
    window: CaptureWindow,
    clock: &C,
) -> Result<EvidenceAdmission, AdmissionError> {
    let now = clock.now();
    let issued = ledger.issued(request_id)?;
    ledger.ensure_current(&issued, now)?;
    match ledger.admission(request_id) {
        Ok(_) => return Err(AdmissionError::Conflict),
        Err(AdmissionError::NotFound) => (),
        Err(e) => return Err(e),
    }
    let bundle =
        ObservationBundleWire::parse_untrusted(bytes).map_err(|_| AdmissionError::Invalid)?;
    let mut valid_until = validate_capture(&issued, &bundle, window, now)?;
    validate_payloads(&bundle, payloads)?;
    let findings = verifier.verify(&issued, &bundle, payloads, window)?;
    validate_findings(&bundle, &findings)?;
    let mut runtime_cases = BTreeSet::new();
    for claim in bundle.claims.iter().filter(|c| {
        c.address.effect == EffectKindV2::RuntimeBinding
            && c.observed == super::state::StateValue::Present
    }) {
        if !runtime_cases.insert(&claim.case_id)
            || claim.denial_cause.is_some()
            || claim.connection.is_some()
            || !claim.controls.is_empty()
            || !claim.transport.is_empty()
            || claim.sql_context.is_some()
        {
            return Err(AdmissionError::Invalid);
        }
        let case = issued
            .request
            .cases
            .iter()
            .find(|c| c.id == claim.case_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        let context = super::runtime_binding::RuntimeCaptureContext::for_case(&issued, case)
            .map_err(|_| AdmissionError::ScopeMismatch)?;
        let (observed_at, checked_out_at, witness_valid_until, digests) =
            if findings.recipe_id == super::aws_runtime_cutover::RECIPE {
                let proof = verifier
                    .aws_runtime_cutover(&claim.case_id)
                    .ok_or(AdmissionError::VerifierUnavailable)?;
                if proof.context != context {
                    return Err(AdmissionError::ScopeMismatch);
                }
                (
                    proof.observed_at,
                    proof.checked_out_at,
                    proof.valid_until,
                    proof.evidence_digests.iter().collect::<Vec<_>>(),
                )
            } else {
                let proof = verifier
                    .runtime_cutover(&claim.case_id)
                    .ok_or(AdmissionError::VerifierUnavailable)?;
                let observed = proof.observations();
                if proof.candidate().context != context || observed.context != context {
                    return Err(AdmissionError::ScopeMismatch);
                }
                let refs = &observed.evidence_refs;
                (
                    observed.latest_observed_at(),
                    proof.candidate().switch.checked_out_at,
                    observed.valid_until,
                    vec![
                        &refs.kernel_peer,
                        &refs.postgres_session,
                        &refs.pool_checkout,
                    ],
                )
            };
        if observed_at > now
            || observed_at > claim.finished_at
            || checked_out_at < issued.request.issued_at
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        for digest in digests {
            if !bundle.artifacts.iter().any(|artifact| {
                artifact.sha256 == *digest
                    && claim.evidence_refs.contains(&artifact.id)
                    && findings.source_evidence_refs.contains(&artifact.id)
            }) {
                return Err(AdmissionError::Integrity);
            }
        }
        valid_until = valid_until.min(witness_valid_until);
        if valid_until <= now {
            return Err(AdmissionError::Expired);
        }
    }
    let r = &issued.request;
    let request_digest = r.digest().map_err(|_| AdmissionError::Invalid)?;
    let bundle_digest = super::hash_bytes(bytes);
    let id = super::hash_bytes(
        format!("veil-db-guard/evidence-admission/v1\0{request_digest}\0{bundle_digest}")
            .as_bytes(),
    );
    let saved = archive.persist(&issued, bytes, payloads)?;
    if saved.bundle_digest != bundle_digest
        || saved.request_digest != request_digest
        || !valid_id(&saved.run_id)
        || !valid_hash(&saved.manifest_digest)
    {
        return Err(AdmissionError::Integrity);
    }
    let committed_at = clock.now();
    if committed_at < now {
        return Err(AdmissionError::Invalid);
    }
    if committed_at >= valid_until {
        return Err(AdmissionError::Expired);
    }
    let candidate = VerifiedCandidate {
        admission: EvidenceAdmission {
            schema_version: 1,
            id,
            request_digest,
            bundle_digest,
            policy_revision_hash: r.policy_revision_hash.clone(),
            change_hash: r.change_hash.clone(),
            operation_id: r.operation_id.clone(),
            source_snapshot_digest: r.source.revision_digest.clone(),
            source_trust_epoch: r.source_trust_epoch,
            collector_build_id: r.collector_build_id.clone(),
            verifier_build_id: r.verifier_build_id.clone(),
            evaluation_contract: r.evaluation_contract,
            verification_recipe: findings.recipe_id,
            source_evidence_refs: findings.source_evidence_refs,
            accepted_at: committed_at,
            valid_until,
            capture_started_at: bundle.started_at,
            capture_finished_at: bundle.finished_at,
            assurances: findings.assurances,
            archive: saved,
        },
    };
    ledger.admit(&candidate, committed_at)
}

pub fn validate_receipt(
    issued: &IssuedObservation,
    admission: &EvidenceAdmission,
    now: u64,
) -> Result<(), AdmissionError> {
    validate_issued(issued)?;
    let r = &issued.request;
    let digest = r.digest().map_err(|_| AdmissionError::Invalid)?;
    let expected_id = super::hash_bytes(
        format!(
            "veil-db-guard/evidence-admission/v1\0{digest}\0{}",
            admission.bundle_digest
        )
        .as_bytes(),
    );
    if admission.schema_version != 1
        || admission.id != expected_id
        || admission.request_digest != digest
        || admission.archive.request_digest != digest
        || admission.bundle_digest != admission.archive.bundle_digest
        || !valid_hash(&admission.bundle_digest)
        || !valid_hash(&admission.archive.manifest_digest)
        || !valid_id(&admission.archive.run_id)
        || !valid_id(&admission.verification_recipe)
        || admission.policy_revision_hash != r.policy_revision_hash
        || admission.change_hash != r.change_hash
        || admission.operation_id != r.operation_id
        || admission.source_snapshot_digest != r.source.revision_digest
        || admission.source_trust_epoch != r.source_trust_epoch
        || admission.collector_build_id != r.collector_build_id
        || admission.verifier_build_id != r.verifier_build_id
        || admission.evaluation_contract != r.evaluation_contract
        || admission.capture_finished_at < admission.capture_started_at
        || admission.capture_finished_at - admission.capture_started_at > MAX_CAPTURE_SECONDS
        || admission.accepted_at < r.issued_at
        || admission.accepted_at > now
        || admission.valid_until <= admission.accepted_at
        || admission.valid_until > r.expires_at
        || admission.valid_until
            > admission
                .capture_started_at
                .saturating_add(DEFAULT_FRESHNESS_SECONDS + MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(AdmissionError::Integrity);
    }
    if now >= admission.valid_until || now >= r.expires_at {
        return Err(AdmissionError::Expired);
    }
    Ok(())
}

/// Offline rehydration only: current local trust + the original receipt and
/// exact archived files. There is no verifier/cloud/credential call or refresh.
pub fn load_admitted<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &A,
    request_id: &str,
    now: u64,
) -> Result<VerifiedObservationFacts, AdmissionError> {
    let issued = ledger.issued(request_id)?;
    ledger.ensure_current(&issued, now)?;
    let admission = ledger.admission(request_id)?;
    validate_receipt(&issued, &admission, now)?;
    let bundle = read_original_bundle(&issued, &admission, archive)?;
    ledger.ensure_current(&issued, now)?;
    Ok(VerifiedObservationFacts::admitted(
        admission.request_digest.clone(),
        admission.bundle_digest.clone(),
        admission.id.clone(),
        bundle.claims,
        admission.assurances.clone(),
        admission,
    ))
}

/// Original admitted history, never current verified facts. Rechecking at the
/// original receipt time does not renew trust, sample time, or validity.
#[derive(Debug, Clone, Serialize)]
pub struct StoredObservationHistory {
    pub admission: EvidenceAdmission,
    pub claims: Vec<ObservationClaim>,
}
pub fn read_admitted_history<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &A,
    id: &str,
) -> Result<StoredObservationHistory, AdmissionError> {
    let issued = ledger.issued(id)?;
    let admission = ledger.admission(id)?;
    validate_receipt(&issued, &admission, admission.accepted_at)?;
    let bundle = read_original_bundle(&issued, &admission, archive)?;
    Ok(StoredObservationHistory {
        admission,
        claims: bundle.claims,
    })
}
fn read_original_bundle<A: EvidenceArchive>(
    issued: &IssuedObservation,
    admission: &EvidenceAdmission,
    archive: &A,
) -> Result<ObservationBundleWire, AdmissionError> {
    let (bytes, payloads) = archive.read(issued, &admission.archive)?;
    if super::hash_bytes(&bytes) != admission.bundle_digest {
        return Err(AdmissionError::Integrity);
    }
    let bundle =
        ObservationBundleWire::parse_untrusted(&bytes).map_err(|_| AdmissionError::Integrity)?;
    if bundle.started_at != admission.capture_started_at
        || bundle.finished_at != admission.capture_finished_at
        || bundle.request_digest != admission.request_digest
        || bundle.collector_build_id != admission.collector_build_id
    {
        return Err(AdmissionError::Integrity);
    }
    validate_payloads(&bundle, &payloads)?;
    validate_findings(
        &bundle,
        &VerifierFindings {
            recipe_id: admission.verification_recipe.clone(),
            source_evidence_refs: admission.source_evidence_refs.clone(),
            assurances: admission.assurances.clone(),
        },
    )?;
    // The stored bundle was admitted in this scope; repeat the exact address
    // check without stamping a new capture window or obtaining a new token.
    for claim in &bundle.claims {
        if claim.policy_revision_hash != issued.request.policy_revision_hash
            || !issued
                .request
                .cases
                .iter()
                .any(|c| c.id == claim.case_id && c.address == claim.address)
        {
            return Err(AdmissionError::Integrity);
        }
    }
    Ok(bundle)
}

/// Offline composition: reload local receipts, expiry, source heads and archive
/// integrity for each evaluation. This never launches a native tool or restamps
/// a capture. Operation completion is not a protection result.
pub fn evaluate_admitted_change<L: EvidenceLedger, A: EvidenceArchive>(
    ledger: &mut L,
    archive: &A,
    change: &super::change::PreparedChange,
    request_ids: &[String],
    now: u64,
) -> Result<super::state_v2::StateReportV2, AdmissionError> {
    change.verify().map_err(|_| AdmissionError::Invalid)?;
    if request_ids.len() > 32768 {
        return Err(AdmissionError::Limit);
    }
    let desired = super::state_v2::desired_for_change_v2(
        &change.policy,
        change.previous_policy.as_ref(),
        &[],
        now,
    )
    .map_err(|_| AdmissionError::Invalid)?;
    let mut facts = vec![];
    for id in request_ids {
        let issued = ledger.issued(id)?;
        if issued.request.change_hash != change.change_hash {
            return Err(AdmissionError::ScopeMismatch);
        }
        facts.push(load_admitted(ledger, archive, id, now)?);
    }
    // Catch revocation/build changes that raced an earlier archive read.
    for id in request_ids {
        let issued = ledger.issued(id)?;
        ledger.ensure_current(&issued, now)?;
    }
    super::state_v2::evaluate_state_v2(&StateEvaluationInputV2 {
        contract: EvaluationContract::SourceBoundV2,
        now,
        max_age_seconds: DEFAULT_FRESHNESS_SECONDS,
        desired,
        evidence: facts,
        permission_removals: vec![],
    })
    .map_err(|_| AdmissionError::Invalid)
}
