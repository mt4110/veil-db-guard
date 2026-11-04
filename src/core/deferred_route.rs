//! Delayed AWS flow-log diagnostics. Historical records never become current
//! observation facts, denial claims, or authorization to close a route.
use super::{
    admission::{AdmissionError, EvidenceArchiveRef, IssuedObservation, load_admitted},
    evidence::{
        Assurance, ConnectionTuple, EffectAddress, FixedObservationCase, VerifiedObservationFacts,
    },
    policy::{PlacementKind, RouteKind, valid_hash},
    ports::{EvidenceArchive, EvidenceClock, EvidenceLedger},
    state::StateValue,
};
use serde::{Deserialize, Serialize};
use std::future::Future;

pub const MAX_DELIVERY_SECONDS: u64 = 3600;
pub const MAX_FLOW_EVENTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredProbe {
    pub schema_version: u32,
    pub issued: IssuedObservation,
    pub probe_admission_id: String,
    pub probe_bundle_digest: String,
    pub case_id: String,
    pub address: EffectAddress,
    pub connection: ConnectionTuple,
    pub observed_at: u64,
    pub probe_finished_at: u64,
    pub probe_observed: StateValue,
    pub registered_at: u64,
    pub delivery_deadline: u64,
}
impl DeferredProbe {
    pub fn digest(&self) -> Result<String, AdmissionError> {
        self.validate()?;
        Ok(super::hash_bytes(
            &serde_json::to_vec(self).map_err(|_| AdmissionError::Invalid)?,
        ))
    }
    pub fn validate(&self) -> Result<(), AdmissionError> {
        super::admission::validate_issued(&self.issued)?;
        let r = &self.issued.request;
        let case = r
            .cases
            .iter()
            .find(|c| c.id == self.case_id)
            .ok_or(AdmissionError::ScopeMismatch)?;
        if self.schema_version != 1
            || self.issued.snapshot.aws().is_none()
            || case.kind != FixedObservationCase::DirectPath
            || case.address != self.address
            || case.address.route.kind != RouteKind::Direct
            || case.address.target.placement.kind != PlacementKind::AwsRds
            || self.connection.endpoint != case.endpoint
            || self.connection.peer_port != case.port
            || self.connection.local_port == 0
            || self.connection.peer_port == 0
            || self.connection.local_ip.is_ipv4() != self.connection.peer_ip.is_ipv4()
            || !valid_hash(&self.probe_admission_id)
            || !valid_hash(&self.probe_bundle_digest)
            || self.observed_at < r.issued_at
            || self.probe_finished_at < self.observed_at
            || self.probe_finished_at - self.observed_at > super::evidence::MAX_CAPTURE_SECONDS
            || self.registered_at < self.probe_finished_at
            || self.registered_at >= r.expires_at
            || self.delivery_deadline != self.probe_finished_at.saturating_add(MAX_DELIVERY_SECONDS)
            || self.registered_at >= self.delivery_deadline
        {
            return Err(AdmissionError::Invalid);
        }
        Ok(())
    }
}

/// Only the current-admission loader can mint this issue capability. A JSON
/// record can be read for history but cannot be registered as a trusted probe.
#[derive(Debug)]
pub struct DeferredProbeTicket(DeferredProbe);
impl DeferredProbeTicket {
    pub fn probe(&self) -> &DeferredProbe {
        &self.0
    }
}

pub trait DeferredRouteLedger {
    fn issue(&mut self, ticket: &DeferredProbeTicket) -> Result<String, AdmissionError>;
    fn probe(&mut self, digest: &str) -> Result<DeferredProbe, AdmissionError>;
    /// CAS consumes the original probe nonce once, after archive durability.
    fn commit(&mut self, receipt: &DeferredRouteReceipt, now: u64) -> Result<(), AdmissionError>;
    fn receipt(&mut self, digest: &str) -> Result<DeferredRouteReceipt, AdmissionError>;
}

pub fn issue_deferred_probe<L: EvidenceLedger, A: EvidenceArchive, D: DeferredRouteLedger>(
    ledger: &mut L,
    archive: &A,
    deferred: &mut D,
    request_id: &str,
    case_id: &str,
    now: u64,
) -> Result<String, AdmissionError> {
    let issued = ledger.issued(request_id)?;
    let facts = load_admitted(ledger, archive, request_id, now)?;
    let claim = facts
        .claims()
        .iter()
        .find(|c| c.case_id == case_id)
        .ok_or(AdmissionError::NotFound)?;
    let coverage = facts
        .assurances()
        .iter()
        .find(|a| a.claim_id == claim.id)
        .ok_or(AdmissionError::Integrity)?;
    if !matches!(coverage.coverage.source, Assurance::Verified { .. })
        || !matches!(coverage.coverage.temporal, Assurance::Verified { .. })
    {
        return Err(AdmissionError::VerifierUnavailable);
    }
    let probe = DeferredProbe {
        schema_version: 1,
        issued,
        probe_admission_id: facts.admission_id().into(),
        probe_bundle_digest: facts.bundle_digest().into(),
        case_id: case_id.into(),
        address: claim.address.clone(),
        connection: claim
            .connection
            .clone()
            .ok_or(AdmissionError::VerifierUnavailable)?,
        observed_at: claim.started_at,
        probe_finished_at: claim.finished_at,
        probe_observed: claim.observed,
        registered_at: now,
        delivery_deadline: claim.finished_at.saturating_add(MAX_DELIVERY_SECONDS),
    };
    probe.validate()?;
    ledger.ensure_current(&probe.issued, now)?;
    deferred.issue(&DeferredProbeTicket(probe))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowAction {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowEventCandidate {
    pub event_digest: String,
    pub account_id: String,
    pub interface_id: String,
    pub source_ip: std::net::IpAddr,
    pub destination_ip: std::net::IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub bytes: u64,
    /// Native aggregate range, not exact probe time or local receipt time.
    pub aggregate_started_at: u64,
    pub aggregate_finished_at: u64,
    pub action: FlowAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredCapture {
    pub probe_digest: String,
    pub received_at: u64,
    pub events: Vec<FlowEventCandidate>,
    pub scan_complete: bool,
}
pub trait DeferredRouteProducer {
    fn collect(
        &mut self,
        probe: &DeferredProbe,
    ) -> impl Future<Output = Result<DeferredCapture, AdmissionError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferredRouteLimitation {
    NativeLogOriginUnconfirmed,
    AggregateCannotAttributeSingleProbe,
    SourcePortReuseNotExcluded,
    HistoricalOnly,
}
fn historical_limitations() -> Vec<DeferredRouteLimitation> {
    vec![
        DeferredRouteLimitation::NativeLogOriginUnconfirmed,
        DeferredRouteLimitation::AggregateCannotAttributeSingleProbe,
        DeferredRouteLimitation::SourcePortReuseNotExcluded,
        DeferredRouteLimitation::HistoricalOnly,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeferredRouteReceipt {
    pub probe_digest: String,
    pub capture_digest: String,
    pub observed_at: u64,
    pub received_at: u64,
    pub limitations: Vec<DeferredRouteLimitation>,
    pub reject_candidate_count: usize,
    pub accept_candidate_count: usize,
    pub probe_was_allowed: bool,
    pub current_allowed_claim_refs: Vec<String>,
    pub scan_complete: bool,
    pub archive: EvidenceArchiveRef,
}

fn validate_capture(
    p: &DeferredProbe,
    c: &DeferredCapture,
    now: u64,
) -> Result<(), AdmissionError> {
    p.validate()?;
    if now >= p.delivery_deadline || c.received_at >= p.delivery_deadline {
        return Err(AdmissionError::Expired);
    }
    if c.probe_digest != p.digest()?
        || c.received_at < p.registered_at
        || c.received_at > now
        || c.events.len() > MAX_FLOW_EVENTS
    {
        return Err(AdmissionError::ScopeMismatch);
    }
    let mut seen = std::collections::BTreeSet::new();
    for e in &c.events {
        if !valid_hash(&e.event_digest)
            || !seen.insert(&e.event_digest)
            || e.account_id != p.address.target.placement.account_id
            || e.protocol != 6
            || e.interface_id.is_empty()
            || e.interface_id.len() > 64
            || e.source_ip != p.connection.local_ip
            || e.destination_ip != p.connection.peer_ip
            || e.source_port != p.connection.local_port
            || e.destination_port != p.connection.peer_port
            || e.aggregate_finished_at < e.aggregate_started_at
            || e.aggregate_finished_at - e.aggregate_started_at > 600
            || e.aggregate_started_at > p.probe_finished_at.saturating_add(60)
            || e.aggregate_finished_at.saturating_add(60) < p.observed_at
            || e.aggregate_finished_at > c.received_at
            || e.packets == 0
            || e.bytes == 0
        {
            return Err(AdmissionError::ScopeMismatch);
        }
    }
    Ok(())
}

/// No SQLite transaction spans the asynchronous acquisition. An expired source
/// request remains expired: the delayed result is saved only in a separate
/// historical namespace, never through accept_evidence/load_admitted.
pub async fn collect_deferred_route<
    D: DeferredRouteLedger,
    A: EvidenceArchive,
    P: DeferredRouteProducer,
    C: EvidenceClock,
>(
    ledger: &mut D,
    archive: &mut A,
    producer: &mut P,
    digest: &str,
    current: &[VerifiedObservationFacts],
    clock: &C,
) -> Result<DeferredRouteReceipt, AdmissionError> {
    let p = ledger.probe(digest)?;
    match ledger.receipt(digest) {
        Ok(_) => return Err(AdmissionError::Conflict),
        Err(AdmissionError::NotFound) => (),
        Err(e) => return Err(e),
    }
    if clock.now() >= p.delivery_deadline {
        return Err(AdmissionError::Expired);
    }
    let capture = producer.collect(&p).await?;
    let now = clock.now();
    validate_capture(&p, &capture, now)?;
    let bytes = serde_json::to_vec(&capture).map_err(|_| AdmissionError::Invalid)?;
    let saved = archive.persist(&p.issued, &bytes, &[])?;
    if saved.bundle_digest != super::hash_bytes(&bytes)
        || saved.request_digest
            != p.issued
                .request
                .digest()
                .map_err(|_| AdmissionError::Integrity)?
    {
        return Err(AdmissionError::Integrity);
    }
    let mut allowed = vec![];
    for facts in current {
        if facts.admission().valid_until <= now {
            continue;
        }
        for c in facts.claims() {
            if c.address == p.address
                && c.observed == StateValue::Allowed
                && c.finished_at >= p.probe_finished_at
            {
                allowed.push(format!("{}:{}", facts.admission_id(), c.id));
            }
        }
    }
    allowed.sort();
    allowed.dedup();
    let r = DeferredRouteReceipt {
        probe_digest: digest.into(),
        capture_digest: super::hash_bytes(&bytes),
        observed_at: p.observed_at,
        received_at: capture.received_at,
        limitations: historical_limitations(),
        reject_candidate_count: capture
            .events
            .iter()
            .filter(|e| e.action == FlowAction::Reject)
            .count(),
        accept_candidate_count: capture
            .events
            .iter()
            .filter(|e| e.action == FlowAction::Accept)
            .count(),
        probe_was_allowed: p.probe_observed == StateValue::Allowed,
        current_allowed_claim_refs: allowed,
        scan_complete: capture.scan_complete,
        archive: saved,
    };
    ledger.commit(&r, clock.now())?;
    Ok(r)
}

pub fn read_deferred_history<D: DeferredRouteLedger, A: EvidenceArchive>(
    ledger: &mut D,
    archive: &A,
    digest: &str,
) -> Result<(DeferredRouteReceipt, DeferredCapture), AdmissionError> {
    let p = ledger.probe(digest)?;
    let r = ledger.receipt(digest)?;
    let (bytes, payloads) = archive.read(&p.issued, &r.archive)?;
    if !payloads.is_empty() || super::hash_bytes(&bytes) != r.capture_digest {
        return Err(AdmissionError::Integrity);
    }
    let c: DeferredCapture =
        serde_json::from_slice(&bytes).map_err(|_| AdmissionError::Integrity)?;
    validate_capture(&p, &c, r.received_at)?;
    if c.received_at != r.received_at
        || p.observed_at != r.observed_at
        || r.probe_digest != digest
        || r.limitations != historical_limitations()
        || r.reject_candidate_count
            != c.events
                .iter()
                .filter(|e| e.action == FlowAction::Reject)
                .count()
        || r.accept_candidate_count
            != c.events
                .iter()
                .filter(|e| e.action == FlowAction::Accept)
                .count()
        || r.probe_was_allowed != (p.probe_observed == StateValue::Allowed)
        || r.scan_complete != c.scan_complete
    {
        return Err(AdmissionError::Integrity);
    }
    Ok((r, c))
}
