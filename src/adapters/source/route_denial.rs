//! Opt-in GCP firewall-log candidate acquisition. Log fields and HTTPS transport
//! do not prove provider generation; normalization remains Unknown. No mutation.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{gce_host::*, postgres::InstanceIdentity, process};
use crate::core::{admission::IssuedObservation, evidence::*, state::*};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::Path};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpRouteDenialConfig {
    pub source_ip: IpAddr,
    pub instance_name: String,
    pub network_name: String,
    pub subnetwork_name: String,
    pub firewall_name: String,
    pub firewall_priority: u32,
}
fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
impl GcpRouteDenialConfig {
    pub(super) fn validate(&self, i: &IssuedObservation) -> Result<(), SourceError> {
        let source = i.snapshot.gce().ok_or(SourceError::Unsupported)?;
        if ![
            &self.instance_name,
            &self.network_name,
            &self.subnetwork_name,
            &self.firewall_name,
        ]
        .iter()
        .all(|s| component(s))
            || !matches!(self.source_ip, IpAddr::V4(v) if v.is_private())
            || self.firewall_priority > 65535
            || !component(&source.native_identity.project_id)
            || !component(&source.native_identity.zone)
        {
            return Err(SourceError::Invalid);
        }
        Ok(())
    }
    fn rule(&self) -> String {
        format!(
            "network:{}/firewall:{}",
            self.network_name, self.firewall_name
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceNetwork {
    instance_id: String,
    instance_name: String,
    network: String,
    subnetwork: String,
    source_ip: IpAddr,
}
impl SourceNetwork {
    fn matches(&self, i: &IssuedObservation, config: &GcpRouteDenialConfig) -> bool {
        i.snapshot.gce().is_some_and(|s| {
            let n = &s.native_identity;
            let region = n.zone.rsplit_once('-').map(|v| v.0).unwrap_or("");
            self.instance_id == n.instance_id && self.instance_name == config.instance_name
                && self.source_ip == config.source_ip
                && self.network == format!("https://www.googleapis.com/compute/v1/projects/{}/global/networks/{}", n.project_id, config.network_name)
                && self.subnetwork == format!("https://www.googleapis.com/compute/v1/projects/{}/regions/{region}/subnetworks/{}", n.project_id, config.subnetwork_name)
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FirewallDecision {
    pub decision_at: u64,
    pub entry_digest: String,
    pub rule_reference: String,
    pub priority: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderClockBound {
    provider_at: u64,
    local_started_millis: u64,
    local_finished_millis: u64,
    elapsed_millis: u64,
}
impl ProviderClockBound {
    fn valid(&self) -> bool {
        let start = i128::from(self.local_started_millis);
        let end = i128::from(self.local_finished_millis);
        let date = i128::from(self.provider_at) * 1000;
        let bound = i128::from(MAX_CLOCK_SKEW_SECONDS) * 1000;
        end >= start
            && self.elapsed_millis <= 3000
            && (end - start - i128::from(self.elapsed_millis)).abs() <= 100
            && date - end >= -bound
            && date + 1000 - start <= bound
    }
}
fn http_date(value: &str) -> Result<u64, SourceError> {
    let p: Vec<_> = value.split(' ').collect();
    if p.len() != 6
        || p[0].len() != 4
        || !p[0].ends_with(',')
        || p[1].len() != 2
        || p[3].len() != 4
        || p[4].len() != 8
        || p[5] != "GMT"
    {
        return Err(SourceError::Invalid);
    }
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = months
        .iter()
        .position(|m| *m == p[2])
        .ok_or(SourceError::Invalid)?
        + 1;
    let at = super::denial::timestamp(&format!("{}-{month:02}-{}T{}Z", p[3], p[1], p[4]))?;
    let weekdays = ["Thu,", "Fri,", "Sat,", "Sun,", "Mon,", "Tue,", "Wed,"];
    if p[0] != weekdays[(at / 86400 % 7) as usize] {
        return Err(SourceError::Invalid);
    }
    Ok(at)
}
fn timed_body(
    bytes: &[u8],
    start: u64,
    end: u64,
    elapsed: u64,
) -> Result<(Vec<u8>, ProviderClockBound), SourceError> {
    if bytes.len() > 65536 {
        return Err(SourceError::Limit);
    }
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(SourceError::Invalid)?;
    if split > 8192 {
        return Err(SourceError::Limit);
    }
    let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| SourceError::Invalid)?;
    if !headers.is_ascii() {
        return Err(SourceError::Invalid);
    }
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or(SourceError::Invalid)?;
    if !matches!(
        status,
        "HTTP/1.1 200 OK" | "HTTP/1.1 200" | "HTTP/2 200" | "HTTP/2 200 "
    ) {
        return Err(SourceError::Invalid);
    }
    let mut date = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(SourceError::Invalid)?;
        if name.is_empty()
            || name
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
            || value.bytes().any(|b| b.is_ascii_control())
        {
            return Err(SourceError::Invalid);
        }
        if name.eq_ignore_ascii_case("date") {
            if date.is_some() {
                return Err(SourceError::Invalid);
            }
            date = Some(http_date(value.trim())?);
        }
    }
    let clock = ProviderClockBound {
        provider_at: date.ok_or(SourceError::Invalid)?,
        local_started_millis: start,
        local_finished_millis: end,
        elapsed_millis: elapsed,
    };
    if !clock.valid() {
        return Err(SourceError::ContextUnverified);
    }
    Ok((bytes[split + 4..].to_vec(), clock))
}
fn utc_millis() -> Result<u64, SourceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .ok_or(SourceError::ContextUnverified)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GcpRouteObservation {
    pub case_id: String,
    pub config: GcpRouteDenialConfig,
    pub source_before: SourceNetwork,
    pub source_after: SourceNetwork,
    pub target_before: InstanceIdentity,
    pub target_after: InstanceIdentity,
    pub decision: FirewallDecision,
    pub clock_bounds: [ProviderClockBound; 3],
    pub port_reserved_at: u64,
    pub probe_started_at: u64,
    pub probe_finished_at: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComputeInstance {
    id: String,
    name: String,
    zone: String,
    network_interfaces: Vec<Interface>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Interface {
    network: String,
    subnetwork: String,
    #[serde(rename = "networkIP")]
    network_ip: IpAddr,
}
fn parse_source(
    bytes: &[u8],
    i: &IssuedObservation,
    config: &GcpRouteDenialConfig,
) -> Result<SourceNetwork, SourceError> {
    let a: ComputeInstance = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
    let n = &i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity;
    if a.zone
        != format!(
            "https://www.googleapis.com/compute/v1/projects/{}/zones/{}",
            n.project_id, n.zone
        )
    {
        return Err(SourceError::Invalid);
    }
    let mut interfaces = a
        .network_interfaces
        .into_iter()
        .filter(|v| v.network_ip == config.source_ip);
    let v = interfaces.next().ok_or(SourceError::Invalid)?;
    if interfaces.next().is_some() {
        return Err(SourceError::Invalid);
    }
    let s = SourceNetwork {
        instance_id: a.id,
        instance_name: a.name,
        network: v.network,
        subnetwork: v.subnetwork,
        source_ip: v.network_ip,
    };
    if !s.matches(i, config) {
        return Err(SourceError::Invalid);
    }
    Ok(s)
}
async fn https(
    url: &str,
    body: Option<&str>,
    token: &str,
    cancel: &CancellationToken,
) -> Result<(Vec<u8>, ProviderClockBound), SourceError> {
    trusted_program(Path::new("/usr/bin/curl"))?;
    let mut args: Vec<String> = [
        "-q",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--max-time",
        "3",
        "--max-filesize",
        "65536",
        "--silent",
        "--fail",
        "--include",
        "--header",
        "@-",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    if let Some(body) = body {
        args.extend([
            "--header".into(),
            "Content-Type: application/json".into(),
            "--data-raw".into(),
            body.into(),
        ]);
    }
    args.push(url.into());
    let start = utc_millis()?;
    let monotonic = tokio::time::Instant::now();
    let bytes = process::run(
        Path::new("/usr/bin/curl"),
        &args,
        format!("Authorization: Bearer {token}\n").as_bytes(),
        65536,
        3,
        cancel,
    )
    .await?;
    let end = utc_millis()?;
    let elapsed =
        u64::try_from(monotonic.elapsed().as_millis()).map_err(|_| SourceError::Invalid)?;
    timed_body(&bytes, start, end, elapsed)
}
async fn source(
    i: &IssuedObservation,
    config: &GcpRouteDenialConfig,
    token: &str,
    cancel: &CancellationToken,
) -> Result<(SourceNetwork, ProviderClockBound), SourceError> {
    let n = &i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity;
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/zones/{}/instances/{}",
        n.project_id, n.zone, config.instance_name
    );
    let (body, clock) = https(&url, None, token, cancel).await?;
    Ok((parse_source(&body, i, config)?, clock))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entries {
    #[serde(default)]
    entries: Vec<Entry>,
    #[serde(default)]
    next_page_token: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    insert_id: String,
    timestamp: String,
    log_name: String,
    resource: Resource,
    json_payload: Payload,
}
#[derive(Deserialize)]
struct Resource {
    #[serde(rename = "type")]
    kind: String,
    labels: Labels,
}
#[derive(Deserialize)]
struct Labels {
    project_id: String,
    subnetwork_name: String,
    location: String,
}
#[derive(Deserialize)]
struct Payload {
    connection: Flow,
    disposition: String,
    rule_details: Rule,
    instance: Vm,
    vpc: Vpc,
}
#[derive(Deserialize)]
struct Flow {
    src_ip: IpAddr,
    src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    protocol: u8,
}
#[derive(Deserialize)]
struct Rule {
    reference: String,
    priority: u32,
    action: String,
    direction: String,
}
#[derive(Deserialize)]
struct Vm {
    project_id: String,
    vm_name: String,
    zone: String,
    region: String,
}
#[derive(Deserialize)]
struct Vpc {
    project_id: String,
    vpc_name: String,
    subnetwork_name: String,
}
fn select(
    bytes: &[u8],
    i: &IssuedObservation,
    config: &GcpRouteDenialConfig,
    tuple: &ConnectionTuple,
    start: u64,
    end: u64,
) -> Result<Option<FirewallDecision>, SourceError> {
    if bytes.len() > 65536 || start > end {
        return Err(SourceError::Invalid);
    }
    let r: Entries = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
    if !r.next_page_token.is_empty() || r.entries.is_empty() || r.entries.len() > 16 {
        return Ok(None);
    }
    let n = &i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity;
    let region = n.zone.rsplit_once('-').map(|v| v.0).unwrap_or("");
    let mut selected = None;
    for e in r.entries {
        let p = e.json_payload;
        let at = super::denial::timestamp(&e.timestamp)?;
        if e.insert_id.is_empty()
            || e.insert_id.len() > 1024
            || e.log_name
                != format!(
                    "projects/{}/logs/compute.googleapis.com%2Ffirewall",
                    n.project_id
                )
            || e.resource.kind != "gce_subnetwork"
            || e.resource.labels.project_id != n.project_id
            || e.resource.labels.subnetwork_name != config.subnetwork_name
            || e.resource.labels.location != region
            || p.disposition != "DENIED"
            || p.rule_details.action != "DENY"
            || p.rule_details.direction != "EGRESS"
            || p.rule_details.reference != config.rule()
            || p.rule_details.priority != config.firewall_priority
            || p.instance.project_id != n.project_id
            || p.instance.vm_name != config.instance_name
            || p.instance.zone != n.zone
            || p.instance.region != region
            || p.vpc.project_id != n.project_id
            || p.vpc.vpc_name != config.network_name
            || p.vpc.subnetwork_name != config.subnetwork_name
            || p.connection.protocol != 6
            || p.connection.src_ip != tuple.local_ip
            || p.connection.src_port != tuple.local_port
            || p.connection.dest_ip != tuple.peer_ip
            || p.connection.dest_port != tuple.peer_port
            || at < start
            || at > end
        {
            return Ok(None);
        }
        selected = Some(FirewallDecision {
            decision_at: at,
            entry_digest: crate::config::hash_bytes(e.insert_id.as_bytes()),
            rule_reference: config.rule(),
            priority: config.firewall_priority,
        });
    }
    Ok(selected)
}
fn query(
    i: &IssuedObservation,
    tuple: &ConnectionTuple,
    start: u64,
    end: u64,
) -> Result<String, SourceError> {
    let n = &i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity;
    let q = |s: &str| serde_json::to_string(s).expect("string");
    // Do not filter DENIED, rule, or VM: mixed/ambiguous outcomes must be seen.
    let filter = format!(
        "logName={} AND jsonPayload.connection.src_ip={} AND jsonPayload.connection.src_port={} AND jsonPayload.connection.dest_ip={} AND jsonPayload.connection.dest_port={} AND jsonPayload.connection.protocol=6 AND timestamp>={} AND timestamp<={}",
        q(&format!(
            "projects/{}/logs/compute.googleapis.com%2Ffirewall",
            n.project_id
        )),
        q(&tuple.local_ip.to_string()),
        tuple.local_port,
        q(&tuple.peer_ip.to_string()),
        tuple.peer_port,
        q(&super::denial::utc(start)?),
        q(&format!(
            "{}.999999999Z",
            super::denial::utc(end)?.trim_end_matches('Z')
        ))
    );
    serde_json::to_string(&serde_json::json!({"resourceNames":[format!("projects/{}",n.project_id)],"filter":filter,"pageSize":16})).map_err(|_|SourceError::Invalid)
}

#[cfg(unix)]
pub(super) async fn observe(
    i: &IssuedObservation,
    c: &RequestedCase,
    endpoint: &CollectorEndpoint,
    config: &GcpRouteDenialConfig,
    cancel: &CancellationToken,
) -> Result<(CaseDiagnostic, Option<GcpRouteObservation>), SourceError> {
    config.validate(i)?;
    let mut d = CaseDiagnostic {
        runtime_capture: None,
        runtime_failure: None,
        iam_inventory: None,
        case_id: c.id.clone(),
        started_at: crate::domain::now(),
        finished_at: crate::domain::now(),
        outcome: DiagnosticOutcome::TcpUnavailable,
        connection: None,
        postgres: None,
    };
    let attempt = async {
        let t = super::postgres_native::token(
            i,
            "https://www.googleapis.com/auth/cloud-platform",
            cancel,
        )
        .await?;
        let target_before = super::postgres_native::instance(c, &t, cancel).await?;
        if !target_before.matches(c) || target_before.private_ip != endpoint.ip {
            return Err(SourceError::Invalid);
        }
        let (source_before, clock_before) = source(i, config, &t.access_token, cancel).await?;
        let (probe, mut held) =
            super::collector::bound_tcp_diagnostic(c, endpoint.ip, config.source_ip, cancel)
                .await?;
        let probe_started_at = probe.started_at;
        let probe_finished_at = probe.finished_at;
        d.outcome = probe.outcome;
        d.connection = probe.connection;
        if d.outcome == DiagnosticOutcome::TcpConnected {
            drop(held);
            return Ok(None);
        }
        let tuple = d.connection.as_ref().ok_or(SourceError::Invalid)?.clone();
        let port_reserved_at = held.reserved_at;
        if !held.exclusive(&tuple) { return Ok(None); }
        let acquisition = async {
            let body = query(i, &tuple, probe_started_at, probe_finished_at)?;
            let (bytes, clock_log) = https("https://logging.googleapis.com/v2/entries:list", Some(&body), &t.access_token, cancel).await?;
            let decision = select(&bytes, i, config, &tuple, probe_started_at, probe_finished_at)?;
            let (source_after, clock_after) = source(i, config, &t.access_token, cancel).await?;
            let target_after = super::postgres_native::instance(c, &t, cancel).await?;
            if source_before != source_after || target_before != target_after { return Ok(None); }
            Ok(decision.map(|decision| GcpRouteObservation {
                case_id: c.id.clone(), config: config.clone(), source_before, source_after,
                target_before, target_after, decision, clock_bounds: [clock_before, clock_log, clock_after], port_reserved_at, probe_started_at, probe_finished_at,
            }))
        };
        // A timed-out SYN can still complete while logs/readbacks are fetched.
        // Observe its task concurrently; any late success keeps TCPConnected
        // and suppresses the denial rather than silently dropping the future.
        let result = if let Some(pending) = held.pending.as_mut() {
            tokio::select! { biased;
                connection = pending => {
                    held.pending = None;
                    if let Ok(Ok(stream)) = connection { d.outcome = DiagnosticOutcome::TcpConnected; drop(stream); }
                    return Ok(None);
                },
                result = acquisition => result,
            }
        } else { acquisition.await };
        if held.pending.as_ref().is_some_and(|p| p.is_finished()) {
            let connection = held.pending.take().expect("finished task").await;
            if let Ok(Ok(stream)) = connection { d.outcome = DiagnosticOutcome::TcpConnected; drop(stream); }
            return Ok(None);
        }
        if !held.exclusive(&tuple) { return Ok(None); }
        result
    }
    .await;
    d.finished_at = crate::domain::now();
    match attempt {
        Ok(o) => Ok((d, o)),
        Err(SourceError::Cancelled) => Err(SourceError::Cancelled),
        Err(SourceError::Unsupported) => {
            d.outcome = DiagnosticOutcome::UnsupportedCase;
            Ok((d, None))
        }
        Err(_) => Ok((d, None)),
    }
}

pub(super) fn validate_observations(
    i: &IssuedObservation,
    diagnostics: &[CaseDiagnostic],
    observations: &[GcpRouteObservation],
) -> Result<(), SourceError> {
    let mut seen = std::collections::BTreeSet::new();
    for o in observations {
        let d = diagnostics
            .iter()
            .find(|d| d.case_id == o.case_id)
            .ok_or(SourceError::Invalid)?;
        let c = i
            .request
            .cases
            .iter()
            .find(|c| c.id == o.case_id)
            .ok_or(SourceError::Invalid)?;
        o.config.validate(i)?;
        if !seen.insert(&o.case_id)
            || c.port != 5432
            || c.address.effect != EffectKindV2::NewConnections
            || c.kind != FixedObservationCase::DirectPath
            || c.address.route.kind != crate::core::policy::RouteKind::Direct
            || !matches!(
                d.outcome,
                DiagnosticOutcome::TcpRefused
                    | DiagnosticOutcome::TcpTimedOut
                    | DiagnosticOutcome::TcpUnavailable
            )
            || d.postgres.is_some()
            || !o.source_before.matches(i, &o.config)
            || o.source_before != o.source_after
            || !o.target_before.matches(c)
            || o.target_before != o.target_after
            || o.decision.rule_reference != o.config.rule()
            || o.decision.priority != o.config.firewall_priority
            || !crate::core::policy::valid_hash(&o.decision.entry_digest)
            || o.clock_bounds.iter().any(|clock| {
                !clock.valid()
                    || clock.local_started_millis / 1000 < d.started_at
                    || clock.local_finished_millis / 1000 > d.finished_at
            })
            || o.clock_bounds[0].local_finished_millis / 1000 > o.port_reserved_at
            || o.clock_bounds[1].local_started_millis / 1000 < o.probe_finished_at
            || o.clock_bounds[2].local_started_millis < o.clock_bounds[1].local_finished_millis
            || o.port_reserved_at < d.started_at
            || o.probe_started_at <= o.port_reserved_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
            || o.probe_started_at < d.started_at
            || o.probe_finished_at > d.finished_at
            || o.probe_started_at > o.probe_finished_at
            || o.decision.decision_at < o.probe_started_at
            || o.decision.decision_at > o.probe_finished_at
            || d.connection.as_ref().is_none_or(|t| {
                t.local_ip != o.config.source_ip
                    || t.local_port == 0
                    || t.peer_ip != o.target_before.private_ip
                    || t.peer_port != c.port
                    || t.endpoint != c.endpoint
            })
        {
            return Err(SourceError::Invalid);
        }
    }
    Ok(())
}
pub(super) fn normalize(
    i: &IssuedObservation,
    c: &RequestedCase,
    d: &CaseDiagnostic,
    o: &GcpRouteObservation,
    proof_id: &str,
) -> Result<
    (
        ObservationClaim,
        ClaimAssurance,
        ObservationClaim,
        ClaimAssurance,
    ),
    SourceError,
> {
    validate_observations(i, std::slice::from_ref(d), std::slice::from_ref(o))?;
    let native_id = format!("route-log-candidate-{}", c.id);
    let claim = ObservationClaim {
        id: format!("source-{}", c.id),
        case_id: c.id.clone(),
        policy_revision_hash: i.request.policy_revision_hash.clone(),
        address: c.address.clone(),
        started_at: d.started_at,
        finished_at: d.finished_at,
        observed: StateValue::Unknown,
        layer: StateLayer::RouteEnforcement,
        denial_cause: Some(DenialCause::Unclassified),
        connection: d.connection.clone(),
        // Logging writers can supply these fields; no provider-origin proof
        // exists, so even an exact candidate cannot become a native decision.
        controls: vec![],
        transport: vec![],
        sql_context: None,
        evidence_refs: vec![proof_id.into()],
        permission_inventory: None,
        runtime_capture: None,
        postgres_login_failure: None,
        login_catalog: vec![],
    };
    let yes = || Assurance::Verified {
        evidence_refs: vec![proof_id.into()],
    };
    let a = ClaimAssurance {
        claim_id: claim.id.clone(),
        coverage: AssuranceCoverage {
            target: yes(),
            principal: yes(),
            source: yes(),
            route: Assurance::Unconfirmed {
                reason: EvidenceReason::NativeLogOriginUnconfirmed,
            },
            transport: yes(),
            temporal: yes(),
            completeness: Assurance::Unconfirmed {
                reason: EvidenceReason::NativeLogOriginUnconfirmed,
            },
        },
    };
    let mut native = claim.clone();
    native.id = native_id;
    native.controls.clear();
    let mut na = a.clone();
    na.claim_id = native.id.clone();
    Ok((claim, a, native, na))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::adapters::source) fn sample() -> (
        IssuedObservation,
        CollectorConfig,
        CaseDiagnostic,
        GcpRouteObservation,
        serde_json::Value,
    ) {
        let (mut i, mut collector) = super::super::testsupport::fixture();
        let n = i.snapshot.gce().unwrap().native_identity.clone();
        let config = GcpRouteDenialConfig {
            source_ip: "10.0.0.2".parse().unwrap(),
            instance_name: "workload-vm".into(),
            network_name: "application".into(),
            subnetwork_name: "application-subnet".into(),
            firewall_name: "deny-direct-pg".into(),
            firewall_priority: 900,
        };
        let target = InstanceIdentity {
            project: n.project_id.clone(),
            name: "billing-postgres".into(),
            region: "asia-northeast1".into(),
            connection_name: format!("{}:asia-northeast1:billing-postgres", n.project_id),
            create_time: "1970-01-01T00:00:01Z".into(),
            database_version: "POSTGRES_16".into(),
            private_ip: "10.0.0.1".parse().unwrap(),
        };
        let generation = crate::adapters::deployment::gcp::generation_fingerprint(
            &target.project,
            &target.name,
            &target.create_time,
        );
        i.request.cases[0]
            .address
            .target
            .native_ref
            .generation_fingerprint = Some(generation.clone());
        collector.endpoints[0].generation_digest = generation;
        collector.endpoints[0].ip = target.private_ip;
        collector.route_denial = Some(config.clone());
        i.snapshot.gce_mut().unwrap().collector_config_digest =
            crate::config::hash_bytes(&serde_json::to_vec(&collector).unwrap());
        i.request.source.revision_digest = i.snapshot.revision_digest().unwrap();
        i.request.cases[0].address.source = i.request.source.snapshot_ref();
        let tuple = ConnectionTuple {
            endpoint: i.request.cases[0].endpoint.clone(),
            local_ip: config.source_ip,
            local_port: 40001,
            peer_ip: target.private_ip,
            peer_port: 5432,
        };
        let d = CaseDiagnostic {
            runtime_capture: None,
            runtime_failure: None,
            iam_inventory: None,
            case_id: "direct".into(),
            started_at: 111,
            finished_at: 124,
            outcome: DiagnosticOutcome::TcpTimedOut,
            connection: Some(tuple.clone()),
            postgres: None,
        };
        let source = SourceNetwork {
            instance_id: n.instance_id.clone(),
            instance_name: config.instance_name.clone(),
            network: format!(
                "https://www.googleapis.com/compute/v1/projects/{}/global/networks/{}",
                n.project_id, config.network_name
            ),
            subnetwork: format!(
                "https://www.googleapis.com/compute/v1/projects/{}/regions/asia-northeast1/subnetworks/{}",
                n.project_id, config.subnetwork_name
            ),
            source_ip: config.source_ip,
        };
        let log = serde_json::json!({"entries":[{"insertId":"native-firewall-entry-1","timestamp":"1970-01-01T00:01:59.123456789Z","logName":format!("projects/{}/logs/compute.googleapis.com%2Ffirewall",n.project_id),"resource":{"type":"gce_subnetwork","labels":{"project_id":n.project_id,"subnetwork_name":config.subnetwork_name,"location":"asia-northeast1"}},"jsonPayload":{"connection":{"src_ip":tuple.local_ip,"src_port":tuple.local_port,"dest_ip":tuple.peer_ip,"dest_port":tuple.peer_port,"protocol":6},"disposition":"DENIED","rule_details":{"reference":config.rule(),"priority":900,"action":"DENY","direction":"EGRESS"},"instance":{"project_id":n.project_id,"vm_name":config.instance_name,"zone":n.zone,"region":"asia-northeast1"},"vpc":{"project_id":n.project_id,"vpc_name":config.network_name,"subnetwork_name":config.subnetwork_name}}}]});
        let decision = select(
            &serde_json::to_vec(&log).unwrap(),
            &i,
            &config,
            &tuple,
            118,
            121,
        )
        .unwrap()
        .unwrap();
        let observation = GcpRouteObservation {
            case_id: d.case_id.clone(),
            config,
            source_before: source.clone(),
            source_after: source,
            target_before: target.clone(),
            target_after: target,
            decision,
            clock_bounds: [
                ProviderClockBound {
                    provider_at: 111,
                    local_started_millis: 111000,
                    local_finished_millis: 111100,
                    elapsed_millis: 100,
                },
                ProviderClockBound {
                    provider_at: 122,
                    local_started_millis: 122000,
                    local_finished_millis: 122100,
                    elapsed_millis: 100,
                },
                ProviderClockBound {
                    provider_at: 123,
                    local_started_millis: 123000,
                    local_finished_millis: 123100,
                    elapsed_millis: 100,
                },
            ],
            port_reserved_at: 112,
            probe_started_at: 118,
            probe_finished_at: 121,
        };
        (i, collector, d, observation, log)
    }
    #[test]
    fn exact_firewall_tuple_native_context_and_rule_are_required() {
        let (i, _, d, o, log) = sample();
        let check = |v: &serde_json::Value| {
            select(
                &serde_json::to_vec(v).unwrap(),
                &i,
                &o.config,
                d.connection.as_ref().unwrap(),
                118,
                121,
            )
        };
        assert!(check(&log).unwrap().is_some());
        for pointer in [
            "/entries/0/jsonPayload/connection/src_ip",
            "/entries/0/jsonPayload/connection/dest_ip",
            "/entries/0/jsonPayload/disposition",
            "/entries/0/jsonPayload/rule_details/action",
            "/entries/0/jsonPayload/rule_details/direction",
            "/entries/0/jsonPayload/rule_details/reference",
            "/entries/0/jsonPayload/instance/project_id",
            "/entries/0/jsonPayload/instance/vm_name",
            "/entries/0/jsonPayload/instance/zone",
            "/entries/0/jsonPayload/vpc/vpc_name",
            "/entries/0/resource/labels/subnetwork_name",
            "/entries/0/logName",
        ] {
            let mut v = log.clone();
            *v.pointer_mut(pointer).unwrap() = serde_json::json!("other");
            assert!(check(&v).ok().flatten().is_none(), "{pointer}");
        }
        for pointer in [
            "/entries/0/jsonPayload/connection/src_port",
            "/entries/0/jsonPayload/connection/dest_port",
            "/entries/0/jsonPayload/connection/protocol",
            "/entries/0/jsonPayload/rule_details/priority",
        ] {
            let mut v = log.clone();
            *v.pointer_mut(pointer).unwrap() = serde_json::json!(1);
            assert!(check(&v).unwrap().is_none(), "{pointer}");
        }
    }
    #[test]
    fn incomplete_mixed_old_and_oversized_logs_cannot_prove_route_block() {
        let (i, _, d, o, log) = sample();
        let check = |v: &serde_json::Value| {
            select(
                &serde_json::to_vec(v).unwrap(),
                &i,
                &o.config,
                d.connection.as_ref().unwrap(),
                118,
                121,
            )
        };
        let mut paged = log.clone();
        paged["nextPageToken"] = serde_json::json!("more");
        assert!(check(&paged).unwrap().is_none());
        let mut mixed = log.clone();
        let mut allowed = log["entries"][0].clone();
        allowed["jsonPayload"]["disposition"] = serde_json::json!("ALLOWED");
        mixed["entries"].as_array_mut().unwrap().push(allowed);
        assert!(check(&mixed).unwrap().is_none());
        let mut old = log.clone();
        old["entries"][0]["timestamp"] = serde_json::json!("1970-01-01T00:01:51Z");
        assert!(check(&old).unwrap().is_none());
        let mut missing = log.clone();
        missing["entries"][0]["jsonPayload"]
            .as_object_mut()
            .unwrap()
            .remove("instance");
        assert!(check(&missing).is_err());
        assert!(check(&serde_json::json!({"entries":[]})).unwrap().is_none());
        assert!(
            select(
                &vec![b' '; 65537],
                &i,
                &o.config,
                d.connection.as_ref().unwrap(),
                118,
                121
            )
            .is_err()
        );
        let text = serde_json::to_string(&log).unwrap().replace(
            "\"disposition\":\"DENIED\"",
            "\"disposition\":\"DENIED\",\"disposition\":\"ALLOWED\"",
        );
        assert!(
            select(
                text.as_bytes(),
                &i,
                &o.config,
                d.connection.as_ref().unwrap(),
                118,
                121
            )
            .is_err()
        );
    }
    #[test]
    fn admission_normalizer_rejects_connected_changed_generation_and_unbound_source() {
        let (i, config, d, o, _) = sample();
        config.validate_request(&i).unwrap();
        validate_observations(&i, std::slice::from_ref(&d), std::slice::from_ref(&o)).unwrap();
        let (claim, _, native, _) = normalize(&i, &i.request.cases[0], &d, &o, "proof").unwrap();
        assert_eq!(claim.denial_cause, Some(DenialCause::Unclassified));
        assert_eq!(claim.observed, StateValue::Unknown);
        assert_eq!(claim.layer, StateLayer::RouteEnforcement);
        assert!(claim.controls.is_empty());
        assert_eq!(native.observed, StateValue::Unknown);
        assert!(native.controls.is_empty());
        let mut connected = d.clone();
        connected.outcome = DiagnosticOutcome::TcpConnected;
        assert!(validate_observations(&i, &[connected], std::slice::from_ref(&o)).is_err());
        let mut changed = o.clone();
        changed.target_after.create_time = "changed".into();
        assert!(validate_observations(&i, std::slice::from_ref(&d), &[changed]).is_err());
        let mut changed = o.clone();
        changed.source_after.instance_id = "other".into();
        assert!(validate_observations(&i, std::slice::from_ref(&d), &[changed]).is_err());
        let mut changed = d.clone();
        changed.connection.as_mut().unwrap().local_ip = "10.0.0.3".parse().unwrap();
        assert!(validate_observations(&i, &[changed], std::slice::from_ref(&o)).is_err());
        assert!(validate_observations(&i, std::slice::from_ref(&d), &[o.clone(), o]).is_err());
    }
    #[test]
    fn query_sees_mixed_dispositions_and_never_infers_connector_refusal() {
        let (i, _, d, _, _) = sample();
        let q = query(&i, d.connection.as_ref().unwrap(), 118, 121).unwrap();
        assert!(q.contains("connection.src_port=40001"));
        assert!(!q.contains("disposition"));
        assert!(!q.contains("rule_details"));
        assert!(!q.contains("connectorEnforcement"));
    }
    #[test]
    fn native_compute_readback_requires_immutable_vm_and_exact_primary_network() {
        let (i, _, _, o, _) = sample();
        let n = &i.snapshot.gce().unwrap().native_identity;
        let value = serde_json::json!({"id":n.instance_id,"name":o.config.instance_name,"zone":format!("https://www.googleapis.com/compute/v1/projects/{}/zones/{}",n.project_id,n.zone),"networkInterfaces":[{"network":o.source_before.network,"subnetwork":o.source_before.subnetwork,"networkIP":o.config.source_ip}]});
        assert_eq!(
            parse_source(&serde_json::to_vec(&value).unwrap(), &i, &o.config).unwrap(),
            o.source_before
        );
        let mut wrong = value.clone();
        wrong["id"] = serde_json::json!("old-vm");
        assert!(parse_source(&serde_json::to_vec(&wrong).unwrap(), &i, &o.config).is_err());
        let mut shared = value.clone();
        shared["networkInterfaces"][0]["network"] = serde_json::json!(
            "https://www.googleapis.com/compute/v1/projects/another/global/networks/application"
        );
        assert!(parse_source(&serde_json::to_vec(&shared).unwrap(), &i, &o.config).is_err());
        let mut duplicate = value.clone();
        duplicate["networkInterfaces"]
            .as_array_mut()
            .unwrap()
            .push(value["networkInterfaces"][0].clone());
        assert!(parse_source(&serde_json::to_vec(&duplicate).unwrap(), &i, &o.config).is_err());
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    fn response(date: &str) -> Vec<u8> {
        format!(
            "HTTP/2 200\r\ndate: {date}\r\ncontent-type: application/json\r\n\r\n{{\"entries\":[]}}"
        )
        .into_bytes()
    }
    #[test]
    fn authenticated_date_bounds_the_entire_provider_clock_interval() {
        let good = response("Thu, 01 Jan 1970 00:01:59 GMT");
        let (body, clock) = timed_body(&good, 119000, 119200, 200).unwrap();
        assert_eq!(body, br#"{"entries":[]}"#);
        assert!(clock.valid());
        // Two seconds ahead is bounded; old tuple traffic is still excluded by
        // the separate >5-second reservation quarantine and strict probe window.
        assert!(timed_body(&good, 117000, 117200, 200).is_ok());
        assert!(timed_body(&good, 113000, 113200, 200).is_err());
        assert!(timed_body(&good, 125000, 125200, 200).is_err());
        assert!(timed_body(&good, 119000, 118000, 200).is_err());
        assert!(timed_body(&good, 119000, 122500, 3500).is_err());
        assert!(timed_body(&good, 119000, 119900, 100).is_err());
    }
    #[test]
    fn missing_duplicate_malformed_http_date_and_untrusted_status_fail_closed() {
        for date in [
            "Fri, 01 Jan 1970 00:01:59 GMT",
            "Thu, 31 Feb 1970 00:01:59 GMT",
            "Thu, 01 Jan 1970 00:01:59 UTC",
            "Thu, 1 Jan 1970 00:01:59 GMT",
            "bad",
        ] {
            assert!(timed_body(&response(date), 119000, 119200, 200).is_err());
        }
        let good = String::from_utf8(response("Thu, 01 Jan 1970 00:01:59 GMT")).unwrap();
        let duplicate = good.replace(
            "content-type:",
            "Date: Thu, 01 Jan 1970 00:01:59 GMT\r\ncontent-type:",
        );
        assert!(timed_body(duplicate.as_bytes(), 119000, 119200, 200).is_err());
        assert!(
            timed_body(
                b"HTTP/2 200\r\ncontent-type: application/json\r\n\r\n{}",
                119000,
                119200,
                200
            )
            .is_err()
        );
        assert!(
            timed_body(
                good.replace("HTTP/2 200", "HTTP/2 301").as_bytes(),
                119000,
                119200,
                200
            )
            .is_err()
        );
        assert!(timed_body(&vec![b'x'; 65537], 119000, 119200, 200).is_err());
    }
    #[test]
    fn two_second_ahead_old_tuple_cannot_cross_the_quarantine() {
        let (i, _, d, mut o, mut log) = super::tests::sample();
        // Old traffic just before port reservation, timestamped +2 seconds.
        log["entries"][0]["timestamp"] = serde_json::json!("1970-01-01T00:01:54Z");
        assert!(
            select(
                &serde_json::to_vec(&log).unwrap(),
                &i,
                &o.config,
                d.connection.as_ref().unwrap(),
                118,
                121
            )
            .unwrap()
            .is_none()
        );
        // A forged shortened quarantine is rejected at sealed normalization,
        // even if the selected log otherwise appears inside the probe window.
        o.probe_started_at = 114;
        o.decision.decision_at = 114;
        assert!(validate_observations(&i, std::slice::from_ref(&d), &[o]).is_err());
    }
}

#[cfg(test)]
mod origin_tests {
    use super::*;
    #[test]
    fn caller_writable_firewall_looking_entry_never_becomes_native_rejection() {
        let (i, _, d, o, _) = super::tests::sample();
        let (claim, assurance, auxiliary, auxiliary_assurance) = normalize(
            &i,
            &i.request.cases[0],
            &d,
            &o,
            "verified-source-https-capture",
        )
        .unwrap();
        for c in [&claim, &auxiliary] {
            assert_eq!(c.observed, StateValue::Unknown);
            assert_eq!(c.denial_cause, Some(DenialCause::Unclassified));
            assert!(c.controls.is_empty());
        }
        for a in [&assurance, &auxiliary_assurance] {
            assert!(matches!(
                a.coverage.route,
                Assurance::Unconfirmed {
                    reason: EvidenceReason::NativeLogOriginUnconfirmed
                }
            ));
            assert!(matches!(
                a.coverage.completeness,
                Assurance::Unconfirmed {
                    reason: EvidenceReason::NativeLogOriginUnconfirmed
                }
            ));
            assert!(matches!(a.coverage.transport, Assurance::Verified { .. }));
        }
    }
}
