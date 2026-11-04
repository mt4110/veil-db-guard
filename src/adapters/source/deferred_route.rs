//! Fixed CloudWatch FilterLogEvents acquisition port and VPC Flow Logs v2
//! parser and explicit metadata-IAM JSON client. No CLI/config URL fallback.
use crate::core::{admission::AdmissionError, deferred_route::*};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, future::Future};

/// Preserve the actual bound tuple even on a failed IPv4 connect. This is a
/// source diagnostic only: raw socket outcomes grant no denial assurance and
/// the socket is released on return, so reuse is not excluded.
#[cfg(unix)]
pub(super) async fn probe_diagnostic(
    case: &crate::core::evidence::RequestedCase,
    peer_ip: std::net::IpAddr,
    source_ip: std::net::IpAddr,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<super::gce_host::CaseDiagnostic, super::gce_host::SourceError> {
    use super::{
        gce_host::{CaseDiagnostic, DiagnosticOutcome, SourceError},
        origin::KernelSocketOutcome,
    };
    if case.kind != crate::core::evidence::FixedObservationCase::DirectPath {
        return Err(SourceError::Invalid);
    }
    let started_at = crate::domain::now();
    let (connection, outcome, _) = super::origin::socket_probe(
        &case.endpoint,
        std::net::SocketAddr::new(source_ip, 0),
        std::net::SocketAddr::new(peer_ip, case.port),
        cancel,
    )
    .await?;
    Ok(CaseDiagnostic {
        runtime_capture: None,
        runtime_failure: None,
        iam_inventory: None,
        case_id: case.id.clone(),
        started_at,
        finished_at: crate::domain::now(),
        outcome: match outcome {
            KernelSocketOutcome::Connected => DiagnosticOutcome::TcpConnected,
            KernelSocketOutcome::Refused => DiagnosticOutcome::TcpRefused,
            KernelSocketOutcome::TimedOut => DiagnosticOutcome::TcpTimedOut,
            _ => DiagnosticOutcome::TcpUnavailable,
        },
        connection: Some(connection),
        postgres: None,
    })
}

pub const MAX_FILTER_PAGES: usize = 4;
pub const MAX_FILTER_PAGE_BYTES: usize = 262144;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsDeferredRouteConfig {
    pub log_group_name: String,
    pub interface_id: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterLogEventsRequest {
    pub region: &'static str,
    pub log_group_name: String,
    pub start_time_millis: u64,
    pub end_time_millis: u64,
    pub filter_pattern: String,
    pub limit: u16,
    pub next_token: Option<String>,
}
/// Authenticated transport alone does not prove event origin. Implementations
/// must select the registered metadata-IAM actor explicitly; this port gives no
/// authority to use ambient credentials, change IAM or enable logs.
pub trait CloudWatchFilterLogEvents {
    fn filter_log_events(
        &mut self,
        request: &FilterLogEventsRequest,
    ) -> impl Future<Output = Result<Vec<u8>, AdmissionError>> + Send;
}
/// Authenticates the explicit metadata IAM actor; it never asserts this process
/// ran on the probe VM or that AWS generated the returned log payloads.
pub struct NativeCloudWatchClient {
    actor: crate::core::source::AwsMetadataCredential,
    account_id: String,
    cancellation: tokio_util::sync::CancellationToken,
    expected: FilterLogEventsRequest,
}
impl NativeCloudWatchClient {
    pub fn for_probe(
        probe: &DeferredProbe,
        config: &AwsDeferredRouteConfig,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<Self, AdmissionError> {
        probe.validate()?;
        let source = probe
            .issued
            .snapshot
            .aws()
            .ok_or(AdmissionError::VerifierUnavailable)?;
        Ok(Self {
            actor: source
                .metadata_credential
                .clone()
                .ok_or(AdmissionError::VerifierUnavailable)?,
            account_id: source.native_identity.account_id.clone(),
            cancellation,
            expected: fixed_request(probe, config)?,
        })
    }
}
fn native_error(_: super::gce_host::SourceError) -> AdmissionError {
    AdmissionError::VerifierUnavailable
}
impl CloudWatchFilterLogEvents for NativeCloudWatchClient {
    async fn filter_log_events(
        &mut self,
        r: &FilterLogEventsRequest,
    ) -> Result<Vec<u8>, AdmissionError> {
        if r.region != "ap-northeast-1"
            || r.log_group_name != self.expected.log_group_name
            || r.filter_pattern != self.expected.filter_pattern
            || r.start_time_millis != self.expected.start_time_millis
            || r.end_time_millis != self.expected.end_time_millis
            || !safe_name(&r.log_group_name)
            || r.limit != 128
            || r.end_time_millis < r.start_time_millis
            || r.end_time_millis - r.start_time_millis > 1_400_000
            || r.filter_pattern.len() > 2048
            || r.filter_pattern.chars().any(char::is_control)
            || r.next_token
                .as_ref()
                .is_some_and(|t| t.is_empty() || t.len() > 4096 || t.chars().any(char::is_control))
        {
            return Err(AdmissionError::Invalid);
        }
        let creds =
            super::aws_native::authenticate(&self.actor, &self.account_id, &self.cancellation)
                .await
                .map_err(native_error)?;
        let mut body = serde_json::json!({"logGroupName":r.log_group_name,"startTime":r.start_time_millis,"endTime":r.end_time_millis,"filterPattern":r.filter_pattern,"limit":r.limit});
        if let Some(token) = &r.next_token {
            body["nextToken"] = token.clone().into();
        }
        super::aws_native::json_api(
            &creds,
            "logs",
            "Logs_20140328.FilterLogEvents",
            &serde_json::to_vec(&body).map_err(|_| AdmissionError::Invalid)?,
            &self.cancellation,
        )
        .await
        .map_err(native_error)
    }
}
pub struct AwsDeferredRouteProducer<T, C> {
    pub transport: T,
    pub clock: C,
    pub config: AwsDeferredRouteConfig,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    events: Vec<Event>,
    next_token: Option<String>,
    #[serde(default, rename = "searchedLogStreams")]
    _searched_log_streams: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    event_id: String,
    timestamp: u64,
    ingestion_time: u64,
    message: String,
}

fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-#".contains(&b))
}
fn fixed_request(
    probe: &DeferredProbe,
    config: &AwsDeferredRouteConfig,
) -> Result<FilterLogEventsRequest, AdmissionError> {
    probe.validate()?;
    if !safe_name(&config.log_group_name)
        || !config.interface_id.starts_with("eni-")
        || !safe_name(&config.interface_id)
        || config.interface_id.len() > 64
        || probe.address.target.placement.region != "ap-northeast-1"
    {
        return Err(AdmissionError::Invalid);
    }
    let c = &probe.connection;
    Ok(FilterLogEventsRequest {
        region: "ap-northeast-1",
        log_group_name: config.log_group_name.clone(),
        start_time_millis: probe.observed_at.saturating_sub(660).saturating_mul(1000),
        end_time_millis: probe
            .probe_finished_at
            .saturating_add(660)
            .saturating_mul(1000),
        filter_pattern: format!(
            "[version = 2, account, interface = {}, srcaddr = {}, dstaddr = {}, srcport = {}, dstport = {}, protocol = 6, packets, bytes, start, end, action, status]",
            config.interface_id, c.local_ip, c.peer_ip, c.local_port, c.peer_port
        ),
        limit: 128,
        next_token: None,
    })
}
fn flow(e: &Event) -> Result<FlowEventCandidate, AdmissionError> {
    let p: Vec<_> = e.message.split_whitespace().collect();
    if e.message.len() > 2048
        || p.len() != 14
        || p[0] != "2"
        || p[13] != "OK"
        || !matches!(p[12], "ACCEPT" | "REJECT")
        || !safe_name(&e.event_id)
        || e.ingestion_time < e.timestamp
    {
        return Err(AdmissionError::Invalid);
    }
    let number = |i: usize| p[i].parse::<u64>().map_err(|_| AdmissionError::Invalid);
    let source_port = u16::try_from(number(5)?).map_err(|_| AdmissionError::Invalid)?;
    let destination_port = u16::try_from(number(6)?).map_err(|_| AdmissionError::Invalid)?;
    Ok(FlowEventCandidate {
        event_digest: crate::config::hash_bytes(
            &serde_json::to_vec(&(
                e.event_id.as_str(),
                e.timestamp,
                e.ingestion_time,
                e.message.as_str(),
            ))
            .map_err(|_| AdmissionError::Invalid)?,
        ),
        account_id: p[1].into(),
        interface_id: p[2].into(),
        source_ip: p[3].parse().map_err(|_| AdmissionError::Invalid)?,
        destination_ip: p[4].parse().map_err(|_| AdmissionError::Invalid)?,
        source_port,
        destination_port,
        protocol: u8::try_from(number(7)?).map_err(|_| AdmissionError::Invalid)?,
        packets: number(8)?,
        bytes: number(9)?,
        aggregate_started_at: number(10)?,
        aggregate_finished_at: number(11)?,
        action: if p[12] == "ACCEPT" {
            FlowAction::Accept
        } else {
            FlowAction::Reject
        },
    })
}
impl<T: CloudWatchFilterLogEvents + Send, C: crate::core::ports::EvidenceClock + Sync + Send>
    DeferredRouteProducer for AwsDeferredRouteProducer<T, C>
{
    async fn collect(&mut self, probe: &DeferredProbe) -> Result<DeferredCapture, AdmissionError> {
        let mut request = fixed_request(probe, &self.config)?;
        // V2's fixed positions. Deliberately do not filter action: ACCEPT must
        // remain visible alongside REJECT. Numeric/IP values cannot inject DSL.
        let mut events = vec![];
        let mut seen_events = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        let mut complete = false;
        for _ in 0..MAX_FILTER_PAGES {
            if self.clock.now() >= probe.delivery_deadline {
                return Err(AdmissionError::Expired);
            }
            let bytes = self.transport.filter_log_events(&request).await?;
            if bytes.len() > MAX_FILTER_PAGE_BYTES {
                return Err(AdmissionError::Limit);
            }
            let page: Page = serde_json::from_slice(&bytes).map_err(|_| AdmissionError::Invalid)?;
            if page.events.len() > MAX_FLOW_EVENTS {
                return Err(AdmissionError::Limit);
            }
            for event in page.events {
                let selected = flow(&event)?;
                if selected.interface_id != self.config.interface_id {
                    return Err(AdmissionError::ScopeMismatch);
                }
                if seen_events.insert(selected.event_digest.clone()) {
                    events.push(selected);
                }
                if events.len() > MAX_FLOW_EVENTS {
                    return Err(AdmissionError::Limit);
                }
            }
            match page.next_token {
                None => {
                    complete = true;
                    break;
                }
                Some(token)
                    if !token.is_empty()
                        && token.len() <= 4096
                        && !token.chars().any(char::is_control) =>
                {
                    if !seen_tokens.insert(token.clone()) {
                        break;
                    }
                    request.next_token = Some(token);
                }
                _ => return Err(AdmissionError::Invalid),
            }
        }
        Ok(DeferredCapture {
            probe_digest: probe.digest()?,
            received_at: self.clock.now(),
            events,
            scan_complete: complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapters::evidence::RunEvidenceArchive,
        core::{admission::*, evidence::*, policy::*, ports::*, source::*, state::*},
        deferred_route_store::DeferredRouteStore,
        evidence_store::{EvidenceStore, ObservationRequestSpec},
    };
    struct Clock(u64);
    impl EvidenceClock for Clock {
        fn now(&self) -> u64 {
            self.0
        }
    }
    struct SyntheticVerifier;
    impl ObservationVerifier for SyntheticVerifier {
        fn verify(
            &mut self,
            _: &IssuedObservation,
            b: &ObservationBundleWire,
            _: &[EvidencePayload],
            _: CaptureWindow,
        ) -> Result<VerifierFindings, AdmissionError> {
            let yes = Assurance::Verified {
                evidence_refs: vec!["fixture".into()],
            };
            let no = Assurance::Unconfirmed {
                reason: EvidenceReason::NativeLogOriginUnconfirmed,
            };
            Ok(VerifierFindings {
                recipe_id: "synthetic-deferred-test".into(),
                source_evidence_refs: vec!["fixture".into()],
                assurances: b
                    .claims
                    .iter()
                    .map(|c| ClaimAssurance {
                        claim_id: c.id.clone(),
                        coverage: AssuranceCoverage {
                            source: yes.clone(),
                            temporal: yes.clone(),
                            target: no.clone(),
                            principal: no.clone(),
                            route: no.clone(),
                            transport: no.clone(),
                            completeness: no.clone(),
                        },
                    })
                    .collect(),
            })
        }
    }
    struct Lab {
        _temp: tempfile::TempDir,
        ledger: EvidenceStore,
        deferred: DeferredRouteStore,
        archive: RunEvidenceArchive,
        issued: IssuedObservation,
    }
    impl Lab {
        fn new(connection: bool, allowed: bool) -> Self {
            let (fixture, _) = super::super::aws_host::tests::fixture();
            let mut p =
                parse_policy(include_str!("../../../examples/core-aws-policy.yaml")).unwrap();
            p.schema_version = 2;
            p.targets[0].resource = fixture.request.cases[0].address.target.native_ref.clone();
            p.source_bindings = p
                .subjects
                .iter()
                .enumerate()
                .map(|(n, s)| {
                    if n == 0 {
                        fixture.request.source.clone()
                    } else {
                        SourceBinding {
                            source_id: s.workload_sources[0].clone(),
                            registration_id: "recovery-source".into(),
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
            p.evaluation = Some(EvaluationPolicy {
                contract: EvaluationContract::SourceBoundV2,
                denial_requirements: vec![ProfileDenialRequirement {
                    profile_id: p.protection_profiles[0].id.clone(),
                    accepted_layers: vec![AcceptedDenialLayer::ConnectionAuthorization],
                }],
            });
            let plan = crate::core::plan::build_plan(
                &p,
                crate::adapters::capabilities_for_policy(&p).unwrap(),
                vec![],
                100,
            )
            .unwrap();
            let change = crate::core::change::prepare_change(
                &p,
                &plan,
                &[],
                None,
                crate::core::change::OperationLimits::default(),
            )
            .unwrap();
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("ledger.sqlite");
            let mut ledger = EvidenceStore::open(&path).unwrap();
            ledger.register_source(&fixture.snapshot, None).unwrap();
            ledger.start_session(&change, "session", 100).unwrap();
            let mut cases = fixture.request.cases.clone();
            cases[0].address.target.registration_id = p.targets[0].registration_id.clone();
            cases[0].address.db_identity = p.grants[0].db_identity.clone();
            cases[0].endpoint = p.targets[0].aws.as_ref().unwrap().db_endpoint.clone();
            let issued = ledger
                .issue_request(
                    &ObservationRequestSpec {
                        request_id: "probe".into(),
                        operation_id: "session".into(),
                        source_id: fixture.request.source.source_id.clone(),
                        ttl_seconds: 120,
                        cases,
                    },
                    100,
                )
                .unwrap();
            let archive_root = temp.path().join("archive");
            std::fs::create_dir(&archive_root).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&archive_root, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            let mut archive = RunEvidenceArchive::open(&archive_root).unwrap();
            let payload = EvidencePayload {
                id: "fixture".into(),
                bytes: b"local synthetic probe".to_vec(),
            };
            let b = ObservationBundleWire {
                schema_version: 1,
                request_digest: issued.request.digest().unwrap(),
                collector_build_id: issued.request.collector_build_id.clone(),
                started_at: 110,
                finished_at: 115,
                capture_complete: false,
                artifacts: vec![ArtifactRef {
                    id: payload.id.clone(),
                    sha256: crate::config::hash_bytes(&payload.bytes),
                }],
                claims: vec![ObservationClaim {
                    id: "claim".into(),
                    case_id: issued.request.cases[0].id.clone(),
                    policy_revision_hash: issued.request.policy_revision_hash.clone(),
                    address: issued.request.cases[0].address.clone(),
                    started_at: 111,
                    finished_at: 114,
                    observed: if allowed {
                        StateValue::Allowed
                    } else {
                        StateValue::Unknown
                    },
                    layer: StateLayer::RouteEnforcement,
                    denial_cause: None,
                    connection: connection.then(|| ConnectionTuple {
                        endpoint: issued.request.cases[0].endpoint.clone(),
                        local_ip: "10.0.0.10".parse().unwrap(),
                        local_port: 45000,
                        peer_ip: "10.0.1.20".parse().unwrap(),
                        peer_port: 5432,
                    }),
                    runtime_capture: None,
                    postgres_login_failure: None,
                    login_catalog: vec![],
                    controls: vec![],
                    transport: vec![],
                    sql_context: None,
                    evidence_refs: vec!["fixture".into()],
                    permission_inventory: None,
                }],
            };
            accept_evidence(
                &mut ledger,
                &mut archive,
                &mut SyntheticVerifier,
                "probe",
                &serde_json::to_vec(&b).unwrap(),
                &[payload],
                CaptureWindow {
                    sent_at: 110,
                    received_at: 115,
                    elapsed_millis: 5000,
                },
                &Clock(116),
            )
            .unwrap();
            let deferred = DeferredRouteStore::open(&path).unwrap();
            Self {
                _temp: temp,
                ledger,
                deferred,
                archive,
                issued,
            }
        }
        fn issue(&mut self) -> Result<String, AdmissionError> {
            issue_deferred_probe(
                &mut self.ledger,
                &self.archive,
                &mut self.deferred,
                "probe",
                &self.issued.request.cases[0].id,
                117,
            )
        }
    }
    struct FakeCloudWatch {
        pages: std::collections::VecDeque<Vec<u8>>,
        requests: Vec<FilterLogEventsRequest>,
        ledger_path: Option<std::path::PathBuf>,
    }
    impl CloudWatchFilterLogEvents for FakeCloudWatch {
        async fn filter_log_events(
            &mut self,
            request: &FilterLogEventsRequest,
        ) -> Result<Vec<u8>, AdmissionError> {
            tokio::task::yield_now().await;
            if let Some(path) = &self.ledger_path {
                let c = rusqlite::Connection::open(path).unwrap();
                c.execute_batch("BEGIN IMMEDIATE; COMMIT;").unwrap();
            }
            self.requests.push(request.clone());
            self.pages
                .pop_front()
                .ok_or(AdmissionError::VerifierUnavailable)
        }
    }
    fn event(action: &str, id: &str) -> serde_json::Value {
        serde_json::json!({"eventId":id,"timestamp":114000,"ingestionTime":250000,"message":format!("2 123456789012 eni-0123456789abcdef0 10.0.0.10 10.0.1.20 45000 5432 6 1 60 100 120 {action} OK")})
    }
    fn producer(
        pages: Vec<serde_json::Value>,
        now: u64,
    ) -> AwsDeferredRouteProducer<FakeCloudWatch, Clock> {
        AwsDeferredRouteProducer {
            transport: FakeCloudWatch {
                pages: pages
                    .into_iter()
                    .map(|v| serde_json::to_vec(&v).unwrap())
                    .collect(),
                requests: vec![],
                ledger_path: None,
            },
            clock: Clock(now),
            config: AwsDeferredRouteConfig {
                log_group_name: "/aws/vpc/flowlogs".into(),
                interface_id: "eni-0123456789abcdef0".into(),
            },
        }
    }
    #[tokio::test]
    async fn deferred_history_uses_real_sqlite_archive_and_retains_accept_and_allowed() {
        let mut lab = Lab::new(true, true);
        let digest = lab.issue().unwrap();
        let facts = load_admitted(&mut lab.ledger, &lab.archive, "probe", 118).unwrap();
        assert_eq!(lab.issue(), Err(AdmissionError::Conflict));
        let mut p = producer(
            vec![
                serde_json::json!({"events":[event("REJECT","reject")],"nextToken":"page2"}),
                serde_json::json!({"events":[event("ACCEPT","accept")]}),
            ],
            250,
        );
        p.transport.ledger_path = Some(lab._temp.path().join("ledger.sqlite"));
        let r = collect_deferred_route(
            &mut lab.deferred,
            &mut lab.archive,
            &mut p,
            &digest,
            &[facts],
            &Clock(250),
        )
        .await
        .unwrap();
        assert_eq!((r.observed_at, r.received_at), (111, 250));
        assert_eq!((r.reject_candidate_count, r.accept_candidate_count), (1, 1));
        assert!(r.probe_was_allowed);
        assert!(
            r.limitations
                .contains(&DeferredRouteLimitation::NativeLogOriginUnconfirmed)
        );
        // Its current admission has expired; the original Allowed remains in
        // history and can never be turned into a current denial by this API.
        assert!(r.current_allowed_claim_refs.is_empty());
        assert_eq!(p.transport.requests[1].next_token.as_deref(), Some("page2"));
        assert!(!p.transport.requests[0].filter_pattern.contains("REJECT"));
        let (_, capture) = read_deferred_history(&mut lab.deferred, &lab.archive, &digest).unwrap();
        assert_eq!(capture.events.len(), 2);
        assert_eq!(
            collect_deferred_route(
                &mut lab.deferred,
                &mut lab.archive,
                &mut p,
                &digest,
                &[],
                &Clock(251)
            )
            .await,
            Err(AdmissionError::Conflict)
        );
        assert_eq!(
            load_admitted(&mut lab.ledger, &lab.archive, "probe", 250).unwrap_err(),
            AdmissionError::Expired
        );
        let artifact = lab
            ._temp
            .path()
            .join("archive")
            .join(r.archive.run_id)
            .join("evidence-bundle.json");
        std::fs::write(artifact, b"{}").unwrap();
        assert!(matches!(
            read_deferred_history(&mut lab.deferred, &lab.archive, &digest),
            Err(AdmissionError::Integrity)
        ));
    }
    #[tokio::test]
    async fn current_allowed_is_explicit_when_still_fresh() {
        let mut lab = Lab::new(true, true);
        let digest = lab.issue().unwrap();
        let facts = load_admitted(&mut lab.ledger, &lab.archive, "probe", 118).unwrap();
        let mut p = producer(vec![serde_json::json!({"events":[]})], 119);
        let r = collect_deferred_route(
            &mut lab.deferred,
            &mut lab.archive,
            &mut p,
            &digest,
            &[facts],
            &Clock(119),
        )
        .await
        .unwrap();
        assert_eq!(r.current_allowed_claim_refs.len(), 1);
    }
    #[tokio::test]
    async fn missing_probe_tuple_expiry_and_mismatched_five_tuple_fail_closed() {
        let mut missing = Lab::new(false, false);
        assert_eq!(missing.issue(), Err(AdmissionError::VerifierUnavailable));
        let mut lab = Lab::new(true, false);
        let digest = lab.issue().unwrap();
        let mut p = producer(vec![serde_json::json!({"events":[]})], 4000);
        assert_eq!(
            collect_deferred_route(
                &mut lab.deferred,
                &mut lab.archive,
                &mut p,
                &digest,
                &[],
                &Clock(4000)
            )
            .await,
            Err(AdmissionError::Expired)
        );
        assert!(p.transport.requests.is_empty());
        let mut wrong = event("REJECT", "wrong");
        wrong["message"] = wrong["message"]
            .as_str()
            .unwrap()
            .replace("45000", "45001")
            .into();
        let mut p = producer(vec![serde_json::json!({"events":[wrong]})], 250);
        assert_eq!(
            collect_deferred_route(
                &mut lab.deferred,
                &mut lab.archive,
                &mut p,
                &digest,
                &[],
                &Clock(250)
            )
            .await,
            Err(AdmissionError::ScopeMismatch)
        );
        assert_eq!(lab.deferred.receipt(&digest), Err(AdmissionError::NotFound));
    }
    #[tokio::test]
    async fn bounded_pages_and_duplicate_tokens_are_incomplete_never_verified() {
        let mut lab = Lab::new(true, false);
        let digest = lab.issue().unwrap();
        let page = serde_json::json!({"events":[event("REJECT","same")],"nextToken":"repeated"});
        let mut p = producer(vec![page.clone(), page], 250);
        let r = collect_deferred_route(
            &mut lab.deferred,
            &mut lab.archive,
            &mut p,
            &digest,
            &[],
            &Clock(250),
        )
        .await
        .unwrap();
        assert!(!r.scan_complete);
        assert_eq!(r.reject_candidate_count, 1);
    }

    #[tokio::test]
    async fn api_errors_cannot_become_empty_complete_scans_and_missing_actor_is_unsupported() {
        let mut lab = Lab::new(true, false);
        let digest = lab.issue().unwrap();
        let probe = lab.deferred.probe(&digest).unwrap();
        let mut p = producer(
            vec![serde_json::json!({"__type":"AccessDeniedException","message":"redacted"})],
            250,
        );
        assert_eq!(
            collect_deferred_route(
                &mut lab.deferred,
                &mut lab.archive,
                &mut p,
                &digest,
                &[],
                &Clock(250)
            )
            .await,
            Err(AdmissionError::Invalid)
        );
        assert!(matches!(
            NativeCloudWatchClient::for_probe(
                &probe,
                &p.config,
                tokio_util::sync::CancellationToken::new()
            ),
            Err(AdmissionError::VerifierUnavailable)
        ));
    }

    #[tokio::test]
    async fn persisted_probe_scope_tampering_cannot_be_rebound() {
        let mut lab = Lab::new(true, false);
        let digest = lab.issue().unwrap();
        let original = lab.deferred.probe(&digest).unwrap();
        for field in ["operation", "change", "generation", "source", "port"] {
            let mut p = original.clone();
            match field {
                "operation" => p.issued.request.operation_id = "foreign-operation".into(),
                "change" => p.issued.request.change_hash = "f".repeat(64),
                "generation" => {
                    p.address.target.native_ref.generation_fingerprint = Some("f".repeat(64));
                    p.issued.request.cases[0].address = p.address.clone();
                }
                "source" => p.issued.request.source.revision_digest = "f".repeat(64),
                _ => p.connection.local_port += 1,
            }
            let c = rusqlite::Connection::open(lab._temp.path().join("ledger.sqlite")).unwrap();
            c.execute(
                "UPDATE deferred_route_probes SET body=?1 WHERE digest=?2",
                rusqlite::params![serde_json::to_string(&p).unwrap(), digest],
            )
            .unwrap();
            assert!(lab.deferred.probe(&digest).is_err(), "{field}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_loopback_refusal_keeps_source_tuple_without_native_denial_proof() {
        let (i, _) = super::super::aws_host::tests::fixture();
        let mut c = i.request.cases[0].clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        c.port = listener.local_addr().unwrap().port();
        drop(listener);
        let ip = "127.0.0.1".parse().unwrap();
        let d = probe_diagnostic(&c, ip, ip, &tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            d.outcome,
            super::super::gce_host::DiagnosticOutcome::TcpRefused
        );
        let t = d.connection.unwrap();
        assert_eq!(t.local_ip, ip);
        assert_ne!(t.local_port, 0);
        assert_eq!(t.peer_port, c.port);
        assert!(d.postgres.is_none());
        assert!(d.iam_inventory.is_none());
    }
}
