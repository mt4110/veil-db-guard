//! Field-matched GCP connection-authorization log candidates. Authenticated
//! Logging retrieval does not establish the original log producer; candidates
//! remain Unknown until a provider-origin trust boundary is established.
use super::{gce_host::SourceError, process};
use crate::core::{admission::IssuedObservation, evidence::*, state::*};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio_util::sync::CancellationToken;

const PERMISSION: &str = "cloudsql.instances.connect";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GcpConnectDenial {
    pub marker: String,
    pub principal: String,
    pub caller_ip: std::net::IpAddr,
    pub resource: String,
    pub permission: String,
    pub decision_at: u64,
    pub entry_digest: String,
}
/// This marker is bound to an issued nonce and the exact case. It is passed to
/// a private, one-case Proxy process; merely matching a principal/time is not
/// enough to attribute an audit entry to this workload's attempt.
pub(super) fn marker(i: &IssuedObservation, c: &RequestedCase) -> String {
    let bytes = serde_json::to_vec(&(&i.request.nonce, &c.id)).expect("string tuple");
    format!("veil-observe/{}", crate::config::hash_bytes(&bytes))
}
impl GcpConnectDenial {
    pub(super) fn matches(
        &self,
        i: &IssuedObservation,
        c: &RequestedCase,
        start: u64,
        end: u64,
    ) -> bool {
        i.snapshot.gce().is_some_and(|s| {
            self.principal == s.native_identity.service_account
                && s.gce_host
                    .as_ref()
                    .is_some_and(|h| h.ssh_ip == self.caller_ip)
                && self.marker == marker(i, c)
                && self.resource == c.address.target.native_ref.native_id
                && self.permission == PERMISSION
                && self.decision_at >= start
                && self.decision_at <= end
                && crate::core::policy::valid_hash(&self.entry_digest)
        })
    }
}

// Provider additions are ignored on raw responses; duplicate known fields are
// rejected by serde. Raw textPayload/status.message/customer rows are not read.
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
    proto_payload: Audit,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Audit {
    #[serde(rename = "@type")]
    kind: String,
    service_name: String,
    method_name: String,
    resource_name: String,
    status: Status,
    authentication_info: Authentication,
    authorization_info: Vec<Authorization>,
    request_metadata: Metadata,
}
#[derive(Deserialize)]
struct Status {
    code: i32,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authentication {
    principal_email: String,
    principal_subject: String,
    #[serde(default)]
    service_account_delegation_info: Vec<serde_json::Value>,
}
#[derive(Deserialize)]
struct Authorization {
    permission: String,
    resource: String,
    granted: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    caller_ip: String,
    caller_supplied_user_agent: String,
}

/// Parse canonical UTC provider timestamps, including fractional seconds,
/// with calendar validation. All comparison is at the existing capture's
/// second precision; no freshness is created from receiveTimestamp.
pub(super) fn timestamp(s: &str) -> Result<u64, SourceError> {
    let canonical = if s.len() == 20 {
        s.to_owned()
    } else {
        let b = s.as_bytes();
        if !(22..=30).contains(&b.len())
            || b.get(19) != Some(&b'.')
            || b.last() != Some(&b'Z')
            || !b[20..b.len() - 1].iter().all(u8::is_ascii_digit)
        {
            return Err(SourceError::Invalid);
        }
        format!("{}Z", s.get(..19).ok_or(SourceError::Invalid)?)
    };
    // Shared fixed-format calendar parser; no AWS IO or credentials involved.
    super::aws_native::parse_time(&canonical)
}
pub(super) fn utc(seconds: u64) -> Result<String, SourceError> {
    if seconds > 4_102_444_799 {
        return Err(SourceError::Invalid);
    }
    let mut days = seconds / 86400;
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let mut year = 1970;
    loop {
        let n = if leap(year) { 366 } else { 365 };
        if days < n {
            break;
        }
        days -= n;
        year += 1;
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= months[month] {
        days -= months[month];
        month += 1;
    }
    Ok(format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        days + 1,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    ))
}
pub(super) fn select(
    bytes: &[u8],
    i: &IssuedObservation,
    c: &RequestedCase,
    start: u64,
    end: u64,
) -> Result<Option<GcpConnectDenial>, SourceError> {
    if bytes.len() > 65536 || start > end {
        return Err(SourceError::Invalid);
    }
    let response: Entries = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
    if !response.next_page_token.is_empty()
        || response.entries.is_empty()
        || response.entries.len() > 16
    {
        return Ok(None);
    }
    let actor = &i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity
        .service_account;
    let expected_ip = i
        .snapshot
        .gce()
        .and_then(|s| s.gce_host.as_ref())
        .ok_or(SourceError::Unsupported)?
        .ssh_ip;
    let expected_marker = marker(i, c);
    let resource = &c.address.target.native_ref.native_id;
    let mut selected = None;
    for e in response.entries {
        let p = e.proto_payload;
        let at = timestamp(&e.timestamp)?;
        if e.insert_id.is_empty()
            || e.insert_id.len() > 1024
            || e.log_name
                != format!(
                    "projects/{}/logs/cloudaudit.googleapis.com%2Factivity",
                    c.address.target.placement.account_id
                )
            || p.kind != "type.googleapis.com/google.cloud.audit.AuditLog"
            || p.service_name != "cloudsql.googleapis.com"
            || p.method_name != PERMISSION
            || p.resource_name != *resource
            || p.status.code != 7
            || p.authentication_info.principal_email != *actor
            || p.authentication_info.principal_subject != format!("serviceAccount:{actor}")
            || !p
                .authentication_info
                .service_account_delegation_info
                .is_empty()
            || p.request_metadata
                .caller_ip
                .parse::<std::net::IpAddr>()
                .ok()
                != Some(expected_ip)
            || p.request_metadata.caller_supplied_user_agent.len() > 4096
            || !p
                .request_metadata
                .caller_supplied_user_agent
                .split_ascii_whitespace()
                .any(|a| a == expected_marker)
            || p.authorization_info.len() != 1
            || !p
                .authorization_info
                .iter()
                .all(|a| a.resource == *resource && a.permission == PERMISSION && !a.granted)
            || at < start
            || at > end
        {
            // Includes mixed authorization outcomes for this marker. Do not
            // filter successful attempts out before interpreting the results.
            return Ok(None);
        }
        let decision = GcpConnectDenial {
            marker: expected_marker.clone(),
            principal: actor.clone(),
            caller_ip: expected_ip,
            resource: resource.clone(),
            permission: PERMISSION.into(),
            decision_at: at,
            entry_digest: crate::config::hash_bytes(e.insert_id.as_bytes()),
        };
        if selected
            .as_ref()
            .is_none_or(|old: &GcpConnectDenial| old.decision_at <= at)
        {
            selected = Some(decision);
        }
    }
    Ok(selected)
}
fn query(
    i: &IssuedObservation,
    c: &RequestedCase,
    start: u64,
    end: u64,
) -> Result<String, SourceError> {
    let actor = &i
        .snapshot
        .gce()
        .ok_or(SourceError::Unsupported)?
        .native_identity
        .service_account;
    // Every interpolated value is JSON-quoted as a Logging string literal.
    let q = |s: &str| serde_json::to_string(s).expect("string");
    let filter = format!(
        "protoPayload.serviceName={} AND protoPayload.methodName={} AND protoPayload.resourceName={} AND protoPayload.authenticationInfo.principalEmail={} AND protoPayload.requestMetadata.callerSuppliedUserAgent:{} AND timestamp>={} AND timestamp<={}",
        q("cloudsql.googleapis.com"),
        q(PERMISSION),
        q(&c.address.target.native_ref.native_id),
        q(actor),
        q(&marker(i, c)),
        q(&utc(start)?),
        q(&format!("{}.999999999Z", utc(end)?.trim_end_matches('Z')))
    );
    serde_json::to_string(&serde_json::json!({"resourceNames":[format!("projects/{}", c.address.target.placement.account_id)],"filter":filter,"orderBy":"timestamp desc","pageSize":16})).map_err(|_|SourceError::Invalid)
}
/// Read-only Cloud Logging request. The workload token remains in scrubbed
/// process stdin; no body, token, error text, or delegation material is saved.
pub(super) async fn collect_connect_denial(
    i: &IssuedObservation,
    c: &RequestedCase,
    token: &str,
    start: u64,
    end: u64,
    cancel: &CancellationToken,
) -> Result<Option<GcpConnectDenial>, SourceError> {
    let body = query(i, c, start, end)?;
    let args: Vec<String> = [
        "-q",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--max-time",
        "5",
        "--max-filesize",
        "65536",
        "--silent",
        "--fail",
        "--header",
        "@-",
        "--header",
        "Content-Type: application/json",
        "--data-raw",
        &body,
        "https://logging.googleapis.com/v2/entries:list",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    let header = format!("Authorization: Bearer {token}\n");
    let bytes = process::run(
        Path::new("/usr/bin/curl"),
        &args,
        header.as_bytes(),
        65536,
        5,
        cancel,
    )
    .await?;
    select(&bytes, i, c, start, end)
}

/// The main claim binds the failed new connection to its separately selected
/// native authorization decision. Health still needs an independent successful
/// connection from admitted evidence; this function never manufactures health.
pub(super) fn append_native_decisions(
    claims: &mut Vec<ObservationClaim>,
    assurances: &mut Vec<ClaimAssurance>,
) {
    let mut extra = vec![];
    for claim in claims.iter_mut().filter(|c| {
        (c.id.starts_with("source-") || c.id.starts_with("aws-pg-"))
            && c.observed == StateValue::Denied
            && ((c.layer == StateLayer::ConnectionAuthorization
                && c.denial_cause == Some(DenialCause::PermissionDenied))
                || (c.layer == StateLayer::Authentication
                    && c.denial_cause == Some(DenialCause::LoginRejected)
                    && c.postgres_login_failure.is_some()))
    }) {
        let Some(a) = assurances.iter().find(|a| a.claim_id == claim.id).cloned() else {
            continue;
        };
        let mut native = claim.clone();
        native.id = format!("native-{}", claim.case_id);
        native.controls.clear();
        claim.controls.push(ControlReference {
            bundle_digest: None,
            claim_id: native.id.clone(),
            purpose: ControlPurpose::NativeBoundaryDecision,
        });
        extra.push((native, a));
    }
    for (claim, mut assurance) in extra {
        assurance.claim_id = claim.id.clone();
        claims.push(claim);
        assurances.push(assurance);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(in crate::adapters::source) fn sample()
    -> (IssuedObservation, RequestedCase, serde_json::Value) {
        let (i, c, _) = super::super::postgres::tests::sample();
        let actor = i
            .snapshot
            .gce()
            .unwrap()
            .native_identity
            .service_account
            .clone();
        let resource = c.address.target.native_ref.native_id.clone();
        let value = serde_json::json!({"entries":[{
            "insertId":"provider-entry-id", "timestamp":"1970-01-01T00:01:52.123456789Z",
            "logName":format!("projects/{}/logs/cloudaudit.googleapis.com%2Factivity", c.address.target.placement.account_id),
            "protoPayload":{
                "@type":"type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName":"cloudsql.googleapis.com", "methodName":PERMISSION,
                "resourceName":resource,"status":{"code":7,"message":"PRIVATE-SENTINEL"},
                "authenticationInfo":{"principalEmail":actor,"principalSubject":format!("serviceAccount:{actor}")},
                "authorizationInfo":[{"permission":PERMISSION,"resource":resource,"granted":false}],
                "requestMetadata":{"callerIp":i.snapshot.gce().unwrap().gce_host.as_ref().unwrap().ssh_ip.to_string(),"callerSuppliedUserAgent":format!("cloud-sql-proxy/2.26.3 {}",marker(&i,&c))},
                "request":{"public_key":"PRIVATE-SENTINEL"}
            }
        }]});
        (i, c, value)
    }
    #[test]
    fn audit_recipe_selects_only_exact_nonce_actor_permission_resource_and_capture_time() {
        let (i, c, value) = sample();
        let selected = select(&serde_json::to_vec(&value).unwrap(), &i, &c, 111, 114)
            .unwrap()
            .unwrap();
        assert!(selected.matches(&i, &c, 111, 114));
        assert!(
            !serde_json::to_string(&selected)
                .unwrap()
                .contains("PRIVATE-SENTINEL")
        );
        for n in 0..16 {
            let mut value = value.clone();
            let p = &mut value["entries"][0]["protoPayload"];
            match n {
                0 => p["status"]["code"] = 0.into(),
                1 => {
                    p["authenticationInfo"]["principalEmail"] =
                        "other@project.iam.gserviceaccount.com".into()
                }
                2 => p["authenticationInfo"]["principalSubject"] = "serviceAccount:other".into(),
                3 => p["authorizationInfo"][0]["permission"] = "cloudsql.instances.get".into(),
                4 => {
                    p["authorizationInfo"][0]["resource"] =
                        "projects/other/instances/same-name".into()
                }
                5 => p["authorizationInfo"][0]["granted"] = true.into(),
                6 => {
                    p["requestMetadata"]["callerSuppliedUserAgent"] =
                        "cloud-sql-proxy/2.26.3".into()
                }
                7 => p["methodName"] = "cloudsql.instances.login".into(),
                8 => p["serviceName"] = "untrusted.googleapis.com".into(),
                9 => {
                    p["authenticationInfo"]["serviceAccountDelegationInfo"] =
                        serde_json::json!([{}])
                }
                10 => value["entries"][0]["timestamp"] = "1970-01-01T00:01:50Z".into(),
                11 => value["nextPageToken"] = "more".into(),
                12 => {
                    value["entries"][0]["logName"] =
                        "projects/other/logs/cloudaudit.googleapis.com%2Factivity".into()
                }
                13 => value["entries"][0]["timestamp"] = "1970-01-01T00:01:55Z".into(),
                14 => p["requestMetadata"]["callerIp"] = "192.0.2.11".into(),
                _ => p["requestMetadata"]["callerIp"] = "private".into(),
            }
            assert!(
                select(&serde_json::to_vec(&value).unwrap(), &i, &c, 111, 114)
                    .unwrap()
                    .is_none(),
                "case {n}"
            );
        }
    }
    #[test]
    fn mixed_success_reused_nonce_duplicate_fields_and_missing_logs_never_prove_denial() {
        let (i, c, value) = sample();
        let mut mixed = value.clone();
        let mut success = mixed["entries"][0].clone();
        success["protoPayload"]["status"]["code"] = 0.into();
        mixed["entries"].as_array_mut().unwrap().push(success);
        assert!(
            select(&serde_json::to_vec(&mixed).unwrap(), &i, &c, 111, 114)
                .unwrap()
                .is_none()
        );
        let mut other = i.clone();
        other.request.nonce = "e".repeat(64);
        assert!(
            select(&serde_json::to_vec(&value).unwrap(), &other, &c, 111, 114)
                .unwrap()
                .is_none()
        );
        assert!(select(br#"{}"#, &i, &c, 111, 114).unwrap().is_none());
        let text = serde_json::to_string(&value)
            .unwrap()
            .replace("\"code\":7", "\"code\":7,\"code\":0");
        assert!(select(text.as_bytes(), &i, &c, 111, 114).is_err());
        assert!(
            select(
                br#"{"error":{"code":403,"message":"cloudsql.instances.connect denied"}}"#,
                &i,
                &c,
                111,
                114
            )
            .unwrap()
            .is_none()
        );
        assert!(select(&vec![b' '; 65537], &i, &c, 111, 114).is_err());
    }
    #[test]
    fn query_is_read_only_bounded_and_never_filters_out_successful_decisions() {
        let (i, c, _) = sample();
        let request: serde_json::Value =
            serde_json::from_str(&query(&i, &c, 111, 114).unwrap()).unwrap();
        assert_eq!(request["pageSize"], 16);
        let filter = request["filter"].as_str().unwrap();
        assert!(!filter.contains("status.code"));
        assert!(filter.contains(&marker(&i, &c)));
        assert!(filter.contains("1970-01-01T00:01:54.999999999Z"));
        assert_eq!(
            timestamp("2024-02-29T23:59:59.000000001Z").unwrap(),
            1709251199
        );
        assert!(timestamp("2023-02-29T00:00:00Z").is_err());
        assert!(timestamp("2024-02-29T23:59:59.Z").is_err());
        for seconds in [0, 111, 1709251199, 1793664000, 4_102_444_799] {
            assert_eq!(timestamp(&utc(seconds).unwrap()).unwrap(), seconds);
        }
    }
    #[test]
    fn exact_audit_candidate_stays_unknown_without_producer_origin_and_retains_allowed() {
        let (i, c, mut d) = super::super::postgres::tests::sample();
        let (_, _, raw) = sample();
        let n = select(
            &serde_json::to_vec(&raw).unwrap(),
            &i,
            &c,
            d.started_at,
            d.finished_at,
        )
        .unwrap()
        .unwrap();
        let p = d.postgres.as_mut().unwrap();
        p.connected = false;
        p.catalog = None;
        p.stage = super::super::postgres::PgStage::Connect;
        p.connect_denial = Some(n);
        let (claim, a) = super::super::postgres::normalize(&i, &c, &d, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Unknown);
        assert_eq!(claim.layer, StateLayer::ConnectionAuthorization);
        assert_eq!(claim.denial_cause, Some(DenialCause::Unclassified));
        for facet in [
            &a.coverage.principal,
            &a.coverage.route,
            &a.coverage.transport,
            &a.coverage.completeness,
        ] {
            assert_eq!(
                *facet,
                Assurance::Unconfirmed {
                    reason: EvidenceReason::NativeLogOriginUnconfirmed
                }
            );
        }
        let mut claims = vec![claim];
        let mut assurances = vec![a];
        append_native_decisions(&mut claims, &mut assurances);
        assert_eq!(claims.len(), 1);
        assert_eq!(assurances.len(), 1);
        assert!(claims[0].controls.is_empty());
        assert!(d.postgres.as_ref().unwrap().connect_denial.is_some());
        for n in 0..3 {
            let mut d = d.clone();
            let p = d.postgres.as_mut().unwrap();
            match n {
                0 => p.instance_after = None,
                1 => p.connect_denial.as_mut().unwrap().marker = "replayed".into(),
                _ => p.stage = super::super::postgres::PgStage::Deadline,
            }
            assert_eq!(
                super::super::postgres::normalize(&i, &c, &d, "proof")
                    .unwrap()
                    .0
                    .observed,
                StateValue::Unknown
            );
        }
        let mut direct = d.clone();
        let p = direct.postgres.as_mut().unwrap();
        p.sqlstate = Some("28000".into());
        p.login_rejection = Some(crate::core::postgres_login::PostgresLoginFailure {
            db_identity: c.address.db_identity.clone(),
            kind: crate::core::postgres_login::PostgresLoginFailureKind::AuthenticatedNoLoginV1,
        });
        let (claim, assurance) =
            super::super::postgres::normalize(&i, &c, &direct, "proof").unwrap();
        assert_eq!(claim.observed, StateValue::Denied);
        assert_eq!(claim.layer, StateLayer::Authentication);
        assert_eq!(claim.denial_cause, Some(DenialCause::LoginRejected));
        assert!(claim.postgres_login_failure.is_some());
        assert!(matches!(
            assurance.coverage.completeness,
            Assurance::Verified { .. }
        ));
        let (_, _, mut allowed) = super::super::postgres::tests::sample();
        allowed.postgres.as_mut().unwrap().connect_denial = d.postgres.unwrap().connect_denial;
        assert_eq!(
            super::super::postgres::normalize(&i, &c, &allowed, "proof")
                .unwrap()
                .0
                .observed,
            StateValue::Allowed
        );
    }
    #[test]
    fn old_postgres_config_omits_opt_ins_and_new_reads_need_explicit_registration() {
        let config: super::super::postgres::PostgresCollectorConfig =
            serde_json::from_value(serde_json::json!({"proxy_sha256":"a".repeat(64)})).unwrap();
        assert!(!config.collect_connect_denial_audit);
        assert!(!config.collect_iam_inventory);
        assert_eq!(
            serde_json::to_value(config).unwrap(),
            serde_json::json!({"proxy_sha256":"a".repeat(64)})
        );
    }
}
