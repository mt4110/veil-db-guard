//! Bounded IAM permission inventory for the registered GCP PostgreSQL connector.
//! This is an effective permission set for one principal/resource, not a dump of
//! owned bindings. Broad/inherited grants are resolved by Troubleshooter v3beta;
//! v3 and Cloud Asset's allow-only analysis are deliberately not substitutes.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{gce_host::SourceError, postgres_native, process};
use crate::core::{admission::IssuedObservation, evidence::*, policy::*, state::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use tokio_util::sync::CancellationToken;

const API: &str = "https://policytroubleshooter.googleapis.com/v3beta/iam:troubleshoot";
const MAX_RESPONSE: usize = 262_144;
const PERMISSIONS: [&str; 3] = [
    "cloudsql.instances.connect",
    "cloudsql.instances.get",
    "cloudsql.instances.login",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AccessDecision {
    Allowed,
    Denied,
    Unknown,
}

/// Selected native response fields only. No policy bindings, group member lists,
/// tokens, provider error text, or caller-supplied completeness flag on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GcpIamDecision {
    permission: String,
    overall: AccessDecision,
    allow: AccessDecision,
    deny: AccessDecision,
    boundary: AccessDecision,
    unresolved_explanations: bool,
    response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GcpIamObservation {
    request_digest: String,
    case_id: String,
    principal: String,
    resource: String,
    generation: String,
    instance_before: super::postgres::InstanceIdentity,
    instance_after: super::postgres::InstanceIdentity,
    pub(super) started_at: u64,
    pub(super) finished_at: u64,
    decisions: Vec<GcpIamDecision>,
}

fn context(i: &IssuedObservation, c: &RequestedCase) -> Result<(String, String), SourceError> {
    let s = i.snapshot.gce().ok_or(SourceError::Unsupported)?;
    let t = &c.address.target;
    let prefix = format!("projects/{}/instances/", t.placement.account_id);
    let instance = t
        .native_ref
        .native_id
        .strip_prefix(&prefix)
        .ok_or(SourceError::Invalid)?;
    if c.kind != FixedObservationCase::NewConnection
        || c.address.effect != EffectKindV2::NewConnections
        || c.address.route.kind != RouteKind::NativeConnector
        || t.placement.kind != PlacementKind::GcpCloudSql
        || t.engine_binding.family != EngineFamily::PostgreSql
        || t.engine_binding.version != "16.15"
        || t.placement.region != "asia-northeast1"
        || t.native_ref
            .generation_fingerprint
            .as_ref()
            .is_none_or(|g| !valid_hash(g))
        || c.address.source != i.request.source.snapshot_ref()
        || c.address.db_identity
            != s.native_identity
                .service_account
                .strip_suffix(".gserviceaccount.com")
                .ok_or(SourceError::Invalid)?
        || !i.request.cases.iter().any(|requested| requested == c)
        || [t.placement.account_id.as_str(), instance].iter().any(|v| {
            v.is_empty()
                || v.len() > 128
                || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(SourceError::Unsupported);
    }
    Ok((
        s.native_identity.service_account.clone(),
        format!("//cloudsql.googleapis.com/{}", t.native_ref.native_id),
    ))
}

fn timestamp(seconds: u64) -> Result<String, SourceError> {
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let mut days = seconds / 86400;
    let mut year = 1970;
    while year <= 2100 {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    if year > 2100 {
        return Err(SourceError::Invalid);
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
    let day_seconds = seconds % 86400;
    Ok(format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        days + 1,
        day_seconds / 3600,
        day_seconds / 60 % 60,
        day_seconds % 60
    ))
}

fn access_tuple(
    principal: &str,
    resource: &str,
    permission: &str,
    at: u64,
) -> Result<Value, SourceError> {
    let name = resource
        .strip_prefix("//cloudsql.googleapis.com/")
        .ok_or(SourceError::Invalid)?;
    Ok(
        json!({"principal":principal,"fullResourceName":resource,"permission":permission,
        "conditionContext":{"request":{"receiveTime":timestamp(at)?},
            "resource":{"service":"sqladmin.googleapis.com","name":name,"type":"sqladmin.googleapis.com/Instance"}}}),
    )
}

fn explained_condition(e: &Value) -> bool {
    e.as_object().is_some_and(|o| {
        o.keys()
            .all(|k| matches!(k.as_str(), "value" | "errors" | "evaluationStates"))
    }) && e.get("value") == Some(&Value::Bool(true))
        && e.get("errors")
            .is_none_or(|v| v.as_array().is_some_and(|a| a.is_empty()))
        && e.get("evaluationStates").is_none_or(|v| {
            v.as_array().is_some_and(|a| {
                a.iter().all(|s| {
                    s.as_object().is_some_and(|o| {
                        o.keys()
                            .all(|k| matches!(k.as_str(), "start" | "end" | "value" | "errors"))
                    }) && s.get("value") == Some(&Value::Bool(true))
                        && s.get("errors")
                            .is_none_or(|v| v.as_array().is_some_and(|a| a.is_empty()))
                })
            })
        })
}

/// Only the native adapter's exact immutable resource selector is admitted.
/// Bindings and native explanations must align; no generic CEL interpretation.
fn resolve_resource_selectors(r: &mut Value, tuple: &Value) -> bool {
    let Some(name) = tuple
        .pointer("/conditionContext/resource/name")
        .and_then(Value::as_str)
    else {
        return false;
    };
    let expression =
        format!("resource.name == '{name}' && resource.type == 'sqladmin.googleapis.com/Instance'");
    let Some(policies) = r
        .pointer_mut("/allowPolicyExplanation/explainedPolicies")
        .and_then(Value::as_array_mut)
    else {
        return true;
    };
    for policy in policies {
        let Some(raw) = policy
            .pointer("/policy/bindings")
            .and_then(Value::as_array)
            .cloned()
        else {
            continue;
        };
        let Some(explanations) = policy
            .get_mut("bindingExplanations")
            .and_then(Value::as_array_mut)
        else {
            return false;
        };
        if raw.len() != explanations.len() {
            return false;
        }
        let mut resolved = Vec::new();
        for (index, (binding, explanation)) in raw.iter().zip(explanations).enumerate() {
            if binding.get("role") != explanation.get("role") {
                return false;
            }
            let Some(condition) = binding.get("condition") else {
                continue;
            };
            if condition.get("expression").and_then(Value::as_str) != Some(&expression)
                || explanation
                    .pointer("/condition/expression")
                    .and_then(Value::as_str)
                    != Some(&expression)
                || !explanation
                    .get("conditionExplanation")
                    .is_some_and(explained_condition)
                || condition.as_object().is_none_or(|c| {
                    c.keys().any(|k| {
                        !matches!(
                            k.as_str(),
                            "expression" | "title" | "description" | "location"
                        )
                    })
                })
                || explanation
                    .get("condition")
                    .and_then(Value::as_object)
                    .is_none_or(|c| {
                        c.keys().any(|k| {
                            !matches!(
                                k.as_str(),
                                "expression" | "title" | "description" | "location"
                            )
                        })
                    })
            {
                return false;
            }
            let Some(fields) = explanation.as_object_mut() else {
                return false;
            };
            fields.remove("condition");
            fields.remove("conditionExplanation");
            resolved.push(index);
        }
        for index in resolved {
            let Some(binding) = policy["policy"]["bindings"][index].as_object_mut() else {
                return false;
            };
            binding.remove("condition");
        }
    }
    true
}

/// Unknown group/custom-role/deny/boundary/context information is never hidden
/// by an overall CAN_ACCESS (another broad binding may have made it decisive).
/// Only exact native resource-only selectors can be resolved before this check;
/// arbitrary conditional results do not establish a stable permission set.
fn unresolved(v: &Value) -> bool {
    match v {
        Value::Object(fields) => fields.iter().any(|(k, v)| {
            (matches!(k.as_str(), "condition" | "conditionExplanation") && !v.is_null())
                || (matches!(k.as_str(), "errors" | "error" | "nonCriticalErrors")
                    && !v.is_null()
                    && v.as_array().is_none_or(|a| !a.is_empty()))
                || (k == "policy"
                    && match v {
                        Value::Object(p) => p.is_empty(),
                        Value::String(p) => p.is_empty(),
                        _ => true,
                    })
                || ((k.ends_with("State") || matches!(k.as_str(), "membership" | "rolePermission"))
                    && v.as_str().is_some_and(|s| !known_state(s)))
                || (k == "explainedBindingsAndPolicies"
                    && v.as_array().is_none_or(|entries| {
                        entries.iter().any(|entry| {
                            entry.get("explainedPolicy").is_none()
                                || entry.get("explainedPolicyBinding").is_none()
                        })
                    }))
                || unresolved(v)
        }),
        Value::Array(values) => values.iter().any(unresolved),
        Value::String(s) => {
            s.contains("UNKNOWN") || s.contains("UNSPECIFIED") || s.contains("ERROR")
        }
        _ => false,
    }
}

fn known_state(s: &str) -> bool {
    matches!(
        s,
        "CAN_ACCESS"
            | "CANNOT_ACCESS"
            | "ALLOW_ACCESS_STATE_GRANTED"
            | "ALLOW_ACCESS_STATE_NOT_GRANTED"
            | "DENY_ACCESS_STATE_DENIED"
            | "DENY_ACCESS_STATE_NOT_DENIED"
            | "PAB_ACCESS_STATE_ALLOWED"
            | "PAB_ACCESS_STATE_NOT_ALLOWED"
            | "PAB_ACCESS_STATE_NOT_ENFORCED"
            | "POLICY_BINDING_STATE_ENFORCED"
            | "POLICY_BINDING_STATE_NOT_ENFORCED"
            | "PAB_POLICY_ENFORCEMENT_STATE_ENFORCED"
            | "PAB_POLICY_ENFORCEMENT_STATE_NOT_ENFORCED"
            | "MEMBERSHIP_MATCHED"
            | "MEMBERSHIP_NOT_MATCHED"
            | "ROLE_PERMISSION_INCLUDED"
            | "ROLE_PERMISSION_NOT_INCLUDED"
            | "PERMISSION_PATTERN_MATCHED"
            | "PERMISSION_PATTERN_NOT_MATCHED"
            | "PRINCIPAL_MATCHED"
            | "PRINCIPAL_NOT_MATCHED"
            | "RESOURCE_INCLUSION_STATE_INCLUDED"
            | "RESOURCE_INCLUSION_STATE_NOT_INCLUDED"
    )
}

fn decision(bytes: &[u8], expected: &Value) -> Result<GcpIamDecision, SourceError> {
    if bytes.len() > MAX_RESPONSE {
        return Err(SourceError::Limit);
    }
    let r: Value = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
    let actual = r.get("accessTuple").ok_or(SourceError::Invalid)?;
    // permissionFqdn/effectiveTags are output-only additions. Every input field
    // must still match, including principal, full resource name and request time.
    for key in ["principal", "fullResourceName", "permission"] {
        if actual.get(key) != expected.get(key) {
            return Err(SourceError::Invalid);
        }
    }
    if actual.pointer("/conditionContext/request") != expected.pointer("/conditionContext/request")
    {
        return Err(SourceError::Invalid);
    }
    if actual.pointer("/conditionContext/resource")
        != expected.pointer("/conditionContext/resource")
    {
        return Err(SourceError::Invalid);
    }
    let state = |path, yes, no| match r.pointer(path).and_then(Value::as_str) {
        Some(v) if v == yes => AccessDecision::Allowed,
        Some(v) if v == no => AccessDecision::Denied,
        _ => AccessDecision::Unknown,
    };
    let boundary = match r
        .pointer("/pabPolicyExplanation/principalAccessBoundaryAccessState")
        .and_then(Value::as_str)
    {
        Some("PAB_ACCESS_STATE_ALLOWED" | "PAB_ACCESS_STATE_NOT_ENFORCED") => {
            AccessDecision::Allowed
        }
        Some("PAB_ACCESS_STATE_NOT_ALLOWED") => AccessDecision::Denied,
        _ => AccessDecision::Unknown,
    };
    let allow = state(
        "/allowPolicyExplanation/allowAccessState",
        "ALLOW_ACCESS_STATE_GRANTED",
        "ALLOW_ACCESS_STATE_NOT_GRANTED",
    );
    let missing_allow_detail = allow == AccessDecision::Allowed
        && r.pointer("/allowPolicyExplanation/explainedPolicies")
            .and_then(Value::as_array)
            .is_none_or(|p| p.is_empty());
    let mut explained = r.clone();
    let selectors_known = resolve_resource_selectors(&mut explained, expected);
    Ok(GcpIamDecision {
        permission: expected["permission"]
            .as_str()
            .ok_or(SourceError::Invalid)?
            .into(),
        overall: state("/overallAccessState", "CAN_ACCESS", "CANNOT_ACCESS"),
        allow,
        // Allowed here means the deny layer permits access, not an allow grant.
        deny: state(
            "/denyPolicyExplanation/denyAccessState",
            "DENY_ACCESS_STATE_NOT_DENIED",
            "DENY_ACCESS_STATE_DENIED",
        ),
        boundary,
        unresolved_explanations: !selectors_known || unresolved(&explained) || missing_allow_detail,
        response_sha256: crate::config::hash_bytes(bytes),
    })
}

fn complete(d: &GcpIamDecision) -> bool {
    if d.unresolved_explanations
        || [d.overall, d.allow, d.deny, d.boundary].contains(&AccessDecision::Unknown)
    {
        return false;
    }
    let allowed = [d.allow, d.deny, d.boundary]
        .iter()
        .all(|v| *v == AccessDecision::Allowed);
    (d.overall == AccessDecision::Allowed) == allowed
}

fn curl_config(token: &str, tuple: &Value) -> Result<Vec<u8>, SourceError> {
    let body =
        serde_json::to_string(&json!({"accessTuple":tuple})).map_err(|_| SourceError::Invalid)?;
    // JSON quoting is also curl config quoting: no argv/environment secret.
    Ok(format!(
        "header = {}\ndata = {}\n",
        serde_json::to_string(&format!("Authorization: Bearer {token}"))
            .map_err(|_| SourceError::Invalid)?,
        serde_json::to_string(&body).map_err(|_| SourceError::Invalid)?
    )
    .into_bytes())
}

pub(super) async fn observe_gcp(
    i: &IssuedObservation,
    c: &RequestedCase,
    cancel: &CancellationToken,
) -> Result<GcpIamObservation, SourceError> {
    let (principal, resource) = context(i, c)?;
    let started = crate::domain::now();
    if started < i.request.issued_at || started >= i.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    let token =
        postgres_native::token(i, "https://www.googleapis.com/auth/cloud-platform", cancel).await?;
    let instance_before = postgres_native::instance(c, &token, cancel).await?;
    if !instance_before.matches(c) {
        return Err(SourceError::Invalid);
    }
    let mut decisions = vec![];
    for permission in PERMISSIONS {
        let at = crate::domain::now();
        if at >= i.request.expires_at {
            return Err(SourceError::RequestExpired);
        }
        let tuple = access_tuple(&principal, &resource, permission, at)?;
        let input = curl_config(&token.access_token, &tuple)?;
        let args = vec![
            "-q",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--max-time",
            "5",
            "--max-filesize",
            "262144",
            "--silent",
            "--fail",
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--config",
            "-",
            API,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let bytes = process::run(
            Path::new("/usr/bin/curl"),
            &args,
            &input,
            MAX_RESPONSE,
            5,
            cancel,
        )
        .await?;
        decisions.push(decision(&bytes, &tuple)?);
    }
    let instance_after = postgres_native::instance(c, &token, cancel).await?;
    if instance_after != instance_before {
        return Err(SourceError::Invalid);
    }
    let finished = crate::domain::now();
    if finished >= i.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    Ok(GcpIamObservation {
        request_digest: i.request.digest().map_err(|_| SourceError::Invalid)?,
        case_id: c.id.clone(),
        principal,
        resource,
        generation: c
            .address
            .target
            .native_ref
            .generation_fingerprint
            .clone()
            .ok_or(SourceError::Invalid)?,
        instance_before,
        instance_after,
        started_at: started,
        finished_at: finished,
        decisions,
    })
}

/// Existing authenticated source/target/channel assurances remain separate.
/// IAM inspection cannot manufacture a successful DB transport or target
/// incarnation check. In particular, this claim cannot by itself grant Pending.
pub(super) fn normalize_gcp(
    i: &IssuedObservation,
    c: &RequestedCase,
    o: &GcpIamObservation,
    proof_id: &str,
    mut coverage: AssuranceCoverage,
) -> Result<(ObservationClaim, ClaimAssurance), SourceError> {
    let (principal, resource) = context(i, c)?;
    if o.request_digest != i.request.digest().map_err(|_| SourceError::Invalid)?
        || o.case_id != c.id
        || o.principal != principal
        || o.resource != resource
        || Some(&o.generation) != c.address.target.native_ref.generation_fingerprint.as_ref()
        || !o.instance_before.matches(c)
        || o.instance_before != o.instance_after
        || o.started_at < i.request.issued_at
        || o.finished_at >= i.request.expires_at
        || o.finished_at < o.started_at
        || o.finished_at - o.started_at > 40
        || o.decisions.len() != PERMISSIONS.len()
        || o.decisions
            .iter()
            .zip(PERMISSIONS)
            .any(|(d, p)| d.permission != p || !valid_hash(&d.response_sha256))
    {
        return Err(SourceError::Invalid);
    }
    let known = o.decisions.iter().all(complete);
    let yes = || Assurance::Verified {
        evidence_refs: vec![proof_id.into()],
    };
    coverage.principal = yes();
    coverage.completeness = if known {
        yes()
    } else {
        Assurance::Unconfirmed {
            reason: EvidenceReason::PermissionInventoryIncomplete,
        }
    };
    let id = format!("iam-{}", c.id);
    Ok((
        ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: id.clone(),
            case_id: c.id.clone(),
            policy_revision_hash: i.request.policy_revision_hash.clone(),
            address: c.address.clone(),
            started_at: o.started_at,
            finished_at: o.finished_at,
            observed: StateValue::Unknown,
            layer: StateLayer::ConnectionAuthorization,
            denial_cause: None,
            connection: None,
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec![proof_id.into()],
            permission_inventory: Some(NativePermissionInventory {
                complete: known,
                permissions: o
                    .decisions
                    .iter()
                    .filter(|d| d.overall == AccessDecision::Allowed && complete(d))
                    .map(|d| d.permission.clone())
                    .collect(),
            }),
        },
        ClaimAssurance {
            claim_id: id,
            coverage,
        },
    ))
}

/// Synthetic selected observations for the signed-source integration lab only.
#[cfg(test)]
pub(super) fn fixture_for_capture(
    i: &IssuedObservation,
    c: &RequestedCase,
    instance: &super::postgres::InstanceIdentity,
    started_at: u64,
    finished_at: u64,
) -> GcpIamObservation {
    let (principal, resource) = context(i, c).unwrap();
    GcpIamObservation {
        request_digest: i.request.digest().unwrap(),
        case_id: c.id.clone(),
        principal,
        resource,
        generation: c
            .address
            .target
            .native_ref
            .generation_fingerprint
            .clone()
            .unwrap(),
        instance_before: instance.clone(),
        instance_after: instance.clone(),
        started_at,
        finished_at,
        decisions: PERMISSIONS
            .iter()
            .map(|p| GcpIamDecision {
                permission: (*p).into(),
                overall: AccessDecision::Allowed,
                allow: AccessDecision::Allowed,
                deny: AccessDecision::Allowed,
                boundary: AccessDecision::Allowed,
                unresolved_explanations: false,
                response_sha256: crate::config::hash_bytes(p.as_bytes()),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (IssuedObservation, RequestedCase) {
        let (mut i, _) = super::super::testsupport::fixture();
        let c = &mut i.request.cases[0];
        c.id = "new-connection".into();
        c.kind = FixedObservationCase::NewConnection;
        c.address.route.kind = RouteKind::NativeConnector;
        c.address.target.native_ref.generation_fingerprint =
            Some(crate::adapters::deployment::gcp::generation_fingerprint(
                "vdg-example-000000",
                "billing-postgres",
                "2026-10-01T00:00:00Z",
            ));
        let c = c.clone();
        context(&i, &c).unwrap();
        (i, c)
    }
    fn response(tuple: &Value, permitted: bool) -> Value {
        json!({
            "accessTuple":tuple,
            "overallAccessState":if permitted { "CAN_ACCESS" } else { "CANNOT_ACCESS" },
            "allowPolicyExplanation":{
                "allowAccessState":if permitted { "ALLOW_ACCESS_STATE_GRANTED" } else { "ALLOW_ACCESS_STATE_NOT_GRANTED" },
                "explainedPolicies":[{
                    "fullResourceName":"//cloudresourcemanager.googleapis.com/organizations/123",
                    "allowAccessState":if permitted { "ALLOW_ACCESS_STATE_GRANTED" } else { "ALLOW_ACCESS_STATE_NOT_GRANTED" },
                    "policy":{"version":1,"etag":"abc","bindings":[{"role":"roles/owner","members":["group:database-operators@example.invalid"]}]},
                    "bindingExplanations":[{
                        "role":"roles/owner", "rolePermission":"ROLE_PERMISSION_INCLUDED",
                        "allowAccessState":if permitted { "ALLOW_ACCESS_STATE_GRANTED" } else { "ALLOW_ACCESS_STATE_NOT_GRANTED" },
                        "combinedMembership":{"membership":if permitted { "MEMBERSHIP_MATCHED" } else { "MEMBERSHIP_NOT_MATCHED" }}
                    }]
                }]
            },
            "denyPolicyExplanation":{"denyAccessState":"DENY_ACCESS_STATE_NOT_DENIED", "explainedResources":[]},
            "pabPolicyExplanation":{"principalAccessBoundaryAccessState":"PAB_ACCESS_STATE_NOT_ENFORCED", "explainedBindingsAndPolicies":[]}
        })
    }
    fn parsed(r: &Value, tuple: &Value) -> GcpIamDecision {
        decision(&serde_json::to_vec(r).unwrap(), tuple).unwrap()
    }
    fn observation(
        i: &IssuedObservation,
        c: &RequestedCase,
        permissions: usize,
    ) -> GcpIamObservation {
        let (principal, resource) = context(i, c).unwrap();
        GcpIamObservation {
            request_digest: i.request.digest().unwrap(),
            case_id: c.id.clone(),
            principal: principal.clone(),
            resource: resource.clone(),
            generation: c
                .address
                .target
                .native_ref
                .generation_fingerprint
                .clone()
                .unwrap(),
            instance_before: super::super::postgres::InstanceIdentity {
                project: "vdg-example-000000".into(),
                name: "billing-postgres".into(),
                region: "asia-northeast1".into(),
                connection_name: "vdg-example-000000:asia-northeast1:billing-postgres".into(),
                create_time: "2026-10-01T00:00:00Z".into(),
                database_version: "POSTGRES_16".into(),
                private_ip: "203.0.113.10".parse().unwrap(),
            },
            instance_after: super::super::postgres::InstanceIdentity {
                project: "vdg-example-000000".into(),
                name: "billing-postgres".into(),
                region: "asia-northeast1".into(),
                connection_name: "vdg-example-000000:asia-northeast1:billing-postgres".into(),
                create_time: "2026-10-01T00:00:00Z".into(),
                database_version: "POSTGRES_16".into(),
                private_ip: "203.0.113.10".parse().unwrap(),
            },
            started_at: 110,
            finished_at: 115,
            decisions: PERMISSIONS
                .iter()
                .enumerate()
                .map(|(n, p)| {
                    let tuple = access_tuple(&principal, &resource, p, 110).unwrap();
                    parsed(&response(&tuple, n < permissions), &tuple)
                })
                .collect(),
        }
    }
    fn coverage() -> AssuranceCoverage {
        let yes = || Assurance::Verified {
            evidence_refs: vec!["proof".into()],
        };
        AssuranceCoverage {
            target: yes(),
            principal: yes(),
            source: yes(),
            route: yes(),
            transport: yes(),
            temporal: yes(),
            completeness: yes(),
        }
    }

    #[test]
    fn complete_effective_set_retains_alternative_broad_and_inherited_grants() {
        let (i, c) = fixture();
        let before = observation(&i, &c, 3);
        // An owned binding disappeared, but the organization's broad group
        // binding still grants the same permissions: this is not a removal.
        let after = observation(&i, &c, 3);
        let (b, _) = normalize_gcp(&i, &c, &before, "proof", coverage()).unwrap();
        let (a, _) = normalize_gcp(&i, &c, &after, "proof", coverage()).unwrap();
        assert_eq!(a.permission_inventory, b.permission_inventory);
        let inventory = a.permission_inventory.unwrap();
        assert!(inventory.complete);
        assert_eq!(inventory.permissions, PERMISSIONS);
        assert_eq!(a.observed, StateValue::Unknown);
        assert!(a.denial_cause.is_none());
    }

    #[test]
    fn full_known_absence_is_distinct_from_missing_or_partial_information() {
        let (i, c) = fixture();
        let o = observation(&i, &c, 0);
        let (a, _) = normalize_gcp(&i, &c, &o, "proof", coverage()).unwrap();
        assert!(a.permission_inventory.as_ref().unwrap().complete);
        assert!(a.permission_inventory.unwrap().permissions.is_empty());
        let mut incomplete = o.clone();
        incomplete.decisions[0].boundary = AccessDecision::Unknown;
        let (a, s) = normalize_gcp(&i, &c, &incomplete, "proof", coverage()).unwrap();
        assert!(!a.permission_inventory.unwrap().complete);
        assert!(matches!(
            s.coverage.completeness,
            Assurance::Unconfirmed {
                reason: EvidenceReason::PermissionInventoryIncomplete
            }
        ));
    }

    #[test]
    fn unknown_groups_roles_denies_boundaries_and_conditions_cannot_hide_behind_allow() {
        let tuple = access_tuple(
            "app@example.invalid",
            "//cloudsql.googleapis.com/projects/project/instances/pg",
            PERMISSIONS[0],
            110,
        )
        .unwrap();
        let baseline = response(&tuple, true);
        assert!(complete(&parsed(&baseline, &tuple)));
        for (pointer, value) in [
            (
                "/allowPolicyExplanation/explainedPolicies/0/bindingExplanations/0/combinedMembership/membership",
                json!("MEMBERSHIP_UNKNOWN_INFO"),
            ),
            (
                "/allowPolicyExplanation/explainedPolicies/0/bindingExplanations/0/rolePermission",
                json!("ROLE_PERMISSION_UNKNOWN_INFO"),
            ),
            (
                "/denyPolicyExplanation/denyAccessState",
                json!("DENY_ACCESS_STATE_UNKNOWN_INFO"),
            ),
            (
                "/pabPolicyExplanation/principalAccessBoundaryAccessState",
                json!("PAB_ACCESS_STATE_UNKNOWN_INFO"),
            ),
            (
                "/allowPolicyExplanation/explainedPolicies/0/policy",
                json!({}),
            ),
        ] {
            let mut r = baseline.clone();
            *r.pointer_mut(pointer).unwrap() = value;
            assert!(!complete(&parsed(&r, &tuple)), "{pointer}");
        }
        let mut conditional = baseline.clone();
        conditional["allowPolicyExplanation"]["explainedPolicies"][0]["bindingExplanations"][0]["condition"] =
            json!({"expression":"request.time < timestamp('2026-12-01T00:00:00Z')"});
        assert!(!complete(&parsed(&conditional, &tuple)));
        let mut old_v3 = baseline.clone();
        old_v3
            .as_object_mut()
            .unwrap()
            .remove("pabPolicyExplanation");
        assert!(!complete(&parsed(&old_v3, &tuple)));
    }

    #[test]
    fn exact_owned_resource_selector_requires_paired_native_condition_evaluation() {
        let tuple = access_tuple(
            "app@example.invalid",
            "//cloudsql.googleapis.com/projects/project/instances/pg",
            PERMISSIONS[0],
            110,
        )
        .unwrap();
        let condition = json!({"title":"owned", "expression":"resource.name == 'projects/project/instances/pg' && resource.type == 'sqladmin.googleapis.com/Instance'"});
        let mut r = response(&tuple, true);
        r["allowPolicyExplanation"]["explainedPolicies"][0]["policy"]["bindings"][0]["condition"] =
            condition.clone();
        r["allowPolicyExplanation"]["explainedPolicies"][0]["bindingExplanations"][0]["condition"] =
            condition;
        r["allowPolicyExplanation"]["explainedPolicies"][0]["bindingExplanations"][0]["conditionExplanation"] = json!({"value":true,"errors":[],"evaluationStates":[{"start":0,"end":54,"value":true},{"start":59,"end":114,"value":true}]});
        assert!(complete(&parsed(&r, &tuple)));
        for (pointer, value) in [
            (
                "/allowPolicyExplanation/explainedPolicies/0/bindingExplanations/0/conditionExplanation/value",
                json!(false),
            ),
            (
                "/allowPolicyExplanation/explainedPolicies/0/bindingExplanations/0/conditionExplanation/evaluationStates/0/value",
                Value::Null,
            ),
            (
                "/allowPolicyExplanation/explainedPolicies/0/bindingExplanations/0/conditionExplanation/errors",
                json!([{"code":7}]),
            ),
            (
                "/allowPolicyExplanation/explainedPolicies/0/policy/bindings/0/condition/expression",
                json!(
                    "resource.name == 'projects/project/instances/other' && resource.type == 'sqladmin.googleapis.com/Instance'"
                ),
            ),
            (
                "/allowPolicyExplanation/explainedPolicies/0/bindingExplanations/0/role",
                json!("roles/another"),
            ),
        ] {
            let mut changed = r.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(!complete(&parsed(&changed, &tuple)), "{pointer}");
        }
        let mut missing = r.clone();
        missing["allowPolicyExplanation"]["explainedPolicies"][0]["bindingExplanations"][0]
            .as_object_mut()
            .unwrap()
            .remove("conditionExplanation");
        assert!(!complete(&parsed(&missing, &tuple)));
        let mut changed = r;
        changed["accessTuple"]["conditionContext"]["resource"]["type"] =
            json!("other.googleapis.com/Resource");
        assert!(decision(&serde_json::to_vec(&changed).unwrap(), &tuple).is_err());
    }

    #[test]
    fn changed_native_generation_during_inventory_is_rejected() {
        let (i, c) = fixture();
        let mut o = observation(&i, &c, 3);
        o.instance_after.create_time = "2026-11-03T00:00:00Z".into();
        assert!(normalize_gcp(&i, &c, &o, "proof", coverage()).is_err());
        o.instance_before.create_time = o.instance_after.create_time.clone();
        assert!(normalize_gcp(&i, &c, &o, "proof", coverage()).is_err());
    }

    #[test]
    fn response_echo_binds_actor_resource_permission_and_condition_time() {
        let tuple = access_tuple(
            "app@example.invalid",
            "//cloudsql.googleapis.com/projects/project/instances/pg",
            PERMISSIONS[0],
            110,
        )
        .unwrap();
        for key in ["principal", "fullResourceName", "permission"] {
            let mut r = response(&tuple, true);
            r["accessTuple"][key] = json!("different");
            assert!(decision(&serde_json::to_vec(&r).unwrap(), &tuple).is_err());
        }
        let mut r = response(&tuple, true);
        r["accessTuple"]["conditionContext"]["request"]["receiveTime"] =
            json!("1970-01-01T00:01:51Z");
        assert!(decision(&serde_json::to_vec(&r).unwrap(), &tuple).is_err());
        let oversized = vec![b' '; MAX_RESPONSE + 1];
        assert_eq!(
            decision(&oversized, &tuple).unwrap_err(),
            SourceError::Limit
        );
    }

    #[test]
    fn normalized_inventory_rejects_cross_request_case_target_and_stale_capture() {
        let (i, c) = fixture();
        let original = observation(&i, &c, 3);
        for n in 0..8 {
            let mut o = original.clone();
            match n {
                0 => o.request_digest = "0".repeat(64),
                1 => o.case_id = "another-case".into(),
                2 => o.principal = "another@example.invalid".into(),
                3 => o.resource.push_str("-other"),
                4 => o.generation = "0".repeat(64),
                5 => o.started_at = 99,
                6 => o.finished_at = 220,
                _ => o.decisions[1] = o.decisions[0].clone(),
            }
            assert!(
                normalize_gcp(&i, &c, &o, "proof", coverage()).is_err(),
                "{n}"
            );
        }
    }

    #[test]
    fn inventory_does_not_mint_unobserved_database_transport_or_route() {
        let (i, c) = fixture();
        let o = observation(&i, &c, 2);
        let mut s = coverage();
        s.transport = Assurance::Unconfirmed {
            reason: EvidenceReason::TransportUnconfirmed,
        };
        s.route = Assurance::Unconfirmed {
            reason: EvidenceReason::RouteUnconfirmed,
        };
        let (_, a) = normalize_gcp(&i, &c, &o, "proof", s.clone()).unwrap();
        assert_eq!(a.coverage.transport, s.transport);
        assert_eq!(a.coverage.route, s.route);
    }

    #[test]
    fn inconsistent_provider_states_and_missing_details_cannot_be_complete() {
        let tuple = access_tuple(
            "app@example.invalid",
            "//cloudsql.googleapis.com/projects/project/instances/pg",
            PERMISSIONS[0],
            110,
        )
        .unwrap();
        let mut r = response(&tuple, true);
        r["denyPolicyExplanation"]["denyAccessState"] = json!("DENY_ACCESS_STATE_DENIED");
        assert!(!complete(&parsed(&r, &tuple)));
        let mut r = response(&tuple, true);
        r["allowPolicyExplanation"]["explainedPolicies"] = json!([]);
        assert!(!complete(&parsed(&r, &tuple)));
        let mut r = response(&tuple, true);
        r["pabPolicyExplanation"]["principalAccessBoundaryAccessState"] =
            json!("PAB_ACCESS_STATE_NEW_FUTURE_VALUE");
        assert!(!complete(&parsed(&r, &tuple)));
    }

    #[test]
    fn request_time_conversion_covers_leap_days_and_secret_stays_in_stdin() {
        for epoch in [0, 110, 951782400, 1709164800, 1793635200] {
            assert_eq!(
                super::super::aws_native::parse_time(&timestamp(epoch).unwrap()).unwrap(),
                epoch
            );
        }
        let tuple = access_tuple(
            "app@example.invalid",
            "//cloudsql.googleapis.com/projects/project/instances/pg",
            PERMISSIONS[0],
            110,
        )
        .unwrap();
        let input = curl_config("fixture-token", &tuple).unwrap();
        let lines = std::str::from_utf8(&input)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "header = \"Authorization: Bearer fixture-token\"");
        let body: String = serde_json::from_str(lines[1].strip_prefix("data = ").unwrap()).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["accessTuple"],
            tuple
        );
    }
}
