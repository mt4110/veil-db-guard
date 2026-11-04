//! Versioned, bounded EC2 instance-profile / same-account default RDS Proxy
//! `rds-db:connect` policy inventory. No simulator result or caller completeness
//! flag is authority. Unsupported policy semantics / Organizations membership
//! remain explicit gaps and never manufacture a denial or propagation Pending.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{aws_native::*, gce_host::SourceError};
use crate::core::{admission::IssuedObservation, evidence::*, policy::*, state::*};
use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const ACTION: &str = "rds-db:connect";
const MAX_POLICIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AwsIamGap {
    RolePoliciesUnreadable,
    OrganizationUnreadable,
    OrganizationMemberScp,
    UnsupportedPolicySemantics,
    InventoryChanged,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Organization {
    NotMember,
    ManagementAccount { organization_id: String },
    MemberAccount { organization_id: String },
    Unreadable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyResult {
    NoGrant,
    Allow,
    Deny,
    Unsupported,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRead {
    policy_id: String,
    document_sha256: String,
    result: PolicyResult,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleInventory {
    role_arn: String,
    role_id: String,
    policies: Vec<PolicyRead>,
    boundary: Option<PolicyRead>,
}
/// Facts emitted only by the registered binary over the sealed source channel.
/// No supplied `complete` field; the verifier derives coverage from version,
/// scope, provenance, both inventory reads, policy subset and Organizations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AwsIamObservation {
    version: u32,
    request_digest: String,
    pub(super) case_id: String,
    principal: crate::core::source::AwsMetadataCredential,
    resource: String,
    generation: String,
    before: Metadata,
    after: Metadata,
    first: Option<RoleInventory>,
    second: Option<RoleInventory>,
    organization: Organization,
    organization_after: Organization,
    pub(super) started_at: u64,
    pub(super) finished_at: u64,
}

fn scope(
    i: &IssuedObservation,
    c: &RequestedCase,
    t: &AwsDatabaseTarget,
) -> Result<String, SourceError> {
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;

    let proxy = t.proxy_arn.rsplit(':').next().ok_or(SourceError::Invalid)?;
    if t.target_id != c.address.target_id
        || t.db_arn != c.address.target.native_ref.native_id
        || t.proxy_endpoint != c.endpoint
        || c.address.target.placement.kind != PlacementKind::AwsRds
        || c.address.target.placement.region != "ap-northeast-1"
        || c.address.target.placement.account_id != s.native_identity.account_id
        || c.kind != FixedObservationCase::NewConnection
        || c.address.effect != EffectKindV2::NewConnections
        || c.address.source != i.request.source.snapshot_ref()
        || !i.request.cases.contains(c)
        || !proxy.starts_with("prx-")
        || c.address.db_identity.is_empty()
        || c.address.db_identity.len() > 63
        || !c
            .address
            .db_identity
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(SourceError::Unsupported);
    }
    Ok(format!(
        "arn:aws:rds-db:ap-northeast-1:{}:dbuser:{proxy}/{}",
        s.native_identity.account_id, c.address.db_identity
    ))
}

fn name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
}
fn arn(s: &str) -> bool {
    s.starts_with("arn:aws:iam::")
        && s.contains(":policy/")
        && s.len() <= 2048
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":/_+=,.@-".contains(&b))
}
fn list_element<'a>(xml: &'a str, tag: &str) -> Result<&'a str, SourceError> {
    let empty = format!("<{tag}/>");
    let spaced = format!("<{tag} />");
    if xml.matches(&empty).count() + xml.matches(&spaced).count() == 1
        && !xml.contains(&format!("<{tag}>"))
        && !xml.contains(&format!("</{tag}>"))
    {
        return Ok("");
    }
    element(xml, tag)
}
fn list_members(xml: &str) -> Result<Vec<&str>, SourceError> {
    let mut rest = xml.trim();
    let mut out = vec![];
    while !rest.is_empty() {
        rest = rest.strip_prefix("<member>").ok_or(SourceError::Invalid)?;
        let end = rest.find("</member>").ok_or(SourceError::Invalid)?;
        if rest[..end].contains("<member>") || out.len() >= MAX_POLICIES {
            return Err(SourceError::Limit);
        }
        out.push(&rest[..end]);
        rest = rest[end + 9..].trim();
    }
    Ok(out)
}
fn strings(v: &Value) -> Option<Vec<&str>> {
    if let Some(s) = v.as_str() {
        Some(vec![s])
    } else {
        let a = v.as_array()?;
        if a.is_empty() || a.len() > 128 {
            return None;
        }
        a.iter().map(Value::as_str).collect()
    }
}
fn literal_match(pattern: &str, exact: &str, action: bool) -> Option<bool> {
    if pattern == "*" {
        return Some(true);
    }
    if pattern.is_empty()
        || pattern.len() > 2048
        || pattern.contains(['*', '?', '$', '{', '}'])
        || !pattern.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return None;
    }
    Some(if action {
        pattern.eq_ignore_ascii_case(exact)
    } else {
        pattern == exact
    })
}
/// A deliberately small evaluator. Every statement must be understood, including
/// nonmatching statements: no Condition, NotAction/NotResource, variables,
/// Principal, nonliteral wildcard, unknown keys or policy language versions.
fn policy(document: &str, resource: &str) -> Result<(String, PolicyResult), SourceError> {
    let document = decode(document.trim())?;
    let v = strict_json(document.as_bytes())?;
    let digest = crate::config::hash_bytes(document.as_bytes());
    let unsupported = || Ok((digest.clone(), PolicyResult::Unsupported));
    let Some(o) = v.as_object() else {
        return unsupported();
    };
    if o.keys()
        .any(|k| !matches!(k.as_str(), "Version" | "Id" | "Statement"))
        || o.get("Version")
            .is_some_and(|v| v.as_str() != Some("2012-10-17"))
        || o.get("Id").is_some_and(|v| v.as_str().is_none())
    {
        return unsupported();
    }
    let Some(s) = o.get("Statement") else {
        return unsupported();
    };
    let statements: Vec<&Value> = match s.as_array() {
        Some(a) if a.len() <= 128 => a.iter().collect(),
        None if s.is_object() => vec![s],
        _ => return unsupported(),
    };
    let mut allow = false;
    let mut deny = false;
    for s in statements {
        let Some(s) = s.as_object() else {
            return unsupported();
        };
        if s.keys()
            .any(|k| !matches!(k.as_str(), "Sid" | "Effect" | "Action" | "Resource"))
            || s.get("Sid").is_some_and(|v| v.as_str().is_none())
        {
            return unsupported();
        }
        let Some(actions) = s.get("Action").and_then(strings) else {
            return unsupported();
        };
        let Some(resources) = s.get("Resource").and_then(strings) else {
            return unsupported();
        };
        let Some(am): Option<Vec<_>> = actions
            .into_iter()
            .map(|s| literal_match(s, ACTION, true))
            .collect()
        else {
            return unsupported();
        };
        let Some(rm): Option<Vec<_>> = resources
            .into_iter()
            .map(|s| literal_match(s, resource, false))
            .collect()
        else {
            return unsupported();
        };
        match s.get("Effect").and_then(Value::as_str) {
            Some("Allow") => allow |= am.contains(&true) && rm.contains(&true),
            Some("Deny") => deny |= am.contains(&true) && rm.contains(&true),
            _ => return unsupported(),
        }
    }
    Ok((
        digest,
        if deny {
            PolicyResult::Deny
        } else if allow {
            PolicyResult::Allow
        } else {
            PolicyResult::NoGrant
        },
    ))
}
fn decode(s: &str) -> Result<String, SourceError> {
    if s.starts_with('{') {
        return Ok(s.to_owned());
    }
    let mut bytes = vec![];
    let mut input = s.as_bytes().iter().copied();
    while let Some(b) = input.next() {
        if b == b'%' {
            let a = input
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or(SourceError::Invalid)?;
            let b = input
                .next()
                .and_then(|c| (c as char).to_digit(16))
                .ok_or(SourceError::Invalid)?;
            bytes.push((a * 16 + b) as u8);
        } else {
            bytes.push(b);
        }
        if bytes.len() > 131072 {
            return Err(SourceError::Limit);
        }
    }
    String::from_utf8(bytes).map_err(|_| SourceError::Invalid)
}

// serde_json's default map parser accepts duplicate keys. Native policy bytes
// must have a single interpretation before the selected result is persisted.
fn strict_json(bytes: &[u8]) -> Result<Value, SourceError> {
    use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Seed(usize);
    impl<'de> DeserializeSeed<'de> for Seed {
        type Value = Value;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            if self.0 > 32 {
                return Err(de::Error::custom("depth"));
            }
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Seed {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bounded unambiguous JSON")
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.into()))
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
            serde_json::Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| de::Error::custom("number"))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut out = vec![];
            while let Some(v) = a.next_element_seed(Seed(self.0 + 1))? {
                if out.len() >= 256 {
                    return Err(de::Error::custom("count"));
                }
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if out.contains_key(&k) || out.len() >= 256 {
                    return Err(de::Error::custom("duplicate/count"));
                }
                out.insert(k, a.next_value_seed(Seed(self.0 + 1))?);
            }
            Ok(Value::Object(out))
        }
    }
    if bytes.len() > 131072 {
        return Err(SourceError::Limit);
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let v = Seed(0)
        .deserialize(&mut d)
        .map_err(|_| SourceError::Invalid)?;
    d.end().map_err(|_| SourceError::Invalid)?;
    Ok(v)
}

trait IamRead {
    async fn query(&self, action: &str, params: &[(&str, &str)]) -> Result<String, SourceError>;
}
struct NativeRead<'a> {
    creds: &'a Credentials,
    cancel: &'a CancellationToken,
}
impl IamRead for NativeRead<'_> {
    async fn query(&self, action: &str, params: &[(&str, &str)]) -> Result<String, SourceError> {
        api(self.creds, "iam", action, params, self.cancel).await
    }
}
async fn managed(read: &impl IamRead, id: &str, resource: &str) -> Result<PolicyRead, SourceError> {
    if !arn(id) {
        return Err(SourceError::Invalid);
    }
    let raw = read.query("GetPolicy", &[("PolicyArn", id)]).await?;
    let p = element(&raw, "Policy")?;
    if scalar(p, "Arn")? != id {
        return Err(SourceError::ContextUnverified);
    }
    let version = scalar(p, "DefaultVersionId")?;
    if version.len() > 64 || !version.starts_with('v') || !name(&version, 64) {
        return Err(SourceError::Invalid);
    }
    let raw = read
        .query(
            "GetPolicyVersion",
            &[("PolicyArn", id), ("VersionId", &version)],
        )
        .await?;
    let p = element(&raw, "PolicyVersion")?;
    if scalar(p, "VersionId")? != version || scalar(p, "IsDefaultVersion")? != "true" {
        return Err(SourceError::ContextUnverified);
    }
    let (document_sha256, result) = policy(element(p, "Document")?, resource)?;
    Ok(PolicyRead {
        policy_id: format!("{id}:{version}"),
        document_sha256,
        result,
    })
}
async fn role_inventory(
    read: &impl IamRead,
    principal: &crate::core::source::AwsMetadataCredential,
    resource: &str,
) -> Result<RoleInventory, SourceError> {
    let role = principal
        .role_arn
        .rsplit('/')
        .next()
        .ok_or(SourceError::Invalid)?;
    if !name(role, 64) {
        return Err(SourceError::Invalid);
    }
    let raw = read.query("GetRole", &[("RoleName", role)]).await?;
    let r = element(&raw, "Role")?;
    if scalar(r, "Arn")? != principal.role_arn
        || scalar(r, "RoleId")? != principal.role_id
        || scalar(r, "RoleName")? != role
    {
        return Err(SourceError::IdentityUnverified);
    }
    let boundary = if r.contains("<PermissionsBoundary>") {
        let b = element(r, "PermissionsBoundary")?;
        if scalar(b, "PermissionsBoundaryType")? != "Policy" {
            return Err(SourceError::Unsupported);
        }
        Some(managed(read, &scalar(b, "PermissionsBoundaryArn")?, resource).await?)
    } else {
        None
    };
    let mut policies = vec![];
    // A bounded single page is intentional. Truncation is an acquisition gap,
    // never an empty policy set; no unbounded account-wide IAM dump.
    let raw = read
        .query(
            "ListRolePolicies",
            &[("RoleName", role), ("MaxItems", "32")],
        )
        .await?;
    let r = element(&raw, "ListRolePoliciesResult")?;
    if scalar(r, "IsTruncated")? != "false" {
        return Err(SourceError::Limit);
    }
    for p in list_members(list_element(r, "PolicyNames")?)? {
        if !name(p, 128) {
            return Err(SourceError::Invalid);
        }
        let raw = read
            .query("GetRolePolicy", &[("RoleName", role), ("PolicyName", p)])
            .await?;
        let r = element(&raw, "GetRolePolicyResult")?;
        if scalar(r, "RoleName")? != role || scalar(r, "PolicyName")? != p {
            return Err(SourceError::ContextUnverified);
        }
        let (document_sha256, result) = policy(element(r, "PolicyDocument")?, resource)?;
        policies.push(PolicyRead {
            policy_id: format!("inline:{p}"),
            document_sha256,
            result,
        });
    }
    let raw = read
        .query(
            "ListAttachedRolePolicies",
            &[("RoleName", role), ("MaxItems", "32")],
        )
        .await?;
    let r = element(&raw, "ListAttachedRolePoliciesResult")?;
    if scalar(r, "IsTruncated")? != "false" {
        return Err(SourceError::Limit);
    }
    for p in list_members(list_element(r, "AttachedPolicies")?)? {
        policies.push(managed(read, &scalar(p, "PolicyArn")?, resource).await?);
        if policies.len() > MAX_POLICIES {
            return Err(SourceError::Limit);
        }
    }
    policies.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
    if policies
        .windows(2)
        .any(|p| p[0].policy_id == p[1].policy_id)
    {
        return Err(SourceError::Invalid);
    }
    Ok(RoleInventory {
        role_arn: principal.role_arn.clone(),
        role_id: principal.role_id.clone(),
        policies,
        boundary,
    })
}

fn organization(bytes: &[u8], account: &str) -> Result<Organization, SourceError> {
    let v = strict_json(bytes)?;
    if let Some(error) = v.get("__type").and_then(Value::as_str) {
        return Ok(
            if error.rsplit('#').next() == Some("AWSOrganizationsNotInUseException")
                && v.get("Organization").is_none()
            {
                Organization::NotMember
            } else {
                Organization::Unreadable
            },
        );
    }
    let Some(o) = v.get("Organization").and_then(Value::as_object) else {
        return Ok(Organization::Unreadable);
    };
    let Some(id) = o.get("Id").and_then(Value::as_str) else {
        return Err(SourceError::Invalid);
    };
    let Some(master) = o.get("MasterAccountId").and_then(Value::as_str) else {
        return Err(SourceError::Invalid);
    };
    if !id.starts_with("o-")
        || !name(id, 34)
        || master.len() != 12
        || !master.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(SourceError::Invalid);
    }
    Ok(if master == account {
        Organization::ManagementAccount {
            organization_id: id.into(),
        }
    } else {
        Organization::MemberAccount {
            organization_id: id.into(),
        }
    })
}
async fn read_organization(
    creds: &Credentials,
    account: &str,
    cancel: &CancellationToken,
) -> Result<Organization, SourceError> {
    let bytes = json_api(
        creds,
        "organizations",
        "AWSOrganizationsV20161128.DescribeOrganization",
        b"{}",
        cancel,
    )
    .await?;
    organization(&bytes, account)
}

pub(super) async fn observe(
    i: &IssuedObservation,
    c: &RequestedCase,
    t: &AwsDatabaseTarget,
    cancel: &CancellationToken,
) -> Result<AwsIamObservation, SourceError> {
    let resource = scope(i, c, t)?;
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    let principal = s.metadata_credential.as_ref().ok_or(SourceError::Invalid)?;
    let started_at = crate::domain::now();
    let budget = i
        .request
        .expires_at
        .saturating_sub(started_at)
        .saturating_sub(12)
        .min(40);
    if budget == 0 {
        return Err(SourceError::Limit);
    }
    let work = async {
        // Fetch directly from IMDSv2, authenticate with STS, never AssumeRole or
        // accept caller credentials. This bounds session-policy provenance.
        let creds = authenticate(principal, &s.native_identity.account_id, cancel).await?;
        let before = metadata(&creds, t, c.address.target.engine_binding.family, cancel).await?;
        let read = NativeRead {
            creds: &creds,
            cancel,
        };
        let first = role_inventory(&read, principal, &resource).await.ok();
        let organization = read_organization(&creds, &s.native_identity.account_id, cancel)
            .await
            .unwrap_or(Organization::Unreadable);
        let second = role_inventory(&read, principal, &resource).await.ok();
        let organization_after = read_organization(&creds, &s.native_identity.account_id, cancel)
            .await
            .unwrap_or(Organization::Unreadable);
        let after = metadata(&creds, t, c.address.target.engine_binding.family, cancel).await?;
        Ok(AwsIamObservation {
            version: 1,
            request_digest: i.request.digest().map_err(|_| SourceError::Invalid)?,
            case_id: c.id.clone(),
            principal: principal.clone(),
            resource,
            generation: c
                .address
                .target
                .native_ref
                .generation_fingerprint
                .clone()
                .ok_or(SourceError::Invalid)?,
            before,
            after,
            first,
            second,
            organization,
            organization_after,
            started_at,
            finished_at: crate::domain::now(),
        })
    };
    tokio::select! { biased; _=cancel.cancelled()=>Err(SourceError::Cancelled),r=tokio::time::timeout(Duration::from_secs(budget),work)=>r.map_err(|_|SourceError::Limit)? }
}

fn gaps(o: &AwsIamObservation) -> Vec<AwsIamGap> {
    let mut gaps = vec![];
    if o.organization != o.organization_after {
        gaps.push(AwsIamGap::InventoryChanged);
    }
    match (&o.first, &o.second) {
        (Some(a), Some(b)) => {
            if a != b {
                gaps.push(AwsIamGap::InventoryChanged);
            }
            if a.policies
                .iter()
                .chain(a.boundary.iter())
                .chain(b.policies.iter())
                .chain(b.boundary.iter())
                .any(|p| p.result == PolicyResult::Unsupported)
            {
                gaps.push(AwsIamGap::UnsupportedPolicySemantics);
            }
        }
        _ => gaps.push(AwsIamGap::RolePoliciesUnreadable),
    }
    match o.organization {
        Organization::Unreadable => gaps.push(AwsIamGap::OrganizationUnreadable),
        Organization::MemberAccount { .. } => gaps.push(AwsIamGap::OrganizationMemberScp),
        _ => {}
    }
    gaps
}
fn allowed(r: &RoleInventory) -> bool {
    !r.policies.iter().any(|p| p.result == PolicyResult::Deny)
        && r.policies.iter().any(|p| p.result == PolicyResult::Allow)
        && r.boundary
            .as_ref()
            .is_none_or(|b| b.result == PolicyResult::Allow)
}
pub(super) fn normalize(
    i: &IssuedObservation,
    c: &RequestedCase,
    o: &AwsIamObservation,
    proof: &str,
    mut coverage: AssuranceCoverage,
) -> Result<(ObservationClaim, ClaimAssurance), SourceError> {
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    let proxy = o
        .before
        .proxy_arn
        .rsplit(':')
        .next()
        .ok_or(SourceError::Invalid)?;
    let resource = format!(
        "arn:aws:rds-db:ap-northeast-1:{}:dbuser:{proxy}/{}",
        s.native_identity.account_id, c.address.db_identity
    );
    if o.version != 1
        || c.kind != FixedObservationCase::NewConnection
        || c.address.effect != EffectKindV2::NewConnections
        || c.address.route.kind != RouteKind::NativeProxy
        || c.address.target.placement.account_id != s.native_identity.account_id
        || c.address.target.placement.region != "ap-northeast-1"
        || !proxy.starts_with("prx-")
        || o.request_digest != i.request.digest().map_err(|_| SourceError::Invalid)?
        || o.case_id != c.id
        || Some(&o.principal) != s.metadata_credential.as_ref()
        || o.resource != resource
        || Some(&o.generation) != c.address.target.native_ref.generation_fingerprint.as_ref()
        || !valid_hash(&o.generation)
        || o.before != o.after
        || o.before.db_arn != c.address.target.native_ref.native_id
        || o.before.proxy_endpoint != c.endpoint
        || aws_generation_fingerprint(
            &s.native_identity.account_id,
            "ap-northeast-1",
            &o.before.db_arn,
            &o.before.db_resource_id,
        ) != o.generation
        || o.started_at < i.request.issued_at
        || o.finished_at >= i.request.expires_at
        || o.finished_at < o.started_at
        || o.finished_at - o.started_at > 40
        || o.first.iter().chain(o.second.iter()).any(|r| {
            r.role_arn != o.principal.role_arn
                || r.role_id != o.principal.role_id
                || r.policies.len() > MAX_POLICIES
                || r.policies
                    .windows(2)
                    .any(|p| p[0].policy_id >= p[1].policy_id)
                || r.policies.iter().chain(r.boundary.iter()).any(|p| {
                    !valid_hash(&p.document_sha256)
                        || p.policy_id.len() > 2113
                        || p.policy_id.chars().any(char::is_control)
                })
        })
    {
        return Err(SourceError::Invalid);
    }
    let known = gaps(o).is_empty();
    coverage.principal = Assurance::Verified {
        evidence_refs: vec![proof.into()],
    };
    coverage.completeness = if known {
        Assurance::Verified {
            evidence_refs: vec![proof.into()],
        }
    } else {
        Assurance::Unconfirmed {
            reason: EvidenceReason::PermissionInventoryIncomplete,
        }
    };
    let id = format!("aws-iam-{}", c.id);
    Ok((
        ObservationClaim {
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
            evidence_refs: vec![proof.into()],
            permission_inventory: Some(NativePermissionInventory {
                complete: known,
                permissions: if known && o.first.as_ref().is_some_and(allowed) {
                    vec![ACTION.into()]
                } else {
                    vec![]
                },
            }),
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
        },
        ClaimAssurance {
            claim_id: id,
            coverage,
        },
    ))
}

#[cfg(test)]
pub(super) fn fixture_for_capture(
    i: &IssuedObservation,
    c: &RequestedCase,
    t: &AwsDatabaseTarget,
) -> AwsIamObservation {
    let principal = i
        .snapshot
        .aws()
        .unwrap()
        .metadata_credential
        .clone()
        .unwrap();
    let resource = scope(i, c, t).unwrap();
    let document=serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":ACTION,"Resource":resource}]}).to_string();
    let (document_sha256, result) = policy(&document, &resource).unwrap();
    let r = RoleInventory {
        role_arn: principal.role_arn.clone(),
        role_id: principal.role_id.clone(),
        policies: vec![PolicyRead {
            policy_id: "inline:connect".into(),
            document_sha256,
            result,
        }],
        boundary: None,
    };
    let m = Metadata {
        db_arn: t.db_arn.clone(),
        db_resource_id: t.db_resource_id.clone(),
        db_endpoint: t.db_endpoint.clone(),
        engine_version: c.address.target.engine_binding.version.clone(),
        proxy_arn: t.proxy_arn.clone(),
        proxy_endpoint: t.proxy_endpoint.clone(),
        target_resource_name: t.db_arn.rsplit(':').next().unwrap().into(),
        target_endpoint: t.db_endpoint.clone(),
    };
    AwsIamObservation {
        version: 1,
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
        before: m.clone(),
        after: m,
        first: Some(r.clone()),
        second: Some(r),
        organization: Organization::NotMember,
        organization_after: Organization::NotMember,
        started_at: 111,
        finished_at: 114,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn p(effect: &str, action: &str, resource: &str) -> String {
        serde_json::json!({"Version":"2012-10-17","Statement":{"Effect":effect,"Action":action,"Resource":resource}}).to_string()
    }
    fn observation() -> (IssuedObservation, RequestedCase, AwsIamObservation) {
        let (i, config, _) = super::super::aws_postgres::tests::sample();
        let c = i.request.cases[0].clone();
        let o = fixture_for_capture(&i, &c, &config.postgres.unwrap().targets[0]);
        (i, c, o)
    }
    fn normalized(
        i: &IssuedObservation,
        c: &RequestedCase,
        o: &AwsIamObservation,
    ) -> ObservationClaim {
        let (_, _, pg) = super::super::aws_postgres::tests::sample();
        let (_, a) = super::super::aws_postgres::normalize(i, c, 111, 114, &pg, "proof").unwrap();
        normalize(i, c, o, "proof", a.coverage).unwrap().0
    }
    #[test]
    fn exact_proxy_scope_uses_proxy_not_db_resource_and_default_config_wire_is_unchanged() {
        let (i, c, o) = observation();
        assert!(o.resource.contains(":dbuser:prx-"));
        assert!(!o.resource.contains(":dbuser:db-"));
        assert_eq!(
            normalized(&i, &c, &o).permission_inventory.unwrap(),
            NativePermissionInventory {
                complete: true,
                permissions: vec![ACTION.into()]
            }
        );
        assert_eq!(normalized(&i, &c, &o).observed, StateValue::Unknown);
        let (_, config, _) = super::super::aws_postgres::tests::sample();
        assert!(
            !serde_json::to_string(&config)
                .unwrap()
                .contains("collect_iam_inventory")
        );
    }
    #[test]
    fn static_subset_has_explicit_deny_precedence_and_unrelated_exact_action_is_no_grant() {
        let r = "arn:aws:rds-db:ap-northeast-1:123456789012:dbuser:prx-x/user";
        assert_eq!(
            policy(&p("Allow", ACTION, r), r).unwrap().1,
            PolicyResult::Allow
        );
        assert_eq!(
            policy(&p("Allow", "*", "*"), r).unwrap().1,
            PolicyResult::Allow
        );
        assert_eq!(
            policy(&p("Allow", "RDS-DB:CONNECT", r), r).unwrap().1,
            PolicyResult::Allow
        );
        assert_eq!(
            policy(&p("Allow", "s3:ListAllMyBuckets", "*"), r)
                .unwrap()
                .1,
            PolicyResult::NoGrant
        );
        let v = serde_json::json!({"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":ACTION,"Resource":r}]});
        assert_eq!(policy(&v.to_string(), r).unwrap().1, PolicyResult::Deny);
        let (_, _, mut o) = observation();
        o.first.as_mut().unwrap().policies.push(PolicyRead {
            policy_id: "inline:deny".into(),
            document_sha256: "a".repeat(64),
            result: PolicyResult::Deny,
        });
        assert!(!allowed(o.first.as_ref().unwrap()));
        o.first.as_mut().unwrap().policies.pop();
        o.first.as_mut().unwrap().boundary = Some(PolicyRead {
            policy_id: "arn:aws:iam::123456789012:policy/bound:v1".into(),
            document_sha256: "a".repeat(64),
            result: PolicyResult::NoGrant,
        });
        assert!(!allowed(o.first.as_ref().unwrap()));
    }
    #[test]
    fn unsupported_semantics_and_duplicate_json_are_never_complete() {
        let r = "resource";
        for field in [
            "Condition",
            "NotAction",
            "NotResource",
            "Principal",
            "Future",
        ] {
            let mut v: Value = serde_json::from_str(&p("Allow", "*", "*")).unwrap();
            v["Statement"][field] = serde_json::json!({});
            assert_eq!(
                policy(&v.to_string(), r).unwrap().1,
                PolicyResult::Unsupported,
                "{field}"
            );
        }
        for pattern in [
            "rds-db:*",
            "rds-db:connec?",
            "${aws:username}",
            "",
            "rds-db:connect\n",
        ] {
            assert_eq!(
                policy(&p("Allow", pattern, "*"), r).unwrap().1,
                PolicyResult::Unsupported
            );
        }
        for raw in [
            r#"{"Statement":{},"Statement":[]}"#,
            r#"{"Statement":{"Action":"*","Action":"s3:*"}}"#,
        ] {
            assert!(policy(raw, r).is_err());
        }
        assert!(decode("%7B%22bad%22%3A%22%2B%22%7D").unwrap().contains('+'));
        assert!(decode("%GG").is_err());
        assert!(policy(r#"{"Statement":[]} trailing"#, r).is_err());
    }
    #[test]
    fn organization_requires_native_explicit_no_membership_or_matching_management_account() {
        assert_eq!(
            organization(
                br#"{"__type":"AWSOrganizationsNotInUseException","message":"not in use"}"#,
                "123456789012"
            )
            .unwrap(),
            Organization::NotMember
        );
        assert_eq!(
            organization(br#"{"__type":"AccessDeniedException"}"#, "123456789012").unwrap(),
            Organization::Unreadable
        );
        assert_eq!(
            organization(br#"{}"#, "123456789012").unwrap(),
            Organization::Unreadable
        );
        let b = br#"{"Organization":{"Id":"o-example1234","MasterAccountId":"123456789012"}}"#;
        assert!(matches!(
            organization(b, "123456789012").unwrap(),
            Organization::ManagementAccount { .. }
        ));
        assert!(matches!(
            organization(b, "999999999999").unwrap(),
            Organization::MemberAccount { .. }
        ));
        // Deprecated AvailablePolicyTypes isn't used as completeness authority.
        let b=br#"{"Organization":{"Id":"o-example1234","MasterAccountId":"999999999999","AvailablePolicyTypes":[]}}"#;
        assert!(matches!(
            organization(b, "123456789012").unwrap(),
            Organization::MemberAccount { .. }
        ));
    }
    #[test]
    fn gaps_preserve_unknown_inventory_and_scope_or_generation_tamper_is_rejected() {
        let (i, c, base) = observation();
        for n in 0..5 {
            let mut o = base.clone();
            match n {
                0 => o.first = None,
                1 => o.organization = Organization::Unreadable,
                2 => {
                    o.organization = Organization::MemberAccount {
                        organization_id: "o-example1234".into(),
                    }
                }
                3 => o.second.as_mut().unwrap().policies[0].document_sha256 = "b".repeat(64),
                _ => {
                    o.first.as_mut().unwrap().policies[0].result = PolicyResult::Unsupported;
                    o.second = o.first.clone();
                }
            }
            let claim = normalized(&i, &c, &o);
            assert_eq!(claim.observed, StateValue::Unknown);
            assert!(!claim.permission_inventory.unwrap().complete, "{n}");
            assert!(claim.denial_cause.is_none());
        }
        for n in 0..8 {
            let mut o = base.clone();
            match n {
                0 => o.version = 2,
                1 => o.resource.push('x'),
                2 => o.generation = "b".repeat(64),
                3 => o.principal.role_id.push('x'),
                4 => o.after.proxy_arn.push('x'),
                5 => o.started_at = 99,
                6 => o.request_digest = "b".repeat(64),
                _ => o.case_id.push('x'),
            }
            let (_, _, pg) = super::super::aws_postgres::tests::sample();
            let (_, a) =
                super::super::aws_postgres::normalize(&i, &c, 111, 114, &pg, "proof").unwrap();
            assert!(normalize(&i, &c, &o, "proof", a.coverage).is_err(), "{n}");
        }
        let mut value = serde_json::to_value(base).unwrap();
        value["complete"] = Value::Bool(true);
        assert!(serde_json::from_value::<AwsIamObservation>(value).is_err());
    }
    struct Transcript(std::sync::Mutex<std::collections::VecDeque<(&'static str, String)>>);
    impl IamRead for Transcript {
        async fn query(
            &self,
            action: &str,
            params: &[(&str, &str)],
        ) -> Result<String, SourceError> {
            let (expected, body) = self.0.lock().unwrap().pop_front().expect("unexpected API");
            assert_eq!(expected, action);
            assert!(!params.is_empty());
            Ok(body)
        }
    }
    #[tokio::test]
    async fn native_read_sequence_acquires_inline_managed_default_and_boundary_documents() {
        let (_, _, o) = observation();
        let a = &o.principal;
        let role = a.role_arn.rsplit('/').next().unwrap();
        let id = "arn:aws:iam::123456789012:policy/managed";
        let document = p("Allow", ACTION, &o.resource);
        let getpolicy =
            format!("<Policy><Arn>{id}</Arn><DefaultVersionId>v1</DefaultVersionId></Policy>");
        let version = format!(
            "<PolicyVersion><Document>{document}</Document><VersionId>v1</VersionId><IsDefaultVersion>true</IsDefaultVersion></PolicyVersion>"
        );
        let transcript=Transcript(std::sync::Mutex::new(std::collections::VecDeque::from([
            ("GetRole",format!("<Role><Arn>{}</Arn><RoleId>{}</RoleId><RoleName>{role}</RoleName><PermissionsBoundary><PermissionsBoundaryType>Policy</PermissionsBoundaryType><PermissionsBoundaryArn>{id}</PermissionsBoundaryArn></PermissionsBoundary></Role>",a.role_arn,a.role_id)),
            ("GetPolicy",getpolicy.clone()),("GetPolicyVersion",version.clone()),
            ("ListRolePolicies","<ListRolePoliciesResult><IsTruncated>false</IsTruncated><PolicyNames><member>connect</member></PolicyNames></ListRolePoliciesResult>".into()),
            ("GetRolePolicy",format!("<GetRolePolicyResult><RoleName>{role}</RoleName><PolicyName>connect</PolicyName><PolicyDocument>{document}</PolicyDocument></GetRolePolicyResult>")),
            ("ListAttachedRolePolicies",format!("<ListAttachedRolePoliciesResult><IsTruncated>false</IsTruncated><AttachedPolicies><member><PolicyArn>{id}</PolicyArn><PolicyName>managed</PolicyName></member></AttachedPolicies></ListAttachedRolePoliciesResult>")),
            ("GetPolicy",getpolicy),("GetPolicyVersion",version)
        ])));
        let result = role_inventory(&transcript, a, &o.resource).await.unwrap();
        assert_eq!(result.policies.len(), 2);
        assert!(result.boundary.is_some());
        assert!(allowed(&result));
        assert!(transcript.0.lock().unwrap().is_empty());
        let transcript=Transcript(std::sync::Mutex::new(std::collections::VecDeque::from([
            ("GetRole",format!("<Role><Arn>{}</Arn><RoleId>{}</RoleId><RoleName>{role}</RoleName></Role>",a.role_arn,a.role_id)),
            ("ListRolePolicies","<ListRolePoliciesResult><IsTruncated>true</IsTruncated><PolicyNames></PolicyNames></ListRolePoliciesResult>".into())
        ])));
        assert!(role_inventory(&transcript, a, &o.resource).await.is_err());
    }
    #[test]
    fn fixed_signed_api_origins_and_actions_never_put_credentials_in_argv() {
        let credentials = Credentials::new(
            "AKIA_TEST_SENTINEL",
            "SECRET_SENTINEL",
            Some("TOKEN_SENTINEL".into()),
            None,
            "test",
        );
        let config = String::from_utf8(
            json_signed_config(
                &credentials,
                "organizations",
                "AWSOrganizationsV20161128.DescribeOrganization",
                b"{}",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(config.contains("organizations.us-east-1.amazonaws.com"));
        assert!(config.contains("Credential=AKIA_TEST_SENTINEL/"));
        assert!(!api_args().join(" ").contains("SENTINEL"));
        assert!(
            json_signed_config(
                &credentials,
                "organizations",
                "AWSOrganizationsV20161128.LeaveOrganization",
                b"{}"
            )
            .is_err()
        );
        let config = String::from_utf8(
            signed_config(&credentials, "iam", "GetRole", &[("RoleName", "role")]).unwrap(),
        )
        .unwrap();
        assert!(config.contains("iam.amazonaws.com"));
        assert!(config.contains("us-east-1%2Fiam"));
        assert!(signed_config(&credentials, "iam", "DeleteRole", &[]).is_err());
    }
}

#[cfg(test)]
mod organization_stability_tests {
    use super::*;
    #[test]
    fn membership_change_cannot_produce_complete_permission_inventory() {
        let (i, config, _) = super::super::aws_postgres::tests::sample();
        let c = &i.request.cases[0];
        let mut o = fixture_for_capture(&i, c, &config.postgres.as_ref().unwrap().targets[0]);
        assert!(gaps(&o).is_empty());
        o.organization_after = Organization::MemberAccount {
            organization_id: "o-changed1234".into(),
        };
        assert!(gaps(&o).contains(&AwsIamGap::InventoryChanged));
        o.organization_after = Organization::Unreadable;
        assert!(gaps(&o).contains(&AwsIamGap::InventoryChanged));
    }
}
