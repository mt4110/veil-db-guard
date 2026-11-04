//! Shared source-side AWS reads. No management SDK/profile/environment fallback.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{
    aws_host::{MetadataRequest, metadata_request},
    collector,
    gce_host::{SourceError, trusted_program},
    process,
};
use crate::core::{
    admission::IssuedObservation,
    evidence::*,
    policy::*,
    source::{AwsEc2Identity, AwsMetadataCredential},
};
use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime},
};
use tokio_util::sync::CancellationToken;
pub const CA_PATH: &str = "/etc/veil-db-guard/aws-rds-ca.pem";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsDatabaseTarget {
    pub target_id: String,
    pub db_arn: String,
    pub db_resource_id: String,
    pub db_endpoint: String,
    pub proxy_name: String,
    pub proxy_arn: String,
    pub proxy_endpoint: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Credential,
    TargetMetadata,
    Connect,
    Catalog,
    Completed,
    Deadline,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    pub(super) db_arn: String,
    pub(super) db_resource_id: String,
    pub(super) db_endpoint: String,
    pub(super) engine_version: String,
    pub(super) proxy_arn: String,
    pub(super) proxy_endpoint: String,
    pub(super) target_resource_name: String,
    pub(super) target_endpoint: String,
}

pub(super) fn engine_profile(
    family: EngineFamily,
) -> Result<(&'static str, &'static str, &'static str, u16), SourceError> {
    match family {
        EngineFamily::PostgreSql => Ok(("postgres", "16.15", "POSTGRESQL", 5432)),
        EngineFamily::MySql => Ok(("mysql", "8.0.43", "MYSQL", 3306)),
        _ => Err(SourceError::Unsupported),
    }
}
pub(super) fn validate_config(
    i: &IssuedObservation,
    ca_sha256: &str,
    targets: &[AwsDatabaseTarget],
    family: EngineFamily,
) -> Result<(), SourceError> {
    let (_, version, _, port) = engine_profile(family)?;
    let s = i.snapshot.aws().ok_or(SourceError::Unsupported)?;
    if !valid_hash(ca_sha256)
        || targets.is_empty()
        || targets.len() > 8
        || s.metadata_credential.is_none()
    {
        return Err(SourceError::Invalid);
    }
    let mut ids = std::collections::BTreeSet::new();
    for t in targets {
        if !ids.insert(&t.target_id)
            || !valid_id(&t.target_id)
            || !valid_id(&t.proxy_name)
            || !valid_id(&t.db_resource_id)
            || !t.db_arn.starts_with(&format!(
                "arn:aws:rds:ap-northeast-1:{}:db:",
                s.native_identity.account_id
            ))
            || !t.proxy_arn.starts_with(&format!(
                "arn:aws:rds:ap-northeast-1:{}:db-proxy:prx-",
                s.native_identity.account_id
            ))
            || [&t.db_endpoint, &t.proxy_endpoint].iter().any(|s| {
                s.len() > 253
                    || !s.ends_with(".ap-northeast-1.rds.amazonaws.com")
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            })
        {
            return Err(SourceError::Invalid);
        }
    }
    for c in &i.request.cases {
        if c.kind == FixedObservationCase::DirectPath
            || c.address.target.engine_binding.family != family
        {
            continue;
        }
        let t = targets
            .iter()
            .find(|t| t.target_id == c.address.target_id)
            .ok_or(SourceError::Invalid)?;
        if c.address.target.placement.kind != PlacementKind::AwsRds
            || c.address.target.placement.account_id != s.native_identity.account_id
            || c.address.target.placement.region != "ap-northeast-1"
            || c.address.target.engine_binding.version != version
            || c.address.target.native_ref.native_id != t.db_arn
            || c.address
                .target
                .native_ref
                .generation_fingerprint
                .as_deref()
                != Some(
                    aws_generation_fingerprint(
                        &s.native_identity.account_id,
                        "ap-northeast-1",
                        &t.db_arn,
                        &t.db_resource_id,
                    )
                    .as_str(),
                )
            || c.address.route.kind != RouteKind::NativeProxy
            || c.endpoint != t.proxy_endpoint
            || c.port != port
        {
            return Err(SourceError::Invalid);
        }
    }
    Ok(())
}
#[cfg(unix)]
pub(super) fn pinned_ca(digest: &str) -> Result<Vec<u8>, SourceError> {
    let ca = collector::root_file(Path::new(CA_PATH), 1_048_576)?;
    if crate::config::hash_bytes(&ca) != digest {
        return Err(SourceError::Integrity);
    }
    Ok(ca)
}
pub(super) async fn authenticate(
    actor: &AwsMetadataCredential,
    account: &str,
    cancel: &CancellationToken,
) -> Result<Credentials, SourceError> {
    let creds = credentials(actor, cancel).await?;
    let identity = api(&creds, "sts", "GetCallerIdentity", &[], cancel).await?;
    sts(&identity, actor, account)?;
    Ok(creds)
}

/// Authenticate the exact IMDSv2 credentials used for application token signing.
/// The fixed local metadata origin is part of the EC2 host trust boundary.
pub(crate) async fn authenticate_application(
    actor: &AwsMetadataCredential,
    expected: &AwsEc2Identity,
    cancel: &CancellationToken,
) -> Result<Credentials, SourceError> {
    let (document, signature) = super::aws_host::metadata_identity(cancel).await?;
    super::aws_iid::verify(&document, &signature, expected, crate::domain::now())?;
    let creds = credentials(actor, cancel).await?;
    let identity = api(&creds, "sts", "GetCallerIdentity", &[], cancel).await?;
    sts(&identity, actor, &expected.account_id)?;
    let result = element(&identity, "GetCallerIdentityResult")?;
    if scalar(result, "UserId")? != format!("{}:{}", actor.role_id, expected.instance_id) {
        return Err(SourceError::IdentityUnverified);
    }
    Ok(creds)
}
// No Debug/Serialize; temporary credentials remain in memory.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct MetadataCredentials {
    code: String,
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
    #[serde(rename = "Type")]
    kind: String,
}
impl MetadataCredentials {
    pub(super) fn parse(bytes: &[u8], now: u64) -> Result<Credentials, SourceError> {
        if bytes.len() > 16384 {
            return Err(SourceError::Limit);
        }
        let c: Self = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
        let expires = parse_time(&c.expiration)?;
        if c.code != "Success"
            || c.kind != "AWS-HMAC"
            || expires <= now.saturating_add(60)
            || c.access_key_id.len() < 16
            || c.access_key_id.len() > 128
            || !c.access_key_id.bytes().all(|b| b.is_ascii_alphanumeric())
            || c.secret_access_key.len() < 16
            || c.secret_access_key.len() > 256
            || !c
                .secret_access_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
            || c.token.is_empty()
            || c.token.len() > 8192
            || c.token.bytes().any(|b| !(0x21..=0x7e).contains(&b))
        {
            return Err(SourceError::IdentityUnverified);
        }
        Ok(Credentials::new(
            c.access_key_id,
            c.secret_access_key,
            Some(c.token),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(expires)),
            "ec2-imdsv2-only",
        ))
    }
}
pub(super) fn parse_time(s: &str) -> Result<u64, SourceError> {
    let b = s.as_bytes();
    if !s.is_ascii() {
        return Err(SourceError::Invalid);
    }
    if b.len() != 20
        || [4, 7].iter().any(|&i| b[i] != b'-')
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return Err(SourceError::Invalid);
    }
    let n = |a, b| s[a..b].parse::<u64>().map_err(|_| SourceError::Invalid);
    let (y, m, d, h, mi, se) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    if !(1970..=2100).contains(&y)
        || !(1..=12).contains(&m)
        || d == 0
        || h > 23
        || mi > 59
        || se > 59
    {
        return Err(SourceError::Invalid);
    }
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let mut days = 0u64;
    for yr in 1970..y {
        days += if leap(yr) { 366 } else { 365 };
    }
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
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
    if d > months[(m - 1) as usize] {
        return Err(SourceError::Invalid);
    }
    days += months[..(m - 1) as usize].iter().sum::<u64>() + d - 1;
    Ok(days * 86400 + h * 3600 + mi * 60 + se)
}
pub(super) async fn credentials(
    actor: &AwsMetadataCredential,
    cancel: &CancellationToken,
) -> Result<Credentials, SourceError> {
    let token = metadata_request(MetadataRequest::Token, None, cancel).await?;
    let token = std::str::from_utf8(&token).map_err(|_| SourceError::Invalid)?;
    let name = metadata_request(MetadataRequest::RoleName, Some(token), cancel).await?;
    let name = std::str::from_utf8(&name)
        .map_err(|_| SourceError::Invalid)?
        .trim();
    if actor.role_arn.rsplit('/').next() != Some(name) {
        return Err(SourceError::IdentityUnverified);
    }
    let bytes =
        metadata_request(MetadataRequest::RoleCredentials(name), Some(token), cancel).await?;
    MetadataCredentials::parse(&bytes, crate::domain::now())
}
pub(super) fn signed_config(
    creds: &Credentials,
    service: &str,
    action: &str,
    parameters: &[(&str, &str)],
) -> Result<Vec<u8>, SourceError> {
    use aws_sigv4::{
        http_request::{SignableBody, SignableRequest, SignatureLocation, SigningSettings, sign},
        sign::v4,
    };
    if !matches!(
        (service, action),
        ("sts", "GetCallerIdentity")
            | ("rds", "DescribeDBInstances")
            | ("rds", "DescribeDBProxies")
            | ("rds", "DescribeDBProxyTargets")
            | (
                "iam",
                "GetRole"
                    | "ListRolePolicies"
                    | "GetRolePolicy"
                    | "ListAttachedRolePolicies"
                    | "GetPolicy"
                    | "GetPolicyVersion"
            )
    ) {
        return Err(SourceError::Invalid);
    }
    let origin = if service == "iam" {
        "https://iam.amazonaws.com/".to_owned()
    } else {
        format!("https://{service}.ap-northeast-1.amazonaws.com/")
    };
    let mut url = url::Url::parse(&origin).map_err(|_| SourceError::Invalid)?;
    url.query_pairs_mut()
        .append_pair("Action", action)
        .append_pair(
            "Version",
            if service == "iam" {
                "2010-05-08"
            } else if service == "sts" {
                "2011-06-15"
            } else {
                "2014-10-31"
            },
        );
    for (n, v) in parameters {
        url.query_pairs_mut().append_pair(n, v);
    }
    let identity = creds.clone().into();
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(Duration::from_secs(60));
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(if service == "iam" {
            "us-east-1"
        } else {
            "ap-northeast-1"
        })
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|_| SourceError::Invalid)?;
    let request = SignableRequest::new(
        "GET",
        url.as_str(),
        std::iter::empty(),
        SignableBody::Bytes(&[]),
    )
    .map_err(|_| SourceError::Invalid)?;
    let (instructions, _) = sign(request, &params.into())
        .map_err(|_| SourceError::Invalid)?
        .into_parts();
    for (n, v) in instructions.params() {
        url.query_pairs_mut().append_pair(n, v);
    }
    // Presigned URLs contain temporary credentials. Only pipe the config to
    // curl stdin; never put URL/signature/session token in argv or environment.
    Ok(format!("url = \"{}\"\n", url.as_str()).into_bytes())
}
pub(super) fn api_args() -> Vec<String> {
    [
        "-q",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--max-time",
        "5",
        "--max-filesize",
        "131072",
        "--silent",
        "--fail",
        "--config",
        "-",
    ]
    .map(str::to_owned)
    .to_vec()
}
pub(super) async fn api(
    creds: &Credentials,
    service: &str,
    action: &str,
    params: &[(&str, &str)],
    cancel: &CancellationToken,
) -> Result<String, SourceError> {
    trusted_program(Path::new("/usr/bin/curl"))?;
    let config = signed_config(creds, service, action, params)?;
    let bytes = process::run(
        Path::new("/usr/bin/curl"),
        &api_args(),
        &config,
        131072,
        5,
        cancel,
    )
    .await?;
    let s = String::from_utf8(bytes).map_err(|_| SourceError::Invalid)?;
    if s.contains("<!") || s.contains('&') || (service != "iam" && s.contains("<Marker>")) {
        return Err(SourceError::Invalid);
    }
    Ok(s)
}
pub(super) fn json_signed_config(
    creds: &Credentials,
    service: &str,
    action: &str,
    body: &[u8],
) -> Result<Vec<u8>, SourceError> {
    use aws_sigv4::{
        http_request::{SignableBody, SignableRequest, SigningSettings, sign},
        sign::v4,
    };
    let region = match (service, action) {
        ("organizations", "AWSOrganizationsV20161128.DescribeOrganization") if body == b"{}" => {
            "us-east-1"
        }
        ("logs", "Logs_20140328.FilterLogEvents") => "ap-northeast-1",
        _ => return Err(SourceError::Unsupported),
    };
    if body.len() > 16384 {
        return Err(SourceError::Limit);
    }
    let origin = format!("https://{service}.{region}.amazonaws.com/");
    let identity = creds.clone().into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .map_err(|_| SourceError::Invalid)?;
    let headers = [
        ("content-type", "application/x-amz-json-1.1"),
        ("x-amz-target", action),
    ];
    let request = SignableRequest::new(
        "POST",
        &origin,
        headers.into_iter(),
        SignableBody::Bytes(body),
    )
    .map_err(|_| SourceError::Invalid)?;
    let (instructions, _) = sign(request, &params.into())
        .map_err(|_| SourceError::Invalid)?
        .into_parts();
    let escape = |s: &str| -> Result<String, SourceError> {
        if s.chars().any(char::is_control) {
            return Err(SourceError::Invalid);
        }
        Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
    };
    let body = std::str::from_utf8(body).map_err(|_| SourceError::Invalid)?;
    let mut out = format!(
        "url = \"{origin}\"\nrequest = \"POST\"\ndata = \"{}\"\n",
        escape(body)?
    );
    for (n, v) in headers.into_iter().chain(instructions.headers()) {
        out.push_str(&format!("header = \"{}: {}\"\n", escape(n)?, escape(v)?));
    }
    Ok(out.into_bytes())
}
pub(super) async fn json_api(
    creds: &Credentials,
    service: &str,
    action: &str,
    body: &[u8],
    cancel: &CancellationToken,
) -> Result<Vec<u8>, SourceError> {
    trusted_program(Path::new("/usr/bin/curl"))?;
    let config = json_signed_config(creds, service, action, body)?;
    // Organizations' exact NotInUse error is useful negative membership
    // evidence. Callers must parse success/error schemas, never infer from HTTP.
    let args: Vec<_> = api_args().into_iter().filter(|s| s != "--fail").collect();
    process::run(
        Path::new("/usr/bin/curl"),
        &args,
        &config,
        131072,
        5,
        cancel,
    )
    .await
}
// Deliberately restricted selector for fixed AWS Query responses: one exact
// element, no entities/DTD/CDATA/namespace aliases/duplicate or nested scalars.
pub(super) fn element<'a>(xml: &'a str, tag: &str) -> Result<&'a str, SourceError> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if xml.matches(&open).count() != 1 || xml.matches(&close).count() != 1 {
        return Err(SourceError::Invalid);
    }
    let a = xml.find(&open).ok_or(SourceError::Invalid)? + open.len();
    let b = xml.find(&close).ok_or(SourceError::Invalid)?;
    if a > b {
        return Err(SourceError::Invalid);
    }
    Ok(&xml[a..b])
}
pub(super) fn single_member(xml: &str) -> Result<&str, SourceError> {
    let s = xml.trim();
    if !s.starts_with("<member>") {
        return Err(SourceError::Invalid);
    }
    let mut depth = 0usize;
    let mut pos = 0;
    while let Some(start) = s[pos..].find('<') {
        let start = pos + start;
        let end = s[start..].find('>').ok_or(SourceError::Invalid)? + start;
        let name = &s[start + 1..end];
        if name == "member" {
            depth += 1;
        } else if name == "/member" {
            depth = depth.checked_sub(1).ok_or(SourceError::Invalid)?;
            if depth == 0 {
                if !s[end + 1..].trim().is_empty() {
                    return Err(SourceError::Invalid);
                }
                return Ok(&s[8..start]);
            }
        }
        pos = end + 1;
    }
    Err(SourceError::Invalid)
}
pub(super) fn scalar(xml: &str, tag: &str) -> Result<String, SourceError> {
    let s = element(xml, tag)?;
    if s.is_empty()
        || s.len() > 512
        || s.contains(['<', '>', '&'])
        || s.chars().any(char::is_control)
    {
        return Err(SourceError::Invalid);
    }
    Ok(s.to_owned())
}
pub(super) fn sts(
    xml: &str,
    actor: &AwsMetadataCredential,
    account: &str,
) -> Result<(), SourceError> {
    let r = element(xml, "GetCallerIdentityResult")?;
    let arn = scalar(r, "Arn")?;
    let user = scalar(r, "UserId")?;
    let session = arn.rsplit('/').next().ok_or(SourceError::Invalid)?;
    let role = actor
        .role_arn
        .rsplit('/')
        .next()
        .ok_or(SourceError::Invalid)?;
    if scalar(r, "Account")? != account
        || !arn.starts_with(&format!("arn:aws:sts::{account}:assumed-role/{role}/"))
        || session.is_empty()
        || user != format!("{}:{session}", actor.role_id)
    {
        return Err(SourceError::IdentityUnverified);
    }
    Ok(())
}
pub(super) async fn metadata(
    creds: &Credentials,
    t: &AwsDatabaseTarget,
    family: EngineFamily,
    cancel: &CancellationToken,
) -> Result<Metadata, SourceError> {
    let (engine, version, proxy_engine, port) = engine_profile(family)?;

    let db = api(
        creds,
        "rds",
        "DescribeDBInstances",
        &[("DBInstanceIdentifier", &t.db_arn)],
        cancel,
    )
    .await?;
    let db = element(&db, "DBInstance")?;
    let endpoint = element(db, "Endpoint")?;
    if scalar(db, "Engine")? != engine
        || scalar(db, "EngineVersion")? != version
        || scalar(db, "DBInstanceArn")? != t.db_arn
        || scalar(db, "DbiResourceId")? != t.db_resource_id
        || scalar(endpoint, "Address")? != t.db_endpoint
        || scalar(endpoint, "Port")? != port.to_string()
    {
        return Err(SourceError::ContextUnverified);
    }
    let proxy = api(
        creds,
        "rds",
        "DescribeDBProxies",
        &[("DBProxyName", &t.proxy_name)],
        cancel,
    )
    .await?;
    let proxy = single_member(element(&proxy, "DBProxies")?)?;
    if scalar(proxy, "DBProxyArn")? != t.proxy_arn
        || scalar(proxy, "Endpoint")? != t.proxy_endpoint
        || scalar(proxy, "EngineFamily")? != proxy_engine
        || scalar(proxy, "Status")? != "available"
        || scalar(proxy, "RequireTLS")? != "true"
    {
        return Err(SourceError::ContextUnverified);
    }
    let targets = api(
        creds,
        "rds",
        "DescribeDBProxyTargets",
        &[
            ("DBProxyName", &t.proxy_name),
            ("TargetGroupName", "default"),
        ],
        cancel,
    )
    .await?;
    let target = single_member(element(&targets, "Targets")?)?;
    let name = t.db_arn.rsplit(':').next().ok_or(SourceError::Invalid)?;
    if scalar(target, "RdsResourceId")? != name
        || scalar(target, "Endpoint")? != t.db_endpoint
        || scalar(target, "Port")? != port.to_string()
        || scalar(element(target, "TargetHealth")?, "State")? != "AVAILABLE"
    {
        return Err(SourceError::ContextUnverified);
    }
    Ok(Metadata {
        db_arn: t.db_arn.clone(),
        db_resource_id: t.db_resource_id.clone(),
        db_endpoint: t.db_endpoint.clone(),
        engine_version: version.into(),
        proxy_arn: t.proxy_arn.clone(),
        proxy_endpoint: t.proxy_endpoint.clone(),
        target_resource_name: name.to_owned(),
        target_endpoint: t.db_endpoint.clone(),
    })
}
