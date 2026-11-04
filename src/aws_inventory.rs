//! Fixed AWS CLI read operations. Live execution is explicit; fixtures never invoke AWS.
use crate::{
    config::{GuardError, config_hash, validate_config, validate_snapshot},
    domain::*,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct InspectOptions {
    pub aws_profile: Option<String>,
    pub allow_aws_read: bool,
}
#[derive(Clone, Debug)]
pub struct CommandRequest {
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub max_bytes: usize,
}
pub struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
pub trait CommandRunner {
    fn run(
        &self,
        request: CommandRequest,
        cancel: CancellationToken,
    ) -> impl Future<Output = Result<CommandOutput, GuardError>> + Send;
}
pub struct AwsCliRunner;
async fn read_pipe<R: AsyncRead + Unpin>(pipe: R, max: usize) -> Result<Vec<u8>, GuardError> {
    let mut output = Vec::new();
    pipe.take(max as u64 + 1)
        .read_to_end(&mut output)
        .await
        .map_err(|_| GuardError::OperationFailed)?;
    if output.len() > max {
        return Err(GuardError::LimitExceeded);
    }
    Ok(output)
}
impl CommandRunner for AwsCliRunner {
    async fn run(
        &self,
        request: CommandRequest,
        cancel: CancellationToken,
    ) -> Result<CommandOutput, GuardError> {
        if cancel.is_cancelled() {
            return Err(GuardError::Cancelled);
        }
        let mut child = Command::new("aws")
            .args(&request.args)
            .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
            .env("AWS_PAGER", "")
            .env("AWS_CLI_AUTO_PROMPT", "off")
            .env("AWS_MAX_ATTEMPTS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| GuardError::OperationFailed)?;
        let stdout = child.stdout.take().ok_or(GuardError::OperationFailed)?;
        let stderr = child.stderr.take().ok_or(GuardError::OperationFailed)?;
        let work = async {
            let (status, stdout, stderr) = tokio::try_join!(
                async { child.wait().await.map_err(|_| GuardError::OperationFailed) },
                read_pipe(stdout, request.max_bytes),
                read_pipe(stderr, request.max_bytes)
            )?;
            Ok(CommandOutput {
                success: status.success(),
                stdout,
                stderr,
            })
        };
        let result = tokio::select! {
            _=cancel.cancelled()=>Err(GuardError::Cancelled),
            result=tokio::time::timeout(Duration::from_millis(request.timeout_ms),work)=>
                result.unwrap_or(Err(GuardError::OperationFailed))
        };
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result
    }
}
fn request(
    c: &TargetConfig,
    o: &InspectOptions,
    operation: &str,
    selectors: Vec<String>,
    remaining: u64,
) -> CommandRequest {
    let service = if operation == "describe-security-groups" {
        "ec2"
    } else {
        "rds"
    };
    let seconds = c
        .limits
        .connect_timeout_ms
        .div_ceil(1000)
        .max(1)
        .to_string();
    let mut args = vec![service.into(), operation.into()];
    args.extend(selectors);
    args.extend([
        "--region".into(),
        c.target.region.clone(),
        "--output".into(),
        "json".into(),
        "--no-cli-pager".into(),
        "--no-cli-auto-prompt".into(),
        "--color".into(),
        "off".into(),
        "--cli-connect-timeout".into(),
        seconds.clone(),
        "--cli-read-timeout".into(),
        seconds,
        "--max-items".into(),
        c.limits.max_results.to_string(),
    ]);
    if let Some(p) = &o.aws_profile {
        args.extend(["--profile".into(), p.clone()]);
    }
    CommandRequest {
        args,
        timeout_ms: remaining,
        max_bytes: c.limits.max_bytes,
    }
}
async fn fetch<R: CommandRunner>(
    runner: &R,
    c: &TargetConfig,
    o: &InspectOptions,
    query: (&str, Vec<String>),
    responses: &mut BTreeMap<String, Value>,
    cancel: &CancellationToken,
    started: std::time::Instant,
) -> Result<(), GuardError> {
    let (operation, selectors) = query;
    let remaining = c
        .limits
        .total_timeout_ms
        .saturating_sub(started.elapsed().as_millis() as u64);
    if remaining == 0 {
        return Err(GuardError::OperationFailed);
    }
    let req = request(c, o, operation, selectors, remaining);
    let run = tokio::select! {
        _=cancel.cancelled()=>return Err(GuardError::Cancelled),
        r=tokio::time::timeout(Duration::from_millis(remaining),runner.run(req,cancel.child_token()))=>r.unwrap_or(Err(GuardError::OperationFailed))
    };
    let value = match run {
        Ok(out) => {
            if out.stdout.len() > c.limits.max_bytes || out.stderr.len() > c.limits.max_bytes {
                return Err(GuardError::LimitExceeded);
            }
            if out.success {
                serde_json::from_slice(&out.stdout).map_err(|_| GuardError::EvidenceIncompatible)?
            } else {
                // Classify a known AWS code, never preserve or print diagnostic text.
                let text = String::from_utf8_lossy(&out.stderr);
                let denied =
                    text.contains("AccessDenied") || text.contains("UnauthorizedOperation");
                serde_json::json!({"_error":if denied {"access_denied"}else{"failed"}})
            }
        }
        Err(GuardError::Cancelled) => return Err(GuardError::Cancelled),
        Err(GuardError::LimitExceeded) => return Err(GuardError::LimitExceeded),
        Err(_) => serde_json::json!({"_error":"failed"}),
    };
    responses.insert(operation.into(), value);
    Ok(())
}
pub async fn inspect(
    c: &TargetConfig,
    o: &InspectOptions,
    cancel: CancellationToken,
) -> Result<InventorySnapshot, GuardError> {
    // Synthetic documentation targets must fail before even spawning the credential provider.
    if c.target.account_id == "000000000000" {
        return Err(GuardError::ConfigInvalid);
    }
    inspect_with_runner(c, o, cancel, &AwsCliRunner).await
}
pub async fn inspect_with_runner<R: CommandRunner>(
    c: &TargetConfig,
    o: &InspectOptions,
    cancel: CancellationToken,
    runner: &R,
) -> Result<InventorySnapshot, GuardError> {
    validate_config(c)?;
    if !o.allow_aws_read {
        return Err(GuardError::PermissionRequired);
    }
    if o.aws_profile
        .as_ref()
        .is_some_and(|p| !crate::config::safe_id(p) || p.starts_with('-'))
    {
        return Err(GuardError::ConfigInvalid);
    }
    if cancel.is_cancelled() {
        return Err(GuardError::Cancelled);
    }
    let started = std::time::Instant::now();
    let mut data = BTreeMap::new();
    for (op, sel) in [
        (
            "describe-db-proxies",
            vec!["--db-proxy-name".into(), c.target.proxy_name.clone()],
        ),
        (
            "describe-db-instances",
            vec![
                "--db-instance-identifier".into(),
                c.target.db_instance_arn.clone(),
            ],
        ),
        (
            "describe-db-proxy-target-groups",
            vec![
                "--db-proxy-name".into(),
                c.target.proxy_name.clone(),
                "--target-group-name".into(),
                "default".into(),
            ],
        ),
        (
            "describe-db-proxy-targets",
            vec![
                "--db-proxy-name".into(),
                c.target.proxy_name.clone(),
                "--target-group-name".into(),
                "default".into(),
            ],
        ),
    ] {
        fetch(runner, c, o, (op, sel), &mut data, &cancel, started).await?;
    }
    // Normalize before deriving any dependent selectors: reject a different ARN immediately.
    let first = normalize(c, &data)?;
    if let Some(group) = first.db.as_ref().and_then(|d| d.parameter_group.as_ref()) {
        if !crate::config::safe_id(group) || group.starts_with('-') {
            return Err(GuardError::EvidenceIncompatible);
        }
        fetch(
            runner,
            c,
            o,
            (
                "describe-db-parameters",
                vec![
                    "--db-parameter-group-name".into(),
                    group.clone(),
                    "--filters".into(),
                    "Name=parameter-name,Values=rds.force_ssl".into(),
                ],
            ),
            &mut data,
            &cancel,
            started,
        )
        .await?;
    }
    let ids: BTreeSet<String> = first
        .db
        .iter()
        .flat_map(|d| d.security_group_ids.clone())
        .chain(
            first
                .proxy
                .iter()
                .flat_map(|p| p.security_group_ids.clone()),
        )
        .collect();
    if !ids.is_empty() {
        let mut selectors = vec!["--group-ids".into()];
        selectors.extend(ids);
        fetch(
            runner,
            c,
            o,
            ("describe-security-groups", selectors),
            &mut data,
            &cancel,
            started,
        )
        .await?;
    }
    let mut snapshot = normalize(c, &data)?;
    snapshot.evidence_kind = EvidenceKind::AwsConfiguration;
    Ok(snapshot)
}
fn str_value(v: &Value, key: &str) -> Result<String, GuardError> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(GuardError::EvidenceIncompatible)
}
fn boolean(v: &Value, key: &str) -> Result<bool, GuardError> {
    v.get(key)
        .and_then(Value::as_bool)
        .ok_or(GuardError::EvidenceIncompatible)
}
fn optional_string(
    v: &Value,
    key: &str,
    valid: impl FnOnce(&str) -> bool,
) -> Result<Option<String>, GuardError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if valid(s) => Ok(Some(s.clone())),
        Some(_) => Err(GuardError::EvidenceIncompatible),
    }
}
fn instance_class(s: &str) -> bool {
    let labels: Vec<_> = s.split('.').collect();
    s.len() <= 64
        && labels.len() == 3
        && labels[0] == "db"
        && !labels[1].is_empty()
        && labels[1].as_bytes()[0].is_ascii_lowercase()
        && labels[1]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !labels[2].is_empty()
        && labels[2]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}
fn availability_zone(c: &TargetConfig, s: &str) -> bool {
    s.strip_prefix(&c.target.region)
        .is_some_and(|suffix| suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_lowercase())
}
fn strings(v: &Value, key: &str) -> Result<Vec<String>, GuardError> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or(GuardError::EvidenceIncompatible)?
        .iter()
        .map(|x| {
            x.as_str()
                .map(str::to_owned)
                .ok_or(GuardError::EvidenceIncompatible)
        })
        .collect()
}
fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, GuardError> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or(GuardError::EvidenceIncompatible)
}
fn one<'a>(v: &'a Value, key: &str) -> Result<&'a Value, GuardError> {
    let a = array(v, key)?;
    if a.len() != 1 {
        return Err(GuardError::TargetMismatch);
    }
    Ok(&a[0])
}
fn status(v: Option<&Value>) -> RetrievalStatus {
    match v {
        None => RetrievalStatus::NotRequested,
        Some(v) if v.get("_error").and_then(Value::as_str) == Some("access_denied") => {
            RetrievalStatus::AccessDenied
        }
        Some(v) if v.get("_error").is_some() => RetrievalStatus::Failed,
        Some(v)
            if ["NextToken", "Marker", "NextMarker"].iter().any(|k| {
                v.get(k)
                    .is_some_and(|x| !x.is_null() && x.as_str() != Some(""))
            }) =>
        {
            RetrievalStatus::Partial
        }
        Some(_) => RetrievalStatus::Complete,
    }
}
fn usable(s: RetrievalStatus) -> bool {
    matches!(s, RetrievalStatus::Complete | RetrievalStatus::Partial)
}
fn sg_ids(v: &Value) -> Result<Vec<String>, GuardError> {
    array(v, "VpcSecurityGroups")?
        .iter()
        .map(|s| str_value(s, "VpcSecurityGroupId"))
        .collect()
}
fn hex_id(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix)
        .is_some_and(|s| matches!(s.len(), 8 | 17) && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn validate_sg_id(id: &str) -> Result<(), GuardError> {
    if !hex_id(id, "sg-") {
        return Err(GuardError::EvidenceIncompatible);
    }
    Ok(())
}
fn role_arn(c: &TargetConfig, value: &str) -> bool {
    value
        .strip_prefix(&format!("arn:aws:iam::{}:role/", c.target.account_id))
        .is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 576
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/+=,.@_-".contains(&b))
        })
}
fn parameter_group_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
}
fn aws_endpoint(c: &TargetConfig, e: &Endpoint) -> bool {
    crate::config::valid_endpoint(e)
        && e.host
            .ends_with(&format!(".{}.rds.amazonaws.com", c.target.region))
        && e.host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
/// Fixture keys are CLI operation names. Raw diagnostic and free-text fields are discarded.
pub fn normalize(
    c: &TargetConfig,
    responses: &BTreeMap<String, Value>,
) -> Result<InventorySnapshot, GuardError> {
    validate_config(c)?;
    if serde_json::to_vec(responses)
        .map_err(|_| GuardError::EvidenceIncompatible)?
        .len()
        > c.limits.max_bytes
    {
        return Err(GuardError::LimitExceeded);
    }
    let ops = [
        "describe-db-proxies",
        "describe-db-instances",
        "describe-db-proxy-target-groups",
        "describe-db-proxy-targets",
        "describe-db-parameters",
        "describe-security-groups",
    ];
    let mut snapshot = InventorySnapshot {
        schema_version: 1,
        target: c.target.clone(),
        config_hash: config_hash(c),
        observed_at: now(),
        evidence_kind: EvidenceKind::LocalFixture,
        db: None,
        proxy: None,
        security_groups: vec![],
        retrievals: ops
            .iter()
            .map(|op| Retrieval {
                operation: (*op).into(),
                status: status(responses.get(*op)),
            })
            .collect(),
    };
    let get = |op: &str| responses.get(op).filter(|v| usable(status(Some(v))));
    if let Some(v) = get("describe-db-instances") {
        let d = one(v, "DBInstances")?;
        if str_value(d, "DBInstanceArn")? != c.target.db_instance_arn {
            return Err(GuardError::TargetMismatch);
        }
        let ep = d.get("Endpoint").ok_or(GuardError::EvidenceIncompatible)?;
        let groups = array(d, "DBParameterGroups")?;
        if groups.len() != 1 {
            return Err(GuardError::EvidenceIncompatible);
        }
        snapshot.db = Some(DbState {
            arn: str_value(d, "DBInstanceArn")?,
            resource_id: str_value(d, "DbiResourceId")?,
            endpoint: Endpoint {
                host: str_value(ep, "Address")?,
                port: ep
                    .get("Port")
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0)
                    .ok_or(GuardError::EvidenceIncompatible)?,
            },
            engine: str_value(d, "Engine")?,
            engine_version: str_value(d, "EngineVersion")?,
            iam_auth_enabled: boolean(d, "IAMDatabaseAuthenticationEnabled")?,
            publicly_accessible: boolean(d, "PubliclyAccessible")?,
            security_group_ids: sg_ids(d)?,
            parameter_group: Some(str_value(&groups[0], "DBParameterGroupName")?),
            parameters_in_sync: groups[0]
                .get("ParameterApplyStatus")
                .and_then(Value::as_str)
                == Some("in-sync"),
            force_ssl: None,
            instance_class: optional_string(d, "DBInstanceClass", instance_class)?,
            availability_zone: optional_string(d, "AvailabilityZone", |s| availability_zone(c, s))?,
        });
    }
    if let Some(v) = get("describe-db-proxies") {
        let p = one(v, "DBProxies")?;
        if str_value(p, "DBProxyArn")? != c.target.proxy_arn
            || str_value(p, "DBProxyName")? != c.target.proxy_name
        {
            return Err(GuardError::TargetMismatch);
        }
        let mode = match p.get("DefaultAuthScheme").and_then(Value::as_str) {
            Some("IAM_AUTH") => AuthMode::EndToEndIam,
            Some("NONE") => {
                let auth = array(p, "Auth")?;
                if auth.is_empty()
                    || auth
                        .iter()
                        .any(|a| a.get("IAMAuth").and_then(Value::as_str) != Some("REQUIRED"))
                {
                    return Err(GuardError::UnsupportedTarget);
                }
                AuthMode::StandardIam
            }
            _ => return Err(GuardError::EvidenceIncompatible),
        };
        snapshot.proxy = Some(ProxyState {
            arn: str_value(p, "DBProxyArn")?,
            endpoint: Endpoint {
                host: str_value(p, "Endpoint")?,
                port: 5432,
            },
            auth_mode: mode,
            require_tls: boolean(p, "RequireTLS")?,
            security_group_ids: strings(p, "VpcSecurityGroupIds")?,
            target_db_resource_id: None,
            target_health: TargetHealth::Unknown,
            role_arn: str_value(p, "RoleArn")?,
        });
        if p.get("EngineFamily").and_then(Value::as_str) != Some("POSTGRESQL") {
            return Err(GuardError::TargetMismatch);
        }
    }
    if let Some(v) = get("describe-db-proxy-targets") {
        let t = one(v, "Targets")?;
        // RdsResourceId here is the DB instance NAME, not DBInstance.DbiResourceId.
        let instance_name = c
            .target
            .db_instance_arn
            .rsplit(':')
            .next()
            .ok_or(GuardError::TargetMismatch)?;
        if str_value(t, "RdsResourceId")? != instance_name
            || t.get("TargetArn")
                .is_some_and(|a| a.as_str() != Some(&c.target.db_instance_arn))
            || t.get("Type").and_then(Value::as_str) != Some("RDS_INSTANCE")
            || t.get("Role").and_then(Value::as_str) != Some("READ_WRITE")
            || t.get("TrackedClusterId")
                .is_some_and(|a| !a.is_null() && a.as_str() != Some(""))
        {
            return Err(GuardError::TargetMismatch);
        }
        if let Some(db) = &snapshot.db {
            if t.get("Endpoint").and_then(Value::as_str) != Some(&db.endpoint.host)
                || t.get("Port").and_then(Value::as_u64) != Some(db.endpoint.port as u64)
            {
                return Err(GuardError::TargetMismatch);
            }
            if let Some(p) = snapshot.proxy.as_mut() {
                p.target_db_resource_id = Some(db.resource_id.clone());
                p.target_health = match t.pointer("/TargetHealth/State").and_then(Value::as_str) {
                    Some("AVAILABLE") => TargetHealth::Available,
                    Some("UNAVAILABLE") => TargetHealth::Unavailable,
                    _ => TargetHealth::Unknown,
                };
            }
        } else {
            snapshot
                .retrievals
                .iter_mut()
                .find(|r| r.operation == "describe-db-proxy-targets")
                .unwrap()
                .status = RetrievalStatus::Partial;
        }
    }
    if let Some(v) = get("describe-db-proxy-target-groups") {
        let g = one(v, "TargetGroups")?;
        if str_value(g, "DBProxyName")? != c.target.proxy_name
            || str_value(g, "TargetGroupName")? != "default"
        {
            return Err(GuardError::TargetMismatch);
        }
    }
    if let Some(v) = get("describe-db-parameters") {
        let params = array(v, "Parameters")?;
        if params.len() > c.limits.max_results {
            return Err(GuardError::LimitExceeded);
        }
        let matches: Vec<_> = params
            .iter()
            .filter(|p| p.get("ParameterName").and_then(Value::as_str) == Some("rds.force_ssl"))
            .collect();
        if matches.len() > 1 {
            return Err(GuardError::EvidenceIncompatible);
        }
        if let (Some(db), Some(p)) = (snapshot.db.as_mut(), matches.first()) {
            db.force_ssl = match p.get("ParameterValue").and_then(Value::as_str) {
                Some("1") => Some(true),
                Some("0") => Some(false),
                _ => None,
            };
        }
    }
    if let Some(v) = get("describe-security-groups") {
        let groups = array(v, "SecurityGroups")?;
        if groups.len() > c.limits.max_results {
            return Err(GuardError::LimitExceeded);
        }
        let expected: BTreeSet<_> = snapshot
            .db
            .iter()
            .flat_map(|d| d.security_group_ids.iter())
            .chain(
                snapshot
                    .proxy
                    .iter()
                    .flat_map(|p| p.security_group_ids.iter()),
            )
            .cloned()
            .collect();
        let mut seen = BTreeSet::new();
        for g in groups {
            let id = str_value(g, "GroupId")?;
            if !expected.contains(&id) || !seen.insert(id.clone()) {
                return Err(GuardError::TargetMismatch);
            }
            if g.get("OwnerId").and_then(Value::as_str) != Some(&c.target.account_id) {
                return Err(GuardError::TargetMismatch);
            }
            let mut ingress = Vec::new();
            for rule in array(g, "IpPermissions")? {
                let protocol = str_value(rule, "IpProtocol")?;
                if !matches!(protocol.as_str(), "tcp" | "udp" | "icmp" | "icmpv6" | "-1")
                    && protocol.parse::<u8>().is_err()
                {
                    return Err(GuardError::EvidenceIncompatible);
                }
                let port = |key: &str| -> Result<Option<u16>, GuardError> {
                    match rule.get(key) {
                        None => Ok(None),
                        Some(n) => n
                            .as_i64()
                            .and_then(|p| u16::try_from(p).ok())
                            .map(Some)
                            .ok_or(GuardError::EvidenceIncompatible),
                    }
                };
                // ICMP has type/code rather than ports. Only TCP/all are relevant to DB reachability.
                let (from_port, to_port) = if protocol == "tcp" || protocol == "6" {
                    (port("FromPort")?, port("ToPort")?)
                } else {
                    (None, None)
                };
                for (key, field, kind) in [
                    ("IpRanges", "CidrIp", 0),
                    ("Ipv6Ranges", "CidrIpv6", 1),
                    ("UserIdGroupPairs", "GroupId", 2),
                ] {
                    if let Some(values) = rule.get(key) {
                        for source in values.as_array().ok_or(GuardError::EvidenceIncompatible)? {
                            let val = str_value(source, field)?;
                            let source = match kind {
                                0 => {
                                    val.parse::<ipnet::Ipv4Net>()
                                        .map_err(|_| GuardError::EvidenceIncompatible)?;
                                    RuleSource::Ipv4 { cidr: val }
                                }
                                1 => {
                                    val.parse::<ipnet::Ipv6Net>()
                                        .map_err(|_| GuardError::EvidenceIncompatible)?;
                                    RuleSource::Ipv6 { cidr: val }
                                }
                                _ => {
                                    validate_sg_id(&val)?;
                                    RuleSource::SecurityGroup { id: val }
                                }
                            };
                            ingress.push(SecurityRule {
                                protocol: protocol.clone(),
                                from_port,
                                to_port,
                                source,
                            });
                            if ingress.len() > c.limits.max_results {
                                return Err(GuardError::LimitExceeded);
                            }
                        }
                    }
                }
                if rule
                    .get("PrefixListIds")
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty())
                {
                    snapshot
                        .retrievals
                        .iter_mut()
                        .find(|r| r.operation == "describe-security-groups")
                        .unwrap()
                        .status = RetrievalStatus::Partial;
                }
            }
            let vpc_id = str_value(g, "VpcId")?;
            if !hex_id(&vpc_id, "vpc-") {
                return Err(GuardError::EvidenceIncompatible);
            }
            snapshot.security_groups.push(SecurityGroup {
                id,
                vpc_id,
                ingress,
            });
        }
        if expected != seen {
            snapshot
                .retrievals
                .iter_mut()
                .find(|r| r.operation == "describe-security-groups")
                .unwrap()
                .status = RetrievalStatus::Partial;
        }
    }
    for id in snapshot
        .db
        .iter()
        .flat_map(|d| d.security_group_ids.iter())
        .chain(
            snapshot
                .proxy
                .iter()
                .flat_map(|p| p.security_group_ids.iter()),
        )
    {
        validate_sg_id(id)?;
    }
    if snapshot.db.as_ref().is_some_and(|d| {
        !aws_endpoint(c, &d.endpoint)
            || !parameter_group_name(d.parameter_group.as_deref().unwrap_or(""))
    }) || snapshot
        .proxy
        .as_ref()
        .is_some_and(|p| !aws_endpoint(c, &p.endpoint) || !role_arn(c, &p.role_arn))
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    validate_snapshot(c, &snapshot)?;
    Ok(snapshot)
}
