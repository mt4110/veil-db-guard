//! Explicit Cloud SQL read-only capture. Raw process output and credentials are never serialized.
use super::{config, model::*};
use crate::config::GuardError;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
pub struct LiveTools {
    pub gcloud: PathBuf,
    pub proxy: PathBuf,
    pub psql: PathBuf,
    pub work_dir: PathBuf,
}

const SQL: &str = "SELECT json_build_object('current_user',current_user,'database',current_database(),'engine_version',current_setting('server_version'),'backend_ssl',(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()))::text;\n";
const SDK_PROPERTIES: &str = "json(auth.disable_credentials,auth.disable_ssl_validation,auth.credential_file_override,auth.access_token_file,auth.authorization_token_file,auth.impersonate_service_account,auth.token_host,auth.mtls_token_host,auth.auth_host,core.universe_domain,core.custom_ca_certs_file,api_endpoint_overrides,proxy)";
const INSTANCE_FIELDS: &str = "json(name,project,region,databaseVersion,databaseInstalledVersion,connectionName,ipAddresses,serverCaCert.cert,settings.ipConfiguration,settings.connectorEnforcement,settings.databaseFlags)";

/// All inherited PG*, CSQL_PROXY_*, ADC, proxy and SDK overrides are removed.
/// The supplied gcloud is also the executable the Proxy's gcloud-auth helper can find.
pub fn sanitized_environment(
    tools: &LiveTools,
    inherited: &BTreeMap<OsString, OsString>,
) -> Result<BTreeMap<OsString, OsString>, GuardError> {
    for key in ["CLOUDSDK_CONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME"] {
        if inherited
            .get(OsStr::new(key))
            .is_some_and(|value| !value.is_empty())
        {
            return Err(GuardError::ConfigInvalid);
        }
    }
    let mut environment = BTreeMap::new();
    for key in ["HOME", "USER", "LOGNAME", "TMPDIR", "SYSTEMROOT"] {
        if let Some(value) = inherited.get(OsStr::new(key)) {
            environment.insert(key.into(), value.clone());
        }
    }
    let parent = tools.gcloud.parent().ok_or(GuardError::ConfigInvalid)?;
    let mut paths = vec![parent.to_path_buf()];
    paths.extend(
        [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
        ]
        .into_iter()
        .map(PathBuf::from),
    );
    environment.insert(
        "PATH".into(),
        std::env::join_paths(paths).map_err(|_| GuardError::ConfigInvalid)?,
    );
    for (key, value) in [
        ("LC_ALL", "C"),
        ("LANG", "C"),
        ("NO_COLOR", "1"),
        ("CLOUDSDK_CORE_DISABLE_PROMPTS", "1"),
        ("CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", "1"),
        ("CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK", "1"),
        ("CLOUDSDK_CORE_LOG_HTTP", "false"),
        ("CLOUDSDK_CORE_LOG_HTTP_REDACT_TOKEN", "true"),
        ("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "true"),
        ("CLOUDSDK_CORE_UNIVERSE_DOMAIN", "googleapis.com"),
        ("CLOUDSDK_AUTH_DISABLE_SSL_VALIDATION", "false"),
        ("CLOUDSDK_AUTH_DISABLE_CREDENTIALS", "false"),
        (
            "CLOUDSDK_AUTH_AUTH_HOST",
            "https://accounts.google.com/o/oauth2/auth",
        ),
        (
            "CLOUDSDK_AUTH_TOKEN_HOST",
            "https://oauth2.googleapis.com/token",
        ),
        (
            "CLOUDSDK_AUTH_MTLS_TOKEN_HOST",
            "https://oauth2.mtls.googleapis.com/token",
        ),
        (
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_SQL",
            "https://sqladmin.googleapis.com/",
        ),
        (
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_IAM",
            "https://iam.googleapis.com/",
        ),
        (
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_IAMCREDENTIALS",
            "https://iamcredentials.googleapis.com/",
        ),
        (
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDRESOURCEMANAGER",
            "https://cloudresourcemanager.googleapis.com/",
        ),
    ] {
        environment.insert(key.into(), value.into());
    }
    Ok(environment)
}

fn executable(path: &Path) -> Result<PathBuf, GuardError> {
    if !path.is_absolute() {
        return Err(GuardError::ConfigInvalid);
    }
    let path = std::fs::canonicalize(path).map_err(|_| GuardError::ConfigInvalid)?;
    if !std::fs::metadata(&path)
        .map_err(|_| GuardError::ConfigInvalid)?
        .is_file()
    {
        return Err(GuardError::ConfigInvalid);
    }
    Ok(path)
}
fn now() -> u64 {
    crate::domain::now()
}
fn ready(deadline: Instant, cancel: &CancellationToken) -> Result<(), GuardError> {
    if cancel.is_cancelled() {
        Err(GuardError::Cancelled)
    } else if Instant::now() >= deadline {
        Err(GuardError::TimedOut)
    } else {
        Ok(())
    }
}
fn command_deadline(c: &GcpConfig, deadline: Instant) -> Instant {
    deadline.min(Instant::now() + Duration::from_millis(c.limits.connect_timeout_ms))
}
struct RawOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
struct Process {
    child: Option<Child>,
    group: Option<i32>,
}
impl Process {
    fn new(child: Child) -> Self {
        let group = child.id().and_then(|id| i32::try_from(id).ok());
        Self {
            child: Some(child),
            group,
        }
    }
    fn signal(&self) {
        #[cfg(unix)]
        if let Some(group) = self.group {
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        }
    }
    async fn stop(&mut self) {
        self.signal();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        self.child = None;
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.signal();
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = child.wait().await;
                });
            }
        }
    }
}
fn child_command(
    path: &Path,
    args: &[String],
    environment: &BTreeMap<OsString, OsString>,
) -> Command {
    let mut command = Command::new(path);
    command
        .args(args)
        .env_clear()
        .envs(environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    command
}
async fn read_pipe<R: AsyncRead + Unpin>(pipe: R, max: usize) -> Result<Vec<u8>, GuardError> {
    let mut bytes = Vec::new();
    pipe.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| GuardError::OperationFailed)?;
    if bytes.len() > max {
        return Err(GuardError::LimitExceeded);
    }
    Ok(bytes)
}
async fn execute(
    path: &Path,
    args: &[String],
    environment: &BTreeMap<OsString, OsString>,
    input: Option<&[u8]>,
    max: usize,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<RawOutput, GuardError> {
    ready(deadline, cancel)?;
    let mut command = child_command(path, args, environment);
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut process = Process::new(command.spawn().map_err(|_| GuardError::OperationFailed)?);
    let child = process.child.as_mut().ok_or(GuardError::OperationFailed)?;
    let stdout = child.stdout.take().ok_or(GuardError::OperationFailed)?;
    let stderr = child.stderr.take().ok_or(GuardError::OperationFailed)?;
    let stdin = child.stdin.take();
    let work = async {
        let (status, stdout, stderr, ()) = tokio::try_join!(
            async { child.wait().await.map_err(|_| GuardError::OperationFailed) },
            read_pipe(stdout, max),
            read_pipe(stderr, max),
            async {
                if let (Some(mut stdin), Some(input)) = (stdin, input) {
                    stdin
                        .write_all(input)
                        .await
                        .map_err(|_| GuardError::OperationFailed)?;
                }
                Ok(())
            }
        )?;
        Ok(RawOutput {
            success: status.success(),
            stdout,
            stderr,
        })
    };
    let result = tokio::select! {biased;_=cancel.cancelled()=>Err(GuardError::Cancelled),result=timeout_at(deadline,work)=>result.unwrap_or(Err(GuardError::TimedOut))};
    process.stop().await;
    result
}
fn gcloud_args(c: &GcpConfig, operation: &[&str], format: &str) -> Vec<String> {
    let mut args = operation
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<_>>();
    args.extend([
        format!("--project={}", c.target.project_id),
        "--quiet".into(),
        "--verbosity=error".into(),
        format!("--format={format}"),
    ]);
    args
}
fn nonempty(value: &Value, pointer: &str) -> bool {
    value.pointer(pointer).is_some_and(|value| match value {
        Value::Null => false,
        Value::String(value) => !value.is_empty(),
        Value::Bool(value) => *value,
        _ => true,
    })
}
pub fn validate_sdk_properties(value: &Value) -> Result<(), GuardError> {
    for pointer in [
        "/auth/credential_file_override",
        "/auth/access_token_file",
        "/auth/authorization_token_file",
        "/auth/impersonate_service_account",
        "/core/custom_ca_certs_file",
    ] {
        if nonempty(value, pointer) {
            return Err(GuardError::ConfigInvalid);
        }
    }
    for pointer in ["/auth/disable_credentials", "/auth/disable_ssl_validation"] {
        if value.pointer(pointer).is_some_and(|v| {
            v == &Value::Bool(true) || v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true"))
        }) {
            return Err(GuardError::ConfigInvalid);
        }
    }
    if value
        .get("proxy")
        .and_then(Value::as_object)
        .is_some_and(|values| {
            values
                .values()
                .any(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.is_empty()))
        })
    {
        return Err(GuardError::ConfigInvalid);
    }
    for (pointer, expected) in [
        ("/auth/token_host", "https://oauth2.googleapis.com/token"),
        (
            "/auth/mtls_token_host",
            "https://oauth2.mtls.googleapis.com/token",
        ),
        (
            "/auth/auth_host",
            "https://accounts.google.com/o/oauth2/auth",
        ),
        ("/core/universe_domain", "googleapis.com"),
    ] {
        if value
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|actual| !actual.is_empty() && actual != expected)
        {
            return Err(GuardError::ConfigInvalid);
        }
    }
    if let Some(overrides) = value
        .get("api_endpoint_overrides")
        .and_then(Value::as_object)
    {
        for (key, value) in overrides {
            if let Some(value) = value.as_str() {
                if value.is_empty() {
                    continue;
                }
                let allowed = match key.as_str() {
                    "sql" => Some("https://sqladmin.googleapis.com/"),
                    "iam" => Some("https://iam.googleapis.com/"),
                    "iamcredentials" => Some("https://iamcredentials.googleapis.com/"),
                    "cloudresourcemanager" => Some("https://cloudresourcemanager.googleapis.com/"),
                    _ => None,
                };
                if allowed != Some(value) {
                    return Err(GuardError::ConfigInvalid);
                }
            } else if !value.is_null() {
                return Err(GuardError::ConfigInvalid);
            }
        }
    }
    Ok(())
}
async fn preflight(
    c: &GcpConfig,
    tools: &LiveTools,
    environment: &BTreeMap<OsString, OsString>,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), GuardError> {
    let args = gcloud_args(c, &["config", "list", "--all"], SDK_PROPERTIES);
    let result = execute(
        &tools.gcloud,
        &args,
        environment,
        None,
        c.limits.max_bytes.min(262_144),
        command_deadline(c, deadline),
        cancel,
    )
    .await?;
    if !result.success {
        return Err(GuardError::OperationFailed);
    }
    let properties: Value =
        serde_json::from_slice(&result.stdout).map_err(|_| GuardError::EvidenceIncompatible)?;
    if !properties.is_object() {
        return Err(GuardError::EvidenceIncompatible);
    }
    validate_sdk_properties(&properties)
}

struct Inventory {
    snapshot: GcpSnapshot,
    ca_pem: Option<Vec<u8>>,
}
fn blank_snapshot(c: &GcpConfig) -> GcpSnapshot {
    GcpSnapshot {
        target: c.target.clone(),
        observed_at: now(),
        complete: false,
        engine_version: String::new(),
        connection_name: String::new(),
        public_ip: None,
        ca_mode: String::new(),
        ca_fingerprint: String::new(),
        iam_auth_enabled: false,
        connector_enforcement: GcpConnectorEnforcement::Unknown,
        ssl_mode: GcpSslMode::Unknown,
        authorized_networks: vec![],
        principal_roles: vec![],
        registered_principal_ids: vec![],
    }
}
fn incomplete_after(before: &GcpSnapshot) -> GcpSnapshot {
    // Preserve the last known target metadata, but never present its old settings as a fresh read.
    let mut snapshot = before.clone();
    snapshot.complete = false;
    snapshot.observed_at = now();
    snapshot
}

pub fn normalize_inventory(
    c: &GcpConfig,
    instance: &Value,
    policy: &Value,
    users: &Value,
) -> Result<GcpSnapshot, GuardError> {
    Ok(normalize(c, instance, policy, users)?.snapshot)
}
fn normalize(
    c: &GcpConfig,
    instance: &Value,
    policy: &Value,
    users: &Value,
) -> Result<Inventory, GuardError> {
    let mut snapshot = blank_snapshot(c);
    for (pointer, expected) in [
        ("/name", c.target.instance_id.as_str()),
        ("/project", c.target.project_id.as_str()),
        ("/region", c.target.region.as_str()),
    ] {
        if instance.pointer(pointer).and_then(Value::as_str) != Some(expected) {
            return Err(GuardError::TargetMismatch);
        }
    }
    let connection = format!(
        "{}:{}:{}",
        c.target.project_id, c.target.region, c.target.instance_id
    );
    if instance.get("connectionName").and_then(Value::as_str) != Some(&connection) {
        return Err(GuardError::TargetMismatch);
    }
    snapshot.connection_name = connection;
    snapshot.engine_version = instance
        .get("databaseInstalledVersion")
        .or_else(|| instance.get("databaseVersion"))
        .and_then(Value::as_str)
        .ok_or(GuardError::EvidenceIncompatible)?
        .into();
    if snapshot.engine_version != c.target.engine_version {
        return Err(GuardError::UnsupportedTarget);
    }
    let settings = instance
        .get("settings")
        .and_then(Value::as_object)
        .ok_or(GuardError::EvidenceIncompatible)?;
    let ip = settings
        .get("ipConfiguration")
        .and_then(Value::as_object)
        .ok_or(GuardError::EvidenceIncompatible)?;
    snapshot.ca_mode = ip
        .get("serverCaMode")
        .or_else(|| settings.get("serverCaMode"))
        .and_then(Value::as_str)
        .unwrap_or("GOOGLE_MANAGED_INTERNAL_CA")
        .into();
    if ![
        "GOOGLE_MANAGED_INTERNAL_CA",
        "GOOGLE_MANAGED_CAS_CA",
        "CUSTOMER_MANAGED_CAS_CA",
    ]
    .contains(&snapshot.ca_mode.as_str())
    {
        return Err(GuardError::UnsupportedTarget);
    }
    snapshot.connector_enforcement =
        match settings.get("connectorEnforcement").and_then(Value::as_str) {
            Some("REQUIRED") => GcpConnectorEnforcement::Required,
            Some("NOT_REQUIRED") => GcpConnectorEnforcement::NotRequired,
            _ => GcpConnectorEnforcement::Unknown,
        };
    snapshot.ssl_mode = match ip.get("sslMode").and_then(Value::as_str) {
        Some("ENCRYPTED_ONLY") => GcpSslMode::EncryptedOnly,
        Some("TRUSTED_CLIENT_CERTIFICATE_REQUIRED") => GcpSslMode::TrustedClientCertificateRequired,
        Some("ALLOW_UNENCRYPTED_AND_ENCRYPTED") => GcpSslMode::AllowUnencrypted,
        _ => GcpSslMode::Unknown,
    };
    let no_networks = Vec::new();
    let networks = match ip.get("authorizedNetworks") {
        None => &no_networks,
        Some(value) => value.as_array().ok_or(GuardError::EvidenceIncompatible)?,
    };
    if networks.len() > 128 {
        return Err(GuardError::LimitExceeded);
    }
    for network in networks {
        let cidr = network
            .get("value")
            .and_then(Value::as_str)
            .ok_or(GuardError::EvidenceIncompatible)?;
        let parsed: ipnet::IpNet = cidr.parse().map_err(|_| GuardError::EvidenceIncompatible)?;
        snapshot.authorized_networks.push(parsed.to_string());
    }
    snapshot.authorized_networks.sort();
    snapshot.authorized_networks.dedup();
    snapshot.iam_auth_enabled = settings
        .get("databaseFlags")
        .and_then(Value::as_array)
        .is_some_and(|flags| {
            flags.iter().any(|flag| {
                flag.get("name").and_then(Value::as_str) == Some("cloudsql.iam_authentication")
                    && flag.get("value").and_then(Value::as_str) == Some("on")
            })
        });
    let mut public_ips = Vec::new();
    for ip in instance
        .get("ipAddresses")
        .and_then(Value::as_array)
        .ok_or(GuardError::EvidenceIncompatible)?
    {
        if ip.get("type").and_then(Value::as_str) == Some("PRIMARY") {
            public_ips.push(
                ip.get("ipAddress")
                    .and_then(Value::as_str)
                    .ok_or(GuardError::EvidenceIncompatible)?
                    .parse::<Ipv4Addr>()
                    .map_err(|_| GuardError::EvidenceIncompatible)?,
            );
        }
    }
    if public_ips.len() > 1 {
        return Err(GuardError::TargetMismatch);
    }
    snapshot.public_ip = public_ips.first().copied();
    let pem = instance
        .pointer("/serverCaCert/cert")
        .and_then(Value::as_str)
        .ok_or(GuardError::EvidenceIncompatible)?;
    if pem.len() > 65_536 {
        return Err(GuardError::LimitExceeded);
    }
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    if certificates.len() != 1 {
        return Err(GuardError::EvidenceIncompatible);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificates[0].clone())
        .map_err(|_| GuardError::EvidenceIncompatible)?;
    snapshot.ca_fingerprint = crate::config::hash_bytes(certificates[0].as_ref());
    let bindings = policy
        .get("bindings")
        .and_then(Value::as_array)
        .ok_or(GuardError::EvidenceIncompatible)?;
    if bindings.len() > 4096 {
        return Err(GuardError::LimitExceeded);
    }
    for principal in &c.principals {
        let member = format!("serviceAccount:{}", principal.service_account);
        let mut roles = BTreeSet::new();
        for binding in bindings {
            let members = binding
                .get("members")
                .and_then(Value::as_array)
                .ok_or(GuardError::EvidenceIncompatible)?;
            if !members.iter().any(|value| value.as_str() == Some(&member)) {
                continue;
            }
            let role = if binding.get("condition").is_some() {
                GcpRole::Other
            } else {
                match binding.get("role").and_then(Value::as_str) {
                    Some("roles/cloudsql.client") => GcpRole::CloudSqlClient,
                    Some("roles/cloudsql.instanceUser") => GcpRole::CloudSqlInstanceUser,
                    Some("roles/serviceusage.serviceUsageConsumer") => {
                        GcpRole::ServiceUsageConsumer
                    }
                    _ => GcpRole::Other,
                }
            };
            roles.insert(role);
        }
        snapshot.principal_roles.push(GcpPrincipalRoles {
            principal_id: principal.id.clone(),
            roles: roles.into_iter().collect(),
        });
    }
    snapshot
        .principal_roles
        .sort_by(|a, b| a.principal_id.cmp(&b.principal_id));
    snapshot.complete = true;
    snapshot.observed_at = now();
    let users = users.as_array().ok_or(GuardError::EvidenceIncompatible)?;
    if users.len() > 4096 {
        return Err(GuardError::LimitExceeded);
    }
    for principal in &c.principals {
        if users.iter().any(|user| {
            user.get("type").and_then(Value::as_str) == Some("CLOUD_IAM_SERVICE_ACCOUNT")
                && user.get("name").and_then(Value::as_str) == Some(principal.db_user().as_str())
        }) {
            snapshot.registered_principal_ids.push(principal.id.clone());
        }
    }
    snapshot.registered_principal_ids.sort();
    Ok(Inventory {
        snapshot,
        ca_pem: Some(pem.as_bytes().to_vec()),
    })
}
async fn inventory(
    c: &GcpConfig,
    tools: &LiveTools,
    environment: &BTreeMap<OsString, OsString>,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Inventory, GuardError> {
    let args = gcloud_args(
        c,
        &["sql", "instances", "describe", &c.target.instance_id],
        INSTANCE_FIELDS,
    );
    let instance = execute(
        &tools.gcloud,
        &args,
        environment,
        None,
        c.limits.max_bytes,
        command_deadline(c, deadline),
        cancel,
    )
    .await?;
    if !instance.success {
        return Err(GuardError::OperationFailed);
    }
    let instance: Value =
        serde_json::from_slice(&instance.stdout).map_err(|_| GuardError::EvidenceIncompatible)?;
    let args = gcloud_args(
        c,
        &["projects", "get-iam-policy", &c.target.project_id],
        "json(bindings)",
    );
    let policy = execute(
        &tools.gcloud,
        &args,
        environment,
        None,
        c.limits.max_bytes,
        command_deadline(c, deadline),
        cancel,
    )
    .await?;
    if !policy.success {
        return Err(GuardError::OperationFailed);
    }
    let policy: Value =
        serde_json::from_slice(&policy.stdout).map_err(|_| GuardError::EvidenceIncompatible)?;
    let mut args = gcloud_args(c, &["sql", "users", "list"], "json(name,type)");
    args.push(format!("--instance={}", c.target.instance_id));
    let users = execute(
        &tools.gcloud,
        &args,
        environment,
        None,
        c.limits.max_bytes,
        command_deadline(c, deadline),
        cancel,
    )
    .await?;
    if !users.success {
        return Err(GuardError::OperationFailed);
    }
    let users: Value =
        serde_json::from_slice(&users.stdout).map_err(|_| GuardError::EvidenceIncompatible)?;
    normalize(c, &instance, &policy, &users)
}

pub async fn inspect(
    c: &GcpConfig,
    tools: &LiveTools,
    cancel: CancellationToken,
    deadline: Instant,
) -> Result<GcpSnapshot, GuardError> {
    config::validate_config(c)?;
    let mut tools = tools.clone();
    tools.gcloud = executable(&tools.gcloud)?;
    let environment = sanitized_environment(&tools, &std::env::vars_os().collect())?;
    preflight(c, &tools, &environment, deadline, &cancel).await?;
    Ok(inventory(c, &tools, &environment, deadline, &cancel)
        .await?
        .snapshot)
}

struct Secret(Vec<u8>);
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
async fn login_token(
    c: &GcpConfig,
    principal: &GcpPrincipal,
    tools: &LiveTools,
    environment: &BTreeMap<OsString, OsString>,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Secret, (GuardError, Option<GcpPermission>)> {
    let mut args = gcloud_args(c, &["sql", "generate-login-token"], "value(token)");
    // generate-login-token already emits a scalar token. Do not request a generic JSON formatter.
    args.retain(|arg| !arg.starts_with("--format="));
    args.push(format!("--instance={}", c.target.instance_id));
    args.push(format!(
        "--impersonate-service-account={}",
        principal.service_account
    ));
    let output = execute(
        &tools.gcloud,
        &args,
        environment,
        None,
        65_536,
        command_deadline(c, deadline),
        cancel,
    )
    .await
    .map_err(|error| (error, None))?;
    if !output.success {
        let text = String::from_utf8_lossy(&output.stderr);
        let permission =
            if text.contains("403") && text.contains("iam.serviceAccounts.getAccessToken") {
                Some(GcpPermission::TokenCreation)
            } else if text.contains("403") && text.contains("serviceusage.services.use") {
                Some(GcpPermission::ServiceUsage)
            } else {
                None
            };
        return Err((GuardError::OperationFailed, permission));
    }
    let token = output.stdout.strip_suffix(b"\n").unwrap_or(&output.stdout);
    let token = token.strip_suffix(b"\r").unwrap_or(token);
    if token.is_empty() || !token.iter().all(|byte| byte.is_ascii_graphic()) {
        return Err((GuardError::EvidenceIncompatible, None));
    }
    Ok(Secret(token.to_vec()))
}

#[derive(Clone, Copy, Default, Debug)]
struct ProxyDiagnostics {
    ready: bool,
    connect_denied: bool,
    limit_exceeded: bool,
}
fn inspect_proxy_line(line: &[u8], port: u16, summary: &mut ProxyDiagnostics) {
    let parsed = serde_json::from_slice::<Value>(line).ok();
    let message = parsed
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .map(str::as_bytes)
        .unwrap_or(line);
    let text = String::from_utf8_lossy(message);
    if text
        .split_once("Listening on ")
        .is_some_and(|(_, address)| address.trim() == format!("127.0.0.1:{port}"))
    {
        summary.ready = true;
    }
    if text.contains("403") && text.contains("cloudsql.instances.connect") {
        summary.connect_denied = true;
    }
}
async fn proxy_pipe<R: AsyncRead + Unpin>(
    mut pipe: R,
    max: usize,
    port: u16,
    summary: Arc<Mutex<ProxyDiagnostics>>,
) -> Result<(), GuardError> {
    let mut count = 0usize;
    let mut line = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let read = pipe
            .read(&mut buffer)
            .await
            .map_err(|_| GuardError::OperationFailed)?;
        if read == 0 {
            break;
        }
        count = count.saturating_add(read);
        if count > max {
            summary
                .lock()
                .map_err(|_| GuardError::OperationFailed)?
                .limit_exceeded = true;
            return Err(GuardError::LimitExceeded);
        }
        for byte in &buffer[..read] {
            if *byte == b'\n' {
                inspect_proxy_line(
                    &line,
                    port,
                    &mut *summary.lock().map_err(|_| GuardError::OperationFailed)?,
                );
                line.clear();
            } else {
                if line.len() >= 16_384 {
                    summary
                        .lock()
                        .map_err(|_| GuardError::OperationFailed)?
                        .limit_exceeded = true;
                    return Err(GuardError::LimitExceeded);
                }
                line.push(*byte);
            }
        }
    }
    if !line.is_empty() {
        inspect_proxy_line(
            &line,
            port,
            &mut *summary.lock().map_err(|_| GuardError::OperationFailed)?,
        );
    }
    Ok(())
}
struct Proxy {
    process: Process,
    summary: Arc<Mutex<ProxyDiagnostics>>,
    readers: Vec<JoinHandle<Result<(), GuardError>>>,
    port: u16,
}
impl Proxy {
    async fn stop(&mut self) -> ProxyDiagnostics {
        self.process.stop().await;
        for mut task in self.readers.drain(..) {
            if tokio::time::timeout(Duration::from_secs(1), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        self.summary
            .lock()
            .map(|summary| *summary)
            .unwrap_or_default()
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        for reader in &self.readers {
            reader.abort();
        }
    }
}
async fn start_proxy(
    c: &GcpConfig,
    snapshot: &GcpSnapshot,
    principal: &GcpPrincipal,
    tools: &LiveTools,
    environment: &BTreeMap<OsString, OsString>,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<Proxy, GuardError> {
    ready(deadline, cancel)?;
    let selector = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| GuardError::OperationFailed)?;
    let port = selector
        .local_addr()
        .map_err(|_| GuardError::OperationFailed)?
        .port();
    drop(selector);
    let args = vec![
        "--gcloud-auth".into(),
        "--address=127.0.0.1".into(),
        format!("--port={port}"),
        "--structured-logs".into(),
        format!("--quota-project={}", c.target.project_id),
        format!(
            "--impersonate-service-account={}",
            principal.service_account
        ),
        snapshot.connection_name.clone(),
    ];
    let child = child_command(&tools.proxy, &args, environment)
        .spawn()
        .map_err(|_| GuardError::OperationFailed)?;
    let mut process = Process::new(child);
    let child = process.child.as_mut().ok_or(GuardError::OperationFailed)?;
    let stdout = child.stdout.take().ok_or(GuardError::OperationFailed)?;
    let stderr = child.stderr.take().ok_or(GuardError::OperationFailed)?;
    let summary = Arc::new(Mutex::new(ProxyDiagnostics::default()));
    let max = c.limits.max_bytes.min(1_048_576);
    let readers = vec![
        tokio::spawn(proxy_pipe(stdout, max, port, summary.clone())),
        tokio::spawn(proxy_pipe(stderr, max, port, summary.clone())),
    ];
    let mut proxy = Proxy {
        process,
        summary,
        readers,
        port,
    };
    loop {
        if let Err(error) = ready(deadline, cancel) {
            proxy.stop().await;
            return Err(error);
        }
        let state = *proxy
            .summary
            .lock()
            .map_err(|_| GuardError::OperationFailed)?;
        if state.limit_exceeded {
            proxy.stop().await;
            return Err(GuardError::LimitExceeded);
        }
        if state.ready
            || proxy
                .process
                .child
                .as_mut()
                .ok_or(GuardError::OperationFailed)?
                .try_wait()
                .map_err(|_| GuardError::OperationFailed)?
                .is_some()
        {
            return Ok(proxy);
        }
        tokio::select! {biased;_=cancel.cancelled()=>{proxy.stop().await;return Err(GuardError::Cancelled);},_=tokio::time::sleep_until(deadline.min(Instant::now()+Duration::from_millis(20)))=>{}}
    }
}

fn execution(error: &GuardError) -> GcpExecution {
    match error {
        GuardError::Cancelled => GcpExecution::Cancelled,
        GuardError::TimedOut => GcpExecution::Timeout,
        _ => GcpExecution::Error,
    }
}
fn identity_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:@".contains(&byte))
        })
        .map(str::to_owned)
}
pub fn classify_failure(proxy_log: &[u8], postgres_error: &[u8]) -> GcpProof {
    let mut summary = ProxyDiagnostics::default();
    for line in proxy_log.split(|byte| *byte == b'\n') {
        inspect_proxy_line(line, 0, &mut summary);
    }
    let text = String::from_utf8_lossy(postgres_error).to_ascii_lowercase();
    let iam = text.contains("iam user authentication failed")
        || text.contains("iam service account authentication failed");
    let permission = if summary.connect_denied {
        Some(GcpPermission::InstanceConnect)
    } else if iam && text.contains("cloudsql.instances.login") {
        Some(GcpPermission::InstanceLogin)
    } else {
        None
    };
    GcpProof {
        denied_permission: permission,
        iam_login_rejected: iam,
        transport_positive: false,
        ..Default::default()
    }
}
fn parse_sql(
    c: &GcpConfig,
    principal: &GcpPrincipal,
    route: GcpRoute,
    output: &RawOutput,
    proof: &mut GcpProof,
) {
    if !output.success {
        return;
    }
    proof.sql_authenticated = true;
    if let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) {
        // A successful but unexpected identity is still Allowed. Keep only equality
        // with the declared identity, never an unrequested server-supplied string.
        proof.db_user =
            identity_field(&value, "current_user").filter(|user| user == &principal.db_user());
        proof.database =
            identity_field(&value, "database").filter(|database| database == &c.target.database);
        proof.backend_ssl = value.get("backend_ssl").and_then(Value::as_bool);
        let engine = value
            .get("engine_version")
            .and_then(Value::as_str)
            .and_then(|version| version.split_whitespace().next())
            .map(|version| format!("POSTGRES_{}", version.replace('.', "_")));
        proof.sql_ok = proof.db_user.as_deref() == Some(&principal.db_user())
            && proof.database.as_deref() == Some(&c.target.database)
            && engine.as_deref() == Some(&c.target.engine_version)
            && (route == GcpRoute::Proxy || proof.backend_ssl == Some(true));
    }
    proof.transport_positive = true;
    if route == GcpRoute::Direct {
        proof.tls_established = Some(true);
        proof.ca_verified = true;
    }
}

fn preserve_ca(tools: &LiveTools, inventory: &Inventory) -> Result<PathBuf, GuardError> {
    if inventory.snapshot.ca_mode != "GOOGLE_MANAGED_INTERNAL_CA" {
        return Err(GuardError::UnsupportedTarget);
    }
    let metadata =
        std::fs::symlink_metadata(&tools.work_dir).map_err(|_| GuardError::StorageFailed)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(GuardError::StorageFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(GuardError::StorageFailed);
        }
    }
    let bytes = inventory
        .ca_pem
        .as_deref()
        .ok_or(GuardError::EvidenceIncompatible)?;
    let path = tools.work_dir.join(format!(
        "instance-ca-{}.pem",
        inventory.snapshot.ca_fingerprint
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path).map_err(|_| GuardError::StorageFailed)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| GuardError::StorageFailed)?;
    Ok(path)
}

struct SqlConnection<'a> {
    host: String,
    port: u16,
    ca_file: Option<&'a Path>,
}
#[derive(Clone, Copy)]
struct Runtime<'a> {
    tools: &'a LiveTools,
    environment: &'a BTreeMap<OsString, OsString>,
    deadline: Instant,
    cancel: &'a CancellationToken,
}
async fn psql(
    c: &GcpConfig,
    principal: &GcpPrincipal,
    token: &Secret,
    connection: SqlConnection<'_>,
    runtime: Runtime<'_>,
) -> Result<RawOutput, GuardError> {
    let Runtime {
        tools,
        environment,
        deadline,
        cancel,
    } = runtime;
    let mut environment = environment.clone();
    for (key, value) in [
        ("PGHOST", connection.host),
        ("PGPORT", connection.port.to_string()),
        ("PGDATABASE", c.target.database.clone()),
        ("PGUSER", principal.db_user()),
        (
            "PGPASSWORD",
            String::from_utf8(token.0.clone()).map_err(|_| GuardError::EvidenceIncompatible)?,
        ),
        (
            "PGCONNECT_TIMEOUT",
            c.limits
                .connect_timeout_ms
                .div_ceil(1000)
                .max(1)
                .to_string(),
        ),
        (
            "PGSSLMODE",
            if connection.ca_file.is_some() {
                "verify-ca"
            } else {
                "disable"
            }
            .into(),
        ),
        ("PGSSLCERTMODE", "disable".into()),
        ("PGGSSENCMODE", "disable".into()),
        ("PGAPPNAME", "veil-db-guard-gcp".into()),
        ("PGPASSFILE", "/dev/null".into()),
        ("PGSERVICEFILE", "/dev/null".into()),
        (
            "PGOPTIONS",
            format!(
                "-c default_transaction_read_only=on -c statement_timeout={} -c lock_timeout={} -c idle_in_transaction_session_timeout={}",
                c.limits.query_timeout_ms, c.limits.query_timeout_ms, c.limits.query_timeout_ms
            ),
        ),
    ] {
        environment.insert(key.into(), value.into());
    }
    if let Some(ca) = connection.ca_file {
        environment.insert("PGSSLROOTCERT".into(), ca.as_os_str().to_owned());
    }
    let args = [
        "--no-psqlrc",
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        "--set=VERBOSITY=verbose",
        "--tuples-only",
        "--no-align",
        "--file=-",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    execute(
        &tools.psql,
        &args,
        &environment,
        Some(SQL.as_bytes()),
        16_384,
        deadline.min(
            Instant::now()
                + Duration::from_millis(
                    c.limits
                        .connect_timeout_ms
                        .saturating_add(c.limits.query_timeout_ms),
                ),
        ),
        cancel,
    )
    .await
}

async fn proxy_attempt(
    c: &GcpConfig,
    inventory: &Inventory,
    principal: &GcpPrincipal,
    token: &Secret,
    runtime: Runtime<'_>,
    observation: &mut GcpObservation,
) {
    let Runtime {
        tools,
        environment,
        deadline,
        cancel,
    } = runtime;
    let mut proxy = match start_proxy(
        c,
        &inventory.snapshot,
        principal,
        tools,
        environment,
        command_deadline(c, deadline),
        cancel,
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(error) => {
            observation.execution = execution(&error);
            return;
        }
    };
    let was_ready = proxy
        .summary
        .lock()
        .map(|summary| summary.ready)
        .unwrap_or(false);
    if !was_ready {
        let summary = proxy.stop().await;
        if summary.connect_denied {
            observation.proof.denied_permission = Some(GcpPermission::InstanceConnect);
            observation.observed = GcpAccess::Denied;
            observation.execution = GcpExecution::Completed;
        } else {
            observation.execution = GcpExecution::Error;
        }
        return;
    }
    observation.proof.tcp_reachable = Some(true);
    observation.proof.tls_established = Some(false);
    let sql = psql(
        c,
        principal,
        token,
        SqlConnection {
            host: Ipv4Addr::LOCALHOST.to_string(),
            port: proxy.port,
            ca_file: None,
        },
        runtime,
    )
    .await;
    let summary = proxy.stop().await;
    if summary.limit_exceeded {
        observation.execution = GcpExecution::Error;
        return;
    }
    match sql {
        Ok(output) => {
            parse_sql(
                c,
                principal,
                GcpRoute::Proxy,
                &output,
                &mut observation.proof,
            );
            if output.success {
                observation.observed = GcpAccess::Allowed;
                observation.execution = GcpExecution::Completed;
                return;
            }
            let rejected = classify_failure(&[], &output.stderr);
            observation.proof.iam_login_rejected = rejected.iam_login_rejected;
            observation.proof.transport_positive = rejected.transport_positive;
            observation.proof.denied_permission = if summary.connect_denied {
                Some(GcpPermission::InstanceConnect)
            } else {
                rejected.denied_permission
            };
            if observation.proof.denied_permission == Some(GcpPermission::InstanceConnect)
                || observation.proof.iam_login_rejected
            {
                observation.observed = GcpAccess::Denied;
                observation.execution = GcpExecution::Completed;
            } else {
                observation.execution = GcpExecution::Error;
            }
        }
        Err(error) => {
            observation.execution = execution(&error);
            // A timeout alone is unknown. An explicit connect permission response is an independent cause.
            if summary.connect_denied && error != GuardError::Cancelled {
                observation.proof.denied_permission = Some(GcpPermission::InstanceConnect);
                observation.observed = GcpAccess::Denied;
                observation.execution = GcpExecution::Completed;
            }
        }
    }
}

struct DirectContext<'a> {
    ca_file: Option<&'a Path>,
    tools: &'a LiveTools,
    environment: &'a BTreeMap<OsString, OsString>,
    deadline: Instant,
    cancel: &'a CancellationToken,
}
async fn direct_attempt(
    c: &GcpConfig,
    inventory: &Inventory,
    principal: &GcpPrincipal,
    token: &Secret,
    context: DirectContext<'_>,
    observation: &mut GcpObservation,
) {
    let DirectContext {
        ca_file,
        tools,
        environment,
        deadline,
        cancel,
    } = context;
    let (Some(ip), Some(ca_file)) = (inventory.snapshot.public_ip, ca_file) else {
        observation.execution = GcpExecution::NotRun;
        return;
    };
    if inventory.snapshot.ca_mode != "GOOGLE_MANAGED_INTERNAL_CA" {
        observation.execution = GcpExecution::NotRun;
        return;
    }
    let tcp = tokio::select! {biased;_=cancel.cancelled()=>Err(GuardError::Cancelled),result=timeout_at(command_deadline(c,deadline),tokio::net::TcpStream::connect(SocketAddrV4::new(ip,5432)))=>match result{Ok(Ok(stream))=>{drop(stream);Ok(true)},Ok(Err(_))=>Ok(false),Err(_)=>Err(GuardError::TimedOut)}};
    match tcp {
        Ok(true) => observation.proof.tcp_reachable = Some(true),
        Ok(false) => {
            observation.proof.tcp_reachable = Some(false);
            observation.execution = GcpExecution::Error;
            return;
        }
        Err(error) => {
            observation.execution = execution(&error);
            return;
        }
    }
    let output = psql(
        c,
        principal,
        token,
        SqlConnection {
            host: ip.to_string(),
            port: 5432,
            ca_file: Some(ca_file),
        },
        Runtime {
            tools,
            environment,
            deadline,
            cancel,
        },
    )
    .await;
    match output {
        Ok(output) => {
            parse_sql(
                c,
                principal,
                GcpRoute::Direct,
                &output,
                &mut observation.proof,
            );
            if output.success {
                observation.observed = GcpAccess::Allowed;
                observation.execution = GcpExecution::Completed;
            } else {
                let rejected = classify_failure(&[], &output.stderr);
                observation.proof.iam_login_rejected = rejected.iam_login_rejected;
                observation.proof.transport_positive = rejected.transport_positive;
                observation.proof.denied_permission = rejected.denied_permission;
                if rejected.iam_login_rejected {
                    observation.observed = GcpAccess::Denied;
                    observation.execution = GcpExecution::Completed;
                } else {
                    observation.execution = GcpExecution::Error;
                }
            }
        }
        Err(error) => observation.execution = execution(&error),
    }
}

/// Only fixed read operations and short-lived DB authentication are invoked. No resources are changed.
pub async fn probe(
    c: &GcpConfig,
    tools: &LiveTools,
    run_id: &str,
    cancel: CancellationToken,
    deadline: Instant,
) -> Result<GcpRunEvidence, GuardError> {
    config::validate_config(c)?;
    if !crate::config::safe_id(run_id) || c.cases.len() > c.limits.max_results {
        return Err(GuardError::ConfigInvalid);
    }
    let started_at = now();
    let deadline = deadline.min(Instant::now() + Duration::from_millis(c.limits.total_timeout_ms));
    let mut tools = tools.clone();
    tools.gcloud = executable(&tools.gcloud)?;
    tools.proxy = executable(&tools.proxy)?;
    tools.psql = executable(&tools.psql)?;
    let environment = sanitized_environment(&tools, &std::env::vars_os().collect())?;
    preflight(c, &tools, &environment, deadline, &cancel).await?;
    for (binary, expected) in [
        (&tools.proxy, "cloud-sql-proxy version 2.26.3"),
        (&tools.psql, "psql (PostgreSQL) 17."),
    ] {
        let version = execute(
            binary,
            &["--version".into()],
            &environment,
            None,
            4096,
            command_deadline(c, deadline),
            &cancel,
        )
        .await?;
        let text = String::from_utf8_lossy(&version.stdout);
        let suffix = text.trim().strip_prefix(expected);
        let matches = suffix.is_some_and(|suffix| {
            binary != &tools.proxy || suffix.is_empty() || suffix.starts_with('+')
        });
        if !version.success || !matches {
            return Err(GuardError::UnsupportedTarget);
        }
    }
    let before = inventory(c, &tools, &environment, deadline, &cancel).await?;
    let ca_file = if c.cases.iter().any(|case| case.route == GcpRoute::Direct)
        && before.snapshot.ca_mode == "GOOGLE_MANAGED_INTERNAL_CA"
    {
        Some(preserve_ca(&tools, &before)?)
    } else {
        None
    };
    let mut observations = Vec::with_capacity(c.cases.len());
    for case in &c.cases {
        let principal = c
            .principals
            .iter()
            .find(|principal| principal.id == case.principal_id)
            .ok_or(GuardError::ConfigInvalid)?;
        let mut observation = GcpObservation {
            case_id: case.id.clone(),
            attempt_id: crate::config::hash_bytes(format!("{run_id}\0{}", case.id).as_bytes()),
            principal_id: principal.id.clone(),
            route: case.route,
            started_at: now(),
            finished_at: now(),
            execution: GcpExecution::NotRun,
            observed: GcpAccess::Unknown,
            proof: GcpProof::default(),
        };
        if let Err(error) = ready(deadline, &cancel) {
            observation.execution = execution(&error);
            observations.push(observation);
            continue;
        }
        if case.route == GcpRoute::Direct
            && (ca_file.is_none() || before.snapshot.public_ip.is_none())
        {
            observation.finished_at = now();
            observations.push(observation);
            continue;
        }
        match login_token(c, principal, &tools, &environment, deadline, &cancel).await {
            Ok(token) => {
                observation.proof.credential_issued = true;
                match case.route {
                    GcpRoute::Proxy => {
                        proxy_attempt(
                            c,
                            &before,
                            principal,
                            &token,
                            Runtime {
                                tools: &tools,
                                environment: &environment,
                                deadline,
                                cancel: &cancel,
                            },
                            &mut observation,
                        )
                        .await
                    }
                    GcpRoute::Direct => {
                        direct_attempt(
                            c,
                            &before,
                            principal,
                            &token,
                            DirectContext {
                                ca_file: ca_file.as_deref(),
                                tools: &tools,
                                environment: &environment,
                                deadline,
                                cancel: &cancel,
                            },
                            &mut observation,
                        )
                        .await
                    }
                }
            }
            Err((error, permission)) => {
                observation.proof.denied_permission = permission;
                observation.execution = if permission.is_some() {
                    GcpExecution::Completed
                } else {
                    execution(&error)
                };
                if permission.is_some() {
                    observation.observed = GcpAccess::Denied;
                }
            }
        }
        observation.finished_at = now();
        observations.push(observation);
    }
    let controls = observations
        .iter()
        .filter(|observation| {
            observation.route == GcpRoute::Proxy
                && observation.execution == GcpExecution::Completed
                && observation.observed == GcpAccess::Allowed
                && observation.proof.sql_ok
                && observation.proof.sql_authenticated
                && observation.proof.credential_issued
                && c.cases.iter().any(|case| {
                    case.id == observation.case_id
                        && case.expected == GcpExpectation::Allow
                        && case.route == GcpRoute::Proxy
                })
        })
        .map(|observation| observation.case_id.clone())
        .collect::<Vec<_>>();
    for observation in &mut observations {
        if observation.route == GcpRoute::Proxy
            && observation.proof.iam_login_rejected
            && observation.proof.credential_issued
            && observation.proof.denied_permission != Some(GcpPermission::InstanceConnect)
            && let Some(control) = controls
                .iter()
                .find(|control| *control != &observation.case_id)
        {
            observation.proof.transport_positive = true;
            observation.proof.transport_control_case_id = Some(control.clone());
        }
    }
    let mut capture_execution = if cancel.is_cancelled() {
        GcpExecution::Cancelled
    } else if Instant::now() >= deadline {
        GcpExecution::Timeout
    } else {
        GcpExecution::Completed
    };
    let after = if ready(deadline, &cancel).is_ok() {
        match inventory(c, &tools, &environment, deadline, &cancel).await {
            Ok(after) => after.snapshot,
            Err(error) => {
                capture_execution = execution(&error);
                incomplete_after(&before.snapshot)
            }
        }
    } else {
        incomplete_after(&before.snapshot)
    };
    let evidence = GcpRunEvidence {
        schema_version: 1,
        run_id: run_id.into(),
        build_id: crate::BUILD_ID.into(),
        config_hash: config::config_hash(c),
        history_compatibility_hash: config::history_compatibility_hash(c),
        evidence_kind: GcpEvidenceKind::Live,
        execution: capture_execution,
        target: c.target.clone(),
        started_at,
        finished_at: now(),
        before: before.snapshot,
        after,
        observations,
    };
    if serde_json::to_vec(&evidence)
        .map_err(|_| GuardError::OperationFailed)?
        .len()
        > c.limits.max_bytes
    {
        return Err(GuardError::LimitExceeded);
    }
    Ok(evidence)
}
