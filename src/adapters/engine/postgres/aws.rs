//! AWS PostgreSQL management over hostname-verified TLS and freshly signed IAM
//! credentials. Construction is local: only PgTransport methods obtain
//! credentials or open a connection. The injected read-only authenticator must
//! verify STS identity on the exact credentials returned for signing, and must
//! re-observe the registered DB/proxy binding before returning them.
use super::*;
use crate::{domain::Endpoint, probe::auth::sign_iam_token};
use aws_credential_types::Credentials;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{future::Future, pin::Pin, sync::Arc, time::SystemTime};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsPgTargetBinding {
    pub db_instance_arn: String,
    pub dbi_resource_id: String,
    pub db_endpoint: Endpoint,
    pub database: String,
    /// The approved management route: either the registered DB endpoint or
    /// the registered native proxy endpoint, never a caller supplied DSN.
    pub management_endpoint: Endpoint,
    pub proxy_arn: Option<String>,
    pub proxy_name: Option<String>,
    pub proxy_role_arn: Option<String>,
    pub proxy_role_id: Option<String>,
}

/// Derived by the composing factory from the independent recovery exception.
/// A role name alone is insufficient: RoleId survives neither deletion nor
/// recreation, while the ARN can be reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsPgManagementIdentity {
    pub role_arn: String,
    pub role_id: String,
    pub db_username: String,
}

/// No Debug/Serialize implementation: credentials remain in process memory.
pub struct AwsPgAuthentication {
    pub credentials: Credentials,
    pub role_arn: String,
    pub role_id: String,
    pub target: AwsPgTargetBinding,
}
pub type AwsPgAuthenticationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AwsPgAuthentication, PgError>> + Send + 'a>>;

/// Trusted read-only authentication boundary. Implementations authenticate the
/// returned credentials with STS, then bind the observed DB's immutable
/// DbiResourceId, engine database and both endpoints. They may not mutate cloud
/// configuration, use ambient credentials for a separate identity check, or
/// claim that matching configuration strings are remote identity evidence.
pub trait AwsPgAuthProvider: Send + Sync {
    fn authenticate<'a>(&'a self, target: &'a AwsPgTargetBinding) -> AwsPgAuthenticationFuture<'a>;
}

pub struct AwsRdsPgTransport {
    target: Target,
    binding: AwsPgTargetBinding,
    management: AwsPgManagementIdentity,
    auth: Arc<dyn AwsPgAuthProvider>,
    tls: rustls::ClientConfig,
    timeout: Duration,
    cancel: CancellationToken,
    lifecycle: Option<PgLifecycleContext>,
    ownership_directory: Option<std::path::PathBuf>,
    ownership: Mutex<Option<PgOwnershipReceipt>>,
}

impl AwsRdsPgTransport {
    /// Expert composition boundary. The factory must bind `management` and the
    /// requested endpoint to the policy's explicit independent recovery route.
    /// A direct route requires its own management exception; configuring an
    /// application proxy does not authorize a direct administrator connection.
    pub fn new(
        mut target: Target,
        binding: AwsPgTargetBinding,
        management: AwsPgManagementIdentity,
        auth: Arc<dyn AwsPgAuthProvider>,
        root_ca_pem: &[u8],
        timeout: Duration,
    ) -> Result<Self, PgError> {
        validate_binding(&target, &binding, &management, timeout)?;
        // Match the canonical target used by typed SQL compilation even when a
        // programmatic caller supplied equivalent managed lists out of order.
        target.managed_surface.fields.sort();
        target.managed_surface.db_identities.sort();
        target.managed_surface.sql_scopes.sort();
        let tls = verified_tls(root_ca_pem)?;
        Ok(Self {
            target,
            binding,
            management,
            auth,
            tls,
            timeout,
            cancel: CancellationToken::new(),
            lifecycle: None,
            ownership_directory: None,
            ownership: Mutex::new(None),
        })
    }

    pub fn with_lifecycle_context(mut self, context: PgLifecycleContext) -> Self {
        self.lifecycle = Some(context);
        self
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    pub fn with_ownership_directory(mut self, path: std::path::PathBuf) -> Self {
        self.ownership_directory = Some(path);
        self
    }

    fn persist_ownership(
        &self,
        batch: &SqlBatch,
        owned: &PgOwnershipReceipt,
    ) -> Result<(), PgError> {
        let path = self
            .ownership_directory
            .as_ref()
            .ok_or(PgError::Unavailable)?
            .join(format!("postgres-ownership-{}", crate::store::new_run_id()));
        let mut writer = crate::store::RunWriter::create_for_config(
            &path,
            &batch.target_id,
            batch,
            "postgres-ownership",
            2 * 1024 * 1024,
            true,
        )
        .map_err(|_| PgError::Unavailable)?;
        writer
            .write_json("postgres-ownership.json", owned)
            .map_err(|_| PgError::Unavailable)?;
        writer
            .finish(crate::store::RunStatus::Complete)
            .map_err(|_| PgError::Unavailable)
    }

    /// Secret-free settings for local review. Hostname is retained for both DNS
    /// and TLS verification; SSL negotiation is mandatory, without a fallback.
    pub fn connection_settings(&self) -> tokio_postgres::Config {
        let mut config = tokio_postgres::Config::new();
        config
            .host(&self.binding.management_endpoint.host)
            .port(self.binding.management_endpoint.port)
            .user(&self.management.db_username)
            .dbname(&self.binding.database)
            .connect_timeout(self.timeout)
            .ssl_mode(tokio_postgres::config::SslMode::Require);
        config
    }

    fn validate_batch(&self, batch: &SqlBatch) -> Result<(), PgError> {
        let target_hash = crate::config::hash_bytes(
            &serde_json::to_vec(&self.target).map_err(|_| PgError::Scope)?,
        );
        if batch.target_hash != target_hash
            || batch.database != self.binding.database
            || batch.login == self.management.db_username
        {
            return Err(PgError::Precondition);
        }
        Ok(())
    }

    fn run(
        &self,
        batch: &SqlBatch,
        mode: Mode,
        guard: Option<&mut BeforeSqlWrite<'_>>,
    ) -> Result<PgOutcome, PgError> {
        self.validate_batch(batch)?;
        if self.cancel.is_cancelled() {
            return Err(PgError::Unavailable);
        }
        // Clear stale proof even if authentication or opening TCP subsequently
        // fails. It cannot become evidence for a different attempted mutation.
        if mode == Mode::Execute {
            *self.ownership.lock().map_err(|_| PgError::Unavailable)? = None;
        }
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| PgError::Unavailable)?;
                    runtime.block_on(async {
                        let work = self.run_async(batch, mode, guard);
                        tokio::select! {
                            biased;
                            _ = self.cancel.cancelled() => Err(PgError::Unknown),
                            result = tokio::time::timeout(self.timeout, work) => {
                                result.unwrap_or(Err(PgError::Unknown))
                            }
                        }
                    })
                })
                .join()
                .map_err(|_| PgError::Unknown)?
        })
    }

    async fn run_async(
        &self,
        batch: &SqlBatch,
        mode: Mode,
        mut guard: Option<&mut BeforeSqlWrite<'_>>,
    ) -> Result<PgOutcome, PgError> {
        let authenticated = self.auth.authenticate(&self.binding).await?;
        if authenticated.target != self.binding
            || authenticated.role_arn != self.management.role_arn
            || authenticated.role_id != self.management.role_id
        {
            return Err(PgError::Precondition);
        }
        let token = sign_iam_token(
            authenticated.credentials,
            &self.binding.management_endpoint,
            &self.management.db_username,
            &self.target.placement.region,
            SystemTime::now(),
        )
        .map_err(|_| PgError::Precondition)?;
        let mut config = self.connection_settings();
        config.password(token.expose());
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(self.tls.clone());
        let (mut client, connection) = config
            .connect(tls)
            .await
            .map_err(|_| PgError::Unavailable)?;
        // Drop aborts the task even if an outer timeout/cancellation drops this
        // future. Detached live sessions must not survive cancelled management.
        let _connection = ConnectionTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let identity = client
            .query_one("SELECT session_user::text, current_user::text", &[])
            .await
            .map_err(|_| PgError::Precondition)?;
        if identity.get::<_, String>(0) != self.management.db_username
            || identity.get::<_, String>(1) != self.management.db_username
        {
            return Err(PgError::Precondition);
        }
        let tx = client
            .transaction()
            .await
            .map_err(|_| PgError::Unavailable)?;
        // Set read-only before the first query for both preflight and reconcile.
        if mode != Mode::Execute {
            tx.batch_execute("SET TRANSACTION READ ONLY")
                .await
                .map_err(|_| PgError::Precondition)?;
        }
        tx.batch_execute("SET LOCAL search_path = pg_catalog; SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '30s'")
            .await
            .map_err(|_| PgError::Precondition)?;
        verify_identity(&tx, batch).await?;
        verify_revoke_preconditions(&tx, batch).await?;
        if mode == Mode::Preflight {
            return Ok(PgOutcome::NotApplied);
        }
        let before = if mode == Mode::Execute
            && batch.action != PgAction::RevokeSqlPrivileges
            && (!batch.roles.is_empty() || !batch.checks.is_empty())
        {
            Some(capture_ownership(&tx, batch).await?)
        } else {
            None
        };
        if mode == Mode::Execute {
            for sql in &batch.statements {
                if let Some(g) = guard.as_mut() {
                    g()?;
                }
                tx.batch_execute(sql)
                    .await
                    .map_err(|_| PgError::Precondition)?;
            }
        }
        let applied = readback(&tx, batch).await?;
        if mode == Mode::Execute {
            if !applied {
                tx.rollback().await.map_err(|_| PgError::Unknown)?;
                return Ok(PgOutcome::NotApplied);
            }
            let owned = if let Some(before) = before {
                Some(ownership_delta(
                    &before,
                    capture_ownership(&tx, batch).await?,
                ))
            } else {
                None
            };
            // A lost COMMIT reply never authorizes resending the statements.
            if let Some(g) = guard.as_mut() {
                g()?;
            }
            tx.commit().await.map_err(|_| PgError::Unknown)?;
            // Persistence failure cannot reverse COMMIT. Publish removal
            // authority only after the verified artifact is durable.
            if let Some(owned) = owned
                && self.persist_ownership(batch, &owned).is_ok()
            {
                *self.ownership.lock().map_err(|_| PgError::Unknown)? = Some(owned);
            }
        }
        Ok(if applied {
            PgOutcome::Applied
        } else {
            PgOutcome::NotApplied
        })
    }
}

impl PgTransport for AwsRdsPgTransport {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn execute_atomic_guarded(
        &mut self,
        batch: &SqlBatch,
        guard: &mut BeforeSqlWrite<'_>,
    ) -> Result<PgOutcome, PgError> {
        self.run(batch, Mode::Execute, Some(guard))
    }
    fn lifecycle_context(&self) -> Option<&PgLifecycleContext> {
        self.lifecycle.as_ref()
    }
    fn owned_receipt(&self) -> Option<PgOwnershipReceipt> {
        self.ownership.lock().ok()?.clone()
    }
    fn preflight(&mut self, batch: &SqlBatch) -> Result<(), PgError> {
        self.run(batch, Mode::Preflight, None).map(|_| ())
    }
    fn execute_atomic(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.run(batch, Mode::Execute, None)
    }
    fn query(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.run(batch, Mode::Query, None)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Preflight,
    Execute,
    Query,
}

struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn valid_hostname(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && host.parse::<std::net::IpAddr>().is_err()
}

fn validate_binding(
    target: &Target,
    binding: &AwsPgTargetBinding,
    identity: &AwsPgManagementIdentity,
    timeout: Duration,
) -> Result<(), PgError> {
    let arn: Vec<_> = binding.db_instance_arn.splitn(6, ':').collect();
    let role: Vec<_> = identity.role_arn.splitn(6, ':').collect();
    let approved = target.aws.as_ref().ok_or(PgError::Precondition)?;
    if target.placement.kind != PlacementKind::AwsRds
        || target.engine.family != EngineFamily::PostgreSql
        || !target.engine.version.starts_with("16.")
        || binding.database != target.engine.database
        || binding.db_instance_arn != target.resource.native_id
        || binding.dbi_resource_id != approved.db_resource_id
        || binding.db_endpoint.host != approved.db_endpoint
        || identity.db_username != approved.management_db_identity
        || arn.len() != 6
        || arn[0] != "arn"
        || !matches!(arn[1], "aws" | "aws-cn" | "aws-us-gov")
        || arn[2] != "rds"
        || arn[3] != target.placement.region
        || arn[4] != target.placement.account_id
        || !arn[5].starts_with("db:")
        || binding.dbi_resource_id.len() < 4
        || !binding.dbi_resource_id.starts_with("db-")
        || !binding
            .dbi_resource_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !valid_hostname(&binding.db_endpoint.host)
        || !valid_hostname(&binding.management_endpoint.host)
        || binding.db_endpoint.port == 0
        || binding.management_endpoint.port == 0
        || role.len() != 6
        || role[0] != "arn"
        || role[1] != arn[1]
        || role[2] != "iam"
        || !role[3].is_empty()
        || role[4] != target.placement.account_id
        || !role[5].starts_with("role/")
        || role[5].len() <= 5
        || !aws_role_arn(&identity.role_arn, &target.placement.account_id)
        || !aws_role_id(&identity.role_id)
        || identity.db_username.eq_ignore_ascii_case("public")
        || quote_identifier(&identity.db_username).is_err()
        || quote_identifier(&binding.database).is_err()
        || timeout.is_zero()
        || timeout > Duration::from_secs(120)
    {
        return Err(PgError::Precondition);
    }
    if let Some(proxy) = &binding.proxy_arn {
        let parts: Vec<_> = proxy.splitn(6, ':').collect();
        if parts.len() != 6
            || parts[..5] != arn[..5]
            || !parts[5].starts_with("db-proxy:prx-")
            || binding.management_endpoint == binding.db_endpoint
            || proxy != &approved.proxy_arn
            || binding.management_endpoint.host != approved.proxy_endpoint
            || binding.proxy_name.as_deref() != Some(&approved.proxy_name)
            || binding.proxy_role_arn.as_deref() != Some(&approved.proxy_role_arn)
            || binding.proxy_role_id.as_deref() != Some(&approved.proxy_role_id)
        {
            return Err(PgError::Precondition);
        }
    } else if binding.management_endpoint != binding.db_endpoint
        || binding.proxy_name.is_some()
        || binding.proxy_role_arn.is_some()
        || binding.proxy_role_id.is_some()
    {
        return Err(PgError::Precondition);
    }
    // The shared deployment adapter computes the exact immutable tuple. SQL
    // current_database()/server_version is an additional engine check, never a
    // substitute for the fresh DB/proxy metadata checked by the auth provider.
    let generation = crate::adapters::deployment::aws::generation_fingerprint(
        &target.placement.account_id,
        &target.placement.region,
        &binding.db_instance_arn,
        &binding.dbi_resource_id,
    );
    if target.resource.generation_fingerprint.as_deref() != Some(&generation) {
        return Err(PgError::Precondition);
    }
    Ok(())
}

pub(crate) fn verified_tls(pem: &[u8]) -> Result<rustls::ClientConfig, PgError> {
    if pem.is_empty() || pem.len() > 1_048_576 {
        return Err(PgError::Precondition);
    }
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PgError::Precondition)?;
    if certificates.is_empty() {
        return Err(PgError::Precondition);
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|_| PgError::Precondition)?;
    }
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
        .map_err(|_| PgError::Precondition)
}

/// Explicit profile export, followed by STS/IAM/metadata reads on that exact
/// credential set. No provider-chain fallback, credential argv, raw diagnostic
/// output, endpoint override or environment-supplied profile is accepted.
pub struct AwsCliPgAuthProvider {
    aws_path: std::path::PathBuf,
    profile: String,
    role_arn: String,
    role_id: String,
    cancel: CancellationToken,
}
impl AwsCliPgAuthProvider {
    pub fn new(
        aws_path: std::path::PathBuf,
        profile: String,
        role_arn: String,
        role_id: String,
        cancel: CancellationToken,
    ) -> Result<Self, PgError> {
        let account = role_arn.split(':').nth(4).ok_or(PgError::Precondition)?;
        if !aws_path.is_absolute()
            || profile.is_empty()
            || profile.len() > 128
            || !profile
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.@".contains(&b))
            || !aws_role_arn(&role_arn, account)
            || !aws_role_id(&role_id)
        {
            return Err(PgError::Precondition);
        }
        let aws_path = aws_path.canonicalize().map_err(|_| PgError::Unavailable)?;
        let metadata = aws_path.metadata().map_err(|_| PgError::Unavailable)?;
        if !metadata.is_file() {
            return Err(PgError::Precondition);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(PgError::Precondition);
            }
        }
        Ok(Self {
            aws_path,
            profile,
            role_arn,
            role_id,
            cancel,
        })
    }

    /// Capture one explicit profile credential set and authenticate that exact
    /// set with STS. This needs no IAM/RDS reads, so a connection observer can
    /// exercise a minimally privileged application role. Management must verify
    /// DB/proxy metadata independently before interpreting those observations.
    /// Secrets are passed to AWS subprocesses only through their environment.
    pub async fn role_credentials(&self, region: &str) -> Result<Credentials, PgError> {
        validate_region(region)?;
        let mut export = self.command();
        export.args([
            "configure",
            "export-credentials",
            "--profile",
            &self.profile,
            "--format",
            "process",
        ]);
        // Only explicit CLI profile/config files participate in this export.
        // Ambient access keys, endpoint overrides and web identity are absent.
        for key in ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"] {
            if let Some(value) = std::env::var_os(key) {
                export.env(key, value);
            }
        }
        let value = self.read_json(export).await?;
        let access = json_string(&value, "/AccessKeyId")?;
        let secret = json_string(&value, "/SecretAccessKey")?;
        let session = json_string(&value, "/SessionToken")?;
        if access.len() > 256 || secret.len() > 4096 || session.len() > 65_536 {
            return Err(PgError::Precondition);
        }
        // A successful STS request below validates these credentials now. The
        // native PostgreSQL login independently checks their remaining validity.
        let credentials =
            Credentials::new(access, secret, Some(session), None, "explicit-role-profile");
        let caller = self
            .cloud_json(&credentials, region, "sts", &["get-caller-identity"])
            .await?;
        verify_sts_identity(&caller, &self.role_arn, &self.role_id)?;
        Ok(credentials)
    }

    /// Management credential capture adds authoritative IAM role metadata to
    /// the same frozen credential set used for the STS identity verification.
    pub async fn authenticated_credentials(&self, region: &str) -> Result<Credentials, PgError> {
        let credentials = self.role_credentials(region).await?;
        self.verify_role(&credentials, region, &self.role_arn, &self.role_id)
            .await?;
        Ok(credentials)
    }

    fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.aws_path);
        command.env_clear();
        // HOME supports the explicitly selected CLI profile. PATH supports its
        // configured credential_process; neither selects a credential profile.
        for key in ["HOME", "PATH", "TMPDIR", "SYSTEMROOT"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("AWS_PAGER", "")
            .env("AWS_CLI_AUTO_PROMPT", "off")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("AWS_MAX_ATTEMPTS", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        command
    }

    async fn read_json(
        &self,
        mut command: tokio::process::Command,
    ) -> Result<serde_json::Value, PgError> {
        use tokio::io::AsyncReadExt;
        if self.cancel.is_cancelled() {
            return Err(PgError::Unavailable);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }
        let child = command.spawn().map_err(|_| PgError::Unavailable)?;
        let mut process = AwsProcess::new(child);
        let stdout = process
            .child
            .as_mut()
            .ok_or(PgError::Unavailable)?
            .stdout
            .take()
            .ok_or(PgError::Unavailable)?;
        let work = async {
            let mut bytes = vec![];
            stdout
                .take(1_048_577)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| PgError::Unavailable)?;
            if bytes.len() > 1_048_576 {
                return Err(PgError::Precondition);
            }
            let status = process
                .child
                .as_mut()
                .ok_or(PgError::Unavailable)?
                .wait()
                .await
                .map_err(|_| PgError::Unavailable)?;
            if !status.success() {
                return Err(PgError::Precondition);
            }
            serde_json::from_slice(&bytes).map_err(|_| PgError::Precondition)
        };
        let result = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(PgError::Unavailable),
            result = tokio::time::timeout(Duration::from_secs(30),work) => result.unwrap_or(Err(PgError::Unavailable)),
        };
        process.stop().await;
        result
    }

    async fn cloud_json(
        &self,
        credentials: &Credentials,
        region: &str,
        service: &str,
        args: &[&str],
    ) -> Result<serde_json::Value, PgError> {
        validate_region(region)?;
        let endpoint = match service {
            "sts" => format!("https://sts.{region}.amazonaws.com"),
            "rds" => format!("https://rds.{region}.amazonaws.com"),
            "iam" => "https://iam.amazonaws.com".into(),
            _ => return Err(PgError::Scope),
        };
        let mut command = self.command();
        command
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AWS_ACCESS_KEY_ID", credentials.access_key_id())
            .env("AWS_SECRET_ACCESS_KEY", credentials.secret_access_key())
            .env(
                "AWS_SESSION_TOKEN",
                credentials.session_token().ok_or(PgError::Precondition)?,
            )
            .arg(service)
            .args(args)
            .args([
                "--region",
                region,
                "--endpoint-url",
                &endpoint,
                "--output",
                "json",
                "--no-cli-pager",
                "--no-cli-auto-prompt",
            ]);
        self.read_json(command).await
    }

    async fn verify_role(
        &self,
        credentials: &Credentials,
        region: &str,
        arn: &str,
        id: &str,
    ) -> Result<(), PgError> {
        let name = arn.rsplit('/').next().ok_or(PgError::Precondition)?;
        let role = self
            .cloud_json(
                credentials,
                region,
                "iam",
                &["get-role", "--role-name", name],
            )
            .await?;
        if json_string(&role, "/Role/Arn")? != arn || json_string(&role, "/Role/RoleId")? != id {
            return Err(PgError::Precondition);
        }
        Ok(())
    }

    /// Shared frozen-credential metadata check. Only the two explicitly
    /// supported engine families can be selected by composing transports.
    pub(crate) async fn authenticate_engine_target(
        &self,
        target: &AwsPgTargetBinding,
        engine: EngineFamily,
    ) -> Result<AwsPgAuthentication, PgError> {
        let (db_engine, proxy_engine) = match engine {
            EngineFamily::PostgreSql => ("postgres", "POSTGRESQL"),
            EngineFamily::MySql => ("mysql", "MYSQL"),
            _ => return Err(PgError::Unsupported),
        };
        let arn: Vec<_> = target.db_instance_arn.splitn(6, ':').collect();
        if arn.len() != 6 || arn[1] != "aws" || !arn[5].starts_with("db:") {
            return Err(PgError::Precondition);
        }
        let region = arn[3];
        let credentials = self.authenticated_credentials(region).await?;
        if self.role_arn.split(':').nth(4) != Some(arn[4]) {
            return Err(PgError::Precondition);
        }
        let db = self
            .cloud_json(
                &credentials,
                region,
                "rds",
                &[
                    "describe-db-instances",
                    "--db-instance-identifier",
                    &arn[5][3..],
                ],
            )
            .await?;
        let instances = db
            .get("DBInstances")
            .and_then(serde_json::Value::as_array)
            .ok_or(PgError::Precondition)?;
        if instances.len() != 1 {
            return Err(PgError::Precondition);
        }
        let db = &instances[0];
        if json_string(db, "/DBInstanceArn")? != target.db_instance_arn
            || json_string(db, "/DbiResourceId")? != target.dbi_resource_id
            || json_string(db, "/Endpoint/Address")? != target.db_endpoint.host
            || db
                .pointer("/Endpoint/Port")
                .and_then(serde_json::Value::as_u64)
                != Some(target.db_endpoint.port.into())
            || json_string(db, "/Engine")? != db_engine
            || (engine == EngineFamily::MySql && json_string(db, "/EngineVersion")? != "8.0.43")
            || db
                .get("IAMDatabaseAuthenticationEnabled")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(PgError::Precondition);
        }
        if let Some(proxy_arn) = &target.proxy_arn {
            let name = target.proxy_name.as_deref().ok_or(PgError::Precondition)?;
            let proxy_role = target
                .proxy_role_arn
                .as_deref()
                .ok_or(PgError::Precondition)?;
            let proxy_role_id = target
                .proxy_role_id
                .as_deref()
                .ok_or(PgError::Precondition)?;
            let proxies = self
                .cloud_json(
                    &credentials,
                    region,
                    "rds",
                    &["describe-db-proxies", "--db-proxy-name", name],
                )
                .await?;
            let proxies = proxies
                .get("DBProxies")
                .and_then(serde_json::Value::as_array)
                .ok_or(PgError::Precondition)?;
            if proxies.len() != 1 {
                return Err(PgError::Precondition);
            }
            let proxy = &proxies[0];
            if json_string(proxy, "/DBProxyArn")? != *proxy_arn
                || json_string(proxy, "/DBProxyName")? != name
                || json_string(proxy, "/Endpoint")? != target.management_endpoint.host
                || json_string(proxy, "/RoleArn")? != proxy_role
                || json_string(proxy, "/DefaultAuthScheme")? != "IAM_AUTH"
                // DefaultAuthScheme can coexist with per-user Secrets Manager
                // Auth entries. The initial exclusive IAM profile cannot
                // accept or silently remove those independent credentials.
                || proxy.get("Auth").is_some_and(|auth| !auth.as_array().is_some_and(Vec::is_empty))
                || json_string(proxy, "/EngineFamily")? != proxy_engine
                || json_string(proxy, "/Status")? != "available"
                || proxy.get("RequireTLS").and_then(serde_json::Value::as_bool) != Some(true)
            {
                return Err(PgError::Precondition);
            }
            self.verify_role(&credentials, region, proxy_role, proxy_role_id)
                .await?;
            let targets = self
                .cloud_json(
                    &credentials,
                    region,
                    "rds",
                    &[
                        "describe-db-proxy-targets",
                        "--db-proxy-name",
                        name,
                        "--target-group-name",
                        "default",
                    ],
                )
                .await?;
            let targets = targets
                .get("Targets")
                .and_then(serde_json::Value::as_array)
                .ok_or(PgError::Precondition)?;
            if targets.len() != 1 {
                return Err(PgError::Precondition);
            }
            let native = &targets[0];
            if json_string(native, "/RdsResourceId")? != arn[5][3..]
                || json_string(native, "/Endpoint")? != target.db_endpoint.host
                || native.get("Port").and_then(serde_json::Value::as_u64)
                    != Some(target.db_endpoint.port.into())
                || json_string(native, "/Type")? != "RDS_INSTANCE"
                || json_string(native, "/TargetHealth/State")? != "AVAILABLE"
                || native
                    .get("TargetArn")
                    .is_some_and(|value| value.as_str() != Some(&target.db_instance_arn))
            {
                return Err(PgError::Precondition);
            }
        }
        Ok(AwsPgAuthentication {
            credentials,
            role_arn: self.role_arn.clone(),
            role_id: self.role_id.clone(),
            target: target.clone(),
        })
    }
}
impl AwsPgAuthProvider for AwsCliPgAuthProvider {
    fn authenticate<'a>(&'a self, target: &'a AwsPgTargetBinding) -> AwsPgAuthenticationFuture<'a> {
        Box::pin(self.authenticate_engine_target(target, EngineFamily::PostgreSql))
    }
}

/// Every AWS CLI invocation owns a separate Unix process group so configured
/// credential_process descendants cannot retain credentials after cancellation.
/// Normal exits and handled errors await the parent; Drop also covers an outer
/// native-request timeout that discards read_json while its runtime is closing.
struct AwsProcess {
    child: Option<tokio::process::Child>,
    #[cfg(unix)]
    group: Option<i32>,
}
impl AwsProcess {
    fn new(child: tokio::process::Child) -> Self {
        Self {
            #[cfg(unix)]
            group: child.id().and_then(|id| i32::try_from(id).ok()),
            child: Some(child),
        }
    }
    fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(group) = self.group {
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
    async fn stop(&mut self) {
        self.kill();
        if let Some(child) = self.child.as_mut()
            && matches!(
                tokio::time::timeout(Duration::from_secs(2), child.wait()).await,
                Ok(Ok(_))
            )
        {
            self.child.take();
            #[cfg(unix)]
            {
                self.group = None;
            }
        }
    }
}
impl Drop for AwsProcess {
    fn drop(&mut self) {
        self.kill();
        if let Some(mut child) = self.child.take() {
            // try_wait is synchronous. Reap independently of the disappearing
            // Tokio runtime when cancellation dropped the async cleanup path.
            if !matches!(child.try_wait(), Ok(Some(_))) {
                std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    loop {
                        match child.try_wait() {
                            Ok(Some(_)) | Err(_) => return,
                            Ok(None) => {}
                        }
                        if std::time::Instant::now() >= deadline {
                            return;
                        }
                        let _ = child.start_kill();
                        std::thread::sleep(Duration::from_millis(10));
                    }
                });
            }
        }
    }
}

fn json_string(value: &serde_json::Value, pointer: &str) -> Result<String, PgError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|v| !v.is_empty() && v.len() <= 65_536 && !v.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(PgError::Precondition)
}
fn validate_region(region: &str) -> Result<(), PgError> {
    if region.is_empty()
        || region.len() > 32
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(PgError::Precondition);
    }
    Ok(())
}
fn verify_sts_identity(
    value: &serde_json::Value,
    role_arn: &str,
    role_id: &str,
) -> Result<(), PgError> {
    let account = role_arn.split(':').nth(4).ok_or(PgError::Precondition)?;
    let leaf = role_arn.rsplit('/').next().ok_or(PgError::Precondition)?;
    let arn = json_string(value, "/Arn")?;
    let prefix = format!("arn:aws:sts::{account}:assumed-role/{leaf}/");
    let caller_id = json_string(value, "/UserId")?;
    let session = arn.strip_prefix(&prefix).ok_or(PgError::Precondition)?;
    if json_string(value, "/Account")? != account
        || session.is_empty()
        || session.contains('/')
        || caller_id != format!("{role_id}:{session}")
    {
        return Err(PgError::Precondition);
    }
    Ok(())
}
