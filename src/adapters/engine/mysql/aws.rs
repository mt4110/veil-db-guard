//! Native MySQL protocol, IAM signing and mandatory verified TLS. Construction
//! is local; only explicit transport/probe calls obtain credentials or connect.
use super::*;
use crate::adapters::engine::postgres::{
    PgError,
    aws::{AwsCliPgAuthProvider, AwsPgManagementIdentity, AwsPgTargetBinding},
};
use crate::{domain::Endpoint, probe::auth::sign_iam_token};
use aws_credential_types::Credentials;
use mysql_async::{Conn, Opts, OptsBuilder, SslOpts, prelude::Queryable};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio_util::sync::CancellationToken;

pub type AwsMysqlTargetBinding = AwsPgTargetBinding;
pub type AwsMysqlManagementIdentity = AwsPgManagementIdentity;
/// No Debug/Serialize: the exact credentials proved with STS sign the token.
pub struct AwsMysqlAuthentication {
    pub credentials: Credentials,
    pub role_arn: String,
    pub role_id: String,
    pub target: AwsMysqlTargetBinding,
}
pub type AwsMysqlAuthenticationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AwsMysqlAuthentication, MysqlError>> + Send + 'a>>;
/// Must prove the returned credential set's STS RoleId and freshly observe the
/// immutable database, exact engine, proxy target, TLS/IAM mode and proxy role.
pub trait AwsMysqlAuthProvider: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        target: &'a AwsMysqlTargetBinding,
    ) -> AwsMysqlAuthenticationFuture<'a>;
}
impl AwsMysqlAuthProvider for AwsCliPgAuthProvider {
    fn authenticate<'a>(
        &'a self,
        target: &'a AwsMysqlTargetBinding,
    ) -> AwsMysqlAuthenticationFuture<'a> {
        Box::pin(async move {
            let auth = self
                .authenticate_engine_target(target, EngineFamily::MySql)
                .await
                .map_err(pg_error)?;
            Ok(AwsMysqlAuthentication {
                credentials: auth.credentials,
                role_arn: auth.role_arn,
                role_id: auth.role_id,
                target: auth.target,
            })
        })
    }
}
fn pg_error(error: PgError) -> MysqlError {
    match error {
        PgError::Scope => MysqlError::Scope,
        PgError::Unsupported => MysqlError::Unsupported,
        PgError::Precondition | PgError::SourceGuardRejected => MysqlError::Precondition,
        PgError::Unavailable => MysqlError::Unavailable,
        PgError::Unknown => MysqlError::Unknown,
    }
}

pub struct AwsRdsMysqlTransport {
    target: Target,
    binding: AwsMysqlTargetBinding,
    management: AwsMysqlManagementIdentity,
    auth: Arc<dyn AwsMysqlAuthProvider>,
    ssl: SslOpts,
    timeout: Duration,
    cancel: CancellationToken,
    lifecycle: Option<MysqlLifecycleContext>,
    ownership_directory: Option<std::path::PathBuf>,
    ownership: Mutex<Option<MysqlOwnershipReceipt>>,
}
impl AwsRdsMysqlTransport {
    pub fn new(
        mut target: Target,
        binding: AwsMysqlTargetBinding,
        management: AwsMysqlManagementIdentity,
        auth: Arc<dyn AwsMysqlAuthProvider>,
        root_ca_pem: &[u8],
        timeout: Duration,
    ) -> Result<Self, MysqlError> {
        validate_binding(&target, &binding, &management, timeout)?;
        target.managed_surface.fields.sort();
        target.managed_surface.db_identities.sort();
        target.managed_surface.sql_scopes.sort();
        Ok(Self {
            target,
            binding,
            management,
            auth,
            ssl: verified_tls(root_ca_pem)?,
            timeout,
            cancel: CancellationToken::new(),
            lifecycle: None,
            ownership_directory: None,
            ownership: Mutex::new(None),
        })
    }
    pub fn with_lifecycle_context(mut self, context: MysqlLifecycleContext) -> Self {
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
    /// Secret-free options for review. Actual token-bearing options never leave
    /// the connection function and are never logged or placed in a DSN/argv.
    pub fn connection_settings(&self) -> Opts {
        connection_options(
            &self.binding.management_endpoint,
            &self.binding.database,
            &self.management.db_username,
            self.ssl.clone(),
        )
    }
    fn persist(&self, batch: &SqlBatch, owned: &MysqlOwnershipReceipt) -> Result<(), MysqlError> {
        let path = self
            .ownership_directory
            .as_ref()
            .ok_or(MysqlError::Unavailable)?
            .join(format!("mysql-ownership-{}", crate::store::new_run_id()));
        let mut writer = crate::store::RunWriter::create_for_config(
            &path,
            &batch.target_id,
            batch,
            "mysql-ownership",
            2 * 1024 * 1024,
            true,
        )
        .map_err(|_| MysqlError::Unavailable)?;
        writer
            .write_json("mysql-ownership.json", owned)
            .map_err(|_| MysqlError::Unavailable)?;
        writer
            .finish(crate::store::RunStatus::Complete)
            .map_err(|_| MysqlError::Unavailable)
    }
    fn publish(&self, batch: &SqlBatch, owned: &MysqlOwnershipReceipt) -> Result<(), MysqlError> {
        self.persist(batch, owned)?;
        *self.ownership.lock().map_err(|_| MysqlError::Unavailable)? = Some(owned.clone());
        Ok(())
    }
    fn validate_batch(&self, batch: &SqlBatch) -> Result<(), MysqlError> {
        let mysql = self.target.mysql.as_ref().ok_or(MysqlError::Precondition)?;
        if batch.target_hash
            != crate::config::hash_bytes(
                &serde_json::to_vec(&self.target).map_err(|_| MysqlError::Scope)?,
            )
            || batch.database != self.binding.database
            || batch.version != "8.0.43"
            || batch.login == self.management.db_username
            || batch.account_host != mysql.account_host
            || batch.management_account_host != mysql.management_account_host
        {
            return Err(MysqlError::Precondition);
        }
        if batch.action == MysqlAction::RevokeSqlPrivileges {
            let context = self.lifecycle.as_ref().ok_or(MysqlError::Precondition)?;
            let owned = context.ownership.as_ref().ok_or(MysqlError::Precondition)?;
            if owned.outcome != MysqlOutcome::Applied
                || owned.uncertain_statement.is_some()
                || batch.management_identity.as_deref()
                    != Some(
                        quote_account(
                            &self.management.db_username,
                            &mysql.management_account_host,
                        )?
                        .as_str(),
                    )
            {
                return Err(MysqlError::Precondition);
            }
        }
        Ok(())
    }
    fn run(
        &self,
        batch: &SqlBatch,
        mode: Mode,
        guard: Option<&mut BeforeMysqlWrite<'_>>,
    ) -> Result<MysqlOutcome, MysqlError> {
        self.validate_batch(batch)?;
        if self.cancel.is_cancelled() {
            return Err(MysqlError::Unavailable);
        }
        if mode == Mode::Execute {
            *self.ownership.lock().map_err(|_| MysqlError::Unavailable)? = None;
        }
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
            let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_|MysqlError::Unavailable)?;
            runtime.block_on(async {tokio::select! {biased;
                _=self.cancel.cancelled()=>Err(MysqlError::Unknown),
                result=tokio::time::timeout(self.timeout,self.run_async(batch,mode,guard))=>result.unwrap_or(Err(MysqlError::Unknown)),
            }})
        }).join().map_err(|_|MysqlError::Unknown)?
        });
        // A durable attempted-statement receipt remains available to the
        // executor even when an outer deadline discarded the future.
        match result {
            Err(MysqlError::Unknown) if mode == Mode::Execute && self.owned_receipt().is_some() => {
                Ok(MysqlOutcome::Unknown)
            }
            other => other,
        }
    }
    async fn run_async(
        &self,
        batch: &SqlBatch,
        mode: Mode,
        mut guard: Option<&mut BeforeMysqlWrite<'_>>,
    ) -> Result<MysqlOutcome, MysqlError> {
        let auth = self.auth.authenticate(&self.binding).await?;
        if auth.target != self.binding
            || auth.role_arn != self.management.role_arn
            || auth.role_id != self.management.role_id
        {
            return Err(MysqlError::Precondition);
        }
        let token = sign_iam_token(
            auth.credentials,
            &self.binding.management_endpoint,
            &self.management.db_username,
            &self.target.placement.region,
            SystemTime::now(),
        )
        .map_err(|_| MysqlError::Precondition)?;
        let opts = OptsBuilder::from_opts(self.connection_settings()).pass(Some(token.expose()));
        let mut conn = Conn::new(opts).await.map_err(|_| MysqlError::Unavailable)?;
        let mysql = self.target.mysql.as_ref().ok_or(MysqlError::Precondition)?;
        verify_session(
            &mut conn,
            &batch.database,
            &batch.version,
            &self.management.db_username,
            &mysql.management_account_host,
        )
        .await?;
        let management = verify_account(
            &mut conn,
            &self.management.db_username,
            &mysql.management_account_host,
        )
        .await?;
        if management.locked {
            return Err(MysqlError::Precondition);
        }
        let account = verify_account(&mut conn, &batch.login, &batch.account_host).await?;
        if mode != Mode::Query
            && matches!(
                batch.action,
                MysqlAction::RegisterNativeDbIdentity | MysqlAction::ConfigureSqlPrivileges
            )
            && account.locked
        {
            return Err(MysqlError::Precondition);
        }
        if mode != Mode::Query
            && batch.action == MysqlAction::RevokeSqlPrivileges
            && !account.locked
        {
            return Err(MysqlError::Precondition);
        }
        // Reject ambiguous anonymous/alternate-host accounts, broad privileges,
        // role membership, dynamic privileges, proxy grants and column grants.
        verify_exclusive_account(&mut conn, batch, &self.management.db_username).await?;
        let before = capture_privileges(&mut conn, batch).await?;
        if batch.action == MysqlAction::RevokeSqlPrivileges {
            let owned = self
                .lifecycle
                .as_ref()
                .and_then(|c| c.ownership.as_ref())
                .ok_or(MysqlError::Precondition)?;
            let valid = if mode == Mode::Query {
                before.iter().all(|p| owned.after_privileges.contains(p))
                    && owned.before_privileges.iter().all(|p| before.contains(p))
            } else {
                before.len() == owned.after_privileges.len()
                    && before.iter().all(|p| owned.after_privileges.contains(p))
            };
            if !valid {
                return Err(MysqlError::Precondition);
            }
        }
        if mode == Mode::Preflight {
            return Ok(MysqlOutcome::NotApplied);
        }
        if mode == Mode::Query {
            return Ok(readback(batch, &account, &before));
        }
        let mut owned = MysqlOwnershipReceipt {
            policy_hash: batch.policy_hash.clone(),
            apply_batch_hash: batch.hash(),
            management_identity: quote_account(
                &self.management.db_username,
                &mysql.management_account_host,
            )?,
            before_privileges: before.clone(),
            after_privileges: before,
            added_privileges: vec![],
            acknowledged_statements: vec![],
            uncertain_statement: None,
            outcome: MysqlOutcome::Unknown,
        };
        // Before every independently committed statement, persist its uncertain
        // index. Timeout, cancellation and process loss retain honest evidence.
        for (index, sql) in batch.statements.iter().enumerate() {
            owned.uncertain_statement = Some(index);
            owned.outcome = MysqlOutcome::Unknown;
            self.publish(batch, &owned).map_err(|error| {
                if index == 0 {
                    error
                } else {
                    MysqlError::Unknown
                }
            })?;
            if let Some(g) = guard.as_mut()
                && let Err(error) = g()
            {
                // Prior statements implicitly committed. Never claim the
                // whole batch absent or enable replay after partial apply.
                owned.uncertain_statement = None;
                owned.outcome = if index == 0 {
                    MysqlOutcome::NotApplied
                } else {
                    MysqlOutcome::Unknown
                };
                self.publish(batch, &owned)
                    .map_err(|_| MysqlError::Unknown)?;
                return if index == 0 {
                    Err(error)
                } else {
                    Ok(MysqlOutcome::Unknown)
                };
            }
            match conn.query_drop(sql).await {
                Ok(()) => {
                    owned.acknowledged_statements.push(index);
                    owned.uncertain_statement = None;
                }
                Err(mysql_async::Error::Server(_)) => {
                    owned.uncertain_statement = None;
                    owned.outcome = MysqlOutcome::Unknown;
                    if let Ok(after) = capture_privileges(&mut conn, batch).await {
                        let changed = after.len() != owned.before_privileges.len()
                            || after.iter().any(|p| !owned.before_privileges.contains(p));
                        update_delta(&mut owned, after);
                        // Explicit server failure does not establish rollback.
                        // Account DDL is not represented by privilege deltas.
                        if batch.action != MysqlAction::DisableNewConnections {
                            owned.outcome = if changed || index > 0 {
                                MysqlOutcome::Partial
                            } else {
                                MysqlOutcome::NotApplied
                            };
                        }
                    }
                    self.publish(batch, &owned)
                        .map_err(|_| MysqlError::Unknown)?;
                    return Ok(owned.outcome);
                }
                Err(_) => return Err(MysqlError::Unknown),
            }
            self.publish(batch, &owned)
                .map_err(|_| MysqlError::Unknown)?;
        }
        let after = capture_privileges(&mut conn, batch)
            .await
            .map_err(|_| MysqlError::Unknown)?;
        let account = verify_account(&mut conn, &batch.login, &batch.account_host)
            .await
            .map_err(|_| MysqlError::Unknown)?;
        update_delta(&mut owned, after);
        owned.outcome = readback(batch, &account, &owned.after_privileges);
        if owned.outcome != MysqlOutcome::Applied && !owned.acknowledged_statements.is_empty() {
            owned.outcome = MysqlOutcome::Partial;
        }
        self.publish(batch, &owned)
            .map_err(|_| MysqlError::Unknown)?;
        let _ = conn.disconnect().await;
        Ok(owned.outcome)
    }
}
impl MysqlTransport for AwsRdsMysqlTransport {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn execute_guarded(
        &mut self,
        batch: &SqlBatch,
        guard: &mut BeforeMysqlWrite<'_>,
    ) -> Result<MysqlOutcome, MysqlError> {
        self.run(batch, Mode::Execute, Some(guard))
    }
    fn lifecycle_context(&self) -> Option<&MysqlLifecycleContext> {
        self.lifecycle.as_ref()
    }
    fn owned_receipt(&self) -> Option<MysqlOwnershipReceipt> {
        self.ownership.lock().ok()?.clone()
    }
    fn evidence_refs(&self) -> Vec<String> {
        self.owned_receipt()
            .map(|r| vec![r.hash()])
            .unwrap_or_default()
    }
    fn preflight(&mut self, batch: &SqlBatch) -> Result<(), MysqlError> {
        self.run(batch, Mode::Preflight, None).map(|_| ())
    }
    fn execute(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
        self.run(batch, Mode::Execute, None)
    }
    fn query(&mut self, batch: &SqlBatch) -> Result<MysqlOutcome, MysqlError> {
        self.run(batch, Mode::Query, None)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Preflight,
    Execute,
    Query,
}
fn update_delta(owned: &mut MysqlOwnershipReceipt, after: Vec<PrivilegeCheck>) {
    owned.added_privileges = after
        .iter()
        .filter(|p| !owned.before_privileges.contains(p))
        .cloned()
        .collect();
    owned.after_privileges = after;
}
pub(crate) fn connection_options(
    endpoint: &Endpoint,
    database: &str,
    user: &str,
    ssl: SslOpts,
) -> Opts {
    OptsBuilder::default()
        .ip_or_hostname(&endpoint.host)
        .tcp_port(endpoint.port)
        .db_name(Some(database))
        .user(Some(user))
        .ssl_opts(Some(ssl))
        .prefer_socket(false)
        .socket::<String>(None)
        .enable_cleartext_plugin(true)
        .max_allowed_packet(Some(1024 * 1024))
        .wait_timeout(Some(30))
        .stmt_cache_size(0)
        .connect_attributes(std::collections::HashMap::<String, String>::new())
        .into()
}
pub(crate) fn verified_tls(pem: &[u8]) -> Result<SslOpts, MysqlError> {
    if pem.is_empty() || pem.len() > 1_048_576 {
        return Err(MysqlError::Precondition);
    }
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MysqlError::Precondition)?;
    if certs.is_empty() {
        return Err(MysqlError::Precondition);
    }
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|_| MysqlError::Precondition)?;
    }
    Ok(SslOpts::default()
        .with_root_certs(vec![pem.to_vec().into()])
        .with_disable_built_in_roots(true))
}
fn hostname(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn validate_binding(
    t: &Target,
    b: &AwsMysqlTargetBinding,
    m: &AwsMysqlManagementIdentity,
    timeout: Duration,
) -> Result<(), MysqlError> {
    let aws = t.aws.as_ref().ok_or(MysqlError::Precondition)?;
    let mysql = t.mysql.as_ref().ok_or(MysqlError::Precondition)?;
    let arn: Vec<_> = b.db_instance_arn.splitn(6, ':').collect();
    let proxy = b.proxy_arn.as_ref().ok_or(MysqlError::Precondition)?;
    if t.placement.kind != PlacementKind::AwsRds
        || t.placement.region != "ap-northeast-1"
        || t.engine.family != EngineFamily::MySql
        || t.engine.version != "8.0.43"
        || b.database != t.engine.database
        || b.db_instance_arn != t.resource.native_id
        || b.dbi_resource_id != aws.db_resource_id
        || b.db_endpoint.host != aws.db_endpoint
        || b.management_endpoint.host != aws.proxy_endpoint
        || b.db_endpoint.port != 3306
        || b.management_endpoint.port != 3306
        || !hostname(&b.db_endpoint.host)
        || !hostname(&b.management_endpoint.host)
        || b.db_endpoint == b.management_endpoint
        || proxy != &aws.proxy_arn
        || b.proxy_name.as_deref() != Some(&aws.proxy_name)
        || b.proxy_role_arn.as_deref() != Some(&aws.proxy_role_arn)
        || b.proxy_role_id.as_deref() != Some(&aws.proxy_role_id)
        || m.db_username != aws.management_db_identity
        || !aws_role_arn(&m.role_arn, &t.placement.account_id)
        || !aws_role_id(&m.role_id)
        || !aws_role_arn(&aws.proxy_role_arn, &t.placement.account_id)
        || !aws_role_id(&aws.proxy_role_id)
        || arn.len() != 6
        || arn[0] != "arn"
        || arn[1] != "aws"
        || arn[2] != "rds"
        || arn[3] != t.placement.region
        || arn[4] != t.placement.account_id
        || !arn[5].starts_with("db:")
        || !proxy.starts_with(&format!(
            "arn:aws:rds:{}:{}:db-proxy:prx-",
            t.placement.region, t.placement.account_id
        ))
        || !b.dbi_resource_id.starts_with("db-")
        || b.dbi_resource_id.len() < 4
        || !b
            .dbi_resource_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        || !valid_login(&m.db_username)
        || !valid_account_host(&mysql.account_host)
        || !valid_account_host(&mysql.management_account_host)
        || timeout.is_zero()
        || timeout > Duration::from_secs(120)
    {
        return Err(MysqlError::Precondition);
    }
    let generation = crate::adapters::deployment::aws::generation_fingerprint(
        &t.placement.account_id,
        &t.placement.region,
        &b.db_instance_arn,
        &b.dbi_resource_id,
    );
    if t.resource.generation_fingerprint.as_deref() != Some(&generation) {
        return Err(MysqlError::Precondition);
    }
    Ok(())
}
pub(crate) async fn verify_session(
    conn: &mut Conn,
    database: &str,
    version: &str,
    user: &str,
    host: &str,
) -> Result<(), MysqlError> {
    verify_session_identity(conn, database, version, user, host).await?;
    let ssl: Option<(String, String)> = conn
        .query_first("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
        .await
        .map_err(|_| MysqlError::Precondition)?;
    if !ssl.is_some_and(|(key, value)| key == "Ssl_cipher" && !value.is_empty()) {
        return Err(MysqlError::Precondition);
    }
    Ok(())
}

pub(crate) async fn verify_session_identity(
    conn: &mut Conn,
    database: &str,
    version: &str,
    user: &str,
    host: &str,
) -> Result<(), MysqlError> {
    let row: Option<(String, String, String, u64)> = conn
        .query_first("SELECT CURRENT_USER(), DATABASE(), VERSION(), @@lower_case_table_names")
        .await
        .map_err(|_| MysqlError::Precondition)?;
    let Some((identity, db, v, case)) = row else {
        return Err(MysqlError::Precondition);
    };
    if identity != format!("{user}@{host}") || db != database || v != version || case != 0 {
        return Err(MysqlError::Precondition);
    }
    Ok(())
}
struct Account {
    locked: bool,
}
async fn verify_account(conn: &mut Conn, user: &str, host: &str) -> Result<Account, MysqlError> {
    let row:Option<(String,String,String)>=conn.exec_first("SELECT plugin, ssl_type, account_locked FROM mysql.user WHERE BINARY User = BINARY ? AND BINARY Host = BINARY ?",(user,host))
        .await.map_err(|_|MysqlError::Precondition)?;
    let Some((plugin, ssl, locked)) = row else {
        return Err(MysqlError::Precondition);
    };
    if plugin != "AWSAuthenticationPlugin"
        || !matches!(ssl.as_str(), "ANY" | "X509" | "SPECIFIED")
        || !matches!(locked.as_str(), "Y" | "N")
    {
        return Err(MysqlError::Precondition);
    }
    Ok(Account {
        locked: locked == "Y",
    })
}
async fn verify_exclusive_account(
    conn: &mut Conn,
    batch: &SqlBatch,
    management: &str,
) -> Result<(), MysqlError> {
    let ambiguous:Option<u64>=conn.exec_first("SELECT COUNT(*) FROM mysql.user WHERE User = '' OR (User = ? AND BINARY Host <> BINARY ?) OR (User = ? AND BINARY Host <> BINARY ?)",
        (&batch.login,&batch.account_host,management,&batch.management_account_host)).await.map_err(|_|MysqlError::Precondition)?;
    if ambiguous != Some(0) {
        return Err(MysqlError::Precondition);
    }
    let grantee = quote_account(&batch.login, &batch.account_host)?;
    for sql in [
        "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = ? AND PRIVILEGE_TYPE <> 'USAGE'",
        "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = ?",
        "SELECT COUNT(*) FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = ?",
    ] {
        let count: Option<u64> = conn
            .exec_first(sql, (&grantee,))
            .await
            .map_err(|_| MysqlError::Precondition)?;
        if count != Some(0) {
            return Err(MysqlError::Precondition);
        }
    }
    for sql in [
        "SELECT COUNT(*) FROM mysql.role_edges WHERE TO_USER = ? AND TO_HOST = ?",
        "SELECT COUNT(*) FROM mysql.global_grants WHERE USER = ? AND HOST = ?",
        "SELECT COUNT(*) FROM mysql.proxies_priv WHERE User = ? AND Host = ?",
        "SELECT COUNT(*) FROM mysql.procs_priv WHERE User = ? AND Host = ?",
    ] {
        let count: Option<u64> = conn
            .exec_first(sql, (&batch.login, &batch.account_host))
            .await
            .map_err(|_| MysqlError::Precondition)?;
        if count != Some(0) {
            return Err(MysqlError::Precondition);
        }
    }
    // A mandatory role would confer privileges without a role_edges row.
    let mandatory: Option<String> = conn
        .query_first("SELECT @@mandatory_roles")
        .await
        .map_err(|_| MysqlError::Precondition)?;
    if mandatory.as_deref() != Some("") {
        return Err(MysqlError::Precondition);
    }
    Ok(())
}
async fn capture_privileges(
    conn: &mut Conn,
    batch: &SqlBatch,
) -> Result<Vec<PrivilegeCheck>, MysqlError> {
    let grantee = quote_account(&batch.login, &batch.account_host)?;
    // LIMIT bounds memory even with an adversarial/broadly configured account.
    let rows:Vec<(String,String,String,String)>=conn.exec("SELECT TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = ? LIMIT 1025",(&grantee,))
        .await.map_err(|_|MysqlError::Precondition)?;
    if rows.len() > 1024 {
        return Err(MysqlError::Precondition);
    }
    let allowed = if batch.action != MysqlAction::ConfigureSqlPrivileges {
        // The prior complete snapshot contains both preexisting and added rights.
        // Revoke readback itself still examines only owned additions.
        None
    } else {
        Some(&batch.checks)
    };
    for (db, table, action, grantable) in &rows {
        if grantable != "NO"
            || db != &batch.database
            || !matches!(action.as_str(), "SELECT" | "INSERT" | "UPDATE" | "DELETE")
            || allowed.is_some_and(|checks| {
                !checks.iter().any(|c| {
                    c.database == *db && c.object.as_ref() == Some(table) && c.action == *action
                })
            })
        {
            return Err(MysqlError::Precondition);
        }
    }
    // Require exact case-sensitive base-table existence, excluding views.
    for check in &batch.checks {
        let found:Option<u64>=conn.exec_first("SELECT COUNT(*) FROM information_schema.TABLES WHERE BINARY TABLE_SCHEMA = BINARY ? AND BINARY TABLE_NAME = BINARY ? AND TABLE_TYPE = 'BASE TABLE'",(&check.database,check.object.as_deref().ok_or(MysqlError::Scope)?))
            .await.map_err(|_|MysqlError::Precondition)?;
        if found != Some(1) {
            return Err(MysqlError::Precondition);
        }
    }
    let checks = if let Some(checks) = allowed {
        checks.clone()
    } else {
        rows.iter()
            .map(|(db, table, action, _)| PrivilegeCheck {
                kind: SqlObjectKind::Table,
                database: db.clone(),
                object: Some(table.clone()),
                action: action.clone(),
            })
            .collect()
    };
    Ok(checks
        .into_iter()
        .filter(|c| {
            rows.iter().any(|(db, table, action, _)| {
                c.database == *db && c.object.as_ref() == Some(table) && c.action == *action
            })
        })
        .collect())
}
fn readback(batch: &SqlBatch, account: &Account, privileges: &[PrivilegeCheck]) -> MysqlOutcome {
    let applied = match batch.action {
        MysqlAction::RegisterNativeDbIdentity => !account.locked,
        MysqlAction::DisableNewConnections => account.locked,
        MysqlAction::ConfigureSqlPrivileges => {
            !account.locked && batch.checks.iter().all(|c| privileges.contains(c))
        }
        MysqlAction::RevokeSqlPrivileges => batch.checks.iter().all(|c| !privileges.contains(c)),
    };
    if applied {
        MysqlOutcome::Applied
    } else if matches!(
        batch.action,
        MysqlAction::ConfigureSqlPrivileges | MysqlAction::RevokeSqlPrivileges
    ) && !batch.checks.is_empty()
        && batch.checks.iter().any(|c| privileges.contains(c))
        && batch.checks.iter().any(|c| !privileges.contains(c))
    {
        MysqlOutcome::Partial
    } else {
        MysqlOutcome::NotApplied
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlAccessProbe {
    Allowed,
    Unknown,
}
/// Read-only, fixed query probe; caller supplies one frozen STS-proved
/// credential set. A generic MySQL 1045 never proves IAM denial.
#[allow(clippy::too_many_arguments)]
pub async fn probe_mysql_iam(
    endpoint: &Endpoint,
    database: &str,
    version: &str,
    user: &str,
    account_host: &str,
    region: &str,
    credentials: Credentials,
    root_ca_pem: &[u8],
    timeout: Duration,
    cancel: CancellationToken,
) -> MysqlAccessProbe {
    if !hostname(&endpoint.host)
        || endpoint.port != 3306
        || version != "8.0.43"
        || region != "ap-northeast-1"
        || !mysql_database(database)
        || !valid_login(user)
        || !valid_account_host(account_host)
        || timeout.is_zero()
        || timeout > Duration::from_secs(120)
    {
        return MysqlAccessProbe::Unknown;
    }
    let Ok(ssl) = verified_tls(root_ca_pem) else {
        return MysqlAccessProbe::Unknown;
    };
    let work = async {
        let token = sign_iam_token(credentials, endpoint, user, region, SystemTime::now())
            .map_err(|_| ())?;
        let opts = OptsBuilder::from_opts(connection_options(endpoint, database, user, ssl))
            .pass(Some(token.expose()));
        let mut conn = Conn::new(opts).await.map_err(|_| ())?;
        verify_session(&mut conn, database, version, user, account_host)
            .await
            .map_err(|_| ())?;
        let _ = conn.disconnect().await;
        Ok::<(), ()>(())
    };
    tokio::select! {biased;
        _=cancel.cancelled()=>MysqlAccessProbe::Unknown,
        result=tokio::time::timeout(timeout,work)=>if matches!(result,Ok(Ok(()))){MysqlAccessProbe::Allowed}else{MysqlAccessProbe::Unknown},
    }
}
