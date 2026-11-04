//! Native management path: explicit Cloud SQL Auth Proxy, automatic IAM, and
//! an ephemeral loopback socket. No arbitrary DSN, ADC override or SQL token file.
use super::*;
use crate::gcp::{
    live::{LiveTools, sanitized_environment},
    model::GcpConfig,
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::Path,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub struct ConnectorPgTransport {
    target: Target,
    config: GcpConfig,
    tools: LiveTools,
    management_service_account: String,
    timeout: Duration,
    cancel: CancellationToken,
    lifecycle: Option<PgLifecycleContext>,
    ownership: Mutex<Option<PgOwnershipReceipt>>,
}
impl ConnectorPgTransport {
    pub fn new(
        target: Target,
        config: GcpConfig,
        mut tools: LiveTools,
        management_service_account: String,
        timeout: Duration,
    ) -> Result<Self, PgError> {
        crate::gcp::config::validate_config(&config).map_err(|_| PgError::Precondition)?;
        let prefix = format!("projects/{}/instances/", target.placement.account_id);
        if target.placement.kind != PlacementKind::GcpCloudSql
            || target.engine.family != EngineFamily::PostgreSql
            || target.resource.generation_fingerprint.is_none()
            || target.resource.native_id != format!("{prefix}{}", config.target.instance_id)
            || target.placement.account_id != config.target.project_id
            || target.placement.region != config.target.region
            || target.engine.database != config.target.database
            || !management_service_account.ends_with(".iam.gserviceaccount.com")
            || management_service_account.len() > 128
            || !management_service_account
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            || management_service_account
                .bytes()
                .filter(|b| *b == b'@')
                .count()
                != 1
            || timeout.is_zero()
            || timeout > Duration::from_secs(120)
        {
            return Err(PgError::Precondition);
        }
        tools.gcloud = explicit_executable(&tools.gcloud)?;
        tools.proxy = explicit_executable(&tools.proxy)?;
        // Proxy's --gcloud-auth helper resolves the literal name `gcloud`.
        // Ensure PATH reaches precisely the reviewed executable, rather than
        // falling through to a different installed SDK binary.
        if tools
            .gcloud
            .parent()
            .ok_or(PgError::Precondition)?
            .join("gcloud")
            .canonicalize()
            .map_err(|_| PgError::Precondition)?
            != tools.gcloud
        {
            return Err(PgError::Precondition);
        }
        Ok(Self {
            target,
            config,
            tools,
            management_service_account,
            timeout,
            cancel: CancellationToken::new(),
            lifecycle: None,
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
    /// Reviewable argv builder; neither this method nor construction spawns a
    /// process. Tests exercise it without a cloud account or a database.
    pub fn proxy_arguments(&self, port: u16) -> Vec<String> {
        vec![
            "--gcloud-auth".into(),
            "--auto-iam-authn".into(),
            "--address=127.0.0.1".into(),
            format!("--port={port}"),
            "--structured-logs".into(),
            format!("--quota-project={}", self.target.placement.account_id),
            format!(
                "--impersonate-service-account={}",
                self.management_service_account
            ),
            format!(
                "{}:{}:{}",
                self.target.placement.account_id,
                self.target.placement.region,
                self.config.target.instance_id
            ),
        ]
    }
    pub fn environment(
        &self,
        inherited: &BTreeMap<OsString, OsString>,
    ) -> Result<BTreeMap<OsString, OsString>, PgError> {
        sanitized_environment(&self.tools, inherited).map_err(|_| PgError::Precondition)
    }
    fn run(
        &self,
        batch: &SqlBatch,
        mode: u8,
        mut guard: Option<&mut BeforeSqlWrite<'_>>,
    ) -> Result<PgOutcome, PgError> {
        if batch.target_hash
            != crate::config::hash_bytes(
                &serde_json::to_vec(&self.target).map_err(|_| PgError::Scope)?,
            )
        {
            return Err(PgError::Precondition);
        }
        if self.cancel.is_cancelled() {
            return Err(PgError::Unavailable);
        }
        let environment = self.environment(&std::env::vars_os().collect())?;
        std::thread::scope(|scope| {
            scope.spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| PgError::Unavailable)?;
            runtime.block_on(async {
                let deadline = Instant::now() + self.timeout;
                // SDK config, endpoint overrides and actual native metadata
                // are checked using the established read-only capture path.
                let snapshot = crate::gcp::live::inspect(&self.config, &self.tools, self.cancel.clone(), deadline).await.map_err(|_| PgError::Precondition)?;
                let expected = self.proxy_arguments(1).last().cloned().ok_or(PgError::Precondition)?;
                if snapshot.connection_name != expected { return Err(PgError::Precondition); }
                let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(|_| PgError::Unavailable)?;
                let port = listener.local_addr().map_err(|_| PgError::Unavailable)?.port();
                drop(listener);
                let mut command = Command::new(&self.tools.proxy);
                command.args(self.proxy_arguments(port)).env_clear().envs(environment).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
                #[cfg(unix)] { use std::os::unix::process::CommandExt; command.as_std_mut().process_group(0); }
                let child = command.spawn().map_err(|_| PgError::Unavailable)?;
                let mut process = ProxyProcess { child, readers: vec![] };
                let ready = Arc::new(AtomicBool::new(false));
                let exceeded = Arc::new(AtomicBool::new(false));
                let stdout = process.child.stdout.take().ok_or(PgError::Unavailable)?;
                let stderr = process.child.stderr.take().ok_or(PgError::Unavailable)?;
                process.readers.push(tokio::spawn(drain(stdout, port, ready.clone(), exceeded.clone())));
                process.readers.push(tokio::spawn(drain(stderr, port, ready.clone(), exceeded.clone())));
                let work = async {
                    while !ready.load(Ordering::Acquire) {
                        if exceeded.load(Ordering::Acquire) || process.child.try_wait().map_err(|_| PgError::Unavailable)?.is_some() { return Err(PgError::Unavailable); }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    let username = self.management_service_account.strip_suffix(".gserviceaccount.com").ok_or(PgError::Precondition)?;
                    let mut config = tokio_postgres::Config::new();
                    config.host("127.0.0.1").port(port).user(username).dbname(&batch.database).connect_timeout(self.timeout).ssl_mode(tokio_postgres::config::SslMode::Disable);
                    let (mut client, connection) = config.connect(tokio_postgres::NoTls).await.map_err(|_| PgError::Unavailable)?;
                    let connection = tokio::spawn(async move { let _ = connection.await; });
                    let result = async {
                        let row = client.query_one("SELECT session_user, current_user", &[]).await.map_err(|_| PgError::Precondition)?;
                        if row.get::<_, String>(0) != username || row.get::<_, String>(1) != username { return Err(PgError::Precondition); }
                        let tx = client.transaction().await.map_err(|_| PgError::Unavailable)?;
                        tx.batch_execute("SET LOCAL search_path = pg_catalog; SET LOCAL lock_timeout = '5s'; SET LOCAL statement_timeout = '30s'").await.map_err(|_| PgError::Precondition)?;
                        if mode != 1 { tx.batch_execute("SET TRANSACTION READ ONLY").await.map_err(|_| PgError::Precondition)?; }
                        verify_identity(&tx, batch).await?;
                        verify_revoke_preconditions(&tx, batch).await?;
                        if mode == 0 { return Ok(PgOutcome::NotApplied); }
                        if mode == 1 { *self.ownership.lock().map_err(|_| PgError::Unavailable)? = None; }
                        let before = if mode == 1 && batch.action == PgAction::ConfigureSqlPrivileges { Some(capture_ownership(&tx, batch).await?) } else { None };
                        if mode == 1 { for statement in &batch.statements { if let Some(g)=guard.as_mut(){g()?;} tx.batch_execute(statement).await.map_err(|_| PgError::Precondition)?; } }
                        let applied = readback(&tx, batch).await?;
                        let owned = if let Some(before) = before { Some(ownership_delta(&before, capture_ownership(&tx, batch).await?)) } else { None };
                        if mode == 1 {
                            if !applied { tx.rollback().await.map_err(|_| PgError::Unknown)?; return Ok(PgOutcome::NotApplied); }
                            if let Some(g)=guard.as_mut(){g()?;}
                            tx.commit().await.map_err(|_| PgError::Unknown)?;
                            // Persistence only makes a later removal possible. A failed
                            // artifact write never reverses an already committed GRANT.
                            if let Some(owned) = owned && self.persist_ownership(batch, &owned).is_ok() {
                                *self.ownership.lock().map_err(|_| PgError::Unknown)? = Some(owned);
                            }
                        }
                        if exceeded.load(Ordering::Acquire) { return Err(PgError::Unknown); }
                        Ok(if applied { PgOutcome::Applied } else { PgOutcome::NotApplied })
                    }.await;
                    connection.abort();
                    result
                };
                let result=tokio::select! {biased; _=self.cancel.cancelled()=>Err(PgError::Unknown), result=tokio::time::timeout_at(deadline,work)=>result.unwrap_or(Err(PgError::Unknown))};
                process.stop().await;
                result
            })
        }).join().map_err(|_| PgError::Unknown)?
        })
    }
}
impl ConnectorPgTransport {
    fn persist_ownership(
        &self,
        batch: &SqlBatch,
        owned: &PgOwnershipReceipt,
    ) -> Result<(), PgError> {
        let path = self
            .tools
            .work_dir
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
}
impl PgTransport for ConnectorPgTransport {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn lifecycle_context(&self) -> Option<&PgLifecycleContext> {
        self.lifecycle.as_ref()
    }
    fn owned_receipt(&self) -> Option<PgOwnershipReceipt> {
        self.ownership.lock().ok()?.clone()
    }

    fn preflight(&mut self, batch: &SqlBatch) -> Result<(), PgError> {
        self.run(batch, 0, None).map(|_| ())
    }
    fn execute_atomic(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.run(batch, 1, None)
    }
    fn execute_atomic_guarded(
        &mut self,
        batch: &SqlBatch,
        guard: &mut BeforeSqlWrite<'_>,
    ) -> Result<PgOutcome, PgError> {
        self.run(batch, 1, Some(guard))
    }
    fn query(&mut self, batch: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.run(batch, 2, None)
    }
}
fn explicit_executable(path: &Path) -> Result<std::path::PathBuf, PgError> {
    if !path.is_absolute() {
        return Err(PgError::Precondition);
    }
    let path = path.canonicalize().map_err(|_| PgError::Unavailable)?;
    let meta = path.metadata().map_err(|_| PgError::Unavailable)?;
    if !meta.is_file() {
        return Err(PgError::Precondition);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(PgError::Precondition);
        }
    }
    Ok(path)
}
struct ProxyProcess {
    child: Child,
    readers: Vec<tokio::task::JoinHandle<()>>,
}
impl ProxyProcess {
    fn kill(&mut self) {
        #[cfg(unix)]
        if let Some(id) = self.child.id().and_then(|id| i32::try_from(id).ok()) {
            unsafe {
                libc::kill(-id, libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
    }
    async fn stop(&mut self) {
        self.kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
        for reader in &self.readers {
            reader.abort();
        }
    }
}
impl Drop for ProxyProcess {
    fn drop(&mut self) {
        self.kill();
        for reader in &self.readers {
            reader.abort();
        }
    }
}
async fn drain<R: tokio::io::AsyncRead + Unpin>(
    stream: R,
    port: u16,
    ready: Arc<AtomicBool>,
    exceeded: Arc<AtomicBool>,
) {
    let mut stream = BufReader::new(stream);
    let mut bytes = 0usize;
    loop {
        // fill_buf bounds each chunk even if a child writes no newline. Raw
        // diagnostics are discarded and never exposed in structured errors.
        let mut line = vec![];
        let mut done = false;
        while !done {
            let chunk = match stream.fill_buf().await {
                Ok(chunk) if !chunk.is_empty() => chunk,
                _ => return,
            };
            let count = chunk
                .iter()
                .position(|b| *b == b'\n')
                .map_or(chunk.len(), |n| {
                    done = true;
                    n + 1
                });
            bytes = bytes.saturating_add(count);
            if bytes > 1_048_576 || line.len() + count > 16_384 {
                exceeded.store(true, Ordering::Release);
                return;
            }
            line.extend_from_slice(&chunk[..count]);
            stream.consume(count);
        }
        let parsed = serde_json::from_slice::<serde_json::Value>(&line).ok();
        let message = parsed
            .as_ref()
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if message
            .split_once("Listening on ")
            .is_some_and(|(_, address)| address.trim() == format!("127.0.0.1:{port}"))
        {
            ready.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn proxy_diagnostics_are_bounded_and_only_exact_loopback_marks_ready() {
        let ready = Arc::new(AtomicBool::new(false));
        let exceeded = Arc::new(AtomicBool::new(false));
        let wrong = b"{\"message\":\"[target] Listening on 0.0.0.0:1234\"}\n";
        drain(&wrong[..], 1234, ready.clone(), exceeded.clone()).await;
        assert!(!ready.load(Ordering::Acquire));
        let correct = b"{\"message\":\"[target] Listening on 127.0.0.1:1234\"}\n";
        drain(&correct[..], 1234, ready.clone(), exceeded.clone()).await;
        assert!(ready.load(Ordering::Acquire));
        let large = vec![b'x'; 16_385];
        drain(&large[..], 1234, ready, exceeded.clone()).await;
        assert!(exceeded.load(Ordering::Acquire));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn fake_proxy_cleanup_kills_and_reaps_the_local_process_group() {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "while :; do sleep 1; done"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        command.as_std_mut().process_group(0);
        let child = command.spawn().unwrap();
        let pid = child.id().unwrap();
        let mut process = ProxyProcess {
            child,
            readers: vec![],
        };
        process.stop().await;
        assert!(process.child.try_wait().unwrap().is_some());
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }
}
