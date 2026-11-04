//! Opt-in collector-side reads. Fixed metadata/SQLAdmin origins, fixed pinned
//! proxy, private Unix IPC, and catalog-only repeatable-read transactions.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::{collector, gce_host::*, postgres::*, process};
use crate::core::{admission::IssuedObservation, evidence::*, policy::*};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

// Debug/Serialize deliberately absent. Tokens exist only in bounded process
// memory and the explicitly scrubbed proxy environment, never argv/artifacts.
#[derive(Deserialize)]
pub(super) struct AccessToken {
    pub(super) access_token: String,
    token_type: String,
    expires_in: u64,
}
impl AccessToken {
    fn parse(bytes: &[u8]) -> Result<Self, SourceError> {
        let t: Self = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
        if t.token_type != "Bearer"
            || t.expires_in < 60
            || t.expires_in > 86400
            || t.access_token.is_empty()
            || t.access_token.len() > 16384
            || !t
                .access_token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.~+/=".contains(&b))
        {
            return Err(SourceError::Invalid);
        }
        Ok(t)
    }
}
pub(super) async fn token(
    i: &IssuedObservation,
    scope: &str,
    cancel: &CancellationToken,
) -> Result<AccessToken, SourceError> {
    let mut path =
        url::Url::parse("http://169.254.169.254/computeMetadata/v1/instance/service-accounts/")
            .map_err(|_| SourceError::Invalid)?;
    path.path_segments_mut()
        .map_err(|_| SourceError::Invalid)?
        .push(
            &i.snapshot
                .gce()
                .ok_or(SourceError::Unsupported)?
                .native_identity
                .service_account,
        )
        .push("token");
    path.query_pairs_mut()
        .append_pair("enforce_scopes", "true")
        .append_pair("scopes", scope);
    trusted_program(Path::new("/usr/bin/curl"))?;
    let args = vec![
        "-q".into(),
        "--noproxy".into(),
        "*".into(),
        "--proto".into(),
        "=http".into(),
        "--max-time".into(),
        "5".into(),
        "--max-filesize".into(),
        "32768".into(),
        "--include".into(),
        "--silent".into(),
        "--fail".into(),
        "--header".into(),
        "Metadata-Flavor: Google".into(),
        path.to_string(),
    ];
    let bytes = process::run(Path::new("/usr/bin/curl"), &args, &[], 32768, 5, cancel).await?;
    AccessToken::parse(&collector::metadata_body(&bytes)?)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiInstance {
    project: String,
    name: String,
    region: String,
    connection_name: String,
    create_time: String,
    database_version: String,
    ip_addresses: Vec<ApiIp>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiIp {
    r#type: String,
    ip_address: String,
}
fn parse_instance(bytes: &[u8]) -> Result<InstanceIdentity, SourceError> {
    let a: ApiInstance = serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
    let ips: Vec<_> = a
        .ip_addresses
        .iter()
        .filter(|ip| ip.r#type == "PRIVATE")
        .collect();
    if ips.len() != 1 || a.create_time.is_empty() || a.create_time.len() > 64 {
        return Err(SourceError::Invalid);
    }
    let private_ip = ips[0]
        .ip_address
        .parse()
        .map_err(|_| SourceError::Invalid)?;
    Ok(InstanceIdentity {
        project: a.project,
        name: a.name,
        region: a.region,
        connection_name: a.connection_name,
        create_time: a.create_time,
        database_version: a.database_version,
        private_ip,
    })
}
fn api_args(project: &str, name: &str) -> Vec<String> {
    vec![
        "-q".into(),
        "--noproxy".into(),
        "*".into(),
        "--proto".into(),
        "=https".into(),
        "--max-time".into(),
        "5".into(),
        "--max-filesize".into(),
        "65536".into(),
        "--silent".into(),
        "--fail".into(),
        "--header".into(),
        "@-".into(),
        format!("https://sqladmin.googleapis.com/sql/v1beta4/projects/{project}/instances/{name}"),
    ]
}
pub(super) async fn instance(
    c: &RequestedCase,
    t: &AccessToken,
    cancel: &CancellationToken,
) -> Result<InstanceIdentity, SourceError> {
    let project = &c.address.target.placement.account_id;
    let prefix = format!("projects/{project}/instances/");
    let name = c
        .address
        .target
        .native_ref
        .native_id
        .strip_prefix(&prefix)
        .ok_or(SourceError::Invalid)?;
    if [project.as_str(), name].iter().any(|s| {
        s.is_empty() || s.len() > 128 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return Err(SourceError::Invalid);
    }
    let header = format!("Authorization: Bearer {}\n", t.access_token);
    let bytes = process::run(
        Path::new("/usr/bin/curl"),
        &api_args(project, name),
        header.as_bytes(),
        65536,
        5,
        cancel,
    )
    .await?;
    parse_instance(&bytes)
}
#[cfg(unix)]
struct WorkDirectory(PathBuf);
#[cfg(unix)]
impl WorkDirectory {
    fn create(i: &IssuedObservation, index: usize) -> Result<Self, SourceError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let root = std::fs::symlink_metadata("/run").map_err(|_| SourceError::Unavailable)?;
        if !root.is_dir() || root.uid() != 0 || root.mode() & 0o022 != 0 {
            return Err(SourceError::Integrity);
        }
        let path = PathBuf::from(format!("/run/veil-pg-{}-{index}", &i.request.nonce[..16]));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| SourceError::Unavailable)?;
        Ok(Self(path))
    }
}
#[cfg(unix)]
impl Drop for WorkDirectory {
    fn drop(&mut self) {
        // Only an exclusively created private directory under trusted /run.
        // No caller-supplied cleanup paths and no recursive foreign traversal.
        let _ = std::fs::remove_file(self.0.join(".s.PGSQL.5432"));
        let _ = std::fs::remove_file(self.0.join(".s.PGSQL.5432.lock"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
struct Proxy {
    child: Child,
    group: process::ProcessGroup,
}
impl Proxy {
    async fn stop(&mut self) {
        self.group.kill();
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
    }
}
fn version_matches(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| {
        s.trim()
            .strip_prefix("cloud-sql-proxy version ")
            .is_some_and(|version| {
                let (base, metadata) = version.split_once('+').unwrap_or((version, ""));
                base == PROXY_VERSION
                    && metadata
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            })
    })
}

fn proxy_args(connection: &str, dir: &Path) -> Vec<String> {
    vec![
        "--auto-iam-authn".into(),
        "--private-ip".into(),
        "--lazy-refresh".into(),
        "--max-connections=1".into(),
        "--quiet".into(),
        format!("{connection}?unix-socket-path={}", dir.display()),
    ]
}
fn bound_proxy_args(
    connection: &str,
    dir: &Path,
    i: &IssuedObservation,
    c: &RequestedCase,
    audit_enabled: bool,
) -> Vec<String> {
    let mut args = proxy_args(connection, dir);
    if audit_enabled {
        args.push(format!("--user-agent={}", super::denial::marker(i, c)));
    }
    args
}
fn proxy_command(args: &[String], api: &AccessToken, login: &AccessToken) -> Command {
    let mut c = Command::new(PROXY_PATH);
    c.args(args)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("CSQL_PROXY_TOKEN", &api.access_token)
        .env("CSQL_PROXY_LOGIN_TOKEN", &login.access_token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(unix)]
    c.process_group(0);
    c
}
struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn pg_error(o: &mut PgObservation, e: &tokio_postgres::Error) {
    o.sqlstate = e.code().map(|c| c.code().into());
}

#[cfg(unix)]
pub(super) async fn observe(
    i: &IssuedObservation,
    c: &RequestedCase,
    endpoint: &CollectorEndpoint,
    config: &PostgresCollectorConfig,
    index: usize,
    budget: u64,
    cancel: &CancellationToken,
) -> Result<PgObservation, SourceError> {
    config.validate()?;
    if c.address.route.kind != RouteKind::NativeConnector
        || c.address.target.placement.kind != PlacementKind::GcpCloudSql
        || c.address.target.engine_binding.family != EngineFamily::PostgreSql
        || c.address.target.engine_binding.version != "16.15"
        || c.address.target.placement.region != "asia-northeast1"
        || c.address.db_identity
            != i.snapshot
                .gce()
                .ok_or(SourceError::Unsupported)?
                .native_identity
                .service_account
                .strip_suffix(".gserviceaccount.com")
                .ok_or(SourceError::Invalid)?
    {
        return Err(SourceError::Unsupported);
    }
    trusted_program(Path::new(PROXY_PATH))?;
    {
        use std::os::unix::fs::MetadataExt;
        for path in Path::new(PROXY_PATH).ancestors() {
            let m = std::fs::symlink_metadata(path).map_err(|_| SourceError::Unavailable)?;
            if m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(SourceError::Integrity);
            }
        }
    }
    if collector::file_digest(Path::new(PROXY_PATH), 128 * 1024 * 1024)? != config.proxy_sha256 {
        return Err(SourceError::Integrity);
    }
    let version = process::run(
        Path::new(PROXY_PATH),
        &["--version".into()],
        &[],
        4096,
        3,
        cancel,
    )
    .await?;
    if !version_matches(&version) {
        return Err(SourceError::Integrity);
    }
    let mut observation = PgObservation::failed(i, &config.proxy_sha256);
    let work = async {
        let api = token(i, "https://www.googleapis.com/auth/cloud-platform", cancel).await?;
        let login = token(
            i,
            "https://www.googleapis.com/auth/sqlservice.login",
            cancel,
        )
        .await?;
        observation.stage = PgStage::InstanceMetadata;
        let before = instance(c, &api, cancel).await?;
        observation.instance_before = Some(before.clone());
        if !before.matches(c) || before.private_ip != endpoint.ip {
            // This case is unconfirmed; earlier independent Allowed samples
            // remain available rather than being discarded as source failures.
            return Err(SourceError::Invalid);
        }
        observation.stage = PgStage::ProxyStartup;
        let dir = WorkDirectory::create(i, index)?;
        let args = bound_proxy_args(
            &before.connection_name,
            &dir.0,
            i,
            c,
            config.collect_connect_denial_audit,
        );
        let attempt_start = crate::domain::now();
        let child = proxy_command(&args, &api, &login)
            .spawn()
            .map_err(|_| SourceError::Unavailable)?;
        let group = process::ProcessGroup::new(child.id());
        let mut proxy = Proxy { child, group };
        let session_work = async {
            let deadline = Instant::now() + Duration::from_secs(10);
            let socket = dir.0.join(".s.PGSQL.5432");
            loop {
                if proxy.child.try_wait().map_err(|_| SourceError::Unavailable)?.is_some() {
                    return Err(SourceError::Unavailable);
                }
                if let Ok(m) = std::fs::symlink_metadata(&socket) {
                    use std::os::unix::fs::{MetadataExt, FileTypeExt};
                    if !m.file_type().is_socket() || m.uid() != 0 {
                        return Err(SourceError::Integrity);
                    }
                    break;
                }
                if Instant::now() >= deadline {return Err(SourceError::TimedOut);}
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            observation.stage = PgStage::Connect;
            let mut pg = tokio_postgres::Config::new();
            pg.host_path(&dir.0).user(&c.address.db_identity)
                .dbname(&c.address.target.engine_binding.database)
                .application_name("veil-db-guard-observation-v2")
                .connect_timeout(Duration::from_secs(10))
                .options("-c default_transaction_read_only=on -c search_path=pg_catalog -c statement_timeout=3000 -c lock_timeout=1000");
            let connected = tokio::time::timeout(Duration::from_secs(10), pg.connect(tokio_postgres::NoTls))
                .await.map_err(|_| SourceError::TimedOut)?;
            let (mut client, connection) = match connected {
                Ok(connection) => connection,
                Err(error) => {
                    pg_error(&mut observation, &error);
                    observation.login_rejection = super::postgres_login::recognize(&error, &c.address.db_identity);
                    return Ok(());
                }
            };
            observation.connected = true;
            let _connection = ConnectionTask(tokio::spawn(async move {let _ = connection.await;}));
            observation.stage = PgStage::Catalog;
            match catalog(&mut client, c).await {
                Ok(selected) => {observation.catalog = Some(selected); observation.stage = PgStage::Completed;}
                Err(error) => pg_error(&mut observation, &error),
            }
            Ok(())
        }.await;
        proxy.stop().await;
        drop(dir);
        // Keep connection success if a later read fails. Target assurance needs
        // both independent authenticated reads; pg_stat_ssl cannot replace them.
        observation.instance_after = instance(c, &api, cancel).await.ok();
        if config.collect_connect_denial_audit
            && !observation.connected
            && observation.stage == PgStage::Connect
            && c.address.effect == EffectKindV2::NewConnections
        {
            let attempt_end = crate::domain::now();
            // No polling loop or permission fallback. Delivery delays and read
            // permission failures remain unconfirmed in this capture.
            observation.connect_denial = super::denial::collect_connect_denial(
                i,
                c,
                &api.access_token,
                attempt_start,
                attempt_end,
                cancel,
            )
            .await
            .ok()
            .flatten();
        }
        session_work
    };
    let result = tokio::time::timeout(Duration::from_secs(budget.min(30)), work).await;
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    match result {
        Err(_) | Ok(Err(SourceError::TimedOut)) => observation.stage = PgStage::Deadline,
        Ok(Err(SourceError::Integrity)) => return Err(SourceError::Integrity),
        _ => {}
    }
    Ok(observation)
}

const SESSION_SQL: &str = "SELECT session_user::text,current_user::text,current_database()::text,current_setting('server_version_num')::int,r.oid,r.rolcanlogin,(SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_backend_pid()) FROM pg_catalog.pg_roles r WHERE r.rolname=session_user";
const ROLES_SQL: &str = "SELECT oid,rolname::text,pg_catalog.pg_has_role(session_user,oid,'USAGE') FROM pg_catalog.pg_roles WHERE pg_catalog.pg_has_role(session_user,oid,'USAGE') OR pg_catalog.pg_has_role(session_user,oid,'SET') ORDER BY oid LIMIT 129";
pub(super) async fn catalog(
    client: &mut tokio_postgres::Client,
    c: &RequestedCase,
) -> Result<PgCatalog, tokio_postgres::Error> {
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let r = tx.query_one(SESSION_SQL, &[]).await?;
    let mut selected = PgCatalog {
        session_user: r.try_get(0)?,
        current_user: r.try_get(1)?,
        database: r.try_get(2)?,
        server_version_num: r.try_get(3)?,
        login_oid: r.try_get(4)?,
        login_can_login: r.try_get(5)?,
        backend_ssl: r.try_get(6)?,
        login_catalog: vec![],
        active_roles: vec![],
        object_oid: None,
        object_kind: None,
        effective_privilege: None,
        roles_complete: false,
    };
    let roles = tx.query(ROLES_SQL, &[]).await?;
    selected.roles_complete = roles.len() <= 128;
    for role in roles.iter().take(128) {
        let usable: bool = role.try_get(2)?;
        let name: String = role.try_get(1)?;
        if name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || name.contains("://")
            || name.contains("${")
            || name.contains("{{")
            || ["password=", "pwd=", "token=", "secret="]
                .iter()
                .any(|s| name.to_ascii_lowercase().contains(s))
        {
            selected.roles_complete = false;
            continue;
        }
        if usable {
            selected.active_roles.push(name)
        }
    }
    if let EffectKindV2::EffectiveSqlRole { role } = &c.address.effect {
        let found = tx
            .query_opt(
                "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=$1::text",
                &[role],
            )
            .await?;
        if let Some(r) = found {
            let oid: u32 = r.try_get(0)?;
            selected.object_oid = Some(oid);
            let row=tx.query_one("SELECT pg_catalog.pg_has_role(session_user,$1::oid,'USAGE') OR pg_catalog.pg_has_role(session_user,$1::oid,'SET')",&[&oid]).await?;
            selected.effective_privilege = Some(row.try_get(0)?);
        }
    }
    if let EffectKindV2::EffectiveSqlPrivilege { scope, action } = &c.address.effect {
        let query = match scope.kind {
            SqlObjectKind::Database => Some((
                "SELECT oid FROM pg_catalog.pg_database WHERE datname=$1::text",
                scope.database.clone(),
            )),
            SqlObjectKind::Schema => Some((
                "SELECT oid FROM pg_catalog.pg_namespace WHERE nspname=$1::text",
                scope.schema.clone().unwrap_or_default(),
            )),
            _ => None,
        };
        let object = if let Some((sql, name)) = query {
            tx.query_opt(sql, &[&name]).await?
        } else if scope.kind == SqlObjectKind::Table {
            tx.query_opt("SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname=$1::text AND c.relname=$2::text AND c.relkind IN ('r','p','v','m','f')",&[&scope.schema,&scope.object]).await?
        } else {
            None
        };
        if let Some(o) = object {
            let oid: u32 = o.try_get(0)?;
            selected.object_oid = Some(oid);
            selected.object_kind = Some(scope.kind);
            let acl = match (scope.kind, action) {
                (SqlObjectKind::Database, SqlAction::Connect) => Some((
                    "SELECT pg_catalog.has_database_privilege($1::oid,$2::oid,$3::text)",
                    "CONNECT",
                )),
                (SqlObjectKind::Schema, SqlAction::Usage) => Some((
                    "SELECT pg_catalog.has_schema_privilege($1::oid,$2::oid,$3::text)",
                    "USAGE",
                )),
                (SqlObjectKind::Table, SqlAction::Read) => Some((
                    "SELECT pg_catalog.has_table_privilege($1::oid,$2::oid,$3::text) OR pg_catalog.has_any_column_privilege($1::oid,$2::oid,$3::text)",
                    "SELECT",
                )),
                (SqlObjectKind::Table, SqlAction::Insert) => Some((
                    "SELECT pg_catalog.has_table_privilege($1::oid,$2::oid,$3::text) OR pg_catalog.has_any_column_privilege($1::oid,$2::oid,$3::text)",
                    "INSERT",
                )),
                (SqlObjectKind::Table, SqlAction::Update) => Some((
                    "SELECT pg_catalog.has_table_privilege($1::oid,$2::oid,$3::text) OR pg_catalog.has_any_column_privilege($1::oid,$2::oid,$3::text)",
                    "UPDATE",
                )),
                (SqlObjectKind::Table, SqlAction::Delete) => Some((
                    "SELECT pg_catalog.has_table_privilege($1::oid,$2::oid,$3::text)",
                    "DELETE",
                )),
                _ => None,
            };
            if let Some((sql, privilege)) = acl {
                let mut present = false;
                for r in roles.iter().take(128) {
                    let role_oid: u32 = r.try_get(0)?;
                    let row = tx.query_one(sql, &[&role_oid, &oid, &privilege]).await?;
                    present |= row.try_get::<_, bool>(0)?;
                }
                selected.effective_privilege = Some(present);
            }
        }
    }
    selected.login_catalog =
        super::postgres_login::read_catalog(&tx, &c.login_catalog_targets).await?;
    tx.rollback().await?;
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn access_tokens_are_bounded_and_never_in_proxy_arguments_or_inherited_adc() {
        let secret = "PRIVATE-SENTINEL";
        let bytes =
            format!(r#"{{"access_token":"{secret}","token_type":"Bearer","expires_in":3600}}"#);
        let t = AccessToken::parse(bytes.as_bytes()).unwrap();
        let args = proxy_args(
            "project:asia-northeast1:instance",
            Path::new("/run/private"),
        );
        assert!(!args.join(" ").contains(secret));
        assert!(
            !args
                .iter()
                .any(|a| a.contains("gcloud") || a.contains("credentials"))
        );
        let cmd = proxy_command(&args, &t, &t);
        let env: Vec<_> = cmd
            .as_std()
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().to_string())
            .collect();
        assert_eq!(
            env,
            vec![
                "CSQL_PROXY_LOGIN_TOKEN",
                "CSQL_PROXY_TOKEN",
                "LANG",
                "LC_ALL",
                "PATH"
            ]
        );
        for invalid in [
            bytes.replace("3600", "0"),
            bytes.replace("Bearer", "Other"),
            bytes.replace(secret, "PRIVATE\nSENTINEL"),
            bytes.replace(secret, &"x".repeat(16385)),
        ] {
            assert!(AccessToken::parse(invalid.as_bytes()).is_err());
        }
        assert!(!api_args("project", "instance").join(" ").contains(secret));
        assert!(api_args("project", "instance").contains(&"@-".into()));
    }
    #[test]
    fn audit_correlation_is_opt_in_nonce_case_bound_and_passed_only_as_fixed_argument() {
        let (i, c, _) = super::super::postgres::tests::sample();
        let connection = "project:asia-northeast1:instance";
        let dir = Path::new("/run/private");
        assert_eq!(
            bound_proxy_args(connection, dir, &i, &c, false),
            proxy_args(connection, dir)
        );
        let args = bound_proxy_args(connection, dir, &i, &c, true);
        assert_eq!(
            args.last().unwrap(),
            &format!("--user-agent={}", super::super::denial::marker(&i, &c))
        );
        assert!(!args.join(" ").contains(&i.request.nonce));
        let mut other = c.clone();
        other.id = "other-case".into();
        assert_ne!(args, bound_proxy_args(connection, dir, &i, &other, true));
        assert!(
            !args
                .iter()
                .any(|a| a.contains("impersonate") || a.contains("credentials"))
        );
    }
    #[test]
    fn api_selection_requires_one_private_ip_and_duplicate_known_fields_are_rejected() {
        let bytes=br#"{"project":"p","name":"i","region":"r","connectionName":"p:r:i","createTime":"2026-01-01T00:00:00Z","databaseVersion":"POSTGRES_16","ipAddresses":[{"type":"PRIVATE","ipAddress":"10.0.0.1"}],"unknownProviderField":"ignored"}"#;
        assert_eq!(
            parse_instance(bytes).unwrap().private_ip,
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(
            parse_instance(
                text.replace(
                    "\"project\":\"p\"",
                    "\"project\":\"p\",\"project\":\"other\""
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(parse_instance(text.replace("PRIVATE", "PRIMARY").as_bytes()).is_err());
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const OBSERVED_LOGIN: &str = "app'; ALTER ROLE recovery NOLOGIN; --";
    fn message(kind: u8, body: &[u8], out: &mut Vec<u8>) {
        out.push(kind);
        out.extend(((body.len() + 4) as u32).to_be_bytes());
        out.extend(body);
    }
    fn row_description(types: &[u32]) -> Vec<u8> {
        let mut out = vec![];
        out.extend((types.len() as i16).to_be_bytes());
        for (index, t) in types.iter().enumerate() {
            out.extend(format!("col{index}\0").as_bytes());
            out.extend(0u32.to_be_bytes());
            out.extend(0i16.to_be_bytes());
            out.extend(t.to_be_bytes());
            out.extend((-1i16).to_be_bytes());
            out.extend((-1i32).to_be_bytes());
            out.extend(0i16.to_be_bytes());
        }
        out
    }
    fn data_row(values: &[Option<Vec<u8>>]) -> Vec<u8> {
        let mut b = vec![];
        b.extend((values.len() as i16).to_be_bytes());
        for v in values {
            if let Some(v) = v {
                b.extend((v.len() as i32).to_be_bytes());
                b.extend(v)
            } else {
                b.extend((-1i32).to_be_bytes())
            }
        }
        b
    }
    fn strings(body: &[u8]) -> (String, String) {
        let mut s = body.split(|b| *b == 0);
        (
            String::from_utf8(s.next().unwrap().to_vec()).unwrap(),
            String::from_utf8(s.next().unwrap().to_vec()).unwrap(),
        )
    }
    fn result(sql: &str, user: &str) -> (Vec<u32>, Vec<Option<Vec<u8>>>, Vec<u32>) {
        if sql == super::super::postgres_login::LOGIN_SQL {
            return (
                vec![26, 25, 16],
                vec![
                    Some(300u32.to_be_bytes().to_vec()),
                    Some(OBSERVED_LOGIN.as_bytes().to_vec()),
                    Some(vec![0]),
                ],
                vec![25],
            );
        }
        if sql == SESSION_SQL {
            return (
                vec![25, 25, 25, 23, 26, 16, 16],
                vec![
                    Some(user.as_bytes().to_vec()),
                    Some(user.as_bytes().to_vec()),
                    Some(b"billing".to_vec()),
                    Some(160015i32.to_be_bytes().to_vec()),
                    Some(100u32.to_be_bytes().to_vec()),
                    Some(vec![1]),
                    Some(vec![1]),
                ],
                vec![],
            );
        }
        if sql == ROLES_SQL {
            return (
                vec![26, 25, 16],
                vec![
                    Some(100u32.to_be_bytes().to_vec()),
                    Some(user.as_bytes().to_vec()),
                    Some(vec![1]),
                ],
                vec![],
            );
        }
        if sql.starts_with("SELECT c.oid") {
            return (
                vec![26],
                vec![Some(200u32.to_be_bytes().to_vec())],
                vec![25, 25],
            );
        }
        if sql.starts_with("SELECT pg_catalog.has_table_privilege") {
            return (vec![16], vec![Some(vec![1])], vec![26, 26, 25]);
        }
        panic!("unexpected fixed query: {sql}")
    }
    #[tokio::test]
    async fn actual_pg_driver_uses_readonly_transaction_bound_identifiers_catalog_only_and_rollback()
     {
        let (i, mut c, _) = super::super::postgres::tests::sample();
        let schema = "billing'; GRANT ALL ON DATABASE billing TO public; --";
        c.address.effect = EffectKindV2::EffectiveSqlPrivilege {
            scope: SqlScope {
                database: "billing".into(),
                kind: SqlObjectKind::Table,
                schema: Some(schema.into()),
                object: Some("invoices".into()),
            },
            action: SqlAction::Read,
        };
        c.login_catalog_targets = vec![crate::core::postgres_login::LoginCatalogTarget {
            grant_id: "app-grant".into(),
            subject_id: "app-subject".into(),
            db_identity: OBSERVED_LOGIN.into(),
        }];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let user = c.address.db_identity.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let size = s.read_u32().await.unwrap();
            let mut startup = vec![0; size as usize - 4];
            s.read_exact(&mut startup).await.unwrap();
            let mut out = vec![];
            message(b'R', &0u32.to_be_bytes(), &mut out);
            message(b'Z', b"I", &mut out);
            s.write_all(&out).await.unwrap();
            let mut statements = BTreeMap::new();
            let mut active = String::new();
            let mut queries = vec![];
            let mut saw_bound_schema = false;
            let mut saw_bound_login = false;
            while let Ok(kind) = s.read_u8().await {
                let len = s.read_u32().await.unwrap();
                let mut body = vec![0; len as usize - 4];
                s.read_exact(&mut body).await.unwrap();
                let mut out = vec![];
                match kind {
                    b'Q' => {
                        let sql = String::from_utf8(body[..body.len() - 1].to_vec()).unwrap();
                        queries.push(sql.clone());
                        message(
                            b'C',
                            if sql.starts_with("START TRANSACTION") {
                                b"BEGIN\0"
                            } else {
                                b"ROLLBACK\0"
                            },
                            &mut out,
                        );
                        message(b'Z', b"T", &mut out);
                    }
                    b'P' => {
                        let (name, sql) = strings(&body);
                        queries.push(sql.clone());
                        statements.insert(name, sql);
                        message(b'1', &[], &mut out);
                    }
                    b'D' => {
                        let name = std::str::from_utf8(&body[1..body.len() - 1]).unwrap();
                        let sql = &statements[name];
                        let (types, _, params) = result(sql, &user);
                        let mut p = vec![];
                        p.extend((params.len() as i16).to_be_bytes());
                        for param in params {
                            p.extend(param.to_be_bytes())
                        }
                        message(b't', &p, &mut out);
                        message(b'T', &row_description(&types), &mut out);
                    }
                    b'B' => {
                        let (_, name) = strings(&body);
                        active = statements[&name].clone();
                        saw_bound_schema |=
                            body.windows(schema.len()).any(|w| w == schema.as_bytes());
                        saw_bound_login |= body
                            .windows(OBSERVED_LOGIN.len())
                            .any(|w| w == OBSERVED_LOGIN.as_bytes());
                        message(b'2', &[], &mut out);
                    }
                    b'E' => {
                        let (_, values, _) = result(&active, &user);
                        message(b'D', &data_row(&values), &mut out);
                        message(b'C', b"SELECT 1\0", &mut out);
                    }
                    b'S' => message(b'Z', b"T", &mut out),
                    b'X' => break,
                    b'C' => message(b'3', &[], &mut out),
                    _ => panic!("unexpected PG message {kind}"),
                }
                s.write_all(&out).await.unwrap();
            }
            (queries, saw_bound_schema, saw_bound_login)
        });
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(port)
            .user(&c.address.db_identity)
            .dbname("billing");
        let (mut client, connection) = config.connect(tokio_postgres::NoTls).await.unwrap();
        let task = tokio::spawn(connection);
        let observed = tokio::time::timeout(Duration::from_secs(5), catalog(&mut client, &c))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(observed.login_oid, 100);
        assert_eq!(observed.object_oid, Some(200));
        assert_eq!(observed.effective_privilege, Some(true));
        assert!(observed.roles_complete);
        assert_eq!(
            observed.login_catalog,
            vec![crate::core::postgres_login::LoginCatalogFact {
                target: c.login_catalog_targets[0].clone(),
                role_oid: 300,
                can_login: false,
            }]
        );
        drop(client);
        task.await.unwrap().unwrap();
        let (queries, bound, bound_login) = server.await.unwrap();
        assert!(queries[0].contains("READ ONLY"));
        assert!(queries[0].contains("REPEATABLE READ"));
        assert_eq!(queries.last().unwrap(), "ROLLBACK");
        assert!(bound);
        assert!(bound_login);
        assert!(!queries.iter().any(|q| q.contains(schema)
            || q.contains("GRANT ")
            || q.contains("invoices")
            || q.contains(OBSERVED_LOGIN)
            || q.contains("ALTER ROLE")));
        let _ = i; // Native credentials are never obtained in this loopback test.
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;
    #[test]
    fn pinned_proxy_version_accepts_build_metadata_but_not_other_versions_or_prereleases() {
        assert!(version_matches(b"cloud-sql-proxy version 2.26.3\n"));
        assert!(version_matches(
            b"cloud-sql-proxy version 2.26.3+linux.amd64\n"
        ));
        for bytes in [
            b"cloud-sql-proxy version 2.26.30".as_slice(),
            b"cloud-sql-proxy version 2.26.3-rc1",
            b"anything 2.26.3",
            b"cloud-sql-proxy version 2.26.3+host\nsecond line",
        ] {
            assert!(!version_matches(bytes));
        }
    }
}

const RUNTIME_API_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const RUNTIME_LOGIN_SCOPE: &str = "https://www.googleapis.com/auth/sqlservice.login";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeConnectSettings {
    region: String,
    database_version: String,
    server_ca_mode: String,
    dns_name: String,
    server_ca_cert: RuntimeCertificate,
    ip_addresses: Vec<ApiIp>,
}

#[derive(Deserialize)]
struct RuntimeCertificate {
    cert: String,
}

fn connector_settings(
    bytes: &[u8],
    instance: &InstanceIdentity,
) -> Result<RuntimeConnectSettings, SourceError> {
    let settings: RuntimeConnectSettings =
        serde_json::from_slice(bytes).map_err(|_| SourceError::Invalid)?;
    let mut private = settings
        .ip_addresses
        .iter()
        .filter(|a| a.r#type == "PRIVATE");
    if settings.region != instance.region
        || settings.database_version != instance.database_version
        || private.next().and_then(|a| a.ip_address.parse().ok()) != Some(instance.private_ip)
        || private.next().is_some()
    {
        return Err(SourceError::ContextUnverified);
    }
    if !matches!(
        settings.server_ca_mode.as_str(),
        "GOOGLE_MANAGED_CAS_CA" | "CUSTOMER_MANAGED_CAS_CA"
    ) || !matches!(
        rustls::pki_types::ServerName::try_from(settings.dns_name.as_str()),
        Ok(rustls::pki_types::ServerName::DnsName(_))
    ) {
        return Err(SourceError::Unsupported);
    }
    Ok(settings)
}

fn cert_config(
    origin: &str,
    token: &AccessToken,
    login: &AccessToken,
    public_key: &str,
) -> Result<String, SourceError> {
    let data = serde_json::to_string(&serde_json::json!({
        "public_key": public_key,
        "access_token": login.access_token,
    }))
    .map_err(|_| SourceError::Invalid)?;
    let escaped = data.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!(
        "url = \"{origin}:generateEphemeralCert\"\nrequest = \"POST\"\nheader = \"Authorization: Bearer {}\"\nheader = \"Content-Type: application/json\"\ndata = \"{escaped}\"\n",
        token.access_token,
    ))
}

pub(crate) async fn bootstrap_runtime_connector(
    issued: &IssuedObservation,
    case: &RequestedCase,
    rsa_key_pkcs8: &[u8],
    cancel: &CancellationToken,
) -> Result<crate::binding::gcp_connector_witness::NativeConnectorBootstrap, SourceError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
    if !cfg!(target_os = "linux") {
        return Err(SourceError::Unsupported);
    }
    if cancel.is_cancelled() {
        return Err(SourceError::Cancelled);
    }
    if rsa_key_pkcs8.len() > 8192 {
        return Err(SourceError::Limit);
    }
    let started_at = crate::domain::now();
    let context = crate::core::runtime_binding::RuntimeCaptureContext::for_case(issued, case)
        .map_err(|_| SourceError::Invalid)?;
    validated_profile(&issued.snapshot)?;
    let source = issued.snapshot.gce().ok_or(SourceError::Unsupported)?;
    let vm = &source.native_identity;
    if context.address.route.kind != RouteKind::NativeConnector
        || context.address.target.placement.region != "asia-northeast1"
        || context.address.target.engine_binding.version != "16.15"
        || vm.service_account.strip_suffix(".gserviceaccount.com")
            != Some(case.address.db_identity.as_str())
    {
        return Err(SourceError::Unsupported);
    }
    if started_at < issued.request.issued_at || started_at >= issued.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    ring::signature::RsaKeyPair::from_pkcs8(rsa_key_pkcs8).map_err(|_| SourceError::Invalid)?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(rsa_key_pkcs8.to_vec()));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
        .map_err(|_| SourceError::Invalid)?;
    let spki = signing_key.public_key().ok_or(SourceError::Invalid)?;
    let mut public_key = "-----BEGIN RSA PUBLIC KEY-----\n".to_owned();
    let encoded = STANDARD.encode(spki.as_ref());
    for chunk in encoded.as_bytes().chunks(64) {
        public_key.push_str(std::str::from_utf8(chunk).map_err(|_| SourceError::Invalid)?);
        public_key.push('\n');
    }
    public_key.push_str("-----END RSA PUBLIC KEY-----\n");

    // The fixed metadata endpoint and a request-bound signed identity supply
    // the source provenance. No SDK/ADC or caller-supplied token fallback.
    let keys = super::jwt::GoogleSigningKeys::fetch(cancel).await?;
    let jwt = collector::metadata_identity(&super::jwt::audience(issued)?, cancel).await?;
    let identity = keys.verify(&jwt, issued, crate::domain::now())?;
    let api = token(issued, RUNTIME_API_SCOPE, cancel).await?;
    let login = token(issued, RUNTIME_LOGIN_SCOPE, cancel).await?;
    let before = instance(case, &api, cancel).await?;
    if !before.matches(case) {
        return Err(SourceError::ContextUnverified);
    }
    let origin = format!(
        "https://sqladmin.googleapis.com/sql/v1beta4/projects/{}/instances/{}",
        before.project, before.name
    );
    let mut args = api_args(&before.project, &before.name);
    *args.last_mut().ok_or(SourceError::Invalid)? = format!("{origin}/connectSettings");
    let header = format!("Authorization: Bearer {}\n", api.access_token);
    let settings = connector_settings(
        &process::run(
            Path::new("/usr/bin/curl"),
            &args,
            header.as_bytes(),
            65536,
            5,
            cancel,
        )
        .await?,
        &before,
    )?;
    let server_ca = CertificateDer::pem_slice_iter(settings.server_ca_cert.cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SourceError::Invalid)?;
    if server_ca.is_empty() || server_ca.len() > 8 {
        return Err(SourceError::Invalid);
    }
    let config = cert_config(&origin, &api, &login, &public_key)?;
    let cert_args = [
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
        "--config",
        "-",
    ]
    .map(str::to_owned);
    let bytes = process::run(
        Path::new("/usr/bin/curl"),
        &cert_args,
        config.as_bytes(),
        65536,
        5,
        cancel,
    )
    .await?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EphemeralResponse {
        ephemeral_cert: RuntimeCertificate,
    }
    let result: EphemeralResponse =
        serde_json::from_slice(&bytes).map_err(|_| SourceError::Invalid)?;
    let client_certificate = CertificateDer::pem_slice_iter(result.ephemeral_cert.cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SourceError::Invalid)?;
    if client_certificate.is_empty()
        || client_certificate.len() > 8
        || instance(case, &api, cancel).await? != before
    {
        return Err(SourceError::ContextUnverified);
    }
    let valid_until = issued
        .request
        .expires_at
        .min(identity.expires_at)
        .min(started_at.saturating_add(api.expires_in.min(login.expires_in)));
    if crate::domain::now() >= valid_until {
        return Err(SourceError::RequestExpired);
    }
    // Exclude the config digest, since the binding digest is stored in config.
    let binding = serde_json::to_vec(&(
        "k11-gcp-metadata-credentials-v1",
        issued.snapshot.registration_id(),
        issued.snapshot.trust_epoch(),
        vm,
        RUNTIME_API_SCOPE,
        RUNTIME_LOGIN_SCOPE,
        &case.address.target.native_ref,
    ))
    .map_err(|_| SourceError::Invalid)?;
    Ok(
        crate::binding::gcp_connector_witness::NativeConnectorBootstrap {
            peer: std::net::SocketAddr::new(before.private_ip, 3307),
            server_name: settings.dns_name,
            server_ca,
            client_certificate,
            client_key: private_key,
            target_generation: crate::adapters::deployment::gcp::generation_fingerprint(
                &before.project,
                &before.name,
                &before.create_time,
            ),
            native_iam_principal: vm.service_account.clone(),
            credential_binding_digest: crate::config::hash_bytes(&binding),
            valid_until,
        },
    )
}

#[cfg(test)]
mod runtime_bootstrap_tests {
    use super::*;

    #[test]
    fn runtime_connect_settings_accept_only_same_private_instance_and_verified_dns_profile() {
        let instance = InstanceIdentity {
            project: "sample-project".into(),
            name: "billing".into(),
            region: "asia-northeast1".into(),
            connection_name: "sample-project:asia-northeast1:billing".into(),
            create_time: "2026-10-01T00:00:00Z".into(),
            database_version: "POSTGRES_16".into(),
            private_ip: "10.0.0.2".parse().unwrap(),
        };
        let sample = serde_json::json!({
            "region": "asia-northeast1", "databaseVersion": "POSTGRES_16",
            "serverCaMode": "GOOGLE_MANAGED_CAS_CA", "dnsName": "billing.example.invalid",
            "serverCaCert": {"cert":"fixture"},
            "ipAddresses": [{"type":"PRIVATE","ipAddress":"10.0.0.2"}],
        });
        assert!(connector_settings(&serde_json::to_vec(&sample).unwrap(), &instance).is_ok());
        for (field, value) in [
            ("region", serde_json::json!("us-central1")),
            ("databaseVersion", serde_json::json!("MYSQL_8_0")),
            (
                "serverCaMode",
                serde_json::json!("GOOGLE_MANAGED_INTERNAL_CA"),
            ),
            ("dnsName", serde_json::json!("10.0.0.2")),
            (
                "ipAddresses",
                serde_json::json!([{"type":"PRIVATE","ipAddress":"10.0.0.9"}]),
            ),
        ] {
            let mut wrong = sample.clone();
            wrong[field] = value;
            assert!(connector_settings(&serde_json::to_vec(&wrong).unwrap(), &instance).is_err());
        }
    }
}

pub(crate) async fn recheck_runtime_connector(
    issued: &IssuedObservation,
    case: &RequestedCase,
    cancel: &CancellationToken,
) -> Result<(), SourceError> {
    if !cfg!(target_os = "linux") {
        return Err(SourceError::Unsupported);
    }
    let api = token(issued, RUNTIME_API_SCOPE, cancel).await?;
    let native = instance(case, &api, cancel).await?;
    if !native.matches(case) {
        return Err(SourceError::ContextUnverified);
    }
    if crate::domain::now() >= issued.request.expires_at {
        return Err(SourceError::RequestExpired);
    }
    Ok(())
}
