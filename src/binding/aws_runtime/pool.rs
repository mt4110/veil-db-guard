//! Bounded application pools for the strict AWS drivers.
use super::{AwsConnectionBundle, AwsMysqlSession, AwsPostgresSession, BindingError};
use crate::core::{
    aws_runtime_cutover::{
        AwsPostgresDatabaseObservation, AwsPostgresPoolObservation, AwsPostgresTransaction,
    },
    policy::{EngineFamily, valid_hash},
    runtime_cutover::{PoolSwitchLink, PostgresSessionIdentity},
};
use mysql_async::prelude::Queryable;
use serde::Serialize;
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::{Mutex as SessionLock, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

enum PhysicalSession {
    Postgres(AwsPostgresSession),
    Mysql(AwsMysqlSession),
}

impl PhysicalSession {
    async fn healthy(&mut self) -> bool {
        match self {
            Self::Postgres(session) => !session.client.is_closed() && !session.task.is_finished(),
            Self::Mysql(session) => session.connection.ping().await.is_ok(),
        }
    }
}

const POSTGRES_BACKEND_SQL: &str = "SELECT a.datname::text, a.usename::text, a.pid, ((extract(epoch FROM a.backend_start) * 1000000)::bigint), s.ssl, pg_catalog.current_setting('transaction_read_only'), ((extract(epoch FROM a.xact_start) * 1000000)::bigint) FROM pg_catalog.pg_stat_activity AS a LEFT JOIN pg_catalog.pg_stat_ssl AS s ON s.pid = a.pid WHERE a.pid = pg_catalog.pg_backend_pid()";

const INSPECT_POSTGRES_BACKEND_SQL: &str = "SELECT session_user::text, pg_catalog.current_database()::text, a.datname::text, a.usename::text, ((extract(epoch FROM a.backend_start) * 1000000)::bigint), ((extract(epoch FROM a.xact_start) * 1000000)::bigint), s.ssl FROM pg_catalog.pg_stat_activity AS a LEFT JOIN pg_catalog.pg_stat_ssl AS s ON s.pid = a.pid WHERE a.pid = $1 AND a.pid <> pg_catalog.pg_backend_pid() AND a.state = 'idle in transaction' AND a.query = $2";

type Slot<S> = Arc<SessionLock<Option<S>>>;

struct Active<S> {
    bundle: AwsConnectionBundle,
    capacity: usize,
    sessions: Vec<Slot<S>>,
    sequence: u64,
    previous_generation: Option<u64>,
    switched_at: u64,
}

impl<S> Active<S> {
    fn new(bundle: AwsConnectionBundle, sessions: Vec<Slot<S>>) -> Self {
        Self {
            bundle,
            capacity: sessions.len(),
            sessions,
            sequence: 0,
            previous_generation: None,
            switched_at: crate::domain::now(),
        }
    }

    fn check_switch(
        &self,
        expected: u64,
        replacement: &AwsConnectionBundle,
    ) -> Result<(), BindingError> {
        if self.bundle.pool_generation != expected || replacement.pool_generation <= expected {
            return Err(BindingError::Pending);
        }
        let mut same_scope = self.bundle.clone();
        same_scope.pool_generation = replacement.pool_generation;
        if same_scope != *replacement {
            return Err(BindingError::Invalid);
        }
        Ok(())
    }

    fn replace(
        &mut self,
        expected: u64,
        bundle: AwsConnectionBundle,
        sessions: Vec<Slot<S>>,
    ) -> Result<Vec<Slot<S>>, BindingError> {
        self.check_switch(expected, &bundle)?;
        let retired = std::mem::replace(&mut self.sessions, sessions);
        self.bundle = bundle;
        self.previous_generation = Some(expected);
        self.switched_at = crate::domain::now();
        Ok(retired)
    }

    fn checkout_record(&mut self, generation: u64) -> Result<AwsPoolCheckoutSample, BindingError> {
        let now = crate::domain::now();
        if self.bundle.pool_generation != generation
            || self
                .bundle
                .lease_expires_at_unix
                .is_some_and(|expires| now >= expires)
        {
            return Err(BindingError::Pending);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(BindingError::Pending)?;
        Ok(AwsPoolCheckoutSample {
            bundle_digest: self.bundle.digest(),
            engine: self.bundle.engine,
            pool_generation: generation,
            previous_generation: self.previous_generation,
            checkout_sequence: self.sequence,
            switched_at: self.switched_at,
            checked_out_at: now,
            postgres_startup_backend_pid: None,
            mysql_proxy_connection_id: None,
        })
    }
}

/// Opens each physical connection through the selected strict AWS driver.
/// Switching changes the generation only after its replacement pool opens.
pub struct AwsSessionPool {
    active: Arc<Mutex<Active<PhysicalSession>>>,
}

/// Pool diagnostics. The PostgreSQL PID is sampled at startup, and the MySQL
/// ID comes from the proxy handshake. RDS Proxy can multiplex backend sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AwsPoolCheckoutSample {
    pub bundle_digest: String,
    pub engine: EngineFamily,
    pub pool_generation: u64,
    pub previous_generation: Option<u64>,
    pub checkout_sequence: u64,
    pub switched_at: u64,
    pub checked_out_at: u64,
    pub postgres_startup_backend_pid: Option<u32>,
    pub mysql_proxy_connection_id: Option<u32>,
}

/// Holds the selected physical session until release, including after a switch.
pub struct AwsPoolCheckout {
    active: Weak<Mutex<Active<PhysicalSession>>>,
    session: OwnedMutexGuard<Option<PhysicalSession>>,
    sample: AwsPoolCheckoutSample,
}

/// A backend sample scoped to the read-only transaction that selected it.
/// Keep the transaction open while an independent observer correlates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AwsPostgresBackendSample {
    pub database: String,
    pub session_user: String,
    pub backend_pid: i32,
    pub backend_started_at_micros: i64,
    pub transaction_started_at_micros: i64,
    pub server_reported_ssl: Option<bool>,
}

pub struct AwsPostgresCheckoutObservation {
    active: Weak<Mutex<Active<PhysicalSession>>>,
    challenge: String,
    session: AwsPostgresSession,
    checkout: AwsPoolCheckoutSample,
    sample: AwsPostgresBackendSample,
}

impl AwsPostgresCheckoutObservation {
    pub fn sample(&self) -> &AwsPostgresBackendSample {
        &self.sample
    }

    pub fn checkout(&self) -> &AwsPoolCheckoutSample {
        &self.checkout
    }

    /// Select the transaction for an independently authenticated observer.
    pub fn transaction(&self) -> AwsPostgresTransaction {
        AwsPostgresTransaction {
            session: PostgresSessionIdentity {
                database: self.sample.database.clone(),
                session_user: self.sample.session_user.clone(),
                backend_pid: self.sample.backend_pid as u32,
                backend_started_at_micros: self.sample.backend_started_at_micros as u64,
            },
            transaction_started_at_micros: self.sample.transaction_started_at_micros as u64,
            marker: self.challenge.clone(),
            server_reported_ssl: self.sample.server_reported_ssl,
        }
    }

    /// Check the generation at observation time, after the independent read.
    pub fn pool_evidence(&self) -> Result<AwsPostgresPoolObservation, BindingError> {
        let active = self.active.upgrade().ok_or(BindingError::Pending)?;
        let active = active.lock().map_err(|_| BindingError::Pending)?;
        let previous_generation = active.previous_generation.ok_or(BindingError::Pending)?;
        if self.session.client.is_closed()
            || self.session.task.is_finished()
            || active.bundle.pool_generation != self.checkout.pool_generation
            || self.checkout.previous_generation != Some(previous_generation)
            || active.switched_at != self.checkout.switched_at
            || active
                .bundle
                .lease_expires_at_unix
                .is_some_and(|expires| crate::domain::now() >= expires)
        {
            return Err(BindingError::Pending);
        }
        Ok(AwsPostgresPoolObservation {
            bundle_digest: self.checkout.bundle_digest.clone(),
            switch: PoolSwitchLink {
                previous_generation,
                active_generation: self.checkout.pool_generation,
                checkout_sequence: self.checkout.checkout_sequence,
                switched_at: self.checkout.switched_at,
                checked_out_at: self.checkout.checked_out_at,
            },
            transaction: self.transaction(),
        })
    }

    pub async fn finish(self) -> Result<(), BindingError> {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.session.client.batch_execute("ROLLBACK"),
        )
        .await
        .map_err(|_| BindingError::Pending)?
        .map_err(|_| BindingError::Pending)
    }
}

/// Read a selected transaction through the independent observer's own DB
/// connection. The caller must authenticate and scope that connection before
/// signing the resulting observation.
pub async fn inspect_aws_postgres_transaction(
    observer: &tokio_postgres::Client,
    expected_observer_user: &str,
    observed_target_generation: &str,
    selected: &AwsPostgresTransaction,
    cancel: &CancellationToken,
) -> Result<AwsPostgresDatabaseObservation, BindingError> {
    if expected_observer_user.is_empty()
        || expected_observer_user == selected.session.session_user
        || !valid_hash(observed_target_generation)
        || !valid_hash(&selected.marker)
    {
        return Err(BindingError::Invalid);
    }
    let pid = i32::try_from(selected.session.backend_pid).map_err(|_| BindingError::Invalid)?;
    let marked_query = marked_backend_query(&selected.marker);
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[&pid, &marked_query];
    let read = async {
        observer
            .batch_execute("SELECT pg_catalog.pg_stat_clear_snapshot()")
            .await?;
        observer
            .query_opt(INSPECT_POSTGRES_BACKEND_SQL, params)
            .await
    };
    let row = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(BindingError::Pending),
        result = tokio::time::timeout(Duration::from_secs(5), read) => result.map_err(|_| BindingError::Pending)?
            .map_err(|_| BindingError::Pending)?.ok_or(BindingError::Pending)?,
    };
    let text = |index| {
        row.try_get::<_, &str>(index)
            .map_err(|_| BindingError::Pending)
    };
    let epoch = |index| {
        let value = row
            .try_get::<_, i64>(index)
            .map_err(|_| BindingError::Pending)?;
        u64::try_from(value).map_err(|_| BindingError::Invalid)
    };
    let observer_user = text(0)?;
    let database = text(2)?;
    let transaction = AwsPostgresTransaction {
        session: PostgresSessionIdentity {
            database: database.to_owned(),
            session_user: text(3)?.to_owned(),
            backend_pid: selected.session.backend_pid,
            backend_started_at_micros: epoch(4)?,
        },
        transaction_started_at_micros: epoch(5)?,
        marker: selected.marker.clone(),
        server_reported_ssl: row.try_get(6).map_err(|_| BindingError::Pending)?,
    };
    if observer_user != expected_observer_user || text(1)? != database || transaction != *selected {
        return Err(BindingError::Invalid);
    }
    Ok(AwsPostgresDatabaseObservation {
        target_generation: observed_target_generation.to_owned(),
        observer_user: observer_user.to_owned(),
        transaction,
    })
}

fn marked_backend_query(challenge: &str) -> String {
    format!("/* veil-k11:{challenge} */ {POSTGRES_BACKEND_SQL}")
}

impl AwsPoolCheckout {
    pub fn postgres(&self) -> Option<&tokio_postgres::Client> {
        match self.session.as_ref()? {
            PhysicalSession::Postgres(session) => Some(session.client()),
            PhysicalSession::Mysql(_) => None,
        }
    }

    pub fn mysql(&mut self) -> Option<&mut AwsMysqlSession> {
        match self.session.as_mut()? {
            PhysicalSession::Mysql(session) => Some(session),
            PhysicalSession::Postgres(_) => None,
        }
    }

    pub fn sample(&self) -> &AwsPoolCheckoutSample {
        &self.sample
    }

    /// Inspect the selected physical checkout. RDS Proxy can choose a new
    /// backend after the transaction ends, so this is a diagnostic only.
    pub async fn observe_postgres_backend(
        self,
        cancel: &CancellationToken,
    ) -> Result<AwsPostgresCheckoutObservation, BindingError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut marker = [0; 32];
        SystemRandom::new()
            .fill(&mut marker)
            .map_err(|_| BindingError::Pending)?;
        self.observe_postgres_backend_marked(&crate::core::hash_bytes(&marker), cancel)
            .await
    }

    /// Use a challenge bound to a single evidence request.
    pub async fn observe_postgres_backend_marked(
        mut self,
        challenge: &str,
        cancel: &CancellationToken,
    ) -> Result<AwsPostgresCheckoutObservation, BindingError> {
        if cancel.is_cancelled() {
            return Err(BindingError::Pending);
        }
        if !valid_hash(challenge) {
            return Err(BindingError::Invalid);
        }
        if self.postgres().is_none() {
            return Err(BindingError::Unsupported);
        }
        // Remove the session before any await. A cancelled BEGIN can have
        // reached the server, so this diagnostic connection is never reused.
        let Some(PhysicalSession::Postgres(session)) = self.session.take() else {
            return Err(BindingError::Invalid);
        };
        let marked_query = marked_backend_query(challenge);
        let work = async {
            session
                .client
                .batch_execute("DISCARD ALL")
                .await
                .map_err(|_| BindingError::Pending)?;
            session
                .client
                .batch_execute("BEGIN READ ONLY")
                .await
                .map_err(|_| BindingError::Pending)?;
            session
                .client
                .batch_execute("SET LOCAL idle_in_transaction_session_timeout = '15s'")
                .await
                .map_err(|_| BindingError::Pending)?;
            let rows = session
                .client
                .simple_query(&marked_query)
                .await
                .map_err(|_| BindingError::Pending)?;
            let [
                tokio_postgres::SimpleQueryMessage::RowDescription(columns),
                tokio_postgres::SimpleQueryMessage::Row(row),
                tokio_postgres::SimpleQueryMessage::CommandComplete(1),
            ] = rows.as_slice()
            else {
                return Err(BindingError::Invalid);
            };
            if columns.len() != 7 || row.get(5) != Some("on") {
                return Err(BindingError::Invalid);
            }
            let required = |i| {
                row.get(i)
                    .filter(|value| !value.is_empty())
                    .ok_or(BindingError::Invalid)
            };
            let sample = AwsPostgresBackendSample {
                database: required(0)?.into(),
                session_user: required(1)?.into(),
                backend_pid: required(2)?.parse().map_err(|_| BindingError::Invalid)?,
                backend_started_at_micros: required(3)?
                    .parse()
                    .map_err(|_| BindingError::Invalid)?,
                transaction_started_at_micros: required(6)?
                    .parse()
                    .map_err(|_| BindingError::Invalid)?,
                server_reported_ssl: match row.get(4) {
                    Some("t") => Some(true),
                    Some("f") => Some(false),
                    None => None,
                    _ => return Err(BindingError::Invalid),
                },
            };
            if sample.backend_pid <= 0
                || sample.backend_started_at_micros <= 0
                || sample.transaction_started_at_micros < sample.backend_started_at_micros
            {
                return Err(BindingError::Invalid);
            }
            Ok(AwsPostgresCheckoutObservation {
                active: self.active,
                challenge: challenge.to_owned(),
                session,
                checkout: self.sample,
                sample,
            })
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(BindingError::Pending),
            result = tokio::time::timeout(Duration::from_secs(5), work) =>
                result.unwrap_or(Err(BindingError::Pending)),
        }
    }
}

async fn open_sessions(
    bundle: &AwsConnectionBundle,
    ca_pem: &[u8],
    capacity: usize,
    cancel: &CancellationToken,
) -> Result<Vec<Slot<PhysicalSession>>, BindingError> {
    if !(1..=16).contains(&capacity) {
        return Err(BindingError::Invalid);
    }
    bundle.check_proxy_ca(ca_pem)?;
    let open = async {
        let mut sessions = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let session = match bundle.engine {
                EngineFamily::PostgreSql => {
                    PhysicalSession::Postgres(bundle.connect_postgres(ca_pem, cancel).await?)
                }
                EngineFamily::MySql => {
                    PhysicalSession::Mysql(bundle.connect_mysql(ca_pem, cancel).await?)
                }
                _ => return Err(BindingError::Unsupported),
            };
            sessions.push(Arc::new(SessionLock::new(Some(session))));
        }
        Ok(sessions)
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(BindingError::Pending),
        result = tokio::time::timeout(Duration::from_secs(120), open) =>
            result.unwrap_or(Err(BindingError::Pending)),
    }
}

impl AwsSessionPool {
    pub async fn open(
        bundle: AwsConnectionBundle,
        ca_pem: &[u8],
        capacity: usize,
        cancel: &CancellationToken,
    ) -> Result<Self, BindingError> {
        let sessions = open_sessions(&bundle, ca_pem, capacity, cancel).await?;
        if cancel.is_cancelled() {
            return Err(BindingError::Pending);
        }
        Ok(Self {
            active: Arc::new(Mutex::new(Active::new(bundle, sessions))),
        })
    }

    pub async fn switch(
        &self,
        expected_generation: u64,
        bundle: AwsConnectionBundle,
        ca_pem: &[u8],
        cancel: &CancellationToken,
    ) -> Result<(), BindingError> {
        let capacity = {
            let active = self.active.lock().map_err(|_| BindingError::Pending)?;
            active.check_switch(expected_generation, &bundle)?;
            active.capacity
        };
        let sessions = open_sessions(&bundle, ca_pem, capacity, cancel).await?;
        let retired = {
            let mut active = self.active.lock().map_err(|_| BindingError::Pending)?;
            if cancel.is_cancelled() {
                return Err(BindingError::Pending);
            }
            active.replace(expected_generation, bundle, sessions)?
        };
        drop(retired);
        Ok(())
    }

    /// Tries available connections. A failed or interrupted health check drops
    /// the affected connection. Switch to a fresh generation to replace it.
    pub async fn checkout(
        &self,
        cancel: &CancellationToken,
    ) -> Result<AwsPoolCheckout, BindingError> {
        let (generation, sessions) = {
            let active = self.active.lock().map_err(|_| BindingError::Pending)?;
            (active.bundle.pool_generation, active.sessions.clone())
        };
        for slot in sessions {
            if cancel.is_cancelled() {
                return Err(BindingError::Pending);
            }
            let Ok(mut session) = slot.try_lock_owned() else {
                continue;
            };
            // Own the connection across the health future. If the caller
            // drops that future midway through a MySQL command, this drops
            // the connection instead of returning it to the idle pool.
            let Some(mut connection) = session.take() else {
                continue;
            };
            let healthy = tokio::select! {
                biased;
                _ = cancel.cancelled() => false,
                result = tokio::time::timeout(Duration::from_secs(2), connection.healthy()) => result.unwrap_or(false),
            };
            if !healthy {
                continue;
            }
            let mut active = self.active.lock().map_err(|_| BindingError::Pending)?;
            if cancel.is_cancelled() {
                return Err(BindingError::Pending);
            }
            let mut sample = active.checkout_record(generation)?;
            match &connection {
                PhysicalSession::Postgres(pg) => {
                    sample.postgres_startup_backend_pid = pg.startup_backend_pid
                }
                PhysicalSession::Mysql(mysql) => {
                    sample.mysql_proxy_connection_id = Some(mysql.connection.id())
                }
            }
            *session = Some(connection);
            return Ok(AwsPoolCheckout {
                active: Arc::downgrade(&self.active),
                session,
                sample,
            });
        }
        Err(BindingError::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::aws_runtime::tests::bundle_for;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn postgres_backend_sample_keeps_its_checkout_in_read_only_transaction() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        fn frame(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
            out.push(tag);
            out.extend(((body.len() + 4) as u32).to_be_bytes());
            out.extend_from_slice(body);
        }
        let server = tokio::spawn(async move {
            let n = server_io.read_u32().await.unwrap();
            server_io
                .read_exact(&mut vec![0; (n - 4) as usize])
                .await
                .unwrap();
            let mut out = vec![];
            frame(&mut out, b'R', &[0; 4]);
            frame(&mut out, b'Z', b"I");
            server_io.write_all(&out).await.unwrap();
            let marked_query = format!("/* veil-k11:{} */ {POSTGRES_BACKEND_SQL}", "a".repeat(64));
            for (sql, tag, state) in [
                ("DISCARD ALL", b"DISCARD ALL\0".as_slice(), b"I"),
                ("BEGIN READ ONLY", b"BEGIN\0".as_slice(), b"T"),
                (
                    "SET LOCAL idle_in_transaction_session_timeout = '15s'",
                    b"SET\0".as_slice(),
                    b"T",
                ),
                (marked_query.as_str(), b"SELECT 1\0".as_slice(), b"T"),
                ("ROLLBACK", b"ROLLBACK\0".as_slice(), b"I"),
            ] {
                assert_eq!(server_io.read_u8().await.unwrap(), b'Q');
                let n = server_io.read_u32().await.unwrap();
                let mut query = vec![0; (n - 4) as usize];
                server_io.read_exact(&mut query).await.unwrap();
                assert_eq!(query.strip_suffix(&[0]), Some(sql.as_bytes()));
                out.clear();
                if sql == marked_query {
                    let mut description = vec![0, 7];
                    for _ in 0..7 {
                        description.extend_from_slice(b"column\0");
                        description.extend_from_slice(&[0; 18]);
                    }
                    frame(&mut out, b'T', &description);
                    let mut row = vec![0, 7];
                    for value in [
                        "billing",
                        "app",
                        "23",
                        "1800000000000000",
                        "t",
                        "on",
                        "1800000001000000",
                    ] {
                        row.extend((value.len() as u32).to_be_bytes());
                        row.extend(value.as_bytes());
                    }
                    frame(&mut out, b'D', &row);
                }
                frame(&mut out, b'C', tag);
                frame(&mut out, b'Z', state);
                server_io.write_all(&out).await.unwrap();
            }
            let _ = server_io.read_u8().await;
        });
        let (client, connection) = tokio_postgres::Config::new()
            .user("app")
            .dbname("billing")
            .connect_raw(client_io, tokio_postgres::NoTls)
            .await
            .unwrap();
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let slot = Arc::new(SessionLock::new(Some(PhysicalSession::Postgres(
            AwsPostgresSession {
                client,
                task,
                startup_backend_pid: Some(10),
            },
        ))));
        let mut active = Active::new(bundle_for(EngineFamily::PostgreSql), vec![slot.clone()]);
        let sample = active
            .checkout_record(active.bundle.pool_generation)
            .unwrap();
        let checkout = AwsPoolCheckout {
            active: Weak::new(),
            session: slot.clone().try_lock_owned().unwrap(),
            sample,
        };
        let observation = checkout
            .observe_postgres_backend_marked(&"a".repeat(64), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(observation.sample().backend_pid, 23);
        assert_eq!(observation.sample().server_reported_ssl, Some(true));
        assert_eq!(observation.checkout().checkout_sequence, 1);
        assert!(
            slot.try_lock().unwrap().is_none(),
            "observation owns the session"
        );
        observation.finish().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires dedicated loopback PostgreSQL fixture"]
    async fn postgres_backend_corroboration_uses_an_independent_session() {
        async fn connect(user: &str) -> (tokio_postgres::Client, tokio::task::JoinHandle<()>) {
            let port = std::env::var("VEIL_K11_TEST_PG_PORT")
                .expect("dedicated local test fixture port")
                .parse()
                .unwrap();
            let ca_path = std::env::var("VEIL_K11_TEST_PG_CA").expect("local test CA path");
            let ca_pem = std::fs::read(ca_path).unwrap();
            let tls = crate::adapters::engine::postgres::aws::verified_tls(&ca_pem).unwrap();
            let (client, connection) = tokio_postgres::Config::new()
                .host("127.0.0.1")
                .port(port)
                .user(user)
                .password("veil-test-only")
                .dbname("billing")
                .ssl_mode(tokio_postgres::config::SslMode::Require)
                .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
                .await
                .unwrap();
            let task = tokio::spawn(async move {
                let _ = connection.await;
            });
            (client, task)
        }
        let cancel = CancellationToken::new();
        let (client, task) = connect("billing_app").await;
        let (observer, _observer_task) = connect("veil_recovery").await;
        let (unprivileged, _unprivileged_task) = connect("veil_test_unprivileged").await;
        let slot = Arc::new(SessionLock::new(Some(PhysicalSession::Postgres(
            AwsPostgresSession {
                client,
                task,
                startup_backend_pid: None,
            },
        ))));
        let mut fixture =
            crate::adapters::source::aws_runtime_cutover::tests::AdmissionFixture::new(
                crate::domain::now(),
            );
        let replacement = fixture.bundle.clone();
        let target_generation = replacement.target_generation.clone();
        let previous = replacement.pool_generation - 1;
        let mut initial = replacement.clone();
        initial.pool_generation = previous;
        let mut active = Active::new(initial, vec![]);
        active.replace(previous, replacement, vec![slot]).unwrap();
        let pool = AwsSessionPool {
            active: Arc::new(Mutex::new(active)),
        };
        let challenge =
            crate::core::aws_runtime_cutover::aws_postgres_runtime_marker(&fixture.context);
        let observation = pool
            .checkout(&cancel)
            .await
            .unwrap()
            .observe_postgres_backend_marked(&challenge, &cancel)
            .await
            .unwrap();
        let selected = observation.transaction();
        assert_eq!(selected.server_reported_ssl, Some(true));
        let database = inspect_aws_postgres_transaction(
            &observer,
            "veil_recovery",
            &target_generation,
            &selected,
            &cancel,
        )
        .await
        .unwrap();
        let database_at = crate::domain::now();
        let pool_evidence = observation.pool_evidence().unwrap();
        fixture.admit_and_reload(&pool_evidence, &database, database_at, crate::domain::now());
        assert_eq!(pool_evidence.transaction, database.transaction);
        {
            let mut active = pool.active.lock().unwrap();
            let generation = active.bundle.pool_generation;
            let mut replacement = active.bundle.clone();
            replacement.pool_generation += 1;
            active.replace(generation, replacement, vec![]).unwrap();
        }
        assert!(matches!(
            observation.pool_evidence(),
            Err(BindingError::Pending)
        ));
        assert!(matches!(
            inspect_aws_postgres_transaction(
                &observer,
                "other",
                &target_generation,
                &selected,
                &cancel
            )
            .await,
            Err(BindingError::Invalid),
        ));
        assert!(matches!(
            inspect_aws_postgres_transaction(
                &unprivileged,
                "veil_test_unprivileged",
                &target_generation,
                &selected,
                &cancel
            )
            .await,
            Err(BindingError::Pending),
        ));
        let mut altered = selected.clone();
        altered.marker = "a".repeat(64);
        assert!(matches!(
            inspect_aws_postgres_transaction(
                &observer,
                "veil_recovery",
                &target_generation,
                &altered,
                &cancel
            )
            .await,
            Err(BindingError::Pending),
        ));
        altered = selected.clone();
        altered.transaction_started_at_micros += 1;
        assert!(matches!(
            inspect_aws_postgres_transaction(
                &observer,
                "veil_recovery",
                &target_generation,
                &altered,
                &cancel
            )
            .await,
            Err(BindingError::Invalid),
        ));
        observation.finish().await.unwrap();
        assert!(matches!(
            inspect_aws_postgres_transaction(
                &observer,
                "veil_recovery",
                &target_generation,
                &selected,
                &cancel
            )
            .await,
            Err(BindingError::Pending),
        ));
    }

    struct Tracked(Arc<AtomicUsize>);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn generation_switch_releases_idle_and_keeps_held_old_session() {
        for engine in [EngineFamily::PostgreSql, EngineFamily::MySql] {
            let drops = Arc::new(AtomicUsize::new(0));
            let slot = || Arc::new(SessionLock::new(Some(Tracked(drops.clone()))));
            let initial = bundle_for(engine);
            let generation = initial.pool_generation;
            let mut active = Active::new(initial.clone(), vec![slot(), slot()]);
            let held = Arc::clone(&active.sessions[0]).try_lock_owned().unwrap();
            assert!(Arc::clone(&active.sessions[0]).try_lock_owned().is_err());
            let before = active.checkout_record(generation).unwrap();
            let mut replacement = initial.clone();
            replacement.pool_generation += 1;
            let retired = active
                .replace(generation, replacement, vec![slot(), slot()])
                .unwrap();
            drop(retired);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(active.checkout_record(generation).is_err());
            let after = active.checkout_record(generation + 1).unwrap();
            assert_eq!(after.previous_generation, Some(generation));
            assert_eq!(after.checkout_sequence, before.checkout_sequence + 1);
            assert_ne!(after.bundle_digest, before.bundle_digest);
            assert!(!serde_json::to_string(&after).unwrap().contains("X-Amz-"));
            drop(held);
            assert_eq!(drops.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn switching_rejects_scope_change_and_losing_concurrent_rotation() {
        let bundle = bundle_for(EngineFamily::PostgreSql);
        let generation = bundle.pool_generation;
        let mut active = Active::<()>::new(bundle.clone(), vec![]);
        let mut next = bundle;
        next.pool_generation += 1;
        active.check_switch(generation, &next).unwrap();
        let mut other = next.clone();
        other.proxy_ca_sha256 = "c".repeat(64);
        assert_eq!(
            active.check_switch(generation, &other),
            Err(BindingError::Invalid)
        );
        active.replace(generation, next.clone(), vec![]).unwrap();
        next.pool_generation += 1;
        assert!(matches!(
            active.replace(generation, next, vec![]),
            Err(BindingError::Pending)
        ));
        assert!(active.checkout_record(generation + 1).is_ok());
    }

    #[tokio::test]
    async fn both_pool_engines_reject_unpinned_ca_before_native_io() {
        let cancel = CancellationToken::new();
        for engine in [EngineFamily::PostgreSql, EngineFamily::MySql] {
            assert!(matches!(
                AwsSessionPool::open(bundle_for(engine), b"wrong-ca", 1, &cancel).await,
                Err(BindingError::Invalid)
            ));
        }
    }
}
