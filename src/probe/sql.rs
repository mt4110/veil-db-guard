//! Fixed SQL only. Identifiers are generated and validated; synthetic values are bound.
use super::transport::{Session, bounded, classify};
use crate::domain::*;
use sha2::{Digest, Sha256};
use std::{future::Future, time::Duration};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct SqlCase {
    pub case: &'static str,
    pub matched: bool,
    pub facts: Vec<Fact>,
}
#[derive(Debug)]
pub struct SqlProgress {
    pub schema: String,
    pub cases: Vec<SqlCase>,
    pub failure: Option<ReasonCode>,
    pub commit_uncertain: bool,
}

pub fn owned_schema(prefix: &str, run: &str, path: &str) -> Result<String, ReasonCode> {
    if !crate::config::sql_id(prefix)
        || !crate::config::safe_id(run)
        || !crate::config::safe_id(path)
    {
        return Err(ReasonCode::ConfigInvalid);
    }
    let digest = format!("{:x}", Sha256::digest(format!("{run}\0{path}").as_bytes()));
    let schema = format!("{}_{}", &prefix[..prefix.len().min(38)], &digest[..24]);
    if !crate::config::sql_id(&schema) {
        return Err(ReasonCode::ConfigInvalid);
    }
    Ok(schema)
}

pub async fn query<F, T>(
    future: F,
    config: &TargetConfig,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<T, ReasonCode>
where
    F: Future<Output = Result<T, tokio_postgres::Error>>,
{
    bounded(
        future,
        deadline.min(Instant::now() + Duration::from_millis(config.limits.query_timeout_ms)),
        cancel,
        ReasonCode::QueryTimeout,
    )
    .await?
    .map_err(|error| classify(&error, false))
}

/// CREATE SCHEMA deliberately has no IF NOT EXISTS. An existing run/foreign schema is never reused.
pub async fn positive(
    session: &Session,
    second: &Session,
    config: &TargetConfig,
    run: &str,
    path: &str,
    deadline: Instant,
    cancel: &CancellationToken,
) -> SqlProgress {
    let schema = match owned_schema(
        config
            .test_scope
            .as_ref()
            .map(|s| s.schema_prefix.as_str())
            .unwrap_or(""),
        run,
        path,
    ) {
        Ok(schema) => schema,
        Err(reason) => {
            return SqlProgress {
                schema: String::new(),
                cases: vec![],
                failure: Some(reason),
                commit_uncertain: false,
            };
        }
    };
    let mut progress = SqlProgress {
        schema: schema.clone(),
        cases: vec![],
        failure: None,
        commit_uncertain: false,
    };
    let client = &session.client;
    let table = format!("\"{schema}\".operations");
    let result: Result<(),ReasonCode> = async {
        query(client.batch_execute(&format!("CREATE SCHEMA \"{schema}\"; CREATE TABLE {table} (operation_id text PRIMARY KEY, value integer NOT NULL)")), config, deadline, cancel).await?;
        query(client.batch_execute("BEGIN"), config, deadline, cancel).await?;
        let operation = "synthetic-crud";
        let initial = 11_i32;
        query(client.execute(&format!("INSERT INTO {table} (operation_id,value) VALUES ($1,$2)"), &[&operation,&initial]), config, deadline,cancel).await?;
        let select = format!("SELECT value FROM {table} WHERE operation_id=$1");
        let row = query(client.query_one(&select, &[&operation]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.insert_read", matched:row.get::<_,i32>(0)==initial, facts:vec![Fact::CrudMatched] });
        let updated = 29_i32;
        query(client.execute(&format!("UPDATE {table} SET value=$1 WHERE operation_id=$2"), &[&updated,&operation]),config,deadline,cancel).await?;
        let row = query(client.query_one(&select, &[&operation]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.update_read", matched:row.get::<_,i32>(0)==updated, facts:vec![Fact::CrudMatched] });
        // Only this run's synthetic row is deleted, within the rollback-only CRUD transaction.
        query(client.execute(&format!("DELETE FROM {table} WHERE operation_id=$1"), &[&operation]),config,deadline,cancel).await?;
        let rows = query(client.query(&select,&[&operation]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.delete_read", matched:rows.is_empty(), facts:vec![Fact::CrudMatched] });
        query(client.batch_execute("ROLLBACK"),config,deadline,cancel).await?;
        let rows = query(client.query(&format!("SELECT operation_id FROM {table}"),&[]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.rollback", matched:rows.is_empty(), facts:vec![Fact::RollbackMatched] });

        query(client.batch_execute("BEGIN"),config,deadline,cancel).await?;
        let operation = "committed-operation";
        query(client.execute(&format!("INSERT INTO {table} (operation_id,value) VALUES ($1,$2)"), &[&operation,&initial]),config,deadline,cancel).await?;
        let before = query(second.client.query(&select,&[&operation]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.session_isolation", matched:before.is_empty(), facts:vec![Fact::SessionIsolated] });
        // From this point a timeout/connection loss may hide a successful commit. Never replay this write.
        if let Err(reason) = commit_once(session,config,deadline,cancel).await {
            progress.commit_uncertain = true; return Err(reason);
        }
        let rows = query(second.client.query(&select,&[&operation]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.commit", matched:rows.len()==1 && rows[0].get::<_,i32>(0)==initial, facts:vec![Fact::CommitMatched, Fact::PostconditionVerified, Fact::NoWriteReplay] });

        query(client.batch_execute("BEGIN"),config,deadline,cancel).await?;
        let failed_operation = "rolled-back-error";
        query(client.execute(&format!("INSERT INTO {table} (operation_id,value) VALUES ($1,$2)"), &[&failed_operation,&initial]),config,deadline,cancel).await?;
        let expected_error = bounded(client.query_one("SELECT 1/0",&[]),deadline.min(Instant::now()+Duration::from_millis(config.limits.query_timeout_ms)),cancel,ReasonCode::QueryTimeout).await?;
        let exact_error = expected_error.as_ref().err().and_then(|e|e.as_db_error()).is_some_and(|e|e.code().code()=="22012");
        query(client.batch_execute("ROLLBACK"),config,deadline,cancel).await?;
        let rows = query(second.client.query(&select,&[&failed_operation]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V06.error_rollback", matched:exact_error && rows.is_empty(), facts:vec![Fact::ErrorRollbackMatched] });
        let statement = query(client.prepare("SELECT $1::integer + $2::integer"),config,deadline,cancel).await?;
        let prepared = query(client.query_one(&statement,&[&3_i32,&4_i32]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V16.prepared_statement",matched:prepared.get::<_,i32>(0)==7,facts:vec![Fact::PreparedStatementUsed] });
        // A bound session-local value must not appear on the independent connection.
        let marker = "vdg-session-state";
        query(client.query_one("SELECT set_config('application_name',$1,false)",&[&marker]),config,deadline,cancel).await?;
        let row = query(second.client.query_one("SELECT current_setting('application_name')",&[]),config,deadline,cancel).await?;
        progress.cases.push(SqlCase { case:"V16.session_state",matched:row.get::<_,String>(0)!=marker,facts:vec![Fact::SessionIsolated] });
        Ok(())
    }.await;
    if let Err(reason) = result {
        progress.failure = Some(reason);
    }
    progress
}

/// Sends COMMIT exactly once. Every missing acknowledgment leaves the write result uncertain.
pub async fn commit_once(
    session: &Session,
    config: &TargetConfig,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), ReasonCode> {
    query(
        session.client.batch_execute("COMMIT"),
        config,
        deadline,
        cancel,
    )
    .await
    .map_err(|_| ReasonCode::WriteOutcomeUnknown)
}

/// Read-only reconciliation of the unique operation marker; never resubmits INSERT/COMMIT.
pub async fn reconcile_commit(
    session: &Session,
    schema: &str,
    config: &TargetConfig,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<bool, ReasonCode> {
    if !crate::config::sql_id(schema) {
        return Err(ReasonCode::ConfigInvalid);
    }
    let rows = query(
        session.client.query(
            &format!("SELECT value FROM \"{schema}\".operations WHERE operation_id=$1"),
            &[&"committed-operation"],
        ),
        config,
        deadline,
        cancel,
    )
    .await?;
    Ok(rows.len() == 1 && rows[0].get::<_, i32>(0) == 11)
}

/// A reset is exercised on a disposable dedicated session, never the application's pool.
pub async fn reset_session(
    session: &Session,
    config: &TargetConfig,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<bool, ReasonCode> {
    query(
        session.client.batch_execute(
            "SET application_name='vdg-reset-synthetic'; PREPARE vdg_reset_marker AS SELECT 1",
        ),
        config,
        deadline,
        cancel,
    )
    .await?;
    query(
        session.client.batch_execute("DISCARD ALL"),
        config,
        deadline,
        cancel,
    )
    .await?;
    let row=query(session.client.query_one("SELECT current_setting('application_name'), (SELECT count(*)::bigint FROM pg_prepared_statements WHERE name=$1)",&[&"vdg_reset_marker"]),config,deadline,cancel).await?;
    let reset = row.get::<_, String>(0) != "vdg-reset-synthetic" && row.get::<_, i64>(1) == 0;
    // DISCARD ALL reset statement_timeout, so restore it immediately on this session.
    let setting = config.limits.query_timeout_ms.to_string();
    query(
        session.client.query_one(
            "SELECT set_config('statement_timeout',$1,false)",
            &[&setting],
        ),
        config,
        deadline,
        cancel,
    )
    .await?;
    Ok(reset)
}

pub async fn long_transaction(
    session: &Session,
    duration_ms: u64,
    config: &TargetConfig,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<bool, ReasonCode> {
    if duration_ms == 0
        || duration_ms >= config.limits.query_timeout_ms
        || duration_ms >= config.limits.total_timeout_ms
    {
        return Err(ReasonCode::ConfigInvalid);
    }
    query(
        session.client.batch_execute("BEGIN READ ONLY"),
        config,
        deadline,
        cancel,
    )
    .await?;
    let before = query(
        session.client.query_one("SELECT txid_current()::text", &[]),
        config,
        deadline,
        cancel,
    )
    .await?
    .get::<_, String>(0);
    let seconds = duration_ms as f64 / 1000.0;
    query(
        session
            .client
            .query_one("SELECT pg_sleep($1::double precision)", &[&seconds]),
        config,
        deadline,
        cancel,
    )
    .await?;
    let after = query(
        session.client.query_one("SELECT txid_current()::text", &[]),
        config,
        deadline,
        cancel,
    )
    .await?
    .get::<_, String>(0);
    query(
        session.client.batch_execute("COMMIT"),
        config,
        deadline,
        cancel,
    )
    .await?;
    Ok(before == after)
}

/// Only this fixed, read-only sleep workload is exposed for deadline/cancel fault trials.
pub async fn sleep_read(
    session: &Session,
    config: &TargetConfig,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), ReasonCode> {
    query(
        session.client.query_one("SELECT pg_sleep(0.2)", &[]),
        config,
        deadline,
        cancel,
    )
    .await
    .map(|_| ())
}
