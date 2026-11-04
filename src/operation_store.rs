//! Transactional local operation ledger. No native/cloud executor lives here.
use crate::{
    config::hash_bytes,
    core::{
        approval::ApprovalGrant,
        change::{ConflictKey, PreparedChange},
        operation::*,
        policy::{valid_hash, valid_id},
        ports::OperationLedger,
    },
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, fs::OpenOptions, path::Path, time::Duration};

const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_LEASE_SECONDS: u64 = 3600;
pub const MAX_LEDGER_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_OPERATION_EVENTS: usize = 16_384;
const APPLICATION_ID: u32 = 0x5644_4731; // VDG1

pub struct OperationStore {
    connection: Connection,
}

// Keep the existing concrete API available to callers while the kernel depends
// only on its inner port. All writes retain the transactional implementation.
impl OperationLedger for OperationStore {
    fn get(&self, id: &str) -> Result<Operation, StoreError> {
        OperationStore::get(self, id)
    }
    fn load_change(&self, hash: &str) -> Result<PreparedChange, StoreError> {
        OperationStore::load_change(self, hash)
    }
    fn steps(&self, id: &str) -> Result<Vec<StepRecord>, StoreError> {
        OperationStore::steps(self, id)
    }
    fn acquire_leases(
        &mut self,
        operation_id: &str,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError> {
        OperationStore::acquire_leases(self, operation_id, holder, now, ttl)
    }
    fn renew_leases(
        &mut self,
        lease: &LeaseSet,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError> {
        OperationStore::renew_leases(self, lease, now, ttl)
    }
    fn release_leases(&mut self, lease: &LeaseSet) -> Result<(), StoreError> {
        OperationStore::release_leases(self, lease)
    }
    fn dispatch(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        identity: &str,
        now: u64,
    ) -> Result<DispatchTicket, StoreError> {
        OperationStore::dispatch(
            self,
            operation_id,
            step_id,
            expected_version,
            leases,
            identity,
            now,
        )
    }
    fn record_receipt(
        &mut self,
        ticket: &DispatchTicket,
        receipt: &StepReceipt,
        now: u64,
    ) -> Result<Operation, StoreError> {
        OperationStore::record_receipt(self, ticket, receipt, now)
    }
    fn resolve(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        receipt: &StepReceipt,
        identity: &str,
        now: u64,
    ) -> Result<Operation, StoreError> {
        OperationStore::resolve(
            self,
            operation_id,
            step_id,
            expected_version,
            leases,
            receipt,
            identity,
            now,
        )
    }
    fn set_state(
        &mut self,
        id: &str,
        expected_version: u64,
        state: ExecutionState,
        now: u64,
    ) -> Result<Operation, StoreError> {
        OperationStore::set_state(self, id, expected_version, state, now)
    }
}

fn encoded<T: Serialize>(value: &T) -> Result<String, StoreError> {
    let s = serde_json::to_string(value).map_err(|_| StoreError::Invalid)?;
    if s.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Limit);
    }
    Ok(s)
}
fn decoded<T: DeserializeOwned>(s: &str) -> Result<T, StoreError> {
    if s.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Limit);
    }
    serde_json::from_str(s).map_err(|_| StoreError::Invalid)
}
fn db<T>(result: rusqlite::Result<T>) -> Result<T, StoreError> {
    result.map_err(|_| StoreError::Storage)
}
fn timestamp(now: u64) -> Result<(), StoreError> {
    if now == 0 || now > i64::MAX as u64 {
        Err(StoreError::Invalid)
    } else {
        Ok(())
    }
}
fn event(
    connection: &Connection,
    op: &str,
    kind: EventKind,
    step: Option<&str>,
    at: u64,
) -> Result<(), StoreError> {
    db(connection.execute(
        "INSERT INTO operation_events(operation_id,kind,step_id,at) VALUES(?1,?2,?3,?4)",
        params![op, encoded(&kind)?, step, at],
    ))?;
    Ok(())
}
fn get_operation(connection: &Connection, id: &str) -> Result<Operation, StoreError> {
    let body: Option<String> = db(connection
        .query_row("SELECT body FROM operations WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional())?;
    decoded(&body.ok_or(StoreError::NotFound)?)
}
fn get_change(connection: &Connection, hash: &str) -> Result<PreparedChange, StoreError> {
    let body: Option<String> = db(connection
        .query_row("SELECT body FROM plans WHERE hash=?1", [hash], |r| r.get(0))
        .optional())?;
    let change: PreparedChange = decoded(&body.ok_or(StoreError::NotFound)?)?;
    change.verify().map_err(|_| StoreError::Invalid)?;
    Ok(change)
}
fn get_approval(connection: &Connection, id: &str) -> Result<ApprovalGrant, StoreError> {
    let body: Option<String> = db(connection
        .query_row("SELECT body FROM approvals WHERE id=?1", [id], |r| r.get(0))
        .optional())?;
    decoded(&body.ok_or(StoreError::NotFound)?)
}
fn get_step(connection: &Connection, op: &str, step: &str) -> Result<StepRecord, StoreError> {
    let body: Option<String> = db(connection
        .query_row(
            "SELECT body FROM steps WHERE operation_id=?1 AND step_id=?2",
            params![op, step],
            |r| r.get(0),
        )
        .optional())?;
    decoded(&body.ok_or(StoreError::NotFound)?)
}
fn all_steps(connection: &Connection, op: &str) -> Result<Vec<StepRecord>, StoreError> {
    let mut stmt =
        db(connection.prepare("SELECT body FROM steps WHERE operation_id=?1 ORDER BY ordinal"))?;
    let rows = db(stmt.query_map([op], |r| r.get::<_, String>(0)))?;
    rows.map(|row| decoded(&db(row)?)).collect()
}
fn save_operation(
    connection: &Connection,
    op: &mut Operation,
    expected: u64,
    now: u64,
) -> Result<(), StoreError> {
    if now < op.updated_at {
        return Err(StoreError::Invalid);
    }
    op.version = expected.checked_add(1).ok_or(StoreError::Limit)?;
    op.updated_at = now;
    let n = db(connection.execute(
        "UPDATE operations SET version=?1,state=?2,body=?3 WHERE id=?4 AND version=?5",
        params![
            op.version,
            encoded(&op.state)?,
            encoded(op)?,
            op.id,
            expected
        ],
    ))?;
    if n != 1 {
        return Err(StoreError::Stale);
    }
    Ok(())
}
fn save_step(connection: &Connection, op: &str, step: &StepRecord) -> Result<(), StoreError> {
    let n = db(connection.execute(
        "UPDATE steps SET state=?1,body=?2 WHERE operation_id=?3 AND step_id=?4",
        params![encoded(&step.state)?, encoded(step)?, op, step.step_id],
    ))?;
    if n != 1 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}
fn unresolved(state: StepState) -> bool {
    matches!(
        state,
        StepState::Dispatching
            | StepState::Submitted
            | StepState::ConfigApplied
            | StepState::OutcomeUnknown
            | StepState::Compensating
    )
}
fn satisfied(state: StepState) -> bool {
    matches!(state, StepState::EffectSatisfied | StepState::NoOpSatisfied)
}
fn active_desired(connection: &Connection, policy: &str) -> Result<Option<String>, StoreError> {
    db(connection
        .query_row(
            "SELECT revision_hash FROM desired_heads WHERE policy_id=?1",
            [policy],
            |r| r.get(0),
        )
        .optional())
}
fn conflict_keys(change: &PreparedChange) -> Vec<ConflictKey> {
    let mut keys = change.conflict_keys.clone();
    // Conservative whole-resource locks also protect plans from different policy IDs.
    for target in &change.policy.targets {
        keys.push(ConflictKey {
            resource_identity: target.resource.native_id.clone(),
            field_or_domain: "*".into(),
        });
    }
    keys.sort();
    keys.dedup();
    keys
}

impl OperationStore {
    /// Infrastructure-only access for the evidence ledger sharing this safely
    /// opened SQLite file. Core still depends solely on ledger ports.
    pub(crate) fn evidence_connection(&mut self) -> &mut Connection {
        &mut self.connection
    }
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_inner(path, true)
    }
    pub fn open_existing(path: &Path) -> Result<Self, StoreError> {
        Self::open_inner(path, false)
    }
    fn open_inner(path: &Path, create: bool) -> Result<Self, StoreError> {
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(StoreError::Invalid);
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let pm = std::fs::symlink_metadata(parent).map_err(|_| StoreError::Storage)?;
        if !pm.is_dir() || pm.file_type().is_symlink() {
            return Err(StoreError::Invalid);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // The ledger directory must not permit another OS user to swap its files.
            if pm.uid() != unsafe { libc::geteuid() } || pm.mode() & 0o022 != 0 {
                return Err(StoreError::Invalid);
            }
        }
        let actual = parent
            .canonicalize()
            .map_err(|_| StoreError::Storage)?
            .join(path.file_name().ok_or(StoreError::Invalid)?);
        let mut newly_created = false;
        match std::fs::symlink_metadata(&actual) {
            Ok(m) => {
                if !m.is_file() || m.file_type().is_symlink() {
                    return Err(StoreError::Invalid);
                }
                if m.len() > MAX_LEDGER_BYTES {
                    return Err(StoreError::Limit);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if m.mode() & 0o077 != 0
                        || m.uid() != unsafe { libc::geteuid() }
                        || m.nlink() != 1
                    {
                        return Err(StoreError::Invalid);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                let mut o = OpenOptions::new();
                o.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    o.mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                }
                o.open(&actual)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| StoreError::Storage)?;
                newly_created = true;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(_) => return Err(StoreError::Storage),
        }
        if !newly_created {
            // Check the namespace before SQLite can read/recover a hot journal.
            // Even opening an unrelated SQLite file for a PRAGMA could recover it.
            use std::io::Read;
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            let mut header = [0u8; 100];
            options
                .open(&actual)
                .and_then(|mut file| file.read_exact(&mut header))
                .map_err(|_| StoreError::Invalid)?;
            let version =
                u32::from_be_bytes(header[60..64].try_into().map_err(|_| StoreError::Invalid)?);
            let application =
                u32::from_be_bytes(header[68..72].try_into().map_err(|_| StoreError::Invalid)?);
            if &header[..16] != b"SQLite format 3\0"
                || version != 1
                || application != APPLICATION_ID
            {
                return Err(StoreError::Invalid);
            }
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            let side = std::path::PathBuf::from(format!(
                "{}{suffix}",
                actual.to_str().ok_or(StoreError::Invalid)?
            ));
            if let Ok(m) = std::fs::symlink_metadata(side) {
                if !m.is_file() || m.file_type().is_symlink() {
                    return Err(StoreError::Invalid);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if m.mode() & 0o077 != 0
                        || m.uid() != unsafe { libc::geteuid() }
                        || m.nlink() != 1
                    {
                        return Err(StoreError::Invalid);
                    }
                }
            }
        }
        // URI processing is deliberately absent; even a name beginning file: is a path.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = db(Connection::open_with_flags(&actual, flags))?;
        db(connection.busy_timeout(Duration::from_secs(2)))?;
        let version: u32 = db(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        if version > 1 || (!newly_created && version != 1) {
            return Err(StoreError::Invalid);
        }
        let application_id: u32 =
            db(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
        if !newly_created && application_id != APPLICATION_ID {
            return Err(StoreError::Invalid);
        }
        db(connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;"))?;
        let page_size: u64 = db(connection.pragma_query_value(None, "page_size", |r| r.get(0)))?;
        if page_size == 0 {
            return Err(StoreError::Invalid);
        }
        let max_pages = MAX_LEDGER_BYTES / page_size;
        let actual_max: u64 = db(connection.query_row(
            &format!("PRAGMA max_page_count={max_pages}"),
            [],
            |r| r.get(0),
        ))?;
        if actual_max > max_pages {
            return Err(StoreError::Limit);
        }
        if newly_created {
            db(connection.execute_batch("BEGIN IMMEDIATE;
                CREATE TABLE policy_revisions(hash TEXT PRIMARY KEY,policy_id TEXT NOT NULL,body TEXT NOT NULL);
                CREATE TABLE plans(hash TEXT PRIMARY KEY,policy_hash TEXT NOT NULL REFERENCES policy_revisions(hash),body TEXT NOT NULL);
                CREATE TABLE approvals(id TEXT PRIMARY KEY,change_hash TEXT NOT NULL REFERENCES plans(hash),body TEXT NOT NULL,cancelled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE approval_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,approval_id TEXT NOT NULL REFERENCES approvals(id),at INTEGER NOT NULL,kind TEXT NOT NULL);
                CREATE TABLE desired_heads(policy_id TEXT PRIMARY KEY,revision_hash TEXT NOT NULL REFERENCES policy_revisions(hash));
                CREATE TABLE operations(id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,input_hash TEXT NOT NULL,change_hash TEXT NOT NULL REFERENCES plans(hash),approval_id TEXT NOT NULL REFERENCES approvals(id),policy_id TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL);
                CREATE TABLE steps(operation_id TEXT NOT NULL REFERENCES operations(id),step_id TEXT NOT NULL,ordinal INTEGER NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(operation_id,step_id));
                CREATE TABLE step_attempts(operation_id TEXT NOT NULL,step_id TEXT NOT NULL,attempt INTEGER NOT NULL,idempotency_key TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(operation_id,step_id,attempt),FOREIGN KEY(operation_id,step_id) REFERENCES steps(operation_id,step_id));
                CREATE TABLE step_results(seq INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT NOT NULL,step_id TEXT NOT NULL,attempt INTEGER NOT NULL,body TEXT NOT NULL,at INTEGER NOT NULL,FOREIGN KEY(operation_id,step_id,attempt) REFERENCES step_attempts(operation_id,step_id,attempt));
                CREATE TABLE operation_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,operation_id TEXT NOT NULL REFERENCES operations(id),kind TEXT NOT NULL,step_id TEXT,at INTEGER NOT NULL);
                CREATE TABLE resource_leases(key TEXT PRIMARY KEY,resource TEXT NOT NULL,domain TEXT NOT NULL,operation_id TEXT NOT NULL REFERENCES operations(id),holder TEXT NOT NULL,token INTEGER NOT NULL,expires_at INTEGER NOT NULL);
                CREATE TABLE ledger_counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
                INSERT INTO ledger_counters(name,value) VALUES('lease_fence',0);
                PRAGMA application_id=1447315249; PRAGMA user_version=1; COMMIT;"))?;
        }
        Ok(Self { connection })
    }

    pub fn register_change(&mut self, change: &PreparedChange) -> Result<(), StoreError> {
        change.verify().map_err(|_| StoreError::Invalid)?;
        let body = encoded(change)?;
        let policy = encoded(&change.policy)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        check_lifecycle_source(&tx, change)?;
        let existing: Option<String> = db(tx
            .query_row(
                "SELECT body FROM plans WHERE hash=?1",
                [&change.change_hash],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(existing) = existing {
            if existing != body {
                return Err(StoreError::Conflict);
            }
            return Ok(());
        }
        let hash = &change.plan.policy_revision_hash;
        let old: Option<String> = db(tx
            .query_row(
                "SELECT body FROM policy_revisions WHERE hash=?1",
                [hash],
                |r| r.get(0),
            )
            .optional())?;
        if old.as_ref().is_some_and(|v| v != &policy) {
            return Err(StoreError::Conflict);
        }
        db(tx.execute(
            "INSERT OR IGNORE INTO policy_revisions(hash,policy_id,body) VALUES(?1,?2,?3)",
            params![hash, change.policy.policy_id, policy],
        ))?;
        db(tx.execute(
            "INSERT INTO plans(hash,policy_hash,body) VALUES(?1,?2,?3)",
            params![change.change_hash, hash, body],
        ))?;
        db(tx.commit())
    }
    pub fn register_approval(
        &mut self,
        change: &PreparedChange,
        approval: &ApprovalGrant,
    ) -> Result<(), StoreError> {
        change.verify().map_err(|_| StoreError::Invalid)?;
        // Issuance may precede dispatch and validates at its own bounded interval.
        approval
            .validate(
                change,
                &approval.execution_identity,
                approval.issued_at,
                false,
            )
            .map_err(|_| StoreError::Approval)?;
        let body = encoded(approval)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let stored = get_change(&tx, &change.change_hash)?;
        if encoded(&stored)? != encoded(change)? {
            return Err(StoreError::Conflict);
        }
        let old: Option<String> = db(tx
            .query_row(
                "SELECT body FROM approvals WHERE id=?1",
                [&approval.id],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(old) = old {
            if old != body {
                return Err(StoreError::Conflict);
            }
            return Ok(());
        }
        db(tx.execute(
            "INSERT INTO approvals(id,change_hash,body) VALUES(?1,?2,?3)",
            params![approval.id, change.change_hash, body],
        ))?;
        db(tx.commit())
    }
    pub fn load_change(&self, hash: &str) -> Result<PreparedChange, StoreError> {
        get_change(&self.connection, hash)
    }
    pub fn load_approval(&self, id: &str) -> Result<ApprovalGrant, StoreError> {
        get_approval(&self.connection, id)
    }
    pub fn desired_head(&self, policy_id: &str) -> Result<Option<String>, StoreError> {
        active_desired(&self.connection, policy_id)
    }
    pub fn get(&self, id: &str) -> Result<Operation, StoreError> {
        get_operation(&self.connection, id)
    }
    pub fn steps(&self, id: &str) -> Result<Vec<StepRecord>, StoreError> {
        self.get(id)?;
        all_steps(&self.connection, id)
    }
    pub fn events(&self, id: &str) -> Result<Vec<OperationEvent>, StoreError> {
        self.get(id)?;
        let mut s=db(self.connection.prepare("SELECT seq,kind,step_id,at FROM operation_events WHERE operation_id=?1 ORDER BY seq LIMIT 16385"))?;
        let rows = db(s.query_map([id], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, u64>(3)?,
            ))
        }))?;
        let events = rows
            .map(|r| {
                let (sequence, kind, step_id, at) = db(r)?;
                Ok(OperationEvent {
                    sequence,
                    operation_id: id.into(),
                    event: decoded(&kind)?,
                    step_id,
                    at,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        if events.len() > MAX_OPERATION_EVENTS {
            return Err(StoreError::Limit);
        }
        Ok(events)
    }

    pub fn begin(&mut self, request: &BeginRequest) -> Result<Operation, StoreError> {
        timestamp(request.now)?;
        if !valid_id(&request.request_id)
            || !valid_id(&request.operation_id)
            || !valid_id(&request.approval_id)
            || !valid_hash(&request.change_hash)
            || !valid_execution_identity(&request.execution_identity)
            || request
                .expected_desired_head
                .as_ref()
                .is_some_and(|v| !valid_hash(v))
        {
            return Err(StoreError::Invalid);
        }
        // Time is not request intent: the same request survives a later retry.
        let input_hash = hash_bytes(
            encoded(&(
                &request.operation_id,
                &request.change_hash,
                &request.approval_id,
                &request.expected_desired_head,
                &request.execution_identity,
            ))?
            .as_bytes(),
        );
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let sessions:bool=db(tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_sessions')",[],|r|r.get(0)))?;
        if sessions
            && db(tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM evidence_sessions WHERE id=?1)",
                [&request.operation_id],
                |r| r.get::<_, bool>(0),
            ))?
        {
            return Err(StoreError::Conflict);
        }
        let prior: Option<String> = db(tx
            .query_row(
                "SELECT body FROM operations WHERE request_id=?1",
                [&request.request_id],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(body) = prior {
            let op: Operation = decoded(&body)?;
            if op.input_hash != input_hash {
                return Err(StoreError::Conflict);
            }
            return Ok(op);
        }
        let change = get_change(&tx, &request.change_hash)?;
        check_lifecycle_source(&tx, &change)?;
        check_repair_budget(&tx, &change)?;
        let approval = get_approval(&tx, &request.approval_id)?;
        ensure_approval(
            &tx,
            &change,
            &approval,
            &request.execution_identity,
            request.now,
            false,
        )?;
        let current = active_desired(&tx, &change.policy.policy_id)?;
        if current != request.expected_desired_head {
            return Err(StoreError::Conflict);
        }
        if current.is_some()
            && current != change.policy.parent_revision_hash
            && current != Some(change.plan.policy_revision_hash.clone())
        {
            return Err(StoreError::Conflict);
        }
        if current.is_none() && change.policy.parent_revision_hash.is_some() {
            return Err(StoreError::Conflict);
        }
        let op = Operation {
            id: request.operation_id.clone(),
            request_id: request.request_id.clone(),
            input_hash,
            change_hash: change.change_hash.clone(),
            approval_id: approval.id,
            policy_id: change.policy.policy_id.clone(),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            execution_identity: request.execution_identity.clone(),
            version: 0,
            state: ExecutionState::Prepared,
            attempts: 0,
            created_at: request.now,
            updated_at: request.now,
        };
        db(tx.execute("INSERT INTO operations(id,request_id,input_hash,change_hash,approval_id,policy_id,version,state,body) VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8)",params![op.id,op.request_id,op.input_hash,op.change_hash,op.approval_id,op.policy_id,encoded(&op.state)?,encoded(&op)?]))?;
        db(tx.execute("INSERT INTO desired_heads(policy_id,revision_hash) VALUES(?1,?2) ON CONFLICT(policy_id) DO UPDATE SET revision_hash=excluded.revision_hash",params![op.policy_id,op.policy_revision_hash]))?;
        for (ordinal, step) in change.plan.steps.iter().enumerate() {
            let key = hash_bytes(
                encoded(&(
                    &op.id,
                    &step.id,
                    &step.target_id,
                    &step.parameters_hash,
                    &change
                        .target_scope_hash()
                        .map_err(|_| StoreError::Invalid)?,
                ))?
                .as_bytes(),
            );
            let record = StepRecord {
                step_id: step.id.clone(),
                state: StepState::Prepared,
                attempt: 0,
                idempotency_key: key,
                receipt: None,
            };
            db(tx.execute(
                "INSERT INTO steps(operation_id,step_id,ordinal,state,body) VALUES(?1,?2,?3,?4,?5)",
                params![
                    op.id,
                    step.id,
                    ordinal,
                    encoded(&record.state)?,
                    encoded(&record)?
                ],
            ))?;
        }
        event(&tx, &op.id, EventKind::Begun, None, request.now)?;
        db(tx.commit())?;
        Ok(op)
    }

    pub fn acquire_leases(
        &mut self,
        operation_id: &str,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError> {
        timestamp(now)?;
        if !valid_id(holder) || ttl == 0 || ttl > MAX_LEASE_SECONDS {
            return Err(StoreError::Invalid);
        }
        let expires_at = now
            .checked_add(ttl)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let op = get_operation(&tx, operation_id)?;
        let change = get_change(&tx, &op.change_hash)?;
        let keys = conflict_keys(&change);
        let mut existing_token = None;
        let mut all_owned = true;
        for key in &keys {
            let mut s=db(tx.prepare("SELECT resource,domain,operation_id,holder,token,expires_at FROM resource_leases WHERE expires_at>?1"))?;
            let rows = db(s.query_map([now], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, u64>(4)?,
                    r.get::<_, u64>(5)?,
                ))
            }))?;
            let mut exact_owned = false;
            for row in rows {
                let (resource, domain, owner, who, token, _) = db(row)?;
                let other = ConflictKey {
                    resource_identity: resource,
                    field_or_domain: domain,
                };
                if key.conflicts(&other) && (owner != operation_id || who != holder) {
                    return Err(StoreError::Lease);
                }
                if *key == other && owner == operation_id && who == holder {
                    if existing_token.is_some_and(|v| v != token) {
                        return Err(StoreError::Lease);
                    }
                    existing_token = Some(token);
                    exact_owned = true;
                }
            }
            all_owned &= exact_owned;
        }
        let token = if all_owned {
            existing_token.ok_or(StoreError::Invalid)?
        } else {
            let old: u64 = db(tx.query_row(
                "SELECT value FROM ledger_counters WHERE name='lease_fence'",
                [],
                |r| r.get(0),
            ))?;
            let next = old
                .checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or(StoreError::Limit)?;
            db(tx.execute(
                "UPDATE ledger_counters SET value=?1 WHERE name='lease_fence'",
                [next],
            ))?;
            next
        };
        for key in &keys {
            db(tx.execute("INSERT INTO resource_leases(key,resource,domain,operation_id,holder,token,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(key) DO UPDATE SET operation_id=excluded.operation_id,holder=excluded.holder,token=excluded.token,expires_at=excluded.expires_at",params![key.canonical_key(),key.resource_identity,key.field_or_domain,operation_id,holder,token,expires_at]))?;
        }
        let lease = LeaseSet {
            holder: holder.into(),
            token,
            keys: keys.iter().map(ConflictKey::canonical_key).collect(),
            expires_at,
        };
        db(tx.commit())?;
        Ok(lease)
    }
    pub fn renew_leases(
        &mut self,
        lease: &LeaseSet,
        now: u64,
        ttl: u64,
    ) -> Result<LeaseSet, StoreError> {
        timestamp(now)?;
        if ttl == 0 || ttl > MAX_LEASE_SECONDS {
            return Err(StoreError::Invalid);
        }
        let expires_at = now
            .checked_add(ttl)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(StoreError::Invalid)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        for key in &lease.keys {
            let n=db(tx.execute("UPDATE resource_leases SET expires_at=?1 WHERE key=?2 AND holder=?3 AND token=?4 AND expires_at>?5",params![expires_at,key,lease.holder,lease.token,now]))?;
            if n != 1 {
                return Err(StoreError::Stale);
            }
        }
        db(tx.commit())?;
        Ok(LeaseSet {
            expires_at,
            ..lease.clone()
        })
    }
    pub fn release_leases(&mut self, lease: &LeaseSet) -> Result<(), StoreError> {
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        for key in &lease.keys {
            db(tx.execute(
                "DELETE FROM resource_leases WHERE key=?1 AND holder=?2 AND token=?3",
                params![key, lease.holder, lease.token],
            ))?;
        }
        db(tx.commit())
    }

    pub fn dispatch(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        identity: &str,
        now: u64,
    ) -> Result<DispatchTicket, StoreError> {
        timestamp(now)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut op = get_operation(&tx, operation_id)?;
        if op.version != expected_version {
            return Err(StoreError::Stale);
        }
        if matches!(
            op.state,
            ExecutionState::Completed | ExecutionState::Cancelled | ExecutionState::FailedPartial
        ) {
            return Err(StoreError::Transition);
        }
        let change = get_change(&tx, &op.change_hash)?;
        check_lifecycle_source(&tx, &change)?;
        let approval = get_approval(&tx, &op.approval_id)?;
        ensure_approval(&tx, &change, &approval, identity, now, false)?;
        if identity != op.execution_identity {
            return Err(StoreError::Approval);
        }
        check_leases(&tx, &op, &change, leases, now)?;
        if active_desired(&tx, &op.policy_id)? != Some(op.policy_revision_hash.clone()) {
            return Err(StoreError::Conflict);
        }
        if now < op.created_at
            || now.saturating_sub(op.created_at) > change.limits.max_operation_seconds
            || op.attempts >= change.limits.max_attempts
        {
            return Err(StoreError::Limit);
        }
        if !approval.allowed_step_ids.iter().any(|id| id == step_id) {
            return Err(StoreError::Approval);
        }
        let specification = change
            .plan
            .steps
            .iter()
            .find(|s| s.id == step_id)
            .ok_or(StoreError::NotFound)?;
        let mut step = get_step(&tx, operation_id, step_id)?;
        if !matches!(step.state, StepState::Prepared | StepState::NotApplied) {
            return Err(if unresolved(step.state) {
                StoreError::Unresolved
            } else {
                StoreError::Transition
            });
        }
        for dependency in &specification.dependencies {
            if !satisfied(get_step(&tx, operation_id, dependency)?.state) {
                return Err(StoreError::Transition);
            }
        }
        if all_steps(&tx, operation_id)?
            .iter()
            .any(|s| s.step_id != step_id && unresolved(s.state))
        {
            return Err(StoreError::Unresolved);
        }
        check_other_unresolved(&tx, &op, &change)?;
        step.attempt = step.attempt.checked_add(1).ok_or(StoreError::Limit)?;
        step.state = StepState::Dispatching;
        step.receipt = None;
        op.attempts += 1;
        op.state = ExecutionState::Running;
        save_operation(&tx, &mut op, expected_version, now)?;
        save_step(&tx, operation_id, &step)?;
        let ticket = DispatchTicket {
            operation_id: operation_id.into(),
            step_id: step_id.into(),
            attempt: step.attempt,
            operation_version: op.version,
            idempotency_key: step.idempotency_key.clone(),
            leases: leases.clone(),
        };
        db(tx.execute("INSERT INTO step_attempts(operation_id,step_id,attempt,idempotency_key,body) VALUES(?1,?2,?3,?4,?5)",params![operation_id,step_id,step.attempt,step.idempotency_key,encoded(&ticket)?]))?;
        event(&tx, operation_id, EventKind::Dispatched, Some(step_id), now)?;
        db(tx.commit())?;
        Ok(ticket)
    }
    pub fn record_receipt(
        &mut self,
        ticket: &DispatchTicket,
        receipt: &StepReceipt,
        now: u64,
    ) -> Result<Operation, StoreError> {
        self.record_result(
            &ticket.operation_id,
            &ticket.step_id,
            ticket.operation_version,
            &ticket.leases,
            receipt,
            None,
            now,
            Some(ticket),
        )
    }
    // Keep operation/step/version/lease/identity/time explicit at this trust boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        receipt: &StepReceipt,
        identity: &str,
        now: u64,
    ) -> Result<Operation, StoreError> {
        self.record_result(
            operation_id,
            step_id,
            expected_version,
            leases,
            receipt,
            Some(identity),
            now,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn record_result(
        &mut self,
        operation_id: &str,
        step_id: &str,
        expected_version: u64,
        leases: &LeaseSet,
        receipt: &StepReceipt,
        identity: Option<&str>,
        now: u64,
        ticket: Option<&DispatchTicket>,
    ) -> Result<Operation, StoreError> {
        timestamp(now)?;
        validate_receipt(receipt)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut op = get_operation(&tx, operation_id)?;
        if op.version != expected_version {
            return Err(StoreError::Stale);
        }
        if identity.is_some_and(|v| v != op.execution_identity) {
            return Err(StoreError::Approval);
        }
        let change = get_change(&tx, &op.change_hash)?;
        check_leases(&tx, &op, &change, leases, now)?;
        let mut step = get_step(&tx, operation_id, step_id)?;
        if !unresolved(step.state) {
            return Err(StoreError::Transition);
        }
        if let Some(ticket) = ticket
            && (step.state != StepState::Dispatching
                || ticket.attempt != step.attempt
                || ticket.idempotency_key != step.idempotency_key)
        {
            return Err(StoreError::Stale);
        }
        if matches!(receipt.state, StepState::NotApplied)
            && matches!(step.state, StepState::ConfigApplied)
        {
            return Err(StoreError::Transition);
        }
        if step.state == StepState::ConfigApplied && receipt.state == StepState::Submitted {
            return Err(StoreError::Transition);
        }
        let mut stored_receipt = receipt.clone();
        if let Some(previous) = step
            .receipt
            .as_ref()
            .and_then(|v| v.native_operation_ref.as_ref())
        {
            if stored_receipt
                .native_operation_ref
                .as_ref()
                .is_some_and(|v| v != previous)
            {
                return Err(StoreError::Conflict);
            }
            if stored_receipt.native_operation_ref.is_none() {
                stored_receipt.native_operation_ref = Some(previous.clone());
            }
        }
        step.state = stored_receipt.state;
        step.receipt = Some(stored_receipt.clone());
        if op.state != ExecutionState::Cancelled {
            op.state = match receipt.state {
                StepState::Submitted => ExecutionState::WaitingProvider,
                StepState::ConfigApplied => ExecutionState::WaitingEffect,
                StepState::EffectSatisfied | StepState::NoOpSatisfied => ExecutionState::Running,
                StepState::Failed => ExecutionState::FailedPartial,
                _ => ExecutionState::NeedsAction,
            };
        }
        save_operation(&tx, &mut op, expected_version, now)?;
        save_step(&tx, operation_id, &step)?;
        db(tx.execute(
            "INSERT INTO step_results(operation_id,step_id,attempt,body,at) VALUES(?1,?2,?3,?4,?5)",
            params![
                operation_id,
                step_id,
                step.attempt,
                encoded(&stored_receipt)?,
                now
            ],
        ))?;
        event(
            &tx,
            operation_id,
            if ticket.is_some() {
                EventKind::ReceiptRecorded
            } else {
                EventKind::Resolved
            },
            Some(step_id),
            now,
        )?;
        db(tx.commit())?;
        Ok(op)
    }
    pub fn set_state(
        &mut self,
        id: &str,
        expected_version: u64,
        state: ExecutionState,
        now: u64,
    ) -> Result<Operation, StoreError> {
        timestamp(now)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let mut op = get_operation(&tx, id)?;
        if op.version != expected_version {
            return Err(StoreError::Stale);
        }
        if matches!(
            op.state,
            ExecutionState::Completed | ExecutionState::Cancelled
        ) && op.state != state
        {
            return Err(StoreError::Transition);
        }
        if state == ExecutionState::Completed {
            let steps = all_steps(&tx, id)?;
            let change = get_change(&tx, &op.change_hash)?;
            if steps.is_empty()
                || steps.iter().any(|s| !satisfied(s.state))
                || !change.plan.required_effect_gaps.is_empty()
                || active_desired(&tx, &op.policy_id)? != Some(op.policy_revision_hash.clone())
            {
                return Err(StoreError::Transition);
            }
        }
        op.state = state;
        save_operation(&tx, &mut op, expected_version, now)?;
        event(&tx, id, EventKind::StateChanged, None, now)?;
        db(tx.commit())?;
        Ok(op)
    }
    pub fn cancel_approval(&mut self, id: &str, now: u64) -> Result<(), StoreError> {
        timestamp(now)?;
        let tx = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let cancelled: Option<bool> = db(tx
            .query_row("SELECT cancelled FROM approvals WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional())?;
        match cancelled {
            Some(true) => return Ok(()),
            None => return Err(StoreError::NotFound),
            Some(false) => {}
        }
        let n = db(tx.execute("UPDATE approvals SET cancelled=1 WHERE id=?1", [id]))?;
        if n != 1 {
            return Err(StoreError::NotFound);
        }
        db(tx.execute(
            "INSERT INTO approval_events(approval_id,at,kind) VALUES(?1,?2,'cancelled')",
            params![id, now],
        ))?;
        let mut stmt = db(tx.prepare("SELECT id FROM operations WHERE approval_id=?1"))?;
        let ids = db(stmt.query_map([id], |r| r.get::<_, String>(0)))?
            .map(db)
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        for op in ids {
            event(&tx, &op, EventKind::ApprovalCancelled, None, now)?;
        }
        db(tx.commit())
    }
}

fn ensure_approval(
    connection: &Connection,
    change: &PreparedChange,
    approval: &ApprovalGrant,
    identity: &str,
    now: u64,
    recovery: bool,
) -> Result<(), StoreError> {
    let cancelled: bool = db(connection.query_row(
        "SELECT cancelled FROM approvals WHERE id=?1",
        [&approval.id],
        |r| r.get(0),
    ))?;
    if cancelled {
        return Err(StoreError::Approval);
    }
    approval
        .validate(change, identity, now, recovery)
        .map_err(|_| StoreError::Approval)
}
fn check_lifecycle_source(
    connection: &Connection,
    change: &PreparedChange,
) -> Result<(), StoreError> {
    let Some(context) = &change.lifecycle else {
        return Ok(());
    };
    let operation = get_operation(connection, &context.source_operation_id)?;
    if operation.change_hash != context.source_change_hash
        || operation.policy_revision_hash != context.source_policy_revision_hash
    {
        return Err(StoreError::Conflict);
    }
    if context.kind == crate::core::lifecycle::LifecycleKind::Recover
        && !matches!(
            operation.state,
            ExecutionState::Cancelled | ExecutionState::NeedsAction | ExecutionState::FailedPartial
        )
    {
        return Err(StoreError::Transition);
    }
    let source = get_change(connection, &operation.change_hash)?;
    crate::core::lifecycle::validate_source(change, &source).map_err(|_| StoreError::Invalid)
}
fn check_repair_budget(connection: &Connection, change: &PreparedChange) -> Result<(), StoreError> {
    let Some(context) = &change.lifecycle else {
        return Ok(());
    };
    if context.kind == crate::core::lifecycle::LifecycleKind::Revoke {
        return Ok(());
    }
    let source = get_change(connection, &context.source_change_hash)?;
    let mut stmt = db(connection.prepare(
        "SELECT p.body FROM operations o JOIN plans p ON p.hash=o.change_hash WHERE o.policy_id=?1",
    ))?;
    let mut rows = db(stmt.query([&change.policy.policy_id]))?;
    let mut count = 0u32;
    let mut scanned = 0u32;
    while let Some(row) = db(rows.next())? {
        scanned += 1;
        if scanned > 16384 {
            return Err(StoreError::Limit);
        }
        let body: String = db(row.get(0))?;
        let prior: PreparedChange = decoded(&body)?;
        if prior.lifecycle.as_ref().is_some_and(|v| {
            v.source_operation_id == context.source_operation_id
                && v.kind != crate::core::lifecycle::LifecycleKind::Revoke
        }) {
            count += 1;
        }
    }
    if count >= source.limits.max_repair_executions {
        return Err(StoreError::Limit);
    }
    Ok(())
}
fn check_leases(
    connection: &Connection,
    op: &Operation,
    change: &PreparedChange,
    lease: &LeaseSet,
    now: u64,
) -> Result<(), StoreError> {
    let keys = conflict_keys(change)
        .iter()
        .map(ConflictKey::canonical_key)
        .collect::<BTreeSet<_>>();
    if lease.keys.iter().collect::<BTreeSet<_>>().len() != lease.keys.len()
        || keys != lease.keys.iter().cloned().collect()
        || lease.keys.is_empty()
    {
        return Err(StoreError::Lease);
    }
    for key in &lease.keys {
        let ok:bool=db(connection.query_row("SELECT EXISTS(SELECT 1 FROM resource_leases WHERE key=?1 AND operation_id=?2 AND holder=?3 AND token=?4 AND expires_at>?5)",params![key,op.id,lease.holder,lease.token,now],|r|r.get(0)))?;
        if !ok {
            return Err(StoreError::Stale);
        }
    }
    Ok(())
}
fn check_other_unresolved(
    connection: &Connection,
    op: &Operation,
    change: &PreparedChange,
) -> Result<(), StoreError> {
    let own = conflict_keys(change);
    let mut stmt=db(connection.prepare("SELECT DISTINCT operations.change_hash FROM operations JOIN steps ON operations.id=steps.operation_id WHERE operations.id<>?1 AND steps.state IN (?2,?3,?4,?5,?6)"))?;
    let hashes = db(stmt.query_map(
        params![
            op.id,
            encoded(&StepState::Dispatching)?,
            encoded(&StepState::Submitted)?,
            encoded(&StepState::ConfigApplied)?,
            encoded(&StepState::OutcomeUnknown)?,
            encoded(&StepState::Compensating)?
        ],
        |r| r.get::<_, String>(0),
    ))?
    .map(db)
    .collect::<Result<Vec<_>, _>>()?;
    for hash in hashes {
        let other = get_change(connection, &hash)?;
        if conflict_keys(&other)
            .iter()
            .any(|a| own.iter().any(|b| a.conflicts(b)))
        {
            return Err(StoreError::Unresolved);
        }
    }
    Ok(())
}
fn validate_receipt(receipt: &StepReceipt) -> Result<(), StoreError> {
    let valid_effect = match receipt.state {
        StepState::Submitted => {
            matches!(receipt.effect, EffectState::Unknown | EffectState::Pending)
        }
        StepState::ConfigApplied => matches!(
            receipt.effect,
            EffectState::Unknown | EffectState::Pending | EffectState::NotSatisfied
        ),
        StepState::EffectSatisfied | StepState::NoOpSatisfied => {
            receipt.effect == EffectState::Enforced
        }
        StepState::OutcomeUnknown => receipt.effect == EffectState::Unknown,
        StepState::NotApplied | StepState::Failed => matches!(
            receipt.effect,
            EffectState::Unknown | EffectState::NotSatisfied
        ),
        _ => false,
    };
    if !valid_effect
        || receipt.evidence_refs.len() > 128
        || receipt.evidence_refs.iter().any(|v| !valid_hash(v))
        || receipt.native_operation_ref.as_ref().is_some_and(|v| {
            v.is_empty()
                || v.len() > 512
                || v.chars().any(char::is_control)
                || v.contains('?')
                || v.contains("token=")
                || v.contains("password=")
        })
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
