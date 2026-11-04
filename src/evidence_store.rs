//! Evidence tables share OperationStore's private, bounded SQLite file and
//! FULL-synchronous transactions. Existing v1 operation tables are unchanged.
use crate::{
    core::{
        admission::*, evidence::*, policy::valid_id, ports::EvidenceLedger,
        source::RegisteredSourceSnapshot,
    },
    operation_store::OperationStore,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use std::{io::Read, path::Path};

pub struct EvidenceStore {
    operations: OperationStore,
}

/// A read-only observation context. It is not an Operation/ApprovalGrant and
/// never advances desired_heads, creates dispatch steps, or grants native writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSession {
    pub schema_version: u32,
    pub id: String,
    pub change_hash: String,
    pub policy_revision_hash: String,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct ObservationRequestSpec {
    pub request_id: String,
    pub operation_id: String,
    pub source_id: String,
    pub ttl_seconds: u64,
    pub cases: Vec<RequestedCase>,
}

fn db<T>(r: rusqlite::Result<T>) -> Result<T, AdmissionError> {
    r.map_err(|e| {
    if matches!(e, rusqlite::Error::SqliteFailure(ref e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation) {
        AdmissionError::Conflict
    } else { AdmissionError::Storage }
})
}
fn encode<T: Serialize>(v: &T) -> Result<String, AdmissionError> {
    let s = serde_json::to_string(v).map_err(|_| AdmissionError::Invalid)?;
    if s.len() > MAX_EVIDENCE_RECORD_BYTES {
        return Err(AdmissionError::Limit);
    }
    Ok(s)
}
fn decode<T: DeserializeOwned>(v: &str) -> Result<T, AdmissionError> {
    if v.len() > MAX_EVIDENCE_RECORD_BYTES {
        return Err(AdmissionError::Limit);
    }
    serde_json::from_str(v).map_err(|_| AdmissionError::Integrity)
}
fn storage(_: crate::core::operation::StoreError) -> AdmissionError {
    AdmissionError::Storage
}
fn snapshot_head(
    c: &Connection,
    registration: &str,
) -> Result<RegisteredSourceSnapshot, AdmissionError> {
    let value: Option<(String, String)> = db(c.query_row(
        "SELECT h.digest,s.body FROM evidence_source_heads h JOIN evidence_source_snapshots s ON s.digest=h.digest WHERE h.registration_id=?1",
        [registration], |r| Ok((r.get(0)?, r.get(1)?))).optional())?;
    let (digest, body) = value.ok_or(AdmissionError::NotFound)?;
    let snapshot: RegisteredSourceSnapshot = decode(&body)?;
    if snapshot.registration_id() != registration
        || snapshot
            .revision_digest()
            .map_err(|_| AdmissionError::Integrity)?
            != digest
    {
        return Err(AdmissionError::Integrity);
    }
    Ok(snapshot)
}
fn current(c: &Connection, issued: &IssuedObservation, now: u64) -> Result<(), AdmissionError> {
    validate_issued(issued)?;
    let r = &issued.request;
    if r.verifier_build_id != crate::BUILD_ID {
        return Err(AdmissionError::TrustChanged);
    }
    let s = snapshot_head(c, &r.source.registration_id)?;
    if s != issued.snapshot {
        return Err(AdmissionError::TrustChanged);
    }
    if now < r.issued_at {
        return Err(AdmissionError::Invalid);
    }
    if now >= r.expires_at {
        return Err(AdmissionError::Expired);
    }
    Ok(())
}
fn issued(c: &Connection, id: &str) -> Result<IssuedObservation, AdmissionError> {
    if !valid_id(id) {
        return Err(AdmissionError::Invalid);
    }
    let row: Option<(String, String, String)> = db(c
        .query_row(
            "SELECT digest,nonce,body FROM evidence_requests WHERE request_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional())?;
    let (digest, nonce, body) = row.ok_or(AdmissionError::NotFound)?;
    let i: IssuedObservation = decode(&body)?;
    validate_issued(&i)?;
    if i.request.request_id != id
        || i.request.nonce != nonce
        || i.request.digest().map_err(|_| AdmissionError::Integrity)? != digest
    {
        return Err(AdmissionError::Integrity);
    }
    Ok(i)
}

impl EvidenceStore {
    pub(crate) fn operation_store(&self) -> &OperationStore {
        &self.operations
    }
    /// Explicit evidence setup; v1 readers/open_existing never add these tables.
    pub fn open(path: &Path) -> Result<Self, AdmissionError> {
        let mut operations = OperationStore::open(path).map_err(storage)?;
        let c = operations.evidence_connection();
        let present: bool = db(c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_schema')", [], |r| r.get(0)))?;
        if present {
            let (count, version): (u32, u32) = db(c.query_row(
                "SELECT count(*),min(version) FROM evidence_schema",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ))?;
            if count != 1 || version != 1 {
                return Err(AdmissionError::Invalid);
            }
            return Ok(Self { operations });
        }
        db(c.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS evidence_schema(version INTEGER PRIMARY KEY CHECK(version=1));
            INSERT OR IGNORE INTO evidence_schema VALUES(1);
            CREATE TABLE IF NOT EXISTS evidence_source_snapshots(digest TEXT PRIMARY KEY,registration_id TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_source_heads(registration_id TEXT PRIMARY KEY,digest TEXT NOT NULL REFERENCES evidence_source_snapshots(digest));
            CREATE TABLE IF NOT EXISTS evidence_requests(request_id TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,digest TEXT UNIQUE NOT NULL,expires_at INTEGER NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence_admissions(request_id TEXT PRIMARY KEY REFERENCES evidence_requests(request_id),id TEXT UNIQUE NOT NULL,bundle_digest TEXT NOT NULL,body TEXT NOT NULL);
            COMMIT;"))?;
        Ok(Self { operations })
    }
    pub fn open_existing(path: &Path) -> Result<Self, AdmissionError> {
        let mut operations = OperationStore::open_existing(path).map_err(storage)?;
        let schema: Option<String> = db(operations
            .evidence_connection()
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_schema'",
                [],
                |r| r.get(0),
            )
            .optional())?;
        if schema.is_none() {
            return Err(AdmissionError::NotFound);
        }
        let version: u32 = db(operations.evidence_connection().query_row(
            "SELECT version FROM evidence_schema",
            [],
            |r| r.get(0),
        ))?;
        if version != 1 {
            return Err(AdmissionError::Invalid);
        }
        Ok(Self { operations })
    }

    /// Explicit CAS update of a source snapshot. It invalidates old captures;
    /// it neither edits a policy nor substitutes the new source into an approval.
    pub fn register_source<S: Clone + Into<RegisteredSourceSnapshot>>(
        &mut self,
        snapshot: &S,
        expected_digest: Option<&str>,
    ) -> Result<String, AdmissionError> {
        let snapshot = snapshot.clone().into();
        let digest = snapshot
            .revision_digest()
            .map_err(|_| AdmissionError::Invalid)?;
        let body = encode(&snapshot)?;
        let tx = db(self
            .operations
            .evidence_connection()
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let previous = match snapshot_head(&tx, snapshot.registration_id()) {
            Ok(s) => Some(s),
            Err(AdmissionError::NotFound) => None,
            Err(e) => return Err(e),
        };
        let old_digest = previous
            .as_ref()
            .map(|s| s.revision_digest().map_err(|_| AdmissionError::Integrity))
            .transpose()?;
        if old_digest.as_deref() != expected_digest {
            return Err(AdmissionError::Conflict);
        }
        if let Some(old) = &previous {
            if old == &snapshot {
                return Ok(digest);
            }
            if snapshot.trust_epoch() <= old.trust_epoch() {
                return Err(AdmissionError::TrustChanged);
            }
        }
        let mut stmt = db(tx.prepare("SELECT s.body FROM evidence_source_heads h JOIN evidence_source_snapshots s ON s.digest=h.digest"))?;
        let rows = db(stmt.query_map([], |r| r.get::<_, String>(0)))?;
        let mut count = 0;
        for row in rows {
            let s: RegisteredSourceSnapshot = decode(&db(row)?)?;
            count += 1;
            if s.registration_id() != snapshot.registration_id() && s.same_host(&snapshot) {
                return Err(AdmissionError::ScopeMismatch);
            }
        }
        drop(stmt);
        if previous.is_none() && count >= MAX_SOURCE_REGISTRATIONS {
            return Err(AdmissionError::Limit);
        }
        db(tx.execute(
            "INSERT INTO evidence_source_snapshots(digest,registration_id,body) VALUES(?1,?2,?3)",
            params![digest, snapshot.registration_id(), body],
        ))?;
        db(tx.execute("INSERT INTO evidence_source_heads(registration_id,digest) VALUES(?1,?2) ON CONFLICT(registration_id) DO UPDATE SET digest=excluded.digest", params![snapshot.registration_id(),digest]))?;
        db(tx.commit())?;
        Ok(digest)
    }

    /// Explicit local setup only. Existing v1 readers do not create this table.
    pub fn start_session(
        &mut self,
        change: &crate::core::change::PreparedChange,
        id: &str,
        now: u64,
    ) -> Result<ObservationSession, AdmissionError> {
        if !valid_id(id)
            || now < change.plan.created_at
            || now == 0
            || change.policy.schema_version != 2
        {
            return Err(AdmissionError::Invalid);
        }
        change.verify().map_err(|_| AdmissionError::Invalid)?;
        self.operations.register_change(change).map_err(storage)?;
        let c = self.operations.evidence_connection();
        db(c.execute_batch("CREATE TABLE IF NOT EXISTS evidence_sessions(id TEXT PRIMARY KEY,change_hash TEXT NOT NULL REFERENCES plans(hash),body TEXT NOT NULL);"))?;
        let tx = db(c.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let collision: bool = db(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
            [id],
            |r| r.get(0),
        ))?;
        if collision {
            return Err(AdmissionError::Conflict);
        }
        let old: Option<String> = db(tx
            .query_row(
                "SELECT body FROM evidence_sessions WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(body) = old {
            let old: ObservationSession = decode(&body)?;
            if old.change_hash != change.change_hash
                || old.policy_revision_hash != change.plan.policy_revision_hash
                || old.id != id
            {
                return Err(AdmissionError::Conflict);
            }
            return Ok(old);
        }
        let session = ObservationSession {
            schema_version: 1,
            id: id.into(),
            change_hash: change.change_hash.clone(),
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            created_at: now,
        };
        db(tx.execute(
            "INSERT INTO evidence_sessions(id,change_hash,body) VALUES(?1,?2,?3)",
            params![id, session.change_hash, encode(&session)?],
        ))?;
        db(tx.commit())?;
        Ok(session)
    }
    pub fn session(&mut self, id: &str) -> Result<ObservationSession, AdmissionError> {
        if !valid_id(id) {
            return Err(AdmissionError::Invalid);
        }
        let c = self.operations.evidence_connection();
        let table:bool=db(c.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_sessions')",[],|r|r.get(0)))?;
        if !table {
            return Err(AdmissionError::NotFound);
        }
        let body: Option<String> = db(c
            .query_row(
                "SELECT body FROM evidence_sessions WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .optional())?;
        let session: ObservationSession = decode(&body.ok_or(AdmissionError::NotFound)?)?;
        let change = self
            .operations
            .load_change(&session.change_hash)
            .map_err(storage)?;
        if session.schema_version != 1
            || session.id != id
            || session.policy_revision_hash != change.plan.policy_revision_hash
            || session.created_at == 0
        {
            return Err(AdmissionError::Integrity);
        }
        Ok(session)
    }
    pub fn context_change(
        &mut self,
        id: &str,
    ) -> Result<crate::core::change::PreparedChange, AdmissionError> {
        let hash = match self.operations.get(id) {
            Ok(op) => op.change_hash,
            Err(crate::core::operation::StoreError::NotFound) => self.session(id)?.change_hash,
            Err(_) => return Err(AdmissionError::Storage),
        };
        self.operations.load_change(&hash).map_err(storage)
    }
    pub fn request_ids(&mut self, context: &str) -> Result<Vec<String>, AdmissionError> {
        if !valid_id(context) {
            return Err(AdmissionError::Invalid);
        }
        let mut stmt=db(self.operations.evidence_connection().prepare("SELECT request_id FROM evidence_requests WHERE json_extract(body,'$.request.operation_id')=?1 ORDER BY request_id LIMIT 32769"))?;
        let rows = db(stmt.query_map([context], |r| r.get::<_, String>(0)))?;
        let mut ids = vec![];
        for row in rows {
            ids.push(db(row)?)
        }
        if ids.len() > 32768 {
            return Err(AdmissionError::Limit);
        }
        Ok(ids)
    }

    pub fn source_snapshot(
        &mut self,
        registration: &str,
    ) -> Result<RegisteredSourceSnapshot, AdmissionError> {
        snapshot_head(self.operations.evidence_connection(), registration)
    }
    pub fn issue_request(
        &mut self,
        spec: &ObservationRequestSpec,
        now: u64,
    ) -> Result<IssuedObservation, AdmissionError> {
        if spec.ttl_seconds == 0
            || spec.ttl_seconds > MAX_REQUEST_TTL_SECONDS
            || now > i64::MAX as u64 - MAX_REQUEST_TTL_SECONDS
        {
            return Err(AdmissionError::Invalid);
        }
        let change = self.context_change(&spec.operation_id)?;
        let created_at = match self.operations.get(&spec.operation_id) {
            Ok(op) => op.created_at,
            Err(crate::core::operation::StoreError::NotFound) => {
                self.session(&spec.operation_id)?.created_at
            }
            Err(_) => return Err(AdmissionError::Storage),
        };
        if now < created_at {
            return Err(AdmissionError::Invalid);
        }
        let source = change
            .policy
            .source_bindings
            .iter()
            .find(|s| s.source_id == spec.source_id)
            .ok_or(AdmissionError::ScopeMismatch)?
            .clone();
        let nonce = random_nonce()?;
        let tx = db(self
            .operations
            .evidence_connection()
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let snapshot = snapshot_head(&tx, &source.registration_id)?;
        let r = ObservationRequest {
            schema_version: 1,
            request_id: spec.request_id.clone(),
            nonce,
            policy_revision_hash: change.plan.policy_revision_hash.clone(),
            change_hash: change.change_hash.clone(),
            operation_id: spec.operation_id.clone(),
            source,
            source_trust_epoch: snapshot.trust_epoch(),
            evaluation_contract: EvaluationContract::SourceBoundV2,
            collector_build_id: snapshot.collector_build_id().to_owned(),
            verifier_build_id: crate::BUILD_ID.into(),
            issued_at: now,
            expires_at: now + spec.ttl_seconds,
            cases: spec.cases.clone(),
        };
        r.validate().map_err(|_| AdmissionError::Invalid)?;
        validate_request_scope(&r, &change)?;
        let i = IssuedObservation {
            request: r,
            snapshot,
        };
        validate_source_actor_binding(&i, &change)?;
        let active: u64 = db(tx.query_row("SELECT count(*) FROM evidence_requests r WHERE r.expires_at>?1 AND NOT EXISTS(SELECT 1 FROM evidence_admissions a WHERE a.request_id=r.request_id)", [now], |r| r.get(0)))?;
        if active >= MAX_ACTIVE_REQUESTS as u64 {
            return Err(AdmissionError::Limit);
        }
        let body = encode(&i)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(AdmissionError::Limit);
        }
        db(tx.execute("INSERT INTO evidence_requests(request_id,nonce,digest,expires_at,body) VALUES(?1,?2,?3,?4,?5)",
            params![i.request.request_id,i.request.nonce,i.request.digest().map_err(|_| AdmissionError::Invalid)?,i.request.expires_at,body]))?;
        db(tx.commit())?;
        Ok(i)
    }
}

impl EvidenceLedger for EvidenceStore {
    fn issued(&mut self, id: &str) -> Result<IssuedObservation, AdmissionError> {
        issued(self.operations.evidence_connection(), id)
    }
    fn ensure_current(&mut self, i: &IssuedObservation, now: u64) -> Result<(), AdmissionError> {
        current(self.operations.evidence_connection(), i, now)
    }
    fn admission(&mut self, id: &str) -> Result<EvidenceAdmission, AdmissionError> {
        let c = self.operations.evidence_connection();
        let i = issued(c, id)?;
        let row: Option<(String, String, String)> = db(c
            .query_row(
                "SELECT id,bundle_digest,body FROM evidence_admissions WHERE request_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional())?;
        let (id, digest, body) = row.ok_or(AdmissionError::NotFound)?;
        let a: EvidenceAdmission = decode(&body)?;
        if a.id != id
            || a.bundle_digest != digest
            || a.request_digest != i.request.digest().map_err(|_| AdmissionError::Integrity)?
        {
            return Err(AdmissionError::Integrity);
        }
        Ok(a)
    }
    fn admit(
        &mut self,
        candidate: &VerifiedCandidate,
        now: u64,
    ) -> Result<EvidenceAdmission, AdmissionError> {
        let a = candidate.admission();
        let tx = db(self
            .operations
            .evidence_connection()
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let request_id: Option<String> = db(tx
            .query_row(
                "SELECT request_id FROM evidence_requests WHERE digest=?1",
                [&a.request_digest],
                |r| r.get(0),
            )
            .optional())?;
        let request_id = request_id.ok_or(AdmissionError::NotFound)?;
        let i = issued(&tx, &request_id)?;
        current(&tx, &i, now)?;
        validate_receipt(&i, a, now)?;
        // One atomic compare-and-insert. Even an identical retransmission does
        // not mint a new receipt/time; readers reuse the original admission.
        db(tx.execute(
            "INSERT INTO evidence_admissions(request_id,id,bundle_digest,body) VALUES(?1,?2,?3,?4)",
            params![request_id, a.id, a.bundle_digest, encode(a)?],
        ))?;
        db(tx.commit())?;
        Ok(a.clone())
    }
}

fn random_nonce() -> Result<String, AdmissionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/urandom")
            .map_err(|_| AdmissionError::Storage)?;
        let mut bytes = [0u8; 32];
        file.read_exact(&mut bytes)
            .map_err(|_| AdmissionError::Storage)?;
        Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    #[cfg(not(unix))]
    {
        Err(AdmissionError::VerifierUnavailable)
    }
}
