//! Separate delayed-history tables on the existing private operation SQLite
//! ledger. No operation, approval, desired head or current admission is edited.
use crate::{
    core::{admission::AdmissionError, deferred_route::*},
    operation_store::OperationStore,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::path::Path;

pub struct DeferredRouteStore {
    operations: OperationStore,
}
fn db<T>(r: rusqlite::Result<T>) -> Result<T, AdmissionError> {
    r.map_err(|e| if matches!(e, rusqlite::Error::SqliteFailure(ref e, _) if e.code == rusqlite::ErrorCode::ConstraintViolation) {
        AdmissionError::Conflict
    } else { AdmissionError::Storage })
}
fn encode<T: serde::Serialize>(v: &T) -> Result<String, AdmissionError> {
    let s = serde_json::to_string(v).map_err(|_| AdmissionError::Invalid)?;
    if s.len() > 262144 {
        return Err(AdmissionError::Limit);
    }
    Ok(s)
}
fn decode<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, AdmissionError> {
    if body.len() > 262144 {
        return Err(AdmissionError::Limit);
    }
    serde_json::from_str(body).map_err(|_| AdmissionError::Integrity)
}
impl DeferredRouteStore {
    /// Explicit local setup only; safely-opened storage is inherited from the
    /// operation store. This does not register a source or extend a request TTL.
    pub fn open(path: &Path) -> Result<Self, AdmissionError> {
        let mut operations =
            OperationStore::open_existing(path).map_err(|_| AdmissionError::Storage)?;
        db(operations.evidence_connection().execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS deferred_route_schema(version INTEGER PRIMARY KEY CHECK(version=1));
            INSERT OR IGNORE INTO deferred_route_schema VALUES(1);
            CREATE TABLE IF NOT EXISTS deferred_route_probes(digest TEXT PRIMARY KEY,nonce TEXT UNIQUE NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS deferred_route_receipts(probe_digest TEXT PRIMARY KEY REFERENCES deferred_route_probes(digest),digest TEXT NOT NULL,body TEXT NOT NULL);
            COMMIT;"))?;
        let (count, version): (u32, u32) = db(operations.evidence_connection().query_row(
            "SELECT count(*),min(version) FROM deferred_route_schema",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        if count != 1 || version != 1 {
            return Err(AdmissionError::Invalid);
        }
        Ok(Self { operations })
    }
}
impl DeferredRouteLedger for DeferredRouteStore {
    fn issue(&mut self, ticket: &DeferredProbeTicket) -> Result<String, AdmissionError> {
        let p = ticket.probe();
        let digest = p.digest()?;
        let body = encode(p)?;
        let tx = db(self
            .operations
            .evidence_connection()
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let count: u64 = db(
            tx.query_row("SELECT count(*) FROM deferred_route_probes", [], |r| {
                r.get(0)
            }),
        )?;
        if count >= 4096 {
            return Err(AdmissionError::Limit);
        }
        db(tx.execute(
            "INSERT INTO deferred_route_probes(digest,nonce,body) VALUES(?1,?2,?3)",
            params![digest, p.issued.request.nonce, body],
        ))?;
        db(tx.commit())?;
        Ok(digest)
    }
    fn probe(&mut self, digest: &str) -> Result<DeferredProbe, AdmissionError> {
        if !crate::core::policy::valid_hash(digest) {
            return Err(AdmissionError::Invalid);
        }
        let row: Option<(String, String)> = db(self
            .operations
            .evidence_connection()
            .query_row(
                "SELECT nonce,body FROM deferred_route_probes WHERE digest=?1",
                [digest],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let (nonce, body) = row.ok_or(AdmissionError::NotFound)?;
        let p: DeferredProbe = decode(&body)?;
        if p.digest()? != digest || p.issued.request.nonce != nonce {
            return Err(AdmissionError::Integrity);
        }
        Ok(p)
    }
    fn commit(&mut self, receipt: &DeferredRouteReceipt, now: u64) -> Result<(), AdmissionError> {
        let p = self.probe(&receipt.probe_digest)?;
        if now >= p.delivery_deadline || receipt.received_at >= p.delivery_deadline {
            return Err(AdmissionError::Expired);
        }
        if receipt.received_at < p.registered_at
            || receipt.received_at > now
            || receipt.observed_at != p.observed_at
            || receipt.capture_digest != receipt.archive.bundle_digest
            || receipt.archive.request_digest
                != p.issued
                    .request
                    .digest()
                    .map_err(|_| AdmissionError::Integrity)?
        {
            return Err(AdmissionError::Integrity);
        }
        let body = encode(receipt)?;
        let hash = crate::config::hash_bytes(body.as_bytes());
        let tx = db(self
            .operations
            .evidence_connection()
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let current: String = db(tx.query_row(
            "SELECT body FROM deferred_route_probes WHERE digest=?1",
            [&receipt.probe_digest],
            |r| r.get(0),
        ))?;
        if current != encode(&p)? {
            return Err(AdmissionError::Integrity);
        }
        db(tx.execute(
            "INSERT INTO deferred_route_receipts(probe_digest,digest,body) VALUES(?1,?2,?3)",
            params![receipt.probe_digest, hash, body],
        ))?;
        db(tx.commit())?;
        Ok(())
    }
    fn receipt(&mut self, digest: &str) -> Result<DeferredRouteReceipt, AdmissionError> {
        let row: Option<(String, String)> = db(self
            .operations
            .evidence_connection()
            .query_row(
                "SELECT digest,body FROM deferred_route_receipts WHERE probe_digest=?1",
                [digest],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let (hash, body) = row.ok_or(AdmissionError::NotFound)?;
        if crate::config::hash_bytes(body.as_bytes()) != hash {
            return Err(AdmissionError::Integrity);
        }
        let r: DeferredRouteReceipt = decode(&body)?;
        if r.probe_digest != digest {
            return Err(AdmissionError::Integrity);
        }
        Ok(r)
    }
}
