//! Request-scoped PostgreSQL checkout correlation for AWS RDS Proxy.
use super::{
    evidence::{DEFAULT_FRESHNESS_SECONDS, MAX_CLOCK_SKEW_SECONDS},
    policy::valid_hash,
    runtime_binding::RuntimeCaptureContext,
    runtime_cutover::{PoolSwitchLink, PostgresSessionIdentity, RuntimeCutoverError},
};
use serde::{Deserialize, Serialize};

pub(crate) const RECIPE: &str = "k11-aws-postgres-runtime-cutover-v1";

/// Use the issued request's random nonce indirectly through its digest.
/// Only this marker can be admitted for the request and case.
pub fn aws_postgres_runtime_marker(context: &RuntimeCaptureContext) -> String {
    super::hash_bytes(
        format!(
            "veil-db-guard/k11/aws-postgres-transaction/v1\0{}\0{}",
            context.request_digest, context.case_id
        )
        .as_bytes(),
    )
}

/// Identity of a transaction pinned by RDS Proxy while it remains open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsPostgresTransaction {
    pub session: PostgresSessionIdentity,
    pub transaction_started_at_micros: u64,
    pub marker: String,
    pub server_reported_ssl: Option<bool>,
}

/// The managed pool uses only the pinned IAM credential binding and strict
/// Proxy TLS configuration identified by the bundle digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsPostgresPoolObservation {
    pub bundle_digest: String,
    pub switch: PoolSwitchLink,
    pub transaction: AwsPostgresTransaction,
}

/// The independent database observer reads the matching active backend on
/// its registered target. SSL here is PostgreSQL's report of encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsPostgresDatabaseObservation {
    pub target_generation: String,
    pub observer_user: String,
    pub transaction: AwsPostgresTransaction,
}

/// Produced only after authenticated, role-separated witnesses have matched.
/// It cannot be deserialized or supplied as a wire verdict.
#[derive(Debug)]
pub struct CorroboratedAwsPostgresCutover {
    pub(crate) context: RuntimeCaptureContext,
    pub(crate) checked_out_at: u64,
    pub(crate) observed_at: u64,
    pub(crate) valid_until: u64,
    pub(crate) evidence_digests: [String; 2],
}

pub(crate) struct AwsPostgresCutoverExpectation<'a> {
    pub context: RuntimeCaptureContext,
    pub bundle_digest: &'a str,
    pub previous_generation: u64,
    pub active_generation: u64,
    pub database_observer_user: &'a str,
    pub not_before: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub(crate) struct VerifiedWitness<T> {
    pub context: RuntimeCaptureContext,
    pub observed_at: u64,
    pub valid_until: u64,
    pub observation: T,
    pub digest: String,
}

pub(crate) fn corroborate(
    expected: AwsPostgresCutoverExpectation<'_>,
    pool: VerifiedWitness<AwsPostgresPoolObservation>,
    database: VerifiedWitness<AwsPostgresDatabaseObservation>,
    now: u64,
) -> Result<CorroboratedAwsPostgresCutover, RuntimeCutoverError> {
    let switch = &pool.observation.switch;
    let transaction = &pool.observation.transaction;
    let session = &transaction.session;
    let target = &expected.context.address.target;
    if pool.context != expected.context
        || database.context != expected.context
        || pool.observation.bundle_digest != expected.bundle_digest
        || switch.previous_generation != expected.previous_generation
        || switch.active_generation != expected.active_generation
        || switch.checkout_sequence == 0
        || target.native_ref.generation_fingerprint.as_deref()
            != Some(database.observation.target_generation.as_str())
        || database.observation.observer_user != expected.database_observer_user
        || database.observation.observer_user == session.session_user
        || transaction != &database.observation.transaction
        || session.database != target.engine_binding.database
        || session.session_user != expected.context.address.db_identity
        || transaction.marker != aws_postgres_runtime_marker(&expected.context)
        || session.backend_pid == 0
        || session.backend_pid > i32::MAX as u32
        || session.backend_started_at_micros == 0
        || transaction.transaction_started_at_micros < session.backend_started_at_micros
        || transaction.server_reported_ssl != Some(true)
        || !valid_hash(&pool.digest)
        || !valid_hash(&database.digest)
        || pool.digest == database.digest
    {
        return Err(RuntimeCutoverError::ScopeMismatch);
    }
    let transaction_started_at = transaction.transaction_started_at_micros / 1_000_000;
    let valid_until = pool
        .valid_until
        .min(database.valid_until)
        .min(expected.expires_at);
    if switch.switched_at <= expected.not_before
        || switch.checked_out_at < expected.issued_at
        || switch.checked_out_at < switch.switched_at
        || transaction_started_at.saturating_add(MAX_CLOCK_SKEW_SECONDS) < switch.checked_out_at
        || transaction_started_at > database.observed_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || database.observed_at < switch.checked_out_at
        || pool.observed_at < database.observed_at
        || pool.observed_at > now
        || pool.valid_until <= pool.observed_at
        || database.valid_until <= database.observed_at
        || pool.valid_until.saturating_sub(pool.observed_at) > DEFAULT_FRESHNESS_SECONDS
        || database.valid_until.saturating_sub(database.observed_at) > DEFAULT_FRESHNESS_SECONDS
        || now.saturating_sub(switch.checked_out_at) >= DEFAULT_FRESHNESS_SECONDS
        || valid_until <= now
    {
        return Err(RuntimeCutoverError::Expired);
    }
    Ok(CorroboratedAwsPostgresCutover {
        context: expected.context,
        checked_out_at: switch.checked_out_at,
        observed_at: pool.observed_at,
        valid_until,
        evidence_digests: [pool.digest, database.digest],
    })
}
