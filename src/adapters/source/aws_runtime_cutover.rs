//! Registered pool and database witnesses for a single AWS PostgreSQL checkout.
//! Trust comes from separately provisioned measurement producers. A public key
//! supplied alongside a statement has no authority.
use super::{
    aws_host::AwsCollectorConfig,
    gce_host::SourceError,
    runtime_witness::{SignedStatement, key, sign_statement},
};
use crate::{
    binding::aws_runtime::AwsConnectionBundle,
    core::{
        admission::*,
        aws_runtime_cutover::{self, *},
        change::PreparedChange,
        evidence::*,
        hash_bytes,
        policy::{PlacementKind, RouteKind, valid_hash, valid_id},
        ports::ObservationVerifier,
        postgres_login::identity,
        runtime_binding::RuntimeCaptureContext,
        runtime_cutover::RuntimeCutoverError,
        source::SourceBoundaryKind,
        state::{ArtifactRef, StateLayer, StateValue},
    },
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};

const POOL_DOMAIN: &[u8] = b"veil-db-guard/k11/aws-postgres-pool/v1\0";
const DATABASE_DOMAIN: &[u8] = b"veil-db-guard/k11/aws-postgres-database/v1\0";
const POOL_ARTIFACT: &str = "k11-aws-postgres-pool-witness";
const DATABASE_ARTIFACT: &str = "k11-aws-postgres-database-witness";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsPostgresRuntimeWitnessPolicy {
    pub target_id: String,
    pub grant_id: String,
    pub subject_id: String,
    pub pool_key: String,
    pub database_key: String,
    pub database_observer_user: String,
    pub proxy_ca_sha256: String,
    pub previous_generation: u64,
    pub active_generation: u64,
    pub not_before: u64,
}

impl AwsPostgresRuntimeWitnessPolicy {
    pub(super) fn validate(&self) -> Result<(), SourceError> {
        if key(&self.pool_key)? == key(&self.database_key)?
            || ![&self.target_id, &self.grant_id, &self.subject_id]
                .into_iter()
                .all(|value| valid_id(value))
            || !identity(&self.database_observer_user)
            || !valid_hash(&self.proxy_ca_sha256)
            || self.previous_generation == 0
            || self.active_generation <= self.previous_generation
            || self.not_before == 0
        {
            return Err(SourceError::Invalid);
        }
        Ok(())
    }

    pub(super) fn matches(&self, address: &EffectAddress) -> bool {
        address.target_id == self.target_id
            && address.grant_id == self.grant_id
            && address.subject_id == self.subject_id
            && address.route.kind == RouteKind::NativeProxy
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AwsPostgresWitnessRole {
    Pool,
    Database,
}

/// Use only in the trusted measurement producers. Provision each PKCS#8 key
/// separately to the registered role and keep it out of the app's wire input.
pub struct AwsPostgresRuntimeSigner {
    role: AwsPostgresWitnessRole,
    key: Ed25519KeyPair,
}

impl AwsPostgresRuntimeSigner {
    pub fn from_pkcs8(
        bytes: &[u8],
        policy: &AwsPostgresRuntimeWitnessPolicy,
        role: AwsPostgresWitnessRole,
    ) -> Result<Self, SourceError> {
        policy.validate()?;
        if bytes.len() > 4096 {
            return Err(SourceError::Limit);
        }
        let signer = Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| SourceError::Invalid)?;
        let expected = match role {
            AwsPostgresWitnessRole::Pool => &policy.pool_key,
            AwsPostgresWitnessRole::Database => &policy.database_key,
        };
        if signer.public_key().as_ref() != key(expected)? {
            return Err(SourceError::IdentityUnverified);
        }
        Ok(Self { role, key: signer })
    }

    pub fn sign_pool(
        &self,
        context: &RuntimeCaptureContext,
        observed_at: u64,
        valid_until: u64,
        observation: &AwsPostgresPoolObservation,
    ) -> Result<SignedStatement, SourceError> {
        if self.role != AwsPostgresWitnessRole::Pool {
            return Err(SourceError::IdentityUnverified);
        }
        sign_statement(
            &self.key,
            POOL_DOMAIN,
            context,
            observed_at,
            valid_until,
            observation,
        )
    }

    pub fn sign_database(
        &self,
        context: &RuntimeCaptureContext,
        observed_at: u64,
        valid_until: u64,
        observation: &AwsPostgresDatabaseObservation,
    ) -> Result<SignedStatement, SourceError> {
        if self.role != AwsPostgresWitnessRole::Database {
            return Err(SourceError::IdentityUnverified);
        }
        sign_statement(
            &self.key,
            DATABASE_DOMAIN,
            context,
            observed_at,
            valid_until,
            observation,
        )
    }
}

/// The two detached measurements can be admitted through the existing ledger
/// and archive, with their original signed bytes retained. This entry point
/// performs no native read and accepts no unsigned verdict or app candidate.
pub struct AwsPostgresRuntimeCapture {
    pub bundle: Vec<u8>,
    pub payloads: Vec<EvidencePayload>,
    pub window: CaptureWindow,
    pub verifier: AwsPostgresRuntimeVerifier,
}

impl AwsPostgresRuntimeCapture {
    pub fn corroborate(
        issued: &IssuedObservation,
        change: &PreparedChange,
        pinned_config: &[u8],
        pool_statement: &[u8],
        database_statement: &[u8],
        window: CaptureWindow,
        now: u64,
    ) -> Result<Self, SourceError> {
        if [pinned_config, pool_statement, database_statement]
            .into_iter()
            .any(|bytes| bytes.len() > super::runtime_witness::MAX_WITNESS_INPUT)
        {
            return Err(SourceError::Limit);
        }
        if hash_bytes(pinned_config) != issued.snapshot.collector_config_digest() {
            return Err(SourceError::Integrity);
        }
        let config: AwsCollectorConfig =
            serde_json::from_slice(pinned_config).map_err(|_| SourceError::Invalid)?;
        config.validate_request(issued)?;
        validate_request_scope(&issued.request, change).map_err(SourceError::AdmissionFailed)?;
        validate_source_actor_binding(issued, change).map_err(SourceError::AdmissionFailed)?;
        let [case] = issued.request.cases.as_slice() else {
            return Err(SourceError::Unsupported);
        };
        let context = RuntimeCaptureContext::for_case(issued, case)
            .map_err(|_| SourceError::ContextUnverified)?;
        let policy = config
            .postgres_runtime
            .as_ref()
            .filter(|policy| policy.matches(&case.address))
            .ok_or(SourceError::Unsupported)?;
        if case.address.source.boundary != SourceBoundaryKind::AwsHostNetwork
            || case.address.target.placement.kind != PlacementKind::AwsRds
            || policy.not_before >= issued.request.expires_at
        {
            return Err(SourceError::ContextUnverified);
        }
        let expected_bundle = AwsConnectionBundle::prepare(
            change,
            &case.address.grant_id,
            &case.address.source.source_id,
            &case.address.route.id,
            policy.active_generation,
            &issued.snapshot,
            &policy.proxy_ca_sha256,
        )
        .map_err(|_| SourceError::ContextUnverified)?;
        let pool = verify_statement(pool_statement, &policy.pool_key, POOL_DOMAIN)?;
        let database = verify_statement(database_statement, &policy.database_key, DATABASE_DOMAIN)?;
        let proof = aws_runtime_cutover::corroborate(
            AwsPostgresCutoverExpectation {
                context,
                bundle_digest: &expected_bundle.digest(),
                previous_generation: policy.previous_generation,
                active_generation: policy.active_generation,
                database_observer_user: &policy.database_observer_user,
                not_before: policy.not_before,
                issued_at: issued.request.issued_at,
                expires_at: issued.request.expires_at,
            },
            pool,
            database,
            now,
        )
        .map_err(|error| match error {
            RuntimeCutoverError::Expired => SourceError::RequestExpired,
            _ => SourceError::ContextUnverified,
        })?;
        if proof.checked_out_at < window.sent_at || proof.observed_at > window.received_at {
            return Err(SourceError::ContextUnverified);
        }
        let evidence_refs = vec![POOL_ARTIFACT.to_owned(), DATABASE_ARTIFACT.to_owned()];
        let bundle = ObservationBundleWire {
            schema_version: 1,
            request_digest: proof.context.request_digest.clone(),
            collector_build_id: proof.context.collector_build_id.clone(),
            started_at: proof.checked_out_at,
            finished_at: proof.observed_at,
            capture_complete: true,
            claims: vec![ObservationClaim {
                id: case.id.clone(),
                case_id: case.id.clone(),
                policy_revision_hash: proof.context.policy_revision_hash.clone(),
                address: proof.context.address.clone(),
                started_at: proof.checked_out_at,
                finished_at: proof.observed_at,
                observed: StateValue::Present,
                layer: StateLayer::Configuration,
                evidence_refs: evidence_refs.clone(),
                runtime_capture: None,
                postgres_login_failure: None,
                login_catalog: vec![],
                denial_cause: None,
                connection: None,
                controls: vec![],
                transport: vec![],
                sql_context: None,
                permission_inventory: None,
            }],
            artifacts: evidence_refs
                .iter()
                .zip(&proof.evidence_digests)
                .map(|(id, sha256)| ArtifactRef {
                    id: id.clone(),
                    sha256: sha256.clone(),
                })
                .collect(),
        };
        bundle.validate_shape().map_err(|_| SourceError::Invalid)?;
        let measured = Assurance::Verified {
            evidence_refs: evidence_refs.clone(),
        };
        let findings = VerifierFindings {
            recipe_id: RECIPE.into(),
            source_evidence_refs: evidence_refs,
            assurances: vec![ClaimAssurance {
                claim_id: case.id.clone(),
                coverage: AssuranceCoverage {
                    target: measured.clone(),
                    principal: measured.clone(),
                    source: measured.clone(),
                    route: measured.clone(),
                    transport: measured.clone(),
                    temporal: measured.clone(),
                    completeness: measured,
                },
            }],
        };
        let bundle = serde_json::to_vec(&bundle).map_err(|_| SourceError::Invalid)?;
        Ok(Self {
            verifier: AwsPostgresRuntimeVerifier {
                bundle_digest: hash_bytes(&bundle),
                window,
                findings,
                proof,
                used: false,
            },
            bundle,
            payloads: vec![
                EvidencePayload {
                    id: POOL_ARTIFACT.into(),
                    bytes: pool_statement.into(),
                },
                EvidencePayload {
                    id: DATABASE_ARTIFACT.into(),
                    bytes: database_statement.into(),
                },
            ],
            window,
        })
    }
}

fn verify_statement<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    public_key: &str,
    domain: &[u8],
) -> Result<VerifiedWitness<T>, SourceError> {
    let signed: SignedStatement = serde_json::from_slice(raw).map_err(|_| SourceError::Invalid)?;
    let statement = signed.verify(public_key, domain)?;
    Ok(VerifiedWitness {
        context: statement.context,
        observed_at: statement.observed_at,
        valid_until: statement.valid_until,
        observation: statement.observation,
        digest: hash_bytes(raw),
    })
}

/// A verifier bound to one already corroborated capture.
pub struct AwsPostgresRuntimeVerifier {
    bundle_digest: String,
    window: CaptureWindow,
    findings: VerifierFindings,
    proof: CorroboratedAwsPostgresCutover,
    used: bool,
}

impl ObservationVerifier for AwsPostgresRuntimeVerifier {
    fn verify(
        &mut self,
        issued: &IssuedObservation,
        bundle: &ObservationBundleWire,
        payloads: &[EvidencePayload],
        window: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        if self.used
            || issued
                .request
                .digest()
                .map_err(|_| AdmissionError::Invalid)?
                != self.proof.context.request_digest
            || hash_bytes(&serde_json::to_vec(bundle).map_err(|_| AdmissionError::Invalid)?)
                != self.bundle_digest
            || window.sent_at != self.window.sent_at
            || window.received_at != self.window.received_at
            || window.elapsed_millis != self.window.elapsed_millis
            || payloads.len() != self.proof.evidence_digests.len()
            || payloads
                .iter()
                .zip(&self.proof.evidence_digests)
                .any(|(payload, digest)| hash_bytes(&payload.bytes) != *digest)
        {
            return Err(AdmissionError::ScopeMismatch);
        }
        self.used = true;
        Ok(self.findings.clone())
    }

    fn aws_runtime_cutover(&self, case_id: &str) -> Option<&CorroboratedAwsPostgresCutover> {
        (case_id == self.proof.context.case_id).then_some(&self.proof)
    }
}

#[cfg(test)]
pub(crate) mod tests;
