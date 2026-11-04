//! Detached evidence from explicitly registered, independently operated
//! connector and pool witnesses. A signature authenticates the registered
//! witness, so the registration must pin a producer that measures these facts.
use crate::core::runtime_cutover::{
    NativePoolUseObservation, NativePostgresSessionObservation, RuntimeCutoverCandidate,
};
use crate::core::{policy::valid_hash, runtime_binding::RuntimeCaptureContext};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use super::gce_host::SourceError;

pub(super) const MAX_WITNESS_INPUT: usize = 64 * 1024;
const MAX_STATEMENT: usize = 8192;
const CONNECTOR_DOMAIN: &[u8] = b"veil-db-guard/k11/connector/v1\0";
const POOL_DOMAIN: &[u8] = b"veil-db-guard/k11/pool/v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWitnessPolicy {
    pub connector_key: String,
    pub pool_key: String,
    pub bundle_digest: String,
    pub previous_generation: u64,
    pub active_generation: u64,
    pub credential_binding_digest: String,
    pub not_before: u64,
}

impl RuntimeWitnessPolicy {
    pub(super) fn validate(&self) -> Result<(), SourceError> {
        let connector = key(&self.connector_key)?;
        let pool = key(&self.pool_key)?;
        if connector == pool
            || !valid_hash(&self.bundle_digest)
            || !valid_hash(&self.credential_binding_digest)
            || self.previous_generation == 0
            || self.active_generation <= self.previous_generation
            || self.not_before == 0
        {
            return Err(SourceError::Invalid);
        }
        Ok(())
    }
}

pub(super) fn key(encoded: &str) -> Result<[u8; 32], SourceError> {
    if encoded.len() != 44 {
        return Err(SourceError::Invalid);
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| SourceError::Invalid)?
        .try_into()
        .map_err(|_| SourceError::Invalid)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub candidate: RuntimeCutoverCandidate,
    pub connector: SignedStatement,
    pub pool: SignedStatement,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStatement {
    statement_base64: String,
    signature_base64: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuntimeWitnessRole {
    Connector,
    Pool,
}

/// The caller provisions the private key directly to the registered observer.
/// This type never serializes the key or accepts unsigned facts from wire input.
pub struct RuntimeWitnessSigner {
    role: RuntimeWitnessRole,
    key: Ed25519KeyPair,
}

impl RuntimeWitnessSigner {
    pub fn from_pkcs8(
        bytes: &[u8],
        policy: &RuntimeWitnessPolicy,
        role: RuntimeWitnessRole,
    ) -> Result<Self, SourceError> {
        policy.validate()?;
        if bytes.len() > 4096 {
            return Err(SourceError::Limit);
        }
        let signer = Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| SourceError::Invalid)?;
        let expected = match role {
            RuntimeWitnessRole::Connector => &policy.connector_key,
            RuntimeWitnessRole::Pool => &policy.pool_key,
        };
        if signer.public_key().as_ref() != key(expected)? {
            return Err(SourceError::IdentityUnverified);
        }
        Ok(Self { role, key: signer })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn sign_pool(
        &self,
        context: &RuntimeCaptureContext,
        observed_at: u64,
        valid_until: u64,
        observation: &NativePoolUseObservation,
    ) -> Result<SignedStatement, SourceError> {
        self.sign(
            RuntimeWitnessRole::Pool,
            POOL_DOMAIN,
            context,
            observed_at,
            valid_until,
            observation,
        )
    }

    pub(crate) fn sign_connector(
        &self,
        context: &RuntimeCaptureContext,
        observed_at: u64,
        valid_until: u64,
        observation: &NativePostgresSessionObservation,
    ) -> Result<SignedStatement, SourceError> {
        self.sign(
            RuntimeWitnessRole::Connector,
            CONNECTOR_DOMAIN,
            context,
            observed_at,
            valid_until,
            observation,
        )
    }

    fn sign(
        &self,
        role: RuntimeWitnessRole,
        domain: &[u8],
        context: &RuntimeCaptureContext,
        observed_at: u64,
        valid_until: u64,
        observation: &impl Serialize,
    ) -> Result<SignedStatement, SourceError> {
        if self.role != role {
            return Err(SourceError::Invalid);
        }
        sign_statement(
            &self.key,
            domain,
            context,
            observed_at,
            valid_until,
            observation,
        )
    }
}

pub(super) fn sign_statement(
    key: &Ed25519KeyPair,
    domain: &[u8],
    context: &RuntimeCaptureContext,
    observed_at: u64,
    valid_until: u64,
    observation: &impl Serialize,
) -> Result<SignedStatement, SourceError> {
    if observed_at == 0
        || valid_until <= observed_at
        || valid_until - observed_at > crate::core::evidence::DEFAULT_FRESHNESS_SECONDS
    {
        return Err(SourceError::Invalid);
    }
    let statement = Statement {
        context: context.clone(),
        observed_at,
        valid_until,
        observation,
    };
    let raw = serde_json::to_vec(&statement).map_err(|_| SourceError::Invalid)?;
    if raw.len() > MAX_STATEMENT {
        return Err(SourceError::Limit);
    }
    let mut message = Vec::with_capacity(domain.len() + raw.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&raw);
    let signature = key.sign(&message);
    Ok(SignedStatement {
        statement_base64: STANDARD.encode(raw),
        signature_base64: STANDARD.encode(signature.as_ref()),
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Statement<T> {
    pub context: RuntimeCaptureContext,
    pub observed_at: u64,
    pub valid_until: u64,
    pub observation: T,
}

impl SignedStatement {
    pub(super) fn connector(
        &self,
        policy: &RuntimeWitnessPolicy,
    ) -> Result<Statement<NativePostgresSessionObservation>, SourceError> {
        self.verify(&policy.connector_key, CONNECTOR_DOMAIN)
    }

    pub(super) fn pool(
        &self,
        policy: &RuntimeWitnessPolicy,
    ) -> Result<Statement<NativePoolUseObservation>, SourceError> {
        self.verify(&policy.pool_key, POOL_DOMAIN)
    }

    pub(super) fn verify<T: serde::de::DeserializeOwned>(
        &self,
        public_key: &str,
        domain: &[u8],
    ) -> Result<Statement<T>, SourceError> {
        if self.statement_base64.len() > MAX_STATEMENT.div_ceil(3) * 4
            || self.signature_base64.len() != 88
        {
            return Err(SourceError::Limit);
        }
        let raw = STANDARD
            .decode(&self.statement_base64)
            .map_err(|_| SourceError::Invalid)?;
        let signature = STANDARD
            .decode(&self.signature_base64)
            .map_err(|_| SourceError::Invalid)?;
        if raw.len() > MAX_STATEMENT || signature.len() != 64 {
            return Err(SourceError::Limit);
        }
        let mut message = Vec::with_capacity(domain.len() + raw.len());
        message.extend_from_slice(domain);
        message.extend_from_slice(&raw);
        UnparsedPublicKey::new(&ED25519, key(public_key)?)
            .verify(&message, &signature)
            .map_err(|_| SourceError::IdentityUnverified)?;
        serde_json::from_slice(&raw).map_err(|_| SourceError::Invalid)
    }
}
