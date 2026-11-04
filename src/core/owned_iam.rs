//! Source-bound ownership proof for one Cloud SQL project IAM policy update.
use super::hash_bytes;
use super::{
    capability::ActionKind,
    change::PreparedChange,
    operation::{StepReceipt, valid_execution_identity},
    policy::{
        AdmissionIntent, EngineFamily, Grant, GrantLifetime, IdentityProvider, ManagedField,
        PlacementKind, Subject, Target, valid_hash, valid_id,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedIamDeltaReceipt {
    pub source_operation_id: String,
    pub source_change_hash: String,
    pub source_policy_revision_hash: String,
    pub source_step_id: String,
    pub attempt: u32,
    pub idempotency_key: String,
    pub execution_identity: String,
    pub step_receipt_hash: String,
    pub project_id: String,
    pub project_number: String,
    pub native_resource_id: String,
    pub registration_id: String,
    pub generation_fingerprint: String,
    pub engine_version: String,
    pub grant_id: String,
    pub service_account_email: String,
    pub service_account_unique_id: String,
    pub db_login: String,
    pub before_etag: String,
    pub before_digest: String,
    pub before_read_at: u64,
    pub after_etag: String,
    pub after_digest: String,
    pub after_read_at: u64,
    pub bindings: [OwnedIamBinding; 2],
}

impl OwnedIamDeltaReceipt {
    pub fn hash(&self) -> String {
        digest("gcp-iam-owned-delta-v1", self)
    }

    pub fn step_receipt_hash(receipt: &StepReceipt) -> String {
        digest("gcp-iam-owned-source-step-receipt-v1", receipt)
    }

    pub fn validate(&self) -> bool {
        valid_id(&self.source_operation_id)
            && valid_id(&self.source_step_id)
            && self.attempt > 0
            && valid_hash(&self.idempotency_key)
            && valid_execution_identity(&self.execution_identity)
            && [
                &self.source_change_hash,
                &self.source_policy_revision_hash,
                &self.step_receipt_hash,
                &self.generation_fingerprint,
                &self.before_digest,
                &self.after_digest,
            ]
            .into_iter()
            .all(|hash| valid_hash(hash))
            && valid_id(&self.project_id)
            && numeric_id(&self.project_number)
            && valid_id(&self.registration_id)
            && valid_id(&self.grant_id)
            && numeric_id(&self.service_account_unique_id)
            && self.engine_version == "16.15"
            && valid_etag(&self.before_etag)
            && valid_etag(&self.after_etag)
            && self.before_etag != self.after_etag
            && self.before_digest != self.after_digest
            && self.before_read_at > 0
            && self.after_read_at >= self.before_read_at
    }

    pub fn matches_change(&self, change: &PreparedChange) -> bool {
        if !self.validate()
            || change.lifecycle.is_some()
            || change.policy.schema_version != super::policy::SOURCE_BOUND_POLICY_SCHEMA_VERSION
            || change.change_hash != self.source_change_hash
            || change.plan.policy_revision_hash != self.source_policy_revision_hash
        {
            return false;
        }
        let Some(step) = change.plan.steps.iter().find(|step| {
            step.id == self.source_step_id
                && step.grant_id == self.grant_id
                && step.action == ActionKind::ConfigureIdentity
        }) else {
            return false;
        };
        let Some(target) = change
            .policy
            .targets
            .iter()
            .find(|target| target.id == step.target_id)
        else {
            return false;
        };
        let Some(grant) = change.policy.grants.iter().find(|grant| {
            grant.id == step.grant_id
                && grant.target == target.id
                && grant.profile == step.profile_id
                && grant.admission == AdmissionIntent::Allow
        }) else {
            return false;
        };
        let Some(subject) = change
            .policy
            .subjects
            .iter()
            .find(|subject| subject.id == grant.subject)
        else {
            return false;
        };
        self.matches_scope(&change.policy.policy_id, target, grant, subject)
    }

    pub fn matches_scope(
        &self,
        policy_id: &str,
        target: &Target,
        grant: &Grant,
        subject: &Subject,
    ) -> bool {
        target.placement.kind == PlacementKind::GcpCloudSql
            && target.placement.region == "asia-northeast1"
            && target.engine.family == EngineFamily::PostgreSql
            && target
                .managed_surface
                .fields
                .contains(&ManagedField::GcpIamBinding)
            && grant.lifetime == GrantLifetime::Standing
            && subject.identity.provider == IdentityProvider::Gcp
            && self.project_id == target.placement.account_id
            && self.native_resource_id == target.resource.native_id
            && self.registration_id == target.registration_id
            && target.resource.generation_fingerprint.as_deref()
                == Some(self.generation_fingerprint.as_str())
            && self.engine_version == target.engine.version
            && self.grant_id == grant.id
            && self.service_account_email == subject.identity.principal
            && subject.identity.immutable_id.as_deref()
                == Some(self.service_account_unique_id.as_str())
            && self.db_login == grant.db_identity
            && self.bindings == OwnedIamBinding::for_grant(policy_id, target, grant, subject)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedIamBinding {
    pub role: String,
    pub member: String,
    pub condition: OwnedIamCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedIamCondition {
    pub title: String,
    pub description: String,
    pub expression: String,
}

impl OwnedIamBinding {
    pub fn for_grant(
        policy_id: &str,
        target: &Target,
        grant: &Grant,
        subject: &Subject,
    ) -> [Self; 2] {
        // Keep titles stable across the Allow/Deny boundary and existing artifacts.
        let ownership = hash_bytes(
            &serde_json::to_vec(&(
                policy_id,
                &target.registration_id,
                &target.resource.generation_fingerprint,
                &grant.id,
                &subject.identity.immutable_id,
            ))
            .expect("fixed ownership tuple serializes"),
        );
        [
            ("connect", "roles/cloudsql.client"),
            ("login", "roles/cloudsql.instanceUser"),
        ]
        .map(|(suffix, role)| Self {
            role: role.into(),
            member: format!("serviceAccount:{}", subject.identity.principal),
            condition: OwnedIamCondition {
                title: format!("veil-db-guard-{}-{suffix}", &ownership[..32]),
                description: "Veil-owned instance-scoped allow; no broad role replacement".into(),
                expression: format!(
                    "resource.name == '{}' && resource.type == 'sqladmin.googleapis.com/Instance'",
                    target.resource.native_id
                ),
            },
        })
    }
}

pub(crate) fn valid_etag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=_-".contains(&byte))
}

pub(crate) fn numeric_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn digest(domain: &str, value: &impl Serialize) -> String {
    hash_bytes(&serde_json::to_vec(&(domain, value)).expect("typed ownership receipt serializes"))
}
