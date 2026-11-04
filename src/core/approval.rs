//! Bounded local operator intent. Hashes provide integrity, not approver authentication.
use super::operation::valid_execution_identity;
use super::{
    change::{ChangeError, PreparedChange, digest, json},
    policy::{valid_hash, valid_id},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("APPROVAL_INVALID: approval scope or immutable change is invalid")]
    Invalid,
    #[error("APPROVAL_EXPIRED: approval does not allow starting this operation now")]
    Expired,
    #[error("APPROVAL_SCOPE_MISMATCH: operation requires a new scoped plan and approval")]
    ScopeMismatch,
}
impl From<ChangeError> for ApprovalError {
    fn from(_: ChangeError) -> Self {
        Self::Invalid
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrant {
    pub schema_version: u32,
    pub id: String,
    pub approval_hash: String,
    pub change_hash: String,
    pub policy_revision_hash: String,
    pub target_scope_hash: String,
    pub allowed_step_ids: Vec<String>,
    pub allowed_repair_recipe_hashes: Vec<String>,
    pub recovery_scope_hash: String,
    pub execution_identity: String,
    pub issued_at: u64,
    pub forward_valid_until: u64,
    pub recovery_valid_until: u64,
    pub limits_hash: String,
    pub approver: String,
}

pub fn issue(
    change: &PreparedChange,
    id: &str,
    approver: &str,
    execution_identity: &str,
    forward_valid_until: u64,
    recovery_valid_until: u64,
    now: u64,
) -> Result<ApprovalGrant, ApprovalError> {
    change.verify()?;
    if !valid_id(id)
        || !valid_id(approver)
        || !valid_execution_identity(execution_identity)
        || now < change.plan.created_at
        || forward_valid_until <= now
        || recovery_valid_until < forward_valid_until
        || recovery_valid_until
            > now
                .checked_add(change.limits.max_operation_seconds)
                .ok_or(ApprovalError::Invalid)?
    {
        return Err(ApprovalError::Invalid);
    }
    let mut allowed_step_ids = change
        .plan
        .steps
        .iter()
        .map(|step| step.id.clone())
        .collect::<Vec<_>>();
    allowed_step_ids.sort();
    let mut allowed_repair_recipe_hashes = change
        .repair_recipes
        .iter()
        .map(|recipe| recipe.recipe_hash.clone())
        .collect::<Vec<_>>();
    allowed_repair_recipe_hashes.sort();
    let mut grant = ApprovalGrant {
        schema_version: 1,
        id: id.into(),
        approval_hash: String::new(),
        change_hash: change.change_hash.clone(),
        policy_revision_hash: change.plan.policy_revision_hash.clone(),
        target_scope_hash: change.target_scope_hash()?,
        allowed_step_ids,
        allowed_repair_recipe_hashes,
        recovery_scope_hash: change.recovery.scope_hash.clone(),
        execution_identity: execution_identity.into(),
        issued_at: now,
        forward_valid_until,
        recovery_valid_until,
        limits_hash: change.limits_hash()?,
        approver: approver.into(),
    };
    grant.approval_hash = grant.computed_hash()?;
    Ok(grant)
}

impl ApprovalGrant {
    fn computed_hash(&self) -> Result<String, ApprovalError> {
        let mut copy = self.clone();
        copy.approval_hash.clear();
        Ok(digest("approval", &copy)?)
    }
    pub fn verify_integrity(&self) -> Result<(), ApprovalError> {
        if self.schema_version != 1
            || !valid_id(&self.id)
            || !valid_id(&self.approver)
            || !valid_execution_identity(&self.execution_identity)
            || !valid_hash(&self.approval_hash)
            || self.approval_hash != self.computed_hash()?
            || self.forward_valid_until <= self.issued_at
            || self.recovery_valid_until < self.forward_valid_until
        {
            return Err(ApprovalError::Invalid);
        }
        Ok(())
    }
    /// Includes exact plan and target generations; elapsed forward scope cannot
    /// be revived merely by choosing a recovery deadline.
    pub fn validate(
        &self,
        change: &PreparedChange,
        execution_identity: &str,
        now: u64,
        recovery: bool,
    ) -> Result<(), ApprovalError> {
        self.verify_integrity()?;
        change.verify()?;
        let mut steps = change
            .plan
            .steps
            .iter()
            .map(|step| step.id.clone())
            .collect::<Vec<_>>();
        steps.sort();
        let mut recipes = change
            .repair_recipes
            .iter()
            .map(|recipe| recipe.recipe_hash.clone())
            .collect::<Vec<_>>();
        recipes.sort();
        if self.change_hash != change.change_hash
            || self.policy_revision_hash != change.plan.policy_revision_hash
            || self.target_scope_hash != change.target_scope_hash()?
            || self.allowed_step_ids != steps
            || self.allowed_repair_recipe_hashes != recipes
            || self.recovery_scope_hash != change.recovery.scope_hash
            || self.limits_hash != change.limits_hash()?
            || self.execution_identity != execution_identity
            || self.issued_at < change.plan.created_at
            || now < self.issued_at
            || self.recovery_valid_until
                > self
                    .issued_at
                    .checked_add(change.limits.max_operation_seconds)
                    .ok_or(ApprovalError::Invalid)?
        {
            return Err(ApprovalError::ScopeMismatch);
        }
        let until = if recovery {
            self.recovery_valid_until
        } else {
            self.forward_valid_until
        };
        if now >= until {
            return Err(ApprovalError::Expired);
        }
        Ok(())
    }
    pub fn permits_step(&self, step_id: &str) -> bool {
        self.allowed_step_ids.iter().any(|step| step == step_id)
    }
    pub fn permits_repair(&self, recipe_hash: &str) -> bool {
        self.allowed_repair_recipe_hashes
            .iter()
            .any(|recipe| recipe == recipe_hash)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ApprovalError> {
        Ok(json(self)?)
    }
}
