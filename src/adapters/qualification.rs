//! Pure, current-code qualification of the selected change. This is a static
//! compatibility report, never approval, native readiness or observed protection.
use super::{
    capabilities_for_policy,
    engine::{mysql, postgres},
};
use crate::{
    binding,
    core::{capability::ActionKind, change::PreparedChange, plan::PlanStep, policy::*},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationDisposition {
    Unsupported,
    RuntimePrerequisite,
}

/// Stable codes only; compiler messages, generated SQL and credentials are never
/// copied into the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationReason {
    MultipleTargets,
    DescriptorMissing,
    ActionNotImplemented,
    ContractMismatch,
    RequiredEffectUnavailable,
    StandingLifetimeRequired,
    IdentityReferenceUnsupported,
    RecoveryReferenceUnsupported,
    ExactlyOneRecoveryRequired,
    PrincipalLimitExceeded,
    SharedLoginUnsupported,
    PostgresSqlScope,
    PostgresSqlUnsupported,
    PostgresSqlPrecondition,
    MysqlSqlScope,
    MysqlSqlUnsupported,
    MysqlSqlPrecondition,
    BindingUnsupported,
    RuntimeStateNotVerified,
    OwnedSqlReceiptRequired,
    IdentityReferenceRequired,
    TargetGenerationReferenceRequired,
    SourceEvidencePipelineMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualificationScope {
    Policy,
    Grant,
    Identity,
    Recovery,
    ExistingRoles,
    SqlScope { scope: SqlScope },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationFinding {
    pub target_id: Option<String>,
    pub grant_id: Option<String>,
    pub step_id: Option<String>,
    pub action: Option<ActionKind>,
    pub scope: QualificationScope,
    pub disposition: QualificationDisposition,
    pub reason: QualificationReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReport {
    pub schema_version: u32,
    pub policy_revision_hash: String,
    pub change_hash: String,
    pub readiness_only: bool,
    pub runtime_verified: bool,
    pub findings: Vec<QualificationFinding>,
}
impl QualificationReport {
    /// A positive result means only that no known static incompatibility was
    /// found. Callers must recompute this report; deserialized reports authorize
    /// nothing and must never replace runtime executor preconditions.
    pub fn is_qualified(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.disposition == QualificationDisposition::Unsupported)
    }
    /// Pinned references are inputs of the reviewed policy and cannot be
    /// supplied by a future handoff. Native observations, checkpoint success
    /// and ownership receipts remain stage-specific runtime prerequisites.
    pub fn is_dispatch_qualified(&self) -> bool {
        self.is_qualified()
            && !self.findings.iter().any(|f| {
                matches!(
                    f.reason,
                    QualificationReason::IdentityReferenceRequired
                        | QualificationReason::TargetGenerationReferenceRequired
                )
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QualificationError {
    #[error("QUALIFICATION_INVALID_CHANGE: prepared change failed integrity or scope validation")]
    InvalidChange,
}

fn finding(
    step: Option<&PlanStep>,
    scope: QualificationScope,
    reason: QualificationReason,
    disposition: QualificationDisposition,
) -> QualificationFinding {
    QualificationFinding {
        target_id: step.map(|s| s.target_id.clone()),
        grant_id: step.map(|s| s.grant_id.clone()),
        step_id: step.map(|s| s.id.clone()),
        action: step.map(|s| s.action),
        scope,
        disposition,
        reason,
    }
}

/// Checks exactly the actions embedded in the verified change, including scoped
/// reconcile/recover plans. No cloud process, driver, file, clock, metadata
/// lookup, future checkpoint or ownership receipt is consulted here.
pub fn qualify_change(change: &PreparedChange) -> Result<QualificationReport, QualificationError> {
    change
        .verify()
        .map_err(|_| QualificationError::InvalidChange)?;
    let mut report = QualificationReport {
        schema_version: 1,
        policy_revision_hash: change.plan.policy_revision_hash.clone(),
        change_hash: change.change_hash.clone(),
        readiness_only: true,
        runtime_verified: false,
        findings: vec![finding(
            None,
            QualificationScope::Policy,
            QualificationReason::RuntimeStateNotVerified,
            QualificationDisposition::RuntimePrerequisite,
        )],
    };
    let current_capabilities =
        capabilities_for_policy(&change.policy).map_err(|_| QualificationError::InvalidChange)?;
    if change.policy.schema_version == 2
        && !super::registry::source_execution_supported(&change.policy)
    {
        // Even a caller-supplied descriptor marked Implemented cannot enable
        // dispatch before the source admission pipeline is composed (K10-F).
        report.findings.push(finding(
            None,
            QualificationScope::Policy,
            QualificationReason::SourceEvidencePipelineMissing,
            QualificationDisposition::Unsupported,
        ));
    }
    // Current native factories bind one target per operation, even when a
    // library caller supplies a policy with additional logical targets.
    if change.policy.targets.len() != 1 {
        report.findings.push(finding(
            None,
            QualificationScope::Policy,
            QualificationReason::MultipleTargets,
            QualificationDisposition::Unsupported,
        ));
    }
    for gap in &change.plan.required_effect_gaps {
        report.findings.push(QualificationFinding {
            target_id: Some(gap.target_id.clone()),
            grant_id: Some(gap.grant_id.clone()),
            step_id: None,
            action: None,
            scope: QualificationScope::Grant,
            disposition: QualificationDisposition::Unsupported,
            reason: QualificationReason::RequiredEffectUnavailable,
        });
    }
    for step in &change.plan.steps {
        let target = change
            .policy
            .targets
            .iter()
            .find(|t| t.id == step.target_id)
            .ok_or(QualificationError::InvalidChange)?;
        let grant = change
            .policy
            .grants
            .iter()
            .find(|g| g.id == step.grant_id)
            .ok_or(QualificationError::InvalidChange)?;
        let current: Vec<_> = current_capabilities
            .iter()
            .filter(|c| c.target_id.as_ref() == Some(&target.id))
            .collect();
        let reason = match current.iter().find(|c| c.action == step.action) {
            None => Some(QualificationReason::DescriptorMissing),
            Some(c) if !c.has_implementation() => Some(QualificationReason::ActionNotImplemented),
            Some(c) if c.contract_revision != step.adapter_contract => {
                Some(QualificationReason::ContractMismatch)
            }
            Some(_) => None,
        };
        if let Some(reason) = reason {
            report.findings.push(finding(
                Some(step),
                QualificationScope::Grant,
                reason,
                QualificationDisposition::Unsupported,
            ));
        }
        static_native(change, step, target, grant, &mut report.findings)?;
        match step.action {
            ActionKind::ConfigureSqlPrivileges => {
                qualify_sql(&change.policy, step, &mut report.findings)
            }
            ActionKind::RegisterNativeDbIdentity
                if target.placement.kind == PlacementKind::AwsRds =>
            {
                push_compile(
                    &change.policy,
                    step,
                    QualificationScope::Identity,
                    &mut report.findings,
                );
            }
            ActionKind::DisableNewConnections => {
                push_compile(
                    &change.policy,
                    step,
                    QualificationScope::Identity,
                    &mut report.findings,
                );
            }
            ActionKind::RevokeSqlPrivileges => {
                // The runtime factory validates the trusted source receipt and
                // owns the exact-delta compiler. Compile the prior intent only;
                // absence of a future receipt is not static incompatibility.
                if let Some(previous) = &change.previous_policy {
                    let mut prior_step = step.clone();
                    prior_step.action = ActionKind::ConfigureSqlPrivileges;
                    let before = report.findings.len();
                    qualify_sql(previous, &prior_step, &mut report.findings);
                    for f in &mut report.findings[before..] {
                        f.action = Some(step.action);
                    }
                }
                report.findings.push(finding(
                    Some(step),
                    QualificationScope::Grant,
                    QualificationReason::OwnedSqlReceiptRequired,
                    QualificationDisposition::RuntimePrerequisite,
                ));
            }
            ActionKind::PublishBinding
                if binding::connection_profile(&change.policy, &step.grant_id).is_err() =>
            {
                report.findings.push(finding(
                    Some(step),
                    QualificationScope::Grant,
                    QualificationReason::BindingUnsupported,
                    QualificationDisposition::Unsupported,
                ));
            }
            _ => {}
        }
    }
    report.findings.sort();
    report.findings.dedup();
    Ok(report)
}

fn compile_reason(policy: &PolicyRevision, step: &PlanStep) -> Option<QualificationReason> {
    let target = policy.targets.iter().find(|t| t.id == step.target_id)?;
    match target.engine.family {
        EngineFamily::PostgreSql => {
            let action = match step.action {
                ActionKind::RegisterNativeDbIdentity => {
                    postgres::PgAction::RegisterNativeDbIdentity
                }
                ActionKind::DisableNewConnections => postgres::PgAction::DisableNewConnections,
                _ => postgres::PgAction::ConfigureSqlPrivileges,
            };
            postgres::compile(policy, &step.target_id, &step.grant_id, action)
                .err()
                .map(|e| match e {
                    postgres::PgError::Scope => QualificationReason::PostgresSqlScope,
                    postgres::PgError::Unsupported => QualificationReason::PostgresSqlUnsupported,
                    _ => QualificationReason::PostgresSqlPrecondition,
                })
        }
        EngineFamily::MySql => {
            let action = match step.action {
                ActionKind::RegisterNativeDbIdentity => {
                    mysql::MysqlAction::RegisterNativeDbIdentity
                }
                ActionKind::DisableNewConnections => mysql::MysqlAction::DisableNewConnections,
                _ => mysql::MysqlAction::ConfigureSqlPrivileges,
            };
            mysql::compile(policy, &step.target_id, &step.grant_id, action)
                .err()
                .map(|e| match e {
                    mysql::MysqlError::Scope => QualificationReason::MysqlSqlScope,
                    mysql::MysqlError::Unsupported => QualificationReason::MysqlSqlUnsupported,
                    _ => QualificationReason::MysqlSqlPrecondition,
                })
        }
        _ => Some(QualificationReason::ActionNotImplemented),
    }
}
fn push_compile(
    policy: &PolicyRevision,
    step: &PlanStep,
    scope: QualificationScope,
    findings: &mut Vec<QualificationFinding>,
) {
    if let Some(reason) = compile_reason(policy, step) {
        findings.push(finding(
            Some(step),
            scope,
            reason,
            QualificationDisposition::Unsupported,
        ));
    }
}
fn qualify_sql(policy: &PolicyRevision, step: &PlanStep, findings: &mut Vec<QualificationFinding>) {
    let Some(full_reason) = compile_reason(policy, step) else {
        return;
    };
    let Some(index) = policy.grants.iter().position(|g| g.id == step.grant_id) else {
        return;
    };
    let intent = &policy.grants[index].sql_access;
    let mut isolated = policy.clone();
    isolated.grants[index].sql_access = SqlAccessIntent::default();
    let before = findings.len();
    if compile_reason(&isolated, step).is_some() {
        findings.push(finding(
            Some(step),
            QualificationScope::Grant,
            full_reason,
            QualificationDisposition::Unsupported,
        ));
        return;
    }
    if !intent.existing_roles.is_empty() {
        isolated.grants[index].sql_access.existing_roles = intent.existing_roles.clone();
        push_compile(&isolated, step, QualificationScope::ExistingRoles, findings);
        isolated.grants[index].sql_access.existing_roles.clear();
    }
    for privilege in &intent.privileges {
        isolated.grants[index].sql_access.privileges = vec![privilege.clone()];
        push_compile(
            &isolated,
            step,
            QualificationScope::SqlScope {
                scope: privilege.scope.clone(),
            },
            findings,
        );
    }
    if findings.len() == before {
        findings.push(finding(
            Some(step),
            QualificationScope::Grant,
            full_reason,
            QualificationDisposition::Unsupported,
        ));
    }
}

fn identity_supported(target: &Target, subject: &Subject) -> bool {
    match target.placement.kind {
        PlacementKind::AwsRds => {
            subject.identity.provider == IdentityProvider::Aws
                && aws_role_arn(&subject.identity.principal, &target.placement.account_id)
                && subject
                    .identity
                    .principal
                    .rsplit('/')
                    .next()
                    .is_some_and(|n| n.len() <= 64)
                && subject
                    .identity
                    .immutable_id
                    .as_deref()
                    .is_some_and(aws_role_id)
        }
        PlacementKind::GcpCloudSql => {
            subject.identity.provider == IdentityProvider::Gcp
                && subject.identity.principal.len() <= 254
                && subject
                    .identity
                    .principal
                    .ends_with(".iam.gserviceaccount.com")
                && subject
                    .identity
                    .principal
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"-_.@".contains(&v))
                && subject
                    .identity
                    .principal
                    .bytes()
                    .filter(|b| *b == b'@')
                    .count()
                    == 1
                && subject
                    .identity
                    .immutable_id
                    .as_ref()
                    .is_none_or(|v| !v.is_empty())
        }
        _ => false,
    }
}

fn static_native(
    change: &PreparedChange,
    step: &PlanStep,
    target: &Target,
    grant: &Grant,
    findings: &mut Vec<QualificationFinding>,
) -> Result<(), QualificationError> {
    let policy = &change.policy;
    let subject = policy
        .subjects
        .iter()
        .find(|s| s.id == grant.subject)
        .ok_or(QualificationError::InvalidChange)?;
    let profile = policy
        .protection_profiles
        .iter()
        .find(|p| p.id == grant.profile)
        .ok_or(QualificationError::InvalidChange)?;
    if subject.identity.immutable_id.is_none() {
        findings.push(finding(
            Some(step),
            QualificationScope::Identity,
            QualificationReason::IdentityReferenceRequired,
            QualificationDisposition::RuntimePrerequisite,
        ));
    }
    if target.resource.generation_fingerprint.is_none() {
        findings.push(finding(
            Some(step),
            QualificationScope::Identity,
            QualificationReason::TargetGenerationReferenceRequired,
            QualificationDisposition::RuntimePrerequisite,
        ));
    }
    for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
        if policy
            .subjects
            .iter()
            .any(|s| s.id == exception.subject && s.identity.immutable_id.is_none())
        {
            findings.push(finding(
                Some(step),
                QualificationScope::Recovery,
                QualificationReason::IdentityReferenceRequired,
                QualificationDisposition::RuntimePrerequisite,
            ));
        }
    }
    let mut reject = |scope, reason| {
        findings.push(finding(
            Some(step),
            scope,
            reason,
            QualificationDisposition::Unsupported,
        ))
    };
    if !matches!(grant.lifetime, GrantLifetime::Standing) {
        reject(
            QualificationScope::Grant,
            QualificationReason::StandingLifetimeRequired,
        );
    }
    if !identity_supported(target, subject)
        || (target.placement.kind == PlacementKind::GcpCloudSql
            && grant.db_identity
                != subject
                    .identity
                    .principal
                    .trim_end_matches(".gserviceaccount.com"))
    {
        reject(
            QualificationScope::Identity,
            QualificationReason::IdentityReferenceUnsupported,
        );
    }
    if policy.grants.iter().any(|other| {
        other.id != grant.id
            && other.db_identity == grant.db_identity
            && other.admission == AdmissionIntent::Allow
            && policy.targets.iter().any(|t| {
                t.id == other.target
                    && t.placement.kind == target.placement.kind
                    && t.placement.account_id == target.placement.account_id
                    && t.resource.native_id == target.resource.native_id
            })
    }) {
        reject(
            QualificationScope::Identity,
            QualificationReason::SharedLoginUnsupported,
        );
    }
    let mut recovery_ids = BTreeSet::new();
    let mut principals = BTreeSet::from([subject.identity.principal.clone()]);
    for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
        let recovery = policy
            .subjects
            .iter()
            .find(|s| s.id == exception.subject)
            .ok_or(QualificationError::InvalidChange)?;
        recovery_ids.insert(&recovery.id);
        principals.insert(recovery.identity.principal.clone());
        if !identity_supported(target, recovery)
            || recovery.identity.principal == subject.identity.principal
            || (subject.identity.immutable_id.is_some()
                && recovery.identity.immutable_id == subject.identity.immutable_id)
            || !matches!(exception.lifetime, GrantLifetime::Standing)
            || !profile.allowed_routes.iter().any(|r| {
                r.id == exception.route_id
                    && (target.placement.kind != PlacementKind::AwsRds
                        || r.kind == RouteKind::NativeProxy)
            })
        {
            reject(
                QualificationScope::Recovery,
                QualificationReason::RecoveryReferenceUnsupported,
            );
        }
    }
    // The native AWS observer and factory use the whole operation's declared
    // principal set. Do not qualify unrelated SQL intent in maintenance plans.
    if target.placement.kind == PlacementKind::AwsRds {
        for other in policy.grants.iter().filter(|g| g.target == target.id) {
            let u = policy
                .subjects
                .iter()
                .find(|s| s.id == other.subject)
                .ok_or(QualificationError::InvalidChange)?;
            principals.insert(u.identity.principal.clone());
            if !identity_supported(target, u) {
                reject(
                    QualificationScope::Identity,
                    QualificationReason::IdentityReferenceUnsupported,
                );
            }
            let p = policy
                .protection_profiles
                .iter()
                .find(|p| p.id == other.profile)
                .ok_or(QualificationError::InvalidChange)?;
            for e in p.management_exceptions.iter().filter(|e| e.recovery) {
                let r = policy
                    .subjects
                    .iter()
                    .find(|s| s.id == e.subject)
                    .ok_or(QualificationError::InvalidChange)?;
                recovery_ids.insert(&r.id);
                principals.insert(r.identity.principal.clone());
                if !identity_supported(target, r)
                    || r.identity.principal == u.identity.principal
                    || r.identity.immutable_id == u.identity.immutable_id
                    || !matches!(e.lifetime, GrantLifetime::Standing)
                    || !p
                        .allowed_routes
                        .iter()
                        .any(|route| route.id == e.route_id && route.kind == RouteKind::NativeProxy)
                {
                    reject(
                        QualificationScope::Recovery,
                        QualificationReason::RecoveryReferenceUnsupported,
                    );
                }
            }
        }
        if principals.len() > 8 {
            reject(
                QualificationScope::Identity,
                QualificationReason::PrincipalLimitExceeded,
            );
        }
    }
    if recovery_ids.is_empty()
        || (target.placement.kind == PlacementKind::AwsRds && recovery_ids.len() != 1)
    {
        reject(
            QualificationScope::Recovery,
            QualificationReason::ExactlyOneRecoveryRequired,
        );
    }
    Ok(())
}
