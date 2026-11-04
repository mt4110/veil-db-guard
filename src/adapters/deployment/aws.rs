//! Existing RDS PostgreSQL/MySQL + existing RDS Proxy, one native write per dispatch.
//!
//! No constructor performs I/O beyond executable metadata. Production execution
//! is opt-in through an absolute AWS CLI path and a pinned profile/account/role.
//! AWS PutRolePolicy/ModifyDBProxy have no compare-and-swap: an externally
//! enforced exclusive change window is a mandatory operational precondition.
//! Only the exact owned inline document and explicit single ingress-rule ID
//! are writable. Config readback never establishes a working protected route.
//!
//! API contracts checked against official documentation:
//! https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBProxy.html
//! https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-iam-setup.html
//! https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html
//! https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html
use crate::{
    binding::CheckpointGate,
    config::hash_bytes,
    core::{
        capability::ActionKind,
        change::PreparedChange,
        operation::{DispatchTicket, EffectState, StepReceipt, StepRecord, StepState},
        orchestrator::{ExecutorError, StepExecutor},
        plan::PlanStep,
        policy::{
            AdmissionIntent, AwsRuleSource, AwsSecurityGroupRuleBinding, EngineFamily, Grant,
            GrantLifetime, IdentityProvider, ManagedField, PlacementKind, ProfileKind, Subject,
            Target,
        },
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    Unavailable,
    Precondition,
    NotApplied,
    Unknown,
}
impl From<ProviderError> for ExecutorError {
    fn from(v: ProviderError) -> Self {
        match v {
            ProviderError::Unavailable => Self::Unavailable,
            ProviderError::Precondition => Self::PreconditionsNotMet,
            ProviderError::NotApplied => Self::NotApplied,
            ProviderError::Unknown => Self::OutcomeUnknown,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdsInstance {
    pub arn: String,
    pub resource_id: String,
    pub endpoint: String,
    pub version: String,
    pub engine_family: EngineFamily,
    pub available: bool,
    pub iam_authentication: bool,
    pub security_group_ids: BTreeSet<String>,
    pub port: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdsProxy {
    pub arn: String,
    pub name: String,
    pub endpoint: String,
    pub role_arn: String,
    pub available: bool,
    pub engine_family: EngineFamily,
    pub require_tls: bool,
    pub iam_authentication: bool,
    /// Secrets-based per-user Auth entries can coexist with IAM_AUTH. The
    /// initial exclusive-IAM profile requires an empty Auth configuration.
    pub auth_entries: usize,
    pub security_group_ids: BTreeSet<String>,
    /// Resolved immutable DB IDs after exact target ARN/name/endpoint matching.
    /// DBProxyTarget.RdsResourceId itself is the mutable instance identifier.
    pub target_resource_ids: BTreeSet<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroupRule {
    pub id: String,
    pub group_id: String,
    pub ingress: bool,
    pub protocol: String,
    pub from_port: i64,
    pub to_port: i64,
    pub source: Option<AwsRuleSource>,
    pub owner_account: String,
    pub tags: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionEvidence {
    pub generation: String,
    pub observed_at: u64,
    /// Each principal passed IAM authentication, verified TLS, and SQL access.
    pub proxy_allowed_principals: BTreeSet<String>,
    /// Explicit attributable refusal; a timeout is never sufficient.
    pub direct_denied_principals: BTreeSet<String>,
    pub evidence_refs: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Allowed,
    Denied,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvidence {
    pub complete: bool,
    pub generation: String,
    pub observed_at: u64,
    pub denied_principal: String,
    pub access: Access,
    /// True only for a current rds-db:connect rejection, with a fresh positive
    /// recovery control; SQL ACL failure alone does not establish IAM denial.
    pub iam_connect_denied: bool,
    pub proxy_allowed_principals: BTreeSet<String>,
    pub direct_denied_principals: BTreeSet<String>,
    pub evidence_refs: Vec<String>,
}
/// Trusted Rust implementation, never deserialized commands or receipts. Every
/// mutation must re-read its exact domain and reject drift, never retry after
/// ambiguity. The caller supplies an externally enforced exclusive window.
pub type BeforeAwsWrite<'a> = dyn FnMut() -> Result<(), ProviderError> + 'a;
pub trait AwsProvider {
    fn supports_source_guard(&self) -> bool {
        false
    }
    /// V3 transports must call the guard after their LAST domain read and
    /// immediately before native mutation. Legacy providers fail closed.
    fn put_inline_policy_guarded(
        &mut self,
        _: &str,
        _: &str,
        _: &Value,
        _: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable)
    }
    fn delete_inline_policy_guarded(
        &mut self,
        _: &str,
        _: &str,
        _: &Value,
        _: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable)
    }
    fn prepare_proxy_guarded(
        &mut self,
        _: &Target,
        _: &RdsProxy,
        _: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable)
    }
    fn revoke_rule_guarded(
        &mut self,
        _: &Target,
        _: &SecurityGroupRule,
        _: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable)
    }
    fn now(&self) -> u64 {
        crate::domain::now()
    }
    fn cancelled(&self) -> bool {
        false
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError>;
    fn instance(&mut self, target: &Target) -> Result<RdsInstance, ProviderError>;
    fn proxy(&mut self, target: &Target) -> Result<RdsProxy, ProviderError>;
    fn role_id(&mut self, arn: &str) -> Result<String, ProviderError>;
    fn inline_policy(&mut self, arn: &str, name: &str) -> Result<Option<Value>, ProviderError>;
    fn put_inline_policy(
        &mut self,
        arn: &str,
        name: &str,
        desired: &Value,
    ) -> Result<(), ProviderError>;
    fn delete_inline_policy(
        &mut self,
        arn: &str,
        name: &str,
        expected: &Value,
    ) -> Result<(), ProviderError>;
    fn prepare_proxy(&mut self, target: &Target, before: &RdsProxy) -> Result<(), ProviderError>;
    fn rules(&mut self, target: &Target) -> Result<Vec<SecurityGroupRule>, ProviderError>;
    fn revoke_rule(
        &mut self,
        target: &Target,
        rule: &SecurityGroupRule,
    ) -> Result<(), ProviderError>;
    fn observe_connections(
        &mut self,
        _: &PreparedChange,
        _: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        Ok(None)
    }
    fn observe_revocation(
        &mut self,
        _: &PreparedChange,
        _: &Target,
        _: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        Ok(None)
    }
}
pub fn generation_fingerprint(
    account: &str,
    region: &str,
    db_arn: &str,
    db_resource_id: &str,
) -> String {
    crate::core::policy::aws_generation_fingerprint(account, region, db_arn, db_resource_id)
}
/// Secret-free pre-switch configuration bound into the explicit dedicated-proxy
/// preparation declaration. Availability is transient and deliberately omitted.
pub fn preparation_fingerprint(instance: &RdsInstance, proxy: &RdsProxy) -> String {
    hash_bytes(&serde_json::to_vec(&json!({
        "domain":"aws-rds-native-preparation-v2",
        "instance":{"arn":instance.arn,"resource_id":instance.resource_id,"endpoint":instance.endpoint,"version":instance.version,"engine_family":instance.engine_family,"iam_authentication":instance.iam_authentication,"security_group_ids":instance.security_group_ids,"port":instance.port},
        "proxy":{"arn":proxy.arn,"name":proxy.name,"endpoint":proxy.endpoint,"role_arn":proxy.role_arn,"engine_family":proxy.engine_family,"require_tls":proxy.require_tls,"iam_authentication":proxy.iam_authentication,"auth_entries":proxy.auth_entries,"security_group_ids":proxy.security_group_ids,"target_resource_ids":proxy.target_resource_ids}
    })).expect("secret-free native configuration serializes"))
}
/// Exact initial provider contracts. Other engines and versions never inherit
/// MySQL behavior merely because they are not PostgreSQL.
fn engine_contract(
    t: &Target,
) -> Result<(&'static str, &'static str, u16, ProfileKind), ProviderError> {
    match (t.engine.family, t.engine.version.as_str()) {
        (EngineFamily::PostgreSql, "16.15") => Ok((
            "postgres",
            "POSTGRESQL",
            5432,
            ProfileKind::AwsRdsPostgresProxyV1,
        )),
        (EngineFamily::MySql, "8.0.43") => {
            Ok(("mysql", "MYSQL", 3306, ProfileKind::AwsRdsMysqlProxyV1))
        }
        _ => Err(ProviderError::Precondition),
    }
}
fn native_engine(v: &str) -> Result<EngineFamily, ProviderError> {
    match v {
        "postgres" => Ok(EngineFamily::PostgreSql),
        "mysql" => Ok(EngineFamily::MySql),
        _ => Err(ProviderError::Precondition),
    }
}
fn proxy_engine(v: &str) -> Result<EngineFamily, ProviderError> {
    match v {
        "POSTGRESQL" => Ok(EngineFamily::PostgreSql),
        "MYSQL" => Ok(EngineFamily::MySql),
        _ => Err(ProviderError::Precondition),
    }
}
fn token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+=,@".contains(&b))
}
fn db_user(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 63
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_".contains(&b))
}
fn role_name(arn: &str) -> Result<&str, ProviderError> {
    let parts: Vec<_> = arn.splitn(6, ':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || parts[1] != "aws"
        || parts[2] != "iam"
        || !parts[3].is_empty()
        || parts[4].len() != 12
        || !parts[4].bytes().all(|b| b.is_ascii_digit())
        || !parts[5].starts_with("role/")
    {
        return Err(ProviderError::Precondition);
    }
    let name = parts[5]
        .rsplit('/')
        .next()
        .ok_or(ProviderError::Precondition)?;
    if !token(name) || name.len() > 64 || arn.chars().any(char::is_control) {
        return Err(ProviderError::Precondition);
    }
    Ok(name)
}
fn owned_rule(t: &Target, r: &SecurityGroupRule, a: &AwsSecurityGroupRuleBinding) -> bool {
    t.aws.as_ref().is_some_and(|b| {
        r.id == a.rule_id
            && r.group_id == b.db_security_group_id
            && r.owner_account == t.placement.account_id
            && r.ingress
            && r.protocol == a.protocol
            && r.from_port == i64::from(a.from_port)
            && r.to_port == i64::from(a.to_port)
            && r.source.as_ref() == Some(&a.source)
            && r.tags.get(&a.ownership_tag_key) == Some(&a.ownership_tag_value)
    })
}
fn rule_source(r: &Value) -> Result<Option<AwsRuleSource>, ProviderError> {
    let mut sources = vec![];
    if let Some(cidr) = r.get("CidrIpv4").and_then(Value::as_str) {
        sources.push(AwsRuleSource::CidrV4 { cidr: cidr.into() });
    }
    if let Some(cidr) = r.get("CidrIpv6").and_then(Value::as_str) {
        sources.push(AwsRuleSource::CidrV6 { cidr: cidr.into() });
    }
    if r.get("ReferencedGroupInfo").is_some() {
        sources.push(AwsRuleSource::SecurityGroup {
            group_id: string(r, "/ReferencedGroupInfo/GroupId")?,
            account_id: string(r, "/ReferencedGroupInfo/UserId")?,
        });
    }
    if sources.len() + usize::from(r.get("PrefixListId").is_some()) > 1 {
        return Err(ProviderError::Unavailable);
    }
    // Prefix-list and unknown sources remain representable but can never match
    // an approved owned rule or the exact proxy path.
    Ok(sources.pop())
}
fn rule_tags(r: &Value) -> Result<BTreeMap<String, String>, ProviderError> {
    let Some(tags) = r.get("Tags") else {
        return Ok(BTreeMap::new());
    };
    let mut result = BTreeMap::new();
    for tag in tags.as_array().ok_or(ProviderError::Unavailable)? {
        if result
            .insert(string(tag, "/Key")?, string(tag, "/Value")?)
            .is_some()
        {
            return Err(ProviderError::Unavailable);
        }
    }
    Ok(result)
}
/// Existing backend policy is deliberately read-only. This proves the selected
/// policy document, not effective IAM in the presence of SCPs or boundaries.
pub fn required_proxy_policy(c: &PreparedChange, t: &Target) -> Result<Value, ProviderError> {
    let b = t.aws.as_ref().ok_or(ProviderError::Precondition)?;
    let mut users = BTreeSet::from([b.management_db_identity.clone()]);
    for g in c.policy.grants.iter().filter(|g| g.target == t.id) {
        users.insert(g.db_identity.clone());
    }
    if users.iter().any(|u| !db_user(u)) {
        return Err(ProviderError::Precondition);
    }
    let resources: Vec<_> = users
        .into_iter()
        .map(|u| {
            format!(
                "arn:aws:rds-db:{}:{}:dbuser:{}/{}",
                t.placement.region, t.placement.account_id, b.db_resource_id, u
            )
        })
        .collect();
    Ok(
        json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds-db:connect","Resource":resources}]}),
    )
}
fn positive_principals(
    c: &PreparedChange,
    t: &Target,
    recoveries: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut result = recoveries.clone();
    for g in c
        .policy
        .grants
        .iter()
        .filter(|g| g.target == t.id && g.admission == AdmissionIntent::Allow)
    {
        if let Some(u) = c.policy.subjects.iter().find(|u| u.id == g.subject) {
            result.insert(u.identity.principal.clone());
        }
    }
    result
}
fn policy_name(target: &Target, grant: &Grant, subject: &Subject) -> Result<String, ProviderError> {
    let b = target.aws.as_ref().ok_or(ProviderError::Precondition)?;
    if !token(&b.managed_policy_name) || b.managed_policy_name.len() > 100 {
        return Err(ProviderError::Precondition);
    }
    let suffix = hash_bytes(
        &serde_json::to_vec(&(
            subject.id.as_str(),
            grant.id.as_str(),
            grant.db_identity.as_str(),
        ))
        .expect("tuple serializes"),
    );
    Ok(format!("{}-{}", b.managed_policy_name, &suffix[..16]))
}
pub fn desired_identity_policy(
    target: &Target,
    grant: &Grant,
    subject: &Subject,
) -> Result<Value, ProviderError> {
    if !db_user(&grant.db_identity) {
        return Err(ProviderError::Precondition);
    }
    let b = target.aws.as_ref().ok_or(ProviderError::Precondition)?;
    let resource = b
        .proxy_arn
        .rsplit(':')
        .next()
        .filter(|s| s.starts_with("prx-"))
        .ok_or(ProviderError::Precondition)?;
    let owner = hash_bytes(
        &serde_json::to_vec(&(
            target.registration_id.as_str(),
            subject.id.as_str(),
            subject.identity.immutable_id.as_ref(),
        ))
        .map_err(|_| ProviderError::Precondition)?,
    );
    Ok(
        json!({"Version":"2012-10-17","Statement":[{"Sid":format!("VeilDbGuard{}",&owner[..32]),"Effect":"Allow","Action":"rds-db:connect","Resource":format!("arn:aws:rds-db:{}:{}:dbuser:{}/{}",target.placement.region,target.placement.account_id,resource,grant.db_identity)}]}),
    )
}

pub struct AwsExecutor<P, G> {
    pub provider: P,
    execution_identity: String,
    checkpoints: G,
    last_revocation: Option<RevocationEvidence>,
    source_contract_scope: bool,
}
impl<P: AwsProvider, G: CheckpointGate> AwsExecutor<P, G> {
    fn with_source_contract<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        self.source_contract_scope = true;
        let result = f(self);
        self.source_contract_scope = false;
        result
    }
    pub(crate) fn source_available(&self) -> bool {
        self.provider.supports_source_guard()
    }
    pub(crate) fn preflight_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<(), ExecutorError> {
        self.with_source_contract(|this| this.preflight(c, s))
    }
    pub(crate) fn submit_source(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        ticket: &DispatchTicket,
        gate: &mut dyn crate::core::source_execution::SourceStepGate,
    ) -> Result<StepReceipt, ExecutorError> {
        self.with_source_contract(|this| {
            this.submit_checked(c, s, ticket, &mut || {
                gate.validate_sources(c)
                    .map_err(|_| ExecutorError::NotApplied)?;
                if matches!(
                    s.action,
                    ActionKind::ConstrainDirectPath
                        | ActionKind::DisableNativeIdentity
                        | ActionKind::ObserveRevocation
                ) {
                    let proof = gate
                        .check(
                            c,
                            s,
                            crate::core::source_execution::SourceStepPhase::BeforeDispatch,
                        )
                        .map_err(|_| ExecutorError::NotApplied)?;
                    if !proof.satisfied() {
                        return Err(ExecutorError::NotApplied);
                    }
                }
                Ok(gate.now())
            })
        })
    }
    fn submit_checked(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        ticket: &DispatchTicket,
        before_write: &mut dyn FnMut() -> Result<u64, ExecutorError>,
    ) -> Result<StepReceipt, ExecutorError> {
        if ticket.step_id != s.id || ticket.attempt == 0 || ticket.idempotency_key.is_empty() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        self.preflight(c, s)?;
        let (t, g, u, db, p) = self.context(c, s, true, false)?;
        if self.configured(c, s, t, g, u, &p)? {
            return self.receipt(c, s, t, g, true);
        }
        self.checkpoints
            .validate_change_window(c, &t.id, self.provider.now())
            .map_err(|_| ExecutorError::NotApplied)?;
        if c.policy.schema_version == 1 && s.action == ActionKind::ConstrainDirectPath {
            let (_, recovery) = self.principals(c, t)?;
            let needed = positive_principals(c, t, &recovery);
            let evidence = self
                .provider
                .observe_connections(c, t)?
                .ok_or(ExecutorError::NotApplied)?;
            let (_, _, _, _, fresh_proxy) = self.context(c, s, true, false)?;
            if !self.fresh(
                t,
                &evidence.generation,
                evidence.observed_at,
                &evidence.evidence_refs,
            ) || !needed.is_subset(&evidence.proxy_allowed_principals)
                || self.configured(c, s, t, g, u, &fresh_proxy)?
            {
                return Err(ExecutorError::NotApplied);
            }
        }
        // This callback is invoked by source-capable providers AFTER their
        // own potentially slow native reads. Check time windows after source IO.
        let checkpoints = &self.checkpoints;
        let mut guard = || {
            let now = before_write().map_err(|_| ProviderError::NotApplied)?;
            checkpoints
                .validate_change_window(c, &t.id, now)
                .map_err(|_| ProviderError::NotApplied)?;
            if s.action == ActionKind::ConstrainDirectPath {
                checkpoints
                    .validate(c, &t.id, now)
                    .map_err(|_| ProviderError::NotApplied)?;
            }
            if s.action == ActionKind::PrepareNativeRoute
                && (!p.require_tls || !p.iam_authentication)
            {
                checkpoints
                    .validate_preparation(c, &t.id, &preparation_fingerprint(&db, &p), now)
                    .map_err(|_| ProviderError::NotApplied)?;
            }
            Ok(())
        };
        let v3 = c.policy.schema_version == 2;
        match s.action {
            ActionKind::PrepareNativeRoute => {
                if v3 {
                    self.provider.prepare_proxy_guarded(t, &p, &mut guard)?;
                } else {
                    guard()?;
                    self.provider.prepare_proxy(t, &p)?;
                }
            }
            ActionKind::ConfigureIdentity | ActionKind::DisableNativeIdentity => {
                let name = policy_name(t, g, u)?;
                let desired = desired_identity_policy(t, g, u)?;
                if s.action == ActionKind::ConfigureIdentity {
                    if v3 {
                        self.provider.put_inline_policy_guarded(
                            &u.identity.principal,
                            &name,
                            &desired,
                            &mut guard,
                        )?;
                    } else {
                        guard()?;
                        self.provider
                            .put_inline_policy(&u.identity.principal, &name, &desired)?;
                    }
                } else if v3 {
                    self.provider.delete_inline_policy_guarded(
                        &u.identity.principal,
                        &name,
                        &desired,
                        &mut guard,
                    )?;
                } else {
                    guard()?;
                    self.provider
                        .delete_inline_policy(&u.identity.principal, &name, &desired)?;
                }
            }
            ActionKind::ConstrainDirectPath => {
                let b = t.aws.as_ref().ok_or(ExecutorError::PreconditionsNotMet)?;
                let rules = self.provider.rules(t)?;
                let r = rules
                    .iter()
                    .find(|r| b.owned_direct_rules.iter().any(|a| a.rule_id == r.id))
                    .ok_or(ExecutorError::NotApplied)?;
                // Preserve the bounded owner/group/source/port predicate.
                if !b.owned_direct_rules.iter().any(|a| owned_rule(t, r, a)) {
                    return Err(ExecutorError::NotApplied);
                }
                if v3 {
                    self.provider.revoke_rule_guarded(t, r, &mut guard)?;
                } else {
                    guard()?;
                    self.provider.revoke_rule(t, r)?;
                }
            }
            _ => return Err(ExecutorError::Unavailable),
        }
        // The write response is never effect proof. Query performs current readback.
        Ok(StepReceipt {
            state: StepState::Submitted,
            effect: EffectState::Pending,
            native_operation_ref: Some(operation_ref(c, s)),
            evidence_refs: vec![],
        })
    }
    pub fn new(provider: P, execution_identity: String, checkpoints: G) -> Self {
        Self {
            provider,
            execution_identity,
            checkpoints,
            last_revocation: None,
            source_contract_scope: false,
        }
    }
    pub fn last_revocation_evidence(&self) -> Option<&RevocationEvidence> {
        self.last_revocation.as_ref()
    }
    pub fn revalidate_target(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<(), ExecutorError> {
        self.context(c, s, false, true).map(|_| ())
    }
    fn context<'a>(
        &mut self,
        c: &'a PreparedChange,
        s: &PlanStep,
        dispatch: bool,
        composite: bool,
    ) -> Result<(&'a Target, &'a Grant, &'a Subject, RdsInstance, RdsProxy), ExecutorError> {
        if c.verify().is_err()
            || !c.plan.steps.contains(s)
            || (!composite && !self.available(c, s))
            || self.provider.cancelled()
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if self.provider.execution_identity()? != self.execution_identity {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let t = c
            .policy
            .targets
            .iter()
            .find(|t| t.id == s.target_id)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let g = c
            .policy
            .grants
            .iter()
            .find(|g| g.id == s.grant_id && g.target == t.id && g.profile == s.profile_id)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let u = c
            .policy
            .subjects
            .iter()
            .find(|u| u.id == g.subject)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let b = t.aws.as_ref().ok_or(ExecutorError::PreconditionsNotMet)?;
        let profile = c
            .policy
            .protection_profiles
            .iter()
            .find(|p| p.id == g.profile)
            .ok_or(ExecutorError::PreconditionsNotMet)?;
        let (_, _, _, expected_profile) = engine_contract(t)?;
        let expected_contract = if t.engine.family == EngineFamily::MySql {
            "core-adapter-v3"
        } else {
            "core-adapter-v2"
        };
        if !crate::core::source_execution::execution_contract_matches(c, s, expected_contract)
            || (c.policy.schema_version == 2 && dispatch && !self.source_contract_scope)
            || profile.kind != expected_profile
            || t.placement.kind != PlacementKind::AwsRds
            || t.placement.region != "ap-northeast-1"
            || b.owned_direct_rules.len() > 1
            || !matches!(g.lifetime, GrantLifetime::Standing)
            || u.identity.provider != IdentityProvider::Aws
            || !db_user(&g.db_identity)
            || !t.managed_surface.db_identities.contains(&g.db_identity)
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        self.check_role(t, u)?;
        if self.provider.role_id(&b.proxy_role_arn)? != b.proxy_role_id
            || self
                .provider
                .inline_policy(&b.proxy_role_arn, &b.proxy_policy_name)?
                != Some(required_proxy_policy(c, t)?)
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let db = self.provider.instance(t)?;
        let proxy = self.provider.proxy(t)?;
        self.check_resources(t, &db, &proxy)?;
        if (dispatch || composite) && !proxy.available {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        if !composite {
            let field = match s.action {
                ActionKind::PrepareNativeRoute => ManagedField::AwsProxy,
                ActionKind::ConfigureIdentity
                | ActionKind::DisableNativeIdentity
                | ActionKind::ObserveRevocation => ManagedField::AwsIamBinding,
                ActionKind::ConstrainDirectPath => ManagedField::AwsSecurityGroupRule,
                _ => return Err(ExecutorError::Unavailable),
            };
            if !t.managed_surface.fields.contains(&field)
                || (g.admission == AdmissionIntent::Deny
                    && !matches!(
                        s.action,
                        ActionKind::DisableNativeIdentity | ActionKind::ObserveRevocation
                    ))
                || (g.admission == AdmissionIntent::Allow
                    && matches!(
                        s.action,
                        ActionKind::DisableNativeIdentity | ActionKind::ObserveRevocation
                    ))
            {
                return Err(ExecutorError::PreconditionsNotMet);
            }
        }
        if c.policy.schema_version == 2
            && dispatch
            && matches!(
                s.action,
                ActionKind::ConstrainDirectPath
                    | ActionKind::DisableNativeIdentity
                    | ActionKind::ObserveRevocation
            )
        {
            // Preserve current immutable application/recovery RoleId checks;
            // admitted source observations do not replace native incarnation reads.
            self.principals(c, t)?;
        }
        if dispatch && s.action != ActionKind::ObserveRevocation {
            self.checkpoints
                .validate_change_window(c, &t.id, self.provider.now())
                .map_err(|_| ExecutorError::PreconditionsNotMet)?;
            if s.action == ActionKind::PrepareNativeRoute
                && (!proxy.require_tls || !proxy.iam_authentication)
            {
                self.checkpoints
                    .validate_preparation(
                        c,
                        &t.id,
                        &preparation_fingerprint(&db, &proxy),
                        self.provider.now(),
                    )
                    .map_err(|_| ExecutorError::PreconditionsNotMet)?;
            }
            if s.action == ActionKind::ConstrainDirectPath {
                self.checkpoints
                    .validate(c, &t.id, self.provider.now())
                    .map_err(|_| ExecutorError::PreconditionsNotMet)?;
            }
        }
        Ok((t, g, u, db, proxy))
    }
    fn check_role(&mut self, t: &Target, u: &Subject) -> Result<(), ExecutorError> {
        role_name(&u.identity.principal)?;
        if !u
            .identity
            .principal
            .starts_with(&format!("arn:aws:iam::{}:role/", t.placement.account_id))
            || Some(self.provider.role_id(&u.identity.principal)?) != u.identity.immutable_id
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(())
    }
    fn check_resources(
        &self,
        t: &Target,
        d: &RdsInstance,
        p: &RdsProxy,
    ) -> Result<(), ExecutorError> {
        let b = t.aws.as_ref().ok_or(ExecutorError::PreconditionsNotMet)?;
        let (_, _, port, _) = engine_contract(t)?;
        if d.endpoint != b.db_endpoint
            || d.arn != t.resource.native_id
            || d.resource_id != b.db_resource_id
            || !d.resource_id.starts_with("db-")
            || d.version != t.engine.version
            || d.engine_family != t.engine.family
            || !d.available
            || !d.iam_authentication
            || d.port != port
            || d.security_group_ids != BTreeSet::from([b.db_security_group_id.clone()])
            || p.arn != b.proxy_arn
            || p.name != b.proxy_name
            || p.endpoint != b.proxy_endpoint
            || p.role_arn != b.proxy_role_arn
            || p.auth_entries != 0
            || p.engine_family != t.engine.family
            || p.security_group_ids != BTreeSet::from([b.proxy_security_group_id.clone()])
            || p.target_resource_ids != BTreeSet::from([d.resource_id.clone()])
            || Some(generation_fingerprint(
                &t.placement.account_id,
                &t.placement.region,
                &d.arn,
                &d.resource_id,
            )) != t.resource.generation_fingerprint
        {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok(())
    }
    fn principals(
        &mut self,
        c: &PreparedChange,
        t: &Target,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>), ExecutorError> {
        let mut all = BTreeSet::new();
        let mut recoveries = BTreeSet::new();
        for g in c.policy.grants.iter().filter(|g| g.target == t.id) {
            let u = c
                .policy
                .subjects
                .iter()
                .find(|u| u.id == g.subject)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            self.check_role(t, u)?;
            all.insert(u.identity.principal.clone());
            let p = c
                .policy
                .protection_profiles
                .iter()
                .find(|p| p.id == g.profile)
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            for e in p.management_exceptions.iter().filter(|e| e.recovery) {
                let r = c
                    .policy
                    .subjects
                    .iter()
                    .find(|r| r.id == e.subject)
                    .ok_or(ExecutorError::PreconditionsNotMet)?;
                if r.identity.principal == u.identity.principal
                    || r.identity.immutable_id == u.identity.immutable_id
                    || !matches!(e.lifetime, GrantLifetime::Standing)
                    || !p.allowed_routes.iter().any(|r| {
                        r.id == e.route_id && r.kind == crate::core::policy::RouteKind::NativeProxy
                    })
                {
                    return Err(ExecutorError::PreconditionsNotMet);
                }
                self.check_role(t, r)?;
                all.insert(r.identity.principal.clone());
                recoveries.insert(r.identity.principal.clone());
            }
        }
        if all.len() > 8 || recoveries.is_empty() {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        Ok((all, recoveries))
    }
    fn fresh(&self, t: &Target, generation: &str, at: u64, refs: &[String]) -> bool {
        t.resource.generation_fingerprint.as_deref() == Some(generation)
            && at <= self.provider.now()
            && self.provider.now().saturating_sub(at) <= 60
            && !refs.is_empty()
            && refs.iter().all(|r| crate::core::policy::valid_hash(r))
    }
    fn configured(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        t: &Target,
        g: &Grant,
        u: &Subject,
        p: &RdsProxy,
    ) -> Result<bool, ExecutorError> {
        let b = t.aws.as_ref().ok_or(ExecutorError::PreconditionsNotMet)?;
        match s.action {
            ActionKind::PrepareNativeRoute => {
                Ok(p.available && p.require_tls && p.iam_authentication)
            }
            ActionKind::ConfigureIdentity | ActionKind::DisableNativeIdentity => {
                let desired = desired_identity_policy(t, g, u)?;
                let current = self
                    .provider
                    .inline_policy(&u.identity.principal, &policy_name(t, g, u)?)?;
                if current.as_ref().is_some_and(|v| v != &desired) {
                    return Err(ExecutorError::PreconditionsNotMet);
                }
                Ok(if s.action == ActionKind::DisableNativeIdentity {
                    current.is_none()
                } else {
                    current == Some(desired)
                })
            }
            ActionKind::ConstrainDirectPath => {
                if !p.require_tls || !p.iam_authentication {
                    return Err(ExecutorError::PreconditionsNotMet);
                }
                let rules = self.provider.rules(t)?;
                let (_, _, port, _) = engine_contract(t)?;
                // Preserve the one existing exact proxy-to-DB ingress path.
                if !rules.iter().any(|r|r.group_id==b.db_security_group_id&&r.ingress&&matches!(r.protocol.as_str(),"tcp"|"6")&&r.from_port==i64::from(port)&&r.to_port==i64::from(port)&&matches!(&r.source,Some(AwsRuleSource::SecurityGroup{group_id,account_id}) if group_id==&b.proxy_security_group_id&&account_id==&t.placement.account_id)&&!b.owned_direct_rules.iter().any(|a|a.rule_id==r.id)){return Err(ExecutorError::PreconditionsNotMet)}
                for r in rules
                    .iter()
                    .filter(|r| b.owned_direct_rules.iter().any(|a| a.rule_id == r.id))
                {
                    if !b.owned_direct_rules.iter().any(|a| owned_rule(t, r, a)) {
                        return Err(ExecutorError::PreconditionsNotMet);
                    }
                }
                Ok(!rules
                    .iter()
                    .any(|r| b.owned_direct_rules.iter().any(|a| a.rule_id == r.id)))
            }
            ActionKind::ObserveRevocation => {
                let _ = c;
                Ok(true)
            }
            _ => Err(ExecutorError::Unavailable),
        }
    }
    fn receipt(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        t: &Target,
        g: &Grant,
        no_op: bool,
    ) -> Result<StepReceipt, ExecutorError> {
        if c.policy.schema_version == 2
            && matches!(
                s.action,
                ActionKind::ConstrainDirectPath | ActionKind::ObserveRevocation
            )
        {
            return Ok(StepReceipt {
                state: StepState::ConfigApplied,
                effect: EffectState::Unknown,
                native_operation_ref: Some(operation_ref(c, s)),
                evidence_refs: vec![],
            });
        }
        let mut refs = vec![];
        let satisfied = match s.action {
            ActionKind::ConstrainDirectPath => {
                let (needed, recovery) = self.principals(c, t)?;
                let positive = positive_principals(c, t, &recovery);
                let before_db = self.provider.instance(t)?;
                let before_proxy = self.provider.proxy(t)?;
                self.check_resources(t, &before_db, &before_proxy)?;
                let observation = self.provider.observe_connections(c, t)?;
                let unchanged = self.provider.instance(t)? == before_db
                    && self.provider.proxy(t)? == before_proxy;
                self.principals(c, t)?;
                let subject = c
                    .policy
                    .subjects
                    .iter()
                    .find(|u| u.id == g.subject)
                    .ok_or(ExecutorError::PreconditionsNotMet)?;
                let still_configured = self.configured(c, s, t, g, subject, &before_proxy)?;
                observation.is_some_and(|e| {
                    let ok = self.fresh(t, &e.generation, e.observed_at, &e.evidence_refs)
                        && unchanged
                        && still_configured
                        && positive.is_subset(&e.proxy_allowed_principals)
                        && needed.is_subset(&e.direct_denied_principals);
                    refs = e
                        .evidence_refs
                        .into_iter()
                        .filter(|r| crate::core::policy::valid_hash(r))
                        .collect();
                    ok
                })
            }
            ActionKind::ObserveRevocation => {
                let (_, recovery) = self.principals(c, t)?;
                let (needed, _) = self.principals(c, t)?;
                self.collect_revocation_evidence(c, s)?.is_some_and(|e| {
                    let ok = e.complete
                        && e.access == Access::Denied
                        && e.iam_connect_denied
                        && recovery.is_subset(&e.proxy_allowed_principals)
                        && needed.is_subset(&e.direct_denied_principals);
                    refs = e.evidence_refs;
                    ok
                })
            }
            _ => true,
        };
        let _ = g;
        Ok(StepReceipt {
            state: if satisfied {
                if no_op {
                    StepState::NoOpSatisfied
                } else {
                    StepState::EffectSatisfied
                }
            } else {
                StepState::ConfigApplied
            },
            effect: if satisfied {
                EffectState::Enforced
            } else {
                EffectState::Pending
            },
            native_operation_ref: Some(operation_ref(c, s)),
            evidence_refs: refs,
        })
    }
    pub fn collect_revocation_evidence(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
    ) -> Result<Option<RevocationEvidence>, ExecutorError> {
        self.last_revocation = None;
        if s.action != ActionKind::ObserveRevocation {
            return Err(ExecutorError::PreconditionsNotMet);
        }
        let (t, g, u, db, p) = self.context(c, s, false, false)?;
        self.principals(c, t)?;
        let Some(e) = self.provider.observe_revocation(c, t, g)? else {
            return Ok(None);
        };
        if !p.iam_authentication
            || !p.require_tls
            || e.denied_principal != u.identity.principal
            || !self.fresh(t, &e.generation, e.observed_at, &e.evidence_refs)
        {
            return Ok(None);
        }
        if self.provider.instance(t)? != db || self.provider.proxy(t)? != p {
            return Ok(None);
        }
        self.check_role(t, u)?;
        self.principals(c, t)?;
        self.last_revocation = Some(e.clone());
        Ok(Some(e))
    }
}
fn operation_ref(c: &PreparedChange, s: &PlanStep) -> String {
    format!(
        "aws-sync-{}",
        hash_bytes(
            &serde_json::to_vec(&(c.change_hash.as_str(), s.id.as_str()))
                .expect("tuple serializes")
        )
    )
}
impl<P: AwsProvider, G: CheckpointGate> StepExecutor for AwsExecutor<P, G> {
    fn lease_duration_seconds(&self) -> u64 {
        3600
    }
    fn identity(&self) -> &str {
        &self.execution_identity
    }
    fn cancelled(&self) -> bool {
        self.provider.cancelled()
    }
    fn available(&self, _: &PreparedChange, s: &PlanStep) -> bool {
        matches!(
            s.action,
            ActionKind::PrepareNativeRoute
                | ActionKind::ConfigureIdentity
                | ActionKind::ConstrainDirectPath
                | ActionKind::DisableNativeIdentity
                | ActionKind::ObserveRevocation
        )
    }
    fn preflight(&mut self, c: &PreparedChange, s: &PlanStep) -> Result<(), ExecutorError> {
        let (t, g, u, _, p) = self.context(c, s, true, false)?;
        let configured = self.configured(c, s, t, g, u, &p)?;
        if c.policy.schema_version == 1
            && s.action == ActionKind::ConstrainDirectPath
            && !configured
        {
            let (_, recovery) = self.principals(c, t)?;
            let needed = positive_principals(c, t, &recovery);
            let e = self
                .provider
                .observe_connections(c, t)?
                .ok_or(ExecutorError::PreconditionsNotMet)?;
            if !self.fresh(t, &e.generation, e.observed_at, &e.evidence_refs)
                || !needed.is_subset(&e.proxy_allowed_principals)
            {
                return Err(ExecutorError::PreconditionsNotMet);
            }
        }
        Ok(())
    }
    fn submit(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        ticket: &DispatchTicket,
    ) -> Result<StepReceipt, ExecutorError> {
        let now = self.provider.now();
        self.submit_checked(c, s, ticket, &mut || Ok(now))
    }
    fn query(
        &mut self,
        c: &PreparedChange,
        s: &PlanStep,
        r: &StepRecord,
    ) -> Result<StepReceipt, ExecutorError> {
        if r.step_id != s.id
            || r.receipt
                .as_ref()
                .and_then(|r| r.native_operation_ref.as_deref())
                != Some(operation_ref(c, s).as_str())
        {
            return Err(ExecutorError::OutcomeUnknown);
        }
        let (t, g, u, _, p) = self.context(c, s, false, false)?;
        if !self.configured(c, s, t, g, u, &p)? {
            return Ok(StepReceipt {
                state: StepState::Submitted,
                effect: EffectState::Pending,
                native_operation_ref: Some(operation_ref(c, s)),
                evidence_refs: vec![],
            });
        }
        self.receipt(c, s, t, g, false)
    }
}

/// Trusted observer composition. The default production backend has no current
/// connection evidence and therefore cannot certify protected-route effects.
pub trait AwsObserver {
    fn connections(
        &mut self,
        c: &PreparedChange,
        t: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError>;
    fn revocation(
        &mut self,
        _: &PreparedChange,
        _: &Target,
        _: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        Ok(None)
    }
}
pub struct AwsCliProvider {
    executable: PathBuf,
    profile: String,
    account: String,
    role_arn: String,
    role_id: String,
    cancel: CancellationToken,
    observer: Option<Box<dyn AwsObserver>>,
    credentials: Option<FrozenCredentials>,
}
// Intentionally no Debug/Serialize implementation. Values never enter logs,
// operation receipts, argv, artifacts, or on-disk credential files.
struct FrozenCredentials {
    access_key: String,
    secret_key: String,
    session_token: String,
}
impl AwsCliProvider {
    pub fn new(
        executable: PathBuf,
        profile: String,
        account: String,
        role_arn: String,
        role_id: String,
        cancel: CancellationToken,
    ) -> Result<Self, ProviderError> {
        if !executable.is_absolute()
            || !token(&profile)
            || account.len() != 12
            || !account.bytes().all(|b| b.is_ascii_digit())
            || !role_arn.starts_with(&format!("arn:aws:iam::{account}:role/"))
            || role_name(&role_arn).is_err()
            || !crate::core::policy::aws_role_id(&role_id)
        {
            return Err(ProviderError::Precondition);
        }
        let executable = executable
            .canonicalize()
            .map_err(|_| ProviderError::Precondition)?;
        let metadata = executable
            .metadata()
            .map_err(|_| ProviderError::Precondition)?;
        if !metadata.is_file() {
            return Err(ProviderError::Precondition);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(ProviderError::Precondition);
            }
        }
        Ok(Self {
            executable,
            profile,
            account,
            role_arn,
            role_id,
            cancel,
            observer: None,
            credentials: None,
        })
    }
    pub fn with_observer(mut self, observer: Box<dyn AwsObserver>) -> Self {
        self.observer = Some(observer);
        self
    }
    fn call(
        &self,
        service: &str,
        operation: &str,
        args: Vec<String>,
        mutation: bool,
    ) -> Result<Value, ProviderError> {
        let credentials = self
            .credentials
            .as_ref()
            .ok_or(ProviderError::Precondition)?;
        let mut all = vec![
            service.into(),
            operation.into(),
            "--region".into(),
            "ap-northeast-1".into(),
            "--output".into(),
            "json".into(),
            "--no-cli-pager".into(),
            "--cli-connect-timeout".into(),
            "5".into(),
            "--cli-read-timeout".into(),
            "20".into(),
        ];
        all.extend(args);
        let bytes =
            run_process(&self.executable, &all, &self.cancel, Some(credentials)).map_err(|_| {
                if mutation {
                    ProviderError::Unknown
                } else {
                    ProviderError::Unavailable
                }
            })?;
        if bytes.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            if mutation {
                ProviderError::Unknown
            } else {
                ProviderError::Unavailable
            }
        })
    }
    fn put_inline_policy_checked(
        &mut self,
        arn: &str,
        name: &str,
        desired: &Value,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        if self.inline_policy(arn, name)?.is_some() {
            return Err(ProviderError::Precondition);
        }
        guard()?;
        self.call(
            "iam",
            "put-role-policy",
            vec![
                "--role-name".into(),
                self.checked_role(arn)?,
                "--policy-name".into(),
                name.into(),
                "--policy-document".into(),
                desired.to_string(),
            ],
            true,
        )?;
        Ok(())
    }
    fn delete_inline_policy_checked(
        &mut self,
        arn: &str,
        name: &str,
        expected: &Value,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        if self.inline_policy(arn, name)?.as_ref() != Some(expected) {
            return Err(ProviderError::Precondition);
        }
        guard()?;
        self.call(
            "iam",
            "delete-role-policy",
            vec![
                "--role-name".into(),
                self.checked_role(arn)?,
                "--policy-name".into(),
                name.into(),
            ],
            true,
        )?;
        Ok(())
    }
    fn prepare_proxy_checked(
        &mut self,
        t: &Target,
        before: &RdsProxy,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        if &self.proxy(t)? != before {
            return Err(ProviderError::Precondition);
        }
        guard()?;
        self.call(
            "rds",
            "modify-db-proxy",
            vec![
                "--db-proxy-name".into(),
                before.name.clone(),
                "--default-auth-scheme".into(),
                "IAM_AUTH".into(),
                "--require-tls".into(),
            ],
            true,
        )?;
        Ok(())
    }
    fn revoke_rule_checked(
        &mut self,
        t: &Target,
        rule: &SecurityGroupRule,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        let b = t.aws.as_ref().ok_or(ProviderError::Precondition)?;
        if b.owned_direct_rules.len() != 1
            || !b.owned_direct_rules.iter().any(|a| a.rule_id == rule.id)
            || rule.group_id != b.db_security_group_id
            || !rule.ingress
            || matches!(&rule.source,Some(AwsRuleSource::SecurityGroup{group_id,account_id}) if group_id==&b.proxy_security_group_id&&account_id==&t.placement.account_id)
            || !b.owned_direct_rules.iter().any(|a| owned_rule(t, rule, a))
            || !self.rules(t)?.contains(rule)
        {
            return Err(ProviderError::Precondition);
        }
        guard()?;
        self.call(
            "ec2",
            "revoke-security-group-ingress",
            vec![
                "--group-id".into(),
                rule.group_id.clone(),
                "--security-group-rule-ids".into(),
                rule.id.clone(),
            ],
            true,
        )?;
        Ok(())
    }
    fn check_target(&self, t: &Target) -> Result<(), ProviderError> {
        engine_contract(t)?;
        if t.placement.kind != PlacementKind::AwsRds
            || t.placement.account_id != self.account
            || t.placement.region != "ap-northeast-1"
        {
            return Err(ProviderError::Precondition);
        }
        Ok(())
    }
    fn checked_role(&self, arn: &str) -> Result<String, ProviderError> {
        if !arn.starts_with(&format!("arn:aws:iam::{}:role/", self.account)) {
            return Err(ProviderError::Precondition);
        }
        Ok(role_name(arn)?.into())
    }
}
fn string(v: &Value, p: &str) -> Result<String, ProviderError> {
    v.pointer(p)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or(ProviderError::Unavailable)
}
fn policy_document(v: &Value) -> Result<Value, ProviderError> {
    if v.is_object() {
        return Ok(v.clone());
    }
    let text = v.as_str().ok_or(ProviderError::Unavailable)?;
    if let Ok(value) = serde_json::from_str::<Value>(text)
        && value.is_object()
    {
        return Ok(value);
    }
    // RFC3986 percent decoding exactly once; '+' remains a literal plus.
    let input = text.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            let h = input
                .get(i + 1)
                .and_then(|v| (*v as char).to_digit(16))
                .ok_or(ProviderError::Unavailable)?;
            let l = input
                .get(i + 2)
                .and_then(|v| (*v as char).to_digit(16))
                .ok_or(ProviderError::Unavailable)?;
            decoded.push((h * 16 + l) as u8);
            i += 3;
        } else {
            decoded.push(input[i]);
            i += 1;
        }
    }
    let value: Value = serde_json::from_slice(&decoded).map_err(|_| ProviderError::Unavailable)?;
    if !value.is_object() {
        return Err(ProviderError::Unavailable);
    }
    Ok(value)
}
fn strings(v: &Value, p: &str, key: Option<&str>) -> Result<BTreeSet<String>, ProviderError> {
    v.pointer(p)
        .and_then(Value::as_array)
        .ok_or(ProviderError::Unavailable)?
        .iter()
        .map(|v| {
            if let Some(k) = key {
                string(v, k)
            } else {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or(ProviderError::Unavailable)
            }
        })
        .collect()
}
impl AwsProvider for AwsCliProvider {
    fn supports_source_guard(&self) -> bool {
        true
    }
    fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
    fn execution_identity(&mut self) -> Result<String, ProviderError> {
        self.credentials = None;
        let args = vec![
            "configure".into(),
            "export-credentials".into(),
            "--profile".into(),
            self.profile.clone(),
            "--format".into(),
            "process".into(),
        ];
        let bytes = run_process(&self.executable, &args, &self.cancel, None)?;
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| ProviderError::Unavailable)?;
        let credentials = FrozenCredentials {
            access_key: string(&v, "/AccessKeyId")?,
            secret_key: string(&v, "/SecretAccessKey")?,
            session_token: string(&v, "/SessionToken")?,
        };
        if [
            credentials.access_key.as_str(),
            credentials.secret_key.as_str(),
            credentials.session_token.as_str(),
        ]
        .iter()
        .any(|v| v.len() > 16384 || v.chars().any(char::is_control))
        {
            return Err(ProviderError::Precondition);
        }
        self.credentials = Some(credentials);
        let v = self.call("sts", "get-caller-identity", vec![], false)?;
        let arn = string(&v, "/Arn")?;
        let user = string(&v, "/UserId")?;
        let name = role_name(&self.role_arn)?;
        if string(&v, "/Account")? != self.account
            || !arn.starts_with(&format!(
                "arn:aws:sts::{}:assumed-role/{name}/",
                self.account
            ))
            || user
                != format!(
                    "{}:{}",
                    self.role_id,
                    arn.rsplit('/').next().unwrap_or_default()
                )
        {
            self.credentials = None;
            return Err(ProviderError::Precondition);
        }
        Ok(format!("aws-role:{}:{}", self.role_arn, self.role_id))
    }
    fn role_id(&mut self, arn: &str) -> Result<String, ProviderError> {
        let name = self.checked_role(arn)?;
        let v = self.call("iam", "get-role", vec!["--role-name".into(), name], false)?;
        if string(&v, "/Role/Arn")? != arn {
            return Err(ProviderError::Precondition);
        }
        string(&v, "/Role/RoleId")
    }
    fn instance(&mut self, t: &Target) -> Result<RdsInstance, ProviderError> {
        self.check_target(t)?;
        let v = self.call(
            "rds",
            "describe-db-instances",
            vec![
                "--db-instance-identifier".into(),
                t.resource.native_id.clone(),
            ],
            false,
        )?;
        let a = v
            .get("DBInstances")
            .and_then(Value::as_array)
            .filter(|a| a.len() == 1)
            .ok_or(ProviderError::Unavailable)?;
        let d = &a[0];
        let engine_family = native_engine(&string(d, "/Engine")?)?;
        if engine_family != t.engine.family {
            return Err(ProviderError::Precondition);
        }
        Ok(RdsInstance {
            arn: string(d, "/DBInstanceArn")?,
            resource_id: string(d, "/DbiResourceId")?,
            endpoint: string(d, "/Endpoint/Address")?,
            version: string(d, "/EngineVersion")?,
            engine_family,
            available: string(d, "/DBInstanceStatus")? == "available",
            iam_authentication: d
                .get("IAMDatabaseAuthenticationEnabled")
                .and_then(Value::as_bool)
                == Some(true),
            security_group_ids: strings(d, "/VpcSecurityGroups", Some("/VpcSecurityGroupId"))?,
            port: d
                .pointer("/Endpoint/Port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .ok_or(ProviderError::Unavailable)?,
        })
    }
    fn proxy(&mut self, t: &Target) -> Result<RdsProxy, ProviderError> {
        self.check_target(t)?;
        let b = t.aws.as_ref().ok_or(ProviderError::Precondition)?;
        let (_, expected_engine, port, _) = engine_contract(t)?;
        let v = self.call(
            "rds",
            "describe-db-proxies",
            vec!["--db-proxy-name".into(), b.proxy_name.clone()],
            false,
        )?;
        let a = v
            .get("DBProxies")
            .and_then(Value::as_array)
            .filter(|a| a.len() == 1)
            .ok_or(ProviderError::Unavailable)?;
        let p = &a[0];
        let engine_family = proxy_engine(&string(p, "/EngineFamily")?)?;
        if string(p, "/EngineFamily")? != expected_engine {
            return Err(ProviderError::Precondition);
        }
        let targets = self.call(
            "rds",
            "describe-db-proxy-targets",
            vec!["--db-proxy-name".into(), b.proxy_name.clone()],
            false,
        )?;
        // Bind the proxy target to the exact currently registered DB. Target
        // health is observed separately: IAM registration can legitimately
        // follow proxy configuration in the durable plan.
        let a = targets
            .get("Targets")
            .and_then(Value::as_array)
            .filter(|a| a.len() == 1)
            .ok_or(ProviderError::Precondition)?;
        if string(&a[0], "/TargetArn")? != t.resource.native_id
            || string(&a[0], "/RdsResourceId")?
                != t.resource
                    .native_id
                    .rsplit(':')
                    .next()
                    .ok_or(ProviderError::Precondition)?
            || string(&a[0], "/Type")? != "RDS_INSTANCE"
            || string(&a[0], "/Endpoint")? != b.db_endpoint
            || a[0].get("Port").and_then(Value::as_u64) != Some(u64::from(port))
            || a[0]
                .get("TrackedClusterId")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
        {
            return Err(ProviderError::Precondition);
        }
        Ok(RdsProxy {
            arn: string(p, "/DBProxyArn")?,
            name: string(p, "/DBProxyName")?,
            endpoint: string(p, "/Endpoint")?,
            role_arn: string(p, "/RoleArn")?,
            available: string(p, "/Status")? == "available",
            engine_family,
            require_tls: p.get("RequireTLS").and_then(Value::as_bool) == Some(true),
            iam_authentication: p.get("DefaultAuthScheme").and_then(Value::as_str)
                == Some("IAM_AUTH"),
            auth_entries: match p.get("Auth") {
                None => 0,
                Some(v) => v.as_array().ok_or(ProviderError::Unavailable)?.len(),
            },
            security_group_ids: strings(p, "/VpcSecurityGroupIds", None)?,
            target_resource_ids: BTreeSet::from([b.db_resource_id.clone()]),
        })
    }
    fn inline_policy(&mut self, arn: &str, name: &str) -> Result<Option<Value>, ProviderError> {
        if !token(name) {
            return Err(ProviderError::Precondition);
        }
        let role = self.checked_role(arn)?;
        let policies = self.call(
            "iam",
            "list-role-policies",
            vec!["--role-name".into(), role.clone()],
            false,
        )?;
        if !strings(&policies, "/PolicyNames", None)?.contains(name) {
            return Ok(None);
        }
        let v = self.call(
            "iam",
            "get-role-policy",
            vec![
                "--role-name".into(),
                role,
                "--policy-name".into(),
                name.into(),
            ],
            false,
        )?;
        Ok(Some(policy_document(
            v.get("PolicyDocument").ok_or(ProviderError::Unavailable)?,
        )?))
    }
    fn put_inline_policy(
        &mut self,
        arn: &str,
        name: &str,
        desired: &Value,
    ) -> Result<(), ProviderError> {
        self.put_inline_policy_checked(arn, name, desired, &mut || Ok(()))
    }
    fn put_inline_policy_guarded(
        &mut self,
        arn: &str,
        name: &str,
        desired: &Value,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        self.put_inline_policy_checked(arn, name, desired, guard)
    }
    fn delete_inline_policy(
        &mut self,
        arn: &str,
        name: &str,
        expected: &Value,
    ) -> Result<(), ProviderError> {
        self.delete_inline_policy_checked(arn, name, expected, &mut || Ok(()))
    }
    fn delete_inline_policy_guarded(
        &mut self,
        arn: &str,
        name: &str,
        expected: &Value,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        self.delete_inline_policy_checked(arn, name, expected, guard)
    }
    fn prepare_proxy(&mut self, t: &Target, before: &RdsProxy) -> Result<(), ProviderError> {
        self.prepare_proxy_checked(t, before, &mut || Ok(()))
    }
    fn prepare_proxy_guarded(
        &mut self,
        t: &Target,
        before: &RdsProxy,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        self.prepare_proxy_checked(t, before, guard)
    }
    fn rules(&mut self, t: &Target) -> Result<Vec<SecurityGroupRule>, ProviderError> {
        self.check_target(t)?;
        let b = t.aws.as_ref().ok_or(ProviderError::Precondition)?;
        let v = self.call(
            "ec2",
            "describe-security-group-rules",
            vec![
                "--filters".into(),
                format!("Name=group-id,Values={}", b.db_security_group_id),
            ],
            false,
        )?;
        v.get("SecurityGroupRules")
            .and_then(Value::as_array)
            .ok_or(ProviderError::Unavailable)?
            .iter()
            .map(|r| {
                Ok(SecurityGroupRule {
                    id: string(r, "/SecurityGroupRuleId")?,
                    group_id: string(r, "/GroupId")?,
                    ingress: r.get("IsEgress").and_then(Value::as_bool) == Some(false),
                    protocol: string(r, "/IpProtocol")?,
                    from_port: r.get("FromPort").and_then(Value::as_i64).unwrap_or(-1),
                    to_port: r.get("ToPort").and_then(Value::as_i64).unwrap_or(-1),
                    source: rule_source(r)?,
                    owner_account: string(r, "/GroupOwnerId")?,
                    tags: rule_tags(r)?,
                })
            })
            .collect()
    }
    fn revoke_rule(&mut self, t: &Target, rule: &SecurityGroupRule) -> Result<(), ProviderError> {
        self.revoke_rule_checked(t, rule, &mut || Ok(()))
    }
    fn revoke_rule_guarded(
        &mut self,
        t: &Target,
        rule: &SecurityGroupRule,
        guard: &mut BeforeAwsWrite<'_>,
    ) -> Result<(), ProviderError> {
        self.revoke_rule_checked(t, rule, guard)
    }
    fn observe_connections(
        &mut self,
        c: &PreparedChange,
        t: &Target,
    ) -> Result<Option<ConnectionEvidence>, ProviderError> {
        match self.observer.as_mut() {
            Some(o) => o.connections(c, t),
            None => Ok(None),
        }
    }
    fn observe_revocation(
        &mut self,
        c: &PreparedChange,
        t: &Target,
        g: &Grant,
    ) -> Result<Option<RevocationEvidence>, ProviderError> {
        match self.observer.as_mut() {
            Some(o) => o.revocation(c, t, g),
            None => Ok(None),
        }
    }
}
async fn read_pipe<R: AsyncRead + Unpin>(pipe: R) -> Result<Vec<u8>, ProviderError> {
    let mut b = vec![];
    pipe.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut b)
        .await
        .map_err(|_| ProviderError::Unavailable)?;
    if b.len() > 2 * 1024 * 1024 {
        return Err(ProviderError::Unavailable);
    }
    Ok(b)
}
fn run_process(
    path: &Path,
    args: &[String],
    cancel: &CancellationToken,
    credentials: Option<&FrozenCredentials>,
) -> Result<Vec<u8>, ProviderError> {
    let path = path.to_owned();
    let args = args.to_vec();
    let cancel = cancel.clone();
    let credentials = credentials.map(|v| FrozenCredentials {
        access_key: v.access_key.clone(),
        secret_key: v.secret_key.clone(),
        session_token: v.session_token.clone(),
    });
    // Separate bounded runtime also works when invoked by a synchronous adapter
    // inside an existing Tokio runtime. No process output is ever displayed.
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        runtime.block_on(async {
            if cancel.is_cancelled() {
                return Err(ProviderError::Unavailable);
            }
            let mut command = tokio::process::Command::new(path);
            for key in [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
                "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE",
                "AWS_CONFIG_FILE",
                "AWS_SHARED_CREDENTIALS_FILE",
                "AWS_ROLE_ARN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_ENDPOINT_URL",
                "AWS_ENDPOINT_URL_RDS",
                "AWS_ENDPOINT_URL_IAM",
                "AWS_ENDPOINT_URL_EC2",
                "AWS_ENDPOINT_URL_STS",
                "AWS_CA_BUNDLE",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "https_proxy",
                "http_proxy",
                "all_proxy",
            ] {
                command.env_remove(key);
            }
            if let Some(c) = credentials {
                command
                    .env("AWS_ACCESS_KEY_ID", c.access_key)
                    .env("AWS_SECRET_ACCESS_KEY", c.secret_key)
                    .env("AWS_SESSION_TOKEN", c.session_token)
                    .env("AWS_CONFIG_FILE", "/dev/null")
                    .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null");
            }
            #[cfg(unix)]
            command.process_group(0);
            let mut child = command
                .args(args)
                .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "true")
                .env("AWS_PAGER", "")
                .env("AWS_CLI_AUTO_PROMPT", "off")
                .env("AWS_MAX_ATTEMPTS", "1")
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| ProviderError::Unavailable)?;
            let child_id = child.id();
            let out = child.stdout.take().ok_or(ProviderError::Unavailable)?;
            let err = child.stderr.take().ok_or(ProviderError::Unavailable)?;
            let work = async {
                let (status, out, _) = tokio::try_join!(
                    async { child.wait().await.map_err(|_| ProviderError::Unavailable) },
                    read_pipe(out),
                    read_pipe(err)
                )?;
                if !status.success() {
                    return Err(ProviderError::Unavailable);
                }
                Ok(out)
            };
            let result = tokio::select! {
                _ = cancel.cancelled() => Err(ProviderError::Unavailable),
                result = tokio::time::timeout(Duration::from_secs(30), work) =>
                    result.unwrap_or(Err(ProviderError::Unavailable)),
            };
            if result.is_err() {
                #[cfg(unix)]
                if let Some(pid) = child_id {
                    // This dedicated group contains only the CLI and its
                    // credential helper descendants; never the parent shell.
                    unsafe {
                        libc::kill(-(pid as i32), libc::SIGKILL);
                    }
                }
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
            }
            result
        })
    })
    .join()
    .map_err(|_| ProviderError::Unavailable)?
}
