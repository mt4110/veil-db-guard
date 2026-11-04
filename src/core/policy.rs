//! Secret-free desired policy. Parsing and hashing never contact a provider or DB.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const POLICY_SCHEMA_VERSION: u32 = 1;
pub const SOURCE_BOUND_POLICY_SCHEMA_VERSION: u32 = 2;
pub const MAX_POLICY_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("POLICY_INVALID: policy is invalid; input values are not echoed")]
    Invalid,
    #[error("POLICY_LIMIT_EXCEEDED: policy exceeds the local input limit")]
    LimitExceeded,
    #[error("POLICY_REFERENCE_INVALID: a reference is missing, duplicated, or conflicting")]
    ReferenceInvalid,
    #[error("POLICY_SCOPE_VIOLATION: requested access exceeds the declared managed surface")]
    ScopeViolation,
    #[error("POLICY_PROFILE_INVALID: policy does not meet the selected protection profile")]
    ProfileInvalid,
}

macro_rules! choice {
    ($name:ident {$($variant:ident),+ $(,)?}) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {$($variant),+}
    };
}
choice!(PlacementKind {
    GcpCloudSql,
    AwsRds,
    SelfManaged
});
choice!(EngineFamily {
    PostgreSql,
    MySql,
    MariaDb,
    SqlServer,
    Oracle,
    Sqlite
});
choice!(SubjectKind {
    Application,
    Operator,
    Batch
});
choice!(IdentityProvider {
    Gcp,
    Aws,
    Local,
    Federated
});
choice!(CredentialSourceKind {
    WorkloadIdentity,
    NativeSdk,
    ExternalSecret
});
choice!(GenerationAssurance {
    Confirmed,
    Unconfirmed
});
choice!(AdmissionIntent { Allow, Deny });
choice!(ProfileKind {
    GcpCloudSqlPostgresConnectorV1,
    AwsRdsPostgresProxyV1,
    AwsRdsMysqlProxyV1,
    NativePathV1
});
choice!(RouteKind {
    NativeConnector,
    NativeProxy,
    Direct
});
choice!(AuthenticationRequirement {
    NativeIam,
    NativeDatabase
});
choice!(EncryptionRequirement {
    VerifiedTls,
    VerifiedTlsWithAwsRdsProxyManagedBackendV1
});
impl EncryptionRequirement {
    pub fn backend_tls_trust(self) -> Option<super::evidence::BackendTlsTrustContract> {
        match self {
            Self::VerifiedTls => None,
            Self::VerifiedTlsWithAwsRdsProxyManagedBackendV1 => {
                Some(super::evidence::BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1)
            }
        }
    }
}
choice!(ExpiryMode {
    NativeEnforced,
    ControllerReconciled
});
choice!(SqlObjectKind {
    Database,
    Schema,
    Table,
    Routine
});
choice!(SqlAction {
    Read,
    Insert,
    Update,
    Delete,
    Execute,
    Usage,
    Connect
});
choice!(ManagedField {
    GcpIamBinding,
    GcpConnectorEnforcement,
    GcpDatabaseFlag,
    AwsIamBinding,
    AwsSecurityGroupRule,
    AwsProxy,
    DbLogin,
    DbRole,
    DbObjectPrivilege,
    ApplicationBinding
});
choice!(EffectKind {
    BindingApplied,
    NewConnectionsAllowed,
    NewConnectionsDenied,
    SessionsTerminated,
    SqlPrivilegesApplied,
    SqlPrivilegesRevoked,
    LeaseExpired
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevision {
    pub schema_version: u32,
    pub policy_id: String,
    pub revision: u64,
    #[serde(default)]
    pub parent_revision_hash: Option<String>,
    pub subjects: Vec<Subject>,
    pub targets: Vec<Target>,
    pub grants: Vec<Grant>,
    pub protection_profiles: Vec<ProtectionProfile>,
    /// Absent in v1 serialization: old policy/change/approval hashes stay exact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_bindings: Vec<super::source::SourceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<super::evidence::EvaluationPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub id: String,
    pub kind: SubjectKind,
    pub identity: ExternalIdentityRef,
    pub workload_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalIdentityRef {
    pub provider: IdentityProvider,
    pub principal: String,
    #[serde(default)]
    pub immutable_id: Option<String>,
    pub credential_source: CredentialSourceRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSourceRef {
    pub kind: CredentialSourceKind,
    pub reference: String,
    #[serde(default)]
    pub secret_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub registration_id: String,
    pub placement: PlacementRef,
    pub resource: ResourceIdentity,
    pub engine: EngineRef,
    pub managed_surface: ManagedSurface,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsRdsBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql: Option<MysqlTargetBinding>,
}

/// MySQL accounts are user@host, not a PostgreSQL cluster role. These exact
/// host selectors are part of the approved account identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MysqlTargetBinding {
    pub account_host: String,
    pub management_account_host: String,
}

pub fn mysql_account_host(value: &str) -> bool {
    value == "%"
        || (!value.is_empty()
            && value.len() <= 255
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:-".contains(&b)))
}

pub fn mysql_db_user(value: &str) -> bool {
    aws_db_user(value)
        && value.len() <= 32
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "root" | "mysql" | "admin"
        )
}

pub fn mysql_database(value: &str) -> bool {
    aws_db_user(value)
        && value.len() <= 64
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "mysql" | "information_schema" | "performance_schema" | "sys"
        )
}

/// Approved native references for the initial existing-RDS/Proxy profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsRdsBinding {
    pub db_resource_id: String,
    pub db_endpoint: String,
    pub proxy_name: String,
    pub proxy_arn: String,
    pub proxy_endpoint: String,
    pub proxy_role_arn: String,
    pub proxy_role_id: String,
    pub proxy_policy_name: String,
    pub proxy_security_group_id: String,
    pub db_security_group_id: String,
    pub managed_policy_name: String,
    pub management_db_identity: String,
    pub owned_direct_rules: Vec<AwsSecurityGroupRuleBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSecurityGroupRuleBinding {
    pub rule_id: String,
    pub protocol: String,
    pub from_port: i32,
    pub to_port: i32,
    pub source: AwsRuleSource,
    pub ownership_tag_key: String,
    pub ownership_tag_value: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AwsRuleSource {
    CidrV4 {
        cidr: String,
    },
    CidrV6 {
        cidr: String,
    },
    SecurityGroup {
        group_id: String,
        account_id: String,
    },
}
/// Hash the declared immutable DB resource reference. This computes an
/// expected binding, never authenticates a resource or upgrades its assurance.
pub fn aws_generation_fingerprint(
    account: &str,
    region: &str,
    db_arn: &str,
    db_resource_id: &str,
) -> String {
    super::hash_bytes(
        &serde_json::to_vec(&(
            "aws-rds-proxy-generation-v1",
            account,
            region,
            db_arn,
            db_resource_id,
        ))
        .expect("native identity tuple serializes"),
    )
}
pub fn aws_role_arn(value: &str, account: &str) -> bool {
    value
        .strip_prefix(&format!("arn:aws:iam::{account}:role/"))
        .is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 256
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-/".contains(&b))
                && !s.contains("..")
        })
}
pub fn aws_db_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && value.as_bytes()[0].is_ascii_alphabetic()
        && !value.to_ascii_lowercase().starts_with("rds_")
        && !value.to_ascii_lowercase().starts_with("pg_")
}
pub fn aws_role_id(value: &str) -> bool {
    value.starts_with("AROA")
        && value.len() == 21
        && value.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn aws_component(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn aws_host(value: &str, region: &str) -> bool {
    value.len() <= 253
        && value.ends_with(&format!(".{region}.rds.amazonaws.com"))
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.".contains(&b))
        && !value.contains("..")
}
fn validate_aws(target: &Target, b: &AwsRdsBinding) -> bool {
    let account = &target.placement.account_id;
    let region = &target.placement.region;
    target.placement.kind == PlacementKind::AwsRds
        && target
            .resource
            .native_id
            .strip_prefix(&format!("arn:aws:rds:{region}:{account}:db:"))
            .is_some_and(|v| {
                !v.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            })
        && aws_component(&b.db_resource_id, "db-")
        && aws_host(&b.db_endpoint, region)
        && aws_host(&b.proxy_endpoint, region)
        && b.db_endpoint != b.proxy_endpoint
        && valid_id(&b.proxy_name)
        && b.proxy_arn
            .strip_prefix(&format!("arn:aws:rds:{region}:{account}:db-proxy:"))
            .is_some_and(|v| aws_component(v, "prx-"))
        && aws_role_arn(&b.proxy_role_arn, account)
        && aws_role_id(&b.proxy_role_id)
        && aws_component(&b.proxy_security_group_id, "sg-")
        && aws_component(&b.db_security_group_id, "sg-")
        && b.proxy_security_group_id != b.db_security_group_id
        && valid_id(&b.managed_policy_name)
        && b.managed_policy_name.len() <= 100
        && valid_id(&b.proxy_policy_name)
        && aws_db_user(&b.management_db_identity)
        && b.owned_direct_rules.len() <= 1
        && b.owned_direct_rules.iter().all(|r| {
            aws_component(&r.rule_id, "sgr-")
                && matches!(r.protocol.as_str(), "tcp" | "6")
                && r.from_port == native_db_port(target.engine.family).unwrap_or(0) as i32
                && r.to_port == native_db_port(target.engine.family).unwrap_or(0) as i32
                && valid_id(&r.ownership_tag_key)
                && native_ref(&r.ownership_tag_value)
                && match &r.source {
                    AwsRuleSource::CidrV4 { cidr } => cidr
                        .parse::<ipnet::Ipv4Net>()
                        .is_ok_and(|v| v.trunc().to_string() == *cidr),
                    AwsRuleSource::CidrV6 { cidr } => cidr
                        .parse::<ipnet::Ipv6Net>()
                        .is_ok_and(|v| v.trunc().to_string() == *cidr),
                    AwsRuleSource::SecurityGroup {
                        group_id,
                        account_id,
                    } => {
                        aws_component(group_id, "sg-")
                            && account_id == account
                            && group_id != &b.proxy_security_group_id
                    }
                }
        })
}

/// Ports for the currently implemented native bindings, not arbitrary engines.
pub fn native_db_port(engine: EngineFamily) -> Option<u16> {
    match engine {
        EngineFamily::PostgreSql => Some(5432),
        EngineFamily::MySql => Some(3306),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlacementRef {
    pub kind: PlacementKind,
    pub account_id: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceIdentity {
    pub native_id: String,
    #[serde(default)]
    pub generation_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRef {
    pub family: EngineFamily,
    pub version: String,
    pub database: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetHandle {
    pub registration_id: String,
    pub native_ref: ResourceIdentity,
    pub placement: PlacementRef,
    pub engine_binding: EngineRef,
    pub generation_assurance: GenerationAssurance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSurface {
    pub fields: Vec<ManagedField>,
    pub db_identities: Vec<String>,
    pub sql_scopes: Vec<SqlScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlScope {
    pub database: String,
    pub kind: SqlObjectKind,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub object: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub subject: String,
    pub target: String,
    pub db_identity: String,
    pub admission: AdmissionIntent,
    pub sql_access: SqlAccessIntent,
    pub profile: String,
    pub lifetime: GrantLifetime,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlAccessIntent {
    #[serde(default)]
    pub existing_roles: Vec<String>,
    #[serde(default)]
    pub privileges: Vec<SqlPrivilege>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlPrivilege {
    pub scope: SqlScope,
    pub actions: Vec<SqlAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantLifetime {
    Standing,
    Lease {
        expires_at_unix: u64,
        expiry_mode: ExpiryMode,
        #[serde(default)]
        reconciler_ref: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectPathPolicy {
    Deny,
    ExplicitException { exception_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionProfile {
    pub id: String,
    pub kind: ProfileKind,
    pub allowed_routes: Vec<Route>,
    pub application_direct_path: DirectPathPolicy,
    pub authentication: AuthenticationRequirement,
    pub encryption: EncryptionRequirement,
    pub management_exceptions: Vec<ManagementException>,
    pub required_effects: Vec<EffectKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    pub kind: RouteKind,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementException {
    pub id: String,
    pub subject: String,
    pub source_ids: Vec<String>,
    pub route_id: String,
    pub reason_code: String,
    pub lifetime: GrantLifetime,
    pub recovery: bool,
}

/// Logical IDs are Veil-owned. Native identifiers retain case and Unicode for adapters.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
        && !value.contains("..")
}

pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn native_ref(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !value.chars().any(char::is_control)
        && !value.contains("${")
        && !value.contains("{{")
        && !value.contains("://")
        && !["password=", "pwd=", "token=", "secret="]
            .iter()
            .any(|part| lower.contains(part))
}

fn unique<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn valid_refs(values: &[String], max: usize, allow_empty: bool) -> bool {
    (allow_empty || !values.is_empty())
        && values.len() <= max
        && values.iter().all(|value| valid_id(value))
        && unique(values)
}

fn valid_native_refs(values: &[String], max: usize) -> bool {
    values.len() <= max && values.iter().all(|value| native_ref(value)) && unique(values)
}

pub(crate) fn valid_scope(scope: &SqlScope) -> bool {
    native_ref(&scope.database)
        && scope.schema.as_ref().is_none_or(|v| native_ref(v))
        && scope.object.as_ref().is_none_or(|v| native_ref(v))
        && match scope.kind {
            SqlObjectKind::Database => scope.schema.is_none() && scope.object.is_none(),
            SqlObjectKind::Schema => scope.schema.is_some() && scope.object.is_none(),
            SqlObjectKind::Table | SqlObjectKind::Routine => {
                scope.schema.is_some() && scope.object.is_some()
            }
        }
}

fn scope_contains(managed: &SqlScope, requested: &SqlScope) -> bool {
    managed.database == requested.database
        && match managed.kind {
            SqlObjectKind::Database => true,
            SqlObjectKind::Schema => managed.schema == requested.schema,
            SqlObjectKind::Table | SqlObjectKind::Routine => managed == requested,
        }
}

fn valid_lifetime(lifetime: &GrantLifetime) -> bool {
    match lifetime {
        GrantLifetime::Standing => true,
        GrantLifetime::Lease {
            expires_at_unix,
            expiry_mode,
            reconciler_ref,
        } => {
            *expires_at_unix > 0
                && *expires_at_unix <= 253_402_300_799
                && match expiry_mode {
                    ExpiryMode::NativeEnforced => reconciler_ref.is_none(),
                    ExpiryMode::ControllerReconciled => {
                        reconciler_ref.as_ref().is_some_and(|v| valid_id(v))
                    }
                }
        }
    }
}

fn valid_resource_binding(target: &Target) -> bool {
    match target.placement.kind {
        PlacementKind::GcpCloudSql => {
            let prefix = format!("projects/{}/instances/", target.placement.account_id);
            target
                .resource
                .native_id
                .strip_prefix(&prefix)
                .is_some_and(|id| valid_id(id) && !id.contains(':'))
        }
        PlacementKind::AwsRds => {
            let parts: Vec<_> = target.resource.native_id.splitn(6, ':').collect();
            parts.len() == 6
                && parts[0] == "arn"
                && matches!(parts[1], "aws" | "aws-cn" | "aws-us-gov")
                && parts[2] == "rds"
                && parts[3] == target.placement.region
                && parts[4] == target.placement.account_id
                && parts[5]
                    .strip_prefix("db:")
                    .is_some_and(|id| valid_id(id) && !id.contains(':'))
        }
        PlacementKind::SelfManaged => true,
    }
}

impl PolicyRevision {
    pub fn validate(&self) -> Result<(), PolicyError> {
        use PolicyError::*;
        if !matches!(
            self.schema_version,
            POLICY_SCHEMA_VERSION | SOURCE_BOUND_POLICY_SCHEMA_VERSION
        ) || !valid_id(&self.policy_id)
            || self.revision == 0
            || (self.revision == 1 && self.parent_revision_hash.is_some())
            || (self.revision > 1 && self.parent_revision_hash.is_none())
            || self
                .parent_revision_hash
                .as_ref()
                .is_some_and(|v| !valid_hash(v))
        {
            return Err(Invalid);
        }
        super::source::validate_policy_sources(self)?;
        if self.subjects.is_empty()
            || self.subjects.len() > 128
            || self.targets.is_empty()
            || self.targets.len() > 64
            || self.grants.is_empty()
            || self.grants.len() > 256
            || self.protection_profiles.is_empty()
            || self.protection_profiles.len() > 64
        {
            return Err(LimitExceeded);
        }
        if !unique(self.subjects.iter().map(|v| &v.id))
            || !unique(self.targets.iter().map(|v| &v.id))
            || !unique(self.targets.iter().map(|v| &v.registration_id))
            || !unique(self.targets.iter().map(|v| {
                (
                    v.placement.kind,
                    &v.placement.account_id,
                    &v.placement.region,
                    &v.resource.native_id,
                )
            }))
            || !unique(self.grants.iter().map(|v| &v.id))
            || !unique(self.protection_profiles.iter().map(|v| &v.id))
        {
            return Err(ReferenceInvalid);
        }
        for subject in &self.subjects {
            let identity = &subject.identity;
            if !valid_id(&subject.id)
                || !valid_refs(&subject.workload_sources, 32, false)
                || !native_ref(&identity.principal)
                || identity
                    .immutable_id
                    .as_ref()
                    .is_some_and(|v| !native_ref(v))
                || !valid_id(&identity.credential_source.reference)
                || identity
                    .credential_source
                    .secret_version
                    .as_ref()
                    .is_some_and(|v| !valid_id(v))
                || (identity.credential_source.kind == CredentialSourceKind::ExternalSecret
                    && identity.credential_source.secret_version.is_none())
                || (identity.credential_source.kind != CredentialSourceKind::ExternalSecret
                    && identity.credential_source.secret_version.is_some())
            {
                return Err(Invalid);
            }
        }
        for target in &self.targets {
            let managed = &target.managed_surface;
            if !valid_id(&target.id)
                || !valid_id(&target.registration_id)
                || !native_ref(&target.placement.account_id)
                || !valid_id(&target.placement.region)
                || !native_ref(&target.resource.native_id)
                || !valid_resource_binding(target)
                || target
                    .resource
                    .generation_fingerprint
                    .as_ref()
                    .is_some_and(|v| !valid_hash(v))
                || !native_ref(&target.engine.version)
                || !native_ref(&target.engine.database)
                || managed.fields.len() > 32
                || !unique(&managed.fields)
                || !valid_native_refs(&managed.db_identities, 128)
                || managed.sql_scopes.len() > 256
                || !unique(&managed.sql_scopes)
                || managed
                    .sql_scopes
                    .iter()
                    .any(|v| !valid_scope(v) || v.database != target.engine.database)
            {
                return Err(Invalid);
            }
            if target
                .aws
                .as_ref()
                .is_some_and(|binding| !validate_aws(target, binding))
            {
                return Err(Invalid);
            }
            if let Some(binding) = &target.mysql
                && (target.engine.family != EngineFamily::MySql
                    || !mysql_account_host(&binding.account_host)
                    || !mysql_account_host(&binding.management_account_host))
            {
                return Err(Invalid);
            }
            if target.placement.kind == PlacementKind::AwsRds
                && (target.placement.account_id.len() != 12
                    || !target
                        .placement
                        .account_id
                        .bytes()
                        .all(|c| c.is_ascii_digit()))
            {
                return Err(Invalid);
            }
        }
        let known_sources: BTreeSet<_> = self
            .subjects
            .iter()
            .flat_map(|s| &s.workload_sources)
            .collect();
        for profile in &self.protection_profiles {
            if !valid_id(&profile.id)
                || profile.allowed_routes.is_empty()
                || profile.allowed_routes.len() > 32
                || !unique(profile.allowed_routes.iter().map(|r| &r.id))
                || profile.management_exceptions.len() > 32
                || !unique(profile.management_exceptions.iter().map(|e| &e.id))
                || profile.required_effects.is_empty()
                || profile.required_effects.len() > 16
                || !unique(&profile.required_effects)
            {
                return Err(ProfileInvalid);
            }
            for route in &profile.allowed_routes {
                if !valid_id(&route.id)
                    || !valid_refs(&route.source_ids, 128, false)
                    || route.source_ids.iter().any(|s| !known_sources.contains(s))
                {
                    return Err(ReferenceInvalid);
                }
            }
            for exception in &profile.management_exceptions {
                let subject = self
                    .subjects
                    .iter()
                    .find(|s| s.id == exception.subject)
                    .ok_or(ReferenceInvalid)?;
                let route = profile
                    .allowed_routes
                    .iter()
                    .find(|r| r.id == exception.route_id)
                    .ok_or(ReferenceInvalid)?;
                if !valid_id(&exception.id)
                    || !valid_id(&exception.reason_code)
                    || subject.kind == SubjectKind::Application
                    || !valid_refs(&exception.source_ids, 32, false)
                    || exception.source_ids.iter().any(|s| {
                        !subject.workload_sources.contains(s) || !route.source_ids.contains(s)
                    })
                    || !valid_lifetime(&exception.lifetime)
                {
                    return Err(ProfileInvalid);
                }
            }
            if let DirectPathPolicy::ExplicitException { exception_id } =
                &profile.application_direct_path
            {
                let exception = profile
                    .management_exceptions
                    .iter()
                    .find(|e| &e.id == exception_id)
                    .ok_or(ReferenceInvalid)?;
                if !profile
                    .allowed_routes
                    .iter()
                    .any(|r| r.id == exception.route_id && r.kind == RouteKind::Direct)
                {
                    return Err(ProfileInvalid);
                }
            }
            if profile.kind == ProfileKind::GcpCloudSqlPostgresConnectorV1
                && (profile.application_direct_path != DirectPathPolicy::Deny
                    || profile.authentication != AuthenticationRequirement::NativeIam
                    || profile
                        .allowed_routes
                        .iter()
                        .any(|r| r.kind != RouteKind::NativeConnector)
                    || !profile.management_exceptions.iter().any(|e| e.recovery)
                    || (self.grants.iter().any(|grant| {
                        grant.profile == profile.id && grant.admission == AdmissionIntent::Allow
                    }) && !profile
                        .required_effects
                        .contains(&EffectKind::BindingApplied)))
            {
                return Err(ProfileInvalid);
            }
        }
        for profile in &self.protection_profiles {
            if profile.encryption.backend_tls_trust().is_some()
                && (self.schema_version != SOURCE_BOUND_POLICY_SCHEMA_VERSION
                    || !matches!(
                        profile.kind,
                        ProfileKind::AwsRdsPostgresProxyV1 | ProfileKind::AwsRdsMysqlProxyV1
                    )
                    || profile
                        .allowed_routes
                        .iter()
                        .any(|r| r.kind != RouteKind::NativeProxy))
            {
                return Err(ProfileInvalid);
            }
            if matches!(
                profile.kind,
                ProfileKind::AwsRdsPostgresProxyV1 | ProfileKind::AwsRdsMysqlProxyV1
            ) && (profile.application_direct_path != DirectPathPolicy::Deny
                || profile.authentication != AuthenticationRequirement::NativeIam
                || profile
                    .allowed_routes
                    .iter()
                    .any(|r| r.kind != RouteKind::NativeProxy)
                || !profile.management_exceptions.iter().any(|e| e.recovery)
                || (self
                    .grants
                    .iter()
                    .any(|g| g.profile == profile.id && g.admission == AdmissionIntent::Allow)
                    && !profile
                        .required_effects
                        .contains(&EffectKind::BindingApplied)))
            {
                return Err(ProfileInvalid);
            }
        }
        let mut subject_targets = BTreeSet::new();
        for grant in &self.grants {
            let subject = self
                .subjects
                .iter()
                .find(|s| s.id == grant.subject)
                .ok_or(ReferenceInvalid)?;
            let target = self
                .targets
                .iter()
                .find(|t| t.id == grant.target)
                .ok_or(ReferenceInvalid)?;
            let profile = self
                .protection_profiles
                .iter()
                .find(|p| p.id == grant.profile)
                .ok_or(ReferenceInvalid)?;
            if !valid_id(&grant.id)
                || !native_ref(&grant.db_identity)
                || !subject_targets.insert((&grant.subject, &grant.target))
                || !valid_lifetime(&grant.lifetime)
            {
                return Err(ReferenceInvalid);
            }
            if matches!(grant.lifetime, GrantLifetime::Standing)
                && profile.required_effects.contains(&EffectKind::LeaseExpired)
            {
                return Err(ProfileInvalid);
            }
            let access = &grant.sql_access;
            if grant.admission == AdmissionIntent::Allow
                && !target
                    .managed_surface
                    .db_identities
                    .contains(&grant.db_identity)
            {
                return Err(ScopeViolation);
            }
            if !valid_native_refs(&access.existing_roles, 64)
                || access.privileges.len() > 256
                || !unique(access.privileges.iter().map(|p| &p.scope))
            {
                return Err(Invalid);
            }
            if grant.admission == AdmissionIntent::Deny
                && (!access.existing_roles.is_empty() || !access.privileges.is_empty())
            {
                return Err(Invalid);
            }
            if (!access.existing_roles.is_empty()
                && !target
                    .managed_surface
                    .fields
                    .contains(&ManagedField::DbRole))
                || (!access.privileges.is_empty()
                    && !target
                        .managed_surface
                        .fields
                        .contains(&ManagedField::DbObjectPrivilege))
                || access
                    .existing_roles
                    .iter()
                    .any(|role| !target.managed_surface.db_identities.contains(role))
            {
                return Err(ScopeViolation);
            }
            for privilege in &access.privileges {
                if !valid_scope(&privilege.scope)
                    || privilege.actions.is_empty()
                    || privilege.actions.len() > 7
                    || !unique(&privilege.actions)
                    || privilege
                        .actions
                        .iter()
                        .any(|action| !match privilege.scope.kind {
                            SqlObjectKind::Database => *action == SqlAction::Connect,
                            SqlObjectKind::Schema => *action == SqlAction::Usage,
                            SqlObjectKind::Table => matches!(
                                action,
                                SqlAction::Read
                                    | SqlAction::Insert
                                    | SqlAction::Update
                                    | SqlAction::Delete
                            ),
                            SqlObjectKind::Routine => *action == SqlAction::Execute,
                        })
                {
                    return Err(Invalid);
                }
                if !target
                    .managed_surface
                    .sql_scopes
                    .iter()
                    .any(|scope| scope_contains(scope, &privilege.scope))
                {
                    return Err(ScopeViolation);
                }
            }
            if grant.admission == AdmissionIntent::Allow
                && !profile.allowed_routes.iter().any(|route| {
                    route
                        .source_ids
                        .iter()
                        .any(|s| subject.workload_sources.contains(s))
                })
            {
                return Err(ProfileInvalid);
            }
            if grant.admission == AdmissionIntent::Allow
                && subject.kind == SubjectKind::Application
                && profile.allowed_routes.iter().any(|route| {
                    route.kind == RouteKind::Direct
                        && route
                            .source_ids
                            .iter()
                            .any(|s| subject.workload_sources.contains(s))
                })
            {
                // A direct management exception cannot silently permit an application bypass.
                return Err(ProfileInvalid);
            }
            if matches!(
                profile.kind,
                ProfileKind::AwsRdsPostgresProxyV1 | ProfileKind::AwsRdsMysqlProxyV1
            ) {
                let binding = target.aws.as_ref().ok_or(ProfileInvalid)?;
                if target.placement.kind != PlacementKind::AwsRds
                    || (profile.kind == ProfileKind::AwsRdsPostgresProxyV1
                        && target.engine.family != EngineFamily::PostgreSql)
                    || (profile.kind == ProfileKind::AwsRdsMysqlProxyV1
                        && (target.engine.family != EngineFamily::MySql
                            || target.mysql.is_none()
                            || !mysql_db_user(&grant.db_identity)
                            || !mysql_db_user(&binding.management_db_identity)
                            || !mysql_database(&target.engine.database)))
                    || subject.identity.provider != IdentityProvider::Aws
                    || !aws_role_arn(&subject.identity.principal, &target.placement.account_id)
                    || !subject
                        .identity
                        .immutable_id
                        .as_deref()
                        .is_some_and(aws_role_id)
                    || subject.identity.principal == binding.proxy_role_arn
                    || grant.db_identity == binding.management_db_identity
                    || !aws_db_user(&grant.db_identity)
                    || !aws_db_user(&target.engine.database)
                    || (subject.kind == SubjectKind::Application
                        && subject.identity.credential_source.kind
                            != CredentialSourceKind::WorkloadIdentity)
                {
                    return Err(ProfileInvalid);
                }
                for exception in profile.management_exceptions.iter().filter(|e| e.recovery) {
                    let recovery = self
                        .subjects
                        .iter()
                        .find(|s| s.id == exception.subject)
                        .ok_or(ProfileInvalid)?;
                    if recovery.identity.provider != IdentityProvider::Aws
                        || !aws_role_arn(&recovery.identity.principal, &target.placement.account_id)
                        || !recovery
                            .identity
                            .immutable_id
                            .as_deref()
                            .is_some_and(aws_role_id)
                        || recovery.identity.principal == subject.identity.principal
                        || recovery.identity.principal == binding.proxy_role_arn
                        || exception
                            .source_ids
                            .iter()
                            .any(|s| subject.workload_sources.contains(s))
                    {
                        return Err(ProfileInvalid);
                    }
                }
            }
            if profile.kind == ProfileKind::GcpCloudSqlPostgresConnectorV1
                && (target.placement.kind != PlacementKind::GcpCloudSql
                    || target.engine.family != EngineFamily::PostgreSql
                    || subject.identity.provider != IdentityProvider::Gcp
                    || (subject.kind == SubjectKind::Application
                        && subject.identity.credential_source.kind
                            != CredentialSourceKind::WorkloadIdentity))
            {
                return Err(ProfileInvalid);
            }
            if profile.kind == ProfileKind::GcpCloudSqlPostgresConnectorV1 {
                // First connector profile binds a service account to the exact native PG login.
                // This conversion is intentionally not a rule for other engines/deployments.
                let login = subject
                    .identity
                    .principal
                    .strip_suffix(".gserviceaccount.com")
                    .unwrap_or(&subject.identity.principal);
                if grant.db_identity != login
                    || (subject.kind == SubjectKind::Application
                        && !subject
                            .identity
                            .principal
                            .ends_with(".iam.gserviceaccount.com"))
                {
                    return Err(ProfileInvalid);
                }
            }
            if profile.kind == ProfileKind::GcpCloudSqlPostgresConnectorV1
                && subject.kind == SubjectKind::Application
                && profile
                    .management_exceptions
                    .iter()
                    .filter(|e| e.recovery)
                    .any(|e| {
                        self.subjects
                            .iter()
                            .find(|s| s.id == e.subject)
                            .is_some_and(|recovery| {
                                recovery.identity.provider == subject.identity.provider
                                    && recovery.identity.principal == subject.identity.principal
                            })
                    })
            {
                return Err(ProfileInvalid);
            }
        }
        Ok(())
    }

    /// Versioned canonical digest of policy semantics, excluding its own derived digest.
    pub fn revision_hash(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let canonical = self.normalized();
        let bytes = serde_json::to_vec(&canonical).map_err(|_| PolicyError::Invalid)?;
        let mut digest = Sha256::new();
        digest.update(if self.schema_version == POLICY_SCHEMA_VERSION {
            b"veil-db-guard/policy-revision/v1\0"
        } else {
            b"veil-db-guard/policy-revision/v2\0"
        });
        digest.update(bytes);
        Ok(format!("{:x}", digest.finalize()))
    }

    pub fn normalized(&self) -> Self {
        let mut policy = self.clone();
        policy
            .source_bindings
            .sort_by(|a, b| a.source_id.cmp(&b.source_id));
        for binding in &mut policy.source_bindings {
            binding.allowed_uses.sort();
        }
        if let Some(evaluation) = &mut policy.evaluation {
            evaluation.normalize();
        }
        policy.subjects.sort_by(|a, b| a.id.cmp(&b.id));
        for subject in &mut policy.subjects {
            subject.workload_sources.sort();
        }
        policy.targets.sort_by(|a, b| a.id.cmp(&b.id));
        for target in &mut policy.targets {
            if target.resource.generation_fingerprint.is_none()
                && let Some(binding) = &target.aws
            {
                target.resource.generation_fingerprint = Some(aws_generation_fingerprint(
                    &target.placement.account_id,
                    &target.placement.region,
                    &target.resource.native_id,
                    &binding.db_resource_id,
                ));
            }

            target.managed_surface.fields.sort();
            target.managed_surface.db_identities.sort();
            target.managed_surface.sql_scopes.sort();
        }
        policy.grants.sort_by(|a, b| a.id.cmp(&b.id));
        for grant in &mut policy.grants {
            grant.sql_access.existing_roles.sort();
            grant
                .sql_access
                .privileges
                .sort_by(|a, b| a.scope.cmp(&b.scope));
            for privilege in &mut grant.sql_access.privileges {
                privilege.actions.sort();
            }
        }
        policy.protection_profiles.sort_by(|a, b| a.id.cmp(&b.id));
        for profile in &mut policy.protection_profiles {
            profile.allowed_routes.sort_by(|a, b| a.id.cmp(&b.id));
            for route in &mut profile.allowed_routes {
                route.source_ids.sort();
            }
            profile
                .management_exceptions
                .sort_by(|a, b| a.id.cmp(&b.id));
            for exception in &mut profile.management_exceptions {
                exception.source_ids.sort();
            }
            profile.required_effects.sort();
        }
        policy
    }
}

pub fn parse_policy(input: &str) -> Result<PolicyRevision, PolicyError> {
    if input.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::LimitExceeded);
    }
    if input.bytes().any(|c| b"&*!".contains(&c)) {
        return Err(PolicyError::Invalid);
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_reader_input_bytes = Some(MAX_POLICY_BYTES);
    budget.max_depth = 24;
    budget.max_nodes = 25_000;
    budget.max_events = 50_000;
    budget.max_total_scalar_bytes = MAX_POLICY_BYTES;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_documents = 1;
    budget.max_merge_keys = 0;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let policy: PolicyRevision = serde_saphyr::from_slice_with_options(input.as_bytes(), options)
        .map_err(|_| PolicyError::Invalid)?;
    policy.validate()?;
    Ok(policy.normalized())
}
