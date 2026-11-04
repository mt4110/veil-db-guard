//! Selected, secret-free GCP contracts. Cloud permission and SQL permission are separate.
use crate::domain::Limits;
use serde::{Deserialize, Serialize};

macro_rules! choice { ($n:ident {$($v:ident),+ $(,)?}) => {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all="snake_case")] pub enum $n {$($v),+}
}; }
choice!(GcpRoute { Proxy, Direct });
choice!(GcpExpectation { Allow, Deny });
choice!(GcpDenial {
    ConnectIam,
    LoginIam,
    NetworkBlocked
});
choice!(GcpEvidenceKind { Live, Fixture });
choice!(GcpAccess {
    Allowed,
    Denied,
    Unknown
});
choice!(GcpVerdict {
    Pass,
    Fail,
    Pending,
    Unknown
});
choice!(GcpExecution {
    Completed,
    Timeout,
    Cancelled,
    Error,
    NotRun
});
choice!(GcpPermission {
    InstanceConnect,
    InstanceGet,
    InstanceLogin,
    ServiceUsage,
    TokenCreation
});
choice!(GcpRole {
    CloudSqlClient,
    CloudSqlInstanceUser,
    ServiceUsageConsumer,
    Other
});
choice!(GcpConnectorEnforcement {
    Required,
    NotRequired,
    Unknown
});
choice!(GcpSslMode {
    EncryptedOnly,
    TrustedClientCertificateRequired,
    AllowUnencrypted,
    Unknown
});
choice!(GcpReason {
    None,
    MissingEvidence,
    InvalidEvidence,
    StaleEvidence,
    FixtureOnly,
    TargetMismatch,
    ConfigMismatch,
    BuildMismatch,
    IncoherentSnapshot,
    IncompleteInventory,
    IdentityMismatch,
    UnclassifiedFailure,
    WrongDenialLayer,
    AccessStillAllowed,
    PropagationPending,
    ChangeUncorroborated,
    PermissionDenied,
    NetworkCauseUnconfirmed,
    MixedHistory
});

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpConfig {
    pub schema_version: u32,
    pub target: GcpTarget,
    pub principals: Vec<GcpPrincipal>,
    pub cases: Vec<GcpCase>,
    #[serde(default)]
    pub permission_changes: Vec<GcpPermissionChange>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default = "default_age")]
    pub max_age_seconds: u64,
    #[serde(default = "default_pending")]
    pub pending_window_seconds: u64,
}
fn default_age() -> u64 {
    3600
}
fn default_pending() -> u64 {
    600
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpTarget {
    pub project_id: String,
    pub instance_id: String,
    pub region: String,
    pub engine_version: String,
    pub database: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpPrincipal {
    pub id: String,
    pub service_account: String,
}
impl GcpPrincipal {
    pub fn db_user(&self) -> String {
        self.service_account
            .trim_end_matches(".gserviceaccount.com")
            .into()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpCase {
    pub id: String,
    pub principal_id: String,
    pub route: GcpRoute,
    pub expected: GcpExpectation,
    #[serde(default)]
    pub expected_denial: Option<GcpDenial>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpPermissionChange {
    pub principal_id: String,
    pub layer: GcpDenial,
    pub changed_at: u64,
    pub before_roles: Vec<GcpRole>,
    pub after_roles: Vec<GcpRole>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpPrincipalRoles {
    pub principal_id: String,
    pub roles: Vec<GcpRole>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpSnapshot {
    pub target: GcpTarget,
    pub observed_at: u64,
    pub complete: bool,
    pub engine_version: String,
    pub connection_name: String,
    pub public_ip: Option<std::net::Ipv4Addr>,
    pub ca_mode: String,
    pub ca_fingerprint: String,
    pub iam_auth_enabled: bool,
    pub connector_enforcement: GcpConnectorEnforcement,
    pub ssl_mode: GcpSslMode,
    pub authorized_networks: Vec<String>,
    pub principal_roles: Vec<GcpPrincipalRoles>,
    pub registered_principal_ids: Vec<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpProof {
    pub tcp_reachable: Option<bool>,
    pub tls_established: Option<bool>,
    pub ca_verified: bool,
    pub sql_authenticated: bool,
    pub sql_ok: bool,
    pub db_user: Option<String>,
    pub database: Option<String>,
    pub backend_ssl: Option<bool>,
    pub credential_issued: bool,
    pub denied_permission: Option<GcpPermission>,
    pub iam_login_rejected: bool,
    pub transport_positive: bool,
    pub transport_control_case_id: Option<String>,
    pub network_rejection_explicit: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpObservation {
    pub case_id: String,
    pub attempt_id: String,
    pub principal_id: String,
    pub route: GcpRoute,
    pub started_at: u64,
    pub finished_at: u64,
    pub execution: GcpExecution,
    pub observed: GcpAccess,
    pub proof: GcpProof,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpRunEvidence {
    pub schema_version: u32,
    pub run_id: String,
    pub build_id: String,
    pub config_hash: String,
    pub history_compatibility_hash: String,
    pub evidence_kind: GcpEvidenceKind,
    pub target: GcpTarget,
    pub started_at: u64,
    pub finished_at: u64,
    pub execution: GcpExecution,
    pub before: GcpSnapshot,
    pub after: GcpSnapshot,
    pub observations: Vec<GcpObservation>,
}
#[derive(Debug, Clone)]
pub struct GcpHistoricalRun {
    pub config: GcpConfig,
    pub evidence: GcpRunEvidence,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpCaseAssessment {
    pub case_id: String,
    pub principal_id: String,
    pub route: GcpRoute,
    pub expected: GcpExpectation,
    pub expected_denial: Option<GcpDenial>,
    pub observed: GcpAccess,
    pub denial: Option<GcpDenial>,
    pub denied_permission: Option<GcpPermission>,
    pub verdict: GcpVerdict,
    pub protected: bool,
    pub reason: GcpReason,
    pub execution: GcpExecution,
    pub observed_at: Option<u64>,
    pub mixed_history: bool,
    pub consecutive_denials: usize,
    pub evidence_runs: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpAssessment {
    pub schema_version: u32,
    pub target: GcpTarget,
    pub evaluated_at: u64,
    pub verdict: GcpVerdict,
    pub protected: bool,
    pub cases: Vec<GcpCaseAssessment>,
    pub reasons: Vec<GcpReason>,
}
