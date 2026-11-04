//! Shared, secret-free contracts. No network or credential acquisition.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

macro_rules! enumeration {
    ($name:ident { $($v:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($v),+ }
    };
}
enumeration!(Profile {
    LocalContractV1,
    AwsSandboxCoreV1,
    ExistingDbCoreV1,
    DecoyV1,
    ContinuousV1
});
enumeration!(AuthMode {
    EndToEndIam,
    StandardIam
});
enumeration!(SourceKind {
    VpcHost,
    Vpn,
    Tunnel,
    LocalLab
});
enumeration!(Actor {
    Application,
    Unauthorized,
    Admin
});
enumeration!(Destination { Proxy, Database });
enumeration!(Expectation { Allow, Deny });
enumeration!(AddressFamily { Ipv4, Ipv6 });
enumeration!(EvidenceKind {
    LocalFixture,
    LocalConnection,
    AwsConfiguration,
    AwsConnection,
    OperatorAttestation
});
enumeration!(Execution {
    Completed,
    Error,
    Timeout,
    Cancelled,
    NotRun
});
enumeration!(Verdict {
    Pass,
    Fail,
    Unknown,
    NotApplicable
});
enumeration!(Stage {
    ObservedTrue,
    ObservedFalse,
    Unknown
});
enumeration!(SourceVerification {
    Declared,
    Corroborated
});
enumeration!(RetrievalStatus {
    Complete,
    Partial,
    AccessDenied,
    Failed,
    NotRequested
});
enumeration!(TargetHealth {
    Available,
    Unavailable,
    Unknown
});
enumeration!(Suite {
    Positive,
    AuthNegative,
    TlsNegative,
    DirectPath,
    Recovery,
    Performance
});
enumeration!(Outcome {
    CheckSatisfied,
    CheckViolated,
    Authenticated,
    AuthenticationRejected,
    TlsRejected,
    TcpReachable,
    ConnectionNotEstablished,
    PostconditionMatched,
    WriteOutcomeUnknown,
    Interrupted,
    Unsupported,
    Measured
});
enumeration!(ReasonCode {
    None,
    ConfigInvalid,
    TargetMismatch,
    UnsupportedTarget,
    AwsAccessDenied,
    SnapshotIncomplete,
    IamDenied,
    TlsRejected,
    DbAuthFailed,
    DbPermissionDenied,
    NetworkUnreachable,
    UnexpectedReachability,
    ConnectTimeout,
    QueryTimeout,
    WriteOutcomeUnknown,
    Cancelled,
    EvidenceStale,
    EvidenceIncompatible,
    StorageFailed,
    MissingEvidence,
    MissingPositiveControl,
    UncorroboratedSource,
    UnsupportedCase,
    LimitExceeded,
    Unknown
});
enumeration!(Fact {
    ChainVerified,
    HostnameVerified,
    CrudMatched,
    CommitMatched,
    RollbackMatched,
    ErrorRollbackMatched,
    SessionIsolated,
    TokenRefreshed,
    ExpiredTokenUsed,
    ExistingSessionAfterExpiry,
    NoWriteReplay,
    PostconditionVerified,
    TargetMatched,
    DatabaseAvailable,
    NetworkPolicyDenied,
    RuntimeTlsRequired,
    BackendTlsObserved,
    ConfigBeforeAfterMatched,
    NoChangesAttested,
    SamplesBounded,
    PinningObserved,
    PreparedStatementUsed,
    ProtocolV3,
    PoolResetVerified,
    LongTransactionVerified,
    DeadlineRespected,
    CancellationRespected,
    ResourcesOwned,
    CleanupApproved,
    EvidencePreserved,
    ResidualResourcesChecked,
    NoSnapshotMarkedUnknown,
    PartialSnapshotMarkedUnknown,
    OnlyNewResourcesPlanned,
    BootstrapRecoverySeparated,
    AccessDeniedRecorded,
    PageMissingRecorded,
    EmptyNotAssumedSafe,
    AmbiguousTargetRejected,
    ForeignIdentityRejected,
    TargetMismatchRejected,
    DesiredRuntimeSeparated,
    HealthNotAuthorization,
    ConfigurationNotConnection,
    AwsCredentialExpiryHandled,
    FaultRecoveryVerified,
    RecoveryCasesRevalidated
});

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub schema_version: u32,
    pub assessment_profile: Profile,
    pub experiment_id: String,
    pub phase_id: String,
    pub configuration_epoch: String,
    pub target: Target,
    pub auth: Auth,
    pub sources: Vec<Source>,
    pub paths: Vec<PathSpec>,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub test_scope: Option<TestScope>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub evidence_policy: EvidencePolicy,
    #[serde(default)]
    pub performance_profile: Option<PerformanceProfile>,
    #[serde(default)]
    pub auth_negative: Option<AuthNegativeConfig>,
    #[serde(default)]
    pub recovery_profile: Option<RecoveryProfile>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthNegativeConfig {
    pub unauthorized_aws_profile: Option<String>,
    pub unauthorized_db_user: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProfile {
    pub allow_token_expiry_wait: bool,
    pub long_transaction_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub account_id: String,
    pub region: String,
    pub db_instance_arn: String,
    pub proxy_arn: String,
    pub proxy_name: String,
    pub engine: String,
    pub engine_version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    pub mode: AuthMode,
    pub db_user: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub kind: SourceKind,
    #[serde(default, skip_serializing)]
    pub description: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSpec {
    pub id: String,
    pub source_id: String,
    pub actor: Actor,
    pub destination: Destination,
    pub expected: Expectation,
    pub address_family: AddressFamily,
    #[serde(default)]
    pub exception_code: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub ca_file: Option<PathBuf>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestScope {
    pub database: String,
    pub schema_prefix: String,
    pub db_user: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub connect_timeout_ms: u64,
    pub query_timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub max_concurrency: usize,
    pub max_retries: usize,
    pub max_results: usize,
    pub max_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 10_000,
            query_timeout_ms: 10_000,
            total_timeout_ms: 120_000,
            max_concurrency: 1,
            max_retries: 0,
            max_results: 1000,
            max_bytes: 8 * 1024 * 1024,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EvidencePolicy {
    pub max_age_seconds: u64,
}
impl Default for EvidencePolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 3600,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceProfile {
    pub workload_id: String,
    pub samples: usize,
    pub warmup: usize,
    pub max_p95_ms: u64,
    pub max_error_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbState {
    pub arn: String,
    pub resource_id: String,
    pub endpoint: Endpoint,
    pub engine: String,
    pub engine_version: String,
    pub iam_auth_enabled: bool,
    pub publicly_accessible: bool,
    pub security_group_ids: Vec<String>,
    pub parameter_group: Option<String>,
    pub parameters_in_sync: bool,
    pub force_ssl: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_zone: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyState {
    pub arn: String,
    pub endpoint: Endpoint,
    pub auth_mode: AuthMode,
    pub require_tls: bool,
    pub security_group_ids: Vec<String>,
    pub target_db_resource_id: Option<String>,
    pub target_health: TargetHealth,
    pub role_arn: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleSource {
    SecurityGroup { id: String },
    Ipv4 { cidr: String },
    Ipv6 { cidr: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityRule {
    pub protocol: String,
    pub from_port: Option<u16>,
    pub to_port: Option<u16>,
    pub source: RuleSource,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityGroup {
    pub id: String,
    pub vpc_id: String,
    pub ingress: Vec<SecurityRule>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retrieval {
    pub operation: String,
    pub status: RetrievalStatus,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySnapshot {
    pub schema_version: u32,
    pub target: Target,
    pub config_hash: String,
    pub observed_at: u64,
    pub evidence_kind: EvidenceKind,
    pub db: Option<DbState>,
    pub proxy: Option<ProxyState>,
    pub security_groups: Vec<SecurityGroup>,
    pub retrievals: Vec<Retrieval>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathStages {
    pub transport_reachable: Stage,
    pub tls_established: Stage,
    pub db_authenticated: Stage,
}
impl Default for PathStages {
    fn default() -> Self {
        Self {
            transport_reachable: Stage::Unknown,
            tls_established: Stage::Unknown,
            db_authenticated: Stage::Unknown,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u32,
    pub run_id: String,
    pub experiment_id: String,
    pub phase_id: String,
    pub configuration_epoch: String,
    pub assessment_profile: Profile,
    pub verification_id: String,
    pub case_id: String,
    pub attempt_id: String,
    pub requirement_ids: Vec<String>,
    pub evidence_kind: EvidenceKind,
    pub target_id: String,
    pub path_id: String,
    pub source_id: String,
    pub source_verification: SourceVerification,
    pub config_hash: String,
    pub snapshot_hash: String,
    pub observed_at: u64,
    pub duration_ms: u64,
    pub execution: Execution,
    pub outcome: Outcome,
    pub path_stages: PathStages,
    pub reason_code: ReasonCode,
    pub facts: Vec<Fact>,
    pub evidence_refs: Vec<String>,
    pub build_id: String,
    #[serde(default)]
    pub details: Option<ProbeDetails>,
}
impl Observation {
    pub fn new(
        config: &TargetConfig,
        run_id: &str,
        verification: &str,
        case: &str,
        source_id: &str,
        path_id: &str,
        kind: EvidenceKind,
    ) -> Self {
        Self {
            schema_version: 1,
            run_id: run_id.into(),
            experiment_id: config.experiment_id.clone(),
            phase_id: config.phase_id.clone(),
            configuration_epoch: config.configuration_epoch.clone(),
            assessment_profile: config.assessment_profile,
            verification_id: verification.into(),
            case_id: case.into(),
            attempt_id: format!("{run_id}-{case}"),
            requirement_ids: vec![],
            evidence_kind: kind,
            target_id: config.target.id.clone(),
            path_id: path_id.into(),
            source_id: source_id.into(),
            source_verification: SourceVerification::Declared,
            config_hash: crate::config::config_hash(config),
            snapshot_hash: String::new(),
            observed_at: now(),
            duration_ms: 0,
            execution: Execution::NotRun,
            outcome: Outcome::Unsupported,
            path_stages: PathStages::default(),
            reason_code: ReasonCode::MissingEvidence,
            facts: vec![],
            evidence_refs: vec![],
            build_id: crate::BUILD_ID.into(),
            details: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseResult {
    pub verification_id: String,
    pub case_id: String,
    pub path_id: String,
    pub verdict: Verdict,
    pub reason_code: ReasonCode,
    pub evidence_runs: Vec<String>,
    pub evidence_kinds: Vec<EvidenceKind>,
    pub executions: Vec<Execution>,
    pub source_ids: Vec<String>,
    pub source_verifications: Vec<SourceVerification>,
    pub outcomes: Vec<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase_id: Option<String>,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeDetails {
    pub resolved_addresses: Vec<String>,
    pub retained_schema: Option<String>,
    pub samples_ms: Vec<u64>,
    pub sample_count: usize,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub p99_ms: Option<u64>,
    pub error_count: usize,
    pub connection_mode: Option<Destination>,
    pub workload_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ObservationProtocol>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub schema_version: u32,
    pub target_id: String,
    pub profile: Profile,
    pub evaluated_at: u64,
    pub verdict: Verdict,
    pub configuration_verdict: Verdict,
    pub connection_verdict: Verdict,
    pub cases: Vec<CaseResult>,
    pub limitations: Vec<ReasonCode>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentPlan {
    pub schema_version: u32,
    pub experiment_id: String,
    pub profile: Profile,
    pub phases: Vec<ExperimentPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ExperimentProtocol>,
}

enumeration!(SnapshotField {
    DbEndpoint,
    ProxyEndpoint,
    DbSecurityGroups,
    ProxySecurityGroups,
    SecurityGroupRules,
    DbIam,
    ProxyAuth,
    ProxyTls,
    DbTls,
    ParametersInSync,
    TargetHealth
});
enumeration!(FaultKind {
    Disconnect,
    DnsFailure,
    Unreachable,
    Deadline,
    Cancellation,
    AmbiguousCommit
});
enumeration!(MeasurementKind {
    ConnectionSetup,
    PooledQuery
});
enumeration!(PinningScenario { NonPinned, Pinned });
enumeration!(PhaseKind {
    Baseline,
    Protected,
    Fault,
    Recovered,
    Cleanup
});

/// The immutable pre-execution protocol. Actual observations live in run artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentProtocol {
    pub planned_at: u64,
    pub phase_contracts: Vec<PhaseContract>,
    pub transitions: Vec<PhaseTransition>,
    pub comparisons: Vec<PerformanceComparison>,
    pub management: Option<ManagementContract>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseContract {
    pub phase_id: String,
    pub kind: PhaseKind,
    pub configuration_epoch: String,
    pub config: TargetConfig,
    pub starts_at: u64,
    pub ends_at: u64,
    pub before_snapshot_ref: String,
    pub after_snapshot_ref: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedStateChange {
    pub field: SnapshotField,
    pub before_value_hash: String,
    pub after_value_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseTransition {
    pub from_phase: String,
    pub to_phase: String,
    pub fault: Option<FaultKind>,
    pub case_ids: Vec<String>,
    pub allowed_changes: Vec<AllowedStateChange>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeasurementConditions {
    pub workload_id: String,
    pub workload_hash: String,
    pub driver_version: String,
    pub db_resource_id: String,
    pub db_instance_class: Option<String>,
    #[serde(default)]
    pub availability_zone: Option<String>,
    #[serde(default)]
    pub runner_os: Option<String>,
    #[serde(default)]
    pub runner_arch: Option<String>,
    #[serde(default)]
    pub runner_identity_hash: Option<String>,
    pub engine_version: String,
    pub db_user: String,
    pub concurrency: usize,
    pub warmup: usize,
    pub retries: usize,
    pub tls_verified: bool,
    pub kind: MeasurementKind,
    pub pinning: Option<PinningScenario>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceComparison {
    pub case_id: String,
    pub baseline_phase: String,
    pub protected_phase: String,
    pub baseline_path: String,
    pub protected_path: String,
    pub conditions: MeasurementConditions,
    pub minimum_success_samples: usize,
    pub max_p95_ms: u64,
    pub max_error_rate: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEvidence {
    /// A predeclared logical reference (the future artifact hash is not known at planning time).
    pub reference_id: String,
    pub artifact_hash: String,
    pub snapshot: InventorySnapshot,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationProtocol {
    pub plan_hash: String,
    pub before: Option<SnapshotEvidence>,
    pub after: Option<SnapshotEvidence>,
    pub operation: Option<OperationPostcondition>,
    pub identity: Option<IdentityEvidence>,
    pub measurement: Option<MeasurementConditions>,
    pub pinning: Option<PinningEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPostcondition {
    pub operation_id: String,
    pub fault: Option<FaultKind>,
    pub expected_rows: u64,
    pub observed_rows: u64,
    pub write_attempts: usize,
    pub replay_attempts: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEvidence {
    pub iam_principal_arn: String,
    pub requested_db_user: String,
    pub authenticated_db_user: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementContract {
    pub application_principal_arn: String,
    pub admin_principal_arn: String,
    pub application_db_user: String,
    pub admin_db_user: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinningEvidence {
    pub starts_at: u64,
    pub ends_at: u64,
    pub pinned_connections: Vec<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentPhase {
    pub phase_id: String,
    pub configuration_epoch: String,
    pub config_hash: String,
    pub target_id: String,
    pub case_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePlan {
    pub schema_version: u32,
    pub target_id: String,
    pub operation_only: bool,
    pub snapshot_available: bool,
    pub changes: Vec<PlanItem>,
    pub unknowns: Vec<ReasonCode>,
    pub bootstrap_required: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanItem {
    pub code: String,
    pub required: bool,
    pub verification_ids: Vec<String>,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
