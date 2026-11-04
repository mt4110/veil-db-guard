//! Pure, conservative assessment. Input records are claims, not signed attestations.
use crate::{config::config_hash, domain::*};
mod protocol;
pub use protocol::{
    field_hash as snapshot_field_hash, plan_hash, validate_experiment_plan,
    validate_observation_protocol, validate_protocol_links,
};

const GLOBAL: &str = "global";

fn cases_for(v: &str) -> &'static [&'static str] {
    match v {
        "V01" => &[
            "reject_missing",
            "reject_duplicate",
            "reject_unknown",
            "reject_placeholder",
            "reject_sql",
            "reject_foreign_target",
        ],
        "V02" => &[
            "no_snapshot",
            "partial_snapshot",
            "new_resources_only",
            "bootstrap_recovery",
        ],
        "V03" => &[
            "access_denied",
            "page_missing",
            "empty",
            "ambiguous",
            "foreign_identity",
            "target_mismatch",
        ],
        "V04" => &[
            "interrupted",
            "limit",
            "write_failure",
            "symlink",
            "existing_output",
            "bad_reference",
        ],
        "V05" => &[
            "stale",
            "wrong_target",
            "changed_config",
            "all_na",
            "empty",
            "local_not_aws",
            "bad_hash",
        ],
        "V06" => &[
            "insert_read",
            "update_read",
            "delete_read",
            "commit",
            "rollback",
            "error_rollback",
            "session_isolation",
        ],
        "V07" => &[
            "missing_auth",
            "bad_signature",
            "unauthorized_principal",
            "unauthorized_user",
            "expired_new_connection",
        ],
        "V08" => &[
            "verified_client_tls",
            "tls_disabled",
            "untrusted_ca",
            "wrong_hostname",
            "proxy_db_tls",
        ],
        "V09" => &["application_db_transport"],
        "V10" => &[
            "new_token",
            "expired_new_connection",
            "existing_after_expiry",
            "aws_credential_expiry",
        ],
        "V11" => &[
            "disconnect",
            "dns_failure",
            "unreachable",
            "deadline",
            "cancellation",
            "ambiguous_commit",
        ],
        "V12" => &[
            "admin_allowed",
            "application_admin_denied",
            "recovered_revalidation",
        ],
        "V13" => &[
            "connection_setup",
            "pooled_query",
            "pinning",
            "errors",
            "bounded_samples",
        ],
        "V14" => &[
            "sdk_error",
            "driver_error",
            "config",
            "sql_values",
            "stdout_stderr",
            "artifacts",
        ],
        "V15" => &[
            "desired_vs_runtime",
            "health_not_authorization",
            "configuration_not_connection",
        ],
        "V16" => &[
            "protocol",
            "prepared_statement",
            "pool_reset",
            "session_state",
            "long_transaction",
            "pinning",
        ],
        "V17" => &["existing_adoption"],
        "V18" => &["isolation"],
        "V19" => &["detection_notification"],
        "V20" => &["drift_invalidation"],
        "V21" => &[
            "ownership",
            "approved_cleanup",
            "evidence_preserved",
            "residual_resources",
        ],
        "V22" => &["operator_validation"],
        _ => &[],
    }
}

fn blank(v: &str, suffix: &str, path: &str) -> CaseResult {
    CaseResult {
        verification_id: v.into(),
        case_id: format!("{v}.{suffix}"),
        path_id: path.into(),
        verdict: Verdict::Unknown,
        reason_code: ReasonCode::MissingEvidence,
        evidence_runs: vec![],
        evidence_kinds: vec![],
        executions: vec![],
        source_ids: vec![],
        source_verifications: vec![],
        outcomes: vec![],
        phase_id: None,
    }
}

/// The fixed requirement universe is independent of supplied observations.
pub fn required_cases(config: &TargetConfig) -> Vec<CaseResult> {
    let vs: Vec<&str> = match config.assessment_profile {
        Profile::LocalContractV1 => vec!["V01", "V02", "V03", "V04", "V05", "V14"],
        Profile::AwsSandboxCoreV1 => vec![
            "V02", "V03", "V06", "V07", "V08", "V09", "V10", "V11", "V12", "V13", "V14", "V15",
            "V16", "V21",
        ],
        Profile::ExistingDbCoreV1 => vec![
            "V02", "V03", "V06", "V07", "V08", "V09", "V10", "V11", "V12", "V13", "V14", "V15",
            "V16", "V17", "V21", "V22",
        ],
        Profile::DecoyV1 => vec!["V18", "V19"],
        Profile::ContinuousV1 => vec!["V20"],
    };
    let local = config.assessment_profile == Profile::LocalContractV1;
    let mut result = Vec::new();
    for v in vs {
        for suffix in cases_for(v) {
            let paths: Vec<&PathSpec> = if local
                || matches!(
                    v,
                    "V02" | "V03" | "V14" | "V15" | "V17" | "V18" | "V19" | "V20" | "V21" | "V22"
                ) {
                vec![]
            } else {
                config
                    .paths
                    .iter()
                    .filter(|p| match v {
                        "V09" => {
                            p.destination == Destination::Database
                                && p.expected == Expectation::Deny
                        }
                        "V12" if *suffix == "admin_allowed" => {
                            p.actor == Actor::Admin && p.expected == Expectation::Allow
                        }
                        "V12" if *suffix == "application_admin_denied" => {
                            p.actor == Actor::Application
                                && p.destination == Destination::Database
                                && p.expected == Expectation::Deny
                        }
                        _ => {
                            p.actor == Actor::Application
                                && p.destination == Destination::Proxy
                                && p.expected == Expectation::Allow
                        }
                    })
                    .collect()
            };
            if paths.is_empty() {
                result.push(blank(v, suffix, GLOBAL));
            } else {
                for p in paths {
                    result.push(blank(v, suffix, &p.id));
                }
            }
        }
    }
    result
}

fn has(o: &Observation, facts: &[Fact]) -> bool {
    facts.iter().all(|f| o.facts.contains(f))
}
fn sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 160
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn is_local_case(c: &TargetConfig, v: &str) -> bool {
    c.assessment_profile == Profile::LocalContractV1 || v == "V14"
}

fn provenance(
    c: &TargetConfig,
    o: &Observation,
    now: u64,
    plan: Option<&ExperimentPlan>,
) -> Result<(), ReasonCode> {
    if o.schema_version != 1
        || o.build_id != crate::BUILD_ID
        || !safe_id(&o.run_id)
        || !safe_id(&o.attempt_id)
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    if o.target_id != c.target.id {
        return Err(ReasonCode::TargetMismatch);
    }
    if o.observed_at > now || now.saturating_sub(o.observed_at) > c.evidence_policy.max_age_seconds
    {
        return Err(ReasonCode::EvidenceStale);
    }
    if o.experiment_id != c.experiment_id {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    let phase_config = protocol::phase_config(c, o, plan);
    let applicable = phase_config.unwrap_or(c);
    if o.phase_id != applicable.phase_id || o.configuration_epoch != applicable.configuration_epoch
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    let ancillary = o.verification_id == "V14" && o.assessment_profile == Profile::LocalContractV1;
    let mut expected_config = applicable.clone();
    if ancillary {
        expected_config.assessment_profile = Profile::LocalContractV1;
    }
    if o.assessment_profile != expected_config.assessment_profile
        || o.config_hash != config_hash(&expected_config)
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    if o.path_id == GLOBAL {
        if o.source_id != GLOBAL {
            return Err(ReasonCode::EvidenceIncompatible);
        }
    } else if !applicable
        .paths
        .iter()
        .any(|p| p.id == o.path_id && p.source_id == o.source_id)
        || !applicable.sources.iter().any(|s| s.id == o.source_id)
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    Ok(())
}

fn strong_at(
    c: &TargetConfig,
    o: &Observation,
    plan: Option<&ExperimentPlan>,
    now: u64,
) -> Result<(), ReasonCode> {
    if let Some(plan) = plan.filter(|p| p.protocol.is_some()) {
        if o.evidence_kind != EvidenceKind::AwsConnection {
            return Err(ReasonCode::EvidenceIncompatible);
        }
        if o.source_verification != SourceVerification::Corroborated {
            return Err(ReasonCode::UncorroboratedSource);
        }
        let (phase, _) = protocol::context(c, o, plan, now)?;
        if !matches!(phase.kind, PhaseKind::Protected | PhaseKind::Recovered) {
            return Err(ReasonCode::EvidenceIncompatible);
        }
        Ok(())
    } else {
        Err(ReasonCode::MissingEvidence)
    }
}

fn planned_case(c: &TargetConfig, o: &Observation, plan: Option<&ExperimentPlan>) -> bool {
    plan.is_some_and(|p| {
        p.schema_version == 1
            && p.experiment_id == c.experiment_id
            && p.profile == c.assessment_profile
            && p.phases.iter().any(|phase| {
                phase.phase_id == o.phase_id
                    && phase.configuration_epoch == o.configuration_epoch
                    && phase.target_id == o.target_id
                    && phase.config_hash == o.config_hash
                    && phase.case_ids.contains(&o.case_id)
            })
    })
}

fn configuration_case(
    c: &TargetConfig,
    row: &CaseResult,
    o: &Observation,
    plan: Option<&ExperimentPlan>,
    now: u64,
) -> (Verdict, ReasonCode) {
    let Some(p) = plan.filter(|p| p.protocol.is_some()) else {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    };
    if let Err(r) = protocol::context(c, o, p, now) {
        return (Verdict::Unknown, r);
    }
    if o.evidence_kind != EvidenceKind::AwsConfiguration
        || o.evidence_refs.is_empty()
        || !has(o, &[Fact::TargetMatched])
    {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    }
    if o.execution != Execution::Completed {
        return (Verdict::Unknown, ReasonCode::Unknown);
    }
    let suffix = row.case_id.split_once('.').map_or("", |(_, s)| s);
    if !(row.verification_id == "V02" && suffix == "no_snapshot") && !sha256(&o.snapshot_hash) {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    }
    if row.verification_id == "V21" && (o.phase_id != "cleanup" || !planned_case(c, o, plan)) {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    }
    let fact = match (row.verification_id.as_str(), suffix) {
        ("V02", "no_snapshot") => Fact::NoSnapshotMarkedUnknown,
        ("V02", "partial_snapshot") => Fact::PartialSnapshotMarkedUnknown,
        ("V02", "new_resources_only") => Fact::OnlyNewResourcesPlanned,
        ("V02", "bootstrap_recovery") => Fact::BootstrapRecoverySeparated,
        ("V03", "access_denied") => Fact::AccessDeniedRecorded,
        ("V03", "page_missing") => Fact::PageMissingRecorded,
        ("V03", "empty") => Fact::EmptyNotAssumedSafe,
        ("V03", "ambiguous") => Fact::AmbiguousTargetRejected,
        ("V03", "foreign_identity") => Fact::ForeignIdentityRejected,
        ("V03", "target_mismatch") => Fact::TargetMismatchRejected,
        ("V15", "desired_vs_runtime") => Fact::DesiredRuntimeSeparated,
        ("V15", "health_not_authorization") => Fact::HealthNotAuthorization,
        ("V15", "configuration_not_connection") => Fact::ConfigurationNotConnection,
        ("V21", "ownership") => Fact::ResourcesOwned,
        ("V21", "approved_cleanup") => Fact::CleanupApproved,
        ("V21", "evidence_preserved") => Fact::EvidencePreserved,
        ("V21", "residual_resources") => Fact::ResidualResourcesChecked,
        _ => return (Verdict::Unknown, ReasonCode::UnsupportedCase),
    };
    if o.outcome == Outcome::CheckViolated {
        return (Verdict::Fail, ReasonCode::Unknown);
    }
    if o.outcome == Outcome::CheckSatisfied && o.reason_code == ReasonCode::None && has(o, &[fact])
    {
        (Verdict::Pass, ReasonCode::None)
    } else {
        (Verdict::Unknown, ReasonCode::MissingEvidence)
    }
}

fn authenticated(o: &Observation) -> bool {
    o.execution == Execution::Completed
        && o.reason_code == ReasonCode::None
        && o.path_stages.transport_reachable == Stage::ObservedTrue
        && o.path_stages.tls_established == Stage::ObservedTrue
        && o.path_stages.db_authenticated == Stage::ObservedTrue
        && has(o, &[Fact::ChainVerified, Fact::HostnameVerified])
        && matches!(
            o.outcome,
            Outcome::Authenticated | Outcome::PostconditionMatched
        )
}

fn positive_control(
    c: &TargetConfig,
    o: &Observation,
    all: &[Observation],
    now: u64,
    direct: bool,
    plan: Option<&ExperimentPlan>,
) -> bool {
    let applicable = protocol::phase_config(c, o, plan).unwrap_or(c);
    all.iter().any(|p| {
        p.verification_id == "V08"
            && p.case_id == "V08.verified_client_tls"
            && provenance(c, p, now, plan).is_ok()
            && strong_at(c, p, plan, now).is_ok()
            && authenticated(p)
            && p.source_id == o.source_id
            && p.phase_id == o.phase_id
            && p.configuration_epoch == o.configuration_epoch
            && p.config_hash == o.config_hash
            && p.snapshot_hash == o.snapshot_hash
            && p.observed_at.abs_diff(o.observed_at).saturating_mul(1000)
                <= c.limits.total_timeout_ms
            && if direct {
                applicable.paths.iter().any(|path| {
                    path.id == p.path_id
                        && path.destination == Destination::Proxy
                        && path.expected == Expectation::Allow
                        && path.address_family
                            == applicable
                                .paths
                                .iter()
                                .find(|x| x.id == o.path_id)
                                .map_or(AddressFamily::Ipv4, |x| x.address_family)
                })
            } else {
                p.path_id == o.path_id
            }
    })
}

fn decide(
    c: &TargetConfig,
    row: &CaseResult,
    o: &Observation,
    all: &[Observation],
    now: u64,
    plan: Option<&ExperimentPlan>,
) -> (Verdict, ReasonCode) {
    let unknown = |r| (Verdict::Unknown, r);
    if is_local_case(c, &row.verification_id) {
        if o.evidence_kind != EvidenceKind::LocalFixture {
            return unknown(ReasonCode::EvidenceIncompatible);
        }
        if o.execution != Execution::Completed {
            return unknown(if o.reason_code == ReasonCode::None {
                ReasonCode::Unknown
            } else {
                o.reason_code
            });
        }
        return match o.outcome {
            Outcome::CheckSatisfied if o.reason_code == ReasonCode::None => {
                (Verdict::Pass, ReasonCode::None)
            }
            Outcome::CheckViolated => (
                Verdict::Fail,
                if o.reason_code == ReasonCode::None {
                    ReasonCode::Unknown
                } else {
                    o.reason_code
                },
            ),
            _ => unknown(ReasonCode::MissingEvidence),
        };
    }
    if matches!(
        row.verification_id.as_str(),
        "V17" | "V18" | "V19" | "V20" | "V22"
    ) {
        return unknown(ReasonCode::UnsupportedCase);
    }
    if matches!(row.verification_id.as_str(), "V02" | "V03" | "V15" | "V21") {
        return configuration_case(c, row, o, plan, now);
    }
    if row.path_id == GLOBAL
        && !matches!(row.verification_id.as_str(), "V02" | "V03" | "V15" | "V21")
    {
        return unknown(ReasonCode::MissingEvidence);
    }
    if let Err(r) = strong_at(c, o, plan, now) {
        return unknown(r);
    }
    // A reached transport is a definite contradiction even when authentication later fails.
    if matches!(row.verification_id.as_str(), "V09")
        && o.path_stages.transport_reachable == Stage::ObservedTrue
    {
        return (Verdict::Fail, ReasonCode::UnexpectedReachability);
    }
    if o.execution != Execution::Completed {
        return unknown(if o.reason_code == ReasonCode::None {
            ReasonCode::Unknown
        } else {
            o.reason_code
        });
    }
    let suffix = row.case_id.split_once('.').map_or("", |(_, s)| s);
    if o.outcome == Outcome::CheckViolated {
        return (
            Verdict::Fail,
            if o.reason_code == ReasonCode::None {
                ReasonCode::Unknown
            } else {
                o.reason_code
            },
        );
    }
    match row.verification_id.as_str() {
        "V06" => {
            let fact = match suffix {
                "commit" => Fact::CommitMatched,
                "rollback" => Fact::RollbackMatched,
                "error_rollback" => Fact::ErrorRollbackMatched,
                "session_isolation" => Fact::SessionIsolated,
                _ => Fact::CrudMatched,
            };
            if authenticated(o)
                && o.outcome == Outcome::PostconditionMatched
                && has(o, &[fact, Fact::PostconditionVerified])
            {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::MissingEvidence)
            }
        }
        "V07" | "V10" if row.verification_id == "V07" || suffix == "expired_new_connection" => {
            if o.path_stages.db_authenticated == Stage::ObservedTrue
                || o.outcome == Outcome::Authenticated
            {
                return (Verdict::Fail, ReasonCode::DbAuthFailed);
            }
            if !positive_control(c, o, all, now, false, plan) {
                return unknown(ReasonCode::MissingPositiveControl);
            }
            if suffix == "expired_new_connection" && !has(o, &[Fact::ExpiredTokenUsed]) {
                return unknown(ReasonCode::MissingEvidence);
            }
            if o.outcome == Outcome::AuthenticationRejected
                && o.path_stages.transport_reachable == Stage::ObservedTrue
                && o.path_stages.tls_established == Stage::ObservedTrue
                && o.path_stages.db_authenticated == Stage::ObservedFalse
                && matches!(
                    o.reason_code,
                    ReasonCode::IamDenied | ReasonCode::DbAuthFailed
                )
            {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::Unknown)
            }
        }
        "V08" => match suffix {
            "verified_client_tls" if authenticated(o) => (Verdict::Pass, ReasonCode::None),
            "proxy_db_tls"
                if authenticated(o)
                    && has(o, &[Fact::RuntimeTlsRequired, Fact::BackendTlsObserved]) =>
            {
                (Verdict::Pass, ReasonCode::None)
            }
            "tls_disabled" | "untrusted_ca" | "wrong_hostname" => {
                if o.path_stages.db_authenticated == Stage::ObservedTrue {
                    return (Verdict::Fail, ReasonCode::TlsRejected);
                }
                if !positive_control(c, o, all, now, false, plan) {
                    return unknown(ReasonCode::MissingPositiveControl);
                }
                if o.outcome == Outcome::TlsRejected
                    && o.path_stages.transport_reachable == Stage::ObservedTrue
                    && o.reason_code == ReasonCode::TlsRejected
                {
                    (Verdict::Pass, ReasonCode::None)
                } else {
                    unknown(ReasonCode::Unknown)
                }
            }
            _ => unknown(ReasonCode::MissingEvidence),
        },
        "V09" => {
            if !positive_control(c, o, all, now, true, plan) {
                return unknown(ReasonCode::MissingPositiveControl);
            }
            if o.path_stages.transport_reachable == Stage::ObservedFalse
                && has(o, &[Fact::NetworkPolicyDenied, Fact::DatabaseAvailable])
                && o.outcome == Outcome::ConnectionNotEstablished
                && o.reason_code == ReasonCode::NetworkUnreachable
            {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::Unknown)
            }
        }
        "V10" => {
            let fact = match suffix {
                "new_token" => Fact::TokenRefreshed,
                "existing_after_expiry" => Fact::ExistingSessionAfterExpiry,
                "aws_credential_expiry" => Fact::AwsCredentialExpiryHandled,
                _ => return unknown(ReasonCode::UnsupportedCase),
            };
            if authenticated(o) && has(o, &[fact]) {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::MissingEvidence)
            }
        }
        "V11" => {
            if o.outcome == Outcome::WriteOutcomeUnknown {
                return unknown(ReasonCode::WriteOutcomeUnknown);
            }
            let fact = match suffix {
                "deadline" => Fact::DeadlineRespected,
                "cancellation" => Fact::CancellationRespected,
                "ambiguous_commit" => Fact::NoWriteReplay,
                _ => return protocol::recovery(c, row, o, all, plan, now),
            };
            if authenticated(o)
                && has(o, &[fact, Fact::PostconditionVerified, Fact::NoWriteReplay])
                && o.outcome == Outcome::PostconditionMatched
            {
                let fault = match suffix {
                    "deadline" => FaultKind::Deadline,
                    "cancellation" => FaultKind::Cancellation,
                    _ => FaultKind::AmbiguousCommit,
                };
                protocol::operation(c, o, plan, now, fault)
            } else {
                unknown(ReasonCode::MissingEvidence)
            }
        }
        "V12" if suffix == "admin_allowed" => {
            if let Err(r) = protocol::admin_identity(c, o, plan, now, true) {
                return unknown(r);
            }
            if authenticated(o) {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::MissingEvidence)
            }
        }
        "V12" if suffix == "application_admin_denied" => {
            if let Err(r) = protocol::admin_identity(c, o, plan, now, false) {
                return unknown(r);
            }
            if o.path_stages.db_authenticated == Stage::ObservedTrue
                || o.outcome == Outcome::Authenticated
            {
                return (Verdict::Fail, ReasonCode::DbPermissionDenied);
            }
            if !positive_control(c, o, all, now, true, plan) {
                return unknown(ReasonCode::MissingPositiveControl);
            }
            let authentication_denied = o.outcome == Outcome::AuthenticationRejected
                && o.path_stages.db_authenticated == Stage::ObservedFalse
                && matches!(
                    o.reason_code,
                    ReasonCode::IamDenied
                        | ReasonCode::DbAuthFailed
                        | ReasonCode::DbPermissionDenied
                );
            let network_denied = o.outcome == Outcome::ConnectionNotEstablished
                && o.path_stages.transport_reachable == Stage::ObservedFalse
                && has(o, &[Fact::NetworkPolicyDenied, Fact::DatabaseAvailable]);
            if authentication_denied || network_denied {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::Unknown)
            }
        }
        "V12" if suffix == "recovered_revalidation" => {
            let Some(plan) = plan else {
                return unknown(ReasonCode::MissingEvidence);
            };
            let Ok((phase, _)) = protocol::context(c, o, plan, now) else {
                return unknown(ReasonCode::MissingEvidence);
            };
            if phase.kind != PhaseKind::Recovered
                || !authenticated(o)
                || !has(o, &[Fact::RecoveryCasesRevalidated])
            {
                return unknown(ReasonCode::MissingEvidence);
            }
            let subset: Vec<_> = required_cases(&phase.config)
                .into_iter()
                .filter(|r| matches!(r.verification_id.as_str(), "V06" | "V07" | "V08" | "V09"))
                .collect();
            for required in subset {
                let attempts: Vec<_> = all
                    .iter()
                    .filter(|a| {
                        a.case_id == required.case_id
                            && a.path_id == required.path_id
                            && a.phase_id == o.phase_id
                            && a.configuration_epoch == o.configuration_epoch
                            && provenance(c, a, now, Some(plan)).is_ok()
                    })
                    .collect();
                let decisions: Vec<_> = attempts
                    .into_iter()
                    .map(|a| decide(c, &required, a, all, now, Some(plan)).0)
                    .collect();
                if decisions.contains(&Verdict::Fail) {
                    return (Verdict::Fail, ReasonCode::EvidenceIncompatible);
                }
                if !decisions.contains(&Verdict::Pass) {
                    return unknown(ReasonCode::MissingEvidence);
                }
            }
            (Verdict::Pass, ReasonCode::None)
        }
        "V13" if suffix == "bounded_samples" => {
            let Some(profile) = c.performance_profile.as_ref() else {
                return unknown(ReasonCode::ConfigInvalid);
            };
            let Some(details) = o.details.as_ref() else {
                return unknown(ReasonCode::MissingEvidence);
            };
            if details.sample_count > profile.samples {
                return (Verdict::Fail, ReasonCode::LimitExceeded);
            }
            let consistent = details.sample_count > 0
                && details.sample_count <= profile.samples
                && details.samples_ms.len().checked_add(details.error_count)
                    == Some(details.sample_count)
                && details.workload_id.as_ref() == Some(&profile.workload_id);
            if o.outcome == Outcome::Measured && has(o, &[Fact::SamplesBounded]) && consistent {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::MissingEvidence)
            }
        }
        "V13" => protocol::performance(c, row, all, plan, now),
        "V16" => {
            let fact = match suffix {
                "protocol" => Fact::ProtocolV3,
                "prepared_statement" => Fact::PreparedStatementUsed,
                "pool_reset" => Fact::PoolResetVerified,
                "session_state" => Fact::SessionIsolated,
                "long_transaction" => Fact::LongTransactionVerified,
                "pinning" => Fact::PinningObserved,
                _ => return unknown(ReasonCode::UnsupportedCase),
            };
            if authenticated(o) && has(o, &[fact]) {
                (Verdict::Pass, ReasonCode::None)
            } else {
                unknown(ReasonCode::MissingEvidence)
            }
        }
        _ => unknown(ReasonCode::UnsupportedCase),
    }
}

fn aggregate<'a>(rows: impl Iterator<Item = &'a CaseResult>) -> Verdict {
    let mut any = false;
    let mut unknown = false;
    for r in rows {
        any = true;
        match r.verdict {
            Verdict::Fail => return Verdict::Fail,
            Verdict::Pass => {}
            _ => unknown = true,
        }
    }
    if any && !unknown {
        Verdict::Pass
    } else {
        Verdict::Unknown
    }
}

fn evaluation_cases(config: &TargetConfig, plan: Option<&ExperimentPlan>) -> Vec<CaseResult> {
    let initial = required_cases(config);
    let Some(plan) = plan else {
        return initial;
    };
    if validate_experiment_plan(config, plan).is_err() {
        return initial;
    }
    let Some(protocol) = &plan.protocol else {
        return initial;
    };
    let mut rows = Vec::new();
    for row in initial {
        let mut assigned = false;
        if !is_local_case(config, &row.verification_id) {
            for phase in &protocol.phase_contracts {
                let allowed_kind = match row.verification_id.as_str() {
                    "V21" => phase.kind == PhaseKind::Cleanup,
                    "V11"
                        if matches!(
                            row.case_id.as_str(),
                            "V11.disconnect" | "V11.dns_failure" | "V11.unreachable"
                        ) =>
                    {
                        phase.kind == PhaseKind::Recovered
                    }
                    "V12" if row.case_id == "V12.recovered_revalidation" => {
                        phase.kind == PhaseKind::Recovered
                    }
                    _ => matches!(phase.kind, PhaseKind::Protected | PhaseKind::Recovered),
                };
                let declared = plan.phases.iter().any(|p| {
                    p.phase_id == phase.phase_id
                        && p.configuration_epoch == phase.configuration_epoch
                        && p.case_ids.contains(&row.case_id)
                });
                if allowed_kind && declared {
                    let mut scoped = row.clone();
                    scoped.phase_id = Some(phase.phase_id.clone());
                    rows.push(scoped);
                    assigned = true;
                }
            }
        }
        if !assigned {
            rows.push(row);
        }
    }
    rows
}

pub fn evaluate(
    config: &TargetConfig,
    observations: &[Observation],
    plan: Option<&ExperimentPlan>,
    now: u64,
) -> Assessment {
    let mut rows = evaluation_cases(config, plan);
    let invalid_plan = plan.is_some_and(|p| {
        p.schema_version != 1
            || p.experiment_id != config.experiment_id
            || p.profile != config.assessment_profile
            || (p.protocol.is_some() && validate_experiment_plan(config, p).is_err())
    });
    for row in &mut rows {
        let matching: Vec<_> = observations
            .iter()
            .filter(|o| {
                o.verification_id == row.verification_id
                    && o.case_id == row.case_id
                    && o.path_id == row.path_id
                    && row
                        .phase_id
                        .as_ref()
                        .is_none_or(|phase| phase == &o.phase_id)
            })
            .collect();
        for o in matching {
            let provenance_result = provenance(config, o, now, plan);
            let (verdict, reason) = match provenance_result {
                Err(r) => (Verdict::Unknown, r),
                Ok(()) if invalid_plan => (Verdict::Unknown, ReasonCode::EvidenceIncompatible),
                Ok(()) => decide(config, row, o, observations, now, plan),
            };
            if provenance_result.is_ok() {
                row.evidence_runs.push(o.run_id.clone());
                row.evidence_kinds.push(o.evidence_kind);
                row.executions.push(o.execution);
                row.source_ids.push(o.source_id.clone());
                row.source_verifications.push(o.source_verification);
                row.outcomes.push(o.outcome);
            }
            // A current definite failure cannot be overwritten by a later retry success.
            if row.verdict != Verdict::Fail
                && (verdict == Verdict::Fail
                    || verdict == Verdict::Pass
                    || row.verdict != Verdict::Pass)
            {
                row.verdict = verdict;
                row.reason_code = reason;
            }
        }
    }
    let verdict = aggregate(rows.iter());
    let configuration_verdict = aggregate(
        rows.iter()
            .filter(|r| matches!(r.verification_id.as_str(), "V02" | "V03" | "V15")),
    );
    let connection_verdict = if config.assessment_profile == Profile::LocalContractV1 {
        Verdict::Unknown
    } else {
        aggregate(rows.iter().filter(|r| {
            matches!(
                r.verification_id.as_str(),
                "V06" | "V07" | "V08" | "V09" | "V10" | "V11" | "V12" | "V13" | "V16"
            )
        }))
    };
    let mut limitations: Vec<_> = rows
        .iter()
        .filter(|r| r.verdict == Verdict::Unknown)
        .map(|r| r.reason_code)
        .collect();
    limitations.sort();
    limitations.dedup();
    Assessment {
        schema_version: 1,
        target_id: config.target.id.clone(),
        profile: config.assessment_profile,
        evaluated_at: now,
        verdict,
        configuration_verdict,
        connection_verdict,
        cases: rows,
        limitations,
    }
}
