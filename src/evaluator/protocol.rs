//! Cross-run validation of recorded observations, not network operations.
use super::{authenticated, has, sha256};
use crate::{config, domain::*};
use serde_json::Value;

pub fn plan_hash(plan: &ExperimentPlan) -> String {
    config::hash_bytes(&serde_json::to_vec(plan).unwrap_or_default())
}

/// Validate a capture protocol before any network/DB operation. Legacy plans can
/// still be read, but cannot authorize a new cross-phase capture protocol.
pub fn validate_experiment_plan(c: &TargetConfig, plan: &ExperimentPlan) -> Result<(), ReasonCode> {
    let invalid = ReasonCode::EvidenceIncompatible;
    if plan.schema_version != 1
        || plan.experiment_id != c.experiment_id
        || plan.profile != c.assessment_profile
    {
        return Err(invalid);
    }
    let p = plan.protocol.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    if p.phase_contracts.is_empty()
        || p.phase_contracts.len() > 32
        || p.phase_contracts.len() != plan.phases.len()
        || p.transitions.len() > 128
        || p.comparisons.len() > 128
    {
        return Err(invalid);
    }
    let known: std::collections::BTreeSet<_> = super::required_cases(c)
        .into_iter()
        .map(|r| r.case_id)
        .collect();
    let mut ids = std::collections::BTreeSet::new();
    let mut refs = std::collections::BTreeSet::new();
    for phase in &p.phase_contracts {
        if !ids.insert(&phase.phase_id)
            || config::validate_config(&phase.config).is_err()
            || phase.config.target != c.target
            || phase.config.experiment_id != c.experiment_id
            || phase.config.assessment_profile != c.assessment_profile
            || phase.config.phase_id != phase.phase_id
            || phase.config.configuration_epoch != phase.configuration_epoch
            || p.planned_at > phase.starts_at
            || phase.starts_at > phase.ends_at
            || !config::safe_id(&phase.before_snapshot_ref)
            || !config::safe_id(&phase.after_snapshot_ref)
            || !refs.insert(&phase.before_snapshot_ref)
            || !refs.insert(&phase.after_snapshot_ref)
        {
            return Err(invalid);
        }
        if matches!(phase.kind, PhaseKind::Protected | PhaseKind::Recovered) {
            let mut source_a: Vec<_> = c.sources.iter().map(|s| (&s.id, s.kind)).collect();
            source_a.sort();
            let mut source_b: Vec<_> = phase
                .config
                .sources
                .iter()
                .map(|s| (&s.id, s.kind))
                .collect();
            source_b.sort();
            let mut paths_a = c.paths.clone();
            paths_a.sort_by(|a, b| a.id.cmp(&b.id));
            let mut paths_b = phase.config.paths.clone();
            paths_b.sort_by(|a, b| a.id.cmp(&b.id));
            if source_a != source_b
                || serde_json::to_value(paths_a).ok() != serde_json::to_value(paths_b).ok()
            {
                return Err(invalid);
            }
        }
        let declarations: Vec<_> = plan
            .phases
            .iter()
            .filter(|d| d.phase_id == phase.phase_id)
            .collect();
        if declarations.len() != 1 {
            return Err(invalid);
        }
        let d = declarations[0];
        let unique: std::collections::BTreeSet<_> = d.case_ids.iter().collect();
        if d.configuration_epoch != phase.configuration_epoch
            || d.target_id != c.target.id
            || d.config_hash != config::config_hash(&phase.config)
            || unique.len() != d.case_ids.len()
            || d.case_ids.len() > c.limits.max_results
            || d.case_ids.iter().any(|id| !known.contains(id))
        {
            return Err(invalid);
        }
    }
    if p.phase_contracts
        .windows(2)
        .any(|w| w[0].ends_at > w[1].starts_at)
    {
        return Err(invalid);
    }
    let mut transitions = std::collections::BTreeSet::new();
    for t in &p.transitions {
        let from = p
            .phase_contracts
            .iter()
            .position(|p| p.phase_id == t.from_phase)
            .ok_or(invalid)?;
        let to = p
            .phase_contracts
            .iter()
            .position(|p| p.phase_id == t.to_phase)
            .ok_or(invalid)?;
        if from >= to
            || !transitions.insert((&t.from_phase, &t.to_phase, t.fault))
            || t.case_ids.is_empty()
            || t.case_ids.iter().any(|id| !known.contains(id))
        {
            return Err(invalid);
        }
        let fields: std::collections::BTreeSet<_> =
            t.allowed_changes.iter().map(|c| c.field).collect();
        if fields.len() != t.allowed_changes.len()
            || t.allowed_changes
                .iter()
                .any(|d| !sha256(&d.before_value_hash) || !sha256(&d.after_value_hash))
        {
            return Err(invalid);
        }
    }
    for comparison in &p.comparisons {
        if !matches!(
            comparison.case_id.as_str(),
            "V13.connection_setup" | "V13.pooled_query" | "V13.pinning" | "V13.errors"
        ) || comparison.minimum_success_samples < 20
            || comparison.max_p95_ms == 0
            || !comparison.max_error_rate.is_finite()
            || !(0.0..=1.0).contains(&comparison.max_error_rate)
            || !sha256(&comparison.conditions.workload_hash)
            || !config::safe_id(&comparison.conditions.workload_id)
            || !config::safe_id(&comparison.conditions.driver_version)
            || !config::safe_id(&comparison.conditions.db_resource_id)
            || comparison
                .conditions
                .db_instance_class
                .as_ref()
                .is_none_or(|s| !config::safe_id(s))
            || comparison.conditions.pinning.is_none()
            || !comparison.conditions.tls_verified
            || !conditions_grammar(&comparison.conditions)
        {
            return Err(invalid);
        }
        let a = p
            .phase_contracts
            .iter()
            .find(|p| p.phase_id == comparison.baseline_phase)
            .ok_or(invalid)?;
        let b = p
            .phase_contracts
            .iter()
            .find(|p| p.phase_id == comparison.protected_phase)
            .ok_or(invalid)?;
        if a.kind != PhaseKind::Baseline
            || !matches!(b.kind, PhaseKind::Protected | PhaseKind::Recovered)
        {
            return Err(invalid);
        }
        let ap = a
            .config
            .paths
            .iter()
            .find(|p| p.id == comparison.baseline_path && p.destination == Destination::Database)
            .ok_or(invalid)?;
        let bp = b
            .config
            .paths
            .iter()
            .find(|p| p.id == comparison.protected_path && p.destination == Destination::Proxy)
            .ok_or(invalid)?;
        if ap.source_id != bp.source_id
            || ap.address_family != bp.address_family
            || ap.expected != Expectation::Allow
            || bp.expected != Expectation::Allow
        {
            return Err(invalid);
        }
        let asource = a
            .config
            .sources
            .iter()
            .find(|s| s.id == ap.source_id)
            .ok_or(invalid)?;
        let bsource = b
            .config
            .sources
            .iter()
            .find(|s| s.id == bp.source_id)
            .ok_or(invalid)?;
        if asource.kind != bsource.kind {
            return Err(invalid);
        }
        for phase in [a, b] {
            let profile = phase.config.performance_profile.as_ref().ok_or(invalid)?;
            if comparison.conditions.workload_id != profile.workload_id
                || comparison.conditions.db_user != phase.config.auth.db_user
                || comparison.conditions.engine_version != phase.config.target.engine_version
                || comparison.conditions.concurrency != phase.config.limits.max_concurrency
                || comparison.conditions.retries != phase.config.limits.max_retries
                || comparison.conditions.warmup != profile.warmup
                || comparison.minimum_success_samples > profile.samples
                || comparison.max_p95_ms != profile.max_p95_ms
                || comparison.max_error_rate != profile.max_error_rate
            {
                return Err(invalid);
            }
        }
    }
    if let Some(m) = &p.management
        && (management(Some(plan)).is_none()
            || !principal(&m.admin_principal_arn, &c.target.account_id)
            || !principal(&m.application_principal_arn, &c.target.account_id))
    {
        return Err(invalid);
    }
    Ok(())
}

/// Importers must match nested snapshots to the actual, manifest-verified artifacts.
/// The tuple key is the file's artifact hash; the snapshot hash is canonical content.
pub fn validate_protocol_links(o: &Observation, imported: &[(String, InventorySnapshot)]) -> bool {
    let Some(p) = o.details.as_ref().and_then(|d| d.protocol.as_ref()) else {
        return true;
    };
    [&p.before, &p.after].into_iter().flatten().all(|e| {
        o.evidence_refs.contains(&e.artifact_hash)
            && imported.iter().any(|(hash, snapshot)| {
                hash == &e.artifact_hash
                    && config::snapshot_hash(snapshot) == config::snapshot_hash(&e.snapshot)
            })
    })
}

pub(super) fn phase_config<'a>(
    c: &TargetConfig,
    o: &Observation,
    plan: Option<&'a ExperimentPlan>,
) -> Option<&'a TargetConfig> {
    let p = plan?;
    if p.schema_version != 1
        || p.experiment_id != c.experiment_id
        || p.profile != c.assessment_profile
    {
        return None;
    }
    let phase = p
        .protocol
        .as_ref()?
        .phase_contracts
        .iter()
        .find(|p| p.phase_id == o.phase_id && p.configuration_epoch == o.configuration_epoch)?;
    if phase.config.target != c.target
        || phase.config.assessment_profile != c.assessment_profile
        || phase.config.experiment_id != c.experiment_id
        || phase.config.phase_id != o.phase_id
        || phase.config.configuration_epoch != o.configuration_epoch
        || config::config_hash(&phase.config) != o.config_hash
        || config::validate_config(&phase.config).is_err()
    {
        return None;
    }
    Some(&phase.config)
}

fn observation_protocol(o: &Observation) -> Result<&ObservationProtocol, ReasonCode> {
    o.details
        .as_ref()
        .and_then(|d| d.protocol.as_ref())
        .ok_or(ReasonCode::MissingEvidence)
}

fn principal(s: &str, account: &str) -> bool {
    let p: Vec<_> = s.splitn(6, ':').collect();
    p.len() == 6
        && p[0] == "arn"
        && p[1] == "aws"
        && matches!(p[2], "iam" | "sts")
        && p[3].is_empty()
        && p[4] == account
        && !p[5].is_empty()
        && s.len() <= 1024
        && p[5]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/+=,.@_-".contains(&b))
        && ["role/", "user/", "assumed-role/"]
            .iter()
            .any(|prefix| p[5].starts_with(prefix))
}

fn conditions_grammar(m: &MeasurementConditions) -> bool {
    [
        m.workload_id.as_str(),
        m.driver_version.as_str(),
        m.db_resource_id.as_str(),
        m.engine_version.as_str(),
    ]
    .iter()
    .all(|s| config::safe_id(s))
        && sha256(&m.workload_hash)
        && config::sql_id(&m.db_user)
        && (1..=32).contains(&m.concurrency)
        && m.warmup <= 1000
        && m.retries <= 3
        && [
            &m.db_instance_class,
            &m.availability_zone,
            &m.runner_os,
            &m.runner_arch,
        ]
        .into_iter()
        .flatten()
        .all(|s| config::safe_id(s))
        && m.runner_identity_hash.as_ref().is_none_or(|s| sha256(s))
}

/// Grammar/size checks for capture and import; missing data is not promoted.
pub fn validate_observation_protocol(o: &Observation, c: &TargetConfig) -> Result<(), ReasonCode> {
    let Some(p) = o.details.as_ref().and_then(|d| d.protocol.as_ref()) else {
        return Ok(());
    };
    let bad = ReasonCode::EvidenceIncompatible;
    if (!p.plan_hash.is_empty() && !sha256(&p.plan_hash))
        || o.evidence_refs.len() > c.limits.max_results
    {
        return Err(bad);
    }
    for e in [&p.before, &p.after].into_iter().flatten() {
        let s = &e.snapshot;
        if !config::safe_id(&e.reference_id)
            || !sha256(&e.artifact_hash)
            || !sha256(&p.plan_hash)
            || s.target != c.target
            || s.config_hash != o.config_hash
            || s.schema_version != 1
            || s.security_groups.len() > c.limits.max_results
            || s.retrievals.len() > 6
        {
            return Err(bad);
        }
        if let Some(db) = &s.db
            && (db.arn != c.target.db_instance_arn
                || !config::safe_id(&db.resource_id)
                || !config::valid_endpoint(&db.endpoint)
                || !config::safe_id(&db.engine)
                || !config::safe_id(&db.engine_version)
                || [
                    &db.parameter_group,
                    &db.instance_class,
                    &db.availability_zone,
                ]
                .into_iter()
                .flatten()
                .any(|s| !config::safe_id(s))
                || db.security_group_ids.len() > 32
                || db.security_group_ids.iter().any(|s| !config::safe_id(s)))
        {
            return Err(bad);
        }
        if let Some(proxy) = &s.proxy
            && (proxy.arn != c.target.proxy_arn
                || !config::valid_endpoint(&proxy.endpoint)
                || !principal(&proxy.role_arn, &c.target.account_id)
                || proxy.security_group_ids.len() > 32
                || proxy.security_group_ids.iter().any(|s| !config::safe_id(s))
                || proxy
                    .target_db_resource_id
                    .as_ref()
                    .is_some_and(|s| !config::safe_id(s)))
        {
            return Err(bad);
        }
        for group in &s.security_groups {
            if !config::safe_id(&group.id)
                || !config::safe_id(&group.vpc_id)
                || group.ingress.len() > c.limits.max_results
            {
                return Err(bad);
            }
            for rule in &group.ingress {
                if !["tcp", "udp", "icmp", "icmpv6", "6", "17", "1", "58", "-1"]
                    .contains(&rule.protocol.as_str())
                {
                    return Err(bad);
                }
                let valid = match &rule.source {
                    RuleSource::SecurityGroup { id } => config::safe_id(id),
                    RuleSource::Ipv4 { cidr } => cidr.parse::<ipnet::Ipv4Net>().is_ok(),
                    RuleSource::Ipv6 { cidr } => cidr.parse::<ipnet::Ipv6Net>().is_ok(),
                };
                if !valid {
                    return Err(bad);
                }
            }
        }
        let ops = [
            "describe-db-proxies",
            "describe-db-instances",
            "describe-db-proxy-target-groups",
            "describe-db-proxy-targets",
            "describe-db-parameters",
            "describe-security-groups",
        ];
        if s.retrievals
            .iter()
            .any(|r| !ops.contains(&r.operation.as_str()))
        {
            return Err(bad);
        }
    }
    if p.operation
        .as_ref()
        .is_some_and(|op| !config::safe_id(&op.operation_id))
        || p.identity.as_ref().is_some_and(|i| {
            !principal(&i.iam_principal_arn, &c.target.account_id)
                || !config::sql_id(&i.requested_db_user)
                || i.authenticated_db_user
                    .as_ref()
                    .is_some_and(|u| !config::sql_id(u))
        })
        || p.measurement
            .as_ref()
            .is_some_and(|m| !conditions_grammar(m))
        || p.pinning.as_ref().is_some_and(|p| {
            p.pinned_connections.len() > c.limits.max_results || p.starts_at > p.ends_at
        })
    {
        return Err(bad);
    }
    Ok(())
}

fn complete_snapshot(s: &InventorySnapshot, c: &TargetConfig) -> bool {
    let required = [
        "describe-db-proxies",
        "describe-db-instances",
        "describe-db-proxy-target-groups",
        "describe-db-proxy-targets",
        "describe-db-parameters",
        "describe-security-groups",
    ];
    if s.schema_version != 1
        || s.evidence_kind != EvidenceKind::AwsConfiguration
        || s.target != c.target
        || s.config_hash != config::config_hash(c)
        || s.retrievals.is_empty()
        || s.retrievals
            .iter()
            .any(|r| r.status != RetrievalStatus::Complete)
    {
        return false;
    }
    if required.iter().any(|name| {
        s.retrievals
            .iter()
            .filter(|r| r.operation == *name && r.status == RetrievalStatus::Complete)
            .count()
            != 1
    }) {
        return false;
    }
    let (Some(db), Some(proxy)) = (&s.db, &s.proxy) else {
        return false;
    };
    db.arn == c.target.db_instance_arn
        && proxy.arn == c.target.proxy_arn
        && db.engine == c.target.engine
        && db.engine_version == c.target.engine_version
        && proxy.target_db_resource_id.as_ref() == Some(&db.resource_id)
}

fn state(s: &InventorySnapshot) -> Value {
    serde_json::json!({"target": s.target, "db": s.db, "proxy": s.proxy,
        "security_groups": s.security_groups, "retrievals": s.retrievals})
}

fn pointer(f: SnapshotField) -> &'static str {
    match f {
        SnapshotField::DbEndpoint => "/db/endpoint",
        SnapshotField::ProxyEndpoint => "/proxy/endpoint",
        SnapshotField::DbSecurityGroups => "/db/security_group_ids",
        SnapshotField::ProxySecurityGroups => "/proxy/security_group_ids",
        SnapshotField::SecurityGroupRules => "/security_groups",
        SnapshotField::DbIam => "/db/iam_auth_enabled",
        SnapshotField::ProxyAuth => "/proxy/auth_mode",
        SnapshotField::ProxyTls => "/proxy/require_tls",
        SnapshotField::DbTls => "/db/force_ssl",
        SnapshotField::ParametersInSync => "/db/parameters_in_sync",
        SnapshotField::TargetHealth => "/proxy/target_health",
    }
}

pub fn field_hash(s: &InventorySnapshot, f: SnapshotField) -> String {
    config::hash_bytes(
        &serde_json::to_vec(state(s).pointer(pointer(f)).unwrap_or(&Value::Null))
            .unwrap_or_default(),
    )
}

fn permitted_difference(
    before: &InventorySnapshot,
    after: &InventorySnapshot,
    allowed: &[AllowedStateChange],
) -> bool {
    let mut a = state(before);
    let mut b = state(after);
    let mut seen = std::collections::BTreeSet::new();
    for change in allowed {
        if !seen.insert(change.field)
            || !sha256(&change.before_value_hash)
            || !sha256(&change.after_value_hash)
            || field_hash(before, change.field) != change.before_value_hash
            || field_hash(after, change.field) != change.after_value_hash
        {
            return false;
        }
        let p = pointer(change.field);
        let (Some(x), Some(y)) = (a.pointer_mut(p), b.pointer_mut(p)) else {
            return false;
        };
        *x = Value::Null;
        *y = Value::Null;
    }
    a == b
}

pub(super) fn context<'a>(
    c: &TargetConfig,
    o: &'a Observation,
    plan: &'a ExperimentPlan,
    now: u64,
) -> Result<(&'a PhaseContract, &'a ObservationProtocol), ReasonCode> {
    if o.schema_version != 1
        || o.build_id != crate::BUILD_ID
        || o.assessment_profile != c.assessment_profile
        || o.experiment_id != c.experiment_id
        || o.target_id != c.target.id
        || !config::safe_id(&o.run_id)
        || !config::safe_id(&o.attempt_id)
        || o.observed_at > now
        || now.saturating_sub(o.observed_at) > c.evidence_policy.max_age_seconds
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    let protocol = plan.protocol.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    validate_observation_protocol(o, c)?;
    let phase = protocol
        .phase_contracts
        .iter()
        .find(|p| p.phase_id == o.phase_id && p.configuration_epoch == o.configuration_epoch)
        .ok_or(ReasonCode::EvidenceIncompatible)?;
    let declared = plan
        .phases
        .iter()
        .find(|p| p.phase_id == o.phase_id && p.configuration_epoch == o.configuration_epoch)
        .ok_or(ReasonCode::EvidenceIncompatible)?;
    if protocol
        .phase_contracts
        .iter()
        .filter(|p| p.phase_id == o.phase_id)
        .count()
        != 1
        || plan
            .phases
            .iter()
            .filter(|p| p.phase_id == o.phase_id)
            .count()
            != 1
        || (o.path_id == "global" && o.source_id != "global")
        || (o.path_id != "global"
            && !phase
                .config
                .paths
                .iter()
                .any(|p| p.id == o.path_id && p.source_id == o.source_id))
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    if phase_config(c, o, Some(plan)).is_none()
        || declared.config_hash != o.config_hash
        || declared.target_id != o.target_id
        || !declared.case_ids.contains(&o.case_id)
        || protocol.planned_at > phase.starts_at
        || phase.starts_at > phase.ends_at
        || o.observed_at < phase.starts_at
        || o.observed_at.saturating_add(o.duration_ms.div_ceil(1000)) > phase.ends_at
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    let observed = observation_protocol(o)?;
    if observed.plan_hash != plan_hash(plan) {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    let before = observed
        .before
        .as_ref()
        .ok_or(ReasonCode::MissingEvidence)?;
    let after = observed.after.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    if before.reference_id != phase.before_snapshot_ref
        || after.reference_id != phase.after_snapshot_ref
        || before.reference_id == after.reference_id
        || !sha256(&before.artifact_hash)
        || !sha256(&after.artifact_hash)
        || !o.evidence_refs.contains(&before.artifact_hash)
        || !o.evidence_refs.contains(&after.artifact_hash)
        || config::snapshot_hash(&before.snapshot) != o.snapshot_hash
        || !complete_snapshot(&before.snapshot, &phase.config)
        || !complete_snapshot(&after.snapshot, &phase.config)
        || before.snapshot.observed_at < phase.starts_at
        || before.snapshot.observed_at > o.observed_at
        || after.snapshot.observed_at < o.observed_at.saturating_add(o.duration_ms.div_ceil(1000))
        || after.snapshot.observed_at > phase.ends_at
        || after.snapshot.observed_at > now
        || now.saturating_sub(before.snapshot.observed_at) > c.evidence_policy.max_age_seconds
        || state(&before.snapshot) != state(&after.snapshot)
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    Ok((phase, observed))
}

fn transition<'a>(
    c: &TargetConfig,
    from: &'a Observation,
    to: &'a Observation,
    plan: &'a ExperimentPlan,
    now: u64,
    fault: Option<FaultKind>,
) -> Result<(), ReasonCode> {
    let (from_phase, a) = context(c, from, plan, now)?;
    let (to_phase, b) = context(c, to, plan, now)?;
    let p = plan.protocol.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    let t = p
        .transitions
        .iter()
        .find(|t| {
            t.from_phase == from.phase_id
                && t.to_phase == to.phase_id
                && t.fault == fault
                && t.case_ids.contains(&to.case_id)
        })
        .ok_or(ReasonCode::MissingEvidence)?;
    let before = a.after.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    let after = b.before.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    if from_phase.ends_at > to_phase.starts_at
        || from.observed_at > to.observed_at
        || from.source_id != to.source_id
        || from.build_id != to.build_id
        || !permitted_difference(&before.snapshot, &after.snapshot, &t.allowed_changes)
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    Ok(())
}

fn postcondition(o: &Observation, expected_fault: FaultKind) -> Result<(), ReasonCode> {
    let operation = observation_protocol(o)?
        .operation
        .as_ref()
        .ok_or(ReasonCode::MissingEvidence)?;
    if !config::safe_id(&operation.operation_id)
        || operation.fault != Some(expected_fault)
        || operation.expected_rows != 1
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    if operation.observed_rows != operation.expected_rows
        || operation.replay_attempts != 0
        || operation.write_attempts > 1
    {
        return Err(ReasonCode::WriteOutcomeUnknown);
    }
    if expected_fault == FaultKind::AmbiguousCommit && operation.write_attempts != 1 {
        return Err(ReasonCode::MissingEvidence);
    }
    Ok(())
}

pub(super) fn operation(
    c: &TargetConfig,
    o: &Observation,
    plan: Option<&ExperimentPlan>,
    now: u64,
    fault: FaultKind,
) -> (Verdict, ReasonCode) {
    let Some(plan) = plan else {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    };
    if let Err(r) = context(c, o, plan, now) {
        return (Verdict::Unknown, r);
    }
    match postcondition(o, fault) {
        Ok(()) => (Verdict::Pass, ReasonCode::None),
        Err(ReasonCode::WriteOutcomeUnknown) => (Verdict::Fail, ReasonCode::WriteOutcomeUnknown),
        Err(r) => (Verdict::Unknown, r),
    }
}

pub(super) fn recovery(
    c: &TargetConfig,
    row: &CaseResult,
    o: &Observation,
    all: &[Observation],
    plan: Option<&ExperimentPlan>,
    now: u64,
) -> (Verdict, ReasonCode) {
    let Some(plan) = plan else {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    };
    let kind = match row.case_id.as_str() {
        "V11.disconnect" => FaultKind::Disconnect,
        "V11.dns_failure" => FaultKind::DnsFailure,
        "V11.unreachable" => FaultKind::Unreachable,
        _ => return (Verdict::Unknown, ReasonCode::UnsupportedCase),
    };
    if let Err(r) = context(c, o, plan, now) {
        return (Verdict::Unknown, r);
    }
    if !authenticated(o) || !has(o, &[Fact::PostconditionVerified, Fact::NoWriteReplay]) {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    }
    if let Err(r) = postcondition(o, kind) {
        return (
            if r == ReasonCode::WriteOutcomeUnknown {
                Verdict::Fail
            } else {
                Verdict::Unknown
            },
            r,
        );
    }
    let current = observation_protocol(o).unwrap().operation.as_ref().unwrap();
    let fault = all.iter().find(|f| {
        f.case_id == o.case_id
            && f.path_id == o.path_id
            && f.phase_id != o.phase_id
            && f.evidence_kind == EvidenceKind::AwsConnection
            && f.source_verification == SourceVerification::Corroborated
            && f.build_id == crate::BUILD_ID
            && f.execution == Execution::Completed
            && observation_protocol(f)
                .ok()
                .and_then(|p| p.operation.as_ref())
                .is_some_and(|op| {
                    op.operation_id == current.operation_id
                        && op.fault == Some(kind)
                        && op.replay_attempts == 0
                })
            && match kind {
                FaultKind::DnsFailure => {
                    f.outcome == Outcome::ConnectionNotEstablished
                        && f.reason_code == ReasonCode::NetworkUnreachable
                }
                FaultKind::Unreachable => {
                    f.outcome == Outcome::ConnectionNotEstablished
                        && f.path_stages.transport_reachable != Stage::ObservedTrue
                }
                _ => f.outcome == Outcome::Interrupted,
            }
            && transition(c, f, o, plan, now, Some(kind)).is_ok()
    });
    if fault.is_some() {
        (Verdict::Pass, ReasonCode::None)
    } else {
        (Verdict::Unknown, ReasonCode::MissingEvidence)
    }
}

fn management(plan: Option<&ExperimentPlan>) -> Option<&ManagementContract> {
    let m = plan?.protocol.as_ref()?.management.as_ref()?;
    if m.admin_principal_arn == m.application_principal_arn
        || m.admin_db_user == m.application_db_user
        || !config::sql_id(&m.admin_db_user)
        || !config::sql_id(&m.application_db_user)
        || !m.admin_principal_arn.starts_with("arn:aws:")
        || !m.application_principal_arn.starts_with("arn:aws:")
    {
        return None;
    }
    Some(m)
}

pub(super) fn admin_identity(
    c: &TargetConfig,
    o: &Observation,
    plan: Option<&ExperimentPlan>,
    now: u64,
    admin: bool,
) -> Result<(), ReasonCode> {
    let m = management(plan).ok_or(ReasonCode::MissingEvidence)?;
    let plan = plan.ok_or(ReasonCode::MissingEvidence)?;
    context(c, o, plan, now)?;
    let identity = observation_protocol(o)?
        .identity
        .as_ref()
        .ok_or(ReasonCode::MissingEvidence)?;
    let expected_principal = if admin {
        &m.admin_principal_arn
    } else {
        &m.application_principal_arn
    };
    if &identity.iam_principal_arn != expected_principal
        || identity.requested_db_user != m.admin_db_user
        || (admin && identity.authenticated_db_user.as_ref() != Some(&m.admin_db_user))
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    Ok(())
}

fn quantile95(samples: &[u64]) -> Option<u64> {
    if samples.len() < 20 {
        return None;
    }
    let mut s = samples.to_vec();
    s.sort_unstable();
    s.get((s.len() * 95).div_ceil(100).saturating_sub(1))
        .copied()
}

fn measurement(
    c: &TargetConfig,
    o: &Observation,
    planned: &PerformanceComparison,
    plan: &ExperimentPlan,
    now: u64,
    baseline: bool,
) -> Result<(), ReasonCode> {
    let (phase, p) = context(c, o, plan, now)?;
    let details = o.details.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    let conditions = p.measurement.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    let profile = phase
        .config
        .performance_profile
        .as_ref()
        .ok_or(ReasonCode::ConfigInvalid)?;
    let expected_phase = if baseline {
        &planned.baseline_phase
    } else {
        &planned.protected_phase
    };
    let expected_path = if baseline {
        &planned.baseline_path
    } else {
        &planned.protected_path
    };
    let expected_destination = if baseline {
        Destination::Database
    } else {
        Destination::Proxy
    };
    let observed_snapshot = &p.before.as_ref().unwrap().snapshot;
    if &o.phase_id != expected_phase
        || &o.path_id != expected_path
        || o.evidence_kind != EvidenceKind::AwsConnection
        || o.source_verification != SourceVerification::Corroborated
        || o.execution != Execution::Completed
        || o.outcome != Outcome::Measured
        || details.connection_mode != Some(expected_destination)
        || conditions != &planned.conditions
        || conditions.db_resource_id != observed_snapshot.db.as_ref().unwrap().resource_id
        || conditions.db_instance_class != observed_snapshot.db.as_ref().unwrap().instance_class
        || conditions.availability_zone != observed_snapshot.db.as_ref().unwrap().availability_zone
        || conditions.availability_zone.is_none()
        || conditions.runner_os.is_none()
        || conditions.runner_arch.is_none()
        || conditions.runner_identity_hash.is_none()
        || conditions.engine_version != observed_snapshot.target.engine_version
        || conditions.db_user != phase.config.auth.db_user
        || conditions
            .db_instance_class
            .as_ref()
            .is_none_or(|s| s.is_empty())
        || !sha256(&conditions.workload_hash)
        || !conditions.tls_verified
        || conditions.pinning.is_none()
        || conditions.concurrency != phase.config.limits.max_concurrency
        || conditions.retries != phase.config.limits.max_retries
        || conditions.warmup != profile.warmup
        || conditions.workload_id != profile.workload_id
        || details.workload_id.as_ref() != Some(&conditions.workload_id)
        || details.sample_count != details.samples_ms.len().saturating_add(details.error_count)
        || details.sample_count > profile.samples
        || details.samples_ms.len() < planned.minimum_success_samples
        || planned.minimum_success_samples < 20
        || quantile95(&details.samples_ms) != details.p95_ms
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    let pinning = p.pinning.as_ref().ok_or(ReasonCode::MissingEvidence)?;
    if pinning.starts_at > o.observed_at
        || pinning.ends_at < o.observed_at.saturating_add(o.duration_ms.div_ceil(1000))
        || pinning.pinned_connections.len() < 2
        || pinning.ends_at > phase.ends_at
    {
        return Err(ReasonCode::MissingEvidence);
    }
    let max = pinning
        .pinned_connections
        .iter()
        .max()
        .copied()
        .unwrap_or(0);
    if matches!(conditions.pinning, Some(PinningScenario::NonPinned)) && max != 0
        || matches!(conditions.pinning, Some(PinningScenario::Pinned)) && max == 0
    {
        return Err(ReasonCode::EvidenceIncompatible);
    }
    Ok(())
}

pub(super) fn performance(
    c: &TargetConfig,
    row: &CaseResult,
    all: &[Observation],
    plan: Option<&ExperimentPlan>,
    now: u64,
) -> (Verdict, ReasonCode) {
    let Some(plan) = plan else {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    };
    let Some(protocol) = &plan.protocol else {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    };
    let comparisons: Vec<_> = protocol
        .comparisons
        .iter()
        .filter(|p| {
            p.case_id == row.case_id
                && p.protected_path == row.path_id
                && row.phase_id.as_deref() == Some(p.protected_phase.as_str())
        })
        .collect();
    let required: &[(MeasurementKind, PinningScenario)] = match row.case_id.as_str() {
        "V13.connection_setup" => &[(MeasurementKind::ConnectionSetup, PinningScenario::NonPinned)],
        "V13.pooled_query" => &[(MeasurementKind::PooledQuery, PinningScenario::NonPinned)],
        "V13.pinning" => &[
            (MeasurementKind::PooledQuery, PinningScenario::NonPinned),
            (MeasurementKind::PooledQuery, PinningScenario::Pinned),
        ],
        "V13.errors" => &[
            (MeasurementKind::ConnectionSetup, PinningScenario::NonPinned),
            (MeasurementKind::PooledQuery, PinningScenario::NonPinned),
            (MeasurementKind::PooledQuery, PinningScenario::Pinned),
        ],
        _ => return (Verdict::Unknown, ReasonCode::UnsupportedCase),
    };
    if required.iter().any(|(kind, pinning)| {
        !comparisons
            .iter()
            .any(|p| p.conditions.kind == *kind && p.conditions.pinning == Some(*pinning))
    }) {
        return (Verdict::Unknown, ReasonCode::MissingEvidence);
    }
    let Some(profile) = &c.performance_profile else {
        return (Verdict::Unknown, ReasonCode::ConfigInvalid);
    };
    for comparison in comparisons {
        if comparison.max_p95_ms != profile.max_p95_ms
            || comparison.max_error_rate != profile.max_error_rate
            || !comparison.max_error_rate.is_finite()
            || !(0.0..=1.0).contains(&comparison.max_error_rate)
        {
            return (Verdict::Unknown, ReasonCode::EvidenceIncompatible);
        }
        let baseline: Vec<_> = all
            .iter()
            .filter(|o| {
                o.case_id == row.case_id && measurement(c, o, comparison, plan, now, true).is_ok()
            })
            .collect();
        let protected: Vec<_> = all
            .iter()
            .filter(|o| {
                o.case_id == row.case_id && measurement(c, o, comparison, plan, now, false).is_ok()
            })
            .collect();
        let mut paired = false;
        for b in protected {
            if baseline
                .iter()
                .any(|a| a.source_id == b.source_id && transition(c, a, b, plan, now, None).is_ok())
            {
                paired = true;
                let d = b.details.as_ref().unwrap();
                if quantile95(&d.samples_ms).unwrap_or(u64::MAX) > comparison.max_p95_ms
                    || d.error_count as f64 / d.sample_count as f64 > comparison.max_error_rate
                {
                    return (Verdict::Fail, ReasonCode::LimitExceeded);
                }
            }
        }
        if !paired {
            return (Verdict::Unknown, ReasonCode::MissingEvidence);
        }
    }
    (Verdict::Pass, ReasonCode::None)
}
