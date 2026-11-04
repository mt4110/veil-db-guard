use super::model::*;
use crate::config::{GuardError, MAX_INPUT_BYTES, hash_bytes, read_bounded, safe_id, sql_id};
use std::{collections::BTreeSet, path::Path};

pub fn load_config(path: &Path) -> Result<GcpConfig, GuardError> {
    parse_config(&read_bounded(path, MAX_INPUT_BYTES)?)
}
pub fn parse_config(bytes: &[u8]) -> Result<GcpConfig, GuardError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(GuardError::LimitExceeded);
    }
    if bytes.iter().any(|b| b"&*!".contains(b)) {
        return Err(GuardError::ConfigInvalid);
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_reader_input_bytes = Some(MAX_INPUT_BYTES);
    budget.max_depth = 24;
    budget.max_nodes = 20_000;
    budget.max_events = 40_000;
    budget.max_total_scalar_bytes = MAX_INPUT_BYTES;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_documents = 1;
    budget.max_merge_keys = 0;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let c: GcpConfig = serde_saphyr::from_slice_with_options(bytes, options)
        .map_err(|_| GuardError::ConfigInvalid)?;
    validate_config(&c)?;
    Ok(c)
}
fn resource_id(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn config_hash(c: &GcpConfig) -> String {
    hash_bytes(&serde_json::to_vec(c).expect("typed configuration serializes"))
}
pub fn history_compatibility_hash(c: &GcpConfig) -> String {
    let mut stable = c.clone();
    stable.permission_changes.clear();
    config_hash(&stable)
}
pub fn validate_config(c: &GcpConfig) -> Result<(), GuardError> {
    let bad = GuardError::ConfigInvalid;
    if c.schema_version != 1
        || !resource_id(&c.target.project_id, 6, 30)
        || !resource_id(&c.target.instance_id, 1, 98)
        || !sql_id(&c.target.database)
    {
        return Err(bad);
    }
    if c.target.region != "asia-northeast1" || c.target.engine_version != "POSTGRES_16_15" {
        return Err(GuardError::UnsupportedTarget);
    }
    if c.principals.is_empty()
        || c.principals.len() > 8
        || c.cases.is_empty()
        || c.cases.len() > 64
        || c.permission_changes.len() > 32
    {
        return Err(bad);
    }
    let mut ids = BTreeSet::new();
    let mut emails = BTreeSet::new();
    let suffix = format!("@{}.iam.gserviceaccount.com", c.target.project_id);
    for p in &c.principals {
        if !safe_id(&p.id)
            || !ids.insert(&p.id)
            || !emails.insert(&p.service_account)
            || !p
                .service_account
                .strip_suffix(&suffix)
                .is_some_and(|s| resource_id(s, 6, 30))
            || p.db_user().len() > 63
        {
            return Err(GuardError::ConfigInvalid);
        }
    }
    let mut cases = BTreeSet::new();
    for case in &c.cases {
        if !safe_id(&case.id)
            || !cases.insert(&case.id)
            || !ids.contains(&case.principal_id)
            || (case.expected == GcpExpectation::Allow && case.expected_denial.is_some())
            || (case.expected_denial == Some(GcpDenial::ConnectIam)
                && case.route != GcpRoute::Proxy)
            || (case.expected_denial == Some(GcpDenial::NetworkBlocked)
                && case.route != GcpRoute::Direct)
        {
            return Err(GuardError::ConfigInvalid);
        }
    }
    let l = &c.limits;
    if l.connect_timeout_ms == 0
        || l.query_timeout_ms == 0
        || l.total_timeout_ms == 0
        || l.connect_timeout_ms > l.total_timeout_ms
        || l.query_timeout_ms > l.total_timeout_ms
        || l.total_timeout_ms > 3_600_000
        || l.max_concurrency != 1
        || l.max_retries > 3
        || l.max_results < c.cases.len()
        || l.max_results > 10_000
        || l.max_bytes < 1024
        || l.max_bytes > 64 * 1024 * 1024
        || c.max_age_seconds == 0
        || c.max_age_seconds > 86_400
        || c.pending_window_seconds == 0
        || c.pending_window_seconds > 1800
    {
        return Err(GuardError::ConfigInvalid);
    }
    let mut changes = BTreeSet::new();
    for change in &c.permission_changes {
        let needed = match change.layer {
            GcpDenial::ConnectIam => GcpRole::CloudSqlClient,
            GcpDenial::LoginIam => GcpRole::CloudSqlInstanceUser,
            _ => return Err(GuardError::ConfigInvalid),
        };
        let before: BTreeSet<_> = change.before_roles.iter().copied().collect();
        let after: BTreeSet<_> = change.after_roles.iter().copied().collect();
        if !ids.contains(&change.principal_id)
            || !changes.insert((&change.principal_id, change.layer))
            || change.changed_at == 0
            || before.len() != change.before_roles.len()
            || after.len() != change.after_roles.len()
            || !before.contains(&needed)
            || after.contains(&needed)
            || before.difference(&after).copied().collect::<Vec<_>>() != vec![needed]
            || !after.is_subset(&before)
        {
            return Err(GuardError::ConfigInvalid);
        }
    }
    Ok(())
}
fn hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn validate_snapshot(c: &GcpConfig, s: &GcpSnapshot) -> Result<(), GuardError> {
    if s.target != c.target {
        return Err(GuardError::TargetMismatch);
    }
    if s.engine_version != c.target.engine_version
        || s.connection_name
            != format!(
                "{}:{}:{}",
                c.target.project_id, c.target.region, c.target.instance_id
            )
        || ![
            "GOOGLE_MANAGED_INTERNAL_CA",
            "GOOGLE_MANAGED_CAS_CA",
            "CUSTOMER_MANAGED_CAS_CA",
            "UNKNOWN",
        ]
        .contains(&s.ca_mode.as_str())
        || (!s.ca_fingerprint.is_empty() && !hash(&s.ca_fingerprint))
        || s.authorized_networks.len() > 100
        || s.principal_roles.len() > c.principals.len()
        || s.registered_principal_ids.len() > c.principals.len()
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if s.authorized_networks
        .iter()
        .any(|n| n.parse::<ipnet::Ipv4Net>().is_err())
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let ids: BTreeSet<_> = c.principals.iter().map(|p| &p.id).collect();
    let mut seen = BTreeSet::new();
    for p in &s.principal_roles {
        let roles: BTreeSet<_> = p.roles.iter().collect();
        if !ids.contains(&p.principal_id)
            || !seen.insert(&p.principal_id)
            || roles.len() != p.roles.len()
            || roles.len() > 4
        {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    let registered: BTreeSet<_> = s.registered_principal_ids.iter().collect();
    if registered.len() != s.registered_principal_ids.len()
        || registered.iter().any(|id| !ids.contains(*id))
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if s.complete && seen.len() != c.principals.len() {
        return Err(GuardError::EvidenceIncompatible);
    }
    Ok(())
}
pub fn validate_evidence(c: &GcpConfig, r: &GcpRunEvidence) -> Result<(), GuardError> {
    validate_config(c)?;
    if r.target != c.target {
        return Err(GuardError::TargetMismatch);
    }
    if r.schema_version != 1
        || !safe_id(&r.run_id)
        || !hash(&r.build_id)
        || r.config_hash != config_hash(c)
        || r.history_compatibility_hash != history_compatibility_hash(c)
        || r.started_at > r.finished_at
        || r.observations.len() > c.limits.max_results
        || r.before.observed_at < r.started_at
        || r.after.observed_at > r.finished_at
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    validate_snapshot(c, &r.before)?;
    validate_snapshot(c, &r.after)?;
    let mut attempts = BTreeSet::new();
    for o in &r.observations {
        let case = c
            .cases
            .iter()
            .find(|x| x.id == o.case_id)
            .ok_or(GuardError::EvidenceIncompatible)?;
        let p = c
            .principals
            .iter()
            .find(|p| p.id == case.principal_id)
            .ok_or(GuardError::EvidenceIncompatible)?;
        if !safe_id(&o.attempt_id)
            || !attempts.insert(&o.attempt_id)
            || o.principal_id != case.principal_id
            || o.route != case.route
            || o.started_at > o.finished_at
            || o.started_at < r.before.observed_at
            || o.finished_at > r.after.observed_at
            || o.proof
                .transport_control_case_id
                .as_ref()
                .is_some_and(|s| !safe_id(s))
            || o.proof.db_user.as_ref().is_some_and(|u| u != &p.db_user())
            || o.proof
                .database
                .as_ref()
                .is_some_and(|d| d != &c.target.database)
        {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    Ok(())
}
