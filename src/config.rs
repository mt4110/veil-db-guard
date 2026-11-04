use crate::domain::*;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error(transparent)]
    Ledger(#[from] crate::core::operation::StoreError),
    #[error(transparent)]
    Change(#[from] crate::core::change::ChangeError),
    #[error(transparent)]
    Approval(#[from] crate::core::approval::ApprovalError),
    #[error(transparent)]
    EvidenceAdmission(#[from] crate::core::admission::AdmissionError),
    #[error(transparent)]
    Source(#[from] crate::adapters::source::gce_host::SourceError),
    #[error("CONFIG_INVALID: configuration is invalid; input values are not echoed")]
    ConfigInvalid,
    #[error("TARGET_MISMATCH: evidence does not match the declared target")]
    TargetMismatch,
    #[error("UNSUPPORTED_TARGET: this target or operation is not supported")]
    UnsupportedTarget,
    #[error(
        "INTENT_NOT_QUALIFIED: selected requirements are unsupported or required policy references are missing; review the scoped qualification report"
    )]
    IntentNotQualified,
    #[error(
        "SOURCE_EVIDENCE_NOT_READY: current source evidence is missing or incomplete for the next native step"
    )]
    SourceEvidenceNotReady,
    #[error("STORAGE_FAILED: local storage operation failed")]
    StorageFailed,
    #[error("EVIDENCE_INCOMPATIBLE: malformed, incomplete, or incompatible evidence")]
    EvidenceIncompatible,
    #[error("PERMISSION_REQUIRED: an explicit operation permission is required")]
    PermissionRequired,
    #[error("LIMIT_EXCEEDED: configured resource limit exceeded")]
    LimitExceeded,
    #[error("CANCELLED: operation was cancelled")]
    Cancelled,
    #[error("OPERATION_FAILED: operation failed; raw diagnostic values are not emitted")]
    OperationFailed,
    #[error("TOTAL_TIMEOUT: command execution deadline exceeded")]
    TimedOut,
}

pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;

pub fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:".contains(&c))
        && !s.contains("..")
        && !s.to_ascii_uppercase().contains("TO_BE_")
        && !s.to_ascii_uppercase().contains("PLACEHOLDER")
}
pub fn sql_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, GuardError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| GuardError::StorageFailed)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(GuardError::EvidenceIncompatible);
    }
    if meta.len() > max as u64 {
        return Err(GuardError::LimitExceeded);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| GuardError::StorageFailed)?;
    let opened = file.metadata().map_err(|_| GuardError::StorageFailed)?;
    if !opened.is_file() {
        return Err(GuardError::EvidenceIncompatible);
    }
    if opened.len() > max as u64 {
        return Err(GuardError::LimitExceeded);
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GuardError::StorageFailed)?;
    if bytes.len() > max {
        return Err(GuardError::LimitExceeded);
    }
    Ok(bytes)
}
pub fn read_json<T: DeserializeOwned>(path: &Path, max: usize) -> Result<T, GuardError> {
    serde_json::from_slice(&read_bounded(path, max)?).map_err(|_| GuardError::EvidenceIncompatible)
}
pub fn load_config(path: &Path) -> Result<TargetConfig, GuardError> {
    parse_config(&read_bounded(path, MAX_INPUT_BYTES)?)
}
pub fn parse_config(bytes: &[u8]) -> Result<TargetConfig, GuardError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(GuardError::LimitExceeded);
    }
    // No anchors/aliases/tags or interpolation in this deliberately small YAML subset.
    // Conservative rejection also covers these characters in descriptions, before parsing.
    if bytes.iter().any(|c| b"&*!".contains(c)) {
        return Err(GuardError::ConfigInvalid);
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_reader_input_bytes = Some(MAX_INPUT_BYTES);
    budget.max_depth = 32;
    budget.max_nodes = 50_000;
    budget.max_events = 100_000;
    budget.max_total_scalar_bytes = MAX_INPUT_BYTES;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_documents = 1;
    budget.max_merge_keys = 0;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    let config: TargetConfig = serde_saphyr::from_slice_with_options(bytes, options)
        .map_err(|_| GuardError::ConfigInvalid)?;
    validate_config(&config)?;
    Ok(config)
}
pub fn validate_config(c: &TargetConfig) -> Result<(), GuardError> {
    let err = GuardError::ConfigInvalid;
    if c.schema_version != 1
        || !safe_id(&c.experiment_id)
        || !safe_id(&c.phase_id)
        || !safe_id(&c.configuration_epoch)
        || !safe_id(&c.target.id)
    {
        return Err(err);
    }
    let t = &c.target;
    if t.account_id.len() != 12 || !t.account_id.bytes().all(|x| x.is_ascii_digit()) {
        return Err(err);
    }
    if t.region != "ap-northeast-1"
        || t.engine != "postgres"
        || t.engine_version != "16.15"
        || c.auth.mode != AuthMode::EndToEndIam
    {
        return Err(GuardError::UnsupportedTarget);
    }
    let prefix = format!("arn:aws:rds:{}:{}:", t.region, t.account_id);
    for (arn, kind) in [(&t.db_instance_arn, "db:"), (&t.proxy_arn, "db-proxy:")] {
        let resource = arn
            .strip_prefix(&format!("{prefix}{kind}"))
            .ok_or(GuardError::ConfigInvalid)?;
        if !safe_id(resource) {
            return Err(GuardError::ConfigInvalid);
        }
    }
    if !safe_id(&t.proxy_name) || !sql_id(&c.auth.db_user) {
        return Err(err);
    }
    if c.sources.is_empty() || c.sources.len() > 32 || c.paths.is_empty() || c.paths.len() > 128 {
        return Err(err);
    }
    let mut ids = BTreeSet::new();
    for s in &c.sources {
        if !safe_id(&s.id) || s.id == "global" || !ids.insert(&s.id) {
            return Err(GuardError::ConfigInvalid);
        }
    }
    let mut paths = BTreeSet::new();
    for p in &c.paths {
        if !safe_id(&p.id)
            || p.id == "global"
            || !ids.contains(&p.source_id)
            || !paths.insert(&p.id)
            || p.exception_code.as_ref().is_some_and(|s| !safe_id(s))
        {
            return Err(GuardError::ConfigInvalid);
        }
        if p.actor == Actor::Admin && p.expected == Expectation::Allow && p.exception_code.is_none()
        {
            return Err(GuardError::ConfigInvalid);
        }
        if p.actor == Actor::Application
            && p.destination == Destination::Database
            && p.expected != Expectation::Deny
        {
            return Err(GuardError::ConfigInvalid);
        }
    }
    let apps: Vec<_> = c
        .paths
        .iter()
        .filter(|p| {
            p.actor == Actor::Application
                && p.destination == Destination::Proxy
                && p.expected == Expectation::Allow
        })
        .collect();
    if apps.is_empty()
        || apps.iter().any(|a| {
            !c.paths.iter().any(|p| {
                p.actor == Actor::Application
                    && p.destination == Destination::Database
                    && p.expected == Expectation::Deny
                    && p.source_id == a.source_id
                    && p.address_family == a.address_family
            })
        })
    {
        return Err(err);
    }
    if let Some(s) = &c.test_scope
        && (!sql_id(&s.database)
            || !sql_id(&s.schema_prefix)
            || !s.schema_prefix.starts_with("vdg_")
            || !sql_id(&s.db_user)
            || s.db_user != c.auth.db_user)
    {
        return Err(err);
    }
    let l = &c.limits;
    if l.connect_timeout_ms == 0
        || l.query_timeout_ms == 0
        || l.total_timeout_ms == 0
        || l.connect_timeout_ms > l.total_timeout_ms
        || l.query_timeout_ms > l.total_timeout_ms
        || l.total_timeout_ms > 86_400_000
        || l.max_concurrency == 0
        || l.max_concurrency > 32
        || l.max_retries > 3
        || l.max_results == 0
        || l.max_results > 100_000
        || l.max_bytes < 1024
        || l.max_bytes > 64 * 1024 * 1024
        || c.evidence_policy.max_age_seconds == 0
        || c.evidence_policy.max_age_seconds > 604_800
    {
        return Err(err);
    }
    if let Some(p) = &c.performance_profile
        && (!safe_id(&p.workload_id)
            || p.samples == 0
            || p.samples > l.max_results
            || p.warmup > 1000
            || !p.max_error_rate.is_finite()
            || !(0.0..=1.0).contains(&p.max_error_rate)
            || p.max_p95_ms == 0)
    {
        return Err(err);
    }
    if let Some(n) = &c.auth_negative
        && (n
            .unauthorized_aws_profile
            .as_ref()
            .is_some_and(|p| !safe_id(p) || p.starts_with('-'))
            || n.unauthorized_db_user
                .as_ref()
                .is_some_and(|u| !sql_id(u) || u == &c.auth.db_user))
    {
        return Err(err);
    }
    if let Some(r) = &c.recovery_profile
        && (r.long_transaction_ms > l.query_timeout_ms / 2
            || r.long_transaction_ms > 30_000
            || (r.allow_token_expiry_wait && l.total_timeout_ms < 905_000))
    {
        return Err(err);
    }
    Ok(())
}
pub fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn config_hash(config: &TargetConfig) -> String {
    hash_bytes(&serde_json::to_vec(config).expect("secret-free config serialization cannot fail"))
}
pub fn snapshot_hash(snapshot: &InventorySnapshot) -> String {
    hash_bytes(&serde_json::to_vec(snapshot).expect("snapshot serialization cannot fail"))
}
pub fn validate_snapshot(c: &TargetConfig, s: &InventorySnapshot) -> Result<(), GuardError> {
    if s.schema_version != 1 || s.target != c.target || s.config_hash != config_hash(c) {
        return Err(GuardError::TargetMismatch);
    }
    if s.observed_at > now()
        || now().saturating_sub(s.observed_at) > c.evidence_policy.max_age_seconds
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    if let Some(db) = &s.db
        && (db.arn != c.target.db_instance_arn
            || db.engine != c.target.engine
            || db.engine_version != c.target.engine_version
            || !valid_endpoint(&db.endpoint)
            || !safe_id(&db.resource_id))
    {
        return Err(GuardError::TargetMismatch);
    }
    if let Some(proxy) = &s.proxy {
        if proxy.arn != c.target.proxy_arn || !valid_endpoint(&proxy.endpoint) {
            return Err(GuardError::TargetMismatch);
        }
        if let (Some(db), Some(target)) = (&s.db, &proxy.target_db_resource_id)
            && &db.resource_id != target
        {
            return Err(GuardError::TargetMismatch);
        }
    }
    let sg_id = |s: &str| {
        s.starts_with("sg-")
            && (5..=20).contains(&s.len())
            && s[3..].bytes().all(|b| b.is_ascii_hexdigit())
    };
    if s.security_groups.len() > c.limits.max_results || s.retrievals.len() > 6 {
        return Err(GuardError::LimitExceeded);
    }
    if s.db.as_ref().is_some_and(|d| {
        d.security_group_ids.iter().any(|id| !sg_id(id))
            || d.parameter_group.as_ref().is_some_and(|id| !safe_id(id))
            || d.instance_class.as_ref().is_some_and(|s| {
                !s.starts_with("db.")
                    || s.len() > 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.')
            })
            || d.availability_zone.as_ref().is_some_and(|s| {
                s.len() != c.target.region.len() + 1
                    || !s.starts_with(&c.target.region)
                    || !s.as_bytes().last().is_some_and(u8::is_ascii_lowercase)
            })
    }) {
        return Err(GuardError::EvidenceIncompatible);
    }
    if let Some(proxy) = &s.proxy {
        let prefix = format!("arn:aws:iam::{}:role/", c.target.account_id);
        if proxy.security_group_ids.iter().any(|id| !sg_id(id))
            || !proxy.role_arn.strip_prefix(&prefix).is_some_and(|role| {
                !role.is_empty()
                    && role.len() <= 512
                    && role
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/+=,.@_-".contains(&b))
            })
        {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    let operations = [
        "describe-db-proxies",
        "describe-db-instances",
        "describe-db-proxy-target-groups",
        "describe-db-proxy-targets",
        "describe-db-parameters",
        "describe-security-groups",
    ];
    let mut seen = BTreeSet::new();
    if s.retrievals
        .iter()
        .any(|r| !operations.contains(&r.operation.as_str()) || !seen.insert(&r.operation))
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    for group in &s.security_groups {
        if !sg_id(&group.id)
            || !group.vpc_id.starts_with("vpc-")
            || group.vpc_id.len() > 21
            || !group.vpc_id[4..].bytes().all(|b| b.is_ascii_hexdigit())
            || group.ingress.len() > c.limits.max_results
        {
            return Err(GuardError::EvidenceIncompatible);
        }
        for rule in &group.ingress {
            if !["tcp", "udp", "icmp", "icmpv6", "6", "17", "1", "58", "-1"]
                .contains(&rule.protocol.as_str())
                || matches!((rule.from_port,rule.to_port),(Some(a),Some(b)) if a>b)
            {
                return Err(GuardError::EvidenceIncompatible);
            }
            let valid = match &rule.source {
                RuleSource::SecurityGroup { id } => sg_id(id),
                RuleSource::Ipv4 { cidr } => cidr.parse::<ipnet::Ipv4Net>().is_ok(),
                RuleSource::Ipv6 { cidr } => cidr.parse::<ipnet::Ipv6Net>().is_ok(),
            };
            if !valid {
                return Err(GuardError::EvidenceIncompatible);
            }
        }
    }
    Ok(())
}
pub fn valid_endpoint(e: &Endpoint) -> bool {
    e.port > 0
        && !e.host.is_empty()
        && e.host.len() <= 253
        && !e.host.starts_with('-')
        && e.host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))
}
