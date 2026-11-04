use super::{config, model::*};
use crate::config::GuardError;
use std::collections::BTreeSet;

fn roles(s: &GcpSnapshot, id: &str) -> Option<BTreeSet<GcpRole>> {
    s.principal_roles
        .iter()
        .find(|r| r.principal_id == id)
        .map(|r| r.roles.iter().copied().collect())
}
fn coherent(r: &GcpRunEvidence) -> bool {
    let mut a = r.before.clone();
    let mut b = r.after.clone();
    a.observed_at = 0;
    b.observed_at = 0;
    for s in [&mut a, &mut b] {
        s.authorized_networks.sort();
        s.registered_principal_ids.sort();
        s.principal_roles
            .sort_by(|a, b| a.principal_id.cmp(&b.principal_id));
        for p in &mut s.principal_roles {
            p.roles.sort();
        }
    }
    a == b
}
fn safe_state(r: &GcpRunEvidence) -> bool {
    r.before.complete
        && r.after.complete
        && r.before.iam_auth_enabled
        && r.after.iam_auth_enabled
        && matches!(
            r.before.ssl_mode,
            GcpSslMode::EncryptedOnly | GcpSslMode::TrustedClientCertificateRequired
        )
        && r.before.connector_enforcement != GcpConnectorEnforcement::Unknown
        && !r.before.ca_fingerprint.is_empty()
}
fn access(o: &GcpObservation) -> (GcpAccess, Option<GcpDenial>) {
    // A successful SQL operation stays visible even when the surrounding capture is partial.
    if o.proof.sql_authenticated || o.proof.sql_ok {
        return (GcpAccess::Allowed, None);
    }
    if o.execution != GcpExecution::Completed {
        return (GcpAccess::Unknown, None);
    }
    match o.proof.denied_permission {
        Some(GcpPermission::InstanceConnect) => (GcpAccess::Denied, Some(GcpDenial::ConnectIam)),
        Some(GcpPermission::InstanceLogin) => (GcpAccess::Denied, Some(GcpDenial::LoginIam)),
        Some(
            GcpPermission::InstanceGet | GcpPermission::ServiceUsage | GcpPermission::TokenCreation,
        ) => (GcpAccess::Denied, None),
        None if o.proof.iam_login_rejected
            && o.proof.credential_issued
            && o.proof.transport_positive =>
        {
            (GcpAccess::Denied, Some(GcpDenial::LoginIam))
        }
        None if o.proof.network_rejection_explicit && o.proof.tcp_reachable == Some(false) => {
            (GcpAccess::Denied, Some(GcpDenial::NetworkBlocked))
        }
        _ => (GcpAccess::Unknown, None),
    }
}
#[derive(Clone, Copy)]
struct Sample<'a> {
    run: &'a GcpRunEvidence,
    observation: &'a GcpObservation,
}
fn eligible(c: &GcpConfig, r: &GcpRunEvidence, now: u64) -> Result<(), GcpReason> {
    if r.target != c.target {
        return Err(GcpReason::TargetMismatch);
    }
    if r.build_id != crate::BUILD_ID {
        return Err(GcpReason::BuildMismatch);
    }
    if r.config_hash != config::config_hash(c)
        || r.history_compatibility_hash != config::history_compatibility_hash(c)
    {
        return Err(GcpReason::ConfigMismatch);
    }
    if config::validate_evidence(c, r).is_err() {
        return Err(GcpReason::InvalidEvidence);
    }
    if r.finished_at > now
        || r.before.observed_at > now
        || r.after.observed_at > now
        || now.saturating_sub(r.started_at) > c.max_age_seconds
    {
        return Err(GcpReason::StaleEvidence);
    }
    if r.evidence_kind != GcpEvidenceKind::Live {
        return Err(GcpReason::FixtureOnly);
    }
    Ok(())
}
fn full_capture(r: &GcpRunEvidence) -> Result<(), GcpReason> {
    if r.execution != GcpExecution::Completed {
        return Err(GcpReason::IncompleteInventory);
    }
    if !r.before.complete || !r.after.complete {
        return Err(GcpReason::IncompleteInventory);
    }
    if !coherent(r) {
        return Err(GcpReason::IncoherentSnapshot);
    }
    if !safe_state(r) {
        return Err(GcpReason::IncompleteInventory);
    }
    Ok(())
}
fn identity(c: &GcpConfig, case: &GcpCase, o: &GcpObservation) -> bool {
    c.principals
        .iter()
        .find(|p| p.id == case.principal_id)
        .is_some_and(|p| {
            o.proof.sql_ok
                && o.proof.db_user.as_ref() == Some(&p.db_user())
                && o.proof.database.as_ref() == Some(&c.target.database)
        })
}
fn transport_control(c: &GcpConfig, case: &GcpCase, s: Sample<'_>) -> bool {
    let o = s.observation;
    if !o.proof.transport_positive {
        return false;
    }
    let Some(id) = &o.proof.transport_control_case_id else {
        return false;
    };
    if id == &case.id {
        return false;
    }
    let Some(control) = c.cases.iter().find(|p| {
        p.id == *id
            && p.expected == GcpExpectation::Allow
            && p.route == GcpRoute::Proxy
            && p.principal_id != case.principal_id
    }) else {
        return false;
    };
    s.run.observations.iter().any(|p| {
        p.case_id == *id
            && p.principal_id == control.principal_id
            && p.route == GcpRoute::Proxy
            && p.execution == GcpExecution::Completed
            && p.observed == GcpAccess::Allowed
            && access(p).0 == GcpAccess::Allowed
            && identity(c, control, p)
            && p.proof.credential_issued
            && s.run
                .before
                .registered_principal_ids
                .contains(&control.principal_id)
    })
}
fn pending(
    c: &GcpConfig,
    case: &GcpCase,
    s: Sample<'_>,
    history: &[GcpHistoricalRun],
    now: u64,
) -> Option<String> {
    let layer = case.expected_denial?;
    let change = c
        .permission_changes
        .iter()
        .find(|x| x.principal_id == case.principal_id && x.layer == layer)?;
    if change.changed_at > s.run.started_at
        || change.changed_at > now
        || now - change.changed_at > c.pending_window_seconds
    {
        return None;
    }
    let expected_before: BTreeSet<_> = change.before_roles.iter().copied().collect();
    let expected_after: BTreeSet<_> = change.after_roles.iter().copied().collect();
    if expected_before.contains(&GcpRole::Other)
        || expected_after.contains(&GcpRole::Other)
        || roles(&s.run.before, &case.principal_id) != Some(expected_after.clone())
        || roles(&s.run.after, &case.principal_id) != Some(expected_after)
    {
        return None;
    }
    history
        .iter()
        .filter(|h| {
            config::history_compatibility_hash(&h.config) == config::history_compatibility_hash(c)
                && eligible(&h.config, &h.evidence, now).is_ok()
                && full_capture(&h.evidence).is_ok()
                && h.evidence.finished_at <= change.changed_at
                && h.evidence.run_id != s.run.run_id
                && roles(&h.evidence.before, &case.principal_id) == Some(expected_before.clone())
                && roles(&h.evidence.after, &case.principal_id) == Some(expected_before.clone())
                && h.evidence.observations.iter().any(|o| {
                    o.case_id == case.id
                        && o.execution == GcpExecution::Completed
                        && access(o).0 == GcpAccess::Allowed
                        && identity(c, case, o)
                        && o.observed == GcpAccess::Allowed
                        && o.proof.credential_issued
                        && h.evidence
                            .before
                            .registered_principal_ids
                            .contains(&case.principal_id)
                })
        })
        .max_by_key(|h| h.evidence.finished_at)
        .map(|h| h.evidence.run_id.clone())
}
fn assessment(
    c: &GcpConfig,
    case: &GcpCase,
    s: Sample<'_>,
    history: &[GcpHistoricalRun],
    now: u64,
) -> (GcpVerdict, GcpReason) {
    let o = s.observation;
    let (observed, denial) = access(o);
    if o.observed != observed {
        return (GcpVerdict::Unknown, GcpReason::InvalidEvidence);
    }
    if let Err(reason) = full_capture(s.run) {
        return (GcpVerdict::Unknown, reason);
    }
    if o.execution != GcpExecution::Completed {
        return (GcpVerdict::Unknown, GcpReason::UnclassifiedFailure);
    }
    if observed == GcpAccess::Allowed && !identity(c, case, o) {
        return (GcpVerdict::Unknown, GcpReason::IdentityMismatch);
    }
    if observed == GcpAccess::Allowed
        && (!o.proof.credential_issued
            || !s
                .run
                .before
                .registered_principal_ids
                .contains(&case.principal_id))
    {
        return (GcpVerdict::Unknown, GcpReason::IncompleteInventory);
    }
    if case.route == GcpRoute::Direct
        && observed == GcpAccess::Allowed
        && (!o.proof.ca_verified || o.proof.tls_established != Some(true))
    {
        return (GcpVerdict::Unknown, GcpReason::IncompleteInventory);
    }
    match (case.expected, observed) {
        (GcpExpectation::Allow, GcpAccess::Allowed) => (GcpVerdict::Pass, GcpReason::None),
        (GcpExpectation::Allow, GcpAccess::Denied) => {
            (GcpVerdict::Fail, GcpReason::PermissionDenied)
        }
        (GcpExpectation::Deny, GcpAccess::Allowed) => {
            if pending(c, case, s, history, now).is_some() {
                (GcpVerdict::Pending, GcpReason::PropagationPending)
            } else {
                (GcpVerdict::Fail, GcpReason::AccessStillAllowed)
            }
        }
        (GcpExpectation::Deny, GcpAccess::Denied) => {
            if case.expected_denial.is_some() && case.expected_denial != denial {
                return (GcpVerdict::Unknown, GcpReason::WrongDenialLayer);
            }
            if denial == Some(GcpDenial::ConnectIam) && case.route != GcpRoute::Proxy {
                return (GcpVerdict::Unknown, GcpReason::WrongDenialLayer);
            }
            if matches!(denial, Some(GcpDenial::ConnectIam | GcpDenial::LoginIam))
                && !o.proof.credential_issued
            {
                return (GcpVerdict::Unknown, GcpReason::IncompleteInventory);
            }
            if denial == Some(GcpDenial::LoginIam)
                && (!s
                    .run
                    .before
                    .registered_principal_ids
                    .contains(&case.principal_id)
                    || !o.proof.credential_issued
                    || !transport_control(c, case, s))
            {
                return (GcpVerdict::Unknown, GcpReason::IncompleteInventory);
            }
            if denial.is_none() {
                return (GcpVerdict::Unknown, GcpReason::WrongDenialLayer);
            }
            (GcpVerdict::Pass, GcpReason::PermissionDenied)
        }
        (_, GcpAccess::Unknown) => (
            GcpVerdict::Unknown,
            if o.proof.tcp_reachable != Some(true) {
                GcpReason::NetworkCauseUnconfirmed
            } else {
                GcpReason::UnclassifiedFailure
            },
        ),
    }
}
pub fn evaluate(
    c: &GcpConfig,
    current: &[GcpRunEvidence],
    history: &[GcpHistoricalRun],
    now: u64,
) -> GcpAssessment {
    let mut rows = Vec::new();
    let invalid_config = config::validate_config(c).is_err();
    for case in &c.cases {
        let mut row = GcpCaseAssessment {
            case_id: case.id.clone(),
            principal_id: case.principal_id.clone(),
            route: case.route,
            expected: case.expected,
            expected_denial: case.expected_denial,
            observed: GcpAccess::Unknown,
            denial: None,
            denied_permission: None,
            verdict: GcpVerdict::Unknown,
            protected: false,
            reason: GcpReason::MissingEvidence,
            execution: GcpExecution::NotRun,
            observed_at: None,
            mixed_history: false,
            consecutive_denials: 0,
            evidence_runs: vec![],
        };
        if invalid_config {
            row.reason = GcpReason::InvalidEvidence;
            rows.push(row);
            continue;
        }
        let mut samples = Vec::new();
        let mut seen = BTreeSet::new();
        let mut repeated = false;
        let mut boundary_error = None;
        let mut missing_run = None;
        for run in current {
            if let Err(reason) = eligible(c, run, now) {
                row.reason = reason;
                boundary_error = Some(reason);
                continue;
            }
            if !run.observations.iter().any(|o| o.case_id == case.id) {
                missing_run = Some(missing_run.unwrap_or(0).max(run.finished_at));
            }
            for o in run.observations.iter().filter(|o| o.case_id == case.id) {
                if !seen.insert((&run.run_id, &o.attempt_id)) {
                    repeated = true;
                    continue;
                }
                samples.push(Sample {
                    run,
                    observation: o,
                });
            }
        }
        samples.sort_by_key(|s| (s.observation.finished_at, s.observation.started_at));
        let mut timeline: Vec<_> = samples
            .iter()
            .map(|s| (s.observation.finished_at, access(s.observation).0))
            .collect();
        for h in history {
            if config::history_compatibility_hash(&h.config)
                != config::history_compatibility_hash(c)
                || eligible(&h.config, &h.evidence, now).is_err()
                || full_capture(&h.evidence).is_err()
            {
                continue;
            }
            for o in h
                .evidence
                .observations
                .iter()
                .filter(|o| o.case_id == case.id)
            {
                if seen.insert((&h.evidence.run_id, &o.attempt_id)) {
                    timeline.push((o.finished_at, access(o).0));
                }
            }
        }
        timeline.sort_by_key(|x| x.0);
        row.mixed_history = timeline.iter().any(|x| x.1 == GcpAccess::Allowed)
            && timeline.iter().any(|x| x.1 == GcpAccess::Denied);
        row.consecutive_denials = timeline
            .iter()
            .rev()
            .take_while(|x| x.1 == GcpAccess::Denied)
            .count();
        if let Some(s) = samples.last().copied() {
            let o = s.observation;
            let (observed, denial) = access(o);
            row.observed = observed;
            row.denial = denial;
            row.denied_permission = o.proof.denied_permission;
            row.execution = o.execution;
            row.observed_at = Some(o.finished_at);
            row.evidence_runs = samples.iter().map(|s| s.run.run_id.clone()).collect();
            row.evidence_runs.sort();
            row.evidence_runs.dedup();
            let (v, reason) = assessment(c, case, s, history, now);
            row.verdict = v;
            row.reason = reason;
            if v == GcpVerdict::Pending
                && let Some(baseline) = pending(c, case, s, history, now)
            {
                row.evidence_runs.push(baseline);
                row.evidence_runs.sort();
                row.evidence_runs.dedup();
            }
            if repeated
                || samples
                    .iter()
                    .rev()
                    .skip(1)
                    .take_while(|s| s.observation.finished_at == o.finished_at)
                    .any(|s| access(s.observation) != access(o))
            {
                row.verdict = GcpVerdict::Unknown;
                row.reason = GcpReason::InvalidEvidence;
                if samples
                    .iter()
                    .filter(|s| s.observation.finished_at == o.finished_at)
                    .any(|s| access(s.observation).0 == GcpAccess::Allowed)
                {
                    row.observed = GcpAccess::Allowed;
                    row.denial = None;
                }
            }
            row.protected = row.verdict == GcpVerdict::Pass;
        }
        if let Some(reason) = boundary_error {
            row.verdict = GcpVerdict::Unknown;
            row.protected = false;
            row.reason = reason;
        }
        if missing_run.is_some_and(|t| row.observed_at.is_none_or(|last| t >= last)) {
            row.verdict = GcpVerdict::Unknown;
            row.protected = false;
            row.reason = GcpReason::MissingEvidence;
        }
        rows.push(row);
    }
    let verdict = if rows.iter().any(|r| r.verdict == GcpVerdict::Fail) {
        GcpVerdict::Fail
    } else if rows.iter().any(|r| r.verdict == GcpVerdict::Pending) {
        GcpVerdict::Pending
    } else if rows.is_empty() || rows.iter().any(|r| r.verdict != GcpVerdict::Pass) {
        GcpVerdict::Unknown
    } else {
        GcpVerdict::Pass
    };
    let mut reasons: Vec<_> = rows
        .iter()
        .filter(|r| r.reason != GcpReason::None)
        .map(|r| r.reason)
        .collect();
    reasons.sort();
    reasons.dedup();
    GcpAssessment {
        schema_version: 1,
        target: c.target.clone(),
        evaluated_at: now,
        verdict,
        protected: verdict == GcpVerdict::Pass,
        cases: rows,
        reasons,
    }
}

/// Exposes only a fixed error code to consumers of imported evidence.
pub fn validate(c: &GcpConfig, r: &GcpRunEvidence) -> Result<(), GuardError> {
    config::validate_evidence(c, r)
}
