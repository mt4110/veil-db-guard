use veil_db_guard::core::{
    policy::{ExpiryMode, GenerationAssurance, GrantLifetime, parse_policy},
    state::*,
};

fn input() -> StateEvaluationInput {
    let p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    let mut desired = desired_for_policy(&p, &[], 120).unwrap();
    let mut d = desired.remove(0);
    d.scope.target.generation_assurance = GenerationAssurance::Confirmed;
    d.scope.target.native_ref.generation_fingerprint = Some("a".repeat(64));
    StateEvaluationInput {
        schema_version: 1,
        now: 120,
        max_age_seconds: 100,
        expected_build_id: "local-build".into(),
        desired: vec![d],
        evidence: vec![],
        permission_removals: vec![],
    }
}
fn provenance() -> EvidenceProvenance {
    EvidenceProvenance {
        origin: EvidenceOrigin::AdapterValidated,
        build_id: "local-build".into(),
        artifacts: vec![ArtifactRef {
            id: "capture".into(),
            sha256: "b".repeat(64),
        }],
    }
}
fn sample(
    i: &StateEvaluationInput,
    id: &str,
    observed: StateValue,
    start: u64,
    end: u64,
) -> StateEvidence {
    let scope = i.desired[0].scope.clone();
    let denial = (observed == StateValue::Denied).then_some(DenialProof {
        layer: scope.layer,
        cause: DenialCause::PermissionDenied,
        credential_issued: true,
        identity_registered: true,
        transport_control_ref: None,
    });
    StateEvidence {
        id: id.into(),
        scope,
        started_at: start,
        finished_at: end,
        valid_until: 200,
        provenance: provenance(),
        complete: true,
        identity_confirmed: true,
        observed,
        denial,
        sessions_attributed: true,
    }
}
fn denied_input() -> StateEvaluationInput {
    let mut i = input();
    i.desired[0].expected = StateValue::Denied;
    i.desired[0].scope.layer = StateLayer::ConnectionAuthorization;
    i
}
fn with_removal() -> StateEvaluationInput {
    let mut i = denied_input();
    i.evidence
        .push(sample(&i, "before-access", StateValue::Allowed, 70, 80));
    i.evidence
        .push(sample(&i, "current-access", StateValue::Allowed, 110, 115));
    let snapshot = |id: &str, at, permissions: Vec<&str>| PermissionSnapshot {
        id: id.into(),
        scope: i.desired[0].scope.clone(),
        observed_at: at,
        complete: true,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        provenance: provenance(),
    };
    i.permission_removals.push(PermissionRemoval {
        id: "removal".into(),
        scope: i.desired[0].scope.clone(),
        before_policy_revision_hash: i.desired[0].scope.policy_revision_hash.clone(),
        changed_at: 90,
        deadline: 130,
        removed_permissions: vec!["connect".into()],
        before: snapshot("before-config", 85, vec!["connect", "get"]),
        after: snapshot("after-config", 100, vec!["get"]),
        prior_allowed_evidence_id: "before-access".into(),
        partial_failure: false,
    });
    i
}
fn row(i: &StateEvaluationInput) -> StateRow {
    evaluate_state(i).unwrap().rows.remove(0)
}

#[test]
fn missing_or_fixture_records_never_establish_current_protection() {
    let mut i = input();
    let absent = evaluate_state(&i).unwrap();
    assert_eq!(absent.assessment, StateAssessment::Unknown);
    assert!(!absent.protection_evaluated);
    assert!(!absent.all_required_effects_satisfied);
    let mut e = sample(&i, "fixture", StateValue::Allowed, 110, 115);
    e.provenance.origin = EvidenceOrigin::Fixture;
    i.evidence.push(e);
    let report = evaluate_state(&i).unwrap();
    assert!(!report.protection_evaluated);
    assert!(!report.all_required_effects_satisfied);
    assert_eq!(report.rows[0].history[0].observed, StateValue::Allowed);
    assert!(report.rows[0].reasons.contains(&StateReason::FixtureOnly));
}

#[test]
fn exact_scope_prevents_cross_generation_revision_registration_and_identity_reuse() {
    for change in 0..12 {
        let mut i = input();
        let mut e = sample(&i, "foreign", StateValue::Allowed, 110, 115);
        match change {
            0 => e.scope.target.native_ref.generation_fingerprint = Some("c".repeat(64)),
            1 => e.scope.target.registration_id = "other-registration".into(),
            2 => e.scope.target.native_ref.native_id = "other-instance".into(),
            3 => e.scope.policy_revision_hash = "c".repeat(64),
            4 => e.scope.subject_id = "other-subject".into(),
            5 => e.scope.grant_id = "other-grant".into(),
            6 => e.scope.source_id = "other-source".into(),
            7 => e.scope.route.id = "other-route".into(),
            8 => e.scope.effect = StateEffect::ExistingSessions,
            9 => e.scope.layer = StateLayer::ConnectionAuthorization,
            10 => e.scope.db_identity = "other-db-user".into(),
            _ => e.scope.target.engine_binding.database = "other-database".into(),
        }
        i.evidence.push(e);
        let r = row(&i);
        assert_ne!(r.assessment, StateAssessment::Satisfied, "change={change}");
        assert!(!r.protection_evaluated, "change={change}");
    }
}

#[test]
fn capture_start_future_time_validity_and_build_control_freshness() {
    for change in 0..5 {
        let mut i = input();
        let mut e = sample(&i, "capture", StateValue::Allowed, 110, 115);
        match change {
            0 => e.started_at = 10,
            1 => e.finished_at = 121,
            2 => e.valid_until = 119,
            3 => e.started_at = 116,
            _ => e.provenance.build_id = "older-build".into(),
        }
        i.evidence.push(e);
        assert_eq!(row(&i).assessment, StateAssessment::Unknown);
        assert!(!row(&i).protection_evaluated);
    }
    let mut i = input();
    i.evidence
        .push(sample(&i, "capture", StateValue::Allowed, 20, 120));
    assert_eq!(row(&i).assessment, StateAssessment::Satisfied);
}

#[test]
fn allowed_access_remains_visible_even_when_capture_is_incomplete_or_contradictory() {
    let mut i = denied_input();
    let mut e = sample(&i, "partial", StateValue::Allowed, 110, 115);
    e.complete = false;
    i.evidence.push(e);
    let r = row(&i);
    assert_eq!(r.observed, StateValue::Allowed);
    assert_eq!(r.assessment, StateAssessment::Unknown);
    assert!(r.reasons.contains(&StateReason::IncompleteCapture));
    i.evidence[0].complete = true;
    i.evidence[0].denial = Some(DenialProof {
        layer: StateLayer::ConnectionAuthorization,
        cause: DenialCause::PermissionDenied,
        credential_issued: true,
        identity_registered: true,
        transport_control_ref: None,
    });
    let r = row(&i);
    assert_eq!(r.observed, StateValue::Allowed);
    assert_eq!(r.assessment, StateAssessment::Unknown);
    assert!(r.reasons.contains(&StateReason::ContradictoryEvidence));
}

#[test]
fn only_a_corroborated_target_denial_can_satisfy_deny() {
    let mut i = denied_input();
    i.evidence
        .push(sample(&i, "deny", StateValue::Denied, 110, 115));
    assert_eq!(row(&i).assessment, StateAssessment::Satisfied);
    for cause in [
        DenialCause::TokenCreationDenied,
        DenialCause::ServiceUnavailable,
        DenialCause::Timeout,
        DenialCause::Unclassified,
    ] {
        i.evidence[0].denial.as_mut().unwrap().cause = cause;
        assert_eq!(row(&i).assessment, StateAssessment::Unknown);
    }
    i.evidence[0].denial.as_mut().unwrap().cause = DenialCause::PermissionDenied;
    i.evidence[0].denial.as_mut().unwrap().credential_issued = false;
    assert_eq!(row(&i).assessment, StateAssessment::Unknown);
    i.evidence[0].denial.as_mut().unwrap().credential_issued = true;
    i.evidence[0].denial.as_mut().unwrap().layer = StateLayer::Authentication;
    assert!(row(&i).reasons.contains(&StateReason::WrongDenialLayer));
}

#[test]
fn login_denial_requires_independent_contemporaneous_successful_control() {
    let mut i = denied_input();
    i.desired[0].scope.layer = StateLayer::Authentication;
    let mut deny = sample(&i, "deny", StateValue::Denied, 110, 115);
    deny.denial.as_mut().unwrap().cause = DenialCause::LoginRejected;
    deny.denial.as_mut().unwrap().transport_control_ref = Some("control".into());
    i.evidence.push(deny);
    assert_eq!(row(&i).assessment, StateAssessment::Unknown);
    let mut control = sample(&i, "control", StateValue::Allowed, 109, 114);
    control.scope.subject_id = "control-subject".into();
    control.scope.grant_id = "control-grant".into();
    control.scope.db_identity = "control-user".into();
    i.evidence.push(control);
    assert_eq!(row(&i).assessment, StateAssessment::Satisfied);
    i.evidence[1].started_at = 90;
    i.evidence[1].finished_at = 100;
    assert_eq!(row(&i).assessment, StateAssessment::Unknown);
}

#[test]
fn corroborated_permission_removal_is_bounded_pending_and_keeps_allowed_visible() {
    let mut i = with_removal();
    let r = row(&i);
    assert_eq!(r.assessment, StateAssessment::Pending);
    assert_eq!(r.observed, StateValue::Allowed);
    assert_eq!(r.propagation_deadline, Some(130));
    assert_eq!(r.history.len(), 2);
    i.now = 130;
    let r = row(&i);
    assert_eq!(r.observed, StateValue::Allowed);
    assert_eq!(r.assessment, StateAssessment::NeedsAction);
    assert!(
        r.reasons
            .contains(&StateReason::PropagationDeadlineExceeded)
    );
    i.permission_removals[0].partial_failure = true;
    assert_eq!(row(&i).assessment, StateAssessment::FailedPartial);
}

#[test]
fn permission_removal_claim_without_linked_before_after_and_prior_access_is_not_pending() {
    for change in 0..8 {
        let mut i = with_removal();
        match change {
            0 => i.permission_removals[0].before.complete = false,
            1 => i.permission_removals[0]
                .after
                .permissions
                .push("connect".into()),
            2 => i.permission_removals[0]
                .after
                .permissions
                .push("new-permission".into()),
            3 => i.permission_removals[0].after.observed_at = 111,
            4 => i.permission_removals[0].prior_allowed_evidence_id = "missing".into(),
            5 => i.evidence[0].identity_confirmed = false,
            6 => i.permission_removals[0].after.provenance.origin = EvidenceOrigin::Fixture,
            _ => i.permission_removals[0].before.scope.target.registration_id = "other".into(),
        }
        let r = row(&i);
        assert_eq!(
            r.assessment,
            StateAssessment::NeedsAction,
            "change={change}"
        );
        assert_eq!(r.observed, StateValue::Allowed);
        assert!(r.reasons.contains(&StateReason::RemovalUncorroborated));
    }
}

#[test]
fn expired_propagation_deadline_requires_action_even_after_evidence_goes_stale() {
    let mut i = with_removal();
    i.now = 300;
    let r = row(&i);
    assert_eq!(r.assessment, StateAssessment::NeedsAction);
    assert_eq!(r.observed, StateValue::Unknown);
    assert!(!r.protection_evaluated);
    assert!(r.reasons.contains(&StateReason::StaleEvidence));
}

#[test]
fn mixed_history_and_simultaneous_contradiction_are_retained_without_hiding_access() {
    let mut i = denied_input();
    i.evidence
        .push(sample(&i, "past-allow", StateValue::Allowed, 80, 90));
    i.evidence
        .push(sample(&i, "current-deny", StateValue::Denied, 110, 115));
    let r = row(&i);
    assert_eq!(r.assessment, StateAssessment::Satisfied);
    assert_eq!(r.observed, StateValue::Denied);
    assert!(r.reasons.contains(&StateReason::MixedHistory));
    assert_eq!(r.history.len(), 2);
    i.evidence[0].started_at = 109;
    i.evidence[0].finished_at = 112;
    let r = row(&i);
    assert_eq!(r.assessment, StateAssessment::NeedsAction);
    assert_eq!(r.observed, StateValue::Allowed);
    assert_eq!(r.current_evidence_ids.len(), 2);
    assert!(r.reasons.contains(&StateReason::ContradictoryEvidence));
}

#[test]
fn new_connection_denial_does_not_prove_session_termination_or_sql_revocation() {
    let mut i = denied_input();
    i.evidence
        .push(sample(&i, "denied", StateValue::Denied, 110, 115));
    let mut sessions = i.desired[0].clone();
    sessions.id = "sessions".into();
    sessions.scope.effect = StateEffect::ExistingSessions;
    sessions.scope.layer = StateLayer::SessionControl;
    sessions.expected = StateValue::Terminated;
    let mut sql = i.desired[0].clone();
    sql.id = "sql".into();
    sql.scope.effect = StateEffect::SqlRole {
        role: "writer".into(),
    };
    sql.scope.layer = StateLayer::SqlAuthorization;
    sql.expected = StateValue::Absent;
    i.desired.extend([sessions, sql]);
    let report = evaluate_state(&i).unwrap();
    assert_eq!(report.rows[0].assessment, StateAssessment::Satisfied);
    assert_eq!(report.rows[1].assessment, StateAssessment::Unknown);
    assert_eq!(report.rows[2].assessment, StateAssessment::Unknown);
    assert!(!report.all_required_effects_satisfied);
    let mut sessions = sample(&i, "sessions-ended", StateValue::Terminated, 110, 115);
    sessions.scope = i.desired[1].scope.clone();
    sessions.sessions_attributed = false;
    i.evidence.push(sessions);
    assert!(
        evaluate_state(&i).unwrap().rows[1]
            .reasons
            .contains(&StateReason::SessionsUnattributed)
    );
}

#[test]
fn desired_universe_comes_from_policy_and_expired_lease_never_implies_effect() {
    let mut p = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    p.grants[0].lifetime = GrantLifetime::Lease {
        expires_at_unix: 100,
        expiry_mode: ExpiryMode::ControllerReconciled,
        reconciler_ref: Some("controller".into()),
    };
    let desired = desired_for_policy(&p, &[], 120).unwrap();
    assert!(
        desired
            .iter()
            .any(|d| d.scope.effect == StateEffect::LeaseExpiry)
    );
    assert!(
        desired
            .iter()
            .filter(|d| d.scope.effect == StateEffect::NewConnections)
            .all(|d| d.expected == StateValue::Denied)
    );
    assert!(
        desired
            .iter()
            .filter(|d| matches!(
                d.scope.effect,
                StateEffect::SqlRole { .. } | StateEffect::SqlPrivilege { .. }
            ))
            .all(|d| d.expected == StateValue::Absent)
    );
    let mut i = input();
    i.desired = desired;
    let report = evaluate_state(&i).unwrap();
    assert!(!report.protection_evaluated);
    assert!(!report.all_required_effects_satisfied);
    assert!(
        report
            .rows
            .iter()
            .all(|r| r.assessment == StateAssessment::Unknown)
    );
}

#[test]
fn malformed_hash_missing_artifacts_and_duplicate_ids_fail_without_echoing_values() {
    let mut i = input();
    i.evidence
        .push(sample(&i, "capture", StateValue::Allowed, 110, 115));
    i.evidence[0].provenance.artifacts[0].sha256 = "invalid-sensitive-value".into();
    assert_eq!(evaluate_state(&i).unwrap_err(), StateError::Invalid);
    assert!(!StateError::Invalid.to_string().contains("sensitive"));
    i.evidence[0].provenance = provenance();
    i.evidence.push(i.evidence[0].clone());
    assert_eq!(evaluate_state(&i).unwrap_err(), StateError::Invalid);
}

#[test]
fn sql_revocation_requires_exact_parent_privilege_scope_and_never_passes_vacuously() {
    let old = parse_policy(include_str!("../examples/core-policy.yaml")).unwrap();
    let mut current = old.clone();
    current.revision = 2;
    current.parent_revision_hash = Some(old.revision_hash().unwrap());
    current.grants[0].admission = veil_db_guard::core::policy::AdmissionIntent::Deny;
    current.grants[0].sql_access = Default::default();
    current.protection_profiles[0].required_effects = vec![
        veil_db_guard::core::policy::EffectKind::BindingApplied,
        veil_db_guard::core::policy::EffectKind::NewConnectionsDenied,
        veil_db_guard::core::policy::EffectKind::SqlPrivilegesRevoked,
    ];
    assert_eq!(
        desired_for_policy(&current, &[], 120).unwrap_err(),
        StateError::Invalid
    );
    let desired = desired_for_change(&current, Some(&old), &[], 120).unwrap();
    let sql: Vec<_> = desired
        .iter()
        .filter(|d| {
            matches!(
                d.scope.effect,
                StateEffect::SqlRole { .. } | StateEffect::SqlPrivilege { .. }
            )
        })
        .collect();
    assert_eq!(sql.len(), 4);
    assert!(sql.iter().all(|d| d.expected == StateValue::Absent));
    let mut foreign = old.clone();
    foreign.grants[0].db_identity = "different-native-user".into();
    assert_eq!(
        desired_for_change(&current, Some(&foreign), &[], 120).unwrap_err(),
        StateError::Invalid
    );
}
