use veil_db_guard::{
    domain::Limits,
    gcp::{config, evaluate, model::*, report},
};

fn config() -> GcpConfig {
    GcpConfig {
        schema_version: 1,
        target: GcpTarget {
            project_id: "vdg-eval-lab".into(),
            instance_id: "pg-lab".into(),
            region: "asia-northeast1".into(),
            engine_version: "POSTGRES_16_15".into(),
            database: "vdg_lab".into(),
        },
        principals: vec![
            GcpPrincipal {
                id: "app".into(),
                service_account: "tester-one@vdg-eval-lab.iam.gserviceaccount.com".into(),
            },
            GcpPrincipal {
                id: "control".into(),
                service_account: "tester-two@vdg-eval-lab.iam.gserviceaccount.com".into(),
            },
        ],
        cases: vec![
            GcpCase {
                id: "login-deny".into(),
                principal_id: "app".into(),
                route: GcpRoute::Proxy,
                expected: GcpExpectation::Deny,
                expected_denial: Some(GcpDenial::LoginIam),
            },
            GcpCase {
                id: "control-allow".into(),
                principal_id: "control".into(),
                route: GcpRoute::Proxy,
                expected: GcpExpectation::Allow,
                expected_denial: None,
            },
        ],
        permission_changes: vec![],
        limits: Limits::default(),
        max_age_seconds: 3600,
        pending_window_seconds: 600,
    }
}
fn before_roles() -> Vec<GcpRole> {
    vec![
        GcpRole::CloudSqlClient,
        GcpRole::CloudSqlInstanceUser,
        GcpRole::ServiceUsageConsumer,
    ]
}
fn after_roles() -> Vec<GcpRole> {
    vec![GcpRole::CloudSqlClient, GcpRole::ServiceUsageConsumer]
}
fn change(c: &mut GcpConfig) {
    c.permission_changes.push(GcpPermissionChange {
        principal_id: "app".into(),
        layer: GcpDenial::LoginIam,
        changed_at: 700,
        before_roles: before_roles(),
        after_roles: after_roles(),
    });
}
fn run(c: &GcpConfig, id: &str, t: u64, access: GcpAccess, roles: Vec<GcpRole>) -> GcpRunEvidence {
    let snapshot = |at| GcpSnapshot {
        target: c.target.clone(),
        observed_at: at,
        complete: true,
        engine_version: c.target.engine_version.clone(),
        connection_name: "vdg-eval-lab:asia-northeast1:pg-lab".into(),
        public_ip: Some("203.0.113.5".parse().unwrap()),
        ca_mode: "GOOGLE_MANAGED_INTERNAL_CA".into(),
        ca_fingerprint: "a".repeat(64),
        iam_auth_enabled: true,
        connector_enforcement: GcpConnectorEnforcement::Required,
        ssl_mode: GcpSslMode::EncryptedOnly,
        authorized_networks: vec![],
        principal_roles: vec![
            GcpPrincipalRoles {
                principal_id: "app".into(),
                roles: roles.clone(),
            },
            GcpPrincipalRoles {
                principal_id: "control".into(),
                roles: before_roles(),
            },
        ],
        registered_principal_ids: vec!["app".into(), "control".into()],
    };
    let mut proof = GcpProof {
        credential_issued: true,
        ..Default::default()
    };
    match access {
        GcpAccess::Allowed => {
            proof.sql_authenticated = true;
            proof.sql_ok = true;
            proof.db_user = Some(c.principals[0].db_user());
            proof.database = Some(c.target.database.clone());
            proof.tcp_reachable = Some(true);
            proof.tls_established = Some(false);
        }
        GcpAccess::Denied => {
            proof.transport_positive = true;
            proof.transport_control_case_id = Some("control-allow".into());
            proof.iam_login_rejected = true;
            proof.denied_permission = Some(GcpPermission::InstanceLogin);
        }
        _ => {}
    }
    let case = &c.cases[0];
    GcpRunEvidence {
        schema_version: 1,
        run_id: id.into(),
        build_id: veil_db_guard::BUILD_ID.into(),
        config_hash: config::config_hash(c),
        history_compatibility_hash: config::history_compatibility_hash(c),
        evidence_kind: GcpEvidenceKind::Live,
        target: c.target.clone(),
        started_at: t,
        finished_at: t + 5,
        execution: GcpExecution::Completed,
        before: snapshot(t + 1),
        after: snapshot(t + 4),
        observations: vec![
            GcpObservation {
                case_id: case.id.clone(),
                attempt_id: format!("{id}-attempt"),
                principal_id: case.principal_id.clone(),
                route: case.route,
                started_at: t + 2,
                finished_at: t + 3,
                execution: GcpExecution::Completed,
                observed: access,
                proof,
            },
            GcpObservation {
                case_id: "control-allow".into(),
                attempt_id: format!("{id}-control"),
                principal_id: "control".into(),
                route: GcpRoute::Proxy,
                started_at: t + 2,
                finished_at: t + 3,
                execution: GcpExecution::Completed,
                observed: GcpAccess::Allowed,
                proof: GcpProof {
                    credential_issued: true,
                    sql_authenticated: true,
                    sql_ok: true,
                    db_user: Some(c.principals[1].db_user()),
                    database: Some(c.target.database.clone()),
                    ..Default::default()
                },
            },
        ],
    }
}
fn pending_fixture() -> (GcpConfig, GcpRunEvidence, Vec<GcpHistoricalRun>) {
    let base = config();
    let historical = run(&base, "before", 600, GcpAccess::Allowed, before_roles());
    let mut c = base.clone();
    change(&mut c);
    let current = run(&c, "after", 800, GcpAccess::Allowed, after_roles());
    (
        c,
        current,
        vec![GcpHistoricalRun {
            config: base,
            evidence: historical,
        }],
    )
}

#[test]
fn strict_config_rejects_unknown_duplicate_cross_project_and_scope_values() {
    let c = config();
    let value = serde_json::to_value(&c).unwrap();
    assert!(config::parse_config(&serde_json::to_vec(&value).unwrap()).is_ok());
    let mut v = value;
    v["password"] = serde_json::json!("SENTINEL-SECRET");
    let err = config::parse_config(&serde_json::to_vec(&v).unwrap()).unwrap_err();
    assert!(!err.to_string().contains("SENTINEL"));
    assert!(config::parse_config(b"schema_version: 1\nschema_version: 1\n").is_err());
    let mut c = config();
    c.principals[0].service_account = "tester-one@different-project.iam.gserviceaccount.com".into();
    assert!(config::validate_config(&c).is_err());
    let mut c = config();
    c.cases.push(c.cases[0].clone());
    assert!(config::validate_config(&c).is_err());
    let mut c = config();
    c.cases[0].expected_denial = Some(GcpDenial::NetworkBlocked);
    assert!(config::validate_config(&c).is_err());
}

#[test]
fn positive_and_specific_login_denial_are_evaluated_separately() {
    let mut c = config();
    c.cases[0].expected = GcpExpectation::Allow;
    c.cases[0].expected_denial = None;
    let r = run(&c, "positive", 800, GcpAccess::Allowed, before_roles());
    let a = evaluate::evaluate(&c, &[r], &[], 810);
    assert_eq!(a.verdict, GcpVerdict::Pass);
    assert!(a.protected);
    let c = config();
    let r = run(&c, "denial", 800, GcpAccess::Denied, after_roles());
    let a = evaluate::evaluate(&c, &[r], &[], 810);
    assert_eq!(a.verdict, GcpVerdict::Pass);
    assert_eq!(a.cases[0].denial, Some(GcpDenial::LoginIam));
}

#[test]
fn declaration_alone_never_excuses_current_allowed() {
    let mut c = config();
    change(&mut c);
    let r = run(&c, "allowed", 800, GcpAccess::Allowed, after_roles());
    let a = evaluate::evaluate(&c, &[r], &[], 810);
    assert_eq!(a.verdict, GcpVerdict::Fail);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
    assert!(!a.protected);
    assert_eq!(report::exit_code(&a), 1);
}

#[test]
fn pending_needs_measured_role_change_and_keeps_allowed_visible() {
    let (c, r, h) = pending_fixture();
    assert_ne!(r.config_hash, h[0].evidence.config_hash);
    assert_eq!(
        r.history_compatibility_hash,
        h[0].evidence.history_compatibility_hash
    );
    let a = evaluate::evaluate(&c, &[r], &h, 810);
    assert_eq!(a.verdict, GcpVerdict::Pending);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
    assert!(!a.protected);
    assert_eq!(report::exit_code(&a), 3);
    assert!(a.cases[0].evidence_runs.contains(&"before".into()));
    assert!(a.cases[0].evidence_runs.contains(&"after".into()));
    assert!(report::render_markdown(&a).contains("現在は接続できる／保護成立未確認"));
}

#[test]
fn changed_route_expectation_or_history_hash_cannot_be_pending_baseline() {
    for m in 0..4 {
        let (c, r, mut h) = pending_fixture();
        match m {
            0 => {
                h[0].config.cases[0].expected = GcpExpectation::Allow;
                h[0].config.cases[0].expected_denial = None;
                h[0].evidence = run(
                    &h[0].config,
                    "changed",
                    600,
                    GcpAccess::Allowed,
                    before_roles(),
                );
            }
            1 => h[0].evidence.config_hash = "0".repeat(64),
            2 => h[0].evidence.evidence_kind = GcpEvidenceKind::Fixture,
            _ => h[0].evidence.before.principal_roles[0].roles = after_roles(),
        };
        let a = evaluate::evaluate(&c, &[r], &h, 810);
        assert_eq!(a.verdict, GcpVerdict::Fail, "mutation {m}");
    }
}

#[test]
fn propagation_window_expiry_is_fail_not_an_endless_pending() {
    let (c, r, h) = pending_fixture();
    let a = evaluate::evaluate(&c, &[r], &h, 1301);
    assert_eq!(a.verdict, GcpVerdict::Fail);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
    assert!(!a.protected);
}

#[test]
fn unexpected_role_or_incoherent_after_snapshot_cannot_be_pending() {
    let (c, mut r, h) = pending_fixture();
    r.before.principal_roles[0].roles.push(GcpRole::Other);
    r.after.principal_roles[0].roles.push(GcpRole::Other);
    assert_eq!(
        evaluate::evaluate(&c, &[r], &h, 810).verdict,
        GcpVerdict::Fail
    );
    let (c, mut r, h) = pending_fixture();
    r.after.connector_enforcement = GcpConnectorEnforcement::NotRequired;
    let a = evaluate::evaluate(&c, &[r], &h, 810);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
}

#[test]
fn partial_capture_does_not_hide_allowed_or_pass() {
    let (c, mut r, h) = pending_fixture();
    r.execution = GcpExecution::Cancelled;
    let a = evaluate::evaluate(&c, &[r], &h, 810);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
    assert!(!a.protected);
}

#[test]
fn timeout_is_not_network_or_iam_denial() {
    let mut c = config();
    c.cases[0].route = GcpRoute::Direct;
    c.cases[0].expected_denial = Some(GcpDenial::NetworkBlocked);
    let mut r = run(&c, "timeout", 800, GcpAccess::Unknown, after_roles());
    r.observations[0].execution = GcpExecution::Timeout;
    r.observations[0].proof.tcp_reachable = Some(false);
    let a = evaluate::evaluate(&c, &[r], &[], 810);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
    assert_eq!(a.cases[0].observed, GcpAccess::Unknown);
    assert_eq!(a.cases[0].denial, None);
}

#[test]
fn get_serviceusage_and_tokencreation_are_not_connect_permission_denial() {
    let mut c = config();
    c.cases[0].expected_denial = Some(GcpDenial::ConnectIam);
    for permission in [
        GcpPermission::InstanceGet,
        GcpPermission::ServiceUsage,
        GcpPermission::TokenCreation,
    ] {
        let mut r = run(&c, "wrong-layer", 800, GcpAccess::Denied, after_roles());
        r.observations[0].proof.denied_permission = Some(permission);
        r.observations[0].proof.iam_login_rejected = false;
        let a = evaluate::evaluate(&c, &[r], &[], 810);
        assert_eq!(a.verdict, GcpVerdict::Unknown);
        assert_eq!(a.cases[0].observed, GcpAccess::Denied);
        assert_eq!(a.cases[0].reason, GcpReason::WrongDenialLayer);
    }
    let mut r = run(&c, "right-layer", 800, GcpAccess::Denied, after_roles());
    r.observations[0].proof.denied_permission = Some(GcpPermission::InstanceConnect);
    assert_eq!(
        evaluate::evaluate(&c, &[r], &[], 810).verdict,
        GcpVerdict::Pass
    );
}

#[test]
fn missing_db_registration_transport_or_credential_is_not_login_cause_pass() {
    for m in 0..3 {
        let c = config();
        let mut r = run(&c, "missing", 800, GcpAccess::Denied, after_roles());
        match m {
            0 => {
                r.before.registered_principal_ids.clear();
                r.after.registered_principal_ids.clear();
            }
            1 => r.observations[0].proof.transport_positive = false,
            _ => r.observations[0].proof.credential_issued = false,
        };
        assert_eq!(
            evaluate::evaluate(&c, &[r], &[], 810).verdict,
            GcpVerdict::Unknown
        );
    }
}

#[test]
fn old_or_fixture_current_cannot_be_hidden_by_earlier_pass() {
    let c = config();
    let good = run(&c, "good", 800, GcpAccess::Denied, after_roles());
    for m in 0..5 {
        let mut bad = run(&c, "bad", 801, GcpAccess::Denied, after_roles());
        match m {
            0 => bad.build_id = "0".repeat(64),
            1 => bad.config_hash = "0".repeat(64),
            2 => bad.evidence_kind = GcpEvidenceKind::Fixture,
            3 => bad.finished_at = 9000,
            _ => bad.observations[0].attempt_id = "unsafe-secret://value".into(),
        };
        let a = evaluate::evaluate(&c, &[good.clone(), bad], &[], 810);
        assert_eq!(a.verdict, GcpVerdict::Unknown, "mutation {m}");
        assert!(!a.protected);
    }
}

#[test]
fn mixed_history_remains_after_three_denials_without_stability_claim() {
    let (c, _, h) = pending_fixture();
    let runs = (0..3)
        .map(|n| {
            run(
                &c,
                &format!("denied-{n}"),
                800 + n * 20,
                GcpAccess::Denied,
                after_roles(),
            )
        })
        .collect::<Vec<_>>();
    let a = evaluate::evaluate(&c, &runs, &h, 850);
    assert_eq!(a.verdict, GcpVerdict::Pass);
    assert!(a.cases[0].mixed_history);
    assert_eq!(a.cases[0].consecutive_denials, 3);
    let text = report::render_markdown(&a);
    assert!(text.contains("3回連続"));
    assert!(text.contains("保証しません"));
}

#[test]
fn duplicate_attempts_never_inflate_three_denials() {
    let c = config();
    let r = run(&c, "same", 800, GcpAccess::Denied, after_roles());
    let a = evaluate::evaluate(&c, &[r.clone(), r.clone(), r], &[], 810);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
    assert_eq!(a.cases[0].consecutive_denials, 1);
}

#[test]
fn unsafe_ssl_or_iam_flag_never_pass_despite_denial() {
    for m in 0..2 {
        let c = config();
        let mut r = run(&c, "unsafe", 800, GcpAccess::Denied, after_roles());
        if m == 0 {
            r.before.iam_auth_enabled = false;
            r.after.iam_auth_enabled = false;
        } else {
            r.before.ssl_mode = GcpSslMode::AllowUnencrypted;
            r.after.ssl_mode = GcpSslMode::AllowUnencrypted;
        }
        assert_eq!(
            evaluate::evaluate(&c, &[r], &[], 810).verdict,
            GcpVerdict::Unknown
        );
    }
}

#[test]
fn direct_positive_requires_ca_verified_and_identity_matches() {
    let mut c = config();
    c.cases[0].expected = GcpExpectation::Allow;
    c.cases[0].expected_denial = None;
    c.cases[0].route = GcpRoute::Direct;
    let mut r = run(&c, "direct", 800, GcpAccess::Allowed, before_roles());
    assert_eq!(
        evaluate::evaluate(&c, &[r.clone()], &[], 810).verdict,
        GcpVerdict::Unknown
    );
    r.observations[0].proof.ca_verified = true;
    r.observations[0].proof.tls_established = Some(true);
    assert_eq!(
        evaluate::evaluate(&c, &[r], &[], 810).verdict,
        GcpVerdict::Pass
    );
}

#[test]
fn missing_case_and_unsupported_observation_are_not_all_pass() {
    let c = config();
    let mut r = run(&c, "unknown", 800, GcpAccess::Denied, after_roles());
    r.observations[0].case_id = "invented-case".into();
    assert_eq!(
        evaluate::evaluate(&c, &[r], &[], 810).verdict,
        GcpVerdict::Unknown
    );
    let a = evaluate::evaluate(&c, &[], &[], 810);
    assert_eq!(a.cases.len(), 2);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
}

#[test]
fn newer_capture_missing_case_prevents_old_pass_fallback() {
    let c = config();
    let old = run(&c, "old", 800, GcpAccess::Denied, after_roles());
    let mut new = run(&c, "new", 820, GcpAccess::Denied, after_roles());
    new.execution = GcpExecution::Error;
    new.observations.retain(|o| o.case_id != "login-deny");
    let a = evaluate::evaluate(&c, &[old, new], &[], 830);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
    assert!(!a.cases[0].protected);
    assert_eq!(a.cases[0].reason, GcpReason::MissingEvidence);
}

#[test]
fn claimed_transport_boolean_needs_a_different_allow_case_link() {
    for reference in [None, Some("login-deny"), Some("invented-case")] {
        let c = config();
        let mut r = run(&c, "link", 800, GcpAccess::Denied, after_roles());
        r.observations[0].proof.transport_control_case_id = reference.map(str::to_owned);
        let a = evaluate::evaluate(&c, &[r], &[], 810);
        assert_eq!(a.verdict, GcpVerdict::Unknown);
        assert_eq!(a.cases[0].observed, GcpAccess::Denied);
    }
    let c = config();
    let mut r = run(&c, "bad-control", 800, GcpAccess::Denied, after_roles());
    r.observations[1].proof.sql_ok = false;
    r.observations[1].proof.sql_authenticated = false;
    r.observations[1].observed = GcpAccess::Unknown;
    r.observations[1].execution = GcpExecution::Error;
    assert_eq!(
        evaluate::evaluate(&c, &[r], &[], 810).cases[0].verdict,
        GcpVerdict::Unknown
    );
}

#[test]
fn after_read_failure_retains_real_allowed_without_claiming_fresh_inventory() {
    let (c, mut r, h) = pending_fixture();
    r.after.complete = false;
    r.execution = GcpExecution::Error;
    let a = evaluate::evaluate(&c, &[r], &h, 810);
    assert_eq!(a.verdict, GcpVerdict::Unknown);
    assert_eq!(a.cases[0].observed, GcpAccess::Allowed);
    assert!(!a.protected);
}

#[test]
fn same_time_conflicting_observations_remain_unprotected_and_allowed_is_visible() {
    let c = config();
    let a = run(&c, "allowed", 800, GcpAccess::Allowed, after_roles());
    let b = run(&c, "denied", 800, GcpAccess::Denied, after_roles());
    let evaluated = evaluate::evaluate(&c, &[a, b], &[], 810);
    assert_eq!(evaluated.verdict, GcpVerdict::Unknown);
    assert_eq!(evaluated.cases[0].observed, GcpAccess::Allowed);
    assert!(evaluated.cases[0].mixed_history);
}
