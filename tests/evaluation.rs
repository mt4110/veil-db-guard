use veil_db_guard::{
    domain::*,
    evaluator::{evaluate, required_cases},
    report,
};
#[path = "evaluation/protocol.rs"]
mod protocol_cases;

const NOW: u64 = 10_000;

fn config(profile: Profile) -> TargetConfig {
    TargetConfig {
        schema_version: 1,
        assessment_profile: profile,
        experiment_id: "experiment".into(),
        phase_id: "protected".into(),
        configuration_epoch: "epoch1".into(),
        target: Target {
            id: "target".into(),
            account_id: "123456789012".into(),
            region: "ap-northeast-1".into(),
            db_instance_arn: "arn:aws:rds:ap-northeast-1:123456789012:db:example".into(),
            proxy_arn: "arn:aws:rds:ap-northeast-1:123456789012:db-proxy:prx-example".into(),
            proxy_name: "example".into(),
            engine: "postgres".into(),
            engine_version: "17.7".into(),
        },
        auth: Auth {
            mode: AuthMode::EndToEndIam,
            db_user: "app".into(),
        },
        sources: vec![Source {
            id: "app-source".into(),
            kind: SourceKind::VpcHost,
            description: None,
        }],
        paths: vec![
            PathSpec {
                id: "app-proxy".into(),
                source_id: "app-source".into(),
                actor: Actor::Application,
                destination: Destination::Proxy,
                expected: Expectation::Allow,
                address_family: AddressFamily::Ipv4,
                exception_code: None,
            },
            PathSpec {
                id: "app-db".into(),
                source_id: "app-source".into(),
                actor: Actor::Application,
                destination: Destination::Database,
                expected: Expectation::Deny,
                address_family: AddressFamily::Ipv4,
                exception_code: None,
            },
        ],
        tls: TlsConfig::default(),
        test_scope: None,
        limits: Limits::default(),
        evidence_policy: EvidencePolicy::default(),
        performance_profile: None,
        auth_negative: None,
        recovery_profile: None,
    }
}

fn observation(
    c: &TargetConfig,
    v: &str,
    case: &str,
    path: &str,
    kind: EvidenceKind,
) -> Observation {
    let source = if path == "global" {
        "global"
    } else {
        "app-source"
    };
    let mut o = Observation::new(c, "run1", v, case, source, path, kind);
    o.observed_at = NOW;
    o.execution = Execution::Completed;
    o.outcome = Outcome::CheckSatisfied;
    o.reason_code = ReasonCode::None;
    o
}

fn local_complete(c: &TargetConfig) -> Vec<Observation> {
    required_cases(c)
        .iter()
        .map(|r| {
            observation(
                c,
                &r.verification_id,
                &r.case_id,
                &r.path_id,
                EvidenceKind::LocalFixture,
            )
        })
        .collect()
}

fn strong(c: &TargetConfig, v: &str, case: &str, path: &str) -> Observation {
    let mut o = observation(c, v, case, path, EvidenceKind::AwsConnection);
    o.source_verification = SourceVerification::Corroborated;
    o.snapshot_hash = "a".repeat(64);
    o.evidence_refs = vec!["snapshot.json".into()];
    o.facts = vec![
        Fact::TargetMatched,
        Fact::ConfigBeforeAfterMatched,
        Fact::NoChangesAttested,
    ];
    o
}

fn positive(c: &TargetConfig) -> Observation {
    let mut o = strong(c, "V08", "V08.verified_client_tls", "app-proxy");
    o.outcome = Outcome::Authenticated;
    o.path_stages = PathStages {
        transport_reachable: Stage::ObservedTrue,
        tls_established: Stage::ObservedTrue,
        db_authenticated: Stage::ObservedTrue,
    };
    o.facts
        .extend([Fact::ChainVerified, Fact::HostnameVerified]);
    o
}

fn verdict(a: &Assessment, case: &str) -> Verdict {
    a.cases.iter().find(|r| r.case_id == case).unwrap().verdict
}

#[test]
fn fixed_local_universe_passes_only_as_local_contract() {
    let c = config(Profile::LocalContractV1);
    let a = evaluate(&c, &local_complete(&c), None, NOW);
    assert_eq!(a.cases.len(), 35);
    assert_eq!(a.verdict, Verdict::Pass);
    assert_eq!(a.connection_verdict, Verdict::Unknown);
    assert_eq!(report::exit_code(&a), 0);
}

#[test]
fn missing_case_cannot_be_replaced_by_repeated_attempts() {
    let c = config(Profile::LocalContractV1);
    let mut observations = local_complete(&c);
    let missing = observations.pop().unwrap().case_id;
    for i in 0..20 {
        let mut o = observations[0].clone();
        o.attempt_id = format!("repeat{i}");
        observations.push(o);
    }
    let a = evaluate(&c, &observations, None, NOW);
    assert_eq!(a.verdict, Verdict::Unknown);
    assert_eq!(verdict(&a, &missing), Verdict::Unknown);
}

#[test]
fn empty_and_future_profiles_never_pass() {
    for p in [
        Profile::LocalContractV1,
        Profile::AwsSandboxCoreV1,
        Profile::DecoyV1,
        Profile::ContinuousV1,
    ] {
        let c = config(p);
        let a = evaluate(&c, &[], None, NOW);
        assert!(!a.cases.is_empty());
        assert_eq!(a.verdict, Verdict::Unknown);
        assert_eq!(report::exit_code(&a), 3);
    }
}

#[test]
fn stale_fail_is_history_not_current_failure() {
    let c = config(Profile::LocalContractV1);
    let mut observations = local_complete(&c);
    let mut old = observations[0].clone();
    old.observed_at = NOW - 4000;
    old.outcome = Outcome::CheckViolated;
    observations.push(old);
    assert_eq!(
        evaluate(&c, &observations, None, NOW).verdict,
        Verdict::Pass
    );
    observations[0].observed_at = NOW - 4000;
    assert_eq!(
        evaluate(&c, &observations, None, NOW).verdict,
        Verdict::Unknown
    );
}

#[test]
fn current_failure_is_not_erased_by_a_successful_retry() {
    let c = config(Profile::LocalContractV1);
    let mut observations = local_complete(&c);
    let mut failed = observations[0].clone();
    failed.outcome = Outcome::CheckViolated;
    failed.reason_code = ReasonCode::ConfigInvalid;
    observations.insert(0, failed);
    let a = evaluate(&c, &observations, None, NOW);
    assert_eq!(a.verdict, Verdict::Fail);
    assert_eq!(report::exit_code(&a), 1);
}

#[test]
fn mismatched_clock_build_target_config_epoch_or_kind_is_unknown() {
    let c = config(Profile::LocalContractV1);
    for mutation in 0..7 {
        let mut observations = local_complete(&c);
        match mutation {
            0 => observations[0].observed_at = NOW + 1,
            1 => observations[0].build_id = "other".into(),
            2 => observations[0].target_id = "other".into(),
            3 => observations[0].config_hash = "0".repeat(64),
            4 => observations[0].configuration_epoch = "other".into(),
            5 => observations[0].evidence_kind = EvidenceKind::OperatorAttestation,
            _ => observations[0].execution = Execution::Cancelled,
        }
        assert_eq!(
            evaluate(&c, &observations, None, NOW).verdict,
            Verdict::Unknown,
            "mutation {mutation}"
        );
    }
}

#[test]
fn invalid_metadata_is_not_copied_into_the_report() {
    let c = config(Profile::LocalContractV1);
    let mut observations = local_complete(&c);
    observations[0].run_id = "secret://SENTINEL-DO-NOT-OUTPUT".into();
    observations[1].source_id = "SENTINEL-DO-NOT-OUTPUT".into();
    let a = evaluate(&c, &observations, None, NOW);
    assert!(!report::render_markdown(&a).contains("SENTINEL-DO-NOT-OUTPUT"));
    assert!(
        !serde_json::to_string(&a)
            .unwrap()
            .contains("SENTINEL-DO-NOT-OUTPUT")
    );
}

#[test]
fn local_and_generic_check_satisfied_never_prove_aws_authentication() {
    let c = config(Profile::AwsSandboxCoreV1);
    for kind in [
        EvidenceKind::LocalFixture,
        EvidenceKind::LocalConnection,
        EvidenceKind::AwsConfiguration,
        EvidenceKind::AwsConnection,
    ] {
        let mut o = strong(&c, "V07", "V07.missing_auth", "app-proxy");
        o.evidence_kind = kind;
        assert_eq!(
            verdict(&evaluate(&c, &[o], None, NOW), "V07.missing_auth"),
            Verdict::Unknown
        );
    }
}

#[test]
fn timeout_and_tls_failure_are_not_authentication_refusal() {
    let c = config(Profile::AwsSandboxCoreV1);
    for outcome in [Outcome::ConnectionNotEstablished, Outcome::TlsRejected] {
        let mut negative = strong(&c, "V07", "V07.missing_auth", "app-proxy");
        negative.outcome = outcome;
        negative.reason_code = ReasonCode::ConnectTimeout;
        assert_eq!(
            verdict(
                &evaluate(&c, &[positive(&c), negative], None, NOW),
                "V07.missing_auth"
            ),
            Verdict::Unknown
        );
    }
}

#[test]
fn authentication_refusal_requires_same_source_positive_control_and_provenance() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut negative = strong(&c, "V07", "V07.missing_auth", "app-proxy");
    negative.outcome = Outcome::AuthenticationRejected;
    negative.reason_code = ReasonCode::IamDenied;
    negative.path_stages = PathStages {
        transport_reachable: Stage::ObservedTrue,
        tls_established: Stage::ObservedTrue,
        db_authenticated: Stage::ObservedFalse,
    };
    assert_eq!(
        verdict(
            &evaluate(&c, &[negative.clone()], None, NOW),
            "V07.missing_auth"
        ),
        Verdict::Unknown
    );
    assert_eq!(
        verdict(
            &evaluate(&c, &[positive(&c), negative.clone()], None, NOW),
            "V07.missing_auth"
        ),
        Verdict::Unknown
    );
    negative.source_verification = SourceVerification::Declared;
    assert_eq!(
        verdict(
            &evaluate(&c, &[positive(&c), negative], None, NOW),
            "V07.missing_auth"
        ),
        Verdict::Unknown
    );
}

#[test]
fn positive_control_cannot_be_taken_from_a_different_snapshot_or_old_interval() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut negative = strong(&c, "V07", "V07.missing_auth", "app-proxy");
    negative.outcome = Outcome::AuthenticationRejected;
    negative.reason_code = ReasonCode::IamDenied;
    negative.path_stages.tls_established = Stage::ObservedTrue;
    negative.path_stages.transport_reachable = Stage::ObservedTrue;
    negative.path_stages.db_authenticated = Stage::ObservedFalse;
    for change in 0..2 {
        let mut p = positive(&c);
        if change == 0 {
            p.snapshot_hash = "b".repeat(64);
        } else {
            p.observed_at -= 121;
        }
        assert_eq!(
            verdict(
                &evaluate(&c, &[p, negative.clone()], None, NOW),
                "V07.missing_auth"
            ),
            Verdict::Unknown
        );
    }
}

#[test]
fn unlinked_tcp_reachability_claim_is_unconfirmed_without_protocol() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut o = strong(&c, "V09", "V09.application_db_transport", "app-db");
    o.outcome = Outcome::AuthenticationRejected;
    o.path_stages.transport_reachable = Stage::ObservedTrue;
    o.path_stages.db_authenticated = Stage::ObservedFalse;
    assert_eq!(
        verdict(
            &evaluate(&c, &[o], None, NOW),
            "V09.application_db_transport"
        ),
        Verdict::Unknown
    );
}

#[test]
fn direct_path_pass_requires_policy_database_and_positive_control() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut o = strong(&c, "V09", "V09.application_db_transport", "app-db");
    o.outcome = Outcome::ConnectionNotEstablished;
    o.reason_code = ReasonCode::NetworkUnreachable;
    o.path_stages.transport_reachable = Stage::ObservedFalse;
    o.facts
        .extend([Fact::DatabaseAvailable, Fact::NetworkPolicyDenied]);
    assert_eq!(
        verdict(
            &evaluate(&c, &[positive(&c), o.clone()], None, NOW),
            "V09.application_db_transport"
        ),
        Verdict::Unknown
    );
    o.execution = Execution::Timeout;
    o.reason_code = ReasonCode::ConnectTimeout;
    assert_eq!(
        verdict(
            &evaluate(&c, &[positive(&c), o], None, NOW),
            "V09.application_db_transport"
        ),
        Verdict::Unknown
    );
}

#[test]
fn missing_refs_do_not_prove_tls_and_backend_fact_cannot_prove_frontend_tls() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut o = positive(&c);
    o.evidence_refs.clear();
    assert_eq!(
        verdict(&evaluate(&c, &[o], None, NOW), "V08.verified_client_tls"),
        Verdict::Unknown
    );
    let mut o = strong(&c, "V08", "V08.verified_client_tls", "app-proxy");
    o.facts
        .extend([Fact::BackendTlsObserved, Fact::RuntimeTlsRequired]);
    assert_eq!(
        verdict(&evaluate(&c, &[o], None, NOW), "V08.verified_client_tls"),
        Verdict::Unknown
    );
}

#[test]
fn unplanned_cross_epoch_evidence_is_unknown_even_when_a_plan_exists() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut o = positive(&c);
    o.configuration_epoch = "epoch2".into();
    let plan = ExperimentPlan {
        schema_version: 1,
        experiment_id: c.experiment_id.clone(),
        profile: c.assessment_profile,
        phases: vec![],
        protocol: None,
    };
    assert_eq!(
        verdict(
            &evaluate(&c, &[o], Some(&plan), NOW),
            "V08.verified_client_tls"
        ),
        Verdict::Unknown
    );
}

#[test]
fn an_undefined_case_cannot_supply_the_positive_control() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut p = positive(&c);
    p.case_id = "V08.invented_positive".into();
    let mut n = strong(&c, "V07", "V07.missing_auth", "app-proxy");
    n.outcome = Outcome::AuthenticationRejected;
    n.reason_code = ReasonCode::IamDenied;
    n.path_stages = PathStages {
        transport_reachable: Stage::ObservedTrue,
        tls_established: Stage::ObservedTrue,
        db_authenticated: Stage::ObservedFalse,
    };
    assert_eq!(
        verdict(&evaluate(&c, &[p, n], None, NOW), "V07.missing_auth"),
        Verdict::Unknown
    );
}

#[test]
fn bounded_sample_claim_without_protocol_stays_unknown() {
    let mut c = config(Profile::AwsSandboxCoreV1);
    c.performance_profile = Some(PerformanceProfile {
        workload_id: "read".into(),
        samples: 3,
        warmup: 0,
        max_p95_ms: 100,
        max_error_rate: 0.1,
    });
    let mut o = strong(&c, "V13", "V13.bounded_samples", "app-proxy");
    o.outcome = Outcome::Measured;
    o.facts.push(Fact::SamplesBounded);
    o.details = Some(ProbeDetails {
        samples_ms: vec![1, 2],
        sample_count: 3,
        error_count: 1,
        workload_id: Some("read".into()),
        ..ProbeDetails::default()
    });
    assert_eq!(
        verdict(
            &evaluate(&c, &[o.clone()], None, NOW),
            "V13.bounded_samples"
        ),
        Verdict::Unknown
    );
    o.details.as_mut().unwrap().sample_count = 2;
    assert_eq!(
        verdict(&evaluate(&c, &[o], None, NOW), "V13.bounded_samples"),
        Verdict::Unknown
    );
}

#[test]
fn configuration_claim_needs_its_exact_typed_fact_and_actual_configuration_kind() {
    let c = config(Profile::AwsSandboxCoreV1);
    let mut o = observation(
        &c,
        "V03",
        "V03.access_denied",
        "global",
        EvidenceKind::AwsConfiguration,
    );
    o.snapshot_hash = "c".repeat(64);
    o.evidence_refs = vec!["snapshot.json".into()];
    o.facts = vec![Fact::TargetMatched, Fact::AccessDeniedRecorded];
    assert_eq!(
        verdict(&evaluate(&c, &[o.clone()], None, NOW), "V03.access_denied"),
        Verdict::Unknown
    );
    o.facts = vec![Fact::TargetMatched, Fact::EmptyNotAssumedSafe];
    assert_eq!(
        verdict(&evaluate(&c, &[o.clone()], None, NOW), "V03.access_denied"),
        Verdict::Unknown
    );
    o.facts = vec![Fact::TargetMatched, Fact::AccessDeniedRecorded];
    o.evidence_kind = EvidenceKind::LocalFixture;
    assert_eq!(
        verdict(&evaluate(&c, &[o], None, NOW), "V03.access_denied"),
        Verdict::Unknown
    );
}

#[test]
fn cleanup_needs_a_matching_cleanup_phase_and_plan_case() {
    let mut c = config(Profile::AwsSandboxCoreV1);
    c.phase_id = "cleanup".into();
    c.configuration_epoch = "cleanup-epoch".into();
    let mut o = observation(
        &c,
        "V21",
        "V21.ownership",
        "global",
        EvidenceKind::AwsConfiguration,
    );
    o.snapshot_hash = "c".repeat(64);
    o.evidence_refs = vec!["resources.json".into()];
    o.facts = vec![Fact::TargetMatched, Fact::ResourcesOwned];
    assert_eq!(
        verdict(&evaluate(&c, &[o.clone()], None, NOW), "V21.ownership"),
        Verdict::Unknown
    );
    let mut plan = ExperimentPlan {
        schema_version: 1,
        experiment_id: c.experiment_id.clone(),
        profile: c.assessment_profile,
        phases: vec![ExperimentPhase {
            phase_id: c.phase_id.clone(),
            configuration_epoch: c.configuration_epoch.clone(),
            config_hash: o.config_hash.clone(),
            target_id: c.target.id.clone(),
            case_ids: vec![o.case_id.clone()],
        }],
        protocol: None,
    };
    assert_eq!(
        verdict(
            &evaluate(&c, &[o.clone()], Some(&plan), NOW),
            "V21.ownership"
        ),
        Verdict::Unknown
    );
    plan.phases[0].case_ids.clear();
    assert_eq!(
        verdict(&evaluate(&c, &[o], Some(&plan), NOW), "V21.ownership"),
        Verdict::Unknown
    );
}

#[test]
fn future_contracts_and_multi_phase_measurements_cannot_use_generic_success() {
    for (profile, case, v, path) in [
        (Profile::DecoyV1, "V18.isolation", "V18", "global"),
        (
            Profile::ContinuousV1,
            "V20.drift_invalidation",
            "V20",
            "global",
        ),
        (
            Profile::AwsSandboxCoreV1,
            "V13.connection_setup",
            "V13",
            "app-proxy",
        ),
    ] {
        let c = config(profile);
        let o = strong(&c, v, case, path);
        assert_eq!(
            verdict(&evaluate(&c, &[o], None, NOW), case),
            Verdict::Unknown
        );
    }
}

#[test]
fn markdown_escapes_inline_html_and_table_separators() {
    let c = config(Profile::LocalContractV1);
    let mut a = evaluate(&c, &[], None, NOW);
    a.target_id = "<img src=x>|[click](https://example.com)".into();
    let rendered = report::render_markdown(&a);
    assert!(!rendered.contains("<img"));
    assert!(!rendered.contains("[click]"));
    assert!(rendered.contains("&#124;"));
    assert!(rendered.contains("Unknown"));
}
