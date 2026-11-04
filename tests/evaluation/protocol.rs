//! Synthetic recorded evidence tests; these do not contact or validate AWS.
use super::*;
use veil_db_guard::{
    config as configuration,
    evaluator::{plan_hash, snapshot_field_hash, validate_protocol_links},
};

const N: u64 = 11_000;

struct Fixture {
    c: TargetConfig,
    plan: ExperimentPlan,
    observations: Vec<Observation>,
}

fn snapshot(c: &TargetConfig, at: u64, kind: PhaseKind) -> InventorySnapshot {
    let mut rules = vec![SecurityRule {
        protocol: "tcp".into(),
        from_port: Some(5432),
        to_port: Some(5432),
        source: RuleSource::SecurityGroup {
            id: "sg-proxy".into(),
        },
    }];
    if kind == PhaseKind::Baseline {
        rules.push(SecurityRule {
            protocol: "tcp".into(),
            from_port: Some(5432),
            to_port: Some(5432),
            source: RuleSource::SecurityGroup {
                id: "sg-app".into(),
            },
        });
    }
    InventorySnapshot {
        schema_version: 1,
        target: c.target.clone(),
        config_hash: configuration::config_hash(c),
        observed_at: at,
        evidence_kind: EvidenceKind::AwsConfiguration,
        db: Some(DbState {
            arn: c.target.db_instance_arn.clone(),
            resource_id: "db-example".into(),
            endpoint: Endpoint {
                host: "example.abc.ap-northeast-1.rds.amazonaws.com".into(),
                port: 5432,
            },
            engine: "postgres".into(),
            engine_version: "16.15".into(),
            iam_auth_enabled: true,
            publicly_accessible: false,
            security_group_ids: vec!["sg-db".into()],
            parameter_group: Some("parameters".into()),
            parameters_in_sync: true,
            force_ssl: Some(true),
            instance_class: Some("db.t4g.small".into()),
            availability_zone: Some("ap-northeast-1a".into()),
        }),
        proxy: Some(ProxyState {
            arn: c.target.proxy_arn.clone(),
            endpoint: Endpoint {
                host: "example.proxy-abc.ap-northeast-1.rds.amazonaws.com".into(),
                port: 5432,
            },
            auth_mode: AuthMode::EndToEndIam,
            require_tls: true,
            security_group_ids: vec!["sg-proxy".into()],
            target_db_resource_id: Some("db-example".into()),
            target_health: if kind == PhaseKind::Fault {
                TargetHealth::Unavailable
            } else {
                TargetHealth::Available
            },
            role_arn: "arn:aws:iam::123456789012:role/proxy".into(),
        }),
        security_groups: vec![SecurityGroup {
            id: "sg-db".into(),
            vpc_id: "vpc-test".into(),
            ingress: rules,
        }],
        retrievals: [
            "describe-db-proxies",
            "describe-db-instances",
            "describe-db-proxy-target-groups",
            "describe-db-proxy-targets",
            "describe-db-parameters",
            "describe-security-groups",
        ]
        .iter()
        .map(|s| Retrieval {
            operation: (*s).into(),
            status: RetrievalStatus::Complete,
        })
        .collect(),
    }
}

fn snapshots(phase: &PhaseContract) -> (SnapshotEvidence, SnapshotEvidence) {
    let before = snapshot(&phase.config, phase.starts_at + 5, phase.kind);
    let after = snapshot(&phase.config, phase.ends_at - 5, phase.kind);
    let evidence = |s: InventorySnapshot, reference: &str| SnapshotEvidence {
        reference_id: reference.into(),
        artifact_hash: configuration::hash_bytes(&serde_json::to_vec(&s).unwrap()),
        snapshot: s,
    };
    (
        evidence(before, &phase.before_snapshot_ref),
        evidence(after, &phase.after_snapshot_ref),
    )
}

fn bind(o: &mut Observation, plan: &ExperimentPlan) {
    let phase = plan
        .protocol
        .as_ref()
        .unwrap()
        .phase_contracts
        .iter()
        .find(|p| p.phase_id == o.phase_id)
        .unwrap();
    let (before, after) = snapshots(phase);
    o.observed_at = phase.starts_at + 20;
    o.duration_ms = 1000;
    o.snapshot_hash = configuration::snapshot_hash(&before.snapshot);
    o.evidence_refs = vec![before.artifact_hash.clone(), after.artifact_hash.clone()];
    o.details.get_or_insert_with(ProbeDetails::default).protocol = Some(ObservationProtocol {
        plan_hash: plan_hash(plan),
        before: Some(before),
        after: Some(after),
        ..Default::default()
    });
}

fn authenticated_record(c: &TargetConfig, v: &str, case: &str, path: &str) -> Observation {
    let source = c
        .paths
        .iter()
        .find(|p| p.id == path)
        .map_or("global", |p| p.source_id.as_str());
    let mut o = Observation::new(
        c,
        "recorded-run",
        v,
        case,
        source,
        path,
        EvidenceKind::AwsConnection,
    );
    o.execution = Execution::Completed;
    o.reason_code = ReasonCode::None;
    o.outcome = Outcome::PostconditionMatched;
    o.source_verification = SourceVerification::Corroborated;
    o.path_stages = PathStages {
        transport_reachable: Stage::ObservedTrue,
        tls_established: Stage::ObservedTrue,
        db_authenticated: Stage::ObservedTrue,
    };
    o.facts = vec![
        Fact::TargetMatched,
        Fact::ChainVerified,
        Fact::HostnameVerified,
        Fact::PostconditionVerified,
        Fact::NoWriteReplay,
    ];
    o
}

fn fixed_fact(case: &str) -> Option<Fact> {
    Some(match case {
        "V02.no_snapshot" => Fact::NoSnapshotMarkedUnknown,
        "V02.partial_snapshot" => Fact::PartialSnapshotMarkedUnknown,
        "V02.new_resources_only" => Fact::OnlyNewResourcesPlanned,
        "V02.bootstrap_recovery" => Fact::BootstrapRecoverySeparated,
        "V03.access_denied" => Fact::AccessDeniedRecorded,
        "V03.page_missing" => Fact::PageMissingRecorded,
        "V03.empty" => Fact::EmptyNotAssumedSafe,
        "V03.ambiguous" => Fact::AmbiguousTargetRejected,
        "V03.foreign_identity" => Fact::ForeignIdentityRejected,
        "V03.target_mismatch" => Fact::TargetMismatchRejected,
        "V06.insert_read" | "V06.update_read" | "V06.delete_read" => Fact::CrudMatched,
        "V06.commit" => Fact::CommitMatched,
        "V06.rollback" => Fact::RollbackMatched,
        "V06.error_rollback" => Fact::ErrorRollbackMatched,
        "V06.session_isolation" => Fact::SessionIsolated,
        "V10.new_token" => Fact::TokenRefreshed,
        "V10.existing_after_expiry" => Fact::ExistingSessionAfterExpiry,
        "V10.aws_credential_expiry" => Fact::AwsCredentialExpiryHandled,
        "V11.deadline" => Fact::DeadlineRespected,
        "V11.cancellation" => Fact::CancellationRespected,
        "V12.recovered_revalidation" => Fact::RecoveryCasesRevalidated,
        "V15.desired_vs_runtime" => Fact::DesiredRuntimeSeparated,
        "V15.health_not_authorization" => Fact::HealthNotAuthorization,
        "V15.configuration_not_connection" => Fact::ConfigurationNotConnection,
        "V16.protocol" => Fact::ProtocolV3,
        "V16.prepared_statement" => Fact::PreparedStatementUsed,
        "V16.pool_reset" => Fact::PoolResetVerified,
        "V16.session_state" => Fact::SessionIsolated,
        "V16.long_transaction" => Fact::LongTransactionVerified,
        "V16.pinning" => Fact::PinningObserved,
        "V21.ownership" => Fact::ResourcesOwned,
        "V21.approved_cleanup" => Fact::CleanupApproved,
        "V21.evidence_preserved" => Fact::EvidencePreserved,
        "V21.residual_resources" => Fact::ResidualResourcesChecked,
        _ => return None,
    })
}

impl Fixture {
    fn new() -> Self {
        let mut c = config(Profile::AwsSandboxCoreV1);
        c.target.engine_version = "16.15".into();
        c.phase_id = "recovered".into();
        c.configuration_epoch = "recovered-epoch".into();
        c.limits.total_timeout_ms = 1_000_000;
        c.performance_profile = Some(PerformanceProfile {
            workload_id: "read".into(),
            samples: 40,
            warmup: 0,
            max_p95_ms: 50,
            max_error_rate: 0.1,
        });
        c.sources.push(Source {
            id: "admin-source".into(),
            kind: SourceKind::VpcHost,
            description: None,
        });
        c.paths.push(PathSpec {
            id: "admin-proxy".into(),
            source_id: "admin-source".into(),
            actor: Actor::Admin,
            destination: Destination::Proxy,
            expected: Expectation::Allow,
            address_family: AddressFamily::Ipv4,
            exception_code: Some("maintenance".into()),
        });
        let required = required_cases(&c);
        let all: std::collections::BTreeSet<_> =
            required.iter().map(|r| r.case_id.clone()).collect();
        let specs = [
            ("baseline", PhaseKind::Baseline, 9000, 9100),
            ("fault", PhaseKind::Fault, 9200, 9300),
            ("recovered", PhaseKind::Recovered, 9400, 10_500),
            ("cleanup", PhaseKind::Cleanup, 10_600, 10_700),
        ];
        let mut plan = ExperimentPlan {
            schema_version: 1,
            experiment_id: c.experiment_id.clone(),
            profile: c.assessment_profile,
            phases: vec![],
            protocol: Some(ExperimentProtocol {
                planned_at: 8900,
                phase_contracts: vec![],
                transitions: vec![],
                comparisons: vec![],
                management: Some(ManagementContract {
                    application_principal_arn: "arn:aws:iam::123456789012:role/app".into(),
                    admin_principal_arn: "arn:aws:iam::123456789012:role/admin".into(),
                    application_db_user: "app".into(),
                    admin_db_user: "admin".into(),
                }),
            }),
        };
        for (id, kind, start, end) in specs {
            let mut pc = c.clone();
            pc.phase_id = id.into();
            pc.configuration_epoch = format!("{id}-epoch");
            if kind == PhaseKind::Baseline {
                pc.paths.push(PathSpec {
                    id: "baseline-db".into(),
                    source_id: "app-source".into(),
                    actor: Actor::Admin,
                    destination: Destination::Database,
                    expected: Expectation::Allow,
                    address_family: AddressFamily::Ipv4,
                    exception_code: Some("baseline-only".into()),
                });
            }
            let case_ids = all
                .iter()
                .filter(|s| match kind {
                    PhaseKind::Baseline => s.starts_with("V13.") && !s.ends_with("bounded_samples"),
                    PhaseKind::Fault => matches!(
                        s.as_str(),
                        "V11.disconnect" | "V11.dns_failure" | "V11.unreachable"
                    ),
                    PhaseKind::Cleanup => s.starts_with("V21."),
                    _ => !s.starts_with("V21."),
                })
                .cloned()
                .collect();
            plan.phases.push(ExperimentPhase {
                phase_id: id.into(),
                configuration_epoch: pc.configuration_epoch.clone(),
                config_hash: configuration::config_hash(&pc),
                target_id: c.target.id.clone(),
                case_ids,
            });
            plan.protocol
                .as_mut()
                .unwrap()
                .phase_contracts
                .push(PhaseContract {
                    phase_id: id.into(),
                    kind,
                    configuration_epoch: pc.configuration_epoch.clone(),
                    config: pc,
                    starts_at: start,
                    ends_at: end,
                    before_snapshot_ref: format!("{id}-before"),
                    after_snapshot_ref: format!("{id}-after"),
                });
        }
        for fault in [
            FaultKind::Disconnect,
            FaultKind::DnsFailure,
            FaultKind::Unreachable,
        ] {
            let case = match fault {
                FaultKind::Disconnect => "V11.disconnect",
                FaultKind::DnsFailure => "V11.dns_failure",
                _ => "V11.unreachable",
            };
            let a = snapshots(&plan.protocol.as_ref().unwrap().phase_contracts[1])
                .1
                .snapshot;
            let b = snapshots(&plan.protocol.as_ref().unwrap().phase_contracts[2])
                .0
                .snapshot;
            plan.protocol
                .as_mut()
                .unwrap()
                .transitions
                .push(PhaseTransition {
                    from_phase: "fault".into(),
                    to_phase: "recovered".into(),
                    fault: Some(fault),
                    case_ids: vec![case.into()],
                    allowed_changes: vec![AllowedStateChange {
                        field: SnapshotField::TargetHealth,
                        before_value_hash: snapshot_field_hash(&a, SnapshotField::TargetHealth),
                        after_value_hash: snapshot_field_hash(&b, SnapshotField::TargetHealth),
                    }],
                });
        }
        let a = snapshots(&plan.protocol.as_ref().unwrap().phase_contracts[0])
            .1
            .snapshot;
        let b = snapshots(&plan.protocol.as_ref().unwrap().phase_contracts[2])
            .0
            .snapshot;
        plan.protocol
            .as_mut()
            .unwrap()
            .transitions
            .push(PhaseTransition {
                from_phase: "baseline".into(),
                to_phase: "recovered".into(),
                fault: None,
                case_ids: vec![
                    "V13.connection_setup".into(),
                    "V13.pooled_query".into(),
                    "V13.pinning".into(),
                    "V13.errors".into(),
                ],
                allowed_changes: vec![AllowedStateChange {
                    field: SnapshotField::SecurityGroupRules,
                    before_value_hash: snapshot_field_hash(&a, SnapshotField::SecurityGroupRules),
                    after_value_hash: snapshot_field_hash(&b, SnapshotField::SecurityGroupRules),
                }],
            });
        for (case, combinations) in [
            (
                "V13.connection_setup",
                vec![(MeasurementKind::ConnectionSetup, PinningScenario::NonPinned)],
            ),
            (
                "V13.pooled_query",
                vec![(MeasurementKind::PooledQuery, PinningScenario::NonPinned)],
            ),
            (
                "V13.pinning",
                vec![
                    (MeasurementKind::PooledQuery, PinningScenario::NonPinned),
                    (MeasurementKind::PooledQuery, PinningScenario::Pinned),
                ],
            ),
            (
                "V13.errors",
                vec![
                    (MeasurementKind::ConnectionSetup, PinningScenario::NonPinned),
                    (MeasurementKind::PooledQuery, PinningScenario::NonPinned),
                    (MeasurementKind::PooledQuery, PinningScenario::Pinned),
                ],
            ),
        ] {
            for (kind, pinning) in combinations {
                plan.protocol
                    .as_mut()
                    .unwrap()
                    .comparisons
                    .push(PerformanceComparison {
                        case_id: case.into(),
                        baseline_phase: "baseline".into(),
                        protected_phase: "recovered".into(),
                        baseline_path: "baseline-db".into(),
                        protected_path: "app-proxy".into(),
                        conditions: MeasurementConditions {
                            workload_id: "read".into(),
                            workload_hash: "d".repeat(64),
                            driver_version: "0.7.18".into(),
                            db_resource_id: "db-example".into(),
                            db_instance_class: Some("db.t4g.small".into()),
                            availability_zone: Some("ap-northeast-1a".into()),
                            runner_os: Some("linux".into()),
                            runner_arch: Some("aarch64".into()),
                            runner_identity_hash: Some("f".repeat(64)),
                            engine_version: "16.15".into(),
                            db_user: "app".into(),
                            concurrency: 1,
                            warmup: 0,
                            retries: 0,
                            tls_verified: true,
                            kind,
                            pinning: Some(pinning),
                        },
                        minimum_success_samples: 20,
                        max_p95_ms: 50,
                        max_error_rate: 0.1,
                    });
            }
        }
        let mut observations = Vec::new();
        for row in required {
            if row.verification_id == "V13" && row.case_id != "V13.bounded_samples" {
                continue;
            }
            let cfg = if row.verification_id == "V21" {
                &plan.protocol.as_ref().unwrap().phase_contracts[3].config
            } else {
                &c
            };
            let mut o = authenticated_record(cfg, &row.verification_id, &row.case_id, &row.path_id);
            if let Some(fact) = fixed_fact(&row.case_id) {
                o.facts.push(fact);
            }
            if matches!(row.verification_id.as_str(), "V02" | "V03" | "V15" | "V21") {
                o.evidence_kind = EvidenceKind::AwsConfiguration;
                o.outcome = Outcome::CheckSatisfied;
            }
            if row.verification_id == "V14" {
                o.evidence_kind = EvidenceKind::LocalFixture;
                o.outcome = Outcome::CheckSatisfied;
            }
            if row.case_id == "V08.verified_client_tls" {
                o.outcome = Outcome::Authenticated;
            }
            if row.case_id == "V08.proxy_db_tls" {
                o.facts
                    .extend([Fact::RuntimeTlsRequired, Fact::BackendTlsObserved]);
            }
            if row.verification_id == "V07" || row.case_id == "V10.expired_new_connection" {
                o.outcome = Outcome::AuthenticationRejected;
                o.reason_code = ReasonCode::IamDenied;
                o.path_stages.db_authenticated = Stage::ObservedFalse;
                o.facts.push(Fact::ExpiredTokenUsed);
            }
            if matches!(
                row.case_id.as_str(),
                "V08.tls_disabled" | "V08.untrusted_ca" | "V08.wrong_hostname"
            ) {
                o.outcome = Outcome::TlsRejected;
                o.reason_code = ReasonCode::TlsRejected;
                o.path_stages.db_authenticated = Stage::ObservedFalse;
            }
            if row.verification_id == "V09" || row.case_id == "V12.application_admin_denied" {
                o.outcome = Outcome::ConnectionNotEstablished;
                o.reason_code = ReasonCode::NetworkUnreachable;
                o.path_stages = PathStages {
                    transport_reachable: Stage::ObservedFalse,
                    tls_established: Stage::Unknown,
                    db_authenticated: Stage::ObservedFalse,
                };
                o.facts
                    .extend([Fact::DatabaseAvailable, Fact::NetworkPolicyDenied]);
            }
            bind(&mut o, &plan);
            if row.verification_id == "V11" {
                let fault = match row.case_id.as_str() {
                    "V11.disconnect" => FaultKind::Disconnect,
                    "V11.dns_failure" => FaultKind::DnsFailure,
                    "V11.unreachable" => FaultKind::Unreachable,
                    "V11.deadline" => FaultKind::Deadline,
                    "V11.cancellation" => FaultKind::Cancellation,
                    _ => FaultKind::AmbiguousCommit,
                };
                o.details
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .operation = Some(OperationPostcondition {
                    operation_id: format!("operation-{}", row.case_id),
                    fault: Some(fault),
                    expected_rows: 1,
                    observed_rows: 1,
                    write_attempts: usize::from(fault == FaultKind::AmbiguousCommit),
                    replay_attempts: 0,
                });
                if matches!(
                    fault,
                    FaultKind::Disconnect | FaultKind::DnsFailure | FaultKind::Unreachable
                ) {
                    let fc = &plan.protocol.as_ref().unwrap().phase_contracts[1].config;
                    let mut failed = authenticated_record(fc, "V11", &row.case_id, &row.path_id);
                    failed.outcome = if fault == FaultKind::Disconnect {
                        Outcome::Interrupted
                    } else {
                        Outcome::ConnectionNotEstablished
                    };
                    failed.reason_code = ReasonCode::NetworkUnreachable;
                    failed.path_stages = PathStages::default();
                    bind(&mut failed, &plan);
                    failed
                        .details
                        .as_mut()
                        .unwrap()
                        .protocol
                        .as_mut()
                        .unwrap()
                        .operation = o
                        .details
                        .as_ref()
                        .unwrap()
                        .protocol
                        .as_ref()
                        .unwrap()
                        .operation
                        .clone();
                    observations.push(failed);
                }
            }
            if row.verification_id == "V12" && row.case_id != "V12.recovered_revalidation" {
                o.details
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .identity = Some(IdentityEvidence {
                    iam_principal_arn: format!(
                        "arn:aws:iam::123456789012:role/{}",
                        if row.case_id.ends_with("admin_allowed") {
                            "admin"
                        } else {
                            "app"
                        }
                    ),
                    requested_db_user: "admin".into(),
                    authenticated_db_user: if row.case_id.ends_with("admin_allowed") {
                        Some("admin".into())
                    } else {
                        None
                    },
                });
            }
            if row.case_id == "V13.bounded_samples" {
                o.outcome = Outcome::Measured;
                o.facts.push(Fact::SamplesBounded);
                let d = o.details.as_mut().unwrap();
                d.sample_count = 20;
                d.samples_ms = vec![10; 20];
                d.p95_ms = Some(10);
                d.workload_id = Some("read".into());
            }
            observations.push(o);
        }
        for comparison in &plan.protocol.as_ref().unwrap().comparisons {
            for baseline in [true, false] {
                let cfg = if baseline {
                    &plan.protocol.as_ref().unwrap().phase_contracts[0].config
                } else {
                    &c
                };
                let path = if baseline {
                    &comparison.baseline_path
                } else {
                    &comparison.protected_path
                };
                let mut o = authenticated_record(cfg, "V13", &comparison.case_id, path);
                o.outcome = Outcome::Measured;
                bind(&mut o, &plan);
                let d = o.details.as_mut().unwrap();
                d.sample_count = 20;
                d.samples_ms = vec![if baseline { 20 } else { 10 }; 20];
                d.p95_ms = Some(if baseline { 20 } else { 10 });
                d.connection_mode = Some(if baseline {
                    Destination::Database
                } else {
                    Destination::Proxy
                });
                d.workload_id = Some("read".into());
                let p = d.protocol.as_mut().unwrap();
                p.measurement = Some(comparison.conditions.clone());
                p.pinning = Some(PinningEvidence {
                    starts_at: o.observed_at,
                    ends_at: o.observed_at + 1,
                    pinned_connections: if comparison.conditions.pinning
                        == Some(PinningScenario::Pinned)
                    {
                        vec![1, 1]
                    } else {
                        vec![0, 0]
                    },
                });
                observations.push(o);
            }
        }
        Self {
            c,
            plan,
            observations,
        }
    }
    fn assessment(&self) -> Assessment {
        evaluate(&self.c, &self.observations, Some(&self.plan), N)
    }
}

#[test]
fn complete_synthetic_core_evidence_is_evaluable_without_claiming_real_aws_execution() {
    let f = Fixture::new();
    let a = f.assessment();
    let failures: Vec<_> = a
        .cases
        .iter()
        .filter(|c| c.verdict != Verdict::Pass)
        .map(|c| (&c.case_id, &c.path_id, c.verdict, c.reason_code))
        .collect();
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(a.verdict, Verdict::Pass);
}

#[test]
fn recovery_requires_observed_fault_transition_and_matching_postcondition() {
    let mut f = Fixture::new();
    f.observations
        .retain(|o| !(o.case_id == "V11.disconnect" && o.phase_id == "fault"));
    assert_eq!(verdict(&f.assessment(), "V11.disconnect"), Verdict::Unknown);
    let mut f = Fixture::new();
    let o = f
        .observations
        .iter_mut()
        .find(|o| o.case_id == "V11.disconnect" && o.phase_id == "recovered")
        .unwrap();
    o.details
        .as_mut()
        .unwrap()
        .protocol
        .as_mut()
        .unwrap()
        .operation
        .as_mut()
        .unwrap()
        .observed_rows = 2;
    assert_eq!(verdict(&f.assessment(), "V11.disconnect"), Verdict::Fail);
}

#[test]
fn plan_hash_or_snapshot_content_or_unapproved_change_cannot_be_substituted() {
    for mutation in 0..3 {
        let mut f = Fixture::new();
        let o = f
            .observations
            .iter_mut()
            .find(|o| o.case_id == "V11.disconnect" && o.phase_id == "recovered")
            .unwrap();
        let p = o.details.as_mut().unwrap().protocol.as_mut().unwrap();
        match mutation {
            0 => p.plan_hash = "0".repeat(64),
            1 => {
                p.after
                    .as_mut()
                    .unwrap()
                    .snapshot
                    .db
                    .as_mut()
                    .unwrap()
                    .iam_auth_enabled = false
            }
            _ => {
                p.before
                    .as_mut()
                    .unwrap()
                    .snapshot
                    .proxy
                    .as_mut()
                    .unwrap()
                    .require_tls = false
            }
        }
        assert_eq!(
            verdict(&f.assessment(), "V11.disconnect"),
            Verdict::Unknown,
            "mutation {mutation}"
        );
    }
}

#[test]
fn performance_checks_raw_counts_conditions_pinning_and_all_retries() {
    for mutation in 0..5 {
        let mut f = Fixture::new();
        let o = f
            .observations
            .iter_mut()
            .find(|o| o.case_id == "V13.connection_setup" && o.phase_id == "recovered")
            .unwrap();
        match mutation {
            0 => {
                o.details
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .measurement
                    .as_mut()
                    .unwrap()
                    .concurrency = 2
            }
            1 => o.details.as_mut().unwrap().sample_count = 21,
            2 => {
                o.details
                    .as_mut()
                    .unwrap()
                    .protocol
                    .as_mut()
                    .unwrap()
                    .pinning
                    .as_mut()
                    .unwrap()
                    .pinned_connections = vec![0, 1]
            }
            3 => {
                let d = o.details.as_mut().unwrap();
                d.samples_ms = vec![100; 20];
                d.p95_ms = Some(100);
            }
            _ => {
                let mut bad = o.clone();
                bad.attempt_id = "retry-bad".into();
                let d = bad.details.as_mut().unwrap();
                d.samples_ms = vec![100; 20];
                d.p95_ms = Some(100);
                f.observations.push(bad);
            }
        }
        assert_eq!(
            verdict(&f.assessment(), "V13.connection_setup"),
            if mutation >= 3 {
                Verdict::Fail
            } else {
                Verdict::Unknown
            },
            "mutation {mutation}"
        );
    }
}

#[test]
fn recovered_validation_cannot_reuse_old_phase_or_omit_a_negative_case() {
    let mut f = Fixture::new();
    f.observations.retain(|o| o.case_id != "V07.bad_signature");
    assert_eq!(
        verdict(&f.assessment(), "V12.recovered_revalidation"),
        Verdict::Unknown
    );
}

#[test]
fn management_identity_must_differ_and_match_the_observed_principal() {
    let mut f = Fixture::new();
    let o = f
        .observations
        .iter_mut()
        .find(|o| o.case_id == "V12.admin_allowed")
        .unwrap();
    o.details
        .as_mut()
        .unwrap()
        .protocol
        .as_mut()
        .unwrap()
        .identity
        .as_mut()
        .unwrap()
        .iam_principal_arn = "arn:aws:iam::123456789012:role/app".into();
    assert_eq!(
        verdict(&f.assessment(), "V12.admin_allowed"),
        Verdict::Unknown
    );
}

#[test]
fn imported_nested_snapshots_must_match_the_manifest_verified_artifact() {
    let f = Fixture::new();
    let o = f
        .observations
        .iter()
        .find(|o| o.case_id == "V11.disconnect" && o.phase_id == "recovered")
        .unwrap();
    let p = o.details.as_ref().unwrap().protocol.as_ref().unwrap();
    let mut index: Vec<_> = [&p.before, &p.after]
        .into_iter()
        .flatten()
        .map(|e| (e.artifact_hash.clone(), e.snapshot.clone()))
        .collect();
    assert!(validate_protocol_links(o, &index));
    assert!(!validate_protocol_links(o, &[]));
    index[0].1.db.as_mut().unwrap().resource_id = "db-other".into();
    assert!(!validate_protocol_links(o, &index));
}

#[test]
fn operation_facts_without_recorded_attempts_and_rows_never_pass() {
    for case in ["V11.deadline", "V11.cancellation", "V11.ambiguous_commit"] {
        let mut f = Fixture::new();
        let o = f
            .observations
            .iter_mut()
            .find(|o| o.case_id == case && o.phase_id == "recovered")
            .unwrap();
        o.details
            .as_mut()
            .unwrap()
            .protocol
            .as_mut()
            .unwrap()
            .operation = None;
        assert_eq!(verdict(&f.assessment(), case), Verdict::Unknown, "{case}");
    }
}

#[test]
fn direct_reachability_and_authentication_refusal_have_distinct_real_protocol_results() {
    let mut f = Fixture::new();
    let o = f
        .observations
        .iter_mut()
        .find(|o| o.case_id == "V09.application_db_transport")
        .unwrap();
    o.path_stages.transport_reachable = Stage::ObservedTrue;
    o.outcome = Outcome::AuthenticationRejected;
    assert_eq!(
        verdict(&f.assessment(), "V09.application_db_transport"),
        Verdict::Fail
    );
    let mut f = Fixture::new();
    f.observations
        .retain(|o| o.case_id != "V08.verified_client_tls");
    assert_eq!(
        verdict(&f.assessment(), "V07.missing_auth"),
        Verdict::Unknown
    );
}

#[test]
fn observed_instance_class_and_az_must_match_comparison_conditions() {
    for which in 0..2 {
        let mut f = Fixture::new();
        let o = f
            .observations
            .iter_mut()
            .find(|o| o.case_id == "V13.connection_setup" && o.phase_id == "recovered")
            .unwrap();
        let m = o
            .details
            .as_mut()
            .unwrap()
            .protocol
            .as_mut()
            .unwrap()
            .measurement
            .as_mut()
            .unwrap();
        if which == 0 {
            m.db_instance_class = Some("db.r7g.large".into());
        } else {
            m.availability_zone = Some("ap-northeast-1c".into());
        }
        assert_eq!(
            verdict(&f.assessment(), "V13.connection_setup"),
            Verdict::Unknown
        );
    }
}

fn refresh(f: &mut Fixture) {
    for o in &mut f.observations {
        let saved = o.details.as_ref().and_then(|d| d.protocol.clone());
        bind(o, &f.plan);
        if let Some(saved) = saved {
            let p = o.details.as_mut().unwrap().protocol.as_mut().unwrap();
            p.operation = saved.operation;
            p.identity = saved.identity;
            p.measurement = saved.measurement;
            p.pinning = saved.pinning.map(|mut pinning| {
                pinning.starts_at = o.observed_at;
                pinning.ends_at = o.observed_at + 1;
                pinning
            });
        }
    }
}

#[test]
fn measurement_in_one_protected_phase_cannot_fulfill_another_phase_row() {
    let mut f = Fixture::new();
    let mut phase = f.plan.protocol.as_ref().unwrap().phase_contracts[2].clone();
    phase.phase_id = "later".into();
    phase.configuration_epoch = "later-epoch".into();
    phase.config.phase_id = phase.phase_id.clone();
    phase.config.configuration_epoch = phase.configuration_epoch.clone();
    phase.starts_at = 10_510;
    phase.ends_at = 10_590;
    phase.before_snapshot_ref = "later-before".into();
    phase.after_snapshot_ref = "later-after".into();
    f.plan.phases.insert(
        3,
        ExperimentPhase {
            phase_id: phase.phase_id.clone(),
            configuration_epoch: phase.configuration_epoch.clone(),
            config_hash: configuration::config_hash(&phase.config),
            target_id: f.c.target.id.clone(),
            case_ids: vec!["V13.connection_setup".into()],
        },
    );
    f.plan
        .protocol
        .as_mut()
        .unwrap()
        .phase_contracts
        .insert(3, phase.clone());
    let mut later = f
        .observations
        .iter()
        .find(|o| o.case_id == "V13.connection_setup" && o.phase_id == "recovered")
        .unwrap()
        .clone();
    later.phase_id = phase.phase_id.clone();
    later.configuration_epoch = phase.configuration_epoch.clone();
    later.config_hash = configuration::config_hash(&phase.config);
    later.attempt_id = "later-measurement".into();
    f.observations.push(later);
    refresh(&mut f);
    let a = f.assessment();
    let rows: Vec<_> = a
        .cases
        .iter()
        .filter(|r| r.case_id == "V13.connection_setup")
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .find(|r| r.phase_id.as_deref() == Some("recovered"))
            .unwrap()
            .verdict,
        Verdict::Pass
    );
    assert_eq!(
        rows.iter()
            .find(|r| r.phase_id.as_deref() == Some("later"))
            .unwrap()
            .verdict,
        Verdict::Unknown
    );
}

#[test]
fn changed_source_kind_or_address_family_is_not_the_same_performance_origin() {
    for which in 0..2 {
        let mut f = Fixture::new();
        let p = &mut f.plan.protocol.as_mut().unwrap().phase_contracts[0];
        if which == 0 {
            p.config
                .sources
                .iter_mut()
                .find(|s| s.id == "app-source")
                .unwrap()
                .kind = SourceKind::Tunnel;
        } else {
            p.config
                .paths
                .iter_mut()
                .find(|s| s.id == "baseline-db")
                .unwrap()
                .address_family = AddressFamily::Ipv6;
        }
        f.plan.phases[0].config_hash = configuration::config_hash(&p.config);
        refresh(&mut f);
        assert!(veil_db_guard::evaluator::validate_experiment_plan(&f.c, &f.plan).is_err());
        assert_eq!(f.assessment().verdict, Verdict::Unknown);
    }
}

#[test]
fn additional_protected_application_paths_are_explicitly_unsupported_not_silently_omitted() {
    let mut f = Fixture::new();
    let p = &mut f.plan.protocol.as_mut().unwrap().phase_contracts[2];
    let mut source = p.config.sources[0].clone();
    source.id = "new-source".into();
    p.config.sources.push(source);
    for (id, destination, expected) in [
        ("new-proxy", Destination::Proxy, Expectation::Allow),
        ("new-db", Destination::Database, Expectation::Deny),
    ] {
        p.config.paths.push(PathSpec {
            id: id.into(),
            source_id: "new-source".into(),
            actor: Actor::Application,
            destination,
            expected,
            address_family: AddressFamily::Ipv4,
            exception_code: None,
        });
    }
    f.plan.phases[2].config_hash = configuration::config_hash(&p.config);
    refresh(&mut f);
    assert!(veil_db_guard::evaluator::validate_experiment_plan(&f.c, &f.plan).is_err());
    let a = f.assessment();
    assert_eq!(a.verdict, Verdict::Unknown);
    assert!(
        a.cases
            .iter()
            .any(|r| r.path_id == "app-proxy" && r.verdict == Verdict::Unknown)
    );
}

#[test]
fn arbitrary_protocol_strings_are_rejected_before_summary_rendering() {
    let mut f = Fixture::new();
    f.plan.protocol.as_mut().unwrap().phase_contracts[2].phase_id = "SENTINEL<script>".into();
    let a = f.assessment();
    assert_eq!(a.verdict, Verdict::Unknown);
    assert!(!report::render_markdown(&a).contains("SENTINEL"));
    let mut f = Fixture::new();
    let o = f
        .observations
        .iter_mut()
        .find(|o| o.case_id == "V11.deadline")
        .unwrap();
    o.details
        .as_mut()
        .unwrap()
        .protocol
        .as_mut()
        .unwrap()
        .operation
        .as_mut()
        .unwrap()
        .operation_id = "SENTINEL<script>".into();
    assert!(veil_db_guard::evaluator::validate_observation_protocol(o, &f.c).is_err());
}
