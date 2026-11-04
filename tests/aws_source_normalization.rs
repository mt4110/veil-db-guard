//! Selected AWS records are untrusted wire claims, not source attestations.
use veil_db_guard::{
    adapters::{
        capabilities_for_policy,
        source::{aws::*, support},
    },
    core::{
        change::{OperationLimits, PreparedChange, prepare_change},
        evidence::*,
        plan::build_plan,
        policy::*,
        source::*,
        state::*,
    },
};
fn fixture(mysql: bool) -> (PreparedChange, ObservationRequest, AwsSelectedCapture) {
    let mut p = parse_policy(if mysql {
        include_str!("../examples/core-aws-mysql-policy.yaml")
    } else {
        include_str!("../examples/core-aws-policy.yaml")
    })
    .unwrap();
    p.schema_version = 2;
    p.targets[0].resource.generation_fingerprint = Some(aws_generation_fingerprint(
        &p.targets[0].placement.account_id,
        &p.targets[0].placement.region,
        &p.targets[0].resource.native_id,
        &p.targets[0].aws.as_ref().unwrap().db_resource_id,
    ));
    p.source_bindings = p
        .subjects
        .iter()
        .enumerate()
        .map(|(i, s)| SourceBinding {
            source_id: s.workload_sources[0].clone(),
            registration_id: format!("source-{i}"),
            revision_digest: format!("{}", i + 1).repeat(64),
            boundary: SourceBoundaryKind::AwsHostNetwork,
            allowed_uses: vec![SourceUse {
                subject_id: s.id.clone(),
                purpose: if i == 0 {
                    SourcePurpose::Application
                } else {
                    SourcePurpose::Recovery
                },
            }],
        })
        .collect();
    p.evaluation = Some(EvaluationPolicy {
        contract: EvaluationContract::SourceBoundV2,
        denial_requirements: vec![ProfileDenialRequirement {
            profile_id: p.protection_profiles[0].id.clone(),
            accepted_layers: vec![AcceptedDenialLayer::ConnectionAuthorization],
        }],
    });
    let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
    let change = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let t = &p.targets[0];
    let source = p.source_bindings[0].clone();
    let aws = t.aws.as_ref().unwrap();
    let request = ObservationRequest {
        schema_version: 1,
        request_id: "aws-request".into(),
        nonce: "a".repeat(64),
        policy_revision_hash: p.revision_hash().unwrap(),
        change_hash: change.change_hash.clone(),
        operation_id: "observation-context".into(),
        source: source.clone(),
        source_trust_epoch: 1,
        evaluation_contract: EvaluationContract::SourceBoundV2,
        collector_build_id: "b".repeat(64),
        verifier_build_id: veil_db_guard::BUILD_ID.into(),
        issued_at: 100,
        expires_at: 220,
        cases: vec![RequestedCase {
            backend_tls_trust: None,
            login_catalog_targets: vec![],
            mysql_account_host: if mysql { Some("%".into()) } else { None },
            id: "connection".into(),
            kind: FixedObservationCase::NewConnection,
            purpose: SourcePurpose::Application,
            endpoint: aws.proxy_endpoint.clone(),
            port: if mysql { 3306 } else { 5432 },
            address_family: AddressFamily::Ipv4,
            address: EffectAddress {
                target_id: t.id.clone(),
                target: TargetHandle {
                    registration_id: t.registration_id.clone(),
                    native_ref: t.resource.clone(),
                    placement: t.placement.clone(),
                    engine_binding: t.engine.clone(),
                    generation_assurance: GenerationAssurance::Unconfirmed,
                },
                grant_id: p.grants[0].id.clone(),
                subject_id: p.grants[0].subject.clone(),
                db_identity: p.grants[0].db_identity.clone(),
                source: source.snapshot_ref(),
                route: StateRoute {
                    id: "app-proxy".into(),
                    kind: RouteKind::NativeProxy,
                },
                effect: EffectKindV2::NewConnections,
            },
        }],
    };
    let user = &p.grants[0].db_identity;
    let sql = if mysql {
        AwsSqlSelection::MySql {
            login_user: user.clone(),
            current_account: format!("{user}@%"),
            active_roles: vec![],
            inventory_complete: true,
            effective_privilege: Some(true),
        }
    } else {
        AwsSqlSelection::PostgreSql {
            session_user: user.clone(),
            current_user: user.clone(),
            login_oid: 100,
            object_oid: Some(200),
            active_roles: vec!["reader".into()],
            inventory_complete: true,
            effective_privilege: Some(true),
        }
    };
    let capture = AwsSelectedCapture {
        schema_version: 1,
        request_digest: request.digest().unwrap(),
        cases: vec![AwsCaseSelection {
            case_id: "connection".into(),
            started_at: 110,
            finished_at: 115,
            stage: AwsObservationStage::Completed,
            session_established: true,
            sqlstate: None,
            mysql_error_code: None,
            database: t.engine.database.clone(),
            engine_version: t.engine.version.clone(),
            proxy_arn: aws.proxy_arn.clone(),
            db_resource_id: aws.db_resource_id.clone(),
            transport: vec![],
            sql: Some(sql),
        }],
    };
    (change, request, capture)
}
#[test]
fn pg_and_mysql_claims_keep_success_without_minting_source_or_admission() {
    for mysql in [false, true] {
        let (change, request, capture) = fixture(mysql);
        let out = normalize(&change, &request, &capture, "selected-proof").unwrap();
        assert_eq!(out.claims[0].observed, StateValue::Allowed);
        assert!(!out.source_verified);
        assert!(!out.admission_available);
        for a in [
            &out.assurances[0].coverage.target,
            &out.assurances[0].coverage.principal,
            &out.assurances[0].coverage.source,
            &out.assurances[0].coverage.route,
            &out.assurances[0].coverage.transport,
            &out.assurances[0].coverage.temporal,
            &out.assurances[0].coverage.completeness,
        ] {
            assert!(!matches!(a, Assurance::Verified { .. }));
        }
        let coverage = support::for_policy(&change.policy).unwrap();
        assert!(coverage.iter().all(|r| {
            r.normalizer_implemented
                && r.collector_implemented
                && r.reasons.contains(&if mysql {
                    support::SourceSupportReason::AwsMysqlMetadataProfileOptIn
                } else {
                    support::SourceSupportReason::AwsPostgresMetadataProfileOptIn
                })
                && !r.native_verified
        }));
    }
}
#[test]
fn auth_errors_tls_failure_and_timeouts_do_not_become_iam_or_route_denial() {
    for mysql in [false, true] {
        for stage in [
            AwsObservationStage::DatabaseLogin,
            AwsObservationStage::Tls,
            AwsObservationStage::Deadline,
            AwsObservationStage::Credential,
        ] {
            let (change, request, mut capture) = fixture(mysql);
            let s = &mut capture.cases[0];
            s.stage = stage;
            s.session_established = false;
            s.sql = None;
            s.sqlstate = Some(if mysql { "28000" } else { "28P01" }.into());
            if mysql {
                s.mysql_error_code = Some(1045)
            }
            let out = normalize(&change, &request, &capture, "proof").unwrap();
            assert_eq!(out.claims[0].observed, StateValue::Unknown);
            assert_ne!(
                out.claims[0].denial_cause,
                Some(DenialCause::PermissionDenied)
            );
            assert_ne!(out.claims[0].denial_cause, Some(DenialCause::RouteBlocked));
        }
    }
}
#[test]
fn generation_nonce_proxy_endpoint_and_provider_scope_are_exact() {
    let (change, request, capture) = fixture(false);
    for n in 0..7 {
        let mut r = request.clone();
        let mut c = capture.clone();
        match n {
            0 => r.nonce = "f".repeat(64),
            1 => c.cases[0].db_resource_id = "db-replacement".into(),
            2 => c.cases[0].proxy_arn.push('x'),
            3 => r.cases[0].endpoint = "attacker.invalid".into(),
            4 => r.source.boundary = SourceBoundaryKind::GceHostNetwork,
            5 => r.cases[0].address.target.native_ref.generation_fingerprint = Some("f".repeat(64)),
            _ => c.cases[0].finished_at = 221,
        };
        assert!(normalize(&change, &r, &c, "proof").is_err(), "case {n}");
    }
}
#[test]
fn mysql_account_host_and_pg_context_cannot_be_substituted_for_each_other() {
    let (change, r, mut c) = fixture(true);
    if let Some(AwsSqlSelection::MySql {
        current_account, ..
    }) = &mut c.cases[0].sql
    {
        *current_account = "billing_app@localhost".into()
    };
    assert!(normalize(&change, &r, &c, "proof").is_err());
    let (_, _, pg) = fixture(false);
    c.cases[0].sql = pg.cases[0].sql.clone();
    assert!(normalize(&change, &r, &c, "proof").is_err());
}
#[test]
fn sql_privilege_and_owned_delta_have_disjoint_effects_and_tls_segments_remain_separate() {
    for mysql in [false, true] {
        let (change, mut r, mut capture) = fixture(mysql);
        let privilege = &change.policy.grants[0].sql_access.privileges[0];
        r.cases[0].kind = FixedObservationCase::EffectiveSqlPrivilege;
        r.cases[0].address.effect = EffectKindV2::EffectiveSqlPrivilege {
            scope: privilege.scope.clone(),
            action: privilege.actions[0],
        };
        capture.request_digest = r.digest().unwrap();
        let out = normalize(&change, &r, &capture, "proof").unwrap();
        assert_eq!(out.claims[0].observed, StateValue::Present);
        assert_eq!(out.claims[0].layer, StateLayer::SqlAuthorization);
        r.cases[0].kind = FixedObservationCase::Transport;
        r.cases[0].address.effect = EffectKindV2::Transport {
            segment: TransportSegment::NativeRouteToDatabase,
        };
        capture.request_digest = r.digest().unwrap();
        capture.cases[0].transport = vec![TransportFact {
            validation_basis: None,
            segment: TransportSegment::ClientToNativeRoute,
            encrypted: Some(true),
            ca_verified: Some(true),
            hostname_verified: Some(true),
            ipc_boundary_verified: None,
            evidence_refs: vec![],
        }];
        assert_eq!(
            normalize(&change, &r, &capture, "proof").unwrap().claims[0].observed,
            StateValue::Unknown
        );
    }
}
#[test]
fn arbitrary_trust_flags_raw_error_fields_oversized_payloads_and_sqlstate_text_are_rejected() {
    let (_, _, capture) = fixture(false);
    let bytes = serde_json::to_vec(&capture).unwrap();
    assert!(AwsSelectedCapture::parse_untrusted(&bytes).is_ok());
    for field in ["source_verified", "identity_verified", "raw_error", "token"] {
        let mut v = serde_json::to_value(&capture).unwrap();
        v[field] = serde_json::json!("PRIVATE_SENTINEL");
        assert!(AwsSelectedCapture::parse_untrusted(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    assert!(AwsSelectedCapture::parse_untrusted(&vec![b'x'; MAX_REQUEST_BYTES + 1]).is_err());
    let mut c = capture;
    c.cases[0].sqlstate = Some("PRIVATE_SENTINEL".into());
    assert!(AwsSelectedCapture::parse_untrusted(&serde_json::to_vec(&c).unwrap()).is_err());
}

#[test]
fn native_gate_rejects_even_complete_serialized_effect_rows_without_a_source_aware_executor() {
    use veil_db_guard::adapters::source::native_gate::{NativeGateReason, evaluate};
    let (change, _, _) = fixture(false);
    let mut report =
        veil_db_guard::adapters::source::state::empty(&change, "context", 120).unwrap();
    assert!(
        report
            .native_step_evidence
            .iter()
            .all(|r| !r.native_dispatch_available && !r.observed_effects_satisfied)
    );
    for row in &mut report.effective.rows {
        row.assessment = StateAssessment::Satisfied;
        row.observed = row.desired.expected;
    }
    let diagnostics = evaluate(&change, &report.effective);
    assert!(diagnostics.iter().all(|r| r.observed_effects_satisfied
        && !r.native_dispatch_available
        && r.reason == NativeGateReason::RuntimeChecksRequired));
}

#[test]
fn approved_aws_route_rejects_manual_alternate_proxy_host_or_port_before_issuing() {
    for mysql in [false, true] {
        let (change, request, _) = fixture(mysql);
        veil_db_guard::core::admission::validate_request_scope(&request, &change).unwrap();
        let mut wrong = request.clone();
        wrong.cases[0].endpoint = "alternate.proxy-other.ap-northeast-1.rds.amazonaws.com".into();
        assert!(veil_db_guard::core::admission::validate_request_scope(&wrong, &change).is_err());
        let mut wrong = request.clone();
        wrong.cases[0].port += 1;
        assert!(veil_db_guard::core::admission::validate_request_scope(&wrong, &change).is_err());
        let mut wrong = request.clone();
        wrong.cases[0].endpoint = change.policy.targets[0]
            .aws
            .as_ref()
            .unwrap()
            .db_endpoint
            .clone();
        assert!(veil_db_guard::core::admission::validate_request_scope(&wrong, &change).is_err());
    }
}

#[test]
fn mysql_account_selector_is_request_bound_and_must_match_the_approved_host() {
    let (change, request, _) = fixture(true);
    let digest = request.digest().unwrap();
    for host in [None, Some("localhost".into())] {
        let mut wrong = request.clone();
        wrong.cases[0].mysql_account_host = host;
        assert_ne!(wrong.digest().unwrap(), digest);
        assert!(veil_db_guard::core::admission::validate_request_scope(&wrong, &change).is_err());
    }
    let (change, mut pg, _) = fixture(false);
    pg.cases[0].mysql_account_host = Some("%".into());
    assert!(pg.validate().is_err());
    assert!(veil_db_guard::core::admission::validate_request_scope(&pg, &change).is_err());
}

#[test]
fn explicit_managed_backend_policy_changes_hash_approval_and_preserves_required_segments() {
    use veil_db_guard::core::{approval, state_v2::desired_for_change_v2};
    for mysql in [false, true] {
        let (strict, _, _) = fixture(mysql);
        let strict_bytes = serde_json::to_vec(&strict.policy).unwrap();
        let strict_hash = strict.policy.revision_hash().unwrap();
        let mut p = strict.policy.clone();
        p.protection_profiles[0].encryption =
            EncryptionRequirement::VerifiedTlsWithAwsRdsProxyManagedBackendV1;
        assert!(p.validate().is_ok());
        assert_ne!(p.revision_hash().unwrap(), strict_hash);
        let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
        let managed = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
        assert_ne!(managed.change_hash, strict.change_hash);
        let prior_approval =
            approval::issue(&strict, "approval", "reviewer", "runner", 300, 900, 100).unwrap();
        assert_ne!(
            prior_approval.policy_revision_hash,
            managed.plan.policy_revision_hash
        );
        assert_ne!(prior_approval.change_hash, managed.change_hash);
        assert!(
            prior_approval
                .validate(&managed, "runner", 101, false)
                .is_err()
        );
        let rows = desired_for_change_v2(&p, None, &[], 100).unwrap();
        let backend = rows
            .iter()
            .filter(|r| {
                r.address.effect
                    == (EffectKindV2::Transport {
                        segment: TransportSegment::NativeRouteToDatabase,
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(backend.len(), 2); // Application and independent recovery.
        assert!(backend.iter().all(|r| r.backend_tls_trust
            == Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1)));
        assert!(
            rows.iter()
                .filter(|r| r.address.effect
                    != (EffectKindV2::Transport {
                        segment: TransportSegment::NativeRouteToDatabase
                    }))
                .all(|r| r.backend_tls_trust.is_none())
        );
        assert!(
            rows.iter()
                .any(|r| r.address.effect == EffectKindV2::RuntimeBinding)
        );
        let mut legacy = p.clone();
        legacy.schema_version = 1;
        legacy.source_bindings.clear();
        legacy.evaluation = None;
        assert!(legacy.validate().is_err());
        legacy.protection_profiles[0].encryption = EncryptionRequirement::VerifiedTls;
        assert!(legacy.validate().is_ok());
        assert_eq!(serde_json::to_vec(&strict.policy).unwrap(), strict_bytes);
        assert_eq!(strict.policy.revision_hash().unwrap(), strict_hash);
    }
}

#[test]
fn backend_trust_request_requires_exact_approved_policy_and_backend_case() {
    use veil_db_guard::core::admission::validate_request_scope;
    let (strict, mut r, _) = fixture(false);
    let c = &mut r.cases[0];
    c.kind = FixedObservationCase::Transport;
    c.address.effect = EffectKindV2::Transport {
        segment: TransportSegment::NativeRouteToDatabase,
    };
    c.backend_tls_trust = Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1);
    assert!(r.validate().is_ok());
    assert!(validate_request_scope(&r, &strict).is_err());
    let mut p = strict.policy.clone();
    p.protection_profiles[0].encryption =
        EncryptionRequirement::VerifiedTlsWithAwsRdsProxyManagedBackendV1;
    let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
    let managed = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    r.policy_revision_hash = managed.plan.policy_revision_hash.clone();
    r.change_hash = managed.change_hash.clone();
    assert!(validate_request_scope(&r, &managed).is_ok());
    let good = r.clone();
    r.cases[0].backend_tls_trust = None;
    assert!(validate_request_scope(&r, &managed).is_err());
    for mode in 0..4 {
        let mut r = good.clone();
        match mode {
            0 => {
                r.cases[0].address.effect = EffectKindV2::Transport {
                    segment: TransportSegment::ClientToNativeRoute,
                }
            }
            1 => r.cases[0].address.route.kind = RouteKind::Direct,
            2 => r.cases[0].address.target.placement.kind = PlacementKind::GcpCloudSql,
            _ => {
                r.source.boundary = SourceBoundaryKind::GceHostNetwork;
                r.cases[0].address.source = r.source.snapshot_ref();
            }
        }
        assert!(r.validate().is_err(), "mode {mode}");
    }
}
