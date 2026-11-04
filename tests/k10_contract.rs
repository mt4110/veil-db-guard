//! K10-A is an offline contract foundation, not a live source verifier.
use serde_json::{Value, json};
use veil_db_guard::{
    adapters::{capabilities_for, capabilities_for_policy, qualification::*},
    core::{
        approval::{self, ApprovalError, ApprovalGrant},
        capability::{ActionKind, Implementation, requires_source_evidence},
        change::{
            DifferenceField, DifferenceKind, OperationLimits, PreparedChange, prepare_change,
        },
        evidence::*,
        plan::{PlanError, build_plan},
        policy::*,
        source::*,
        state::{self, ArtifactRef, StateLayer, StateRoute, StateValue},
    },
};

fn policy() -> PolicyRevision {
    parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap()
}
fn prepare(p: &PolicyRevision, prior: Option<&PolicyRevision>) -> PreparedChange {
    let plan = build_plan(p, capabilities_for_policy(p).unwrap(), vec![], 100).unwrap();
    prepare_change(p, &plan, &[], prior, OperationLimits::default()).unwrap()
}
fn next(p: &PolicyRevision) -> PolicyRevision {
    let mut p = p.clone();
    p.parent_revision_hash = Some(p.revision_hash().unwrap());
    p.revision += 1;
    p
}
fn request() -> ObservationRequest {
    let p = policy();
    let t = &p.targets[0];
    let source = p
        .source_bindings
        .iter()
        .find(|b| b.source_id == "billing-runtime")
        .unwrap()
        .clone();
    let address = EffectAddress {
        target_id: t.id.clone(),
        target: TargetHandle {
            registration_id: t.registration_id.clone(),
            native_ref: ResourceIdentity {
                native_id: t.resource.native_id.clone(),
                generation_fingerprint: Some("c".repeat(64)),
            },
            placement: t.placement.clone(),
            engine_binding: t.engine.clone(),
            generation_assurance: GenerationAssurance::Confirmed,
        },
        grant_id: p.grants[0].id.clone(),
        subject_id: "billing-app".into(),
        db_identity: p.grants[0].db_identity.clone(),
        source: source.snapshot_ref(),
        route: StateRoute {
            id: "app-connector".into(),
            kind: RouteKind::NativeConnector,
        },
        effect: EffectKindV2::NewConnections,
    };
    ObservationRequest {
        schema_version: 1,
        request_id: "request-1".into(),
        nonce: "d".repeat(64), // Fixed test value, NOT production entropy.
        policy_revision_hash: p.revision_hash().unwrap(),
        change_hash: "e".repeat(64),
        operation_id: "operation-1".into(),
        source,
        source_trust_epoch: 1,
        evaluation_contract: EvaluationContract::SourceBoundV2,
        collector_build_id: "f".repeat(64),
        verifier_build_id: "a".repeat(64),
        issued_at: 100,
        expires_at: 200,
        cases: vec![RequestedCase {
            backend_tls_trust: None,
            login_catalog_targets: vec![],
            mysql_account_host: None,
            id: "allowed".into(),
            kind: FixedObservationCase::NewConnection,
            address,
            purpose: SourcePurpose::Application,
            endpoint: "db.example.invalid".into(),
            port: 5432,
            address_family: AddressFamily::Ipv4,
        }],
    }
}
fn bundle() -> ObservationBundleWire {
    let r = request();
    ObservationBundleWire {
        schema_version: 1,
        request_digest: r.digest().unwrap(),
        collector_build_id: r.collector_build_id,
        started_at: 110,
        finished_at: 115,
        capture_complete: false,
        claims: vec![ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: "claim-1".into(),
            case_id: "allowed".into(),
            policy_revision_hash: r.policy_revision_hash,
            address: r.cases[0].address.clone(),
            started_at: 111,
            finished_at: 114,
            observed: StateValue::Allowed,
            layer: StateLayer::Authentication,
            denial_cause: None,
            connection: None,
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec!["capture".into()],
            permission_inventory: None,
        }],
        artifacts: vec![ArtifactRef {
            id: "capture".into(),
            sha256: "a".repeat(64),
        }],
    }
}

#[test]
fn frozen_v1_policy_plan_change_and_approval_remain_valid_without_rehash_upgrade() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/k10/v1-changes.json")).unwrap();
    for (_, value) in fixture.as_object().unwrap() {
        let c: PreparedChange = serde_json::from_value(value.clone()).unwrap();
        c.verify().unwrap();
        assert_eq!(
            c.policy.revision_hash().unwrap(),
            c.plan.policy_revision_hash
        );
        assert!(c.policy.source_bindings.is_empty());
        assert!(c.policy.evaluation.is_none());
        assert_eq!(serde_json::to_value(&c).unwrap(), *value);
        assert_eq!(
            capabilities_for_policy(&c.policy).unwrap(),
            c.policy
                .targets
                .iter()
                .flat_map(capabilities_for)
                .collect::<Vec<_>>()
        );
        assert!(qualify_change(&c).unwrap().is_qualified());
    }
    let c: PreparedChange = serde_json::from_value(fixture["gcp-pg"].clone()).unwrap();
    let a: ApprovalGrant =
        serde_json::from_str(include_str!("fixtures/k10/v1-approval.json")).unwrap();
    a.validate(&c, &a.execution_identity, a.issued_at, false)
        .unwrap();
    assert_eq!(
        a.policy_revision_hash,
        "b7245e515bc39bb3b30299fd2b074097c3eb1c7336c7f2c9c5fa51a42ef9cfd6"
    );
}

#[test]
fn v2_is_strict_and_does_not_automatically_promote_v1_sources() {
    let p = policy();
    let mut old = p.clone();
    old.schema_version = 1;
    assert!(old.validate().is_err());
    old.source_bindings.clear();
    old.evaluation = None;
    old.validate().unwrap();
    assert_ne!(p.revision_hash().unwrap(), old.revision_hash().unwrap());
    let mut upgraded = old.clone();
    upgraded.schema_version = 2;
    assert!(upgraded.validate().is_err());
    let raw = serde_json::to_string(&p).unwrap();
    assert_eq!(parse_policy(&raw).unwrap(), p.normalized());
    for bad in [
        raw.replace("\"schema_version\":2", "\"schema_version\":99"),
        raw.replace("\"source_bound_v2\"", "\"source_bound_v99\""),
        raw.replacen("\"source_id\":", "\"confirmed\":true,\"source_id\":", 1),
    ] {
        assert!(parse_policy(&bad).is_err());
    }
}

#[test]
fn source_and_denial_requirements_are_canonical_and_hash_relevant() {
    let p = policy();
    let mut q = p.clone();
    q.source_bindings.reverse();
    q.subjects.reverse();
    assert_eq!(p.revision_hash().unwrap(), q.revision_hash().unwrap());
    q.source_bindings[0].revision_digest = "c".repeat(64);
    assert_ne!(p.revision_hash().unwrap(), q.revision_hash().unwrap());
    let mut q = p.clone();
    q.evaluation.as_mut().unwrap().denial_requirements[0]
        .accepted_layers
        .push(AcceptedDenialLayer::DatabaseLogin);
    assert_ne!(p.revision_hash().unwrap(), q.revision_hash().unwrap());
    q.evaluation.as_mut().unwrap().denial_requirements[0]
        .accepted_layers
        .reverse();
    let hash = q.revision_hash().unwrap();
    q.evaluation.as_mut().unwrap().denial_requirements[0]
        .accepted_layers
        .reverse();
    assert_eq!(hash, q.revision_hash().unwrap());
}

#[test]
fn missing_duplicate_unused_or_management_on_application_source_is_rejected() {
    let p = policy();
    let mut cases = vec![];
    let mut q = p.clone();
    q.source_bindings.pop();
    cases.push(q);
    let mut q = p.clone();
    q.source_bindings.push(q.source_bindings[0].clone());
    cases.push(q);
    let mut q = p.clone();
    q.source_bindings[0].registration_id = q.source_bindings[1].registration_id.clone();
    cases.push(q);
    let mut q = p.clone();
    q.source_bindings[0].allowed_uses[0].subject_id = "missing".into();
    cases.push(q);
    let mut q = p.clone();
    q.source_bindings[0].allowed_uses[0].purpose = SourcePurpose::Recovery;
    cases.push(q);
    let mut q = p.clone();
    q.source_bindings[1].allowed_uses[0].purpose = SourcePurpose::Application;
    cases.push(q);
    let mut q = p.clone();
    q.evaluation.as_mut().unwrap().denial_requirements.clear();
    cases.push(q);
    let mut q = p.clone();
    q.evaluation.as_mut().unwrap().denial_requirements[0]
        .accepted_layers
        .clear();
    cases.push(q);
    let mut q = p.clone();
    q.source_bindings[0].allowed_uses.push(SourceUse {
        subject_id: "recovery-operator".into(),
        purpose: SourcePurpose::Recovery,
    });
    cases.push(q);
    for q in cases {
        assert!(q.validate().is_err());
    }
}

#[test]
fn source_or_denial_changes_require_a_new_plan_diff_and_approval() {
    let p = policy();
    let c = prepare(&p, None);
    let a = approval::issue(&c, "approval-1", "reviewer", "runner", 200, 300, 100).unwrap();
    for denial_change in [false, true] {
        let mut q = next(&p);
        if denial_change {
            q.evaluation.as_mut().unwrap().denial_requirements[0]
                .accepted_layers
                .push(AcceptedDenialLayer::DatabaseLogin);
        } else {
            q.source_bindings[0].revision_digest = "c".repeat(64);
        }
        let d = prepare(&q, Some(&p));
        assert_ne!(c.change_hash, d.change_hash);
        assert_ne!(
            c.plan.steps[0].parameters_hash,
            d.plan.steps[0].parameters_hash
        );
        assert!(
            d.differences
                .iter()
                .any(|row| row.field == DifferenceField::PolicyGrant
                    && row.kind == DifferenceKind::Changed)
        );
        assert_eq!(
            a.validate(&d, "runner", 101, false),
            Err(ApprovalError::ScopeMismatch)
        );
    }
}

#[test]
fn v2_capabilities_are_policy_scoped_and_cannot_dispatch_with_legacy_or_forged_descriptors() {
    let p = policy();
    let without_descriptors = build_plan(&p, vec![], vec![], 100).unwrap();
    assert!(
        without_descriptors
            .steps
            .iter()
            .filter(|s| requires_source_evidence(s.action))
            .all(|s| s.adapter_contract == SOURCE_BOUND_ADAPTER_CONTRACT)
    );
    assert!(!without_descriptors.capability_gaps.is_empty());
    assert_eq!(
        build_plan(
            &p,
            p.targets.iter().flat_map(capabilities_for).collect(),
            vec![],
            100
        )
        .unwrap_err(),
        PlanError::CapabilityInvalid
    );
    let mut caps = capabilities_for_policy(&p).unwrap();
    assert!(
        caps.iter()
            .filter(|c| requires_source_evidence(c.action))
            .all(|c| c.contract_revision
                == veil_db_guard::core::source_execution::SOURCE_BOUND_EXECUTION_CONTRACT
                && c.implementation == Implementation::Implemented)
    );
    // Old evaluation-only descriptors, even marked implemented, cannot enable
    // the executable contract without replan and reapproval.
    for cap in &mut caps {
        cap.implementation = Implementation::Implemented;
        cap.contract_revision = if requires_source_evidence(cap.action) {
            SOURCE_BOUND_ADAPTER_CONTRACT
        } else {
            "core-adapter-v2"
        }
        .into();
    }
    let plan = build_plan(&p, caps, vec![], 100).unwrap();
    let c = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
    let report = qualify_change(&c).unwrap();
    assert!(!report.is_qualified());
    assert!(!report.is_dispatch_qualified());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.reason == QualificationReason::ContractMismatch)
    );
}

#[test]
fn v2_cannot_be_silently_evaluated_by_v1_state() {
    assert_eq!(
        state::desired_for_policy(&policy(), &[], 100),
        Err(state::StateError::Invalid)
    );
}

#[test]
fn registration_digest_binds_vm_generation_key_build_context_and_trust_epoch() {
    let snapshot = SourceRegistrationSnapshot {
        schema_version: 1,
        registration_id: "source-registration".into(),
        trust_epoch: 1,
        native_identity: GceVmIdentity {
            project_id: "example-project".into(),
            project_number: "1234567890".into(),
            zone: "asia-northeast1-a".into(),
            instance_id: "9876543210".into(),
            created_at_unix: 100,
            service_account: "app@example-project.iam.gserviceaccount.com".into(),
            service_account_id: "123456789012345678901".into(),
        },
        ssh_host_key_digest: "a".repeat(64),
        collector_build_id: "b".repeat(64),
        collector_config_digest: "c".repeat(64),
        network_context_digest: "d".repeat(64),
        execution_user: "collector".into(),
        credential_kind: SourceCredentialKind::GceMetadata,
        credential_reference: "vm-metadata-only".into(),
        gce_host: None,
    };
    let digest = snapshot.revision_digest().unwrap();
    let mut b = policy().source_bindings[0].clone();
    b.registration_id = snapshot.registration_id.clone();
    b.revision_digest = digest.clone();
    assert!(snapshot.matches_binding(&b).unwrap());
    for i in 0..7 {
        let mut s = snapshot.clone();
        match i {
            0 => s.trust_epoch += 1,
            1 => s.native_identity.instance_id.push('1'),
            2 => s.native_identity.created_at_unix += 1,
            3 => s.ssh_host_key_digest = "e".repeat(64),
            4 => s.collector_build_id = "f".repeat(64),
            5 => s.network_context_digest = "a".repeat(64),
            _ => s.execution_user = "other-user".into(),
        }
        assert_ne!(s.revision_digest().unwrap(), digest);
        assert!(!s.matches_binding(&b).unwrap());
    }
}

#[test]
fn request_nonce_scope_build_and_time_are_bound_and_fixed_cases_are_bounded() {
    let r = request();
    r.validate().unwrap();
    let digest = r.digest().unwrap();
    for i in 0..4 {
        let mut s = r.clone();
        match i {
            0 => s.nonce = "e".repeat(64),
            1 => s.source_trust_epoch += 1,
            2 => s.verifier_build_id = "b".repeat(64),
            _ => s.cases[0].address_family = AddressFamily::Ipv6,
        }
        assert_ne!(s.digest().unwrap(), digest);
    }
    let mut s = r.clone();
    s.expires_at = s.issued_at + MAX_REQUEST_TTL_SECONDS + 1;
    assert_eq!(s.validate(), Err(EvidenceError::Invalid));
    let mut s = r.clone();
    s.cases = vec![s.cases[0].clone(); MAX_CASES_PER_SOURCE + 1];
    assert_eq!(s.validate(), Err(EvidenceError::Limit));
    let mut s = r.clone();
    s.cases[0].address.source.revision_digest = "f".repeat(64);
    assert_eq!(s.validate(), Err(EvidenceError::Invalid));
    let mut s = r.clone();
    s.cases[0].purpose = SourcePurpose::Recovery;
    assert_eq!(s.validate(), Err(EvidenceError::Invalid));
    let mut value = serde_json::to_value(&r).unwrap();
    value["shell"] = json!("anything");
    assert_eq!(
        ObservationRequest::parse_untrusted(&serde_json::to_vec(&value).unwrap()),
        Err(EvidenceError::Invalid)
    );
}

#[test]
fn untrusted_partial_allowed_is_preserved_without_assurance_or_confirmation_flag() {
    let b = bundle();
    let parsed = ObservationBundleWire::parse_untrusted(&serde_json::to_vec(&b).unwrap()).unwrap();
    assert!(!parsed.capture_complete);
    assert_eq!(parsed.claims[0].observed, StateValue::Allowed);
    let mut value = serde_json::to_value(b).unwrap();
    value["confirmed"] = json!(true);
    assert_eq!(
        ObservationBundleWire::parse_untrusted(&serde_json::to_vec(&value).unwrap()),
        Err(EvidenceError::Invalid)
    );
    assert_eq!(
        ObservationBundleWire::parse_untrusted(&vec![b' '; MAX_BUNDLE_BYTES + 1]),
        Err(EvidenceError::Limit)
    );
}

#[test]
fn self_cycles_dangling_refs_and_duplicate_or_future_claims_are_rejected() {
    let mut b = bundle();
    b.claims[0].controls.push(ControlReference {
        bundle_digest: None,
        claim_id: "claim-1".into(),
        purpose: ControlPurpose::TargetHealth,
    });
    assert_eq!(b.validate_shape(), Err(EvidenceError::Invalid));
    b.claims[0].controls[0].claim_id = "claim-2".into();
    assert!(b.validate_shape().is_err());
    let mut c = b.claims[0].clone();
    c.id = "claim-2".into();
    c.controls[0].claim_id = "claim-1".into();
    b.claims.push(c);
    assert!(b.validate_shape().is_err());
    let mut b = bundle();
    b.claims.push(b.claims[0].clone());
    assert!(b.validate_shape().is_err());
    let mut b = bundle();
    b.claims[0].finished_at += 100;
    assert!(b.validate_shape().is_err());
    let mut b = bundle();
    b.claims[0].evidence_refs.push("missing".into());
    assert!(b.validate_shape().is_err());
}

#[test]
fn independent_control_and_transport_sql_binding_effects_have_distinct_types() {
    let mut b = bundle();
    b.claims[0].controls.push(ControlReference {
        bundle_digest: Some("b".repeat(64)),
        claim_id: "independent-recovery".into(),
        purpose: ControlPurpose::TargetHealth,
    });
    b.validate_shape().unwrap(); // Shape only; admission/correlation is NOT implied.
    let a = b.claims[0].address.clone();
    let mut runtime = a.clone();
    runtime.effect = EffectKindV2::RuntimeBinding;
    let mut declared = a.clone();
    declared.effect = EffectKindV2::BindingPublication;
    assert_ne!(runtime, declared);
    let mut delta = a;
    delta.effect = EffectKindV2::OwnedSqlDelta {
        receipt_digest: "c".repeat(64),
        delta_digest: "d".repeat(64),
    };
    assert_ne!(runtime, delta);
    assert!(
        serde_json::from_value::<AssuranceCoverage>(
            json!({"target":{"status":"verified","evidence_refs":[]}})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<Assurance>(json!({"status":"not_applicable"})).is_err());
    assert!(requires_source_evidence(ActionKind::ConstrainDirectPath));
}
