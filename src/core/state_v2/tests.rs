//! Synthetic admitted facts only. No cloud/DB/real source claim.
use super::*;
use crate::core::{admission::*, policy::*, state::*};
fn policy() -> PolicyRevision {
    let mut p = parse_policy(include_str!("../../../examples/core-policy-v2.yaml")).unwrap();
    p.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    p
}
fn desired() -> RequiredEffectV2 {
    desired_for_change_v2(&policy(), None, &[], 130)
        .unwrap()
        .into_iter()
        .find(|d| {
            d.address.effect == EffectKindV2::NewConnections
                && d.address.route.kind != RouteKind::Direct
        })
        .unwrap()
}
fn claim(d: &RequiredEffectV2, id: &str, value: StateValue) -> ObservationClaim {
    ObservationClaim {
        runtime_capture: None,
        postgres_login_failure: None,
        login_catalog: vec![],
        id: id.into(),
        case_id: id.into(),
        policy_revision_hash: d.policy_revision_hash.clone(),
        address: d.address.clone(),
        started_at: 110,
        finished_at: 115,
        observed: value,
        layer: StateLayer::Authentication,
        denial_cause: None,
        connection: None,
        controls: vec![],
        transport: vec![],
        sql_context: None,
        evidence_refs: vec!["proof".into()],
        permission_inventory: None,
    }
}
fn facts(claims: Vec<ObservationClaim>) -> VerifiedObservationFacts {
    let verified = Assurance::Verified {
        evidence_refs: vec!["proof".into()],
    };
    let assurances = claims
        .iter()
        .map(|c| ClaimAssurance {
            claim_id: c.id.clone(),
            coverage: AssuranceCoverage {
                target: verified.clone(),
                principal: verified.clone(),
                source: verified.clone(),
                route: verified.clone(),
                transport: verified.clone(),
                temporal: verified.clone(),
                completeness: verified.clone(),
            },
        })
        .collect::<Vec<_>>();
    let bundle = super::super::hash_bytes(&serde_json::to_vec(&claims).unwrap());
    let a = EvidenceAdmission {
        schema_version: 1,
        id: "admission".into(),
        request_digest: "b".repeat(64),
        bundle_digest: bundle.clone(),
        policy_revision_hash: claims[0].policy_revision_hash.clone(),
        change_hash: "c".repeat(64),
        operation_id: "operation".into(),
        source_snapshot_digest: claims[0].address.source.revision_digest.clone(),
        source_trust_epoch: 1,
        collector_build_id: "d".repeat(64),
        verifier_build_id: "e".repeat(64),
        evaluation_contract: EvaluationContract::SourceBoundV2,
        verification_recipe: "synthetic-only".into(),
        source_evidence_refs: vec!["proof".into()],
        accepted_at: 120,
        valid_until: 170,
        capture_started_at: 100,
        capture_finished_at: 120,
        assurances: assurances.clone(),
        archive: EvidenceArchiveRef {
            run_id: "fixture".into(),
            bundle_digest: bundle.clone(),
            manifest_digest: "f".repeat(64),
            request_digest: "b".repeat(64),
        },
    };
    VerifiedObservationFacts::admitted(
        a.request_digest.clone(),
        bundle,
        a.id.clone(),
        claims,
        assurances,
        a,
    )
}
fn input(d: RequiredEffectV2, f: Vec<VerifiedObservationFacts>) -> StateEvaluationInputV2 {
    StateEvaluationInputV2 {
        contract: EvaluationContract::SourceBoundV2,
        now: 130,
        max_age_seconds: 60,
        desired: vec![d],
        evidence: f,
        permission_removals: vec![],
    }
}
#[test]
fn policy_universe_keeps_missing_binding_tls_sql_and_direct_rows() {
    let p = policy();
    let rows = desired_for_change_v2(&p, None, &[], 130).unwrap();
    assert!(
        rows.iter()
            .any(|d| d.address.effect == EffectKindV2::RuntimeBinding)
    );
    assert_eq!(
        rows.iter()
            .filter(|d| d.address.subject_id == "billing-app"
                && matches!(d.address.effect, EffectKindV2::Transport { .. }))
            .count(),
        2
    );
    assert!(
        rows.iter()
            .any(|d| d.address.route.kind == RouteKind::Direct && d.expected == StateValue::Denied)
    );
    let mut i = input(
        rows[0].clone(),
        vec![facts(vec![claim(&rows[0], "allowed", StateValue::Allowed)])],
    );
    i.desired = rows;
    let r = evaluate_state_v2(&i).unwrap();
    assert!(r.protection_evaluated);
    assert!(!r.all_required_effects_satisfied);
    assert!(
        r.rows
            .iter()
            .find(|r| r.desired.address.effect == EffectKindV2::RuntimeBinding)
            .unwrap()
            .assessment
            == StateAssessment::Unknown
    );
    let mut unregistered = p;
    unregistered.targets[0].resource.generation_fingerprint = None;
    i.desired = desired_for_change_v2(&unregistered, None, &[], 130).unwrap();
    i.evidence.clear();
    assert!(evaluate_state_v2(&i).is_ok());
}
#[test]
fn partial_allowed_and_overlapping_denial_do_not_hide_access() {
    let mut d = desired();
    d.expected = StateValue::Denied;
    let allowed = claim(&d, "allowed", StateValue::Allowed);
    let mut denied = claim(&d, "denied", StateValue::Denied);
    denied.layer = StateLayer::ConnectionAuthorization;
    denied.denial_cause = Some(DenialCause::PermissionDenied);
    let mut f = facts(vec![allowed, denied]);
    f.test_assurances()[0].coverage.completeness = Assurance::Unconfirmed {
        reason: EvidenceReason::IncompleteCapture,
    };
    let r = evaluate_state_v2(&input(d, vec![f])).unwrap();
    let row = &r.rows[0];
    assert_eq!(row.observed, StateValue::Allowed);
    assert_eq!(row.assessment, StateAssessment::NeedsAction);
    assert!(row.reasons.contains(&StateReason::MixedHistory));
    assert!(row.reasons.contains(&StateReason::ContradictoryEvidence));
    assert_eq!(row.history.len(), 2);
}
#[test]
fn cached_facts_expire_and_foreign_revision_or_source_stays_history() {
    let d = desired();
    let c = claim(&d, "allowed", StateValue::Allowed);
    let f = facts(vec![c]);
    let mut i = input(d, vec![f]);
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    i.now = 170;
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].observed,
        StateValue::Unknown
    );
    i.now = 130;
    i.evidence[0].test_claims()[0].policy_revision_hash = "1".repeat(64);
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].history[0].reason,
        Some(EvidenceReason::ContractMismatch)
    );
    i.evidence[0].test_claims()[0].policy_revision_hash = i.desired[0].policy_revision_hash.clone();
    i.evidence[0].test_claims()[0]
        .address
        .source
        .revision_digest = "2".repeat(64);
    assert!(!evaluate_state_v2(&i).unwrap().protection_evaluated);
}
#[test]
fn missing_facets_or_ssl_without_ca_hostname_cannot_satisfy() {
    let mut d = desired();
    d.address.effect = EffectKindV2::Transport {
        segment: TransportSegment::NativeRouteToDatabase,
    };
    d.expected = StateValue::Present;
    let mut c = claim(&d, "transport", StateValue::Present);
    c.transport = vec![TransportFact {
        validation_basis: None,
        segment: TransportSegment::NativeRouteToDatabase,
        encrypted: Some(true),
        ca_verified: None,
        hostname_verified: None,
        ipc_boundary_verified: None,
        evidence_refs: vec!["proof".into()],
    }];
    let mut i = input(d, vec![facts(vec![c])]);
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Unknown
    );
    i.evidence[0].test_claims()[0].transport[0].ca_verified = Some(true);
    i.evidence[0].test_claims()[0].transport[0].hostname_verified = Some(true);
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    for k in all_facets() {
        let mut i = i.clone();
        let a = &mut i.evidence[0].test_assurances()[0].coverage;
        let un = Assurance::Unconfirmed {
            reason: EvidenceReason::IncompleteCapture,
        };
        match k {
            AssuranceFacet::Target => a.target = un,
            AssuranceFacet::Principal => a.principal = un,
            AssuranceFacet::Source => a.source = un,
            AssuranceFacet::Route => a.route = un,
            AssuranceFacet::Transport => a.transport = un,
            AssuranceFacet::Temporal => a.temporal = un,
            AssuranceFacet::Completeness => a.completeness = un,
        };
        assert!(
            !evaluate_state_v2(&i)
                .unwrap()
                .all_required_effects_satisfied
        );
    }
}
#[test]
fn denial_requires_accepted_layer_native_decision_and_purpose_scoped_health() {
    let mut d = desired();
    d.expected = StateValue::Denied;
    let mut denial = claim(&d, "denial", StateValue::Denied);
    denial.layer = StateLayer::ConnectionAuthorization;
    denial.denial_cause = Some(DenialCause::PermissionDenied);
    let mut decision = denial.clone();
    decision.id = "decision".into();
    let mut health = claim(&d, "health", StateValue::Allowed);
    health.address.source.source_id = "recovery".into();
    health.address.source.revision_digest = "f".repeat(64);
    health.address.subject_id = "recovery-operator".into();
    health.address.db_identity = "recovery".into();
    denial.controls = vec![
        ControlReference {
            bundle_digest: None,
            claim_id: "decision".into(),
            purpose: ControlPurpose::NativeBoundaryDecision,
        },
        ControlReference {
            bundle_digest: None,
            claim_id: "health".into(),
            purpose: ControlPurpose::TargetHealth,
        },
    ];
    let mut hf = facts(vec![health]);
    hf.test_admission().source_snapshot_digest =
        hf.test_claims()[0].address.source.revision_digest.clone();
    let mut f = facts(vec![denial, decision]);
    f.test_claims()[0].controls[1].bundle_digest = Some(hf.bundle_digest().to_owned());
    let mut i = input(d, vec![f, hf]);
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    i.evidence[0].test_claims()[0].controls[1].purpose =
        ControlPurpose::SameSourceRouteReachability;
    assert_ne!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    i.evidence[0].test_claims()[0].layer = StateLayer::Authentication;
    i.evidence[0].test_claims()[0].denial_cause = Some(DenialCause::LoginRejected);
    assert!(
        evaluate_state_v2(&i).unwrap().rows[0]
            .reasons
            .contains(&StateReason::WrongDenialLayer)
    );
}
#[test]
fn owned_delta_and_effective_privilege_are_independent() {
    let mut d = desired();
    d.address.effect = EffectKindV2::EffectiveSqlRole {
        role: "reader".into(),
    };
    d.expected = StateValue::Absent;
    let mut c = claim(&d, "effective", StateValue::Present);
    c.layer = StateLayer::SqlAuthorization;
    c.sql_context = Some(SqlAuthorizationContext {
        session_user: d.address.db_identity.clone(),
        current_user: d.address.db_identity.clone(),
        active_roles: vec!["reader".into()],
        login_catalog_identity: Some("pg-role-10".into()),
        object_catalog_identity: Some("pg-role-20".into()),
        permission_inventory_complete: true,
    });
    let mut delta = c.clone();
    delta.id = "delta".into();
    delta.address.effect = EffectKindV2::OwnedSqlDelta {
        receipt_digest: "1".repeat(64),
        delta_digest: "2".repeat(64),
    };
    delta.observed = StateValue::Absent;
    let r = evaluate_state_v2(&input(d, vec![facts(vec![c, delta])])).unwrap();
    assert_eq!(r.rows[0].observed, StateValue::Present);
    assert_eq!(r.rows[0].assessment, StateAssessment::NeedsAction);
}
fn propagation_input() -> StateEvaluationInputV2 {
    let mut d = desired();
    d.expected = StateValue::Denied;
    let mut c = claim(&d, "current", StateValue::Allowed);
    c.started_at = 117;
    c.finished_at = 118;
    let mut prior = claim(&d, "prior", StateValue::Allowed);
    prior.policy_revision_hash = "9".repeat(64);
    prior.started_at = 101;
    prior.finished_at = 103;
    let mut before = prior.clone();
    before.id = "before".into();
    before.observed = StateValue::Unknown;
    before.permission_inventory = Some(NativePermissionInventory {
        complete: true,
        permissions: vec!["connect".into(), "instance-get".into()],
    });
    let mut after = claim(&d, "after", StateValue::Unknown);
    after.started_at = 112;
    after.finished_at = 113;
    after.permission_inventory = Some(NativePermissionInventory {
        complete: true,
        permissions: vec!["instance-get".into()],
    });
    let bf = facts(vec![before, prior]);
    let af = facts(vec![after]);
    let cf = facts(vec![c]);
    let r = PermissionRemovalV2 {
        address: d.address.clone(),
        policy_revision_hash: d.policy_revision_hash.clone(),
        before_policy_revision_hash: "9".repeat(64),
        change_hash: af.admission().change_hash.clone(),
        operation_id: af.admission().operation_id.clone(),
        references: RemovalReferencesWire {
            before_inventory: (bf.bundle_digest().to_owned(), "before".into()),
            after_inventory: (af.bundle_digest().to_owned(), "after".into()),
            prior_allowed: (bf.bundle_digest().to_owned(), "prior".into()),
            changed_at: 110,
            deadline: 150,
        },
        partial_failure: false,
    };
    let mut i = input(d, vec![bf, af, cf]);
    i.permission_removals = vec![r];
    i
}
#[test]
fn pending_requires_complete_differences_and_before_after_access_and_has_finite_deadline() {
    let mut i = propagation_input();
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Pending
    );
    for n in 0..6 {
        let mut i = i.clone();
        match n {
            0 => {
                i.evidence[0].test_claims()[0]
                    .permission_inventory
                    .as_mut()
                    .unwrap()
                    .complete = false
            }
            1 => i.evidence[1].test_claims()[0]
                .permission_inventory
                .as_mut()
                .unwrap()
                .permissions
                .push("connect".into()),
            2 => i.evidence[0].test_claims()[1].observed = StateValue::Unknown,
            3 => i.evidence[1].test_admission().operation_id = "foreign".into(),
            4 => i.evidence[1].test_claims()[0].started_at = 109,
            _ => {
                i.evidence[1].test_assurances()[0].coverage.completeness = Assurance::Unconfirmed {
                    reason: EvidenceReason::PermissionInventoryIncomplete,
                }
            }
        };
        assert_ne!(
            evaluate_state_v2(&i).unwrap().rows[0].assessment,
            StateAssessment::Pending,
            "case {n}"
        );
    }
    i.now = 150;
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::NeedsAction
    );
    i.now = 200;
    assert!(
        evaluate_state_v2(&i).unwrap().rows[0]
            .reasons
            .contains(&StateReason::PropagationDeadlineExceeded)
    );
    i.permission_removals[0].partial_failure = true;
    assert_eq!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::FailedPartial
    );
}

#[test]
fn removal_ticket_requires_exact_approved_change_and_preserves_prior_sql_scope() {
    use crate::core::{
        approval,
        change::{OperationLimits, prepare_change},
        operation::ExecutionState,
        plan::build_plan,
    };
    // The core test supplies explicit capabilities from the policy profile,
    // independently of an infrastructure composition root.
    let old = policy();
    let mut new = old.clone();
    new.revision = 2;
    new.parent_revision_hash = Some(old.revision_hash().unwrap());
    new.grants[0].admission = AdmissionIntent::Deny;
    new.grants[0].sql_access = Default::default();
    new.protection_profiles[0].required_effects = vec![
        EffectKind::BindingApplied,
        EffectKind::NewConnectionsDenied,
        EffectKind::SqlPrivilegesRevoked,
    ];
    let desired = desired_for_change_v2(&new, Some(&old), &[], 130).unwrap();
    assert_eq!(
        desired
            .iter()
            .filter(|d| matches!(d.address.effect, EffectKindV2::EffectiveSqlPrivilege { .. }))
            .count(),
        3
    );
    let plan = build_plan(&new, vec![], vec![], 100).unwrap();
    let change = prepare_change(&new, &plan, &[], Some(&old), OperationLimits::default()).unwrap();
    let approval =
        approval::issue(&change, "approval", "reviewer", "runner", 200, 900, 100).unwrap();
    let op = Operation {
        id: "operation".into(),
        request_id: "request".into(),
        input_hash: "f".repeat(64),
        change_hash: change.change_hash.clone(),
        approval_id: approval.id.clone(),
        policy_id: new.policy_id.clone(),
        policy_revision_hash: change.plan.policy_revision_hash.clone(),
        execution_identity: "runner".into(),
        version: 1,
        state: ExecutionState::WaitingEffect,
        attempts: 1,
        created_at: 101,
        updated_at: 110,
    };
    let address = &desired
        .iter()
        .find(|d| {
            d.address.effect == EffectKindV2::NewConnections
                && d.address.route.kind != RouteKind::Direct
        })
        .unwrap()
        .address;
    let refs = RemovalReferencesV2 {
        before_inventory: ("a".repeat(64), "before".into()),
        after_inventory: ("b".repeat(64), "after".into()),
        prior_allowed: ("a".repeat(64), "prior".into()),
        changed_at: 110,
        deadline: 150,
    };
    assert!(
        PermissionRemovalV2::from_approved_change(&change, &approval, &op, address, refs.clone())
            .is_ok()
    );
    let mut wrong = op.clone();
    wrong.approval_id = "foreign".into();
    assert!(
        PermissionRemovalV2::from_approved_change(
            &change,
            &approval,
            &wrong,
            address,
            refs.clone()
        )
        .is_err()
    );
    let mut refs = refs;
    refs.deadline = 110 + state::MAX_PROPAGATION_SECONDS + 1;
    assert!(
        PermissionRemovalV2::from_approved_change(&change, &approval, &op, address, refs).is_err()
    );
    let mut tampered = new;
    tampered.parent_revision_hash = Some("0".repeat(64));
    assert!(desired_for_change_v2(&tampered, Some(&old), &[], 130).is_err());
}

fn native_denial_health_input() -> StateEvaluationInputV2 {
    let mut d = desired();
    d.expected = StateValue::Denied;
    d.address.route.kind = RouteKind::NativeConnector;
    let mut c = claim(&d, "denied", StateValue::Denied);
    c.layer = StateLayer::ConnectionAuthorization;
    c.denial_cause = Some(DenialCause::PermissionDenied);
    let mut decision = c.clone();
    decision.id = "decision".into();
    c.controls.push(ControlReference {
        bundle_digest: None,
        claim_id: "decision".into(),
        purpose: ControlPurpose::NativeBoundaryDecision,
    });
    let mut owner = facts(vec![c, decision]);
    owner.test_admission().verification_recipe = "gce-host-network-root-v1".into();
    let mut hd = d.clone();
    hd.id = "health-effect".into();
    hd.expected = StateValue::Allowed;
    hd.address.source.source_id = "recovery".into();
    hd.address.source.revision_digest = "f".repeat(64);
    hd.address.subject_id = "recovery-operator".into();
    hd.address.db_identity = "recovery".into();
    let health = facts(vec![claim(&hd, "health", StateValue::Allowed)]);
    let mut i = input(d, vec![owner, health]);
    i.desired.push(hd);
    i
}
#[test]
fn native_health_is_derived_without_mutating_admitted_wire_or_using_foreign_evidence() {
    let i = native_denial_health_input();
    let original = serde_json::to_vec(i.evidence[0].claims()).unwrap();
    let result = evaluate_source_state_v2(&i).unwrap();
    assert_eq!(result.rows[0].assessment, StateAssessment::Satisfied);
    assert_eq!(result.derived_controls.len(), 1);
    assert_eq!(
        serde_json::to_vec(i.evidence[0].claims()).unwrap(),
        original
    );
    assert_ne!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    for n in 0..7 {
        let mut j = native_denial_health_input();
        match n {
            0 => j.evidence[1].test_admission().operation_id = "foreign".into(),
            1 => j.evidence[1].test_admission().change_hash = "9".repeat(64),
            2 => {
                j.evidence[1].test_claims()[0]
                    .address
                    .target
                    .native_ref
                    .generation_fingerprint = Some("9".repeat(64))
            }
            3 => j.evidence[1].test_claims()[0].finished_at = 1,
            4 => j.evidence[0].test_claims()[0].controls.clear(),
            5 => j.evidence[0].test_admission().verification_recipe = "synthetic-only".into(),
            _ => j.evidence[0].test_claims()[0]
                .controls
                .push(ControlReference {
                    bundle_digest: None,
                    claim_id: "nonexistent".into(),
                    purpose: ControlPurpose::TargetHealth,
                }),
        }
        assert_ne!(
            evaluate_source_state_v2(&j).unwrap().rows[0].assessment,
            StateAssessment::Satisfied
        );
    }
}
#[test]
fn removal_pool_is_only_for_before_refs_never_current_rows_or_after_refs() {
    let mut i = propagation_input();
    let before = i.evidence.remove(0);
    assert_eq!(
        evaluate_source_state_v2_with_removal_evidence(&i, std::slice::from_ref(&before))
            .unwrap()
            .rows[0]
            .assessment,
        StateAssessment::Pending
    );
    assert_ne!(
        evaluate_source_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Pending
    );
    let after = i.evidence.remove(0);
    assert_ne!(
        evaluate_source_state_v2_with_removal_evidence(&i, &[before, after])
            .unwrap()
            .rows[0]
            .assessment,
        StateAssessment::Pending
    );
    let mut j = native_denial_health_input();
    let health = j.evidence.remove(1);
    assert_ne!(
        evaluate_source_state_v2_with_removal_evidence(&j, &[health])
            .unwrap()
            .rows[0]
            .assessment,
        StateAssessment::Satisfied
    );
}

#[test]
fn superseded_or_contradictory_health_cannot_corroborate_native_denial() {
    for value in [StateValue::Denied, StateValue::Unknown] {
        let mut i = native_denial_health_input();
        let mut newer = i.evidence[1].claims()[0].clone();
        newer.id = "new-health".into();
        newer.started_at = 116;
        newer.finished_at = 120;
        newer.observed = value;
        i.evidence.push(facts(vec![newer]));
        assert_ne!(
            evaluate_source_state_v2(&i).unwrap().rows[0].assessment,
            StateAssessment::Satisfied
        );
    }
    let mut i = native_denial_health_input();
    let mut conflict = i.evidence[1].claims()[0].clone();
    conflict.id = "conflict".into();
    conflict.observed = StateValue::Denied;
    i.evidence.push(facts(vec![conflict]));
    assert_ne!(
        evaluate_source_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
}

#[test]
fn managed_backend_contract_requires_matching_basis_and_native_recipe() {
    let mut d = desired();
    d.backend_tls_trust = Some(BackendTlsTrustContract::AwsRdsProxyManagedEncryptionV1);
    d.address.effect = EffectKindV2::Transport {
        segment: TransportSegment::NativeRouteToDatabase,
    };
    d.expected = StateValue::Present;
    d.address.route.kind = RouteKind::NativeProxy;
    d.address.target.placement.kind = PlacementKind::AwsRds;
    d.address.source.boundary = crate::core::source::SourceBoundaryKind::AwsHostNetwork;
    let mut c = claim(&d, "managed-backend", StateValue::Present);
    c.transport = vec![TransportFact {
        validation_basis: d.backend_tls_trust,
        segment: TransportSegment::NativeRouteToDatabase,
        encrypted: Some(true),
        ca_verified: None,
        hostname_verified: None,
        ipc_boundary_verified: None,
        evidence_refs: vec!["proof".into()],
    }];
    let mut f = facts(vec![c]);
    f.test_admission().verification_recipe = "aws-ec2-host-network-root-v1".into();
    let good = input(d, vec![f]);
    assert_eq!(
        evaluate_state_v2(&good).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    for mutation in 0..7 {
        let mut i = good.clone();
        match mutation {
            0 => i.evidence[0].test_claims()[0].transport[0].encrypted = None,
            1 => i.evidence[0].test_claims()[0].transport[0].encrypted = Some(false),
            2 => i.evidence[0].test_claims()[0].transport[0].validation_basis = None,
            3 => i.evidence[0].test_claims()[0].transport[0].ca_verified = Some(true),
            4 => i.evidence[0].test_claims()[0].transport[0].hostname_verified = Some(true),
            5 => i.evidence[0].test_admission().verification_recipe = "synthetic-only".into(),
            _ => i.desired[0].backend_tls_trust = None,
        }
        assert_eq!(
            evaluate_state_v2(&i).unwrap().rows[0].assessment,
            StateAssessment::Unknown,
            "mutation {mutation}"
        );
    }
    let mut wrong_segment = good;
    wrong_segment.desired[0].address.effect = EffectKindV2::Transport {
        segment: TransportSegment::ClientToNativeRoute,
    };
    assert!(evaluate_state_v2(&wrong_segment).is_err());
}

fn native_nologin_input() -> StateEvaluationInputV2 {
    use crate::core::postgres_login::*;
    let mut i = native_denial_health_input();
    i.desired[0].accepted_denial_layers = vec![AcceptedDenialLayer::DatabaseLogin];
    let target = LoginCatalogTarget {
        grant_id: i.desired[0].address.grant_id.clone(),
        subject_id: i.desired[0].address.subject_id.clone(),
        db_identity: i.desired[0].address.db_identity.clone(),
    };
    for c in i.evidence[0].test_claims() {
        c.layer = StateLayer::Authentication;
        c.denial_cause = Some(DenialCause::LoginRejected);
        c.postgres_login_failure = Some(PostgresLoginFailure {
            db_identity: c.address.db_identity.clone(),
            kind: PostgresLoginFailureKind::AuthenticatedNoLoginV1,
        });
    }
    i.evidence[1].test_admission().verification_recipe = "gce-host-network-root-v1".into();
    i.evidence[1].test_claims()[0].login_catalog = vec![LoginCatalogFact {
        target,
        role_oid: 42,
        can_login: false,
    }];
    i
}
#[test]
fn nologin_needs_authenticated_phase_exact_role_and_independent_current_catalog() {
    let i = native_nologin_input();
    let wire = serde_json::to_vec(i.evidence[0].claims()).unwrap();
    let r = evaluate_source_state_v2(&i).unwrap();
    assert_eq!(r.rows[0].assessment, StateAssessment::Satisfied);
    assert!(
        r.derived_controls
            .iter()
            .any(|l| l.control.purpose == ControlPurpose::CredentialValidity)
    );
    assert_eq!(serde_json::to_vec(i.evidence[0].claims()).unwrap(), wire);
    assert_ne!(
        evaluate_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    for n in 0..11 {
        let mut j = native_nologin_input();
        match n {
            0 => j.evidence[0].test_claims()[0].postgres_login_failure = None,
            1 => j.evidence[1].test_claims()[0].login_catalog.clear(),
            2 => j.evidence[1].test_claims()[0].login_catalog[0].can_login = true,
            3 => j.evidence[1].test_claims()[0].login_catalog[0].role_oid = 0,
            4 => {
                j.evidence[1].test_claims()[0].login_catalog[0]
                    .target
                    .db_identity = "different".into()
            }
            5 => j.evidence[1].test_admission().operation_id = "foreign".into(),
            6 => j.evidence[0].test_claims()[0].controls.clear(),
            7 => j.evidence[1].test_admission().verification_recipe = "synthetic-only".into(),
            8 => {
                j.evidence[0].test_claims()[0]
                    .postgres_login_failure
                    .as_mut()
                    .unwrap()
                    .db_identity = "different".into()
            }
            9 => j.evidence[0].test_claims()[0]
                .controls
                .push(ControlReference {
                    bundle_digest: None,
                    claim_id: "nonexistent".into(),
                    purpose: ControlPurpose::CredentialValidity,
                }),
            _ => {
                j.desired[0].accepted_denial_layers =
                    vec![AcceptedDenialLayer::ConnectionAuthorization]
            }
        }
        assert_ne!(
            evaluate_source_state_v2(&j).unwrap().rows[0].assessment,
            StateAssessment::Satisfied,
            "{n}"
        );
    }
}
#[test]
fn nologin_does_not_hide_a_current_success_or_a_conflicting_catalog() {
    let mut i = native_nologin_input();
    let mut other = i.evidence[1].claims()[0].clone();
    other.id = "conflicting-catalog".into();
    other.login_catalog[0].can_login = true;
    i.evidence.push(facts(vec![other]));
    i.evidence[2].test_admission().verification_recipe = "gce-host-network-root-v1".into();
    assert_ne!(
        evaluate_source_state_v2(&i).unwrap().rows[0].assessment,
        StateAssessment::Satisfied
    );
    let mut i = native_nologin_input();
    let mut allowed = i.evidence[0].claims()[0].clone();
    allowed.id = "current-allowed".into();
    allowed.observed = StateValue::Allowed;
    allowed.denial_cause = None;
    allowed.postgres_login_failure = None;
    allowed.controls.clear();
    i.evidence.push(facts(vec![allowed]));
    let r = evaluate_source_state_v2(&i).unwrap();
    assert_eq!(r.rows[0].observed, StateValue::Allowed);
    assert_ne!(r.rows[0].assessment, StateAssessment::Satisfied);
}
