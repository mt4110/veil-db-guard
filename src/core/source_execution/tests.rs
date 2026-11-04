//! Synthetic typed facts for phase semantics, never native producer evidence.
use super::*;
use crate::core::{admission::*, capability::*, change::*, plan::*, policy::*, state::*};
pub(crate) fn change() -> PreparedChange {
    let mut p = parse_policy(include_str!("../../../examples/core-policy-v2.yaml")).unwrap();
    p.targets[0].resource.generation_fingerprint = Some("c".repeat(64));
    for (i, s) in p.subjects.iter_mut().enumerate() {
        s.identity.immutable_id = Some(format!("{}", i + 1));
    }
    let caps = [
        ActionKind::PrepareNativeRoute,
        ActionKind::ConfigureIdentity,
        ActionKind::RegisterNativeDbIdentity,
        ActionKind::ConfigureSqlPrivileges,
        ActionKind::PublishBinding,
        ActionKind::ConfirmRecoveryReadiness,
        ActionKind::AwaitApplicationCutover,
        ActionKind::ConstrainDirectPath,
    ]
    .into_iter()
    .map(|a| {
        let mut c = CapabilityDescriptor::planned(
            p.targets[0].placement.kind,
            p.targets[0].engine.family,
            a,
        )
        .for_target(&p.targets[0]);
        c.support = Support::Supported;
        c.implementation = Implementation::Implemented;
        c.contract_revision = SOURCE_BOUND_EXECUTION_CONTRACT.into();
        c
    })
    .collect();
    let plan = build_plan(&p, caps, vec![], 100).unwrap();
    prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap()
}
pub(crate) fn facts(
    c: &PreparedChange,
    runtime: bool,
    direct: bool,
) -> Vec<VerifiedObservationFacts> {
    facts_at(c, runtime, direct, 130)
}

pub(crate) fn facts_at(
    c: &PreparedChange,
    runtime: bool,
    direct: bool,
    now: u64,
) -> Vec<VerifiedObservationFacts> {
    let offset = now.saturating_sub(130);
    let mut groups = std::collections::BTreeMap::<String, Vec<ObservationClaim>>::new();
    let desired = desired_for_change_v2(&c.policy, None, &[], now).unwrap();
    for d in desired {
        let id = d.id.clone();
        let effect = &d.address.effect;
        let conn = *effect == EffectKindV2::NewConnections;
        let is_direct = d.address.route.kind == RouteKind::Direct;
        if !(conn
            || matches!(effect, EffectKindV2::Transport { .. })
            || (runtime && *effect == EffectKindV2::RuntimeBinding))
        {
            continue;
        }
        if is_direct && !direct {
            continue;
        }
        let transport = if let EffectKindV2::Transport { segment } = effect {
            vec![TransportFact {
                validation_basis: None,
                segment: *segment,
                encrypted: Some(true),
                ca_verified: Some(true),
                hostname_verified: Some(true),
                ipc_boundary_verified: Some(true),
                evidence_refs: vec!["proof".into()],
            }]
        } else {
            vec![]
        };
        let mut claim = ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: id.clone(),
            case_id: id,
            policy_revision_hash: d.policy_revision_hash,
            address: d.address.clone(),
            started_at: offset + 110,
            finished_at: offset + 115,
            observed: if conn {
                if is_direct {
                    StateValue::Denied
                } else {
                    StateValue::Allowed
                }
            } else {
                StateValue::Present
            },
            layer: if is_direct {
                StateLayer::RouteEnforcement
            } else if matches!(effect, EffectKindV2::RuntimeBinding) {
                StateLayer::Configuration
            } else {
                StateLayer::Authentication
            },
            denial_cause: if is_direct {
                Some(DenialCause::RouteBlocked)
            } else {
                None
            },
            connection: None,
            controls: vec![],
            transport,
            sql_context: None,
            evidence_refs: vec!["proof".into()],
            permission_inventory: None,
        };
        if is_direct {
            let mut control = claim.clone();
            control.id = format!("{}-decision", claim.id);
            claim.controls.push(ControlReference {
                bundle_digest: None,
                claim_id: control.id.clone(),
                purpose: ControlPurpose::NativeBoundaryDecision,
            });
            groups
                .entry(claim.address.source.revision_digest.clone())
                .or_default()
                .push(control);
        }
        groups
            .entry(claim.address.source.revision_digest.clone())
            .or_default()
            .push(claim);
    }
    groups
        .into_iter()
        .map(|(source, claims)| {
            let verified = Assurance::Verified {
                evidence_refs: vec!["proof".into()],
            };
            let assurances = claims
                .iter()
                .map(|claim| ClaimAssurance {
                    claim_id: claim.id.clone(),
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
            let digest = crate::core::hash_bytes(&serde_json::to_vec(&claims).unwrap());
            let a = EvidenceAdmission {
                schema_version: 1,
                id: format!("admission-{}", &source[..8]),
                request_digest: "1".repeat(64),
                bundle_digest: digest.clone(),
                policy_revision_hash: c.plan.policy_revision_hash.clone(),
                change_hash: c.change_hash.clone(),
                operation_id: "operation".into(),
                source_snapshot_digest: source,
                source_trust_epoch: 1,
                collector_build_id: "2".repeat(64),
                verifier_build_id: "3".repeat(64),
                evaluation_contract: EvaluationContract::SourceBoundV2,
                verification_recipe: "synthetic-only".into(),
                source_evidence_refs: vec!["proof".into()],
                accepted_at: offset + 120,
                valid_until: offset + 170,
                capture_started_at: offset + 100,
                capture_finished_at: offset + 120,
                assurances: assurances.clone(),
                archive: EvidenceArchiveRef {
                    run_id: "fixture".into(),
                    manifest_digest: "4".repeat(64),
                    bundle_digest: digest.clone(),
                    request_digest: "1".repeat(64),
                },
            };
            VerifiedObservationFacts::admitted(
                a.request_digest.clone(),
                digest,
                a.id.clone(),
                claims,
                assurances,
                a,
            )
        })
        .collect()
}
fn close(c: &PreparedChange) -> &PlanStep {
    c.plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConstrainDirectPath)
        .unwrap()
}
#[test]
fn preclose_checks_runtime_allowed_tls_and_independent_recovery_not_future_denial() {
    let c = change();
    let step = close(&c);
    assert!(
        !check_source_step(
            &c,
            step,
            SourceStepPhase::BeforeDispatch,
            130,
            facts(&c, false, false)
        )
        .unwrap()
        .satisfied()
    );
    let f = facts(&c, true, false);
    assert!(
        check_source_step(&c, step, SourceStepPhase::BeforeDispatch, 130, f.clone())
            .unwrap()
            .satisfied()
    );
    let mut missing_recovery = f.clone();
    missing_recovery.retain(|f| f.claims()[0].address.subject_id == "billing-app");
    assert!(
        !check_source_step(
            &c,
            step,
            SourceStepPhase::BeforeDispatch,
            130,
            missing_recovery
        )
        .unwrap()
        .satisfied()
    );
    for mut f in [f.clone(), f] {
        f[0].test_assurances()[0].coverage.source = Assurance::Unconfirmed {
            reason: EvidenceReason::IncompleteCapture,
        };
        assert!(
            !check_source_step(&c, step, SourceStepPhase::BeforeDispatch, 130, f)
                .unwrap()
                .satisfied()
        );
    }
}

#[test]
fn recovery_alias_cannot_pass_the_close_gate_as_an_independent_source() {
    let c = change();
    let mut report = evaluate_source_state_v2(&StateEvaluationInputV2 {
        contract: EvaluationContract::SourceBoundV2,
        now: 130,
        max_age_seconds: DEFAULT_FRESHNESS_SECONDS,
        desired: desired_for_change_v2(&c.policy, None, &[], 130).unwrap(),
        evidence: facts(&c, true, false),
        permission_removals: vec![],
    })
    .unwrap();
    let source = c
        .policy
        .source_bindings
        .iter()
        .find(|s| s.source_id == "billing-runtime")
        .unwrap();
    let phase = SourceStepPhase::BeforeDispatch;
    assert!(
        stage_check(&c, close(&c), phase, &report)
            .unwrap()
            .satisfied()
    );
    for row in &mut report.rows {
        if row.desired.address.subject_id == "recovery-operator" {
            row.desired.address.source.registration_id = source.registration_id.clone();
        }
    }
    assert!(
        !stage_check(&c, close(&c), phase, &report)
            .unwrap()
            .satisfied()
    );
}
#[test]
fn completion_needs_post_dispatch_denial_and_keeps_unknown_without_native_cause() {
    let c = change();
    let s = close(&c);
    let phase = SourceStepPhase::AfterConfiguration { not_before: 99 };
    assert!(
        !check_source_step(&c, s, phase, 130, facts(&c, true, false))
            .unwrap()
            .satisfied()
    );
    let f = facts(&c, true, true);
    assert!(
        check_source_step(&c, s, phase, 130, f.clone())
            .unwrap()
            .satisfied()
    );
    assert!(
        !check_source_step(
            &c,
            s,
            SourceStepPhase::AfterConfiguration { not_before: 100 },
            130,
            f.clone()
        )
        .unwrap()
        .satisfied()
    );
    let mut unclassified = f;
    for f in &mut unclassified {
        for claim in f.test_claims() {
            if claim.address.route.kind == RouteKind::Direct {
                claim.denial_cause = Some(DenialCause::Unclassified);
            }
        }
    }
    assert!(
        !check_source_step(&c, s, phase, 130, unclassified)
            .unwrap()
            .satisfied()
    );
}
#[test]
fn recovery_step_does_not_need_app_runtime_or_closure_and_expires_with_facts() {
    let c = change();
    let s = c
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfirmRecoveryReadiness)
        .unwrap();
    let f = facts(&c, false, false);
    assert!(
        check_source_step(&c, s, SourceStepPhase::BeforeDispatch, 130, f.clone())
            .unwrap()
            .satisfied()
    );
    assert!(
        !check_source_step(&c, s, SourceStepPhase::BeforeDispatch, 170, f)
            .unwrap()
            .satisfied()
    );
}
#[test]
fn foreign_change_and_evaluation_only_contract_cannot_mint_execution_check() {
    let c = change();
    let mut f = facts(&c, true, true);
    f[0].test_admission().change_hash = "f".repeat(64);
    assert!(check_source_step(&c, close(&c), SourceStepPhase::BeforeDispatch, 130, f).is_err());
    let mut old = close(&c).clone();
    old.adapter_contract = SOURCE_BOUND_ADAPTER_CONTRACT.into();
    assert!(check_source_step(&c, &old, SourceStepPhase::BeforeDispatch, 130, vec![]).is_err());
}

#[test]
fn gate_records_cross_row_derived_health_bundle_for_replay() {
    let c = change();
    let desired = desired_for_change_v2(&c.policy, None, &[], 130).unwrap();
    let mut report = evaluate_source_state_v2(&StateEvaluationInputV2 {
        contract: EvaluationContract::SourceBoundV2,
        now: 130,
        max_age_seconds: DEFAULT_FRESHNESS_SECONDS,
        desired,
        evidence: facts(&c, true, false),
        permission_removals: vec![],
    })
    .unwrap();
    let owner = report
        .rows
        .iter()
        .find_map(|r| r.current_claims.first())
        .unwrap()
        .clone();
    let (bundle, claim) = owner.split_once(':').unwrap();
    report
        .derived_controls
        .push(crate::core::state_v2::DerivedControlLink {
            owner_bundle_digest: bundle.into(),
            owner_claim_id: claim.into(),
            control: ControlReference {
                bundle_digest: Some("9".repeat(64)),
                claim_id: "external-health".into(),
                purpose: ControlPurpose::TargetHealth,
            },
        });
    let result = stage_check(&c, close(&c), SourceStepPhase::BeforeDispatch, &report).unwrap();
    assert!(result.evidence_refs.contains(&"9".repeat(64)));
}
