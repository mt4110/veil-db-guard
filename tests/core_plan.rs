use veil_db_guard::{
    adapters::capabilities_for,
    core::{
        capability::ActionKind,
        plan::{PlanError, build_plan},
        policy::{ManagedField, parse_policy},
    },
};

fn policy() -> veil_db_guard::core::policy::PolicyRevision {
    parse_policy(include_str!("../examples/core-policy.yaml")).unwrap()
}

#[test]
fn protection_graph_places_recovery_and_cutover_before_sealing() {
    let p = policy();
    let caps = p.targets.iter().flat_map(capabilities_for).collect();
    let plan = build_plan(&p, caps, vec![], 100).unwrap();
    let actions: Vec<_> = plan.steps.iter().map(|s| s.action).collect();
    let recovery = actions
        .iter()
        .position(|a| *a == ActionKind::ConfirmRecoveryReadiness)
        .unwrap();
    let cutover = actions
        .iter()
        .position(|a| *a == ActionKind::AwaitApplicationCutover)
        .unwrap();
    let seal = actions
        .iter()
        .position(|a| *a == ActionKind::ConstrainDirectPath)
        .unwrap();
    assert!(recovery < cutover && cutover < seal);
    for window in plan.steps.windows(2) {
        assert!(window[1].dependencies.contains(&window[0].id));
    }
    assert!(!plan.execution_available);
    assert!(!plan.protection_evaluated);
    assert!(plan.capability_gaps.is_empty());
    assert!(
        !plan
            .limitations
            .contains(&veil_db_guard::core::plan::PlanLimitation::NativeWritesNotImplemented)
    );
    assert_eq!(plan.plan_hash.len(), 64);
}

#[test]
fn policy_semantics_bind_the_entire_plan_not_input_order() {
    let p = policy();
    let a = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    let mut reordered = p.clone();
    reordered.subjects.reverse();
    reordered.targets[0].managed_surface.fields.reverse();
    reordered.grants[0].sql_access.privileges[0]
        .actions
        .reverse();
    let b = build_plan(
        &reordered,
        reordered
            .targets
            .iter()
            .flat_map(capabilities_for)
            .collect(),
        vec![],
        100,
    )
    .unwrap();
    assert_eq!(a.plan_hash, b.plan_hash);
    let mut changed = p.clone();
    changed.grants[0].sql_access.privileges[0].actions.pop();
    let c = build_plan(
        &changed,
        changed.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    assert_ne!(a.policy_revision_hash, c.policy_revision_hash);
    assert_ne!(a.plan_hash, c.plan_hash);
}

#[test]
fn closure_outside_managed_surface_never_becomes_a_step() {
    let mut p = policy();
    p.targets[0]
        .managed_surface
        .fields
        .retain(|f| *f != ManagedField::GcpConnectorEnforcement);
    assert_eq!(
        build_plan(&p, vec![], vec![], 100).unwrap_err(),
        PlanError::ScopeViolation
    );
}

#[test]
fn capabilities_are_bound_to_target_and_version() {
    let p = policy();
    let mut caps = capabilities_for(&p.targets[0]);
    for c in &mut caps {
        c.target_id = Some("other-db".into());
    }
    assert_eq!(
        build_plan(&p, caps, vec![], 100).unwrap_err(),
        PlanError::CapabilityInvalid
    );
}

#[test]
fn shared_target_cannot_close_before_all_applications_cut_over() {
    let mut p = policy();
    let mut second = p
        .subjects
        .iter()
        .find(|s| s.id == "billing-app")
        .unwrap()
        .clone();
    second.id = "batch-app".into();
    second.workload_sources = vec!["batch-runtime".into()];
    second.identity.principal = "batch-app@vdg-example-000000.iam.gserviceaccount.com".into();
    p.subjects.push(second);
    p.protection_profiles[0].allowed_routes[0]
        .source_ids
        .push("batch-runtime".into());
    let mut grant = p.grants[0].clone();
    grant.id = "batch-access".into();
    grant.subject = "batch-app".into();
    grant.db_identity = "batch-app@vdg-example-000000.iam".into();
    p.targets[0]
        .managed_surface
        .db_identities
        .push(grant.db_identity.clone());
    p.grants.push(grant);
    let plan = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    let all_handoffs = plan
        .steps
        .iter()
        .filter(|s| {
            matches!(
                s.action,
                ActionKind::AwaitApplicationCutover | ActionKind::ConfirmRecoveryReadiness
            )
        })
        .map(|s| &s.id)
        .collect::<Vec<_>>();
    assert_eq!(all_handoffs.len(), 4);
    for close in plan
        .steps
        .iter()
        .filter(|s| s.action == ActionKind::ConstrainDirectPath)
    {
        for handoff in &all_handoffs {
            assert!(close.dependencies.contains(handoff));
        }
    }
}

#[test]
fn duplicate_capabilities_and_non_digest_refs_are_rejected() {
    let p = policy();
    let caps = capabilities_for(&p.targets[0]);
    let mut twice = caps.clone();
    twice.extend(caps);
    assert_eq!(
        build_plan(&p, twice, vec![], 100).unwrap_err(),
        PlanError::CapabilityInvalid
    );
    assert_eq!(
        build_plan(&p, vec![], vec!["unverified-file-path".into()], 100).unwrap_err(),
        PlanError::CapabilityInvalid
    );
}

#[test]
fn required_effects_never_disappear_when_an_intent_has_no_corresponding_step() {
    use veil_db_guard::core::policy::{AdmissionIntent, EffectKind, SqlAccessIntent};
    let mut p = policy();
    p.grants[0].admission = AdmissionIntent::Deny;
    p.grants[0].sql_access = SqlAccessIntent::default();
    let plan = build_plan(
        &p,
        p.targets.iter().flat_map(capabilities_for).collect(),
        vec![],
        100,
    )
    .unwrap();
    assert!(
        plan.required_effect_gaps
            .iter()
            .any(|gap| gap.effect == EffectKind::BindingApplied)
    );
    assert!(
        plan.required_effect_gaps
            .iter()
            .any(|gap| gap.effect == EffectKind::NewConnectionsAllowed)
    );
    assert!(
        plan.required_effect_gaps
            .iter()
            .any(|gap| gap.effect == EffectKind::SqlPrivilegesApplied)
    );
    assert!(!plan.execution_available);
}
