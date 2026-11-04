//! Cross-source NOLOGIN corroboration. Native error and observer catalog stay
//! immutable; only evaluation annotations connect their admitted evidence.
use super::*;
use crate::core::postgres_login::PostgresLoginFailureKind;

pub(super) fn corroboration<'a>(
    input: &'a StateEvaluationInputV2,
    owner: &VerifiedObservationFacts,
    c: &ObservationClaim,
) -> Option<(&'a VerifiedObservationFacts, &'a ObservationClaim)> {
    let native = |f: &VerifiedObservationFacts, c: &ObservationClaim| {
        matches!(
            (
                f.admission().verification_recipe.as_str(),
                c.address.source.boundary,
                c.address.route.kind
            ),
            (
                "gce-host-network-root-v1",
                super::super::source::SourceBoundaryKind::GceHostNetwork,
                RouteKind::NativeConnector
            ) | (
                "aws-ec2-host-network-root-v1",
                super::super::source::SourceBoundaryKind::AwsHostNetwork,
                RouteKind::NativeProxy
            )
        )
    };
    if !native(owner, c)
        || c.observed != StateValue::Denied
        || c.address.effect != EffectKindV2::NewConnections
        || c.layer != StateLayer::Authentication
        || c.denial_cause != Some(DenialCause::LoginRejected)
        || c.address.target.engine_binding.family != policy::EngineFamily::PostgreSql
        || c.address.target.engine_binding.version != "16.15"
        || c.postgres_login_failure.as_ref().is_none_or(|failure| {
            failure.kind != PostgresLoginFailureKind::AuthenticatedNoLoginV1
                || failure.db_identity != c.address.db_identity
        })
        || !fresh(input, owner, c)
        || !missing(owner, c, &all_facets()).is_empty()
        || !control(
            input,
            owner,
            c,
            ControlPurpose::NativeBoundaryDecision,
            false,
        )
    {
        return None;
    }
    let matching = |other: &ObservationClaim| {
        other.address.target == c.address.target
            && other.policy_revision_hash == c.policy_revision_hash
            && other.address.subject_id != c.address.subject_id
            && other.address.source != c.address.source
            && other.started_at <= c.finished_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
            && c.started_at <= other.finished_at.saturating_add(MAX_CLOCK_SKEW_SECONDS)
    };
    let candidate = input
        .evidence
        .iter()
        .flat_map(|f| f.claims().iter().map(move |other| (f, other)))
        .find(|(f, other)| {
            native(f, other)
                && matching(other)
                && f.admission().operation_id == owner.admission().operation_id
                && f.admission().change_hash == owner.admission().change_hash
                && other.observed == StateValue::Allowed
                && other.layer == StateLayer::Authentication
                && other.address.effect == EffectKindV2::NewConnections
                && fresh(input, f, other)
                && missing(f, other, &all_facets()).is_empty()
                && health_is_current(input, f, other)
                && catalog(other, c).is_some_and(|fact| fact.role_oid > 0 && !fact.can_login)
        })?;
    let selected_oid = catalog(candidate.1, c)?.role_oid;
    // A current contradictory catalog from another approved observer must not
    // be hidden by selecting an earlier/other false record.
    if input.evidence.iter().any(|f| {
        f.claims().iter().any(|other| {
            native(f, other)
                && matching(other)
                && f.admission().operation_id == owner.admission().operation_id
                && f.admission().change_hash == owner.admission().change_hash
                && fresh(input, f, other)
                && missing(f, other, &all_facets()).is_empty()
                && health_is_current(input, f, other)
                && catalog(other, c)
                    .is_some_and(|fact| fact.can_login || fact.role_oid != selected_oid)
        })
    }) {
        return None;
    }
    Some(candidate)
}

fn catalog<'a>(
    other: &'a ObservationClaim,
    c: &ObservationClaim,
) -> Option<&'a crate::core::postgres_login::LoginCatalogFact> {
    other.login_catalog.iter().find(|fact| {
        fact.target.grant_id == c.address.grant_id
            && fact.target.subject_id == c.address.subject_id
            && fact.target.db_identity == c.address.db_identity
    })
}
