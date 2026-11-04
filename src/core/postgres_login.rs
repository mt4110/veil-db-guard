//! Versioned PostgreSQL login evidence selected by a trusted native recipe.
//! These wire facts confer no authority before admission and cross-source checks.
use super::{evidence::*, policy::*, source::SourcePurpose};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCatalogTarget {
    pub grant_id: String,
    pub subject_id: String,
    pub db_identity: String,
}
impl LoginCatalogTarget {
    pub fn valid(&self) -> bool {
        valid_id(&self.grant_id) && valid_id(&self.subject_id) && identity(&self.db_identity)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCatalogFact {
    pub target: LoginCatalogTarget,
    pub role_oid: u32,
    pub can_login: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresLoginFailureKind {
    AuthenticatedNoLoginV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresLoginFailure {
    pub db_identity: String,
    pub kind: PostgresLoginFailureKind,
}
pub fn identity(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.chars().any(char::is_control)
        && !["://", "${", "{{", "password=", "token=", "secret="]
            .iter()
            .any(|part| s.to_ascii_lowercase().contains(part))
}
/// Only an independently registered Recovery source may inspect another
/// approved grant's login catalog in the same target and protection profile.
pub fn authorized_targets(policy: &PolicyRevision, c: &RequestedCase) -> Vec<LoginCatalogTarget> {
    if c.purpose != SourcePurpose::Recovery
        || !matches!(
            c.kind,
            FixedObservationCase::TargetHealth | FixedObservationCase::NewConnection
        )
        || c.address.effect != EffectKindV2::NewConnections
        || c.address.route.kind == RouteKind::Direct
        || c.address.target.engine_binding.family != EngineFamily::PostgreSql
    {
        return vec![];
    }
    let Some(base) = policy
        .grants
        .iter()
        .find(|g| g.id == c.address.grant_id && g.target == c.address.target_id)
    else {
        return vec![];
    };
    let Some(profile) = policy
        .protection_profiles
        .iter()
        .find(|p| p.id == base.profile)
    else {
        return vec![];
    };
    if !profile.management_exceptions.iter().any(|e| {
        e.recovery
            && e.subject == c.address.subject_id
            && e.source_ids.contains(&c.address.source.source_id)
            && e.route_id == c.address.route.id
    }) {
        return vec![];
    }
    let mut result: Vec<_> = policy
        .grants
        .iter()
        .filter(|g| {
            g.target == base.target
                && g.profile == base.profile
                && g.subject != c.address.subject_id
        })
        .map(|g| LoginCatalogTarget {
            grant_id: g.id.clone(),
            subject_id: g.subject.clone(),
            db_identity: g.db_identity.clone(),
        })
        .collect();
    result.sort();
    result.dedup();
    result
}
pub fn validate_catalog_request(policy: &PolicyRevision, c: &RequestedCase) -> bool {
    if c.login_catalog_targets.len() > 8 || c.login_catalog_targets.iter().any(|t| !t.valid()) {
        return false;
    }
    let allowed = authorized_targets(policy, c);
    c.login_catalog_targets.iter().all(|t| allowed.contains(t))
        && c.login_catalog_targets
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == c.login_catalog_targets.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn recovery() -> (PolicyRevision, RequestedCase) {
        let mut p = parse_policy(include_str!("../../examples/core-policy-v2.yaml")).unwrap();
        p.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
        let d = super::super::state_v2::desired_for_change_v2(&p, None, &[], 130)
            .unwrap()
            .into_iter()
            .find(|d| {
                d.address.subject_id == "recovery-operator"
                    && d.address.effect == EffectKindV2::NewConnections
            })
            .unwrap();
        let c = RequestedCase {
            id: "observer".into(),
            kind: FixedObservationCase::TargetHealth,
            address: d.address,
            purpose: SourcePurpose::Recovery,
            endpoint: "db.example.test".into(),
            port: 5432,
            address_family: AddressFamily::Ipv4,
            mysql_account_host: None,
            backend_tls_trust: None,
            login_catalog_targets: vec![],
        };
        (p, c)
    }
    #[test]
    fn recovery_catalog_is_scoped_to_approved_grants_not_arbitrary_roles() {
        let (p, mut c) = recovery();
        c.login_catalog_targets = authorized_targets(&p, &c);
        assert_eq!(c.login_catalog_targets.len(), 1);
        assert!(validate_catalog_request(&p, &c));
        for n in 0..5 {
            let mut c = c.clone();
            match n {
                0 => c.purpose = SourcePurpose::Application,
                1 => c.login_catalog_targets[0].db_identity = "unapproved".into(),
                2 => c.address.route.kind = RouteKind::Direct,
                3 => c
                    .login_catalog_targets
                    .push(c.login_catalog_targets[0].clone()),
                _ => c.login_catalog_targets[0].subject_id = "different".into(),
            }
            assert!(!validate_catalog_request(&p, &c), "{n}");
        }
    }
}
