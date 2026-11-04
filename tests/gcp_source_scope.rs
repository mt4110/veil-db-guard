//! Pure production-classifier regressions. These are synthetic local inputs,
//! never observations from a real workload or cloud endpoint.
use std::collections::BTreeSet;
use veil_db_guard::{
    adapters::deployment::gcp::{
        DirectTransportObservation, DirectTransportOutcome, classify_cli_connection_evidence,
    },
    config::hash_bytes,
    gcp::model::*,
};

fn principals() -> Vec<GcpPrincipal> {
    ["app", "recovery"]
        .into_iter()
        .map(|id| GcpPrincipal {
            id: id.into(),
            service_account: format!("{id}@vdg-example.iam.gserviceaccount.com"),
        })
        .collect()
}
fn allowed(principal: &GcpPrincipal) -> GcpObservation {
    GcpObservation {
        case_id: format!("{}-connector", principal.id),
        attempt_id: format!("{}-attempt", principal.id),
        principal_id: principal.id.clone(),
        route: GcpRoute::Proxy,
        started_at: 100,
        finished_at: 101,
        execution: GcpExecution::Completed,
        observed: GcpAccess::Allowed,
        proof: GcpProof {
            credential_issued: true,
            sql_authenticated: true,
            sql_ok: true,
            db_user: Some(principal.db_user()),
            database: Some("billing".into()),
            ..Default::default()
        },
    }
}

#[test]
fn cli_transport_diagnostics_never_cover_workload_sources_and_refs_survive() {
    let principals = principals();
    let samples = principals.iter().map(allowed).collect::<Vec<_>>();
    for outcome in [
        DirectTransportOutcome::ExplicitRefusal,
        DirectTransportOutcome::Connected,
        DirectTransportOutcome::Timeout,
        DirectTransportOutcome::OtherFailure,
        DirectTransportOutcome::Cancelled,
    ] {
        let transport = DirectTransportObservation {
            target_id: "billing-db".into(),
            generation: "a".repeat(64),
            address: "192.0.2.1".parse().unwrap(),
            port: 5432,
            observed_at: 101,
            outcome,
        };
        let refs = vec![
            hash_bytes(&serde_json::to_vec(&samples).unwrap()),
            hash_bytes(&serde_json::to_vec(&transport).unwrap()),
        ];
        let coverage = classify_cli_connection_evidence(
            &samples,
            &principals,
            "billing",
            transport.generation.clone(),
            100,
            refs.clone(),
        );
        assert_eq!(coverage.connector_principals.len(), 2, "{outcome:?}");
        assert!(coverage.direct_denied_principals.is_empty(), "{outcome:?}");
        assert_eq!(coverage.generation, transport.generation);
        assert_eq!(coverage.observed_at, 100);
        assert_eq!(coverage.evidence_refs, refs, "{outcome:?}");
    }
}

#[test]
fn declared_principal_direct_refusal_has_no_verified_workload_source() {
    let principals = principals();
    let mut direct = allowed(&principals[0]);
    direct.route = GcpRoute::Direct;
    direct.observed = GcpAccess::Denied;
    direct.proof = GcpProof {
        credential_issued: true,
        network_rejection_explicit: true,
        tcp_reachable: Some(false),
        ..Default::default()
    };
    for execution in [GcpExecution::Completed, GcpExecution::Timeout] {
        direct.execution = execution;
        let coverage = classify_cli_connection_evidence(
            std::slice::from_ref(&direct),
            &principals,
            "billing",
            "a".repeat(64),
            100,
            vec!["b".repeat(64)],
        );
        assert!(coverage.connector_principals.is_empty());
        assert!(coverage.direct_denied_principals.is_empty());
    }
    // A successful direct sample is retained verbatim in the artifact and can
    // never be overwritten by a refused sample into workload denial.
    direct.execution = GcpExecution::Completed;
    let mut success = allowed(&principals[0]);
    success.route = GcpRoute::Direct;
    let observations = vec![direct, success];
    let original = serde_json::to_vec(&observations).unwrap();
    let artifact = hash_bytes(&original);
    let coverage = classify_cli_connection_evidence(
        &observations,
        &principals,
        "billing",
        "a".repeat(64),
        100,
        vec![artifact.clone()],
    );
    assert!(coverage.direct_denied_principals.is_empty());
    assert_eq!(coverage.evidence_refs, vec![artifact]);
    assert_eq!(serde_json::to_vec(&observations).unwrap(), original);
}

#[test]
fn connector_coverage_still_requires_fresh_completed_authenticated_matching_sql() {
    let principals = principals();
    for fault in [
        "none",
        "timeout",
        "stale",
        "user",
        "database",
        "auth",
        "sql",
        "principal",
    ] {
        let mut sample = allowed(&principals[0]);
        match fault {
            "timeout" => sample.execution = GcpExecution::Timeout,
            "stale" => sample.started_at = 99,
            "user" => sample.proof.db_user = Some("other-user".into()),
            "database" => sample.proof.database = Some("other-db".into()),
            "auth" => sample.proof.sql_authenticated = false,
            "sql" => sample.proof.sql_ok = false,
            "principal" => sample.principal_id = "unknown-principal".into(),
            _ => {}
        }
        let coverage = classify_cli_connection_evidence(
            &[sample],
            &principals,
            "billing",
            "a".repeat(64),
            100,
            vec![],
        );
        assert_eq!(
            coverage.connector_principals,
            if fault == "none" {
                BTreeSet::from([principals[0].service_account.clone()])
            } else {
                BTreeSet::new()
            },
            "{fault}"
        );
        assert!(coverage.direct_denied_principals.is_empty());
    }
}
