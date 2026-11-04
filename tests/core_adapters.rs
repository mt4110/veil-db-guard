mod common;
use veil_db_guard::{
    adapters::{self, ObservationNotice, ObservationOrigin, ObservedAccess, ObservedVerdict},
    core::{
        capability::{ActionKind, Implementation},
        policy::*,
    },
    domain,
    gcp::{config as gcp_config, model::*},
    store::{RunStatus, RunWriter},
};

#[test]
fn partial_aws_import_still_binds_engine_and_database() {
    let config = common::config();
    let target = aws_target(&config);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial-aws");
    let mut run = RunWriter::create(&path, &config, "inspect", true).unwrap();
    run.finish(RunStatus::Partial).unwrap();
    let mut wrong = target.clone();
    wrong.engine.family = EngineFamily::MySql;
    assert!(adapters::import::import_verified_run(&wrong, &path, domain::now()).is_err());
    wrong = target;
    wrong.engine.database = "another_database".into();
    assert!(adapters::import::import_verified_run(&wrong, &path, domain::now()).is_err());
}

fn gcp_config() -> GcpConfig {
    let mut config = gcp_config::parse_config(include_bytes!("../examples/gcp.yaml")).unwrap();
    config.cases.retain(|case| case.id == "unauthorized-proxy");
    config
        .principals
        .retain(|principal| principal.id == "unauthorized");
    config
}

fn target(config: &GcpConfig) -> Target {
    Target {
        aws: None,
        mysql: None,
        id: "billing-db".into(),
        registration_id: "registration-1".into(),
        placement: PlacementRef {
            kind: PlacementKind::GcpCloudSql,
            account_id: config.target.project_id.clone(),
            region: config.target.region.clone(),
        },
        resource: ResourceIdentity {
            native_id: adapters::gcp_native_id(config),
            generation_fingerprint: None,
        },
        engine: EngineRef {
            family: EngineFamily::PostgreSql,
            version: "16.15".into(),
            database: config.target.database.clone(),
        },
        managed_surface: ManagedSurface {
            fields: vec![],
            db_identities: vec![],
            sql_scopes: vec![],
        },
    }
}

fn aws_target(config: &domain::TargetConfig) -> Target {
    Target {
        aws: None,
        mysql: None,
        id: "billing-db".into(),
        registration_id: "registration-aws".into(),
        placement: PlacementRef {
            kind: PlacementKind::AwsRds,
            account_id: config.target.account_id.clone(),
            region: config.target.region.clone(),
        },
        resource: ResourceIdentity {
            native_id: config.target.db_instance_arn.clone(),
            generation_fingerprint: None,
        },
        engine: EngineRef {
            family: EngineFamily::PostgreSql,
            version: config.target.engine_version.clone(),
            database: config.test_scope.as_ref().unwrap().database.clone(),
        },
        managed_surface: ManagedSurface {
            fields: vec![],
            db_identities: vec![],
            sql_scopes: vec![],
        },
    }
}

fn before_roles() -> Vec<GcpRole> {
    vec![
        GcpRole::CloudSqlClient,
        GcpRole::CloudSqlInstanceUser,
        GcpRole::ServiceUsageConsumer,
    ]
}
fn after_roles() -> Vec<GcpRole> {
    vec![GcpRole::CloudSqlInstanceUser, GcpRole::ServiceUsageConsumer]
}
fn run(config: &GcpConfig, id: &str, started_at: u64, roles: Vec<GcpRole>) -> GcpRunEvidence {
    let snapshot = |observed_at| GcpSnapshot {
        target: config.target.clone(),
        observed_at,
        complete: true,
        engine_version: config.target.engine_version.clone(),
        connection_name: format!(
            "{}:{}:{}",
            config.target.project_id, config.target.region, config.target.instance_id
        ),
        public_ip: Some("203.0.113.5".parse().unwrap()),
        ca_mode: "GOOGLE_MANAGED_INTERNAL_CA".into(),
        ca_fingerprint: "a".repeat(64),
        iam_auth_enabled: true,
        connector_enforcement: GcpConnectorEnforcement::Required,
        ssl_mode: GcpSslMode::EncryptedOnly,
        authorized_networks: vec![],
        principal_roles: vec![GcpPrincipalRoles {
            principal_id: "unauthorized".into(),
            roles: roles.clone(),
        }],
        registered_principal_ids: vec!["unauthorized".into()],
    };
    GcpRunEvidence {
        schema_version: 1,
        run_id: id.into(),
        build_id: veil_db_guard::BUILD_ID.into(),
        config_hash: gcp_config::config_hash(config),
        history_compatibility_hash: gcp_config::history_compatibility_hash(config),
        evidence_kind: GcpEvidenceKind::Live,
        target: config.target.clone(),
        started_at,
        finished_at: started_at + 5,
        execution: GcpExecution::Completed,
        before: snapshot(started_at + 1),
        after: snapshot(started_at + 4),
        observations: vec![GcpObservation {
            case_id: "unauthorized-proxy".into(),
            attempt_id: format!("{id}-attempt"),
            principal_id: "unauthorized".into(),
            route: GcpRoute::Proxy,
            started_at: started_at + 2,
            finished_at: started_at + 3,
            execution: GcpExecution::Completed,
            observed: GcpAccess::Allowed,
            proof: GcpProof {
                credential_issued: true,
                sql_authenticated: true,
                sql_ok: true,
                db_user: Some(config.principals[0].db_user()),
                database: Some(config.target.database.clone()),
                ..Default::default()
            },
        }],
    }
}

#[test]
fn registration_separates_local_implementations_from_target_qualification() {
    let config = gcp_config();
    let mut target = target(&config);
    let capabilities = adapters::capabilities_for(&target);
    assert!(
        capabilities
            .iter()
            .any(|cap| cap.action == ActionKind::ObserveAccess && cap.has_implementation())
    );
    assert!(
        capabilities
            .iter()
            .all(|cap| cap.target_id.as_deref() == Some(target.id.as_str())
                && cap.engine_version.as_deref() == Some("16.15"))
    );
    assert!(
        capabilities
            .iter()
            .filter(|cap| matches!(
                cap.action,
                ActionKind::PrepareNativeRoute
                    | ActionKind::ConfigureIdentity
                    | ActionKind::RegisterNativeDbIdentity
                    | ActionKind::ConfigureSqlPrivileges
                    | ActionKind::ConstrainDirectPath
                    | ActionKind::DisableNativeIdentity
                    | ActionKind::DisableNewConnections
                    | ActionKind::RevokeSqlPrivileges
                    | ActionKind::ObserveRevocation
            ))
            .all(|cap| cap.implementation == Implementation::Implemented
                && cap.contract_revision == "core-adapter-v2"
                && cap.coverage == veil_db_guard::core::capability::Coverage::LocalCovered)
    );
    assert!(
        capabilities
            .iter()
            .filter(|cap| matches!(
                cap.action,
                ActionKind::EnforceLeaseExpiry | ActionKind::TerminateSelectedSessions
            ))
            .all(|cap| cap.implementation == Implementation::Planned)
    );
    target.engine.family = EngineFamily::MySql;
    assert!(
        adapters::capabilities_for(&target)
            .iter()
            .all(|cap| !cap.has_implementation())
    );
    target.engine.family = EngineFamily::PostgreSql;
    target.placement.region = "us-central1".into();
    assert!(
        adapters::capabilities_for(&target)
            .iter()
            .all(|cap| !cap.has_implementation())
    );
    target.placement.region = "asia-northeast1".into();
    target.engine.version = "17.1".into();
    assert!(
        adapters::capabilities_for(&target)
            .iter()
            .all(|cap| !cap.has_implementation())
    );
}

#[test]
fn aws_fixture_and_missing_inventory_do_not_prove_incarnation_or_protection() {
    let config = common::config();
    let mut snapshot = common::snapshot();
    let target = aws_target(&config);
    let state =
        adapters::bridge_aws(&target, &config, &snapshot, &[], None, domain::now()).unwrap();
    assert_eq!(
        state.target.generation_assurance,
        GenerationAssurance::Unconfirmed
    );
    assert_eq!(state.target.native_ref.generation_fingerprint, None);
    assert!(state.origins.contains(&ObservationOrigin::Fixture));
    assert!(state.samples.is_empty());
    assert!(
        state
            .access
            .iter()
            .all(|case| case.actual == ObservedAccess::Unknown)
    );
    snapshot.db = None;
    snapshot.retrievals[0].status = domain::RetrievalStatus::AccessDenied;
    let state =
        adapters::bridge_aws(&target, &config, &snapshot, &[], None, domain::now()).unwrap();
    assert!(!state.inventory_complete);
    assert!(
        state
            .notices
            .contains(&ObservationNotice::IncompleteInventory)
    );
}

#[test]
fn current_allowed_survives_pending_with_verified_permission_history() {
    let baseline_config = gcp_config();
    let baseline = run(&baseline_config, "baseline", 1000, before_roles());
    let mut config = baseline_config.clone();
    config.permission_changes.push(GcpPermissionChange {
        principal_id: "unauthorized".into(),
        layer: GcpDenial::ConnectIam,
        changed_at: 1050,
        before_roles: before_roles(),
        after_roles: after_roles(),
    });
    let current = run(&config, "current", 1100, after_roles());
    let state = adapters::bridge_gcp(
        &target(&config),
        &config,
        &[current],
        &[GcpHistoricalRun {
            config: baseline_config,
            evidence: baseline,
        }],
        1106,
    )
    .unwrap();
    assert_eq!(state.access[0].actual, ObservedAccess::Allowed);
    assert_eq!(state.access[0].verdict, ObservedVerdict::Pending);
    assert_eq!(state.samples[0].actual, ObservedAccess::Allowed);
    assert_eq!(
        state.target.generation_assurance,
        GenerationAssurance::Unconfirmed
    );
}

#[test]
fn timeout_and_fixture_are_not_promoted_to_denial_or_current_protection() {
    let config = gcp_config();
    let mut capture = run(&config, "timeout", 1000, before_roles());
    capture.observations[0].observed = GcpAccess::Denied;
    capture.observations[0].execution = GcpExecution::Timeout;
    capture.observations[0].proof = GcpProof::default();
    let state = adapters::bridge_gcp(&target(&config), &config, &[capture], &[], 1006).unwrap();
    assert_eq!(state.access[0].actual, ObservedAccess::Unknown);
    assert_eq!(state.samples[0].actual, ObservedAccess::Unknown);
    let mut capture = run(&config, "fixture", 1000, before_roles());
    capture.evidence_kind = GcpEvidenceKind::Fixture;
    let state = adapters::bridge_gcp(&target(&config), &config, &[capture], &[], 1006).unwrap();
    assert_eq!(state.access[0].verdict, ObservedVerdict::Unknown);
    assert_eq!(state.samples[0].actual, ObservedAccess::Allowed);
    assert_eq!(state.samples[0].origin, ObservationOrigin::Fixture);
    assert!(state.notices.contains(&ObservationNotice::FixtureOnly));
}

#[test]
fn stale_or_old_build_remains_historical_evidence() {
    let config = gcp_config();
    let mut capture = run(&config, "old", 1000, before_roles());
    capture.build_id = "b".repeat(64);
    let state = adapters::bridge_gcp(&target(&config), &config, &[capture], &[], 5000).unwrap();
    assert_eq!(state.samples[0].actual, ObservedAccess::Allowed);
    assert_eq!(state.access[0].verdict, ObservedVerdict::Unknown);
    assert!(state.notices.contains(&ObservationNotice::StaleEvidence));
    assert!(state.notices.contains(&ObservationNotice::BuildMismatch));
}

#[test]
fn target_registration_must_match_native_config_not_only_logical_id() {
    let config = gcp_config();
    let mut target = target(&config);
    target.resource.native_id = "projects/another-project/instances/vdg-pg-lab".into();
    assert!(adapters::bridge_gcp(&target, &config, &[], &[], 1000).is_err());
}

fn gcp_writer(path: &std::path::Path, config: &GcpConfig) -> RunWriter {
    let id = format!(
        "gcp-{}",
        veil_db_guard::config::hash_bytes(&serde_json::to_vec(&config.target).unwrap())
    );
    RunWriter::create_for_config(
        path,
        &id,
        config,
        "gcp-check",
        config.limits.max_bytes,
        false,
    )
    .unwrap()
}

#[test]
fn import_binds_capture_to_manifest_and_rechecks_before_after_artifacts() {
    let workspace = common::workspace();
    let config = gcp_config();
    let path = workspace.join("mismatched-snapshot");
    let mut writer = gcp_writer(&path, &config);
    let mut capture = run(
        &config,
        &writer.manifest.run_id,
        domain::now(),
        before_roles(),
    );
    capture.evidence_kind = GcpEvidenceKind::Fixture;
    writer.write_json("observations.json", &capture).unwrap();
    writer
        .write_json("snapshot.before.json", &capture.before)
        .unwrap();
    let mut after = capture.after.clone();
    after.connector_enforcement = GcpConnectorEnforcement::NotRequired;
    writer.write_json("snapshot.after.json", &after).unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    assert!(
        adapters::import::import_verified_run(&target(&config), &path, domain::now() + 10).is_err()
    );
}

#[test]
fn complete_gcp_fixture_import_remains_a_fixture_and_recomputes_verdict() {
    let workspace = common::workspace();
    let config = gcp_config();
    let path = workspace.join("gcp-fixture");
    let mut writer = gcp_writer(&path, &config);
    let mut capture = run(
        &config,
        &writer.manifest.run_id,
        domain::now(),
        before_roles(),
    );
    capture.evidence_kind = GcpEvidenceKind::Fixture;
    writer.write_json("observations.json", &capture).unwrap();
    writer
        .write_json("snapshot.before.json", &capture.before)
        .unwrap();
    writer
        .write_json("snapshot.after.json", &capture.after)
        .unwrap();
    // There is intentionally no assessment.json. Only the source capture is used.
    writer.finish(RunStatus::Complete).unwrap();
    let state =
        adapters::import::import_verified_run(&target(&config), &path, domain::now() + 10).unwrap();
    assert_eq!(state.access[0].verdict, ObservedVerdict::Unknown);
    assert_eq!(state.samples[0].origin, ObservationOrigin::Fixture);
    assert!(
        matches!(&state.samples[0].actor, adapters::ActorReference::GcpDeclaredServiceAccount { service_account, .. } if service_account == &config.principals[0].service_account)
    );
    assert_eq!(
        state.target.generation_assurance,
        GenerationAssurance::Unconfirmed
    );
    assert!(!state.evidence_refs.is_empty());
}

#[test]
fn complete_aws_inventory_import_uses_source_config_and_preserves_fixture_origin() {
    let workspace = common::workspace();
    let config = common::config();
    let snapshot = common::snapshot();
    let path = workspace.join("aws-inventory");
    let mut writer = RunWriter::create(&path, &config, "inspect", true).unwrap();
    writer.write_json("snapshot.json", &snapshot).unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    let state =
        adapters::import::import_verified_run(&aws_target(&config), &path, domain::now()).unwrap();
    assert!(state.origins.contains(&ObservationOrigin::Fixture));
    assert!(state.samples.is_empty());
    assert_eq!(
        state.target.generation_assurance,
        GenerationAssurance::Unconfirmed
    );
}

#[test]
fn imported_partial_without_capture_stays_missing_and_reports_are_not_observations() {
    let workspace = common::workspace();
    let config = gcp_config();
    let path = workspace.join("missing-capture");
    let mut writer = gcp_writer(&path, &config);
    writer.finish(RunStatus::Partial).unwrap();
    let state =
        adapters::import::import_verified_run(&target(&config), &path, domain::now()).unwrap();
    assert!(!state.inventory_complete);
    assert!(state.samples.is_empty());
    assert!(state.notices.contains(&ObservationNotice::MissingEvidence));
    let config = common::config();
    let path = workspace.join("report-only");
    let mut writer = RunWriter::create(&path, &config, "report", false).unwrap();
    writer.finish(RunStatus::Complete).unwrap();
    assert!(
        adapters::import::import_verified_run(&aws_target(&config), &path, domain::now()).is_err()
    );
}

#[test]
fn control_projection_rejects_wrong_provider_payload_and_keeps_unknown_generation() {
    let config = gcp_config();
    let target = target(&config);
    let capture = run(&config, "projection-1", 90, before_roles());
    let state = adapters::bridge_gcp(&target, &config, &[capture], &[], 100).unwrap();
    let facts = state.for_change(&target).unwrap();
    assert_eq!(
        facts.target.generation_assurance,
        GenerationAssurance::Unconfirmed
    );
    assert!(facts.configuration.is_some());
    let mut forged = state.clone();
    if let Some(adapters::NativeConfiguration::Gcp(snapshot)) = &mut forged.native_configuration {
        snapshot.target.project_id = "another-project".into();
    }
    assert!(forged.for_change(&target).is_err());
}
