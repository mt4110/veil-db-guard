use veil_db_guard::{
    adapters::engine::postgres::*,
    core::{
        capability::ActionKind,
        change::{OperationLimits, prepare_change},
        operation::{StepRecord, StepState},
        orchestrator::StepExecutor,
        plan::build_plan,
        policy::*,
    },
};

fn policy() -> PolicyRevision {
    parse_policy(include_str!("../examples/core-policy.yaml")).unwrap()
}

#[test]
fn typed_sql_keeps_exact_scope_and_quotes_all_identifiers() {
    let mut policy = policy();
    policy.targets[0].managed_surface.db_identities[1] = "読者\"; DROP ROLE dangerous;--".into();
    policy.grants[0].sql_access.existing_roles[0] =
        policy.targets[0].managed_surface.db_identities[1].clone();
    policy.grants[0].sql_access.privileges[0].scope.object =
        Some("invoices\"; DELETE FROM other;--".into());
    let batch = compile(
        &policy,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    assert_eq!(
        batch.statements()[0],
        "GRANT \"読者\"\"; DROP ROLE dangerous;--\" TO \"billing-app@vdg-example-000000.iam\" WITH ADMIN FALSE, INHERIT TRUE, SET FALSE"
    );
    assert!(
        batch.statements()[1]
            .contains("ON TABLE \"billing\".\"invoices\"\"; DELETE FROM other;--\"")
    );
    assert!(
        !batch
            .statements()
            .iter()
            .any(|s| s.contains("GRANT ALL") || s.contains("WITH GRANT OPTION"))
    );
    let hash = batch.hash();
    policy.grants[0].sql_access.privileges[0].actions.pop();
    assert_ne!(
        hash,
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::ConfigureSqlPrivileges
        )
        .unwrap()
        .hash()
    );
}

#[test]
fn invalid_native_identifiers_and_scope_are_refused_before_transport() {
    assert_eq!(quote_identifier(&"a".repeat(64)), Err(PgError::Scope));
    assert_eq!(quote_identifier("a\0b"), Err(PgError::Scope));
    let mut policy = policy();
    policy.grants[0].sql_access.privileges[0].scope.schema = Some("foreign".into());
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::ConfigureSqlPrivileges
        ),
        Err(PgError::Scope)
    );
    let mut policy = self::policy();
    policy.targets[0]
        .managed_surface
        .fields
        .retain(|f| *f != ManagedField::DbObjectPrivilege);
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::ConfigureSqlPrivileges
        ),
        Err(PgError::Scope)
    );
    let mut policy = self::policy();
    policy.targets[0].managed_surface.sql_scopes[0].database = "other-database".into();
    policy.grants[0].sql_access.privileges[0].scope.database = "other-database".into();
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::ConfigureSqlPrivileges
        ),
        Err(PgError::Scope)
    );
}

#[test]
fn routine_overload_is_not_guessed_and_deny_cannot_grant() {
    let mut policy = policy();
    policy.grants[0].sql_access.privileges[0].scope.kind = SqlObjectKind::Routine;
    policy.grants[0].sql_access.privileges[0].actions = vec![SqlAction::Execute];
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::ConfigureSqlPrivileges
        ),
        Err(PgError::Unsupported)
    );
    policy.grants[0].admission = AdmissionIntent::Deny;
    policy.grants[0].sql_access = SqlAccessIntent::default();
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::ConfigureSqlPrivileges
        ),
        Err(PgError::Scope)
    );
    let batch = compile(
        &policy,
        "billing-db",
        "billing-access",
        PgAction::DisableNewConnections,
    )
    .unwrap();
    assert_eq!(
        batch.statements(),
        &["ALTER ROLE \"billing-app@vdg-example-000000.iam\" NOLOGIN"]
    );
    policy.targets[0].managed_surface.db_identities.clear();
    assert_eq!(
        compile(
            &policy,
            "billing-db",
            "billing-access",
            PgAction::DisableNewConnections
        ),
        Err(PgError::Scope)
    );
}

struct LostCommit {
    submits: usize,
    queries: usize,
}
impl PgTransport for LostCommit {
    fn preflight(&mut self, _: &SqlBatch) -> Result<(), PgError> {
        Ok(())
    }
    fn execute_atomic(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.submits += 1;
        Ok(PgOutcome::Unknown)
    }
    fn query(&mut self, _: &SqlBatch) -> Result<PgOutcome, PgError> {
        self.queries += 1;
        Ok(PgOutcome::NotApplied)
    }
}
#[test]
fn unknown_commit_resume_reads_only_and_absence_cannot_authorize_resend() {
    let policy = policy();
    let capabilities = policy
        .targets
        .iter()
        .flat_map(veil_db_guard::adapters::capabilities_for)
        .collect();
    let plan = build_plan(&policy, capabilities, vec![], 100).unwrap();
    let change = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConfigureSqlPrivileges)
        .unwrap();
    let batch = compile(
        &policy,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let mut executor = PostgresStepExecutor::new(
        "operator".into(),
        PostgresEngine {
            transport: LostCommit {
                submits: 0,
                queries: 0,
            },
        },
    );
    assert_eq!(executor.engine.submit(&batch).unwrap(), PgOutcome::Unknown);
    let record = StepRecord {
        step_id: step.id.clone(),
        state: StepState::OutcomeUnknown,
        attempt: 1,
        idempotency_key: "a".repeat(64),
        receipt: None,
    };
    assert_eq!(
        executor.query(&change, step, &record).unwrap().state,
        StepState::OutcomeUnknown
    );
    assert_eq!(executor.engine.transport.submits, 1);
    assert_eq!(executor.engine.transport.queries, 1);
}

#[cfg(unix)]
#[test]
fn connector_has_explicit_target_identity_argv_and_strips_secret_overrides() {
    use std::{
        collections::BTreeMap, ffi::OsString, fs, os::unix::fs::PermissionsExt, time::Duration,
    };
    use veil_db_guard::gcp::{config::parse_config, live::LiveTools};
    let root = tempfile::tempdir().unwrap();
    let gcloud = root.path().join("gcloud");
    let proxy = root.path().join("proxy");
    fs::write(&gcloud,"#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/gcloud-argv\"\n[ -z \"${PGPASSWORD+x}\" ] || exit 7\n[ -z \"${GOOGLE_APPLICATION_CREDENTIALS+x}\" ] || exit 8\nprintf '%s' '{\"auth\":{\"disable_ssl_validation\":true}}'\n").unwrap();
    fs::write(
        &proxy,
        "#!/bin/sh\nprintf invoked > \"$(dirname \"$0\")/proxy-invoked\"\nexit 9\n",
    )
    .unwrap();
    for path in [&gcloud, &proxy] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let tools = LiveTools {
        gcloud,
        proxy,
        psql: root.path().join("never-used-psql"),
        work_dir: root.path().into(),
    };
    let mut policy = policy();
    policy.targets[0].resource.generation_fingerprint = Some("a".repeat(64));
    let mut config = parse_config(include_bytes!("../examples/gcp.yaml")).unwrap();
    config.target.instance_id = "billing-postgres".into();
    config.target.database = "billing".into();
    let mut transport = ConnectorPgTransport::new(
        policy.targets[0].clone(),
        config,
        tools,
        "recovery@vdg-example-000000.iam.gserviceaccount.com".into(),
        Duration::from_secs(2),
    )
    .unwrap();
    let args = transport.proxy_arguments(12345);
    assert!(args.contains(&"--auto-iam-authn".into()));
    assert!(args.contains(&"--gcloud-auth".into()));
    assert!(args.contains(&"--address=127.0.0.1".into()));
    assert!(args.contains(&"--port=12345".into()));
    assert_eq!(
        args.last().unwrap(),
        "vdg-example-000000:asia-northeast1:billing-postgres"
    );
    let inherited: BTreeMap<OsString, OsString> = [
        ("PGPASSWORD", "SENSITIVE"),
        ("GOOGLE_APPLICATION_CREDENTIALS", "credential.json"),
        ("CSQL_PROXY_TOKEN", "SENSITIVE"),
        ("HTTP_PROXY", "http://invalid"),
        ("HOME", "/tmp"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let env = transport.environment(&inherited).unwrap();
    for name in [
        "PGPASSWORD",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CSQL_PROXY_TOKEN",
        "HTTP_PROXY",
    ] {
        assert!(!env.contains_key(std::ffi::OsStr::new(name)));
    }
    let mut overridden = inherited;
    overridden.insert("CLOUDSDK_CONFIG".into(), "/tmp/unsafe".into());
    assert!(transport.environment(&overridden).is_err());
    let batch = compile(
        &policy,
        "billing-db",
        "billing-access",
        PgAction::ConfigureSqlPrivileges,
    )
    .unwrap();
    let cancelled = tokio_util::sync::CancellationToken::new();
    cancelled.cancel();
    transport = transport.with_cancel(cancelled);
    assert_eq!(transport.preflight(&batch), Err(PgError::Unavailable));
    assert!(!root.path().join("gcloud-argv").exists());
    assert!(!root.path().join("proxy-invoked").exists());
    transport = transport.with_cancel(tokio_util::sync::CancellationToken::new());
    assert_eq!(transport.preflight(&batch), Err(PgError::Precondition));
    assert!(
        fs::read_to_string(root.path().join("gcloud-argv"))
            .unwrap()
            .contains("config\nlist\n--all")
    );
    assert!(!root.path().join("proxy-invoked").exists());
}
