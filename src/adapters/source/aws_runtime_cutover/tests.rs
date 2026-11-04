use super::*;
use crate::{
    adapters::evidence::RunEvidenceArchive,
    core::{
        change::{OperationLimits, prepare_change},
        plan::build_plan,
        policy::parse_policy,
        ports::{EvidenceArchive, EvidenceClock, EvidenceLedger},
        runtime_cutover::{PoolSwitchLink, PostgresSessionIdentity},
        source::{RegisteredSourceSnapshot, SourceBinding, SourcePurpose, SourceUse},
    },
    evidence_store::{EvidenceStore, ObservationRequestSpec},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::rand::SystemRandom;

struct Clock(u64);
impl EvidenceClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}

pub(crate) struct AdmissionFixture {
    pub(crate) bundle: AwsConnectionBundle,
    pub(crate) context: RuntimeCaptureContext,
    issued: IssuedObservation,
    change: PreparedChange,
    config: Vec<u8>,
    pool_signer: AwsPostgresRuntimeSigner,
    database_signer: AwsPostgresRuntimeSigner,
    ledger: EvidenceStore,
    dir: tempfile::TempDir,
}

impl AdmissionFixture {
    pub(crate) fn new(issued_at: u64) -> Self {
        let (mut fixture, mut config, _) = super::super::aws_postgres::tests::sample();
        let app = &mut fixture.request.cases[0];
        app.kind = FixedObservationCase::RuntimeBinding;
        app.address.effect = EffectKindV2::RuntimeBinding;
        let generate = || {
            let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let pair = Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap();
            (bytes, STANDARD.encode(pair.public_key().as_ref()))
        };
        let (pool_bytes, pool_key) = generate();
        let (database_bytes, database_key) = generate();
        let pins = AwsPostgresRuntimeWitnessPolicy {
            target_id: app.address.target_id.clone(),
            grant_id: app.address.grant_id.clone(),
            subject_id: app.address.subject_id.clone(),
            pool_key,
            database_key,
            database_observer_user: "veil_recovery".into(),
            proxy_ca_sha256: "d".repeat(64),
            previous_generation: 1,
            active_generation: 2,
            not_before: issued_at - 1,
        };
        let pool_signer = AwsPostgresRuntimeSigner::from_pkcs8(
            pool_bytes.as_ref(),
            &pins,
            AwsPostgresWitnessRole::Pool,
        )
        .unwrap();
        let database_signer = AwsPostgresRuntimeSigner::from_pkcs8(
            database_bytes.as_ref(),
            &pins,
            AwsPostgresWitnessRole::Database,
        )
        .unwrap();
        config.postgres_runtime = Some(pins.clone());
        let mut direct = config.endpoints[0].clone();
        direct.endpoint = config.postgres.as_ref().unwrap().targets[0]
            .db_endpoint
            .clone();
        config.endpoints.push(direct);
        let config_bytes = serde_json::to_vec(&config).unwrap();
        let RegisteredSourceSnapshot::Aws(snapshot) = &mut fixture.snapshot else {
            unreachable!()
        };
        snapshot.collector_config_digest = hash_bytes(&config_bytes);
        fixture.request.source.revision_digest = fixture.snapshot.revision_digest().unwrap();
        app.address.source = fixture.request.source.snapshot_ref();

        let mut policy =
            parse_policy(include_str!("../../../../examples/core-aws-policy.yaml")).unwrap();
        policy.schema_version = 2;
        policy.targets[0].resource = app.address.target.native_ref.clone();
        policy.source_bindings = vec![
            fixture.request.source.clone(),
            SourceBinding {
                source_id: policy.subjects[1].workload_sources[0].clone(),
                registration_id: "aws-recovery-source".into(),
                revision_digest: "b".repeat(64),
                boundary: SourceBoundaryKind::AwsHostNetwork,
                allowed_uses: vec![SourceUse {
                    subject_id: policy.subjects[1].id.clone(),
                    purpose: SourcePurpose::Recovery,
                }],
            },
        ];
        policy.evaluation = Some(EvaluationPolicy {
            contract: EvaluationContract::SourceBoundV2,
            denial_requirements: vec![ProfileDenialRequirement {
                profile_id: policy.protection_profiles[0].id.clone(),
                accepted_layers: vec![AcceptedDenialLayer::ConnectionAuthorization],
            }],
        });
        let plan = build_plan(
            &policy,
            crate::adapters::capabilities_for_policy(&policy).unwrap(),
            vec![],
            issued_at,
        )
        .unwrap();
        let change = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
        let plan = super::super::requests::plan_aws(
            &change,
            &app.address.source.source_id,
            &config,
            issued_at,
        )
        .unwrap();
        let runtime_batches: Vec<_> = plan
            .batches
            .into_iter()
            .filter(|batch| {
                batch
                    .iter()
                    .any(|case| case.kind == FixedObservationCase::RuntimeBinding)
            })
            .collect();
        assert_eq!(runtime_batches.len(), 1);
        assert_eq!(runtime_batches[0].len(), 1);
        assert_eq!(runtime_batches[0][0].address, app.address);
        let bundle = AwsConnectionBundle::prepare(
            &change,
            &app.address.grant_id,
            &app.address.source.source_id,
            &app.address.route.id,
            pins.active_generation,
            &fixture.snapshot,
            &pins.proxy_ca_sha256,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut ledger = EvidenceStore::open(&dir.path().join("ledger.sqlite3")).unwrap();
        ledger.register_source(&fixture.snapshot, None).unwrap();
        ledger
            .start_session(&change, "aws-runtime-session", issued_at)
            .unwrap();
        let issued = ledger
            .issue_request(
                &ObservationRequestSpec {
                    request_id: "aws-runtime-request".into(),
                    operation_id: "aws-runtime-session".into(),
                    source_id: app.address.source.source_id.clone(),
                    ttl_seconds: 120,
                    cases: runtime_batches.into_iter().next().unwrap(),
                },
                issued_at,
            )
            .unwrap();
        let context = RuntimeCaptureContext::for_case(&issued, &issued.request.cases[0]).unwrap();
        Self {
            bundle,
            context,
            issued,
            change,
            config: config_bytes,
            pool_signer,
            database_signer,
            ledger,
            dir,
        }
    }

    fn signed(
        &self,
        pool: &AwsPostgresPoolObservation,
        database: &AwsPostgresDatabaseObservation,
        database_at: u64,
        pool_at: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let pool = self
            .pool_signer
            .sign_pool(&self.context, pool_at, pool_at + 35, pool)
            .unwrap();
        let database = self
            .database_signer
            .sign_database(&self.context, database_at, database_at + 30, database)
            .unwrap();
        (
            serde_json::to_vec(&pool).unwrap(),
            serde_json::to_vec(&database).unwrap(),
        )
    }

    fn window(&self, finished_at: u64) -> CaptureWindow {
        CaptureWindow {
            sent_at: self.issued.request.issued_at,
            received_at: finished_at,
            elapsed_millis: (finished_at - self.issued.request.issued_at) * 1000,
        }
    }

    pub(crate) fn admit_and_reload(
        &mut self,
        pool: &AwsPostgresPoolObservation,
        database: &AwsPostgresDatabaseObservation,
        database_at: u64,
        pool_at: u64,
    ) {
        let (pool_bytes, database_bytes) = self.signed(pool, database, database_at, pool_at);
        let mut capture = AwsPostgresRuntimeCapture::corroborate(
            &self.issued,
            &self.change,
            &self.config,
            &pool_bytes,
            &database_bytes,
            self.window(pool_at),
            pool_at,
        )
        .unwrap();
        let mut archive = RunEvidenceArchive::open(self.dir.path()).unwrap();
        let id = &self.issued.request.request_id;
        let admission = accept_evidence(
            &mut self.ledger,
            &mut archive,
            &mut capture.verifier,
            id,
            &capture.bundle,
            &capture.payloads,
            capture.window,
            &Clock(pool_at),
        )
        .unwrap();
        assert_eq!(admission.verification_recipe, RECIPE);
        assert_eq!(admission.valid_until, database_at + 30);
        let mut reopened = EvidenceStore::open(&self.dir.path().join("ledger.sqlite3")).unwrap();
        let facts = load_admitted(&mut reopened, &archive, id, pool_at).unwrap();
        let [claim] = facts.claims() else {
            panic!("exactly one RuntimeBinding claim")
        };
        assert_eq!(claim.address, self.context.address);
        assert_eq!(claim.observed, StateValue::Present);
        assert!(claim.transport.is_empty());
        assert!(claim.connection.is_none());
        let (_, archived) = archive.read(&self.issued, &admission.archive).unwrap();
        assert_eq!(archived[0].bytes, pool_bytes);
        assert_eq!(archived[1].bytes, database_bytes);
        assert!(matches!(
            load_admitted(&mut reopened, &archive, id, database_at + 30),
            Err(AdmissionError::Expired)
        ));
        let report = evaluate_admitted_change(
            &mut reopened,
            &archive,
            &self.change,
            std::slice::from_ref(id),
            pool_at,
        )
        .unwrap();
        assert_eq!(
            report
                .rows
                .iter()
                .filter(|row| row.assessment == crate::core::state::StateAssessment::Satisfied)
                .count(),
            1
        );
        assert!(!report.all_required_effects_satisfied);
    }
}

fn samples(
    fixture: &AdmissionFixture,
) -> (AwsPostgresPoolObservation, AwsPostgresDatabaseObservation) {
    let address = &fixture.context.address;
    let issued_at = fixture.issued.request.issued_at;
    let transaction = AwsPostgresTransaction {
        session: PostgresSessionIdentity {
            database: address.target.engine_binding.database.clone(),
            session_user: address.db_identity.clone(),
            backend_pid: 42,
            backend_started_at_micros: (issued_at - 5) * 1_000_000 + 101,
        },
        transaction_started_at_micros: (issued_at + 3) * 1_000_000 + 228,
        marker: aws_postgres_runtime_marker(&fixture.context),
        server_reported_ssl: Some(true),
    };
    (
        AwsPostgresPoolObservation {
            bundle_digest: fixture.bundle.digest(),
            switch: PoolSwitchLink {
                previous_generation: 1,
                active_generation: 2,
                checkout_sequence: 6,
                switched_at: issued_at + 1,
                checked_out_at: issued_at + 2,
            },
            transaction: transaction.clone(),
        },
        AwsPostgresDatabaseObservation {
            target_generation: address
                .target
                .native_ref
                .generation_fingerprint
                .clone()
                .unwrap(),
            observer_user: "veil_recovery".into(),
            transaction,
        },
    )
}

#[test]
fn signed_aws_runtime_transaction_is_admitted_archived_and_reloaded() {
    let mut fixture = AdmissionFixture::new(100);
    let (pool, database) = samples(&fixture);
    fixture.admit_and_reload(&pool, &database, 104, 105);
}

#[test]
fn signed_aws_runtime_rejects_conflicting_provenance_or_transaction() {
    let mut fixture = AdmissionFixture::new(100);
    let (pool, database) = samples(&fixture);
    let (pool_bytes, database_bytes) = fixture.signed(&pool, &database, 104, 105);
    let corroborate = |config: &[u8], pool: &[u8], database: &[u8], now| {
        AwsPostgresRuntimeCapture::corroborate(
            &fixture.issued,
            &fixture.change,
            config,
            pool,
            database,
            fixture.window(105),
            now,
        )
    };
    assert!(corroborate(&fixture.config, &pool_bytes, &database_bytes, 105).is_ok());
    assert!(corroborate(&fixture.config, &pool_bytes, &pool_bytes, 105).is_err());
    assert!(corroborate(&fixture.config, &database_bytes, &pool_bytes, 105).is_err());
    assert!(corroborate(&fixture.config, &pool_bytes, &database_bytes, 134).is_err());
    assert!(corroborate(&fixture.config, &pool_bytes, b"{}", 105).is_err());
    let mut tampered = fixture.config.clone();
    tampered.push(b' ');
    assert!(corroborate(&tampered, &pool_bytes, &database_bytes, 105).is_err());

    for n in 0..12 {
        let mut pool = pool.clone();
        let mut database = database.clone();
        match n {
            0 => pool.bundle_digest = "c".repeat(64),
            1 => pool.switch.active_generation += 1,
            2 => pool.switch.checkout_sequence = 0,
            3 => database.transaction.marker = "b".repeat(64),
            4 => database.transaction.transaction_started_at_micros += 1,
            5 => database.transaction.session.backend_started_at_micros += 1,
            6 => database.transaction.session.backend_pid += 1,
            7 => database.target_generation = "c".repeat(64),
            8 => database.observer_user = database.transaction.session.session_user.clone(),
            9 => {
                pool.transaction.server_reported_ssl = None;
                database.transaction.server_reported_ssl = None;
            }
            10 => pool.switch.switched_at = 99,
            _ => {
                pool.transaction.marker = "b".repeat(64);
                database.transaction.marker = "b".repeat(64);
            }
        }
        let (pool, database) = fixture.signed(&pool, &database, 104, 105);
        assert!(
            corroborate(&fixture.config, &pool, &database, 105).is_err(),
            "{n}"
        );
    }
    assert!(matches!(
        fixture.ledger.admission(&fixture.issued.request.request_id),
        Err(AdmissionError::NotFound)
    ));
    let replay = fixture
        .ledger
        .issue_request(
            &ObservationRequestSpec {
                request_id: "other-request".into(),
                operation_id: fixture.issued.request.operation_id.clone(),
                source_id: fixture.issued.request.source.source_id.clone(),
                ttl_seconds: 120,
                cases: fixture.issued.request.cases.clone(),
            },
            100,
        )
        .unwrap();
    assert!(
        AwsPostgresRuntimeCapture::corroborate(
            &replay,
            &fixture.change,
            &fixture.config,
            &pool_bytes,
            &database_bytes,
            fixture.window(105),
            105,
        )
        .is_err()
    );
}

#[test]
fn signed_aws_runtime_observe_cli_admits_without_native_read() {
    use clap::Parser;

    #[derive(Parser)]
    struct ObserveCli {
        #[command(flatten)]
        observe: crate::observation_cli::ObserveArgs,
    }

    let now = crate::domain::now();
    let mut fixture = AdmissionFixture::new(now - 5);
    let (pool, database) = samples(&fixture);
    let (pool_bytes, database_bytes) = fixture.signed(&pool, &database, now - 1, now);
    let cases_path = fixture.dir.path().join("cases.json");
    let config_path = fixture.dir.path().join("config.json");
    let pool_path = fixture.dir.path().join("pool.json");
    let database_path = fixture.dir.path().join("database.json");
    let ledger_path = fixture.dir.path().join("ledger.sqlite3");
    std::fs::write(
        &cases_path,
        serde_json::to_vec(&fixture.issued.request.cases).unwrap(),
    )
    .unwrap();
    std::fs::write(&config_path, &fixture.config).unwrap();
    std::fs::write(&pool_path, pool_bytes).unwrap();
    std::fs::write(&database_path, database_bytes).unwrap();
    let command = [
        "observe",
        "--ledger",
        ledger_path.to_str().unwrap(),
        "--context",
        &fixture.issued.request.operation_id,
        "--source",
        &fixture.issued.request.source.source_id,
        "--request-id",
        &fixture.issued.request.request_id,
        "--cases",
        cases_path.to_str().unwrap(),
        "--archive",
        fixture.dir.path().to_str().unwrap(),
        "--runtime-collector-config",
        config_path.to_str().unwrap(),
        "--aws-runtime-pool-witness",
        pool_path.to_str().unwrap(),
        "--aws-runtime-database-witness",
        database_path.to_str().unwrap(),
    ];
    assert!(ObserveCli::try_parse_from(&command[..command.len() - 2]).is_err());
    let parsed = ObserveCli::try_parse_from(command).unwrap();
    let status =
        crate::observation_cli::observe(parsed.observe, tokio_util::sync::CancellationToken::new())
            .unwrap();
    assert_eq!(status, 3);
    let id = &fixture.issued.request.request_id;
    let admission = fixture.ledger.admission(id).unwrap();
    assert_eq!(admission.verification_recipe, RECIPE);
    let archive = RunEvidenceArchive::open(fixture.dir.path()).unwrap();
    let facts = load_admitted(&mut fixture.ledger, &archive, id, crate::domain::now()).unwrap();
    assert_eq!(facts.claims()[0].observed, StateValue::Present);
}
