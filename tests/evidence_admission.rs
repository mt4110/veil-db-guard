//! Synthetic trusted verifiers exercise local admission. No native identity,
//! cloud, SSH or real DB is contacted, and these facts are not production proof.
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
};
use veil_db_guard::{
    adapters::{
        capabilities_for_policy,
        evidence::{NativeSourceVerifierUnavailable, RunEvidenceArchive},
    },
    core::{
        admission::*,
        approval,
        change::{OperationLimits, prepare_change},
        evidence::*,
        operation::BeginRequest,
        plan::build_plan,
        policy::*,
        ports::*,
        source::*,
        state::{ArtifactRef, StateLayer, StateRoute, StateValue},
    },
    evidence_store::{EvidenceStore, ObservationRequestSpec},
    operation_store::OperationStore,
};

fn private_dir(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).unwrap();
}
struct Lab {
    _temp: tempfile::TempDir,
    path: PathBuf,
    root: PathBuf,
    snapshot: SourceRegistrationSnapshot,
    spec: ObservationRequestSpec,
}
impl Lab {
    fn new() -> Self {
        Self::with_gce_host(None)
    }

    fn with_gce_host(gce_host: Option<GceHostProfile>) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.sqlite");
        let root = temp.path().join("archives");
        private_dir(&root);
        let snapshot = SourceRegistrationSnapshot {
            schema_version: if gce_host.is_some() { 2 } else { 1 },
            registration_id: "billing-source-registration".into(),
            trust_epoch: 1,
            native_identity: GceVmIdentity {
                project_id: "vdg-example-000000".into(),
                project_number: "1234567890".into(),
                zone: "asia-northeast1-a".into(),
                instance_id: "9876543210".into(),
                created_at_unix: 1,
                service_account: "billing-app@vdg-example-000000.iam.gserviceaccount.com".into(),
                service_account_id: "123456789012345678901".into(),
            },
            ssh_host_key_digest: "a".repeat(64),
            collector_build_id: "e".repeat(64),
            collector_config_digest: "b".repeat(64),
            network_context_digest: "c".repeat(64),
            execution_user: "collector".into(),
            credential_kind: SourceCredentialKind::GceMetadata,
            credential_reference: "billing-workload".into(),
            gce_host,
        };
        let mut p = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
        p.targets[0].resource.generation_fingerprint = Some("d".repeat(64));
        let subject = p
            .subjects
            .iter_mut()
            .find(|s| s.id == "billing-app")
            .unwrap();
        subject.identity.immutable_id = Some(snapshot.native_identity.service_account_id.clone());
        let source = p
            .source_bindings
            .iter_mut()
            .find(|s| s.source_id == "billing-runtime")
            .unwrap();
        source.revision_digest = snapshot.revision_digest().unwrap();
        let source = source.clone();
        let t = &p.targets[0];
        let address = EffectAddress {
            target_id: t.id.clone(),
            target: TargetHandle {
                registration_id: t.registration_id.clone(),
                native_ref: t.resource.clone(),
                placement: t.placement.clone(),
                engine_binding: t.engine.clone(),
                generation_assurance: GenerationAssurance::Unconfirmed,
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
        let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
        let c = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
        let a = approval::issue(&c, "test-approval", "reviewer", "runner", 300, 900, 100).unwrap();
        let mut operations = OperationStore::open(&path).unwrap();
        operations.register_change(&c).unwrap();
        operations.register_approval(&c, &a).unwrap();
        operations
            .begin(&BeginRequest {
                request_id: "operation-request".into(),
                operation_id: "operation-1".into(),
                change_hash: c.change_hash.clone(),
                approval_id: a.id,
                expected_desired_head: None,
                execution_identity: "runner".into(),
                now: 100,
            })
            .unwrap();
        drop(operations);
        let mut ledger = EvidenceStore::open(&path).unwrap();
        ledger.register_source(&snapshot, None).unwrap();
        let spec = ObservationRequestSpec {
            request_id: "capture-1".into(),
            operation_id: "operation-1".into(),
            source_id: source.source_id,
            ttl_seconds: 120,
            cases: vec![RequestedCase {
                backend_tls_trust: None,
                login_catalog_targets: vec![],
                mysql_account_host: None,
                id: "connection".into(),
                kind: FixedObservationCase::NewConnection,
                address,
                purpose: SourcePurpose::Application,
                endpoint: "db.example.invalid".into(),
                port: 5432,
                address_family: AddressFamily::Ipv4,
            }],
        };
        Self {
            _temp: temp,
            path,
            root,
            snapshot,
            spec,
        }
    }
    fn ledger(&self) -> EvidenceStore {
        EvidenceStore::open_existing(&self.path).unwrap()
    }
    fn archive(&self) -> RunEvidenceArchive {
        RunEvidenceArchive::open(&self.root).unwrap()
    }
    fn issue(&self) -> IssuedObservation {
        self.ledger().issue_request(&self.spec, 100).unwrap()
    }
}
fn sample(i: &IssuedObservation) -> (Vec<u8>, Vec<EvidencePayload>) {
    let payload = EvidencePayload {
        id: "synthetic-proof".into(),
        bytes: br#"{"fixture":"local-test-only"}"#.to_vec(),
    };
    let b = ObservationBundleWire {
        schema_version: 1,
        request_digest: i.request.digest().unwrap(),
        collector_build_id: i.request.collector_build_id.clone(),
        started_at: 110,
        finished_at: 115,
        capture_complete: false,
        claims: vec![ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: "claim-1".into(),
            case_id: "connection".into(),
            policy_revision_hash: i.request.policy_revision_hash.clone(),
            address: i.request.cases[0].address.clone(),
            started_at: 111,
            finished_at: 114,
            observed: StateValue::Allowed,
            layer: StateLayer::Authentication,
            denial_cause: None,
            connection: None,
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec![payload.id.clone()],
            permission_inventory: None,
        }],
        artifacts: vec![ArtifactRef {
            id: payload.id.clone(),
            sha256: veil_db_guard::config::hash_bytes(&payload.bytes),
        }],
    };
    (serde_json::to_vec(&b).unwrap(), vec![payload])
}
fn window() -> CaptureWindow {
    CaptureWindow {
        sent_at: 110,
        received_at: 115,
        elapsed_millis: 5000,
    }
}
struct Clock(u64);
impl EvidenceClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}
struct SyntheticVerifier;
impl ObservationVerifier for SyntheticVerifier {
    fn verify(
        &mut self,
        _: &IssuedObservation,
        b: &ObservationBundleWire,
        _: &[EvidencePayload],
        _: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        let proof = vec!["synthetic-proof".into()];
        let verified = Assurance::Verified {
            evidence_refs: proof.clone(),
        };
        Ok(VerifierFindings {
            recipe_id: "synthetic-only-v1".into(),
            source_evidence_refs: proof,
            assurances: b
                .claims
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
                        completeness: Assurance::Unconfirmed {
                            reason: EvidenceReason::IncompleteCapture,
                        },
                    },
                })
                .collect(),
        })
    }
}
fn accept(
    lab: &Lab,
    bytes: &[u8],
    payloads: &[EvidencePayload],
) -> Result<EvidenceAdmission, AdmissionError> {
    accept_evidence(
        &mut lab.ledger(),
        &mut lab.archive(),
        &mut SyntheticVerifier,
        "capture-1",
        bytes,
        payloads,
        window(),
        &Clock(116),
    )
}
fn load(lab: &Lab, at: u64) -> Result<VerifiedObservationFacts, AdmissionError> {
    load_admitted(&mut lab.ledger(), &lab.archive(), "capture-1", at)
}

#[test]
fn accepted_partial_allowed_rehydrates_offline_with_original_time_and_independent_builds() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, payloads) = sample(&i);
    let a = accept(&lab, &bytes, &payloads).unwrap();
    assert_eq!(a.accepted_at, 116);
    assert_ne!(a.collector_build_id, a.verifier_build_id);
    assert_eq!(a.valid_until, 170);
    let facts = load(&lab, 120).unwrap();
    assert_eq!(facts.admission_id(), a.id);
    assert_eq!(facts.claims()[0].observed, StateValue::Allowed);
    assert_eq!(facts.claims()[0].started_at, 111);
    assert!(matches!(
        facts.assurances()[0].coverage.completeness,
        Assurance::Unconfirmed { .. }
    ));
    assert_eq!(load(&lab, 169).unwrap().admission_id(), a.id);
    assert!(matches!(load(&lab, 170), Err(AdmissionError::Expired)));
    assert_eq!(lab.ledger().admission("capture-1").unwrap(), a);
}

#[test]
fn identical_or_different_replay_cannot_refresh_or_create_a_second_archive() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    let a = accept(&lab, &bytes, &p).unwrap();
    assert_eq!(accept(&lab, &bytes, &p), Err(AdmissionError::Conflict));
    let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    changed["claims"][0]["observed"] = serde_json::json!("denied");
    assert_eq!(
        accept(&lab, &serde_json::to_vec(&changed).unwrap(), &p),
        Err(AdmissionError::Conflict)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 1);
    assert_eq!(lab.ledger().admission("capture-1").unwrap(), a);
}

#[test]
fn old_bundle_cannot_be_pasted_into_a_new_nonce_or_a_foreign_source() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    let mut spec = lab.spec.clone();
    spec.request_id = "capture-2".into();
    let j = lab.ledger().issue_request(&spec, 100).unwrap();
    assert_ne!(i.request.nonce, j.request.nonce);
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            &mut SyntheticVerifier,
            "capture-2",
            &bytes,
            &p,
            window(),
            &Clock(116)
        ),
        Err(AdmissionError::ScopeMismatch)
    );
    let mut b: ObservationBundleWire = serde_json::from_slice(&bytes).unwrap();
    b.claims[0].address.source.revision_digest = "f".repeat(64);
    assert_eq!(
        accept(&lab, &serde_json::to_vec(&b).unwrap(), &p),
        Err(AdmissionError::ScopeMismatch)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);
}

#[test]
fn unavailable_native_verifier_never_saves_or_admits_a_well_formed_claim() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            &mut NativeSourceVerifierUnavailable,
            "capture-1",
            &bytes,
            &p,
            window(),
            &Clock(116)
        ),
        Err(AdmissionError::VerifierUnavailable)
    );
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);
}

#[test]
fn source_update_is_cas_fenced_monotonic_and_invalidates_an_old_receipt() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    accept(&lab, &bytes, &p).unwrap();
    let old = lab.snapshot.revision_digest().unwrap();
    let mut s = lab.snapshot.clone();
    s.network_context_digest = "e".repeat(64);
    assert_eq!(
        lab.ledger().register_source(&s, Some(&old)),
        Err(AdmissionError::TrustChanged)
    );
    s.trust_epoch += 1;
    assert_eq!(
        lab.ledger().register_source(&s, None),
        Err(AdmissionError::Conflict)
    );
    lab.ledger().register_source(&s, Some(&old)).unwrap();
    assert!(matches!(load(&lab, 120), Err(AdmissionError::TrustChanged)));
    assert!(matches!(
        lab.ledger().issue_request(&lab.spec, 120),
        Err(AdmissionError::TrustChanged)
    ));
}

#[test]
fn same_physical_vm_cannot_be_registered_again_under_a_recovery_alias() {
    let lab = Lab::new();
    let mut s = lab.snapshot.clone();
    s.registration_id = "alias-registration".into();
    assert_eq!(
        lab.ledger().register_source(&s, None),
        Err(AdmissionError::ScopeMismatch)
    );
}

#[test]
fn request_scope_rejects_changed_identity_generation_route_and_management_use() {
    let lab = Lab::new();
    for n in 0..5 {
        let mut s = lab.spec.clone();
        match n {
            0 => s.cases[0].address.db_identity = "other-login".into(),
            1 => s.cases[0].address.target.native_ref.generation_fingerprint = Some("f".repeat(64)),
            2 => s.cases[0].address.route.id = "other-route".into(),
            3 => s.cases[0].purpose = SourcePurpose::Recovery,
            _ => s.cases[0].address.subject_id = "recovery-operator".into(),
        }
        assert!(lab.ledger().issue_request(&s, 100).is_err());
    }
    lab.issue(); // Rejections did not claim request ID/nonce or consume quota.
}

#[test]
fn active_request_quota_is_finite_and_expired_records_are_not_deleted_or_reused() {
    let lab = Lab::new();
    let mut ledger = lab.ledger();
    for n in 0..MAX_ACTIVE_REQUESTS {
        let mut s = lab.spec.clone();
        s.request_id = format!("capture-{n}");
        ledger.issue_request(&s, 100).unwrap();
    }
    let mut s = lab.spec.clone();
    s.request_id = "over-quota".into();
    assert_eq!(
        ledger.issue_request(&s, 100).unwrap_err(),
        AdmissionError::Limit
    );
    ledger.issue_request(&s, 221).unwrap();
    assert_eq!(ledger.issued("capture-0").unwrap().request.issued_at, 100);
    let mut old = lab.spec.clone();
    old.request_id = "capture-0".into();
    assert_eq!(
        ledger.issue_request(&old, 221).unwrap_err(),
        AdmissionError::Conflict
    );
}

#[test]
fn payload_integrity_clock_skew_and_build_mismatch_stop_before_file_creation() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    assert_eq!(accept(&lab, &bytes, &[]), Err(AdmissionError::Integrity));
    let mut wrong = p.clone();
    wrong[0].bytes.push(0);
    assert_eq!(accept(&lab, &bytes, &wrong), Err(AdmissionError::Integrity));
    let mut b: ObservationBundleWire = serde_json::from_slice(&bytes).unwrap();
    b.collector_build_id = "f".repeat(64);
    assert_eq!(
        accept(&lab, &serde_json::to_vec(&b).unwrap(), &p),
        Err(AdmissionError::ScopeMismatch)
    );
    let bad = CaptureWindow {
        sent_at: 100,
        received_at: 115,
        elapsed_millis: 1,
    };
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            &mut SyntheticVerifier,
            "capture-1",
            &bytes,
            &p,
            bad,
            &Clock(116)
        ),
        Err(AdmissionError::Invalid)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);
}

struct StepClock(std::cell::Cell<usize>);
impl EvidenceClock for StepClock {
    fn now(&self) -> u64 {
        let n = self.0.get();
        self.0.set(n + 1);
        if n == 0 { 116 } else { 171 }
    }
}
#[test]
fn expiry_during_file_save_leaves_an_unadmitted_archive_without_refreshing_time() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            &mut SyntheticVerifier,
            "capture-1",
            &bytes,
            &p,
            window(),
            &StepClock(std::cell::Cell::new(0))
        ),
        Err(AdmissionError::Expired)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 1);
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert!(matches!(load(&lab, 120), Err(AdmissionError::NotFound)));
}

struct FailCommit(EvidenceStore);
impl EvidenceLedger for FailCommit {
    fn issued(&mut self, id: &str) -> Result<IssuedObservation, AdmissionError> {
        self.0.issued(id)
    }
    fn ensure_current(&mut self, i: &IssuedObservation, n: u64) -> Result<(), AdmissionError> {
        self.0.ensure_current(i, n)
    }
    fn admission(&mut self, id: &str) -> Result<EvidenceAdmission, AdmissionError> {
        self.0.admission(id)
    }
    fn admit(
        &mut self,
        _: &VerifiedCandidate,
        _: u64,
    ) -> Result<EvidenceAdmission, AdmissionError> {
        Err(AdmissionError::Storage)
    }
}
#[test]
fn saved_files_without_a_commit_or_copy_to_a_new_ledger_never_mint_facts() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    assert_eq!(
        accept_evidence(
            &mut FailCommit(lab.ledger()),
            &mut lab.archive(),
            &mut SyntheticVerifier,
            "capture-1",
            &bytes,
            &p,
            window(),
            &Clock(116)
        ),
        Err(AdmissionError::Storage)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 1);
    assert!(matches!(load(&lab, 120), Err(AdmissionError::NotFound)));
    let fresh = lab._temp.path().join("fresh.sqlite");
    let mut ledger = EvidenceStore::open(&fresh).unwrap();
    assert!(matches!(
        load_admitted(&mut ledger, &lab.archive(), "capture-1", 120),
        Err(AdmissionError::NotFound)
    ));
}

struct ChangeTrust {
    archive: RunEvidenceArchive,
    path: PathBuf,
    snapshot: SourceRegistrationSnapshot,
}
impl EvidenceArchive for ChangeTrust {
    fn persist(
        &mut self,
        i: &IssuedObservation,
        b: &[u8],
        p: &[EvidencePayload],
    ) -> Result<EvidenceArchiveRef, AdmissionError> {
        let saved = self.archive.persist(i, b, p)?;
        let old = self.snapshot.revision_digest().unwrap();
        self.snapshot.trust_epoch += 1;
        EvidenceStore::open_existing(&self.path)?.register_source(&self.snapshot, Some(&old))?;
        Ok(saved)
    }
    fn read(
        &self,
        i: &IssuedObservation,
        r: &EvidenceArchiveRef,
    ) -> Result<(Vec<u8>, Vec<EvidencePayload>), AdmissionError> {
        self.archive.read(i, r)
    }
}
#[test]
fn trust_change_between_save_and_commit_is_checked_in_the_sqlite_transaction() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    let mut archive = ChangeTrust {
        archive: lab.archive(),
        path: lab.path.clone(),
        snapshot: lab.snapshot.clone(),
    };
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut archive,
            &mut SyntheticVerifier,
            "capture-1",
            &bytes,
            &p,
            window(),
            &Clock(116)
        ),
        Err(AdmissionError::TrustChanged)
    );
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
}

struct RacingArchive {
    archive: RunEvidenceArchive,
    barrier: Arc<Barrier>,
}
impl EvidenceArchive for RacingArchive {
    fn persist(
        &mut self,
        i: &IssuedObservation,
        b: &[u8],
        p: &[EvidencePayload],
    ) -> Result<EvidenceArchiveRef, AdmissionError> {
        let result = self.archive.persist(i, b, p);
        self.barrier.wait();
        result
    }
    fn read(
        &self,
        i: &IssuedObservation,
        r: &EvidenceArchiveRef,
    ) -> Result<(Vec<u8>, Vec<EvidencePayload>), AdmissionError> {
        self.archive.read(i, r)
    }
}
#[test]
fn simultaneous_distinct_bundles_for_one_nonce_have_exactly_one_atomic_winner() {
    let lab = Lab::new();
    let i = lab.issue();
    let (bytes, p) = sample(&i);
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|n| {
            let path = lab.path.clone();
            let root = lab.root.clone();
            let mut b = bytes.clone();
            let p = p.clone();
            let barrier = barrier.clone();
            if n == 1 {
                let mut bundle: ObservationBundleWire = serde_json::from_slice(&b).unwrap();
                bundle.claims[0].observed = StateValue::Denied;
                b = serde_json::to_vec(&bundle).unwrap();
            }
            std::thread::spawn(move || {
                let mut ledger = EvidenceStore::open_existing(&path).unwrap();
                let mut archive = RacingArchive {
                    archive: RunEvidenceArchive::open(&root).unwrap(),
                    barrier,
                };
                accept_evidence(
                    &mut ledger,
                    &mut archive,
                    &mut SyntheticVerifier,
                    "capture-1",
                    &b,
                    &p,
                    window(),
                    &Clock(116),
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(AdmissionError::Conflict))
            .count(),
        1,
        "{results:?}"
    );
    let a = results.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(load(&lab, 120).unwrap().admission_id(), a.id);
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 2); // Losing saved run remains unadmitted.
}

#[test]
fn modified_or_missing_admitted_artifacts_are_integrity_errors() {
    for file in [
        "manifest.json",
        "evidence-bundle.json",
        "evidence-artifacts.json",
        "config.normalized.json",
    ] {
        let lab = Lab::new();
        let i = lab.issue();
        let (b, p) = sample(&i);
        let a = accept(&lab, &b, &p).unwrap();
        let path = lab.root.join(&a.archive.run_id).join(file);
        fs::rename(&path, path.with_extension("saved")).unwrap();
        assert!(matches!(load(&lab, 120), Err(AdmissionError::Integrity)));
    }
    let lab = Lab::new();
    let i = lab.issue();
    let (b, p) = sample(&i);
    let a = accept(&lab, &b, &p).unwrap();
    fs::write(
        lab.root.join(a.archive.run_id).join("evidence-bundle.json"),
        b"{}",
    )
    .unwrap();
    assert!(matches!(load(&lab, 120), Err(AdmissionError::Integrity)));
}

#[cfg(unix)]
#[test]
fn symlinks_hardlinks_and_fifo_artifacts_are_rejected_without_blocking() {
    use std::os::unix::fs::symlink;
    for kind in 0..3 {
        let lab = Lab::new();
        let i = lab.issue();
        let (b, p) = sample(&i);
        let a = accept(&lab, &b, &p).unwrap();
        let path = lab.root.join(a.archive.run_id).join("evidence-bundle.json");
        let saved = path.with_extension("saved");
        fs::rename(&path, &saved).unwrap();
        match kind {
            0 => symlink(&saved, &path).unwrap(),
            1 => fs::hard_link(&saved, &path).unwrap(),
            _ => {
                let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        }
        assert!(matches!(load(&lab, 120), Err(AdmissionError::Integrity)));
    }
}

#[test]
fn v1_operation_readers_still_work_and_missing_evidence_tables_are_not_created_by_open_existing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("v1.sqlite");
    drop(OperationStore::open(&path).unwrap());
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        EvidenceStore::open_existing(&path),
        Err(AdmissionError::NotFound)
    ));
    assert_eq!(before, fs::read(&path).unwrap());
    let lab = Lab::new();
    let mut reader = OperationStore::open_existing(&lab.path).unwrap();
    let before = reader.get("operation-1").unwrap();
    drop(reader);
    let i = lab.issue();
    let (b, p) = sample(&i);
    accept(&lab, &b, &p).unwrap();
    reader = OperationStore::open_existing(&lab.path).unwrap();
    assert_eq!(reader.get("operation-1").unwrap(), before);
}

#[test]
fn sql_catalog_cases_cannot_widen_the_reviewed_grants_scope() {
    let lab = Lab::new();
    let mut spec = lab.spec.clone();
    spec.cases[0].kind = FixedObservationCase::EffectiveSqlPrivilege;
    spec.cases[0].address.effect = EffectKindV2::EffectiveSqlRole {
        role: "unmanaged-admin".into(),
    };
    assert_eq!(
        lab.ledger().issue_request(&spec, 100).unwrap_err(),
        AdmissionError::ScopeMismatch
    );
    spec.cases[0].address.effect = EffectKindV2::EffectiveSqlRole {
        role: "billing-reader-writer".into(),
    };
    lab.ledger().issue_request(&spec, 100).unwrap();
}

struct ExemptionVerifier;
impl ObservationVerifier for ExemptionVerifier {
    fn verify(
        &mut self,
        i: &IssuedObservation,
        b: &ObservationBundleWire,
        p: &[EvidencePayload],
        w: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        let mut f = SyntheticVerifier.verify(i, b, p, w)?;
        f.assurances[0].coverage.temporal = Assurance::NotApplicable {
            contract_rule: "skip-expiry".into(),
        };
        Ok(f)
    }
}
#[test]
fn an_unrecognized_assurance_exemption_cannot_skip_admission_checks() {
    let lab = Lab::new();
    let i = lab.issue();
    let (b, p) = sample(&i);
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            &mut ExemptionVerifier,
            "capture-1",
            &b,
            &p,
            window(),
            &Clock(116)
        ),
        Err(AdmissionError::Invalid)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);
}

#[test]
fn archive_quota_stops_before_admission_and_preserves_the_partial_run() {
    let lab = Lab::new();
    let i = lab.issue();
    let (b, mut p) = sample(&i);
    p[0].bytes = vec![b'x'; 3 * 1024 * 1024];
    let mut bundle: ObservationBundleWire = serde_json::from_slice(&b).unwrap();
    bundle.artifacts[0].sha256 = veil_db_guard::config::hash_bytes(&p[0].bytes);
    assert_eq!(
        accept(&lab, &serde_json::to_vec(&bundle).unwrap(), &p),
        Err(AdmissionError::Limit)
    );
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 1);
}

#[test]
fn offline_effective_composition_reloads_admission_integrity_and_keeps_partial_allowed() {
    let lab = Lab::new();
    let issued = lab.issue();
    let (bytes, payloads) = sample(&issued);
    accept(&lab, &bytes, &payloads).unwrap();
    let op = OperationStore::open_existing(&lab.path).unwrap();
    let operation = op.get("operation-1").unwrap();
    let change = op.load_change(&operation.change_hash).unwrap();
    let r = evaluate_admitted_change(
        &mut lab.ledger(),
        &lab.archive(),
        &change,
        std::slice::from_ref(&issued.request.request_id),
        120,
    )
    .unwrap();
    assert!(r.protection_evaluated);
    assert!(!r.all_required_effects_satisfied);
    assert!(r.rows.iter().any(|r| r.observed == StateValue::Allowed));
    assert!(
        r.rows
            .iter()
            .any(|r| r.desired.address.effect == EffectKindV2::RuntimeBinding
                && r.observed == StateValue::Unknown)
    );
    assert!(matches!(
        evaluate_admitted_change(
            &mut lab.ledger(),
            &lab.archive(),
            &change,
            &[issued.request.request_id],
            171
        ),
        Err(AdmissionError::Expired)
    ));
}

#[test]
fn readonly_session_has_no_approval_dispatch_or_desired_head_side_effects_and_ids_cannot_be_reused_as_operations()
 {
    let lab = Lab::new();
    let ops = OperationStore::open_existing(&lab.path).unwrap();
    let op = ops.get("operation-1").unwrap();
    let change = ops.load_change(&op.change_hash).unwrap();
    let head = ops.desired_head(&change.policy.policy_id).unwrap();
    drop(ops);
    let mut ledger = lab.ledger();
    let s = ledger.start_session(&change, "read-only", 100).unwrap();
    assert_eq!(ledger.start_session(&change, "read-only", 120).unwrap(), s);
    assert!(matches!(
        ledger.start_session(&change, "operation-1", 100),
        Err(AdmissionError::Conflict)
    ));
    let mut spec = lab.spec.clone();
    spec.operation_id = s.id.clone();
    let issued = ledger.issue_request(&spec, 100).unwrap();
    assert_eq!(issued.request.operation_id, "read-only");
    assert_eq!(
        ledger.request_ids("read-only").unwrap(),
        vec![spec.request_id]
    );
    let mut ops = OperationStore::open_existing(&lab.path).unwrap();
    assert_eq!(ops.desired_head(&change.policy.policy_id).unwrap(), head);
    assert!(ops.get("read-only").is_err());
    assert!(matches!(
        ops.begin(&BeginRequest {
            request_id: "new-forward-request".into(),
            operation_id: s.id,
            change_hash: op.change_hash,
            approval_id: "test-approval".into(),
            expected_desired_head: head,
            execution_identity: "runner".into(),
            now: 120
        }),
        Err(veil_db_guard::core::operation::StoreError::Conflict)
    ));
}
#[test]
fn expired_and_revoked_admissions_remain_ineligible_original_history_without_refresh() {
    use veil_db_guard::adapters::source::state::{AdmissionErrorCode, evaluate};
    let lab = Lab::new();
    let issued = lab.issue();
    let (bytes, payloads) = sample(&issued);
    let original = accept(&lab, &bytes, &payloads).unwrap();
    let ops = OperationStore::open_existing(&lab.path).unwrap();
    let op = ops.get("operation-1").unwrap();
    let change = ops.load_change(&op.change_hash).unwrap();
    for now in [120, 171] {
        let report = evaluate(
            &mut lab.ledger(),
            &lab.archive(),
            &change,
            "operation-1",
            std::slice::from_ref(&issued.request.request_id),
            now,
        )
        .unwrap();
        if now == 120 {
            assert!(report.effective.protection_evaluated);
            assert!(
                report
                    .effective
                    .rows
                    .iter()
                    .any(|r| r.observed == StateValue::Allowed)
            );
        } else {
            assert!(!report.effective.protection_evaluated);
            assert_eq!(
                report.admission_reads[0].error,
                Some(AdmissionErrorCode::Expired)
            );
            assert!(report.effective.rows.iter().flat_map(|r| &r.history).any(
                |h| h.claim.observed == StateValue::Allowed
                    && !h.eligible
                    && h.reason == Some(EvidenceReason::StaleEvidence)
            ));
        }
        assert_eq!(
            report.admission_reads[0].original_admission.as_ref(),
            Some(&original)
        );
        assert!(!report.native_queries_performed);
    }
    let mut replacement = lab.snapshot.clone();
    replacement.trust_epoch += 1;
    lab.ledger()
        .register_source(&replacement, Some(&lab.snapshot.revision_digest().unwrap()))
        .unwrap();
    let report = evaluate(
        &mut lab.ledger(),
        &lab.archive(),
        &change,
        "operation-1",
        std::slice::from_ref(&issued.request.request_id),
        120,
    )
    .unwrap();
    assert_eq!(
        report.admission_reads[0].error,
        Some(AdmissionErrorCode::TrustChanged)
    );
    assert!(!report.effective.protection_evaluated);
    assert_eq!(
        lab.ledger().admission(&issued.request.request_id).unwrap(),
        original
    );
}
#[test]
fn offline_status_never_uses_corrupt_history_or_same_change_from_another_context() {
    use veil_db_guard::adapters::source::state::{AdmissionErrorCode, evaluate};
    let lab = Lab::new();
    let issued = lab.issue();
    let (bytes, payloads) = sample(&issued);
    let receipt = accept(&lab, &bytes, &payloads).unwrap();
    let ops = OperationStore::open_existing(&lab.path).unwrap();
    let op = ops.get("operation-1").unwrap();
    let change = ops.load_change(&op.change_hash).unwrap();
    assert!(matches!(
        evaluate(
            &mut lab.ledger(),
            &lab.archive(),
            &change,
            "another-context",
            std::slice::from_ref(&issued.request.request_id),
            120
        ),
        Err(AdmissionError::ScopeMismatch)
    ));
    fs::write(
        lab.root
            .join(&receipt.archive.run_id)
            .join("evidence-bundle.json"),
        b"PRIVATE_CORRUPT_SENTINEL",
    )
    .unwrap();
    let report = evaluate(
        &mut lab.ledger(),
        &lab.archive(),
        &change,
        "operation-1",
        std::slice::from_ref(&issued.request.request_id),
        171,
    )
    .unwrap();
    assert_eq!(
        report.admission_reads[0].error,
        Some(AdmissionErrorCode::IntegrityError)
    );
    assert!(
        report
            .effective
            .rows
            .iter()
            .all(|r| r.history.is_empty() && r.observed == StateValue::Unknown)
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE_CORRUPT_SENTINEL")
    );
}

#[test]
fn fresh_current_capture_survives_older_expired_history_and_observation_requests_cannot_be_backdated()
 {
    use veil_db_guard::adapters::source::state::{AdmissionErrorCode, evaluate};
    let lab = Lab::new();
    let old = lab.issue();
    let (bytes, payloads) = sample(&old);
    accept(&lab, &bytes, &payloads).unwrap();
    let ops = OperationStore::open_existing(&lab.path).unwrap();
    let op = ops.get("operation-1").unwrap();
    let change = ops.load_change(&op.change_hash).unwrap();
    drop(ops);
    let mut ledger = lab.ledger();
    assert!(matches!(
        ledger.start_session(&change, "backdated", 99),
        Err(AdmissionError::Invalid)
    ));
    ledger.start_session(&change, "later-session", 150).unwrap();
    let mut invalid = lab.spec.clone();
    invalid.operation_id = "later-session".into();
    invalid.request_id = "backdated-request".into();
    assert!(matches!(
        ledger.issue_request(&invalid, 149),
        Err(AdmissionError::Invalid)
    ));
    let mut spec = lab.spec.clone();
    spec.request_id = "fresh-capture".into();
    let fresh = ledger.issue_request(&spec, 150).unwrap();
    let (bytes, payloads) = sample(&fresh);
    let mut bundle: ObservationBundleWire = serde_json::from_slice(&bytes).unwrap();
    bundle.started_at = 152;
    bundle.finished_at = 155;
    bundle.claims[0].started_at = 153;
    bundle.claims[0].finished_at = 154;
    accept_evidence(
        &mut ledger,
        &mut lab.archive(),
        &mut SyntheticVerifier,
        &fresh.request.request_id,
        &serde_json::to_vec(&bundle).unwrap(),
        &payloads,
        CaptureWindow {
            sent_at: 152,
            received_at: 155,
            elapsed_millis: 3000,
        },
        &Clock(156),
    )
    .unwrap();
    let report = evaluate(
        &mut ledger,
        &lab.archive(),
        &change,
        "operation-1",
        &[old.request.request_id, fresh.request.request_id],
        171,
    )
    .unwrap();
    assert_eq!(
        report.admission_reads[0].error,
        Some(AdmissionErrorCode::Expired)
    );
    assert!(report.admission_reads[1].current);
    assert!(report.effective.rows.iter().any(|r| {
        r.observed == StateValue::Allowed
            && r.protection_evaluated
            && r.history
                .iter()
                .any(|h| h.reason == Some(EvidenceReason::StaleEvidence))
    }));
}

#[test]
fn execution_gate_reloads_original_archive_and_requires_real_operation_dispatch() {
    use veil_db_guard::{
        adapters::source::execution::LocalSourceGate,
        core::{capability::ActionKind, source_execution::*},
    };
    let lab = Lab::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issued = lab.ledger().issue_request(&lab.spec, now - 10).unwrap();
    let (bytes, payloads) = sample(&issued);
    let mut bundle: ObservationBundleWire = serde_json::from_slice(&bytes).unwrap();
    bundle.started_at = now - 8;
    bundle.finished_at = now - 5;
    bundle.claims[0].started_at = now - 7;
    bundle.claims[0].finished_at = now - 6;
    let receipt = accept_evidence(
        &mut lab.ledger(),
        &mut lab.archive(),
        &mut SyntheticVerifier,
        "capture-1",
        &serde_json::to_vec(&bundle).unwrap(),
        &payloads,
        CaptureWindow {
            sent_at: now - 8,
            received_at: now - 5,
            elapsed_millis: 3000,
        },
        &Clock(now - 4),
    )
    .unwrap();
    let operations = OperationStore::open_existing(&lab.path).unwrap();
    let op = operations.get("operation-1").unwrap();
    let change = operations.load_change(&op.change_hash).unwrap();
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConstrainDirectPath)
        .unwrap();
    let before = operations.steps(&op.id).unwrap();
    let mut gate = LocalSourceGate::new(
        lab.path.clone(),
        lab.root.clone(),
        op.id.clone(),
        vec!["capture-1".into()],
    );
    // The historical GCE schema-1 snapshot has no executable root collector
    // profile; reject it even before preparatory native changes.
    assert!(gate.validate_sources(&change).is_err());
    // A current partial source receipt is not sufficient for safe closure.
    assert!(
        !gate
            .check(&change, step, SourceStepPhase::BeforeDispatch)
            .unwrap()
            .satisfied()
    );
    assert!(
        gate.check(
            &change,
            step,
            SourceStepPhase::AfterConfiguration { not_before: 0 }
        )
        .is_err()
    );
    assert_eq!(lab.ledger().admission("capture-1").unwrap(), receipt);
    assert_eq!(operations.steps(&op.id).unwrap(), before);
    // Corrupting an originally admitted archive cannot be hidden by a stored
    // verdict or a successful earlier check on the SAME gate object.
    fs::write(
        lab.root
            .join(&receipt.archive.run_id)
            .join("evidence-bundle.json"),
        b"{}",
    )
    .unwrap();
    assert!(
        gate.check(&change, step, SourceStepPhase::BeforeDispatch)
            .is_err()
    );
}

#[test]
fn execution_gate_rejects_readonly_session_and_other_context_request() {
    use veil_db_guard::{
        adapters::source::execution::LocalSourceGate,
        core::{capability::ActionKind, source_execution::*},
    };
    let lab = Lab::new();
    let operations = OperationStore::open_existing(&lab.path).unwrap();
    let op = operations.get("operation-1").unwrap();
    let change = operations.load_change(&op.change_hash).unwrap();
    let step = change
        .plan
        .steps
        .iter()
        .find(|s| s.action == ActionKind::ConstrainDirectPath)
        .unwrap();
    let mut ledger = lab.ledger();
    ledger.start_session(&change, "other-context", 100).unwrap();
    let mut spec = lab.spec.clone();
    spec.operation_id = "other-context".into();
    ledger.issue_request(&spec, 100).unwrap();
    let mut gate = LocalSourceGate::new(
        lab.path.clone(),
        lab.root.clone(),
        "operation-1".into(),
        vec![spec.request_id],
    );
    assert!(
        gate.check(&change, step, SourceStepPhase::BeforeDispatch)
            .is_err()
    );
    let mut readonly = LocalSourceGate::new(
        lab.path.clone(),
        lab.root.clone(),
        "other-context".into(),
        vec![],
    );
    assert!(
        readonly
            .check(&change, step, SourceStepPhase::BeforeDispatch)
            .is_err()
    );
}

// K11-A admission fixtures use a synthetic producer, never the native GCE
// observer. Real SQLite/archive checks establish local protocol behavior only.
fn runtime_lab() -> Lab {
    let mut lab = Lab::new();
    lab.spec.cases[0].kind = FixedObservationCase::RuntimeBinding;
    lab.spec.cases[0].address.effect = EffectKindV2::RuntimeBinding;
    lab
}

fn runtime_sample(i: &IssuedObservation) -> (ObservationBundleWire, Vec<EvidencePayload>) {
    use veil_db_guard::core::runtime_binding::{
        LinuxProcessSocketSnapshot, LinuxRuntimeCaptureWire, RuntimeCaptureContext,
    };
    let (bytes, payloads) = sample(i);
    let mut bundle: ObservationBundleWire = serde_json::from_slice(&bytes).unwrap();
    let snapshot = LinuxProcessSocketSnapshot {
        boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
        pid: 51,
        start_ticks: 820,
        executable_digest: "5".repeat(64),
        uid: 1000,
        effective_uid: 1000,
        gid: 1000,
        effective_gid: 1000,
        net_namespace: 10,
        mount_namespace: 11,
        user_namespace: 12,
        cgroup_digest: "6".repeat(64),
        security_digest: "7".repeat(64),
        fd: 7,
        socket_inode: 813,
        tcp_state: 1,
        connection: ConnectionTuple {
            endpoint: i.request.cases[0].endpoint.clone(),
            local_ip: "10.0.0.1".parse().unwrap(),
            local_port: 50001,
            peer_ip: "10.0.0.2".parse().unwrap(),
            peer_port: i.request.cases[0].port,
        },
    };
    let claim = &mut bundle.claims[0];
    claim.observed = StateValue::Unknown;
    claim.layer = StateLayer::Configuration;
    claim.connection = Some(snapshot.connection.clone());
    claim.runtime_capture = Some(LinuxRuntimeCaptureWire {
        schema_version: 1,
        context: RuntimeCaptureContext::for_case(i, &i.request.cases[0]).unwrap(),
        before: snapshot.clone(),
        after: snapshot,
    });
    (bundle, payloads)
}

struct RuntimeSyntheticAllFacetsVerifier;
impl ObservationVerifier for RuntimeSyntheticAllFacetsVerifier {
    fn verify(
        &mut self,
        issued: &IssuedObservation,
        bundle: &ObservationBundleWire,
        payloads: &[EvidencePayload],
        window: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        let mut findings = SyntheticVerifier.verify(issued, bundle, payloads, window)?;
        for assurance in &mut findings.assurances {
            assurance.coverage.completeness = Assurance::Verified {
                evidence_refs: vec!["synthetic-proof".into()],
            };
        }
        Ok(findings)
    }
}

#[test]
fn runtime_admission_roundtrip_preserves_partial_capture_and_unknown_even_with_all_facets() {
    let lab = runtime_lab();
    let issued = lab.issue();
    let (bundle, payloads) = runtime_sample(&issued);
    let bytes = serde_json::to_vec(&bundle).unwrap();
    let receipt = accept_evidence(
        &mut lab.ledger(),
        &mut lab.archive(),
        &mut RuntimeSyntheticAllFacetsVerifier,
        "capture-1",
        &bytes,
        &payloads,
        window(),
        &Clock(116),
    )
    .unwrap();
    let facts = load(&lab, 120).unwrap();
    assert_eq!(
        facts.claims()[0].runtime_capture,
        bundle.claims[0].runtime_capture
    );
    assert_eq!(facts.claims()[0].observed, StateValue::Unknown);
    let coverage = &facts.assurances()[0].coverage;
    assert!(
        [
            &coverage.target,
            &coverage.principal,
            &coverage.source,
            &coverage.route,
            &coverage.transport,
            &coverage.temporal,
            &coverage.completeness,
        ]
        .iter()
        .all(|facet| matches!(facet, Assurance::Verified { .. }))
    );
    let operations = OperationStore::open_existing(&lab.path).unwrap();
    let operation = operations.get("operation-1").unwrap();
    let change = operations.load_change(&operation.change_hash).unwrap();
    let report = evaluate_admitted_change(
        &mut lab.ledger(),
        &lab.archive(),
        &change,
        &[issued.request.request_id],
        120,
    )
    .unwrap();
    let row = report
        .rows
        .iter()
        .find(|row| row.desired.address == bundle.claims[0].address)
        .unwrap();
    assert_eq!(row.observed, StateValue::Unknown);
    assert_ne!(
        row.assessment,
        veil_db_guard::core::state::StateAssessment::Satisfied
    );
    assert!(!report.all_required_effects_satisfied);
    assert_eq!(
        accept(&lab, &bytes, &payloads),
        Err(AdmissionError::Conflict)
    );
    assert_eq!(lab.ledger().admission("capture-1").unwrap(), receipt);
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 1);
}

#[test]
fn runtime_admission_rejects_context_changes_and_old_capture_under_new_nonce() {
    let lab = runtime_lab();
    let issued = lab.issue();
    let (bundle, payloads) = runtime_sample(&issued);
    for change in 0..6 {
        let mut changed = bundle.clone();
        let runtime = changed.claims[0].runtime_capture.as_mut().unwrap();
        match change {
            0 => runtime.context.request_digest = "f".repeat(64),
            1 => runtime.context.case_id = "other-case".into(),
            2 => runtime.context.source_trust_epoch += 1,
            3 => {
                runtime
                    .context
                    .address
                    .target
                    .native_ref
                    .generation_fingerprint = Some("f".repeat(64))
            }
            4 => runtime.after.socket_inode += 1,
            _ => runtime.before.connection.peer_port += 1,
        }
        assert_eq!(
            accept(&lab, &serde_json::to_vec(&changed).unwrap(), &payloads),
            Err(AdmissionError::ScopeMismatch)
        );
    }
    let mut other_spec = lab.spec.clone();
    other_spec.request_id = "capture-2".into();
    let other = lab.ledger().issue_request(&other_spec, 100).unwrap();
    assert_ne!(issued.request.nonce, other.request.nonce);
    let mut replay = bundle;
    replay.request_digest = other.request.digest().unwrap();
    assert_eq!(
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            &mut SyntheticVerifier,
            "capture-2",
            &serde_json::to_vec(&replay).unwrap(),
            &payloads,
            window(),
            &Clock(116),
        ),
        Err(AdmissionError::ScopeMismatch)
    );
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(
        lab.ledger().admission("capture-2"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);
}

#[test]
fn runtime_admission_original_expiry_and_source_trust_remain_mandatory() {
    let lab = runtime_lab();
    let issued = lab.issue();
    let (bundle, payloads) = runtime_sample(&issued);
    let bytes = serde_json::to_vec(&bundle).unwrap();
    accept(&lab, &bytes, &payloads).unwrap();
    assert!(matches!(load(&lab, 170), Err(AdmissionError::Expired)));
    let old_digest = lab.snapshot.revision_digest().unwrap();
    let mut replacement = lab.snapshot.clone();
    replacement.trust_epoch += 1;
    replacement.network_context_digest = "e".repeat(64);
    lab.ledger()
        .register_source(&replacement, Some(&old_digest))
        .unwrap();
    assert!(matches!(load(&lab, 120), Err(AdmissionError::TrustChanged)));

    let stale_lab = runtime_lab();
    let stale_issued = stale_lab.issue();
    let (stale_bundle, stale_payloads) = runtime_sample(&stale_issued);
    assert_eq!(
        accept_evidence(
            &mut stale_lab.ledger(),
            &mut stale_lab.archive(),
            &mut SyntheticVerifier,
            "capture-1",
            &serde_json::to_vec(&stale_bundle).unwrap(),
            &stale_payloads,
            window(),
            &Clock(170),
        ),
        Err(AdmissionError::Expired)
    );
    assert_eq!(
        stale_lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(fs::read_dir(&stale_lab.root).unwrap().count(), 0);
}

#[test]
fn runtime_admission_cannot_promote_partial_capture_into_allowed_or_present_binding() {
    let lab = runtime_lab();
    let issued = lab.issue();
    let (bundle, payloads) = runtime_sample(&issued);
    for observed in [StateValue::Allowed, StateValue::Present] {
        let mut promoted = bundle.clone();
        promoted.claims[0].observed = observed;
        assert_eq!(promoted.validate_shape(), Err(EvidenceError::Invalid));
        assert_eq!(
            accept(&lab, &serde_json::to_vec(&promoted).unwrap(), &payloads),
            Err(AdmissionError::Invalid)
        );
    }
    let mut boolean_verdict = serde_json::to_value(&bundle).unwrap();
    boolean_verdict["claims"][0]["runtime_capture"]["binding_applied"] = serde_json::json!(true);
    assert_eq!(
        accept(
            &lab,
            &serde_json::to_vec(&boolean_verdict).unwrap(),
            &payloads
        ),
        Err(AdmissionError::Invalid)
    );
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);
}

// K11-C's positive path uses synthetic independent measurements. It exercises
// the typed verifier -> SQLite admission -> archive reload path end to end.
struct SyntheticNativeCutover(
    Option<veil_db_guard::core::runtime_cutover::NativeCutoverObservations>,
);
impl veil_db_guard::core::runtime_cutover::RuntimeCutoverVerifier for SyntheticNativeCutover {
    fn observe(
        &mut self,
        _: &veil_db_guard::core::runtime_cutover::RuntimeCutoverIntent,
    ) -> Result<
        veil_db_guard::core::runtime_cutover::NativeCutoverObservations,
        veil_db_guard::core::runtime_cutover::RuntimeCutoverError,
    > {
        self.0
            .take()
            .ok_or(veil_db_guard::core::runtime_cutover::RuntimeCutoverError::Unavailable)
    }
}

struct SyntheticCutoverAdmissionVerifier(
    Option<veil_db_guard::core::runtime_cutover::CorroboratedRuntimeCutover>,
);
impl ObservationVerifier for SyntheticCutoverAdmissionVerifier {
    fn verify(
        &mut self,
        _: &IssuedObservation,
        bundle: &ObservationBundleWire,
        _: &[EvidencePayload],
        _: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        let refs = bundle.claims[0].evidence_refs.clone();
        let verified = Assurance::Verified {
            evidence_refs: refs.clone(),
        };
        Ok(VerifierFindings {
            recipe_id: "k11-runtime-cutover-v1".into(),
            source_evidence_refs: refs,
            assurances: vec![ClaimAssurance {
                claim_id: bundle.claims[0].id.clone(),
                coverage: AssuranceCoverage {
                    target: verified.clone(),
                    principal: verified.clone(),
                    source: verified.clone(),
                    route: verified.clone(),
                    transport: verified.clone(),
                    temporal: verified.clone(),
                    completeness: verified,
                },
            }],
        })
    }

    fn runtime_cutover(
        &self,
        case_id: &str,
    ) -> Option<&veil_db_guard::core::runtime_cutover::CorroboratedRuntimeCutover> {
        self.0
            .as_ref()
            .filter(|proof| proof.candidate().context.case_id == case_id)
    }
}

#[test]
fn runtime_admission_positive_requires_typed_cutover_and_all_three_artifacts() {
    use veil_db_guard::core::{runtime_binding::RuntimeProcessSelector, runtime_cutover::*};
    let mut lab = Lab::with_gce_host(Some(GceHostProfile {
        ssh_ip: "10.0.0.1".parse().unwrap(),
        ssh_port: 22,
        host_key_ed25519_base64: "dGVzdA==".into(),
        collector_binary_digest: "d".repeat(64),
        execution_uid: 0,
    }));
    lab.spec.cases[0].kind = FixedObservationCase::RuntimeBinding;
    lab.spec.cases[0].address.effect = EffectKindV2::RuntimeBinding;
    let issued = lab.issue();
    let case = &issued.request.cases[0];
    let (mut bundle, _) = runtime_sample(&issued);
    let claim = &mut bundle.claims[0];
    claim.runtime_capture = None;
    claim.connection = None;
    claim.observed = StateValue::Present;
    let payloads: Vec<_> = ["kernel-peer", "postgres-session", "pool-checkout"]
        .into_iter()
        .map(|id| EvidencePayload {
            id: id.into(),
            bytes: format!("synthetic-{id}").into_bytes(),
        })
        .collect();
    bundle.artifacts = payloads
        .iter()
        .map(|p| ArtifactRef {
            id: p.id.clone(),
            sha256: veil_db_guard::config::hash_bytes(&p.bytes),
        })
        .collect();
    claim.evidence_refs = bundle.artifacts.iter().map(|a| a.id.clone()).collect();

    let unix_endpoint = |pid, socket_inode, socket_cookie| UnixProcessEndpoint {
        process: RuntimeProcessIdentity {
            pid,
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            start_ticks: 820,
            executable_digest: "5".repeat(64),
        },
        effective_uid: 1000,
        socket_fd: 7,
        socket_inode,
        socket_cookie,
    };
    let application = unix_endpoint(51, 813, 1);
    let connector = unix_endpoint(52, 814, 2);
    let selector = |p: &RuntimeProcessIdentity| RuntimeProcessSelector {
        pid: p.pid,
        expected_boot_id: p.boot_id.clone(),
        expected_start_ticks: p.start_ticks,
        expected_executable_digest: p.executable_digest.clone(),
    };
    let selection = RuntimeCutoverSelection {
        bundle_digest: "a".repeat(64),
        previous_generation: 1,
        active_generation: 2,
        application: selector(&application.process),
        connector: selector(&connector.process),
        cloud_iam_principal: lab.snapshot.native_identity.service_account.clone(),
        credential_binding_digest: "b".repeat(64),
    };
    let intent = RuntimeCutoverIntent::for_case(&issued, case, selection.clone(), 109).unwrap();
    let session = PostgresSessionIdentity {
        database: case.address.target.engine_binding.database.clone(),
        session_user: case.address.db_identity.clone(),
        backend_pid: 42,
        backend_started_at_micros: 111_500_000,
    };
    let switch = PoolSwitchLink {
        previous_generation: 1,
        active_generation: 2,
        checkout_sequence: 1,
        switched_at: 111,
        checked_out_at: 112,
    };
    let candidate = RuntimeCutoverCandidate {
        context: intent.context().clone(),
        bundle_digest: selection.bundle_digest.clone(),
        app: AppSessionLink {
            process: application.process.clone(),
            socket_fd: application.socket_fd,
            socket_inode: application.socket_inode,
            session: session.clone(),
        },
        switch: switch.clone(),
    };
    let native = NativeCutoverObservations {
        context: candidate.context.clone(),
        kernel_observed_at: 113,
        postgres_observed_at: 114,
        pool_observed_at: 114,
        valid_until: 125,
        kernel: NativeUnixPeerObservation {
            application: application.clone(),
            connector: connector.clone(),
        },
        postgres: NativePostgresSessionObservation {
            connector,
            session,
            current_user: case.address.db_identity.clone(),
            tls_peer_native_id: case.address.target.native_ref.native_id.clone(),
            tls_peer_target_generation: case
                .address
                .target
                .native_ref
                .generation_fingerprint
                .clone()
                .unwrap(),
            tls_peer_certificate_digest: "9".repeat(64),
            native_iam_principal: selection.cloud_iam_principal,
            credential_binding_digest: selection.credential_binding_digest,
        },
        pool: NativePoolUseObservation {
            application,
            bundle_digest: selection.bundle_digest,
            switch,
        },
        evidence_refs: RuntimeCutoverEvidenceRefs {
            kernel_peer: bundle.artifacts[0].sha256.clone(),
            postgres_session: bundle.artifacts[1].sha256.clone(),
            pool_checkout: bundle.artifacts[2].sha256.clone(),
        },
    };
    let admit = |verifier: &mut SyntheticCutoverAdmissionVerifier| {
        accept_evidence(
            &mut lab.ledger(),
            &mut lab.archive(),
            verifier,
            "capture-1",
            &serde_json::to_vec(&bundle).unwrap(),
            &payloads,
            window(),
            &Clock(116),
        )
    };
    assert_eq!(
        admit(&mut SyntheticCutoverAdmissionVerifier(None)),
        Err(AdmissionError::VerifierUnavailable)
    );
    let mut foreign_artifact = native.clone();
    foreign_artifact.evidence_refs.postgres_session = "f".repeat(64);
    let proof = |observation| {
        verify_runtime_cutover(
            &intent,
            &candidate,
            &mut SyntheticNativeCutover(Some(observation)),
            116,
        )
        .unwrap()
    };
    assert_eq!(
        admit(&mut SyntheticCutoverAdmissionVerifier(Some(proof(
            foreign_artifact
        )))),
        Err(AdmissionError::Integrity)
    );
    assert_eq!(
        lab.ledger().admission("capture-1"),
        Err(AdmissionError::NotFound)
    );
    assert_eq!(fs::read_dir(&lab.root).unwrap().count(), 0);

    let receipt = admit(&mut SyntheticCutoverAdmissionVerifier(Some(proof(native)))).unwrap();
    assert_eq!(receipt.valid_until, 125);
    let facts = load(&lab, 124).unwrap();
    assert_eq!(facts.admission(), &receipt);
    assert_eq!(facts.claims()[0].observed, StateValue::Present);
    assert!(matches!(load(&lab, 125), Err(AdmissionError::Expired)));
}
