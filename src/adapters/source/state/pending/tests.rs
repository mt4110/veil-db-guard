//! Local SQLite/archive and synthetic verifier tests. No cloud/DB calls.
use super::*;
use crate::adapters::source::state::{SourceStateReport, read_local};
use crate::{
    adapters::{capabilities_for_policy, evidence::RunEvidenceArchive},
    core::{
        approval,
        change::{OperationLimits, prepare_change},
        plan::build_plan,
        ports::{EvidenceClock, ObservationVerifier},
        state::{ArtifactRef, StateAssessment, StateLayer},
    },
    evidence_store::{EvidenceStore, ObservationRequestSpec},
};

struct Clock(u64);
impl EvidenceClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}
struct Verifier;
impl ObservationVerifier for Verifier {
    fn verify(
        &mut self,
        _: &IssuedObservation,
        b: &ObservationBundleWire,
        _: &[EvidencePayload],
        _: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        let yes = || Assurance::Verified {
            evidence_refs: vec!["proof".into()],
        };
        Ok(VerifierFindings {
            // This verifier is test-only. The production native recipe can
            // only come from the sealed GCE source capture/verifier path.
            recipe_id: "gce-host-network-root-v1".into(),
            source_evidence_refs: vec!["proof".into()],
            assurances: b
                .claims
                .iter()
                .map(|c| ClaimAssurance {
                    claim_id: c.id.clone(),
                    coverage: AssuranceCoverage {
                        target: yes(),
                        principal: yes(),
                        source: yes(),
                        route: yes(),
                        transport: yes(),
                        temporal: yes(),
                        completeness: yes(),
                    },
                })
                .collect(),
        })
    }
}
struct Lab {
    _temp: tempfile::TempDir,
    path: std::path::PathBuf,
    archive: RunEvidenceArchive,
    current: PreparedChange,
    case: RequestedCase,
}
fn begin(store: &mut OperationStore, c: &PreparedChange, id: &str, head: Option<String>, at: u64) {
    let a = approval::issue(
        c,
        &format!("approval-{id}"),
        "operator",
        "runner",
        300,
        900,
        at,
    )
    .unwrap();
    store.register_change(c).unwrap();
    store.register_approval(c, &a).unwrap();
    store
        .begin(&BeginRequest {
            request_id: format!("begin-{id}"),
            operation_id: id.into(),
            change_hash: c.change_hash.clone(),
            approval_id: a.id,
            expected_desired_head: head,
            execution_identity: "runner".into(),
            now: at,
        })
        .unwrap();
}
fn receipt(c: &PreparedChange, step: &crate::core::plan::PlanStep, valid: bool) -> StepReceipt {
    let native_ref = format!(
        "gcp-readback-{}",
        crate::config::hash_bytes(
            &serde_json::to_vec(&(&c.change_hash, &step.id, &step.parameters_hash)).unwrap()
        )
    );
    let proof = crate::config::hash_bytes(
        &serde_json::to_vec(&(
            "native-postcondition-v1",
            &c.change_hash,
            &step.id,
            &native_ref,
        ))
        .unwrap(),
    );
    StepReceipt {
        state: StepState::EffectSatisfied,
        effect: EffectState::Enforced,
        native_operation_ref: Some(native_ref),
        evidence_refs: if valid { vec![proof] } else { vec![] },
    }
}
impl Lab {
    fn new(valid_receipt: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.sqlite");
        let archive_path = temp.path().join("archives");
        std::fs::create_dir(&archive_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let archive = RunEvidenceArchive::open(&archive_path).unwrap();
        let (fixture, _) = crate::adapters::source::testsupport::fixture();
        let mut p =
            parse_policy(include_str!("../../../../../examples/core-policy-v2.yaml")).unwrap();
        p.targets[0].resource = fixture.request.cases[0].address.target.native_ref.clone();
        p.subjects
            .iter_mut()
            .find(|s| s.id == "billing-app")
            .unwrap()
            .identity
            .immutable_id = Some(
            fixture
                .snapshot
                .gce()
                .unwrap()
                .native_identity
                .service_account_id
                .clone(),
        );
        *p.source_bindings
            .iter_mut()
            .find(|s| s.source_id == "billing-runtime")
            .unwrap() = fixture.request.source.clone();
        let plan = build_plan(&p, capabilities_for_policy(&p).unwrap(), vec![], 100).unwrap();
        let source = prepare_change(&p, &plan, &[], None, OperationLimits::default()).unwrap();
        let current = crate::core::lifecycle::prepare_maintenance(
            &source,
            "before-operation",
            LifecycleKind::Revoke,
            "billing-access",
            &[],
            capabilities_for_policy(&p).unwrap(),
            115,
            source.limits.clone(),
            false,
        )
        .unwrap();
        let mut store = OperationStore::open(&path).unwrap();
        begin(&mut store, &source, "before-operation", None, 100);
        let lease = store
            .acquire_leases("before-operation", "worker", 100, 100)
            .unwrap();
        for step in &source.plan.steps {
            let o = store.get("before-operation").unwrap();
            let ticket = store
                .dispatch(&o.id, &step.id, o.version, &lease, "runner", 100)
                .unwrap();
            store
                .record_receipt(&ticket, &receipt(&source, step, true), 100)
                .unwrap();
        }
        let old = store.get("before-operation").unwrap();
        store
            .set_state(&old.id, old.version, ExecutionState::Completed, 100)
            .unwrap();
        store.release_leases(&lease).unwrap();
        begin(
            &mut store,
            &current,
            "current-operation",
            Some(source.plan.policy_revision_hash.clone()),
            115,
        );
        let lease = store
            .acquire_leases("current-operation", "worker", 120, 100)
            .unwrap();
        let step = current
            .plan
            .steps
            .iter()
            .find(|s| s.action == ActionKind::DisableNativeIdentity)
            .unwrap();
        let op = store.get("current-operation").unwrap();
        let ticket = store
            .dispatch(&op.id, &step.id, op.version, &lease, "runner", 120)
            .unwrap();
        store
            .record_receipt(&ticket, &receipt(&current, step, valid_receipt), 121)
            .unwrap();
        store.release_leases(&lease).unwrap();
        let mut ledger = EvidenceStore::open(&path).unwrap();
        ledger.register_source(&fixture.snapshot, None).unwrap();
        let mut case = fixture.request.cases[0].clone();
        case.id = "connection".into();
        case.kind = FixedObservationCase::NewConnection;
        case.address.route.kind = RouteKind::NativeConnector;
        case.address.route.id = "app-connector".into();
        Self {
            _temp: temp,
            path,
            archive,
            current,
            case,
        }
    }
    fn sample(
        &self,
        id: &str,
        operation: &str,
        issued_at: u64,
        started_at: u64,
        permissions: &[&str],
        complete: bool,
    ) {
        self.sample_inner(
            id,
            operation,
            issued_at,
            started_at,
            Some((permissions, complete)),
        );
    }
    fn sample_inner(
        &self,
        id: &str,
        operation: &str,
        issued_at: u64,
        started_at: u64,
        inventory: Option<(&[&str], bool)>,
    ) {
        let (permissions, complete) = inventory.unwrap_or((&[], false));
        let mut ledger = EvidenceStore::open_existing(&self.path).unwrap();
        let i = ledger
            .issue_request(
                &ObservationRequestSpec {
                    request_id: id.into(),
                    operation_id: operation.into(),
                    source_id: "billing-runtime".into(),
                    ttl_seconds: 120,
                    cases: vec![self.case.clone()],
                },
                issued_at,
            )
            .unwrap();
        let payload = EvidencePayload {
            id: "proof".into(),
            bytes: b"synthetic permission evidence".to_vec(),
        };
        let claim = |at: u64, inventory| ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: format!(
                "{}-{}",
                if inventory { "iam" } else { "source" },
                self.case.id
            ),
            case_id: self.case.id.clone(),
            policy_revision_hash: i.request.policy_revision_hash.clone(),
            address: self.case.address.clone(),
            started_at: at,
            finished_at: at + if inventory { 1 } else { 4 },
            observed: if inventory {
                StateValue::Unknown
            } else {
                StateValue::Allowed
            },
            layer: if inventory {
                StateLayer::ConnectionAuthorization
            } else {
                StateLayer::Authentication
            },
            denial_cause: None,
            connection: None,
            controls: vec![],
            transport: vec![],
            sql_context: None,
            evidence_refs: vec!["proof".into()],
            permission_inventory: if inventory {
                Some(NativePermissionInventory {
                    complete,
                    permissions: permissions
                        .iter()
                        .map(|s| format!("cloudsql.instances.{s}"))
                        .collect(),
                })
            } else {
                None
            },
        };
        let b = ObservationBundleWire {
            schema_version: 1,
            request_digest: i.request.digest().unwrap(),
            collector_build_id: i.request.collector_build_id.clone(),
            started_at,
            finished_at: started_at + 4,
            capture_complete: false,
            claims: if inventory.is_some() {
                vec![claim(started_at + 2, true), claim(started_at, false)]
            } else {
                vec![claim(started_at, false)]
            },
            artifacts: vec![ArtifactRef {
                id: "proof".into(),
                sha256: crate::config::hash_bytes(&payload.bytes),
            }],
        };
        accept_evidence(
            &mut ledger,
            &mut RunEvidenceArchive::open(&self._temp.path().join("archives")).unwrap(),
            &mut Verifier,
            id,
            &serde_json::to_vec(&b).unwrap(),
            &[payload],
            CaptureWindow {
                sent_at: started_at,
                received_at: started_at + 4,
                elapsed_millis: 4000,
            },
            &Clock(started_at + 4),
        )
        .unwrap();
    }
    fn report(&self, now: u64) -> SourceStateReport {
        let mut ledger = EvidenceStore::open_existing(&self.path).unwrap();
        read_local(
            &mut ledger,
            &self.archive,
            &self.current,
            "current-operation",
            &[],
            now,
        )
        .unwrap()
    }
    fn later_allowed(&self) {
        self.sample(
            "after-later-allowed",
            "current-operation",
            128,
            128,
            &["get"],
            true,
        );
    }
    fn connection<'a>(&self, r: &'a SourceStateReport) -> &'a crate::core::state_v2::StateRowV2 {
        r.effective
            .rows
            .iter()
            .find(|r| r.desired.address == self.case.address)
            .unwrap()
    }
}

#[test]
fn native_pending_uses_only_approved_lineage_receipt_and_isolated_before_pool() {
    let lab = Lab::new(true);
    lab.sample(
        "before-capture",
        "before-operation",
        100,
        110,
        &["connect", "get", "login"],
        true,
    );
    lab.sample(
        "after-capture",
        "current-operation",
        122,
        123,
        &["get"],
        true,
    );
    let one = lab.report(130);
    assert_eq!(
        lab.connection(&one).assessment,
        StateAssessment::NeedsAction
    );
    lab.later_allowed();
    let report = lab.report(135);
    let row = lab.connection(&report);
    assert_eq!(row.assessment, StateAssessment::Pending);
    assert_eq!(row.propagation_deadline, Some(300));
    assert_eq!(row.observed, StateValue::Allowed);
    assert!(
        row.history
            .iter()
            .all(|h| h.claim.policy_revision_hash == lab.current.plan.policy_revision_hash)
    );
    assert!(
        report
            .admission_reads
            .iter()
            .all(|r| r.request_id.starts_with("after-"))
    );
    assert!(!report.effective.all_required_effects_satisfied);
    assert!(!report.native_queries_performed);
}

#[test]
fn current_allowed_survives_missing_incomplete_unchanged_and_failed_removal_proofs() {
    for scenario in 0..5 {
        let lab = Lab::new(scenario != 4);
        if scenario != 0 {
            lab.sample(
                "before-capture",
                "before-operation",
                100,
                110,
                &["connect", "get", "login"],
                scenario != 1,
            );
        }
        lab.sample(
            "after-capture",
            "current-operation",
            122,
            123,
            if scenario == 2 {
                &["connect", "get", "login"]
            } else {
                &["get"]
            },
            scenario != 3,
        );
        lab.later_allowed();
        let report = lab.report(135);
        let row = lab.connection(&report);
        assert_eq!(row.assessment, StateAssessment::NeedsAction, "{scenario}");
        assert_eq!(row.observed, StateValue::Allowed);
        assert!(row.propagation_deadline.is_none());
    }
}

#[test]
fn prior_facts_expiry_epoch_rotation_and_cancelled_approval_never_grant_pending() {
    for scenario in 0..3 {
        let lab = Lab::new(true);
        lab.sample(
            "before-capture",
            "before-operation",
            100,
            110,
            &["connect", "get", "login"],
            true,
        );
        lab.sample(
            "after-capture",
            "current-operation",
            122,
            123,
            &["get"],
            true,
        );
        lab.later_allowed();
        let now = if scenario == 0 { 175 } else { 135 };
        if scenario == 1 {
            let mut ledger = EvidenceStore::open_existing(&lab.path).unwrap();
            let old = ledger
                .source_snapshot("billing-source-registration")
                .unwrap();
            let mut new = old.clone();
            new.gce_mut().unwrap().trust_epoch += 1;
            ledger
                .register_source(&new, Some(&old.revision_digest().unwrap()))
                .unwrap();
        }
        if scenario == 2 {
            OperationStore::open_existing(&lab.path)
                .unwrap()
                .cancel_approval("approval-current-operation", 129)
                .unwrap();
        }
        let report = lab.report(now);
        assert_ne!(
            lab.connection(&report).assessment,
            StateAssessment::Pending,
            "{scenario}"
        );
    }
}

#[test]
fn failed_cancelled_overlapping_and_foreign_context_proofs_are_not_pending() {
    for scenario in 0..5 {
        let lab = Lab::new(true);
        if scenario == 4 {
            let lineage = lab.current.lifecycle.as_ref().unwrap();
            let source = OperationStore::open_existing(&lab.path)
                .unwrap()
                .load_change(&lineage.source_change_hash)
                .unwrap();
            EvidenceStore::open_existing(&lab.path)
                .unwrap()
                .start_session(&source, "unrelated-before", 100)
                .unwrap();
            lab.sample(
                "before-capture",
                "unrelated-before",
                100,
                110,
                &["connect", "get", "login"],
                true,
            );
        } else {
            lab.sample(
                "before-capture",
                "before-operation",
                100,
                if scenario == 2 { 119 } else { 110 },
                &["connect", "get", "login"],
                true,
            );
        }
        lab.sample(
            "after-capture",
            "current-operation",
            if scenario == 3 { 119 } else { 122 },
            if scenario == 3 { 120 } else { 123 },
            &["get"],
            true,
        );
        lab.later_allowed();
        if scenario < 2 {
            let mut store = OperationStore::open_existing(&lab.path).unwrap();
            let op = store.get("current-operation").unwrap();
            store
                .set_state(
                    &op.id,
                    op.version,
                    if scenario == 0 {
                        ExecutionState::FailedPartial
                    } else {
                        ExecutionState::Cancelled
                    },
                    129,
                )
                .unwrap();
        }
        let report = lab.report(135);
        assert_eq!(lab.connection(&report).observed, StateValue::Allowed);
        assert_eq!(
            lab.connection(&report).assessment,
            StateAssessment::NeedsAction,
            "{scenario}"
        );
    }
}

#[test]
fn newest_incomplete_inventory_does_not_fall_back_to_earlier_complete_inventory() {
    for before in [true, false] {
        let lab = Lab::new(true);
        lab.sample(
            "before-capture",
            "before-operation",
            100,
            106,
            &["connect", "get", "login"],
            true,
        );
        if before {
            lab.sample(
                "before-incomplete",
                "before-operation",
                110,
                114,
                &["connect", "get", "login"],
                false,
            );
        }
        lab.sample(
            "after-capture",
            "current-operation",
            122,
            123,
            &["get"],
            true,
        );
        lab.later_allowed();
        if !before {
            lab.sample(
                "after-incomplete",
                "current-operation",
                133,
                133,
                &["get"],
                false,
            );
        }
        let report = lab.report(140);
        assert_eq!(lab.connection(&report).observed, StateValue::Allowed);
        assert_eq!(
            lab.connection(&report).assessment,
            StateAssessment::NeedsAction
        );
    }
}

#[test]
fn latest_allowed_with_failed_iam_capture_cannot_reuse_old_complete_inventory() {
    let lab = Lab::new(true);
    lab.sample(
        "before-capture",
        "before-operation",
        100,
        110,
        &["connect", "get", "login"],
        true,
    );
    lab.sample(
        "after-capture",
        "current-operation",
        122,
        123,
        &["get"],
        true,
    );
    lab.later_allowed();
    assert_eq!(
        lab.connection(&lab.report(135)).assessment,
        StateAssessment::Pending
    );
    // Same shape as collector API failure: actual PG Allowed survives, but the
    // optional IAM diagnostic/auxiliary claim is completely absent.
    lab.sample_inner("after-iam-failure", "current-operation", 134, 134, None);
    let report = lab.report(140);
    assert_eq!(lab.connection(&report).observed, StateValue::Allowed);
    assert_eq!(
        lab.connection(&report).assessment,
        StateAssessment::NeedsAction
    );
    assert!(lab.connection(&report).propagation_deadline.is_none());
}
