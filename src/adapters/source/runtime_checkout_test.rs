//! Linux acceptance test with separate UID workers and a local mock upstream.
use super::{
    gce_host::*,
    runtime::{NativeProcReader, ProcReader, start_ticks},
    runtime_unix::{RuntimeUnixProcessSelection, RuntimeUnixSelection, collect},
    runtime_witness::RuntimeWitnessPolicy,
};
use crate::{
    adapters::{capabilities_for_policy, evidence::RunEvidenceArchive},
    binding::runtime::ConnectionBundle,
    core::{
        admission::*,
        change::{OperationLimits, PreparedChange, prepare_change},
        evidence::*,
        plan::build_plan,
        policy::*,
        ports::EvidenceArchive,
        runtime_binding::RuntimeProcessSelector,
        source::SourcePurpose,
        state::StateValue,
        state_v2::desired_for_change_v2,
    },
    evidence_store::{EvidenceStore, ObservationRequestSpec},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{PermissionsExt, chown},
        process::CommandExt,
    },
    path::Path,
    process::{Child, ChildStdout, Command, Stdio},
};
use tokio_util::sync::CancellationToken;

const CONNECTOR_UID: u32 = 61001;
const APP_UID: u32 = 61002;
const GID: u32 = 61000;

struct Worker {
    child: Child,
    output: BufReader<ChildStdout>,
    marker: &'static str,
}

impl Worker {
    fn spawn(test: &str, gate: &str, marker: &'static str, uid: u32, dir: &Path) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(gate, "1")
            .env("VDG_K11_TEST_DIR", dir)
            .uid(uid)
            .gid(GID)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            output,
            marker,
        }
    }

    fn next(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                self.output.read_line(&mut line).unwrap(),
                0,
                "worker {} ended before its next message",
                self.marker
            );
            if let Some((_, message)) = line.split_once(self.marker) {
                return serde_json::from_str(message).unwrap();
            }
        }
    }

    fn send(&mut self, value: Value) {
        let input = self.child.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &value).unwrap();
        writeln!(input).unwrap();
        input.flush().unwrap();
    }

    fn selector(&mut self, uid: u32) -> RuntimeUnixProcessSelection {
        let fd = u32::try_from(self.next()["fd"].as_u64().unwrap()).unwrap();
        let pid = self.child.id();
        let proc = NativeProcReader::new(pid).unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        RuntimeUnixProcessSelection {
            selector: RuntimeProcessSelector {
                pid,
                expected_boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .unwrap()
                    .trim()
                    .to_owned(),
                expected_start_ticks: start_ticks(&stat, pid).unwrap(),
                expected_executable_digest: proc
                    .executable_digest(&CancellationToken::new())
                    .unwrap(),
            },
            fd,
            expected_uid: uid,
        }
    }

    fn finish(&mut self) {
        drop(self.child.stdin.take());
        assert!(
            self.child.wait().unwrap().success(),
            "worker {} failed",
            self.marker
        );
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn prepare(policy: &PolicyRevision, now: u64) -> PreparedChange {
    let plan = build_plan(
        policy,
        capabilities_for_policy(policy).unwrap(),
        vec![],
        now,
    )
    .unwrap();
    prepare_change(policy, &plan, &[], None, OperationLimits::default()).unwrap()
}

#[test]
#[ignore = "explicit Linux same-checkout acceptance: root, unix_diag, and cross-UID procfs"]
fn same_checkout_real_witnesses_admit_and_reload() {
    let cancel = CancellationToken::new();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    let sockets = dir.path().join("sockets");
    std::fs::create_dir(&sockets).unwrap();
    chown(&sockets, Some(CONNECTOR_UID), Some(GID)).unwrap();
    std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o750)).unwrap();
    let mut connector = Worker::spawn(
        "binding::gcp_connector_witness::unix::tests::linux_connector_witness_worker",
        "VDG_K11_CONNECTOR_WORKER",
        "VDG_K11_CONNECTOR ",
        CONNECTOR_UID,
        &sockets,
    );
    let connector_endpoint = connector.selector(CONNECTOR_UID);
    let mut app = Worker::spawn(
        "binding::runtime::tests::linux_app_checkout_worker",
        "VDG_K11_APP_WORKER",
        "VDG_K11_APP ",
        APP_UID,
        &sockets,
    );
    let app_endpoint = app.selector(APP_UID);
    let selection = RuntimeUnixSelection {
        app: app_endpoint,
        connector: connector_endpoint,
        socket_path: sockets
            .join("active/.s.PGSQL.5432")
            .to_str()
            .unwrap()
            .into(),
        path_uid: CONNECTOR_UID,
        path_gid: GID,
        path_mode: 0o660,
    };
    let (fixture, mut config) = super::testsupport::fixture();
    let mut snapshot = fixture.snapshot.gce().unwrap().clone();
    let mut policy = parse_policy(include_str!("../../../examples/core-policy-v2.yaml")).unwrap();
    policy.targets[0].resource.generation_fingerprint =
        Some(config.endpoints[0].generation_digest.clone());
    let grant = policy.grants[0].id.clone();
    let subject = policy.grants[0].subject.clone();
    policy
        .subjects
        .iter_mut()
        .find(|s| s.id == subject)
        .unwrap()
        .identity
        .immutable_id = Some(snapshot.native_identity.service_account_id.clone());
    let source = fixture.request.source.source_id;
    let route = "app-connector";
    let now = crate::domain::now();
    let provisional = prepare(&policy, now);
    let scope = ConnectionBundle::prepare(&provisional, &grant, &source, route, 2)
        .unwrap()
        .witness_scope_digest();
    let random = SystemRandom::new();
    let key = || {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        (
            STANDARD.encode(pair.public_key().as_ref()),
            STANDARD.encode(pkcs8.as_ref()),
        )
    };
    let (connector_key, connector_pkcs8_base64) = key();
    let (pool_key, pool_pkcs8_base64) = key();
    let witnesses = RuntimeWitnessPolicy {
        connector_key,
        pool_key,
        bundle_digest: scope.clone(),
        previous_generation: 1,
        active_generation: 2,
        credential_binding_digest: "2".repeat(64),
        not_before: now - 1,
    };
    config.runtime_unix.push(RuntimeUnixBinding {
        target_id: policy.targets[0].id.clone(),
        grant_id: grant.clone(),
        subject_id: subject.clone(),
        route_id: route.into(),
        selection: selection.clone(),
        witnesses: Some(witnesses.clone()),
    });
    let config_bytes = serde_json::to_vec(&config).unwrap();
    snapshot.collector_config_digest = crate::config::hash_bytes(&config_bytes);
    policy
        .source_bindings
        .iter_mut()
        .find(|s| s.source_id == source)
        .unwrap()
        .revision_digest = snapshot.revision_digest().unwrap();
    let change = prepare(&policy, now);
    assert_eq!(
        ConnectionBundle::prepare(&change, &grant, &source, route, 2)
            .unwrap()
            .witness_scope_digest(),
        scope
    );
    let address = desired_for_change_v2(&policy, None, &[], now)
        .unwrap()
        .into_iter()
        .find(|row| {
            row.address.effect == EffectKindV2::RuntimeBinding
                && row.address.subject_id == subject
                && row.address.route.id == route
        })
        .unwrap()
        .address;
    let case = RequestedCase {
        backend_tls_trust: None,
        login_catalog_targets: vec![],
        mysql_account_host: None,
        id: "runtime-checkout".into(),
        kind: FixedObservationCase::RuntimeBinding,
        address,
        purpose: SourcePurpose::Application,
        endpoint: config.endpoints[0].endpoint.clone(),
        port: 5432,
        address_family: AddressFamily::Ipv4,
    };
    let ledger_path = dir.path().join("ledger.sqlite");
    let mut ledger = EvidenceStore::open(&ledger_path).unwrap();
    ledger.register_source(&snapshot, None).unwrap();
    let issued_at = crate::domain::now();
    ledger
        .start_session(&change, "local-checkout", issued_at)
        .unwrap();
    let issued = ledger
        .issue_request(
            &ObservationRequestSpec {
                request_id: "local-checkout-request".into(),
                operation_id: "local-checkout".into(),
                source_id: source.clone(),
                ttl_seconds: 120,
                cases: vec![case.clone()],
            },
            issued_at,
        )
        .unwrap();

    connector.send(json!({
        "issued": issued, "case_id": case.id, "selection": selection,
        "policy": witnesses, "connector_pkcs8_base64": connector_pkcs8_base64,
    }));
    app.send(json!({
        "change": change, "grant_id": grant, "source_id": source, "route_id": route,
        "previous_generation": 1, "active_generation": 2,
        "old_directory": sockets.join("old"), "socket_directory": sockets.join("active"),
        "connector_uid": CONNECTOR_UID, "connector_gid": GID,
    }));
    app.send(json!({
        "issued": issued, "case_id": case.id, "not_before": witnesses.not_before,
        "policy": witnesses, "pool_pkcs8_base64": pool_pkcs8_base64,
        "application": selection.app.selector, "connector": selection.connector.selector,
    }));
    let pool = app.next();
    let trigger = connector.child.stdin.as_mut().unwrap();
    writeln!(trigger).unwrap();
    trigger.flush().unwrap();
    let connector_proof = connector.next();
    let sent_at = crate::domain::now();
    let started = std::time::Instant::now();
    let kernel = collect(&selection, &cancel).unwrap();
    let now = crate::domain::now();
    let window = CaptureWindow {
        sent_at,
        received_at: now,
        elapsed_millis: started.elapsed().as_millis().try_into().unwrap(),
    };
    let input = serde_json::to_vec(&json!({
        "candidate": pool["candidate"], "pool": pool["pool"],
        "connector": connector_proof["connector"],
    }))
    .unwrap();
    let capture =
        test_corroborate_runtime_capture(&issued, &config_bytes, &kernel, &input, window, now)
            .unwrap();
    let archive_path = dir.path().join("archive");
    std::fs::create_dir(&archive_path).unwrap();
    std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut archive = RunEvidenceArchive::open(&archive_path).unwrap();
    let id = &issued.request.request_id;
    let receipt = admit_gce_capture(&mut ledger, &mut archive, id, capture).unwrap();
    drop(ledger);
    let mut ledger = EvidenceStore::open_existing(&ledger_path).unwrap();
    let evaluated_at = crate::domain::now();
    let facts = load_admitted(&mut ledger, &archive, id, evaluated_at).unwrap();
    assert_eq!(facts.claims().len(), 1);
    assert_eq!(facts.claims()[0].observed, StateValue::Present);
    let (_, payloads) = archive.read(&issued, &receipt.archive).unwrap();
    assert_eq!(payloads.len(), 3);
    assert_close_gate(&change, &facts, evaluated_at, receipt.valid_until);
    // Cancel the test connector while the checkout is still held. Dropping
    // the app first can race the relay shutdown with a TLS EOF.
    connector.finish();
    app.finish();
}

fn assert_close_gate(
    change: &PreparedChange,
    runtime: &VerifiedObservationFacts,
    now: u64,
    expires_at: u64,
) {
    use crate::core::{
        capability::ActionKind,
        source_execution::{SourceStepPhase, check_source_step, tests::facts_at},
    };
    let close = change
        .plan
        .steps
        .iter()
        .find(|step| step.action == ActionKind::ConstrainDirectPath)
        .unwrap();
    let check = |time, evidence| {
        check_source_step(
            change,
            close,
            SourceStepPhase::BeforeDispatch,
            time,
            evidence,
        )
        .unwrap()
        .satisfied()
    };
    // Connectivity, TLS effect rows and recovery are separately scoped test
    // facts; the binding itself is always the reloaded SQLite admission.
    let controls = facts_at(change, false, false, now);
    assert!(!check(now, controls.clone()));
    let mut without_recovery = controls
        .iter()
        .filter(|facts| {
            facts
                .claims()
                .iter()
                .all(|claim| claim.address.subject_id == "billing-app")
        })
        .cloned()
        .collect::<Vec<_>>();
    without_recovery.push(runtime.clone());
    assert!(!check(now, without_recovery));
    let mut complete = controls;
    complete.push(runtime.clone());
    assert!(check(now, complete));
    let mut expired = facts_at(change, false, false, expires_at);
    expired.push(runtime.clone());
    assert!(!check(expires_at, expired));
}
