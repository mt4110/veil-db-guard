//! Local CLI + synthetic admitted records only. No source SSH/cloud/DB calls.
use base64::Engine;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use veil_db_guard::{
    adapters::{capabilities_for_policy, evidence::RunEvidenceArchive, source::gce_host::*},
    core::{
        admission::*,
        change::{OperationLimits, PreparedChange, prepare_change},
        evidence::*,
        plan::build_plan,
        policy::*,
        ports::*,
        source::*,
        state::*,
    },
    evidence_store::{EvidenceStore, ObservationRequestSpec},
    store::{RunStatus, RunWriter},
};
fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_veil-db-guard"))
        .args(args)
        .env_clear()
        .env("PATH", root)
        .env("VDG_TOOL_MARKER", root.join("called"))
        .output()
        .unwrap()
}
fn json(out: Output, code: i32) -> serde_json::Value {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
fn traps(root: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in [
            "aws",
            "gcloud",
            "ssh",
            "curl",
            "psql",
            "mysql",
            "cloud-sql-proxy",
        ] {
            let f = root.join(name);
            fs::write(
                &f,
                "#!/bin/sh\nprintf called >> \"$VDG_TOOL_MARKER\"\nexit 99\n",
            )
            .unwrap();
            fs::set_permissions(f, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
struct Lab {
    _dir: tempfile::TempDir,
    root: PathBuf,
    ledger: PathBuf,
    plan: PathBuf,
    config: PathBuf,
    snapshot: SourceRegistrationSnapshot,
    change: PreparedChange,
    at: u64,
}
impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        traps(&root);
        let at = veil_db_guard::domain::now();
        let ledger = root.join("ledger.sqlite");
        let plan = root.join("plan");
        let config_path = root.join("collector.json");
        let context = LinuxHostContext {
            uid: 0,
            effective_uid: 0,
            network_namespace: "net:[1]".into(),
            mount_namespace: "mnt:[1]".into(),
            user_namespace: "user:[1]".into(),
            boot_id_digest: "a".repeat(64),
            cgroup_class: "0::/".into(),
            route_v4_digest: "b".repeat(64),
            route_v6_digest: "c".repeat(64),
            interfaces_digest: "d".repeat(64),
            rules_v4_digest: "e".repeat(64),
            rules_v6_digest: "f".repeat(64),
        };
        let config = CollectorConfig {
            route_denial: None,
            runtime: None,
            runtime_unix: vec![],
            kernel_origin: None,
            schema_version: 2,
            registration_id: "billing-source-registration".into(),
            context: context.clone(),
            postgres: Some(
                veil_db_guard::adapters::source::postgres::PostgresCollectorConfig {
                    proxy_sha256: "f".repeat(64),
                    collect_connect_denial_audit: false,
                    collect_iam_inventory: false,
                },
            ),
            endpoints: vec![CollectorEndpoint {
                target_id: "billing-db".into(),
                native_id: "projects/vdg-example-000000/instances/billing-postgres".into(),
                generation_digest: "d".repeat(64),
                database: "billing".into(),
                endpoint: "billing.internal".into(),
                ip: "10.0.0.1".parse().unwrap(),
                port: 5432,
            }],
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        fs::write(&config_path, &bytes).unwrap();
        let mut key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        key.extend([7; 32]);
        let snapshot = SourceRegistrationSnapshot {
            schema_version: 2,
            registration_id: config.registration_id.clone(),
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
            ssh_host_key_digest: veil_db_guard::config::hash_bytes(&key),
            collector_build_id: veil_db_guard::BUILD_ID.into(),
            collector_config_digest: veil_db_guard::config::hash_bytes(&bytes),
            network_context_digest: context.digest().unwrap(),
            execution_user: "root".into(),
            credential_kind: SourceCredentialKind::GceMetadata,
            credential_reference: "billing-workload".into(),
            gce_host: Some(GceHostProfile {
                ssh_ip: "192.0.2.1".parse().unwrap(),
                ssh_port: 22,
                host_key_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(key),
                collector_binary_digest: "f".repeat(64),
                execution_uid: 0,
            }),
        };
        let sp = root.join("source.json");
        fs::write(&sp, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let registered = json(
            cli(
                &root,
                &[
                    "guard",
                    "source-register",
                    "--ledger",
                    p(&ledger),
                    "--snapshot",
                    p(&sp),
                ],
            ),
            0,
        );
        assert_eq!(registered["source_verified"], false);
        let mut policy = parse_policy(include_str!("../examples/core-policy-v2.yaml")).unwrap();
        policy.targets[0].resource.generation_fingerprint = Some("d".repeat(64));
        policy.subjects[0].identity.immutable_id =
            Some(snapshot.native_identity.service_account_id.clone());
        policy.subjects[1].identity.immutable_id = Some("222222222222222222222".into());
        policy.source_bindings[0].revision_digest = snapshot.revision_digest().unwrap();
        let pl = build_plan(
            &policy,
            capabilities_for_policy(&policy).unwrap(),
            vec![],
            at - 30,
        )
        .unwrap();
        let change = prepare_change(&policy, &pl, &[], None, OperationLimits::default()).unwrap();
        let mut writer = RunWriter::create_for_config(
            &plan,
            &policy.policy_id,
            &policy,
            "guard-plan",
            8 * 1024 * 1024,
            true,
        )
        .unwrap();
        writer.write_json("plan.json", &pl).unwrap();
        writer.write_json("prepared-change.json", &change).unwrap();
        writer.finish(RunStatus::Complete).unwrap();
        Self {
            _dir: dir,
            root,
            ledger,
            plan,
            config: config_path,
            snapshot,
            change,
            at,
        }
    }
    fn start(&self, id: &str) {
        let j = json(
            cli(
                &self.root,
                &[
                    "guard",
                    "observation-start",
                    "--ledger",
                    p(&self.ledger),
                    "--plan-run",
                    p(&self.plan),
                    "--context",
                    id,
                ],
            ),
            0,
        );
        assert_eq!(j["context_kind"], "observation_only");
        assert_eq!(j["native_dispatch_available"], false);
        assert_eq!(j["desired_head_updated"], false);
    }
}
#[test]
fn readonly_cli_start_case_planning_state_and_status_do_not_create_forward_authority_or_call_tools()
{
    let lab = Lab::new();
    lab.start("observe-only");
    let out = lab.root.join("case-plan");
    let j = json(
        cli(
            &lab.root,
            &[
                "guard",
                "observe-plan",
                "--ledger",
                p(&lab.ledger),
                "--context",
                "observe-only",
                "--source",
                "billing-runtime",
                "--collector-config",
                p(&lab.config),
                "--out",
                p(&out),
            ],
        ),
        0,
    );
    assert_eq!(j["batches"], 1);
    assert_eq!(j["source_verified"], false);
    assert!(
        !j["uncollected_required_effects"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let cases: Vec<RequestedCase> =
        serde_json::from_slice(&fs::read(out.join("cases-1.json")).unwrap()).unwrap();
    assert_eq!(cases.len(), 8);
    assert!(
        cases
            .iter()
            .any(|c| c.kind == FixedObservationCase::DirectPath)
    );
    assert_eq!(
        cases
            .iter()
            .filter(|c| c.kind == FixedObservationCase::Transport)
            .count(),
        2
    );
    let j = json(
        cli(
            &lab.root,
            &[
                "guard",
                "state",
                "--ledger",
                p(&lab.ledger),
                "--operation",
                "observe-only",
            ],
        ),
        3,
    );
    assert_eq!(j["schema_version"], 2);
    assert_eq!(j["effective"]["protection_evaluated"], false);
    assert_eq!(j["effective"]["all_required_effects_satisfied"], false);
    let j = json(
        cli(
            &lab.root,
            &[
                "guard",
                "status",
                "--ledger",
                p(&lab.ledger),
                "--operation",
                "observe-only",
            ],
        ),
        0,
    );
    assert_eq!(j["context_kind"], "observation_only");
    assert_eq!(j["native_dispatch_available"], false);
    assert_eq!(j["native_queries_performed"], false);
    let ops = veil_db_guard::operation_store::OperationStore::open_existing(&lab.ledger).unwrap();
    assert!(ops.get("observe-only").is_err());
    assert_eq!(
        ops.desired_head(&lab.change.policy.policy_id).unwrap(),
        None
    );
    assert!(!lab.root.join("called").exists());
}
struct Clock(u64);
impl EvidenceClock for Clock {
    fn now(&self) -> u64 {
        self.0
    }
}
struct Synthetic;
impl ObservationVerifier for Synthetic {
    fn verify(
        &mut self,
        _: &IssuedObservation,
        b: &ObservationBundleWire,
        _: &[EvidencePayload],
        _: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        let yes = Assurance::Verified {
            evidence_refs: vec!["synthetic-proof".into()],
        };
        Ok(VerifierFindings {
            recipe_id: "synthetic-test-only".into(),
            source_evidence_refs: vec!["synthetic-proof".into()],
            assurances: b
                .claims
                .iter()
                .map(|c| ClaimAssurance {
                    claim_id: c.id.clone(),
                    coverage: AssuranceCoverage {
                        target: yes.clone(),
                        principal: yes.clone(),
                        source: yes.clone(),
                        route: yes.clone(),
                        transport: yes.clone(),
                        temporal: yes.clone(),
                        completeness: Assurance::Unconfirmed {
                            reason: EvidenceReason::IncompleteCapture,
                        },
                    },
                })
                .collect(),
        })
    }
}
fn admit(lab: &Lab) -> (IssuedObservation, EvidenceAdmission, PathBuf) {
    let mut ledger = EvidenceStore::open_existing(&lab.ledger).unwrap();
    ledger
        .start_session(&lab.change, "test-only-context", lab.at - 25)
        .unwrap();
    let desired =
        veil_db_guard::core::state_v2::desired_for_change_v2(&lab.change.policy, None, &[], lab.at)
            .unwrap();
    let address = desired
        .into_iter()
        .find(|d| {
            d.address.subject_id == "billing-app"
                && d.address.effect == EffectKindV2::NewConnections
                && d.address.route.kind == RouteKind::NativeConnector
        })
        .unwrap()
        .address;
    let issued = ledger
        .issue_request(
            &ObservationRequestSpec {
                request_id: "capture-1".into(),
                operation_id: "test-only-context".into(),
                source_id: "billing-runtime".into(),
                ttl_seconds: 120,
                cases: vec![RequestedCase {
                    backend_tls_trust: None,
                    login_catalog_targets: vec![],
                    mysql_account_host: None,
                    id: "connection".into(),
                    kind: FixedObservationCase::NewConnection,
                    address,
                    purpose: SourcePurpose::Application,
                    endpoint: "billing.internal".into(),
                    port: 5432,
                    address_family: AddressFamily::Ipv4,
                }],
            },
            lab.at - 20,
        )
        .unwrap();
    let payload = EvidencePayload {
        id: "synthetic-proof".into(),
        bytes: b"local synthetic fixture only".to_vec(),
    };
    let bundle = ObservationBundleWire {
        schema_version: 1,
        request_digest: issued.request.digest().unwrap(),
        collector_build_id: issued.request.collector_build_id.clone(),
        started_at: lab.at - 10,
        finished_at: lab.at - 9,
        capture_complete: false,
        claims: vec![ObservationClaim {
            runtime_capture: None,
            postgres_login_failure: None,
            login_catalog: vec![],
            id: "claim".into(),
            case_id: "connection".into(),
            policy_revision_hash: issued.request.policy_revision_hash.clone(),
            address: issued.request.cases[0].address.clone(),
            started_at: lab.at - 10,
            finished_at: lab.at - 9,
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
    let root = lab.root.join("archive");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut archive = RunEvidenceArchive::open(&root).unwrap();
    let receipt = accept_evidence(
        &mut ledger,
        &mut archive,
        &mut Synthetic,
        &issued.request.request_id,
        &serde_json::to_vec(&bundle).unwrap(),
        &[payload],
        CaptureWindow {
            sent_at: lab.at - 10,
            received_at: lab.at - 8,
            elapsed_millis: 2000,
        },
        &Clock(lab.at - 7),
    )
    .unwrap();
    (issued, receipt, root)
}
#[test]
fn accepted_capture_reuse_and_offline_cli_keep_original_times_and_partial_allowed_without_key_or_tools()
 {
    let lab = Lab::new();
    let (issued, receipt, archive) = admit(&lab);
    let cases = lab.root.join("cases.json");
    fs::write(&cases, serde_json::to_vec(&issued.request.cases).unwrap()).unwrap();
    let args = [
        "guard",
        "observe",
        "--ledger",
        p(&lab.ledger),
        "--context",
        "test-only-context",
        "--source",
        "billing-runtime",
        "--request-id",
        "capture-1",
        "--cases",
        p(&cases),
        "--archive",
        p(&archive),
        "--identity-file",
        "MUST_NOT_READ",
        "--work-directory",
        "MUST_NOT_CREATE",
        "--allow-native-read",
    ];
    let j = json(cli(&lab.root, &args), 3);
    assert_eq!(j["reused_original_admission"], true);
    assert_eq!(j["native_queries_performed"], false);
    assert_eq!(j["admission"], serde_json::to_value(&receipt).unwrap());
    let j = json(
        cli(
            &lab.root,
            &[
                "guard",
                "state",
                "--ledger",
                p(&lab.ledger),
                "--operation",
                "test-only-context",
                "--archive",
                p(&archive),
            ],
        ),
        3,
    );
    assert_eq!(j["effective"]["protection_evaluated"], true);
    assert_eq!(j["effective"]["all_required_effects_satisfied"], false);
    assert!(
        j["effective"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["observed"] == "allowed")
    );
    assert!(!lab.root.join("called").exists());
    assert!(!Path::new("MUST_NOT_CREATE").exists());
    // Changing trust cannot keep a cached affirmative result current.
    let mut snapshot = lab.snapshot.clone();
    snapshot.trust_epoch += 1;
    EvidenceStore::open_existing(&lab.ledger)
        .unwrap()
        .register_source(&snapshot, Some(&lab.snapshot.revision_digest().unwrap()))
        .unwrap();
    let j = json(
        cli(
            &lab.root,
            &[
                "guard",
                "state",
                "--ledger",
                p(&lab.ledger),
                "--operation",
                "test-only-context",
                "--archive",
                p(&archive),
            ],
        ),
        3,
    );
    assert_eq!(j["effective"]["protection_evaluated"], false);
    assert_eq!(j["admission_reads"][0]["error"], "trust_changed");
    assert!(
        j["effective"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| r["history"].as_array().unwrap())
            .any(|h| h["claim"]["observed"] == "allowed" && h["eligible"] == false)
    );
    assert!(!lab.root.join("called").exists());
}
#[test]
fn native_opt_in_precedes_all_paths_and_v2_never_imports_v1_verdicts() {
    let dir = tempfile::tempdir().unwrap();
    let out = cli(
        dir.path(),
        &[
            "guard",
            "observe",
            "--ledger",
            "PRIVATE_SENTINEL",
            "--context",
            "context",
            "--source",
            "source",
            "--request-id",
            "request",
            "--cases",
            "PRIVATE_SENTINEL",
            "--archive",
            "PRIVATE_SENTINEL",
            "--identity-file",
            "PRIVATE_SENTINEL",
            "--work-directory",
            "PRIVATE_SENTINEL",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("PERMISSION_REQUIRED"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("PRIVATE_SENTINEL"));
    assert!(!dir.path().join("PRIVATE_SENTINEL").exists());
    let lab = Lab::new();
    lab.start("observation");
    let output = cli(
        &lab.root,
        &[
            "guard",
            "state",
            "--ledger",
            p(&lab.ledger),
            "--operation",
            "observation",
            "--evidence",
            "MUST_NOT_READ",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("EVIDENCE_INCOMPATIBLE"));
    assert!(!lab.root.join("called").exists());
}

#[test]
fn unregistered_aws_source_stops_offline_planning_before_config_credentials_or_native_reads() {
    let lab = Lab::new();
    let mut policy = parse_policy(include_str!("../examples/core-aws-policy.yaml")).unwrap();
    policy.schema_version = 2;
    policy.targets[0].resource.generation_fingerprint = Some(aws_generation_fingerprint(
        &policy.targets[0].placement.account_id,
        &policy.targets[0].placement.region,
        &policy.targets[0].resource.native_id,
        &policy.targets[0].aws.as_ref().unwrap().db_resource_id,
    ));
    policy.source_bindings = policy
        .subjects
        .iter()
        .enumerate()
        .map(|(i, s)| SourceBinding {
            source_id: s.workload_sources[0].clone(),
            registration_id: format!("aws-source-{i}"),
            revision_digest: format!("{}", i + 1).repeat(64),
            boundary: SourceBoundaryKind::AwsHostNetwork,
            allowed_uses: vec![SourceUse {
                subject_id: s.id.clone(),
                purpose: if i == 0 {
                    SourcePurpose::Application
                } else {
                    SourcePurpose::Recovery
                },
            }],
        })
        .collect();
    policy.evaluation = Some(EvaluationPolicy {
        contract: EvaluationContract::SourceBoundV2,
        denial_requirements: vec![ProfileDenialRequirement {
            profile_id: policy.protection_profiles[0].id.clone(),
            accepted_layers: vec![AcceptedDenialLayer::ConnectionAuthorization],
        }],
    });
    let plan = build_plan(
        &policy,
        capabilities_for_policy(&policy).unwrap(),
        vec![],
        lab.at - 30,
    )
    .unwrap();
    let change = prepare_change(&policy, &plan, &[], None, OperationLimits::default()).unwrap();
    EvidenceStore::open_existing(&lab.ledger)
        .unwrap()
        .start_session(&change, "aws-observation", lab.at - 20)
        .unwrap();
    let output = cli(
        &lab.root,
        &[
            "guard",
            "observe-plan",
            "--ledger",
            p(&lab.ledger),
            "--context",
            "aws-observation",
            "--source",
            "billing-runtime",
            "--collector-config",
            "MUST_NOT_READ",
            "--out",
            "MUST_NOT_CREATE",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("EVIDENCE_NOT_ADMITTED"));
    assert!(output.stdout.is_empty());
    let coverage = veil_db_guard::adapters::source::support::for_policy(&policy).unwrap();
    assert!(
        coverage
            .iter()
            .all(|r| r.collector_implemented && r.normalizer_implemented && !r.native_verified)
    );
    assert!(!lab.root.join("called").exists());
    assert!(!Path::new("MUST_NOT_CREATE").exists());
    let j = json(
        cli(
            &lab.root,
            &[
                "guard",
                "status",
                "--ledger",
                p(&lab.ledger),
                "--operation",
                "aws-observation",
            ],
        ),
        0,
    );
    assert_eq!(j["native_dispatch_available"], false);
    assert_eq!(j["protection_evaluated"], false);
}

#[test]
fn case_planning_keeps_ipv6_alias_batches_and_independent_recovery_tls_rows() {
    use veil_db_guard::adapters::source::requests;
    let lab = Lab::new();
    let mut config: CollectorConfig =
        serde_json::from_slice(&fs::read(&lab.config).unwrap()).unwrap();
    let mut ipv6 = config.endpoints[0].clone();
    ipv6.ip = "2001:db8::1".parse().unwrap();
    ipv6.endpoint = "billing6.internal".into();
    config.endpoints.push(ipv6);
    let plan = requests::plan(&lab.change, "billing-runtime", &config, lab.at).unwrap();
    assert_eq!(plan.batches.len(), 2);
    let cases = plan.batches.into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(
        cases
            .iter()
            .filter(|c| c.address_family == AddressFamily::Ipv4)
            .count(),
        8
    );
    assert_eq!(
        cases
            .iter()
            .filter(|c| c.address_family == AddressFamily::Ipv6)
            .count(),
        8
    );
    config.registration_id = "recovery-source-registration".into();
    config.endpoints.truncate(1);
    let plan = requests::plan(&lab.change, "recovery-runtime", &config, lab.at).unwrap();
    let cases = &plan.batches[0];
    assert_eq!(cases.len(), 3);
    assert_eq!(
        cases
            .iter()
            .filter(|c| c.kind == FixedObservationCase::TargetHealth)
            .count(),
        1
    );
    assert_eq!(
        cases
            .iter()
            .filter(|c| c.kind == FixedObservationCase::Transport)
            .count(),
        2
    );
    assert!(cases.iter().all(
        |c| c.purpose == SourcePurpose::Recovery && c.address.subject_id == "recovery-operator"
    ));
    let mut request = ObservationRequest {
        schema_version: 1,
        request_id: "recovery-request".into(),
        nonce: "a".repeat(64),
        policy_revision_hash: lab.change.plan.policy_revision_hash.clone(),
        change_hash: lab.change.change_hash.clone(),
        operation_id: "context".into(),
        source: lab.change.policy.source_bindings[1].clone(),
        source_trust_epoch: 1,
        evaluation_contract: EvaluationContract::SourceBoundV2,
        collector_build_id: veil_db_guard::BUILD_ID.into(),
        verifier_build_id: veil_db_guard::BUILD_ID.into(),
        issued_at: lab.at,
        expires_at: lab.at + 120,
        cases: cases.clone(),
    };
    validate_request_scope(&request, &lab.change).unwrap();
    request.cases[0].address.effect = EffectKindV2::EffectiveSqlRole {
        role: "reader".into(),
    };
    request.cases[0].kind = FixedObservationCase::EffectiveSqlPrivilege;
    assert!(validate_request_scope(&request, &lab.change).is_err());
}
#[test]
fn readonly_context_cannot_be_applied_as_a_forward_operation() {
    let lab = Lab::new();
    lab.start("readonly-context");
    let output = cli(
        &lab.root,
        &[
            "guard",
            "apply-gcp",
            "--ledger",
            p(&lab.ledger),
            "--operation",
            "readonly-context",
            "--expected-version",
            "0",
            "--execution-identity",
            "runner",
            "--native-config",
            "MUST_NOT_READ",
            "--allow-native-changes",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("LEDGER_NOT_FOUND"));
    assert!(!lab.root.join("called").exists());
}
