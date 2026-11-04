//! Local-only identity fixtures. No production trust override is compiled.
use super::gce_host::*;
use crate::core::{admission::*, evidence::*, policy::*, source::*, state::*};
use base64::Engine;
pub(super) fn fixture() -> (IssuedObservation, CollectorConfig) {
    let mut key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    key.extend([7; 32]);
    let context = LinuxHostContext {
        uid: 0,
        effective_uid: 0,
        network_namespace: "net:[4026531992]".into(),
        mount_namespace: "mnt:[4026531841]".into(),
        user_namespace: "user:[4026531837]".into(),
        boot_id_digest: "a".repeat(64),
        cgroup_class: "0::/user.slice/user-0.slice/session.scope".into(),
        route_v4_digest: "b".repeat(64),
        route_v6_digest: "c".repeat(64),
        interfaces_digest: "d".repeat(64),
        rules_v4_digest: "e".repeat(64),
        rules_v6_digest: "f".repeat(64),
    };
    let config = CollectorConfig {
        schema_version: 1,
        registration_id: "billing-source-registration".into(),
        context: context.clone(),
        postgres: None,
        route_denial: None,
        runtime: None,
        runtime_unix: vec![],
        kernel_origin: None,
        endpoints: vec![CollectorEndpoint {
            target_id: "billing-db".into(),
            native_id: "projects/vdg-example-000000/instances/billing-postgres".into(),
            generation_digest: "d".repeat(64),
            database: "billing".into(),
            endpoint: "db.example.invalid".into(),
            ip: "203.0.113.10".parse().unwrap(),
            port: 5432,
        }],
    };
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
        ssh_host_key_digest: crate::config::hash_bytes(&key),
        collector_build_id: "c".repeat(64),
        collector_config_digest: crate::config::hash_bytes(&serde_json::to_vec(&config).unwrap()),
        network_context_digest: context.digest().unwrap(),
        execution_user: "root".into(),
        credential_kind: SourceCredentialKind::GceMetadata,
        credential_reference: "billing-workload".into(),
        gce_host: Some(GceHostProfile {
            ssh_ip: "192.0.2.10".parse().unwrap(),
            ssh_port: 22,
            host_key_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(key),
            collector_binary_digest: "f".repeat(64),
            execution_uid: 0,
        }),
    };
    let source = SourceBinding {
        source_id: "billing-runtime".into(),
        registration_id: snapshot.registration_id.clone(),
        revision_digest: snapshot.revision_digest().unwrap(),
        boundary: SourceBoundaryKind::GceHostNetwork,
        allowed_uses: vec![SourceUse {
            subject_id: "billing-app".into(),
            purpose: SourcePurpose::Application,
        }],
    };
    let p = parse_policy(include_str!("../../../examples/core-policy-v2.yaml")).unwrap();
    let t = &p.targets[0];
    let request = ObservationRequest {
        schema_version: 1,
        request_id: "source-request-1".into(),
        nonce: "a".repeat(64),
        policy_revision_hash: "b".repeat(64),
        change_hash: "c".repeat(64),
        operation_id: "operation-1".into(),
        source: source.clone(),
        source_trust_epoch: 1,
        evaluation_contract: EvaluationContract::SourceBoundV2,
        collector_build_id: snapshot.collector_build_id.clone(),
        verifier_build_id: crate::BUILD_ID.into(),
        issued_at: 100,
        expires_at: 220,
        cases: vec![RequestedCase {
            backend_tls_trust: None,
            login_catalog_targets: vec![],
            mysql_account_host: None,
            id: "direct".into(),
            kind: FixedObservationCase::DirectPath,
            purpose: SourcePurpose::Application,
            endpoint: "db.example.invalid".into(),
            port: 5432,
            address_family: AddressFamily::Ipv4,
            address: EffectAddress {
                target_id: t.id.clone(),
                target: TargetHandle {
                    registration_id: t.registration_id.clone(),
                    native_ref: ResourceIdentity {
                        native_id: t.resource.native_id.clone(),
                        generation_fingerprint: Some("d".repeat(64)),
                    },
                    placement: t.placement.clone(),
                    engine_binding: t.engine.clone(),
                    generation_assurance: GenerationAssurance::Unconfirmed,
                },
                grant_id: p.grants[0].id.clone(),
                subject_id: "billing-app".into(),
                db_identity: p.grants[0].db_identity.clone(),
                source: source.snapshot_ref(),
                route: StateRoute {
                    id: "application-direct".into(),
                    kind: RouteKind::Direct,
                },
                effect: EffectKindV2::NewConnections,
            },
        }],
    };
    let i = IssuedObservation {
        request,
        snapshot: snapshot.into(),
    };
    validate_issued(&i).unwrap();
    (i, config)
}
