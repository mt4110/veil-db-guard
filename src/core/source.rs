//! Immutable source references, not proof that a collector ran on that source.
//! No SSH, VM metadata, credential lookup or registry persistence belongs here.
use super::policy::{PolicyError, PolicyRevision, SubjectKind, valid_hash, valid_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
// The boundary, not merely the provider, is part of the approved wire name.
#[allow(clippy::enum_variant_names)]
pub enum SourceBoundaryKind {
    GceHostNetwork,
    AwsHostNetwork,
    SelfManagedHostNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePurpose {
    Application,
    Recovery,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUse {
    pub subject_id: String,
    pub purpose: SourcePurpose,
}

/// The digest pins the entire registry snapshot, including its trust epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBinding {
    pub source_id: String,
    pub registration_id: String,
    pub revision_digest: String,
    pub boundary: SourceBoundaryKind,
    pub allowed_uses: Vec<SourceUse>,
}

/// Stable effect address component; policy authorization is held separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotRef {
    pub source_id: String,
    pub registration_id: String,
    pub revision_digest: String,
    pub boundary: SourceBoundaryKind,
}

impl SourceSnapshotRef {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if valid_id(&self.source_id)
            && valid_id(&self.registration_id)
            && valid_hash(&self.revision_digest)
        {
            Ok(())
        } else {
            Err(PolicyError::ReferenceInvalid)
        }
    }
}

impl SourceBinding {
    pub fn snapshot_ref(&self) -> SourceSnapshotRef {
        SourceSnapshotRef {
            source_id: self.source_id.clone(),
            registration_id: self.registration_id.clone(),
            revision_digest: self.revision_digest.clone(),
            boundary: self.boundary,
        }
    }
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !valid_id(&self.source_id)
            || !valid_id(&self.registration_id)
            || !valid_hash(&self.revision_digest)
            || self.allowed_uses.is_empty()
            || self.allowed_uses.len() > 128
            || self.allowed_uses.iter().any(|u| !valid_id(&u.subject_id))
            || self.allowed_uses.iter().collect::<BTreeSet<_>>().len() != self.allowed_uses.len()
            || (self
                .allowed_uses
                .iter()
                .any(|u| u.purpose == SourcePurpose::Application)
                && self
                    .allowed_uses
                    .iter()
                    .any(|u| u.purpose != SourcePurpose::Application))
        {
            return Err(PolicyError::ReferenceInvalid);
        }
        Ok(())
    }
}

/// Validate references without consulting a mutable registry or inferring that
/// any declared source is available. A policy cannot authorize a management
/// credential on an application source by adding a second logical alias.
pub(crate) fn validate_policy_sources(policy: &PolicyRevision) -> Result<(), PolicyError> {
    if policy.schema_version == 1 {
        return if policy.source_bindings.is_empty() && policy.evaluation.is_none() {
            Ok(())
        } else {
            Err(PolicyError::Invalid)
        };
    }
    if policy.source_bindings.is_empty() || policy.source_bindings.len() > 128 {
        return Err(PolicyError::LimitExceeded);
    }
    let mut ids = BTreeSet::new();
    let mut registrations = BTreeSet::new();
    for binding in &policy.source_bindings {
        binding.validate()?;
        if !ids.insert(&binding.source_id) || !registrations.insert(&binding.registration_id) {
            return Err(PolicyError::ReferenceInvalid);
        }
        for usage in &binding.allowed_uses {
            let subject = policy
                .subjects
                .iter()
                .find(|s| s.id == usage.subject_id)
                .ok_or(PolicyError::ReferenceInvalid)?;
            let recovery = policy.protection_profiles.iter().any(|p| {
                p.management_exceptions.iter().any(|e| {
                    e.recovery
                        && e.subject == subject.id
                        && e.source_ids.contains(&binding.source_id)
                })
            });
            if !subject.workload_sources.contains(&binding.source_id)
                || match usage.purpose {
                    SourcePurpose::Application => subject.kind == SubjectKind::Operator || recovery,
                    SourcePurpose::Recovery => subject.kind != SubjectKind::Operator || !recovery,
                    SourcePurpose::Control => subject.kind != SubjectKind::Operator || recovery,
                }
            {
                return Err(PolicyError::ScopeViolation);
            }
        }
    }
    for subject in &policy.subjects {
        for source in &subject.workload_sources {
            if !policy.source_bindings.iter().any(|b| {
                b.source_id == *source && b.allowed_uses.iter().any(|u| u.subject_id == subject.id)
            }) {
                return Err(PolicyError::ReferenceInvalid);
            }
        }
    }
    for profile in &policy.protection_profiles {
        for source in profile
            .allowed_routes
            .iter()
            .flat_map(|r| &r.source_ids)
            .chain(
                profile
                    .management_exceptions
                    .iter()
                    .flat_map(|e| &e.source_ids),
            )
        {
            if !ids.contains(source) {
                return Err(PolicyError::ReferenceInvalid);
            }
        }
    }
    policy
        .evaluation
        .as_ref()
        .ok_or(PolicyError::Invalid)?
        .validate(policy)
}

/// Initial source identity shape. Other boundary kinds are expressible in a
/// policy, but cannot be materialized as this GCE registration profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GceVmIdentity {
    pub project_id: String,
    pub project_number: String,
    pub zone: String,
    pub instance_id: String,
    pub created_at_unix: u64,
    pub service_account: String,
    pub service_account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRegistrationSnapshot {
    pub schema_version: u32,
    pub registration_id: String,
    pub trust_epoch: u64,
    pub native_identity: GceVmIdentity,
    /// Digests of the pinned key/configuration, never secret key material.
    pub ssh_host_key_digest: String,
    pub collector_build_id: String,
    pub collector_config_digest: String,
    pub network_context_digest: String,
    pub execution_user: String,
    pub credential_kind: SourceCredentialKind,
    pub credential_reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gce_host: Option<GceHostProfile>,
}

/// V2 registration explicitly pins the SSH peer and installed collector. It
/// does not register itself or grant installation/native read permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GceHostProfile {
    pub ssh_ip: std::net::IpAddr,
    pub ssh_port: u16,
    pub host_key_ed25519_base64: String,
    pub collector_binary_digest: String,
    pub execution_uid: u32,
}

/// No ADC, local SDK or management-token fallback in the initial profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCredentialKind {
    GceMetadata,
}

impl SourceRegistrationSnapshot {
    pub fn validate(&self) -> Result<(), PolicyError> {
        let vm = &self.native_identity;
        let numeric =
            |v: &str| !v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_digit());
        if !matches!(self.schema_version, 1 | 2)
            || (self.schema_version == 1 && self.gce_host.is_some())
            || (self.schema_version == 2 && self.gce_host.is_none())
            || self.trust_epoch == 0
            || !valid_id(&self.registration_id)
            || !valid_id(&vm.project_id)
            || !valid_id(&vm.zone)
            || !numeric(&vm.project_number)
            || !numeric(&vm.instance_id)
            || !numeric(&vm.service_account_id)
            || vm.created_at_unix == 0
            || vm.service_account.len() > 254
            || !vm
                .service_account
                .strip_suffix(&format!("@{}.iam.gserviceaccount.com", vm.project_id))
                .is_some_and(valid_id)
            || !valid_id(&self.execution_user)
            || !valid_id(&self.credential_reference)
            || [
                &self.ssh_host_key_digest,
                &self.collector_build_id,
                &self.collector_config_digest,
                &self.network_context_digest,
            ]
            .iter()
            .any(|v| !valid_hash(v))
        {
            return Err(PolicyError::Invalid);
        }
        if let Some(profile) = &self.gce_host
            && (profile.ssh_port == 0
                || !valid_hash(&profile.collector_binary_digest)
                || profile.ssh_ip.is_unspecified()
                || profile.ssh_ip.is_multicast()
                || profile.host_key_ed25519_base64.is_empty()
                || profile.host_key_ed25519_base64.len() > 128
                || !profile
                    .host_key_ed25519_base64
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)))
        {
            return Err(PolicyError::Invalid);
        }
        Ok(())
    }

    pub fn revision_digest(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let mut bytes = if self.schema_version == 1 {
            b"veil-db-guard/source-registration/v1\0".to_vec()
        } else {
            b"veil-db-guard/source-registration/v2\0".to_vec()
        };
        bytes.extend(serde_json::to_vec(self).map_err(|_| PolicyError::Invalid)?);
        Ok(super::hash_bytes(&bytes))
    }

    /// Exact snapshot resolution only; matching declarations are not runtime
    /// source verification and do not mint VerifiedObservationFacts.
    pub fn matches_binding(&self, binding: &SourceBinding) -> Result<bool, PolicyError> {
        binding.validate()?;
        Ok(binding.boundary == SourceBoundaryKind::GceHostNetwork
            && binding.registration_id == self.registration_id
            && binding.revision_digest == self.revision_digest()?)
    }
}

/// Provider-specific immutable registration. Untagged keeps historical GCE
/// JSON bytes and digest domains unchanged; AWS has a separate native shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RegisteredSourceSnapshot {
    Gce(SourceRegistrationSnapshot),
    Aws(AwsSourceRegistrationSnapshot),
}
impl From<SourceRegistrationSnapshot> for RegisteredSourceSnapshot {
    fn from(value: SourceRegistrationSnapshot) -> Self {
        Self::Gce(value)
    }
}
impl From<AwsSourceRegistrationSnapshot> for RegisteredSourceSnapshot {
    fn from(value: AwsSourceRegistrationSnapshot) -> Self {
        Self::Aws(value)
    }
}
impl RegisteredSourceSnapshot {
    pub fn validate(&self) -> Result<(), PolicyError> {
        match self {
            Self::Gce(s) => s.validate(),
            Self::Aws(s) => s.validate(),
        }
    }
    pub fn revision_digest(&self) -> Result<String, PolicyError> {
        match self {
            Self::Gce(s) => s.revision_digest(),
            Self::Aws(s) => s.revision_digest(),
        }
    }
    pub fn matches_binding(&self, b: &SourceBinding) -> Result<bool, PolicyError> {
        match self {
            Self::Gce(s) => s.matches_binding(b),
            Self::Aws(s) => s.matches_binding(b),
        }
    }
    pub fn gce(&self) -> Option<&SourceRegistrationSnapshot> {
        if let Self::Gce(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn gce_mut(&mut self) -> Option<&mut SourceRegistrationSnapshot> {
        if let Self::Gce(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn aws(&self) -> Option<&AwsSourceRegistrationSnapshot> {
        if let Self::Aws(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn registration_id(&self) -> &str {
        match self {
            Self::Gce(s) => &s.registration_id,
            Self::Aws(s) => &s.registration_id,
        }
    }
    pub fn trust_epoch(&self) -> u64 {
        match self {
            Self::Gce(s) => s.trust_epoch,
            Self::Aws(s) => s.trust_epoch,
        }
    }
    pub fn collector_build_id(&self) -> &str {
        match self {
            Self::Gce(s) => &s.collector_build_id,
            Self::Aws(s) => &s.collector_build_id,
        }
    }
    pub fn collector_config_digest(&self) -> &str {
        match self {
            Self::Gce(s) => &s.collector_config_digest,
            Self::Aws(s) => &s.collector_config_digest,
        }
    }
    pub fn network_context_digest(&self) -> &str {
        match self {
            Self::Gce(s) => &s.network_context_digest,
            Self::Aws(s) => &s.network_context_digest,
        }
    }
    /// Alias defense uses physical instance identity, regardless of boot epoch.
    pub fn same_host(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Gce(a), Self::Gce(b)) => {
                a.native_identity.project_number == b.native_identity.project_number
                    && a.native_identity.instance_id == b.native_identity.instance_id
            }
            (Self::Aws(a), Self::Aws(b)) => {
                a.native_identity.account_id == b.native_identity.account_id
                    && a.native_identity.region == b.native_identity.region
                    && a.native_identity.instance_id == b.native_identity.instance_id
            }
            _ => false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsEc2Identity {
    pub account_id: String,
    pub region: String,
    pub availability_zone: String,
    pub instance_id: String,
    pub image_id: String,
    pub pending_time: String,
    pub private_ip: std::net::IpAddr,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsHostProfile {
    pub ssh_ip: std::net::IpAddr,
    pub ssh_port: u16,
    pub host_key_ed25519_base64: String,
    pub collector_binary_digest: String,
    pub execution_uid: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSourceRegistrationSnapshot {
    pub schema_version: u32,
    pub registration_id: String,
    pub trust_epoch: u64,
    pub native_identity: AwsEc2Identity,
    pub ssh_host_key_digest: String,
    pub collector_build_id: String,
    pub collector_config_digest: String,
    pub network_context_digest: String,
    pub execution_user: String,
    pub aws_host: AwsHostProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_credential: Option<AwsMetadataCredential>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsMetadataCredential {
    pub role_arn: String,
    pub role_id: String,
    pub credential_reference: String,
}
impl AwsSourceRegistrationSnapshot {
    pub fn validate(&self) -> Result<(), PolicyError> {
        let vm = &self.native_identity;
        if self.metadata_credential.as_ref().is_some_and(|c| {
            !super::policy::aws_role_arn(&c.role_arn, &vm.account_id)
                || !super::policy::aws_role_id(&c.role_id)
                || !valid_id(&c.credential_reference)
        }) {
            return Err(PolicyError::Invalid);
        }

        let native_id = |v: &str, prefix: &str| {
            v.strip_prefix(prefix).is_some_and(|v| {
                matches!(v.len(), 8 | 17)
                    && v.bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            })
        };
        let time = vm.pending_time.as_bytes();
        if self.schema_version != 1
            || self.trust_epoch == 0
            || !valid_id(&self.registration_id)
            || vm.account_id.len() != 12
            || !vm.account_id.bytes().all(|b| b.is_ascii_digit())
            || vm.region != "ap-northeast-1"
            || !vm
                .availability_zone
                .strip_prefix(&vm.region)
                .is_some_and(|s| s.len() == 1 && s.bytes().all(|b| b.is_ascii_lowercase()))
            || !native_id(&vm.instance_id, "i-")
            || !native_id(&vm.image_id, "ami-")
            || time.len() != 20
            || time.iter().enumerate().any(|(n, b)| match n {
                4 | 7 => *b != b'-',
                10 => *b != b'T',
                13 | 16 => *b != b':',
                19 => *b != b'Z',
                _ => !b.is_ascii_digit(),
            })
            || vm.private_ip.is_unspecified()
            || vm.private_ip.is_multicast()
            || self.execution_user != "root"
            || self.aws_host.execution_uid != 0
            || self.aws_host.ssh_port == 0
            || self.aws_host.ssh_ip.is_unspecified()
            || self.aws_host.ssh_ip.is_multicast()
            || self.aws_host.host_key_ed25519_base64.is_empty()
            || self.aws_host.host_key_ed25519_base64.len() > 128
            || [
                &self.ssh_host_key_digest,
                &self.collector_build_id,
                &self.collector_config_digest,
                &self.network_context_digest,
                &self.aws_host.collector_binary_digest,
            ]
            .iter()
            .any(|v| !valid_hash(v))
        {
            return Err(PolicyError::Invalid);
        }
        Ok(())
    }
    pub fn revision_digest(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let mut bytes = b"veil-db-guard/aws-source-registration/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| PolicyError::Invalid)?);
        Ok(super::hash_bytes(&bytes))
    }
    pub fn matches_binding(&self, binding: &SourceBinding) -> Result<bool, PolicyError> {
        binding.validate()?;
        Ok(binding.boundary == SourceBoundaryKind::AwsHostNetwork
            && binding.registration_id == self.registration_id
            && binding.revision_digest == self.revision_digest()?)
    }
}
