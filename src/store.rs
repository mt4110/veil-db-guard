//! New-run only, bounded evidence storage; imported manifests are not signatures.
use crate::{
    config::{GuardError, config_hash, hash_bytes, read_bounded},
    domain::*,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    InProgress,
    Complete,
    Partial,
    Cancelled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub sha256: String,
    pub bytes: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub run_id: String,
    pub target_id: String,
    pub operation: String,
    pub config_hash: String,
    pub build_id: String,
    pub created_at: u64,
    pub status: RunStatus,
    pub operation_only: bool,
    pub artifacts: Vec<Artifact>,
}
pub struct RunWriter {
    dir: PathBuf,
    directory: File,
    pub manifest: Manifest,
    max_bytes: usize,
    written: usize,
}
pub fn new_run_id() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("run-{n}-{}", std::process::id())
}
fn artifact_name(name: &str) -> bool {
    [
        "config.normalized.json",
        "snapshot.json",
        "snapshot.before.json",
        "snapshot.after.json",
        "plan.json",
        "prepared-change.json",
        "intent-qualification.json",
        "sandbox.yaml",
        "bootstrap.sql",
        "observations.json",
        "assessment.json",
        "report.md",
        "experiment-plan.json",
        "operation-error.json",
        "probe-error.json",
        "postgres-ownership.json",
        "mysql-ownership.json",
        "effective-state.json",
        "aws-access.json",
        "native-direct-transport.json",
        "evidence-bundle.json",
        "evidence-artifacts.json",
        "case-plan.json",
        "source-coverage.json",
        "k11-handoff.json",
        "source-state.json",
    ]
    .contains(&name)
        || name
            .strip_prefix("cases-")
            .and_then(|s| s.strip_suffix(".json"))
            .is_some_and(|s| {
                s.len() <= 4
                    && s.parse::<u32>()
                        .is_ok_and(|n| (1..=4096).contains(&n) && n.to_string() == s)
            })
}
#[cfg(unix)]
fn open_private_at(directory: &File, name: &str) -> Result<File, GuardError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = std::ffi::CString::new(name).map_err(|_| GuardError::StorageFailed)?;
    // SAFETY: the directory descriptor and NUL-terminated name remain live; ownership
    // of the newly returned descriptor is transferred exactly once to File.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(GuardError::StorageFailed);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(not(unix))]
fn open_private_at(_: &File, _: &str) -> Result<File, GuardError> {
    Err(GuardError::UnsupportedTarget)
}
#[cfg(unix)]
fn replace_manifest_at(directory: &File, temp: &str) -> Result<(), GuardError> {
    use std::os::fd::AsRawFd;
    let temp = std::ffi::CString::new(temp).map_err(|_| GuardError::StorageFailed)?;
    let name = c"manifest.json";
    // SAFETY: both names and the open directory descriptor remain live.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            temp.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
        )
    } != 0
    {
        return Err(GuardError::StorageFailed);
    }
    directory.sync_all().map_err(|_| GuardError::StorageFailed)
}
#[cfg(not(unix))]
fn replace_manifest_at(_: &File, _: &str) -> Result<(), GuardError> {
    Err(GuardError::UnsupportedTarget)
}
impl RunWriter {
    pub fn create(
        path: &Path,
        config: &TargetConfig,
        operation: &str,
        operation_only: bool,
    ) -> Result<Self, GuardError> {
        Self::create_for_config(
            path,
            &config.target.id,
            config,
            operation,
            config.limits.max_bytes,
            operation_only,
        )
    }

    /// Provider-neutral storage only. The caller validates its own secret-free
    /// configuration before creating a run; the writer never contacts a provider.
    pub fn create_for_config<T: Serialize>(
        path: &Path,
        target_id: &str,
        config: &T,
        operation: &str,
        max_bytes: usize,
        operation_only: bool,
    ) -> Result<Self, GuardError> {
        if !valid_operation(operation)
            || !crate::config::safe_id(target_id)
            || !(1024..=64 * 1024 * 1024).contains(&max_bytes)
            || path.components().any(|x| matches!(x, Component::ParentDir))
        {
            return Err(GuardError::StorageFailed);
        }
        let config_bytes = serde_json::to_vec(config).map_err(|_| GuardError::ConfigInvalid)?;
        if config_bytes.len() > max_bytes {
            return Err(GuardError::LimitExceeded);
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if std::fs::symlink_metadata(parent)
            .map_err(|_| GuardError::StorageFailed)?
            .file_type()
            .is_symlink()
        {
            return Err(GuardError::StorageFailed);
        }
        let parent = parent
            .canonicalize()
            .map_err(|_| GuardError::StorageFailed)?;
        let name = path.file_name().ok_or(GuardError::StorageFailed)?;
        let dir = parent.join(name);
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .map_err(|_| GuardError::StorageFailed)?;
        let mut open = OpenOptions::new();
        open.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC);
        }
        let directory = open.open(&dir).map_err(|_| GuardError::StorageFailed)?;
        let mut writer = Self {
            dir,
            directory,
            max_bytes,
            written: 0,
            manifest: Manifest {
                schema_version: 1,
                run_id: new_run_id(),
                target_id: target_id.into(),
                operation: operation.into(),
                config_hash: hash_bytes(&config_bytes),
                build_id: crate::BUILD_ID.into(),
                created_at: now(),
                status: RunStatus::InProgress,
                operation_only,
                artifacts: vec![],
            },
        };
        writer.persist_manifest()?;
        writer.write_json("config.normalized.json", config)?;
        Ok(writer)
    }
    pub fn write_json<T: Serialize>(&mut self, name: &str, value: &T) -> Result<(), GuardError> {
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| GuardError::StorageFailed)?;
        bytes.push(b'\n');
        self.write_bytes(name, &bytes)
    }
    pub fn write_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<(), GuardError> {
        if !artifact_name(name) || self.manifest.artifacts.iter().any(|a| a.name == name) {
            return Err(GuardError::StorageFailed);
        }
        let mut next = self.manifest.clone();
        next.artifacts.push(Artifact {
            name: name.into(),
            sha256: hash_bytes(bytes),
            bytes: bytes.len(),
        });
        let manifest_bytes = serde_json::to_vec_pretty(&next)
            .map_err(|_| GuardError::StorageFailed)?
            .len();
        if self
            .written
            .saturating_add(bytes.len())
            .saturating_add(manifest_bytes)
            > self.max_bytes
        {
            return Err(GuardError::LimitExceeded);
        }
        let mut file = open_private_at(&self.directory, name)?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| GuardError::StorageFailed)?;
        self.written += bytes.len();
        self.manifest = next;
        self.persist_manifest()
    }
    fn persist_manifest(&self) -> Result<(), GuardError> {
        // Only an internally owned manifest is replaced; no other artifact is overwritten.
        let temp = format!("manifest-{}.tmp", new_run_id());
        let bytes =
            serde_json::to_vec_pretty(&self.manifest).map_err(|_| GuardError::StorageFailed)?;
        if self.written.saturating_add(bytes.len()) > self.max_bytes {
            return Err(GuardError::LimitExceeded);
        }
        let mut file = open_private_at(&self.directory, &temp)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| GuardError::StorageFailed)?;
        replace_manifest_at(&self.directory, &temp)
    }
    pub fn finish(&mut self, status: RunStatus) -> Result<(), GuardError> {
        self.manifest.status = status;
        self.persist_manifest()
    }
    pub fn path(&self) -> &Path {
        &self.dir
    }
}
impl Drop for RunWriter {
    fn drop(&mut self) {
        if self.manifest.status == RunStatus::InProgress {
            self.manifest.status = RunStatus::Partial;
            let _ = self.persist_manifest();
        }
    }
}

pub fn verify_run(path: &Path, max_bytes: usize) -> Result<Manifest, GuardError> {
    let manifest = verify_manifest(path, max_bytes)?;
    if !["plan", "inspect", "probe", "report", "self-check"].contains(&manifest.operation.as_str())
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let config: TargetConfig = read_artifact(path, &manifest, "config.normalized.json", max_bytes)?;
    crate::config::validate_config(&config)?;
    if config_hash(&config) != manifest.config_hash || config.target.id != manifest.target_id {
        return Err(GuardError::EvidenceIncompatible);
    }
    Ok(manifest)
}

fn valid_operation(operation: &str) -> bool {
    [
        "plan",
        "inspect",
        "probe",
        "report",
        "self-check",
        "gcp-check",
        "gcp-report",
        "guard-plan",
        "postgres-ownership",
        "mysql-ownership",
        "guard-state",
        "aws-guard-check",
        "aws-guard-state",
        "aws-guard-inspect",
        "guard-observation",
        "guard-observation-plan",
        "guard-k11-handoff",
    ]
    .contains(&operation)
}

/// Verifies local artifact integrity, not its origin or provider semantics.
/// Importers must also validate the provider configuration, target, config hash,
/// evidence provenance and execution state before using a run in an assessment.
pub fn verify_manifest(path: &Path, max_bytes: usize) -> Result<Manifest, GuardError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| GuardError::StorageFailed)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(GuardError::EvidenceIncompatible);
    }
    let bytes = read_bounded(&path.join("manifest.json"), max_bytes)?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| GuardError::EvidenceIncompatible)?;
    if manifest.schema_version != 1
        || manifest.artifacts.len() > 32
        || !crate::config::safe_id(&manifest.run_id)
        || !crate::config::safe_id(&manifest.target_id)
        || manifest.config_hash.len() != 64
        || !manifest.config_hash.bytes().all(|b| b.is_ascii_hexdigit())
        || manifest.build_id.len() != 64
        || !manifest.build_id.bytes().all(|b| b.is_ascii_hexdigit())
        || !valid_operation(&manifest.operation)
    {
        return Err(GuardError::EvidenceIncompatible);
    }
    let mut total = bytes.len();
    let mut names = BTreeSet::new();
    for a in &manifest.artifacts {
        if !artifact_name(&a.name) || !names.insert(&a.name) {
            return Err(GuardError::EvidenceIncompatible);
        }
        let data = read_bounded(&path.join(&a.name), max_bytes.saturating_sub(total))?;
        total = total.saturating_add(data.len());
        if total > max_bytes || data.len() != a.bytes || hash_bytes(&data) != a.sha256 {
            return Err(GuardError::EvidenceIncompatible);
        }
    }
    if !names.contains(&"config.normalized.json".to_string()) {
        return Err(GuardError::EvidenceIncompatible);
    }
    Ok(manifest)
}
pub fn read_artifact<T: DeserializeOwned>(
    path: &Path,
    manifest: &Manifest,
    name: &str,
    max_bytes: usize,
) -> Result<T, GuardError> {
    if !manifest.artifacts.iter().any(|a| a.name == name) {
        return Err(GuardError::EvidenceIncompatible);
    }
    let data = read_bounded(&path.join(name), max_bytes)?;
    let a = manifest
        .artifacts
        .iter()
        .find(|a| a.name == name)
        .ok_or(GuardError::EvidenceIncompatible)?;
    if hash_bytes(&data) != a.sha256 || data.len() != a.bytes {
        return Err(GuardError::EvidenceIncompatible);
    }
    serde_json::from_slice(&data).map_err(|_| GuardError::EvidenceIncompatible)
}
