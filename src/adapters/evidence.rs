//! Local archive + clock. Native channel/VM verification is intentionally absent
//! until K10-C; no CLI/config hook can supply a positive verifier verdict.
use crate::{
    core::{
        admission::*,
        evidence::ObservationBundleWire,
        ports::{EvidenceArchive, EvidenceClock, ObservationVerifier},
    },
    store::{self, Manifest, RunStatus, RunWriter},
};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
static ARCHIVE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub struct SystemEvidenceClock;
impl EvidenceClock for SystemEvidenceClock {
    fn now(&self) -> u64 {
        crate::domain::now()
    }
}

pub struct NativeSourceVerifierUnavailable;
impl ObservationVerifier for NativeSourceVerifierUnavailable {
    fn verify(
        &mut self,
        _: &IssuedObservation,
        _: &ObservationBundleWire,
        _: &[EvidencePayload],
        _: CaptureWindow,
    ) -> Result<VerifierFindings, AdmissionError> {
        Err(AdmissionError::VerifierUnavailable)
    }
}

pub struct RunEvidenceArchive {
    root: PathBuf,
    directory: File,
}
fn archive_error(error: crate::config::GuardError) -> AdmissionError {
    if matches!(error, crate::config::GuardError::LimitExceeded) {
        AdmissionError::Limit
    } else {
        AdmissionError::Storage
    }
}
impl RunEvidenceArchive {
    /// The caller supplies an existing private directory; this does not deploy,
    /// create a VM, search other paths or delete historical evidence.
    pub fn open(root: &Path) -> Result<Self, AdmissionError> {
        let meta = std::fs::symlink_metadata(root).map_err(|_| AdmissionError::Storage)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(AdmissionError::Invalid);
        }
        private_metadata(&meta, true)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let directory = options.open(root).map_err(|_| AdmissionError::Storage)?;
        private_metadata(
            &directory.metadata().map_err(|_| AdmissionError::Storage)?,
            true,
        )?;
        Ok(Self {
            root: root.canonicalize().map_err(|_| AdmissionError::Storage)?,
            directory,
        })
    }
    fn run(&self, id: &str) -> Result<File, AdmissionError> {
        if !crate::core::policy::valid_id(id) {
            return Err(AdmissionError::Integrity);
        }
        let dir = open_at(&self.directory, id, true)?;
        private_metadata(
            &dir.metadata().map_err(|_| AdmissionError::Integrity)?,
            true,
        )?;
        Ok(dir)
    }
}

fn private_metadata(meta: &std::fs::Metadata, directory: bool) -> Result<(), AdmissionError> {
    if (directory && !meta.is_dir()) || (!directory && !meta.is_file()) {
        return Err(AdmissionError::Integrity);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Every directory/file is owned by this operator and private. Hardlinked
        // artifacts are not accepted as immutable capture files.
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || (!directory && meta.nlink() != 1)
        {
            return Err(AdmissionError::Integrity);
        }
    }
    Ok(())
}
#[cfg(unix)]
fn open_at(dir: &File, name: &str, directory: bool) -> Result<File, AdmissionError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = std::ffi::CString::new(name).map_err(|_| AdmissionError::Integrity)?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: names/descriptors remain live; the returned descriptor is owned once.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(AdmissionError::Integrity);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(not(unix))]
fn open_at(_: &File, _: &str, _: bool) -> Result<File, AdmissionError> {
    Err(AdmissionError::Storage)
}

fn read_at(dir: &File, name: &str, max: usize) -> Result<Vec<u8>, AdmissionError> {
    let file = open_at(dir, name, false)?;
    let meta = file.metadata().map_err(|_| AdmissionError::Integrity)?;
    private_metadata(&meta, false)?;
    if meta.len() > max as u64 {
        return Err(AdmissionError::Limit);
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AdmissionError::Integrity)?;
    if bytes.len() > max {
        return Err(AdmissionError::Limit);
    }
    Ok(bytes)
}

impl EvidenceArchive for RunEvidenceArchive {
    fn persist(
        &mut self,
        issued: &IssuedObservation,
        bytes: &[u8],
        payloads: &[EvidencePayload],
    ) -> Result<EvidenceArchiveRef, AdmissionError> {
        use crate::core::evidence::MAX_BUNDLE_BYTES;
        // macOS wall-clock timestamps can coincide across threads. Keep
        // independent saved attempts distinct before the nonce CAS decides.
        let sequence = ARCHIVE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name = format!("{}-{sequence}", store::new_run_id());
        let mut writer = RunWriter::create_for_config(
            &self.root.join(&name),
            &issued.request.request_id,
            issued,
            "guard-observation",
            MAX_BUNDLE_BYTES,
            true,
        )
        .map_err(archive_error)?;
        writer
            .write_bytes("evidence-bundle.json", bytes)
            .map_err(archive_error)?;
        writer
            .write_json("evidence-artifacts.json", &payloads)
            .map_err(archive_error)?;
        writer.finish(RunStatus::Complete).map_err(archive_error)?;
        let run = self.run(&name)?;
        let manifest = read_at(&run, "manifest.json", MAX_BUNDLE_BYTES)?;
        let archive = EvidenceArchiveRef {
            run_id: name,
            manifest_digest: crate::config::hash_bytes(&manifest),
            bundle_digest: crate::config::hash_bytes(bytes),
            request_digest: issued
                .request
                .digest()
                .map_err(|_| AdmissionError::Invalid)?,
        };
        // Verify the final files through the pinned root handle before returning
        // a receipt to the ledger. No JSON verdict establishes authenticity.
        self.read(issued, &archive)?;
        Ok(archive)
    }

    fn read(
        &self,
        issued: &IssuedObservation,
        archive: &EvidenceArchiveRef,
    ) -> Result<(Vec<u8>, Vec<EvidencePayload>), AdmissionError> {
        use crate::core::evidence::MAX_BUNDLE_BYTES;
        let run = self.run(&archive.run_id)?;
        let bytes = read_at(&run, "manifest.json", MAX_BUNDLE_BYTES)?;
        if crate::config::hash_bytes(&bytes) != archive.manifest_digest {
            return Err(AdmissionError::Integrity);
        }
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| AdmissionError::Integrity)?;
        if manifest.schema_version != 1
            || manifest.operation != "guard-observation"
            || manifest.status != RunStatus::Complete
            || !manifest.operation_only
            || manifest.target_id != issued.request.request_id
            || manifest.build_id != issued.request.verifier_build_id
            || manifest.config_hash
                != crate::config::hash_bytes(
                    &serde_json::to_vec(issued).map_err(|_| AdmissionError::Integrity)?,
                )
            || manifest.artifacts.len() != 3
            || archive.request_digest
                != issued
                    .request
                    .digest()
                    .map_err(|_| AdmissionError::Integrity)?
        {
            return Err(AdmissionError::Integrity);
        }
        let mut total = bytes.len();
        let mut seen = std::collections::BTreeSet::new();
        let mut bundle = None;
        let mut payloads = None;
        for artifact in manifest.artifacts {
            if !seen.insert(artifact.name.clone())
                || ![
                    "config.normalized.json",
                    "evidence-bundle.json",
                    "evidence-artifacts.json",
                ]
                .contains(&artifact.name.as_str())
            {
                return Err(AdmissionError::Integrity);
            }
            let data = read_at(&run, &artifact.name, MAX_BUNDLE_BYTES.saturating_sub(total))?;
            total = total.saturating_add(data.len());
            if data.len() != artifact.bytes || crate::config::hash_bytes(&data) != artifact.sha256 {
                return Err(AdmissionError::Integrity);
            }
            match artifact.name.as_str() {
                "evidence-bundle.json" => {
                    if artifact.sha256 != archive.bundle_digest {
                        return Err(AdmissionError::Integrity);
                    }
                    bundle = Some(data);
                }
                "evidence-artifacts.json" => {
                    payloads =
                        Some(serde_json::from_slice(&data).map_err(|_| AdmissionError::Integrity)?)
                }
                _ => {
                    let config: IssuedObservation =
                        serde_json::from_slice(&data).map_err(|_| AdmissionError::Integrity)?;
                    if config != *issued {
                        return Err(AdmissionError::Integrity);
                    }
                }
            }
        }
        Ok((
            bundle.ok_or(AdmissionError::Integrity)?,
            payloads.ok_or(AdmissionError::Integrity)?,
        ))
    }
}
