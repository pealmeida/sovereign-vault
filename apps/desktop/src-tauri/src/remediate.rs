//! The desktop `VaultSink`: persistence for the remediation crate over the
//! live vault [`Handle`](sv_core::VaultHandle) (plan P8, ADR-0019/0020).
//!
//! Everything this sink stores lives in the dedicated `sv-remediate`
//! container, encrypted by the vault like any other container content.
//! References handed back to the remediation crate are opaque random ids —
//! never filesystem paths — so the caller can hold them in plans, records,
//! and the UI without learning vault layout.
//!
//! ## Durability
//!
//! [`VaultSink::append_journal`] is durable before it returns because
//! `Handle::write_file` is: the storage layer writes through a temp file
//! that is `sync_all`ed, persists it, and fsyncs the parent directory
//! (`sv-storage::atomic_write`). Verified against the sv-storage source —
//! not assumed.
//!
//! ## Startup check
//!
//! [`VaultSink::startup_check`] delegates to
//! `sv_remediate::managed::startup_check` and nothing else. This module
//! contains no process-spawning code by construction; a test below guards
//! that property on the source text.

use std::path::{Path, PathBuf};

use sv_audit::AuditAction;
use sv_core::VaultHandle;
use sv_remediate::managed::{startup_check as builtin_startup_check, ConsumerAdapter};
use sv_remediate::{ApplyError, Digest, JournalEntry, PlanItem, RecoveryRecord, VaultSink};

/// The dedicated vault container holding remediation snapshots, recovery
/// records, and the rewrite journal.
const REMEDIATE_CONTAINER: &str = "sv-remediate";

/// The journal file inside the container, one JSON-encoded
/// [`JournalEntry`](sv_remediate::JournalEntry) per line.
const JOURNAL_FILE: &str = "remediate-journal.jsonl";

/// A [`VaultSink`] backed by the live vault handle.
///
/// `root` is the **vault root** (where `audit.jsonl` lives), not a project
/// directory: the sink never touches anything outside the vault. The
/// container is created on first use, mirroring `ensure_scan_container`.
pub struct HandleSink<'a> {
    handle: &'a VaultHandle,
    root: PathBuf,
}

impl<'a> HandleSink<'a> {
    /// Builds a sink over the unlocked vault handle at vault root `root`.
    pub fn new(handle: &'a VaultHandle, root: PathBuf) -> Self {
        HandleSink { handle, root }
    }

    /// Creates the remediation container on first use.
    fn ensure_container(&self) -> Result<(), ApplyError> {
        let info = self
            .handle
            .list_containers()
            .map_err(|error| ApplyError::Sink(format!("container listing failed: {error}")))?;
        if info.iter().any(|c| c.name == REMEDIATE_CONTAINER) {
            return Ok(());
        }
        self.handle
            .create_container(
                REMEDIATE_CONTAINER,
                sv_core::sv_storage::SecurityMode::Direct,
                Some("Remediation snapshots, recovery records, journal".to_string()),
            )
            .map_err(|error| ApplyError::Sink(format!("container creation failed: {error}")))?;
        Ok(())
    }

    /// Mints an opaque reference: random, path-free, unique per snapshot.
    fn opaque_ref() -> Result<String, ApplyError> {
        let bytes = sv_core::sv_crypto::random_bytes(16)
            .map_err(|error| ApplyError::Sink(format!("entropy unavailable: {error}")))?;
        let mut reference = String::with_capacity(3 + bytes.len() * 2);
        reference.push_str("rm-");
        for byte in &bytes {
            reference.push_str(&format!("{byte:02x}"));
        }
        Ok(reference)
    }
}

impl VaultSink for HandleSink<'_> {
    fn store_snapshot(&mut self, _item: &PlanItem, original: &[u8]) -> Result<String, ApplyError> {
        self.ensure_container()?;
        let reference = Self::opaque_ref()?;
        self.handle
            .write_file(REMEDIATE_CONTAINER, &reference, original)
            .map_err(|error| ApplyError::Sink(format!("snapshot write failed: {error}")))?;
        Ok(reference)
    }

    fn store_managed_snapshot(
        &mut self,
        _project_id: &str,
        _path: &Path,
        original: &[u8],
    ) -> Result<String, ApplyError> {
        // Same container, same opaque-reference scheme: the project binding
        // lives in the recovery record, not in the reference.
        self.ensure_container()?;
        let reference = Self::opaque_ref()?;
        self.handle
            .write_file(REMEDIATE_CONTAINER, &reference, original)
            .map_err(|error| ApplyError::Sink(format!("snapshot write failed: {error}")))?;
        Ok(reference)
    }

    fn commit_locator(
        &mut self,
        _item: &PlanItem,
        _snapshot_ref: &str,
    ) -> Result<Option<String>, ApplyError> {
        // Opaque discovery for now (plan P8): no locator is minted, so the
        // recovery record records the opaque form and no marker is written.
        Ok(None)
    }

    fn store_recovery(&mut self, record: &RecoveryRecord) -> Result<(), ApplyError> {
        self.ensure_container()?;
        let name = format!("recovery-{}", record.snapshot_ref);
        let bytes = serde_json::to_vec_pretty(record)?;
        self.handle
            .write_file(REMEDIATE_CONTAINER, &name, &bytes)
            .map_err(|error| ApplyError::Sink(format!("recovery write failed: {error}")))?;
        Ok(())
    }

    fn append_journal(&mut self, entry: JournalEntry) -> Result<(), ApplyError> {
        self.ensure_container()?;
        // Read-modify-write: the vault write path replaces whole files. The
        // write itself is durable before it returns — sv-storage's atomic
        // write fsyncs the temp file and the containing directory — so the
        // journal entry survives a crash the moment this call does.
        let mut journal = self
            .handle
            .read_file(REMEDIATE_CONTAINER, JOURNAL_FILE)
            .unwrap_or_default();
        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        journal.extend_from_slice(&line);
        self.handle
            .write_file(REMEDIATE_CONTAINER, JOURNAL_FILE, &journal)
            .map_err(|error| ApplyError::Sink(format!("journal write failed: {error}")))?;
        Ok(())
    }

    fn load_snapshot(&self, record: &RecoveryRecord) -> Result<Vec<u8>, ApplyError> {
        self.handle
            .read_file(REMEDIATE_CONTAINER, &record.snapshot_ref)
            .map_err(|error| ApplyError::Sink(format!("snapshot read failed: {error}")))
    }

    fn audit(&mut self, action: AuditAction, operation_digest: Digest) -> Result<(), ApplyError> {
        // Mirrors `record_desktop_event`: digest only, never the material.
        let mut event =
            sv_audit::AuditEvent::new(action, sv_audit::AuditDecision::Allowed, "desktop-ui");
        event.detail = Some(hex::encode(operation_digest.as_bytes()));
        let log = sv_audit::AuditLog::with_hmac_key(&self.root, self.handle.audit_hmac_key())
            .map_err(|error| ApplyError::Sink(format!("audit log unavailable: {error}")))?;
        log.record(&event)
            .map_err(|error| ApplyError::Sink(format!("audit record failed: {error}")))?;
        Ok(())
    }

    fn startup_check(
        &self,
        adapter: ConsumerAdapter,
        project_root: &Path,
        manifest_path: &Path,
        consumed_path: &Path,
    ) -> Result<(), ApplyError> {
        // Delegation only: the built-in manifest check, verified against the
        // plan's consumed path. No process, no shell, no renderer-supplied
        // command line.
        builtin_startup_check(adapter, project_root, manifest_path, consumed_path)
            .map_err(|reason| ApplyError::Sink(format!("startup check failed: {reason}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sv_core::CustodyMode;

    fn temp_vault() -> (tempfile::TempDir, VaultHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let boot = sv_core::VaultHandle::bootstrap(
            dir.path(),
            CustodyMode::Passphrase,
            Some("correct horse battery staple"),
        )
        .expect("bootstrap");
        (dir, boot.handle)
    }

    fn sample_record(snapshot_ref: &str, bytes: &[u8]) -> RecoveryRecord {
        use sv_remediate::FileIdentity;
        RecoveryRecord {
            plan_digest: sv_remediate::Digest::from_bytes([1u8; 32]),
            project_id: "proj".to_string(),
            path: PathBuf::from(".env"),
            identity: FileIdentity::Unix {
                device: 0,
                inode: 0,
            },
            snapshot_digest: test_digest(bytes),
            snapshot_ref: snapshot_ref.to_string(),
            discovery: sv_remediate::DiscoveryPolicy::Opaque,
            locator: None,
            span: None,
            replacement: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn test_digest(bytes: &[u8]) -> sv_remediate::Digest {
        let key = sv_remediate::PlanKey::from_bytes(&[7u8; 32]).expect("key");
        sv_remediate::keyed_digest(&key, bytes)
    }

    #[test]
    fn snapshot_roundtrips_through_the_sink() {
        let (dir, handle) = temp_vault();
        let root = dir.path().to_path_buf();
        let mut sink = HandleSink::new(&handle, root);

        let original = b"API_KEY=round-trip\n".to_vec();
        let reference = sink
            .store_managed_snapshot("proj", Path::new(".env"), &original)
            .expect("store managed snapshot");

        // The reference is opaque: not a path, not the container name.
        assert!(reference.starts_with("rm-"));
        assert!(!reference.contains('\\') && !reference.contains('/'));

        let record = sample_record(&reference, &original);
        sink.store_recovery(&record).expect("store recovery");
        let loaded = sink.load_snapshot(&record).expect("load snapshot");
        assert_eq!(loaded, original);

        // Journal entries land in the container and parse back.
        sink.append_journal(JournalEntry {
            path: PathBuf::from(".env"),
            state: sv_remediate::JournalState::VaultStored { locator: None },
            at: chrono::Utc::now(),
        })
        .expect("append journal");
        sink.append_journal(JournalEntry {
            path: PathBuf::from(".env"),
            state: sv_remediate::JournalState::FileReplaced,
            at: chrono::Utc::now(),
        })
        .expect("append journal");
        let journal = handle
            .read_file(REMEDIATE_CONTAINER, JOURNAL_FILE)
            .expect("journal readable through the vault");
        let lines: Vec<&[u8]> = journal
            .split(|&b| b == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 2, "one JSONL line per entry");
        let first: JournalEntry = serde_json::from_slice(lines[0]).expect("entry parses");
        assert_eq!(first.path, PathBuf::from(".env"));
    }

    /// P8.4: the sink must not spawn anything. Asserted by construction on
    /// the module source, in the same spirit as sv-remediate's write guard.
    /// The needles are assembled at runtime so this test's own source does
    /// not contain them contiguously.
    #[test]
    fn module_contains_no_process_spawning() {
        let source = include_str!("remediate.rs");
        let process_import = format!("std::{}", "process");
        let command_construction = format!("{}::{}", "Command", "new");
        assert!(
            !source.contains(&process_import),
            "the desktop sink must never import the process std module"
        );
        assert!(
            !source.contains(&command_construction),
            "the desktop sink must never construct a process command"
        );
    }
}
