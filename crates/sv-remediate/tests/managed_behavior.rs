//! Behavior tests for whole-file ingestion (ADR-0020). Everything runs
//! against tempdirs — never the real repository. Compiled only with the
//! `apply` feature.
#![cfg(feature = "apply")]

use std::fs;
use std::path::{Path, PathBuf};

use sv_audit::AuditAction;
use sv_remediate::{
    detect_unexpected_plaintext, ingest_managed_file, ApplyError, ConsumerAdapter,
    IdentityAssurance, JournalState, ManagedFilePlan, ManagedIngestStatus, PermissionSnapshot,
    PlaintextStatus, PlanKey, SharedBinding, TempMaterial, VaultSink,
};

const ENV_BODY: &str = "DATABASE_URL=postgres://localhost/app\nAPI_KEY=assemble-me-elsewhere\n";

struct MemSink {
    fail_startup: bool,
    snapshots: Vec<(String, Vec<u8>)>,
    recoveries: Vec<sv_remediate::RecoveryRecord>,
    journal: Vec<JournalState>,
    audits: Vec<AuditAction>,
    counter: usize,
}

impl MemSink {
    fn new() -> Self {
        MemSink {
            fail_startup: false,
            snapshots: Vec::new(),
            recoveries: Vec::new(),
            journal: Vec::new(),
            audits: Vec::new(),
            counter: 0,
        }
    }

    /// Simulates the vault removing one managed record (revocation), so a
    /// test can prove that removing project A's record leaves project B's
    /// intact.
    fn remove_snapshot(&mut self, reference: &str) {
        self.snapshots.retain(|(r, _)| r != reference);
    }
}

impl VaultSink for MemSink {
    fn store_snapshot(
        &mut self,
        _item: &sv_remediate::PlanItem,
        _original: &[u8],
    ) -> Result<String, ApplyError> {
        Err(ApplyError::Sink("span path unused here".to_string()))
    }

    fn commit_locator(
        &mut self,
        _item: &sv_remediate::PlanItem,
        _snapshot_ref: &str,
    ) -> Result<Option<String>, ApplyError> {
        Ok(None)
    }

    fn store_recovery(&mut self, record: &sv_remediate::RecoveryRecord) -> Result<(), ApplyError> {
        self.recoveries.push(record.clone());
        Ok(())
    }

    fn append_journal(&mut self, entry: sv_remediate::JournalEntry) -> Result<(), ApplyError> {
        self.journal.push(entry.state);
        Ok(())
    }

    fn load_snapshot(&self, record: &sv_remediate::RecoveryRecord) -> Result<Vec<u8>, ApplyError> {
        self.snapshots
            .iter()
            .find(|(reference, _)| *reference == record.snapshot_ref)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| ApplyError::Sink("unknown snapshot".to_string()))
    }

    fn audit(
        &mut self,
        action: AuditAction,
        _operation_digest: sv_remediate::Digest,
    ) -> Result<(), ApplyError> {
        self.audits.push(action);
        Ok(())
    }

    fn store_managed_snapshot(
        &mut self,
        _project_id: &str,
        _path: &Path,
        original: &[u8],
    ) -> Result<String, ApplyError> {
        self.counter += 1;
        let reference = format!("managed-snap-{}", self.counter);
        self.snapshots.push((reference.clone(), original.to_vec()));
        Ok(reference)
    }

    fn startup_check(
        &self,
        _adapter: ConsumerAdapter,
        _project_root: &Path,
        _manifest_path: &Path,
    ) -> Result<(), ApplyError> {
        if self.fail_startup {
            return Err(ApplyError::Sink(
                "the project failed to start without the file".to_string(),
            ));
        }
        Ok(())
    }
}

fn write_env(dir: &Path) -> PathBuf {
    let file = dir.join(".env");
    fs::write(&file, ENV_BODY).expect("fixture");
    file
}

/// Full enforcement on platforms that can capture identity (Unix); the
/// explicit acknowledgement on Windows.
fn platform_assurance() -> IdentityAssurance {
    if cfg!(windows) {
        IdentityAssurance::AcknowledgedUnavailable
    } else {
        IdentityAssurance::Enforced
    }
}

fn plan_for(dir: &Path, key: &PlanKey) -> ManagedFilePlan {
    ManagedFilePlan::build(
        "proj",
        Path::new(".env"),
        dir,
        ConsumerAdapter::EnvInjection,
        Path::new(".sv/managed/.env.manifest.json"),
        SharedBinding::Independent,
        key,
    )
    .expect("plan")
}

#[test]
fn env_is_ingested_and_the_original_removed_with_a_manifest_left_behind() {
    let dir = tempfile::tempdir().unwrap();
    write_env(dir.path());
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    let plan = plan_for(dir.path(), &key);

    let mut sink = MemSink::new();
    let outcome = ingest_managed_file(&plan, dir.path(), &key, platform_assurance(), &mut sink)
        .expect("ingest");
    let manifest_path = match outcome {
        ManagedIngestStatus::Ingested { manifest } => manifest,
        other => panic!("expected Ingested, got {other:?}"),
    };
    assert_eq!(
        manifest_path,
        PathBuf::from(".sv/managed/.env.manifest.json")
    );

    // The original is gone from the consumed path.
    assert!(!dir.path().join(".env").exists());
    // The manifest exists — somewhere the consumer does NOT read.
    let manifest_file = dir.path().join(&manifest_path);
    assert!(manifest_file.exists());
    let raw = fs::read_to_string(&manifest_file).unwrap();
    assert!(raw.contains("\"env-injection\""));
    assert!(!raw.contains("API_KEY"), "manifest must be non-secret");

    // Journal: vault side committed, then done. Recovery + audit recorded.
    assert_eq!(
        sink.journal,
        vec![
            JournalState::VaultStored { locator: None },
            JournalState::FileReplaced
        ]
    );
    assert_eq!(sink.recoveries.len(), 1);
    assert_eq!(sink.audits, vec![AuditAction::PlanExecute]);
}

#[test]
fn a_failing_startup_check_keeps_the_original_and_cleans_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    write_env(dir.path());
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    let plan = plan_for(dir.path(), &key);

    let mut sink = MemSink::new();
    sink.fail_startup = true;
    let outcome = ingest_managed_file(&plan, dir.path(), &key, platform_assurance(), &mut sink)
        .expect("ingest");
    match &outcome {
        ManagedIngestStatus::StartupCheckFailed { reason } => {
            // The status itself is what carries "the startup check refused
            // this"; the reason is the adapter's own words, passed through
            // verbatim rather than reworded, so assert on that text.
            assert!(
                reason.contains("failed to start"),
                "adapter reason should be surfaced verbatim, got {reason}"
            );
        }
        other => panic!("expected StartupCheckFailed, got {other:?}"),
    }
    // The removal was REFUSED: the original is still there.
    assert!(dir.path().join(".env").exists());
    // The manifest was cleaned up so no stale instructions remain.
    assert!(!dir.path().join(".sv/managed/.env.manifest.json").exists());
    // The vault side is committed: the run is resumable, not lost.
    assert_eq!(
        sink.journal,
        vec![JournalState::VaultStored { locator: None }]
    );
}

#[test]
fn a_partly_sensitive_file_is_refused_for_whole_file_ingestion() {
    let dir = tempfile::tempdir().unwrap();
    // A docker-compose.yml: four keys among legitimate configuration.
    let compose = dir.path().join("docker-compose.yml");
    fs::write(
        &compose,
        "services:\n  db:\n    image: postgres:16\n    ports: [\"5432:5432\"]\n\
         environment:\n      API_KEY: k1\n      DB_PASS: k2\n      SECRET: k3\n      TOKEN: k4\n\
         volumes:\n      - pgdata:/var/lib/postgresql/data\n",
    )
    .unwrap();
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    let error = ManagedFilePlan::build(
        "proj",
        Path::new("docker-compose.yml"),
        dir.path(),
        ConsumerAdapter::EnvInjection,
        Path::new(".sv/managed/compose.manifest.json"),
        SharedBinding::Independent,
        &key,
    )
    .expect_err("partly-sensitive file must be refused");
    assert!(error.to_string().contains("not eligible"), "{error}");
    // The file is untouched — it routes through span redaction instead.
    assert!(compose.exists());
}

#[test]
fn a_manifest_at_the_consumed_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    write_env(dir.path());
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    let error = ManagedFilePlan::build(
        "proj",
        Path::new(".env"),
        dir.path(),
        ConsumerAdapter::EnvInjection,
        Path::new(".env"),
        SharedBinding::Independent,
        &key,
    )
    .expect_err("manifest must not live at the consumed path");
    assert!(error.to_string().contains("manifest"), "{error}");
}

#[test]
fn re_created_plaintext_is_detected_at_launch_time() {
    let dir = tempfile::tempdir().unwrap();
    write_env(dir.path());
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    let plan = plan_for(dir.path(), &key);
    let mut sink = MemSink::new();
    ingest_managed_file(&plan, dir.path(), &key, platform_assurance(), &mut sink).expect("ingest");
    assert_eq!(
        detect_unexpected_plaintext(dir.path(), Path::new(".env")),
        PlaintextStatus::Clear
    );

    // The user's own tooling puts plaintext back; detection runs after the
    // fact — nothing prevented the write, and nothing here claims to.
    fs::write(dir.path().join(".env"), "API_KEY=back-again\n").unwrap();
    assert_eq!(
        detect_unexpected_plaintext(dir.path(), Path::new(".env")),
        PlaintextStatus::UnexpectedPlaintext
    );
}

#[test]
fn content_changed_since_the_plan_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    write_env(dir.path());
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    let plan = plan_for(dir.path(), &key);
    // Mutate AFTER the plan was built.
    fs::write(dir.path().join(".env"), "API_KEY=different\n").unwrap();

    let mut sink = MemSink::new();
    let outcome = ingest_managed_file(&plan, dir.path(), &key, platform_assurance(), &mut sink)
        .expect("ingest");
    assert!(matches!(outcome, ManagedIngestStatus::Failed { .. }));
    // The file was not removed on a failed check.
    assert!(dir.path().join(".env").exists());
    assert!(sink.snapshots.is_empty());
}

#[test]
fn temp_material_is_restricted_and_cleaned_up() {
    let material = TempMaterial::materialize(ENV_BODY.as_bytes()).expect("materialize");
    let path = material.path().to_path_buf();
    assert!(path.exists());
    let metadata = fs::metadata(&path).unwrap();
    let permissions = PermissionSnapshot::capture(&metadata.permissions());
    #[cfg(unix)]
    assert_eq!(
        permissions.unix_mode,
        Some(0o600),
        "temp material is user-only"
    );
    assert!(!permissions.readonly);
    drop(material);
    assert!(!path.exists(), "cleanup on drop");
}

#[test]
fn two_projects_with_identical_envs_ingest_independently() {
    // ADR-0020 §5 in end-to-end miniature: the same .env bytes in two
    // project directories produce two independent ingests with two
    // The same .env bytes in two project directories: one vault, two
    // ingests, two managed records. Storage dedup (identical bytes) never
    // implies shared authorization.
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    write_env(dir_a.path());
    write_env(dir_b.path());
    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();

    let plan_a = ManagedFilePlan::build(
        "proj-a",
        Path::new(".env"),
        dir_a.path(),
        ConsumerAdapter::EnvInjection,
        Path::new(".sv/managed/.env.manifest.json"),
        SharedBinding::Independent,
        &key,
    )
    .unwrap();
    let plan_b = ManagedFilePlan::build(
        "proj-b",
        Path::new(".env"),
        dir_b.path(),
        ConsumerAdapter::EnvInjection,
        Path::new(".sv/managed/.env.manifest.json"),
        SharedBinding::Independent,
        &key,
    )
    .unwrap();

    assert_ne!(
        plan_a.snapshot_digest,
        sv_remediate::keyed_digest(
            &PlanKey::from_bytes(&[99u8; 32]).unwrap(),
            ENV_BODY.as_bytes()
        )
    );
    assert_eq!(
        plan_a.snapshot_digest, plan_b.snapshot_digest,
        "the bytes are identical — dedup would store them once"
    );

    // ONE sink, because there is one vault. Two sinks would each mint
    // "managed-snap-1" from their own counter, so comparing references
    // across them would prove nothing about authorization independence.
    let mut sink = MemSink::new();
    ingest_managed_file(&plan_a, dir_a.path(), &key, platform_assurance(), &mut sink)
        .expect("ingest a");
    ingest_managed_file(&plan_b, dir_b.path(), &key, platform_assurance(), &mut sink)
        .expect("ingest b");

    // Byte-identical files, but TWO stored snapshots under two distinct
    // references: dedup at the storage layer must never collapse two
    // authorization decisions into one.
    assert_eq!(sink.snapshots.len(), 2, "one record per project");
    assert_ne!(
        sink.snapshots[0].0, sink.snapshots[1].0,
        "identical bytes must still yield distinct managed records"
    );
    assert_eq!(
        sink.snapshots[0].1, sink.snapshots[1].1,
        "the stored bytes really are identical — that is the point"
    );

    // Each project derives its own authorization record. Identical content
    // digests, but distinct resource ids: dedup never collapses authority.
    let record_a = sv_remediate::authorization_record(
        "proj-a",
        plan_a.snapshot_digest,
        &SharedBinding::Independent,
    );
    let record_b = sv_remediate::authorization_record(
        "proj-b",
        plan_b.snapshot_digest,
        &SharedBinding::Independent,
    );
    assert_eq!(record_a.content_digest, record_b.content_digest);
    assert_ne!(
        record_a.resource_id, record_b.resource_id,
        "identical bytes must still yield two authorization resources"
    );
    assert_eq!(record_a.project_id, "proj-a");
    assert_eq!(record_b.project_id, "proj-b");
    assert!(record_a.binding_id.is_none());

    // The vault-side recovery records carry the same per-project bindings.
    assert_eq!(sink.recoveries.len(), 2);
    assert_eq!(sink.recoveries[0].project_id, "proj-a");
    assert_eq!(sink.recoveries[1].project_id, "proj-b");
    assert_eq!(sink.recoveries[0].snapshot_ref, sink.snapshots[0].0);
    assert_eq!(sink.recoveries[1].snapshot_ref, sink.snapshots[1].0);

    // Revoking/removing project A's record leaves project B's intact and
    // usable: independence is the guarantee, not an accident of the fake.
    let reference_a = sink.snapshots[0].0.clone();
    sink.remove_snapshot(&reference_a);
    assert!(
        sink.load_snapshot(&sink.recoveries[0]).is_err(),
        "project A's record must be gone after removal"
    );
    assert_eq!(
        sink.load_snapshot(&sink.recoveries[1])
            .expect("project B intact"),
        ENV_BODY.as_bytes(),
        "project B's record is untouched"
    );

    // An Independent binding means rotating one project's material touches
    // exactly that project — never the other, even though both hold the
    // same bytes.
    let remaining = [record_a, record_b];
    assert_eq!(
        sv_remediate::rotation_blast_radius(&remaining, &SharedBinding::Independent),
        1
    );
}

/// Identity enforcement applies to managed files too: a different file with
/// identical bytes at the planned path is refused where the platform can
/// capture identity.
#[test]
#[cfg(unix)]
fn swapped_file_with_identical_bytes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file_a = dir.path().join(".env");
    let file_b = dir.path().join("other.env");
    fs::write(&file_a, ENV_BODY).unwrap();
    fs::write(&file_b, ENV_BODY).unwrap();
    let identity_b = sv_remediate::FileIdentity::capture_from_path(&file_b).unwrap();

    let key = PlanKey::from_bytes(&[7u8; 32]).unwrap();
    // Build the plan normally (identity of file A), then swap the recorded
    // identity to file B's: the same bytes, a different file.
    let mut plan = plan_for(dir.path(), &key);
    plan.identity = identity_b;

    let mut sink = MemSink::new();
    let outcome = ingest_managed_file(&plan, dir.path(), &key, platform_assurance(), &mut sink)
        .expect("ingest");
    assert!(matches!(outcome, ManagedIngestStatus::Failed { .. }));
    assert!(file_a.exists(), "nothing was removed");
}
