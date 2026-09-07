//! Behavior tests for the destructive path. Everything runs against
//! tempdirs — never the real repository.
//!
//! This file is compiled only with the `apply` feature; with the default
//! feature set it is empty and the crate has no write path at all.
#![cfg(feature = "apply")]

use std::fs;
use std::path::{Path, PathBuf};

use sv_audit::AuditAction;
use sv_remediate::{
    execute, restore, resume, ApplyError, ApplyMode, ByteSpan, FileApplyStatus, FileIdentity,
    IdentityAssurance, JournalEntry, JournalState, PlanItem, PlanItemDraft, PlanKey,
    RecoveryRecord, RestoreOutcome, RewriteJournal, RewritePlan, RulePin, VaultSink,
};
use sv_runtime::references::PublicLocator;
use tempfile::TempDir;

const PREFIX: &str = "aws = ";
const BODY: &str = "IOSFODNN7EXAMPLE";

/// Assembled at runtime so this test source never contains a complete
/// example credential.
fn token() -> String {
    format!("AKIA{BODY}")
}

fn content() -> String {
    format!("{PREFIX}{}\n", token())
}

fn marker() -> String {
    PublicLocator::generate().expect("csprng").to_external()
}

/// The assurance a well-behaved caller passes on this platform: full
/// enforcement where identity is obtainable (Unix), the explicit
/// acknowledgement where it is not (Windows).
fn platform_assurance() -> IdentityAssurance {
    if cfg!(windows) {
        IdentityAssurance::AcknowledgedUnavailable
    } else {
        IdentityAssurance::Enforced
    }
}

/// Identity for a fixture file: real where the platform can capture one,
/// a portable placeholder where it cannot (the apply layer then leans on
/// the digests, per the acknowledged gap).
fn identity_of(file: &Path) -> FileIdentity {
    match FileIdentity::capture_from_path(file) {
        Ok(identity) => identity,
        Err(_) => FileIdentity::Windows {
            volume: 0,
            index: 0,
        },
    }
}

struct MemSink {
    fail_store: bool,
    fail_recovery: bool,
    fail_startup: bool,
    fail_journal_call: Option<usize>,
    journal_calls: usize,
    snapshots: Vec<(String, Vec<u8>)>,
    recoveries: Vec<RecoveryRecord>,
    journal: Vec<JournalEntry>,
    audits: Vec<(AuditAction, sv_remediate::Digest)>,
    snapshot_counter: usize,
}

impl MemSink {
    fn new() -> Self {
        MemSink {
            fail_store: false,
            fail_recovery: false,
            fail_startup: false,
            fail_journal_call: None,
            journal_calls: 0,
            snapshots: Vec::new(),
            recoveries: Vec::new(),
            journal: Vec::new(),
            audits: Vec::new(),
            snapshot_counter: 0,
        }
    }
}

impl VaultSink for MemSink {
    fn store_snapshot(&mut self, _item: &PlanItem, original: &[u8]) -> Result<String, ApplyError> {
        if self.fail_store {
            return Err(ApplyError::Sink("store refused".to_string()));
        }
        self.snapshot_counter += 1;
        let reference = format!("snap-{}", self.snapshot_counter);
        self.snapshots.push((reference.clone(), original.to_vec()));
        Ok(reference)
    }

    fn commit_locator(
        &mut self,
        item: &PlanItem,
        _snapshot_ref: &str,
    ) -> Result<Option<String>, ApplyError> {
        // Registers the exact marker the plan carries, when it is one.
        if sv_remediate::is_marker(&item.replacement) {
            Ok(Some(item.replacement.clone()))
        } else {
            Ok(None)
        }
    }

    fn store_recovery(&mut self, record: &RecoveryRecord) -> Result<(), ApplyError> {
        if self.fail_recovery {
            return Err(ApplyError::Sink("recovery refused".to_string()));
        }
        self.recoveries.push(record.clone());
        Ok(())
    }

    fn append_journal(&mut self, entry: JournalEntry) -> Result<(), ApplyError> {
        self.journal_calls += 1;
        if self.fail_journal_call == Some(self.journal_calls) {
            return Err(ApplyError::Sink("journal refused".to_string()));
        }
        self.journal.push(entry);
        Ok(())
    }

    fn load_snapshot(&self, record: &RecoveryRecord) -> Result<Vec<u8>, ApplyError> {
        self.snapshots
            .iter()
            .find(|(reference, _)| *reference == record.snapshot_ref)
            .map(|(_, bytes)| bytes.clone())
            .ok_or_else(|| ApplyError::Sink("unknown snapshot".to_string()))
    }

    fn audit(
        &mut self,
        action: AuditAction,
        operation_digest: sv_remediate::Digest,
    ) -> Result<(), ApplyError> {
        self.audits.push((action, operation_digest));
        Ok(())
    }

    fn store_managed_snapshot(
        &mut self,
        project_id: &str,
        path: &std::path::Path,
        original: &[u8],
    ) -> Result<String, ApplyError> {
        if self.fail_store {
            return Err(ApplyError::Sink("managed store refused".to_string()));
        }
        self.snapshot_counter += 1;
        let reference = format!("managed-snap-{}", self.snapshot_counter);
        self.snapshots.push((reference.clone(), original.to_vec()));
        let _ = (project_id, path);
        Ok(reference)
    }

    fn startup_check(
        &self,
        _adapter: sv_remediate::ConsumerAdapter,
        _project_root: &std::path::Path,
        _manifest_path: &std::path::Path,
    ) -> Result<(), ApplyError> {
        if self.fail_startup {
            return Err(ApplyError::Sink("startup check failed".to_string()));
        }
        Ok(())
    }
}

/// Creates a tempdir project with one sensitive file, an approved plan with
/// one item (replacement = a real locator marker), and the key.
fn setup() -> (TempDir, PathBuf, PlanItem, RewritePlan, PlanKey, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = content();
    let file = dir.path().join("a.env");
    fs::write(&file, &content).expect("write fixture");

    let key = PlanKey::from_bytes(&[7u8; 32]).expect("key");
    let identity = identity_of(&file);
    let start = PREFIX.len();
    let end = start + token().len();
    let replacement = marker();
    let item = PlanItem::build(
        PlanItemDraft {
            project_id: "proj".to_string(),
            path: PathBuf::from("a.env"),
            identity,
            source: content.clone(),
            span: ByteSpan::new(start, end).expect("span"),
            replacement: replacement.clone(),
            kind: sv_scan::FindingKind::Secret {
                rule_id: "aws_access_key_id".to_string(),
            },
            rule_pin: RulePin::scan_baseline(),
        },
        &key,
    )
    .expect("item");
    let plan = RewritePlan::build(vec![item.clone()], &key).expect("plan");
    (dir, file, item, plan, key, replacement)
}

#[test]
fn dry_run_reports_without_writing_or_touching_the_sink() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::DryRun,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("dry run");
    assert_eq!(outcome.mode, ApplyMode::DryRun);
    assert_eq!(outcome.results[0].status, FileApplyStatus::DryRun);
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(!fs::read_to_string(&file).unwrap().contains(&replacement));
    assert!(sink.journal.is_empty());
    assert!(sink.snapshots.is_empty());
    assert!(sink.recoveries.is_empty());
    assert!(sink.audits.is_empty());
}

#[test]
fn commit_runs_the_full_pipeline_in_order() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("commit");
    assert_eq!(
        outcome.results[0].status,
        FileApplyStatus::Applied {
            locator: Some(replacement.clone())
        }
    );
    // The file now carries the marker, and only that.
    let after = fs::read_to_string(&file).unwrap();
    assert_eq!(after, format!("{PREFIX}{replacement}\n"));
    // Journal: in-progress, then done.
    assert_eq!(sink.journal.len(), 2);
    assert_eq!(
        sink.journal[0].state,
        JournalState::VaultStored {
            locator: Some(replacement.clone())
        }
    );
    assert_eq!(sink.journal[1].state, JournalState::FileReplaced);
    // Vault side: snapshot, recovery, locator, audit.
    assert_eq!(sink.snapshots.len(), 1);
    assert_eq!(sink.recoveries.len(), 1);
    assert!(sink.recoveries[0].locator_consistent());
    assert_eq!(sink.audits, vec![(AuditAction::PlanExecute, plan.digest())]);
}

#[test]
fn a_file_modified_between_plan_and_apply_is_stale_and_untouched() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    fs::write(&file, "# edited after the scan\n").expect("modify");
    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("commit");
    assert_eq!(outcome.results[0].status, FileApplyStatus::Stale);
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "# edited after the scan\n"
    );
    assert!(sink.snapshots.is_empty(), "nothing reaches the vault");
    assert!(sink.journal.is_empty());
}

#[test]
fn a_store_failure_leaves_the_file_untouched() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    let mut sink = MemSink::new();
    sink.fail_store = true;
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert!(matches!(
        outcome.results[0].status,
        FileApplyStatus::Failed { .. }
    ));
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(sink.recoveries.is_empty(), "no recovery without a snapshot");
    assert!(sink.journal.is_empty());
}

#[test]
fn a_recovery_failure_leaves_the_file_untouched() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    let mut sink = MemSink::new();
    sink.fail_recovery = true;
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert!(matches!(
        outcome.results[0].status,
        FileApplyStatus::Failed { .. }
    ));
    assert_eq!(sink.snapshots.len(), 1, "the snapshot landed");
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(sink.journal.is_empty());
}

#[test]
fn a_journal_failure_before_the_replace_leaves_the_file_untouched() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    let mut sink = MemSink::new();
    sink.fail_journal_call = Some(1);
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert!(matches!(
        outcome.results[0].status,
        FileApplyStatus::Failed { .. }
    ));
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert_eq!(sink.journal.len(), 0);
}

/// The crash window: vault side committed (steps b–d), file not yet
/// replaced. The journal shows in-progress; a resume completes the run
/// without duplicating vault work.
#[test]
fn interrupted_after_the_vault_side_resumes_to_completion() {
    let (dir, file, item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    sink.fail_journal_call = Some(1);
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert!(matches!(
        outcome.results[0].status,
        FileApplyStatus::Failed { .. }
    ));
    assert_eq!(fs::read_to_string(&file).unwrap(), content());

    // The in-progress entry is what a crashed process leaves behind when
    // the append reached durable storage before the process died.
    sink.journal.push(JournalEntry {
        path: item.path.clone(),
        state: JournalState::VaultStored {
            locator: Some(replacement.clone()),
        },
        at: chrono::Utc::now(),
    });
    let journal = RewriteJournal {
        plan_digest: plan.digest(),
        project_id: "proj".to_string(),
        entries: sink.journal.clone(),
    };

    sink.fail_journal_call = None;
    let snapshots_before = sink.snapshots.len();
    let recoveries_before = sink.recoveries.len();
    let resumed = resume(
        &plan,
        &journal,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("resume");
    assert_eq!(
        resumed.results[0].status,
        FileApplyStatus::Applied {
            locator: Some(replacement.clone())
        }
    );
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        format!("{PREFIX}{replacement}\n")
    );
    // Resume did not duplicate the vault side.
    assert_eq!(sink.snapshots.len(), snapshots_before);
    assert_eq!(sink.recoveries.len(), recoveries_before);
    assert_eq!(
        sink.journal.last().unwrap().state,
        JournalState::FileReplaced
    );
}

/// On Windows, replacing a read-only target fails — a real interruption
/// between the journal's in-progress entry and the replace. Making the file
/// writable and resuming completes the run.
#[test]
#[cfg(windows)]
// `set_readonly(false)` is the Windows API for clearing the attribute; the
// clippy suggestion (PermissionsExt) is Unix-only.
#[allow(clippy::permissions_set_readonly_false)]
fn readonly_target_fails_then_resume_completes() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut perms = fs::metadata(&file).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&file, perms).expect("readonly");

    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert!(matches!(
        outcome.results[0].status,
        FileApplyStatus::Failed { .. }
    ));
    // The journal shows in-progress: vault side committed, file untouched.
    assert_eq!(sink.journal.len(), 1);
    assert_eq!(
        sink.journal[0].state,
        JournalState::VaultStored {
            locator: Some(replacement.clone())
        }
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), content());

    let mut perms = fs::metadata(&file).unwrap().permissions();
    perms.set_readonly(false);
    fs::set_permissions(&file, perms).expect("writable");

    let journal = RewriteJournal {
        plan_digest: plan.digest(),
        project_id: "proj".to_string(),
        entries: sink.journal.clone(),
    };
    let resumed = resume(
        &plan,
        &journal,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("resume");
    assert_eq!(
        resumed.results[0].status,
        FileApplyStatus::Applied {
            locator: Some(replacement.clone())
        }
    );
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        format!("{PREFIX}{replacement}\n")
    );
}

/// ADR-0017 §4: a marker is never re-redacted. The second pass fails
/// verification (the file changed) and writes nothing.
#[test]
fn a_second_pass_does_not_re_redact_a_marker() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("first pass");
    let snapshots_after_first = sink.snapshots.len();

    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("second pass");
    assert_eq!(outcome.results[0].status, FileApplyStatus::Stale);
    let after = fs::read_to_string(&file).unwrap();
    assert_eq!(after.matches(&replacement).count(), 1, "exactly one marker");
    assert_eq!(sink.snapshots.len(), snapshots_after_first);
}

#[test]
fn restore_returns_historical_bytes_and_journals_the_rollback() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("commit");
    let record = sink.recoveries[0].clone();

    let outcome = restore(&record, dir.path(), platform_assurance(), &mut sink).expect("restore");
    let sv_remediate::RestoreOutcome::Restored { bytes } = outcome else {
        panic!("expected a clean restore, got {outcome:?}");
    };
    assert_eq!(bytes, content().as_bytes());
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(!fs::read_to_string(&file).unwrap().contains(&replacement));
    assert_eq!(sink.journal.last().unwrap().state, JournalState::RolledBack);
    assert_eq!(
        sink.audits.last(),
        Some(&(AuditAction::RedactionRestore, record.snapshot_digest))
    );
}

#[test]
fn restore_refuses_when_the_destination_diverged() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("commit");
    let record = sink.recoveries[0].clone();

    // Someone edited the rewritten file after the fact.
    fs::write(&file, format!("{PREFIX}{replacement}\nextra = 1\n")).expect("diverge");

    let outcome =
        restore(&record, dir.path(), platform_assurance(), &mut sink).expect("restore call");
    assert_eq!(outcome, RestoreOutcome::Conflict);
    // The diverged content is untouched: nothing was silently overwritten.
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        format!("{PREFIX}{replacement}\nextra = 1\n")
    );
}

#[test]
fn permissions_survive_the_replace() {
    let (dir, file, _item, plan, key, _replacement) = setup();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let before = fs::metadata(&file).unwrap().permissions();

    let mut sink = MemSink::new();
    execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("commit");

    let after = fs::metadata(&file).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(after.mode() & 0o777, 0o600, "mode bits must be preserved");
    }
    assert_eq!(
        after.readonly(),
        before.readonly(),
        "readonly attribute must be preserved"
    );
}

/// The identity check is real on platforms that can capture identity
/// (Unix): a different file with IDENTICAL bytes is rejected where the
/// digest alone would pass. On Windows the equivalent guarantee is the
/// refusal test below — capture is impossible there, so a Commit either
/// refuses or runs under an explicit acknowledgement.
#[test]
#[cfg(unix)]
fn identical_bytes_under_a_different_identity_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let content = content();
    let file_a = dir.path().join("a.env");
    let file_b = dir.path().join("b.env");
    fs::write(&file_a, &content).expect("a");
    fs::write(&file_b, &content).expect("b");

    let key = PlanKey::from_bytes(&[7u8; 32]).expect("key");
    // Plan pins file A's path but file B's identity: the swapped-file case.
    let identity_b = FileIdentity::capture_from_path(&file_b).expect("identity b");
    let start = PREFIX.len();
    let item = PlanItem::build(
        PlanItemDraft {
            project_id: "proj".to_string(),
            path: PathBuf::from("a.env"),
            identity: identity_b,
            source: content.clone(),
            span: ByteSpan::new(start, start + token().len()).expect("span"),
            replacement: marker(),
            kind: sv_scan::FindingKind::Secret {
                rule_id: "aws_access_key_id".to_string(),
            },
            rule_pin: RulePin::scan_baseline(),
        },
        &key,
    )
    .expect("item");
    let plan = RewritePlan::build(vec![item], &key).expect("plan");

    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert_eq!(outcome.results[0].status, FileApplyStatus::Stale);
    assert_eq!(fs::read_to_string(&file_a).unwrap(), content);
    assert!(sink.snapshots.is_empty());
}

/// ADR-0019 §2: the pinned detector must re-run. A plan pinned to a
/// detector version that is not the one on this machine cannot be verified,
/// so the commit refuses — loudly, and without writing.
#[test]
fn a_detector_version_drift_refuses_the_commit() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    // Rebuild the plan against an item pinned to a phantom version.
    let key2 = PlanKey::from_bytes(&[7u8; 32]).expect("key");
    let drifted_item = PlanItem {
        rule_pin: RulePin {
            detector_version: "0.0.0-phantom".to_string(),
            pack_id: "sv-scan/baseline".to_string(),
            pack_version: "0.0.0-phantom".to_string(),
        },
        ..plan.items()[0].clone()
    };
    let drifted_plan = RewritePlan::build(vec![drifted_item], &key2).expect("plan");

    let mut sink = MemSink::new();
    let outcome = execute(
        &drifted_plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    match &outcome.results[0].status {
        FileApplyStatus::Failed { reason } => {
            assert!(reason.contains("pinned detector"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(sink.snapshots.is_empty());
}

#[test]
fn resume_rejects_a_journal_from_another_plan() {
    let (dir, _file, _item, plan, key, _replacement) = setup();
    let journal = RewriteJournal {
        plan_digest: sv_remediate::keyed_digest(&key, b"some other plan"),
        project_id: "proj".to_string(),
        entries: Vec::new(),
    };
    let mut sink = MemSink::new();
    let error = resume(
        &plan,
        &journal,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect_err("journal mismatch");
    assert!(matches!(error, ApplyError::JournalMismatch));
}

#[test]
fn resume_skips_files_already_replaced() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("commit");

    let journal = RewriteJournal {
        plan_digest: plan.digest(),
        project_id: "proj".to_string(),
        entries: sink.journal.clone(),
    };
    let snapshots_before = sink.snapshots.len();
    let resumed = resume(
        &plan,
        &journal,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("resume");
    assert_eq!(resumed.results[0].status, FileApplyStatus::AlreadyReplaced);
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        format!("{PREFIX}{replacement}\n")
    );
    assert_eq!(sink.snapshots.len(), snapshots_before, "no duplicate work");
}

#[test]
fn commit_reports_multiple_files_independently() {
    // Two files in one project: one healthy, one modified after the plan.
    // The run is not transactional: the healthy file is applied, the stale
    // one is reported, and the journal reflects exactly what happened.
    let dir = tempfile::tempdir().expect("tempdir");
    let key = PlanKey::from_bytes(&[7u8; 32]).expect("key");
    let replacement = marker();

    let good = dir.path().join("good.env");
    let bad = dir.path().join("bad.env");
    fs::write(&good, content()).expect("good");
    fs::write(&bad, content()).expect("bad");

    let mut items = Vec::new();
    for name in ["good.env", "bad.env"] {
        let path = dir.path().join(name);
        let identity = identity_of(&path);
        let start = PREFIX.len();
        items.push(
            PlanItem::build(
                PlanItemDraft {
                    project_id: "proj".to_string(),
                    path: PathBuf::from(name),
                    identity,
                    source: content(),
                    span: ByteSpan::new(start, start + token().len()).expect("span"),
                    replacement: replacement.clone(),
                    kind: sv_scan::FindingKind::Secret {
                        rule_id: "aws_access_key_id".to_string(),
                    },
                    rule_pin: RulePin::scan_baseline(),
                },
                &key,
            )
            .expect("item"),
        );
    }
    // Modify bad.env AFTER the items were built.
    fs::write(&bad, "changed = true\n").expect("modify");

    let plan = RewritePlan::build(items, &key).expect("plan");
    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");

    // The plan canonicalizes item order (bad.env sorts first); find each
    // result by path rather than assuming order.
    let status_of = |name: &str| {
        outcome
            .results
            .iter()
            .find(|r| r.path == std::path::Path::new(name))
            .expect("result for file")
            .status
            .clone()
    };
    assert!(matches!(
        status_of("good.env"),
        FileApplyStatus::Applied { .. }
    ));
    assert_eq!(status_of("bad.env"), FileApplyStatus::Stale);
    assert_eq!(
        fs::read_to_string(&good).unwrap(),
        format!("{PREFIX}{replacement}\n")
    );
    assert_eq!(fs::read_to_string(&bad).unwrap(), "changed = true\n");
}

/// A plan can be reconstructed by deserialization, bypassing the P5
/// build-time path normalization — so the apply layer re-checks, and a
/// parent-component path is refused before anything is touched.
#[test]
fn a_deserialized_escaping_path_is_refused_at_apply() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    let mut evil = plan.items()[0].clone();
    evil.path = PathBuf::from("../escaped.env");
    let evil_plan = RewritePlan::build(vec![evil], &key).expect("plan accepts items");

    let mut sink = MemSink::new();
    let outcome = execute(
        &evil_plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    match &outcome.results[0].status {
        FileApplyStatus::Failed { reason } => {
            assert!(reason.contains("escapes"), "{reason}");
        }
        other => panic!("expected an escape refusal, got {other:?}"),
    }
    // The in-root file was never touched.
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(sink.snapshots.is_empty());
}

#[cfg(unix)]
#[test]
fn a_symlinked_target_is_refused() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    let link = dir.path().join("link.env");
    std::os::unix::fs::symlink(&file, &link).expect("symlink");
    // Rewrite the plan to target the link path with the link's (target
    // file's) content.
    let key2 = PlanKey::from_bytes(&[7u8; 32]).expect("key");
    let linked_item = PlanItem {
        path: PathBuf::from("link.env"),
        ..plan.items()[0].clone()
    };
    let linked_plan = RewritePlan::build(vec![linked_item], &key2).expect("plan");

    let mut sink = MemSink::new();
    let outcome = execute(
        &linked_plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        platform_assurance(),
        &mut sink,
    )
    .expect("run");
    assert!(matches!(
        outcome.results[0].status,
        FileApplyStatus::Failed { .. }
    ));
    // The real file was not touched through the link.
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
}

/// Addendum requirement, on the primary platform: with full enforcement a
/// Commit on Windows REFUSES, naming the missing check, instead of running
/// with a silently-weaker guarantee. This is not a no-op on Windows — it is
/// the Windows behavior.
#[test]
#[cfg(windows)]
fn commit_without_acknowledgement_is_refused_on_windows() {
    let (dir, file, _item, plan, key, _replacement) = setup();
    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        IdentityAssurance::Enforced,
        &mut sink,
    )
    .expect("run");
    match &outcome.results[0].status {
        FileApplyStatus::Failed { reason } => {
            assert!(reason.contains("identity"), "{reason}");
            assert!(reason.contains("AcknowledgedUnavailable"), "{reason}");
        }
        other => panic!("expected a loud refusal, got {other:?}"),
    }
    assert_eq!(fs::read_to_string(&file).unwrap(), content());
    assert!(sink.snapshots.is_empty(), "nothing reached the vault");
    assert!(sink.journal.is_empty());
}

/// With the explicit acknowledgement, the commit proceeds on Windows with
/// the whole-file digest as the swap guard — and the run is real, not a
/// stub: the marker lands and the journal records it.
#[test]
fn acknowledged_commit_proceeds_where_identity_is_unavailable() {
    let (dir, file, _item, plan, key, replacement) = setup();
    let mut sink = MemSink::new();
    let outcome = execute(
        &plan,
        ApplyMode::Commit,
        dir.path(),
        &key,
        IdentityAssurance::AcknowledgedUnavailable,
        &mut sink,
    )
    .expect("run");
    assert_eq!(
        outcome.results[0].status,
        FileApplyStatus::Applied {
            locator: Some(replacement.clone())
        }
    );
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        format!(
            "{PREFIX}{replacement}
"
        )
    );
    assert_eq!(sink.journal.len(), 2);
}
