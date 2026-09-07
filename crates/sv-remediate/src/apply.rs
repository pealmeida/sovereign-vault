//! The destructive path: journalled, per-file-atomic application of an
//! approved plan (ADR-0017 §4, ADR-0019 §2–3).
//!
//! This module is compiled **only** with the non-default `apply` feature.
//! Without it this crate cannot modify a file; with it, [`ApplyMode::DryRun`]
//! is still the [`Default`](core::default::Default) and [`execute`] takes
//! the mode explicitly. There is no bare function that writes.
//!
//! ## Why every step below exists
//!
//! A false positive here does not produce a bad answer — it corrupts a
//! user's source file. ADR-0017's context says it plainly, and the per-file
//! ordering is the design's answer:
//!
//! 1. path safety (root containment, symlink/reparse rejection, OS file
//!    identity) — refuse before reading anything as if it were the target;
//! 2. verify: whole-file digest, then span bounds, then matched-byte
//!    digest ([`crate::verify::verify_plan_item`]) — any mismatch stops the
//!    file; the caller must re-plan and re-approve. Spans are never
//!    relocated;
//! 3. **pinned-detector re-run** — the plan's rules, at the plan's versions,
//!    must produce matching evidence at the span in the current content
//!    (ADR-0019 §2). A commit without this step does not satisfy the ADR;
//! 4. the original bytes go into the vault and the locator mapping commits;
//! 5. the encrypted [`RecoveryRecord`] is stored;
//! 6. the journal marks the file in-progress;
//! 7. only then is the file replaced, atomically, with its permissions
//!    preserved;
//! 8. the journal marks it done, and the audit record is emitted.
//!
//! If steps 4–6 fail, **nothing is written to the file**. If the process
//! dies between 6 and 7, the journal shows the in-progress state and
//! [`resume`] completes the run. Multi-file runs are **not transactional**;
//! the journal makes them resumable, and nothing here claims more.
//!
//! ## The identity check and its honest limit
//!
//! ADR-0019 §2 requires rejecting a file whose OS identity no longer
//! matches the plan. On Unix that check runs in full (device + inode).
//! On Windows — the project's primary platform — the OS file index and
//! volume serial are not obtainable from safe, stable Rust: `std` gates
//! them behind an unstable feature, the workspace forbids `unsafe`, and no
//! available safe crate publishes them. A Commit on Windows therefore
//! **refuses** unless the caller passes
//! [`IdentityAssurance::AcknowledgedUnavailable`], and the refusal states
//! exactly which check is missing. A silently-weaker guarantee on the
//! primary platform would be worse than a loud refusal. With the
//! acknowledgement, the whole-file digest remains the guard against a
//! swapped file.
//!
//! The vault side of steps 4–5 and the journal and audit persistence are
//! caller-supplied through [`VaultSink`] — this crate never talks to a
//! vault directly, and the sink receives bytes and digests, never a
//! mandate to log the material.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sv_audit::AuditAction;
use sv_scan::FindingKind;

use crate::plan::{is_marker, keyed_digest, Digest, FileIdentity, PlanItem, PlanKey, RewritePlan};
use crate::recovery::{JournalEntry, JournalState, RecoveryRecord, RewriteJournal};

/// How [`execute`] treats an approved plan.
///
/// [`ApplyMode::DryRun`] is the [`Default`](core::default::Default):
/// dry-run is the default, not a flag (ADR-0017 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApplyMode {
    /// Verify everything and report what *would* happen. Writes nothing,
    /// touches no sink.
    #[default]
    DryRun,
    /// Perform the full ordered pipeline, up to and including the atomic
    /// replace.
    Commit,
}

/// Whether the ADR-0019 §2 OS-identity check can run, stated by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAssurance {
    /// Enforce the identity check everywhere. On platforms where the
    /// identity cannot be captured (Windows, today), a Commit **refuses**
    /// with the missing check named, rather than proceeding with a silently
    /// weaker guarantee.
    Enforced,
    /// Explicit acknowledgement — on behalf of the human who approved the
    /// plan — that the identity check is unavailable on this platform and
    /// the whole-file digest is the only guard against a swapped file.
    /// Where the identity *is* obtainable it is still enforced; the
    /// acknowledgement only covers the platforms that cannot capture one.
    AcknowledgedUnavailable,
}

/// The result of applying one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileApplyResult {
    /// The file's normalized path, as carried by the plan.
    pub path: PathBuf,
    /// What happened.
    pub status: FileApplyStatus,
}

/// What happened to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileApplyStatus {
    /// Verified and previewed; nothing was written.
    DryRun,
    /// The full pipeline ran; the file was replaced atomically.
    Applied {
        /// The locator committed for this redaction, when the vault chose a
        /// discoverable marker; `None` when it chose opaque.
        locator: Option<String>,
    },
    /// The journal showed this file already replaced; a resumed run found
    /// nothing left to do.
    AlreadyReplaced,
    /// A check failed: the file changed, or its identity no longer matches,
    /// or the pinned detector no longer finds evidence at the span. Nothing
    /// was written. The caller must obtain a fresh plan and fresh approval.
    Stale,
    /// The run deliberately left this file alone (for example, it was
    /// rolled back earlier).
    Skipped {
        /// Why.
        reason: String,
    },
    /// Something failed *after* verification; nothing was written, except
    /// in the one documented corner where the replace itself succeeded and
    /// a later bookkeeping step failed (the journal then still shows the
    /// pre-replace state and the recovery record allows an undo).
    Failed {
        /// Why. Never echoes matched bytes.
        reason: String,
    },
}

/// The outcome of one `execute`/`resume` run over a whole plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The mode the run ran in.
    pub mode: ApplyMode,
    /// One result per plan item, in plan order.
    pub results: Vec<FileApplyResult>,
}

/// The outcome of [`restore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The file was restored to its historical bytes.
    ///
    /// These are the bytes as they were at plan time. This is **not** a
    /// guarantee that the credential inside them is still valid — a value
    /// that was exposed must be rotated regardless (ADR-0019 §6, ADR-0020
    /// §6).
    Restored {
        /// The historical bytes now back in the file.
        bytes: Vec<u8>,
    },
    /// The destination changed after the rewrite. Nothing was overwritten;
    /// the caller decides what to do.
    Conflict,
}

/// Errors from the destructive path.
///
/// Display strings are generic; they name the failure class without echoing
/// matched values.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Filesystem I/O failed.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The approved root is not a readable directory.
    #[error("project root is not a readable directory")]
    InvalidRoot,
    /// A plan path would escape the approved root.
    #[error("target escapes the approved project root")]
    PathEscapesRoot,
    /// A path component is a symbolic link or a Windows reparse point.
    #[error("target path contains a symbolic link or reparse point; refused")]
    SymlinkRejected,
    /// The target exists but is not a regular file.
    #[error("target is not a regular file")]
    NotARegularFile,
    /// The target is cooperatively locked by another writer.
    #[error("target is locked by another writer")]
    Locked,
    /// The caller-supplied vault sink failed.
    #[error("vault sink failed: {0}")]
    Sink(String),
    /// The pinned detector could not re-run (version drift, or the pinned
    /// rule pack is unavailable on this machine).
    #[error("pinned detector unavailable: {0}")]
    DetectorUnavailable(String),
    /// The journal does not belong to the plan being resumed.
    #[error("journal does not match the plan")]
    JournalMismatch,
    /// The eligibility gate refused the file for whole-file ingestion
    /// (ADR-0020 §1).
    #[error("file is not eligible for whole-file ingestion: {0}")]
    Ineligible(String),
    /// The manifest path collided with the consumed path (ADR-0020 §3).
    #[error("manifest path must differ from the consumed path")]
    ManifestConsumed,
    /// Plan serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<crate::PlanError> for ApplyError {
    fn from(error: crate::PlanError) -> Self {
        // Plan errors are validation failures; their Display strings are
        // already generic and value-free.
        ApplyError::Sink(error.to_string())
    }
}

/// The vault side of the destructive path, supplied by the caller.
///
/// The vault — not this crate — owns storage, encryption, locator minting,
/// journal persistence, and the audit chain. Implementations map their
/// internal errors into [`ApplyError::Sink`]. No method here ever receives
/// a mandate to record the matched value; digests and opaque references
/// only.
pub trait VaultSink {
    /// Stores the original whole-file bytes (encrypted on the vault side)
    /// and returns an opaque snapshot reference.
    fn store_snapshot(&mut self, item: &PlanItem, original: &[u8]) -> Result<String, ApplyError>;

    /// Commits the locator mapping for the redaction and returns the
    /// locator's external wire form when the vault chose a discoverable
    /// marker, or `None` for the opaque form. When the plan's replacement
    /// is itself a marker, the vault must register that exact marker.
    fn commit_locator(
        &mut self,
        item: &PlanItem,
        snapshot_ref: &str,
    ) -> Result<Option<String>, ApplyError>;

    /// Persists the recovery record (encrypted on the vault side).
    fn store_recovery(&mut self, record: &RecoveryRecord) -> Result<(), ApplyError>;

    /// Appends one journal entry, durably, before the caller proceeds.
    fn append_journal(&mut self, entry: JournalEntry) -> Result<(), ApplyError>;

    /// Loads and decrypts the snapshot a recovery record points at.
    fn load_snapshot(&self, record: &RecoveryRecord) -> Result<Vec<u8>, ApplyError>;

    /// Emits one audit record. The operation digest identifies what
    /// happened; the material must never be recorded.
    fn audit(&mut self, action: AuditAction, operation_digest: Digest) -> Result<(), ApplyError>;

    /// Stores the original whole-file bytes of a MANAGED file (encrypted on
    /// the vault side; ADR-0020 §2) and returns an opaque snapshot
    /// reference. Distinct from [`VaultSink::store_snapshot`] so span
    /// redactions and whole-file ingestion remain separately auditable.
    fn store_managed_snapshot(
        &mut self,
        project_id: &str,
        path: &Path,
        original: &[u8],
    ) -> Result<String, ApplyError>;

    /// The consumer-adapter startup check (ADR-0020 §2): the project must
    /// demonstrably still work with the file vaulted before the original is
    /// removed. The real probe belongs to the caller — only the caller
    /// knows the toolchain; [`crate::managed::startup_check`] is the
    /// built-in manifest-based default an implementation may delegate to.
    fn startup_check(
        &self,
        adapter: crate::managed::ConsumerAdapter,
        project_root: &Path,
        manifest_path: &Path,
    ) -> Result<(), ApplyError>;
}

/// Everything the per-file pipeline needs besides the item itself.
struct Ctx<'a> {
    root: &'a Path,
    key: &'a PlanKey,
    sink: &'a mut dyn VaultSink,
    assurance: IdentityAssurance,
}

/// Applies an approved plan in the given mode.
///
/// Per file, in plan order, the pipeline of the module documentation runs.
/// A failure of one file does not stop the others (the run is resumable,
/// not transactional); only an unusable root fails the whole call.
pub fn execute(
    plan: &RewritePlan,
    mode: ApplyMode,
    root: &Path,
    key: &PlanKey,
    assurance: IdentityAssurance,
    sink: &mut dyn VaultSink,
) -> Result<ApplyOutcome, ApplyError> {
    let canonical_root = root.canonicalize().map_err(ApplyError::Io)?;
    if !canonical_root.is_dir() {
        return Err(ApplyError::InvalidRoot);
    }
    let mut ctx = Ctx {
        root: &canonical_root,
        key,
        sink,
        assurance,
    };
    let mut results = Vec::with_capacity(plan.items().len());
    for item in plan.items() {
        let status = match apply_item(item, plan.digest(), mode, &mut ctx, ResumePoint::Fresh) {
            Ok(status) => status,
            Err(error) => FileApplyStatus::Failed {
                reason: error.to_string(),
            },
        };
        results.push(FileApplyResult {
            path: item.path.clone(),
            status,
        });
    }
    Ok(ApplyOutcome { mode, results })
}

/// Completes an interrupted run from its journal.
///
/// Files already marked replaced are left alone; files marked in-progress
/// (vault-side committed, file untouched) are verified and replaced without
/// duplicating vault work; everything else — including earlier failures,
/// which may have been transient — runs the full pipeline. The journal must
/// belong to this plan.
pub fn resume(
    plan: &RewritePlan,
    journal: &RewriteJournal,
    root: &Path,
    key: &PlanKey,
    assurance: IdentityAssurance,
    sink: &mut dyn VaultSink,
) -> Result<ApplyOutcome, ApplyError> {
    if journal.plan_digest != plan.digest() {
        return Err(ApplyError::JournalMismatch);
    }
    let canonical_root = root.canonicalize().map_err(ApplyError::Io)?;
    if !canonical_root.is_dir() {
        return Err(ApplyError::InvalidRoot);
    }
    let mut ctx = Ctx {
        root: &canonical_root,
        key,
        sink,
        assurance,
    };
    let mut results = Vec::with_capacity(plan.items().len());
    for item in plan.items() {
        let state = latest_state(journal, &item.path);
        let result = match state {
            Some(JournalState::FileReplaced) => FileApplyResult {
                path: item.path.clone(),
                status: FileApplyStatus::AlreadyReplaced,
            },
            Some(JournalState::RolledBack) => FileApplyResult {
                path: item.path.clone(),
                status: FileApplyStatus::Skipped {
                    reason: "rolled back".to_string(),
                },
            },
            // A prior failure is retried from the top: the failure may have
            // been transient (a lock, a busy vault), and re-running the full
            // pipeline is always safe — it verifies first.
            Some(JournalState::VaultStored { locator }) => {
                let status = apply_item(
                    item,
                    plan.digest(),
                    ApplyMode::Commit,
                    &mut ctx,
                    ResumePoint::VaultStored {
                        locator: locator.clone(),
                    },
                )
                .unwrap_or_else(|error| FileApplyStatus::Failed {
                    reason: error.to_string(),
                });
                FileApplyResult {
                    path: item.path.clone(),
                    status,
                }
            }
            _ => {
                let status = apply_item(
                    item,
                    plan.digest(),
                    ApplyMode::Commit,
                    &mut ctx,
                    ResumePoint::Fresh,
                )
                .unwrap_or_else(|error| FileApplyStatus::Failed {
                    reason: error.to_string(),
                });
                FileApplyResult {
                    path: item.path.clone(),
                    status,
                }
            }
        };
        results.push(result);
    }
    Ok(ApplyOutcome {
        mode: ApplyMode::Commit,
        results,
    })
}

/// Restores a redacted file to its historical bytes, conflict-checked.
///
/// The restore is refused when the file on disk is not exactly the state
/// the rewrite left it in (reconstructed from the record's span and
/// replacement): the user is told rather than silently overwritten
/// (ADR-0017 §4). Records that predate span bookkeeping are refused too —
/// a restore that cannot check must not proceed.
///
/// On success the file holds the historical bytes. That is **not** a claim
/// that the credential inside is still valid; an exposed value must be
/// rotated regardless (ADR-0019 §6, ADR-0020 §6).
pub fn restore(
    record: &RecoveryRecord,
    root: &Path,
    assurance: IdentityAssurance,
    sink: &mut dyn VaultSink,
) -> Result<RestoreOutcome, ApplyError> {
    // Fail closed on records that cannot be conflict-checked.
    let (Some(span), Some(replacement)) = (&record.span, &record.replacement) else {
        return Ok(RestoreOutcome::Conflict);
    };
    let original = sink
        .load_snapshot(record)
        .map_err(|error| ApplyError::Sink(error.to_string()))?;
    let original_text = match String::from_utf8(original.clone()) {
        Ok(text) => text,
        Err(_) => return Ok(RestoreOutcome::Conflict),
    };
    // The span must land on the historical bytes, or the record does not
    // describe a state this code can reason about.
    if span.slice(&original_text).is_err() {
        return Ok(RestoreOutcome::Conflict);
    }
    // What the rewrite should have left on disk.
    let mut expected = original_text.clone();
    expected.replace_range(span.start..span.end, replacement);

    let canonical_root = root.canonicalize().map_err(ApplyError::Io)?;
    if !canonical_root.is_dir() {
        return Err(ApplyError::InvalidRoot);
    }
    let target = match resolve_target(&canonical_root, &record.path) {
        Ok(target) => target,
        // A vanished, replaced, or re-linked destination is a divergence.
        Err(_) => return Ok(RestoreOutcome::Conflict),
    };

    // The file must still be exactly the state the rewrite left it in.
    //
    // Content, not identity, is what can be checked here. `record.identity`
    // was captured at *plan* time, and the rewrite that produced this record
    // replaced the file atomically — which allocates a new inode on Unix, so
    // the recorded identity necessarily no longer matches and comparing it
    // would make every restore a false conflict. Identity guards the *apply*
    // path, where the file has not yet been replaced; the post-rewrite
    // content digest is the guard that is meaningful here, and it is what
    // detects a file edited after the redaction.
    let _ = assurance;
    let current = fs::read_to_string(&target).unwrap_or_default();
    if current != expected {
        return Ok(RestoreOutcome::Conflict);
    }

    let permissions =
        crate::managed::PermissionSnapshot::capture(&fs::metadata(&target)?.permissions());
    replace_atomic(&target, &original, &permissions).map_err(ApplyError::Io)?;

    sink.append_journal(JournalEntry {
        path: record.path.clone(),
        state: JournalState::RolledBack,
        at: chrono::Utc::now(),
    })
    .map_err(|error| ApplyError::Sink(error.to_string()))?;
    sink.audit(AuditAction::RedactionRestore, record.snapshot_digest)
        .map_err(|error| ApplyError::Sink(error.to_string()))?;
    Ok(RestoreOutcome::Restored { bytes: original })
}

// ---------------------------------------------------------------------------
// Per-file pipeline
// ---------------------------------------------------------------------------

/// Where a resumed run picks an item back up.
enum ResumePoint {
    /// Nothing has happened: run the full pipeline.
    Fresh,
    /// Steps (b)–(d) already committed before the crash; skip them (the
    /// snapshot and recovery record must not be duplicated) and continue at
    /// the replace, carrying the locator the journal recorded.
    VaultStored {
        /// The locator committed in step (b), if any.
        locator: Option<String>,
    },
}

/// Runs one plan item through the ordered pipeline.
///
/// `resume` marks the crash-recovery path where the journal already shows
/// the vault side committed: steps (b)–(d) are skipped so the snapshot and
/// recovery record are not duplicated, and the run continues at the replace
/// step — but only after the full verification suite has re-run.
fn apply_item(
    item: &PlanItem,
    plan_digest: Digest,
    mode: ApplyMode,
    ctx: &mut Ctx,
    resume: ResumePoint,
) -> Result<FileApplyStatus, ApplyError> {
    // (1) Path safety, before anything is read or written.
    let target = resolve_target(ctx.root, &item.path)?;
    let permissions =
        crate::managed::PermissionSnapshot::capture(&fs::metadata(&target)?.permissions());

    // OS file identity: enforce where it can be captured, and refuse loudly
    // where it cannot unless the caller explicitly acknowledged the gap
    // (see the module documentation).
    match (ctx.assurance, FileIdentity::capture_from_path(&target)) {
        (_, Ok(identity)) if identity == item.identity => {}
        (_, Ok(_)) => return Ok(FileApplyStatus::Stale),
        (IdentityAssurance::AcknowledgedUnavailable, Err(_)) => {}
        (IdentityAssurance::Enforced, Err(_)) => {
            return Ok(FileApplyStatus::Failed {
                reason: "OS file identity check is unavailable on this platform; \
                         commit refused because the caller did not acknowledge \
                         IdentityAssurance::AcknowledgedUnavailable (ADR-0019 §2 \
                         identity check)"
                    .to_string(),
            });
        }
    }

    // (2) Cooperative lock, then verify: whole-file digest, span bounds,
    // matched-byte digest — in that order.
    let mut handle = open_locked(&target)?;
    let mut bytes = Vec::new();
    handle.read_to_end(&mut bytes)?;
    if keyed_digest(ctx.key, &bytes) != item.whole_file_digest {
        return Ok(FileApplyStatus::Stale);
    }
    let text = match String::from_utf8(bytes.clone()) {
        Ok(text) => text,
        // The approved snapshot was valid UTF-8; different bytes that happen
        // to match its digest cannot exist, so this is unreachable in
        // practice — and stale rather than fatal if ever reached.
        Err(_) => return Ok(FileApplyStatus::Stale),
    };
    if crate::verify_plan_item(item, ctx.key, &text) == crate::VerifyOutcome::Stale {
        return Ok(FileApplyStatus::Stale);
    }

    // (3) Pinned-detector re-run: the plan's rules, at the plan's versions,
    // must still find matching evidence at this span.
    if !pinned_evidence(item, &text)? {
        return Ok(FileApplyStatus::Stale);
    }

    // The lock has now served its purpose: the verification window is
    // closed. Windows cannot rename over a file while any handle is open —
    // even with FILE_SHARE_DELETE, MoveFileExW fails with Access Denied —
    // so the handle is released before the vault steps, and the content is
    // re-verified immediately before the replace below. The residual race
    // window between that re-check and the rename is exactly the one
    // ADR-0019 §3 documents as unavoidable for a cooperative lock plus
    // non-CAS replace.
    drop(handle);

    if mode == ApplyMode::DryRun {
        return Ok(FileApplyStatus::DryRun);
    }

    // From here on the run is a Commit. Steps (b)–(d) may fail freely: the
    // file is untouched, and the caller can re-run or resume.
    let mut locator = match &resume {
        ResumePoint::Fresh => None,
        ResumePoint::VaultStored { locator: committed } => committed.clone(),
    };
    if matches!(resume, ResumePoint::Fresh) {
        // (b) Vault material and locator mapping.
        let snapshot_ref = ctx
            .sink
            .store_snapshot(item, &bytes)
            .map_err(|error| ApplyError::Sink(error.to_string()))?;
        locator = ctx
            .sink
            .commit_locator(item, &snapshot_ref)
            .map_err(|error| ApplyError::Sink(error.to_string()))?;
        if let Some(external) = &locator {
            if !is_marker(external) {
                return Err(ApplyError::Sink(
                    "vault returned a locator that is not a valid marker".to_string(),
                ));
            }
        }
        // (c) Encrypted recovery record. Opaque removes public resolution,
        // not owner recovery: the record is written whichever policy the
        // vault chose.
        let discovery = if locator.is_some() {
            sv_runtime::DiscoveryPolicy::Discoverable
        } else {
            sv_runtime::DiscoveryPolicy::Opaque
        };
        let record = RecoveryRecord {
            plan_digest,
            project_id: item.project_id.clone(),
            path: item.path.clone(),
            identity: item.identity,
            snapshot_digest: keyed_digest(ctx.key, &bytes),
            snapshot_ref,
            discovery,
            locator: locator.clone(),
            span: Some(item.span),
            replacement: Some(item.replacement.clone()),
            created_at: chrono::Utc::now(),
        };
        ctx.sink
            .store_recovery(&record)
            .map_err(|error| ApplyError::Sink(error.to_string()))?;

        // (d) Journal: in-progress, BEFORE the file is touched.
        ctx.sink
            .append_journal(JournalEntry {
                path: item.path.clone(),
                state: JournalState::VaultStored {
                    locator: locator.clone(),
                },
                at: chrono::Utc::now(),
            })
            .map_err(|error| ApplyError::Sink(error.to_string()))?;
    }

    // (e) Atomic replace, permissions preserved. Immediately before it, the
    // content is verified again — the vault steps took time, and the file
    // must still be the approved bytes at the moment of no return. A
    // mismatch here is the same staleness as anywhere else: no write, fresh
    // plan, fresh approval.
    let mut handle = open_locked(&target)?;
    let mut current = Vec::new();
    handle.read_to_end(&mut current)?;
    drop(handle);
    if keyed_digest(ctx.key, &current) != item.whole_file_digest {
        return Ok(FileApplyStatus::Stale);
    }
    let current_text = match String::from_utf8(current) {
        Ok(text) => text,
        Err(_) => return Ok(FileApplyStatus::Stale),
    };
    if crate::verify_plan_item(item, ctx.key, &current_text) == crate::VerifyOutcome::Stale
        || !pinned_evidence(item, &current_text)?
    {
        return Ok(FileApplyStatus::Stale);
    }
    let mut updated = current_text;
    updated.replace_range(item.span.start..item.span.end, &item.replacement);
    replace_atomic(&target, updated.as_bytes(), &permissions).map_err(ApplyError::Io)?;

    // (f) Journal: done. After the replace, a bookkeeping failure cannot be
    // rolled back from here — the status says so plainly and the recovery
    // record still allows an undo.
    if let Err(error) = ctx.sink.append_journal(JournalEntry {
        path: item.path.clone(),
        state: JournalState::FileReplaced,
        at: chrono::Utc::now(),
    }) {
        return Ok(FileApplyStatus::Failed {
            reason: format!("file replaced but journal append failed: {error}"),
        });
    }
    if let Err(error) = ctx.sink.audit(AuditAction::PlanExecute, plan_digest) {
        return Ok(FileApplyStatus::Failed {
            reason: format!("file replaced but audit failed: {error}"),
        });
    }
    Ok(FileApplyStatus::Applied { locator })
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Resolves `relative` beneath the canonical `root`, refusing anything that
/// could leave it.
///
/// Only normal components are followed. This re-checks the path even though
/// plan construction normalizes: a plan can be reconstructed by
/// deserialization, and the apply layer must not trust that anything
/// upstream ran. Each component is also refused when it is a symbolic link
/// or (on Windows) a reparse point, and the final target must be a regular
/// file.
pub(crate) fn resolve_target(root: &Path, relative: &Path) -> Result<PathBuf, ApplyError> {
    let mut probe = root.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(segment) => probe.push(segment),
            _ => return Err(ApplyError::PathEscapesRoot),
        }
        let metadata = fs::symlink_metadata(&probe)?;
        // `mut` only where the Windows block below reassigns it; elsewhere
        // an unused `mut` is a hard error under `-D warnings`.
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut unsafe_link = metadata.file_type().is_symlink();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            unsafe_link =
                unsafe_link || (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        }
        if unsafe_link {
            return Err(ApplyError::SymlinkRejected);
        }
    }
    let metadata = fs::symlink_metadata(&probe)?;
    if !metadata.is_file() {
        return Err(ApplyError::NotARegularFile);
    }
    Ok(probe)
}

/// Opens a target read-only and takes the cooperative exclusive lock.
///
/// fs4 stays the locking dependency (ADR-0017 §4 names it); the call is
/// trait-qualified because recent toolchains also expose an inherent
/// `File::try_lock`, which would otherwise shadow the trait method and
/// make the dependency silently dead.
fn open_locked(target: &Path) -> Result<std::fs::File, ApplyError> {
    let handle = fs::OpenOptions::new().read(true).open(target)?;
    match fs4::FileExt::try_lock(&handle) {
        Ok(()) => Ok(handle),
        Err(fs4::TryLockError::WouldBlock) => Err(ApplyError::Locked),
        Err(fs4::TryLockError::Error(error)) => Err(ApplyError::Io(error)),
    }
}

/// Replaces the file's content atomically, applying `permissions` to the
/// new content before it takes the target's place.
pub(crate) fn replace_atomic(
    target: &Path,
    content: &[u8],
    permissions: &crate::managed::PermissionSnapshot,
) -> std::result::Result<(), std::io::Error> {
    let atomic =
        atomicwrites::AtomicFile::new(target, atomicwrites::OverwriteBehavior::AllowOverwrite);
    atomic
        .write(|file| {
            file.write_all(content)?;
            permissions.apply_to(file)
        })
        .map_err(|error| match error {
            atomicwrites::Error::Internal(io) => io,
            atomicwrites::Error::User(io) => io,
        })
}

/// Re-runs the pinned detector over `content` and reports whether matching
/// evidence exists at the item's span (ADR-0019 §2).
///
/// Only the plan's own rule versions count: a detector or rule-pack version
/// that drifted from the pin refuses to guess. For baseline secret rules a
/// finding at exactly the span from *any* rule counts as evidence — the
/// scanner's overlap dedup may legitimately let a higher-confidence rule
/// covering the same span win, and the evidence question is about the
/// bytes, not the label. PII requires the same category; jurisdiction
/// matches require the same rule id and pack version.
fn pinned_evidence(item: &PlanItem, content: &str) -> Result<bool, ApplyError> {
    if item.rule_pin.detector_version != sv_scan::version() {
        return Err(ApplyError::DetectorUnavailable(format!(
            "plan pinned detector {}, current is {}",
            item.rule_pin.detector_version,
            sv_scan::version()
        )));
    }
    // The detectors' per-finding fingerprints are process-local UI material
    // and play no part in evidence matching — only spans and kinds are
    // compared — so the salt is a fixed, non-secret value here.
    let fingerprint_salt = [0u8; 32];
    let span_at = |start: usize, end: usize| start == item.span.start && end == item.span.end;
    match &item.kind {
        FindingKind::Secret { .. } => {
            let findings = sv_scan::detect_secrets(
                content,
                &item.path,
                sv_scan::PreviewMode::Opaque,
                fingerprint_salt,
            );
            Ok(findings.iter().any(|f| span_at(f.start, f.end)))
        }
        FindingKind::Pii(category) => {
            let policy = sv_privacy::Policy::all();
            let findings = sv_scan::detect_pii(
                content,
                &item.path,
                &policy,
                sv_scan::PreviewMode::Opaque,
                fingerprint_salt,
            );
            Ok(findings
                .iter()
                .any(|f| span_at(f.start, f.end) && f.kind == sv_scan::FindingKind::Pii(*category)))
        }
        FindingKind::Jurisdiction {
            pack_id,
            pack_version,
            rule_id,
            ..
        } => {
            if item.rule_pin.pack_id != *pack_id || item.rule_pin.pack_version != *pack_version {
                return Err(ApplyError::DetectorUnavailable(
                    "plan pin does not match the finding's rule pack".to_string(),
                ));
            }
            let pack = sv_patterns::load_builtin(pack_id).map_err(|error| {
                ApplyError::DetectorUnavailable(format!("pinned rule pack unavailable: {error}"))
            })?;
            let budget = sv_patterns::MatchBudget::default();
            let (findings, _truncated) = sv_scan::detect_jurisdiction(
                content,
                &item.path,
                std::slice::from_ref(&pack),
                &budget,
                sv_scan::PreviewMode::Opaque,
                fingerprint_salt,
            );
            Ok(findings.iter().any(|f| {
                span_at(f.start, f.end)
                    && matches!(&f.kind, sv_scan::FindingKind::Jurisdiction { rule_id: r, pack_version: v, .. } if r == rule_id && v == pack_version)
            }))
        }
    }
}

/// The latest journal state recorded for a path, if any.
fn latest_state<'j>(journal: &'j crate::RewriteJournal, path: &Path) -> Option<&'j JournalState> {
    journal
        .entries
        .iter()
        .rfind(|entry| entry.path == path)
        .map(|entry| &entry.state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dry-run is the default mode: there is no configuration in which this
    /// crate writes without the caller asking for `Commit` explicitly.
    #[test]
    fn dry_run_is_the_default_mode() {
        assert_eq!(ApplyMode::default(), ApplyMode::DryRun);
    }
}
