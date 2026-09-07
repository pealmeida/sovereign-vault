//! Whole-file ingestion and the consumer adapters (ADR-0020).
//!
//! ADR-0017/0019 redact *spans inside* files. ADR-0020 adds the other user
//! requirement: move a WHOLLY sensitive file — a real `.env`, a `.pem`, a
//! `service-account.json` — into the vault and leave the project working.
//!
//! Two gates from the ADR are enforced here in code, not prose:
//!
//! * **Eligibility (ADR-0020 §1).** Only a wholly-sensitive file may be
//!   ingested. A partly-sensitive file (a `docker-compose.yml` with four
//!   keys among two hundred lines of legitimate configuration) is refused
//!   with the reason stated, because a literal marker inside a YAML value
//!   is still a string the parser hands to the application: whole-file
//!   removal has no fallback for the legitimate content that would be lost
//!   with it. Partly-sensitive files stay in place and route through span
//!   redaction.
//! * **Removal refusal (ADR-0020 §2).** The original file is removed only
//!   after the vault side is committed *and* the consumer adapter's startup
//!   check passes. If the check fails, the original stays and the outcome
//!   says why.
//!
//! ## What still cannot be promised
//!
//! Detecting unexpected plaintext at a managed path (ADR-0020 §4) happens
//! *after the fact*: nothing in this crate prevents `cp .env.example .env`
//! or the next dev-server run from writing plaintext back. Re-creation by
//! the user's own tooling is detectable, not preventable.
//!
//! The [`TempMaterial`] fallback still exposes plaintext to the launched
//! process, its descendants, an attached debugger, backups, and privileged
//! software. "Smaller exposure than a permanent file in the tree" is the
//! honest claim; there is no "no exposure" claim to make (ADR-0020 §3).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::apply::{replace_atomic, resolve_target, ApplyError, VaultSink};
use crate::plan::{keyed_digest, Digest, FileIdentity, PlanKey};
use crate::recovery::{JournalEntry, JournalState, RecoveryRecord};

// ---------------------------------------------------------------------------
// Consumer adapters (ADR-0020 §3)
// ---------------------------------------------------------------------------

/// How a launched consumer receives the vaulted material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsumerAdapter {
    /// **Recommended (ADR-0020 §3):** the material is supplied as
    /// environment variables to the launched process. No file exists for a
    /// consumer to misread; the var mapping travels in the non-secret
    /// manifest and is applied by the trusted launcher at launch time.
    EnvInjection,
    /// **Fallback** for consumers that genuinely require a *path*: a
    /// restricted temporary file is materialized for the launched process
    /// ([`TempMaterial`]). See that type's documentation for the exposure
    /// this still implies.
    TempFile,
}

impl ConsumerAdapter {
    /// Stable wire name used in manifests.
    pub fn as_str(self) -> &'static str {
        match self {
            ConsumerAdapter::EnvInjection => "env-injection",
            ConsumerAdapter::TempFile => "temp-file",
        }
    }

    /// Parses a manifest's adapter name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "env-injection" => Some(ConsumerAdapter::EnvInjection),
            "temp-file" => Some(ConsumerAdapter::TempFile),
            _ => None,
        }
    }
}

/// The fallback materialization for path-bound consumers (ADR-0020 §3).
///
/// The file is created in the OS temporary directory with
/// user-restricted permissions and removed on drop. Dropping it after a
/// crash cannot be guaranteed by this process — that residual cleanup is
/// the crash-recovery responsibility of the OS temp directory and the
/// launcher, and is stated here rather than promised away.
///
/// ## Exposure statement (ADR-0020 §3, stated plainly)
///
/// While it exists, this file **still exposes plaintext** to the launched
/// process, to that process's descendants, to a debugger attached to it,
/// to backups of the temporary directory, and to privileged software on
/// the machine. It is a smaller exposure than a permanent file in the
/// project tree; it is not the end of the exposure.
#[derive(Debug)]
pub struct TempMaterial {
    path: PathBuf,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempMaterial {
    /// Materializes `contents` into a restricted, uniquely named temp file.
    pub fn materialize(contents: &[u8]) -> Result<Self, ApplyError> {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!(".sv-managed-{}-{nonce:016x}", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(contents)?;
        PermissionSnapshot::restricted().apply_to(&mut file)?;
        Ok(TempMaterial { path })
    }

    /// The path to hand to the launched process.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempMaterial {
    fn drop(&mut self) {
        // Best-effort cleanup; the OS temp directory is the crash-recovery
        // backstop.
        let _ = fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Eligibility gate (ADR-0020 §1) — enforced in code
// ---------------------------------------------------------------------------

/// Whether a file may be ingested whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    /// The file is wholly sensitive; whole-file ingestion applies.
    WhollySensitive,
    /// The file is partly sensitive (or not sensitive at all): refused for
    /// whole-file ingestion, routed to span redaction instead.
    PartlySensitive {
        /// Why, in terms a user can act on.
        reason: String,
    },
}

/// The eligibility gate of ADR-0020 §1.
///
/// A conservative **allowlist**: only names that are, by strong convention,
/// wholly sensitive qualify. Anything that can carry legitimate
/// configuration — YAML, TOML, JSON (except service-account keys), Python,
/// INI — is refused with the reason stated, no matter how many keys it
/// contains, because removing it whole would remove the legitimate content
/// too. Widening the allowlist is a code change with a test, not a
/// setting.
pub fn check_eligibility(path: &Path) -> Eligibility {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Eligibility::PartlySensitive {
            reason: "path has no file name".to_string(),
        };
    };
    let lower = name.to_lowercase();
    let wholly = lower == ".env"
        || [".pem", ".key", ".p12", ".pfx"]
            .iter()
            .any(|ext| lower.ends_with(ext))
        || ["id_rsa", "id_ed25519", "id_ecdsa"].contains(&lower.as_str())
        || (lower.starts_with("service-account") && lower.ends_with(".json"));
    if wholly {
        return Eligibility::WhollySensitive;
    }
    let hint = if [
        "yml", "yaml", "toml", "json", "py", "xml", "ini", "conf", "cfg",
    ]
    .iter()
    .any(|ext| lower.ends_with(&format!(".{ext}")))
    {
        "a configuration file whose legitimate content must stay in place; \
         "
    } else if lower.starts_with(".env.") {
        "an env template or example, not live material; \
         "
    } else {
        ""
    };
    Eligibility::PartlySensitive {
        reason: format!(
            "'{name}' is not on the wholly-sensitive allowlist: {hint}\
             partly-sensitive files stay in place and route through span \
             redaction (ADR-0020 §1)"
        ),
    }
}

// ---------------------------------------------------------------------------
// Dedup and authorization (ADR-0020 §5)
// ---------------------------------------------------------------------------

/// Whether this ingestion stands alone or joins an explicit shared binding.
///
/// The default is [`SharedBinding::Independent`]: the same `.env` in forty
/// projects produces forty independent resources with independent
/// permissions. A shared binding is opt-in and widens the rotation blast
/// radius — count it with [`rotation_blast_radius`] and show the number to
/// the user before they accept. Storage-level deduplication of identical
/// bytes must **never** imply shared authorization: authorization records
/// are derived per project here, so two projects referencing identical
/// bytes remain two authorization decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharedBinding {
    /// Default: this project's own resource, revocable alone.
    Independent,
    /// Explicit opt-in: rotate together, break together.
    Shared {
        /// Identifies the group of projects that rotate together.
        binding_id: String,
    },
}

/// One vault-side authorization decision for a managed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    /// Identifies the authorization resource. Two projects with identical
    /// bytes produce two different ids under [`SharedBinding::Independent`]
    /// — storage dedup never collapses authority.
    pub resource_id: String,
    /// The project this decision belongs to.
    pub project_id: String,
    /// Keyed digest of the managed bytes.
    pub content_digest: Digest,
    /// The shared binding, when the record is part of one.
    pub binding_id: Option<String>,
}

/// Derives the authorization record for one project's managed file.
pub fn authorization_record(
    project_id: &str,
    content_digest: Digest,
    binding: &SharedBinding,
) -> AuthorizationRecord {
    let (resource_id, binding_id) = match binding {
        SharedBinding::Independent => (format!("{project_id}:{}", content_digest), None),
        SharedBinding::Shared { binding_id } => {
            (format!("shared:{binding_id}"), Some(binding_id.clone()))
        }
    };
    AuthorizationRecord {
        resource_id,
        project_id: project_id.to_string(),
        content_digest,
        binding_id,
    }
}

/// How many authorizations a rotation of `binding` would hit.
///
/// For an independent record that is exactly one: its own. For a shared
/// binding, the number of projects that opted in — the number a UI must
/// show before the user accepts the binding.
pub fn rotation_blast_radius(records: &[AuthorizationRecord], binding: &SharedBinding) -> usize {
    match binding {
        SharedBinding::Independent => 1,
        SharedBinding::Shared { binding_id } => records
            .iter()
            .filter(|r| r.binding_id.as_deref() == Some(binding_id.as_str()))
            .count(),
    }
}

// ---------------------------------------------------------------------------
// Re-creation detection (ADR-0020 §4)
// ---------------------------------------------------------------------------

/// The result of a launch-time plaintext check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextStatus {
    /// The managed path is clear.
    Clear,
    /// Plaintext exists at a managed path. The launch should refuse and
    /// request reconciliation.
    UnexpectedPlaintext,
}

/// Checks a managed path for plaintext that reappeared after ingestion.
///
/// **This cannot prevent anything.** It cannot stop `cp .env.example .env`
/// and it cannot stop the next `npm run dev` from writing the file back —
/// the user's own tooling wins any race against a checker. What it does is
/// detect re-creation after the fact so a launch can reject it and request
/// reconciliation; a watcher is the same story with worse timing
/// (ADR-0020 §4). It must not be presented to the user as prevention.
pub fn detect_unexpected_plaintext(
    project_root: &Path,
    managed_relative: &Path,
) -> PlaintextStatus {
    if project_root.join(managed_relative).exists() {
        PlaintextStatus::UnexpectedPlaintext
    } else {
        PlaintextStatus::Clear
    }
}

// ---------------------------------------------------------------------------
// Plans, manifests, ingestion
// ---------------------------------------------------------------------------

/// A portable snapshot of a file's permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSnapshot {
    /// The Windows/readonly bit.
    pub readonly: bool,
    /// The Unix mode bits, when the file was captured on Unix.
    pub unix_mode: Option<u32>,
}

impl PermissionSnapshot {
    /// Captures from the platform's permissions.
    pub fn capture(permissions: &fs::Permissions) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            PermissionSnapshot {
                readonly: permissions.readonly(),
                unix_mode: Some(permissions.mode() & 0o777),
            }
        }
        #[cfg(not(unix))]
        {
            PermissionSnapshot {
                readonly: permissions.readonly(),
                unix_mode: None,
            }
        }
    }

    /// User-only permissions, for materialized temp files and manifests.
    pub fn restricted() -> Self {
        #[cfg(unix)]
        {
            PermissionSnapshot {
                readonly: false,
                unix_mode: Some(0o600),
            }
        }
        #[cfg(not(unix))]
        {
            PermissionSnapshot {
                readonly: false,
                unix_mode: None,
            }
        }
    }

    /// Applies this snapshot to an open file.
    ///
    /// The base is the file's *own* metadata: on Windows a `Permissions`
    /// object copied from a different inode carries that inode's attributes,
    /// and re-applying them (directory bits in particular) fails with
    /// InvalidParameter.
    pub fn apply_to(&self, file: &mut fs::File) -> std::io::Result<()> {
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(self.readonly);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            permissions.set_mode(self.unix_mode.unwrap_or(0o600));
        }
        file.set_permissions(permissions)
    }
}

/// The non-secret manifest left behind after ingestion (ADR-0020 §3).
///
/// It lives at a path the consumer does **not** read — never at the
/// consumed pathname — and records how to launch instead of what was
/// vaulted. It carries no secret material: names, an opaque vault
/// reference, and a timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedManifest {
    /// Manifest format version.
    pub manifest_version: u32,
    /// The consumed path, relative to the project root.
    pub original: String,
    /// The selected consumer adapter.
    pub adapter: String,
    /// The project binding.
    pub project_id: String,
    /// Opaque vault-side reference to the encrypted snapshot.
    pub snapshot_ref: String,
    /// How the material reaches a launched process.
    pub launch_hint: String,
    /// When the file was ingested.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

const MANIFEST_VERSION: u32 = 1;

/// The approved plan for ingesting one whole file (ADR-0020 §2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFilePlan {
    /// Project the file belongs to.
    pub project_id: String,
    /// Normalized path of the consumed file, relative to the project root.
    pub path: PathBuf,
    /// OS identity of the file at plan time.
    pub identity: FileIdentity,
    /// The original permissions, restored on rollback.
    pub permissions: PermissionSnapshot,
    /// The consumer adapter, **explicitly selected** — never defaulted.
    pub adapter: ConsumerAdapter,
    /// Where the non-secret manifest will live. Must differ from `path`.
    pub manifest_path: PathBuf,
    /// Keyed digest of the file bytes at plan time.
    pub snapshot_digest: Digest,
    /// Independent by default; shared is an explicit opt-in (§5).
    pub binding: SharedBinding,
}

impl ManagedFilePlan {
    /// Builds a plan for the file at `project_root.join(path)`.
    ///
    /// Runs the eligibility gate (ADR-0020 §1): a partly-sensitive file is
    /// refused here, before anything is read into a plan.
    pub fn build(
        project_id: &str,
        path: &Path,
        project_root: &Path,
        adapter: ConsumerAdapter,
        manifest_path: &Path,
        binding: SharedBinding,
        key: &PlanKey,
    ) -> Result<Self, ApplyError> {
        if let Eligibility::PartlySensitive { reason } = check_eligibility(path) {
            return Err(ApplyError::Ineligible(reason));
        }
        let normalized = crate::plan::normalize_relative(path)?;
        let normalized_manifest = crate::plan::normalize_relative(manifest_path)?;
        if normalized == normalized_manifest {
            // The manifest is for humans and launchers; a consumer reading
            // the consumed pathname would eat it as the value (§3).
            return Err(ApplyError::ManifestConsumed);
        }
        let target = resolve_target(project_root, &normalized)?;
        let metadata = fs::metadata(&target)?;
        let permissions = PermissionSnapshot::capture(&metadata.permissions());
        let bytes = fs::read(&target)?;
        let snapshot_digest = keyed_digest(key, &bytes);
        // Where the platform cannot capture identity (Windows, today), the
        // plan carries the portable placeholder; ingestion then enforces or
        // refuses per the caller's IdentityAssurance, exactly like the span
        // path. The byte digest is the stronger guard either way.
        let identity = FileIdentity::capture_from_path(&target).unwrap_or(FileIdentity::Windows {
            volume: 0,
            index: 0,
        });
        Ok(ManagedFilePlan {
            project_id: project_id.to_string(),
            path: normalized,
            identity,
            permissions,
            adapter,
            manifest_path: normalized_manifest,
            snapshot_digest,
            binding,
        })
    }
}

/// The outcome of ingesting one managed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedIngestStatus {
    /// The file is vaulted, the original removed, the manifest left behind.
    Ingested {
        /// Where the manifest lives, relative to the project root.
        manifest: PathBuf,
    },
    /// The consumer adapter failed its startup check. The original file is
    /// untouched; the manifest was cleaned up.
    StartupCheckFailed {
        /// Why.
        reason: String,
    },
    /// The eligibility gate refused the file.
    Ineligible {
        /// Why.
        reason: String,
    },
    /// Something failed after verification; the original was not removed.
    /// The journal shows the vault side committed, so the run is resumable.
    Failed {
        /// Why. Never echoes file contents.
        reason: String,
    },
}

/// Ingests one whole file: eligibility, vault commit, startup check,
/// removal, manifest, journal — in the ADR-0020 §2 order, reusing the P6
/// digest, journal, and atomic-write machinery.
///
/// The original is removed **only after** the startup check passes. Every
/// earlier failure leaves it exactly where it was.
pub fn ingest_managed_file(
    plan: &ManagedFilePlan,
    project_root: &Path,
    key: &PlanKey,
    assurance: crate::apply::IdentityAssurance,
    sink: &mut dyn VaultSink,
) -> Result<ManagedIngestStatus, ApplyError> {
    // The gate runs again at ingest time: a plan could have been built
    // before a rename, or reconstructed from storage.
    if let Eligibility::PartlySensitive { reason } = check_eligibility(&plan.path) {
        return Ok(ManagedIngestStatus::Ineligible { reason });
    }

    let canonical_root = project_root.canonicalize().map_err(ApplyError::Io)?;
    if !canonical_root.is_dir() {
        return Err(ApplyError::InvalidRoot);
    }
    let target = resolve_target(&canonical_root, &plan.path)?;

    // Snapshot-bound, like every other plan: the file on disk must still be
    // the file that was planned. (The original permissions were captured in
    // the plan itself and are what a rollback restores.)
    match (assurance, FileIdentity::capture_from_path(&target)) {
        (_, Ok(identity)) if identity == plan.identity => {}
        (_, Ok(_)) => {
            return Ok(ManagedIngestStatus::Failed {
                reason: "file identity no longer matches the plan".to_string(),
            });
        }
        (crate::apply::IdentityAssurance::AcknowledgedUnavailable, Err(_)) => {}
        (crate::apply::IdentityAssurance::Enforced, Err(_)) => {
            return Ok(ManagedIngestStatus::Failed {
                reason: "OS file identity check is unavailable on this platform;                          ingestion refused because the caller did not acknowledge                          IdentityAssurance::AcknowledgedUnavailable (ADR-0019 §2                          identity check)"
                    .to_string(),
            });
        }
    }
    let bytes = fs::read(&target)?;
    if keyed_digest(key, &bytes) != plan.snapshot_digest {
        return Ok(ManagedIngestStatus::Failed {
            reason: "file content changed since the plan was built".to_string(),
        });
    }

    // Vault before tree, per the ADR-0017 §4 ordering this crate already
    // uses for spans.
    let snapshot_ref = sink
        .store_managed_snapshot(&plan.project_id, &plan.path, &bytes)
        .map_err(|error| ApplyError::Sink(error.to_string()))?;
    let record = RecoveryRecord {
        plan_digest: plan.snapshot_digest,
        project_id: plan.project_id.clone(),
        path: plan.path.clone(),
        identity: plan.identity,
        snapshot_digest: plan.snapshot_digest,
        snapshot_ref: snapshot_ref.clone(),
        discovery: sv_runtime::DiscoveryPolicy::Opaque,
        locator: None,
        span: None,
        replacement: None,
        created_at: chrono::Utc::now(),
    };
    sink.store_recovery(&record)
        .map_err(|error| ApplyError::Sink(error.to_string()))?;
    sink.append_journal(JournalEntry {
        path: plan.path.clone(),
        state: JournalState::VaultStored { locator: None },
        at: chrono::Utc::now(),
    })
    .map_err(|error| ApplyError::Sink(error.to_string()))?;

    // The non-secret manifest goes to its own path — never the consumed
    // pathname — before the startup check, because a manifest-based check
    // needs it to exist.
    let manifest_target = resolve_target_after_create(&canonical_root, &plan.manifest_path)?;
    if let Some(parent) = manifest_target.parent() {
        fs::create_dir_all(parent).map_err(ApplyError::Io)?;
    }
    let manifest = ManagedManifest {
        manifest_version: MANIFEST_VERSION,
        original: plan.path.to_string_lossy().to_string(),
        adapter: plan.adapter.as_str().to_string(),
        project_id: plan.project_id.clone(),
        snapshot_ref,
        launch_hint: match plan.adapter {
            ConsumerAdapter::EnvInjection => {
                "launch via the vault launch adapter; material is injected as environment variables"
            }
            ConsumerAdapter::TempFile => {
                "launch via the vault launch adapter; material is materialized to a restricted temp path"
            }
        }
        .to_string(),
        created_at: chrono::Utc::now(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    replace_atomic(
        &manifest_target,
        &manifest_bytes,
        &PermissionSnapshot::restricted(),
    )
    .map_err(ApplyError::Io)?;

    // The removal gate: if the adapter cannot demonstrate the project still
    // works, the original stays and the manifest is cleaned up.
    if let Err(error) = sink.startup_check(plan.adapter, project_root, &plan.manifest_path) {
        let _ = fs::remove_file(&manifest_target);
        return Ok(ManagedIngestStatus::StartupCheckFailed {
            reason: error.to_string(),
        });
    }

    // Removal, only now. This is the point of no return; everything before
    // it is recoverable by leaving the file alone.
    if let Err(error) = fs::remove_file(&target) {
        return Ok(ManagedIngestStatus::Failed {
            reason: format!("the startup check passed but removal failed: {error}"),
        });
    }

    sink.append_journal(JournalEntry {
        path: plan.path.clone(),
        state: JournalState::FileReplaced,
        at: chrono::Utc::now(),
    })
    .map_err(|error| ApplyError::Sink(error.to_string()))?;
    sink.audit(sv_audit::AuditAction::PlanExecute, plan.snapshot_digest)
        .map_err(|error| ApplyError::Sink(error.to_string()))?;

    Ok(ManagedIngestStatus::Ingested {
        manifest: plan.manifest_path.clone(),
    })
}

/// Resolves a path that is *about to be created* beneath the root: the
/// same component whitelist and link refusal as [`resolve_target`], minus
/// the must-already-exist check.
fn resolve_target_after_create(root: &Path, relative: &Path) -> Result<PathBuf, ApplyError> {
    let mut probe = root.to_path_buf();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(segment) => probe.push(segment),
            _ => return Err(ApplyError::PathEscapesRoot),
        }
        if let Ok(metadata) = fs::symlink_metadata(&probe) {
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
    }
    Ok(probe)
}

/// The built-in, manifest-based startup check (ADR-0020 §2).
///
/// Verifies that the manifest exists, parses, names the selected adapter,
/// and records the file being ingested. A caller whose toolchain allows a
/// deeper probe — actually launching the project — should perform it inside
/// their [`VaultSink::startup_check`] implementation and may use this as
/// the first step.
pub fn startup_check(
    adapter: ConsumerAdapter,
    project_root: &Path,
    manifest_relative: &Path,
    expected_original: &Path,
) -> Result<(), String> {
    let manifest_path = project_root.join(manifest_relative);
    let raw = fs::read(&manifest_path)
        .map_err(|error| format!("managed-file manifest unreadable: {error}"))?;
    let manifest: ManagedManifest = serde_json::from_slice(&raw)
        .map_err(|error| format!("managed-file manifest malformed: {error}"))?;
    if manifest.adapter != adapter.as_str() {
        return Err(format!(
            "manifest names adapter '{}', but the plan selected '{}'",
            manifest.adapter,
            adapter.as_str()
        ));
    }
    if manifest.original != expected_original.to_string_lossy() {
        return Err("manifest records a different consumed path than the plan".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> PlanKey {
        PlanKey::from_bytes(&[11u8; 32]).expect("key")
    }

    /// The eligibility gate, in code: a .env is wholly sensitive; a
    /// docker-compose.yml — even one full of keys — is partly sensitive and
    /// refused with the reason stated (ADR-0020 §1).
    #[test]
    fn eligibility_gate_accepts_env_and_refuses_compose() {
        assert_eq!(
            check_eligibility(Path::new(".env")),
            Eligibility::WhollySensitive
        );
        assert_eq!(
            check_eligibility(Path::new("server.pem")),
            Eligibility::WhollySensitive
        );
        assert_eq!(
            check_eligibility(Path::new("id_ed25519")),
            Eligibility::WhollySensitive
        );
        assert_eq!(
            check_eligibility(Path::new("service-account-prod.json")),
            Eligibility::WhollySensitive
        );

        let compose = check_eligibility(Path::new("docker-compose.yml"));
        let Eligibility::PartlySensitive { reason } = compose else {
            panic!("docker-compose.yml must be refused");
        };
        assert!(reason.contains("allowlist"), "{reason}");
        assert!(reason.contains("configuration file"), "{reason}");

        // An env TEMPLATE is not live material.
        let example = check_eligibility(Path::new(".env.example"));
        assert!(matches!(example, Eligibility::PartlySensitive { .. }));

        let settings = check_eligibility(Path::new("appsettings.json"));
        assert!(matches!(settings, Eligibility::PartlySensitive { .. }));
    }

    /// ADR-0020 §5: storage dedup never collapses authority. Two projects
    /// with byte-identical .env files (identical keyed digests) produce two
    /// INDEPENDENT authorization records; the shared binding is opt-in and
    /// its blast radius is countable.
    #[test]
    fn identical_bytes_yield_independent_authorizations_unless_shared_explicitly() {
        let digest = keyed_digest(&key(), b"identical .env bytes");
        let first = authorization_record("proj-a", digest, &SharedBinding::Independent);
        let second = authorization_record("proj-b", digest, &SharedBinding::Independent);
        assert_ne!(first.resource_id, second.resource_id);
        assert_eq!(
            rotation_blast_radius(std::slice::from_ref(&first), &SharedBinding::Independent),
            1
        );

        // Opt-in sharing changes the record and widens the blast radius,
        // and the UI must show that number before the user accepts.
        let shared = SharedBinding::Shared {
            binding_id: "monorepo".to_string(),
        };
        let s1 = authorization_record("proj-a", digest, &shared);
        let s2 = authorization_record("proj-b", digest, &shared);
        let s3 = authorization_record("proj-c", digest, &SharedBinding::Independent);
        assert_eq!(s1.resource_id, s2.resource_id);
        assert_ne!(s1.resource_id, s3.resource_id);
        let all = [s1, s2, s3];
        assert_eq!(rotation_blast_radius(&all, &shared), 2);
    }
}
