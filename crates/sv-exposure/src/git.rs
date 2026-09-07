use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str;

use chrono::{TimeZone, Utc};
use sv_scan::ScanFinding;

use crate::urgency::{derive_urgency, Exposure, FindingExposure, ScanLimit};

/// Error running git.
#[derive(Debug, thiserror::Error)]
pub enum GitRunError {
    /// The repository root is not a directory.
    #[error("repo root is not a readable directory")]
    InvalidRoot,
    /// Git is not installed or not on PATH.
    #[error("git executable not found")]
    GitNotFound,
    /// Git returned a non-zero status.
    #[error("git command failed: {message}")]
    CommandFailed {
        /// Exit status, when available.
        status: Option<i32>,
        /// stderr/stdout summary.
        message: String,
    },
    /// Output was not valid UTF-8.
    #[error("git output was not valid UTF-8")]
    NotUtf8,
}

/// Error classifying a finding.
#[derive(Debug, thiserror::Error)]
pub enum ClassificationError {
    /// Could not run git.
    #[error(transparent)]
    Git(#[from] GitRunError),
    /// The finding's rule id is not known to the issuer table.
    #[error("no issuer mapping for rule id {0}")]
    UnknownRuleId(String),
    /// The finding is not a secret, so exposure classification does not apply.
    #[error("exposure classification only applies to secret findings")]
    NotASecret,
}

/// One commit that contained a matching blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitHit {
    /// Commit object id.
    pub oid: String,
    /// Author-commit timestamp as seconds since epoch; may be backdated.
    pub timestamp_seconds: i64,
    /// Remote-tracking ref that reaches this commit, if any.
    pub remote: Option<String>,
}

/// Index of git blobs reachable from local and remote-tracking refs plus
/// reflog roots.
#[derive(Debug, Clone, Default)]
pub struct BlobIndex {
    /// Map from blob object id to the set of commits that reference it.
    pub by_blob: HashMap<String, Vec<CommitHit>>,
    /// Scan limits discovered while building the index.
    pub limits: Vec<ScanLimit>,
    /// Number of refs scanned.
    pub scanned_refs: usize,
}

impl BlobIndex {
    /// True when the index is empty because there is no git history.
    pub fn is_empty(&self) -> bool {
        self.by_blob.is_empty()
    }
}

/// Build a [`BlobIndex`] for the repository at `root`.
///
/// The index contains every unique blob reachable from:
/// * all local refs,
/// * all remote-tracking refs,
/// * all tags,
/// * stash and notes,
/// * reflog roots (best-effort: entries may be expired or garbage-collected).
///
/// External diff and textconv helpers are disabled, and no implicit network fetch
/// is performed. Blobs are not read here — only their object ids are collected.
/// Detection runs later over each blob once via [`classify_finding`].
pub fn collect_blobs(root: &Path) -> Result<BlobIndex, GitRunError> {
    if !root.is_dir() {
        return Err(GitRunError::InvalidRoot);
    }

    // Not a git repository. There is no history to scan; this is a complete
    // answer, not an incomplete one, so no ScanLimit is recorded.
    if !root.join(".git").exists() {
        return Ok(BlobIndex::default());
    }

    let mut index = BlobIndex::default();

    // Collect every ref we will scan. `for-each-ref` is machine-readable and
    // includes local, remote-tracking, and tag refs.
    let ref_lines = run_git(
        root,
        &[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/heads",
            "refs/remotes",
            "refs/tags",
            "refs/stash",
            "refs/notes",
        ],
    )?;

    let mut seen_commits: HashSet<String> = HashSet::new();
    let mut commit_queue: Vec<String> = Vec::new();
    let mut remote_by_commit: HashMap<String, String> = HashMap::new();

    for line in ref_lines.lines().filter(|l| !l.is_empty()) {
        let (oid, refname) = line
            .split_once(' ')
            .ok_or_else(|| GitRunError::CommandFailed {
                status: None,
                message: "unexpected for-each-ref format".into(),
            })?;

        index.scanned_refs += 1;

        // Remote-tracking refs identify commits that have at some point been
        // fetched. We record the remote name so we can later flag
        // `FoundOnRemote`.
        let remote = refname
            .strip_prefix("refs/remotes/")
            .and_then(|suffix| suffix.split('/').next().map(|name| name.to_string()));

        if !seen_commits.insert(oid.to_string()) {
            if let Some(r) = remote {
                remote_by_commit.insert(oid.to_string(), r);
            }
            continue;
        }
        if let Some(r) = remote {
            remote_by_commit.insert(oid.to_string(), r);
        }
        commit_queue.push(oid.to_string());
    }

    // Add reflog roots. These may point to objects unreachable from current
    // refs. If the command fails or some objects are gone, we record the
    // corresponding limits and continue with what we have.
    match collect_reflog_roots(root) {
        Ok(roots) => {
            for oid in roots {
                if seen_commits.insert(oid.clone()) {
                    commit_queue.push(oid);
                    index.limits.push(ScanLimit::ReflogExpired);
                }
            }
        }
        Err(_) => index.limits.push(ScanLimit::ReflogExpired),
    }

    // Walk every queued commit once and collect reachable blob ids.
    // `git rev-list --objects` prints lines of the form:
    //   <commit>
    //   <object> <path>
    // where <object> may be a tree or a blob. We batch-check object types with
    // `cat-file --batch-check` to avoid spawning git once per object.
    let mut object_paths: Vec<(String, String, String)> = Vec::new();
    if !commit_queue.is_empty() {
        let mut args: Vec<String> = vec!["rev-list".to_string(), "--objects".to_string()];
        args.extend(commit_queue);

        let output = run_git(root, &args.iter().map(|s| s.as_str()).collect::<Vec<_>>())?;

        let mut current_commit: Option<String> = None;
        for line in output.lines().filter(|l| !l.is_empty()) {
            // The first whitespace-separated token is an object id.
            let oid = line.split_whitespace().next().unwrap_or(line).to_string();
            if oid.len() != 40 {
                continue;
            }

            // A line with a single 40-hex token is a commit.
            if line.split_whitespace().count() == 1 {
                current_commit = Some(oid);
                continue;
            }

            // Lines with a second token name a path; the object is a tree or
            // blob. Record it for batch type checking.
            if let Some(path) = line.split_whitespace().nth(1) {
                if let Some(commit) = current_commit.as_ref() {
                    object_paths.push((commit.clone(), oid, path.to_string()));
                }
            }
        }
    }

    // Batch-check object types. This is one git subprocess for all candidates.
    let blob_oids = batch_check_blob_types(root, &object_paths)?;

    // Resolve commit timestamps once per commit.
    let mut timestamp_cache: HashMap<String, i64> = HashMap::new();
    for (commit, blob_oid, _) in object_paths {
        if !blob_oids.contains(&blob_oid) {
            continue;
        }
        let ts = *timestamp_cache
            .entry(commit.clone())
            .or_insert(commit_timestamp(root, &commit).unwrap_or(0));
        let remote = remote_by_commit.get(&commit).cloned();
        index.by_blob.entry(blob_oid).or_default().push(CommitHit {
            oid: commit.clone(),
            timestamp_seconds: ts,
            remote,
        });
    }

    // Detect a shallow clone.
    if is_shallow(root)? {
        index.limits.push(ScanLimit::ShallowClone);
    }

    // Detect submodules we did not enter.
    if let Ok(modules) = run_git(root, &["config", "--file", ".gitmodules", "--list"]) {
        let count = modules
            .lines()
            .filter(|l| l.starts_with("submodule."))
            .count();
        if count > 0 {
            index.limits.push(ScanLimit::SubmodulesNotScanned { count });
        }
    }

    Ok(index)
}

fn collect_reflog_roots(root: &Path) -> Result<Vec<String>, GitRunError> {
    // `git reflog show --all` is not reliable. Instead, list every reflog
    // entry for refs and for HEAD, then extract the old/new commit ids.
    let mut roots = Vec::new();
    for reflog in ["HEAD", "--all"] {
        if let Ok(out) = run_git(root, &["reflog", reflog]) {
            for line in out.lines().filter(|l| !l.is_empty()) {
                // Format: <oid> <ref>@{<n>}: <message>
                // We take the first 40-hex token as the commit recorded in the
                // reflog entry.
                if let Some(token) = line.split_whitespace().next() {
                    if token.len() == 40 {
                        roots.push(token.to_string());
                    }
                }
            }
        }
    }
    Ok(roots)
}

fn batch_check_blob_types(
    root: &Path,
    object_paths: &[(String, String, String)],
) -> Result<HashSet<String>, GitRunError> {
    if object_paths.is_empty() {
        return Ok(HashSet::new());
    }

    let mut cmd = base_git_cmd(root);
    cmd.arg("cat-file")
        .arg("--batch-check=%(objectname) %(objecttype)")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(git_spawn_error)?;
    {
        let stdin = child.stdin.as_mut().expect("piped stdin");
        for (_, oid, _) in object_paths {
            use std::io::Write;
            writeln!(stdin, "{oid}").map_err(|e| GitRunError::CommandFailed {
                status: None,
                message: e.to_string(),
            })?;
        }
    }

    let output = child.wait_with_output().map_err(git_spawn_error)?;
    if !output.status.success() {
        return Err(GitRunError::CommandFailed {
            status: output.status.code(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let mut blobs = HashSet::new();
    let text = String::from_utf8(output.stdout).map_err(|_| GitRunError::NotUtf8)?;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 2 && parts[1] == "blob" {
            blobs.insert(parts[0].to_string());
        }
    }
    Ok(blobs)
}

fn is_shallow(root: &Path) -> Result<bool, GitRunError> {
    let path = root.join(".git/shallow");
    match std::fs::metadata(path) {
        Ok(m) => Ok(m.is_file()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(GitRunError::CommandFailed {
            status: None,
            message: format!("could not read .git/shallow: {e}"),
        }),
    }
}

fn commit_timestamp(root: &Path, commit: &str) -> Result<i64, GitRunError> {
    let out = run_git(root, &["log", "-1", "--format=%ct", commit])?;
    out.trim()
        .parse::<i64>()
        .map_err(|e| GitRunError::CommandFailed {
            status: None,
            message: format!("invalid commit timestamp for {commit}: {e}"),
        })
}

/// Build the common git command with helpers and network disabled.
fn base_git_cmd(root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(root)
        // Never invoke external diff/textconv helpers; keep plaintext blobs in
        // git's own process only.
        .env("GIT_EXTERNAL_DIFF", "")
        .env("GIT_DIFF_EXTERNAL", "")
        .env("GIT_TEXTCONV", "")
        .env("GIT_CONFIG_GLOBAL", "")
        .env("GIT_CONFIG_SYSTEM", "")
        .arg("--no-pager")
        .arg("-c")
        .arg("core.pager=")
        .arg("-c")
        .arg("diff.external=")
        .arg("-c")
        .arg("diff.textconv=")
        .arg("-c")
        .arg("protocol.allow=never");
    cmd
}

fn git_spawn_error(e: std::io::Error) -> GitRunError {
    if e.kind() == std::io::ErrorKind::NotFound {
        GitRunError::GitNotFound
    } else {
        GitRunError::CommandFailed {
            status: None,
            message: e.to_string(),
        }
    }
}

/// Run `git` in `root` with external helpers and network disabled.
fn run_git(root: &Path, args: &[&str]) -> Result<String, GitRunError> {
    let mut cmd = base_git_cmd(root);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().map_err(git_spawn_error)?;

    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(GitRunError::CommandFailed {
            status: output.status.code(),
            message,
        });
    }

    String::from_utf8(output.stdout).map_err(|_| GitRunError::NotUtf8)
}

/// Classify the exposure of one scan finding against the blob index.
///
/// The matched value is loaded from git as a blob and scanned in-process. It is
/// never passed as a command-line argument.
pub fn classify_finding(
    root: &Path,
    index: &BlobIndex,
    finding: &ScanFinding,
) -> Result<FindingExposure, ClassificationError> {
    let rule_id = match &finding.kind {
        sv_scan::FindingKind::Secret { rule_id } => rule_id.clone(),
        _ => return Err(ClassificationError::NotASecret),
    };

    let issuer = crate::issuer::lookup(&rule_id)
        .ok_or_else(|| ClassificationError::UnknownRuleId(rule_id.clone()))?;

    if index.is_empty() {
        // An empty index means nothing was examined — not a git repository, or
        // one with no commits. Record that as a limit so the answer derives
        // `Undetermined`: with an empty limits list it would otherwise derive
        // `None` and report "no rotation needed" for a search that never ran.
        let mut limits = index.limits.clone();
        if !limits.contains(&ScanLimit::NothingScanned) {
            limits.push(ScanLimit::NothingScanned);
        }
        let exposure = Exposure::NotFoundInScannedHistory {
            scanned_refs: index.scanned_refs,
            limits,
        };
        return Ok(FindingExposure {
            finding: finding.clone(),
            exposure: exposure.clone(),
            urgency: derive_urgency(&exposure),
            issuer,
        });
    }

    let mut hits: Vec<CommitHit> = Vec::new();
    for blob_oid in index.by_blob.keys() {
        let content = cat_blob(root, blob_oid)?;
        if blob_contains_finding(finding, &content) {
            hits.extend(index.by_blob[blob_oid].iter().cloned());
        }
    }

    if hits.is_empty() {
        let exposure = Exposure::NotFoundInScannedHistory {
            scanned_refs: index.scanned_refs,
            limits: index.limits.clone(),
        };
        return Ok(FindingExposure {
            finding: finding.clone(),
            exposure: exposure.clone(),
            urgency: derive_urgency(&exposure),
            issuer,
        });
    }

    let remote_hits: Vec<_> = hits.iter().filter(|h| h.remote.is_some()).collect();

    let exposure = if remote_hits.is_empty() {
        Exposure::FoundLocalOnly {
            commits: hits.len(),
        }
    } else {
        let earliest = remote_hits
            .iter()
            .map(|h| h.timestamp_seconds)
            .min()
            .unwrap_or(0);
        let earliest_dt = Utc
            .timestamp_opt(earliest, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let remote = remote_hits
            .iter()
            .filter_map(|h| h.remote.as_ref())
            .next()
            .cloned()
            .unwrap_or_default();
        // Public/private status of the remote repository cannot be determined
        // from local evidence. P12 will add the GitHub API check.
        Exposure::FoundOnRemote {
            remote,
            earliest_commit: earliest_dt,
        }
    };

    let urgency = derive_urgency(&exposure);

    Ok(FindingExposure {
        finding: finding.clone(),
        exposure,
        urgency,
        issuer,
    })
}

fn cat_blob(root: &Path, blob_oid: &str) -> Result<Vec<u8>, GitRunError> {
    let mut cmd = base_git_cmd(root);
    cmd.arg("cat-file")
        .arg("blob")
        .arg(blob_oid)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().map_err(git_spawn_error)?;

    if !output.status.success() {
        return Err(GitRunError::CommandFailed {
            status: output.status.code(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    Ok(output.stdout)
}

/// Check whether a blob's bytes contain a match for the same rule as the
/// finding.
///
/// `ScanFinding` does not carry the matched value, so we re-run the existing
/// `sv_scan` detectors over the blob bytes and check whether the same rule
/// matched anywhere in the blob. This may classify more broadly than a strict
/// value equality check, but it never under-rotates: if the credential pattern
/// existed anywhere in scanned history, rotation should be considered. The UI
/// join by path+span prevents attaching the result to the wrong occurrence.
fn blob_contains_finding(finding: &ScanFinding, content: &[u8]) -> bool {
    let Ok(text) = str::from_utf8(content) else {
        return false;
    };

    let salt = [0u8; 32];
    let candidates = sv_scan::detect_secrets(
        text,
        &PathBuf::from("blob"),
        sv_scan::PreviewMode::Opaque,
        salt,
    );

    let target = finding_rule_id(finding);
    candidates.iter().any(|candidate| match &candidate.kind {
        sv_scan::FindingKind::Secret { rule_id } => Some(rule_id.as_str()) == target,
        _ => false,
    })
}

fn finding_rule_id(finding: &ScanFinding) -> Option<&str> {
    match &finding.kind {
        sv_scan::FindingKind::Secret { rule_id } => Some(rule_id.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        run_git(dir.path(), &["init", "--quiet"]).unwrap();
        run_git(dir.path(), &["config", "user.email", "test@example.com"]).unwrap();
        run_git(dir.path(), &["config", "user.name", "Test User"]).unwrap();
        dir
    }

    fn write_and_commit(dir: &tempfile::TempDir, path: &str, content: &str, message: &str) {
        let file_path = dir.path().join(path);
        std::fs::write(&file_path, content).unwrap();
        run_git(dir.path(), &["add", path]).unwrap();
        run_git(dir.path(), &["commit", "-m", message, "--quiet"]).unwrap();
    }

    #[test]
    fn collect_blobs_indexes_committed_blob() {
        let dir = temp_repo();
        // This test only checks that a committed blob lands in the index, so
        // it deliberately holds no credential-shaped literal: a fixture token
        // in a source file is a real match for history scanners, ours and
        // other people's alike. Tests that need a token shape build it at
        // runtime, as `classify_finding_detects_secret_in_history` does.
        write_and_commit(&dir, "notes.txt", "ordinary file contents\n", "add file");
        let index = collect_blobs(dir.path()).unwrap();
        assert!(!index.is_empty());
        assert_eq!(index.scanned_refs, 1); // refs/heads/main only
    }

    #[test]
    fn classify_finding_detects_secret_in_history() {
        use crate::RotationUrgency;
        let dir = temp_repo();
        let token = format!("gho_{}", "a".repeat(36));
        write_and_commit(&dir, "secret.txt", &format!("{token}\n"), "add secret");
        let index = collect_blobs(dir.path()).unwrap();

        let finding = ScanFinding {
            path: PathBuf::from("secret.txt"),
            line: 1,
            start: 0,
            end: token.len(),
            confidence: sv_scan::Confidence::High,
            kind: sv_scan::FindingKind::Secret {
                rule_id: "github_oauth".into(),
            },
            preview: sv_scan::mask_opaque(&token),
            matched_fingerprint: String::new(),
        };

        let exposure = classify_finding(dir.path(), &index, &finding).unwrap();
        assert!(
            matches!(exposure.exposure, Exposure::FoundLocalOnly { commits } if commits >= 1),
            "expected local-only exposure, got {:?}",
            exposure.exposure
        );
        assert_eq!(exposure.issuer.id(), "github_oauth");
        assert_eq!(exposure.urgency, RotationUrgency::BeforePush);
    }

    #[test]
    fn classify_finding_reports_not_found_when_secret_missing() {
        use crate::RotationUrgency;
        let dir = temp_repo();
        write_and_commit(&dir, "safe.txt", "nothing sensitive here\n", "initial");
        let index = collect_blobs(dir.path()).unwrap();
        let finding = ScanFinding {
            path: PathBuf::from("safe.txt"),
            line: 1,
            start: 0,
            end: 40,
            confidence: sv_scan::Confidence::High,
            kind: sv_scan::FindingKind::Secret {
                rule_id: "github_oauth".into(),
            },
            preview: "gho_****".into(),
            matched_fingerprint: String::new(),
        };
        let exposure = classify_finding(dir.path(), &index, &finding).unwrap();
        assert!(
            matches!(exposure.exposure, Exposure::NotFoundInScannedHistory { .. }),
            "expected not found, got {:?}",
            exposure.exposure
        );
        assert_eq!(exposure.urgency, RotationUrgency::None);
    }

    #[test]
    fn not_a_repo_returns_empty_index() {
        let dir = tempfile::tempdir().unwrap();
        let index = collect_blobs(dir.path()).unwrap();
        assert!(index.is_empty());
        assert!(index.limits.is_empty());
    }
}
