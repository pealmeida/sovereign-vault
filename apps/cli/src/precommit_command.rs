//! `sovereign-vault precommit` — gate a commit on the STAGED content.
//!
//! Scans only what git has staged (the index), never the working tree: the two
//! differ when a file is partially staged, and the commit contains the index.
//! Staged blobs are held in memory only — they are never written to disk — and
//! run through [`sv_scan::detect_secrets`], the production detector (P14 step
//! 2: wiring, not new detection).
//!
//! The scan reports a finding's file, line, rule, confidence, and the opaque
//! masked preview. The matched value is never printed, logged, or persisted.
//!
//! Exit codes mirror `scan`: 0 = clean, 2 = findings present, 1 = failure. A
//! pre-commit hook must treat every non-zero exit as BLOCK, so a broken
//! scanner can never become a silent allow (fail closed).
//!
//! Ordering note (P14 §0): if a live credential is ALREADY exposed, rotation
//! comes first. This hook prevents the next leak; it does nothing for a key
//! that is already out. Help text and hook output must not imply otherwise.

use std::path::Path;
use std::process::Command;

use sv_scan::{detect_secrets, PreviewMode, ScanFinding};

/// Scan the staged content of the repository containing `cwd`.
///
/// Returns whether any finding survived, so `main` can map it to exit 2.
pub fn run(cwd: &Path) -> Result<bool, String> {
    let repo = repo_root(cwd)?;
    let paths = staged_paths(&repo)?;
    if paths.is_empty() {
        println!("[precommit] nothing staged; nothing to scan.");
        return Ok(false);
    }
    eprintln!("[precommit] scanning {} staged file(s)...", paths.len());
    scan_staged(&repo, &paths)
}

/// Run one git command with stdout captured.
///
/// P14 E1: only plumbing forms are used — `--name-only` diffs and `git show`
/// of an index blob. Neither invokes textconv or external diff drivers, so no
/// third-party binary ever sees the staged bytes.
fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run git ({e}); treating as failure (fail closed)"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}

fn repo_root(cwd: &Path) -> Result<std::path::PathBuf, String> {
    let out = git(cwd, &["rev-parse", "--show-toplevel"])?;
    let root = String::from_utf8_lossy(&out).trim().to_string();
    if root.is_empty() {
        return Err("not inside a git repository (fail closed)".into());
    }
    Ok(std::path::PathBuf::from(root))
}

/// Staged file list, NUL-separated so git never quotes unusual paths.
fn staged_paths(repo: &Path) -> Result<Vec<String>, String> {
    let out = git(
        repo,
        &["diff", "--cached", "--name-only", "-z", "--diff-filter=ACM"],
    )?;
    Ok(String::from_utf8_lossy(&out)
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect())
}

/// One staged blob's content, from the index — not from the working tree.
///
/// `:0:<path>` is the fully-qualified form of `:<path>` (index stage 0); the
/// explicit stage keeps a path containing `:` from being misread as a
/// revision.
fn staged_blob(repo: &Path, path: &str) -> Result<Vec<u8>, String> {
    git(repo, &["show", &format!(":0:{path}")])
}

fn scan_staged(repo: &Path, paths: &[String]) -> Result<bool, String> {
    // Fresh per-run salt for process-local fingerprints. Fingerprints are
    // never printed here; the salt just keeps two runs unlinkable.
    let salt: [u8; 32] = {
        let bytes = sv_core::sv_crypto::random_bytes(32).map_err(|e| e.to_string())?;
        bytes
            .try_into()
            .map_err(|_| "short random salt".to_string())?
    };

    let started = std::time::Instant::now();
    let mut findings: Vec<ScanFinding> = Vec::new();
    let mut not_examined: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for path in paths {
        // The blob lives only in memory: convert in place, and skip
        // non-UTF-8 blobs the same way the walker does — a legitimate,
        // reported skip, not a failure.
        let blob = staged_blob(repo, path)?;
        let Ok(content) = String::from_utf8(blob) else {
            not_examined.push(format!("{path} (binary/non-UTF-8, not text-scanned)"));
            continue;
        };
        scanned += 1;
        // Opaque previews, explicitly: this output goes to a terminal and
        // possibly into CI logs, so it must never carry a matched value.
        findings.extend(detect_secrets(
            &content,
            Path::new(path),
            PreviewMode::Opaque,
            salt,
        ));
    }

    let elapsed = started.elapsed();
    findings.sort_by(|a, b| a.path.cmp(&b.path).then(a.start.cmp(&b.start)));

    if findings.is_empty() {
        println!(
            "[precommit] {scanned} staged file(s) scanned in {:.2}s; no credentials found.",
            elapsed.as_secs_f64()
        );
        // Say what was checked, not just that nothing turned up. This gate
        // looks for credentials; it does not look for personal data, which
        // would flag every email and IP address in a fixture and get the hook
        // uninstalled. A user who reads "no findings" and infers "nothing
        // sensitive here" has been told something this scan did not check.
        println!(
            "[precommit] (credential patterns only; personal data is not checked here \
             — run `sovereign-vault scan` for that.)"
        );
        for note in &not_examined {
            println!("[precommit] not examined: {note}");
        }
        return Ok(false);
    }

    println!(
        "[precommit] {} finding(s) in staged content (scanned in {:.2}s):",
        findings.len(),
        elapsed.as_secs_f64()
    );
    for finding in &findings {
        println!(
            "  {}:{}  {}  {:?}  {}",
            finding.path.display(),
            finding.line,
            crate::scan_command::class_label(&finding.kind),
            finding.confidence,
            finding.preview
        );
    }
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    for finding in &findings {
        match finding.confidence {
            sv_scan::Confidence::High => high += 1,
            sv_scan::Confidence::Medium => medium += 1,
            sv_scan::Confidence::Low => low += 1,
        }
    }
    println!("[precommit] {high} high, {medium} medium, {low} low confidence.");
    for note in &not_examined {
        println!("[precommit] not examined: {note}");
    }
    println!("[precommit] COMMIT BLOCKED.");
    println!("[precommit]   Fix or remove the flagged content, or commit anyway with:");
    println!("[precommit]     git commit --no-verify");
    println!("[precommit]   --no-verify skips this check entirely; use it deliberately.");
    println!(
        "[precommit] If a flagged credential is already exposed somewhere, rotate it first:
[precommit] this hook prevents the next leak, it does not fix an existing one."
    );
    Ok(true)
}
