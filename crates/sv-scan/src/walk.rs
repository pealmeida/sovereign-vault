//! Read-only file-system walker for the project scanner.
//!
//! Everything here is discovery: the walker never creates, modifies, or
//! deletes any file. Per-file failures are recorded as [`Skipped`] entries
//! instead of aborting the scan.

use std::fs;
use std::path::{Path, PathBuf};

use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;

use crate::types::{Coverage, ScanConfig, SkipReason, Skipped};
use crate::ScanError;

/// Number of leading bytes inspected when sniffing for binary content.
const BINARY_SNIFF_LEN: usize = 8192;

/// A file that passed the walk filters, with its text content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedFile {
    /// Path relative to the scan root.
    pub path: PathBuf,
    /// Full UTF-8 content.
    pub content: String,
}

/// Walk `root`, returning readable UTF-8 text files plus skip accounting.
///
/// Read-only: never creates, modifies, or deletes anything. Files that are
/// too large, binary, non-UTF-8, or unreadable are reported through
/// [`Coverage`] rather than propagated as errors. Results are ordered by
/// path so repeated walks of an unchanged tree are byte-for-byte identical.
pub fn walk(root: &Path, config: &ScanConfig) -> Result<(Vec<ScannedFile>, Coverage), ScanError> {
    if !root.is_dir() {
        return Err(ScanError::InvalidRoot);
    }

    let mut override_builder = OverrideBuilder::new(root);
    // `.git` is history, not working tree: always excluded, regardless of config.
    override_builder
        .add("!.git/**")
        .map_err(|e| ScanError::Walk(e.to_string()))?;
    for pattern in &config.exclude {
        override_builder
            .add(&format!("!{pattern}"))
            .map_err(|e| ScanError::Walk(e.to_string()))?;
    }
    let overrides = override_builder
        .build()
        .map_err(|e| ScanError::Walk(e.to_string()))?;

    let walker = WalkBuilder::new(root)
        // Dotfiles such as `.env` are the primary target of this feature.
        .hidden(false)
        .git_ignore(config.respect_gitignore)
        .git_global(config.respect_gitignore)
        .git_exclude(config.respect_gitignore)
        .parents(config.respect_gitignore)
        .follow_links(config.follow_symlinks)
        .overrides(overrides)
        .build();

    let mut files: Vec<ScannedFile> = Vec::new();
    let mut coverage = Coverage::default();

    for entry in walker {
        // Walker-level errors (e.g. an unreadable directory) skip entries;
        // one failure must not abort the whole scan.
        let Ok(entry) = entry else { continue };

        // Directories are not files: never emit or account for them.
        if entry.file_type().is_some_and(|ft| ft.is_dir()) {
            continue;
        }

        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_path_buf();

        // Size is checked before any content is read.
        let metadata = match fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(_) => {
                record_skip(&mut coverage, relative, SkipReason::Unreadable);
                continue;
            }
        };
        if metadata.is_dir() {
            // E.g. a symlink pointing at a directory with `follow_links` off.
            continue;
        }
        if metadata.len() > config.max_file_bytes {
            record_skip(&mut coverage, relative, SkipReason::TooLarge);
            continue;
        }

        let bytes = match fs::read(entry.path()) {
            Ok(b) => b,
            Err(_) => {
                record_skip(&mut coverage, relative, SkipReason::Unreadable);
                continue;
            }
        };
        let sniff = &bytes[..bytes.len().min(BINARY_SNIFF_LEN)];
        if sniff.contains(&0) {
            record_skip(&mut coverage, relative, SkipReason::Binary);
            continue;
        }
        let content = match String::from_utf8(bytes) {
            Ok(c) => c,
            Err(_) => {
                record_skip(&mut coverage, relative, SkipReason::NotUtf8);
                continue;
            }
        };

        coverage.files_scanned += 1;
        coverage.bytes_scanned += content.len() as u64;
        files.push(ScannedFile {
            path: relative,
            content,
        });
    }

    // Re-include credential-bearing files that an ignore rule excluded. Without
    // this the default configuration defeats the tool: `.env` is both the most
    // common home for a live secret and one of the most commonly ignored paths.
    if config.respect_gitignore && !config.always_scan.is_empty() {
        collect_always_scan(root, config, &mut files, &mut coverage)?;
    }

    // `ignore`'s walker does not guarantee ordering, so sort for determinism.
    files.sort_by(|a, b| a.path.cmp(&b.path));
    coverage.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    coverage.files_skipped = coverage.skipped.len() as u64;
    coverage.files_ignored = count_ignored(root, config, &files, &coverage);

    Ok((files, coverage))
}

/// Count the files an ignore rule or exclude glob removed before they could be
/// read.
///
/// `ignore` applies its filters inside the iterator, so excluded entries are
/// never yielded and are invisible to the main loop. Coverage that omitted them
/// would conflate "the scanner looked and found nothing" with "the scanner
/// never looked" — the exact silent-skip failure ADR-0017 requires the report
/// to rule out. A second, unfiltered walk counts the difference.
///
/// Only the count is kept, not the paths: an excluded tree can hold hundreds of
/// thousands of files, and the number is what makes coverage honest.
fn count_ignored(
    root: &Path,
    config: &ScanConfig,
    files: &[ScannedFile],
    coverage: &Coverage,
) -> u64 {
    let examined = files.len() as u64 + coverage.skipped.len() as u64;

    let mut total: u64 = 0;
    let unfiltered = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .ignore(false)
        .follow_links(config.follow_symlinks)
        .build();
    for entry in unfiltered.flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            // `.git` internals are never in scope, so they are not a coverage
            // gap the user needs to reason about.
            let is_git_internal = entry
                .path()
                .strip_prefix(root)
                .map(|rel| rel.components().any(|c| c.as_os_str() == ".git"))
                .unwrap_or(false);
            if !is_git_internal {
                total += 1;
            }
        }
    }

    total.saturating_sub(examined)
}

/// Append a skip entry to the coverage accounting.
fn record_skip(coverage: &mut Coverage, path: PathBuf, reason: SkipReason) {
    coverage.skipped.push(Skipped { path, reason });
}

/// Scan credential-bearing files that an ignore rule excluded from the main
/// walk.
///
/// A second traversal is required rather than a tweak to the first: `ignore`
/// prunes an ignored *directory* without descending into it, so a `.env` inside
/// an ignored folder is never offered to the main loop at all. This pass walks
/// with ignore handling disabled and keeps only paths matching
/// [`ScanConfig::always_scan`], minus anything the user's own excludes remove.
///
/// Files already collected are not added twice.
fn collect_always_scan(
    root: &Path,
    config: &ScanConfig,
    files: &mut Vec<ScannedFile>,
    coverage: &mut Coverage,
) -> Result<(), ScanError> {
    let mut include_builder = OverrideBuilder::new(root);
    for pattern in &config.always_scan {
        include_builder
            .add(pattern)
            .map_err(|e| ScanError::Walk(e.to_string()))?;
    }
    let includes = include_builder
        .build()
        .map_err(|e| ScanError::Walk(e.to_string()))?;

    // The user's explicit excludes still win: a force-include is a correction
    // to ignore-file defaults, not an override of what the caller asked for.
    let mut exclude_builder = OverrideBuilder::new(root);
    exclude_builder
        .add("!.git/**")
        .map_err(|e| ScanError::Walk(e.to_string()))?;
    for pattern in &config.exclude {
        exclude_builder
            .add(&format!("!{pattern}"))
            .map_err(|e| ScanError::Walk(e.to_string()))?;
    }
    let excludes = exclude_builder
        .build()
        .map_err(|e| ScanError::Walk(e.to_string()))?;

    let already: std::collections::BTreeSet<PathBuf> =
        files.iter().map(|f| f.path.clone()).collect();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .ignore(false)
        .follow_links(config.follow_symlinks)
        .build();

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        if !includes.matched(entry.path(), false).is_whitelist() {
            continue;
        }
        if excludes.matched(entry.path(), false).is_ignore() {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_path_buf();
        if already.contains(&relative) {
            continue;
        }

        let Ok(metadata) = fs::metadata(entry.path()) else {
            record_skip(coverage, relative, SkipReason::Unreadable);
            continue;
        };
        if metadata.len() > config.max_file_bytes {
            record_skip(coverage, relative, SkipReason::TooLarge);
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            record_skip(coverage, relative, SkipReason::Unreadable);
            continue;
        };
        if bytes[..bytes.len().min(BINARY_SNIFF_LEN)].contains(&0) {
            record_skip(coverage, relative, SkipReason::Binary);
            continue;
        }
        let Ok(content) = String::from_utf8(bytes) else {
            record_skip(coverage, relative, SkipReason::NotUtf8);
            continue;
        };

        coverage.files_scanned += 1;
        coverage.bytes_scanned += content.len() as u64;
        files.push(ScannedFile {
            path: relative,
            content,
        });
    }

    Ok(())
}
