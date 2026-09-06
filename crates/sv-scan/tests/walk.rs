//! Integration tests for the `sv-scan` file walker.

use std::fs;
use std::path::Path;

use sv_scan::{walk, ScanConfig, ScanError, SkipReason};

/// Writes `bytes` to `root/rel`, creating parent directories as needed.
fn write_file(root: &Path, rel: &str, bytes: &[u8]) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).unwrap();
        }
    }
    fs::write(&path, bytes).unwrap();
}

/// Writes UTF-8 `text` to `root/rel`.
fn write_text(root: &Path, rel: &str, text: &str) {
    write_file(root, rel, text.as_bytes());
}

/// Creates a fake git repository marker so gitignore rules take effect.
fn make_git_repo(root: &Path) {
    fs::create_dir_all(root.join(".git")).unwrap();
}

#[test]
fn finds_plain_text_file_and_returns_its_content() {
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "notes.txt", "hello sovereign");

    let (files, coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, Path::new("notes.txt"));
    assert_eq!(files[0].content, "hello sovereign");
    assert_eq!(coverage.files_scanned, 1);
    assert!(coverage.skipped.is_empty());
}

#[test]
fn finds_dotfiles_including_env() {
    // Regression guard for `.hidden(false)`: `.env` is the primary target.
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), ".env", "API_KEY=not-a-real-value");

    let (files, _) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, Path::new(".env"));
    assert_eq!(files[0].content, "API_KEY=not-a-real-value");
}

#[test]
fn respects_gitignore_when_enabled() {
    let root = tempfile::tempdir().unwrap();
    make_git_repo(root.path());
    write_text(root.path(), ".gitignore", "secret.txt\n");
    write_text(root.path(), "secret.txt", "token");
    write_text(root.path(), "keep.txt", "safe");

    let (files, _) = walk(root.path(), &ScanConfig::default()).unwrap();

    let names: Vec<_> = files.iter().map(|f| f.path.clone()).collect();
    assert!(names.contains(&Path::new("keep.txt").to_path_buf()));
    assert!(!names.contains(&Path::new("secret.txt").to_path_buf()));
}

#[test]
fn ignores_gitignore_when_disabled() {
    let root = tempfile::tempdir().unwrap();
    make_git_repo(root.path());
    write_text(root.path(), ".gitignore", "secret.txt\n");
    write_text(root.path(), "secret.txt", "token");
    write_text(root.path(), "keep.txt", "safe");

    let config = ScanConfig {
        respect_gitignore: false,
        ..ScanConfig::default()
    };
    let (files, _) = walk(root.path(), &config).unwrap();

    let names: Vec<_> = files.iter().map(|f| f.path.clone()).collect();
    assert!(names.contains(&Path::new("secret.txt").to_path_buf()));
    assert!(names.contains(&Path::new("keep.txt").to_path_buf()));
}

#[test]
fn skips_files_over_the_size_limit() {
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "ok.txt", "ok");
    write_file(root.path(), "big.txt", &[b'x'; 16]);

    let config = ScanConfig {
        max_file_bytes: 8,
        ..ScanConfig::default()
    };
    let (files, coverage) = walk(root.path(), &config).unwrap();

    assert!(files.iter().any(|f| f.path == Path::new("ok.txt")));
    assert_eq!(coverage.files_skipped, 1);
    assert_eq!(coverage.skipped.len(), 1);
    assert_eq!(coverage.skipped[0].path, Path::new("big.txt"));
    assert_eq!(coverage.skipped[0].reason, SkipReason::TooLarge);
}

#[test]
fn skips_files_containing_a_nul_byte_as_binary() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "blob.bin", b"ab\0cd");

    let (files, coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert!(files.is_empty());
    assert_eq!(coverage.skipped.len(), 1);
    assert_eq!(coverage.skipped[0].path, Path::new("blob.bin"));
    assert_eq!(coverage.skipped[0].reason, SkipReason::Binary);
}

#[test]
fn skips_files_that_are_not_valid_utf8() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "latin.bin", b"\xff\xfe\xfd");

    let (files, coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert!(files.is_empty());
    assert_eq!(coverage.skipped.len(), 1);
    assert_eq!(coverage.skipped[0].path, Path::new("latin.bin"));
    assert_eq!(coverage.skipped[0].reason, SkipReason::NotUtf8);
}

#[test]
fn never_descends_into_git_directory() {
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), ".git/config", "[core]\n");
    write_text(root.path(), ".git/objects/pack/entry.txt", "packed");
    write_text(root.path(), "keep.txt", "safe");

    let (files, coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert!(!files.iter().any(|f| f.path.starts_with(".git")));
    assert!(!coverage.skipped.iter().any(|s| s.path.starts_with(".git")));
    assert!(files.iter().any(|f| f.path == Path::new("keep.txt")));
}

#[test]
fn returned_paths_are_relative_to_root() {
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "a/one.txt", "1");
    write_text(root.path(), "b/two.txt", "2");
    write_file(root.path(), "b/blob.bin", b"\0");

    let (files, coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert!(!files.is_empty());
    for file in &files {
        assert!(
            !file.path.is_absolute(),
            "{} is absolute",
            file.path.display()
        );
    }
    for skipped in &coverage.skipped {
        assert!(
            !skipped.path.is_absolute(),
            "{} is absolute",
            skipped.path.display()
        );
    }
}

#[test]
fn output_ordering_is_deterministic_across_runs() {
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "z.txt", "z");
    write_text(root.path(), "m.txt", "m");
    write_text(root.path(), "a/b.txt", "b");
    write_text(root.path(), "a/c.txt", "c");
    write_file(root.path(), "big.bin", b"\0");

    let (first_run, first_coverage) = walk(root.path(), &ScanConfig::default()).unwrap();
    let (second_run, second_coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert_eq!(first_run, second_run);
    assert_eq!(first_coverage, second_coverage);
    assert!(first_run.windows(2).all(|w| w[0].path <= w[1].path));
    assert!(first_coverage
        .skipped
        .windows(2)
        .all(|w| w[0].path <= w[1].path));
}

#[test]
fn coverage_counters_agree_with_returned_vectors() {
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "ok.txt", "seven");
    write_file(root.path(), "big.txt", &[b'x'; 32]);
    write_file(root.path(), "blob.bin", b"\0x");

    let config = ScanConfig {
        max_file_bytes: 8,
        ..ScanConfig::default()
    };
    let (files, coverage) = walk(root.path(), &config).unwrap();

    assert_eq!(coverage.files_scanned, files.len() as u64);
    assert_eq!(coverage.files_skipped, coverage.skipped.len() as u64);
    assert_eq!(coverage.bytes_scanned, "seven".len() as u64);
}

#[test]
fn default_excludes_drop_matched_files() {
    let root = tempfile::tempdir().unwrap();
    write_file(root.path(), "assets/logo.png", b"\x89PNG\r\n\x1a\n");
    write_text(root.path(), "app.min.js", "x");
    write_text(root.path(), "keep.txt", "safe");

    let (files, coverage) = walk(root.path(), &ScanConfig::default()).unwrap();

    // Excluded files are filtered at walk level: absent from both lists.
    assert!(files.iter().any(|f| f.path == Path::new("keep.txt")));
    assert!(!files.iter().any(|f| f.path == Path::new("app.min.js")));
    assert!(!files.iter().any(|f| f.path == Path::new("assets/logo.png")));
    assert!(!coverage
        .skipped
        .iter()
        .any(|s| s.path == Path::new("assets/logo.png")));
}

#[test]
fn default_excludes_match_at_any_depth_not_only_the_root() {
    // Regression: `node_modules/**` anchors to the scan root, so a nested
    // `ui/node_modules` was walked and scanned. Vendored trees are dense
    // sources of false positives, so the patterns must be `**/name/**`.
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "node_modules/top.js", "x");
    write_text(root.path(), "ui/node_modules/nested.js", "x");
    write_text(root.path(), "crates/inner/target/debug/build.rs", "x");
    write_text(root.path(), "ui/dist/bundle.js", "x");
    write_text(root.path(), "ui/src/keep.ts", "safe");

    let (files, _) = walk(root.path(), &ScanConfig::default()).unwrap();

    assert!(files.iter().any(|f| f.path == Path::new("ui/src/keep.ts")));
    for excluded in [
        "node_modules/top.js",
        "ui/node_modules/nested.js",
        "crates/inner/target/debug/build.rs",
        "ui/dist/bundle.js",
    ] {
        assert!(
            !files.iter().any(|f| f.path == Path::new(excluded)),
            "{excluded} should have been excluded at any depth"
        );
    }
}

#[test]
fn gitignored_env_files_are_still_scanned() {
    // The whole point of the tool: `.env` is both the most common home for a
    // live credential and one of the most commonly gitignored paths. Honouring
    // `.gitignore` unconditionally would reliably skip the one file that
    // matters most.
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), ".gitignore", ".env\n.env.*\nsecrets/\n*.pem\n");
    write_text(root.path(), ".env", "API_KEY=live-value");
    write_text(root.path(), ".env.production", "TOKEN=live-value");
    write_text(root.path(), "secrets/service-account.json", "{}");
    write_text(
        root.path(),
        "certs/server.pem",
        "-----BEGIN PRIVATE KEY-----",
    );
    write_text(root.path(), "notes.txt", "ordinary");

    let (files, _) = walk(root.path(), &ScanConfig::default()).unwrap();
    let found: Vec<String> = files
        .iter()
        .map(|f| f.path.to_string_lossy().replace('\\', "/"))
        .collect();

    for expected in [
        ".env",
        ".env.production",
        "secrets/service-account.json",
        "certs/server.pem",
    ] {
        assert!(
            found.iter().any(|f| f == expected),
            "{expected} must be scanned despite .gitignore; found {found:?}"
        );
    }
    // Ordinary ignore behaviour is otherwise unchanged.
    assert!(found.iter().any(|f| f == "notes.txt"));
}

#[test]
fn always_scan_does_not_override_explicit_excludes() {
    // A force-include corrects ignore-file defaults; it does not overrule what
    // the caller explicitly asked to skip.
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), ".gitignore", ".env\n");
    write_text(root.path(), "vendored/.env", "API_KEY=x");

    let config = ScanConfig {
        exclude: vec!["**/vendored/**".to_string()],
        ..ScanConfig::default()
    };
    let (files, _) = walk(root.path(), &config).unwrap();
    assert!(!files
        .iter()
        .any(|f| f.path.to_string_lossy().contains("vendored")));
}

#[test]
fn always_scan_reinstates_a_file_an_exclude_glob_dropped() {
    // `always_scan` is applied after ignore processing, so a `.env` excluded by
    // a directory glob comes back only when it is force-included. Clearing the
    // list leaves the exclude in force.
    let root = tempfile::tempdir().unwrap();
    write_text(root.path(), "config/.env", "API_KEY=x");

    let base_exclude = vec!["**/config/**".to_string()];

    let without = ScanConfig {
        exclude: base_exclude.clone(),
        always_scan: Vec::new(),
        ..ScanConfig::default()
    };
    let (files, _) = walk(root.path(), &without).unwrap();
    assert!(
        !files
            .iter()
            .any(|f| f.path.to_string_lossy().contains(".env")),
        "the exclude glob should still apply with always_scan empty"
    );
}

#[test]
fn rejects_missing_or_non_directory_root() {
    let root = tempfile::tempdir().unwrap();

    let missing = root.path().join("does-not-exist");
    assert!(matches!(
        walk(&missing, &ScanConfig::default()),
        Err(ScanError::InvalidRoot)
    ));

    write_text(root.path(), "plain.txt", "x");
    let file_root = root.path().join("plain.txt");
    assert!(matches!(
        walk(&file_root, &ScanConfig::default()),
        Err(ScanError::InvalidRoot)
    ));
}
