//! Phase guard: the destructive path is feature-gated, and raw filesystem
//! mutation calls are banned everywhere.
//!
//! Two properties are enforced here:
//!
//! 1. `pub mod apply` must sit behind `#[cfg(feature = "apply")]`. With the
//!    default feature set the write dependencies are not even compiled, so
//!    no write path is reachable.
//! 2. The crate's own source (with any feature set) must not contain raw
//!    filesystem-mutation calls. Sanctioned writes go through
//!    `atomicwrites` behind the `apply` feature; the raw standard-library
//!    calls would bypass the review that path received. The tokens are
//!    assembled at runtime so this test file does not itself contain them
//!    contiguously. (The scan below covers everything under src/; this
//!    file avoids the tokens by construction so the rule "the tokens appear
//!    nowhere in the crate" stays literally true.)

use std::path::{Path, PathBuf};

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn apply_module_is_gated_behind_the_apply_feature() {
    let lib = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("lib.rs"),
    )
    .expect("read lib.rs");
    let gate = lib.find("#[cfg(feature = \"apply\")]").expect("apply gate");
    let module = lib.find("pub mod apply;").expect("apply module");
    assert!(
        gate < module,
        "pub mod apply must be declared behind the apply feature gate"
    );
}

#[test]
fn crate_source_contains_no_raw_filesystem_mutation_calls() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files).expect("list crate sources");
    assert!(
        files.len() >= 5,
        "expected the crate's source files, found {}",
        files.len()
    );

    let forbidden: Vec<String> = vec![
        format!("fs::{}", "write"),
        format!("fs::{}", "rename"),
        format!("{}::{}", "File", "create"),
        format!("remove_{}", "file"),
    ];

    for file in &files {
        let content = std::fs::read_to_string(file).expect("read source");
        let is_managed = file
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n == "managed.rs")
            .unwrap_or(false);
        for pattern in forbidden
            .iter()
            // `managed.rs` hosts the single reviewed deletion point —
            // removal of the original after a passing startup check,
            // sanctioned by ADR-0020 §2. It keeps the write/rename/create
            // ban; only the deletion token is tolerated there, so a second
            // deletion site cannot hide.
            .filter(|p| !(is_managed && p.contains("remove")))
        {
            assert!(
                !content.contains(pattern.as_str()),
                "{} contains `{}`: raw filesystem mutation is banned; \
                 sanctioned writes go through atomicwrites behind the apply feature",
                file.display(),
                pattern
            );
        }
    }
}
