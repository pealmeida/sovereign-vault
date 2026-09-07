//! In-memory dry-run diffing: what a plan *would* change, as data.
//!
//! [`dry_run_diff`] is pure: it takes a plan and the files' current texts
//! and returns [`FileDiff`] values. It performs no filesystem access of any
//! kind and produces no side effects; rendering to a string is the
//! caller's choice.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::plan::RewritePlan;

/// Below this many cells in the LCS table the middle diff is computed
/// exactly; above it, the middle is replaced coarsely (delete-then-insert)
/// rather than spending unbounded memory. Common prefix and suffix are
/// always trimmed first, so realistic edits stay far below the cap.
const LCS_CELL_CAP: usize = 1_000_000;

/// One line of a unified diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// The line's role in the change.
    pub tag: DiffTag,
    /// 1-based line number in the original, for context and deletions.
    pub old_no: Option<u32>,
    /// 1-based line number in the result, for context and insertions.
    pub new_no: Option<u32>,
    /// The line's text, without its terminating newline.
    pub text: String,
}

/// The role of a diff line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffTag {
    /// Unchanged line.
    Context,
    /// Line present in the original, removed by the plan.
    Delete,
    /// Line introduced by the plan.
    Insert,
}

/// The preview of what a plan would do to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    /// The file's normalized path, as carried by the plan.
    pub path: PathBuf,
    /// True when the caller did not supply this file's content, so no
    /// preview could be produced.
    pub missing: bool,
    /// Spans that could not be applied to the supplied content (out of
    /// bounds or not on a character boundary). Non-zero means the content
    /// passed in is not the content the plan was built from; the execute
    /// path will refuse it.
    pub skipped_spans: usize,
    /// The full unified line list, context included.
    pub lines: Vec<DiffLine>,
}

/// Builds an in-memory preview of everything `plan` would change.
///
/// Items are grouped by file, applied high-offset-first so spans never
/// shift, and the before/after texts are diffed line by line. This is a
/// review aid, not a gate: the authority check is
/// [`crate::verify::verify_plan_item`] at execute time.
pub fn dry_run_diff(plan: &RewritePlan, files: &BTreeMap<PathBuf, String>) -> Vec<FileDiff> {
    let items = plan.items();
    let mut diffs = Vec::new();
    let mut index = 0;
    while index < items.len() {
        let path = items[index].path.clone();
        let mut end = index + 1;
        while end < items.len() && items[end].path == path {
            end += 1;
        }
        let group = &items[index..end];
        index = end;

        let Some(content) = files.get(&path) else {
            diffs.push(FileDiff {
                path,
                missing: true,
                skipped_spans: 0,
                lines: Vec::new(),
            });
            continue;
        };

        let mut text = content.clone();
        let mut skipped = 0usize;
        // Apply high-offset-first so earlier spans stay valid.
        for item in group.iter().rev() {
            if item.span.end > text.len()
                || !text.is_char_boundary(item.span.start)
                || !text.is_char_boundary(item.span.end)
            {
                skipped += 1;
                continue;
            }
            text.replace_range(item.span.start..item.span.end, &item.replacement);
        }
        diffs.push(FileDiff {
            path,
            missing: false,
            skipped_spans: skipped,
            lines: line_diff(content, &text),
        });
    }
    diffs
}

impl FileDiff {
    /// Renders a simple unified diff. Hunk elision is deliberately not
    /// implemented: the structured [`FileDiff::lines`] is the reviewable
    /// data, and a compressed rendering that merged unrelated changes
    /// could hide more than it saves.
    pub fn to_unified(&self) -> String {
        if self.missing {
            return format!(
                "--- a/{}\n+++ (content not supplied)\n",
                self.path.display()
            );
        }
        let mut out = format!(
            "--- a/{}\n+++ b/{}\n",
            self.path.display(),
            self.path.display()
        );
        for line in &self.lines {
            let prefix = match line.tag {
                DiffTag::Context => ' ',
                DiffTag::Delete => '-',
                DiffTag::Insert => '+',
            };
            out.push(prefix);
            out.push_str(&line.text);
            out.push('\n');
        }
        out
    }
}

/// Splits into lines without their terminating newline. A trailing newline
/// does not produce an empty final line.
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split_inclusive('\n')
        .map(|line| line.strip_suffix('\n').unwrap_or(line))
        .collect()
}

/// Ops for the middle section of a diff, carrying indices into the old
/// (`Del`) and new (`Ins`) line vectors.
enum MiddleOp {
    Equal,
    Del(usize),
    Ins(usize),
}

/// Line diff of `old` into `new`, context included.
fn line_diff(old: &str, new: &str) -> Vec<DiffLine> {
    let a = split_lines(old);
    let b = split_lines(new);

    // Trim the common prefix and suffix; the LCS then runs only on the
    // changed middle, which keeps realistic edits far below the cell cap.
    let mut prefix = 0usize;
    while prefix < a.len() && prefix < b.len() && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < a.len() - prefix
        && suffix < b.len() - prefix
        && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let middle_a = &a[prefix..a.len() - suffix];
    let middle_b = &b[prefix..b.len() - suffix];
    let middle_ops = diff_middle(middle_a, middle_b);

    let mut ops: Vec<MiddleOp> = Vec::with_capacity(a.len() + b.len());
    for _ in 0..prefix {
        ops.push(MiddleOp::Equal);
    }
    // Middle ops carry middle-relative indices; rebase them onto the full
    // arrays so the walk below can index `a` and `b` directly.
    for op in middle_ops {
        ops.push(match op {
            MiddleOp::Equal => MiddleOp::Equal,
            MiddleOp::Del(i) => MiddleOp::Del(prefix + i),
            MiddleOp::Ins(j) => MiddleOp::Ins(prefix + j),
        });
    }
    for _ in 0..suffix {
        ops.push(MiddleOp::Equal);
    }

    let mut lines = Vec::with_capacity(ops.len());
    let mut old_no = 0u32;
    let mut new_no = 0u32;
    for op in ops {
        match op {
            MiddleOp::Equal => {
                old_no += 1;
                new_no += 1;
                lines.push(DiffLine {
                    tag: DiffTag::Context,
                    old_no: Some(old_no),
                    new_no: Some(new_no),
                    text: a[old_no as usize - 1].to_string(),
                });
            }
            MiddleOp::Del(i) => {
                old_no += 1;
                lines.push(DiffLine {
                    tag: DiffTag::Delete,
                    old_no: Some(old_no),
                    new_no: None,
                    text: a[i].to_string(),
                });
            }
            MiddleOp::Ins(j) => {
                new_no += 1;
                lines.push(DiffLine {
                    tag: DiffTag::Insert,
                    old_no: None,
                    new_no: Some(new_no),
                    text: b[j].to_string(),
                });
            }
        }
    }
    lines
}

/// Diffs the (already prefix/suffix-trimmed) middle. Returns delete and
/// insert ops carrying indices into `a` and `b`.
fn diff_middle(a: &[&str], b: &[&str]) -> Vec<MiddleOp> {
    if a.is_empty() {
        return (0..b.len()).map(MiddleOp::Ins).collect();
    }
    if b.is_empty() {
        return (0..a.len()).map(MiddleOp::Del).collect();
    }
    let n = a.len();
    let m = b.len();
    if n.saturating_mul(m) > LCS_CELL_CAP {
        // Coarse fallback: replace the whole middle block rather than
        // spending unbounded memory on, say, two minified bundles. The
        // preview is honest — it shows a block replacement — just not
        // minimal.
        let mut ops: Vec<MiddleOp> = (0..n).map(MiddleOp::Del).collect();
        ops.extend((0..m).map(MiddleOp::Ins));
        return ops;
    }

    // LCS table, row-major, (n+1) * (m+1).
    let width = m + 1;
    let mut table = vec![0u32; (n + 1) * width];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i * width + j] = if a[i] == b[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }

    let mut ops = Vec::new();
    let mut i = 0usize;
    let mut j = 0usize;
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(MiddleOp::Equal);
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            ops.push(MiddleOp::Del(i));
            i += 1;
        } else {
            ops.push(MiddleOp::Ins(j));
            j += 1;
        }
    }
    ops.extend((i..n).map(MiddleOp::Del));
    ops.extend((j..m).map(MiddleOp::Ins));
    ops
}

#[cfg(test)]
mod tests {
    /// Assembled at runtime so this source file never contains a complete
    /// example credential; a literal trips repository secret scanning even
    /// though this is AWS's published documentation placeholder.
    fn aws_token() -> String {
        format!("AKIA{}", "IOSFODNN7EXAMPLE")
    }

    use super::*;
    use crate::plan::{
        ByteSpan, FileIdentity, PlanItem, PlanItemDraft, PlanKey, RewritePlan, RulePin,
    };
    use sv_scan::FindingKind;

    fn key() -> PlanKey {
        PlanKey::from_bytes(&[3u8; 32]).expect("key")
    }

    fn item(path: &str, source: &str, span: (usize, usize), replacement: &str) -> PlanItem {
        PlanItem::build(
            PlanItemDraft {
                project_id: "proj".to_string(),
                path: PathBuf::from(path),
                identity: FileIdentity::Unix {
                    device: 1,
                    inode: 2,
                },
                source: source.to_string(),
                span: ByteSpan::new(span.0, span.1).expect("span"),
                replacement: replacement.to_string(),
                kind: FindingKind::Secret {
                    rule_id: "aws_access_key_id".to_string(),
                },
                rule_pin: RulePin::scan_baseline(),
            },
            &key(),
        )
        .expect("build")
    }

    #[test]
    fn diff_shows_delete_insert_with_context() {
        let source = format!("host = db.example\naws = {}\nport = 5432\n", aws_token());
        let start = "host = db.example\naws = ".len();
        let end = start + aws_token().len();
        let plan = RewritePlan::build(
            vec![item("config.env", &source, (start, end), "[REDACTED]")],
            &key(),
        )
        .expect("plan");

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("config.env"), source.to_string());
        let diffs = dry_run_diff(&plan, &files);
        assert_eq!(diffs.len(), 1);
        let diff = &diffs[0];
        assert!(!diff.missing);
        assert_eq!(diff.skipped_spans, 0);
        // One context line before, the deleted line, its replacement, and
        // one context line after.
        assert_eq!(diff.lines.len(), 4);
        assert_eq!(diff.lines[0].tag, DiffTag::Context);
        assert_eq!(diff.lines[1].tag, DiffTag::Delete);
        assert!(diff.lines[1].text.contains("AKIA"));
        assert_eq!(diff.lines[2].tag, DiffTag::Insert);
        // The diff is line-based: the inserted line is the whole new line,
        // which carries the replacement within it.
        assert_eq!(diff.lines[2].text, "aws = [REDACTED]");
        assert_eq!(diff.lines[3].tag, DiffTag::Context);
        assert_eq!(diff.lines[3].text, "port = 5432");

        let rendered = diff.to_unified();
        assert!(rendered.starts_with("--- a/config.env\n"));
        assert!(rendered.contains(&format!("-aws = {}", aws_token())));
    }

    #[test]
    fn missing_files_and_stale_spans_are_reported_not_invented() {
        // The plan is built over multibyte content whose matched span is
        // 8 bytes long; the same offsets against shorter ASCII content
        // fall outside it.
        let source = "tok = αβγδ\n";
        let plan = RewritePlan::build(vec![item(".env", source, (6, 14), "[REDACTED]")], &key())
            .expect("plan");

        // No content supplied: missing is reported, no lines are invented.
        let diffs = dry_run_diff(&plan, &BTreeMap::new());
        assert!(diffs[0].missing);
        assert!(diffs[0].lines.is_empty());

        // Different content whose span no longer lands: reported through
        // skipped_spans, never spliced blindly.
        let mut files = BTreeMap::new();
        files.insert(PathBuf::from(".env"), "tok = aaaa\n".to_string());
        let diffs = dry_run_diff(&plan, &files);
        assert!(!diffs[0].missing);
        assert_eq!(diffs[0].skipped_spans, 1);
    }

    #[test]
    fn two_items_in_one_file_apply_without_shifting_each_other() {
        let source = "aaa BBBB cccc\nxxxx YYYY zzzz\n";
        // Both spans are on the same line set but disjoint; applying the
        // higher one first must not corrupt the lower one's offsets.
        let first = item("a.txt", source, (4, 8), "bbbb");
        let second = item("a.txt", source, (19, 23), "yyyy");
        let plan = RewritePlan::build(vec![first, second], &key()).expect("plan");

        let mut files = BTreeMap::new();
        files.insert(PathBuf::from("a.txt"), source.to_string());
        let diffs = dry_run_diff(&plan, &files);
        let result: String = diffs[0]
            .lines
            .iter()
            .filter(|l| l.tag != DiffTag::Delete)
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(result.contains("aaa bbbb cccc"), "{result}");
        assert!(result.contains("xxxx yyyy zzzz"), "{result}");
    }
}
