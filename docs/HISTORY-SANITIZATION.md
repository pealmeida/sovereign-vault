# History sanitization record

On 2026-08-04, the public Git history was rewritten once with
`git-filter-repo` 2.47.0 to remove private thesis working notes, a local agent
configuration file, personal commit e-mail addresses and absolute user-home
paths. No source capability, experimental result or research claim was removed.

The rewrite preserved all 243 commits by disabling empty-commit and degenerate
merge pruning. Branch and tag names, commit chronology, parent topology and
messages were retained, except for the explicit replacement of private strings.
The complete old-to-new commit map and the original verified Git bundle are held
in a private archive and are not part of this public repository.

## Research provenance

The preliminary evidence tag `thesis-evidence-preliminary` now resolves to the
sanitized equivalent commit `8cea41adae5e33a3e2cb883133043aa0438c5361`.
The six source subtrees exercised by the evaluation harness are byte-identical
before and after the rewrite:

- `apps/thesis-eval`;
- `crates/sv-mcp`;
- `crates/sv-core`;
- `crates/sv-storage`;
- `crates/sv-privacy`;
- `crates/sv-audit`.

The versioned `latency.csv`, `adversarial.csv` and `micro.csv` blobs are also
unchanged. Therefore, the sanitization changes repository provenance hashes but
does not change the evidence bytes, measurements, qualifications or conclusions
reported in the thesis.

## Verification

The sanitized mirror was checked with `git fsck --full`, full-history Gitleaks,
explicit searches for every removed path and private identifier, workspace tests
and compilation of both thesis variants. Preventive ignore rules, GitHub push
protection and a CI secret scan reduce the chance of recurrence.
