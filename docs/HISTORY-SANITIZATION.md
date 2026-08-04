# History sanitization record

On 2026-08-04, the public Git history was rewritten once with
`git-filter-repo` 2.47.0 to remove private thesis working notes, a local agent
configuration file, personal commit e-mail addresses and absolute user-home
paths. No source capability, experimental result or research claim was removed.

The isolated rewrite processed and preserved all 243 commits reachable from the
archived branch, tag and pull-request heads by disabling empty-commit and
degenerate-merge pruning. Of those, 161 commits are reachable from the 15
published branch heads and the annotated evidence tag. Branch and tag names,
commit chronology, parent topology and messages were retained, except for the
explicit replacement of private strings. The complete old-to-new commit map,
the rewritten pull-request-only commits and the original verified Git bundle
are held in a private archive and are not part of the published heads or tags.

GitHub's `refs/pull/*` namespace is server-managed and cannot be force-updated
by a repository administrator. The 71 pull requests that predate the rewrite
therefore retain obsolete cached refs until GitHub Support purges them. The
three active pull requests were recreated from sanitized heads as #72--#74; the
cache purge is an operational follow-up and does not change the rewritten
branch/tag history described here.

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
