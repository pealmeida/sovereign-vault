# Scanning your projects

Sovereign Vault can inventory the sensitive material already scattered across
your machine — the `.env` files, hard-coded keys, and personal data sitting in
project directories — and store the resulting report in the vault, where an AI
agent can only reach it with your approval.

The scan is **read-only**. It never modifies, moves, or deletes a file in the
directory you point it at.

## Quick start

```bash
# Inventory one project
sovereign-vault scan ~/code/my-project

# Only the findings worth acting on
sovereign-vault scan ~/code/my-project --min-confidence high

# Store the report in the vault so an agent can read it under consent
sovereign-vault scan ~/code/my-project --store
```

## What it looks for

**Credentials** — 13 hand-reviewed rules covering AWS access keys, GitHub
tokens (classic, OAuth, and fine-grained), Slack bot and user tokens, Stripe
live and test keys, OpenAI and Anthropic keys, Google API keys, npm tokens, and
PEM private-key headers.

**Personal data** — email, CPF, CNPJ, Luhn-valid card numbers, IPv4, phone
numbers, and US SSN, via `sv-privacy`.

Each finding reports a file, a line, a class, a confidence, and a **masked
preview**. The matched value itself never leaves the file: it is not printed,
not stored in the report, and not written to the audit log.

## Jurisdiction packs

The baseline detectors are Brazil-centric. Pattern packs add the national
identifiers other regimes care about:

```bash
sovereign-vault scan --list-packs

sovereign-vault scan ~/code/my-project --pack eu-gdpr
sovereign-vault scan ~/code/my-project --pack br-lgpd --pack us
```

| Pack | Covers |
|---|---|
| `br-lgpd` | CPF, CNPJ, CEP, BR phone, RG |
| `eu-gdpr` | IBAN, UK NINO, DE Steuer-ID, ES DNI, IT Codice Fiscale |
| `us` | SSN, EIN, passport, Medicare BIC |

A local pack can be given as a TOML path, so a company can distribute its own.

Three properties are guaranteed by design (see
[ADR-0018](adr/0018-jurisdiction-pattern-packs.md)):

- **Packs only ever add.** There is no ignore, allow, or exempt verb in the pack
  format. No pack can turn off a baseline detector or suppress its findings. A
  pack that silently reduced detection — leaving you *more* exposed while
  feeling safer — is not representable.
- **Packs are off by default.** Enabling everything turns most long digit runs
  into candidates, because the checksums are weak. Opt in to what you need.
- **A requested pack that fails to load is a hard error**, never a quiet
  downgrade to fewer rules.

Findings carry full provenance — pack id, pack version, rule id, and whether the
checksum passed:

```
customers.csv:2  id:br-lgpd/cpf (checksum passed)  111.********
```

That is deliberately a statement of *evidence*, not law. A passing checksum
means a value is well-formed for its identifier type. It does not establish that
the value is real, that it belongs to anyone, or that LGPD, GDPR, or any other
regime applies to it — determinations this tool is not in a position to make.

## `.env` files are scanned even when gitignored

This is deliberate and worth understanding, because the obvious behaviour is
wrong.

`.env` is simultaneously the most common home for a live credential and one of
the most commonly `.gitignore`d paths. A scanner that honours `.gitignore`
unconditionally therefore skips exactly the file you most need it to read — and
reports a reassuring clean result while doing so.

So a small list of credential-bearing paths is always scanned regardless of
ignore rules: `.env` and its variants, `.npmrc`, `.netrc`, `.pypirc`, `*.pem`,
`*.key`, SSH private keys, `credentials`, `secrets.*`, and service-account JSON.
Everything else honours `.gitignore` normally.

The alternative — `--no-gitignore` — is available but is usually the wrong tool:
it drags in `node_modules`, build output, and caches, which produce enormous
numbers of false positives.

## Reading the coverage line

```
scanned 672 files (5285212 bytes) in 1.16s
not examined: 11 unreadable, 126383 excluded by ignore rules
context filters: 159 demoted, 0 removed
```

A scanner that skips silently overstates its own coverage, so every category is
counted:

- **unreadable** — reached but not scannable: too large, binary, or not UTF-8.
- **excluded by ignore rules** — never opened, because `.gitignore` or an
  exclude glob removed them. "The scanner never looked" and "the scanner found
  nothing" are different claims, and this number keeps them apart.
- **demoted / removed** — candidate findings a context filter judged less likely
  to be real.

## Confidence, and why findings are demoted rather than deleted

Detection is syntactic: it matches a shape, not a meaning. On a real project
that produces false positives that are not detector bugs but *context* failures
— an Android vector drawable in one real project produced 709 "card numbers"
from path geometry, because Luhn is a single check digit and roughly one digit
run in ten passes it.

Context filters address this, but they almost always **demote to low confidence
rather than delete**. "This file is generated", "this value looks like a
placeholder", and "this address is private" are statements about likelihood, not
proof:

- a leaked key really can sit inside a committed bundle;
- a live password really can contain the word `sample`;
- `10.23.4.5` really does identify a device inside the network that owns it.

Deleting on a heuristic would hide the finding you most need to see. Only
structurally impossible matches — a digit window inside a longer run, which was
never a whole field — are dropped outright.

Use `--min-confidence high` for the actionable list, and read the low-confidence
findings when you want the full picture.

## Storing reports in the vault

```bash
sovereign-vault scan ~/code/my-project --store
```

The report is written to the `scan-reports` container, created in **APPROVAL**
mode if it does not exist. That single fact is what makes the agent workflow
safe: an agent calling `vault.read` on a report raises a desktop approval prompt,
and you decide.

No new MCP tools are involved. Reports are ordinary vault files, so everything
that already applies to vault files applies to them: per-agent scopes, the
container's security mode, and the hash-chained audit log.

A stored report contains masked previews only. It names *where* sensitive
material lives without reproducing it, so the report itself is not a new place
your secrets exist.

## Using it with an AI agent

1. Run the scan with `--store`.
2. The agent calls `vault.list` on `scan-reports`, then `vault.read` on one.
3. Because the container is `APPROVAL`, you get a desktop prompt naming the
   agent and the file.
4. Approve, and the agent receives the masked report — enough to reason about
   what needs fixing, never enough to leak a key.

Grant a narrower scope if you want an agent that can read reports and nothing
else:

```
container glob: scan-reports
actions:        list_files, read
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings |
| 1 | The scan itself failed |
| 2 | Findings present |

Exit 2 is separate from exit 1 so a pre-commit hook or CI step can act on
findings without parsing stdout:

```bash
sovereign-vault scan . --min-confidence high || exit 1
```

## Options

| Flag | Effect |
|---|---|
| `--json` | Machine-readable report on stdout |
| `--store` | Write the report into the vault |
| `--container <name>` | Target container (default `scan-reports`) |
| `--min-confidence <low\|medium\|high>` | Confidence floor |
| `--max-file-bytes <n>` | Size limit per file (default 5 MiB) |
| `--no-gitignore` | Scan ignored files too (expect noise) |
| `--pack <id\|path>` | Enable a jurisdiction pack; repeatable |
| `--list-packs` | Show bundled packs and their rules |
| `--root <path>` | Vault root; only used with `--store` |

## Limits

Read these before trusting a clean report.

- **Recall is bounded.** The detectors are deterministic and conservative. An
  empty report is evidence of what was found, never proof that a project holds
  no secrets. Unformatted phone numbers, names, addresses, and any credential
  format without a rule are not detected.
- **Redaction is not part of this.** The scan reports; it does not rewrite. That
  is deliberate: rewriting source files is irreversible, and driving it from an
  unmeasured detector would corrupt them. See
  [ADR-0017](adr/0017-project-scanning-and-remediation-boundary.md).
- **History is untouched.** A finding tells you a secret is in your working
  tree. It says nothing about Git history, backups, or copies already made —
  and a scan cannot remove a secret from any of those.
- **No legal determination.** The tool reports structural evidence. It does not
  classify data under LGPD, GDPR, or any other regime, and a checksum passing
  establishes plausibility, not authenticity, ownership, or sensitivity.
