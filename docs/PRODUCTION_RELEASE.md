# Production release procedure

This document defines the release controls for the Sovereign Vault desktop
application. The workflow in `.github/workflows/release.yml` builds signed
Linux, macOS, and Windows installers, creates SBOMs and GitHub attestations,
and opens a **draft** GitHub release. It never publishes a release.

The repository has shipped its first managed release, v0.1.0 (early release).
The release workflow still rejects the `0.0.0` development sentinel and every
version that does not meet the controls below. Do not interpret the presence of
the workflow as a production certification or as evidence that an external
audit has been completed.

## Required repository controls

Create a GitHub environment named `production-release` before enabling release
tags. Configure all of the following controls:

1. Add required reviewers from the release/security team and enable "Prevent
   self-review." Disable administrator bypass where the repository plan allows
   it.
2. Restrict deployments to protected tags matching `v*.*.*`. Protect tag
   creation, update, and deletion with a repository ruleset. Only release
   managers may create production tags.
3. Store every signing value listed below as an **environment secret**, not a
   repository or organization-wide secret.
4. Store the approval and audit values listed below as environment variables.
   Reset tag-scoped values immediately after each draft is produced.
5. Require successful `CI` checks and reviewed changes on `main`. The release
   workflow repeats the complete gate set because a tag must not be able to
   bypass ordinary CI.
6. Enable GitHub artifact attestations for the repository. Private repositories
   may require GitHub Enterprise Cloud for attestations.
7. Enable immutable releases after the draft has passed review if that feature
   is available for the repository. Never replace assets under a published tag.

An environment reference alone does not create an approval rule. A repository
administrator must configure the environment protections in GitHub.

## Approval and audit variables

The protected environment must define these non-secret variables for the exact
release under review:

| Variable | Required value |
| --- | --- |
| `APPROVED_RELEASE_TAG` | Exact tag, for example `v1.0.0` |
| `RELEASE_APPROVAL_RECORD` | URL or immutable identifier for the change-control record |
| `EXTERNAL_AUDIT_APPROVED_TAG` | Exact tag whose commit is covered by the independent audit and accepted remediation report |
| `EXTERNAL_AUDIT_REPORT_SHA256` | 64-character SHA-256 digest of the final audit report/evidence bundle |

Do not set `EXTERNAL_AUDIT_APPROVED_TAG` merely because an audit is scheduled
or underway. The independent assessor's scope must cover the exact tagged
commit, the vault cryptography and key lifecycle, storage/recovery behavior,
gateway authorization boundaries, desktop integration, and this build/release
process. Any code change after the assessed commit requires documented assessor
acceptance or a new delta review.

The release approval record must include the tagged commit, CI run links,
resolved security findings, backup/restore drill evidence, supported operating
systems, known limitations, and named approvers. The environment reviewer and
the person who eventually publishes the draft must be different people.

## Signing secrets

### Linux

| Secret | Content |
| --- | --- |
| `LINUX_GPG_PRIVATE_KEY` | ASCII-armored private release key |
| `LINUX_GPG_KEY_ID` | Full fingerprint of that key |
| `LINUX_GPG_PASSPHRASE` | Strong private-key passphrase |

The workflow enables Tauri/AppImage signing with forced failure and also creates
detached ASCII-armored signatures for every AppImage and Debian package. Publish
the matching public key and full fingerprint through a separately controlled
project channel. AppImage's embedded signature is not self-verifying; the
detached GPG signature is the required Linux authenticity check.

### macOS

| Secret | Content |
| --- | --- |
| `APPLE_CERTIFICATE` | Base64-encoded Developer ID Application `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | Password protecting the `.p12` |
| `APPLE_SIGNING_IDENTITY` | Exact Developer ID Application identity |
| `APPLE_API_ISSUER` | App Store Connect API issuer ID |
| `APPLE_API_KEY` | App Store Connect API key ID |
| `APPLE_API_KEY_P8` | Complete private `.p8` key content |

Use an App Store Connect key with only the permissions needed for notarization.
The workflow imports the certificate into an ephemeral keychain, requires
notarization and stapling to validate, and removes both the keychain and API key
from the runner.

### Windows

| Secret | Content |
| --- | --- |
| `WINDOWS_CERTIFICATE` | Base64-encoded Authenticode `.pfx` |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password protecting the `.pfx` |

The workflow imports the certificate only into the current runner user's store,
injects its thumbprint through a temporary Tauri config override, requires
SHA-256 signing and an RFC 3161 timestamp, verifies every MSI and NSIS signature,
then removes the certificate and override.

## Key custody and recovery

Production signing keys must have named owners, an expiry calendar, and a
revocation procedure. Prefer hardware-backed or managed signing where the
platform and CI integration support it. The exportable keys required by the
current workflow must be created on a controlled workstation and must never be
committed, attached to issues, pasted into logs, or stored unencrypted outside
GitHub's protected environment.

Keep at least two encrypted offline backups in separate physical locations.
Protect backup decryption with split knowledge so one person cannot recover a
production private key alone. Record certificate chains, public keys,
fingerprints, expiry dates, provider account recovery material, and revocation
contacts alongside the encrypted backup. Store passphrases separately.

Run a key recovery drill at least quarterly and before the first production
release:

1. Two custodians restore each key into a quarantined, ephemeral environment.
2. Sign a non-production fixture and verify it from a separate clean machine.
3. For Apple and Windows, exercise timestamp/notarization connectivity without
   distributing the fixture. For Linux, verify with the independently published
   public key.
4. Destroy the restored working copies and runner, then record evidence and
   timing in the release approval system.
5. Confirm that revocation contacts and account recovery paths still work.

Never test recovery by replacing the secrets for an in-progress production
release. Use a separate environment and non-production certificate/key where a
provider supports one.

## Preparing a release

1. Complete the external audit and remediation gate for the exact candidate
   commit. Do not mark the audit variable until this is true.
2. Complete a production backup and a successful restore drill using a copy of
   representative vault data. Confirm compatibility with the candidate binary.
3. Update the version in `Cargo.toml`,
   `apps/desktop/src-tauri/tauri.conf.json`, `ui/package.json`, and
   `ui/package-lock.json` in one reviewed pull request. All four values must be
   the same canonical `MAJOR.MINOR.PATCH` value and must not be `0.0.0`.
4. Review and merge release notes, upgrade/migration notes, known limitations,
   the support plan, and the rollback decision tree.
5. Set the four tag-scoped environment variables. A release manager then creates
   `vMAJOR.MINOR.PATCH` at the reviewed commit on `main`. Never move or force-push
   a release tag.
6. A tag push starts the workflow. A manual rerun must be launched with "Use
   workflow from" set to that same tag and the identical tag supplied as input.
7. Reviewers inspect the commit, approval record, audit digest, and gate results
   before approving the `production-release` environment.

The workflow rejects noncanonical tags, a tag not reachable from `origin/main`,
mixed versions, `0.0.0`, missing platform secrets, missing tag-specific approval
or audit evidence, failed signing/notarization, and incomplete artifact sets.

## Draft review and publication

The workflow creates a draft containing platform installers, detached Linux
signatures, one SPDX JSON SBOM per platform, `RELEASE_METADATA.json`, and
`SHA256SUMS`. GitHub stores build-provenance and SBOM attestations separately.

Before publication, an independent release manager must:

1. Download all assets on a clean machine and perform the verification steps
   below.
2. Compare `RELEASE_METADATA.json` with the tag, commit, workflow run, approval
   record, and external-audit report digest.
3. Confirm the GitHub Actions run used only the expected protected environment
   and that every matrix build and gate succeeded.
4. Install and smoke-test each supported package on clean supported operating
   systems. Exercise create, unlock, lock, backup, restore, MCP consent, and audit
   flows with non-production data.
5. Confirm the support/on-call owner, rollback decision maker, status-page text,
   and certificate-revocation contacts.
6. Record a second approval, then publish the existing draft without changing
   its tag or assets. Reset the tag-scoped environment variables afterward.

## Artifact verification

Download every release asset into one empty directory. Verify checksums first:

```bash
sha256sum -c SHA256SUMS
```

On macOS, use `shasum -a 256` to compare individual values if GNU
`sha256sum` is unavailable. A checksum detects corruption but does not establish
publisher identity.

Verify GitHub build provenance for each installer and SBOM:

```bash
gh attestation verify ./Sovereign_Vault_1.0.0_amd64.AppImage \
  --repo pealmeida/sovereign-vault
gh attestation verify ./sbom-linux-x86_64.spdx.json \
  --repo pealmeida/sovereign-vault
```

Use the actual asset names for the release. Verification must identify the
expected repository and the release workflow at the tagged commit. An
attestation proves build provenance; it does not prove that the software is free
of vulnerabilities.

Verify Linux artifacts with the public key obtained from the independent
project channel and compare its full fingerprint before use:

```bash
gpg --verify Sovereign_Vault_1.0.0_amd64.AppImage.asc \
  Sovereign_Vault_1.0.0_amd64.AppImage
gpg --verify sovereign-vault_1.0.0_amd64.deb.asc \
  sovereign-vault_1.0.0_amd64.deb
```

Verify macOS notarization and signature before opening the disk image:

```bash
xcrun stapler validate Sovereign_Vault_1.0.0_universal.dmg
spctl --assess --type open --context context:primary-signature \
  --verbose=4 Sovereign_Vault_1.0.0_universal.dmg
```

After mounting, run `codesign --verify --deep --strict --verbose=2` and
`spctl --assess --type execute --verbose=4` against the `.app` bundle.

Verify every Windows installer in PowerShell:

```powershell
$signature = Get-AuthenticodeSignature .\Sovereign_Vault_1.0.0_x64-setup.exe
$signature.Status
$signature.SignerCertificate.Subject
$signature.TimeStamperCertificate.Subject
```

`Status` must be `Valid`, the signer must match the published project identity,
and a timestamp certificate must be present. Repeat for the MSI.

Review each SPDX JSON SBOM for unexpected packages, licenses, or source locations
and archive it with the approval record.

## Rollback and incident response

A published artifact is evidence and must not be silently replaced. If a release
is defective:

1. Stop distribution and updater promotion, mark the release as affected, and
   notify users with the impact and safe handling instructions.
2. Preserve the tag, assets, attestations, workflow logs, audit evidence, and
   checksums. Do not move the tag or upload corrected binaries under it.
3. Revert the defective change on `main`, complete the required review and
   regression tests, and ship a higher patch version through the full procedure.
4. Do not open production vaults with an older binary until format and key-state
   compatibility has been demonstrated on a restored copy. Restore from the last
   verified backup when downgrade safety is uncertain.
5. If signing material may be compromised, cancel the workflow, remove the
   affected environment secrets, revoke the certificate/key with the platform,
   publish the revocation through the independent project channel, rotate all
   custody backups, and reissue artifacts only under a new version.

For a draft that has not been published, delete the draft only after preserving
the failed run and approval evidence. Fix the cause, create a new tag only when
the source version changes, and rerun; the workflow deliberately refuses to
overwrite any existing GitHub release.

## What the workflow cannot prove

Local syntax checks cannot exercise GitHub environment approval, hosted-runner
images, platform certificate import, Apple notarization, timestamp services,
GitHub release creation, or GitHub's attestation service. Those controls must be
validated in a private dry run with non-production material before the first
real release.

SBOM generation and dependency policy checks reduce supply-chain uncertainty but
do not replace source review, penetration testing, cryptographic review,
operational monitoring, restore tests, or an independent security audit. The
manual publication gate exists to make those limitations explicit.
