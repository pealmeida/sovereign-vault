# Reviewer D — systems / Rust / applied cryptography

**Model:** `opencode-go/qwen3.7-max` (anymodel, independent voice) · **Lens:** Rust systems + crypto · **Run:** 2026-08 · agentic (read repo).

## VERDICT: accept-with-revisions

## MAJOR ISSUES

1. **§3.6.3 — "Headless descarta escopos" is factually wrong per the code.** The paper claims headless mode discards agent scopes. The actual `call_tool` flow in `sv-mcp` runs `enforce_scopes(agent, &access)` *before* the optional `access_controller.authorize()` check (lines ~1060–1085 of `lib.rs`). Scope enforcement is unconditional; only the HITL consent gate is optional. **Fix:** Replace "descarta escopos" with "contorna o portão de consentimento (HITL), mas a aplicação de escopos de agente permanece ativa." This is a substantive accuracy error that overstates the headless attack surface.

   > **EDITOR ADJUDICATION — REFUTED.** `enforce_scopes` *is* always called, but `HeadlessAuthenticator::authenticate` returns `scopes: Vec::new()` (`apps/cli/src/serve.rs:250`), and `enforce_scopes` short-circuits an empty scope list to `Ok(())` = full surface (`crates/sv-mcp/src/lib.rs:1855-1857`). Both lines were read directly by the editor. The reviewer saw the call site but missed that headless feeds it *empty* scopes. The original finding (headless erases per-agent least privilege) STANDS; this rebuttal is not accepted.

2. **§3.9 — APPROVAL/OTP µs figures lack the AutoAllow caveat in the paper body.** The reported 14–35 µs for APPROVAL/OTP modes are measured with the `AutoAllow` controller, which returns `Ok(())` instantly — measuring only JSON-RPC dispatch overhead, not human consent latency. **Fix:** Add an explicit sentence to §3.9 stating that APPROVAL/OTP µs figures are the *mechanical dispatch floor* and that production T_hitl is dominated by human reaction time (typically 1–10 s), an external parameter not measurable by the gateway.

## MINOR ISSUES

1. **§2.5 — `ring` listed as a direct dep.** The workspace `Cargo.toml` does not depend on `ring` directly; it appears transitively via `reqwest` → `rustls-tls`. Write "dependências transitivas podem incluir `ring`" rather than listing it alongside direct native FFI crates.

2. **§3.6.3 — Ed25519 seed zeroization gap.** `sv_crypto::ed25519_sign` borrows the seed as `&[u8]` and constructs an `ed25519_dalek::SigningKey` (which zeroizes on drop via dalek). However, the *caller's* seed buffer (the wrapped seed stored by `sv-core`) must also be zeroized independently. The paper should note end-to-end seed zeroization depends on caller storage discipline, not solely on `sv-crypto`.

3. **§3.6.4 — Binary content in ANONYMIZED containers is denied, not filtered.** `apply_privacy_filter` rejects non-UTF-8 content. The paper should explicitly state this binary-content limitation for ANONYMIZED reads.

4. **§3.6.4 — Crash-recovery bound is undocumented.** The audit log's `recover_interrupted_commit` accepts exactly *one* uncheckpointed record as a valid interrupted commit; two or more cause a fail-closed integrity error. Correct and safe, but a subtle operational bound worth noting.

## STRENGTHS

1. `#![forbid(unsafe_code)]` enforced at both workspace and per-crate level — verified across `sv-crypto`, `sv-audit`, `sv-mcp`, `sv-storage`, `sv-privacy`.
2. Memory-safety claim is exceptionally well-bounded (explicit native-dep/WebView/OS/same-user exclusions; language-safety vs OS-isolation distinction; no `mlock`/anti-swap admitted; `Vec<u8>` plaintext copies not guaranteed zeroized). Rare honesty.
3. Audit log is production-grade: domain-separated HMAC-SHA256, atomic checkpoint (`sync_all` + dir fsync), symlink-resistant locking (`O_NOFOLLOW`), crash recovery, and explicit statement that full-directory rollback is undetectable without an external anchor.
4. AAD path-binding is cryptographically meaningful (`aad_for(container, file_name)`; cross-container relocation fails auth; verified by `aad_mismatch_fails_decrypt`).
5. Latency decomposition maps cleanly to Eq. 1 with opt-in `TimingSink`; adversarial battery uses real WS transport (not mocked components).
6. Reproducibility envelope (commit `dfb0a49`, release, `rustc 1.96.1`, i7-11600H, checksums) sufficient for replication.
