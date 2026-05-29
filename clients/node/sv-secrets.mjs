// sv-secrets.mjs — Sovereign Vault secrets loader with .env redundancy.
//
// Use the vault as your primary secrets manager, with the local `.env` as an
// automatic fallback so a locked/unavailable vault never blocks your project.
//
// Dependency-free (Node >= 18, ESM). Copy into any project, or reference it
// directly. No secret values are ever logged.
//
// ── Quick start ───────────────────────────────────────────────────────────
//   import { loadSecrets } from "./sv-secrets.mjs";
//   const { source, vars } = await loadSecrets({ container: "env-publimatch" });
//   Object.assign(process.env, vars);
//   console.error(`[secrets] loaded ${Object.keys(vars).length} keys from ${source}`);
//
// ── Switch source (env var, no code change) ─────────────────────────────────
//   SECRETS_SOURCE=auto   (default) try vault, fall back to .env on any failure
//   SECRETS_SOURCE=vault  vault only; throw if unavailable (no silent fallback)
//   SECRETS_SOURCE=env    local .env only; never touch the vault
//
// ── CLI ─────────────────────────────────────────────────────────────────────
//   node sv-secrets.mjs --container env-publimatch            # print .env to stdout
//   node sv-secrets.mjs --container env-publimatch --out .env.runtime
//   SECRETS_SOURCE=env node sv-secrets.mjs --container env-publimatch

import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";

const DEFAULTS = {
  // Path to the vault CLI. Override with SV_BIN.
  bin:
    process.env.SV_BIN ||
    "C:\\Users\\pealm\\Code\\sovereign-vault\\target\\release\\sovereign-vault.exe",
  file: ".env", // file name inside the container
  envPath: ".env", // local fallback path
  timeoutMs: Number(process.env.SV_TIMEOUT_MS) || 30000, // human-in-loop: time to click Approve
};

/** Minimal dotenv parser. Returns a plain object. Does not mutate process.env. */
export function parseDotenv(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (key) out[key] = val;
  }
  return out;
}

/**
 * Read one file from a vault container through the `mcp-stdio` proxy.
 * Resolves to the decoded plaintext string. Rejects on lock/deny/timeout/OTP.
 * The vault must be UNLOCKED; APPROVAL containers raise a desktop prompt.
 */
export function readFromVault({
  container,
  file = DEFAULTS.file,
  bin = DEFAULTS.bin,
  timeoutMs = DEFAULTS.timeoutMs,
  otp,
} = {}) {
  return new Promise((resolve, reject) => {
    if (!container) return reject(new Error("container is required"));
    const args = { container, file_name: file };
    if (otp) args.otp = otp;
    const frame = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "vault.read", arguments: args },
    });

    const child = spawn(bin, ["mcp-stdio"], { stdio: ["pipe", "pipe", "ignore"] });
    let buf = "";
    let done = false;

    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { child.kill(); } catch {}
      err ? reject(err) : resolve(val);
    };

    const timer = setTimeout(
      () => finish(new Error(`vault read timed out after ${timeoutMs}ms`)),
      timeoutMs
    );

    child.on("error", (e) => finish(e));
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id !== 1 || !msg.result) continue;
        const text = msg.result?.content?.[0]?.text ?? "";
        if (msg.result.isError) {
          return finish(new Error(`vault: ${text}`)); // includes otp_required
        }
        let payload;
        try { payload = JSON.parse(text); } catch { return finish(new Error("bad vault payload")); }
        const b64 = payload.content_b64;
        if (!b64) return finish(new Error("vault response missing content_b64"));
        return finish(null, Buffer.from(b64, "base64").toString("utf8"));
      }
    });

    child.stdin.write(frame + "\n");
    // Keep stdin open so the proxy stays alive until the response arrives.
  });
}

/** Read the local .env fallback. Rejects if missing. */
async function readFromEnvFile(envPath = DEFAULTS.envPath) {
  if (!existsSync(envPath)) throw new Error(`no local fallback at ${envPath}`);
  return readFile(envPath, "utf8");
}

/**
 * Load secrets honoring SECRETS_SOURCE (auto|vault|env).
 * Returns { source: "vault"|"env", vars }.
 */
export async function loadSecrets({
  container,
  file = DEFAULTS.file,
  envPath = DEFAULTS.envPath,
  source = process.env.SECRETS_SOURCE || "auto",
  bin = DEFAULTS.bin,
  timeoutMs = DEFAULTS.timeoutMs,
  otp = process.env.SV_OTP,
} = {}) {
  const tryVault = async () => parseDotenv(await readFromVault({ container, file, bin, timeoutMs, otp }));
  const tryEnv = async () => parseDotenv(await readFromEnvFile(envPath));

  if (source === "env") return { source: "env", vars: await tryEnv() };
  if (source === "vault") return { source: "vault", vars: await tryVault() };

  // auto: vault first, fall back to .env on ANY failure.
  try {
    return { source: "vault", vars: await tryVault() };
  } catch (e) {
    process.stderr.write(`[sv-secrets] vault unavailable (${e.message}); falling back to ${envPath}\n`);
    return { source: "env", vars: await tryEnv() };
  }
}

/** Serialize vars back to dotenv text (for --out). */
function toDotenv(vars) {
  return Object.entries(vars).map(([k, v]) => `${k}=${v}`).join("\n") + "\n";
}

// ── CLI ──────────────────────────────────────────────────────────────────────
const isMain = import.meta.url === `file://${process.argv[1]}` ||
  process.argv[1]?.endsWith("sv-secrets.mjs");
if (isMain) {
  const argv = process.argv.slice(2);
  const get = (flag) => { const i = argv.indexOf(flag); return i === -1 ? undefined : argv[i + 1]; };
  const container = get("--container");
  const file = get("--file") || DEFAULTS.file;
  const out = get("--out");
  const source = get("--source") || process.env.SECRETS_SOURCE || "auto";
  if (!container) {
    process.stderr.write("usage: node sv-secrets.mjs --container <name> [--file .env] [--source auto|vault|env] [--out path]\n");
    process.exit(2);
  }
  loadSecrets({ container, file, source })
    .then(async ({ source, vars }) => {
      process.stderr.write(`[sv-secrets] ${Object.keys(vars).length} keys from ${source}\n`);
      const text = toDotenv(vars);
      if (out) { await writeFile(out, text, { mode: 0o600 }); process.stderr.write(`[sv-secrets] wrote ${out}\n`); }
      else process.stdout.write(text);
    })
    .catch((e) => { process.stderr.write(`[sv-secrets] ERROR ${e.message}\n`); process.exit(1); });
}
