# Real-usage guide — Sovereign Vault

How to use the vault for real work: container layout, per-agent scoped tokens,
the `.env` migration playbook, the OTP flow, the session cache, and backups.

Examples below use placeholder names like `env-myproject`. Replace them with
your own. Paths are shown for macOS/Linux; Windows equivalents are noted inline.

## 1. Suggested container layout

Create these in the desktop app (**Vault → New vault**) — pick a mode per
container based on how sensitive the data is:

| Container | Mode | Purpose |
|---|---|---|
| `env-myproject` | APPROVAL | `.env*` files for a codebase |
| `secrets-cloud` | APPROVAL | Cloud-provider keys (AWS, GCP, DO, Vercel…) |
| `secrets-api` | APPROVAL | 3rd-party API keys (Stripe, OpenAI, Anthropic, Supabase…) |
| `personal-id` | **OTP** | IDs, passports, recovery codes — high friction by design |

Mode cheatsheet:
- **DIRECT**: no prompt. Use only for working data that isn't sensitive.
- **APPROVAL**: every access raises a desktop modal (Approve / Deny). Daily-use secrets.
- **OTP**: cross-channel — desktop shows a 6-digit code, agent resends with `otp=<code>`. Single-use, 120s TTL. For irreversible/regulated data.
- ANONYMIZED / ZKP / NATIVE: enum reserved, not implemented yet — don't use.

## 2. Wire an MCP client (any project)

The vault's MCP server binds on unlock at `ws://127.0.0.1:9944` and exposes
pairing on `http://127.0.0.1:9943/.well-known/mcp-pairing`. Every client uses the
same stdio proxy: `sovereign-vault mcp-stdio` (the proxy auto-fetches the
per-launch pairing secret).

Ready-to-paste configs live in [`examples/`](../examples/). For Claude Desktop:

```jsonc
// macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json
// Windows: %APPDATA%\Claude\claude_desktop_config.json
{
  "mcpServers": {
    "sovereign-vault": {
      "command": "/ABSOLUTE/PATH/TO/sovereign-vault/target/release/sovereign-vault",
      "args": ["mcp-stdio"]
    }
  }
}
```

> On Windows the binary is `…\target\release\sovereign-vault.exe`. The desktop
> app's **Settings → MCP server** page has "Copy config" buttons that fill in
> your real binary path for Claude Desktop / Cursor / Continue.dev.

The vault must be **unlocked** before any tool call. Lock = MCP servers stop binding.

You can also install the generated `/sovereign-vault` command packs for
supported agents:

```bash
sovereign-vault agents list-targets
sovereign-vault agents install --target claude-code
sovereign-vault agents install --target codex
```

## 3. Recommended: per-agent scoped tokens

Don't reuse the `Default` agent across every project — mint a scoped agent per
project so a compromised client can only touch its own container:

1. Desktop → **Settings → Agents → New agent**
2. Name: e.g. `myproject-prod`
3. Copy the **one-time token** (shown ONCE).
4. In that project's MCP client environment, set `SV_AGENT_ID=<agent id>` and
   `SV_PAIRING_TOKEN=<the token>`. The `mcp-stdio` proxy sends
   `vault.pair { agent_id, token }` when both are present; with only
   `SV_PAIRING_TOKEN` set it falls back to shared-secret pairing as the Default
   agent.
5. Add scopes (in the Agents panel): glob `env-myproject/*`, actions `read,list`.

Revoke any time from the Agents panel. The token never appears in the UI again.

## 4. Move an `.env` into the vault — playbook

From the project directory (vault unlocked; you'll approve in the desktop):

```bash
# 1. Encode the file (macOS/Linux):
B64=$(base64 < .env | tr -d '\n')

# 2. Write via the MCP proxy:
WRITE="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"vault.write\",\"arguments\":{\"container\":\"env-myproject\",\"file_name\":\".env\",\"content_b64\":\"$B64\"}}}"
{ printf '%s\n' "$WRITE"; sleep 5; } | sovereign-vault mcp-stdio

# 3. Verify the read-back, then DELETE the plaintext .env:
rm .env
git rm --cached .env 2>/dev/null
echo ".env" >> .gitignore && git add .gitignore
```

For an OTP container (e.g. `personal-id`), the first `vault.write` returns
`otp_required` and shows a code on the desktop; resend with `otp=<that code>`.

In dev, your app reads the secret back at startup via the MCP client (an agent
tool call to `vault.read`). Don't echo it to logs.

## 5. Daily safety habits

- **Lock the vault** when you step away — kills MCP access until next unlock.
- **Approve carefully**: every modal shows the agent id, action, container, file. If something asks for `secrets-cloud` and you didn't initiate it, deny.
- **OTP for blast-radius data**: financial, ID, recovery phrases. Cross-channel typing is your friend.
- **Audit log** (`Settings → Open audit folder`) is append-only + hash-chained. Skim it weekly.
- **Backups**: copy the entire vault root and the OS-keychain entry (or recovery phrase) to a cold offline medium. Pre-alpha — keep independent copies.

## 6. Known limits (today)

- ANONYMIZED / ZKP / NATIVE modes are stubs (`"...not implemented for live MCP access"`).
- Container `delete` is destructive and not yet undo-able — confirm twice.
- Broker tools are off by default. Enable with `SV_ENABLE_BROKER=1` to create
  brokered secrets and use `vault.broker_request` without exposing credentials
  to the agent.

## 7. Vault-as-primary with `.env` redundancy (the safe switch)

Use the vault as your main secrets manager, but keep the local `.env` as an
automatic fallback so a locked/buggy vault never blocks a project. Loader:
`clients/node/sv-secrets.mjs` (dependency-free, Node ≥18). Copy it into a
project or reference it directly.

**One env var flips the source — no code change:**

| `SECRETS_SOURCE` | Behavior |
|---|---|
| `auto` (default) | Try vault; on **any** failure (locked, timeout, OTP, denied) fall back to `.env` with a stderr warning |
| `vault` | Vault only; throw if unavailable (no silent fallback — use in CI gates) |
| `env` | Local `.env` only; never touch the vault |

**App integration (startup):**

```js
import { loadSecrets } from "./sv-secrets.mjs";
const { source, vars } = await loadSecrets({ container: "env-myproject" });
Object.assign(process.env, vars);
console.error(`[secrets] ${Object.keys(vars).length} keys via ${source}`);
```

**CLI (materialize a runtime file or pipe):**

```bash
node sv-secrets.mjs --container env-myproject --out .env.runtime   # writes 0600 file
SECRETS_SOURCE=env node sv-secrets.mjs --container env-myproject   # force local
```

Knobs: `SV_BIN` (path to the `sovereign-vault` binary — auto-discovered from the
repo build or your `PATH` if unset), `SV_TIMEOUT_MS` (approval wait, default
30000), `SV_OTP` (code for OTP containers), `SV_CACHE_TTL_MS` (session cache,
default 0 = off).

**Session cache (opt-in) — stop re-prompting on every dev restart.** With
`SV_CACHE_TTL_MS` > 0 (or `--cache-ttl <ms>`), a successful **vault** read is
cached to a `0600` temp file; subsequent runs within the TTL return
`source: "cache"` with **no approval prompt**. Clear it with `--clear-cache`.

```bash
SV_CACHE_TTL_MS=1800000 node sv-secrets.mjs --container env-myproject  # 30-min cache
node sv-secrets.mjs --clear-cache                                      # wipe all cached secrets
```

⚠️ **Tradeoff:** the cache writes *decrypted* secrets to your temp dir for the
TTL window — that partially defeats the vault. Off by default. Use short TTLs,
`--clear-cache` when done, and never enable it on shared machines.

**Other languages (same behavior, same env knobs):**
- **Python** `clients/python/sv_secrets.py` — `from sv_secrets import load_secrets; src, vars = load_secrets(container="env-myproject")`. CLI identical to Node. Stdlib only (≥3.8).
- **Shell** `clients/shell/sv-secrets.sh` — `source sv-secrets.sh; sv_load env-myproject [auto|vault|env]` loads into the current shell; or `eval "$(bash sv-secrets.sh env-myproject --export)"`. Wraps the Node loader by default (`SV_RUNNER=python SV_LOADER=…/sv_secrets.py` to use Python).

Migration path: keep both in sync while you trust-build (`SECRETS_SOURCE=auto`),
then drop the local `.env` (or set `SECRETS_SOURCE=vault`) once confident.
APPROVAL containers prompt on every read — for hands-off dev boots either keep a
session-cached `.env.runtime`, use a DIRECT dev container, or pre-load once per
session.
