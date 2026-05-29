# Real-usage guide — Sovereign Vault

Last updated: 2026-05-29. Layout scaffolded on this machine; populate it yourself.

## 1. Container layout (already created, empty)

| Container | Mode | Purpose |
|---|---|---|
| `env-publimatch` | APPROVAL | `.env*` files for the publimatch codebase |
| `env-sovereign-vault` | APPROVAL | `.env*` files for the sovereign-vault codebase |
| `secrets-cloud` | APPROVAL | Cloud-provider keys (AWS, GCP, DO, Vercel…) |
| `secrets-api` | APPROVAL | 3rd-party API keys (Stripe, OpenAI, Anthropic, Supabase…) |
| `personal-id` | **OTP** | IDs, passports, recovery codes — high friction by design |
| `finance` | OTP | Pre-existing financial container |

Pre-existing test containers (`approval-test`, `claude-test`, `mcp-demo`, `otp-demo`) are still there. Delete them in the desktop UI once you don't need them.

Mode cheatsheet:
- **DIRECT**: no prompt. Use only for working data that isn't sensitive.
- **APPROVAL**: every access raises a desktop modal (Approve / Deny). Daily-use secrets.
- **OTP**: cross-channel — desktop shows a 6-digit code, agent resends with `otp=<code>`. Single-use, 120s TTL. For irreversible/regulated data.
- ANONYMIZED / ZKP / NATIVE: enum reserved, not implemented yet — don't use.

## 2. Wire an MCP client (any project)

The vault's MCP server binds on unlock at `ws://127.0.0.1:9944` and exposes pairing on `http://127.0.0.1:9943/.well-known/mcp-pairing`. Every client uses the same stdio proxy: `sovereign-vault.exe mcp-stdio`. The proxy auto-fetches the per-launch pairing secret.

**Claude Code** (`%APPDATA%\Claude\claude_desktop_config.json` or per-project `.mcp.json`):

```jsonc
{
  "mcpServers": {
    "sovereign-vault": {
      "command": "C:\\Users\\pealm\\Code\\sovereign-vault\\target\\release\\sovereign-vault.exe",
      "args": ["mcp-stdio"]
    }
  }
}
```

**Cursor / Continue.dev**: copy from the desktop app, **Settings → MCP server → Copy Cursor config / Copy Continue.dev config**. Same idea.

The vault must be **unlocked** before the client can call any tool. Lock = MCP servers stop binding.

## 3. Recommended: per-agent scoped tokens

Don't reuse the `Default` agent across every project — mint a scoped agent per project so a compromised client can only touch its own container:

1. Desktop → **Settings → Agents → New agent**
2. Name: e.g. `publimatch-prod`
3. Copy the **one-time token** (shown ONCE).
4. In that project's MCP client config, pass the token instead of using the default secret. (When using `sovereign-vault.exe mcp-stdio` the proxy reads `SV_PAIRING_TOKEN` from env if set; otherwise it falls back to the Default agent's per-launch secret. Set `SV_PAIRING_TOKEN=<the token>` in that project's env so its agent is bound to its scoped identity.)
5. Add scopes (in the Agents panel): glob `env-publimatch/*`, actions `read,list`.

Revoke any time from the Agents panel. The token never appears in the UI again.

## 4. Move an `.env` into the vault — playbook

From the project directory:

```bash
# 1. Encode (Windows Git Bash):
B64=$(base64 -w0 < .env)

# 2. Write via MCP proxy (vault must be unlocked, you'll approve in desktop):
WRITE="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"vault.write\",\"arguments\":{\"container\":\"env-publimatch\",\"file_name\":\".env\",\"content_b64\":\"$B64\"}}}"
{ printf '%s\n' "$WRITE"; sleep 5; } | sovereign-vault.exe mcp-stdio

# 3. Verify, then DELETE the plaintext .env:
rm .env
git rm --cached .env 2>/dev/null
echo ".env" >> .gitignore && git add .gitignore
```

For an OTP container (e.g. `personal-id`), the first `vault.write` returns `otp_required` and shows a code on the desktop; resend with `otp=<that code>`.

In dev, your app reads the secret back at startup via the MCP client (an agent tool call to `vault.read`). Don't echo it to logs.

## 5. Daily safety habits

- **Lock the vault** when you step away — kills MCP access until next unlock.
- **Approve carefully**: every modal shows the agent id, action, container, file. If something asks for `secrets-cloud` and you didn't initiate it, deny.
- **OTP for blast-radius data**: financial, ID, recovery phrases. Cross-channel typing is your friend.
- **Audit log** (`Settings → Open audit folder`) is append-only + hash-chained. Skim it weekly.
- **Backups**: copy the entire vault root and the OS-keychain entry (or recovery phrase) to a cold offline medium (USB stick, encrypted). Pre-alpha — keep independent copies.

## 6. Known limits (today)

- ANONYMIZED / ZKP / NATIVE modes are stubs (`"...not implemented for live MCP access"`).
- Container `delete` is destructive and not yet undo-able — confirm twice.
- Broker (`vault.broker_request`) is off by default. Enable with `SV_ENABLE_BROKER=1` if you want to inject secrets into outbound HTTP without exposing them.

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
const { source, vars } = await loadSecrets({ container: "env-publimatch" });
Object.assign(process.env, vars);
console.error(`[secrets] ${Object.keys(vars).length} keys via ${source}`);
```

**CLI (materialize a runtime file or pipe):**

```bash
node sv-secrets.mjs --container env-publimatch --out .env.runtime   # writes 0600 file
SECRETS_SOURCE=env node sv-secrets.mjs --container env-publimatch   # force local
```

Knobs: `SV_BIN` (path to `sovereign-vault.exe`), `SV_TIMEOUT_MS` (approval wait,
default 30000), `SV_OTP` (code for OTP containers), `SV_CACHE_TTL_MS` (session
cache, default 0 = off).

**Session cache (opt-in) — stop re-prompting on every dev restart.** With
`SV_CACHE_TTL_MS` > 0 (or `--cache-ttl <ms>`), a successful **vault** read is
cached to a `0600` temp file; subsequent runs within the TTL return
`source: "cache"` with **no approval prompt**. Clear it with `--clear-cache`.

```bash
SV_CACHE_TTL_MS=1800000 node sv-secrets.mjs --container env-publimatch  # 30-min cache
node sv-secrets.mjs --clear-cache                                       # wipe all cached secrets
```

⚠️ **Tradeoff:** the cache writes *decrypted* secrets to your temp dir for the
TTL window — that partially defeats the vault. Off by default. Use short TTLs,
`--clear-cache` when done, and never enable it on shared machines. **Verified
live:** first read prompted once + cached; second read served from cache with no
prompt; `--clear-cache` forced the next read back through the vault.

**Verified live 2026-05-29** on `env-publimatch`:
- `source=vault` → 3 keys pulled from vault (after one desktop Approve);
- `source=env` → 3 keys from local `.env`;
- `source=auto` with the vault unreachable → automatic fallback to `.env` + warning.

**Other languages (same behavior, same env knobs):**
- **Python** `clients/python/sv_secrets.py` — `from sv_secrets import load_secrets; src, vars = load_secrets(container="env-publimatch")`. CLI identical to Node. Stdlib only (≥3.8).
- **Shell** `clients/shell/sv-secrets.sh` — `source sv-secrets.sh; sv_load env-publimatch [auto|vault|env]` loads into the current shell; or `eval "$(bash sv-secrets.sh env-publimatch --export)"`. Wraps the Node loader by default (`SV_RUNNER=python SV_LOADER=…/sv_secrets.py` to use Python).

All three verified live: vault read (one Approve), `.env` fallback, `source=env`, and auto-fallback when the vault is unreachable.

Migration path: keep both in sync while you trust-build (`SECRETS_SOURCE=auto`),
then drop the local `.env` (or set `SECRETS_SOURCE=vault`) once confident.
APPROVAL containers prompt on every read — for hands-off dev boots either keep a
session-cached `.env.runtime`, use a DIRECT dev container, or pre-load once per
session.

## 8. What I did NOT touch on your behalf

- No real secrets typed by the agent. Empty container shells only.
- `finance` and any user data left unread.
- Agent identities: only the `Default` agent was used by the scaffolding. You decide which per-project agents to mint.
