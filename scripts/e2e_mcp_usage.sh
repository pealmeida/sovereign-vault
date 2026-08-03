#!/usr/bin/env bash
# Realistic end-to-end usage simulation.
#
# Drives the SAME MCP path a real agent (Claude Desktop / Cursor) uses:
# pipes line-delimited JSON-RPC into the installed `mcp-stdio` proxy, which
# fetches the pairing secret over HTTP, opens the WebSocket to the running
# vault, pairs, and forwards frames. The vault must be UNLOCKED.
#
# Stores CLEARLY-FAKE secrets only — never real credentials.
set -uo pipefail

# Resolve the CLI cross-platform: SV_CLI override, else repo build, else PATH.
EXE="sovereign-vault"; [ "${OS:-}" = "Windows_NT" ] && EXE="sovereign-vault.exe"
CLI="${SV_CLI:-target/release/$EXE}"
[ -x "$CLI" ] || CLI="target/debug/$EXE"
[ -x "$CLI" ] || CLI="$EXE"  # fall back to PATH

# Fake project .env (NOT real keys).
ENV_CONTENT=$'API_KEY=sk-test-FAKE-0000000000\nDATABASE_URL=postgres://user:fakepw@localhost/app\nSTRIPE_KEY=sk_live_FAKE_do_not_use'
ENV_B64=$(printf '%s' "$ENV_CONTENT" | base64 -w0)

# Plaintext to push through the transit key (agent never sees the key).
SECRET_B64=$(printf '%s' 'rotate-me-please' | base64 -w0)

frames() {
  # 1. discover tools
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
  # 2. agent creates a project container (DIRECT so no approval prompt)
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault.create_container","arguments":{"name":"env-e2e","mode":"DIRECT","description":"e2e fake project env"}}}'
  # 3. agent stores the env file (vault rejects leading-dot names, so ".env"
  #    is stored as "webapp.env")
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"vault.write\",\"arguments\":{\"container\":\"env-e2e\",\"file_name\":\"webapp.env\",\"content_b64\":\"$ENV_B64\"}}}"
  # 4. agent reads it back
  printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vault.read","arguments":{"container":"env-e2e","file_name":"webapp.env"}}}'
  # 5. list files
  printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"vault.list","arguments":{"container":"env-e2e"}}}'
  # 6. use a secret WITHOUT seeing the key: transit encrypt then decrypt (demo-key created in the UI)
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"vault.encrypt\",\"arguments\":{\"key_ref\":\"demo-key\",\"plaintext_b64\":\"$SECRET_B64\"}}}"
}

echo "=== running realistic MCP usage simulation against the live vault ==="
# Keep stdin open briefly so responses flush before the proxy sees EOF.
OUT=$( { frames; sleep 3; } | "$CLI" mcp-stdio 2>/tmp/sv_e2e.err )
echo "$OUT"
echo "=== proxy stderr (pairing/errors) ==="
cat /tmp/sv_e2e.err 2>/dev/null | head -5
