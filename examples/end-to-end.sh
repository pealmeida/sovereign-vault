#!/usr/bin/env bash
# end-to-end.sh — drive the real agent path against an UNLOCKED vault.
#
# Pipes line-delimited JSON-RPC into the `mcp-stdio` proxy, which fetches the
# pairing secret over loopback HTTP, opens the WebSocket to the running vault,
# pairs the Default agent, and forwards frames. Stores CLEARLY-FAKE secrets
# only — never real credentials.
#
# Usage (from the repo root, vault unlocked):
#   ./examples/end-to-end.sh
#   SV_CLI=/path/to/sovereign-vault ./examples/end-to-end.sh
set -uo pipefail

# Resolve the CLI cross-platform: SV_CLI override, else the repo build, else PATH.
EXE="sovereign-vault"; [ "${OS:-}" = "Windows_NT" ] && EXE="sovereign-vault.exe"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${SV_CLI:-}"
if [ -z "$CLI" ]; then
  if [ -x "$ROOT/target/release/$EXE" ]; then CLI="$ROOT/target/release/$EXE"
  elif [ -x "$ROOT/target/debug/$EXE" ]; then CLI="$ROOT/target/debug/$EXE"
  else CLI="$EXE"; fi
fi
echo "[e2e] using CLI: $CLI"

# Fake project .env (NOT real keys).
ENV_CONTENT=$'API_KEY=sk-test-FAKE-0000000000\nDATABASE_URL=postgres://user:fakepw@localhost/app'
ENV_B64=$(printf '%s' "$ENV_CONTENT" | base64 | tr -d '\n')

frames() {
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault.create_container","arguments":{"name":"env-e2e","mode":"DIRECT","description":"e2e fake project env"}}}'
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"vault.write\",\"arguments\":{\"container\":\"env-e2e\",\"file_name\":\"webapp.env\",\"content_b64\":\"$ENV_B64\"}}}"
  printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vault.read","arguments":{"container":"env-e2e","file_name":"webapp.env"}}}'
}

# The trailing sleep keeps stdin open so responses flush before EOF.
{ frames; sleep 4; } | "$CLI" mcp-stdio
echo
echo "[e2e] done — check that id:4 round-trips the bytes written in id:3."
echo "[e2e] note: vault.create_container is approval-gated; approve it on the desktop if prompted."
