#!/bin/bash
# Build the headless CLI (provides `sovereign-vault mcp-stdio`).
cd "$(dirname "$0")" || exit 1
REPO="$(pwd)"; LOG="$REPO/cli_build.log"; : > "$LOG"
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
[ -x /usr/local/bin/brew ] && eval "$(/usr/local/bin/brew shellenv)"
[ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

log "Building CLI (cargo build --release -p sovereign-vault)…"
cargo build --release -p sovereign-vault >>"$LOG" 2>&1
RC=$?
BIN="$REPO/target/release/sovereign-vault"
if [ $RC -eq 0 ] && [ -x "$BIN" ]; then
  log "CLI built: $BIN"
  "$BIN" >>"$LOG" 2>&1   # prints version banner
else
  log "CLI build FAILED (exit $RC)"
fi
log "CLI_BUILD_DONE exit=$RC"
