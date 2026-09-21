#!/bin/bash
cd "$(dirname "$0")" || exit 1
REPO="$(pwd)"
LOG="$REPO/run.log"; : > "$LOG"
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

APP="$REPO/target/release/bundle/macos/Sovereign Vault.app"
DMG="$REPO/target/release/bundle/dmg/Sovereign Vault_0.0.0_x64.dmg"

# Strip any quarantine flag so Gatekeeper doesn't block the locally-built app
xattr -dr com.apple.quarantine "$APP" >>"$LOG" 2>&1

log "Opening dmg: $DMG"
open "$DMG" >>"$LOG" 2>&1

log "Launching app: $APP"
open "$APP" >>"$LOG" 2>&1
RC=$?
sleep 2
if pgrep -f "sovereign-vault-desktop" >/dev/null 2>&1 || pgrep -f "Sovereign Vault" >/dev/null 2>&1; then
  log "App process is running."
else
  log "App may not have stayed open (rc=$RC) — check for a Gatekeeper prompt."
fi
log "RUN_DONE exit=$RC"
