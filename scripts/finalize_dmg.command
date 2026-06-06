#!/bin/bash
# Package the already-built Sovereign Vault.app into a .dmg using hdiutil,
# bypassing tauri's AppleScript-based bundle_dmg.sh (which fails under automation).
cd "$(dirname "$0")" || exit 1
REPO="$(pwd)"
LOG="$REPO/finalize.log"
: > "$LOG"
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

APP="$REPO/target/release/bundle/macos/Sovereign Vault.app"
DMGDIR="$REPO/target/release/bundle/dmg"
DMG="$DMGDIR/Sovereign Vault_0.0.0_x64.dmg"

if [ ! -d "$APP" ]; then log "ERROR: app not found at $APP"; log "FINALIZE_DONE exit=2"; exit 2; fi

# Detach any leftover mounted volumes from the failed run
for v in /Volumes/Sovereign\ Vault*; do
  [ -d "$v" ] && { log "Detaching $v"; hdiutil detach "$v" -force >>"$LOG" 2>&1; }
done
# Remove leftover temp + prior dmgs
rm -f "$DMGDIR/rw."*.dmg "$DMG" >>"$LOG" 2>&1

STAGING="$(mktemp -d)"
log "Staging app into $STAGING"
cp -R "$APP" "$STAGING/" >>"$LOG" 2>&1 || { log "copy failed"; log "FINALIZE_DONE exit=3"; exit 3; }
ln -s /Applications "$STAGING/Applications"

log "Creating compressed dmg…"
hdiutil create -volname "Sovereign Vault" -srcfolder "$STAGING" -ov -format UDZO "$DMG" >>"$LOG" 2>&1
RC=$?
rm -rf "$STAGING"

if [ $RC -eq 0 ] && [ -f "$DMG" ]; then
  log "DMG CREATED: $DMG"
  ls -lh "$DMG" | tee -a "$LOG"
else
  log "hdiutil failed (exit $RC)"
fi
log "FINALIZE_DONE exit=$RC"
exit $RC
