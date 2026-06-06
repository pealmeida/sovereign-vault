#!/bin/bash
# Sovereign Vault — macOS build script (build UI, then bundle .app + .dmg)
# Launched by double-click from Finder. All output logged to build.log.

cd "$(dirname "$0")" || exit 1
REPO="$(pwd)"
LOG="$REPO/build.log"

# Fresh log
: > "$LOG"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }

# Make brew + cargo available regardless of how Terminal launched
[ -x /usr/local/bin/brew ] && eval "$(/usr/local/bin/brew shellenv)"
[ -x /opt/homebrew/bin/brew ] && eval "$(/opt/homebrew/bin/brew shellenv)"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

log "Repo: $REPO"
log "node: $(command -v node || echo MISSING)  $(node --version 2>/dev/null)"

# Install Rust via Homebrew if cargo is missing
if ! command -v cargo >/dev/null 2>&1; then
  if ! command -v brew >/dev/null 2>&1; then
    log "ERROR: neither cargo nor brew found."; log "BUILD_DONE exit=90"; exit 90
  fi
  log "cargo missing — installing Rust via Homebrew (brew install rust)…"
  # A dependency link conflict (e.g. python idle3) can make brew exit nonzero
  # even though the rust keg installed fine — so don't abort on nonzero here.
  brew install rust >>"$LOG" 2>&1 || log "brew install returned nonzero; checking whether rust landed anyway…"
  RUSTBIN="$(brew --prefix rust 2>/dev/null)/bin"
  export PATH="$HOME/.cargo/bin:$RUSTBIN:$(brew --prefix)/bin:$PATH"
  hash -r
fi
log "cargo: $(command -v cargo || echo MISSING)  $(cargo --version 2>/dev/null)"
if ! command -v cargo >/dev/null 2>&1; then
  log "ERROR: cargo still not found after install."; log "BUILD_DONE exit=92"; exit 92
fi

# 1) Frontend deps + build
if [ ! -d "$REPO/ui/node_modules" ]; then
  log "Installing UI dependencies (npm install)…"
  ( cd "$REPO/ui" && npm install ) >>"$LOG" 2>&1 || { log "npm install FAILED"; log "BUILD_DONE exit=10"; exit 10; }
fi
log "Building UI (npm run build)…"
( cd "$REPO/ui" && npm run build ) >>"$LOG" 2>&1 || { log "UI build FAILED"; log "BUILD_DONE exit=11"; exit 11; }

# 2) Ensure tauri CLI
if ! cargo tauri --version >/dev/null 2>&1; then
  log "Installing tauri-cli (this can take several minutes)…"
  cargo install tauri-cli --version "^2.0.0" >>"$LOG" 2>&1 || { log "tauri-cli install FAILED"; log "BUILD_DONE exit=12"; exit 12; }
fi
log "tauri-cli: $(cargo tauri --version 2>/dev/null)"

# 3) Bundle the macOS app + dmg
# tauri-cli v2 auto-detects the project from cwd (no --manifest-path); run from apps/desktop.
log "Running cargo tauri build (compiling Rust workspace — this takes a while)…"
( cd "$REPO/apps/desktop" && cargo tauri build ) >>"$LOG" 2>&1
RC=$?

# src-tauri is a workspace member, so output lands in the workspace-root target dir.
BUNDLE="$REPO/target/release/bundle"
[ -d "$BUNDLE" ] || BUNDLE="$REPO/apps/desktop/src-tauri/target/release/bundle"
if [ $RC -eq 0 ]; then
  log "BUILD SUCCEEDED. Artifacts:"
  ls -1 "$BUNDLE/dmg/"*.dmg 2>/dev/null | tee -a "$LOG"
  ls -1d "$BUNDLE/macos/"*.app 2>/dev/null | tee -a "$LOG"
else
  log "cargo tauri build FAILED (exit $RC). See log above."
fi
log "BUILD_DONE exit=$RC"
exit $RC
