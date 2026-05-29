#!/usr/bin/env bash
# sv-secrets.sh — load Sovereign Vault secrets into the current shell, with
# automatic .env fallback. Thin wrapper over clients/node/sv-secrets.mjs
# (override with SV_LOADER; set SV_RUNNER=python + SV_LOADER=.../sv_secrets.py
# to use the Python port instead).
#
# Source it, then call sv_load:
#     source sv-secrets.sh
#     sv_load env-publimatch            # SECRETS_SOURCE env or 'auto'
#     sv_load env-publimatch vault      # force a source
#
# Or run it to print KEY=VALUE for `eval`-style use:
#     eval "$(SECRETS_SOURCE=env bash sv-secrets.sh env-publimatch --export)"
#
# Honors the same env knobs as the loaders: SECRETS_SOURCE, SV_BIN,
# SV_TIMEOUT_MS, SV_OTP, SV_CACHE_TTL_MS.

_svc_loader() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
  echo "${SV_LOADER:-$here/../node/sv-secrets.mjs}"
}

_svc_run() {
  # args passed straight to the loader CLI
  local runner="${SV_RUNNER:-node}"
  "$runner" "$(_svc_loader)" "$@"
}

# Load secrets into the CURRENT shell (must be sourced).
sv_load() {
  local container="$1" src="${2:-${SECRETS_SOURCE:-auto}}"
  if [ -z "$container" ]; then echo "usage: sv_load <container> [auto|vault|env]" >&2; return 2; fi
  local tmp; tmp="$(mktemp)"; chmod 600 "$tmp"
  if SECRETS_SOURCE="$src" _svc_run --container "$container" --out "$tmp"; then
    set -a; . "$tmp"; set +a
    echo "[sv-secrets] loaded container '$container' into shell" >&2
    rm -f "$tmp"; return 0
  fi
  rm -f "$tmp"; echo "[sv-secrets] load failed" >&2; return 1
}

# When executed (not sourced) with a container arg: print to stdout (for eval).
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ] && [ -n "${1:-}" ]; then
  container="$1"; shift
  export_flag=""
  for a in "$@"; do [ "$a" = "--export" ] && export_flag=1; done
  if [ -n "$export_flag" ]; then
    # prefix each KEY=VALUE with `export ` so `eval` puts them in the env
    _svc_run --container "$container" | sed 's/^/export /'
  else
    _svc_run --container "$container"
  fi
fi
