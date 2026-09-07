#!/usr/bin/env bash
# Install the Sovereign Vault pre-commit hook into a repository.
#
# Copies scripts/pre-commit to <git-dir>/hooks/pre-commit and makes it
# executable. Refuses to overwrite an existing hook that is not ours unless
# --force is given. Never touches git config (no core.hooksPath changes) —
# the hook lands in this repository's hooks directory only.
#
# Usage:
#   scripts/install-precommit-hook.sh           # install into this repo
#   scripts/install-precommit-hook.sh <path>    # install into <path>'s repo
#   scripts/install-precommit-hook.sh --force    # overwrite a foreign hook
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
HOOK_SRC="$SCRIPT_DIR/pre-commit"

FORCE=0
TARGET_ARG=""
for arg in "$@"; do
    case $arg in
        --force) FORCE=1 ;;
        *) TARGET_ARG="$arg" ;;
    esac
done

TARGET_DIR="${TARGET_ARG:-$PWD}"
GIT_DIR=$(git -C "$TARGET_DIR" rev-parse --git-dir 2>/dev/null) || {
    echo "error: $TARGET_DIR is not inside a git repository" >&2
    exit 1
}
# Make absolute (git may print a relative --git-dir).
case $GIT_DIR in
    /*) ;;                                        # already absolute (POSIX)
    *) GIT_DIR="$TARGET_DIR/$GIT_DIR" ;;
esac
[ "${OS:-}" = "Windows_NT" ] && case $GIT_DIR in
    [A-Za-z]:*) ;;                                # already absolute (Windows)
esac

HOOK_DST="$GIT_DIR/hooks/pre-commit"
mkdir -p "$GIT_DIR/hooks"

if [ -e "$HOOK_DST" ] && [ "$FORCE" -ne 1 ]; then
    if grep -q "Sovereign Vault pre-commit hook" "$HOOK_DST" 2>/dev/null; then
        echo "existing Sovereign Vault hook found; replacing it."
    else
        echo "error: $HOOK_DST already exists and is not a Sovereign Vault hook." >&2
        echo "       Inspect it, then re-run with --force to overwrite." >&2
        exit 1
    fi
fi

cp "$HOOK_SRC" "$HOOK_DST"
chmod +x "$HOOK_DST"
echo "installed: $HOOK_DST"
echo
echo "The hook scans STAGED content before every commit and blocks on findings"
echo "or scanner failure (fail closed). Bypass when needed, deliberately:"
echo "    git commit --no-verify"
echo
echo "Note: a hook prevents the NEXT leak. If a credential is already exposed,"
echo "rotate it first — installing this hook does not fix an existing leak."
