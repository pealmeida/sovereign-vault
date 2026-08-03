#!/usr/bin/env bash
# Regression tests for the executed `sv-secrets.sh <container> --export` path.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
wrapper="$here/sv-secrets.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/sv-secrets-test.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

python_runner="$tmp/python"
printf '%s\n' '#!/usr/bin/env bash' 'exec python3 "$@"' > "$python_runner"
chmod 700 "$python_runner"

success_loader="$tmp/success-loader.py"
printf '%s\n' \
  '#!/usr/bin/env python3' \
  'import pathlib, sys' \
  'out = pathlib.Path(sys.argv[sys.argv.index("--out") + 1])' \
  'out.write_text(chr(10).join(["API_TOKEN=expected-secret", "SERVICE_KEY=expected-key"]) + chr(10), encoding="utf-8")' \
  > "$success_loader"
chmod 700 "$success_loader"

success_output="$(PATH="$tmp:$PATH" SV_RUNNER=python SV_LOADER="$success_loader" bash "$wrapper" example --export)"
[ "$success_output" = $'export API_TOKEN=expected-secret\nexport SERVICE_KEY=expected-key' ] || \
  fail "Python runner did not emit the expected exports"

failure_loader="$tmp/failure-loader.py"
printf '%s\n' \
  '#!/usr/bin/env python3' \
  'import sys' \
  'sys.stderr.write("forced loader failure" + chr(10))' \
  'raise SystemExit(7)' \
  > "$failure_loader"
chmod 700 "$failure_loader"

set +e
PATH="$tmp:$PATH" SV_RUNNER=python SV_LOADER="$failure_loader" bash "$wrapper" example --export \
  > "$tmp/failure.stdout" 2> "$tmp/failure.stderr"
failure_status=$?
set -e
[ "$failure_status" -ne 0 ] || fail "Python loader failure was reported as success"
[ ! -s "$tmp/failure.stdout" ] || fail "Python loader failure emitted exports"
! rg -q 'expected-secret|expected-key' "$tmp/failure.stderr" || \
  fail "Python loader failure leaked a secret"

# The default Node runner keeps the same eval-ready output contract.
printf '%s\n' 'NODE_TOKEN=expected-node-secret' > "$tmp/.env"
node_output="$(cd "$tmp" && SECRETS_SOURCE=env bash "$wrapper" example --export)"
[ "$node_output" = 'export NODE_TOKEN=expected-node-secret' ] || \
  fail "Node runner did not emit the expected exports"

echo "PASS: shell Python and Node --export paths"
