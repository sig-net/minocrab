#!/usr/bin/env bash
# Self-contained test for the checkpoint-on-v3 bug.
#
# kernel.checkpoint() compiles on the default (v2) backend but crashes the v3
# backend with an internal not-implemented assertion. This script asserts:
#   - v2 compiles cleanly (exit 0)
#   - v3 fails (non-zero) AND the failure is the internal assertion, not a
#     clean diagnostic naming the unsupported construct.
# It PASSES while the bug is present and starts FAILING once v3 either supports
# checkpoint or rejects it with a proper error.
#
# Requires only `compactc` on PATH. Run:
#     ./test.sh
set -uo pipefail
cd "$(dirname "$0")"

src="checkpoint.compact"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

fail() { echo "TEST FAILED: $1" >&2; exit 1; }

# --- v2: must succeed ---
if ! compactc --skip-zk "$src" "$out/v2" >/dev/null 2>&1; then
  fail "v2 backend rejected checkpoint (expected it to compile)"
fi
echo "ok: v2 compiles kernel.checkpoint()"

# --- v3: must fail with the internal not-implemented assertion ---
v3err="$(compactc --skip-zk --feature-zkir-v3 "$src" "$out/v3" 2>&1)"
v3code=$?
if [[ $v3code -eq 0 ]]; then
  fail "v3 backend now compiles checkpoint — bug appears fixed, update this test"
fi
if ! grep -q "not-implemented" <<<"$v3err"; then
  fail "v3 failed, but not with the internal not-implemented assertion. Got:
$v3err"
fi
echo "ok: v3 crashes with the internal assertion (bug reproduced):"
grep -m1 "not-implemented" <<<"$v3err" | sed 's/^/    /'

echo "PASS: checkpoint compiles on v2 and crashes the v3 backend."
