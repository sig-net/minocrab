#!/usr/bin/env bash
# Self-contained test for the `<ledger read> || deserialize<…>(…)` crash.
#
# A short-circuit || whose one side reads a ledger field and whose other side
# calls deserialize crashes check-types/Lflattened with an internal error
# rather than compiling (it compiles on 0.34.0) or producing a diagnostic.
# This script asserts:
#   - the crash is present, on BOTH backends (it is not zkir-v3 specific)
#   - the failure is the internal error, not a clean diagnostic
#   - the control cases still compile, so a "pass" means the bug is really
#     this shape and not the file being broken some other way
# It PASSES while the bug is present and starts FAILING once the compiler
# either accepts the program or rejects it with a proper error.
#
# Requires only `compactc` on PATH. Run:
#     ./test.sh
set -uo pipefail
cd "$(dirname "$0")"

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

fail() { echo "TEST FAILED: $1" >&2; exit 1; }

# --- the bug: both backends must crash with the internal error ---
for flag in "" "--feature-zkir-v3"; do
  label="${flag:-default(v2)}"
  err="$(compactc --skip-zk $flag ice.compact "$out/ice-${label//[^a-z0-9]/}" 2>&1)"
  code=$?
  if [[ $code -eq 0 ]]; then
    fail "[$label] now compiles ice.compact — bug appears fixed, update this test"
  fi
  if ! grep -q "Internal error" <<<"$err"; then
    fail "[$label] failed, but not with an internal error. Got:
$err"
  fi
  if ! grep -q "check-types/Lflattened" <<<"$err"; then
    fail "[$label] crashed somewhere other than check-types/Lflattened. Got:
$err"
  fi
  echo "ok: [$label] crashes in check-types/Lflattened"
done
grep -m1 "incompatible types" <<<"$(compactc --skip-zk ice.compact "$out/msg" 2>&1)" | sed 's/^/    /'

# --- controls: each removes ONE required ingredient and must compile ---
ctl() {
  local name="$1" src="$2"
  printf '%s\n' "$src" > "$out/$name.compact"
  if ! compactc --skip-zk "$out/$name.compact" "$out/$name" >/dev/null 2>&1; then
    fail "control '$name' did not compile; the repro is not isolated to the reported shape"
  fi
  echo "ok: control '$name' compiles"
}

ctl no_shortcircuit 'pragma language_version >= 0.25;

import CompactStandardLibrary;

export ledger flag: Boolean;

export circuit go(output: Bytes<1>): Boolean {
  const a = flag;
  const b = deserialize<Boolean, 1>(output);
  return a;
}'

ctl no_ledger_read 'pragma language_version >= 0.25;

import CompactStandardLibrary;

export circuit go(flag: Boolean, output: Bytes<1>): Boolean {
  return flag || deserialize<Boolean, 1>(output);
}'

ctl no_deserialize 'pragma language_version >= 0.25;

import CompactStandardLibrary;

export ledger flag: Boolean;

export circuit go(output: Bytes<1>): Boolean {
  return flag || output != default<Bytes<1>>;
}'

echo "PASS: the crash needs a short-circuit operator, a ledger read and a deserialize; removing any one compiles."
