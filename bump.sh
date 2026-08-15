#!/usr/bin/env bash
# The runnable half of notes/version-bump.org — the M8 churn-resilience
# workflow. Read that file for the DRIFT TAXONOMY: what a failure in each
# instrument means and what the correct response is.
#
#   ./bump.sh pins     what we pin, what upstream ships, what moved (network)
#   ./bump.sh gates    the post-bump gate sequence, in diagnosis order
#   ./bump.sh accept   every regenerator, i.e. accept-the-new-baseline
#
# Run inside the direnv/nix shell (`nix develop -c ./bump.sh gates` also
# works). Nix supplies BINARIES ONLY — cargo, compactc, zkir, node; every
# build below is plain cargo.
set -uo pipefail
cd "$(dirname "$0")"

LEDGER_REPO="https://github.com/midnightntwrk/midnight-ledger"
COMPACT_REPO="https://github.com/LFDT-Minokawa/compact"

# ---------------------------------------------------------------- utilities

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
rule() { printf '%s\n' "------------------------------------------------------------------------"; }

# What flake.nix pins the compactc release at.
pinned_compactc() { sed -n 's/^ *compactcVersion = "\(.*\)";/\1/p' flake.nix; }

# The single midnight-ledger rev every midnight-* dependency uses.
pinned_ledger_rev() {
  sed -n 's/.*midnightntwrk\/midnight-ledger", rev = "\([0-9a-f]*\)".*/\1/p' Cargo.toml |
    sort -u
}

# ------------------------------------------------------------------- `pins`
#
# Everything a bump decision needs, on one screen: what we pin, what the
# pinned compactc release itself was built against, and what is newer
# upstream. Needs network.

cmd_pins() {
  bold "LOCAL PINS"
  local compactc_version
  compactc_version="$(pinned_compactc)"
  printf '  flake.nix compactc            %s\n' "$compactc_version"
  printf '  Cargo.toml midnight-ledger    %s\n' "$(pinned_ledger_rev | tr '\n' ' ')"
  printf '  Cargo.toml [patch] tag        %s\n' \
    "$(sed -n 's/.*midnight-ledger", tag = "\(.*\)".*/\1/p' Cargo.toml | sort -u | tr '\n' ' ')"
  for bin in compactc zkir zkir-v3 rustc; do
    if command -v "$bin" >/dev/null 2>&1; then
      printf '  %-29s %s\n' "$bin --version" "$("$bin" --version 2>&1 | head -1)"
    else
      printf '  %-29s NOT ON PATH (run inside the nix shell)\n' "$bin"
    fi
  done
  printf '  locked crate versions         %s\n' \
    "$(grep -A1 -E '^name = "midnight-(zkir|zkir-v3)"$' Cargo.lock |
       sed -n 's/^version = "\(.*\)"/\1/p' | tr '\n' ' ')"

  rule
  bold "WHAT THE PINNED compactc WAS BUILT AGAINST"
  echo "  ($COMPACT_REPO @ compactc-v$compactc_version, its own flake.lock)"
  local lock
  lock="$(curl -fsSL "https://raw.githubusercontent.com/LFDT-Minokawa/compact/compactc-v$compactc_version/flake.lock" 2>/dev/null)"
  if [ -z "$lock" ]; then
    echo "  UNAVAILABLE (no network, or the tag has no flake.lock)"
  else
    printf '%s' "$lock" | jq -r '
      .nodes | to_entries[]
      | select((.value.locked.repo // "") | test("ledger"))
      | [.key, .value.locked.rev, (.value.original.ref // "-")] | @tsv' |
      awk -F'\t' '{ printf "  %-16s %s  %s\n", $1, $2, $3 }'
    echo
    echo "  READ THIS AGAINST the Cargo.toml rev above. They are allowed to"
    echo "  differ (we need ONE rev for all midnight-* crates so their types"
    echo "  unify; upstream pins zkir and zkir-v3 from two). What is NOT"
    echo "  allowed is not knowing — see notes/version-bump.org §Hazard 1."
  fi

  rule
  bold "UPSTREAM: IS ANYTHING NEWER?"
  echo "  compactc releases (newest first):"
  if command -v gh >/dev/null 2>&1; then
    gh release list -R LFDT-Minokawa/compact -L 6 2>/dev/null | sed 's/^/    /'
  else
    curl -fsSL "https://api.github.com/repos/LFDT-Minokawa/compact/releases?per_page=6" |
      jq -r '.[] | "    \(.tag_name)\t\(.prerelease|if . then "pre-release" else "latest" end)\t\(.published_at)"'
  fi
  local head ours cmp
  head="$(git ls-remote "$LEDGER_REPO" HEAD 2>/dev/null | cut -f1)"
  ours="$(pinned_ledger_rev | head -1)"
  printf '  midnight-ledger HEAD          %s\n' "$head"
  if [ "$head" = "$ours" ]; then
    echo "                                = our pin"
  elif [ -n "$head" ]; then
    # "newer" is a claim about ANCESTRY, not about dates. Our pin has been
    # on a line that main does not contain — ask, do not assume.
    cmp="$(curl -fsSL "https://api.github.com/repos/midnightntwrk/midnight-ledger/compare/$ours...$head" 2>/dev/null |
      jq -r '"\(.status): main has \(.ahead_by) commits we do not, we have \(.behind_by) main does not (merge base \(.merge_base_commit.sha[0:12]), \(.merge_base_commit.commit.committer.date[0:10]))"')"
    printf '                                %s\n' "${cmp:-comparison unavailable}"
  fi

  rule
  bold "CORPUS SOURCE PINS"
  local name url pin src_head
  for name in $(jq -r '.sources[].name' corpus/sources.json); do
    url="$(jq -r --arg n "$name" '.sources[]|select(.name==$n)|.url' corpus/sources.json)"
    pin="$(jq -r --arg n "$name" '.sources[]|select(.name==$n)|.rev' corpus/sources.json)"
    src_head="$(git ls-remote "$url" HEAD 2>/dev/null | cut -f1)"
    if [ -z "$src_head" ]; then
      printf '  %-30s %.12s  UNREACHABLE\n' "$name" "$pin"
    elif [ "$pin" = "$src_head" ]; then
      printf '  %-30s %.12s  same\n' "$name" "$pin"
    else
      printf '  %-30s %.12s  MOVED -> %.12s\n' "$name" "$pin" "$src_head"
    fi
  done
}

# ------------------------------------------------------------------ `gates`
#
# The ordered gate sequence. Order is DIAGNOSIS order, cheapest and most
# specific first: if the corpus stops round-tripping, nothing later tells you
# anything you did not already know.

STAGE_NAME=()
STAGE_RESULT=()
STAGE_SECS=()
STAGE_MEANING=()

stage() {
  local name="$1" meaning="$2"
  shift 2
  rule
  bold "STAGE $((${#STAGE_NAME[@]} + 1)): $name"
  printf '$ %s\n\n' "$*"
  local start=$SECONDS
  "$@"
  local rc=$? elapsed=$((SECONDS - start))
  STAGE_NAME+=("$name")
  STAGE_SECS+=("$elapsed")
  STAGE_MEANING+=("$meaning")
  if [ "$rc" -eq 0 ]; then STAGE_RESULT+=("PASS"); else STAGE_RESULT+=("FAIL"); fi
  return 0
}

# The corpus's own gate: the pinned compiler must not compile FEWER files
# than the committed report says it did.
check_compile_report() {
  local committed now
  committed="$(git show HEAD:corpus/compile-report.tsv 2>/dev/null | grep -c $'\tok\t')"
  now="$(grep -c $'\tok\t' corpus/compile-report.tsv)"
  printf 'compile-report.tsv: %s OK now, %s OK at HEAD\n' "$now" "$committed"
  if [ "$now" -lt "$committed" ]; then
    printf 'FEWER files compile than before the bump:\n'
    diff <(git show HEAD:corpus/compile-report.tsv) corpus/compile-report.tsv | head -40
    return 1
  fi
}

cmd_gates() {
  local heavy=0
  [ "${1:-}" = "--heavy" ] && heavy=1

  rule
  bold "TOOLCHAIN UNDER TEST"
  printf '  compactc pin  %s\n  ledger rev    %s\n  rustc         %s\n' \
    "$(pinned_compactc)" "$(pinned_ledger_rev | tr '\n' ' ')" "$(rustc --version 2>&1)"

  # Before anything is built: does the pin even RESOLVE? A rev that renames
  # or drops a crate fails here in seconds, and every later stage would only
  # reprint the same cargo error.
  stage "dependency resolution" \
    "the new rev does not provide a crate we name. Upstream renamed or dropped it — find its new name/home before going further (this is how the ledger-v9 rename shows up)." \
    bash -c 'cargo metadata --format-version 1 >/dev/null'
  if [ "${STAGE_RESULT[0]}" = "FAIL" ]; then
    rule
    bold "ABORTED: the pin does not resolve. Nothing downstream can be run."
    printf '  %s\n' "${STAGE_MEANING[0]}"
    return 1
  fi

  # Likewise: a tree that does not BUILD makes every test stage reprint the
  # same rustc errors. Separating "does not build" from "tests disagree" is
  # worth one --no-run pass, which the stages below then reuse.
  stage "workspace builds" \
    "the new crates changed an API we call. Read the FIRST error only: the rest cascade. Our bindings follow theirs — FIX OUR LOWERING, or repin if the change is upstream churn we should not be tracking." \
    cargo test --workspace --no-run
  if [ "${STAGE_RESULT[1]}" = "FAIL" ]; then
    rule
    bold "ABORTED: the workspace does not build. Test results would be noise."
    printf '  %s\n' "${STAGE_MEANING[1]}"
    return 1
  fi

  stage "corpus compile report" \
    "the pinned compiler no longer compiles what it used to — a real toolchain regression, or a corpus source that moved" \
    check_compile_report

  stage "ZKIR round-trip (788 artifacts)" \
    "compactc's own output no longer parses/re-emits under our bindings: the .zkir format, version envelope or instruction set moved. Fix the bindings; do NOT regenerate anything." \
    cargo test -p minocrab-zkir

  stage "ABI + Impact baseline" \
    "contract-info.json's shape, the entry-point hash rule or the Impact op encoding moved. Interface crates and cross-contract calls are downstream of this." \
    cargo test -p minocrab-ledger

  stage "workspace" \
    "see which test: a differential = our lowering disagrees with the new compactc; an artifact-agreement/pin = the corpus recompiled (accept); a spec/vectors/ts drift = the generator's input moved." \
    cargo test --workspace

  stage "row snapshot (release)" \
    "cost changed. A toolchain bump legitimately moves rows; every moved circuit needs a reason before you accept the new table." \
    cargo test --release -p minocrab-contracts --test row_snapshot

  if command -v node >/dev/null 2>&1; then
    stage "TypeScript vectors (node)" \
      "the published spec/ts decoder disagrees with the vectors — only possible if the serialization spec moved." \
      cargo test -p minocrab-contracts --test serialization_conformance -- \
      --ignored the_typescript_vectors_pass
  else
    echo "skipping the TypeScript vectors: no node on PATH (nix develop supplies it)"
  fi

  if [ "$heavy" -eq 1 ]; then
    stage "elevated property run" \
      "a spec/adversarial disagreement that the default case count missed." \
      env PROPTEST_CASES=20000 cargo test --release -p minocrab-contracts \
      --test erc20_vault_spec --test erc20_vault_adversarial
  fi

  rule
  bold "SUMMARY"
  local i failed=0
  for i in "${!STAGE_NAME[@]}"; do
    printf '  %-4s %5ss  %s\n' "${STAGE_RESULT[$i]}" "${STAGE_SECS[$i]}" "${STAGE_NAME[$i]}"
    [ "${STAGE_RESULT[$i]}" = "FAIL" ] && failed=1
  done
  if [ "$failed" -eq 0 ]; then
    echo
    echo "  all gates green."
    [ "$heavy" -eq 1 ] || echo "  not run: ./bump.sh gates --heavy (elevated cases), ./bench.sh (numbers)."
    return 0
  fi
  echo
  bold "  WHAT THE FAILURES MEAN (notes/version-bump.org §Drift taxonomy)"
  for i in "${!STAGE_NAME[@]}"; do
    [ "${STAGE_RESULT[$i]}" = "FAIL" ] || continue
    printf '  %s:\n    %s\n' "${STAGE_NAME[$i]}" "${STAGE_MEANING[$i]}"
  done
  return 1
}

# ----------------------------------------------------------------- `accept`
#
# Every regenerator, in dependency order. This is the "the new baseline is
# correct" path and it is DELIBERATELY one step: after a real bump several
# snapshots move together, and regenerating them one at a time is how a
# session ends up with a half-accepted tree.

cmd_accept() {
  local crate dir source rc=0
  local pinned=()

  bold "1. re-copy each interface crate's contract-info.json from the corpus"
  for dir in crates/*/artifact; do
    [ -f "$dir/pin.json" ] || continue
    crate="$(basename "$(dirname "$dir")")"
    pinned+=(-p "$crate")
    source="$(jq -r '.source' "$dir/pin.json")"
    if [ -f "$source/compiler/contract-info.json" ]; then
      cp "$source/compiler/contract-info.json" "$dir/contract-info.json"
      printf '   %-28s <- %s\n' "$crate" "$source/compiler/contract-info.json"
    else
      printf '   %-28s SOURCE MISSING: %s (recompile the corpus)\n' "$crate" "$source"
      rc=1
    fi
  done

  # ONE cargo invocation for all of them: a per-crate loop resolves a
  # different feature set each time and rebuilds the whole midnight-* graph
  # in between. Measured on the first `accept` run — most of its eight
  # minutes was that.
  bold "2. re-pin the artifacts and their published ABI"
  if [ ${#pinned[@]} -gt 0 ]; then
    cargo test "${pinned[@]}" -- --ignored regenerate_pin_and_schema || rc=1
  fi

  bold "3. regenerate the generated interface crates from their artifacts"
  for dir in crates/*/artifact; do
    [ -f "$dir/generator.json" ] || continue
    crate="$(dirname "$dir")"
    cargo run -q -p minocrab-interface-gen -- --crate "$crate" || rc=1
    printf '   %s\n' "$crate/src/lib.rs"
  done

  bold "4. regenerate spec/borsh-subset.md, spec/vectors/*.json and spec/ts/"
  cargo test -q -p minocrab-contracts --test serialization_conformance -- \
    --ignored --nocapture regenerate_spec || rc=1

  bold "5. regenerate the row and interface snapshots (release: it prices 87 circuits)"
  cargo test --release -q -p minocrab-contracts \
    --test row_snapshot --test interface_snapshot -- \
    --ignored --nocapture regenerate_row_snapshot regenerate_interface_snapshot || rc=1

  rule
  bold "WHAT MOVED"
  git status --short
  echo
  echo "  EVERY line of this diff needs a reason written down before it is"
  echo "  committed. A regenerator makes drift easy to accept; that is what"
  echo "  makes it dangerous. notes/version-bump.org §Accepting a new baseline."
  echo
  echo "  Then: ./bump.sh gates"
  return "$rc"
}

# ------------------------------------------------------------------ dispatch

case "${1:-}" in
  pins) shift; cmd_pins "$@" ;;
  gates) shift; cmd_gates "$@" ;;
  accept) shift; cmd_accept "$@" ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    echo
    echo "The order is: pins -> edit the pin -> corpus/compile.sh -> gates ->"
    echo "(if the movement is legitimate) accept -> gates."
    exit 2
    ;;
esac
