#!/usr/bin/env bash
# Compile every .compact under corpus/src/ with the pinned compactc
# (nix build .#compactc at the repo root provides ../result/bin/compactc).
# Keeps zkir/ + compiler/ outputs under corpus/zkir/, skips proving keys,
# discards the JS runtime output. Never stops on failure; results land in
# corpus/compile-report.tsv. Optional $1 limits to one source name.
set -uo pipefail
cd "$(dirname "$0")"

COMPACTC="${COMPACTC:-../result/bin/compactc}"
if [[ ! -x "$COMPACTC" ]]; then
  echo "ERROR: compactc not found at $COMPACTC (run: nix build .#compactc)" >&2
  exit 1
fi

FILTER="${1:-}"
REPORT="compile-report.tsv"
root="src${FILTER:+/$FILTER}"

# Cross-package imports (e.g. `import "@scope/pkg/..."`) resolve through
# COMPACT_PATH; sources.json's compact_path_links maps package names to
# corpus/src paths.
rm -rf .compact-path
mkdir -p .compact-path
jq -r '.compact_path_links // {} | to_entries[] | "\(.key)\t\(.value)"' sources.json |
while IFS=$'\t' read -r pkg target; do
  mkdir -p ".compact-path/$(dirname "$pkg")"
  ln -sfn "$(pwd)/src/$target" ".compact-path/$pkg"
done
export COMPACT_PATH="$(pwd)/.compact-path"

# keep other sources' lines when filtering
if [[ -n "$FILTER" && -f "$REPORT" ]]; then
  grep -v "^src/$FILTER/" "$REPORT" > "$REPORT.tmp" || true
  mv "$REPORT.tmp" "$REPORT"
else
  : > "$REPORT"
fi

# Per-source extra compiler flags (e.g. --feature-zkir-v3), from sources.json.
declare -A SRC_FLAGS
while IFS=$'\t' read -r n fl; do
  SRC_FLAGS[$n]="$fl"
done < <(jq -r '.sources[] | select(.flags) | "\(.name)\t\(.flags | join(" "))"' sources.json)

total=0 ok=0
while IFS= read -r f; do
  total=$((total + 1))
  rel="${f%.compact}"
  out="zkir/${rel#src/}"
  srcname="${rel#src/}"; srcname="${srcname%%/*}"
  flags="${SRC_FLAGS[$srcname]:-}"
  rm -rf "$out"
  mkdir -p "$out"
  # shellcheck disable=SC2086 — flags are intentionally word-split
  if err=$("$COMPACTC" --skip-zk $flags "$f" "$out" 2>&1); then
    ok=$((ok + 1))
    rm -rf "$out/contract" "$out/keys"
    printf '%s\tok\t\n' "$f" >> "$REPORT"
  else
    firstline=$(head -1 <<<"$err" | tr '\t' ' ')
    printf '%s\tfail\t%s\n' "$f" "$firstline" >> "$REPORT"
    rm -rf "$out"
  fi
done < <(find "$root" -name '*.compact' -type f 2>/dev/null | sort)

sort -o "$REPORT" "$REPORT"
echo "compiled $ok/$total OK (report: corpus/$REPORT)"
