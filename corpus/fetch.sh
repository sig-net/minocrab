#!/usr/bin/env bash
# Fetch pinned .compact sources into corpus/src/ (and corpus/negative/ for
# deliberate-error cases). Reads corpus/sources.json; optional $1 filters by
# source name. Revs must be pinned first — run ./update.sh to (re)pin.
set -euo pipefail
cd "$(dirname "$0")"

FILTER="${1:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

jq -c '.sources[]' sources.json | while read -r src; do
  name=$(jq -r '.name' <<<"$src")
  [[ -n "$FILTER" && "$name" != "$FILTER" ]] && continue
  url=$(jq -r '.url' <<<"$src")
  rev=$(jq -r '.rev' <<<"$src")
  if [[ "$rev" == "null" ]]; then
    echo "ERROR: $name has no pinned rev; run ./update.sh $name first" >&2
    exit 1
  fi

  echo ">> $name @ ${rev:0:12}"
  clone="$TMP/$name"
  git init -q "$clone"
  git -C "$clone" remote add origin "$url"
  git -C "$clone" fetch -q --depth 1 origin "$rev"
  git -C "$clone" checkout -q FETCH_HEAD

  rm -rf "src/$name" "negative/$name"
  mapfile -t paths < <(jq -r '.paths[]' <<<"$src")
  [[ ${#paths[@]} -eq 0 ]] && paths=(".")
  mapfile -t neg < <(jq -r '.negative_paths[]?' <<<"$src")

  for p in "${paths[@]}"; do
    while IFS= read -r f; do
      rel="${f#"$clone"/}"
      dest="src/$name/$rel"
      for n in "${neg[@]:-}"; do
        [[ -n "$n" && "$rel" == "$n"/* ]] && dest="negative/$name/$rel"
      done
      mkdir -p "$(dirname "$dest")"
      cp "$f" "$dest"
    done < <(find "$clone/$p" -name '*.compact' -type f 2>/dev/null)
  done
  count=$( (find "src/$name" -name '*.compact' 2>/dev/null || true) | wc -l | tr -d ' ')
  negcount=$( (find "negative/$name" -name '*.compact' 2>/dev/null || true) | wc -l | tr -d ' ')
  echo "   $count files (+$negcount negative)"
done
