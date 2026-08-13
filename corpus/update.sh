#!/usr/bin/env bash
# Bump pinned revs to each source's current default-branch HEAD, then refetch
# and recompile. Optional $1 limits to one source. Review the resulting diff
# of sources.json + corpus/src before committing.
set -euo pipefail
cd "$(dirname "$0")"

FILTER="${1:-}"

names=$(jq -r '.sources[].name' sources.json)
for name in $names; do
  [[ -n "$FILTER" && "$name" != "$FILTER" ]] && continue
  url=$(jq -r --arg n "$name" '.sources[] | select(.name == $n) | .url' sources.json)
  rev=$(git ls-remote "$url" HEAD | cut -f1)
  if [[ -z "$rev" ]]; then
    echo "ERROR: could not resolve HEAD of $url" >&2
    exit 1
  fi
  echo ">> $name -> ${rev:0:12}"
  jq --arg n "$name" --arg r "$rev" \
    '(.sources[] | select(.name == $n) | .rev) = $r' sources.json > sources.json.tmp
  mv sources.json.tmp sources.json
done

./fetch.sh "$FILTER"
./compile.sh "$FILTER"
