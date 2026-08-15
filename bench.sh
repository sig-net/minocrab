#!/usr/bin/env bash
# M6 baseline benchmark, reproducible from a clean checkout:
#   nix develop -c ./bench.sh     (or just ./bench.sh inside the direnv shell)
#
# 1. Runs the differential tests for the benchmark contracts with preimage
#    dumping on: every preimage is corpus-verified (PI-equal under both
#    toolchains' artifacts) before it is benchmarked. The M10 fork gate
#    dumps the optimized side's own preimages (preimages/opt/) alongside —
#    that side proves its own statement and cannot share the others'.
# 2. Proves every circuit under each artifact (one subprocess per
#    measurement for clean peak-RSS numbers) and writes
#    target/bench/{results.json,report.md,profiles/}.
#
# SRS parameters are fetched (hash-verified) into ~/.cache/midnight/zk-params
# on first use.
set -euo pipefail
cd "$(dirname "$0")"

export MINOCRAB_DUMP_PREIMAGES="$PWD/target/bench/preimages"
mkdir -p "$MINOCRAB_DUMP_PREIMAGES"

cargo test --release -p minocrab-contracts \
  --test erc20_vault_differential --test signet_contract_differential \
  --test erc20_vault_opt_fork \
  -- --quiet

cargo run --release -p minocrab-bench
