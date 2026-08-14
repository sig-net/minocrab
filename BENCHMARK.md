# MinoCrab vs compactc: proving-cost benchmark

MinoCrab is a Rust eDSL for Midnight that compiles to ZKIR, replacing the
Compact language. This report benchmarks the real sig-net cross-chain
contracts — all 9 circuits of `erc20-vault` (sig-net/midnight-examples)
plus the 3 circuits of its Signet singleton dependency
(sig-net/midnight-integration) — written in MinoCrab against the same
contracts compiled by `compactc`, at the same pinned toolchain versions.

**Headline: MinoCrab needs 18–38% fewer rows on every erc20-vault
runtime circuit and 97.5% fewer on the Signet singleton's, which drops
eight of the twelve circuits at least one circuit-size level (k):
those prove 1.6–2× (vault) to 24–39× (singleton) faster in half to
1/20th the RAM, with identical proof sizes and identical statements
proved.** The one circuit with no byte plumbing (`initialize`) is at
exact row parity, by construction.

## Why the numbers are comparable

- **Same statement, not just the same source.** For every circuit, the
  differential test harness first proves that MinoCrab's artifact and
  compactc's artifact agree — same typed input/output schema and equal
  public-input streams (`pis`/`pi_skips`) — on a shared `ProofPreimage`,
  including guard-rejection and tamper agreement. Each benchmark cell
  then proves that *same* preimage under both artifacts. The numbers
  compare two circuits proving the identical statement.
- **Same backend.** Keygen/prove/verify go through Midnight's own `Zkir`
  implementation (`midnight-zkir-v3` at the rev compactc's bundled
  binary is built from, pinned by the flake); the same hash-verified SRS
  parameters serve both sides.
- **Deterministic metrics first.** Halo2 rows and the resulting circuit
  size `k` (rows fit in 2^k; RAM and prove time roughly double per k)
  are deterministic. Wall-clock prove time is the median of 3 in-process
  iterations, measured in one subprocess per cell (peak RSS =
  `getrusage` of that process), all cells in a single session on a quiet
  Apple Silicon machine.

## Results

All 24 cells from one session (2026-08-15, Apple Silicon, quiet
machine), MinoCrab (`mc`) vs compactc (`cc`), prove = median of 3:

| circuit | k mc/cc | rows mc | rows cc | rows Δ | prove mc | prove cc | prove Δ | RSS mc | RSS cc |
|---|---|---|---|---|---|---|---|---|---|
| initialize | 13 / 13 | 4,272 | 4,272 | ±0% | 0.90s | 0.89s | +0.9% | 176MB | 179MB |
| deposit | 15 / 15 | 17,502 | 27,002 | −35.2% | 4.79s | 4.96s | −3.4% | 781MB | 783MB |
| claim | **16 / 17** | 47,660 | 64,549 | −26.2% | 9.45s | 19.13s | **−50.6%** | 1.8GB | 3.2GB |
| approveRouter | **14 / 15** | 13,344 | 20,619 | −35.3% | 3.06s | 4.86s | **−37.0%** | 315MB | 654MB |
| withdraw | 16 / 16 | 42,373 | 52,009 | −18.5% | 9.25s | 9.39s | −1.4% | 1.6GB | 1.6GB |
| completeWithdraw | **16 / 17** | 47,466 | 64,498 | −26.4% | 10.47s | 21.16s | **−50.5%** | 1.8GB | 3.4GB |
| refund | **16 / 17** | 65,231 | 97,026 | −32.8% | 12.69s | 23.85s | **−46.8%** | 1.9GB | 3.5GB |
| swap | **16 / 17** | 51,485 | 71,104 | −27.6% | 11.51s | 21.03s | **−45.3%** | 1.6GB | 3.0GB |
| completeSwap | **16 / 17** | 65,071 | 104,615 | −37.8% | 13.05s | 25.14s | **−48.1%** | 1.9GB | 3.5GB |
| signBidirectional | **11 / 16** | 1,205 | 50,429 | −97.6% | 0.22s | 5.21s | **−95.7%** | 49MB | 888MB |
| respond | **10 / 16** | 1,004 | 40,931 | −97.5% | 0.13s | 5.12s | **−97.4%** | 41MB | 879MB |
| respondBidirectional | **10 / 16** | 1,004 | 40,931 | −97.5% | 0.13s | 5.15s | **−97.4%** | 41MB | 888MB |

Keygen times scale the same way as prove times (e.g. completeSwap
6.97s vs 14.37s; respond 0.10s vs 4.86s). Raw data:
`target/bench/results.json`; the table is `target/bench/report.md`
verbatim, reformatted.

Note the two same-k rows: `deposit` (−35% rows) and `withdraw` (−19%
rows) prove in essentially compactc's time, because Halo2 proving cost
is dominated by the padded circuit size 2^k, not the occupied rows.
Row cuts pay off when they cross a power-of-two boundary — which they
did on eight of the twelve circuits, and the singleton crossed five to
six levels.

## Where the wins come from

The gains decompose cleanly into two effects, both verified by
per-region cost profiles (`target/bench/profiles/`):

1. **Instruction selection.** compactc lowers its standard library's
   byte manipulation (byte-order reversals for signature scalars, ABI
   calldata words, event-payload serialization) to per-byte
   `div_mod_power_of_two` / `reconstitute_field` chains. A measured
   `div_mod` costs ~90–147 rows with a large fixed floor
   (`crates/minocrab-sim/examples/opcost.rs`), so exploding a 31-byte
   limb costs ~4,400 rows — while ZKIR's native `ReverseBytes`
   instruction does a full byte reversal in ~150 rows, and byte-aligned
   slices/shifts are a single `div_mod` plus constant-weight
   multiply-adds. MinoCrab emits the native forms: the attestation
   verify's three scalar imports, all four ABI-word helpers, the Signet
   notification payload (which collapses to one field addition — its
   31-byte limbs align with the caller-address limbs), and a
   segment-based serializer that splits limbs only at output-limb
   boundaries. compactc's own circuits pay the chains everywhere.
2. **k-boundary crossings.** Rows only cost RAM/time through k, so row
   cuts pay off in steps. The cuts above push `refund`, `swap` and
   `completeSwap` from k=17 to k=16, `approveRouter` from 15 to 14, and
   the three singleton circuits from 15/16 down to 10–11 — each crossed
   boundary roughly halving prove time and peak RSS. `claim` and
   `completeWithdraw` were already a boundary below compactc at baseline
   (near-equal rows landing just under 2^16 for MinoCrab, just over for
   compactc).

Everything still in the MinoCrab circuits is either coupled to the
public-input contract (ledger-operation streams, map-lookup embeds,
argument range constraints — unchangeable while proving the same
statement) or real cryptography (Keccak request ids and attestation
digests, Poseidon commitments, in-circuit secp256k1 ECDSA).

## Honest notes

- `initialize` has no byte plumbing, so it shows what the comparison
  looks like with instruction selection taken off the table: identical
  rows, identical k, wall-clock differences within measurement noise.
  Sub-second cells generally have noise-dominated wall-clock deltas;
  rows/k/RSS are exact.
- The MinoCrab rewrites are value-preserving: every optimisation landed
  with the full differential suite green (PI-equality on shared
  preimages, guard-rejection agreement, tamper sweeps) — the same
  harness that establishes comparability also gates every change.
- Proof sizes are identical per circuit (same proof system and public
  input counts); verify times are milliseconds for both sides.

## Reproducing

From a clean checkout (nix + direnv provide the pinned toolchain):

```
nix run .#bench        # or: nix develop -c ./bench.sh
```

This re-runs the differential tests (dumping corpus-verified preimages),
proves all 24 cells, and writes `target/bench/results.json`,
`report.md`, and the per-region cost profiles under
`target/bench/profiles/`. Deleting `target/bench/results.jsonl` forces a
fresh run; leaving it resumes an interrupted one.
