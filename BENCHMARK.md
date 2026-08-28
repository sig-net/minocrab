# erc20-vault proving cost: compactc vs MinoCrab port vs optimized vs borsh

MinoCrab is a Rust eDSL for Midnight that compiles to ZKIR, replacing the
Compact language. This report benchmarks the real sig-net cross-chain
contracts — all 9 circuits of `erc20-vault` (sig-net/midnight-examples)
plus the 3 circuits of its Signet singleton dependency
(sig-net/midnight-integration) — at the same pinned toolchain versions,
across four artifacts:

- **compactc** — the Compact contracts compiled by `compactc`.
- **port (minocrab)** — MinoCrab's direct port. Statement-identical to
  compactc: same typed schema, same shared `ProofPreimage`, equal
  public-input streams (`pis`/`pi_skips`). This is the M6/M7 result — a
  correctness-preserving lowering that is parity-or-better on every
  circuit while proving the *identical* statement.
- **opt** — the M10 optimized vault. A **different artifact**: it proves
  its **own** preimage per circuit, for the same logical operation but
  **not** the same statement. It re-chooses the vault's discretionary
  hash constructions, merges a duplicated branch, and reframes one burn.
  Its comparability to the first two rests on symbolic-effect equality of
  the two contracts — a **weaker** warrant than the PI-equality the port
  and compactc share (see [Four sides, three comparability claims](#four-sides-three-comparability-claims)).
- **borsh** — the optimized vault on the M11 wire format: canonical
  fixed-width Borsh records and attested outputs, and the stage-7 record
  change that replaces 68–75 bytes of in-band schema strings with a
  1-byte response kind (plus a format-version byte, both now bound
  in-circuit by the settle hardening). Same statement caveat as opt; its
  own extra warrant is the serialization-conformance suites, which pin
  every encoder byte-equal to two independent Borsh oracles and to the
  deployed payloads.

## Headline

Against compactc, the borsh artifact cuts rows by 35–58% on every
runtime circuit and 43.5% on `initialize`. But **rows are not prove time
— `k` is.** Halo2 proving cost tracks the padded circuit size 2^k, not
the occupied rows, so a row cut pays off in wall-clock and RAM only when
it crosses a power-of-two boundary. The vault is **hash-bound**: 95–99%
of every circuit's rows are SHA-256, keccak-256 and secp256k1 ECDSA, and
most of that crypto is protocol-pinned and immovable. So the row cuts
are large everywhere, but the **new** prove-time wins over the
already-fast port are exactly three circuits: `deposit` (M10, crosses
k15→14, prove −34%), `withdraw` (M10, crosses k16→15, prove −40%), and —
new in this refresh — **`swap`** (M11, crosses k16→15 on the borsh
artifact: prove −41% and RAM −46% against opt, −67% and −73% against
compactc). M10 had left `swap` 51 rows over the k15 boundary and
deliberately stopped; the stage-7 record change, adopted for wire-format
reasons, paid the 51 rows as a side effect. The other six circuits cut
rows but stay k-floored — their big deltas versus compactc are inherited
from the port's M6/M7 instruction-selection wins, already banked. This
report shows all of it: the full four-way numbers, and an honest split of
which side earned which win.

## Four sides, three comparability claims

- **compactc ↔ port: same statement.** For every circuit the
  differential harness proves that the port's artifact and compactc's
  agree — same typed input/output schema, equal public-input streams
  (`pis`/`pi_skips`) on a shared `ProofPreimage`, including
  guard-rejection and tamper agreement. Each benchmark cell then proves
  that *same* preimage under both artifacts. The numbers compare two
  circuits proving the identical statement.
- **port ↔ opt: same operation, re-framed.** The optimized artifact
  **cannot** share that preimage — it deliberately proves a different
  statement (a shorter user-commitment hash, a non-hashed token
  separator, Poseidon refund commitments, a single-spend burn, a merged
  refund branch). Its warrant is a shared *symbolic effect algebra*: both
  the port's and the opt's reference models emit the same `Vec<Effect>`
  over a term algebra, and the two op streams, run through the pinned
  ledger's `run_program`, produce equal post-state, `Effects` (mints,
  spends, receives, nullifiers, contract calls) and events — swept by the
  spec harness at 1,000,000 cases per circuit (9,000,000 total in the
  gating run).
- **opt ↔ borsh: the same artifact on a new wire format.** Every borsh
  circuit is either byte-identical ZKIR to its optimized twin or a
  divergence declared in a ledger the fork gate checks in both
  directions. The divergences are the M11 stages themselves — Borsh
  output types, the kind-tagged record, the settle hardening — each
  landed against the same reference model (told `Art::Borsh`) and the
  spec harness, with the byte formats additionally pinned by the
  conformance suites against `borsh`/`bincode` as dual oracles and
  against the deployed payload bytes. The `modern` showcase twin is
  byte-identical to borsh on all nine circuits and is not separately
  benched.

## Results

All 42 cells from one session (2026-08-27, Apple Silicon, quiet
machine), prove = median of 3. Raw data: `target/bench/results.json`.

| circuit | side | k | rows | keygen (s) | prove (s) | verify (s) | proof (B) | peak RSS (MB) |
|---|---|---|---|---|---|---|---|---|
| initialize | compactc | 13 | 4,272 | 0.57 | 0.74 | 0.005 | 6,336 | 202 |
| initialize | port | 13 | 4,272 | 0.58 | 0.75 | 0.005 | 6,336 | 209 |
| initialize | opt | 13 | 2,412 | 0.51 | 0.72 | 0.004 | 6,336 | 186 |
| initialize | borsh | 13 | 2,412 | 0.51 | 0.72 | 0.005 | 6,336 | 205 |
| deposit | compactc | 15 | 27,002 | 3.36 | 4.35 | 0.007 | 9,504 | 920 |
| deposit | port | 15 | 17,502 | 2.71 | 4.25 | 0.007 | 9,504 | 793 |
| deposit | opt | **14** | 15,632 | 2.05 | 2.82 | 0.007 | 9,504 | 383 |
| deposit | borsh | **14** | 15,614 | 2.06 | 2.82 | 0.007 | 9,504 | 388 |
| claim | compactc | 17 | 64,549 | 12.24 | 18.57 | 0.008 | 10,304 | 2,878 |
| claim | port | 16 | 47,660 | 6.01 | 8.11 | 0.007 | 10,304 | 1,876 |
| claim | opt | 16 | 42,051 | 5.90 | 9.03 | 0.008 | 10,304 | 1,879 |
| claim | borsh | 16 | 42,059 | 5.55 | 8.93 | 0.007 | 10,304 | 1,888 |
| approveRouter | compactc | 15 | 20,619 | 3.20 | 4.42 | 0.006 | 8,128 | 691 |
| approveRouter | port | 14 | 13,344 | 2.02 | 2.86 | 0.006 | 8,128 | 353 |
| approveRouter | opt | 14 | 13,332 | 2.05 | 2.84 | 0.006 | 8,128 | 368 |
| approveRouter | borsh | 14 | 13,314 | 2.03 | 2.88 | 0.006 | 8,128 | 344 |
| withdraw | compactc | 16 | 52,009 | 5.96 | 8.38 | 0.007 | 9,504 | 1,608 |
| withdraw | port | 16 | 42,373 | 4.97 | 8.09 | 0.007 | 9,504 | 1,646 |
| withdraw | opt | **15** | 23,707 | 3.00 | 4.80 | 0.007 | 9,504 | 823 |
| withdraw | borsh | **15** | 23,689 | 3.06 | 4.83 | 0.007 | 9,504 | 822 |
| completeWithdraw | compactc | 17 | 64,498 | 10.89 | 18.15 | 0.007 | 10,304 | 3,211 |
| completeWithdraw | port | 16 | 47,466 | 5.93 | 8.91 | 0.008 | 10,304 | 1,877 |
| completeWithdraw | opt | 16 | 40,157 | 5.46 | 8.92 | 0.007 | 10,304 | 1,864 |
| completeWithdraw | borsh | 16 | 40,165 | 5.36 | 8.89 | 0.007 | 10,304 | 1,876 |
| refund | compactc | 17 | 97,026 | 12.89 | 18.48 | 0.008 | 10,304 | 3,332 |
| refund | port | 16 | 65,231 | 5.91 | 9.49 | 0.008 | 10,304 | 1,870 |
| refund | opt | 16 | 40,806 | 5.42 | 8.92 | 0.008 | 10,304 | 1,714 |
| refund | borsh | 16 | 40,798 | 5.59 | 8.89 | 0.008 | 10,304 | 1,639 |
| swap | compactc | 17 | 71,104 | 10.92 | 16.00 | 0.008 | 9,504 | 2,899 |
| swap | port | 16 | 51,485 | 6.06 | 8.99 | 0.007 | 9,504 | 1,454 |
| swap | opt | 16 | 32,819 | 5.56 | 8.85 | 0.007 | 9,504 | 1,458 |
| swap | **borsh** | **15** | 28,625 | 3.60 | **5.27** | 0.007 | 9,504 | **788** |
| completeSwap | compactc | 17 | 104,615 | 13.15 | 17.87 | 0.007 | 10,304 | 3,241 |
| completeSwap | port | 16 | 65,071 | 6.40 | 9.21 | 0.007 | 10,304 | 1,736 |
| completeSwap | opt | 16 | 50,254 | 5.62 | 8.92 | 0.008 | 10,304 | 1,714 |
| completeSwap | borsh | 16 | 50,265 | 5.52 | 9.09 | 0.008 | 10,304 | 1,633 |
| signBidirectional | compactc | 16 | 50,429 | 5.26 | 3.60 | 0.004 | 3,824 | 881 |
| signBidirectional | port | 11 | 1,205 | 0.14 | 0.19 | 0.004 | 3,824 | 56 |
| respond | compactc | 16 | 40,931 | 4.66 | 3.45 | 0.003 | 3,824 | 855 |
| respond | port | 10 | 1,004 | 0.08 | 0.12 | 0.003 | 3,824 | 46 |
| respondBidirectional | compactc | 16 | 40,931 | 4.59 | 3.58 | 0.004 | 3,824 | 879 |
| respondBidirectional | port | 10 | 1,004 | 0.08 | 0.12 | 0.004 | 3,824 | 43 |

The three Signet singleton circuits have no opt/borsh variant: the
singleton is deployed compactc output — not ours to optimize — so it
stays in the port-vs-compactc layer (see
[Baseline layer](#baseline-layer-port-vs-compactc)).

## borsh vs compactc — the headline table

The end-state artifact against the compactc baseline. This is the
largest spread, and it carries the [weaker comparability
claim](#four-sides-three-comparability-claims): borsh proves its own
preimage per circuit — the same logical operation, not the same
statement.

| circuit | k borsh / cc | rows Δ | prove Δ | RSS Δ |
|---|---|---|---|---|
| initialize | 13 / 13 | −43.5% | −3.0% | +1.3% |
| deposit | **14 / 15** | −42.2% | **−35.2%** | **−57.8%** |
| claim | **16 / 17** | −34.8% | −51.9% | −34.4% |
| approveRouter | **14 / 15** | −35.4% | −34.8% | −50.2% |
| withdraw | **15 / 16** | −54.5% | **−42.4%** | **−48.9%** |
| completeWithdraw | **16 / 17** | −37.7% | −51.0% | −41.6% |
| refund | **16 / 17** | −58.0% | −51.9% | −50.8% |
| swap | **15 / 17** | −59.7% | **−67.1%** | **−72.8%** |
| completeSwap | **16 / 17** | −52.0% | −49.1% | −49.6% |

## borsh vs opt — what the record change itself bought

Eight circuits are within noise of their optimized twins (the wire-format
divergences are a handful of rows either way: the settle circuits carry
+6..+9 rows of hardening binds, the request circuits −18 rows of
kind-for-schemas serialization). The exception is the point of this
refresh:

| circuit | k borsh / opt | rows Δ | keygen Δ | prove Δ | RSS Δ |
|---|---|---|---|---|---|
| swap | **15 / 16** | −12.8% | −35.3% | **−40.5%** | **−46.0%** |

M10 measured `swap` at 32,819 rows — 51 over the 32,768 k15 boundary —
and stopped rather than force it (the one remaining lever had a
disproportionate blast radius). The M11 stage-7 record change replaced
the swap record's 75 bytes of in-band schema strings with a 1-byte
response kind, shrinking the request-side keccak by enough to land at
28,625 rows: the crossing arrived as a side effect of a wire-format
decision made for the MPC's benefit.

## opt vs the port — isolating the M10 wins

Comparing opt to the **port** isolates the optimization ladder's own
contribution from the port's already-banked M6/M7 wins:

| circuit | k opt / port | rows Δ | prove Δ | new k crossing? |
|---|---|---|---|---|
| initialize | 13 / 13 | −43.5% | −4.0% | no (SHA-floored at k13) |
| deposit | 14 / 15 | −10.7% | **−33.6%** | **yes, k15→14** |
| claim | 16 / 16 | −11.8% | +11.3%¹ | no (ECDSA-floored) |
| approveRouter | 14 / 14 | −0.1% | −0.7% | no (already k14) |
| withdraw | 15 / 16 | −44.1% | **−40.7%** | **yes, k16→15** |
| completeWithdraw | 16 / 16 | −15.4% | +0.1% | no (ECDSA-floored) |
| refund | 16 / 16 | −37.4% | −6.0% | no (ECDSA-floored) |
| swap | 16 / 16 | −36.3% | −1.6% | no — crossed later by M11 (borsh) |
| completeSwap | 16 / 16 | −22.8% | −3.1% | no (ECDSA-floored) |

¹ Same-`k` prove deltas are noise (see the honest notes); claim's +11%
is the same 2^16-padded circuit measured twice.

## Where the wins come from

The vault is hash-bound: reconstructing per-circuit budgets from measured
primitive costs (`cargo run -p minocrab-sim --example cryptocost`;
calibrated SHA-256 pair hash at 3,739 rows, keccak attestation block at
4,207, secp256k1 ECDSA verify at 24,450, Poseidon permutation at 22)
shows 95–99% of every circuit's rows are SHA/keccak/ECDSA, confirmed by
the region profiler attributing by estimated rows (e.g. claim's ECDSA
region is 52.6% of rows against a 53% prediction). So transcript framing,
`constrain_bits` dedup and serialization — worth a few hundred rows
each — cross **no** `k` boundary and were largely not the lever. The row
cuts come from the vault's **own discretionary hash constructions and
structure**, avenue by avenue:

| # | avenue | change | rows | circuits |
|---|---|---|---|---|
| 1 | userCommitment short-SHA | 64-byte (2-block) → 43-byte (1-block) SHA-256, same domain tag; stays SHA (it is the MPC key-derivation path) | −1,860/use | initialize, deposit, claim |
| 2 | token domain separator | `SHA-256([pad("erc20:vault:"), erc20])` → injective non-hashed encoding `0x01 ‖ zeros ‖ erc20` (ledger derives the colour itself and accepts an arbitrary pre-token) | −3,749/use, 8 uses | withdraw, swap, claim, completeWithdraw, refund×2, completeSwap×2 |
| 3 | refund commitment → Poseidon | `withdrawRefundCommitment`/`swapRefundCommitment` SHA-256(96 B) → `transientHash` (internal, one-round-trip, never leaves the contract) | −3,560/use | withdraw, swap, completeWithdraw, refund, completeSwap |
| 4 | refund branch merge | `refund` computed the same mint (domainSep→tokenType→coinCommitment→mint) and commitment hash in both branches; guards gate PI emission, not rows, so both cost full — merged to one shared block, ledger ops still guarded per route | −13,355 | refund |
| 5 | changeNonce derived | completeSwap's `persistentHash([mintNonce, pad("change")])` → the bijection `[255 − hi, lo]` (uniqueness only; a total, disclosed derivation) | −3,747 | completeSwap |
| 6 | burn single-spend | withdraw/swap burn reframed from receive+nullifier+spend to one claimed shielded spend of the burn-address output (subset-checked vs the offer, no contract-address requirement; gate proven against the pinned ledger) | −11,309/use | withdraw, swap |
| 7 | kernel.self dedup | read the contract's own address once and thread it, instead of compactc's per-call-site reads | −12/read, 12 reads | deposit, approveRouter, withdraw, swap, refund, completeSwap |
| 8 | kind-tagged record (M11) | the record's two in-band ABI schema strings (68–75 B, keccak'd into every request id) → a 1-byte response kind + a 1-byte format version, both in-circuit-bound at settle | request-side keccak shrink; **swap k16→15** | deposit, withdraw, swap, approveRouter (requests); all four settles bind it |

None of this touches the protocol-pinned crypto, which is immovable: the
keccak request id and record layout (the MPC decodes the record from raw
ledger state), the keccak attestation digest (what the MPC signed), the
in-circuit secp256k1 ECDSA (the only authentication gate; the MPC is
secp256k1-native), the coin commitments/nullifiers (multiset-checked
against the offer), and `tokenType`'s own SHA derivation in the ledger.
That crypto is why the settle circuits are floored above 2^15 and their
row cuts stay cosmetic for prove time.

## Honest notes and limits

- **`initialize` is cosmetic.** −43.5% rows but SHA-floored at k13 (a
  single SHA block already sits at k13, measured), so prove and RSS are
  flat — what the comparison looks like with `k` off the table.
- **The four settle circuits are ECDSA-floored above 2^15.** `claim`,
  `completeWithdraw`, `refund`, `completeSwap` cut 34–58% of rows but
  cannot cross k16 while the secp256k1 verify (~24,450 rows) is pinned.
  Their row column is real; their prove-time column is mostly inherited
  from the port.
- **The own-statement caveat is not a footnote.** opt and borsh prove a
  different statement from the port and compactc. The chain of trust that
  replaces PI-equality — symbolic-effect equality, `run_program`
  post-state/effect agreement, the 9,000,000-case spec sweep, the
  pinned-ledger burn gate, and for borsh the byte-format conformance
  suites — is machinery, not prose, but it is a **weaker** warrant than
  "identical PI stream on a shared preimage." Treat those numbers as
  "same operation, re-framed, proved cheaper," never as "same statement,
  proved cheaper."
- **The settle hardening is included.** The borsh settle circuits carry
  the stage-7 hardening binds (record.kind == output.kind plus the
  format-version byte, +6..+9 rows) — the numbers above price the
  hardened circuits, not a checks-removed variant.
- **The singleton has no opt/borsh variant.** Its 97.5% row cut is the
  port's M7 result against a deployed compactc artifact, and it stays in
  the baseline layer below.
- Proof sizes are identical per circuit across all four sides (same
  proof system and public-input counts); verify times are milliseconds
  everywhere. Sub-second cells and same-`k` prove deltas are
  noise-dominated; rows/k/RSS are exact. This session's absolute times
  differ from the 2026-08-15 run's by a few percent either way (machine
  state); every `k` and row count is identical where the artifacts are.

## Baseline layer: port vs compactc

The M6/M7 story, unchanged and still the floor the opt and borsh sides
build on: the direct port proves the **identical statement** as compactc
(shared `ProofPreimage`, PI-equal) and is parity-or-better everywhere,
because it emits ZKIR's native byte instructions (`ReverseBytes`,
byte-aligned `div_mod` slices, a segment-based serializer) where compactc
lowers its standard library's byte manipulation to per-byte `div_mod` /
`reconstitute_field` chains.

| circuit | k port/cc | rows Δ | prove Δ | RSS Δ |
|---|---|---|---|---|
| initialize | 13 / 13 | ±0% | +1.0% | +3.7% |
| deposit | 15 / 15 | −35.2% | −2.5% | −13.7% |
| claim | **16 / 17** | −26.2% | **−56.3%** | −34.8% |
| approveRouter | **14 / 15** | −35.3% | **−35.2%** | −48.9% |
| withdraw | 16 / 16 | −18.5% | −3.5% | +2.4% |
| completeWithdraw | **16 / 17** | −26.4% | **−50.9%** | −41.6% |
| refund | **16 / 17** | −32.8% | **−48.7%** | −43.9% |
| swap | **16 / 17** | −27.6% | **−43.8%** | −49.9% |
| completeSwap | **16 / 17** | −37.8% | **−48.5%** | −46.4% |
| signBidirectional | **11 / 16** | −97.6% | **−94.8%** | −93.6% |
| respond | **10 / 16** | −97.5% | **−96.5%** | −94.7% |
| respondBidirectional | **10 / 16** | −97.5% | **−96.7%** | −95.1% |

The same-`k` rows here (`deposit`, `withdraw`) already showed, before any
M10 work, that a row cut without a boundary crossing leaves prove time
essentially flat — which is exactly the effect the opt side turned into
crossings for those two circuits, and the M11 record change then repeated
for `swap`.

## Reproducing

From a clean checkout (nix + direnv provide the pinned toolchain):

```
nix run .#bench        # or: nix develop -c ./bench.sh
```

This re-runs the differential tests (dumping corpus-verified preimages
for all four sides — opt's under `preimages/opt/`, borsh's under
`preimages/borsh/`), proves all 42 cells, and writes
`target/bench/results.json`, `report.md`, and the per-region cost
profiles under `target/bench/profiles/`. The opt and borsh sides prove
their own dumped preimages, checked by their fork gates
(`tests/erc20_vault_opt_fork.rs`, `tests/erc20_vault_borsh_fork.rs` —
each circuit either byte-identical to its parent artifact or a declared,
ledger-checked divergence, with each side's reference model accepting
every dumped preimage) and the spec harness (`erc20_vault_spec.rs`,
9,000,000 cases at `PROPTEST_CASES=1000000` in the gating run). Deleting
`target/bench/results.jsonl` forces a fresh run; leaving it resumes an
interrupted one.
