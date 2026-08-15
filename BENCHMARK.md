# erc20-vault proving cost: compactc vs MinoCrab port vs optimized

MinoCrab is a Rust eDSL for Midnight that compiles to ZKIR, replacing the
Compact language. This report benchmarks the real sig-net cross-chain
contracts — all 9 circuits of `erc20-vault` (sig-net/midnight-examples)
plus the 3 circuits of its Signet singleton dependency
(sig-net/midnight-integration) — at the same pinned toolchain versions,
across three artifacts:

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
  Its comparability to the other two rests on symbolic-effect equality of
  the two contracts — a **weaker** warrant than the PI-equality the port
  and compactc share (see [Three sides, three comparability claims](#three-sides-three-comparability-claims)).

## Headline

Against compactc, the optimized vault cuts rows by 35–58% on every
erc20-vault circuit and 43.5% on `initialize`. But **rows are not prove
time — `k` is.** Halo2 proving cost tracks the padded circuit size 2^k,
not the occupied rows, so a row cut pays off in wall-clock and RAM only
when it crosses a power-of-two boundary. The vault is **hash-bound**:
95–99% of every circuit's rows are SHA-256, keccak-256 and secp256k1
ECDSA, and most of that crypto is protocol-pinned and immovable. So the
optimized artifact's row cuts are large everywhere, but its **new**
prove-time wins over the already-fast port are exactly two circuits:
`deposit` (crosses k15→14, prove −35%, RAM −52% vs the port) and
`withdraw` (crosses k16→15, prove −45%, RAM −51% vs the port). The other
seven cut rows but stay k-floored — their big deltas versus compactc are
inherited from the port's M6/M7 instruction-selection wins, already
banked, not new here. `swap` missed its k15 crossing by 51 rows and was
left there deliberately. This report shows both: the full three-way
numbers, and an honest split of which side earned which win.

## Three sides, three comparability claims

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
  the port's and the opt's reference models emit the same
  `Vec<Effect>` over a term algebra, and the two op streams, run through
  the pinned ledger's `run_program`, produce equal post-state, `Effects`
  (mints, spends, receives, nullifiers, contract calls) and events —
  with the re-mapping between differing terms asserted **injective** on
  the generated corpus. That is the actual security property of changing
  a hash construction, and it was checked at **9,000,000 cases** (1M per
  circuit × 9) by the spec harness, plus a burn well-formedness gate
  driven through the pinned ledger's own `Transaction::well_formed`.
  This is a weaker claim than PI-equality, and it is labeled as such
  throughout. It is the difference between "same statement proved
  cheaper" (port) and "same operation, re-framed, proved much cheaper"
  (opt).
- **Same backend, deterministic metrics.** Keygen/prove/verify go through
  Midnight's own `Zkir` (`midnight-zkir-v3`, pinned by the flake); the
  same hash-verified SRS parameters serve all three sides. Halo2 rows and
  the resulting `k` (rows fit in 2^k) are deterministic. Wall-clock prove
  time is the median of 3 in-process iterations, measured in one
  subprocess per cell (peak RSS = `getrusage` of that process), all cells
  in a single session on a quiet Apple Silicon machine.

Because opt is a separate deployment (its own verifier key ⇒ its own
`ContractOperation` ⇒ its own address), its token colours and commitment
digests differ from the port's by construction. That is correct, not a
discrepancy: the Signet singleton it calls is deployed compactc output
and is left untouched, so the singleton row (below) stays two-sided.

## Results

All 30 cells from one session (2026-08-15, Apple Silicon, quiet
machine), prove = median of 3. Raw data: `target/bench/results.json`.

| circuit | side | k | rows | keygen (s) | prove (s) | verify (s) | proof (B) | peak RSS (MB) |
|---|---|---|---|---|---|---|---|---|
| initialize | compactc | 13 | 4,272 | 0.70 | 0.89 | 0.004 | 6,336 | 179 |
| initialize | port | 13 | 4,272 | 0.68 | 0.90 | 0.004 | 6,336 | 176 |
| initialize | **opt** | 13 | 2,412 | 0.61 | 0.86 | 0.004 | 6,336 | 177 |
| deposit | compactc | 15 | 27,002 | 3.54 | 4.96 | 0.007 | 9,504 | 783 |
| deposit | port | 15 | 17,502 | 2.92 | 4.79 | 0.006 | 9,504 | 781 |
| deposit | **opt** | **14** | 15,632 | 2.13 | 3.10 | 0.006 | 9,504 | 378 |
| claim | compactc | 17 | 64,549 | 10.94 | 19.13 | 0.007 | 10,304 | 3,198 |
| claim | port | 16 | 47,660 | 5.69 | 9.45 | 0.008 | 10,304 | 1,843 |
| claim | **opt** | 16 | 42,051 | 5.55 | 9.35 | 0.007 | 10,304 | 1,858 |
| approveRouter | compactc | 15 | 20,619 | 3.25 | 4.86 | 0.007 | 8,128 | 654 |
| approveRouter | port | 14 | 13,344 | 2.05 | 3.06 | 0.007 | 8,128 | 315 |
| approveRouter | **opt** | 14 | 13,332 | 2.00 | 2.92 | 0.006 | 8,128 | 315 |
| withdraw | compactc | 16 | 52,009 | 5.80 | 9.39 | 0.008 | 9,504 | 1,590 |
| withdraw | port | 16 | 42,373 | 5.07 | 9.25 | 0.009 | 9,504 | 1,583 |
| withdraw | **opt** | **15** | 23,707 | 3.11 | 5.13 | 0.007 | 9,504 | 774 |
| completeWithdraw | compactc | 17 | 64,498 | 11.40 | 21.16 | 0.008 | 10,304 | 3,445 |
| completeWithdraw | port | 16 | 47,466 | 6.11 | 10.47 | 0.008 | 10,304 | 1,846 |
| completeWithdraw | **opt** | 16 | 40,157 | 5.65 | 9.81 | 0.007 | 10,304 | 1,840 |
| refund | compactc | 17 | 97,026 | 13.53 | 23.85 | 0.009 | 10,304 | 3,454 |
| refund | port | 16 | 65,231 | 6.73 | 12.69 | 0.011 | 10,304 | 1,874 |
| refund | **opt** | 16 | 40,806 | 5.82 | 10.04 | 0.008 | 10,304 | 1,845 |
| swap | compactc | 17 | 71,104 | 11.45 | 21.03 | 0.009 | 9,504 | 3,012 |
| swap | port | 16 | 51,485 | 6.42 | 11.51 | 0.010 | 9,504 | 1,594 |
| swap | **opt** | 16 | 32,819 | 5.77 | 9.52 | 0.008 | 9,504 | 1,579 |
| completeSwap | compactc | 17 | 104,615 | 14.37 | 25.14 | 0.009 | 10,304 | 3,454 |
| completeSwap | port | 16 | 65,071 | 6.97 | 13.05 | 0.010 | 10,304 | 1,877 |
| completeSwap | **opt** | 16 | 50,254 | 6.03 | 10.23 | 0.008 | 10,304 | 1,846 |
| signBidirectional | compactc | 16 | 50,429 | 5.45 | 5.21 | 0.006 | 3,824 | 888 |
| signBidirectional | port | 11 | 1,205 | 0.13 | 0.22 | 0.006 | 3,824 | 49 |
| respond | compactc | 16 | 40,931 | 4.86 | 5.12 | 0.006 | 3,824 | 879 |
| respond | port | 10 | 1,004 | 0.10 | 0.13 | 0.005 | 3,824 | 41 |
| respondBidirectional | compactc | 16 | 40,931 | 4.90 | 5.15 | 0.006 | 3,824 | 888 |
| respondBidirectional | port | 10 | 1,004 | 0.10 | 0.13 | 0.005 | 3,824 | 41 |

The three Signet singleton circuits have no `opt` variant: the singleton
is deployed compactc output — not ours to optimize — so it stays in the
port-vs-compactc layer (see [Baseline layer](#baseline-layer-port-vs-compactc)).

## opt vs compactc — the headline table

The optimized artifact against the compactc baseline. This is the largest
spread, and the one carrying the [weaker comparability
claim](#three-sides-three-comparability-claims): opt proves its own
preimage per circuit — the same logical operation, not the same
statement.

| circuit | k opt / cc | rows Δ | prove Δ | RSS Δ |
|---|---|---|---|---|
| initialize | 13 / 13 | −43.5% | −3.3% | −1.3% |
| deposit | **14 / 15** | −42.1% | **−37.6%** | **−51.7%** |
| claim | **16 / 17** | −34.9% | −51.2% | −41.9% |
| approveRouter | **14 / 15** | −35.3% | −39.9% | −51.9% |
| withdraw | **15 / 16** | −54.4% | **−45.4%** | **−51.3%** |
| completeWithdraw | **16 / 17** | −37.7% | −53.6% | −46.6% |
| refund | **16 / 17** | −57.9% | −57.9% | −46.6% |
| swap | **16 / 17** | −53.8% | −54.7% | −47.6% |
| completeSwap | **16 / 17** | −52.0% | −59.3% | −46.6% |

## opt vs the port — isolating the new wins

The table above overstates what M10 itself contributed, because most of
the prove-time gap to compactc was already earned by the port's M6/M7
instruction selection (which drops k below compactc on eight of nine
circuits). Comparing opt to the **port** isolates the optimization
ladder's own contribution:

| circuit | k opt / port | rows Δ | prove Δ | new k crossing? |
|---|---|---|---|---|
| initialize | 13 / 13 | −43.5% | −4.4% | no (SHA-floored at k13) |
| deposit | 14 / 15 | −10.7% | **−35.3%** | **yes, k15→14** |
| claim | 16 / 16 | −11.8% | −1.1% | no (ECDSA-floored) |
| approveRouter | 14 / 14 | −0.1% | −4.6% | no (keccak-floored) |
| withdraw | 15 / 16 | −44.1% | **−44.5%** | **yes, k16→15** |
| completeWithdraw | 16 / 16 | −15.4% | −6.3% | no (ECDSA-floored) |
| refund | 16 / 16 | −37.4% | −20.9% | no (ECDSA-floored) |
| swap | 16 / 16 | −36.3% | −17.3% | no (missed k15 by 51 rows) |
| completeSwap | 16 / 16 | −22.8% | −21.6% | no (ECDSA-floored) |

Read this table as the honest accounting:

- **The two clean prove-time wins are `deposit` and `withdraw`** — the
  only circuits opt pushes across a `k` boundary. Everything else holds
  the port's `k`.
- The k-floored settle circuits (`claim`, `completeWithdraw`, `refund`,
  `swap`, `completeSwap`) still show prove reductions of 1–22% over the
  port. Where the port already had slack in its 2^k bucket (`claim`,
  `completeWithdraw`) the reduction is 1–6%, essentially noise. Where the
  port's circuit sat near the top of its bucket — `refund` at
  65,231/65,536, `completeSwap` at 65,071/65,536 — the row cut frees
  occupancy and prove drops ~20%, a real but secondary within-`k` effect,
  not a boundary crossing. This is the honest reason opt's `refund` and
  `completeSwap` prove faster than the port at the same `k`.
- **opt does not get credit for the port's wins.** `claim`,
  `completeWithdraw`, `refund`, `swap`, `completeSwap` all show −51% to
  −59% vs compactc — but that is overwhelmingly the port's k16-vs-cc-k17
  crossing (banked in M6/M7), which opt inherits by staying at k16. Its
  own contribution on those circuits is the within-`k` fraction above.

## Where the wins come from

The vault is hash-bound: reconstructing per-circuit budgets from measured
primitive costs (`cargo run -p minocrab-sim --example cryptocost`;
`--example cryptocost` calibrated SHA-256 pair hash at 3,739 rows, keccak
attestation block at 4,207, secp256k1 ECDSA verify at 24,450, Poseidon
permutation at 22) shows 95–99% of every circuit's rows are SHA/keccak/
ECDSA, confirmed by the region profiler attributing by estimated rows
(e.g. claim's ECDSA region is 52.6% of rows against a 53% prediction).
So transcript framing, `constrain_bits` dedup and serialization — worth a
few hundred rows each — cross **no** `k` boundary and were largely not
the lever. The row cuts come from the vault's **own discretionary hash
constructions and structure**, avenue by avenue:

| # | avenue | change | rows | circuits |
|---|---|---|---|---|
| 1 | userCommitment short-SHA | 64-byte (2-block) → 43-byte (1-block) SHA-256, same domain tag; stays SHA (it is the MPC key-derivation path) | −1,860/use | initialize, deposit, claim |
| 2 | token domain separator | `SHA-256([pad("erc20:vault:"), erc20])` → injective non-hashed encoding `0x01 ‖ zeros ‖ erc20` (ledger derives the colour itself and accepts an arbitrary pre-token) | −3,749/use, 8 uses | withdraw, swap, claim, completeWithdraw, refund×2, completeSwap×2 |
| 3 | refund commitment → Poseidon | `withdrawRefundCommitment`/`swapRefundCommitment` SHA-256(96 B) → `transientHash` (internal, one-round-trip, never leaves the contract) | −3,560/use | withdraw, swap, completeWithdraw, refund, completeSwap |
| 4 | refund branch merge | `refund` computed the same mint (domainSep→tokenType→coinCommitment→mint) and commitment hash in both branches; guards gate PI emission, not rows, so both cost full — merged to one shared block, ledger ops still guarded per route | −13,355 | refund |
| 5 | changeNonce derived | completeSwap's `persistentHash([mintNonce, pad("change")])` → the bijection `[255 − hi, lo]` (uniqueness only; a total, disclosed derivation) | −3,747 | completeSwap |
| 6 | burn single-spend | withdraw/swap burn reframed from receive+nullifier+spend to one claimed shielded spend of the burn-address output (subset-checked vs the offer, no contract-address requirement; gate proven against the pinned ledger) | −11,309/use | withdraw, swap |
| 7 | kernel.self dedup | read the contract's own address once and thread it, instead of compactc's per-call-site reads | −12/read, 12 reads | deposit, approveRouter, withdraw, swap, refund, completeSwap |

None of this touches the protocol-pinned crypto, which is immovable: the
keccak request id and record layout (the MPC decodes the record from raw
ledger state), the keccak attestation digest (what the MPC signed), the
in-circuit secp256k1 ECDSA (the only authentication gate; the MPC is
secp256k1-native), the coin commitments/nullifiers (multiset-checked
against the offer), and `tokenType`'s own SHA derivation in the ledger.
That crypto is why the settle circuits are floored above 2^15 and their
row cuts stay cosmetic for prove time.

## Honest notes and limits

- **`swap` missed k15 by 51 rows.** It landed at 32,819 rows against the
  32,768 boundary. The one lever that would have crossed it —
  `Map<_, Field>`-typed commitment values, dropping a `div_mod` split of
  ~143 rows per site — was deferred: it needs a new differential corpus
  and shipping-crate ledger builders, a disproportionate blast radius for
  a 51-row gap on the final rung. Measured, not chased. `swap` stays k16;
  its speedup is the port's k16-vs-cc-k17 crossing plus a within-`k` row
  cut.
- **`initialize` is cosmetic.** −43.5% rows but SHA-floored at k13 (a
  single SHA block already sits at k13, measured), so prove and RSS are
  flat — the same shape as the port's `initialize` parity: what the
  comparison looks like with `k` off the table.
- **The four settle circuits are ECDSA-floored above 2^15.** `claim`,
  `completeWithdraw`, `refund`, `completeSwap` cut 34–58% of rows but
  cannot cross k16 while the secp256k1 verify (~24,450 rows) is pinned.
  Their row column is real; their prove-time column is mostly inherited
  from the port.
- **The opt statement caveat is not a footnote.** opt proves a different
  statement from the port and compactc. The chain of trust that replaces
  PI-equality — symbolic-effect equality, `run_program` post-state/effect
  agreement, injective re-mapping over the corpus, the 9,000,000-case
  spec sweep, the pinned-ledger burn gate — is machinery, not prose, but
  it is a **weaker** warrant than "identical PI stream on a shared
  preimage." Treat opt's numbers as "same operation, re-framed, proved
  cheaper," never as "same statement, proved cheaper."
- **The singleton has no opt variant.** Its 97.5% row cut is the port's
  M7 result against a deployed compactc artifact, and it stays in the
  baseline layer below.
- Proof sizes are identical per circuit across all three sides (same
  proof system and public-input counts); verify times are milliseconds
  everywhere. Sub-second cells have noise-dominated wall-clock deltas;
  rows/k/RSS are exact.

## Baseline layer: port vs compactc

The M6/M7 story, unchanged and still the floor the opt side builds on:
the direct port proves the **identical statement** as compactc (shared
`ProofPreimage`, PI-equal) and is parity-or-better everywhere, because it
emits ZKIR's native byte instructions (`ReverseBytes`, byte-aligned
`div_mod` slices, a segment-based serializer) where compactc lowers its
standard library's byte manipulation to per-byte `div_mod` /
`reconstitute_field` chains.

| circuit | k port/cc | rows Δ | prove Δ | RSS Δ |
|---|---|---|---|---|
| initialize | 13 / 13 | ±0% | +0.9% | −1.9% |
| deposit | 15 / 15 | −35.2% | −3.4% | −0.3% |
| claim | **16 / 17** | −26.2% | **−50.6%** | −42.4% |
| approveRouter | **14 / 15** | −35.3% | **−37.0%** | −51.9% |
| withdraw | 16 / 16 | −18.5% | −1.4% | −0.4% |
| completeWithdraw | **16 / 17** | −26.4% | **−50.5%** | −46.4% |
| refund | **16 / 17** | −32.8% | **−46.8%** | −45.8% |
| swap | **16 / 17** | −27.6% | **−45.3%** | −47.1% |
| completeSwap | **16 / 17** | −37.8% | **−48.1%** | −45.7% |
| signBidirectional | **11 / 16** | −97.6% | **−95.7%** | −94.5% |
| respond | **10 / 16** | −97.5% | **−97.4%** | −95.4% |
| respondBidirectional | **10 / 16** | −97.5% | **−97.4%** | −95.4% |

The same-`k` rows here (`deposit`, `withdraw`) already showed, before any
M10 work, that a row cut without a boundary crossing leaves prove time
essentially flat — which is exactly the effect the opt side then turned
into crossings for those two circuits.

## Reproducing

From a clean checkout (nix + direnv provide the pinned toolchain):

```
nix run .#bench        # or: nix develop -c ./bench.sh
```

This re-runs the differential tests (dumping corpus-verified preimages
for all three sides, opt's under `preimages/opt/`), proves all 30 cells,
and writes `target/bench/results.json`, `report.md`, and the per-region
cost profiles under `target/bench/profiles/`. The opt side proves its own
dumped preimages, corpus-verified via the fork gate
(`tests/erc20_vault_opt_fork.rs`, asserting each opt circuit is either
byte-identical to the port or a declared, ledger-checked divergence) and
the spec harness (`erc20_vault_spec.rs`, 9,000,000 cases at
`PROPTEST_CASES=1000000`). Deleting `target/bench/results.jsonl` forces a
fresh run; leaving it resumes an interrupted one.
