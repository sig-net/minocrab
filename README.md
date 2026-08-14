# MinoCrab

A Rust eDSL for writing Midnight contracts, replacing the Compact language. Same
target (ZKIR, never below it), same statements proved, measurably cheaper proofs,
and disclosure tracked in the type system.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose money, and neither you or I will know why.

## Side by side

`erc20-vault`'s `deposit`, from the sig-net corpus
(`corpus/src/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault.compact`):

```compact
struct DepositRequest {
  erc20Address: Bytes<20>;
  amount: Uint<128>;
}

export circuit deposit(
  evmNonce: Uint<64>,
  gasLimit: Uint<64>,
  maxFeePerGas: Uint<128>,
  maxPriorityFeePerGas: Uint<128>,
  keyVersion: Uint<8>,
  depositRequest: DepositRequest
): [] {
  assert(depositRequest.amount > 0 as Uint<128>, "Amount must be positive");
  const caller = disclose(userCommitment(callerSecretKey()));
  // ... compose calldata, tx params, request ...
  const requestId = disclose(calculateRequestId<EvmType2TxParams<2, 0, 0>, 34, 34>(request));
  assert(!signBidirectionalEventMap.member(requestId), "Request already exists");
  signBidirectionalEventMap.insert(requestId, disclose(request));
}
```

The same circuit in MinoCrab:

```rust
label!(Depositor = "depositor identity commitment");
label!(RequestId = "request id");
label!(RequestRecord = "request record");

#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

#[circuit]
fn deposit(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    gas_limit: Uint<64>,
    max_fee_per_gas: Uint<128>,
    max_priority_fee_per_gas: Uint<128>,
    key_version: Uint<8>,
    deposit_request: DepositRequest,
) -> Discloses<(Depositor, RequestId, RequestRecord)> {
    let positive = c.less_than(0u64, deposit_request.amount, 128);
    c.assert(positive);
    let sk = common::witness_sk(c);
    let commitment = common::commitment(c, USER_PAD, &sk);
    let caller = c.disclose_as::<Depositor>(commitment);
    // ... compose calldata, tx params, request ...
    let id = signet::calculate_request_id(c, &request);
    let request_id = c.disclose_as::<RequestId>(id);
    let always = c.constant(1u64);
    let exists = map_member(c, always, SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id);
    let fresh = c.not(exists);
    c.assert(fresh);
    Discloses::of(())
}
```

Argument types are the range constraints (`Uint<64>` *is* `assert_bits(w, 64)`), and
the return type is the disclosure manifest: a private value cannot reach a public
output without a `disclose_as::<Label>` that a generated test checks against the
declared set.

*The `#[circuit]` / `#[derive(CircuitArg)]` syntax above is the API currently landing
(milestone M9, design of record in `notes/contract-api.org`); the circuits that
produce today's numbers are written in the explicit builder form —
`crates/minocrab-contracts/src/erc20_vault.rs`.*

## Why trust it

- **Differential-tested against compactc's own artifacts.** 13 suites: for every
  ported circuit, MinoCrab's artifact and compactc's must agree on typed
  input/output schema and produce equal public-input streams on a *shared*
  `ProofPreimage`, plus guard-rejection and tamper agreement.
- **Simulator cross-checked against Midnight's reference VM** (`IrSource::check`) on
  every run, end-to-end and under property tests.
- **Property tests** over random inputs assert circuit ≡ intent, not just circuit ≡
  compactc.
- **Type-level disclosure tracking.** `Wire<Private>` cannot reach a public output;
  every leak is an explicit, greppable `disclose`, and the simulator prints what a
  run discloses.
- **Frozen instruments.** Interface snapshot (ordered labels/types/witnesses, 55
  circuits) and row snapshot gate every change, so movement is never silent.

## Performance

Selected cells from `BENCHMARK.md` (one session, 2026-08-15, Apple Silicon; MinoCrab
`mc` vs compactc `cc`, prove = median of 3, identical statements proved):

| circuit | k mc/cc | prove mc | prove cc | RAM mc | RAM cc |
|---|---|---|---|---|---|
| deposit | 15 / 15 | 4.79s | 4.96s | 781MB | 783MB |
| claim | **16 / 17** | 9.45s | 19.13s | **1.8GB** | 3.2GB |
| completeSwap | **16 / 17** | 13.05s | 25.14s | **1.9GB** | 3.5GB |
| respond (singleton) | **10 / 16** | 0.13s | 5.12s | **41MB** | 879MB |
| initialize | 13 / 13 | 0.90s | 0.89s | 176MB | 179MB |

Wins come from instruction selection — ZKIR's native `ReverseBytes` and byte-aligned
slices instead of compactc's per-byte `div_mod_power_of_two` / `reconstitute_field`
chains — plus a segment-based serializer that splits limbs only at output-limb
boundaries; constraint cuts turn into time and RAM only when they cross a
power-of-two `k` boundary — each crossing roughly halves both — which they did on
eight of twelve circuits.

Parity is real too: `initialize` has no byte plumbing and is identical row for row,
and `deposit` (−35% rows) and `withdraw` (−19% rows) prove in compactc's time and
memory because Halo2's cost is dominated by the padded size 2^k, not the occupied rows.

Full table (all 24 cells, RSS, keygen), methodology and per-region profiles:
[BENCHMARK.md](BENCHMARK.md).

## Layout

```
crates/minocrab-zkir       L0  ZKIR bindings: read/write/round-trip, reusing midnight-zkir
crates/minocrab-ir         L1  typed circuit builder over ZKIR instructions
crates/minocrab            L2  eDSL core: wires, visibility, disclosure tracking
crates/minocrab-ledger     L2.5 Impact ledger ops, bit-identical public-input encoding
crates/minocrab-std        L3  stdlib ports (hashing, ECDSA, serialization, Signet events)
crates/minocrab-sim        L5  native simulator: disclosure reports + per-region cost profiler
crates/minocrab-contracts       the sig-net corpus rewritten, plus the differential suites
crates/minocrab-bench           the head-to-head proving harness
corpus/                         pinned Compact sources + their compactc artifacts
```

Benchmark, from a clean checkout (nix + direnv supply the pinned toolchain):

```
nix run .#bench
```

## Deeper

`plan.org` (aim and design requirements), `milestones.org` (state of play),
`notes/*.org` (findings and decisions of record — architecture, ZKIR, ledger ABI,
benchmark, contract API).
