# MinoCrab

Rust eDSL for Midnight contracts, replacing Compact. Same target (ZKIR, never below it), same statements proved.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose it, and neither you nor I will know why.

## Safety

- Leaking a `Wire<Private>` is a compile error until `c.disclose(w, label)` ([compile_fail doctest](crates/minocrab/src/lib.rs))
- Argument types are the range constraints — `Uint<64>` *is* `assert_bits(w, 64)`, from compactc's own `emit-constraints-for` table ([v3_leaves.rs](crates/minocrab-std/tests/v3_leaves.rs), [v3_entry.rs](crates/minocrab-std/tests/v3_entry.rs))
- Drift is a test failure: `(k, rows)` and the ordered interface of all 98 circuits are frozen ([row_snapshot.rs](crates/minocrab-contracts/tests/row_snapshot.rs), [interface_snapshot.rs](crates/minocrab-contracts/tests/interface_snapshot.rs))
- 9,000,000 property cases against a Rust spec of every vault circuit, accepted runs replayed through the reference VM and the pinned ledger's `run_program` ([erc20_vault_spec.rs](crates/minocrab-contracts/tests/erc20_vault_spec.rs))
- Adversarial sweeps: `2^128 − 1`, zero addresses, malformed witnesses, witness malleability, injectivity ([erc20_vault_adversarial.rs](crates/minocrab-contracts/tests/erc20_vault_adversarial.rs))
- Bijective serialization — Borsh `bool` is `0|1`, so the `0x02` attestation hazard is unprovable, not refunded ([erc20_vault_borsh_fork.rs](crates/minocrab-contracts/tests/erc20_vault_borsh_fork.rs))
- Every simulator run cross-checked against Midnight's reference VM `IrSource::check`
- Differential against compactc's own artifacts — see [porting kit](#porting-kit)

## Features

- [Borsh](https://borsh.io) subset encoding/decoding ([spec](spec/borsh-subset.md), [vectors](spec/vectors), [conformance](crates/minocrab-contracts/tests/serialization_conformance.rs)), with Rust and TypeScript parser generation ([spec/ts](spec/ts), [vectors.test.ts](spec/ts/vectors.test.ts), [ts_codegen.rs](crates/minocrab-contracts/tests/serialization/ts_codegen.rs))
- FAB Compact too, named at the call site: `persistent_hash_compact` / `transient_hash_compact` ([v3_borsh.rs](crates/minocrab-std/tests/v3_borsh.rs))
- Hashing a Borsh value is free — the hash chips pack in-chip, zero extra rows
- Interfaces for contracts have to be explicitly altered ([spec_doc.rs](crates/minocrab-contracts/tests/serialization/spec_doc.rs))
- x-contract call interfaces are exported/imported as cargo crates
- Interface crates and disclosures are automatically checked against the callee's compiled artifact ([signet-signer-interface](crates/signet-signer-interface/tests/artifact_agreement.rs), [xcall-target-interface](crates/xcall-target-interface/tests/artifact_agreement.rs))
- Any deployed Midnight contract is importable: `minocrab-interface-gen --crate <dir>` ([regenerate.rs](crates/minocrab-interface-gen/tests/regenerate.rs))
- Native compilation of circuits for testing — `cargo test`, fast, no proving, no keys ([minocrab-sim](crates/minocrab-sim/src/lib.rs))
- Per-region cost profiler attributing rows, with calibrated primitive costs ([profile()](crates/minocrab-sim/src/lib.rs), [cryptocost.rs](crates/minocrab-sim/examples/cryptocost.rs), [opcost.rs](crates/minocrab-sim/examples/opcost.rs))
- Bounded integers at any bound — `BoundedUint<70000>` *is* Compact's `Uint<0..70000>`, range end exclusive, lowered by compactc's own table; non-power-of-two `enum`s are the same leaf ([v3_bounded.rs](crates/minocrab-std/tests/v3_bounded.rs), [bounded_differential.rs](crates/minocrab-contracts/tests/bounded_differential.rs))
- Circuit families as const generics, allowing you to encode invariants using the rust type system, monomorphized and unrolled by rustc ([notes/const-generics.org](notes/const-generics.org))
- Macros are thin decorators — `#[circuit]` moves your body, it does not rewrite it; the expansion calls no `Circuit3` method ([circuit.rs](crates/minocrab-macros/src/circuit.rs)), and every derive has a hand-written twin that must lower to byte-identical ZKIR ([v3_derive.rs](crates/minocrab-std/tests/v3_derive.rs), [interface_macro.rs](crates/minocrab-contracts/tests/interface_macro.rs))
- Rust: modules, generics, `pub(crate)`, cargo, rust-analyzer, `#[test]`, crates.io

## Side by side

`erc20-vault`'s `deposit`, from the sig-net corpus:

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

The same circuit, abridged from `crates/minocrab-contracts/src/erc20_vault_modern.rs`:

```rust
/// `struct DepositRequest { erc20Address: Bytes<20>, amount: Uint<128> }`
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

#[circuit]
pub fn deposit(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    gas_limit: Uint<64>,
    max_fee_per_gas: Uint<128>,
    max_priority_fee_per_gas: Uint<128>,
    key_version: Uint<8>,
    deposit_request: DepositRequest,
) -> Discloses<(
    DepositorCommitment,
    RequestId,
    RequestRecord,
    XcallEntryPointHash,
    XcallCommitment,
)> {
    // assert(amount > 0) — the width is the argument type's, not typed here
    c.assert(deposit_request.amount.gt(0u64));

    // const caller = disclose(userCommitment(callerSecretKey()))
    let sk = common::witness_sk(c);
    let caller = common::commitment_short(c, &sk).disclose_as::<DepositorCommitment>(c);

    // a Bytes<20> cell: the FAB atoms come from the slot's type
    let vault_evm = VAULT.vault_evm_address.read(c);
    // ... compose calldata, tx params, request ...

    // requestId, freshness check, map insert, and the call to the signer
    record_and_notify(c, one, me, &request, &VAULT.sign_bidirectional_event_map, [0, 0, 0, 0]);
    Discloses::of(())
}
```

- The return type is the disclosure manifest, and a generated test fails if the circuit discloses anything not in it — that is how the four vault circuits were caught publishing a cross-contract call's entry-point hash undeclared ([disclose.rs](crates/minocrab/src/v3/disclose.rs))
- `#[circuit]` and `#[derive(CircuitArg)]` build 82 of the 98 workspace circuits; the exception is `hashing`, whose WIDTH is a Rust parameter the benchmark sweeps
- This is the *showcase twin*: the same contract as the three zero-movement ports, written through the whole API. It is not prettier prose — it is gated on proving the identical statement (same typed schema, same PI vector on the ports' own preimage) at identical rows and identical `k` ([erc20_vault_modern_fork.rs](crates/minocrab-contracts/tests/erc20_vault_modern_fork.rs))

## Cross-contract calls

```toml
[dependencies]
signet-signer-interface = { path = "../signet-signer-interface" }
```

```rust
use signet_signer_interface::{notification::construct_notification_v1, SignetSigner};

let signer = SignetSigner::at_field(SIGNET_SIGNER).pin(c, one);
let me = ContractAddress::from_limbs(kernel_self(c, one));
let notification = construct_notification_v1::<Public>(c, &me.bytes(), 1, notify_path);
signer.sign_bidirectional(c, one, *request_id, notification);
```

The interface crate is a bodyless trait, one item per callee circuit:

```rust
#[interface]
pub trait SignetSigner {
    fn sign_bidirectional(
        request_id: RequestId<Public>,
        notification: SignBidirectionalEventNotification<Public>,
    );
    // respond, respondBidirectional
}
```

- Last call line is the whole desugar: argument flattening, result-limb witnesses and constraints, communications commitment, effects claim
- Entry-point hashes derived from method names via upstream's own derivation; commitment layout from declaration order
- Every parameter is `Public` — passing a value cross-contract discloses it, so forgetting `disclose()` is a compile error
- No address in the crate: `at_field(index)` names a sealed ledger cell, `at(address)` takes one as data
- Each crate commits the callee's artifact plus a hash pin and checks slots, constraints and the compiled `.zkir` prefix against it; a mutation suite proves the checks bite:

```text
---- mutation::a_reordered_argument_list_is_caught ----
  - `signBidirectional` argument slots: artifact [uint<8>, uint<32>, uint<248>, …]
    != interface [uint<8>, uint<248>, uint<8>, uint<32>, …]

---- mutation::the_zkir_catches_a_widened_constraint ----
  - signBidirectional.zkir slot 2: constraint bits:16 != the interface's bits:8
```

The second forges only the compiled circuit — `contract-info.json` and the pin stay correct — and is caught by reading the instruction stream the prover executes.

Limit: the circuit binds neither the entry point nor the argument types. `callOnce` and `callEmit` compile to byte-identical ZKIR under different entry points, asserted by a test. What protects the verifier is the ledger's `(address, entry point, commitment)` match.

## Porting kit

- `corpus/` is 673 pinned `.compact` sources and the 788 ZKIR circuits (312 contracts) the pinned compactc produced ([corpus/README.org](corpus/README.org), [sources.json](corpus/sources.json))
- Rewrite a contract in the eDSL; the harness checks it against compactc's artifact, not against your reading of the source
- The check is statement identity: same typed schema, same public-input stream on one shared `ProofPreimage`, both handed to Midnight's reference VM. Instruction streams may differ because of our optimiser. Guard rejections and tampered inputs must agree too.

```rust
fn assert_call_compatible(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    // ... typed input schema, field by field
    assert_eq!(types(ours), types(theirs), "input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "output schemas differ");

    let our_run = simulate(ours, pi).expect("our artifact accepts");
    let their_run = simulate(theirs, pi).expect("corpus artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    assert_eq!(ours.check(pi).expect("upstream accepts ours"), our_run.pi_skips);
    assert_eq!(
        theirs.check(pi).expect("upstream accepts theirs"),
        their_run.pi_skips
    );
}
```

Every ported circuit is wired this way ([erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs), [differential_baseline.rs](crates/minocrab-ledger/tests/differential_baseline.rs), [differential_tiny.rs](crates/minocrab-std/tests/differential_tiny.rs), [differential_schnorr.rs](crates/minocrab-std/tests/differential_schnorr.rs)). New ports add a scenario builder and one call.

```
cargo test --workspace --release
```

## Performance

One session, 2026-08-15, Apple Silicon. Port `mc` vs compactc `cc`, identical statements, prove = median of 3.

| circuit | k mc/cc | prove mc | prove cc | RAM mc | RAM cc |
|---|---|---|---|---|---|
| deposit | 15 / 15 | 4.79s | 4.96s | 781MB | 783MB |
| claim | **16 / 17** | 9.45s | 19.13s | **1.8GB** | 3.2GB |
| completeSwap | **16 / 17** | 13.05s | 25.14s | **1.9GB** | 3.5GB |
| respond (singleton) | **10 / 16** | 0.13s | 5.12s | **41MB** | 879MB |
| initialize | 13 / 13 | 0.90s | 0.89s | 176MB | 179MB |

- Wins come from instruction selection: native `ReverseBytes` and byte-aligned slices instead of per-byte `div_mod_power_of_two` / `reconstitute_field` chains, plus a segment-based serializer
- Row cuts pay only when they cross a `k` boundary — nine of twelve circuits did
- `initialize` is identical row for row; `deposit` (−35% rows) and `withdraw` (−19% rows) prove in compactc's time
- The M10 optimized vault cuts 35–58% of rows but proves its **own** preimage, so its warrant is symbolic-effect equality plus the 9M harness, not PI-equality. Its own new prove-time wins are two circuits (`deposit` k15→14, `withdraw` k16→15); `swap` missed k15 by 51 rows and was left there.
- All 30 cells, methodology, per-region profiles: [BENCHMARK.md](BENCHMARK.md)

## What Compact has and MinoCrab does not

Only real gaps. Candidates that failed the check are in [notes/readme-research.org](notes/readme-research.org).

- `Opaque<'ts-type'>`. No such type; the ABI reader and the interface generator reject it ([info.rs](crates/minocrab-abi/src/info.rs), [interface-gen](crates/minocrab-interface-gen/src/lib.rs)).
- Ledger ADTs beyond Cell / Counter / Map / `Set::insert` ([ledger](crates/minocrab-ledger/src/lib.rs)). No `List`, `MerkleTree`, `HistoricMerkleTree`; the Merkle *path* circuits are ported ([merkle.rs](crates/minocrab-std/src/merkle.rs)), the ledger ops on those trees are not.
- Part of the kernel and token stdlib. Missing: `kernel.checkpoint`, the block-time family, all unshielded tokens, `kernel.balance*`, `sendShielded`, `mergeCoin*`. Tracked in [milestones.org](milestones.org).
- A machine-checked semantics. Compact has an Agda spec in-tree with CI; our warrant is differential and property testing. Not formal-verification parity.

## Layout

```
crates/minocrab-zkir       L0  ZKIR bindings: read/write/round-trip, reusing midnight-zkir
crates/minocrab-ir         L1  typed circuit builder over ZKIR instructions
crates/minocrab            L2  eDSL core: wires, visibility, disclosure tracking
crates/minocrab-ledger     L2.5 Impact ledger ops, bit-identical public-input encoding
crates/minocrab-std        L3  stdlib ports (hashing, ECDSA, Borsh serialization, Signet events)
crates/minocrab-macros          the thin decorators: #[circuit], the derives, #[interface]
crates/minocrab-sim        L5  native simulator: disclosure reports + per-region cost profiler
crates/minocrab-contracts       the sig-net corpus rewritten, plus the differential suites
crates/minocrab-bench           the head-to-head proving harness
crates/minocrab-abi             the interface/artifact agreement checker
crates/minocrab-interface-gen   compactc artifact → interface crate (CLI)
crates/signet-signer-interface  an interface crate: the Signet singleton
crates/xcall-target-interface   an interface crate, generated from a contract nobody ported
corpus/                         673 pinned Compact sources + 788 compactc artifacts
spec/                           the Borsh-subset specification, golden vectors, generated TS
```

Benchmark from a clean checkout (nix + direnv supply the pinned toolchain):

```
nix run .#bench
```

## Deeper

`plan.org` (aim and design requirements), `milestones.org` (state of play), `notes/*.org` (findings and decisions of record).
