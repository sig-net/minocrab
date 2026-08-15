# MinoCrab

A Rust eDSL for writing Midnight contracts, replacing the Compact language. Same
target (ZKIR, never below it), same statements proved, measurably cheaper proofs,
and disclosure tracked in the type system.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose it, and neither you nor I will know why.

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

The same circuit in MinoCrab (abridged from
`crates/minocrab-contracts/src/erc20_vault.rs` — this is the circuit that produces
the numbers below):

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
) {
    let amount = deposit_request.amount.field();
    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // assert(amount > 0)
    let amount_positive = c.less_than(zero.private(), amount, 128);
    c.assert(amount_positive);

    // const caller = disclose(userCommitment(callerSecretKey()))
    let sk = common::witness_sk(c);
    let caller_priv = common::commitment(c, USER_PAD, &sk);
    let caller = B32 {
        hi: c.disclose(caller_priv.hi, "depositor identity commitment (hi)"),
        lo: c.disclose(caller_priv.lo, "depositor identity commitment (lo)"),
    };
    // ... compose calldata, tx params, request ...

    // requestId, freshness check, map insert, and the call to the signer
    record_and_notify(c, one, &request, SIGN_BIDIRECTIONAL_EVENT_MAP, [0, 0, 0, 0]);
}
```

Argument types are the range constraints (`Uint<64>` *is* `assert_bits(w, 64)`) and
the parameter list is the wire contract — declaration order, and the Compact
argument labels, both derived rather than hand-written. Disclosure is tracked in
the type system: `caller_priv` is a `Wire<Private>` and cannot reach a public output
or a ledger operation without the `c.disclose(w, label)` that returns a
`Wire<Public>`, so every leak is explicit, labelled and greppable — and the
simulator prints what a run disclosed.

*Honest markers: `#[circuit]` and `#[derive(CircuitArg)]` are landed and in use, but
only `deposit`, `withdraw` and `claim` of the vault (and the singleton's
`signBidirectional`) are written this way so far — the other circuits are still in
the explicit builder form, and porting them is mechanical (M9 phase 5). The typed
disclosure MANIFEST — `label!` / `disclose_as::<L>` / a `Discloses<…>` return type
checked by a generated set-equality test — is designed (`notes/contract-api.org`)
and not built; today the tracking is the type-level one described above.*

## Cross-contract calls: the interface is a crate

Compact has no package manager. MinoCrab's answer is cargo: a callee's interface
ships as an ordinary Rust crate — `crates.io`, git or path, semver'd — and calling
it is one typed method call.

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

That last line is the entire cross-contract desugar: argument flattening in the
callee's slot order, the result-limb witnesses and their constraints, the
communications commitment, and the ledger's effects claim. Before M12 those were
hand-written at every call site.

The crate itself is a bodyless trait — one item per callee circuit, which reads
next to the Compact declaration it describes:

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

Entry-point hashes are **derived** from the method names (`sign_bidirectional` →
`signBidirectional` → its 32-byte hash, computed by upstream's own derivation), and
the commitment layout falls out of declaration order — no hand-typed keys. Every
parameter is `Public` because passing a value cross-contract discloses it; a private
value must `disclose()` first, and forgetting is a compile error. The crate contains
no address: `at_field(index)` names the sealed ledger cell a deployment keeps it in,
`at(address)` takes one as data.

**Drift is a test failure, not a runtime surprise.** Each interface crate commits the
callee's compactc artifact plus a hash pin, and its own suite checks the
declarations against it: the entry point exists, it is `proof: true`, the argument
and result trees flatten to the same slots and constraints, the circuit compiles a
communications commitment, and the compiled `.zkir`'s opening constraint prefix
matches slot for slot. A mutation suite proves the checks bite — this is what two of
them print when the artifact is damaged:

```text
---- mutation::a_reordered_argument_list_is_caught ----
  - `signBidirectional` argument slots: artifact [uint<8>, uint<32>, uint<248>, …]
    != interface [uint<8>, uint<248>, uint<8>, uint<32>, …]
  - `signBidirectional` argument alignment: artifact [bytes 1, bytes 128, bytes 32]
    != interface [bytes 32, bytes 1, bytes 128]

---- mutation::the_zkir_catches_a_widened_constraint ----
  - signBidirectional.zkir slot 2: constraint bits:16 != the interface's bits:8
```

The second one matters most: `contract-info.json` and the pin are left *correct*
there, so every offline check passes and only the compiled circuit is forged. It is
caught by reading the instruction stream the prover actually executes.

**Any deployed Midnight contract is importable**, Compact-authored or not, because
compactc's artifact carries the typed I/O schema:

```
minocrab-interface-gen --crate crates/xcall-target-interface
```

`crates/xcall-target-interface` was generated that way from a corpus contract nobody
here ported, and its callers went through it with zero movement on every snapshot.
`--check` regenerates and diffs, wired as a test, so a hand-edited generated file
fails in CI. Regenerating the hand-authored `signet-signer-interface` reproduced
every declaration byte for byte.

**The honest limit.** The *circuit* binds neither the entry point nor the argument
types: entry-point limbs are prover-supplied witnesses and argument limbs are opaque
field elements inside the commitment. The typing protects the developer and the
transaction builder; what protects the **verifier** is the ledger's `(address, entry
point, commitment)` match. `callOnce` and `callEmit` compile to byte-identical ZKIR
under different entry points — asserted by a test, so the limit is executable rather
than a paragraph.

## Serialization: a Borsh subset, not a format of ours

Payloads that cross the wire — request records, the digests an MPC signs, log
payloads — are **canonical Borsh, restricted to the fixed-width subset**. Not a
dialect: every byte is valid Borsh for the declared types, so `borsh-js` on the
TypeScript side parses it from the same declarations. The restriction has one cause,
that a circuit cannot have data-dependent layout, and one visible consequence:
Compact's `Maybe` is `Flagged<T>` — a `bool` tag and an always-present payload —
never `Option`, whose Borsh encoding omits the payload on `None`.

The finding that started it: **the deployed protocol is already Borsh.** Midnight's
hashed field-aligned binary, for the all-bytes shapes this protocol uses, IS the
Borsh encoding, byte for byte — both request records (so `requestId ==
keccak256(borsh(record))`), all four attestation preimages, and all three of the
singleton's log payloads, the last verified by handing the bytes to the pinned
compactc artifact, which accepts them and rejects every single-byte perturbation
including in the zero pad. Zero divergences. So most of the deliverable was a
specification and a test oracle for what is already running.

One declaration then gives a circuit its arguments, its range constraints, its hash
preimage, its packed bytes and its offset table — and `#[borsh(spec = …)]` generates
a test cross-checking that layout against borsh's own schema of a plain Rust twin,
so the two declarations of one format cannot drift:

```rust
#[derive(CircuitBorsh)]
#[borsh(spec = RespondMisc)]
struct RespondMiscCircuit<V: Vis3> {
    request_id: B32<V>,
    big_r_x: B32<V>,
    big_r_y: B32<V>,
    s: B32<V>,
    recovery_id: Uint<8, V>,
}
```

Hashing such a value is **free**: the hash chips take an alignment and pack bytes
in-chip, so choosing the atom widths to be the Borsh widths buys the encoding for
zero extra rows — `minocrab_std::v3::hash::persistent_hash(c, &v)` is
`SHA-256(borsh::to_vec(v))` and emits no packing instruction at all. (The FAB
spelling stays available as `persistent_hash_compact`, for digest agreement with a
Compact contract.)

Where it changed the protocol, it closed a hazard: attested outputs now carry a
1-byte **response kind** at offset 0, so a signature attesting a claim cannot settle
a withdrawal, and `success` is a Borsh `bool` — `0|1` and nothing else — where the
deployed contract treats any byte other than `0x01` as failure and re-mints on a
*successful* withdrawal. Cost: +6, +6, +9 and −9 rows on the four settle circuits,
no `k` boundary moved.

**[`spec/borsh-subset.md`](spec/borsh-subset.md)** is the specification the
TypeScript and MPC sides implement against — grammar, leaf table, reject rules,
padding rule, response kinds, and per-type byte-offset tables *generated* from the
same schema walk the tests check, with golden vectors in
[`spec/vectors/`](spec/vectors). Three tests fail if the committed document stops
being that generator's output, so the spec cannot drift from the format.

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
- **Frozen instruments.** Interface snapshot (ordered labels/types/witnesses, 78
  circuits) and row snapshot gate every change, so movement is never silent.
- **Interface crates checked against the callee's artifact**, and a spec document
  generated from the same declarations the circuits use — see the two sections
  above.

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
crates/minocrab-abi             the interface/artifact agreement checker
crates/minocrab-interface-gen   compactc artifact → interface crate (CLI)
crates/signet-signer-interface  an interface crate: the Signet singleton
crates/xcall-target-interface   an interface crate, generated from a contract nobody ported
corpus/                         pinned Compact sources + their compactc artifacts
spec/                           the Borsh-subset specification + golden vectors
```

Benchmark, from a clean checkout (nix + direnv supply the pinned toolchain):

```
nix run .#bench
```

## Deeper

`plan.org` (aim and design requirements), `milestones.org` (state of play),
`notes/*.org` (findings and decisions of record — architecture, ZKIR, ledger ABI,
benchmark, contract API).
