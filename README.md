# MinoCrab

A Rust eDSL for writing Midnight contracts, replacing the Compact language. Same
target (ZKIR, never below it), same statements proved, measurably cheaper proofs,
and disclosure tracked in the type system.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose it, and neither you nor I will know why.

Every row of the table below links to the test or the document that enforces it.
That is the organizing idea of this README: the safety properties are checkable
artifacts in the tree, not adjectives.

## MinoCrab and Compact

| | Compact | MinoCrab | enforced by |
|---|---|---|---|
| **Leaking a private value** | `disclose()` at the leak site | the same rule, carried by Rust's types: `Wire<Private>` has no path to a public output or a ledger operation, so the leak is a *compile error* until you write `c.disclose(w, label)` — and the simulator prints what a run disclosed | [`crates/minocrab/src/lib.rs`](crates/minocrab/src/lib.rs) — a `compile_fail` doctest that breaks the build if the leak ever starts compiling |
| **Argument range constraints** | `Uint<0..n>` lowers to its constraint | the argument *type* is the constraint: `Uint<64>` **is** `assert_bits(w, 64)`, emitted from one table ported from compactc's own `emit-constraints-for` | [`v3_leaves.rs`](crates/minocrab-std/tests/v3_leaves.rs), [`v3_entry.rs`](crates/minocrab-std/tests/v3_entry.rs) — the typed form must lower to the byte-identical ZKIR of the hand-written `c.arg` + `assert_bits` block |
| **Drift** — a toolchain bump, a refactor, an edited artifact | up to the project | a test failure. `(k, rows)` and the ordered interface of all 78 workspace circuits are frozen tables; an interface crate is checked against the callee's compiled artifact; the spec document, its vectors and the TypeScript parser must all still be their generator's output | [`row_snapshot.rs`](crates/minocrab-contracts/tests/row_snapshot.rs), [`interface_snapshot.rs`](crates/minocrab-contracts/tests/interface_snapshot.rs), [`artifact_agreement.rs`](crates/signet-signer-interface/tests/artifact_agreement.rs), [`spec_doc.rs`](crates/minocrab-contracts/tests/serialization/spec_doc.rs), [`ts_codegen.rs`](crates/minocrab-contracts/tests/serialization/ts_codegen.rs) |
| **Wire format** | FAB, the toolchain's field-aligned binary | canonical **Borsh**, restricted to the fixed-width subset — a specified, bijective format with mature parsers in TS/JS/Go/Python/Rust. FAB is spoken too: `persistent_hash_compact` / `transient_hash_compact` and the compat ports | [`spec/borsh-subset.md`](spec/borsh-subset.md), [`spec/vectors/`](spec/vectors), [`serialization_conformance.rs`](crates/minocrab-contracts/tests/serialization_conformance.rs), [`v3_borsh.rs`](crates/minocrab-std/tests/v3_borsh.rs) |
| **Off-chain parsers** | written per language against the artifact | generated from the same declaration, in two languages: Rust (serde + borsh derives over the spec twins) and dependency-free TypeScript | [`spec/ts/`](spec/ts), [`spec/ts/vectors.test.ts`](spec/ts/vectors.test.ts), [`ts_codegen.rs`](crates/minocrab-contracts/tests/serialization/ts_codegen.rs) |
| **Package manager** | none; npm plus relative `node_modules` paths in practice, and no package-manager item on the public roadmap as of Aug 2026 ([sourced](notes/readme-research.org)) | cargo. A callee's interface is an ordinary semver'd crate — crates.io, git or path — and the crate is *checkable* against the deployed artifact | [`signet-signer-interface`](crates/signet-signer-interface/tests/artifact_agreement.rs), [`xcall-target-interface`](crates/xcall-target-interface/tests/artifact_agreement.rs), [`regenerate.rs`](crates/minocrab-interface-gen/tests/regenerate.rs), [`contract_matches_its_interface.rs`](crates/minocrab-contracts/tests/contract_matches_its_interface.rs) |
| **The language** | Compact — its own grammar, compiler and editor support | Rust — modules, generics, `pub`/`pub(crate)`, cargo, rust-analyzer, `#[test]`, the crates.io ecosystem | the workspace itself; [`corpus_roundtrip.rs`](crates/minocrab-zkir/tests/corpus_roundtrip.rs) reads and rewrites all 788 corpus artifacts |
| **Macros** | — | thin decorators only. `#[circuit]`, `#[derive(CircuitArg)]`, `#[derive(CircuitBorsh)]` and `#[interface]` expand to impls a reader could have written; your circuit body is **moved**, not rewritten, so spans, `cargo expand` and rust-analyzer all still work | [`circuit.rs`](crates/minocrab-macros/src/circuit.rs) `the_expansion_calls_no_circuit_method` (the thinness rule); [`v3_derive.rs`](crates/minocrab-std/tests/v3_derive.rs), [`interface_macro.rs`](crates/minocrab-contracts/tests/interface_macro.rs) — derived and hand-written must lower to byte-identical ZKIR |
| **Running a circuit** | proving, or the TypeScript runtime | native execution in `cargo test`: no proving, no keys, instant feedback — from a simulator that mirrors the reference VM instruction for instruction and cross-checks every run against upstream's `IrSource::check` | [`crates/minocrab-sim`](crates/minocrab-sim/src/lib.rs), [`erc20_vault_spec.rs`](crates/minocrab-contracts/tests/erc20_vault_spec.rs) |
| **Cost profiling** | — | a per-region profiler that attributes *rows*, not instruction counts, plus calibrated primitive costs | [`profile()`](crates/minocrab-sim/src/lib.rs), [`cryptocost.rs`](crates/minocrab-sim/examples/cryptocost.rs), [`opcost.rs`](crates/minocrab-sim/examples/opcost.rs), [`borshcost.rs`](crates/minocrab-sim/examples/borshcost.rs) |
| **Circuit families** | `#n` nat parameters in the stdlib | const generics, monomorphized per size and depth and unrolled by rustc: `SignBidirectionalEvent<V, WORDS, LEN_OUT, LEN_RESPOND>`, `MerkleTreePath<V, T, DEPTH>`, `BytesN<V, N>` | [`notes/const-generics.org`](notes/const-generics.org); the row snapshot was written *first* and stayed bit-identical through the retyping ([`row_snapshot.rs`](crates/minocrab-contracts/tests/row_snapshot.rs)) |
| **Proving cost** | the baseline | measured head to head at the same pinned versions on the real sig-net contracts: nine of twelve circuits at least one `k` lower, `respond` 16 → 10 | [BENCHMARK.md](BENCHMARK.md), [`crates/minocrab-bench`](crates/minocrab-bench) |

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

## The macros are decorators, not a compiler

There is a standing rule (`notes/contract-api.org`, M9): **macros only generate
impls a reader could have written by hand.** `#[circuit]` does not compile your
circuit — it wraps a plain Rust function, moves the body verbatim into a private
`fn`, and generates the `CircuitArgs` glue around it. The
[thinness test](crates/minocrab-macros/src/circuit.rs) asserts the expansion
contains no `Circuit3` method call at all:

```rust
/// THINNESS RULE: the scaffolding builds no circuit — `c` is passed to
/// the body function and never called on.
#[test]
fn the_expansion_calls_no_circuit_method() {
    let expanded = expansion(syn::parse_quote! {
        pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, request: DepositRequest) {}
    });
    assert!(!expanded.contains("c ."), "expansion calls a method on the circuit:\n{expanded}");
    assert!(
        !expanded.contains("Circuit3 ::"),
        "expansion calls a Circuit3 associated function:\n{expanded}"
    );
}
```

The consequences are the tooling ones. Errors point at your line, not at an
expansion; `cargo expand` prints something you can read and paste back; every
derive has a hand-written twin in the test suite that must lower to the *same
serialized ZKIR* ([`v3_derive.rs`](crates/minocrab-std/tests/v3_derive.rs),
[`v3_entry.rs`](crates/minocrab-std/tests/v3_entry.rs),
[`interface_macro.rs`](crates/minocrab-contracts/tests/interface_macro.rs)), so a
macro can never quietly do more than the impl it stands in for.

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
them print when the artifact is damaged
([`artifact_agreement.rs`](crates/signet-signer-interface/tests/artifact_agreement.rs),
`mod mutation`):

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
`--check` regenerates and diffs, wired as a test
([`regenerate.rs`](crates/minocrab-interface-gen/tests/regenerate.rs)), so a
hand-edited generated file fails in CI. Regenerating the hand-authored
`signet-signer-interface` reproduced every declaration byte for byte.

**The honest limit.** The *circuit* binds neither the entry point nor the argument
types: entry-point limbs are prover-supplied witnesses and argument limbs are opaque
field elements inside the commitment. The typing protects the developer and the
transaction builder; what protects the **verifier** is the ledger's `(address, entry
point, commitment)` match. `callOnce` and `callEmit` compile to byte-identical ZKIR
under different entry points — asserted by a test, so the limit is executable rather
than a paragraph.

## Serialization: a Borsh subset, not a format of ours

Payloads that cross the wire — request records, the digests an MPC signs, log
payloads — are **canonical Borsh, restricted to the fixed-width subset**. Borsh is
the point: a specified, bijective, widely implemented format with mature parsers in
TypeScript, Go, Python, Rust and more. This is not a dialect of it — every byte is
valid Borsh for the declared types, so `borsh-js` parses it from the same
declarations. The restriction has one cause, that a circuit cannot have
data-dependent layout, and one visible consequence: Compact's `Maybe` is
`Flagged<T>` — a `bool` tag and an always-present payload — never `Option`, whose
Borsh encoding omits the payload on `None`.

The finding that started it: **the deployed protocol is already Borsh.** Midnight's
hashed field-aligned binary, for the all-bytes shapes this protocol uses, IS the
Borsh encoding, byte for byte — both request records (so `requestId ==
keccak256(borsh(record))`), all four attestation preimages, and all three of the
singleton's log payloads, the last verified by handing the bytes to the pinned
compactc artifact, which accepts them and rejects every single-byte perturbation
including in the zero pad. Zero divergences
([`serialization_conformance.rs`](crates/minocrab-contracts/tests/serialization_conformance.rs)).
So most of the deliverable was a specification and a test oracle for what is already
running.

One declaration then gives a circuit its arguments, its range constraints, its hash
preimage, its packed bytes and its offset table — and `#[borsh(spec = …)]` generates
a test cross-checking that layout against borsh's own schema of a plain Rust twin,
so the two declarations of one format cannot drift (from
`crates/minocrab-contracts/tests/serialization_conformance.rs`):

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
`SHA-256(borsh::to_vec(v))` and emits no packing instruction at all.

**Both formats, named at the call site.** `persistent_hash` / `transient_hash` are
the Borsh flavors and the default; `persistent_hash_compact` /
`transient_hash_compact` are FAB — field atoms reduced mod p, compress atoms via
`transient_commit`, the reversed-chunk limbing rule — for digest agreement with a
Compact contract or with Compact-produced off-chain digests. The flavor is always
written module-qualified, so which format a digest is in is visible where it is
taken. The two *persistent* flavors are asserted byte-identical in ZKIR from two
independent descriptions; the two *transient* flavors are asserted genuinely
different digests, which is where the choice is real
([`v3_borsh.rs`](crates/minocrab-std/tests/v3_borsh.rs)).

Where the format changed the protocol, it closed a hazard: attested outputs now
carry a 1-byte **response kind** at offset 0, so a signature attesting a claim
cannot settle a withdrawal, and `success` is a Borsh `bool` — `0|1` and nothing
else — where the deployed contract treats any byte other than `0x01` as failure and
re-mints on a *successful* withdrawal. A non-boolean attestation is now unprovable
rather than refunded, and the three-way divergence between the port, the optimized
fork and the Borsh fork is pinned in both directions
([`erc20_vault_borsh_fork.rs`](crates/minocrab-contracts/tests/erc20_vault_borsh_fork.rs)).
Cost: +6, +6, +9 and −9 rows on the four settle circuits, no `k` boundary moved.

**Parsers are generated, in both languages.** The same schema walk emits three
things and nothing may drift from it:

- **[`spec/borsh-subset.md`](spec/borsh-subset.md)** — grammar, leaf table, reject
  rules, padding rule, response kinds, and per-type byte-offset tables *generated*
  from that walk, with golden vectors in [`spec/vectors/`](spec/vectors).
- **Rust** — the spec twins derive `serde` and `borsh`, so the same declaration is
  a circuit type, a wire format and a plain Rust struct; conformance is a dual
  oracle (borsh and bincode-fixint must agree byte for byte).
- **TypeScript** — [`spec/ts/`](spec/ts): a reader, a writer, the offset table as
  data and a codec registry, **dependency-free** (no npm, no `node_modules`, no
  `package.json`). `getU64(view, 148)` and the spec's table row for
  `tx_params.nonce` come out of one walk emitted twice.

Three tests fail if the committed document stops being that generator's output, two
more if the committed TypeScript does
([`spec_doc.rs`](crates/minocrab-contracts/tests/serialization/spec_doc.rs),
[`ts_codegen.rs`](crates/minocrab-contracts/tests/serialization/ts_codegen.rs)), and
39 node tests decode every vector, check it leaf by leaf against the generated
offset table, re-encode it to the vector's hex and exercise the reject rules
([`spec/ts/vectors.test.ts`](spec/ts/vectors.test.ts)). That suite is
mutation-checked so it cannot be a tautology: shifting one generated offset fails
two of its tests, flipping a `getUint16` to big-endian fails three.

## Porting kit

`corpus/` holds 673 pinned `.compact` sources from the public ecosystem and sig-net,
and the **788 ZKIR circuits** (312 compiled contracts) the pinned compactc produced
from them — sources, revs and per-file compile results all recorded
([`corpus/README.org`](corpus/README.org),
[`corpus/sources.json`](corpus/sources.json)). It is the test bed, and it is also
the porting kit: you (or your LLM) rewrite a contract in the eDSL, and the harness
tells you whether you got it right — against compactc's own artifact, not against
your reading of the source.

The check is **statement identity**, and it is one short function
([`erc20_vault_differential.rs`](crates/minocrab-contracts/tests/erc20_vault_differential.rs)):

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

Both artifacts consume *one shared* `ProofPreimage` and must produce the same typed
schema and the same public-input stream — and both are then handed to Midnight's own
reference VM. The instruction streams are free to differ, which is exactly the room
the optimizer works in; what may not differ is the statement. Guard rejections and
tampered inputs have to agree too, so a port that accepts something compactc rejects
fails as loudly as one that computes the wrong hash.

Every ported circuit is wired this way — the nine erc20-vault circuits, the Signet
singleton, and every experiment in the sig-net corpus including the cross-contract
ones (`crates/minocrab-contracts/tests/*_differential.rs`, plus
[`differential_baseline.rs`](crates/minocrab-ledger/tests/differential_baseline.rs),
[`differential_tiny.rs`](crates/minocrab-std/tests/differential_tiny.rs) and
[`differential_schnorr.rs`](crates/minocrab-std/tests/differential_schnorr.rs)). New
ports join by adding a scenario builder and one `assert_call_compatible` call.

```
cargo test --workspace --release
```

## Safety: what actually stops a mistake

- **A leak is a compile error.** `Wire<Private>` has no path to a public output or a
  ledger operation; `disclose(w, label)` is the only bridge, and the label makes
  every leak greppable. The rule is guarded by a `compile_fail` doctest
  ([`crates/minocrab/src/lib.rs`](crates/minocrab/src/lib.rs)), so the day it stops
  being an error the build breaks.
- **A type is a constraint.** `Uint<64>`, `Bool` and `Bytes<20>` each emit their
  range check from one table ported from compactc's `emit-constraints-for`, and the
  typed form must lower to the byte-identical ZKIR of the hand-written version
  ([`v3_leaves.rs`](crates/minocrab-std/tests/v3_leaves.rs)). You cannot forget the
  constraint, because you cannot spell the argument without it. `Tag<K>` goes one
  step further and adds Borsh's own `< K` variant bound, which no Compact circuit
  emits ([`crates/minocrab-std/src/v3/borsh.rs`](crates/minocrab-std/src/v3/borsh.rs)).
- **9,000,000 property cases.** All nine vault circuits carry a specification in
  ordinary Rust — every branch, every guard — checked at `PROPTEST_CASES=1000000`
  per circuit, with accepted runs re-validated by the reference VM and the resulting
  op streams run through the pinned ledger's own `run_program`
  ([`erc20_vault_spec.rs`](crates/minocrab-contracts/tests/erc20_vault_spec.rs),
  [`notes/vault-optimization.org`](notes/vault-optimization.org)). This asserts
  circuit ≡ *intent*, not merely circuit ≡ compactc. It found real things: a
  non-canonical attested byte that both artifacts accept, an `initialize` that
  accepts an identity MPC response key, a missing counter-overflow guard.
- **Adversarial sweeps beside them.** `2^128 − 1` amounts, zero addresses, malformed
  witnesses, wrong-branch and witness-malleability sweeps, injectivity checks and
  named boundary cases
  ([`erc20_vault_adversarial.rs`](crates/minocrab-contracts/tests/erc20_vault_adversarial.rs)).
- **A bijective format closes a class of bug.** Borsh's `bool` is `0|1` and nothing
  else, so the `0x02` hazard — an attestation byte that is neither true nor false,
  which the deployed contract treats as failure and refunds on — becomes unprovable
  rather than differently-interpreted. Response kinds at offset 0 make cross-circuit
  replay structurally impossible, with its own adversarial property.
- **Differential-tested against compactc's own artifacts.** Same typed schema, equal
  public-input streams on a shared `ProofPreimage`, plus guard-rejection and tamper
  agreement — see the porting kit above.
- **The simulator is never trusted alone.** Every run is cross-checked against
  Midnight's reference VM (`IrSource::check`), end to end and under property tests.
- **Frozen instruments.** The row snapshot and the interface snapshot cover all 78
  workspace circuits, so no change to lowering, labels, types or witnesses is ever
  silent — and the artifact forks (port → optimized → Borsh) each carry a ledger
  saying, per circuit, whether compactc's PI-equality still covers it or the spec
  harness has taken over, asserted in both directions
  ([`erc20_vault_opt_fork.rs`](crates/minocrab-contracts/tests/erc20_vault_opt_fork.rs),
  [`erc20_vault_borsh_fork.rs`](crates/minocrab-contracts/tests/erc20_vault_borsh_fork.rs)).

## Performance

Selected cells from [BENCHMARK.md](BENCHMARK.md) (one session, 2026-08-15, Apple
Silicon; MinoCrab's direct port `mc` vs compactc `cc`, prove = median of 3,
identical statements proved):

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
boundaries. Constraint cuts turn into time and RAM only when they cross a
power-of-two `k` boundary — each crossing roughly halves both — which they did on
nine of the twelve (every circuit but `initialize`, `deposit` and `withdraw`; the
[baseline table](BENCHMARK.md#baseline-layer-port-vs-compactc) is the count).

**Parity is real too**, and the report says so: `initialize` has no byte plumbing and
is identical row for row, and `deposit` (−35% rows) and `withdraw` (−19% rows) prove
in compactc's time and memory, because Halo2's cost is dominated by the padded size
2^k, not the occupied rows.

A third artifact — the M10 optimized vault — cuts 35–58% of rows on every
erc20-vault circuit, but it proves its **own** preimage rather than compactc's, so
its warrant is
symbolic-effect equality plus the 9M-case harness, not PI-equality. BENCHMARK.md
splits the two honestly: the optimizer's own *new* prove-time wins are exactly two
circuits (`deposit` k15→14, `withdraw` k16→15); the rest inherit the port's
crossings, and `swap` missed k15 by 51 rows and was left there.

Full table (all 30 cells, RSS, keygen), methodology and per-region profiles:
[BENCHMARK.md](BENCHMARK.md).

## What Compact has and MinoCrab does not

Only real gaps — things possible in Compact today and not possible here. Each was
checked against the tree before it was listed; the last is an assurance gap rather
than a capability one. Candidates that did not survive the check, and why, are in
[`notes/readme-research.org`](notes/readme-research.org).

- **Bounded integers that are not a power of two.** Compact's `Uint<0..n>` accepts
  any bound — the corpus has `Uint<0..10>`, `Uint<0..300>`, `Uint<0..1000>`,
  `Uint<0..70000>` — and compactc lowers a non-power-of-two bound to `less_than` +
  `assert`. MinoCrab's leaf is `Uint<BITS>`, i.e. `Uint<0..2^BITS − 1>` only
  ([`crates/minocrab-std/src/v3.rs`](crates/minocrab-std/src/v3.rs)). The bounded
  constraint exists on the *interop* side (`Prim::UintMax` → `LimbConstraint::Bounded`,
  [`crates/minocrab/src/v3/abi.rs`](crates/minocrab/src/v3/abi.rs)), so an imported
  interface carrying such an argument is handled correctly; declaring one in your own
  circuit is not possible. A Compact `enum` whose variant count is not a power of two
  falls in this class, since it compiles to `Uint<0..k−1>`.
- **`Opaque<'ts-type'>`.** Compact contracts hold and thread TypeScript-side values
  with no in-circuit representation (`ledger ciphertexts: Opaque<"Uint8Array">`,
  `witness set_local_id(participant: Opaque<"string">)`). MinoCrab has no such type;
  both the ABI reader and the interface generator reject `Opaque` by design
  ([`crates/minocrab-abi/src/info.rs`](crates/minocrab-abi/src/info.rs),
  [`crates/minocrab-interface-gen/src/lib.rs`](crates/minocrab-interface-gen/src/lib.rs)).
- **Ledger ADTs beyond Cell / Counter / Map.** `crates/minocrab-ledger` implements
  cells, counters, maps and `Set::insert`
  ([`crates/minocrab-ledger/src/lib.rs`](crates/minocrab-ledger/src/lib.rs)). Compact
  also has `List`, `MerkleTree` and `HistoricMerkleTree` — 25 `List` and 22
  Merkle-tree ledger declarations in the corpus — and the rest of `Set`. The Merkle
  *path* circuits are ported
  ([`crates/minocrab-std/src/merkle.rs`](crates/minocrab-std/src/merkle.rs)); the
  ledger-state operations on those trees are not.
- **Part of the kernel and the token stdlib.** Ported: `kernel.self`,
  `mintShielded`, the three zswap claims, `claimContractCall`, and the shielded-coin
  circuits the vault needs. Not ported: `kernel.checkpoint`, the block-time family
  (`blockTimeLessThan`/`GreaterThan`, `blockTimeLt`/`Lte`/`Gt`/`Gte`), the whole
  unshielded-token family (`mintUnshielded`, `sendUnshielded`, `receiveUnshielded`,
  `claimUnshieldedCoinSpend`, `incUnshieldedInputs`/`Outputs`, `unshieldedBalance*`),
  `kernel.balance`/`balanceLessThan`/`balanceGreaterThan`, `sendShielded`, and
  `mergeCoin`/`mergeCoinImmediate`. Tracked as M4's REMAINING bullet in
  [`milestones.org`](milestones.org).
- **A machine-checked semantics.** Compact's language has an Agda specification
  in-tree with CI ([sourced](notes/readme-research.org)). MinoCrab's warrant is
  differential and property testing against compactc's own artifacts — strong
  evidence, and not the same thing. We do not claim formal-verification parity.

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

Benchmark, from a clean checkout (nix + direnv supply the pinned toolchain):

```
nix run .#bench
```

## Deeper

`plan.org` (aim and design requirements), `milestones.org` (state of play),
`notes/*.org` (findings and decisions of record — architecture, ZKIR, ledger ABI,
benchmark, contract API, Borsh format, interface crates, const generics, vault
optimization).
