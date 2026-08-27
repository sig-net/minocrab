# MinoCrab

Rust eDSL for Midnight contracts, which can be used instead of Compact.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose it, and neither you nor I will know why.

That being said this is a direct port of the Compact compiler and has millions of tests checking compliance. If you are evaluating this stack seriously, start with these two documents:

- [VERIFICATION.md](VERIFICATION.md) — the steps we take to ensure that this compiler behaves correctly.
- [BENCHMARK.md](BENCHMARK.md) — the performance of this eDSL, rows −18..−58% against compactc on the vault, prove time −46..−97% amortized.
 
## Why use this

**Catch many more errors at compile time.** A `Wire<Private>` cannot reach a public output unless you `disclose(w, label)` and name the label in the circuit's signature; a generated test enforces the signature, which caught four real undeclared disclosures ([disclose.rs](crates/minocrab/src/v3/disclose.rs)). Subtraction emits its underflow guard ([`sub`](crates/minocrab-std/src/v3.rs)). A guarded-off read must say what its default means ([`Guarded<T>`](crates/minocrab/src/v3.rs)). A literal outside its operand's bound doesn't build. Argument types are the range constraints: `Uint<64>` *is* `assert_bits(w, 64)`, from compactc's own table ([v3_leaves.rs](crates/minocrab-std/tests/v3_leaves.rs)).

**Use Rust testing, benchmarking and verification tools.** Circuits compile natively and run under `cargo test` for faster CI ([minocrab-sim](crates/minocrab-sim/src/lib.rs)). That makes our 9,000,000 property cases against a Rust spec affordable, each accepted run replayed through Midnight's reference VM and the pinned ledger ([erc20_vault_spec.rs](crates/minocrab-contracts/tests/erc20_vault_spec.rs)), plus adversarial sweeps that found real bugs ([erc20_vault_adversarial.rs](crates/minocrab-contracts/tests/erc20_vault_adversarial.rs)). Every ported circuit is differential-tested against compactc's own artifacts ([porting kit](#porting-kit)); `(k, rows)` and the interfaces of all 167 circuits are frozen, so drift is a test failure ([row_snapshot.rs](crates/minocrab-contracts/tests/row_snapshot.rs)). The benchmark reproduces from a clean checkout with a per-region cost profiler and calibrated primitive costs ([BENCHMARK.md](BENCHMARK.md), [cryptocost.rs](crates/minocrab-sim/examples/cryptocost.rs)).

**Low level circuit generation.** MinoCrab emits ZKIR directly, so you can do low level optimisations: native byte instructions instead of explode/rebuild chains, one-block hashes where the preimage fits, Poseidon where the spec permits it. Measured against compactc on the same contracts: rows −18..−58%, prove time −46..−97% amortized ([BENCHMARK.md](BENCHMARK.md)).

**Use standard serialisation formats — or write your own.** Records are a [Borsh](https://borsh.io) subset: a published, stable spec with implementations in many languages, so both ends of the wire are auditable separately. Compact's FAB encoding can still be used for compatibility, and Compact contract interfaces can be imported. All just a standard `Serialize` implementation.

**It's all just Rust.** A mature toolchain: cargo, crates.io, rust-analyzer, `#[test]`, modules and visibility. Circuit families are const generics, monomorphized by rustc ([notes/const-generics.org](notes/const-generics.org)). A deployed contract imports as a typed crate and is checked against the callee's compiled artifact ([interface-gen](crates/minocrab-interface-gen)). You even have macros if that's your cup of tea.

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
    let caller = common::commitment_packed_tag(c, &sk).disclose_as::<DepositorCommitment>(c);

    // a Bytes<20> cell: the FAB atoms come from the slot's type
    let vault_evm = VAULT.vault_evm_address.read(c);
    // ... compose calldata, tx params, request ...

    // requestId, freshness check, map insert, and the call to the signer
    record_and_notify(c, &request, &VAULT.sign_bidirectional_event_map, [0, 0, 0, 0]);
    Discloses::of(())
}
```

- The return type is the disclosure manifest, and a generated test fails if the circuit discloses anything not in it — that is how the four vault circuits were caught publishing a cross-contract call's entry-point hash undeclared ([disclose.rs](crates/minocrab/src/v3/disclose.rs))
- This is identical to the Compact contract (same typed schema, same PI vector on the ports' own preimage) at identical rows and identical `k` ([erc20_vault_modern_fork.rs](crates/minocrab-contracts/tests/erc20_vault_modern_fork.rs))

## Feature by feature

**Argument struct**

```compact
struct DepositRequest {
  erc20Address: Bytes<20>;
  amount: Uint<128>;
}
```
```rust
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}
```

**Circuit** — the return type is the disclosure manifest, enforced by a generated test.

```compact
export circuit deposit(evmNonce: Uint<64>, gasLimit: Uint<64>): [] { /* ... */ }
```
```rust
#[circuit]
pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, gas_limit: Uint<64>) -> Discloses<()> { /* ... */ }
```

**Cost budget** — `max_k` declares the circuit's ceiling in `k` (log2 of the proving-table rows, which is what sets the proving key, the prover's RAM and the wall clock); a generated test prices the circuit with Midnight's own cost model and fails when it goes over. Compact has no equivalent. Needs `minocrab-sim` as a dev-dependency.

```compact
// no equivalent: cost is discovered by compiling and looking
```
```rust
#[circuit(max_k = 14)]
pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, gas_limit: Uint<64>) { /* ... */ }
```

**Assert** — the comparison width comes from the operand's type, never typed at the call site.

```compact
assert(depositRequest.amount > 0 as Uint<128>, "Amount must be positive");
```
```rust
c.assert(deposit_request.amount.gt(0u64).message("Amount must be positive"));
```

**Subtraction** — Compact's compiler inserts `assert(a >= b)` before every `-`; `sub`/`sub_with` emit the same guard, in the same order, at the same width — proven by porting the vault's own subtraction and finding the ZKIR byte-identical against compactc's artifact. The raw `c.add(a, c.neg(b))` still exists for the instruction-mirroring ports, but it is now the unusual spelling.

```compact
const change = amountInMaximum - amountIn;
```
```rust
let change = amount_in_max.sub(c, amount_in);
```

**Disclose** — the label must appear in the circuit's return type, or a generated set-equality test fails.

```compact
const caller = disclose(userCommitment(callerSecretKey()));
```
```rust
let caller = commitment.disclose_as::<DepositorCommitment>(c);
```

**Ledger cell** — the FAB atoms come from the slot's type; nobody writes an atom list at a call site.

```compact
export ledger vaultEvmAddress: Bytes<20>;
// ...
const addr = vaultEvmAddress;
```
```rust
#[derive(Ledger)]
struct Vault { vault_evm_address: LedgerCell<Bytes<20, Public>>, /* ... */ }
// ...
let addr = VAULT.vault_evm_address.read(c);
```

**Ledger map** — one Impact op per method, with `c` visible because a ledger operation is a cost.

```compact
signBidirectionalEventMap.insert(requestId, disclose(request));
assert(!signBidirectionalEventMap.member(requestId), "Request already exists");
```
```rust
VAULT.sign_bidirectional_event_map.insert(c, &request_id, &record);
let exists = VAULT.sign_bidirectional_event_map.member(c, &request_id);
```

**Conditional effects** — reads, witnesses *and* assertions inside the scope inherit the guard; none of them name it.

```compact
if (cond) { /* ... */ }
```
```rust
c.when(cond, |c| { /* ... */ });
```

**Conditional value** — returns `Selected<T>`, a `#[must_use]` that says every arm was paid for.

```compact
const x = cond ? a : b;
```
```rust
let x = c.when_value(cond, |c| a).otherwise(b);
```

**Guarded read** — a guarded-off read yields the type's default and skips the transcript (upstream VM semantics). `Guarded<T>` makes you say which you meant: `.or_default()` costs nothing, `.or(c, alt)` is the hand-written select, `.assert_read(c)` is one assert.

```compact
if (cond) { const record = eventMap.lookup(requestId); /* ... */ }
```
```rust
let record = VAULT.event_map.lookup_guarded(c, cond, &request_id).or_default();
```

**Bounded integer** — compares at compactc's own width; a literal above the bound is rejected at build time; `add`/`mul` carry the result bound in the type, and `narrow` additionally emits a range check at the narrowing seam — an extra guard beyond what the platform requires, stated at ~BITS/4 rows.

```compact
const requestNonce = signetRequestNonce as Uint<64>;   // Uint<0..n> arithmetic tracked by the compiler
```
```rust
let sum = a.add::<499, 200>(c, b);   // BoundedUint<300> + BoundedUint<200> -> BoundedUint<499>
let small = sum.narrow::<8>(c);      // the CHECKED downcast: ~BITS/4 rows, stated
```

**Cross-contract call** — an `#[interface]`-generated typed method; the callee's disclosures must be named in *your* declaration, which is how four undeclared disclosures were caught.

```compact
SignetSigner.signBidirectional(requestId, notification);
```
```rust
SIGNET.sign_bidirectional(c, &request_id, &notification);
```

**Witness** — inside `c.when` a witness does not consume the private transcript on the untaken branch.

```compact
witness callerSecretKey(): Bytes<32>;
```
```rust
let sk = common::witness_sk(c);
```

**Opaque** — the TypeScript type is a Rust type parameter.

```compact
maybeStr: Opaque<"string">
```
```rust
maybe_str: Opaque<Str>   // Str: TsType
```

**Hash** — or `SHA-256(borsh(value))` in one instruction through the Borsh layer.

```compact
persistentHash<Vector<2, Bytes<32>>>([a, b])
```
```rust
c.persistent_hash(alignment, &[a, b]);
borsh::persistent_hash(c, &value)   // digest of the canonical Borsh encoding
```

The two entries worth reading twice are **subtraction** and **guarded read**:
they carry additional safety features on top of the platform's own — the
underflow guard cannot be forgotten, and a possibly-default value cannot be
consumed without saying what the default means. Every such addition costs
zero rows or a stated number, never a hidden one.

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

- Nested **coin arms** — `insertCoin` / `pushFrontCoin` reached *through* a nested path, e.g. `ms.lookup(k).insertCoin(coin, r)`. Nesting itself landed at M22: `TREASURY.balances.at_key(c, &user).lookup(c, &token)` chains to any depth, over every shape Compact accepts — `Map<K, Map<..>>`, `Map<K, List<V>>`, `Map<K, Set<T>>`, `Map<K, Counter>` and both Merkle trees — with all thirty circuits byte-equal to compactc. (`Map` is the only nestable ADT, and that is *compactc's* kind-checker, not ours: `Set<List<T>>` is its own compile error.) What is missing is only the coin arms at depth: the lowering has them and the `dup` reach is pinned as a function of path length, but no fixture circuit compiles one, so the typed methods stop at declared slots ([the investigation](notes/coin-arms-nested-adts.org)).
- A machine-checked semantics. Compact has an Agda spec in-tree with CI; our warrant is differential and property testing — laid out end to end in [VERIFICATION.md](VERIFICATION.md), honest limits included. Not formal-verification parity.

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

## Crates

Nine of those are library crates meant for crates.io: `minocrab-zkir`, `minocrab-ir`, `minocrab`, `minocrab-macros`, `minocrab-std`, `minocrab-ledger`, `minocrab-sim`, `minocrab-abi`, `minocrab-interface-gen`. A contract depends on **`minocrab-std`** (which re-exports the eDSL and the decorators) plus `minocrab-sim` as a dev-dependency. The rest — the corpus rewrite, the bench harness and the two example interface crates — are `publish = false`.

Nothing is published yet: crates.io rejects git dependencies, and every `midnight-*` crate is pinned to a rev the registry does not carry. The plan is to wait for upstream to publish that line. [PUBLISHING.md](PUBLISHING.md) states the blocker, the publish order, and why no fake version keys were added to sneak past it.

## Deeper

`plan.org` (aim and design requirements), `milestones.org` (state of play), `notes/*.org` (findings and decisions of record).

## Using MinoCrab as a library

MinoCrab is a library first — like the [GHC API](https://hackage.haskell.org/package/ghc), it exposes its innards so you build your own tooling *on* it without forking. Two audiences:

- **Rust users** depend on the crates and reach for ordinary Rust performance tooling — `minocrab_sim::v3::profile()` in a `#[test]`, `cargo bench` / criterion, the row snapshot as a regression gate. No bespoke wrapper.
- **Non-Rust users** get a light, compiler-agnostic CLI (the `minocrab` bin in `minocrab-sim`): `minocrab rows <file.zkir>...` and `minocrab diff <a> <b>` report `(k, rows)` over any ZKIR file — MinoCrab's *or* compactc's — so you can see gate counts without writing MinoCrab.

Consume it today as a **git dependency** (crates.io is blocked on upstream — see [PUBLISHING.md](PUBLISHING.md)). The API is **tiered**: a small, stable-*ish* public surface, kept small deliberately while users are few, and an internals tier that may move.

**Three ways to extend it à la carte, no fork:**

1. **Write a super-optimised gadget** — a crate depending on `minocrab-std` that builds a circuit fragment (a keccak, a Merkle path, an ABI encoder) in fewer rows than the stdlib's. This is the highest-ceiling extension point: the real performance in MinoCrab comes from *typed-layer instruction selection* (native `ReverseBytes`, in-chip keccak packing, `div_mod` byte shifts, guarded read-as-zero), which needs the type information the eDSL has and type-erased ZKIR does not. Prove it equivalent to a reference with the differential / spec harness.

2. **Write an optimisation pass** — implement `minocrab_ir::v3::passes::Pass` (a pure, total `Vec<Instruction> -> (Vec<Instruction>, Vec<String>)`), compose passes as an ordinary `Vec<Box<dyn Pass>>` through `passes::run_pipeline`, and run built-ins by name with `passes::by_name`. Passes see *type-erased* ZKIR, so they are the uniform-transform tail (guards, constants, range constraints) — real, but not where the speed is. **The report is your safety net**: `Pass::run` always returns a `PassReport` whose `warnings` flag anything dangerous — dropping an instruction can move the public-input / witness stream, which is the correctness oracle. A *valid* optimisation can still warn; read it and verify. Machine-checked verification of "preserves meaning" is planned (Kani, then Lean), which is exactly why passes are pure/total — write yours the same way.

3. **Measure** — `minocrab_sim::v3::{cost, profile}` give `(k, rows)` and a region-attributed breakdown; the calibrated primitive-cost tables (`minocrab-sim/examples/`) price individual gadgets.

The design of record is [notes/library-api.org](notes/library-api.org); the optimisation levers are catalogued across [notes/benchmark.org](notes/benchmark.org), [notes/vault-optimization.org](notes/vault-optimization.org) and [notes/manager-port.org](notes/manager-port.org).
