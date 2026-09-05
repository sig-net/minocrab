# MinoCrab

Rust eDSL for Midnight contracts, which can be used instead of Compact.

This whole project is vibe coded. If you use it for Midnight applications that do stuff with money, your users will likely lose it, and neither you nor I will know why.

That being said this is a direct port of the Compact compiler and has millions of tests checking compliance. If you are evaluating this stack seriously, start with these two documents:

- [VERIFICATION.md](VERIFICATION.md) — the steps we take to ensure that this compiler behaves correctly.
- [BENCHMARK.md](BENCHMARK.md) — the performance of this eDSL on the seventeen-circuit vault, proving the identical statement as compactc: every request circuit a `k` level or three lower (prove −44..−81%), the ECDSA-floored settles at parity, the singleton −95..−97%.
 
## Why use this

**Catch many more errors at compile time.** A `Wire<Private>` cannot reach a public output unless you `disclose(w, label)` and name the label in the circuit's signature; a generated test enforces the signature, which caught four real undeclared disclosures ([disclose.rs](crates/minocrab/src/v3/disclose.rs)). Subtraction emits its underflow guard ([`sub`](crates/minocrab-std/src/v3.rs)). A guarded-off read must say what its default means ([`Guarded<T>`](crates/minocrab/src/v3.rs)). A literal outside its operand's bound doesn't build. Argument types are the range constraints: `Uint<64>` *is* `assert_bits(w, 64)`, from compactc's own table ([v3_leaves.rs](crates/minocrab-std/tests/v3_leaves.rs)).

**Use Rust testing, benchmarking and verification tools.** Circuits compile natively and run under `cargo test` for faster CI ([minocrab-sim](crates/minocrab-sim/src/lib.rs)). That makes a property harness against a Rust spec affordable — seventeen properties, five links per case, each accepted run replayed through Midnight's reference VM, the pinned ledger and compactc's own artifact ([erc20_vault_spec.rs](crates/minocrab-contracts/tests/erc20_vault_spec.rs)) — plus adversarial sweeps that found real bugs ([erc20_vault_adversarial.rs](crates/minocrab-contracts/tests/erc20_vault_adversarial.rs)) and a leakage inventory generated from the ZKIR itself ([leakage_inventory.rs](crates/minocrab-contracts/tests/leakage_inventory.rs)). Every ported circuit is differential-tested against compactc's own artifacts ([porting kit](#porting-kit)); `(k, rows)` and the interfaces of all 209 circuits are frozen, so drift is a test failure ([row_snapshot.rs](crates/minocrab-contracts/tests/row_snapshot.rs)). The benchmark reproduces from a clean checkout with a per-region cost profiler and calibrated primitive costs ([BENCHMARK.md](BENCHMARK.md), [cryptocost.rs](crates/minocrab-sim/examples/cryptocost.rs)).

**Low level circuit generation.** MinoCrab emits ZKIR directly, so you can do low level optimisations: native byte instructions instead of explode/rebuild chains, one-block hashes where the preimage fits, Poseidon where the spec permits it. Measured against compactc on the same contracts and the same statement: rows −12..−86% on the vault, prove time −44..−81% wherever a circuit is not floored by protocol-pinned crypto ([BENCHMARK.md](BENCHMARK.md)).

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

The same circuit, abridged from `crates/minocrab-contracts/src/erc20_vault_pending.rs` (the vault on the typed Sig Network API; the instruction-for-instruction port of the Compact source is `erc20_vault.rs`):

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
) -> Discloses<(DepositorCommitment, DepositedErc20, DepositedAmount, Requested)> {
    // assert(amount > 0) — the width is the argument type's, not typed here
    c.assert(deposit_request.amount.gt(0u64));

    // const caller = disclose(userCommitment(callerSecretKey()))
    let sk = common::witness_sk(c);
    let caller = common::commitment_transient(c, &sk).disclose_as::<DepositorCommitment>(c);

    // a Bytes<20> cell: the FAB atoms come from the slot's type
    let vault_evm = VAULT.vault_evm_address.read(c);
    // ... compose the transfer(vaultEvmAddress, amount) transaction ...

    // requestId, freshness check, record + environment insert, the call to
    // the signer — one `Pending` slot owns the whole suspension
    VAULT.deposits.request(c, &VAULT.signet, SignRequest { key_version, path: caller.into(), tx },
        |_, _| DepositEnv { depositor: caller, erc20, amount });
    Discloses::of(())
}
```

- The return type is the disclosure manifest, and a generated test fails if the circuit discloses anything not in it — that is how the four vault circuits were caught publishing a cross-contract call's entry-point hash undeclared ([disclose.rs](crates/minocrab/src/v3/disclose.rs))
- The direct port of the same contract is PI-equal to compactc's own artifact on every circuit — same typed schema, same PI vector on a shared preimage ([erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs)) — and is what the property harness and the adversarial sweeps run ([erc20_vault_spec.rs](crates/minocrab-contracts/tests/erc20_vault_spec.rs)); the `Pending` lineage above is gated on its block layout, its cost against the port, and the round trip through the MPC's own reader ([erc20_vault_pending.rs](crates/minocrab-contracts/tests/erc20_vault_pending.rs), [signet_flow.rs](crates/minocrab-contracts/tests/signet_flow.rs)). See [Cross-chain calls](#cross-chain-calls) for the round trip.

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

Limit: the circuit binds neither the entry point nor the argument types unless it asks to. `callOnce` and `callEmit` compile to byte-identical ZKIR under different entry points, asserted by a test; what protects the verifier there is the ledger's `(address, entry point, commitment)` match. `minocrab_ledger::bind_entry_points(c)` is the opt-in hardened mode — every typed call in that circuit then constrains the entry-point hash to the declared circuit's (two `constrain_eq`), pinned by `xcall::call_once_bound`. Argument types stay unbound.

## Cross-chain calls

A Sig Network cross-chain call is one operation split across two Midnight transactions with an MPC round trip in between: a **request** circuit files the EVM transaction it wants signed and notifies the Signet singleton; the MPC signs it with the contract's derived key, executes it on the EVM chain and attests the call's output back; a **settle** circuit verifies that attestation and finishes the operation, or a **refund** circuit does when the MPC attests that the transaction never executed. `Pending<Env, Resp>` ([signet_flow.rs](crates/minocrab-contracts/src/signet_flow.rs)) makes the two halves one typed value.

A minimal, illustrative shape — a contract that asks the MPC to call `ping()` on an EVM contract and records who may collect the reply:

```rust
/// What the MPC attests back. The kind byte is the type's: a slot of
/// `Pending<_, PingReply>` settles under it and nothing else.
#[derive(CircuitBorsh)]
pub struct PingReply { pub ok: Bool }
impl Response for PingReply { const KIND: u8 = 7; }

/// What crosses the suspension: a commitment to the requester's key,
/// bound to this request. Only `Public` fields and `Commit<_>` unify here.
#[derive(LedgerRepr)]
pub struct PingEnv { pub requester: Commit<SecretKey<Private>> }

#[derive(Ledger)]
pub struct Pinger {
    pub signet: Signet,                        // signer, MPC key, nonce, chain ids
    pub pings: Pending<PingEnv, PingReply, 0>, // request map + env map, one slot
}

/// Transaction 1: file `target.ping()` and notify the singleton.
#[circuit]
pub fn ping(c: &mut Circuit3, evm_nonce: Uint<64>, target: EvmAddress) -> Discloses<(Requested,)> {
    let tx = evm_call(c, &PING_SELECTOR, target, [], evm_nonce, FixedGas::<100_000>::wires(c));
    let sk = witness_sk(c);
    PINGER.pings.request(c, &PINGER.signet, SignRequest { key_version, path: contract_path, tx },
        |c, id| PingEnv { requester: Commit::to::<RequesterCommitment>(c, PAD, &sk, id) });
    Discloses::of(())
}

/// Transaction 2: the MPC attested the reply; only the requester may settle.
#[circuit]
pub fn collect(c: &mut Circuit3, ticket: Settle<PingEnv, PingReply>) -> Discloses<(Settled, Pinged)> {
    let outcome = PINGER.pings.settle(c, &PINGER.signet, ticket); // kind, signature, record + env, removal
    let sk = witness_sk(c);
    outcome.env.requester.open(c, PAD, &sk, outcome.request_id, "not the requester");
    let _ok = outcome.output.ok.disclose_as::<Pinged>(c);
    Discloses::of(())
}

/// Transaction 2': the MPC attested "never executed".
#[circuit]
pub fn abandon(c: &mut Circuit3, ticket: Settle<PingEnv, Failure>) -> Discloses<(Settled,)> {
    let outcome = PINGER.pings.settle_failed(c, &PINGER.signet, ticket);
    let sk = witness_sk(c);
    outcome.env.requester.open(c, PAD, &sk, outcome.request_id, "not the requester");
    Discloses::of(())
}
```

What the type does for the author:

- **Mis-pairing does not compile.** A `Settle<PingEnv, PingReply>` ticket settles `pings` and no other slot; `Settle<PingEnv, Failure>` is the only thing `settle_failed` accepts. The kind check, the version check, the signature check and the removal are inside `settle`, so none can be forgotten.
- **The secret never crosses in the clear.** `Commit::to` stores a Poseidon commitment bound to the request id; `open` on the settle side takes a fresh witness.
- **Nothing is hand-synced with the MPC.** The notification's ledger path is read off the slot; the kind byte is the response type's; the record format version is the API's.

The full flows — burning a shielded coin on request, minting the attested amount on settle, refunding on failure — are the vault's supply, redeem, swap, deposit and withdraw circuits in [erc20_vault_pending.rs](crates/minocrab-contracts/src/erc20_vault_pending.rs); [signet-sim](crates/signet-sim) is the MPC's reader and responder, so a flow round-trips under `cargo test` without an MPC. The cost is the same shape as compactc's for the same operation and lower where the API does less work: `supply` at k14 / 11,474 rows against the port's k15 / 23,038, the settles at k16 within 70 rows of the port ([erc20_vault_pending.rs](crates/minocrab-contracts/tests/erc20_vault_pending.rs) pins every pair).

## Porting kit

- `corpus/` is 673 pinned `.compact` sources and the 806 ZKIR circuits (315 contracts) the pinned compactc produced ([corpus/README.org](corpus/README.org), [sources.json](corpus/sources.json))
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

One session, 2026-09-05, Apple Silicon, pinned toolchain. Port `mc` vs compactc `cc` on the **identical statement** (same schema, same shared preimage, equal public-input streams, proven per circuit by the differential suite); prove = median of 3, RSS = peak of a fresh subprocess.

| circuit | k mc/cc | prove mc | prove cc | RAM mc | RAM cc |
|---|---|---|---|---|---|
| signBidirectional (singleton) | **11 / 16** | **0.14s** | 2.83s | **51MB** | 1,021MB |
| respond (singleton) | **10 / 16** | **0.09s** | 2.69s | **41MB** | 904MB |
| startDeposit | **11 / 14** | **0.15s** | 0.76s | **53MB** | 205MB |
| approveRouter | **11 / 14** | **0.14s** | 0.74s | **54MB** | 223MB |
| startSwap | **15 / 16** | **1.82s** | 3.35s | **674MB** | 1,189MB |
| startRedeem | **15 / 16** | **1.80s** | 3.22s | **615MB** | 1,168MB |
| completeSwap | 16 / 16 | 4.28s | 4.36s | 1.6GB | 1.6GB |
| initialise | 10 / 10 | 0.14s | 0.14s | 49MB | 49MB |

- The Signet singleton — the contract every cross-chain call goes through — proves in **3–4% of compactc's time** at 5–6 `k` levels lower: −97.5% rows on all three circuits
- Every vault request circuit crosses at least one `k` boundary: the 2-word requests (`approveStata`, `approveRouter`, `startDeposit`) drop three levels (k14 → k11, prove −80%); `startSwap` and `startRedeem` drop one (prove −44..−46%)
- Wins come from instruction selection around the protocol's hashes: one `div_mod` at a byte boundary and a native `reverse_bytes` per ABI word where compactc lowers every `Bytes<20>` / `Uint<128>` word through per-byte `div_mod` / `reconstitute_field` chains (~640 rows a word)
- The nine settle circuits cut 12–16% of rows but the secp256k1 verify (~24,450 rows) floors both sides at k16, so their prove time is flat — the port never costs more than compactc, and `initialise` is identical row for row
- All 40 cells, methodology, per-region profiles and the honest limits: [BENCHMARK.md](BENCHMARK.md)

## What Compact has and MinoCrab does not

Only real gaps. Candidates that failed the check are in [notes/readme-research.org](notes/readme-research.org).

- Nested **coin arms** — `insertCoin` / `pushFrontCoin` reached *through* a nested path, e.g. `ms.lookup(k).insertCoin(coin, r)`. Nesting itself landed at M22: `TREASURY.balances.at_key(c, &user).lookup(c, &token)` chains to any depth, over every shape Compact accepts — `Map<K, Map<..>>`, `Map<K, List<V>>`, `Map<K, Set<T>>`, `Map<K, Counter>` and both Merkle trees — with all thirty circuits byte-equal to compactc. (`Map` is the only nestable ADT, and that is *compactc's* kind-checker, not ours: `Set<List<T>>` is its own compile error.) What is missing is only the coin arms at depth: the lowering has them and the `dup` reach is pinned as a function of path length, but no fixture circuit compiles one, so the typed methods stop at declared slots ([the investigation](notes/coin-arms-nested-adts.org)).
- A machine-checked semantics *of the source language's static plumbing*. Compact's in-tree Agda spec machine-checks its syntax representation, typing-rule skeletons and constructor coverage; MinoCrab has no counterpart of that skeleton. Read closely, the spec's semantic content stops there — its arithmetic bound computation is a `TODO` stub, its subtyping a `postulate`-backed placeholder, `disclose` typing-transparent, nothing on ZKIR — while MinoCrab's machine-checked layer runs the other way: Lean models warrant the optimisation passes (reflected as `VerifiedPass`), the numeric bound asserts (sound *and* minimal) and the disclose gate, on top of the differential and property warrant. Both sides' coverage, measured against each other honestly: [VERIFICATION.md](VERIFICATION.md) §5 and [notes/lean-port.org](notes/lean-port.org) §6.

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
corpus/                         673 pinned Compact sources + 806 compactc artifacts
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

**Stability tiers**, concretely (v1 of the boundary — each crate's docs open with its own tier statement):

| tier | what | where |
|---|---|---|
| **stable** | the v3 eDSL authoring core (`Circuit3` + its instruction methods, `Wire3`/`AnyWire3`, the typed leaves, the FAB alignment types, `Compiled3`/`IrSource`) | `minocrab`, `minocrab-std` |
| **stable** | the `Pass` trait + reference passes, the taint lint | `minocrab_ir::v3::{passes, taint}` |
| **stable** | the measurement API: `cost`, `profile`, `assert_max_k`, the calibrated `rowcost` tables, the `minocrab` CLI | `minocrab-sim` |
| **internal** | the raw `Builder3`/`Val` layers, the simulator VMs — gated behind an `unstable` cargo feature | `minocrab-ir`, `minocrab-sim` |
| **internal** | the Impact ledger-op layer, the interface generator | `minocrab-ledger`, `minocrab-interface-gen` |

The `unstable` gate is a hard wall exactly where it matters most: a **pass or lint crate depending on `minocrab-ir` alone** never sees the internals. Graphs that include the full eDSL activate the feature transitively (cargo feature unification), so there the tier lives in the docs and the semver commitment rather than the compiler. The wider contract-authoring surface (ledger declarations, kernel, Borsh, disclosure vocabulary) is *not yet* under the stability promise — the line widens by decision, never by accident.

**Three ways to extend it à la carte, no fork:**

1. **Write a super-optimised gadget** — a crate depending on `minocrab-std` that builds a circuit fragment (a keccak, a Merkle path, an ABI encoder) in fewer rows than the stdlib's. This is the highest-ceiling extension point: the real performance in MinoCrab comes from *typed-layer instruction selection* (native `ReverseBytes`, in-chip keccak packing, `div_mod` byte shifts, guarded read-as-zero), which needs the type information the eDSL has and type-erased ZKIR does not. Prove it equivalent to a reference with the differential / spec harness.

2. **Write an optimisation pass** — implement `minocrab_ir::v3::passes::Pass` (a pure, total `Vec<Instruction> -> (Vec<Instruction>, Vec<String>)`), compose passes as an ordinary `Vec<Box<dyn Pass>>` through `passes::run_pipeline`, and run built-ins by name with `passes::by_name`. Passes see *type-erased* ZKIR, so they are the uniform-transform tail (guards, constants, range constraints) — real, but not where the speed is. **The report is your safety net**: `Pass::run` always returns a `PassReport` whose `warnings` flag anything dangerous — dropping an instruction can move the public-input / witness stream, which is the correctness oracle. A *valid* optimisation can still warn; read it and verify. The built-in passes carry machine-checked "preserves meaning" proofs (Kani-bounded, then Lean unbounded — `crates/minocrab-ir/lean/`), reflected as the `VerifiedPass` marker `passes::run_pipeline_verified` requires; passes are pure/total exactly so a proof can target them — write yours the same way, and cite your own proof with `lean_proof!` if you write one.

3. **Measure** — `minocrab_sim::v3::{cost, profile}` give `(k, rows)` and a region-attributed breakdown; the calibrated primitive-cost tables (`minocrab-sim/examples/`) price individual gadgets.

If you find a good optimisation pass, or circuit, either put it up on cargo, or open a PR if it improves on something in the stdlib. Improvements with lean proofs of equivalence are preferred and may even be merged automatically.

The optimisation levers that cut gate counts are catalogued for gadget authors in [OPTIMIZATION.md](OPTIMIZATION.md) (the measured record behind them is in [notes/benchmark.org](notes/benchmark.org), [notes/vault-optimization.org](notes/vault-optimization.org) and [notes/manager-port.org](notes/manager-port.org)); the library design of record is [notes/library-api.org](notes/library-api.org).
