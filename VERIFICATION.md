# Verification manifest

What MinoCrab claims to be correct, what proves each claim, which command
re-checks it, and where the chain is deliberately cut. Written for a reviewer
who intends to audit before adopting. Every number below is checkable from a
file in this repo; every command is defined here.

This document is a map of instruments, not an assurance. The README's first
line still stands: this project is vibe coded, and nothing here has run on a
live network.

## 1. The claim

"Correct" here means **statement identity with compactc's own artifacts**,
layered. A MinoCrab circuit and the compactc circuit for the same contract are
*call-compatible* when they have the same typed input/output schema, produce
identical `Preprocessed::pis` / `pi_skips` when both are evaluated on one shared
`ProofPreimage`, and accept and reject the same preimages
([notes/ledger-abi.org §6](notes/ledger-abi.org)). That one criterion subsumes
the Impact op sequence, the read expectations, the communications commitment and
the guard/skip behaviour — so two circuits satisfying it prove the same
statement about the same on-chain state transition, whatever their instruction
streams look like. Where a lineage deliberately leaves that criterion — the
optimised, Borsh and modern vault forks prove their **own** preimage — the
anchor becomes a Rust specification executed against the pinned ledger, and the
substitution is recorded per circuit in a divergence ledger the build asserts in
both directions. So: compactc artifacts at the bottom, a reference-VM
cross-check on every accepted run, differential equality where it is claimed,
spec-and-property anchoring where it is not, and type-level constructions that
make specific error classes unwritable rather than merely untested.

## 2. The warrant chain, layer by layer

### (a) ZKIR bindings round-trip

- **Claim** — every artifact the pinned compactc produces parses, re-emits and
  re-parses through our bindings without loss.
- **Instrument** — [corpus_roundtrip.rs](crates/minocrab-zkir/tests/corpus_roundtrip.rs)
  over all 788 `.zkir` in `corpus/zkir` (722 v2 + 66 v3), plus
  [toolchain_accepts.rs](crates/minocrab-zkir/tests/toolchain_accepts.rs), a
  hand-built circuit through the pinned `zkir mock-compile`.
- **Command** — `cargo test -p minocrab-zkir`
- **Why it is first** — it is the most fundamental instrument in the tree; if it
  is red, nothing downstream tells you anything new
  ([notes/version-bump.org §Drift taxonomy 3](notes/version-bump.org)).

### (b) Simulator cross-checked against Midnight's reference VM

- **Claim** — the native simulator is never trusted alone.
- **Instrument** — every accepted run is re-validated by upstream's own
  `IrSource::check` on the same `ProofPreimage`, and the returned `pi_skips`
  must equal the simulator's. This is inside `assert_call_compatible` (quoted in
  the [README porting kit](README.md#porting-kit)) and is link 4 of the spec
  harness's per-case checks
  ([erc20_vault_spec.rs](crates/minocrab-contracts/tests/erc20_vault_spec.rs)).
- **Consequence** — a MinoCrab simulator bug cannot hide a circuit bug; the two
  would have to agree on the same wrong answer.
- **Command** — any differential target, e.g.
  `cargo test -p minocrab-contracts --test erc20_vault_differential`

### (c) Differential equality against compactc

- **Claim** — for every ported circuit, our artifact and compactc's prove the
  same statement.
- **Criterion** — same typed I/O schema, identical `pis`/`pi_skips` on a shared
  preimage, agreement on guard rejections and on tampered inputs. Instruction
  streams are explicitly free ([notes/ledger-abi.org §6](notes/ledger-abi.org)).
- **Instrument** — 19 test targets named `*differential*` across
  `minocrab-contracts`, `minocrab-ledger` and `minocrab-std`.
- **Stronger, for five fixtures** — `adts` (31 circuits), `bounded`, `opaque`
  (14 circuits), `kernel` (24 circuits) and `coins` (3 circuits) compare
  **instruction for instruction**: every opcode, immediate, `ins` depth and
  branch skip, up to identifier renaming
  ([adts_differential.rs](crates/minocrab-contracts/tests/adts_differential.rs),
  [kernel_tokens_differential.rs](crates/minocrab-contracts/tests/kernel_tokens_differential.rs)).
- **The normalisation, stated** — since our `fold_immediate_copies` pass runs on
  every circuit, those five differentials run the **same pass over compactc's
  artifact** before comparing. Their criterion is therefore "identical
  instruction for instruction, **modulo the naming of constants**". compactc's
  choice to name a constant rather than inline it is frontend-driven and carries
  no rows, no public input and no semantics; the normaliser is the shipping pass
  itself, not a test-local approximation. This is an explicit approved
  judgement, recorded with its two structural preconditions — no caller can hold
  a pointer into the wire namespace, and the two out-of-band identifier holders
  (the `Output` terminator and the disclosure record) are both excluded
  ([notes/ir-passes.org §8](notes/ir-passes.org)).
- **Command** — `cargo test --workspace`

### (d) The four-artifact fork chain

Four artifacts of the same erc20-vault, in a chain, each link gated:

| link | criterion | gate |
|---|---|---|
| compactc ≡ port | PI-equality on a shared preimage | [erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs) |
| port ≡ opt | byte-identity, or a declared divergence | [erc20_vault_opt_fork.rs](crates/minocrab-contracts/tests/erc20_vault_opt_fork.rs) |
| opt ≡ borsh | byte-identity, or a declared divergence | [erc20_vault_borsh_fork.rs](crates/minocrab-contracts/tests/erc20_vault_borsh_fork.rs) |
| borsh ≡ modern | `Twin::Identical` — instruction-identical modulo naming, all nine, since the constant fold; `PiEqual` (stream differs, statement does not) remains the vocabulary a future rewrite must adopt explicitly | [erc20_vault_modern_fork.rs](crates/minocrab-contracts/tests/erc20_vault_modern_fork.rs) |

- **The divergence ledger discipline** — the `vault::artifact` ledgers
  (`fork_status`, `borsh_fork_status`, `modern_fork_status`, one per link)
  record per circuit which criterion applies. Each fork test asserts the ledger in **both
  directions**: an `Identical` entry really is byte-identical *and* still
  PI-equal to compactc on the reference model's preimage; a `Diverged` entry
  really does differ. A change that moves a circuit without moving its ledger
  entry fails the build, so leaving compactc's coverage is always an explicit,
  reviewable edit ([notes/vault-optimization.org §"Step 4"](notes/vault-optimization.org)).
- `Twin::SpecAnchored` is asserted **unused** in the modern fork, so a future
  rewrite that moves a public input has to declare it before it can land.
- **Command** — `cargo test -p minocrab-contracts --test erc20_vault_opt_fork
  --test erc20_vault_borsh_fork --test erc20_vault_modern_fork`

### (e) The spec and property harness

- **Claim** — for all nine vault circuits, on generated inputs, the circuit does
  what a Rust specification says, and the ledger agrees.
- **Four independent links per generated case**
  ([erc20_vault_spec.rs](crates/minocrab-contracts/tests/erc20_vault_spec.rs)):
  1. acceptance agreement — spec (a total function) and circuit agree both ways;
  2. PI-equality re-anchored to `Op::field_repr` of **our** reference op stream,
     so the check survives an artifact that deviates from compactc;
  3. ledger execution — the same op stream runs through the pinned Impact VM
     (`QueryContext::query` / `run_program`, `ResultModeVerify`) against a real
     pre-state, and the `Effects` must be exactly the ones the spec declared;
  4. reference VM — `IrSource::check` on every accepted run.
- **Scale, executed** — `PROPTEST_CASES=1000000` across all nine circuits plus
  the adversarial suite: 9 passed, 0 failed, **9,000,000 cases**, 3,121.83 s
  wall, exit 0 ([notes/vault-optimization.org §"Full-scale gating run"](notes/vault-optimization.org)).
  Every property runs against **all four artifacts** since the fork.
- **Adversarial** — 22 tests in
  [erc20_vault_adversarial.rs](crates/minocrab-contracts/tests/erc20_vault_adversarial.rs):
  PI tamper sweeps, witness malleability (out-of-range key limbs, garbage
  `recoveryId`, `s = 0`, `r`/`s` above the curve order, a point at infinity),
  wrong-branch and double-settle, re-mapping injectivity, and six named
  boundary tests on `completeSwap`'s `amountInMaximum − amountIn`.
- **What the sweeps pinned**, as evidence they are not decorative: an identity
  `mpcResponseKey` authenticates any signature and `initialize` does not reject
  one (deployer-gated, one-shot); at `signetRequestNonce == u64::MAX` every
  circuit assert passes and only the Impact VM refuses; a **forged membership
  answer** yields a valid proof and is caught only by
  `ResultModeVerify::process_read` — the single best argument for the
  `run_program` link existing at all; ECDSA `s = 0` aborts rather than returning
  false, and `(r, n − s)` rejects. All are now tests. The property run's first
  execution also caught a bug in the reference model itself
  ([notes/vault-optimization.org §"Findings the sweeps pinned"](notes/vault-optimization.org)).
- **Commands** — default (48 cases/property, keeps the workspace under 90 s):
  `cargo test -p minocrab-contracts --test erc20_vault_spec --test erc20_vault_adversarial`.
  Elevated: `PROPTEST_CASES=20000 cargo test --release -p minocrab-contracts
  --test erc20_vault_spec --test erc20_vault_adversarial` (also `./bump.sh gates
  --heavy`). Full gate: the same with `PROPTEST_CASES=1000000`, ~52 min.

### (f) Disclosure enforcement

- **Claim** — a `Wire<_, Private>` cannot reach a public output without
  `c.disclose(w, label)`, and the set of labels a circuit publishes is declared
  in its signature.
- **Type level** — leaking a private wire is a compile error
  ([compile_fail doctest](crates/minocrab/src/lib.rs)).
- **Manifest level** — a `#[circuit]`'s return type `Discloses<(..)>` is the
  disclosure manifest; the macro emits a generated **set-equality** test per
  circuit (`assert_declared_disclosures`), so a circuit that discloses something
  not in its manifest fails the build
  ([disclose.rs](crates/minocrab/src/v3/disclose.rs),
  [v3_disclose.rs](crates/minocrab-std/tests/v3_disclose.rs), 6 tests).
- **Zero-movement rule** — a declaration is type-level only: the same circuit
  with and without one must lower to byte-identical ZKIR.
- **What it caught, twice** — four vault circuits were publishing a
  cross-contract call's entry-point hash undeclared; the rollout to the
  experiments then found every cross-contract caller doing the same, plus
  `xcontract_events::deposit_via_vault` publishing the callee's result. Nine
  signatures gained `XcallEntryPointHash` / `XcallCommitment` / `XcallResult`
  ([notes/contract-api.org §"M9 closure"](notes/contract-api.org)).
- **Valued report** — the simulator resolves each disclosure to the value it
  took on a real preimage
  ([disclosure_report.rs](crates/minocrab-contracts/tests/disclosure_report.rs)).

### (g) Type-level guarantees — what each makes unwritable

Each is a construction, not a lint. The right-hand column is what a programmer
cannot express.

| construction | makes unwritable | gate |
|---|---|---|
| `Wire<T, Vis>` + `Meet` | a private value reaching a public output without `disclose` | compile_fail doctest, [lib.rs](crates/minocrab/src/lib.rs) |
| `Discloses<..>` manifest | disclosing a label the signature does not name | generated set-equality tests |
| `Guarded<T>` | consuming a guarded-off read without saying what the default means (`.or_default()` / `.or(c, alt)` / `.assert_read(c)`) | [notes/ir-passes.org §10](notes/ir-passes.org); 19 sites had to choose |
| `Uint::sub` / `sub_with` | a field subtraction with no underflow guard — emits `assert(a >= b)` + `neg` + `add`, at the width read off the type | [v3_bounded.rs](crates/minocrab-std/tests/v3_bounded.rs); the vault's only subtraction was ported to it and **the ZKIR dump did not move** |
| `BoundedUint<BOUND>` `add`/`mul` | a result bound too small to hold the value — an inline-const `E0080` at the call site; bound arithmetic is `checked_*`, so an overflowing bound is itself a compile error | [v3_bounded.rs](crates/minocrab-std/tests/v3_bounded.rs), [bounded_differential.rs](crates/minocrab-contracts/tests/bounded_differential.rs) |
| `BoundedUint::narrow::<BITS>` | an unchecked narrowing downcast — MinoCrab **additionally emits** the range check at this seam (one `Prim::Uint { bits }`, ~BITS/4 rows), and asking `narrow` for the free direction is an `E0080` pointing at `to_uint` | [v3_bounded.rs](crates/minocrab-std/tests/v3_bounded.rs) |
| `CheckOperand::MAX` | a comparison against a literal outside the operand's bound (which would make the comparison constant) | [v3_predicates.rs](crates/minocrab-std/tests/v3_predicates.rs), 22 tests |
| `ContractAddress<Public>` | passing an arbitrary `B32` where `kernel.self()` was meant; only `kernel::self_address` and its guarded twin produce one | zero rows, dump unchanged ([notes/api-safety-survey.org §A4](notes/api-safety-survey.org)) |
| `Opaque<T: TsType>` | mixing two TypeScript-side types | compile_fail doctest, [v3.rs](crates/minocrab-std/src/v3.rs) |
| `from_field_unchecked` | *nothing* — it is the escape hatch, named as an assertion. `from_field_checked(c, w)` is the constrained twin (`Uint`, `BoundedUint`, `Bool`, `Bytes`, Borsh `Tag<K>`); there is no bare `from_field` left, so every site chose | [notes/api-safety-survey.org §A1](notes/api-safety-survey.org) |
| guard scoping | an assertion or witness inside `c.when` escaping the guard — the ambient guard reaches reads, witnesses and assertions, none of which name it | [v3_guard_scope.rs](crates/minocrab-std/tests/v3_guard_scope.rs), 20 tests, each asserting the scoped form is byte-identical to the hand-threaded one |

The Borsh layer belongs here as a safety feature in its own right:

- The record format is a **published specification** ([spec/borsh-subset.md](spec/borsh-subset.md),
  628 lines, generated region between markers so it cannot drift), with golden
  vectors ([spec/vectors](spec/vectors), 5 files) and an **independent
  implementation in another language** generated from the same source of truth
  ([spec/ts](spec/ts), 39 node tests). Both ends of the wire are auditable
  separately and checked against each other.
- The subset is **fixed-width**: `borsh::object_length(v) == T::LEN` for all
  `v`, and `T::LEN` equals the deployed FAB alignment's own `bin_len` — so every
  offset is a compile-time constant and there is no value-dependent branching.
- A Borsh `bool` is `0` or `1` and nothing else, so on that lineage a
  non-canonical attested byte is **unprovable rather than refunded**
  ([erc20_vault_borsh_fork.rs](crates/minocrab-contracts/tests/erc20_vault_borsh_fork.rs)).
- Dual oracle: `borsh::to_vec(v) == bincode-fixint(v)` for every spec type over
  generated values, closed against the **deployed bytes** themselves — the
  singleton's `Misc` envelope is handed to the pinned compactc artifact, which
  accepts it and rejects it as soon as any one of the 288 bytes moves, including
  a byte of the zero pad ([notes/borsh-format.org §"stage 0"](notes/borsh-format.org)).

- **Commands** — `cargo test -p minocrab-std`;
  `cargo test -p minocrab-contracts --test serialization_conformance` (29 tests);
  `cargo test -p minocrab-contracts --test serialization_conformance -- --ignored the_typescript_vectors_pass`

### (h) The zero-movement instruments, and their blind spots

Three frozen instruments guard against unintended movement. Each is stated with
what it **cannot** see and which instrument covers that.

| instrument | freezes | cannot see | covered by |
|---|---|---|---|
| [row_snapshot.rs](crates/minocrab-contracts/tests/row_snapshot.rs) | `(k, rows)` for **167 circuits** | a removed `Copy` of an immediate (measured at 0 rows); an argument reorder (a reorder costs nothing) | the ZKIR dump; the interface snapshot |
| [interface_snapshot.rs](crates/minocrab-contracts/tests/interface_snapshot.rs) | the ordered `in`/`out`/`wit` `(label, type)` list of the same 167 circuits | a constraint added or removed; anything inside the instruction stream | the row snapshot; the differentials |
| [zkir_dump.rs](crates/minocrab-contracts/tests/zkir_dump.rs) | nothing by itself — it is an **instrument**, ignored by default: it dumps every circuit's serialized ZKIR for byte-comparison across a change | anything about *meaning*; it says the stream moved, not whether the move was sound | the differentials and the spec harness |
| the differentials | statement identity on **honest** preimages | a **missing guard or range check** — invisible on well-formed input | the type-level constructions in (g), and the survey method in §5 |

The pairing was demonstrated, not asserted — synthetic drift, Exercise C of the
bump dry run ([notes/version-bump.org](notes/version-bump.org)). **C1**, one
duplicated `assert` in `deposit`: row snapshot FAILS (`+10` rows, named), all 30
differentials PASS, interface snapshot PASSES. **C2**, two same-typed arguments
swapped: interface snapshot FAILS with the reorder named, 1 of 30 differentials
FAILS on a public transcript input, row snapshot PASSES. C1 moves rows and not
PIs; C2 moves PIs and not rows. Neither instrument alone catches both.

- **Commands** — `cargo test --release -p minocrab-contracts --test row_snapshot
  --test interface_snapshot`; for the dump, the two-checkout procedure in
  [zkir_dump.rs](crates/minocrab-contracts/tests/zkir_dump.rs)'s header:
  `MINOCRAB_ZKIR_DUMP=<dir> cargo test -p minocrab-contracts --test zkir_dump --
  --ignored dump_every_circuits_zkir`, then `diff -rq before after`.

## 3. Failure class → instrument map

Raw material: the drift taxonomy in [notes/version-bump.org](notes/version-bump.org).

| failure class | fires | silent |
|---|---|---|
| wrong instruction stream, same statement | row snapshot; zkir dump; the four instruction-for-instruction fixtures | the differentials (instruction streams are free under PI-equality) |
| wrong PI framing / transcript shape | the 18 differential targets; spec-harness link 2 (PI re-anchored to our op stream) | row snapshot (a reorder costs no rows) |
| missing guard, assert or range check | the type-level constructions in §2(g); `v3_predicates`; `v3_guard_scope`; row snapshot (as a *row* delta, not a diagnosis) | every differential on an honest preimage — this is the class the API safety survey was commissioned to hunt by reading, not by testing |
| witness-stream drift (a read on the untaken branch) | interface snapshot (`wit` lines, `(guarded)` marked); the differentials, once the private transcript diverges | row snapshot, if the counts happen to match |
| undeclared disclosure | the generated set-equality test per circuit | everything else — the labels are not in the ZKIR |
| range-constraint gap at a typed seam | `v3_bounded` / `v3_leaves` / `v3_entry` (the argument types *are* the constraints); interface-crate check 6 (constraint prefix, slot for slot) | the differentials; the row snapshot sees only a row delta |
| upstream drift after a version bump | in diagnosis order: `cargo metadata` → workspace build → corpus compile report → ZKIR round-trip → ABI/Impact baseline → workspace → row snapshot → spec/vectors/TS → elevated property run | — `./bump.sh gates` runs exactly this sequence and prints the taxonomy line for whatever fired |
| spec divergence between the four artifacts | the fork tests' divergence ledger, asserted in both directions; the spec harness runs every property against all four | a fork test that was never given a ledger entry — which is why a moved circuit with an unmoved entry fails the build |
| interface-crate drift vs a deployed callee | `artifact_agreement.rs` — six checks, hash-pinned artifact, 9 mutation cases proving the checker bites | the circuit binds neither entry point nor argument types (§5) |
| generated code out of date (interface crates, spec, TS, snapshots) | `cargo test -p minocrab-interface-gen` (byte-for-byte regeneration); `serialization_conformance`'s three drift tests | — `./bump.sh accept` regenerates all of them in dependency order |

## 4. Reproducibility and supply chain

- **Toolchain by hash.** `flake.nix` pins `compactcVersion = "0.33.0-rc.2"` with
  a per-architecture `compactcHashes` entry (`sha256-NaKACcmlfSCQLk/…` for
  `aarch64-darwin`), fetched from the upstream release URL. Nix supplies
  **binaries only** — compactc, `zkir`/`zkir-v3`, node, the Rust toolchain. The
  build itself is plain `cargo`; nothing in this repo is built by nix.
- **One rev for the whole stack.** All ~11 `midnight-*` crates and both
  `[patch.crates-io]` entries pin the same 40-character rev
  `04c9c5d9bcebb8d4427d8589fb54d58a55599c14` — never a tag, because a version
  string is not a rev (two artifacts reporting `3.0.0-rc.2` can be different
  code). The authority is the rev the compact release's own `flake.lock` pins
  for the binaries it ships; `./bump.sh pins` prints it.
- **The rev is a hypothesis; the corpus is the proof.** Our pin equals neither
  rev upstream pins, because all `midnight-*` crates must share one for their
  `Fr` / `ProofPreimage` / `IrSource` types to unify. What makes that safe is
  instrument (a): 788 of compactc's own artifacts round-trip through these
  bindings, and 18 differential suites agree with its lowering.
- **Deterministic corpus.** `corpus/` holds 673 pinned `.compact` sources and
  the 788 ZKIR circuits (312 contracts, 618 circuit names) the pinned compactc
  produced. Recompiling at HEAD with the same compiler: `compiled 312/478 OK`
  in 3 m 11 s, and **zero of the 788 artifacts moved** (`git status --short
  corpus/zkir` → nothing). That is what makes a post-bump diff readable: every
  changed artifact is a change the new compiler made
  ([notes/version-bump.org §Dry run D1](notes/version-bump.org)).
- **`accept` is idempotent, and lands reviewable diffs.** At HEAD it rewrote two
  `contract-info.json`, two `pin.json`, two `interface-schema.txt`, two
  generated `src/lib.rs`, the generated region of `spec/borsh-subset.md`, five
  `spec/vectors/*.json`, seven `spec/ts/` files and both snapshot tables — and
  `git status` afterwards listed **not one** of them (exit 0, 8 m 03 s). The
  snapshot tables are rewritten in place between `GENERATED BEGIN` /
  `GENERATED END` markers, so a new baseline arrives as a diff rather than a
  paste; the pin and the accepted baselines are two commits, not one, and every
  line of the second needs a reason.
- **Cost of the loop, measured.** `pins` ~15 s; corpus recompile 3 m 11 s;
  `gates` on a green tree ~6–9 min; `accept` a few minutes. A bad pin is
  rejected in **2 seconds** by dependency resolution and **7.2 seconds** by the
  build stage.
- **Known floating input.** `flake.nix` pins `rust-bin.stable.latest.default`,
  so `nix flake update` can move rustc with no diff in our files (1.97.1 at time
  of writing). Nothing in the tree needs a feature newer than min-const-generics.
- **Commands** — `./bump.sh pins` (needs network) · `./corpus/compile.sh` ·
  `./bump.sh gates [--heavy]` · `./bump.sh accept` · `./bench.sh` or
  `nix run .#bench`

## 5. The honest limits

- **No machine-checked semantics.** Compact ships an Agda specification in-tree
  with CI; MinoCrab has no formal-verification parity. The compensating control
  is the differential warrant (§2c/d) plus the property warrant (§2e), and — for
  the class differentials structurally cannot see — the **method** of
  [notes/api-safety-survey.org §0](notes/api-safety-survey.org): look where a
  test on well-formed input cannot see the error, namely (a) invariants stated
  in prose (`PRECONDITION`, "the caller's job" — grep is a complete enumeration)
  and (b) rules the platform applies automatically that we leave to the author.
  Three bugs of that class were found and fixed in one session: guarded
  witnesses consuming the private transcript on the untaken branch, assertions
  inside a branch not inheriting the guard, and a literal outside its operand's
  bound making a comparison constant. **All three were green on every
  differential the day before.** That is the honest measure of differential
  coverage.
- **The opt / borsh / modern lineage proves its own preimage.** It is
  spec-anchored, and that is a **weaker** warrant than PI-equality on a shared
  preimage. What replaces PI-equality: symbolic-effect equality over a shared
  term algebra, `run_program` post-state and `Effects` agreement, an
  injectivity assertion on the re-mapping between differing terms over the
  generated corpus, the 9,000,000-case sweep, and a burn well-formedness gate
  driven through the pinned ledger's own `Transaction::well_formed`. It is
  machinery, not prose — and it is still weaker. It is labelled per circuit in
  the divergence ledgers and throughout [BENCHMARK.md](BENCHMARK.md). Read
  opt's numbers as "same operation, re-framed, proved cheaper", never as "same
  statement, proved cheaper".
- **Nothing has run end to end on a live network.** Keygen, prove and verify go
  through Midnight's own `Zkir` with hash-verified SRS parameters, so the proofs
  are real; but no MinoCrab verifier key has been deployed in a
  `ContractOperation`, and binding an artifact to a deployed address needs
  keygen that is out of scope so far
  ([notes/interface-crates.org §"Honest limits" #3](notes/interface-crates.org)).
  Planned, not done.
- **Cross-contract calls: the circuit binds neither the entry point nor the
  argument types.** `callOnce` and `callEmit` compile to byte-identical ZKIR
  under different entry points, asserted by a test. What protects the verifier
  is the ledger's `(address, entry point, commitment)` match.
- **Known unported constructs** — the three `insertCoin` / `pushFrontCoin` arms
  (`Set`, `Map`, `List` when the element type is `QualifiedShieldedCoinInfo`);
  nested ADTs (every ledger op assumes a top-level field, which is what path
  suppression rests on); `kernel.checkpoint()`, which is outside our ZKIR-v3
  target; and the hashing sweep family, whose WIDTH is a Rust parameter the
  benchmark sweeps rather than a ported circuit set.
- **The circuit list is hand-written, and nothing yet checks it is complete.**
  `support::circuits()` — 167 entries — is the only statement of which circuits
  exist, and it feeds both snapshots, the dump instrument and the adversarial
  suite. Nothing asserts that every `#[circuit]` in the workspace appears in it;
  the snapshots guard the opposite direction only. A circuit added and not
  listed is covered by nothing. The fix in progress is `#[contract]`, which
  derives the set from the impl block (first adopter: `kernel_tokens`, 24
  circuits) ([notes/review-queue.org](notes/review-queue.org)).
- **The Borsh injectivity obligation is preventable, not prevented.**
  `Serializer::constrained()` plus `Circuit3::dedup_range_constraints` make
  constrain-on-construction **free** — proven by byte-identical serialized ZKIR
  in [v3_dedup.rs](crates/minocrab-std/tests/v3_dedup.rs) — but the flag is off
  on every shipped artifact, and every corpus caller still relies on its
  arguments being constrained at entry. Scanning all 863 `.zkir` in the repo for
  a range constraint implied by an earlier one on the same wire finds **zero**,
  so turning the flag on today would remove nothing
  ([notes/ir-passes.org §11](notes/ir-passes.org)).
- **Four `from_field_unchecked` sites rest on a whole-contract argument.** The
  vault's settle mints claim `Uint<64>` on a word locally bounded only to
  `< 2^128`; the claim holds because every request circuit bounds its amounts
  before a record enters the map — an invariant of the contract as a whole, not
  of the site. Each carries a comment saying so, and they are first in line for
  the checked spelling
  ([notes/api-safety-survey.org §B4, §A1](notes/api-safety-survey.org)).
- **Not covered by the safety survey at all** — the `minocrab-ir`/ZKIR boundary,
  cross-contract argument marshalling beyond the shared constraint path, the
  macros' generated code for anything other than shape, and the proving system.
  `AssertMessage` and region indices are recorded at build time, so an IR pass
  that removes an instruction shifts them; pre-existing, not fixed.
- **Bench numbers are one session on one machine.** Rows, `k`, proof size and
  RSS are deterministic; wall-clock prove is a median of 3 and sub-second cells
  are noise-dominated. Single-shot proves swing up to 3× with machine state.

## 6. How to audit this repo in a day

**Morning — run the gates, cheapest and most diagnostic first.**

1. `./bump.sh pins` — see the four pins and what upstream currently offers (~15 s, needs network).
2. `cargo test -p minocrab-zkir` — 788 artifacts round-trip. If this is red, stop.
3. `cargo test -p minocrab-ledger` — entry-point hash rule over 312 contracts / 618 circuit names, plus the Impact op baseline.
4. `cargo test --workspace` — the 18 differentials, the fork gates, the artifact-agreement suites, the disclosure set-equality tests, `serialization_conformance`.
5. `cargo test --release -p minocrab-contracts --test row_snapshot --test interface_snapshot` — the two frozen tables.
6. `PROPTEST_CASES=20000 cargo test --release -p minocrab-contracts --test erc20_vault_spec --test erc20_vault_adversarial` — the elevated property run (~a few minutes). The full gate is `PROPTEST_CASES=1000000`, ~52 minutes, and is the number quoted in §2(e).
7. `./corpus/compile.sh` — recompile the corpus with the pinned compiler and check `git status --short corpus/zkir` is empty (3 m 11 s). This is the determinism claim, verified rather than trusted.

Or, in one command with a PASS/FAIL/seconds summary and a taxonomy line per
failure: `./bump.sh gates --heavy`.

**Midday — read the arguments, in this order.**

1. [notes/ledger-abi.org §6](notes/ledger-abi.org) — the equivalence criterion. Everything else is downstream of this one page.
2. [notes/version-bump.org](notes/version-bump.org) §"Drift taxonomy" and Exercise C — what each instrument means when it fires, and the demonstration that C1 and C2 are caught by different instruments.
3. [notes/api-safety-survey.org](notes/api-safety-survey.org) — the method, the findings, and which fixes are built. §0 is the part to read even if you read nothing else.
4. [notes/vault-optimization.org](notes/vault-optimization.org) §"Verification-harness design" and §"As built — step 1" — the chain of trust and the harness that makes links 2–4 machinery.
5. [notes/ir-passes.org](notes/ir-passes.org) §0 (the measurement), §8 (the constant-naming normalisation and its approval), §11 (dedup, and why no shipped artifact flips the flag).
6. [BENCHMARK.md](BENCHMARK.md) §"Three sides, three comparability claims" — where the warrant weakens and why.

**Afternoon — grep the escape hatches.** Each is deliberately greppable; that
is the design. Run these against `crates/*/src`:

```
grep -rn 'from_field_unchecked'      # the unchecked type claim; the twin is from_field_checked
grep -rn '\.field()'                 # a typed leaf becoming a raw wire — the range obligation drops here
grep -rn 'or_default()'              # a guarded-off read consumed as the type's default
grep -rnE 'disclose(_as)?\('         # every private→public transition, each declared in a signature
grep -rnE 'PRECONDITION|caller.s job'  # invariants in prose rather than checked — the survey's seam (a)
grep -rn 'dedup_range_constraints'   # the checked-construction profile; off on every shipped artifact
```

Then compare a change of your own against the baseline with the ZKIR dump
procedure in [zkir_dump.rs](crates/minocrab-contracts/tests/zkir_dump.rs)'s
header — the only instrument that sees an instruction reorder at equal row count.

**If you have an evening.** `nix run .#bench` re-runs the differential tests,
dumps corpus-verified preimages for all three benched sides, proves all 30 cells
and writes `target/bench/results.json` plus per-region cost profiles. The
per-primitive calibration behind "the vault is hash-bound" is
`cargo run -p minocrab-sim --example cryptocost` and `--example opcost`.
