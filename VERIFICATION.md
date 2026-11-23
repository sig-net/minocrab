# Verification manifest

What MinoCrab claims to be correct, what proves each claim, which command re-checks it, what each gate means when it fires, and where the chain is deliberately cut. Written for a reviewer who intends to audit before adopting. Every command is defined here; every test file named exists in the tree.

This document is a map of instruments, not an assurance. The README's status paragraph still stands: this project is vibe coded, and nothing here has run on a live network.

## 1. The claim

"Correct" here means **statement identity with compactc's own artifacts**, layered. A MinoCrab circuit and the compactc circuit for the same contract are *call-compatible* when they have the same typed input/output schema, produce identical `Preprocessed::pis` / `pi_skips` when both are evaluated on one shared `ProofPreimage`, and accept and reject the same preimages ([notes/ledger-abi.org §6](notes/ledger-abi.org)). Call this PI-equality. That one criterion subsumes the Impact op sequence, the read expectations, the communications commitment and the guard/skip behaviour, so two circuits satisfying it prove the same statement about the same on-chain state transition, whatever their instruction streams look like.

Where a lineage deliberately leaves that criterion (the `erc20_vault_pending` lineage, the API's own expression of the protocol, proves its **own** preimage) the anchor becomes the reference model's op stream executed against the pinned ledger, and each of its circuits is pinned pair by pair to the compat port's cost.

So: compactc artifacts at the bottom, a reference-VM cross-check on every accepted run, differential equality where it is claimed, spec-and-property anchoring where it is not, and type-level constructions that make specific error classes unwritable rather than merely untested. **Zero movement** is the default expectation for any change to the API: the serialized ZKIR of every circuit is byte-identical across it, proven by dump comparison (§2h), not claimed.

## 2. The warrant chain, layer by layer

### (a) ZKIR bindings round-trip

- **Claim**: every artifact the pinned compactc produces parses, re-emits and re-parses through our bindings without loss.
- **Instrument**: [corpus_roundtrip.rs](crates/minocrab-zkir/tests/corpus_roundtrip.rs) over the `.zkir` files in `corpus/zkir` (the count is asserted), [lean_roundtrip.rs](crates/minocrab-zkir/tests/lean_roundtrip.rs) (byte-exact Lean syntax), plus [builder.rs](crates/minocrab-ir/tests/builder.rs), a hand-built circuit through the pinned `zkir-v3 mock-compile`.
- **Command**: `cargo test -p minocrab-zkir` and `cargo test -p minocrab-ir --test builder`
- **Why it is first**: it is the most fundamental instrument in the tree; if it is red, nothing downstream tells you anything new ([notes/version-bump.org §Drift taxonomy 3](notes/version-bump.org)).

### (b) Simulator cross-checked against Midnight's reference VM

- **Claim**: the native simulator is never trusted alone.
- **Instrument**: every accepted run is re-validated by upstream's own `IrSource::check` on the same `ProofPreimage`, and the returned `pi_skips` must equal the simulator's. This is inside `minocrab_sim::assert_call_compatible`, is link 2 of the Pending lineage's property harness ([erc20_vault_pending_spec.rs](crates/minocrab-contracts/tests/erc20_vault_pending_spec.rs)) and link 3 of the executor gate ([executor_vault.rs](crates/minocrab-contracts/tests/executor_vault.rs)).
- **Consequence**: a MinoCrab simulator bug cannot hide a circuit bug; the two would have to agree on the same wrong answer.
- **Command**: any differential target, e.g. `cargo test -p minocrab-contracts --test erc20_vault_differential`

### (c) Differential equality against compactc

- **Claim**: for every ported circuit, our artifact and compactc's prove the same statement.
- **Criterion**: PI-equality (§1) plus agreement on guard rejections and on tampered inputs. Instruction streams are explicitly free.
- **Instrument**: the `*differential*` test targets in `minocrab-contracts` (for example [erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs), [adts_differential.rs](crates/minocrab-contracts/tests/adts_differential.rs), [bounded_differential.rs](crates/minocrab-contracts/tests/bounded_differential.rs)) and [differential_baseline.rs](crates/minocrab-ledger/tests/differential_baseline.rs) in `minocrab-ledger`. A new port adds a scenario builder and one `assert_call_compatible` call.
- **Stronger, for seven fixtures**: `adts`, `bounded`, `opaque`, `kernel`, `coins`, `nested` (nested ledger ADTs) and `wide` (the sixteen-field ledger block, which is where `#[derive(Ledger)]`'s segmentation is checked against compactc's) compare **instruction for instruction**: every opcode, immediate, `ins` depth and branch skip, up to identifier renaming ([adts_differential.rs](crates/minocrab-contracts/tests/adts_differential.rs), [kernel_tokens_differential.rs](crates/minocrab-contracts/tests/kernel_tokens_differential.rs)).
- **The normalisation, stated**: since our `fold_immediate_copies` pass (a `Copy` of an immediate is a rename) runs on every circuit, those differentials run the **same pass over compactc's artifact** before comparing. Their criterion is therefore "identical instruction for instruction, **modulo the naming of constants**". compactc's choice to name a constant rather than inline it is frontend-driven and carries no rows, no public input and no semantics; the normaliser is the shipping pass itself, not a test-local approximation. This is an explicit approved judgement, recorded with its two structural preconditions (no caller can hold a pointer into the wire namespace, and the two out-of-band identifier holders, the `Output` terminator and the disclosure record, are both excluded; [notes/ir-passes.org §8](notes/ir-passes.org)).
- **Command**: `cargo test --workspace`

### (d) The two lineages

Two artifacts of the same erc20-vault (the three optimisation forks of the earlier nine-circuit vault are retired; [notes/vault-refresh.org §0](notes/vault-refresh.org) has the verdict and the three reasons, each sufficient alone):

| lineage | criterion | gate |
|---|---|---|
| compactc ≡ `erc20_vault` (the compat port: 29 circuits on the flush pattern, at erc20-vault v0.7.0-rc.2) | PI-equality on a shared preimage, every circuit, every branch | [erc20_vault_differential.rs](crates/minocrab-contracts/tests/erc20_vault_differential.rs) |
| `erc20_vault_pending` (the typed EVM-call API) | proves its own preimage: the reference model's op stream through the pinned ledger; the V2 record and kind-tagged outputs of [spec/borsh-subset.md](spec/borsh-subset.md) | [erc20_vault_pending_spec.rs](crates/minocrab-contracts/tests/erc20_vault_pending_spec.rs) (one property per circuit, four links); [erc20_vault_pending.rs](crates/minocrab-contracts/tests/erc20_vault_pending.rs), each request/settle pair pinned to the port's `(k, rows)`; the record bytes and ids in [serialization_conformance.rs](crates/minocrab-contracts/tests/serialization_conformance.rs) and [signet_flow.rs](crates/minocrab-contracts/tests/signet_flow.rs) |

- **What the Pending lineage is not**: PI-equal to compactc. It writes the V2 record (a version byte and a kind byte where the deployed record carries two ABI-JSON schema strings), so no compactc artifact proves its statement. Read its costs as "same operation, re-framed, proved cheaper", never as "same statement, proved cheaper". What stands in for the missing link: the per-pair cost pins against the port, the record-byte and request-id equalities, the reader/responder round trip in `signet-sim`, and the interface snapshot. [BENCHMARK.md](BENCHMARK.md) labels each circuit's comparability.
- **What the leakage inventory adds to both**: [leakage_inventory.rs](crates/minocrab-contracts/tests/leakage_inventory.rs) walks the port's ZKIR statically and freezes, per circuit, every declared component's provenance, every witness's guard / checks / reach, every digest's operands and every Impact operand's accounting. Its completeness gate refuses a witness-dependent wire reaching the public statement without a declared label, and its corpus-twin gate asserts compactc's artifact has the same surface counts ([notes/zkir-semantics.org §7.2](notes/zkir-semantics.org)). [leakage_inventory_pending.rs](crates/minocrab-contracts/tests/leakage_inventory_pending.rs) does the same walk for the Pending lineage.
- **Command**: `cargo test -p minocrab-contracts --test erc20_vault_differential --test erc20_vault_pending --test leakage_inventory`

### (e) The spec and property harness

- **The flush vault has no property harness yet.** What gates `erc20_vault` today is the differential of (c) and (d): per circuit, PI-equality against compactc's artifact on the reference model's preimage, the guard failures both artifacts must reject, and a tamper sweep over every transcript and witness element with zero acceptance disagreements. Its inputs are hand-built scenarios, not generated ones (the scenario builders are in `tests/vault/model.rs`). The property harness and adversarial families for it are open work.
- **Claim, for the Pending lineage**: for every `erc20_vault_pending` circuit, on generated inputs, the circuit does what a Rust specification says and the ledger agrees. There is no compactc link: this lineage has no compactc twin.
- **Four links per generated case** ([erc20_vault_pending_spec.rs](crates/minocrab-contracts/tests/erc20_vault_pending_spec.rs)):
  1. acceptance agreement: the spec (a total function) and `simulate` agree on accept or reject;
  2. reference VM: `IrSource::check` on every accepted run, with `pi_skips` equal to the simulator's;
  3. PI-equality re-anchored to **our** op stream: the preimage's transcript is `Op::field_repr` of the reference op stream, and the PI vector is exactly that transcript plus the skipped Impacts' zeros;
  4. ledger execution: the same op stream runs through the pinned Impact VM against a real pre-state, must fit the guaranteed section, and the `Effect`s it produced must be exactly the ones the spec declared.
- **The executor gate** ([executor_vault.rs](crates/minocrab-contracts/tests/executor_vault.rs), the same generators): the transcript `minocrab_sim::exec` derives from ledger state must equal the hand model's op for op (each `popeq`'s expected value included); both public transcript halves and the communications commitment must equal the model's; `IrSource::check` must accept the executor's preimage; its post-state must equal the model's; and a case the spec rejects must be rejected by the executor (or, for a counter at its maximum, refused by the ledger exactly as the model's op stream is).
- **Scale**: 48 cases per property by default (`DEFAULT_CASES` in `tests/vault_pending/gen.rs`); the nightly job runs both files at `PROPTEST_CASES=100000` in release ([nightly.yml](.github/workflows/nightly.yml)) and `./bump.sh gates --heavy` at 20,000. Scale figures recorded for retired harnesses ([notes/vault-refresh.org §1](notes/vault-refresh.org), [notes/vault-optimization.org §"Full-scale gating run"](notes/vault-optimization.org)) are history and are not claimed for either current vault.
- **What the retired sweeps pinned**: the old adversarial suite found that an identity `mpcResponseKey` authenticates any signature, that at `signetRequestNonce == u64::MAX` only the Impact VM refuses, that a forged membership answer yields a valid proof caught only by `ResultModeVerify::process_read`, and that ECDSA `s = 0` aborts rather than returning false; the first property run also caught a bug in the reference model itself ([notes/vault-optimization.org §"Findings the sweeps pinned"](notes/vault-optimization.org)). Those tests were removed with the suite and are not claimed for the flush vault until a successor re-establishes them.
- **Commands**: default `cargo test -p minocrab-contracts --test erc20_vault_pending_spec --test executor_vault`. Elevated: `PROPTEST_CASES=2000 cargo test --release -p minocrab-contracts --test erc20_vault_pending_spec --test executor_vault` (or `./bump.sh gates --heavy`). The wall clock scales linearly with the count.

### (f) Disclosure enforcement

- **Claim**: a `Wire<_, Private>` cannot reach a public output without `c.disclose(w, label)`, and the set of labels a circuit publishes is declared in its signature.
- **Type level**: leaking a private wire is a compile error ([compile_fail doctest](crates/minocrab/src/lib.rs)).
- **Manifest level**: a `#[circuit]`'s return type `Discloses<(..)>` is the disclosure manifest; the macro emits a generated **set-equality** test per circuit (`assert_declared_disclosures`), so a circuit that discloses something not in its manifest fails the build ([disclose.rs](crates/minocrab/src/disclose.rs), [disclose.rs](crates/minocrab-std/tests/disclose.rs)).
- **Zero-movement rule**: a declaration is type-level only: the same circuit with and without one must lower to byte-identical ZKIR.
- **What it caught, twice**: four vault circuits were publishing a cross-contract call's entry-point hash undeclared; the rollout to the experiments then found every cross-contract caller doing the same, plus `xcontract_events::deposit_via_vault` publishing the callee's result. Nine signatures gained `XcallEntryPointHash` / `XcallCommitment` / `XcallResult` ([notes/contract-api.org §"M9 closure"](notes/contract-api.org)).
- **Valued report**: the simulator resolves each disclosure to the value it took on a real preimage ([disclosure_report.rs](crates/minocrab-contracts/tests/disclosure_report.rs)).

### (g) Type-level guarantees: what each makes unwritable

Each is a construction, not a lint. The middle column is what a programmer cannot express.

| construction | makes unwritable | gate |
|---|---|---|
| `Wire<T, Vis>` + `Meet` | a private value reaching a public output without `disclose` | compile_fail doctest, [lib.rs](crates/minocrab/src/lib.rs) |
| `Discloses<..>` manifest | disclosing a label the signature does not name | generated set-equality tests |
| `Guarded<T>` | consuming a guarded-off read without saying what the default means (`.or_default()` / `.or(c, alt)` / `.assert_read(c)`) | [notes/ir-passes.org §10](notes/ir-passes.org) |
| `Uint::sub` / `sub_with` | a field subtraction with no underflow guard: emits `assert(a >= b)` + `neg` + `add`, at the width read off the type | [bounded.rs](crates/minocrab-std/tests/bounded.rs); the vault's only subtraction was ported to it and **the ZKIR dump did not move** |
| `BoundedUint<BOUND>` `add`/`mul` | a result bound too small to hold the value: an inline-const `E0080` at the call site; bound arithmetic is `checked_*`, so an overflowing bound is itself a compile error | [bounded.rs](crates/minocrab-std/tests/bounded.rs), [bounded_differential.rs](crates/minocrab-contracts/tests/bounded_differential.rs) |
| `BoundedUint::narrow::<BITS>` | an unchecked narrowing downcast: MinoCrab **additionally emits** the range check at this seam (one `Prim::Uint { bits }`, ~BITS/4 rows), and asking `narrow` for the free direction is an `E0080` pointing at `to_uint` | [bounded.rs](crates/minocrab-std/tests/bounded.rs) |
| `CheckOperand::MAX` | a comparison against a literal outside the operand's bound (which would make the comparison constant) | [predicates.rs](crates/minocrab-std/tests/predicates.rs) |
| `ContractAddress<Public>` | passing a bare `B32` where `kernel.self()` was meant: the `_with` twins take the typed address. NOT a proof of self: `ContractAddress` is Compact's value type and is built from any `B32` in a dozen places. The proof of self is `kernel::SelfAddress`, a private-field newtype only the `self_address*` readers produce, taken by the helpers that act AS the contract (`contract_recipient`, `burn_body`); `.address()` is the way down to the value type ([notes/api-safety-survey.org §3 item 5](notes/api-safety-survey.org)) | zero rows, dump unchanged ([notes/api-safety-survey.org §A4](notes/api-safety-survey.org)) |
| `Opaque<T: TsType>` | mixing two TypeScript-side types | compile_fail doctest, [leaves.rs](crates/minocrab-std/src/leaves.rs) |
| `from_field_unchecked` | *nothing*: it is the escape hatch, named as an assertion. `from_field_checked(c, w)` is the constrained twin (`Uint`, `BoundedUint`, `Bool`, `Bytes`, Borsh `Tag<K>`); there is no bare `from_field`, so every site chose | [notes/api-safety-survey.org §A1](notes/api-safety-survey.org) |
| guard scoping | an effect inside `c.when` escaping the guard: every witness read, transcript read, Impact op and check (`assert`, `assert_eq`, `assert_bits`, `assert_boolean`) resolves its guard through ONE private choke point ([effects.rs](crates/minocrab/src/effects.rs)); the scope is the only spelling of a conditional outside the four core primitives it lowers to, and a value read inside a scope comes back as a `Guarded` that must be resolved | [guard_scope.rs](crates/minocrab-std/tests/guard_scope.rs), each case asserting the scoped form is byte-identical to the core primitives' hand-threaded form |

The Borsh layer belongs here as a safety feature in its own right:

- The record format is a **published specification** ([spec/borsh-subset.md](spec/borsh-subset.md), generated region between markers so it cannot drift), with golden vectors ([spec/vectors](spec/vectors)) and an **independent implementation in another language** generated from the same source of truth ([spec/ts](spec/ts)). Both ends of the wire are auditable separately and checked against each other.
- The subset is **fixed-width**: `borsh::object_length(v) == T::LEN` for all `v`, and `T::LEN` equals the deployed FAB alignment's own `bin_len`, so every offset is a compile-time constant and there is no value-dependent branching.
- A Borsh `bool` is `0` or `1` and nothing else, so a non-canonical attested byte is **unprovable rather than refunded**: on the Pending lineage and the treasury through `AbiReturn for Bool` (`treasury.rs` `a_non_boolean_attestation_neither_completes_nor_refunds`), and on the vault port as in compactc 0.36 (`erc20_vault_differential.rs` `complete_*_constrains_the_bool_output`).
- Dual oracle: `borsh::to_vec(v) == bincode-fixint(v)` for every spec type over generated values, closed against the **deployed bytes** themselves: the signet signer's `Misc` envelope is handed to the pinned compactc artifact, which accepts it and rejects it as soon as any one of the 288 bytes moves, including a byte of the zero pad ([notes/borsh-format.org §"stage 0"](notes/borsh-format.org)).
- **Commands**: `cargo test -p minocrab-std`; `cargo test -p minocrab-contracts --test serialization_conformance`; `cargo test -p minocrab-contracts --test serialization_conformance -- --ignored the_typescript_vectors_pass`

### (h) The zero-movement instruments, and their blind spots

Three frozen instruments guard against unintended movement. Each is stated with what it **cannot** see and which instrument covers that.

| instrument | freezes | cannot see | covered by |
|---|---|---|---|
| [row_snapshot.rs](crates/minocrab-contracts/tests/row_snapshot.rs) | `(k, rows)` for all **227 circuits** | a removed `Copy` of an immediate (measured at 0 rows); an argument reorder (a reorder costs nothing) | the ZKIR dump; the interface snapshot |
| [interface_snapshot.rs](crates/minocrab-contracts/tests/interface_snapshot.rs) | the ordered `in`/`out`/`wit` `(label, type)` list of the same circuits | a constraint added or removed; anything inside the instruction stream | the row snapshot; the differentials |
| [zkir_dump.rs](crates/minocrab-contracts/tests/zkir_dump.rs) | nothing by itself: it is an **instrument**, ignored by default, that dumps every circuit's serialized ZKIR for byte-comparison across a change | anything about *meaning*: it says the stream moved, not whether the move was sound | the differentials and the spec harness |
| the differentials | statement identity on **honest** preimages | a **missing guard or range check**, invisible on well-formed input | the type-level constructions in (g), and the survey method in §5 |

The pairing was demonstrated, not asserted: synthetic drift, Exercise C of the bump dry run ([notes/version-bump.org](notes/version-bump.org)). **C1**, one duplicated `assert` in `deposit`: row snapshot FAILS (`+10` rows, named), every differential PASSES, interface snapshot PASSES. **C2**, two same-typed arguments swapped: interface snapshot FAILS with the reorder named, one differential FAILS on a public transcript input, row snapshot PASSES. C1 moves rows and not PIs; C2 moves PIs and not rows. Neither instrument alone catches both.

- **Commands**: `cargo test --release -p minocrab-contracts --test row_snapshot --test interface_snapshot`; for the dump, the two-checkout procedure in [zkir_dump.rs](crates/minocrab-contracts/tests/zkir_dump.rs)'s header: `MINOCRAB_ZKIR_DUMP=<dir> cargo test -p minocrab-contracts --test zkir_dump -- --ignored dump_every_circuits_zkir`, then `diff -rq before after`.
- **Regenerating a table is a reviewable diff, never a paste.** Every snapshot has a regenerator that writes its table back between `GENERATED` markers: `cargo test -p minocrab-contracts --test row_snapshot -- --ignored regenerate_row_snapshot`, `cargo test -p minocrab-contracts --test interface_snapshot -- --ignored regenerate_interface_snapshot`, `MINOCRAB_TAINT_BASELINE=1 cargo test -p minocrab-contracts --test taint_lint`, and `MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base` for [TRUST.md](TRUST.md). `./bump.sh accept` runs every regenerator in dependency order.

## 3. Failure class → instrument map, and what a firing gate means

The drift taxonomy in [notes/version-bump.org](notes/version-bump.org) names the instruments, what a failure in each one *means*, and which of four responses is right (accept the new baseline, fix your change, repin, investigate upstream). It was written for toolchain bumps but applies to any firing. The table is the same idea indexed by failure class.

| failure class | fires | silent |
|---|---|---|
| wrong instruction stream, same statement | row snapshot; zkir dump; the leakage inventory's surface counts | the differentials (instruction streams are free under PI-equality) |
| wrong PI framing / transcript shape | the differential suites; spec-harness link 2 (PI re-anchored to our op stream) | row snapshot (a reorder costs no rows) |
| missing guard, assert or range check | the type-level constructions in §2(g); `predicates`; `guard_scope`; row snapshot (as a *row* delta, not a diagnosis) | every differential on an honest preimage: this is the class the API safety survey was commissioned to hunt by reading, not by testing |
| witness-stream drift (a read on the untaken branch) | interface snapshot (`wit` lines, `(guarded)` marked); the differentials, once the private transcript diverges | row snapshot, if the counts happen to match |
| undeclared disclosure | the generated set-equality test per circuit | everything else: the labels are not in the ZKIR |
| a secret reaching the public statement under no declared label | [leakage_inventory.rs](crates/minocrab-contracts/tests/leakage_inventory.rs) (completeness gate: witness provenance × label taint over the ZKIR, per Impact operand) | the set-equality tests (they check the label SET, not what the labels cover); the differentials (an honest preimage leaks the same either way) |
| a hash-preimage limb not provably bounded | the taint lint, [taint_lint.rs](crates/minocrab-contracts/tests/taint_lint.rs) | every test on honest inputs |
| a circuit added and not listed | [circuit_closure.rs](crates/minocrab-contracts/tests/circuit_closure.rs) (every `#[circuit]` under `src/` is in `support::circuits()`); a `#[contract]` block derives its set | an `entry()`-built family with no attribute: listed by hand, with a comment saying why |
| range-constraint gap at a typed seam | `bounded` / `leaves` / `entry` (the argument types *are* the constraints); interface-crate check 6 (constraint prefix, slot for slot) | the differentials; the row snapshot sees only a row delta |
| upstream drift after a version bump | in diagnosis order: `cargo metadata`, workspace build, corpus compile report, ZKIR round-trip, ABI/Impact baseline, workspace, row snapshot, spec/vectors/TS, elevated property run | `./bump.sh gates` runs exactly this sequence and prints the taxonomy line for whatever fired |
| the Pending lineage drifting from the port's statement | the per-pair cost pins in `erc20_vault_pending.rs`; the record-byte and request-id equalities in `serialization_conformance` and `signet_flow.rs`; the interface snapshot | PI-equality: the lineage does not claim it (§2d) |
| interface-crate drift vs a deployed callee | `artifact_agreement.rs` in each interface crate: six checks, a hash-pinned artifact, nine mutation cases proving the checker bites | the circuit does not bind argument types (§5) |
| generated code out of date (interface crates, spec, TS, snapshots) | `cargo test -p minocrab-interface-gen` (byte-for-byte regeneration); `serialization_conformance`'s drift tests | `./bump.sh accept` regenerates all of them in dependency order |

What to do when each gate fires, beyond the taxonomy:

- **A moved ZKIR byte** needs the commit message to say *which* circuits moved, *by how much*, and *why that is the intended change* (`git log --grep "byte-identical"` shows the house style). Zero movement needs no words. Movement you cannot explain is a bug in your change, not an acceptable cost. CI runs the dump comparison against your PR's base.
- **The taint lint** fires when a hash-preimage limb is not provably bounded, the class no test on honest inputs can see. **Never allowlist.** Either extend the marking rules in `minocrab-taint/src/lib.rs` with a *cited in-circuit warrant*, or take the finding to the maintainers. [notes/taint-lint.org](notes/taint-lint.org) classifies the frozen baseline; read the baseline as a list of open questions, not as accepted findings.
- **A differential suite** disagreeing with compactc means the port's statement changed. That is never routine.
- **Clippy** (`cargo clippy --workspace --all-targets -- -D warnings`, the `clippy` CI job) is STYLE: fix the finding zero-movement (the dump says whether it moved anything), or allow it at the site with a one-line reason. No crate-wide allows. The two lints that fight the tree's deliberate shapes, `type_complexity` (a circuit's `Discloses<(…)>` IS its declaration) and `unusual_byte_groupings` (literals keep their artifact's grouping), are decided once in the root `Cargo.toml` `[workspace.lints]`, and every crate opts in with `[lints] workspace = true`.
- **The interface semver job** (`interface-wire-compat-semver`, PRs only) is WIRE COMPATIBILITY, not style: an interface crate's surface is governed by the callee's deployed artifact, so a reported break means the wire moved. Stop, and read `tests/artifact_agreement.rs` in the crate it names; regenerate nothing until you know why.
- **The supply-chain job** (`cargo deny check`, the `deny` CI job, `deny.toml`) is SUPPLY CHAIN: a firing advisory means a real RUSTSEC finding on something we depend on (fix it or, if genuinely inapplicable, add a reasoned entry to `[advisories.ignore]`, never a bare skip); a firing license or source means a new dependency outside the tree's actual license/source posture (extend the allow list only after confirming the license or host by hand, never widen it with a wildcard). [notes/supply-chain.org](notes/supply-chain.org) has the rationale and every current ignore's reason.

## 4. Reproducibility and supply chain

- **Toolchain by hash.** `flake.nix` pins the compactc version with a per-architecture hash entry, fetched from the upstream release URL. Nix supplies **binaries only** (compactc, `zkir-v3`, node, the Rust toolchain). The build itself is plain `cargo`; nothing in this repo is built by nix.
- **The ledger.** Every `midnight-*` crate comes from crates.io with no `[patch.crates-io]`, and `Cargo.lock` records each crate's checksum ([PUBLISHING.md](PUBLISHING.md) states the versions). `midnight-zkir`'s sources are the ones the pinned compactc's own `flake.lock` pins for its bundled `zkir-v3`; `./bump.sh pins` prints both sides.
- **The pin is a hypothesis; the corpus is the proof.** What makes it safe is instrument (a): the corpus artifacts round-trip through these bindings, and the differential suites agree with compactc's lowering.
- **Deterministic corpus.** `corpus/` holds the pinned `.compact` sources and the ZKIR circuits the pinned compactc produced ([corpus/README.org](corpus/README.org)). Recompiling with the same compiler moves **zero artifacts** (`git status --short corpus/zkir` shows nothing; the weekly CI job checks it). That is what makes a post-bump diff readable: every changed artifact is a change the new compiler made ([notes/version-bump.org §Dry run D1](notes/version-bump.org)).
- **`accept` is idempotent and lands reviewable diffs.** The snapshot tables are rewritten in place between `GENERATED BEGIN` / `GENERATED END` markers, so a new baseline arrives as a diff rather than a paste; the pin and the accepted baselines are two commits, not one, and every line of the second needs a reason.
- **Known floating input.** `flake.nix` pins `rust-bin.stable.latest.default`, so `nix flake update` can move rustc with no diff in our files. Nothing in the tree needs a feature newer than min-const-generics.
- **Commands**: `./bump.sh pins` (needs network) · `./corpus/compile.sh` · `./bump.sh gates [--heavy]` · `./bump.sh accept` · `./bench.sh` or `nix run .#bench`. `pins` answers "is there anything to take?"; `gates` runs the instruments in diagnosis order; `accept` regenerates everything into a reviewable diff. The workflow, the four independent pins and the hazards are in [notes/version-bump.org](notes/version-bump.org); treat any surprise as taxonomy, not noise.

## 5. The honest limits

- **Machine-checked semantics: partial, model-level, and honestly bounded.** Compact ships an Agda specification in-tree with CI. Read at our pinned rev, its checked content is well-formedness plumbing (syntax representation, typing-rule skeletons, constructor coverage) while the semantic content that would matter here is absent: arithmetic result types are `⊢undeclared` stubs ("TODO: define bound computation"), subtyping is a refl/trans stub with a load-bearing `postulate`, `disclose` types through with no visibility judgment, the operational semantics is an unchecked sketch, and nothing covers ZKIR ([notes/lean-port.org §6](notes/lean-port.org) is the full account). MinoCrab's machine-checked layer is Lean **models**: the pass contract (subsequence/passthrough/solution-set/idempotence for constraint dedup; skeleton/observables preservation for copy folding, reflected as `VerifiedPass`); the dedup half is stated over the *real* ZKIR v3 instruction set: `crates/minocrab-zkir/lean/` defines the 38-instruction syntax that round-trips every v3 corpus artifact byte for byte against compactc's own printer, a dataflow that agrees with the Rust `operands_mut` family on every corpus instruction, and the evaluation semantics of `preprocess` with the intrinsics uninterpreted, each gated from `cargo test` and CI ([notes/zkir-semantics.org](notes/zkir-semantics.org) is the design of record and its §9 the honest state of each rung). **The boundary of that layer, stated plainly:** machine-checked is the GROUND: the syntax, the dataflow, the evaluation reading with hashes and curve operations as uninterpreted functions, the pass theorems over it, and the vault's leakage inventory derived from it (§2d). NOT machine-checked: the executable intrinsics (Poseidon, SHA-256, Keccak and the curve arithmetic made concrete and differentially gated against the reference VM: in progress), any statement about what a commitment HIDES (that is the cryptographic assumption on Poseidon and the hybrids of the unlinkability analysis, which no inventory can discharge), and the running Rust itself. The semantics' AUTHORITY is external and two-linked: every corpus artifact round-trips through the Lean syntax byte for byte against compactc's own printer, and the Rust reference the semantics transcribes (`ir_vm.rs` at the pinned blob) is the one every differential and property run agrees with. A transcription error the corpus does not exercise is invisible to both links; that is the honest measure of the ground layer. Beside it sit the numeric/visibility invariants behind the typed leaves (`crates/minocrab-std/lean/`: the `add`/`mul` bound asserts proven sound *and minimal*, the subtraction guard proven to make field subtraction integer subtraction, the disclose gate proven sound and complete over a small expression model). These warrant the *algorithms and rules as modelled*, not the running Rust; the transcription gap is stated in every proof file's header, and extraction is the only thing that would close it. For everything the models do not reach, the compensating control is the differential warrant (§2c/d) plus the property warrant (§2e), and, for the class differentials structurally cannot see, the **method** of [notes/api-safety-survey.org §0](notes/api-safety-survey.org): look where a test on well-formed input cannot see the error, namely (a) invariants stated in prose (`PRECONDITION`, "the caller's job"; grep is a complete enumeration) and (b) rules the platform applies automatically that we leave to the author. [notes/newtype-survey.org](notes/newtype-survey.org) is a second survey. Three bugs of that class were found and fixed in one session: guarded witnesses consuming the private transcript on the untaken branch, assertions inside a branch not inheriting the guard, and a literal outside its operand's bound making a comparison constant. **All three were green on every differential the day before.** That is the honest measure of differential coverage.
- **The Pending lineage proves its own preimage.** It is anchored to the reference model's op stream and the pinned ledger, a **weaker** warrant than PI-equality on a shared preimage (§2d). Its property harness has four links and no compactc link, by construction.
- **Nothing has run end to end on a live network.** Keygen, prove and verify go through Midnight's own `Zkir` with hash-verified SRS parameters, so the proofs are real, and the three Signet signer circuits are deployed with MinoCrab's verifier keys into a `LedgerState`, proven through the ledger's own `Transaction::prove`, verified with `verify_contract_proofs` on and applied, in process, against captured on-chain transactions ([signet_real_proof.rs](crates/minocrab-contracts/tests/signet_real_proof.rs), [signet_ledger_apply.rs](crates/minocrab-contracts/tests/signet_ledger_apply.rs)). What has not happened is a node accepting one: the vault's circuits have no such gate yet, and no MinoCrab artifact has been submitted to a network.
- **Cross-contract calls: the entry point is bound, the argument types are not.** Since compactc 0.36 the callee's entry-point hash is a constant of the call's claim, in compactc's artifacts and in `minocrab_ledger::contract_call` alike, so `callOnce` and `callEmit` are different circuits and each proves only the entry point it names (`xcall_differential`'s `each_call_proves_only_its_own_entry_point`). Argument types remain unbound.
- **Known unported constructs**: the three `insertCoin` / `pushFrontCoin` arms reached through a NESTED path (the arms and nesting both work, but no fixture circuit compiles the combination, so the typed methods stop at declared slots); `kernel.checkpoint()`, which compactc 0.36 compiles for ZKIR v3 but which is not ported; and the hashing sweep family, whose WIDTH is a Rust parameter the benchmark sweeps rather than a ported circuit set.
- **The circuit list is closed in both directions.** `support::circuits()` feeds both snapshots, the dump instrument and the adversarial suite. Every contract declares its circuits under `#[contract]` and the list is the union of the derived sets; the one hand-written remainder is the `entry()`-built parameter families (the hashing width sweep, the events fixtures), which carry no attribute to derive from. The snapshots guard one direction (a listed circuit that moved); [circuit_closure.rs](crates/minocrab-contracts/tests/circuit_closure.rs) guards the other: it walks `src/` for every `#[circuit]` attribute and fails when one is not listed.
- **The Borsh injectivity obligation is preventable, not prevented.** `Serializer::constrained()` plus `Circuit::dedup_range_constraints` make constrain-on-construction **free**, proven by byte-identical serialized ZKIR in [dedup.rs](crates/minocrab-std/tests/dedup.rs), but the flag is off on every shipped artifact, and every corpus caller still relies on its arguments being constrained at entry. Scanning the `.zkir` files in the repo for a range constraint implied by an earlier one on the same wire found **zero**, so turning the flag on would remove nothing at the time of that scan ([notes/ir-passes.org §11](notes/ir-passes.org)).
- **The PORT's attested-amount sites rest on a whole-contract argument.** Three `from_field_unchecked` sites in `erc20_vault.rs` (`complete_swap`'s `amountIn`, `complete_supply`'s `shares`, `complete_redeem`'s `assets`) claim `Uint<64>` on a word the attested output bounds only to its Borsh width. The port keeps the unchecked spelling for compactc parity (compactc's `deserialize<…, 8>` makes the same claim), so the claim holds because the MPC's attested schema says `uint64`: an invariant of the protocol as a whole, not of the site. The Pending lineage carries six such sites for the same reason. Each carries a comment saying so, and they are first in line for the checked spelling ([notes/api-safety-survey.org §B4, §A1](notes/api-safety-survey.org)).
- **Not covered by the safety survey at all**: the `minocrab-ir`/ZKIR boundary, cross-contract argument marshalling beyond the shared constraint path, the macros' generated code for anything other than shape, and the proving system. `AssertMessage` and region indices are recorded at build time, so an IR pass that removes an instruction shifts them; pre-existing, not fixed.
- **Bench numbers are one session on one machine.** Rows, `k`, proof size and RSS are deterministic; wall-clock prove is a median of 3 and sub-second cells are noise-dominated ([BENCHMARK.md](BENCHMARK.md)).

## 6. How to audit this repo in a day

**Morning: run the gates, cheapest and most diagnostic first.**

1. `./bump.sh pins`: the four pins and what upstream currently offers (needs network).
2. `cargo test -p minocrab-zkir`: the corpus artifacts round-trip, count asserted. If this is red, stop.
3. `cargo test -p minocrab-ledger`: the entry-point hash rule over every corpus contract, plus the Impact op baseline.
4. `cargo test --workspace`: the differentials, the Pending lineage's pair pins, the leakage inventory, the artifact-agreement suites, the disclosure set-equality tests, `serialization_conformance`.
5. `cargo test --release -p minocrab-contracts --test row_snapshot --test interface_snapshot`: the two frozen tables.
6. `PROPTEST_CASES=2000 cargo test --release -p minocrab-contracts --test erc20_vault_pending_spec --test executor_vault`: the elevated property run on the Pending lineage (§2e). Raise the count for a longer gate; the wall clock is linear in it. The flush vault has no property run yet.
7. `./corpus/compile.sh`: recompile the corpus with the pinned compiler and check `git status --short corpus/zkir` is empty. This is the determinism claim, verified rather than trusted.

Or, in one command with a PASS/FAIL/seconds summary and a taxonomy line per failure: `./bump.sh gates --heavy`.

**Midday: read the arguments, in this order.**

1. [notes/ledger-abi.org §6](notes/ledger-abi.org): the equivalence criterion. Everything else is downstream of this one page.
2. [notes/version-bump.org](notes/version-bump.org) §"Drift taxonomy" and Exercise C: what each instrument means when it fires, and the demonstration that C1 and C2 are caught by different instruments.
3. [notes/api-safety-survey.org](notes/api-safety-survey.org): the method, the findings, and which fixes are built. §0 is the part to read even if you read nothing else.
4. [notes/vault-optimization.org](notes/vault-optimization.org) §"Verification-harness design" and §"As built, step 1": the chain of trust and the harness that makes links 2 to 4 machinery.
5. [notes/ir-passes.org](notes/ir-passes.org) §0 (the measurement), §8 (the constant-naming normalisation and its approval), §11 (dedup, and why no shipped artifact flips the flag).
6. [BENCHMARK.md](BENCHMARK.md) §"Where the wins come from": where the warrant weakens and why.

**Afternoon: read what machines do not warrant (§7), and grep the escape hatches.** Run against `crates/*/src`. Each hit is a place where an obligation is discharged by hand rather than by a type, and each is deliberately greppable:

```
grep -rn 'from_field_unchecked'      # the unchecked type claim; the twin is from_field_checked
grep -rn '\.field()'                 # a typed leaf becoming a raw wire: the range obligation drops here
grep -rn '\.bytes()'                 # everywhere a newtype's distinction is dropped
grep -rn 'or_default()'              # a guarded-off read consumed as the type's default
grep -rnE 'disclose(_as)?\('         # every private→public transition, each declared in a signature
grep -rnE 'PRECONDITION|caller.s job'  # invariants in prose rather than checked: the survey's seam (a)
grep -rn 'dedup_range_constraints'   # the checked-construction profile; off on every shipped artifact
grep -rn 'unsafe'                    # should be empty in the eDSL crates
```

Then compare a change of your own against the baseline with the ZKIR dump procedure in [zkir_dump.rs](crates/minocrab-contracts/tests/zkir_dump.rs)'s header: the only instrument that sees an instruction reorder at equal row count.

**If you have an evening.** `nix run .#bench` re-runs the differential tests, dumps corpus-verified preimages for all three benched sides, proves every cell and writes `target/bench/results.json` plus per-region cost profiles. The per-primitive calibration behind "the vault is hash-bound" is `cargo run -p minocrab-sim --example cryptocost` and `--example opcost`.

## 7. The trusted computing base: what a human must read

Most of this tree is warranted by machinery: the differentials against compactc's own artifacts, the frozen snapshots, the spec-and-property harness, the reference-VM cross-check, the Lean gates. The part that is not is small and nameable. [TRUST.md](TRUST.md) lists it file by file (what warrants each source file of the eight eDSL crates, and the failure that would hide there if nothing did); the rows whose warrant is **READING** are the trusted computing base. The table is generated and closure-tested by [trust_base.rs](crates/minocrab-contracts/tests/trust_base.rs) (a new source file with no row fails the test), and the design of record, including how the warrant column was decided, is [notes/trust-base.org](notes/trust-base.org). Where unsure a row says READING; a reviewer downgrades it, never the reverse.

What the inventory leaves out: the contracts crate (the vault lineages, the corpus ports) is warranted by its differentials and the spec harness; `signet-sim` is a test aid; the interface crates are generated from artifacts and gated by `artifact_agreement`.

### The read order, with a time budget

Bottom of the stack first, because every layer above is written against the one below. Times are for someone who knows Midnight's ledger and ZKIR v3 internals; double them otherwise. Each item says what to compare against in the pinned ledger sources (the crates.io `midnight-*` versions `Cargo.toml` names) and in compactc's compiler sources (`corpus/src/compact/`).

| # | read | budget | the question it answers | compare against |
|---|---|---|---|---|
| 1 | `crates/minocrab-zkir/src/` | 15 min | is the IR type Midnight's own, re-exported, and is the file envelope the only thing added? | midnight-zkir's `src/ir.rs`: nothing here should redefine a type |
| 2 | `crates/minocrab/src/lib.rs` | 15 min | is the visibility lattice sound: can private meet public and come out public anywhere? | the four `Meet` impls, by hand |
| 3 | `crates/minocrab-ir/src/builder.rs` | 1.5 h | does every instruction's operand-type table match what the VM accepts, including immediates? | midnight-zkir's `src/ir_vm.rs` (`preprocess`, the per-instruction arms) |
| 4 | `crates/minocrab/src/circuit.rs` | 3 h | the disclosure gate (one method, `disclose*`), the guard scopes (`when`, `guarded`), public-input minting order; can an effect escape its guard? | `compiler/zkir-v3-passes/reduce-to-zkir.ss` for the guard and read conventions; `tests/guard_scope.rs` for what is pinned |
| 5 | `crates/minocrab-ledger/src/{impact,ops,reads,kernel,calls}.rs` | 4 h | is each Impact op encoded as compactc's vm-code says, and does every read mint its gates before the op? Concentrate on the known unported constructs (§5) | `compiler/midnight-ledger.ss` (vm-code) |
| 6 | `crates/minocrab-macros/src/` | 2 h | do the expansions add anything the hand-written twins do not: argument order, constraints, the generated tests' bodies? | the twin tests (`circuit`, `derive`, `interface_macro`): read the twin, then the expansion |
| 7 | `crates/minocrab-sim/src/vm.rs` | 1.5 h | is the simulator a port of `preprocess`, and is it ever trusted alone? | midnight-zkir's `src/ir_vm.rs::preprocess`; `IrSource::check` at every call site of `simulate` |
| 8 | `crates/minocrab-ir/src/passes.rs`, `crates/minocrab-taint/src/lib.rs` | 2 h | does each pass have its Lean theorem, and does each taint marking rule cite an in-circuit warrant? | `crates/minocrab-ir/lean/`; `notes/taint-lint.org §4` |
| 9 | `crates/minocrab-std/src/` | 1 day | not line by line: the SEAMS, i.e. every `from_field_unchecked`, every `.field()` that drops a range obligation, every `or_default()` | the greps in §6; `notes/api-safety-survey.org §A1-A2` |

About three days for the READING rows plus the seams; the differentials cover the rest and a reviewer's time is better spent running them (§6).

The taint lint ([taint_lint.rs](crates/minocrab-contracts/tests/taint_lint.rs)) is the one instrument that sees the class no test on honest inputs can; its frozen baseline is classified in `notes/taint-lint.org §5`.
