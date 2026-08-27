# Contributing

The discipline that keeps this codebase correct lives in a *process*, not
just in the tests. If you edit this repo like a normal repo, the
instruments decay into noise and the correctness story dies quietly. This
file is the process, written down. It is short on purpose: where a topic
has a full write-up, this points at it instead of duplicating it.

## The loop: how to make a change

1. **Baseline first.** Before touching circuit-adjacent code, dump every
   circuit's serialized ZKIR:

   ```
   MINOCRAB_ZKIR_DUMP=/tmp/before cargo test -p minocrab-contracts \
     --test zkir_dump -- --ignored dump_every_circuits_zkir
   ```

2. **Make the change.**

3. **Run the gates.**

   ```
   cargo test --workspace                 # the routine loop (deps are
                                          # optimized under dev already)
   cargo test --release -p minocrab-contracts \
     --test row_snapshot --test interface_snapshot   # the frozen tables
   ```

   Then re-dump to `/tmp/after` and `diff -rq /tmp/before /tmp/after`.
   The dump is the instrument the snapshots cannot replace: `row_snapshot`
   freezes `(k, rows)` and is blind to an instruction reorder at equal
   rows or a removed `Copy`; `interface_snapshot` freezes `(label, type)`
   and is blind to everything else. Byte-equality of the dumps sees all
   of it. CI runs this comparison against your PR's base automatically.

4. **Explain every moved byte.** Zero movement needs no words. Any
   movement needs the commit message to say *which* circuits moved, *by
   how much*, and *why that is the intended change* — see the history for
   the house style (`git log --grep "byte-identical"`). Movement that you
   cannot explain is a bug in your change, not an acceptable cost.

5. **Regenerate, never paste.** Every snapshot has a regenerator that
   writes its table back between `GENERATED` markers so acceptance is a
   reviewable `git diff`:

   ```
   cargo test -p minocrab-contracts --test row_snapshot -- --ignored regenerate_row_snapshot
   cargo test -p minocrab-contracts --test interface_snapshot -- --ignored regenerate_interface_snapshot
   MINOCRAB_TAINT_BASELINE=1 cargo test -p minocrab-contracts --test taint_lint
   ```

   `./bump.sh accept` runs every regenerator in dependency order (that
   script's home turf is toolchain bumps — see below — but the
   regenerators are the same ones).

## What an instrument MEANS when it fires

Do not guess. The **drift taxonomy** in
[notes/version-bump.org](notes/version-bump.org) names twelve
instruments, what a failure in each one *means*, and which of four
responses is right (accept the new baseline / fix your change / repin /
investigate upstream). It was written for toolchain bumps but the
taxonomy applies to any firing. Two that deserve their own sentence:

- **The taint lint** (`tests/taint_lint.rs`) fires when a hash-preimage
  limb is not provably bounded — the class no test on honest inputs can
  see. **Never allowlist.** Either extend the marking rules in
  `minocrab-ir/src/v3/taint.rs` with a *cited in-circuit warrant*, or
  take the finding to the maintainers. [notes/taint-lint.org](notes/taint-lint.org)
  has the classification of the frozen baseline.
- **A differential suite** disagreeing with compactc means the port's
  statement changed. That is never routine; see
  [VERIFICATION.md](VERIFICATION.md) for what each suite warrants.

## Divergence ledgers

The four vault artifacts form a chain — `compactc ≡ port ≡ opt ≡ borsh ≡
modern` — and each link has a **ledger** (`fork_status` /
`borsh_fork_status` / `modern_fork_status` in
`crates/minocrab-contracts/tests/vault/`) saying, per circuit, whether
the link is byte-identity or a declared divergence. Both directions are
asserted: an `Identical` entry must really be byte-identical, a
`Diverged` entry must really differ. **If your change moves a circuit
across that line, the ledger entry must move in the same commit** — that
edit *is* the record that the circuit left its predecessor's coverage
and now rests on the spec harness. A collapse or "cleanup" that removes
a ledger trades a correctness instrument for line count: wrong direction.

## The class tests cannot see

Some hazards are invisible to every test that runs on honest inputs
(unconstrained hash-preimage wires, guarded-witness misuse, private
guards driving public effects). The method for finding them is a
*survey*: read the code asking "what can a malicious prover vary?",
write each finding down with severity and either a fix or a written
refusal. [notes/api-safety-survey.org](notes/api-safety-survey.org) §0
is the method and the worked example;
[notes/newtype-survey.org](notes/newtype-survey.org) is a second one.
The escape-hatch greps double as a code-review checklist:

```
grep -rn "\.bytes()"            # everywhere a newtype's distinction is dropped
grep -rn "disclose"             # every Private -> Public gate
grep -rn "from_field_unchecked" # every unproven width claim
grep -rn "_guarded\|_under"     # every guarded read/effect
```

## Toolchain bumps

`./bump.sh pins` answers "is there anything to take?"; `gates` runs the
instruments in diagnosis order; `accept` regenerates everything into a
reviewable diff. The whole workflow, the four independent pins, and the
hazards are in [notes/version-bump.org](notes/version-bump.org). A bump
is a routine chore; treat any surprise as taxonomy, not noise.

## House rules

- Correctness (and *obvious* correctness) > performance > idiomatic Rust.
- Never compile below ZKIR. Reuse Midnight's code before writing our own.
- Nix provides binaries only; the build is plain `cargo` (see
  [CLAUDE.md](CLAUDE.md) for the full list, including the API-rejection
  ladder: missing impl > non-unifying types > inline-const assert >
  build-time panic, in that order of preference).
- Findings and decisions go to `notes/` as they are made
  ([ONBOARDING.md](ONBOARDING.md) maps the notes); milestones are ticked
  in `milestones.org` in place.
- The elevated gates before publishing a spec-anchored claim:
  `PROPTEST_CASES=1000000` on the vault spec suite, and a fresh
  single-session `./bench.sh` for any number that lands in
  [BENCHMARK.md](BENCHMARK.md).
