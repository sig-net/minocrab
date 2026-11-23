# Contributing

The discipline that keeps this codebase correct lives in a *process*, not just in the tests. If you edit this repo like a normal repo, the instruments decay into noise and the correctness story dies quietly. This file is the working loop and the house rules; [VERIFICATION.md](VERIFICATION.md) says what each gate means when it fires, and [PUBLISHING.md](PUBLISHING.md) covers releases.

## Run the gates: how to make a change

1. **Baseline first.** Before touching circuit-adjacent code, dump every circuit's serialized ZKIR:

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

   Then re-dump to `/tmp/after` and `diff -rq /tmp/before /tmp/after`. CI runs this comparison against your PR's base automatically. Clippy (`cargo clippy --workspace --all-targets -- -D warnings`) and `cargo deny check` are CI jobs too.

4. **Explain every moved byte.** Zero movement needs no words. Any movement needs the commit message to say which circuits moved, by how much, and why that is the intended change (`git log --grep "byte-identical"` shows the house style). Movement you cannot explain is a bug in your change.

5. **Regenerate, never paste.** Every snapshot has a regenerator that writes its table back between `GENERATED` markers, so acceptance is a reviewable `git diff`:

   ```
   cargo test -p minocrab-contracts --test row_snapshot -- --ignored regenerate_row_snapshot
   cargo test -p minocrab-contracts --test interface_snapshot -- --ignored regenerate_interface_snapshot
   MINOCRAB_TAINT_BASELINE=1 cargo test -p minocrab-contracts --test taint_lint
   MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base
   ```

   `./bump.sh accept` runs every regenerator in dependency order.

When a gate fires and you do not know what it means, read [VERIFICATION.md](VERIFICATION.md) §3 before changing anything. Never allowlist a taint-lint finding.

## Toolchain bumps

`./bump.sh pins` answers "is there anything to take?"; `gates` runs the instruments in diagnosis order; `accept` regenerates everything into a reviewable diff. The workflow, the four independent pins and the hazards are in [notes/version-bump.org](notes/version-bump.org).

## House rules

- Correctness (and *obvious* correctness) > performance > idiomatic Rust.
- Never compile below ZKIR. Reuse Midnight's code before writing our own.
- Nix provides binaries only; the build is plain `cargo` (see [CLAUDE.md](CLAUDE.md) for the full list, including the API-rejection ladder: missing impl > non-unifying types > inline-const assert > build-time panic, in that order of preference).
- Findings and decisions go to `notes/` as they are made; milestones are ticked in `milestones.org` in place.
- The elevated gates before publishing a spec-anchored claim: `PROPTEST_CASES=1000000` on the vault spec suite, and a fresh single-session `./bench.sh` for any number that lands in [BENCHMARK.md](BENCHMARK.md).
