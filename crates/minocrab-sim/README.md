# minocrab-sim

**L5 of [MinoCrab](https://github.com/sig-net/minocrab) — the native simulator.** Executes a circuit in plain Rust for `cargo test` loops: no proving, no keys, instant feedback, plus a disclosure report and `(k, rows)` cost metrics. Semantics mirror midnight-ledger's reference VM instruction for instruction, and crypto primitives are Midnight's own — never reimplemented here.

```
  crates/minocrab-zkir       L0   ZKIR bindings
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-std        L3   stdlib ports
► crates/minocrab-sim        L5   native simulator: disclosure reports + cost profiler
```

A dev-dependency, not something a contract links.

```rust
let (run, report) = minocrab_sim::simulate_compiled(&compiled, &[], &[Fr::from(42u64)], &[])?;

// The statement disclosed exactly one value: the verdict bit, not the age.
assert_eq!(run.public_transcript_inputs, vec![Fr::from(1u64)]);
assert!(report.disclosures[0].label.contains("not the age"));

// An underage witness fails the in-circuit assertion.
assert!(minocrab_sim::simulate(&compiled.ir, &[], &[Fr::from(11u64)], &[]).is_err());
```

**The simulator is never trusted alone.** `Run::preimage` packages a run as a `ProofPreimage`, and every accepted run is replayed through Midnight's reference VM (`IrSource::check`) and the pinned ledger. This is what makes 9,000,000 property cases against a Rust spec affordable. `v3::simulate` is the current entry point; `profile` gives the per-region cost breakdown the benchmark charts.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
