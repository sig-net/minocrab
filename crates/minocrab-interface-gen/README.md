# minocrab-interface-gen

**The importer for [MinoCrab](https://github.com/sig-net/minocrab): a compactc artifact becomes an interface crate.** Any deployed Midnight contract publishes a `contract-info.json` with every circuit's fully typed signature, so any deployed Midnight contract can be turned into an ordinary Rust crate that a MinoCrab contract imports and calls — Compact-authored or not, ported or not.

```
  crates/minocrab-std        L3   stdlib ports
  crates/minocrab-abi             the interface/artifact agreement checker
► crates/minocrab-interface-gen   compactc artifact → interface crate (CLI)
```

```text
minocrab-interface-gen --crate crates/signet-signer-interface
minocrab-interface-gen --crate crates/xcall-target-interface --check
```

**A CLI, not a `build.rs`.** Generated source that nobody can read is a worse interface than a hand-written one, so the output is committed, reviewable and docs.rs-able, and `--check` regenerates it and diffs — drift between the artifact and the crate is a test failure. Each generated crate commits `artifact/generator.json`, which records exactly how it was produced: the interface name, the source artifact, the summary, and any hand-written modules the crate also carries.

It reads the **same parse** the agreement checker reads (`minocrab_abi::info`), so the generator and the test that validates its output cannot disagree about what the artifact says.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
