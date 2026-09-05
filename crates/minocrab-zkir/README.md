# minocrab-zkir

**L0 of [MinoCrab](https://github.com/sig-net/minocrab).** Read, write and round-trip Midnight's ZKIR. The "spec" is Midnight's own `midnight-zkir` / `midnight-zkir-v3`, whose types are re-exported rather than redefined; this crate adds the file-level I/O and the on-disk version envelope compactc writes.

```
► crates/minocrab-zkir       L0   ZKIR bindings
  crates/minocrab-ir         L1   typed circuit builder
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-std        L3   stdlib ports
  crates/minocrab-sim        L5   native simulator
```

Nothing above L0 touches serialization or the zkir toolchain directly.

```rust
let ir = minocrab_zkir::v3::read_zkir("respond.zkir")?;
println!("v3, {} instructions", ir.instructions.len());
```

`v3::write_zkir` is the exact inverse of the reader, including the `{"major": 3, "minor": m}` envelope — every pinned compactc v3 artifact parses and re-emits byte-identically (the corpus's v2 artifacts are told apart by `major_version` and skipped).

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
