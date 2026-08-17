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
use minocrab_zkir::{read_any, AnyIr};

match read_any("counter_increment.zkir")? {
    AnyIr::V3(ir) => println!("v3, {} instructions", ir.instructions.len()),
    AnyIr::V2(ir) => println!("v2, {} instructions", ir.instructions.len()),
}
```

`write_zkir` is the exact inverse of the reader, including the `{"major": n, "minor": m}` envelope — every one of the 788 pinned compactc artifacts parses and re-emits byte-identically.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
