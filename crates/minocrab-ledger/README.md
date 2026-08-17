# minocrab-ledger

**L2.5 of [MinoCrab](https://github.com/sig-net/minocrab) — ledger-op emission.** A circuit's ledger operations surface as Impact instructions whose elements are exactly `Op::field_repr` of the corresponding Impact-VM op. This crate builds those element streams: fully-constant ops go through Midnight's real `Op` type and its `field_repr` — never hand-encoded — and ops embedding circuit-computed values reproduce the same layout with wires spliced into the value positions.

```
  crates/minocrab-zkir       L0   ZKIR bindings
  crates/minocrab-ir         L1   typed circuit builder
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
► crates/minocrab-ledger     L2.5 Impact ledger ops
  crates/minocrab-std        L3   stdlib ports
```

**Contract code should use the typed slots in `minocrab-std`** (`LedgerMap`, `LedgerCell`, `LedgerCounter`, …), which are one-line wrappers over the functions here. The ADTs sit *above* the ops on purpose, so this crate stays the pure op layer. Reach for it to emit an operation the typed slots do not cover, or to read what the encoding actually is.

```rust
use minocrab_ledger::{cell_write, LedgerValue};

// A Bytes<20> cell at slot 3: FAB atoms from the slot's type, limbs from wires.
let value = LedgerValue::bytes(20, elems);
let ops = cell_write(3, &value);
```

Op sequences per ledger operation are compactc's own vm-code, with its suppression rules: top-level `Cell` writes lose their `idxp`/`insc` wrapper, and the first fetch of a field is always the uncached `idx` variant. The constant header layouts are unit-tested against `field_repr` of real ops, and a 31-circuit differential checks the result against compactc's artifacts.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
