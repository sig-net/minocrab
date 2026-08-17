# minocrab-ir

**L1 of [MinoCrab](https://github.com/sig-net/minocrab).** A typed circuit builder over ZKIR instructions. It tracks the arity and type of every value, so an emitted instruction stream is well-formed by construction — indices cannot dangle, and an operand type an instruction does not support never reaches the prover.

```
  crates/minocrab-zkir       L0   ZKIR bindings
► crates/minocrab-ir         L1   typed circuit builder
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-std        L3   stdlib ports
  crates/minocrab-sim        L5   native simulator
```

This layer knows nothing about wires, visibility or disclosure — that is L2, and it is what contract code should be written against. Reach for this crate to emit ZKIR directly, or to run a pass over it.

```rust
use minocrab_ir::v3::{Arg, Builder3, IrType};

let mut b = Builder3::new();
let x = b.input("x", IrType::Native);
let x_plus_3 = b.add(x, 3u64);          // immediates are inline operands in v3
let hashed = b.transient_hash(&[Arg::from(x_plus_3)]);
b.output(&[Arg::from(hashed)]);
let ir = b.finish(false);               // false: no communications commitment
```

`v3::Builder3` is the current builder (named, typed values); `Builder` is the ZKIR v2 equivalent over an append-only value memory. `v3::passes` holds the normalisations both sides of a differential test are run through.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
