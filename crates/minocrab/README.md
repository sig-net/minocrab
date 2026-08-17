# minocrab

**L2 of [MinoCrab](https://github.com/sig-net/minocrab) — the eDSL.** Circuits are ordinary Rust, and wires carry their visibility in the type. A `Wire<Private>` cannot reach a public output; there is no method for it, until it passes through `disclose`, which is the single, greppable gate for information leaving the private domain. Combining wires taints.

```
  crates/minocrab-zkir       L0   ZKIR bindings
  crates/minocrab-ir         L1   typed circuit builder
► crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-std        L3   stdlib ports
  crates/minocrab-sim        L5   native simulator
```

Contract authors normally depend on **`minocrab-std`**, which re-exports what is needed from here alongside the standard library and the `#[circuit]` decorators.

The enforcement is a type error, not a runtime check:

```rust
use minocrab::Circuit;

let (mut c, _) = Circuit::new(0);
let secret = c.witness();

// c.declare_public(secret, "leak");     // ERROR: expected Wire<Public>, found Wire<Private>

let public = c.disclose(secret, "intentionally published");
c.declare_public(public, "value");
```

`v3::Circuit3` is the current frontend: same discipline, but wires also carry their ZKIR value type, so an unsupported operand is a Rust type error rather than a build-time panic. A circuit's `Discloses<..>` return type is its disclosure manifest, and a generated test fails if it discloses anything not listed — which is how four real undeclared disclosures were caught.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
