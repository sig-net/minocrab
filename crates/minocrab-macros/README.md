# minocrab-macros

**The thin decorators for [MinoCrab](https://github.com/sig-net/minocrab).** `#[circuit]`, `#[contract]`, `#[interface]`, and the `CircuitArg` / `CircuitBorsh` / `Ledger` derives.

```
  crates/minocrab-zkir       L0   ZKIR bindings
  crates/minocrab-ir         L1   typed circuit builder
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-std        L3   stdlib ports
► crates/minocrab-macros          the thin decorators
```

**Do not depend on this crate directly.** `minocrab-std`'s default `macros` feature re-exports every macro next to the trait it implements, the way `serde` does, which is also where they are documented in context.

A leaf of the build graph: it depends on nothing of ours and emits fully-qualified `::minocrab_std::v3::…` paths, so an expansion cannot smuggle circuit-building code in. By the thinness rule the expansions contain no `Circuit3` method call at all — everything goes through `CircuitArg` and `ArgPath`, and each expansion is exactly what was previously written by hand.

```rust
use minocrab_std::v3::{circuit, Circuit3, CircuitArg, Bytes, Uint};

#[derive(CircuitArg)]            // field order is the wire contract
struct DepositRequest {
    erc20_address: Bytes<20>,    // label: depositRequest_erc20Address
    amount: Uint<128>,           // label: depositRequest_amount
}

#[circuit]
fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, request: DepositRequest) {
    c.assert(request.amount.gt(0u64));
}
```

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
