# minocrab-std

**L3 of [MinoCrab](https://github.com/sig-net/minocrab) — the standard library.** Ports of Compact's `standard-library.compact` and `zkir-v3-library.compact`: hashing, Merkle trees, Schnorr, secp256k1 ECDSA and Ethereum addresses, the coin and kernel ADTs, the ledger block as types, and Borsh serialization. Translation is mechanical from Midnight's own sources, and each ported item is differential-tested against compactc's compilation of the original.

```
  crates/minocrab-zkir       L0   ZKIR bindings
  crates/minocrab-ir         L1   typed circuit builder
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-ledger     L2.5 Impact ledger ops
► crates/minocrab-std        L3   stdlib ports
  crates/minocrab-sim        L5   native simulator
```

**This is the crate a contract depends on.** It re-exports the eDSL and, with the default `macros` feature, the decorators. Add `minocrab-sim` as a dev-dependency to run circuits under `cargo test`.

```rust
use minocrab_std::v3::{circuit, hash, Circuit3, CircuitArg, Bytes, Uint};

#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

#[circuit]
fn deposit(c: &mut Circuit3, request: DepositRequest) {
    // The argument's type IS its range constraint: Uint<128> is assert_bits(w, 128).
    c.assert(request.amount.gt(0u64));
    let _digest = hash::persistent_hash(c, &request.erc20_address);
}
```

Hashing is always written module-qualified, because *which bytes get hashed* is a decision that should be visible at the call site.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
