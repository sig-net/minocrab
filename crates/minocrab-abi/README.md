# minocrab-abi

**Artifact agreement for [MinoCrab](https://github.com/sig-net/minocrab).** An `#[interface]` trait is a claim about somebody else's deployed contract, and compactc publishes enough to settle it: `contract-info.json` carries every circuit's fully typed signature, and the `.zkir` carries the constraint run the prover will actually execute. So drift between an interface crate and the contract it describes is a **test failure in the interface crate's own suite**, not a runtime surprise at a call site.

```
  crates/minocrab            L2   eDSL: wires, visibility, disclosure
  crates/minocrab-ledger     L2.5 Impact ledger ops
► crates/minocrab-abi             the interface/artifact agreement checker
  crates/minocrab-interface-gen   compactc artifact → interface crate (CLI)
```

A dev-dependency of an interface crate; nothing shipping links it.

```rust
// signet-signer-interface/tests/artifact_agreement.rs
let artifact = Artifact::open(env!("CARGO_MANIFEST_DIR")).unwrap();
artifact.verify_pin().unwrap();
artifact.assert_interface_matches::<
    (RequestId<Public>, SignBidirectionalEventNotification<Public>), ()>(
    SignetSigner::SIGN_BIDIRECTIONAL,
);
```

The types named there are the ones the `#[interface]` trait declares and the ones a caller passes, so nothing is written down twice: agreement about the artifact *is* agreement about every call site. Three pieces — `info` (the typed tree and its flattening into native slots), `pin` (the hash-pinned distillation a crate commits instead of megabytes of `.zkir`), and `check` + `schema` (the six checks, and the frozen ABI rendering whose diff is the semver decision).

**Honest limit:** it does not bind an artifact to a deployed *address*. That needs the verifier key.

[Repository README](https://github.com/sig-net/minocrab#readme) · [VERIFICATION.md](https://github.com/sig-net/minocrab/blob/main/VERIFICATION.md) · [BENCHMARK.md](https://github.com/sig-net/minocrab/blob/main/BENCHMARK.md)

Licensed under MIT OR Apache-2.0.
