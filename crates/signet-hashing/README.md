# signet-hashing

**The Signet protocol's hashes, off circuit** — part of [MinoCrab](https://github.com/sig-net/minocrab).

Every protocol hash is `upgradeFromTransient(transientHash([HashDomain.x, …]))`: Poseidon over the preimage's field-aligned representation, written out as 32 bytes. This crate computes them with the pinned ledger's own `transient_hash` and `FieldRepr`, whose `[u8]` packing is the compiler's `Bytes<N>` alignment, so it adds no packing of its own and reads its domain tags and enums from [`signet-protocol`](https://github.com/sig-net/minocrab/tree/main/crates/signet-protocol).

- `request_id(&RequestIdPreimage)` — `calculateRequestIdV1`; `SignBidirectionalRecord::request_id()` for a record the MPC has read.
- `evm_type2_tx_params_digest(&EvmType2TxParams)` — `calculateEvmType2TxParamsDigestV1` over the used words, entries and keys; capacities enter nowhere.
- `attested_output_hash(&[u8])` — `calculateAttestedOutputHashV1`.
- `attestation_digest(…)` and `Attestation::over(request_id, height, kind, output)` — `calculateSignetAttestationDigestV1`, and the attestation half of a `respondBidirectional` built in one step.

Pinned against the compiled Compact circuits: `tests/fixtures/api-parity-vectors.json` holds request ids and transaction digests of nine records at four struct shapes and ten attestation digests, produced by compactc 0.33.0-rc.2 over `@sig-net/midnight@0.25.0-rc.1` and captured by sig-net/mpc, with no Rust hash in the loop.

Who reads it: sig-net/mpc (which carried its own copy as `compact-hashing`), `minocrab-publisher` (re-exported as `minocrab_publisher::hashing`), and the contract tests that drive a request → respond → settle round trip.

`publish = false` until the `midnight-*` line is on crates.io at the pinned tags (see PUBLISHING.md).

[Repository README](https://github.com/sig-net/minocrab#readme)

Licensed under MIT OR Apache-2.0.
