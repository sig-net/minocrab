# Fixtures, from `sig-net/mpc` (develop; the reader translation is at `10360c3c`, 2026-09-05)

- `caller-post-state-156.mn` — a caller's raw `contract-state[v8]` blob at
  the notify block of the MPC's capture chain (request index at ledger
  field 4; request id
  `1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b`,
  DEPLOYED record format, filed under the LEGACY keccak id rule — see
  `hashing.rs`). `chain-signatures/chain-midnight/fixtures/`.
- `midnight-epsilon.json` — the epsilon-derivation vectors the MPC's
  `signet-crypto` pins against `@sig-net/midnight@0.14.0`.
  `signet-crypto/fixtures/`.

Copied verbatim; never hand-edited. Recapture per the mpc README.
