# signet-protocol

**What the Signet singleton and the MPC that reads it must agree on**, in the smallest publishable crate that can carry it — part of [MinoCrab](https://github.com/sig-net/minocrab).

```
  crates/minocrab-contracts       the contract that EMITS the signer events (a corpus, never published)
  crates/signet-artifacts         the managed directory: keys, .bzkir, expectedVk.json (never published)
► crates/signet-protocol          the facts both of those and the publisher spell once
  crates/minocrab-publisher       the publisher sig-net/mpc links to BUILD the events
```

Three things, one dependency (`sha2`):

- `misc` — the MIP-0002 `Misc` event's tag (10), version (1) and serialized size (288 = `pad(32, name) ‖ payload(256)`).
- `circuits` — the three signer circuits' Compact names (`signBidirectional`, `respond`, `respondBidirectional`), the event name each pads into its envelope, and `event_name(circuit)`.
- `hash_verifier_key` — `@midnight-ntwrk/compact-js`'s `hashVerifierKey`, character for character: sha256 of the raw `.verifier` bytes as lowercase hex. The function `expectedVk.json` is written with and a deployment is checked with; pinned against the TypeScript original under node in `signet-artifacts`' suite.

No circuit code, no ledger types, no key material. The envelope layouts live in `minocrab-publisher` beside the functions that fill them.

[Repository README](https://github.com/sig-net/minocrab#readme) · [notes/mpc-publisher.org](https://github.com/sig-net/minocrab/blob/main/notes/mpc-publisher.org)

Licensed under MIT OR Apache-2.0.
