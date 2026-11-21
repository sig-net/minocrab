# signet-responder-interface

**The Sig Network signet responder's interface, as an importable crate** for [MinoCrab](https://github.com/sig-net/minocrab) circuits. Since midnight-integration v0.26 the Sig Network contracts on Midnight are two: the signet signer, which a client contract calls cross-contract to file a request (`signet-signer-interface`), and the signet responder, which the MPC calls in its own transactions to post a signature or an attestation. A client reads the responder's events off chain and verifies them in its own circuits; this crate declares the responder's circuits and the response types those circuits and their readers share.

- `SignetResponder`, from an `#[interface]` trait: `respond`, `respond_bidirectional`, with `SignetResponder::at_field(index)` and `SignetResponder::at(address)`.
- `RequestId`, `AffinePoint`, `Signature`, `SignatureRespondedEventV1`, `RespondBidirectionalEventV1`: the argument types, field for field and in declaration order, which is the wire order.

The interface contains no address and no verifier key. `artifact/` ships beside the source: `pin.json` and `contract-info.json` are the compactc artifact the crate was generated from (the signet responder at midnight-integration v0.26.0-rc.15, compiler 0.36.1), and `interface-schema.txt` is the frozen wire layout.

**Versioning follows the deployed contract's wire format, not the MinoCrab workspace.** Any change to `artifact/interface-schema.txt` is a major version; adding a circuit is minor; re-pinning to a same-signature redeploy is a patch. Most users get this crate through `minocrab-signet`.

[Repository README](https://github.com/sig-net/minocrab#readme)

Licensed under MIT OR Apache-2.0.
