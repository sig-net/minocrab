//! What the Signet singleton and the MPC that reads it must agree on, and
//! nothing else.
//!
//! Three parties read these facts: the contract (`minocrab-contracts`'
//! `signet_contract`, which EMITS the events), the artifact pipeline
//! (`signet-artifacts`, which names the circuits on disk and hashes their
//! verifier keys into `expectedVk.json`), and the publisher
//! (`minocrab-publisher`, which `sig-net/mpc` links to BUILD the events). Only
//! the last of those has to be publishable, and the first is a test corpus
//! that never will be — so the facts live here, in a crate with one
//! dependency, and each reader spells them once from this definition
//! (notes/mpc-publisher.org §11).
//!
//! # What is here
//!
//! - [`misc`]: the MIP-0002 `Misc` event's tag, version and serialized size —
//!   Midnight's constants (compactc's `midnight-events.ss:71`), carried here
//!   because the Misc envelope is the whole of what a signer event is.
//! - [`circuits`]: the three signer circuits' Compact names, the event name
//!   each one pads into the envelope's first 32 bytes, and the map between
//!   them.
//! - [`hash_verifier_key`]: `@midnight-ntwrk/compact-js`'s `hashVerifierKey`,
//!   the function `expectedVk.json` is written with and a deployment is
//!   checked with.
//!
//! # What is not here, deliberately
//!
//! No circuit code, no ledger types, no key material. The envelope LAYOUTS
//! (which byte of the 288 carries what) are the publisher's, next to the
//! functions that fill them; the record types, the request id and the ECDSA
//! shapes that notes/interface-crates.org names for this crate are still in
//! `minocrab-contracts/src/signet.rs` and move when something publishable
//! needs them.

/// The MIP-0002 `Misc` event, as the ledger's `Op::Log` carries it:
/// `[version: u32 LE, tag: u8, bytes: Bytes<288>]`, where the 288 bytes are
/// `pad(32, name) ‖ payload(256)`.
///
/// These are Midnight's numbers (compactc's `compiler/midnight-events.ss:71`)
/// and `minocrab-contracts`' `tests/signet_ledger_apply.rs` pins them against
/// the pinned ledger's own `LogEventType::Misc` and against a captured
/// on-chain transaction.
pub mod misc {
    /// The log item version the ledger's `VersionedLogItem` carries.
    pub const MISC_VERSION: u32 = 1;
    /// `LogEventType::Misc as u8`.
    pub const MISC_TAG: u8 = 10;
    /// `name(32) ‖ payload(256)`: the serialized size of one `Misc`.
    pub const MISC_SIZE: usize = 288;
}

/// The three signer circuits and their events.
///
/// The circuit names are the COMPACT names — what compactc's own artifacts
/// are called, what `sig-net/mpc`'s `expectedVk` table and `RESPOND_CIRCUITS`
/// key by, what `signet-artifacts`' managed directory names its files, and
/// what the captured on-chain transactions carry as entry points. NOT the
/// Rust function names.
///
/// The event names are what each circuit pads into the first 32 bytes of its
/// Misc envelope: the field mpc's reader selects its `EmissionKind` on.
pub mod circuits {
    pub const SIGN_BIDIRECTIONAL: &str = "signBidirectional";
    pub const RESPOND: &str = "respond";
    pub const RESPOND_BIDIRECTIONAL: &str = "respondBidirectional";

    /// All three, in the order `signet-artifacts` generates them.
    pub const SIGNER_CIRCUITS: [&str; 3] = [SIGN_BIDIRECTIONAL, RESPOND, RESPOND_BIDIRECTIONAL];

    /// `pad(32, "SignBidirectionalEvent")` opens `signBidirectional`'s Misc.
    pub const SIGN_BIDIRECTIONAL_EVENT: &str = "SignBidirectionalEvent";
    /// `pad(32, "SignatureRespondedEvent")` opens `respond`'s Misc.
    pub const SIGNATURE_RESPONDED_EVENT: &str = "SignatureRespondedEvent";
    /// `pad(32, "RespondBidirectionalEvent")` opens `respondBidirectional`'s
    /// Misc.
    pub const RESPOND_BIDIRECTIONAL_EVENT: &str = "RespondBidirectionalEvent";

    /// The event name a circuit's Misc envelope opens with, or `None` for a
    /// name that is not one of [`SIGNER_CIRCUITS`].
    pub fn event_name(circuit: &str) -> Option<&'static str> {
        match circuit {
            SIGN_BIDIRECTIONAL => Some(SIGN_BIDIRECTIONAL_EVENT),
            RESPOND => Some(SIGNATURE_RESPONDED_EVENT),
            RESPOND_BIDIRECTIONAL => Some(RESPOND_BIDIRECTIONAL_EVENT),
            _ => None,
        }
    }

    /// Every event name fits the 32-byte name field, checked once at compile
    /// time rather than at every envelope.
    const _: () = {
        assert!(SIGN_BIDIRECTIONAL_EVENT.len() <= 32);
        assert!(SIGNATURE_RESPONDED_EVENT.len() <= 32);
        assert!(RESPOND_BIDIRECTIONAL_EVENT.len() <= 32);
    };
}

/// EXACTLY `@midnight-ntwrk/compact-js`'s `hashVerifierKey`
/// (`ContractKeyLocation.js`: `createHash('sha256').update(bytes).digest
/// ('hex')`) on the raw file bytes `prover.ts`'s `keyMaterial` reads with
/// `readFile` — no framing, no prefix. Lowercase hex, 64 characters.
///
/// The one definition in this workspace: `signet-artifacts` writes
/// `expectedVk.json` with it, `minocrab-publisher` checks a deployment's
/// verifier keys with it, and `signet-artifacts`' `tests/hash_verifier_key_pin.rs`
/// pins it against the TypeScript function itself under node (M29 B;
/// notes/mpc-publisher.org §8 has the provenance).
pub fn hash_verifier_key(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_signer_circuit_has_an_event_name_and_nothing_else_does() {
        for circuit in circuits::SIGNER_CIRCUITS {
            assert!(circuits::event_name(circuit).is_some(), "{circuit}");
        }
        assert_eq!(circuits::event_name("transfer"), None);
        assert_eq!(circuits::event_name(""), None);
    }

    /// sha256("") — the one vector everybody knows, so the hex spelling
    /// (lowercase, no prefix) is pinned independently of any key file.
    #[test]
    fn hash_verifier_key_is_lowercase_sha256_hex() {
        assert_eq!(
            hash_verifier_key(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
