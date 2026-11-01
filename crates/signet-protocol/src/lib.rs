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
//! dependency, and each reader spells them once from this definition.
//!
//! # What is here
//!
//! - [`misc`]: the MIP-0002 `Misc` event's tag, version and serialized size —
//!   Midnight's constants (compactc's `midnight-events.ss:71`), carried here
//!   because the Misc envelope is the whole of what a signer event is.
//! - [`circuits`]: the three signer circuits' Compact names, the event name
//!   each one pads into the envelope's first 32 bytes (as a string and as
//!   the padded 32 bytes a reader compares against), and the maps between
//!   them.
//! - [`HashDomain`], [`OutputKind`], [`TxParamType`], [`SignatureAlgorithm`],
//!   [`SignatureDestination`]: the Signet module's protocol enums, as the u8
//!   variant indices the records and hashes carry.
//! - [`hash_verifier_key`]: `@midnight-ntwrk/compact-js`'s `hashVerifierKey`,
//!   the function `expectedVk.json` is written with and a deployment is
//!   checked with.
//!
//! # What is not here, deliberately
//!
//! No circuit code, no ledger types, no key material. The envelope LAYOUTS
//! (which byte of the 288 carries what) are the publisher's, next to the
//! functions that fill and read them. The protocol HASHES (request id,
//! transaction digest, attested output hash, attestation digest) are Poseidon
//! over the ledger's field representation, so they need the ledger's crates
//! and live in `signet-hashing`, which reads its domain tags from here.

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
    /// The first 32 bytes: `pad(32, name)`.
    pub const MISC_NAME_LEN: usize = 32;
    /// The remaining 256 bytes: the event's payload.
    pub const MISC_PAYLOAD_LEN: usize = 256;
    const _: () = assert!(MISC_NAME_LEN + MISC_PAYLOAD_LEN == MISC_SIZE);

    /// `pad(32, name)`: the name's bytes followed by zeros. The form the
    /// envelope's first 32 bytes take, so a reader compares 32 bytes against
    /// a constant rather than trimming zeros and comparing strings.
    ///
    /// A `const fn`, so `padded_name("...")` in a `const` is checked at
    /// compile time; the three event names are 22–25 bytes.
    ///
    /// # Panics
    ///
    /// If `name` is longer than 32 bytes.
    pub const fn padded_name(name: &str) -> [u8; MISC_NAME_LEN] {
        let bytes = name.as_bytes();
        assert!(bytes.len() <= MISC_NAME_LEN, "a Misc event name is padded into 32 bytes");
        let mut out = [0u8; MISC_NAME_LEN];
        let mut i = 0;
        while i < bytes.len() {
            out[i] = bytes[i];
            i += 1;
        }
        out
    }

    /// The two halves of a `Misc`'s 288 bytes, or `None` if `misc` is not
    /// exactly [`MISC_SIZE`] bytes long.
    pub fn split(misc: &[u8]) -> Option<(&[u8; MISC_NAME_LEN], &[u8; MISC_PAYLOAD_LEN])> {
        if misc.len() != MISC_SIZE {
            return None;
        }
        let (name, payload) = misc.split_at(MISC_NAME_LEN);
        Some((name.try_into().ok()?, payload.try_into().ok()?))
    }
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

    use super::misc::{padded_name, MISC_NAME_LEN};

    /// The first 32 bytes of `signBidirectional`'s Misc.
    pub const SIGN_BIDIRECTIONAL_EVENT_NAME: [u8; MISC_NAME_LEN] = padded_name(SIGN_BIDIRECTIONAL_EVENT);
    /// The first 32 bytes of `respond`'s Misc.
    pub const SIGNATURE_RESPONDED_EVENT_NAME: [u8; MISC_NAME_LEN] = padded_name(SIGNATURE_RESPONDED_EVENT);
    /// The first 32 bytes of `respondBidirectional`'s Misc.
    pub const RESPOND_BIDIRECTIONAL_EVENT_NAME: [u8; MISC_NAME_LEN] =
        padded_name(RESPOND_BIDIRECTIONAL_EVENT);

    /// The circuit whose Misc opens with these 32 bytes — the inverse of
    /// [`event_name`] over the padded form a reader finds on the ledger — or
    /// `None` for any other 32 bytes.
    pub fn circuit_of_event_name(name: &[u8; MISC_NAME_LEN]) -> Option<&'static str> {
        match *name {
            SIGN_BIDIRECTIONAL_EVENT_NAME => Some(SIGN_BIDIRECTIONAL),
            SIGNATURE_RESPONDED_EVENT_NAME => Some(RESPOND),
            RESPOND_BIDIRECTIONAL_EVENT_NAME => Some(RESPOND_BIDIRECTIONAL),
            _ => None,
        }
    }
}

/// The Signet module's protocol enums (midnight-integration v0.25.0,
/// `Signet.compact`), each carried on the ledger and in every hash as its
/// variant INDEX in one byte. The source says of every one of them: append
/// variants only.
///
/// Each type converts to its index with `as u8` and back with
/// `TryFrom<u8>`, which rejects an index past the last variant.
macro_rules! protocol_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $index:literal,)+ }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name {
            $($(#[$vdoc])* $variant = $index,)+
        }

        impl $name {
            /// Every variant, in index order.
            pub const ALL: &'static [$name] = &[$($name::$variant,)+];
        }

        impl TryFrom<u8> for $name {
            type Error = UnknownVariant;
            fn try_from(index: u8) -> Result<$name, UnknownVariant> {
                match index {
                    $($index => Ok($name::$variant),)+
                    _ => Err(UnknownVariant { r#enum: stringify!($name), index }),
                }
            }
        }

        impl From<$name> for u8 {
            fn from(variant: $name) -> u8 {
                variant as u8
            }
        }
    };
}

/// An index that names no variant of the enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownVariant {
    pub r#enum: &'static str,
    pub index: u8,
}

impl std::fmt::Display for UnknownVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} has no variant {}", self.r#enum, self.index)
    }
}

impl std::error::Error for UnknownVariant {}

protocol_enum! {
    /// `enum HashDomain`: the tag every protocol hash's preimage opens with,
    /// so no two hashes share a preimage.
    HashDomain {
        /// `calculateRequestIdV1`'s preimage.
        RequestId = 0,
        /// `calculateSignetAttestationDigestV1`'s preimage.
        AttestationDigest = 1,
        /// The head tuple of `calculateEvmType2TxParamsDigestV1`.
        EvmType2TxHeader = 2,
        /// One used calldata word chained onto the running digest.
        EvmType2TxWord = 3,
        /// One used access-list entry chained onto the running digest.
        EvmType2TxAccessEntry = 4,
        /// One used storage key chained onto an entry's running digest.
        EvmType2TxStorageKey = 5,
        /// `calculateAttestedOutputHashV1`'s preimage.
        AttestedOutput = 6,
    }
}

protocol_enum! {
    /// `enum OutputKind`: the MPC's verdict on a request's execution, signed
    /// into the attestation digest. Only `Executed` carries output bytes.
    OutputKind {
        /// Finalised and succeeded: the attested output is the decoded
        /// return data, Borsh-serialised by the MPC.
        Executed = 0,
        /// Finalised and reverted: the attested output is empty.
        Failed = 1,
        /// Another request from the same account took the nonce: the
        /// attested output is empty.
        Unviable = 2,
    }
}

protocol_enum! {
    /// `enum TxParamType`: which transaction decomposition a request's
    /// `txParams` is, so a reader knows how to reassemble it.
    TxParamType {
        /// `EvmType2TxParams`: an EIP-1559 transaction.
        EvmType2 = 0,
        /// Reserved; exists to keep the enum at two variants.
        Reserved = 1,
    }
}

protocol_enum! {
    /// `enum MPCSignatureAlgorithm`.
    SignatureAlgorithm {
        Ecdsa = 0,
        /// Reserved; exists to keep the enum at two variants.
        Reserved = 1,
    }
}

protocol_enum! {
    /// `enum MPCDestination`: a request's `signatureDest`, currently unused.
    SignatureDestination {
        Unused = 0,
        /// Reserved; exists to keep the enum at two variants.
        Reserved = 1,
    }
}

/// EXACTLY `@midnight-ntwrk/compact-js`'s `hashVerifierKey`
/// (`ContractKeyLocation.js`: `createHash('sha256').update(bytes).digest
/// ('hex')`) on the raw file bytes `prover.ts`'s `keyMaterial` reads with
/// `readFile` — no framing, no prefix. Lowercase hex, 64 characters.
///
/// The one definition in this workspace: `signet-artifacts` writes
/// `expectedVk.json` with it, `minocrab-publisher` checks a deployment's
/// verifier keys with it, and `signet-artifacts`' `tests/hash_verifier_key_pin.rs`
/// pins it against the TypeScript function itself under node (M29 B).
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

    #[test]
    fn padded_names_round_trip_through_the_reverse_map() {
        for circuit in circuits::SIGNER_CIRCUITS {
            let name = misc::padded_name(circuits::event_name(circuit).unwrap());
            assert_eq!(circuits::circuit_of_event_name(&name), Some(circuit), "{circuit}");
        }
        assert_eq!(circuits::circuit_of_event_name(&[0; 32]), None);
        let mut truncated = circuits::RESPOND_BIDIRECTIONAL_EVENT_NAME;
        truncated[24] = 0;
        assert_eq!(circuits::circuit_of_event_name(&truncated), None);
    }

    #[test]
    fn padded_name_is_the_bytes_then_zeros() {
        let name = misc::padded_name("SignatureRespondedEvent");
        assert_eq!(&name[..23], b"SignatureRespondedEvent");
        assert!(name[23..].iter().all(|&b| b == 0));
        assert_eq!(name, circuits::SIGNATURE_RESPONDED_EVENT_NAME);
    }

    #[test]
    fn split_takes_exactly_288_bytes() {
        let mut bytes = vec![0u8; misc::MISC_SIZE];
        bytes[..32].copy_from_slice(&circuits::SIGN_BIDIRECTIONAL_EVENT_NAME);
        bytes[32] = 0xee;
        let (name, payload) = misc::split(&bytes).unwrap();
        assert_eq!(name, &circuits::SIGN_BIDIRECTIONAL_EVENT_NAME);
        assert_eq!(payload[0], 0xee);
        assert!(misc::split(&bytes[..287]).is_none());
        bytes.push(0);
        assert!(misc::split(&bytes).is_none());
    }

    #[test]
    fn protocol_enums_index_and_parse_in_order() {
        for (i, d) in HashDomain::ALL.iter().enumerate() {
            assert_eq!(*d as u8, i as u8);
            assert_eq!(HashDomain::try_from(i as u8), Ok(*d));
        }
        assert_eq!(HashDomain::AttestedOutput as u8, 6);
        assert_eq!(HashDomain::try_from(7).unwrap_err().to_string(), "HashDomain has no variant 7");
        assert_eq!(OutputKind::try_from(2), Ok(OutputKind::Unviable));
        assert!(OutputKind::try_from(3).is_err());
        assert_eq!(TxParamType::EvmType2 as u8, 0);
        assert_eq!(SignatureAlgorithm::Ecdsa as u8, 0);
        assert_eq!(SignatureDestination::Unused as u8, 0);
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
