//! One error type for the whole publisher.
//!
//! Everything here is a RUNTIME rejection — a malformed deployment table, a
//! transcript the ledger will not partition, a key file that is not on disk —
//! so it is a `Result`, not a compile error (CLAUDE.md's "compile errors over
//! panics" ranks the value-dependent case last, and this is that case). The
//! upstream failures the ledger reports are generic over the storage backend
//! (`PartitionFailure<D>`, `MalformedTransaction<D>`, `TransactionProvingError
//! <D>`), so they are carried here as their `Debug` rendering rather than
//! leaking `D` into every signature in this crate.

/// Anything that can go wrong building, proving, signing or sealing a signer
/// intent.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// A circuit name that is not one of [`crate::call::SIGNER_CIRCUITS`], or
    /// one the deployment's `expectedVk` table does not carry.
    #[error("unknown signer circuit '{0}'")]
    UnknownCircuit(String),
    /// A verifier-key hash that is not 64 lowercase hex characters, or a
    /// circuit id carrying a `/` or `?` — the three shapes compact-js's
    /// `encodeContractKeyLocation` refuses (`ContractKeyLocation.js`).
    #[error("{0}")]
    KeyLocation(String),
    /// The logged bytes are not exactly one Misc envelope.
    #[error("the Misc payload is {got} bytes, not {want}")]
    MiscSize { got: usize, want: usize },
    /// `partition_transcripts` refused the program.
    #[error("the ledger could not partition the call's transcript: {0}")]
    Partition(String),
    /// `partition_transcripts` returned no transcript pair for a call, or a
    /// pair with no guaranteed half.
    #[error("the ledger produced no guaranteed transcript for '{0}'")]
    NoTranscript(String),
    /// A key, IR or parameter file the resolver needs is missing or unreadable.
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The deployed contract's verifier key for a circuit is not the one the
    /// `expectedVk` table records — the sidecar's `prover.ts` gate, and the
    /// reason a lying endpoint's respond call fails safe
    /// (notes/mpc-publisher.org §5.2).
    #[error("{circuit}: the deployed verifier key hashes to {got}, not the expected {expected}")]
    VerifierKeyMismatch { circuit: String, expected: String, got: String },
    /// A file on disk did not deserialize as the type its name claims.
    #[error("{path} is not a tagged {what}: {message}")]
    Decode { path: String, what: &'static str, message: String },
    /// `Transaction::prove` failed.
    #[error("proving failed: {0}")]
    Proving(String),
    /// `Intent::sign` rejected the intent (a signing key that does not own the
    /// input it was offered, for instance).
    #[error("signing failed: {0}")]
    Signing(String),
    /// The dust seam (M30 rung C) refused to balance the transaction.
    #[error("dust balancing failed: {0}")]
    Dust(String),
}
