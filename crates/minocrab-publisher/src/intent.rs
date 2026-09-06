//! From prototypes to an `Intent` with a TTL, and from an intent to a
//! `Transaction`.
//!
//! The three transaction shapes a publish passes through get names here, in
//! the order they occur:
//!
//! | alias | marker | when |
//! |---|---|---|
//! | [`PreimageTx`] | `ProofPreimageMarker`, `PedersenRandomness` | built, not proved |
//! | [`ProvenTx`] | `ProofMarker`, `PedersenRandomness` | proved, not sealed |
//! | [`SealedTx`] | `ProofMarker`, `PureGeneratorPedersen` | what `well_formed` takes |

use midnight_base_crypto::time::Timestamp;
use midnight_ledger::construct::ContractCallPrototype;
use midnight_ledger::structure::{
    ContractAction, ContractCall, Intent, ProofMarker, ProofPreimageMarker, Signature, Transaction,
};
use midnight_storage::db::DB;
use midnight_transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};
use rand::{CryptoRng, Rng};

/// An intent whose calls carry proof PREIMAGES.
pub type PreimageIntent<D> = Intent<Signature, ProofPreimageMarker, PedersenRandomness, D>;
/// The transaction that intent goes into.
pub type PreimageTx<D> = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, D>;
/// The same transaction after `Transaction::prove`.
pub type ProvenTx<D> = Transaction<Signature, ProofMarker, PedersenRandomness, D>;
/// … and after `seal`, which is the only shape `well_formed` accepts.
pub type SealedTx<D> = Transaction<Signature, ProofMarker, PureGeneratorPedersen, D>;

/// One intent over `protos`, expiring at `ttl`.
///
/// `Intent::new` folds each prototype through `add_call::<ProofPreimage>`,
/// which computes the communication commitment and calls
/// `ContractCallExt::construct_proof` (`ledger/src/construct.rs:515-573`) —
/// so the preimage in the intent is the ledger's, not ours.
///
/// The TTL is the publisher's policy and therefore an argument: past it the
/// transaction is unincludable, and the sidecar's own budget (360 s absolute,
/// with a 5-minute recipe TTL on the wallet side) is the shape of the number
/// mpc will want here.
pub fn build_intent<D: DB, R: Rng + CryptoRng + ?Sized>(
    rng: &mut R,
    protos: Vec<ContractCallPrototype<D>>,
    ttl: Timestamp,
) -> PreimageIntent<D> {
    Intent::new(rng, None, None, protos, vec![], vec![], None, ttl)
}

/// One intent at one segment, as a transaction on `network_id`.
///
/// Segment 0 is the GUARANTEED segment and the ledger refuses an intent
/// there (`PartitionFailure::IllegalSegmentZero`); a publisher picks 1 unless
/// it is merging with something else.
pub fn preimage_tx<D: DB>(network_id: &str, segment: u16, intent: PreimageIntent<D>) -> PreimageTx<D> {
    Transaction::from_intents(
        network_id,
        midnight_storage::storage::HashMap::new().insert(segment, intent),
    )
}

/// Every `ContractCall` in an intent, in order — how a caller reads back what
/// it just built (the preimage included).
pub fn calls_of<D: DB>(intent: &PreimageIntent<D>) -> Vec<ContractCall<ProofPreimageMarker, D>> {
    intent
        .actions
        .iter_deref()
        .filter_map(|action| match action {
            ContractAction::Call(call) => Some((**call).clone()),
            _ => None,
        })
        .collect()
}
