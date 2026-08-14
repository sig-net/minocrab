//! `test-caller-contract` (signet-midnight-integration) — the minimal
//! Signet caller. Only `initialise` is ported so far: it is the corpus's
//! smallest circuit exercising ledger READS (a Counter read and a Cell
//! read) alongside writes.
//!
//! Compact original:
//! ```text
//! export ledger requestLog: List<Bytes<32>>;            // field 0
//! export ledger signetRequestNonce: Counter;            // field 1
//! export ledger mpcResponseKey: Secp256k1Point;         // field 2
//! sealed ledger signetSigner: SignetSigner;             // field 3
//! export ledger signBidirectionalEventMap: …;           // field 4
//! sealed ledger deployer: Bytes<32>;                    // field 5
//! export ledger initialised: Counter;                   // field 6
//! export ledger signBidirectionalEventMap69: …;         // field 7
//!
//! witness deployerSecretKey(): Bytes<32>;
//!
//! initialise(responseKey: Secp256k1Point):
//!     assert(initialised == 0, "Already initialised: …");
//!     assert(deployerCommitment(deployerSecretKey()) == deployer, "Not the deployer");
//!     initialised.increment(1);
//!     mpcResponseKey = disclose(responseKey);
//! ```
//! with `deployerCommitment(sk) =
//! persistentHash<Vector<2, Bytes<32>>>([pad(32, "signet-caller:deployer:"), sk])`.

use minocrab::v3::{Circuit3, Compiled3, Secp256k1PointT};
use minocrab_ledger::{cell_write, counter_increment, emit, ImpactElem, LedgerValue};

use crate::common;

/// Ledger field indices, in declaration order.
pub const MPC_RESPONSE_KEY: u8 = 2;
pub const DEPLOYER: u8 = 5;
pub const INITIALISED: u8 = 6;

/// The domain-separation prefix of `deployerCommitment`.
pub const DEPLOYER_PAD: &str = "signet-caller:deployer:";

pub use crate::common::secp256k1_point_atoms;

/// `export circuit initialise(responseKey: Secp256k1Point): []`
pub fn initialise() -> Compiled3 {
    let mut c = Circuit3::new();
    let response_key = c.arg::<Secp256k1PointT>("responseKey");
    let one = c.constant(1u64);

    // assert(initialised == 0, "Already initialised: …")
    c.region("initialised gate", |c| {
        common::assert_counter_zero(c, one, INITIALISED);
    });

    // assert(deployerCommitment(deployerSecretKey()) == deployer, "Not the deployer")
    c.region("deployer gate", |c| {
        common::assert_deployer(c, one, DEPLOYER_PAD, DEPLOYER);
    });

    // initialised.increment(1)
    emit(&mut c, one, &counter_increment(INITIALISED, 1));

    // mpcResponseKey = disclose(responseKey)
    c.region("pin response key", |c| {
        let pk = c.disclose(response_key, "the MPC response key");
        let limbs = c.encode(pk);
        let value = LedgerValue::new(
            common::secp256k1_point_atoms(),
            limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
        );
        emit(c, one, &cell_write(MPC_RESPONSE_KEY, &value));
    });

    c.finish(true)
}
