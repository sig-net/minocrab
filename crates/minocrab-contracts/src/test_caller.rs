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
//! upgradeFromTransient(transientHash<Vector<2, Bytes<32>>>([pad(32, "signet-caller:deployer:"), sk]))`
//! (signet-midnight-integration `fff3421c`; it was `persistentHash` before).

use minocrab::label;
use minocrab::v3::Circuit3;
use minocrab::AlignmentAtom;
use minocrab_ledger::{cell_read, cell_write, counter_increment, emit, ImpactElem, LedgerValue};
use minocrab_std::v3::hash::upgrade_from_transient;
use minocrab_std::v3::{contract, Disclose, Discloses, Secp256k1Point, B32};

use crate::common;

label! {
    MpcResponseKey = "the MPC response key";
}

/// Ledger field indices, in declaration order.
pub const MPC_RESPONSE_KEY: u8 = 2;
pub const DEPLOYER: u8 = 5;
pub const INITIALISED: u8 = 6;

/// The domain-separation prefix of `deployerCommitment`.
pub const DEPLOYER_PAD: &str = "signet-caller:deployer:";

pub use crate::common::secp256k1_point_atoms;

/// The Signet caller contract — one circuit so far, `initialise`.
pub struct TestCaller;

#[contract]
impl TestCaller {
    /// `export circuit initialise(responseKey: Secp256k1Point): []`
    #[circuit]
    pub fn initialise(
        c: &mut Circuit3,
        response_key: Secp256k1Point,
    ) -> Discloses<(MpcResponseKey,)> {
        let response_key = response_key.point();
        let one = c.constant(1u64);

        // assert(initialised == 0, "Already initialised: …")
        c.region("initialised gate", |c| {
            common::assert_counter_zero(c, one, INITIALISED);
        });

        // assert(deployerCommitment(deployerSecretKey()) == deployer, "Not the deployer")
        // — `upgradeFromTransient(transientHash([pad, sk]))`.
        c.region("deployer gate", |c| {
            let sk = common::witness_sk(c).bytes();
            let pad = B32::pad(c, DEPLOYER_PAD);
            let f = c.transient_hash(&[pad.hi.private(), pad.lo.private(), sk.hi, sk.lo]);
            let digest = upgrade_from_transient(c, f);
            let stored = cell_read(c, one, DEPLOYER, vec![AlignmentAtom::Bytes { length: 32 }]);
            let eq_hi = c.test_eq(digest.hi, stored[0]);
            let eq_lo = c.test_eq(digest.lo, stored[1]);
            let both = c.mul(eq_hi, eq_lo);
            c.assert(both);
        });

        // initialised.increment(1)
        emit(c, one, &counter_increment(INITIALISED, 1));

        // mpcResponseKey = disclose(responseKey)
        c.region("pin response key", |c| {
            let pk = response_key.disclose_as::<MpcResponseKey>(c);
            let limbs = c.encode(pk);
            let value = LedgerValue::new(
                common::secp256k1_point_atoms(),
                limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
            );
            emit(c, one, &cell_write(MPC_RESPONSE_KEY, &value));
        });
        Discloses::of(())
    }
}
