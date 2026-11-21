//! `test-caller-contract` (signet-midnight-integration) — the minimal
//! Signet caller. Only `initialise` is ported so far: it is the corpus's
//! smallest circuit exercising ledger READS (a Counter read and a Cell
//! read) alongside writes.
//!
//! Compact original (signet-midnight-integration v0.26.0-rc.15, `aa91570`):
//! ```text
//! export ledger requestLog: List<Bytes<32>>;            // field 0
//! export ledger mpcResponseKey: Secp256k1Point;         // field 1
//! sealed ledger signetSigner: SignetSigner;             // field 2
//! export ledger signBidirectionalEventMap: …;           // field 3
//! sealed ledger deployer: Bytes<32>;                    // field 4
//! export ledger initialised: Counter;                   // field 5
//! export ledger signBidirectionalEventMap69: …;         // field 6
//! export ledger checkAndDoubleAmounts: Map<…>;          // field 7
//! export ledger failureVerdicts: Map<…>;                // field 8
//!
//! witness deployerSecretKey(): Bytes<32>;
//!
//! initialise(responseKey: Secp256k1Point):
//!     assert(initialised == 0, "Already initialised: …");
//!     assert(deployerCommitment(deployerSecretKey()) == deployer, "Not the deployer");
//!     assert(responseKey != default<Secp256k1Point>, "Response key must not be the identity point");
//!     initialised.increment(1);
//!     mpcResponseKey = disclose(responseKey);
//! ```
//! with `deployerCommitment(sk) =
//! upgradeFromTransient(transientHash<Vector<2, Bytes<32>>>([pad(32, "signet-caller:deployer:"), sk]))`.
//! The `fff3421c` contract this was first ported from had a
//! `signetRequestNonce` counter at field 1 and no identity-key assert.

use minocrab::label;
use minocrab::Circuit;
use minocrab::AlignmentAtom;
use minocrab_experimental::impact::raw::{
    cell_read, cell_write, counter_increment, emit, ImpactElem, LedgerValue,
};
use minocrab_std::hash::upgrade_from_transient;
use minocrab_std::{contract, Disclose, Discloses, Secp256k1Point, B32};

use crate::common;

label! {
    MpcResponseKey = "the MPC response key";
}

/// Ledger field indices, in declaration order.
pub const MPC_RESPONSE_KEY: u8 = 1;
pub const DEPLOYER: u8 = 4;
pub const INITIALISED: u8 = 5;

/// The domain-separation prefix of `deployerCommitment`.
pub const DEPLOYER_PAD: &str = "signet-caller:deployer:";

pub use crate::common::secp256k1_point_atoms;

/// The Signet caller contract — one circuit so far, `initialise`.
pub struct TestCaller;

#[contract(lowering = minocrab_compat::profile)]
impl TestCaller {
    /// `export circuit initialise(responseKey: Secp256k1Point): []`
    #[circuit]
    pub fn initialise(
        c: &mut Circuit,
        response_key: Secp256k1Point,
    ) -> Discloses<(MpcResponseKey,)> {
        let response_key = response_key.point();
        // Kept even though guard threading no longer uses it: dropping this
        // `Copy` would renumber every later identifier, moving the ZKIR
        // (notes/edsl-trim.org §B, the removal's zero-movement gate).
        let _ = c.constant(1u64);

        // assert(initialised == 0, "Already initialised: …")
        c.region("initialised gate", |c| {
            common::assert_counter_zero(c, INITIALISED);
        });

        // assert(deployerCommitment(deployerSecretKey()) == deployer, "Not the deployer")
        // — `upgradeFromTransient(transientHash([pad, sk]))`.
        c.region("deployer gate", |c| {
            let sk = common::witness_sk(c).bytes();
            let pad = B32::pad(c, DEPLOYER_PAD);
            let f = c.transient_hash(&[pad.hi.private(), pad.lo.private(), sk.hi, sk.lo]);
            let digest = upgrade_from_transient(c, f);
            let stored = cell_read(c, DEPLOYER, vec![AlignmentAtom::Bytes { length: 32 }]);
            let eq_hi = c.test_eq(digest.hi, stored[0]);
            let eq_lo = c.test_eq(digest.lo, stored[1]);
            let both = c.mul(eq_hi, eq_lo);
            c.assert(both);
        });

        // assert(responseKey != default<Secp256k1Point>, …), compactc's
        // identity built in circuit.
        c.region("identity-key gate", |c| {
            minocrab_compat::secp::assert_not_identity(
                c,
                response_key,
                Some("Response key must not be the identity point"),
            );
        });

        // initialised.increment(1)
        emit(c, &counter_increment(INITIALISED, 1));

        // mpcResponseKey = disclose(responseKey)
        c.region("pin response key", |c| {
            let pk = response_key.disclose_as::<MpcResponseKey>(c);
            let limbs = c.encode(pk);
            let value = LedgerValue::new(
                common::secp256k1_point_atoms(),
                limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
            );
            emit(c, &cell_write(MPC_RESPONSE_KEY, &value));
        });
        Discloses::of(())
    }
}
