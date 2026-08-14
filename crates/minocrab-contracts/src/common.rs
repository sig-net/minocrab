//! Shapes shared across the sig-net contracts.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Visibility};
use minocrab_ledger::{cell_read, counter_read};
use minocrab_std::v3::B32;

/// A `Secp256k1Point`'s FAB alignment: x as b24+b8, y as b24+b8, plus a
/// native field element (notes/ledger-abi.org §3) — 5 limbs, matching
/// `encode`'s output.
pub fn secp256k1_point_atoms() -> Vec<AlignmentAtom> {
    vec![
        AlignmentAtom::Bytes { length: 24 },
        AlignmentAtom::Bytes { length: 8 },
        AlignmentAtom::Bytes { length: 24 },
        AlignmentAtom::Bytes { length: 8 },
        AlignmentAtom::Field,
    ]
}

/// The identity commitment both contracts derive:
/// `persistentHash<Vector<2, Bytes<32>>>([pad(32, prefix), sk])`.
pub fn commitment(c: &mut Circuit3, prefix: &str, sk: &B32<Private>) -> B32<Private> {
    let pad = B32::pad(c, prefix);
    let alignment = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ]);
    let digest = c.persistent_hash(
        alignment,
        &[
            pad.hi.private().erase(),
            pad.lo.private().erase(),
            sk.hi.erase(),
            sk.lo.erase(),
        ],
    );
    B32::from_typed(c, digest)
}

/// Witness a secret key (`witness …SecretKey(): Bytes<32>`), input-constrained.
pub fn witness_sk(c: &mut Circuit3) -> B32<Private> {
    let sk = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    sk.constrain_input(c);
    sk
}

/// The one-shot gate: `assert(<counter at field> == 0)`.
pub fn assert_counter_zero<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    field: u8,
) {
    let count = counter_read(c, guard, field);
    let zero = c.constant(0u64);
    let unset = c.test_eq(count, zero);
    c.assert(unset);
}

/// The deployer gate: `assert(commitment(prefix, <witnessed sk>) ==
/// <Bytes<32> cell at deployer_field>)`.
pub fn assert_deployer<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    prefix: &str,
    deployer_field: u8,
) {
    let sk = witness_sk(c);
    let digest = commitment(c, prefix, &sk);
    let stored = cell_read(
        c,
        guard,
        deployer_field,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let eq_hi = c.test_eq(digest.hi, stored[0]);
    let eq_lo = c.test_eq(digest.lo, stored[1]);
    let both = c.mul(eq_hi, eq_lo);
    c.assert(both);
}
