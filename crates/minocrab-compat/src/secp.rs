//! `secp256k1EcdsaVerify`, as compactc 0.36 lowers it.
//!
//! WHAT IS COMPACTC'S: the identity point the key is refused against is
//! BUILT in circuit, `ec_mul_generator` of a zero scalar made by two
//! conversions (`into_bytes32` then `from_bytes32`), and the recovered
//! point's x coordinate makes a round trip through `Bytes<32>` (into bytes,
//! the limb pair and back) before it is compared with `r`. THE LEAN FORM
//! compares against the identity as a constant and converts the coordinate
//! once.

use minocrab::v3::{Circuit3, FieldT, Secp256k1PointT, Secp256k1ScalarT, Wire3};
use minocrab::Public;
use minocrab_std::v3::{hash_to_secp256k1_scalar, Secp256k1EcdsaSignature, Vis3, B32};

/// `pk != default<Secp256k1Point>`, asserted. compactc's: the default point
/// is generator · 0, built as `to_bytes(0)` → `from_bytes` scalar →
/// `ec_mul_generator`, where the lean form names the identity directly.
fn assert_not_identity<V: Vis3>(c: &mut Circuit3, pk: Wire3<Secp256k1PointT, V>, message: Option<&'static str>) {
    let zero = c.constant(0u64);
    let zero_bytes = c.into_bytes32(zero);
    let zero_scalar: Wire3<Secp256k1ScalarT, Public> = c.from_bytes32(zero_bytes);
    let identity = c.ec_mul_generator(zero_scalar);
    let is_identity = c.test_eq(pk, V::from_public(identity));
    let not_identity = c.not(is_identity);
    c.assert_with(not_identity, message);
}

/// `circuit secp256k1EcdsaVerify(msgHash, sig, pk): Boolean`
///
/// Standard ECDSA: `w = s⁻¹`, `u1 = z·w`, `u2 = r·w`, `P = u1·G + u2·pk`,
/// valid iff `P.x == r` as 32-byte big-endian integers. Accepts both low-s
/// and high-s signatures (as the library does); `msgHash` is taken as given
/// and must be bound to the real message by the caller. The point at
/// infinity is rejected (`pk != default<Secp256k1Point>`). compactc's in the
/// identity it builds (`assert_not_identity`) and the x coordinate's round
/// trip; the lean form skips both.
pub fn secp256k1_ecdsa_verify<V: Vis3>(
    c: &mut Circuit3,
    msg_hash: &B32<V>,
    sig: &Secp256k1EcdsaSignature<V>,
    pk: Wire3<Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    // Private key 0 signs anything, so the point at infinity is refused
    // first, as compactc 0.36's library does.
    assert_not_identity(
        c,
        pk,
        Some("Secp256k1Point identity is not a permitted secp256k1EcdsaVerify verification key"),
    );
    let z = hash_to_secp256k1_scalar(c, msg_hash);
    let w = c.inv(sig.s);
    let u1 = c.mul(z, w);
    let u2 = c.mul(sig.r, w);
    let g_u1 = c.ec_mul_generator(u1);
    let pk_u2 = c.ec_mul(pk, u2);
    let point = c.add(g_u1, pk_u2);

    // (secp256k1PointX(point) as Bytes<32>) as Secp256k1Scalar == r —
    // compactc emits the into/from round-trip as-is.
    let (x, _y) = c.into_coordinates(point);
    let x_bytes = c.into_bytes32(x);
    let x_pair = B32::from_typed(c, x_bytes);
    let x_typed = x_pair.to_typed(c);
    let x_scalar: Wire3<Secp256k1ScalarT, V> = c.from_bytes32(x_typed);
    c.test_eq(x_scalar, sig.r)
}
