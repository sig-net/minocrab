//! ECDSA over secp256k1, as the MPC's signature is consumed on Midnight:
//! `bigR` as a point, `s`, and a recovery id — the shape the singleton's
//! `respondBidirectional` takes and the caller's settle circuit verifies
//! (`verify_attestation_signature`: `r = bigR.x` and `s`, both big-endian
//! on the wire; the digest is the big-endian message scalar).

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use sha3::{Digest, Keccak256};

/// A signature in the singleton's wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// `bigR.x`, big-endian.
    pub big_r_x: [u8; 32],
    /// `bigR.y`, big-endian.
    pub big_r_y: [u8; 32],
    /// `s`, big-endian.
    pub s: [u8; 32],
    /// `bigR.y`'s parity.
    pub recovery_id: u8,
}

/// The message scalar of a 32-byte digest, as the verifier reads it: the
/// digest as a big-endian integer, reduced.
pub fn message_scalar(digest: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&(*digest).into())
}

/// Sign `digest` under `d`. The nonce is deterministic in `(d, digest)`
/// (keccak, reduced) — a simulator's RFC 6979, not the MPC's threshold
/// protocol, whose output has the same shape.
pub fn sign(digest: &[u8; 32], d: &Scalar) -> Signature {
    let z = message_scalar(digest);
    let mut nonce_input = Vec::with_capacity(64);
    nonce_input.extend_from_slice(&d.to_bytes());
    nonce_input.extend_from_slice(digest);
    let nonce_hash: [u8; 32] = Keccak256::digest(&nonce_input).into();
    let mut k = <Scalar as Reduce<U256>>::reduce_bytes(&nonce_hash.into());
    loop {
        let big_r = (ProjectivePoint::GENERATOR * k).to_affine();
        let r = <Scalar as Reduce<U256>>::reduce_bytes(&big_r.x());
        if bool::from(r.is_zero()) {
            k += Scalar::ONE;
            continue;
        }
        let s = k.invert().unwrap() * (z + r * d);
        if bool::from(s.is_zero()) {
            k += Scalar::ONE;
            continue;
        }
        let encoded = big_r.to_encoded_point(false);
        let mut big_r_x = [0u8; 32];
        let mut big_r_y = [0u8; 32];
        big_r_x.copy_from_slice(encoded.x().unwrap());
        big_r_y.copy_from_slice(encoded.y().unwrap());
        return Signature {
            big_r_x,
            big_r_y,
            s: s.to_bytes().into(),
            recovery_id: big_r_y[31] & 1,
        };
    }
}

/// Textbook verification, for the simulator's own tests: `R' = z·s⁻¹·G +
/// r·s⁻¹·Q`, accept iff `R'.x ≡ r`.
pub fn verify(digest: &[u8; 32], sig: &Signature, q: &AffinePoint) -> bool {
    let z = message_scalar(digest);
    let Some(r) = Option::<Scalar>::from(Scalar::from_repr(sig.big_r_x.into())) else {
        return false;
    };
    let Some(s) = Option::<Scalar>::from(Scalar::from_repr(sig.s.into())) else {
        return false;
    };
    if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
        return false;
    }
    let s_inv = s.invert().unwrap();
    let point = (ProjectivePoint::GENERATOR * (z * s_inv) + ProjectivePoint::from(*q) * (r * s_inv)).to_affine();
    <Scalar as Reduce<U256>>::reduce_bytes(&point.x()) == r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_and_a_tampered_one_does_not() {
        let d = Scalar::from(123_456_789u64);
        let q = (ProjectivePoint::GENERATOR * d).to_affine();
        let digest = Keccak256::digest(b"attest").into();
        let sig = sign(&digest, &d);
        assert!(verify(&digest, &sig, &q));
        let mut bad = sig.clone();
        bad.s[31] ^= 1;
        assert!(!verify(&digest, &bad, &q));
        let other: [u8; 32] = Keccak256::digest(b"other").into();
        assert!(!verify(&other, &sig, &q));
    }
}
