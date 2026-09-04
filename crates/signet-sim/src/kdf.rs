//! Sig Network's epsilon derivation for Midnight, and the derived key.
//!
//! MECHANICAL TRANSLATION of `signet-crypto/src/kdf.rs` at `b940f0a7`
//! (the Midnight arms only), pinned by the same golden vectors the MPC
//! pins itself against (`fixtures/midnight-epsilon.json`).

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
use sha3::{Digest, Keccak256};

pub const EPSILON_DERIVATION_PREFIX_V1: &str = "sig.network v1.0.0 epsilon derivation";
pub const EPSILON_DERIVATION_PREFIX_V2: &str = "sig.network v2.0.0 epsilon derivation";
pub const MIDNIGHT_CHAIN_ID: &str = "midnight:mainnet";
/// The path the MPC derives its RESPONSE key under, per caller.
pub const MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH: &str = "midnight response key";

/// A hash reduced into the scalar field ("from_non_biased" upstream: the
/// bytes are a hash, so a value outside the field is a 2^-128 event).
fn keccak_scalar(s: &str) -> Scalar {
    let hash: [u8; 32] = Keccak256::digest(s.as_bytes()).into();
    <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
}

/// `derive_epsilon_midnight(key_version, address, path)`: the caip-2 form
/// for key version ≥ 1, the legacy comma form for version 0.
pub fn derive_epsilon_midnight(key_version: u32, address: &str, path: &str) -> Scalar {
    let derivation_path = match key_version {
        0 => format!("{EPSILON_DERIVATION_PREFIX_V1},{MIDNIGHT_CHAIN_ID},{address},{path}"),
        _ => format!("{EPSILON_DERIVATION_PREFIX_V2}:{MIDNIGHT_CHAIN_ID}:{address}:{path}"),
    };
    keccak_scalar(&derivation_path)
}

/// `derive_key`: `G·ε + root`.
pub fn derive_key(root: AffinePoint, epsilon: Scalar) -> AffinePoint {
    (ProjectivePoint::GENERATOR * epsilon + ProjectivePoint::from(root)).to_affine()
}

/// The 20-byte EVM address of a public key.
pub fn public_key_to_address(pk: &AffinePoint) -> [u8; 20] {
    let encoded = pk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes[0], 0x04);
    let hash: [u8; 32] = Keccak256::digest(&bytes[1..]).into();
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MPC's own golden: `@sig-net/midnight@0.14.0`'s
    /// `deriveEpsilon(requester, path, "midnight:mainnet")`.
    #[test]
    fn midnight_epsilon_matches_the_reference_implementation() {
        let golden: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/midnight-epsilon.json")).unwrap();
        assert_eq!(golden["constants"]["epsilon_derivation_prefix"], EPSILON_DERIVATION_PREFIX_V2);
        assert_eq!(golden["constants"]["midnight_chain_id"], MIDNIGHT_CHAIN_ID);
        assert_eq!(golden["constants"]["respond_bidirectional_path"], MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH);
        for vector in golden["vectors"].as_array().unwrap() {
            let (requester, path) = (vector["requester"].as_str().unwrap(), vector["path"].as_str().unwrap());
            let mut expected = [0u8; 32];
            hex::decode_to_slice(vector["epsilon"].as_str().unwrap(), &mut expected).unwrap();
            let got: [u8; 32] = derive_epsilon_midnight(1, requester, path).to_bytes().into();
            assert_eq!(
                got,
                expected,
                "requester {requester}, path {path:?}"
            );
        }
    }
}
