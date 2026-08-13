//! Schnorr signatures over the native (Jubjub) curve.
//!
//! Port of `jubjubSchnorrVerify` from `standard-library.compact`, following
//! compactc's v2 lowering (notes/builtin-lowering.org §12): the challenge
//! hash is Poseidon over `[annX, annY, pkX, pkY, msg...]`, and the two
//! `as JubjubScalar` casts are plain copies in v2 (no modular reduction —
//! a real v2/v3 semantic divergence to revisit for the v3 backend).

use minocrab::{Circuit, Wire};

use crate::bundle::{eq, Vis};
use crate::types::JubjubPoint;

/// `struct JubjubSchnorrSignature { announcement: JubjubPoint, response: Field }`
#[derive(Clone, Copy)]
pub struct JubjubSchnorrSignature<V: Vis> {
    pub announcement: JubjubPoint<V>,
    pub response: Wire<V>,
}

/// `circuit jubjubSchnorrVerify<#N>(msg, signature, pk): Boolean`
pub fn jubjub_schnorr_verify<V: Vis>(
    c: &mut Circuit,
    msg: &[Wire<V>],
    signature: &JubjubSchnorrSignature<V>,
    pk: &JubjubPoint<V>,
) -> Wire<V> {
    let JubjubSchnorrSignature {
        announcement,
        response,
    } = *signature;

    // transientHash<JubjubSchnorrHashInput<N>>{annX, annY, pkX, pkY, msg}
    let mut inputs = vec![announcement.x, announcement.y, pk.x, pk.y];
    inputs.extend_from_slice(msg);
    let challenge = c.transient_hash(&inputs);
    // `cNative as JubjubScalar` / `response as JubjubScalar`: v2 copies.

    let (lhs_x, lhs_y) = c.ec_mul_generator(response);
    let scaled = c.ec_mul((pk.x, pk.y), challenge);
    let (rhs_x, rhs_y) = c.ec_add((announcement.x, announcement.y), scaled);

    let lhs = JubjubPoint { x: lhs_x, y: lhs_y };
    let rhs = JubjubPoint { x: rhs_x, y: rhs_y };
    eq(c, &lhs, &rhs)
}
