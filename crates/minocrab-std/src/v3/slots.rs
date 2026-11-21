//! The leaves' SLOTS: [`Encode`] and [`Decode`] for every value type of this
//! crate, written once each.
//!
//! A leaf that exists at both visibilities encodes at its own, generically
//! (`impl<V: Vis3> Encode<V> for Bool<V>`), so the same body is a circuit
//! argument's slots at [`Private`] and a cross-contract argument's, a ledger
//! write's and a proof-wire walk's at [`Public`]. Decoding is [`Public`]
//! only: it is what a call result and a ledger read rebuild, and both are
//! public.
//!
//! The visibility parameter is the soundness statement: `Encode<Public>`
//! holds only for public values, so `signer.sign_bidirectional(c, one,
//! request_id, …)` with a private `request_id` does not compile, and the fix
//! is `disclose`.
//!
//! The exceptions, each with its reason at the impl: the curve points and
//! the scalar encode at `Private` only, with NO slot (their wire is not a
//! field element); the coins encode and decode at `Public` only (nothing
//! takes a coin as a bare circuit argument); the bounded vectors and `Tag`
//! encode at `Private` beside their `CircuitArg` (see there).

use minocrab::v3::{Decode, Encode, FieldT, Wire3};
use minocrab::{Private, Public};

use super::{
    Bool, BoundedUint, Bytes, Bytes0, BytesN, CoinColor, CoinNonce, ContractAddress, Either,
    JubjubPoint, Maybe, MerkleTreeDigest, Opaque, QualifiedShieldedCoinInfo3, Secp256k1Point,
    Secp256k1Scalar, ShieldedCoinInfo3, TsType, Uint, UserAddress, Vis3, B32,
};

/// The one-slot leaves: the slot is `self.field()`, and decoding wraps it
/// back unchecked (the caller constrains it: a call result through the ABI
/// table, a ledger read through the op's `popeq`).
macro_rules! one_slot {
    ($( [$($gen:tt)*] $ty:ident<$($arg:tt),*> ),* $(,)?) => {$(
        impl<$($gen)*, V: Vis3> Encode<V> for $ty<$($arg,)* V> {
            fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
                slots.push(self.field());
            }
        }

        impl<$($gen)*> Decode<Public> for $ty<$($arg,)* Public> {
            fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
                $ty::from_field_unchecked(slots[0])
            }
        }
    )*};
}

one_slot! {
    [const BITS: u32] Uint<BITS>,
    [const BOUND: u128] BoundedUint<BOUND>,
    [const N: usize] Bytes<N>,
    // `Opaque<'ts-type'>`: the commitment limb. Its result is witnessed back
    // with no constraint, which is compactc's own lowering (the fixture's
    // caller binds it only through `transient_hash [cc-rand, arg, result]`,
    // notes/opaque-bridging.org §0a); the `Prim::Opaque` says so, not this.
    [T: TsType] Opaque<T>,
}

impl<V: Vis3> Encode<V> for Bool<V> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
        slots.push(self.field());
    }
}

impl Decode<Public> for Bool<Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        Bool::from_field_unchecked(slots[0])
    }
}

/// `MerkleTreeDigest`: one limb, unconstrained on the way back for the
/// reason an `Opaque` is (its `Prim::Field`).
impl<V: Vis3> Encode<V> for MerkleTreeDigest<V> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
        slots.push(self.field());
    }
}

impl Decode<Public> for MerkleTreeDigest<Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        MerkleTreeDigest::from_field_unchecked(slots[0])
    }
}

/// `Bytes<0>`: no slot.
impl<V: Vis3> Encode<V> for Bytes0<V> {
    fn encode(&self, _slots: &mut Vec<Wire3<FieldT, V>>) {}
}

impl Decode<Public> for Bytes0<Public> {
    fn decode(_slots: &[Wire3<FieldT, Public>]) -> Self {
        Bytes0::new()
    }
}

/// `Bytes<32>`: `hi` then `lo`.
impl<V: Vis3> Encode<V> for B32<V> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
        slots.push(self.hi);
        slots.push(self.lo);
    }
}

impl Decode<Public> for B32<Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        B32 {
            hi: slots[0],
            lo: slots[1],
        }
    }
}

/// `Bytes<N>`: its FAB limbs, the leftover chunk first.
impl<V: Vis3, const N: usize> Encode<V> for BytesN<V, N> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
        slots.extend_from_slice(self.limbs());
    }
}

impl<const N: usize> Decode<Public> for BytesN<Public, N> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        BytesN::from_limbs(slots.to_vec())
    }
}

/// The two address structs: exactly their `Bytes<32>`'s slots.
macro_rules! address {
    ($($ty:ident),*) => {$(
        impl<V: Vis3> Encode<V> for $ty<V> {
            fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
                self.0.encode(slots);
            }
        }

        impl Decode<Public> for $ty<Public> {
            fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
                $ty(B32::decode(slots))
            }
        }
    )*};
}

address!(ContractAddress, UserAddress);

/// Compact's `Maybe<T>`: the tag, then the value, which occupies its slots
/// whether or not the tag is set.
impl<T: Encode<V>, V: Vis3> Encode<V> for Maybe<T, V> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
        self.is_some.encode(slots);
        self.value.encode(slots);
    }
}

impl<T: Decode<Public>> Decode<Public> for Maybe<T, Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        Maybe {
            is_some: Bool::decode(&slots[..1]),
            value: T::decode(&slots[1..]),
        }
    }
}

/// Compact's `Either<A, B>`: the tag, then BOTH arms.
impl<A: Encode<V>, B: Encode<V>, V: Vis3> Encode<V> for Either<A, B, V> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, V>>) {
        self.is_left.encode(slots);
        self.left.encode(slots);
        self.right.encode(slots);
    }
}

impl<A: Decode<Public>, B: Decode<Public>> Decode<Public> for Either<A, B, Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        let left_end = 1 + A::SLOTS;
        Either {
            is_left: Bool::decode(&slots[..1]),
            left: A::decode(&slots[1..left_end]),
            right: B::decode(&slots[left_end..]),
        }
    }
}

/// The points and the scalar, as ARGUMENTS: one slot whose wire is not a
/// field element, so no native slot and no constraint (`(tpoint …) → no
/// constraint`). Not at `Public`: a point is not a cross-contract argument,
/// and its ledger form is computed by `encode` (see `LedgerStore`).
macro_rules! no_native_slot {
    ($($ty:ident),*) => {$(
        impl Encode<Private> for $ty<Private> {
            fn encode(&self, _slots: &mut Vec<Wire3<FieldT, Private>>) {}
        }
    )*};
}

no_native_slot!(Secp256k1Point, Secp256k1Scalar, JubjubPoint);

/// A coin crossing a boundary: nonce, color, value. `Public` only — a coin
/// argument is a derived record of its fields (`ShieldedCoinArg`).
impl Encode<Public> for ShieldedCoinInfo3<Public> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.nonce.encode(slots);
        self.color.encode(slots);
        slots.push(self.value);
    }
}

impl Decode<Public> for ShieldedCoinInfo3<Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        ShieldedCoinInfo3 {
            nonce: CoinNonce::decode(&slots[..2]),
            color: CoinColor::decode(&slots[2..4]),
            value: slots[4],
        }
    }
}

/// A QUALIFIED coin: [`ShieldedCoinInfo3`]'s slots then the `Uint<64>` tree
/// index. The AA manager's `pools` (`Map<Bytes<32>,
/// QualifiedShieldedCoinInfo>`) looks the pooled coin back up.
impl Encode<Public> for QualifiedShieldedCoinInfo3<Public> {
    fn encode(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        self.downcast().encode(slots);
        slots.push(self.mt_index);
    }
}

impl Decode<Public> for QualifiedShieldedCoinInfo3<Public> {
    fn decode(slots: &[Wire3<FieldT, Public>]) -> Self {
        let coin = ShieldedCoinInfo3::decode(&slots[..5]);
        QualifiedShieldedCoinInfo3 {
            nonce: coin.nonce,
            color: coin.color,
            value: coin.value,
            mt_index: slots[5],
        }
    }
}
