//! The [`Disclose`] impls for the stdlib's value types, and the
//! [`CircuitOut`] impl that makes a [`Discloses`] declaration free.
//!
//! The vocabulary itself — `label!`, [`DisclosureLabel`], [`LabelSet`],
//! [`Discloses`] and the generated test's `assert_declared_disclosures` —
//! lives in `minocrab::v3::disclose`, because a disclosure is a frontend
//! concept and minocrab-ledger discloses too (see that module's docs). This
//! file is the half that needs the types: one impl per Compact value shape,
//! each fanning its wires out under ONE label.

use minocrab::v3::{Circuit3, Disclose, DisclosureLabel, Discloses};
use minocrab::{Private, Public};

use super::entry::CircuitOut;
use super::{
    Bool, BoundedUint, Bytes, BytesN, ContractAddress, Either, JubjubPoint, MerkleTreeDigest,
    Opaque,
    Secp256k1Point, ShieldedCoinInfo3, TsType, Uint, UserAddress, B32,
};

impl<const BITS: u32> Disclose for Uint<BITS, Private> {
    type Public = Uint<BITS, Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Uint<BITS, Public> {
        Uint::from_field(self.field().disclose_as::<L>(c))
    }
}

impl<const BOUND: u128> Disclose for BoundedUint<BOUND, Private> {
    type Public = BoundedUint<BOUND, Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> BoundedUint<BOUND, Public> {
        BoundedUint::from_field(self.field().disclose_as::<L>(c))
    }
}

impl Disclose for Bool<Private> {
    type Public = Bool<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Bool<Public> {
        Bool::from_field(self.field().disclose_as::<L>(c))
    }
}

impl<const N: usize> Disclose for Bytes<N, Private> {
    type Public = Bytes<N, Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Bytes<N, Public> {
        Bytes::from_field(self.field().disclose_as::<L>(c))
    }
}

/// Both limbs under ONE label — where the hand-written circuits disclosed
/// `"… (hi)"` and `"… (lo)"` separately.
impl Disclose for B32<Private> {
    type Public = B32<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> B32<Public> {
        let [hi, lo] = c.disclose_all(L::LABEL, [self.hi, self.lo]);
        B32 { hi, lo }
    }
}

impl Disclose for ContractAddress<Private> {
    type Public = ContractAddress<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> ContractAddress<Public> {
        ContractAddress(self.0.disclose_as::<L>(c))
    }
}

/// `Either<A, B>`: the tag and BOTH arms, each under the same label — the
/// disclosure is of the whole value, because both arms occupy their slots
/// whichever way the tag points.
impl<A: Disclose, B: Disclose> Disclose for Either<A, B, Private> {
    type Public = Either<A::Public, B::Public, Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Self::Public {
        Either {
            is_left: self.is_left.disclose_as::<L>(c),
            left: self.left.disclose_as::<L>(c),
            right: self.right.disclose_as::<L>(c),
        }
    }
}

impl Disclose for UserAddress<Private> {
    type Public = UserAddress<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> UserAddress<Public> {
        UserAddress(self.0.disclose_as::<L>(c))
    }
}

impl Disclose for Secp256k1Point<Private> {
    type Public = Secp256k1Point<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Secp256k1Point<Public> {
        Secp256k1Point::from_point(self.point().disclose_as::<L>(c))
    }
}

impl Disclose for JubjubPoint<Private> {
    type Public = JubjubPoint<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> JubjubPoint<Public> {
        JubjubPoint::from_point(self.point().disclose_as::<L>(c))
    }
}

/// One slot, one label — and what the report records is the value's
/// `compress` COMMITMENT, not the TS-side value, because that is all the
/// circuit ever had (see [`Opaque`]'s docs). A disclosure report on an opaque
/// therefore says "this commitment left the circuit", which is the true and
/// the useful statement: the value itself was already on the caller's side.
impl<T: TsType> Disclose for Opaque<T, Private> {
    type Public = Opaque<T, Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> Opaque<T, Public> {
        Opaque::from_field(self.field().disclose_as::<L>(c))
    }
}

/// One slot, one label.
impl Disclose for MerkleTreeDigest<Private> {
    type Public = MerkleTreeDigest<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> MerkleTreeDigest<Public> {
        MerkleTreeDigest::from_field(self.field().disclose_as::<L>(c))
    }
}

/// Every limb of a `Bytes<N>` under one label (the `map_limbs` disclose
/// loops become one record).
impl<const N: usize> Disclose for BytesN<Private, N> {
    type Public = BytesN<Public, N>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> BytesN<Public, N> {
        BytesN::from_limbs(c.disclose_slice(L::LABEL, self.limbs()))
    }
}

/// The whole coin — nonce, color and value — under one label.
impl Disclose for ShieldedCoinInfo3<Private> {
    type Public = ShieldedCoinInfo3<Public>;

    fn disclose_as<L: DisclosureLabel>(self, c: &mut Circuit3) -> ShieldedCoinInfo3<Public> {
        let [nonce_hi, nonce_lo, color_hi, color_lo, value] = c.disclose_all(
            L::LABEL,
            [
                self.nonce.hi,
                self.nonce.lo,
                self.color.hi,
                self.color.lo,
                self.value,
            ],
        );
        ShieldedCoinInfo3 {
            nonce: B32 { hi: nonce_hi, lo: nonce_lo },
            color: B32 { hi: color_hi, lo: color_lo },
            value,
        }
    }
}

// ---- the declaration, as an output --------------------------------------------

/// Returning `Discloses<D, R>` emits exactly what returning `R` emits — the
/// declaration is type-level only.
impl<D, R: CircuitOut> CircuitOut for Discloses<D, R> {
    const SLOTS: usize = R::SLOTS;

    fn emit(self, c: &mut Circuit3, label: &str) {
        self.into_inner().emit(c, label);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use minocrab::v3::{disclosed_labels, FieldT};

    minocrab::label!(TheCoin = "the coin");
    minocrab::label!(TheId = "the id");

    /// Every wire of a value — a coin's five, a `Bytes<32>`'s two — is one
    /// record under one label, and disclosing costs no instruction.
    #[test]
    fn a_value_is_one_record_whatever_its_width() {
        let mut c = Circuit3::new();
        let w = c.arg::<FieldT>("w");
        let coin = ShieldedCoinInfo3::<Private> {
            nonce: B32 { hi: w, lo: w },
            color: B32 { hi: w, lo: w },
            value: w,
        };
        let id = B32::<Private> { hi: w, lo: w };
        let before = c.instruction_count();
        let _ = coin.disclose_as::<TheCoin>(&mut c);
        let _ = id.disclose_as::<TheId>(&mut c);
        assert_eq!(c.instruction_count(), before);

        let compiled = c.finish(false);
        let widths: Vec<(&str, usize)> = compiled
            .disclosures
            .iter()
            .map(|d| (d.label.as_str(), d.values.len()))
            .collect();
        assert_eq!(widths, vec![("the coin", 5), ("the id", 2)]);
        assert_eq!(disclosed_labels(&compiled), ["the coin", "the id"].into());
    }
}
