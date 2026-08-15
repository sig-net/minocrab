//! compactc's input-constraint table, ported once.
//!
//! `reduce-to-zkir.ss:640-667` (`emit-constraints-for`) is ONE function, and
//! it is the whole story of how a flattened primitive type becomes ZKIR
//! constraints. compactc runs it in two places — over a circuit's arguments,
//! and (via `make-witness`) over the values a cross-contract call witnesses
//! back — so before M12 we had the same table written by hand twice: once as
//! the leaves' `constrain_input`, once as `contract_call`'s
//! `&[Option<u32>]` result-bit list. Two hand-written copies of one rule is
//! exactly the drift hazard the M9 `CircuitArg` work was built to remove, so
//! here the rule lives once:
//!
//! ```text
//! (topaque …) | (tfield …) | (tpoint …)  →  no constraint
//! (tunsigned 0)                          →  constrain_eq  var 0
//! (tunsigned 1)                          →  constrain_to_boolean var
//! (tunsigned 2^k − 1)                    →  constrain_bits var k
//! (tunsigned nat)                        →  less_than tmp var (nat+1) bits
//!                                           assert    tmp
//! ```
//!
//! [`Prim`] is the dispatch input (compactc's `Lflattened Primitive-Type`),
//! [`LimbConstraint`] the dispatch output, [`Prim::constraint`] the table
//! itself, and [`LimbConstraint::emit`] the lowering. Nothing above this
//! module decides what a slot's constraint is.

use crate::{AlignmentAtom, Fr, Meet, Public, Visibility};

use super::{Circuit3, FieldT, Wire3};

/// One flattened primitive type — compactc's `Lflattened Primitive-Type`,
/// which is what [`Prim::constraint`] dispatches on.
///
/// The unsigned case is split by representation rather than by the raw
/// `maxval`: [`Prim::Uint`] carries the exponent of a `2^bits − 1` bound
/// (the only shape reachable from a typed leaf, and the shape of every
/// zkir-backed corpus artifact), [`Prim::UintMax`] a literal bound that is
/// not one less than a power of two. `Prim::unsigned` normalizes between
/// them, so a bound arriving as a number cannot land in the wrong variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prim {
    /// `(topaque …)` — an opaque runtime value.
    Opaque,
    /// `(tfield …)` — an unconstrained field element.
    Field,
    /// `(tpoint …)` — a curve point.
    Point,
    /// `(tunsigned nat)` with `nat = 2^bits − 1`. `bits = 0` is `Uint<0..0>`
    /// and `bits = 1` is `Boolean`; the table treats both specially.
    Uint { bits: u32 },
    /// `(tunsigned nat)` for a `nat` that is NOT one less than a power of
    /// two — two fixtures corpus-wide, neither with a compiled `.zkir`.
    UintMax { maxval: u128 },
}

impl Prim {
    /// `(tunsigned maxval)` from the bound itself, normalized: a
    /// `2^bits − 1` bound becomes [`Prim::Uint`], anything else
    /// [`Prim::UintMax`]. The two variants then have exactly one
    /// spelling each, so [`Prim::constraint`] can be a total match.
    pub const fn unsigned(maxval: u128) -> Prim {
        // `maxval + 1` is a power of two iff `maxval & (maxval + 1) == 0`
        // (compactc's own test, `(zero? (bitwise-and nat (1+ nat)))`),
        // taking `maxval = u128::MAX` — where the increment wraps — as the
        // power-of-two case it is (`2^128`).
        let next = maxval.wrapping_add(1);
        if maxval & next == 0 {
            Prim::Uint { bits: integer_length(maxval) }
        } else {
            Prim::UintMax { maxval }
        }
    }

    /// THE TABLE (`emit-constraints-for`, reduce-to-zkir.ss:640-667).
    pub const fn constraint(self) -> LimbConstraint {
        match self {
            // `[(topaque ,opaque-type) instr*]`, `[(tfield ,ftype) instr*]`,
            // `[(tpoint ,ctype) instr*]` — the type carries no range.
            Prim::Opaque | Prim::Field | Prim::Point => LimbConstraint::None,
            // `[(zero? nat) (constrain_eq ,var-name ,0)]`
            Prim::Uint { bits: 0 } => LimbConstraint::Zero,
            // `[(= 1 nat) (constrain_to_boolean ,var-name)]`
            Prim::Uint { bits: 1 } => LimbConstraint::Boolean,
            // `[(zero? (bitwise-and nat (1+ nat)))
            //   (constrain_bits ,var-name ,(integer-length nat))]`
            Prim::Uint { bits } => LimbConstraint::Bits(bits),
            // `[else (less_than ,tmp ,var-name ,(1+ nat) ,bits) (assert ,tmp)]`
            Prim::UintMax { maxval } => LimbConstraint::Bounded {
                bound: maxval + 1,
                bits: bounded_bits(maxval),
            },
        }
    }
}

/// The ZKIR constraint one argument/result slot carries — the output side of
/// [`Prim::constraint`], and the type `contract_call` takes one of per FAB
/// limb of the callee's declared return type.
///
/// `Option<u32>` (what `contract_call` took before M12) cannot express
/// `constrain_to_boolean` or `constrain_eq 0`, which is why this is an enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimbConstraint {
    /// No constraint at all (opaque / field / point slots).
    None,
    /// `constrain_eq var 0` — a `Uint<0..0>`.
    Zero,
    /// `constrain_to_boolean var` — a `Boolean` / `Uint<0..1>`.
    Boolean,
    /// `constrain_bits var k` — a `Uint<0..2^k − 1>`, including every
    /// `Bytes<n>` limb (`k = 8n`).
    Bits(u32),
    /// `less_than tmp var bound bits; assert tmp` — an exclusive bound that
    /// is not a power of two. `bits` is compactc's even-rounded width
    /// (`⌈log₄ bound⌉ · 2`), which Plonk's range gadget requires.
    Bounded { bound: u128, bits: u32 },
}

impl LimbConstraint {
    /// Emit this constraint on `w`, in the shape compactc emits it.
    ///
    /// The bounds are INLINE IMMEDIATES ([`Operand`]), not named constants,
    /// so the instruction stream matches compactc's slot for slot.
    pub fn emit<V: Visibility + Meet<Public, Out = V>>(
        self,
        c: &mut Circuit3,
        w: Wire3<FieldT, V>,
    ) {
        match self {
            LimbConstraint::None => {}
            LimbConstraint::Zero => c.assert_eq(w, 0u64),
            LimbConstraint::Boolean => c.assert_boolean(w),
            LimbConstraint::Bits(bits) => c.assert_bits(w, bits),
            LimbConstraint::Bounded { bound, bits } => {
                let in_range = c.less_than(w, fr_from_u128(bound), bits);
                c.assert(in_range);
            }
        }
    }
}

/// Scheme's `integer-length`: the number of bits in `n`'s binary
/// representation (`integer-length 0 = 0`, `integer-length 7 = 3`).
const fn integer_length(n: u128) -> u32 {
    u128::BITS - n.leading_zeros()
}

/// compactc's width for the `less_than` of a non-power-of-two bound:
/// `(* 2 (quotient (+ (integer-length (+ 1 nat)) 1) 2))` — `⌈log₄(nat+1)⌉`
/// doubled, so the range width is even, "as Plonk requires this to be a
/// multiple of two" (reduce-to-zkir.ss:655-661).
const fn bounded_bits(maxval: u128) -> u32 {
    2 * ((integer_length(maxval + 1) + 1) / 2)
}

/// A `u128` as a field element (`Fr: From<u64>` only). Sixteen
/// little-endian bytes always fit — the native field is 255 bits wide.
fn fr_from_u128(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit the native field")
}

// ---- CircuitAbi -------------------------------------------------------------

/// The ABI of a Compact type: how many native slots it occupies, the FAB
/// atoms of those slots, and the flattened PRIMITIVE type of each one.
///
/// This is the visibility-INDEPENDENT half of an argument type — a schema
/// says nothing about who may see the value — so it is implemented for
/// every visibility, and both directions of the wire build on it:
/// `minocrab_std::v3::CircuitArg` (the callee's own arguments, `Private`)
/// adds declaration and constraints, and [`CallArg`] / [`CallResult`] (the
/// caller's side of a cross-contract call, `Public`) add flattening. One
/// type therefore describes both sides of a call and cannot describe them
/// differently.
///
/// It lives HERE rather than beside the leaves because
/// `minocrab_ledger::call` — which is below the stdlib — has to name it.
///
/// `SLOTS` counts NATIVE SLOTS, which is not the atom count: a
/// `Bytes<32>` is one atom (`bytes 32`) across two slots (`hi`, `lo`).
/// [`Self::prims`] is the per-slot list, so `prims().len() == SLOTS`.
pub trait CircuitAbi {
    /// Native slots this type occupies.
    const SLOTS: usize;

    /// The FAB atoms of these slots, in slot order.
    fn push_atoms(atoms: &mut Vec<AlignmentAtom>);

    /// The flattened primitive type of each slot, in slot order — what
    /// compactc's constraint table dispatches on. Exactly [`Self::SLOTS`].
    fn push_prims(prims: &mut Vec<Prim>);

    /// The FAB atoms of these slots, in slot order.
    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        Self::push_atoms(&mut atoms);
        atoms
    }

    /// The primitive type of each slot, in slot order.
    fn prims() -> Vec<Prim> {
        let mut prims = Vec::with_capacity(Self::SLOTS);
        Self::push_prims(&mut prims);
        debug_assert_eq!(
            prims.len(),
            Self::SLOTS,
            "CircuitAbi::push_prims must describe exactly SLOTS slots"
        );
        prims
    }
}

// ---- the caller's side of a cross-contract call -----------------------------
//
// Both traits are implemented at `Public` ONLY, and that is a soundness
// statement, not a convenience: everything that crosses the contract
// boundary enters the communications commitment the ledger matches
// publicly, so passing a value cross-contract DISCLOSES it. A private value
// has to go through `Circuit3::disclose` first, and forgetting is a compile
// error rather than a leak — the same rule, for the same reason, as
// `CircuitOut`.

/// A value that can be PASSED to another contract's circuit.
pub trait CallArg: CircuitAbi {
    /// This value's slots, in slot order — exactly [`CircuitAbi::SLOTS`] of
    /// them, in the order the callee will declare its arguments.
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>);
}

/// A whole cross-contract argument list: the callee's parameters, in
/// declaration order.
///
/// Implemented for tuples (`()` for a parameterless circuit, `(a,)` for
/// one), which is what a typed call method builds from its own parameters.
/// A single struct standing for the whole list is a [`CallArg`], and
/// `(that,)` makes it an argument list.
pub trait CallArgs {
    /// Total slots — the sum of the members'.
    const SLOTS: usize;

    /// Every member's slots, in declaration order.
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>);

    /// The FAB atoms of the argument list, in slot order.
    fn push_atoms(atoms: &mut Vec<AlignmentAtom>);

    /// The flattened primitive type of each slot, in slot order.
    fn push_prims(prims: &mut Vec<Prim>);

    /// The argument list flattened into the limb vector `contract_call`
    /// hashes into the communications commitment.
    fn call_slots(&self) -> Vec<Wire3<FieldT, Public>> {
        let mut slots = Vec::with_capacity(Self::SLOTS);
        self.push_call_slots(&mut slots);
        debug_assert_eq!(slots.len(), Self::SLOTS, "CallArgs::SLOTS disagrees");
        slots
    }

    /// The FAB atoms of the argument list, in slot order.
    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        Self::push_atoms(&mut atoms);
        atoms
    }
}

/// A value a callee circuit RETURNS.
///
/// The caller witnesses one field element per slot and constrains each with
/// [`CircuitAbi::prims`] run through the SAME table that constrains the
/// callee's own arguments — which is the point of `CircuitAbi` being the
/// shared half: the constraint on a returned `Uint<128>` is the constraint
/// on a passed one, by construction rather than by hand.
pub trait CallResult: CircuitAbi + Sized {
    /// Rebuild from the witnessed result slots, in slot order. `slots` has
    /// exactly [`CircuitAbi::SLOTS`] entries.
    fn from_call_slots(slots: &[Wire3<FieldT, Public>]) -> Self;
}

/// Compact's `Vector<N, T>`: `N` copies of `T` back to back. Arrays are a
/// foreign type, so the impl lives with the trait rather than with the
/// leaves (`minocrab_std::v3` has the matching `CircuitArg` half).
impl<T: CircuitAbi, const N: usize> CircuitAbi for [T; N] {
    const SLOTS: usize = T::SLOTS * N;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        for _ in 0..N {
            T::push_atoms(atoms);
        }
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        for _ in 0..N {
            T::push_prims(prims);
        }
    }
}

impl<T: CallArg, const N: usize> CallArg for [T; N] {
    fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
        for element in self {
            element.push_call_slots(slots);
        }
    }
}

/// `[]` — a circuit that takes or returns nothing.
impl CircuitAbi for () {
    const SLOTS: usize = 0;

    fn push_atoms(_atoms: &mut Vec<AlignmentAtom>) {}

    fn push_prims(_prims: &mut Vec<Prim>) {}
}

impl CallArg for () {
    fn push_call_slots(&self, _slots: &mut Vec<Wire3<FieldT, Public>>) {}
}

impl CallResult for () {
    fn from_call_slots(_slots: &[Wire3<FieldT, Public>]) -> Self {}
}

macro_rules! call_args_tuple {
    ($($name:ident),*) => {
        #[allow(non_snake_case, unused_variables)]
        impl<$($name: CallArg),*> CallArgs for ($($name,)*) {
            const SLOTS: usize = 0usize $( + <$name as CircuitAbi>::SLOTS )*;

            fn push_call_slots(&self, slots: &mut Vec<Wire3<FieldT, Public>>) {
                let ($($name,)*) = self;
                $( <$name as CallArg>::push_call_slots($name, slots); )*
            }

            fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
                $( <$name as CircuitAbi>::push_atoms(atoms); )*
            }

            fn push_prims(prims: &mut Vec<Prim>) {
                $( <$name as CircuitAbi>::push_prims(prims); )*
            }
        }
    };
}

// Compact's own arity ceiling is well under this; twelve matches the
// tuple impls the Rust ecosystem conventionally stops at.
call_args_tuple!();
call_args_tuple!(A);
call_args_tuple!(A, B);
call_args_tuple!(A, B, C);
call_args_tuple!(A, B, C, D);
call_args_tuple!(A, B, C, D, E);
call_args_tuple!(A, B, C, D, E, F);
call_args_tuple!(A, B, C, D, E, F, G);
call_args_tuple!(A, B, C, D, E, F, G, H);
call_args_tuple!(A, B, C, D, E, F, G, H, I);
call_args_tuple!(A, B, C, D, E, F, G, H, I, J);
call_args_tuple!(A, B, C, D, E, F, G, H, I, J, K);
call_args_tuple!(A, B, C, D, E, F, G, H, I, J, K, L);

#[cfg(test)]
mod tests {
    use super::*;

    /// `(topaque …)`, `(tfield …)`, `(tpoint …)` → `instr*` unchanged.
    #[test]
    fn opaque_field_and_point_carry_no_constraint() {
        assert_eq!(Prim::Opaque.constraint(), LimbConstraint::None);
        assert_eq!(Prim::Field.constraint(), LimbConstraint::None);
        assert_eq!(Prim::Point.constraint(), LimbConstraint::None);
    }

    /// `[(zero? nat) (constrain_eq ,var-name ,0)]`.
    #[test]
    fn a_zero_bound_is_constrain_eq_zero() {
        assert_eq!(Prim::unsigned(0), Prim::Uint { bits: 0 });
        assert_eq!(Prim::Uint { bits: 0 }.constraint(), LimbConstraint::Zero);
    }

    /// `[(= 1 nat) (constrain_to_boolean ,var-name)]`.
    #[test]
    fn a_one_bound_is_constrain_to_boolean() {
        assert_eq!(Prim::unsigned(1), Prim::Uint { bits: 1 });
        assert_eq!(Prim::Uint { bits: 1 }.constraint(), LimbConstraint::Boolean);
    }

    /// `[(zero? (bitwise-and nat (1+ nat)))
    ///   (constrain_bits ,var-name ,(integer-length nat))]` — the width IS
    /// `integer-length nat`, checked over every exponent a leaf can produce.
    #[test]
    fn a_power_of_two_bound_is_constrain_bits() {
        for bits in 2..=128u32 {
            let maxval = if bits == 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };
            assert_eq!(
                Prim::unsigned(maxval),
                Prim::Uint { bits },
                "maxval {maxval} should be 2^{bits} - 1"
            );
            assert_eq!(
                Prim::Uint { bits }.constraint(),
                LimbConstraint::Bits(bits),
                "constrain_bits width for 2^{bits} - 1"
            );
        }
        // The widths the FAB leaves actually ask for.
        assert_eq!(Prim::unsigned(255).constraint(), LimbConstraint::Bits(8));
        assert_eq!(
            Prim::Uint { bits: 248 }.constraint(),
            LimbConstraint::Bits(248)
        );
    }

    /// `[else …(less_than ,tmp ,var-name ,(1+ nat) ,bits)…]` with
    /// `bits = (* 2 (quotient (+ (integer-length (+ 1 nat)) 1) 2))`.
    #[test]
    fn any_other_bound_is_an_even_width_less_than() {
        // Worked by hand from the Scheme: nat = 5 ⇒ nat+1 = 6,
        // integer-length 6 = 3, bits = 2·((3+1)/2) = 4.
        assert_eq!(
            Prim::unsigned(5).constraint(),
            LimbConstraint::Bounded { bound: 6, bits: 4 }
        );
        // nat = 2 ⇒ nat+1 = 3, integer-length 3 = 2, bits = 2·((2+1)/2) = 2.
        assert_eq!(
            Prim::unsigned(2).constraint(),
            LimbConstraint::Bounded { bound: 3, bits: 2 }
        );
        // nat = 999 ⇒ nat+1 = 1000, integer-length 1000 = 10,
        // bits = 2·((10+1)/2) = 10.
        assert_eq!(
            Prim::unsigned(999).constraint(),
            LimbConstraint::Bounded { bound: 1000, bits: 10 }
        );
        // The width is always even and always enough for the bound.
        for maxval in 2..2000u128 {
            if let LimbConstraint::Bounded { bound, bits } = Prim::unsigned(maxval).constraint() {
                assert_eq!(bits % 2, 0, "Plonk wants an even width (maxval {maxval})");
                assert!(
                    bound <= 1u128 << bits,
                    "width {bits} cannot hold bound {bound}"
                );
            }
        }
    }

    /// The variants partition the unsigned bounds: every `maxval` lands in
    /// exactly the branch compactc's own predicate picks.
    #[test]
    fn the_two_unsigned_variants_partition_the_bounds() {
        for maxval in 0..4096u128 {
            let compactc_says_power_of_two = maxval & (maxval + 1) == 0;
            match Prim::unsigned(maxval) {
                Prim::Uint { bits } => {
                    assert!(compactc_says_power_of_two, "maxval {maxval}");
                    assert_eq!(bits, integer_length(maxval));
                }
                Prim::UintMax { maxval: m } => {
                    assert!(!compactc_says_power_of_two, "maxval {maxval}");
                    assert_eq!(m, maxval);
                }
                other => panic!("unsigned bound became {other:?}"),
            }
        }
    }

    #[test]
    fn a_u128_bound_reaches_the_field_intact() {
        assert_eq!(fr_from_u128(0), Fr::from(0u64));
        assert_eq!(fr_from_u128(u64::MAX as u128), Fr::from(u64::MAX));
        assert_eq!(
            fr_from_u128(u128::MAX),
            Fr::from_le_bytes(&u128::MAX.to_le_bytes()).unwrap()
        );
        assert_eq!(
            fr_from_u128(1 << 100),
            Fr::from_le_bytes(&(1u128 << 100).to_le_bytes()).unwrap()
        );
    }
}
