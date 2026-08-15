//! Assertion predicates: `c.assert(less_than(0u64, amount))`.
//!
//! A predicate is an INERT DESCRIPTOR of a check. `less_than(a, b)` builds a
//! value and emits nothing; `c.assert(p)` lowers it — the comparison
//! instruction and the `assert`, at the assert site. An unasserted predicate
//! therefore costs nothing at all and warns ([`Check`] is `#[must_use]`),
//! which is strictly safer than today's unasserted `c.less_than(..)`: that
//! one emits cost, constrains nothing, and no lint says so.
//!
//! WHAT IT BUYS is soundness wearing ergonomics clothing:
//!
//! - **the width comes from the operand TYPES.** `c.less_than(a, b, 128)`
//!   takes the width as a hand-typed number — the same genus of bug as the
//!   hand-written `assert_bits` blocks the typed leaves removed, and just as
//!   invisible to PI equality on honest preimages. `less_than(a, amount)`
//!   with `amount: Uint<128>` reads the 128 off the type. Two typed operands
//!   must agree; a raw `Wire3` carries no width, so a comparison of two of
//!   them is a build-time panic naming the fix, not a silently wrong range.
//! - **the constant side is a CHECKED IMMEDIATE.** A literal operand becomes
//!   a v3 inline immediate (`Operand`, phase 7's literals piece — no `Copy`),
//!   and it is checked at build time against the width it is being compared
//!   at: `less_than(amount_u8, 300u64)` panics rather than comparing against
//!   a value the width cannot hold.
//!
//! SCOPE, deliberately hard (notes/contract-api.org §The design): comparisons
//! (`less_than`/`le`/`greater_than`/`ge`/`eq`/`ne`), the combinators
//! [`not`]/[`Check::and`]/[`Check::or`], an optional message
//! ([`Check::message`], Compact's second `assert` argument) and
//! [`Check::eval`] for a circuit that wants the boolean wire. NO deferred
//! ARITHMETIC and no expression templates: `a + b` returning a descriptor
//! would hide emission inside an operator, which is the no-hidden-cost rule
//! this whole layer is built on. And no macros — these are ordinary functions
//! and methods.
//!
//! Two surfaces, one implementation: the free constructors here, and the
//! same names as methods on the typed leaves (`amount.gt(0u64)`), which
//! delegate.
//!
//! Rust fact shaping all of it: `PartialOrd` is hardwired to return `bool`,
//! so `amount > 0` can never be a circuit expression. Named constructors are
//! the ceiling, and they are what this module provides.

use minocrab::v3::{Assertion, Circuit3, FieldT, Operand, Wire3};
use minocrab::{Fr, Meet, Public};

use super::{Bool, Bytes, Uint, Vis3};

/// The comparison a [`Check`] leaf describes, and how it lowers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    /// `a < b` — `less_than a b bits`.
    Less,
    /// `a == b` — `test_eq a b` (no width needed).
    Equal,
}

/// A deferred check. Build one with [`less_than`] and friends, then
/// `c.assert(p)` (or `p.eval(c)` for the wire).
///
/// `V` is the visibility of the result: comparing a private value against
/// anything is private, and the constant side is public, so the usual
/// [`Meet`] applies.
#[must_use = "a predicate describes a check and emits nothing on its own — \
              assert it with `c.assert(p)`, or evaluate it with `p.eval(c)`"]
pub struct Check<V: Vis3> {
    node: Node<V>,
    message: Option<&'static str>,
}

enum Node<V: Vis3> {
    /// A comparison, with the width already resolved from the operand types.
    Compare {
        cmp: Cmp,
        a: Operand<FieldT, V>,
        b: Operand<FieldT, V>,
        bits: u32,
        /// The lowering ends in `not` (`ne`, `le`, `ge` are negated forms).
        negated: bool,
    },
    Not(Box<Node<V>>),
    And(Box<Node<V>>, Box<Node<V>>),
    Or(Box<Node<V>>, Box<Node<V>>),
}

/// One side of a comparison: a typed leaf (which carries the WIDTH), a raw
/// wire (which does not), or a native Rust literal (which becomes an inline
/// immediate, and is range-checked against the width the comparison runs at).
///
/// Implemented for the `Public` leaves at every visibility, because a public
/// value may be compared against a private one — the result is then private,
/// which is what [`Meet`] says.
pub trait CheckOperand {
    /// The visibility this operand contributes.
    type Vis: Vis3;

    /// The width this operand's TYPE carries, if any. `None` for a raw wire
    /// and for a literal.
    const BITS: Option<u32>;

    /// The value, if it is a literal — what the range check looks at.
    fn literal(&self) -> Option<Fr> {
        None
    }

    /// The operand itself.
    fn operand(self) -> Operand<FieldT, Self::Vis>;
}

impl<V: Vis3> CheckOperand for Wire3<FieldT, V> {
    type Vis = V;
    const BITS: Option<u32> = None;

    fn operand(self) -> Operand<FieldT, V> {
        self.into()
    }
}

impl<const BITS: u32, V: Vis3> CheckOperand for Uint<BITS, V> {
    type Vis = V;
    const BITS: Option<u32> = Some(BITS);

    fn operand(self) -> Operand<FieldT, V> {
        self.field().into()
    }
}

impl<const N: usize, V: Vis3> CheckOperand for Bytes<N, V> {
    type Vis = V;
    const BITS: Option<u32> = Some(8 * N as u32);

    fn operand(self) -> Operand<FieldT, V> {
        self.field().into()
    }
}

impl<V: Vis3> CheckOperand for Bool<V> {
    type Vis = V;
    const BITS: Option<u32> = Some(1);

    fn operand(self) -> Operand<FieldT, V> {
        self.field().into()
    }
}

/// Literals: public, no width of their own, and range-checked against the
/// width of whatever they are compared with.
macro_rules! literal_operand {
    ($($ty:ty),* $(,)?) => {$(
        impl CheckOperand for $ty {
            type Vis = Public;
            const BITS: Option<u32> = None;

            fn literal(&self) -> Option<Fr> {
                Some(Fr::from(u64::from(*self)))
            }

            fn operand(self) -> Operand<FieldT, Public> {
                self.into()
            }
        }
    )*};
}

literal_operand!(u64, u32, u8, bool);

impl CheckOperand for Fr {
    type Vis = Public;
    const BITS: Option<u32> = None;

    fn literal(&self) -> Option<Fr> {
        Some(*self)
    }

    fn operand(self) -> Operand<FieldT, Public> {
        self.into()
    }
}

/// The visibility of a comparison of an `A` with a `B`: the meet.
type Joined<A, B> = <<A as CheckOperand>::Vis as Meet<<B as CheckOperand>::Vis>>::Out;

/// The comparison constructors. `Joined` is the meet of the two operands'
/// visibilities; the `Meet` bounds are the lattice's commutativity, which
/// rustc cannot derive but every concrete pair satisfies.
macro_rules! comparison {
    ($(
        $(#[$m:meta])*
        $name:ident($a:ident, $b:ident) => $cmp:expr, negated: $neg:expr, order: ($first:ident, $second:ident)
    );* $(;)?) => {$(
        $(#[$m])*
        pub fn $name<A: CheckOperand, B: CheckOperand>($a: A, $b: B) -> Check<Joined<A, B>>
        where
            A::Vis: Meet<B::Vis>,
            B::Vis: Meet<A::Vis, Out = Joined<A, B>>,
            Joined<A, B>: Vis3,
        {
            compare($cmp, $neg, $first, $second)
        }
    )*};
}

comparison! {
    /// `a < b`. The width comes from the operand types.
    less_than(a, b) => Cmp::Less, negated: false, order: (a, b);
    /// `a > b` — `less_than(b, a)`, the same instruction with the operands
    /// the other way round.
    greater_than(a, b) => Cmp::Less, negated: false, order: (b, a);
    /// `a <= b` — `!(b < a)`, which is a `less_than` and a `not`.
    le(a, b) => Cmp::Less, negated: true, order: (b, a);
    /// `a >= b` — `!(a < b)`.
    ge(a, b) => Cmp::Less, negated: true, order: (a, b);
    /// `a == b`. No width is needed: `test_eq` compares field elements.
    eq(a, b) => Cmp::Equal, negated: false, order: (a, b);
    /// `a != b` — `test_eq` and a `not`.
    ne(a, b) => Cmp::Equal, negated: true, order: (a, b);
}

/// The shared body of the constructors: resolve the width from the types,
/// range-check a literal against it, and build the descriptor. `first` and
/// `second` are the operands in the order the INSTRUCTION takes them, which
/// is why `greater_than` is `less_than` with them swapped.
fn compare<F: CheckOperand, S: CheckOperand>(
    cmp: Cmp,
    negated: bool,
    first: F,
    second: S,
) -> Check<Joined<F, S>>
where
    F::Vis: Meet<S::Vis>,
    S::Vis: Meet<F::Vis, Out = Joined<F, S>>,
    Joined<F, S>: Vis3,
{
    let bits = width(cmp, F::BITS, S::BITS);
    if let Some(bits) = bits {
        check_literal_fits(first.literal(), bits);
        check_literal_fits(second.literal(), bits);
    }
    Check {
        node: Node::Compare {
            cmp,
            a: first.operand().meet::<S::Vis>(),
            b: second.operand().meet::<F::Vis>(),
            bits: bits.unwrap_or(0),
            negated,
        },
        message: None,
    }
}

/// The width a comparison runs at: the operands' types must agree, and for
/// an ORDERING at least one of them has to carry a width at all.
fn width(cmp: Cmp, a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => {
            assert_eq!(
                a, b,
                "comparing a {a}-bit value with a {b}-bit one: the widths a \
                 comparison runs at come from the operand types, so give both \
                 sides the same type (a `Uint<BITS>`, a `Bytes<N>`) or convert \
                 explicitly"
            );
            Some(a)
        }
        (Some(bits), None) | (None, Some(bits)) => Some(bits),
        (None, None) => {
            assert!(
                cmp == Cmp::Equal,
                "an ordering comparison needs a width, and neither operand's \
                 type carries one: compare TYPED values (a `Uint<BITS>`, a \
                 `Bytes<N>`) rather than raw wires — that is where the width \
                 comes from"
            );
            None
        }
    }
}

/// A literal compared at `bits` has to fit in `bits`.
fn check_literal_fits(literal: Option<Fr>, bits: u32) {
    let Some(value) = literal else { return };
    let bytes = value.as_le_bytes();
    let fits = bytes.iter().enumerate().all(|(i, &byte)| {
        let low = (i as u32) * 8;
        if low >= bits {
            byte == 0
        } else {
            let room = bits - low;
            room >= 8 || byte >> room == 0
        }
    });
    assert!(
        fits,
        "the literal {value:?} does not fit the {bits} bits the comparison \
         runs at — a constant compared against a Uint<{bits}> has to be one"
    );
}

/// `!p`.
pub fn not<V: Vis3>(p: Check<V>) -> Check<V> {
    Check {
        node: Node::Not(Box::new(p.node)),
        message: p.message,
    }
}

impl<V: Vis3> Check<V> {
    /// Compact's second `assert` argument: what the check means, surfaced by
    /// the simulator when it fails. Metadata — no instruction, no row.
    pub fn message(self, message: &'static str) -> Self {
        Check {
            message: Some(message),
            ..self
        }
    }

    /// `self && other` — one `mul` over the two lowered booleans.
    pub fn and(self, other: Check<V>) -> Check<V> {
        Check {
            node: Node::And(Box::new(self.node), Box::new(other.node)),
            message: self.message.or(other.message),
        }
    }

    /// `self || other` — De Morgan, `!(!self && !other)`: three `not`s and a
    /// `mul`. Written out rather than folded, because a combinator that
    /// quietly simplified would be hiding cost.
    pub fn or(self, other: Check<V>) -> Check<V> {
        Check {
            node: Node::Or(Box::new(self.node), Box::new(other.node)),
            message: self.message.or(other.message),
        }
    }

    /// Lower to the boolean wire, for a circuit that wants the value (a
    /// branch guard, a `cond_select`) rather than an assertion. This is the
    /// escape hatch; `c.assert(p)` is the normal path.
    pub fn eval(self, c: &mut Circuit3) -> Bool<V> {
        Bool::from_field(lower(c, self.node))
    }
}

/// A predicate is what `Circuit3::assert` takes: it lowers HERE, at the
/// assert, and the message rides along as metadata.
impl<V: Vis3> Assertion for Check<V> {
    fn assert_in(self, c: &mut Circuit3) {
        let message = self.message;
        let cond = lower(c, self.node);
        c.assert_with(cond, message);
    }
}

/// A boolean leaf asserts as its wire does.
impl<V: Vis3> Assertion for Bool<V> {
    fn assert_in(self, c: &mut Circuit3) {
        c.assert_with(self.field(), None);
    }
}

/// THE LOWERING, and the whole claim of this module: every node emits
/// exactly the instructions the hand-written form emits, in the same order.
fn lower<V: Vis3>(c: &mut Circuit3, node: Node<V>) -> Wire3<FieldT, V> {
    match node {
        Node::Compare {
            cmp,
            a,
            b,
            bits,
            negated,
        } => {
            let value = match cmp {
                Cmp::Less => c.less_than(a, b, bits),
                Cmp::Equal => c.test_eq(a, b),
            };
            if negated {
                c.not(value)
            } else {
                value
            }
        }
        Node::Not(inner) => {
            let value = lower(c, *inner);
            c.not(value)
        }
        Node::And(left, right) => {
            let left = lower(c, *left);
            let right = lower(c, *right);
            c.mul(left, right)
        }
        Node::Or(left, right) => {
            let left = lower(c, *left);
            let left = c.not(left);
            let right = lower(c, *right);
            let right = c.not(right);
            let both = c.mul(left, right);
            c.not(both)
        }
    }
}

// ---- the method surface ------------------------------------------------------
//
// The same predicates as methods on the typed leaves, delegating to the free
// constructors above so there is one implementation. `amount.gt(0u64)` and
// `greater_than(amount, 0u64)` are the same value.

macro_rules! comparison_methods {
    ($self_ty:ty, [$($gen:tt)*], $vis:ident, [$($name:ident => $free:ident, $doc:literal),* $(,)?]) => {
        impl<$($gen)*> $self_ty {
            $(
                #[doc = $doc]
                pub fn $name<B: CheckOperand>(self, other: B) -> Check<<$vis as Meet<B::Vis>>::Out>
                where
                    $vis: Meet<B::Vis>,
                    B::Vis: Meet<$vis, Out = <$vis as Meet<B::Vis>>::Out>,
                    <$vis as Meet<B::Vis>>::Out: Vis3,
                {
                    $free(self, other)
                }
            )*
        }
    };
}

macro_rules! leaf_comparisons {
    ($self_ty:ty, [$($gen:tt)*], $vis:ident) => {
        comparison_methods!($self_ty, [$($gen)*], $vis, [
            lt => less_than, "`self < other` — [`less_than`].",
            gt => greater_than, "`self > other` — [`greater_than`].",
            le => le, "`self <= other` — [`le`].",
            ge => ge, "`self >= other` — [`ge`].",
            eq => eq, "`self == other` — [`eq`].",
            ne => ne, "`self != other` — [`ne`].",
        ]);
    };
}

leaf_comparisons!(Uint<BITS, V>, [const BITS: u32, V: Vis3], V);
leaf_comparisons!(Bytes<N, V>, [const N: usize, V: Vis3], V);
leaf_comparisons!(Bool<V>, [V: Vis3], V);
