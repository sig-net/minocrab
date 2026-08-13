//! Wire bundles: Compact values as fixed-width groups of wires.
//!
//! Compact circuit values (structs, `Vector<n, T>`, `Boolean`, …) flatten to
//! a fixed number of field elements in declaration order; every stdlib
//! gadget operates on that flattened form. [`Bundle`] captures the mapping
//! both ways, so generic gadgets (`cond_select`, `eq`, `default_bundle`) can
//! be written once and stay per-wire — exactly how compactc lowers the
//! corresponding Compact operations.

use minocrab::{
    Alignment, AlignmentAtom, AlignmentSegment, Circuit, Meet, Private, Public, Visibility, Wire,
};

/// Visibility usable by bundles: closed under [`Meet`] with itself and
/// reachable from [`Public`] (constants can enter any bundle; retagging
/// public as private is the safe direction of the disclosure lattice).
pub trait Vis: Visibility + Meet<Self, Out = Self> + Sized + Copy {
    fn from_public(w: Wire<Public>) -> Wire<Self>;
}

impl Vis for Public {
    fn from_public(w: Wire<Public>) -> Wire<Public> {
        w
    }
}

impl Vis for Private {
    fn from_public(w: Wire<Public>) -> Wire<Private> {
        w.private()
    }
}

/// A Compact value as a fixed-width bundle of same-visibility wires.
///
/// Laws: `from_wires` is the inverse of `push_wires`, and both touch exactly
/// [`Bundle::WIDTH`] wires in Compact declaration order.
pub trait Bundle<V: Vis>: Sized {
    /// Number of field elements this type flattens to.
    const WIDTH: usize;

    /// Append this value's wires in declaration order.
    fn push_wires(&self, out: &mut Vec<Wire<V>>);

    /// Rebuild from the next [`Bundle::WIDTH`] wires of `wires`.
    ///
    /// # Panics
    /// If `wires` yields fewer than `WIDTH` wires (widths are static, so
    /// this is a gadget bug, not a data error).
    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self;

    /// Append this type's FAB alignment atoms, one per *source atom* (a
    /// multi-slot `Bytes<N>` contributes a single `bytes N` atom covering
    /// all its slots — see notes/builtin-lowering.org §1).
    fn push_atoms(out: &mut Vec<AlignmentAtom>);

    /// The flattened wires in declaration order.
    fn wires(&self) -> Vec<Wire<V>> {
        let mut out = Vec::with_capacity(Self::WIDTH);
        self.push_wires(&mut out);
        out
    }

    /// The FAB [`Alignment`] of this type, as `persistent_hash` expects it.
    fn alignment() -> Alignment {
        let mut atoms = Vec::new();
        Self::push_atoms(&mut atoms);
        Alignment(atoms.into_iter().map(AlignmentSegment::Atom).collect())
    }
}

/// A bare wire is a Compact `Field`.
impl<V: Vis> Bundle<V> for Wire<V> {
    const WIDTH: usize = 1;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        out.push(*self);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        wires.next().expect("bundle width mismatch")
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        out.push(AlignmentAtom::Field);
    }
}

/// `Vector<N, B>`: element-major concatenation.
impl<V: Vis, B: Bundle<V>, const N: usize> Bundle<V> for [B; N] {
    const WIDTH: usize = B::WIDTH * N;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        for item in self {
            item.push_wires(out);
        }
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        std::array::from_fn(|_| B::from_wires(wires))
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        for _ in 0..N {
            B::push_atoms(out);
        }
    }
}

/// Tuples flatten in order (Compact tuple types; also used to prepend a
/// commitment's rand to its value type).
impl<V: Vis, A: Bundle<V>, B: Bundle<V>> Bundle<V> for (A, B) {
    const WIDTH: usize = A::WIDTH + B::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.0.push_wires(out);
        self.1.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        (A::from_wires(wires), B::from_wires(wires))
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        A::push_atoms(out);
        B::push_atoms(out);
    }
}

/// `default<T>`: the all-zeros value (false, 0, zero bytes — Compact's
/// `default` is zero in every leaf).
pub fn default_bundle<V: Vis, B: Bundle<V>>(c: &mut Circuit) -> B {
    let mut zeros = (0..B::WIDTH).map(|_| {
        let z = c.constant(0u64);
        V::from_public(z)
    });
    B::from_wires(&mut zeros)
}

/// `bit ? a : b`, per wire. `bit` must hold 0 or 1.
pub fn cond_select<V: Vis, B: Bundle<V>>(c: &mut Circuit, bit: Wire<V>, a: &B, b: &B) -> B {
    let (a, b) = (a.wires(), b.wires());
    let mut selected = a.iter().zip(&b).map(|(&a, &b)| c.cond_select(bit, a, b));
    B::from_wires(&mut selected)
}

/// Structural equality: the conjunction of per-wire equality.
pub fn eq<V: Vis, B: Bundle<V>>(c: &mut Circuit, a: &B, b: &B) -> Wire<V> {
    let (a, b) = (a.wires(), b.wires());
    let mut result: Option<Wire<V>> = None;
    for (&a, &b) in a.iter().zip(&b) {
        let e = c.test_eq(a, b);
        result = Some(match result {
            // Both operands are booleans, so AND is multiplication.
            Some(acc) => c.mul(acc, e),
            None => e,
        });
    }
    match result {
        Some(w) => w,
        // Zero-width bundles (e.g. `[]`) are vacuously equal.
        None => V::from_public(c.constant(1u64)),
    }
}

/// Boolean AND (operands must hold 0 or 1).
pub fn and<V: Vis>(c: &mut Circuit, a: Wire<V>, b: Wire<V>) -> Wire<V> {
    c.mul(a, b)
}

/// Boolean OR (operands must hold 0 or 1): `a + b - a*b`.
pub fn or<V: Vis>(c: &mut Circuit, a: Wire<V>, b: Wire<V>) -> Wire<V> {
    let ab = c.mul(a, b);
    let sum = c.add(a, b);
    let neg = c.neg(ab);
    c.add(sum, neg)
}

/// A boolean constant, cast into visibility `V`.
pub fn boolean<V: Vis>(c: &mut Circuit, value: bool) -> Wire<V> {
    let w = c.constant(u64::from(value));
    V::from_public(w)
}
