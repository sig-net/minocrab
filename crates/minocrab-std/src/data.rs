//! Generic data types: `Maybe<T>` and `Either<A, B>`.
//!
//! Ports of the "Generic Data" section of `standard-library.compact`.
//! Like the originals, `none`/`left`/`right` fill the unused side with
//! `default<T>` (all zeros); the constructors are zero-cost (constants
//! only) exactly as compactc compiles them.

use minocrab::{AlignmentAtom, Circuit, Wire};

use crate::bundle::{boolean, default_bundle, Bundle, Vis};
use crate::types::Bool;

/// `struct Maybe<T> { is_some: Boolean; value: T; }`
#[derive(Clone, Copy)]
pub struct Maybe<V: Vis, T: Bundle<V>> {
    pub is_some: Bool<V>,
    pub value: T,
}

impl<V: Vis, T: Bundle<V>> Bundle<V> for Maybe<V, T> {
    const WIDTH: usize = 1 + T::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.is_some.push_wires(out);
        self.value.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        Maybe {
            is_some: Bool::from_wires(wires),
            value: T::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        Bool::<V>::push_atoms(out);
        T::push_atoms(out);
    }
}

/// `circuit some<T>(value: T): Maybe<T>`
pub fn some<V: Vis, T: Bundle<V>>(c: &mut Circuit, value: T) -> Maybe<V, T> {
    Maybe {
        is_some: Bool(boolean(c, true)),
        value,
    }
}

/// `circuit none<T>(): Maybe<T>`
pub fn none<V: Vis, T: Bundle<V>>(c: &mut Circuit) -> Maybe<V, T> {
    Maybe {
        is_some: Bool(boolean(c, false)),
        value: default_bundle(c),
    }
}

/// `struct Either<A, B> { is_left: Boolean; left: A; right: B; }`
#[derive(Clone, Copy)]
pub struct Either<V: Vis, A: Bundle<V>, B: Bundle<V>> {
    pub is_left: Bool<V>,
    pub left: A,
    pub right: B,
}

impl<V: Vis, A: Bundle<V>, B: Bundle<V>> Bundle<V> for Either<V, A, B> {
    const WIDTH: usize = 1 + A::WIDTH + B::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.is_left.push_wires(out);
        self.left.push_wires(out);
        self.right.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        Either {
            is_left: Bool::from_wires(wires),
            left: A::from_wires(wires),
            right: B::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        Bool::<V>::push_atoms(out);
        A::push_atoms(out);
        B::push_atoms(out);
    }
}

/// `circuit left<A, B>(value: A): Either<A, B>`
pub fn left<V: Vis, A: Bundle<V>, B: Bundle<V>>(c: &mut Circuit, value: A) -> Either<V, A, B> {
    Either {
        is_left: Bool(boolean(c, true)),
        left: value,
        right: default_bundle(c),
    }
}

/// `circuit right<A, B>(value: B): Either<A, B>`
pub fn right<V: Vis, A: Bundle<V>, B: Bundle<V>>(c: &mut Circuit, value: B) -> Either<V, A, B> {
    Either {
        is_left: Bool(boolean(c, false)),
        left: default_bundle(c),
        right: value,
    }
}
