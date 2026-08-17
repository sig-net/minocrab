//! L2 — the MinoCrab eDSL.
//!
//! Circuits are ordinary Rust built against [`Circuit`]; wires carry their
//! visibility in the type. A `Wire<Private>` cannot reach a public output —
//! there is no method for it — until it passes through [`Circuit::disclose`],
//! which is the single, greppable gate for information leaving the private
//! domain. Combining wires taints: any operation touching a private wire
//! yields a private wire (see [`Meet`]).
//!
//! Disclosure policy escape hatch: `disclose` *is* the override — it always
//! compiles, and every call site names what it discloses, so `grep disclose`
//! is the audit. Stricter application policies wrap wires in newtypes that
//! hide `disclose` behind their own rules (e.g. range-blind first).
//!
//! The enforcement is a type error, not a runtime check:
//!
//! ```compile_fail
//! use minocrab::Circuit;
//! let (mut c, _) = Circuit::new(0);
//! let secret = c.witness();
//! // ERROR: expected `Wire<Public>`, found `Wire<Private>`
//! c.declare_public(secret, "leak");
//! ```
//!
//! With `disclose` it compiles — and the leak is named and greppable:
//!
//! ```
//! use minocrab::Circuit;
//! let (mut c, _) = Circuit::new(0);
//! let secret = c.witness();
//! let public = c.disclose(secret, "intentionally published");
//! c.declare_public(public, "value");
//! ```
//!
//! # Where this sits
//!
//! The middle of the MinoCrab stack: it builds on [`minocrab_ir`] (L1, the
//! typed instruction builder) and is what `minocrab-std` (L3, the ports of
//! Compact's standard library), `minocrab-ledger` (L2.5, Impact ledger ops)
//! and `minocrab-macros` (`#[circuit]`, `#[contract]`) are all written
//! against. `minocrab-sim` runs what [`Circuit::finish`] produces under
//! `cargo test`. Contract authors normally depend on `minocrab-std`, which
//! re-exports what is needed from here.
//!
//! # v2 and v3
//!
//! [`Circuit`] targets ZKIR v2. **[`v3::Circuit3`] is the current frontend**
//! — same discipline, but wires also carry their ZKIR value type, so an
//! unsupported operand is a Rust type error rather than a build-time panic.
//! Every contract in this workspace is v3.
//!
//! # Start here
//!
//! - [`v3::Circuit3`] — the typed frontend, and [`v3::Wire3`], its wires
//! - [`Wire`] and [`Visibility`] ([`Public`] / [`Private`]) — visibility in
//!   the type; [`Meet`] is the taint rule for combining two wires
//! - [`Circuit::disclose`] — the single Private→Public gate, and the thing to
//!   grep for in an audit
//! - [`v3::Discloses`] — a circuit's disclosure manifest, checked against
//!   what it actually disclosed (see [`v3::assert_declared_disclosures`])
//! - [`Compiled`] — a finished circuit: the IR plus its disclosure record

use std::marker::PhantomData;

pub use minocrab_ir::{Alignment, AlignmentAtom, AlignmentSegment, Fr, IrSource, Val};
use minocrab_ir::Builder;

pub mod v3;

// --- visibility -------------------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// Type-level visibility of a wire.
pub trait Visibility: sealed::Sealed + 'static {
    /// Runtime tag, for reports.
    const IS_PUBLIC: bool;
}

/// Value derived only from constants and disclosed/public values.
/// (Clone/Copy so `#[derive(Clone, Copy)]` works on types generic over a
/// visibility — derives bound every type parameter.)
#[derive(Clone, Copy)]
pub enum Public {}
/// Value tainted by witness data.
#[derive(Clone, Copy)]
pub enum Private {}

impl sealed::Sealed for Public {}
impl sealed::Sealed for Private {}
impl Visibility for Public {
    const IS_PUBLIC: bool = true;
}
impl Visibility for Private {
    const IS_PUBLIC: bool = false;
}

/// Visibility join: public only if both sides are public.
pub trait Meet<B: Visibility>: Visibility {
    type Out: Visibility;
}
impl Meet<Public> for Public {
    type Out = Public;
}
impl Meet<Private> for Public {
    type Out = Private;
}
impl Meet<Public> for Private {
    type Out = Private;
}
impl Meet<Private> for Private {
    type Out = Private;
}

// --- wires -------------------------------------------------------------------

/// One circuit value, tagged with its visibility.
pub struct Wire<V: Visibility> {
    val: Val,
    _vis: PhantomData<V>,
}

// Manual impls: Wire is Copy regardless of V.
impl<V: Visibility> Clone for Wire<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V: Visibility> Copy for Wire<V> {}

impl<V: Visibility> Wire<V> {
    fn new(val: Val) -> Self {
        Wire {
            val,
            _vis: PhantomData,
        }
    }

    /// The underlying L1 value handle.
    pub fn val(self) -> Val {
        self.val
    }

    /// Forget that this wire is public. Safe in the disclosure lattice —
    /// private is the restrictive end — and needed to mix constants into
    /// same-visibility operand slices like [`Circuit::transient_hash`]'s.
    pub fn private(self) -> Wire<Private> {
        Wire::new(self.val)
    }
}

/// What a circuit reveals, recorded at build time for the simulator's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    /// Call-site label, e.g. what quantity is being disclosed and why.
    pub label: String,
    /// How it leaves the circuit.
    pub kind: DisclosureKind,
    /// ZKIR memory index of the disclosed value.
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisclosureKind {
    /// `disclose()` — a private value became public inside the circuit.
    Disclosed,
    /// Declared as part of the public statement (public input block).
    Statement,
    /// Returned as a circuit output.
    Output,
}

// --- circuit ------------------------------------------------------------------

/// A named span of instructions, for cost attribution in the profiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub label: String,
    /// Instruction index range [start, end).
    pub start: usize,
    pub end: usize,
}

/// A circuit under construction.
pub struct Circuit {
    b: Builder,
    disclosures: Vec<Disclosure>,
    witnesses: u32,
    regions: Vec<Region>,
}

/// A finished circuit: the lowered ZKIR plus its disclosure record.
pub struct Compiled {
    pub ir: IrSource,
    pub disclosures: Vec<Disclosure>,
    pub witnesses: u32,
    pub regions: Vec<Region>,
}

impl Circuit {
    /// A circuit taking `num_args` private field-element arguments.
    /// (Arguments are witness data in ZKIR; they enter memory directly.)
    pub fn new(num_args: u32) -> (Self, Vec<Wire<Private>>) {
        let (b, args) = Builder::new(num_args);
        let circuit = Circuit {
            b,
            disclosures: Vec::new(),
            witnesses: 0,
            regions: Vec::new(),
        };
        (circuit, args.into_iter().map(Wire::new).collect())
    }

    // --- inputs ---------------------------------------------------------------

    /// Read the next witness value from the private transcript.
    pub fn witness(&mut self) -> Wire<Private> {
        self.witnesses += 1;
        Wire::new(self.b.private_input(None))
    }

    /// Read the next value from the public transcript (visible on-chain).
    pub fn public_transcript_input(&mut self) -> Wire<Public> {
        Wire::new(self.b.public_input(None))
    }

    /// Read the next witness value if `guard` is true at runtime, else 0
    /// without consuming the transcript. (Compact conditionals lower to
    /// guarded reads.)
    pub fn witness_guarded<V: Visibility>(&mut self, guard: Wire<V>) -> Wire<Private> {
        self.witnesses += 1;
        Wire::new(self.b.private_input(Some(guard.val())))
    }

    /// Read the next public-transcript value if `guard` is true at runtime,
    /// else 0 without consuming the transcript. The value read is on-chain
    /// public data, so the wire is public even under a private guard.
    pub fn public_transcript_input_guarded<V: Visibility>(
        &mut self,
        guard: Wire<V>,
    ) -> Wire<Public> {
        Wire::new(self.b.public_input(Some(guard.val())))
    }

    /// A constant; constants are part of the circuit, hence public.
    pub fn constant(&mut self, imm: impl Into<Fr>) -> Wire<Public> {
        Wire::new(self.b.load_imm(imm))
    }

    // --- operations (visibility joins via Meet) ---------------------------------

    pub fn add<A, B>(&mut self, a: Wire<A>, b: Wire<B>) -> Wire<A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire::new(self.b.add(a.val, b.val))
    }

    pub fn mul<A, B>(&mut self, a: Wire<A>, b: Wire<B>) -> Wire<A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire::new(self.b.mul(a.val, b.val))
    }

    pub fn neg<A: Visibility>(&mut self, a: Wire<A>) -> Wire<A> {
        Wire::new(self.b.neg(a.val))
    }

    /// Boolean not; operand must hold 0 or 1.
    pub fn not<A: Visibility>(&mut self, a: Wire<A>) -> Wire<A> {
        Wire::new(self.b.not(a.val))
    }

    /// 1 if equal, else 0.
    pub fn test_eq<A, B>(&mut self, a: Wire<A>, b: Wire<B>) -> Wire<A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire::new(self.b.test_eq(a.val, b.val))
    }

    /// `bit ? a : b`.
    pub fn cond_select<C, A, B>(
        &mut self,
        bit: Wire<C>,
        a: Wire<A>,
        b: Wire<B>,
    ) -> Wire<<C::Out as Meet<B>>::Out>
    where
        C: Visibility + Meet<A>,
        A: Visibility,
        B: Visibility,
        C::Out: Meet<B>,
    {
        Wire::new(self.b.cond_select(bit.val, a.val, b.val))
    }

    /// `a < b` over `bits`-bit values (range-constrains both).
    pub fn less_than<A, B>(&mut self, a: Wire<A>, b: Wire<B>, bits: u32) -> Wire<A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire::new(self.b.less_than(a.val, b.val, bits))
    }

    /// Poseidon-family hash. The hash of private data is still private —
    /// disclose it explicitly if it must leave the circuit.
    pub fn transient_hash<V: Visibility>(&mut self, inputs: &[Wire<V>]) -> Wire<V> {
        let vals: Vec<Val> = inputs.iter().map(|w| w.val).collect();
        Wire::new(self.b.transient_hash(&vals))
    }

    /// SHA-256 persistent hash of `inputs` laid out per `alignment`; the
    /// 32-byte digest spans the two returned wires. Hashing private data
    /// yields private wires, as with [`Circuit::transient_hash`].
    pub fn persistent_hash<V: Visibility>(
        &mut self,
        alignment: Alignment,
        inputs: &[Wire<V>],
    ) -> (Wire<V>, Wire<V>) {
        let vals: Vec<Val> = inputs.iter().map(|w| w.val).collect();
        let (a, b) = self.b.persistent_hash(alignment, &vals);
        (Wire::new(a), Wire::new(b))
    }

    /// Split into `(w >> bits, w mod 2^bits)`.
    pub fn div_mod_power_of_two<V: Visibility>(
        &mut self,
        w: Wire<V>,
        bits: u32,
    ) -> (Wire<V>, Wire<V>) {
        let (d, m) = self.b.div_mod_power_of_two(w.val, bits);
        (Wire::new(d), Wire::new(m))
    }

    /// `divisor * 2^bits + modulus`, checked against field overflow.
    pub fn reconstitute_field<A, B>(
        &mut self,
        divisor: Wire<A>,
        modulus: Wire<B>,
        bits: u32,
    ) -> Wire<A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire::new(self.b.reconstitute_field(divisor.val, modulus.val, bits))
    }

    // --- embedded-curve (Jubjub) operations ---------------------------------

    /// Point addition on the embedded curve; points are `(x, y)` wire pairs.
    pub fn ec_add<A, B>(
        &mut self,
        a: (Wire<A>, Wire<A>),
        b: (Wire<B>, Wire<B>),
    ) -> (Wire<A::Out>, Wire<A::Out>)
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        let (x, y) = self.b.ec_add((a.0.val, a.1.val), (b.0.val, b.1.val));
        (Wire::new(x), Wire::new(y))
    }

    /// Scalar multiplication on the embedded curve.
    pub fn ec_mul<A, B>(
        &mut self,
        point: (Wire<A>, Wire<A>),
        scalar: Wire<B>,
    ) -> (Wire<A::Out>, Wire<A::Out>)
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        let (x, y) = self.b.ec_mul((point.0.val, point.1.val), scalar.val);
        (Wire::new(x), Wire::new(y))
    }

    /// Generator multiplication on the embedded curve.
    pub fn ec_mul_generator<V: Visibility>(&mut self, scalar: Wire<V>) -> (Wire<V>, Wire<V>) {
        let (x, y) = self.b.ec_mul_generator(scalar.val);
        (Wire::new(x), Wire::new(y))
    }

    /// Hash field elements to a curve point.
    pub fn hash_to_curve<V: Visibility>(&mut self, inputs: &[Wire<V>]) -> (Wire<V>, Wire<V>) {
        let vals: Vec<Val> = inputs.iter().map(|w| w.val).collect();
        let (x, y) = self.b.hash_to_curve(&vals);
        (Wire::new(x), Wire::new(y))
    }

    // --- constraints -------------------------------------------------------------

    /// Constrain a boolean wire to be true. Constraining private data is the
    /// point of ZK — this does not disclose the operand.
    pub fn assert<V: Visibility>(&mut self, cond: Wire<V>) {
        self.b.assert(cond.val);
    }

    pub fn assert_eq<A: Visibility, B: Visibility>(&mut self, a: Wire<A>, b: Wire<B>) {
        self.b.constrain_eq(a.val, b.val);
    }

    /// Range-constrain to `bits` bits.
    pub fn assert_bits<V: Visibility>(&mut self, w: Wire<V>, bits: u32) {
        self.b.constrain_bits(w.val, bits);
    }

    pub fn assert_boolean<V: Visibility>(&mut self, w: Wire<V>) {
        self.b.constrain_to_boolean(w.val);
    }

    // --- disclosure: the only Private -> Public gate --------------------------------

    /// Explicitly make a private value public. THE greppable audit point:
    /// every bit of information that leaves the private domain passes through
    /// here, and `label` says what and why.
    pub fn disclose(&mut self, w: Wire<Private>, label: &str) -> Wire<Public> {
        self.disclosures.push(Disclosure {
            label: label.to_string(),
            kind: DisclosureKind::Disclosed,
            index: w.val.index(),
        });
        Wire::new(w.val)
    }

    // --- outputs (public only) -----------------------------------------------------

    /// Declare a wire as part of the public statement.
    pub fn declare_public(&mut self, w: Wire<Public>, label: &str) {
        self.disclosures.push(Disclosure {
            label: label.to_string(),
            kind: DisclosureKind::Statement,
            index: w.val.index(),
        });
        self.b.declare_pub_input(w.val);
    }

    /// Return a wire as a circuit output.
    pub fn output(&mut self, w: Wire<Public>, label: &str) {
        self.disclosures.push(Disclosure {
            label: label.to_string(),
            kind: DisclosureKind::Output,
            index: w.val.index(),
        });
        self.b.output(w.val);
    }

    // --- profiling regions -------------------------------------------------------

    /// Attribute the instructions built inside `f` to a named region in the
    /// cost profiler. Regions may nest; costs attribute to the innermost.
    pub fn region<T>(&mut self, label: &str, f: impl FnOnce(&mut Self) -> T) -> T {
        let start = self.b.len();
        let result = f(self);
        self.regions.push(Region {
            label: label.to_string(),
            start,
            end: self.b.len(),
        });
        result
    }

    // --- finish ---------------------------------------------------------------------

    pub fn finish(self) -> Compiled {
        Compiled {
            ir: self.b.finish(false),
            disclosures: self.disclosures,
            witnesses: self.witnesses,
            regions: self.regions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_taints_public() {
        let (mut c, _) = Circuit::new(0);
        let w = c.witness();
        let k = c.constant(3u64);
        let s = c.add(w, k);
        // s is Wire<Private>: it has no path to declare_public without disclose.
        let s_pub = c.disclose(s, "witness plus three");
        c.declare_public(s_pub, "sum");
        let compiled = c.finish();
        assert_eq!(compiled.disclosures.len(), 2);
        assert_eq!(compiled.witnesses, 1);
    }
}
