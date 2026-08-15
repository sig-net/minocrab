//! L2 for ZKIR v3 — the typed eDSL frontend.
//!
//! Same shape as the v2 [`Circuit`](crate::Circuit) (visibility in the
//! type, `disclose` as the single Private→Public gate) but wires also carry
//! their ZKIR v3 *value type* ([`IrTy`] markers for [`IrType`]), so the
//! per-instruction supported-type lists that [`Builder3`] checks at circuit
//! build time become Rust compile errors here: `ec_mul` of a secp256k1
//! point by a Jubjub scalar simply does not type-check.
//!
//! v3 circuits have one `Output` terminator; [`Circuit3::output`] queues
//! wires and [`Circuit3::finish`] emits the terminator.

use std::marker::PhantomData;

use minocrab_ir::v3::{Arg, Builder3, IrSource, IrType, Val};
pub use minocrab_ir::v3::{Alignment, Identifier};
use minocrab_ir::Fr;

use crate::{DisclosureKind, Meet, Private, Public, Region, Visibility};

mod abi;
mod disclose;

pub use abi::{
    uint_atom_bytes, uint_compare_bits, CallArg, CallArgs, CallResult, CircuitAbi, LimbConstraint,
    Prim,
};

/// Typed disclosure declarations — `label!` types, `.disclose_as::<L>(c)`,
/// and the `Discloses<D, R>` a circuit returns (see the module docs).
pub use disclose::{
    assert_declared_disclosures, disclosed_labels, Declared, Disclose, DisclosureLabel, Discloses,
    LabelSet,
};

// --- value-type markers -------------------------------------------------------

/// Type-level tag for a ZKIR v3 [`IrType`].
pub trait IrTy: 'static {
    fn ir_type() -> IrType;
}

macro_rules! ir_ty {
    ($($(#[$doc:meta])* $name:ident => $variant:ident),* $(,)?) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy)]
        pub enum $name {}
        impl IrTy for $name {
            fn ir_type() -> IrType {
                IrType::$variant
            }
        }
    )*};
}

ir_ty! {
    /// The native BLS12-381 scalar field (Compact `Field`, `Uint`, `Boolean`).
    FieldT => Native,
    /// `Bytes<32>` as a single typed value.
    Bytes32T => Bytes32,
    /// A point on Jubjub, the native embedded curve.
    JubjubPointT => JubjubPoint,
    /// A scalar of Jubjub's scalar field.
    JubjubScalarT => JubjubScalar,
    /// A point on secp256k1.
    Secp256k1PointT => Secp256k1Point,
    /// A base-field element of secp256k1.
    Secp256k1BaseT => Secp256k1Base,
    /// A scalar-field element of secp256k1.
    Secp256k1ScalarT => Secp256k1Scalar,
    /// A point on secp256r1.
    Secp256r1PointT => Secp256r1Point,
    /// A base-field element of secp256r1.
    Secp256r1BaseT => Secp256r1Base,
    /// A scalar-field element of secp256r1.
    Secp256r1ScalarT => Secp256r1Scalar,
    /// A point on Curve25519.
    Curve25519PointT => Curve25519Point,
    /// A base-field element of Curve25519.
    Curve25519BaseT => Curve25519Base,
    /// A scalar-field element of Curve25519.
    Curve25519ScalarT => Curve25519Scalar,
}

/// Types supported by TestEq/Add/Neg/CondSelect/ConstrainEq (everything but
/// `Bytes<32>` and `Scalar<Jubjub>`).
pub trait EqAddTy: IrTy {}
impl EqAddTy for FieldT {}
impl EqAddTy for JubjubPointT {}
impl EqAddTy for Secp256k1PointT {}
impl EqAddTy for Secp256k1BaseT {}
impl EqAddTy for Secp256k1ScalarT {}
impl EqAddTy for Secp256r1PointT {}
impl EqAddTy for Secp256r1BaseT {}
impl EqAddTy for Secp256r1ScalarT {}
impl EqAddTy for Curve25519PointT {}
impl EqAddTy for Curve25519BaseT {}
impl EqAddTy for Curve25519ScalarT {}

/// Field elements supporting Mul/Inv (no points).
pub trait MulTy: EqAddTy {}
impl MulTy for FieldT {}
impl MulTy for Secp256k1BaseT {}
impl MulTy for Secp256k1ScalarT {}
impl MulTy for Secp256r1BaseT {}
impl MulTy for Secp256r1ScalarT {}
impl MulTy for Curve25519BaseT {}
impl MulTy for Curve25519ScalarT {}

/// Prime fields with a canonical 32-byte form (IntoBytes32/FromBytes32).
pub trait Bytes32ConvTy: IrTy {}
impl Bytes32ConvTy for FieldT {}
impl Bytes32ConvTy for Secp256k1BaseT {}
impl Bytes32ConvTy for Secp256k1ScalarT {}
impl Bytes32ConvTy for Secp256r1BaseT {}
impl Bytes32ConvTy for Secp256r1ScalarT {}
impl Bytes32ConvTy for Curve25519BaseT {}
impl Bytes32ConvTy for Curve25519ScalarT {}

/// Scalars whose curve generator `EcMulGenerator` can multiply (the VM
/// dispatches on the scalar type; Jubjub and secp256k1 are supported).
pub trait GeneratorScalarTy: IrTy {
    type Point: PointTy;
}
impl GeneratorScalarTy for JubjubScalarT {
    type Point = JubjubPointT;
}
impl GeneratorScalarTy for Secp256k1ScalarT {
    type Point = Secp256k1PointT;
}

/// Curve points: their coordinate (base-field) and scalar types.
pub trait PointTy: EqAddTy {
    type Coord: IrTy;
    type Scalar: IrTy;
}
impl PointTy for JubjubPointT {
    type Coord = FieldT;
    type Scalar = JubjubScalarT;
}
impl PointTy for Secp256k1PointT {
    type Coord = Secp256k1BaseT;
    type Scalar = Secp256k1ScalarT;
}
impl PointTy for Secp256r1PointT {
    type Coord = Secp256r1BaseT;
    type Scalar = Secp256r1ScalarT;
}
impl PointTy for Curve25519PointT {
    type Coord = Curve25519BaseT;
    type Scalar = Curve25519ScalarT;
}

// --- wires ---------------------------------------------------------------------

/// One v3 circuit value, tagged with its ZKIR type and its visibility.
pub struct Wire3<T: IrTy, V: Visibility> {
    val: Val,
    _marker: PhantomData<(T, V)>,
}

impl<T: IrTy, V: Visibility> Clone for Wire3<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: IrTy, V: Visibility> Copy for Wire3<T, V> {}

impl<T: IrTy, V: Visibility> Wire3<T, V> {
    fn new(val: Val) -> Self {
        Wire3 {
            val,
            _marker: PhantomData,
        }
    }

    /// The underlying L1 value handle.
    pub fn val(self) -> Val {
        self.val
    }

    /// Forget that this wire is public (safe: private is the restrictive
    /// end of the disclosure lattice).
    pub fn private(self) -> Wire3<T, Private> {
        Wire3::new(self.val)
    }

    /// Erase the value type for heterogeneous operand lists (hash inputs),
    /// keeping visibility.
    pub fn erase(self) -> AnyWire3<V> {
        AnyWire3 {
            val: self.val,
            _vis: PhantomData,
        }
    }
}

/// A type-erased wire (known visibility, dynamic [`IrType`]) for
/// heterogeneous instruction operands like hash preimages.
pub struct AnyWire3<V: Visibility> {
    val: Val,
    _vis: PhantomData<V>,
}

/// One element of an Impact public-input block: an inline constant or a
/// circuit-computed (necessarily public) native value.
#[derive(Clone, Copy)]
pub enum ImpactElem {
    Imm(Fr),
    Wire(Wire3<FieldT, Public>),
}

// --- operands -------------------------------------------------------------------

/// What an instruction takes: a wire, or an INLINE IMMEDIATE.
///
/// v3 has no `LoadImm` — an immediate is an operand of the instruction that
/// uses it (`{"op": "less_than", "a": {"immediate": "0"}, …}`), so a native
/// Rust value in an operand position costs NOTHING. Naming one first
/// (`let zero = c.constant(0u64); c.less_than(zero, x, 64)`) emits a `Copy`
/// whose only purpose is the name.
///
/// The type parameters are the ones a wire carries, so an operand cannot
/// launder either of them:
/// - `T` is the ZKIR value type. An immediate is a native field element, so
///   only `Operand<FieldT, _>` has literal conversions — `c.test_eq(point,
///   1u64)` does not compile, and never reaches [`Builder3`]'s type check.
/// - `V` is the visibility, and immediates are [`Public`] because a
///   constant is part of the circuit. Mixing follows the usual [`Meet`]: a
///   comparison of a private wire against a literal is private, since
///   `Private ⊓ Public = Private`.
///
/// Construction is `From`, so call sites write the value itself: a wire, a
/// `u64`, a `bool`, or an [`Fr`] for a wider constant.
pub struct Operand<T: IrTy, V: Visibility> {
    arg: Arg,
    _marker: PhantomData<(T, V)>,
}

impl<T: IrTy, V: Visibility> Clone for Operand<T, V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: IrTy, V: Visibility> Copy for Operand<T, V> {}

impl<T: IrTy, V: Visibility> Operand<T, V> {
    fn arg(self) -> Arg {
        self.arg
    }

    /// This operand seen at the meet of its visibility with `W` — which is
    /// either its own visibility or [`Private`], never the other way round.
    ///
    /// It is `Wire3::private` generalized to the lattice, and it exists so
    /// that a MIXED comparison can be assembled: both sides of
    /// `less_than(0u64, secret)` become operands at `Public ⊓ Private`
    /// before the instruction is built.
    pub fn meet<W: Visibility>(self) -> Operand<T, <V as Meet<W>>::Out>
    where
        V: Meet<W>,
    {
        Operand {
            arg: self.arg,
            _marker: PhantomData,
        }
    }
}

impl<T: IrTy, V: Visibility> From<Wire3<T, V>> for Operand<T, V> {
    fn from(w: Wire3<T, V>) -> Self {
        Operand {
            arg: Arg::Val(w.val),
            _marker: PhantomData,
        }
    }
}

/// Immediates: native only, and [`Public`] — the visibility an inline
/// constant has.
macro_rules! immediate_operand {
    ($($ty:ty => |$v:ident| $conv:expr),* $(,)?) => {$(
        impl From<$ty> for Operand<FieldT, Public> {
            fn from($v: $ty) -> Self {
                Operand {
                    arg: Arg::Imm($conv),
                    _marker: PhantomData,
                }
            }
        }
    )*};
}

immediate_operand! {
    Fr => |v| v,
    u64 => |v| Fr::from(v),
    u32 => |v| Fr::from(u64::from(v)),
    u8 => |v| Fr::from(u64::from(v)),
    bool => |v| Fr::from(u64::from(v)),
}

impl<V: Visibility> Clone for AnyWire3<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V: Visibility> Copy for AnyWire3<V> {}

// --- disclosure records ----------------------------------------------------------

/// What a v3 circuit reveals, recorded at build time — the v3 twin of
/// [`Disclosure`](crate::Disclosure).
///
/// It differs from the v2 record in the one way v3 differs from v2 about
/// values: v2 names a disclosed value by its ZKIR *memory index*, and v3
/// values have no index — they are [`Identifier`]s (`%label.N`), which is
/// what the instruction stream refers to and what the simulator keys its
/// value memory by. So the record carries identifiers, and a v3 report can
/// resolve a disclosure to the value it actually took in a run (the v3
/// record used to store a hard-coded `index: 0`, which resolved to
/// nothing).
///
/// One record is one *logical* value, so `values` is a list: a
/// `Bytes<32>` disclosed under one label contributes both of its limbs
/// here rather than two records named `"… (hi)"` and `"… (lo)"`. That is
/// what makes a declared label set comparable to the disclosed one — labels
/// are per value, not per wire (notes/contract-api.org §Disclosure
/// declaration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure3 {
    /// What is being disclosed and why — the label type's
    /// `DisclosureLabel::LABEL` for a declared disclosure, the call site's
    /// string otherwise.
    pub label: String,
    /// How it leaves the circuit.
    pub kind: DisclosureKind,
    /// The disclosed value's wires, in wire order.
    pub values: Vec<Identifier>,
}

// --- circuit ---------------------------------------------------------------------

/// What [`Circuit3::assert`] accepts.
///
/// A boolean wire is the base case. The other implementor is
/// `minocrab_std::v3::Check`, the deferred predicate — an inert descriptor
/// that emits its comparison HERE, at the assert, and nothing anywhere else
/// (an unasserted predicate emits nothing at all, and warns, being
/// `#[must_use]`).
pub trait Assertion {
    /// Emit this assertion into `c`.
    fn assert_in(self, c: &mut Circuit3);
}

impl<V: Visibility> Assertion for Wire3<FieldT, V> {
    fn assert_in(self, c: &mut Circuit3) {
        c.assert_with(self, None);
    }
}

/// Compact's `assert(cond, "message")` second argument, kept beside the
/// instruction stream: the message and the position of the `Assert` it
/// belongs to. Metadata only — ZKIR has no room for it, and a simulator
/// uses it to name a failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertMessage {
    /// Index of the `Assert` instruction this message belongs to.
    pub instruction: usize,
    /// What the check means, in the contract author's words.
    pub message: String,
}

/// A ZKIR v3 circuit under construction.
pub struct Circuit3 {
    b: Builder3,
    disclosures: Vec<Disclosure3>,
    witnesses: u32,
    regions: Vec<Region>,
    queued_outputs: Vec<(Val, IrType)>,
    assert_messages: Vec<AssertMessage>,
}

/// A finished v3 circuit: the lowered ZKIR plus its disclosure record.
pub struct Compiled3 {
    pub ir: IrSource,
    pub disclosures: Vec<Disclosure3>,
    pub witnesses: u32,
    pub regions: Vec<Region>,
    /// The messages of the asserts that carry one (see [`AssertMessage`]).
    pub assert_messages: Vec<AssertMessage>,
}

impl Compiled3 {
    /// The message of the assert at instruction `index`, if it has one.
    pub fn assert_message(&self, index: usize) -> Option<&str> {
        self.assert_messages
            .iter()
            .find(|m| m.instruction == index)
            .map(|m| m.message.as_str())
    }
}

impl Default for Circuit3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Circuit3 {
    pub fn new() -> Self {
        Circuit3 {
            b: Builder3::new(),
            disclosures: Vec::new(),
            witnesses: 0,
            regions: Vec::new(),
            queued_outputs: Vec::new(),
            assert_messages: Vec::new(),
        }
    }

    // --- circuit arguments (witness data, like v2 args) -------------------------

    /// Declare the next circuit argument. Must precede all instructions.
    pub fn arg<T: IrTy>(&mut self, label: &str) -> Wire3<T, Private> {
        Wire3::new(self.b.input(label, T::ir_type()))
    }

    /// Argument slots declared so far — the entry-point core checks it
    /// against the argument list's declared width.
    pub fn arg_count(&self) -> usize {
        self.b.input_count()
    }

    /// Instructions built so far — the entry-point core checks that
    /// argument declaration emitted none.
    pub fn instruction_count(&self) -> usize {
        self.b.len()
    }

    // --- inputs ------------------------------------------------------------------

    /// Read the next witness value from the private transcript.
    pub fn witness<T: IrTy>(&mut self) -> Wire3<T, Private> {
        self.witnesses += 1;
        Wire3::new(self.b.private_input(T::ir_type(), None))
    }

    /// Read the next witness value under a guard (false ⇒ default value,
    /// transcript not consumed).
    pub fn witness_guarded<T: IrTy, V: Visibility>(
        &mut self,
        guard: Wire3<FieldT, V>,
    ) -> Wire3<T, Private> {
        self.witnesses += 1;
        Wire3::new(
            self.b
                .private_input(T::ir_type(), Some(Arg::Val(guard.val))),
        )
    }

    /// Read the next value from the public transcript (visible on-chain).
    pub fn public_transcript_input<T: IrTy>(&mut self) -> Wire3<T, Public> {
        Wire3::new(self.b.public_input(T::ir_type(), None))
    }

    /// Guarded public-transcript read.
    pub fn public_transcript_input_guarded<T: IrTy, V: Visibility>(
        &mut self,
        guard: Wire3<FieldT, V>,
    ) -> Wire3<T, Public> {
        Wire3::new(self.b.public_input(T::ir_type(), Some(Arg::Val(guard.val))))
    }

    /// A native-field constant, NAMED: `Copy imm` into a reusable wire.
    ///
    /// Only worth it when the value is used as a wire — a hash preimage
    /// element, a record limb, an Impact guard. In an operand position, pass
    /// the native Rust value itself ([`Operand`]): `c.less_than(0u64, x, 64)`
    /// inlines the immediate and emits no instruction at all, while
    /// `c.less_than(c.constant(0u64), x, 64)` emits this `Copy` first.
    pub fn constant(&mut self, imm: impl Into<Fr>) -> Wire3<FieldT, Public> {
        Wire3::new(self.b.imm(imm))
    }

    // --- arithmetic and logic (visibility joins via Meet) --------------------------
    //
    // Every operand position takes an `impl Into<Operand<T, V>>`: a wire, or
    // a native Rust value that becomes an inline immediate (see `Operand`).

    pub fn add<T: EqAddTy, A, B>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.add(a.into().arg(), b.into().arg()))
    }

    pub fn mul<T: MulTy, A, B>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.mul(a.into().arg(), b.into().arg()))
    }

    pub fn neg<T: EqAddTy, V: Visibility>(&mut self, a: impl Into<Operand<T, V>>) -> Wire3<T, V> {
        Wire3::new(self.b.neg(a.into().arg()))
    }

    /// `a^(-1)`; unsatisfiable at proving time if `a` is zero.
    pub fn inv<T: MulTy, V: Visibility>(&mut self, a: impl Into<Operand<T, V>>) -> Wire3<T, V> {
        Wire3::new(self.b.inv(a.into().arg()))
    }

    /// Boolean not; the operand must hold 0 or 1.
    pub fn not<V: Visibility>(&mut self, a: impl Into<Operand<FieldT, V>>) -> Wire3<FieldT, V> {
        Wire3::new(self.b.not(a.into().arg()))
    }

    /// Boolean (native) `a == b`.
    pub fn test_eq<T: EqAddTy, A, B>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.test_eq(a.into().arg(), b.into().arg()))
    }

    /// `a < b` over `bits`-bit native values.
    pub fn less_than<A, B>(
        &mut self,
        a: impl Into<Operand<FieldT, A>>,
        b: impl Into<Operand<FieldT, B>>,
        bits: u32,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.less_than(a.into().arg(), b.into().arg(), bits))
    }

    /// `bit ? a : b`.
    pub fn cond_select<T: EqAddTy, C, A, B>(
        &mut self,
        bit: impl Into<Operand<FieldT, C>>,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) -> Wire3<T, <C::Out as Meet<B>>::Out>
    where
        C: Visibility + Meet<A>,
        A: Visibility,
        B: Visibility,
        C::Out: Meet<B>,
    {
        Wire3::new(
            self.b
                .cond_select(bit.into().arg(), a.into().arg(), b.into().arg()),
        )
    }

    /// Split into `(w >> bits, w mod 2^bits)`.
    pub fn div_mod_power_of_two<V: Visibility>(
        &mut self,
        w: Wire3<FieldT, V>,
        bits: u32,
    ) -> (Wire3<FieldT, V>, Wire3<FieldT, V>) {
        let (d, m) = self.b.div_mod_power_of_two(w.val, bits);
        (Wire3::new(d), Wire3::new(m))
    }

    /// `divisor * 2^bits + modulus`, checked against field overflow.
    pub fn reconstitute_field<A, B>(
        &mut self,
        divisor: Wire3<FieldT, A>,
        modulus: Wire3<FieldT, B>,
        bits: u32,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.reconstitute_field(divisor.val, modulus.val, bits))
    }

    // --- hashes -----------------------------------------------------------------

    /// Poseidon-family hash of native field elements.
    pub fn transient_hash<V: Visibility>(
        &mut self,
        inputs: &[Wire3<FieldT, V>],
    ) -> Wire3<FieldT, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| Arg::Val(w.val)).collect();
        Wire3::new(self.b.transient_hash(&args))
    }

    /// SHA-256 persistent hash of `inputs` laid out per `alignment`.
    pub fn persistent_hash<V: Visibility>(
        &mut self,
        alignment: Alignment,
        inputs: &[AnyWire3<V>],
    ) -> Wire3<Bytes32T, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| Arg::Val(w.val)).collect();
        Wire3::new(self.b.persistent_hash(alignment, &args))
    }

    /// Keccak-256 of `inputs` laid out per `alignment`.
    pub fn keccak256<V: Visibility>(
        &mut self,
        alignment: Alignment,
        inputs: &[AnyWire3<V>],
    ) -> Wire3<Bytes32T, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| Arg::Val(w.val)).collect();
        Wire3::new(self.b.keccak256(alignment, &args))
    }

    /// Hash native field elements to a Jubjub point.
    pub fn hash_to_curve<V: Visibility>(
        &mut self,
        inputs: &[Wire3<FieldT, V>],
    ) -> Wire3<JubjubPointT, V> {
        let args: Vec<Arg> = inputs.iter().map(|w| Arg::Val(w.val)).collect();
        Wire3::new(self.b.hash_to_curve(&args))
    }

    // --- elliptic curves -----------------------------------------------------------

    /// Multiply a point by a scalar of its curve.
    pub fn ec_mul<P: PointTy, A, B>(
        &mut self,
        point: Wire3<P, A>,
        scalar: Wire3<P::Scalar, B>,
    ) -> Wire3<P, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.ec_mul(point.val, scalar.val))
    }

    /// Multiply the curve generator matching the scalar's type (Jubjub or
    /// secp256k1).
    pub fn ec_mul_generator<S: GeneratorScalarTy, V: Visibility>(
        &mut self,
        scalar: Wire3<S, V>,
    ) -> Wire3<S::Point, V> {
        Wire3::new(self.b.ec_mul_generator(scalar.val))
    }

    /// The affine coordinates `(x, y)` of a point (unsatisfiable for the
    /// Weierstrass identity).
    pub fn into_coordinates<P: PointTy, V: Visibility>(
        &mut self,
        point: Wire3<P, V>,
    ) -> (Wire3<P::Coord, V>, Wire3<P::Coord, V>) {
        let (x, y) = self.b.into_coordinates(point.val);
        (Wire3::new(x), Wire3::new(y))
    }

    /// Reconstruct a point from affine coordinates (cannot build the
    /// Weierstrass identity).
    pub fn from_coordinates<P: PointTy, A, B>(
        &mut self,
        x: Wire3<P::Coord, A>,
        y: Wire3<P::Coord, B>,
    ) -> Wire3<P, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.from_coordinates(P::ir_type(), x.val, y.val))
    }

    // --- Bytes<32> conversions --------------------------------------------------------

    /// The canonical little-endian 32-byte form of a prime-field element.
    pub fn into_bytes32<T: Bytes32ConvTy, V: Visibility>(
        &mut self,
        input: Wire3<T, V>,
    ) -> Wire3<Bytes32T, V> {
        Wire3::new(self.b.into_bytes32(input.val))
    }

    /// A prime-field element from its 32-byte form (non-canonical bytes are
    /// reduced mod the field order).
    pub fn from_bytes32<T: Bytes32ConvTy, V: Visibility>(
        &mut self,
        bytes: Wire3<Bytes32T, V>,
    ) -> Wire3<T, V> {
        Wire3::new(self.b.from_bytes32(bytes.val, T::ir_type()))
    }

    /// Reverse the byte order of a `Bytes<32>` value.
    pub fn reverse_bytes<V: Visibility>(
        &mut self,
        bytes: Wire3<Bytes32T, V>,
    ) -> Wire3<Bytes32T, V> {
        Wire3::new(self.b.reverse_bytes(bytes.val))
    }

    /// Decompose `Bytes<32>` into `(low, high)` native elements (low = bytes
    /// 0..30 LE, high = byte 31) — Compact's field-slot view.
    pub fn bytes32_into_low_high<V: Visibility>(
        &mut self,
        bytes: Wire3<Bytes32T, V>,
    ) -> (Wire3<FieldT, V>, Wire3<FieldT, V>) {
        let (low, high) = self.b.bytes32_into_low_high(bytes.val);
        (Wire3::new(low), Wire3::new(high))
    }

    /// Compose `Bytes<32>` from `(low, high)` native elements.
    pub fn bytes32_from_low_high<A, B>(
        &mut self,
        low: Wire3<FieldT, A>,
        high: Wire3<FieldT, B>,
    ) -> Wire3<Bytes32T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.bytes32_from_low_high(low.val, high.val))
    }

    /// A `JubjubScalar` from a native element (reduces mod the Jubjub
    /// scalar-field order — unlike v2's plain copy).
    pub fn jubjub_scalar_from_native<V: Visibility>(
        &mut self,
        native: Wire3<FieldT, V>,
    ) -> Wire3<JubjubScalarT, V> {
        Wire3::new(self.b.jubjub_scalar_from_native(native.val))
    }

    /// Encode a value as its raw native-element representation.
    pub fn encode<T: IrTy, V: Visibility>(&mut self, input: Wire3<T, V>) -> Vec<Wire3<FieldT, V>> {
        self.b
            .encode(input.val)
            .into_iter()
            .map(Wire3::new)
            .collect()
    }

    // --- constraints -----------------------------------------------------------------

    /// Constrain a condition to be true (constraining private data is the
    /// point of ZK — this discloses nothing).
    ///
    /// Takes anything [`Assertion`]: a boolean wire, or a deferred PREDICATE
    /// that lowers itself here (`minocrab_std::v3::Check` —
    /// `c.assert(less_than(0u64, amount))`). A predicate lowers to exactly
    /// the comparison instruction the hand-written form emits, at this call
    /// site.
    pub fn assert(&mut self, cond: impl Assertion) {
        cond.assert_in(self);
    }

    /// [`Circuit3::assert`] with Compact's second `assert(cond, "message")`
    /// argument.
    ///
    /// The message is METADATA — no instruction, no slot, no row, exactly
    /// like a disclosure record — recorded against the position of the
    /// `Assert` about to be emitted, so a simulator can name the failed
    /// check instead of printing an instruction index. ZKIR has nowhere to
    /// put it, which is why it lives beside the stream rather than in it.
    pub fn assert_with<V: Visibility>(&mut self, cond: Wire3<FieldT, V>, message: Option<&str>) {
        if let Some(message) = message {
            self.assert_messages.push(AssertMessage {
                instruction: self.b.len(),
                message: message.to_string(),
            });
        }
        self.b.assert(cond.val);
    }

    /// `constrain_eq a b` — either side may be an inline immediate, which is
    /// compactc's own `(constrain_eq ,var-name ,0)` shape: `c.assert_eq(w,
    /// 0u64)` names no constant and so emits no `Copy`.
    pub fn assert_eq<T: EqAddTy, A: Visibility, B: Visibility>(
        &mut self,
        a: impl Into<Operand<T, A>>,
        b: impl Into<Operand<T, B>>,
    ) {
        self.b.constrain_eq(a.into().arg(), b.into().arg());
    }

    pub fn assert_bits<V: Visibility>(&mut self, w: Wire3<FieldT, V>, bits: u32) {
        self.b.constrain_bits(w.val, bits);
    }

    pub fn assert_boolean<V: Visibility>(&mut self, w: Wire3<FieldT, V>) {
        self.b.constrain_to_boolean(w.val);
    }

    // --- disclosure: the only Private → Public gate --------------------------------------

    /// Explicitly make a private value public — the greppable audit point,
    /// as in the v2 frontend.
    ///
    /// The typed form is `minocrab_std::v3::Disclose::disclose_as::<L>`,
    /// which names the disclosure with a label TYPE that the circuit's
    /// `Discloses<..>` declaration also names, so the two cannot drift; this
    /// is its one-wire, free-string base case.
    pub fn disclose<T: IrTy>(&mut self, w: Wire3<T, Private>, label: &str) -> Wire3<T, Public> {
        let [out] = self.disclose_all(label, [w]);
        out
    }

    /// Disclose the wires of ONE logical value under ONE label — a
    /// `Bytes<32>`'s `[hi, lo]` pair becomes a single record rather than a
    /// `"… (hi)"` / `"… (lo)"` pair (see [`Disclosure3`]).
    ///
    /// The typed layer above (`minocrab_std::v3::Disclose`) is what call
    /// sites use; this is the primitive it fans out through, and the only
    /// place a `Disclosed` record is created.
    pub fn disclose_all<T: IrTy, const N: usize>(
        &mut self,
        label: &str,
        wires: [Wire3<T, Private>; N],
    ) -> [Wire3<T, Public>; N] {
        self.record_disclosure(label, &wires);
        wires.map(|w| Wire3::new(w.val))
    }

    /// [`Circuit3::disclose_all`] for a run-time number of wires (a
    /// `Bytes<N>`'s limbs, an event record's fields): still one record.
    pub fn disclose_slice<T: IrTy>(
        &mut self,
        label: &str,
        wires: &[Wire3<T, Private>],
    ) -> Vec<Wire3<T, Public>> {
        self.record_disclosure(label, wires);
        wires.iter().map(|w| Wire3::new(w.val)).collect()
    }

    /// One `Disclosed` record over `wires` — or NONE, if there are no wires.
    /// A value with no wires discloses nothing (a cross-contract call to a
    /// `[]`-returning circuit has an empty result list), and recording it
    /// anyway would put a label in the disclosed set that no value backs.
    fn record_disclosure<T: IrTy>(&mut self, label: &str, wires: &[Wire3<T, Private>]) {
        if wires.is_empty() {
            return;
        }
        self.disclosures.push(Disclosure3 {
            label: label.to_string(),
            kind: DisclosureKind::Disclosed,
            values: wires.iter().map(|w| self.b.identifier(w.val)).collect(),
        });
    }

    // --- public-input blocks and outputs (public only) --------------------------------------

    /// Declare a guarded block of native public inputs (one Impact
    /// instruction). The full ledger-op encoding layer sits above this.
    pub fn impact<V: Visibility>(
        &mut self,
        guard: impl Into<Operand<FieldT, V>>,
        inputs: &[Wire3<FieldT, Public>],
    ) {
        let elems: Vec<ImpactElem> = inputs.iter().map(|&w| ImpactElem::Wire(w)).collect();
        self.impact_mixed(guard, &elems);
    }

    /// [`Circuit3::impact`] with mixed operands: constants go inline as
    /// immediates (as compactc emits opcode/alignment elements), computed
    /// values as wires.
    ///
    /// The GUARD is an operand too (M9 phase 8): a wire for a branch
    /// condition, or the native `true`/`1u64` for a straight-line operation,
    /// which inlines as an immediate instead of naming a `Copy`. compactc
    /// always names one (it threads a `1` wire through every op of a
    /// straight-line circuit), so the immediate form is a deliberate
    /// departure — zero rows, one fewer instruction, and no longer
    /// byte-identical to compactc's stream.
    pub fn impact_mixed<V: Visibility>(
        &mut self,
        guard: impl Into<Operand<FieldT, V>>,
        elems: &[ImpactElem],
    ) {
        let args: Vec<Arg> = elems
            .iter()
            .map(|e| match e {
                ImpactElem::Imm(imm) => Arg::Imm(*imm),
                ImpactElem::Wire(w) => {
                    self.disclosures.push(Disclosure3 {
                        label: "impact public input".to_string(),
                        kind: DisclosureKind::Statement,
                        values: vec![self.b.identifier(w.val)],
                    });
                    Arg::Val(w.val)
                }
            })
            .collect();
        self.b.impact(guard.into().arg(), &args);
    }

    /// Queue a wire as a circuit output (the single v3 Output terminator is
    /// emitted by [`Circuit3::finish`]).
    pub fn output<T: IrTy>(&mut self, w: Wire3<T, Public>, label: &str) {
        self.disclosures.push(Disclosure3 {
            label: label.to_string(),
            kind: DisclosureKind::Output,
            values: vec![self.b.identifier(w.val)],
        });
        self.queued_outputs.push((w.val, T::ir_type()));
    }

    // --- profiling regions ---------------------------------------------------------------

    /// Attribute the instructions built inside `f` to a named region.
    pub fn region<R>(&mut self, label: &str, f: impl FnOnce(&mut Self) -> R) -> R {
        let start = self.b.len();
        let result = f(self);
        self.regions.push(Region {
            label: label.to_string(),
            start,
            end: self.b.len(),
        });
        result
    }

    // --- finish ------------------------------------------------------------------------------

    pub fn finish(mut self, communications_commitment: bool) -> Compiled3 {
        if !self.queued_outputs.is_empty() {
            let vals: Vec<Arg> = self
                .queued_outputs
                .iter()
                .map(|(v, _)| Arg::Val(*v))
                .collect();
            self.b.output(&vals);
        }
        Compiled3 {
            ir: self.b.finish(communications_commitment),
            disclosures: self.disclosures,
            witnesses: self.witnesses,
            regions: self.regions,
            assert_messages: self.assert_messages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_wires_track_visibility_and_type() {
        let mut c = Circuit3::new();
        let x = c.witness::<FieldT>();
        let k = c.constant(3u64);
        let s = c.add(x, k.private());
        // s is private: no path to output without disclose.
        let s_pub = c.disclose(s, "witness plus three");
        c.output(s_pub, "sum");

        let pk = c.witness::<Secp256k1PointT>();
        let (px, _py) = c.into_coordinates(pk);
        let px_bytes = c.into_bytes32(px);
        let (lo, _hi) = c.bytes32_into_low_high(px_bytes);
        c.assert_bits(lo, 248);

        let compiled = c.finish(false);
        assert_eq!(compiled.witnesses, 2);
        assert_eq!(compiled.ir.outputs.len(), 1);
    }
}
