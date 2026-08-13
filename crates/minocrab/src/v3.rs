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
pub use minocrab_ir::v3::Alignment;
use minocrab_ir::Fr;

use crate::{Disclosure, DisclosureKind, Meet, Private, Public, Region, Visibility};

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

impl<V: Visibility> Clone for AnyWire3<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V: Visibility> Copy for AnyWire3<V> {}

// --- circuit ---------------------------------------------------------------------

/// A ZKIR v3 circuit under construction.
pub struct Circuit3 {
    b: Builder3,
    disclosures: Vec<Disclosure>,
    witnesses: u32,
    regions: Vec<Region>,
    queued_outputs: Vec<(Val, IrType)>,
}

/// A finished v3 circuit: the lowered ZKIR plus its disclosure record.
pub struct Compiled3 {
    pub ir: IrSource,
    pub disclosures: Vec<Disclosure>,
    pub witnesses: u32,
    pub regions: Vec<Region>,
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
        }
    }

    // --- circuit arguments (witness data, like v2 args) -------------------------

    /// Declare the next circuit argument. Must precede all instructions.
    pub fn arg<T: IrTy>(&mut self, label: &str) -> Wire3<T, Private> {
        Wire3::new(self.b.input(label, T::ir_type()))
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

    /// A native-field constant (constants are part of the circuit, hence
    /// public). v3 immediates are inline operands; this names one via a
    /// free `Copy`.
    pub fn constant(&mut self, imm: impl Into<Fr>) -> Wire3<FieldT, Public> {
        Wire3::new(self.b.imm(imm))
    }

    // --- arithmetic and logic (visibility joins via Meet) --------------------------

    pub fn add<T: EqAddTy, A, B>(&mut self, a: Wire3<T, A>, b: Wire3<T, B>) -> Wire3<T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.add(a.val, b.val))
    }

    pub fn mul<T: MulTy, A, B>(&mut self, a: Wire3<T, A>, b: Wire3<T, B>) -> Wire3<T, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.mul(a.val, b.val))
    }

    pub fn neg<T: EqAddTy, V: Visibility>(&mut self, a: Wire3<T, V>) -> Wire3<T, V> {
        Wire3::new(self.b.neg(a.val))
    }

    /// `a^(-1)`; unsatisfiable at proving time if `a` is zero.
    pub fn inv<T: MulTy, V: Visibility>(&mut self, a: Wire3<T, V>) -> Wire3<T, V> {
        Wire3::new(self.b.inv(a.val))
    }

    /// Boolean not; the operand must hold 0 or 1.
    pub fn not<V: Visibility>(&mut self, a: Wire3<FieldT, V>) -> Wire3<FieldT, V> {
        Wire3::new(self.b.not(a.val))
    }

    /// Boolean (native) `a == b`.
    pub fn test_eq<T: EqAddTy, A, B>(
        &mut self,
        a: Wire3<T, A>,
        b: Wire3<T, B>,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.test_eq(a.val, b.val))
    }

    /// `a < b` over `bits`-bit native values.
    pub fn less_than<A, B>(
        &mut self,
        a: Wire3<FieldT, A>,
        b: Wire3<FieldT, B>,
        bits: u32,
    ) -> Wire3<FieldT, A::Out>
    where
        A: Visibility + Meet<B>,
        B: Visibility,
    {
        Wire3::new(self.b.less_than(a.val, b.val, bits))
    }

    /// `bit ? a : b`.
    pub fn cond_select<T: EqAddTy, C, A, B>(
        &mut self,
        bit: Wire3<FieldT, C>,
        a: Wire3<T, A>,
        b: Wire3<T, B>,
    ) -> Wire3<T, <C::Out as Meet<B>>::Out>
    where
        C: Visibility + Meet<A>,
        A: Visibility,
        B: Visibility,
        C::Out: Meet<B>,
    {
        Wire3::new(self.b.cond_select(bit.val, a.val, b.val))
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

    /// Multiply the Jubjub generator by a scalar.
    pub fn ec_mul_generator<V: Visibility>(
        &mut self,
        scalar: Wire3<JubjubScalarT, V>,
    ) -> Wire3<JubjubPointT, V> {
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

    /// Constrain a boolean wire to be true (constraining private data is
    /// the point of ZK — this discloses nothing).
    pub fn assert<V: Visibility>(&mut self, cond: Wire3<FieldT, V>) {
        self.b.assert(cond.val);
    }

    pub fn assert_eq<T: EqAddTy, A: Visibility, B: Visibility>(
        &mut self,
        a: Wire3<T, A>,
        b: Wire3<T, B>,
    ) {
        self.b.constrain_eq(a.val, b.val);
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
    pub fn disclose<T: IrTy>(&mut self, w: Wire3<T, Private>, label: &str) -> Wire3<T, Public> {
        self.disclosures.push(Disclosure {
            label: label.to_string(),
            kind: DisclosureKind::Disclosed,
            index: 0, // v3 values are named, not indexed; see `Builder3::ty`.
        });
        Wire3::new(w.val)
    }

    // --- public-input blocks and outputs (public only) --------------------------------------

    /// Declare a guarded block of native public inputs (one Impact
    /// instruction). The full ledger-op encoding layer sits above this.
    pub fn impact<V: Visibility>(
        &mut self,
        guard: Wire3<FieldT, V>,
        inputs: &[Wire3<FieldT, Public>],
    ) {
        for w in inputs {
            self.disclosures.push(Disclosure {
                label: "impact public input".to_string(),
                kind: DisclosureKind::Statement,
                index: 0,
            });
            let _ = w;
        }
        let args: Vec<Arg> = inputs.iter().map(|w| Arg::Val(w.val)).collect();
        self.b.impact(Arg::Val(guard.val), &args);
    }

    /// Queue a wire as a circuit output (the single v3 Output terminator is
    /// emitted by [`Circuit3::finish`]).
    pub fn output<T: IrTy>(&mut self, w: Wire3<T, Public>, label: &str) {
        self.disclosures.push(Disclosure {
            label: label.to_string(),
            kind: DisclosureKind::Output,
            index: 0,
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
