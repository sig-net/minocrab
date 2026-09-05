/-
secp256k1 — the one foreign curve ZKIR v3's corpus actually exercises
(M27 rung 4; notes/zkir-rung4.org). Ported mechanically from the pinned
sources:

  midnight-ledger 04c9c5d9 zkir-v3/src/ir_instructions/
    add.rs:43-67          `add_offcircuit`           (point, base, scalar)
    mul.rs:39-58          `mul_offcircuit`           (base, scalar; NOT point)
    neg.rs:43-66          `neg_offcircuit`
    inv.rs:39-75          `inv_offcircuit`           (error on zero)
    eq.rs:42-67           `test_eq_offcircuit`
    ec_mul.rs:33-46       `ec_mul_offcircuit`        (point x scalar)
    into_coordinates.rs:41-66  (identity has no affine coordinates: error)
    from_coordinates.rs:39-55  `K256::from_xy`, on-curve validated
    into_bytes32.rs:40-62 `to_bytes_le`, 32 little-endian bytes
    from_bytes32.rs:49-74, 149-154  `from_le_bytes_with_reduction`:
                          the 32-byte little-endian integer MOD the field
    encode.rs:36-83, 137-207  `encode_offcircuit` / `decode_offcircuit`
  midnight-curves 0.3.1 src/k256/curve.rs:31-115 — `K256` is RustCrypto's
    `k256::ProjectivePoint`, i.e. STANDARD secp256k1: y^2 = x^3 + 7 over
    Fp, cofactor 1 (so `try_into_subgroup` is the identity on-curve
    points), with the standard generator.
  midnight-circuits 7.2.4 src/field/foreign/field_chip.rs:130-165 and
    src/ecc/foreign/weierstrass_chip.rs:235-266 — the emulated-field
    public-input encoding, with params from src/field/foreign/params.rs:
    181-189 (Fp) and 212-221 (Fq): LOG2_BASE = 64, NB_LIMBS = 4 over
    BLS12-381's scalar field, whose CAPACITY is 254, so
    `nb_limbs_per_batch = 254 / 64 = 3` and a field element is TWO
    natives: the low three 64-bit limbs packed, then the fourth.

The arithmetic is plain affine short-Weierstrass with a total inversion
(`x^(q-2)`, zero at zero) — the obvious form, not the fast one; a whole
vault circuit does nine curve operations, so the projective rewrite would
buy nothing and cost the reading.

GATE: `zkir-run --kat`, against vectors the Rust reference printed through
these very `*_offcircuit` functions (differential/known-answers.txt), plus
the vault and manager run records.
-/
import MinocrabZkir.Semantics

namespace MinocrabZkir.Secp256k1

open MinocrabZkir

/-! ## The two fields -/

/-- secp256k1's base field order, `2^256 - 2^32 - 977`. -/
def pBase : Nat := 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
/-- secp256k1's group (scalar field) order. -/
def pScalar : Nat := 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

theorem pBase_pos : 0 < pBase := by decide
theorem pScalar_pos : 0 < pScalar := by decide

instance : NeZero pBase := ⟨Nat.pos_iff_ne_zero.mp pBase_pos⟩
instance : NeZero pScalar := ⟨Nat.pos_iff_ne_zero.mp pScalar_pos⟩

abbrev Fp := Fin pBase
abbrev Fq := Fin pScalar

/-- `x^n` by square-and-multiply, over any `Fin m` with `m` nonzero. -/
private def powAux {m : Nat} [NeZero m] (a : Fin m) (n : Nat) (acc : Fin m) : Fin m :=
  if _h : n = 0 then acc
  else powAux (a * a) (n / 2) (if n % 2 = 1 then acc * a else acc)
  termination_by n
  decreasing_by omega

private def pow {m : Nat} [NeZero m] (a : Fin m) (n : Nat) : Fin m := powAux a n 1

namespace Fp
def ofNat (n : Nat) : Fp := ⟨n % pBase, Nat.mod_lt _ pBase_pos⟩
def neg (a : Fp) : Fp := (0 : Fp) - a
/-- Fermat inversion; TOTAL, with `inv 0 = 0`. Callers that must reject
zero (`inv_offcircuit`) test for it first. -/
def inv (a : Fp) : Fp := pow a (pBase - 2)
def sq (a : Fp) : Fp := a * a
end Fp

namespace Fq
def ofNat (n : Nat) : Fq := ⟨n % pScalar, Nat.mod_lt _ pScalar_pos⟩
def neg (a : Fq) : Fq := (0 : Fq) - a
def inv (a : Fq) : Fq := pow a (pScalar - 2)
end Fq

/-! ## The group -/

/-- A curve point: the identity, or an affine pair ON the curve. The
constructors are unguarded; `fromXY` is the only way a point enters from
outside, and it checks. -/
inductive Pt where
  | infinity
  | affine (x y : Fp)
deriving DecidableEq, Inhabited

/-- `y^2 = x^3 + 7`. -/
def onCurve (x y : Fp) : Bool :=
  decide (y * y = x * x * x + Fp.ofNat 7)

/-- `K256::from_xy` (midnight-curves k256/curve.rs:101-113): the SEC1
uncompressed decoder, which validates the point is on the curve. The
cofactor is 1, so `try_into_subgroup` adds nothing. -/
def fromXY (x y : Fp) : Option Pt :=
  if onCurve x y then some (.affine x y) else none

/-- The standard generator (`ProjectivePoint::GENERATOR`). -/
def generator : Pt :=
  .affine
    (Fp.ofNat 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
    (Fp.ofNat 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

def neg : Pt → Pt
  | .infinity => .infinity
  | .affine x y => .affine x (Fp.neg y)

/-- The affine chord-and-tangent law. `a = 0` for secp256k1, so the
doubling slope is `3x^2 / 2y`. -/
def add : Pt → Pt → Pt
  | .infinity, q => q
  | p, .infinity => p
  | .affine x₁ y₁, .affine x₂ y₂ =>
    if x₁ = x₂ then
      -- Either a doubling or a pair of opposites (y₂ = −y₁, including
      -- the y = 0 case, which secp256k1 has no point at but the law
      -- handles uniformly).
      if y₁ + y₂ = 0 then .infinity
      else
        let l := (Fp.ofNat 3 * Fp.sq x₁) * Fp.inv (y₁ + y₁)
        let x₃ := Fp.sq l - x₁ - x₂
        .affine x₃ (l * (x₁ - x₃) - y₁)
    else
      let l := (y₂ - y₁) * Fp.inv (x₂ - x₁)
      let x₃ := Fp.sq l - x₁ - x₂
      .affine x₃ (l * (x₁ - x₃) - y₁)

/-- Double-and-add, MOST SIGNIFICANT BIT FIRST. `mulAux p n k` is
`(n >>> (256 - k)) * p`: the recursion counts bits ALREADY consumed, so
step `k + 1` doubles and then adds bit `255 - k`. (Indexing this the
other way round — bit `k` at step `k + 1` — computes the bit-REVERSED
scalar, and reads exactly as plausibly; the known-answer vectors are
what caught it.) 256 bits cover every `Fq`, whose order is below
`2^256`. -/
private def mulAux (p : Pt) (n : Nat) : Nat → Pt
  | 0 => .infinity
  | k + 1 =>
    let acc := mulAux p n k
    let acc := add acc acc
    if (n / 2 ^ (255 - k)) % 2 = 1 then add acc p else acc

def mul (p : Pt) (s : Fq) : Pt := mulAux p s.val 256

/-- `into_coordinates_offcircuit` (into_coordinates.rs:49-57): the
identity has no affine coordinates and is an ERROR, not a zero pair. -/
def coordinates : Pt → Option (Fp × Fp)
  | .infinity => none
  | .affine x y => some (x, y)

def isIdentity : Pt → Bool
  | .infinity => true
  | .affine _ _ => false

/-! ## Bytes -/

/-- `to_bytes_le`: the canonical value in 32 little-endian bytes. -/
def bytesOfFp (a : Fp) : Bytes32 := Bytes32.ofLE a.val
def bytesOfFq (a : Fq) : Bytes32 := Bytes32.ofLE a.val

/-- `from_le_bytes_with_reduction` (from_bytes32.rs:149-154): the
32-byte little-endian integer REDUCED modulo the field order. -/
def fpOfBytes (b : Bytes32) : Fp := Fp.ofNat (leToNat b.toList)
def fqOfBytes (b : Bytes32) : Fq := Fq.ofNat (leToNat b.toList)

/-! ## The emulated-field public-input encoding

`AssignedField::as_public_input` (field_chip.rs:130-138) shifts by one
for the unique-zero representation, splits into `NB_LIMBS = 4` limbs
base `2^64`, then packs them in batches of `nb_limbs_per_batch = 3`.
With four limbs that is `[l0 + l1·2^64 + l2·2^128, l3]` — the low 192
bits and the top 64 — of `element − 1`.

`from_public_input` (field_chip.rs:141-165) inverts it, rejecting a
first native at or above `2^192` or a second at or above `2^64` (the
`batch_bound` test plus the zero tail), and reduces the recovered
integer modulo the emulated field. -/

private def twoPow192 : Nat := 2 ^ 192
private def twoPow64 : Nat := 2 ^ 64

private def encodeShifted (v : Nat) : List Fr :=
  [Fr.ofNat (v % twoPow192), Fr.ofNat (v / twoPow192)]

def encodeFp (a : Fp) : List Fr := encodeShifted (Fp.neg 1 + a).val
def encodeFq (a : Fq) : List Fr := encodeShifted (Fq.neg 1 + a).val

private def decodeShifted (lo hi : Fr) : Option Nat :=
  if lo.val < twoPow192 ∧ hi.val < twoPow64 then some (lo.val + hi.val * twoPow192 + 1)
  else none

def decodeFp : List Fr → Option Fp
  | [lo, hi] => (decodeShifted lo hi).map Fp.ofNat
  | _ => none

def decodeFq : List Fr → Option Fq
  | [lo, hi] => (decodeShifted lo hi).map Fq.ofNat
  | _ => none

/-- `AssignedForeignPoint::as_public_input` (weierstrass_chip.rs:235-247):
both coordinates, then the identity flag. The identity's coordinates are
`(0, 0)` (`coordinates().unwrap_or((ZERO, ZERO))`), which encode as the
shifted `−1`. -/
def encodePoint (p : Pt) : List Fr :=
  let (x, y) := match coordinates p with
    | some (x, y) => (x, y)
    | none => (0, 0)
  encodeFp x ++ encodeFp y ++ [if isIdentity p then 1 else 0]

/-- `AssignedForeignPoint::from_public_input` (weierstrass_chip.rs:249-266).
Note the order upstream uses: the identity flag is tested FIRST, before
the length, so a trailing `1` yields the identity whatever precedes it. -/
def decodePoint (raw : List Fr) : Option Pt :=
  match raw.getLast? with
  | none => none
  | some flag =>
    if flag = 1 then some .infinity
    else match raw with
      | [x0, x1, y0, y1, _] => do
        let x ← decodeFp [x0, x1]
        let y ← decodeFp [y0, y1]
        fromXY x y
      | _ => none

end MinocrabZkir.Secp256k1
