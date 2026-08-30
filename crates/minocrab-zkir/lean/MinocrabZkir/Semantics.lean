/-
The EVALUATION reading of ZKIR v3 (M27 rung 3; notes/zkir-semantics.org
§4.1, §5): `IrSource::preprocess` (zkir-v3/src/ir_vm.rs:185-691, rev
04c9c5d9) transcribed over the real IR type, with the intrinsics
UNINTERPRETED — a `Model` record of functions the semantics consults and
never defines. Everything Native/Bytes32 is concrete here; the foreign
curve/field carriers are opaque types in `Carriers`.

`Fr` is `Fin p`, which is what Mathlib's `ZMod p` unfolds to for a
positive literal; the package stays mathlib-free like the other two.

Observables (§4.1): `pis`, `piSkips`, `outputs`, accept/reject, and the
consumed prefixes of the three transcripts. Reject is `Except.error`
with the upstream message where one exists.

NOT YET HERE (next session): the constraint reading `Sat` (§4.2), the
completeness lemma, the pass theorems over `Instr`, and the rung-4
differential. This file is the model; the theorems come after it has
been read once more against ir_vm.rs.
-/
import MinocrabZkir.Syntax
import MinocrabZkir.Dataflow

namespace MinocrabZkir

/-- The BLS12-381 scalar field modulus (transient-crypto `Fr`). -/
def p : Nat := 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

theorem p_pos : 0 < p := by decide

instance : NeZero p := ⟨Nat.pos_iff_ne_zero.mp p_pos⟩

/-- `FR_BITS` (transient-crypto): the bit length of `p`. -/
def frBits : Nat := 255
/-- `FR_BYTES_STORED`: bytes a field element holds losslessly — the FAB limb. -/
def frBytesStored : Nat := 31

abbrev Fr := Fin p

namespace Fr

def ofNat (n : Nat) : Fr := ⟨n % p, Nat.mod_lt _ p_pos⟩

/-- `ir_vm.rs:238`: an immediate always resolves as a Native; the signed
literal is reduced here and nowhere else (Syntax.lean). -/
def ofInt (i : Int) : Fr :=
  if i < 0 then (0 : Fr) - ofNat i.natAbs else ofNat i.natAbs

def neg (a : Fr) : Fr := (0 : Fr) - a

/-- Square-and-multiply; `inv a = a^(p−2)`, total with `inv 0 = 0`. -/
def pow (a : Fr) (n : Nat) : Fr :=
  go a n 1
where
  go (a : Fr) (n : Nat) (acc : Fr) : Fr :=
    if _h : n = 0 then acc
    else go (a * a) (n / 2) (if n % 2 = 1 then acc * a else acc)
  termination_by n
  decreasing_by omega

def inv (a : Fr) : Fr := pow a (p - 2)

/-- The `i`-th little-endian bit. -/
def bit (a : Fr) (i : Nat) : Bool := (a.val / 2 ^ i) % 2 = 1

end Fr

abbrev Bytes32 := Vector UInt8 32

/-- Little-endian bytes of `n`, exactly `len` of them (truncating above). -/
def natToLE (n : Nat) (len : Nat) : List UInt8 :=
  (List.range len).map fun i => UInt8.ofNat ((n / 256 ^ i) % 256)

def leToNat (bs : List UInt8) : Nat :=
  bs.foldr (fun b acc => acc * 256 + b.toNat) 0

def Bytes32.ofLE (n : Nat) : Bytes32 :=
  ⟨(natToLE n 32).toArray, by simp [natToLE]⟩

def Bytes32.zero : Bytes32 := Bytes32.ofLE 0

/-- The opaque carriers of the eleven non-Native, non-Bytes32 types. -/
structure Carriers where
  jubjubPoint : Type
  jubjubScalar : Type
  k256Point : Type
  k256Base : Type
  k256Scalar : Type
  p256Point : Type
  p256Base : Type
  p256Scalar : Type
  c25519Point : Type
  c25519Base : Type
  c25519Scalar : Type

/-- `IrValue` (ir_types.rs:114-146) over the carriers. -/
inductive Value (C : Carriers) where
  | native (x : Fr)
  | bytes32 (b : Bytes32)
  | jubjubPoint (x : C.jubjubPoint)
  | jubjubScalar (x : C.jubjubScalar)
  | k256Point (x : C.k256Point)
  | k256Base (x : C.k256Base)
  | k256Scalar (x : C.k256Scalar)
  | p256Point (x : C.p256Point)
  | p256Base (x : C.p256Base)
  | p256Scalar (x : C.p256Scalar)
  | c25519Point (x : C.c25519Point)
  | c25519Base (x : C.c25519Base)
  | c25519Scalar (x : C.c25519Scalar)

variable {C : Carriers}

/-- `IrValue::get_type` (ir_types.rs:149-165). -/
def Value.type : Value C → IrType
  | .native _ => .native
  | .bytes32 _ => .bytes32
  | .jubjubPoint _ => .jubjubPoint
  | .jubjubScalar _ => .jubjubScalar
  | .k256Point _ => .secp256k1Point
  | .k256Base _ => .secp256k1Base
  | .k256Scalar _ => .secp256k1Scalar
  | .p256Point _ => .secp256r1Point
  | .p256Base _ => .secp256r1Base
  | .p256Scalar _ => .secp256r1Scalar
  | .c25519Point _ => .curve25519Point
  | .c25519Base _ => .curve25519Base
  | .c25519Scalar _ => .curve25519Scalar

/-- `IrType::encoded_len` (ir_types.rs:92-111). -/
def IrType.encodedLen : IrType → Nat
  | .native => 1
  | .bytes32 => 2
  | .jubjubPoint => 2
  | .jubjubScalar => 1
  | .secp256k1Point => 5
  | .secp256k1Base => 2
  | .secp256k1Scalar => 2
  | .secp256r1Point => 5
  | .secp256r1Base => 2
  | .secp256r1Scalar => 2
  | .curve25519Point => 4
  | .curve25519Base => 2
  | .curve25519Scalar => 2

abbrev R := Except String

/-- The uninterpreted intrinsics (§5). Foreign-typed arithmetic and the
curve/hash operations are consulted only when the semantics' own
concrete Native/Bytes32 arms do not apply; `default` and
`encode`/`decode` likewise cover the foreign types only. Rung 4
instantiates this record. -/
structure Model (C : Carriers) where
  transientHash : List Fr → Fr
  transientCommit : List Fr → Fr → Fr
  sha256 : List UInt8 → Bytes32
  keccak256 : List UInt8 → Bytes32
  hashToCurve : List Fr → C.jubjubPoint
  jubjubScalarFromNative : Fr → C.jubjubScalar
  addF : Value C → Value C → R (Value C)
  mulF : Value C → Value C → R (Value C)
  negF : Value C → R (Value C)
  invF : Value C → R (Value C)
  eqF : Value C → Value C → R Bool
  ecMul : Value C → Value C → R (Value C)
  ecMulGenerator : Value C → R (Value C)
  intoCoordinates : Value C → R (Value C × Value C)
  fromCoordinates : Value C → Value C → R (Value C)
  intoBytes32F : Value C → R Bytes32
  fromBytes32F : IrType → Bytes32 → R (Value C)
  encodeF : Value C → List Fr
  decodeF : IrType → List Fr → R (Value C)
  defaultF : IrType → Value C

/-- `ProofPreimage` (transient-crypto proofs.rs:716-732), the four
streams and the two bound values. -/
structure Preimage where
  inputs : List Fr
  privateTranscript : List Fr
  publicTranscriptInputs : List Fr
  publicTranscriptOutputs : List Fr
  bindingInput : Fr
  communicationsCommitment : Option (Fr × Fr)

/-- The walk's state: memory as an overwrite-on-insert association list
(`HashMap::insert` semantics: the newest binding wins), the PI vector,
the skip list, the three cursors, and the collected outputs. -/
structure State (C : Carriers) where
  memory : List (Ident × Value C)
  pis : List Fr
  piSkips : List (Option Nat)
  privIdx : Nat
  pubOutIdx : Nat
  pubInIdx : Nat
  outputs : List (Value C)

/-- What `Preprocessed` carries (ir_vm.rs:71-77) plus the outputs. -/
structure Result (C : Carriers) where
  memory : List (Ident × Value C)
  pis : List Fr
  piSkips : List (Option Nat)
  outputs : List (Value C)

def lookup (mem : List (Ident × Value C)) (id : Ident) : Option (Value C) :=
  (mem.find? fun (k, _) => k = id).map (·.2)

def State.insert (st : State C) (id : Ident) (v : Value C) : State C :=
  { st with memory := (id, v) :: st.memory }

namespace Eval

variable (M : Model C)

/-- ir_vm.rs:227-239. -/
def resolve (st : State C) : Operand → R (Value C)
  | .var id => match lookup st.memory id with
    | some v => pure v
    | none => throw s!"variable not found: {id}"
  | .imm i => pure (.native (Fr.ofInt i))

def asNative : Value C → R Fr
  | .native x => pure x
  | v => throw s!"cannot convert {repr v.type} to Native"

def asBytes32 : Value C → R Bytes32
  | .bytes32 b => pure b
  | v => throw s!"cannot convert {repr v.type} to Bytes32"

/-- ir_vm.rs:240-251 `resolve_operand_bool`. -/
def resolveBool (st : State C) (op : Operand) : R Bool := do
  let x ← asNative (← resolve st op)
  if x = 0 then pure false
  else if x = 1 then pure true
  else throw s!"Expected boolean, found: {x.val}"

/-- ir_vm.rs:253-278 `resolve_operand_bits` with a bound: the value
must be below `2^n`, and `n ≥ FR_BITS` is itself an error. -/
def checkBits (x : Fr) (n : Nat) : R Unit := do
  if n ≥ frBits then throw "Excessive bit bound"
  if x.val ≥ 2 ^ n then throw s!"Bit bound failed: {x.val} is not {n}-bit"

/-- `encode_offcircuit` for the concrete types; foreign via the model. -/
def encode (v : Value C) : List Fr :=
  match v with
  | .native x => [x]
  | .bytes32 b =>
    let bs := b.toList
    [Fr.ofNat (leToNat (bs.take 31)), Fr.ofNat (bs.getD 31 0).toNat]
  | v => M.encodeF v

/-- `decode_offcircuit` for the concrete types; foreign via the model. -/
def decode (ty : IrType) (raw : List Fr) : R (Value C) :=
  match ty, raw with
  | .native, [x] => pure (.native x)
  | .bytes32, [lo, hi] => do
    if lo.val ≥ 2 ^ 248 then throw "Bytes32 low limb exceeds 31 bytes"
    if hi.val ≥ 256 then throw "Bytes32 high limb exceeds a byte"
    pure (.bytes32 ⟨(natToLE lo.val 31 ++ [UInt8.ofNat hi.val]).toArray, by simp [natToLE]⟩)
  | ty, raw => M.decodeF ty raw

/-- `IrValue::default` (ir_types.rs:168-186). -/
def default (ty : IrType) : Value C :=
  match ty with
  | .native => .native 0
  | .bytes32 => .bytes32 Bytes32.zero
  | ty => M.defaultF ty

/-- Take `n` elements at cursor `i` of a stream, or fail. -/
def slice (stream : List Fr) (i n : Nat) : R (List Fr) :=
  let s := (stream.drop i).take n
  if s.length = n then pure s else throw "transcript exhausted"

/-- ir_vm.rs:125-180 `fab_decode_to_bytes_atom`, the in-circuit decoder's
operand → byte rule (§3.2): a `field` atom is one operand's 32 LE bytes;
a `bytes n` atom is `n mod 31` stray bytes taken from the FIRST operand
then the full 31-byte limbs in REVERSED operand order, with the stray
bytes appended LAST; `compress` cannot be decoded. Rung 4's differential
checks this against the off-circuit `parse_field_repr` path. -/
def fabAtom (seg : Segment) (inputs : List Fr) : R (List UInt8 × List Fr) :=
  match seg with
  | .field => match inputs with
    | x :: rest => pure (natToLE x.val 32, rest)
    | [] => throw "cannot decode field element from no data"
  | .compress => throw "Cannot decode compressed value from field elements"
  | .bytes length =>
    let stray := length % frBytesStored
    let chunks := length / frBytesStored
    let expected := chunks + (if stray ≠ 0 then 1 else 0)
    if inputs.length < expected then throw "cannot decode bytes from to little data"
    else
      let (strayBytes, rest) :=
        if stray > 0 then (natToLE (inputs.headD 0).val stray, inputs.drop 1) else ([], inputs)
      let limbs := (rest.take chunks).reverse.flatMap fun f => natToLE f.val frBytesStored
      pure (limbs ++ strayBytes, rest.drop chunks)

def fabBytes (segs : List Segment) (inputs : List Fr) : R (List UInt8) := do
  let mut acc : List UInt8 := []
  let mut rest := inputs
  for seg in segs do
    let (bs, r) ← fabAtom seg rest
    acc := acc ++ bs
    rest := r
  pure acc

/-- One instruction (ir_vm.rs:284-646), in the order of that match. -/
def step (prog : Program) (π : Preimage) (st : State C) (i : Instr) : R (State C) := do
  match i with
  | .encode outputs input =>
    let v ← resolve st input
    let enc := encode M v
    if enc.length ≠ outputs.length then
      throw s!"Unexpected output length of encode instruction: {repr v.type}"
    pure (outputs.zip enc |>.foldl (fun st (o, x) => st.insert o (.native x)) st)
  | .add out a b =>
    let a ← resolve st a
    let b ← resolve st b
    match a, b with
    | .native x, .native y => pure (st.insert out (.native (x + y)))
    | a, b => pure (st.insert out (← M.addF a b))
  | .mul out a b =>
    let a ← resolve st a
    let b ← resolve st b
    match a, b with
    | .native x, .native y => pure (st.insert out (.native (x * y)))
    | a, b => pure (st.insert out (← M.mulF a b))
  | .neg out a =>
    match ← resolve st a with
    | .native x => pure (st.insert out (.native (Fr.neg x)))
    | a => pure (st.insert out (← M.negF a))
  | .inv out a =>
    match ← resolve st a with
    | .native x =>
      if x = 0 then throw "Cannot invert zero" else pure (st.insert out (.native (Fr.inv x)))
    | a => pure (st.insert out (← M.invF a))
  | .not out a =>
    let b ← resolveBool st a
    pure (st.insert out (.native (if b then 0 else 1)))
  | .constrainEq a b =>
    let a ← resolve st a
    let b ← resolve st b
    let eq : Bool ← match a, b with
      | .native x, .native y => pure (decide (x = y))
      | .bytes32 x, .bytes32 y => pure (decide (x.toList = y.toList))
      | a, b => M.eqF a b
    if eq then pure st else throw "Failed equality constraint"
  | .condSelect out bit a b =>
    let bit ← resolveBool st bit
    let a ← resolve st a
    let b ← resolve st b
    if a.type ≠ b.type then throw "cond_select: operand types differ"
    pure (st.insert out (if bit then a else b))
  | .assert cond =>
    if ← resolveBool st cond then pure st else throw "Failed direct assertion"
  | .testEq out a b =>
    let a ← resolve st a
    let b ← resolve st b
    let eq : Bool ← match a, b with
      | .native x, .native y => pure (decide (x = y))
      | .bytes32 x, .bytes32 y => pure (decide (x.toList = y.toList))
      | a, b => M.eqF a b
    pure (st.insert out (.native (if eq then 1 else 0)))
  | .publicInput ty out guard =>
    let take ← match guard with
      | some g => do pure (← resolveBool st g)
      | none => pure true
    if take then
      let w := ty.encodedLen
      let raw ← slice π.publicTranscriptOutputs st.pubOutIdx w
      let v ← decode M ty raw
      pure ({ st with pubOutIdx := st.pubOutIdx + w }.insert out v)
    else
      pure (st.insert out (default M ty))
  | .privateInput ty out guard =>
    let take ← match guard with
      | some g => do pure (← resolveBool st g)
      | none => pure true
    if take then
      let w := ty.encodedLen
      let raw ← slice π.privateTranscript st.privIdx w
      let v ← decode M ty raw
      pure ({ st with privIdx := st.privIdx + w }.insert out v)
    else
      pure (st.insert out (default M ty))
  | .copy out val => pure (st.insert out (← resolve st val))
  | .constrainToBoolean val => do
    let _ ← resolveBool st val
    pure st
  | .constrainBits val bits => do
    checkBits (← asNative (← resolve st val)) bits
    pure st
  | .divModPowerOfTwo outputs val bits =>
    match outputs with
    | [q, r] =>
      if bits > frBytesStored * 8 then throw "Excessive bit count"
      let x ← asNative (← resolve st val)
      pure ((st.insert q (.native (Fr.ofNat (x.val / 2 ^ bits)))).insert r
        (.native (Fr.ofNat (x.val % 2 ^ bits))))
    | _ => throw "DivModPowerOfTwo requires exactly 2 outputs"
  | .reconstituteField out divisor modulus bits =>
    if bits > frBytesStored * 8 then throw "Excessive bit count"
    let m ← asNative (← resolve st modulus)
    let d ← asNative (← resolve st divisor)
    checkBits m bits
    checkBits d (frBits - bits)
    let composite := d.val * 2 ^ bits + m.val
    if composite ≥ p then throw "Reconstituted element overflows field"
    pure (st.insert out (.native (Fr.ofNat composite)))
  | .lessThan out a b bits =>
    let x ← asNative (← resolve st a)
    let y ← asNative (← resolve st b)
    checkBits x bits
    checkBits y bits
    pure (st.insert out (.native (if x.val < y.val then 1 else 0)))
  | .jubjubScalarFromNative out native =>
    let x ← asNative (← resolve st native)
    pure (st.insert out (.jubjubScalar (M.jubjubScalarFromNative x)))
  | .transientHash out inputs =>
    let xs ← inputs.mapM fun o => do asNative (← resolve st o)
    pure (st.insert out (.native (M.transientHash xs)))
  | .persistentHash out alignment inputs =>
    let xs ← inputs.mapM fun o => do asNative (← resolve st o)
    let bytes ← fabBytes alignment xs
    pure (st.insert out (.bytes32 (M.sha256 bytes)))
  | .keccak256 out alignment inputs =>
    let xs ← inputs.mapM fun o => do asNative (← resolve st o)
    let bytes ← fabBytes alignment xs
    pure (st.insert out (.bytes32 (M.keccak256 bytes)))
  | .impact guard inputs =>
    let n := inputs.length
    if ← resolveBool st guard then
      let xs ← inputs.mapM fun o => do asNative (← resolve st o)
      let base := st.pubInIdx
      for (k, x) in (List.range n).zip xs do
        let expected := π.publicTranscriptInputs[base + k]?
        if expected ≠ some x then
          throw s!"Public transcript input mismatch for input {base + k}"
      pure { st with pis := st.pis ++ xs, piSkips := st.piSkips ++ [none], pubInIdx := base + n }
    else
      pure { st with pis := st.pis ++ List.replicate n 0, piSkips := st.piSkips ++ [some n] }
  | .hashToCurve out inputs =>
    let xs ← inputs.mapM fun o => do asNative (← resolve st o)
    pure (st.insert out (.jubjubPoint (M.hashToCurve xs)))
  | .ecMul out a scalar =>
    let pt ← resolve st a
    let s ← resolve st scalar
    pure (st.insert out (← M.ecMul pt s))
  | .ecMulGenerator out scalar =>
    let s ← resolve st scalar
    pure (st.insert out (← M.ecMulGenerator s))
  | .intoCoordinates (ox, oy) point =>
    let (x, y) ← M.intoCoordinates (← resolve st point)
    pure ((st.insert ox x).insert oy y)
  | .fromCoordinates out (ix, iy) =>
    let x ← resolve st ix
    let y ← resolve st iy
    pure (st.insert out (← M.fromCoordinates x y))
  | .intoBytes32 out input =>
    match ← resolve st input with
    | .native x => pure (st.insert out (.bytes32 (Bytes32.ofLE x.val)))
    | v => pure (st.insert out (.bytes32 (← M.intoBytes32F v)))
  | .fromBytes32 ty out bytes =>
    let b ← asBytes32 (← resolve st bytes)
    match ty with
    | .native => pure (st.insert out (.native (Fr.ofNat (leToNat b.toList))))
    | ty => pure (st.insert out (← M.fromBytes32F ty b))
  | .reverseBytes out bytes =>
    let b ← asBytes32 (← resolve st bytes)
    pure (st.insert out (.bytes32 b.reverse))
  | .bytes32IntoLowHigh (lo, hi) bytes =>
    let b ← asBytes32 (← resolve st bytes)
    let bs := b.toList
    let high := (bs.getD 31 0).toNat
    let low := leToNat (bs.take 31)
    pure ((st.insert lo (.native (Fr.ofNat low))).insert hi (.native (Fr.ofNat high)))
  | .bytes32FromLowHigh out (ilo, ihi) =>
    let lo ← asNative (← resolve st ilo)
    let hi ← asNative (← resolve st ihi)
    if lo.val ≥ 2 ^ 248 ∨ hi.val ≥ 256 then
      throw "Bytes32FromLowHigh: low operand must fit in 31 bytes and high operand in a single byte"
    pure (st.insert out (.bytes32 ⟨(natToLE lo.val 31 ++ [UInt8.ofNat hi.val]).toArray, by simp [natToLE]⟩))
  | .output vals =>
    if vals.length ≠ prog.outputs.length then
      throw s!"Output: signature declares {prog.outputs.length} return values but instruction has {vals.length}"
    let vs ← (vals.zip prog.outputs).mapM fun (o, ty) => do
      let v ← resolve st o
      if v.type ≠ ty then throw "Output: operand type differs from signature"
      pure v
    pure { st with outputs := st.outputs ++ vs }

/-- ir_vm.rs:189-211: seed memory from `preimage.inputs` per the typed
input list; leftovers are a reject. -/
def prologue (prog : Program) (π : Preimage) : R (List (Ident × Value C)) := do
  let mut mem : List (Ident × Value C) := []
  let mut idx := 0
  for (name, ty) in prog.inputs do
    let w := ty.encodedLen
    if idx + w > π.inputs.length then
      throw s!"Not enough raw inputs: ran out at index {idx} while decoding {name}"
    let v ← decode M ty ((π.inputs.drop idx).take w)
    mem := (name, v) :: mem
    idx := idx + w
  if idx ≠ π.inputs.length then
    throw s!"Expected {idx} raw inputs, received {π.inputs.length}"
  pure mem

/-- The whole of `preprocess`: prologue, the walk, the epilogue checks. -/
def run (prog : Program) (π : Preimage) : R (Result C) := do
  let mem ← prologue M prog π
  let pis0 ← match π.communicationsCommitment, prog.doCommunicationsCommitment with
    | _, false => pure [π.bindingInput]
    | some (c, _), true => pure [π.bindingInput, c]
    | none, true => throw "Expected communications commitment"
  let st0 : State C :=
    { memory := mem, pis := pis0, piSkips := [], privIdx := 0, pubOutIdx := 0, pubInIdx := 0, outputs := [] }
  let st ← prog.instructions.foldlM (step M prog π) st0
  if π.publicTranscriptInputs.length ≠ st.pubInIdx
      ∨ π.publicTranscriptOutputs.length ≠ st.pubOutIdx
      ∨ π.privateTranscript.length ≠ st.privIdx then
    throw "Transcripts not fully consumed"
  if prog.doCommunicationsCommitment then
    match π.communicationsCommitment with
    | none => throw "Expected communications randomness"
    | some (c, rand) =>
      let preimage := π.inputs ++ st.outputs.flatMap (encode M)
      if c ≠ M.transientCommit preimage rand then throw "Communications commitment mismatch"
  pure { memory := st.memory, pis := st.pis, piSkips := st.piSkips, outputs := st.outputs }

end Eval

end MinocrabZkir
