/-
THE CONCRETE MODEL (M27 rung 4; notes/zkir-rung4.org). Rung 3 left the
intrinsics uninterpreted — a `Model C` record over opaque `Carriers`
(Semantics.lean, notes/zkir-semantics.org §5). This file instantiates it
as far as the corpus goes, and says exactly how far that is.

CONCRETE here:
  transient_hash / transient_commit  Poseidon over BLS12-381's scalar
                                     field (Intrinsics/Poseidon.lean)
  persistent_hash                    SHA-256 (Intrinsics/Sha256.lean)
  keccak256                          Keccak-256 (Intrinsics/Keccak.lean)
  every secp256k1 operation          Intrinsics/Secp256k1.lean
  everything Native / Bytes32        already concrete in Semantics.lean

UNINTERPRETED still, and why: Jubjub (`hash_to_curve`,
`jubjub_scalar_from_native`, the point/scalar arithmetic and encodings),
secp256r1 and curve25519. NO run record in differential/ exercises any of
them — the vault, the Signet singleton and the AA-manager between them
use no Jubjub, r1 or 25519 value, and the corpus circuit that does touch
Jubjub (`opaque::op_jubjub`) has no dumped preimage because no
differential suite proves it against a compactc twin. Porting them would
be unvalidated code, so §5's rule applies: leave them out and say so.

That silence is ENFORCED, not trusted: `unsupported` below refuses any
program that could produce a value of an uninterpreted type, and
`zkir-run` fails loudly on it rather than computing with a placeholder.
The placeholder carriers are `Unit` precisely so that a slip cannot look
like a real answer for long.
-/
import MinocrabZkir.Semantics
import MinocrabZkir.Print
import MinocrabZkir.Intrinsics.Poseidon
import MinocrabZkir.Intrinsics.Sha256
import MinocrabZkir.Intrinsics.Keccak
import MinocrabZkir.Intrinsics.Secp256k1

namespace MinocrabZkir.Concrete

open MinocrabZkir

/-- The rung-4 carriers: secp256k1 for real, `Unit` for the eight foreign
types no record exercises (see the header). -/
abbrev C : Carriers where
  jubjubPoint := Unit
  jubjubScalar := Unit
  k256Point := Secp256k1.Pt
  k256Base := Secp256k1.Fp
  k256Scalar := Secp256k1.Fq
  p256Point := Unit
  p256Base := Unit
  p256Scalar := Unit
  c25519Point := Unit
  c25519Base := Unit
  c25519Scalar := Unit

abbrev V := Value C

private def ty (v : V) : String := v.type.name

private def unsupportedOp (op : String) (v : V) : R α :=
  throw s!"{op}: {ty v} is uninterpreted at rung 4 (notes/zkir-rung4.org)"

/-! ## The typed arithmetic (`*_offcircuit`, foreign arms only)

`Semantics.addV` and friends handle Native (and `eqV` Bytes32) before
consulting the model, so these arms see only the foreign cases. Each
mirrors its `ir_instructions/*.rs` match, ERRORING on exactly the pairs
upstream errors on. -/

def addF : V → V → R V
  | .k256Point p, .k256Point q => pure (.k256Point (Secp256k1.add p q))
  | .k256Base a, .k256Base b => pure (.k256Base (a + b))
  | .k256Scalar a, .k256Scalar b => pure (.k256Scalar (a + b))
  | a, b => throw s!"Unsupported addition: {ty a} + {ty b}"

def mulF : V → V → R V
  | .k256Base a, .k256Base b => pure (.k256Base (a * b))
  | .k256Scalar a, .k256Scalar b => pure (.k256Scalar (a * b))
  | a, b => throw s!"Unsupported multiplication: {ty a} x {ty b}"

def negF : V → R V
  | .k256Point p => pure (.k256Point (Secp256k1.neg p))
  | .k256Base a => pure (.k256Base (Secp256k1.Fp.neg a))
  | .k256Scalar a => pure (.k256Scalar (Secp256k1.Fq.neg a))
  | v => throw s!"Unsupported negation of {ty v}"

def invF : V → R V
  | .k256Base a =>
    if a = 0 then throw s!"cannot invert zero of type {IrType.name .secp256k1Base}"
    else pure (.k256Base (Secp256k1.Fp.inv a))
  | .k256Scalar a =>
    if a = 0 then throw s!"cannot invert zero of type {IrType.name .secp256k1Scalar}"
    else pure (.k256Scalar (Secp256k1.Fq.inv a))
  | v => throw s!"Unsupported inversion of {ty v}"

def eqF : V → V → R Bool
  | .k256Point p, .k256Point q => pure (decide (p = q))
  | .k256Base a, .k256Base b => pure (decide (a = b))
  | .k256Scalar a, .k256Scalar b => pure (decide (a = b))
  | a, b => throw s!"Unsupported test_eq: {ty a} == {ty b}"

/-! ## The curve operations -/

def ecMul : V → V → R V
  | .k256Point p, .k256Scalar s => pure (.k256Point (Secp256k1.mul p s))
  | p, s => throw s!"Unsupported EC multiplication: {ty p} x {ty s}"

/-- `ir_vm.rs:559-568`: the generator is chosen by the SCALAR's type. -/
def ecMulGenerator : V → R V
  | .k256Scalar s => pure (.k256Point (Secp256k1.mul Secp256k1.generator s))
  | s => throw s!"Unsupported EcMulGenerator for scalar of type {ty s}"

def intoCoordinates : V → R (V × V)
  | .k256Point p =>
    match Secp256k1.coordinates p with
    | some (x, y) => pure (.k256Base x, .k256Base y)
    | none => throw "Cannot extract coordinates of the Secp256k1 identity"
  | v => unsupportedOp "into_coordinates" v

def fromCoordinates : V → V → R V
  | .k256Base x, .k256Base y =>
    match Secp256k1.fromXY x y with
    | some p => pure (.k256Point p)
    | none => throw "Cannot build a Secp256k1Point point from those coordinates"
  | x, y => throw s!"Unsupported from_coordinates: ({ty x}, {ty y})"

/-! ## Bytes and encodings -/

def intoBytes32F : V → R Bytes32
  | .k256Base a => pure (Secp256k1.bytesOfFp a)
  | .k256Scalar a => pure (Secp256k1.bytesOfFq a)
  | v => throw s!"Unsupported into_bytes32 for {ty v}"

def fromBytes32F (t : IrType) (b : Bytes32) : R V :=
  match t with
  | .secp256k1Base => pure (.k256Base (Secp256k1.fpOfBytes b))
  | .secp256k1Scalar => pure (.k256Scalar (Secp256k1.fqOfBytes b))
  | t => throw s!"Unsupported from_bytes32 for type {t.name}"

/-- `encode_offcircuit`'s foreign arms. Total by signature, so an
uninterpreted type yields the empty limb list — which the `encode`
instruction rejects on length and `unsupported` refuses outright. -/
def encodeF : V → List Fr
  | .k256Point p => Secp256k1.encodePoint p
  | .k256Base a => Secp256k1.encodeFp a
  | .k256Scalar a => Secp256k1.encodeFq a
  | _ => []

def decodeF (t : IrType) (raw : List Fr) : R V :=
  let fail : R V := throw s!"Failed to decode as {t.name}"
  match t with
  | .secp256k1Point => match Secp256k1.decodePoint raw with
    | some p => pure (.k256Point p)
    | none => fail
  | .secp256k1Base => match Secp256k1.decodeFp raw with
    | some a => pure (.k256Base a)
    | none => fail
  | .secp256k1Scalar => match Secp256k1.decodeFq raw with
    | some a => pure (.k256Scalar a)
    | none => fail
  | _ => throw s!"{t.name} is uninterpreted at rung 4 (notes/zkir-rung4.org)"

/-- `IrValue::default` (ir_types.rs:168-186)'s foreign arms. Only the
secp256k1 ones are meaningful; the rest are placeholders no supported
program can reach. -/
def defaultF : IrType → V
  | .secp256k1Point => .k256Point .infinity
  | .secp256k1Base => .k256Base 0
  | .secp256k1Scalar => .k256Scalar 0
  | .jubjubPoint => .jubjubPoint ()
  | .jubjubScalar => .jubjubScalar ()
  | .secp256r1Point => .p256Point ()
  | .secp256r1Base => .p256Base ()
  | .secp256r1Scalar => .p256Scalar ()
  | .curve25519Point => .c25519Point ()
  | .curve25519Base => .c25519Base ()
  | .curve25519Scalar => .c25519Scalar ()
  | .native => .native 0
  | .bytes32 => .bytes32 Bytes32.zero

/-- The rung-4 model. -/
def model : Model C where
  transientHash := Poseidon.hash
  transientCommit := Poseidon.commit
  sha256 := Sha256.hash
  keccak256 := Keccak.hash
  hashToCurve := fun _ => ()
  jubjubScalarFromNative := fun _ => ()
  addF := addF
  mulF := mulF
  negF := negF
  invF := invF
  eqF := eqF
  ecMul := ecMul
  ecMulGenerator := ecMulGenerator
  intoCoordinates := intoCoordinates
  fromCoordinates := fromCoordinates
  intoBytes32F := intoBytes32F
  fromBytes32F := fromBytes32F
  encodeF := encodeF
  decodeF := decodeF
  defaultF := defaultF

/-! ## The honesty guard

Two of the model's fields (`hashToCurve`, `jubjubScalarFromNative`) have
result types that leave no room to fail — they must return a
`C.jubjubPoint` / `C.jubjubScalar`, and at rung 4 those are `Unit`. A
program using them would therefore run to a WRONG answer rather than an
error. `unsupported` closes that hole before the walk starts: a value of
an uninterpreted type can only enter a program through a declared input
or output type, a `public_input` / `private_input` / `from_bytes32` type
annotation, or one of the two Jubjub-producing instructions, and all of
those are checked here. -/

/-- Is this type one the rung-4 model actually interprets? -/
def interpreted : IrType → Bool
  | .native | .bytes32 => true
  | .secp256k1Point | .secp256k1Base | .secp256k1Scalar => true
  | _ => false

/-- The types an instruction can introduce, and the instructions that
introduce an uninterpreted value with no type annotation at all. -/
private def instrObjection : Instr → Option String
  | .publicInput t _ _ =>
    if interpreted t then none else some s!"public_input of {t.name}"
  | .privateInput t _ _ =>
    if interpreted t then none else some s!"private_input of {t.name}"
  | .fromBytes32 t _ _ =>
    if interpreted t then none else some s!"from_bytes32 to {t.name}"
  | .hashToCurve _ _ => some "hash_to_curve (Jubjub)"
  | .jubjubScalarFromNative _ _ => some "jubjub_scalar_from_native"
  | _ => none

/-- `none` when every value the program can hold is one this model
interprets; otherwise the first objection, for the error message. -/
def unsupported (p : Program) : Option String :=
  match p.inputs.find? (fun i => !interpreted i.2) with
  | some (n, t) => some s!"input {n} : {t.name}"
  | none =>
    match p.outputs.find? (fun t => !interpreted t) with
    | some t => some s!"output : {t.name}"
    | none => p.instructions.findSome? instrObjection

end MinocrabZkir.Concrete
