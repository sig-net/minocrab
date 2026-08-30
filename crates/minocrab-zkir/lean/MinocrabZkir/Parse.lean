/-
The reader (M27 rung 1; notes/zkir-semantics.org §1.2, §8). Generic JSON
parsing is core Lean's (`Lean.Json.parse`) — reuse before writing — and
this file is only the decode `Json → Program`, mirroring serde's
key-insensitive read of `IrSource` (ir.rs:59-72, 377-941) plus the
operand lexing rule (ir.rs:225-267). Leniency here is harmless: the
gate is `print (decode (parse s)) = s`, so anything the decoder lets
through that the printer would spell differently is caught by the
corpus, not hidden.
-/
import Lean.Data.Json
import MinocrabZkir.Syntax

namespace MinocrabZkir

open Lean (Json)

abbrev P := Except String

private def key (j : Json) (k : String) : P Json := j.getObjVal? k
private def str (j : Json) (k : String) : P String := do (← key j k).getStr?
private def nat (j : Json) (k : String) : P Nat := do (← key j k).getNat?
private def arr (j : Json) (k : String) : P (List Json) := do pure (← (← key j k).getArr?).toList

/-- ir_types.rs:36-88, inverse of `IrType.name`. -/
def IrType.ofName : String → P IrType
  | "Scalar<BLS12-381>" => pure .native
  | "Bytes<32>" => pure .bytes32
  | "Point<Jubjub>" => pure .jubjubPoint
  | "Scalar<Jubjub>" => pure .jubjubScalar
  | "Point<Secp256k1>" => pure .secp256k1Point
  | "Base<Secp256k1>" => pure .secp256k1Base
  | "Scalar<Secp256k1>" => pure .secp256k1Scalar
  | "Point<Secp256r1>" => pure .secp256r1Point
  | "Base<Secp256r1>" => pure .secp256r1Base
  | "Scalar<Secp256r1>" => pure .secp256r1Scalar
  | "Point<Curve25519>" => pure .curve25519Point
  | "Base<Curve25519>" => pure .curve25519Base
  | "Scalar<Curve25519>" => pure .curve25519Scalar
  | s => throw s!"unknown type {s}"

private def hexVal (c : Char) : P Nat :=
  if '0' ≤ c ∧ c ≤ '9' then pure (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then pure (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then pure (c.toNat - 'A'.toNat + 10)
  else throw s!"bad hex digit {c}"

/-- Hex digit pairs → little-endian bytes → the integer (ir.rs:249-255:
`const_hex::decode` then `Fr::from_le_bytes`; the FIELD reduction is
the semantics' business, not the reader's — see Syntax.lean). -/
private partial def bytesLE (cs : List Char) : P (List Nat) :=
  match cs with
  | [] => pure []
  | [_] => throw "odd number of hex digits"
  | h :: l :: rest => do
    let b := (← hexVal h) * 16 + (← hexVal l)
    pure (b :: (← bytesLE rest))

/-- ir.rs:230-266 `Operand::deserialize`: `%…` is a variable; `-?0x…`
an immediate with at least one hex digit. -/
def Operand.parse (s : String) : P Operand := do
  if s.startsWith "%" then return .var s
  let (neg, body) := match s.toList with
    | '-' :: rest => (true, rest)
    | rest => (false, rest)
  let digits ← match body with
    | '0' :: 'x' :: digits => pure digits
    | '0' :: 'X' :: digits => pure digits
    | _ => throw s!"invalid operand {s}: variables start with '%', immediates with '0x'"
  if digits.isEmpty then throw "hex immediate must have at least one digit after '0x'"
  let bytes ← bytesLE digits
  let v : Nat := bytes.foldr (fun b acc => acc * 256 + b) 0
  return .imm (if neg then -(v : Int) else v)

private def operand (j : Json) (k : String) : P Operand := do Operand.parse (← str j k)
private def operands (j : Json) (k : String) : P (List Operand) := do
  (← arr j k).mapM fun x => do Operand.parse (← x.getStr?)
private def ident (j : Json) (k : String) : P Ident := str j k
private def idents (j : Json) (k : String) : P (List Ident) := do (← arr j k).mapM Json.getStr?
private def pair2 {α} (k : String) : List α → P (α × α)
  | [a, b] => pure (a, b)
  | l => throw s!"{k}: expected exactly 2 elements, got {l.length}"

private def guard (j : Json) : P (Option Operand) := do
  match ← key j "guard" with
  | .null => pure none
  | g => pure (some (← Operand.parse (← g.getStr?)))

/-- print-zkir-v3.ss:20-27 read back; base_crypto's `Alignment` in its
atom-only form (Syntax.lean's stated subset). -/
def Segment.decode (j : Json) : P Segment := do
  unless (← str j "tag") = "atom" do throw "alignment segment is not an atom"
  let v ← key j "value"
  match ← str v "tag" with
  | "bytes" => pure (.bytes (← nat v "length"))
  | "field" => pure .field
  | "compress" => pure .compress
  | t => throw s!"unknown alignment atom {t}"

private def alignment (j : Json) : P (List Segment) := do (← arr j "alignment").mapM Segment.decode

/-- One instruction object, dispatched on `op` (ir.rs:380 `tag = "op"`,
snake_case). -/
def Instr.decode (j : Json) : P Instr := do
  match ← str j "op" with
  | "encode" => pure (.encode (← idents j "outputs") (← operand j "input"))
  | "assert" => pure (.assert (← operand j "cond"))
  | "cond_select" =>
    pure (.condSelect (← ident j "output") (← operand j "bit") (← operand j "a") (← operand j "b"))
  | "constrain_bits" => pure (.constrainBits (← operand j "val") (← nat j "bits"))
  | "constrain_eq" => pure (.constrainEq (← operand j "a") (← operand j "b"))
  | "constrain_to_boolean" => pure (.constrainToBoolean (← operand j "val"))
  | "copy" => pure (.copy (← ident j "output") (← operand j "val"))
  | "impact" => pure (.impact (← operand j "guard") (← operands j "inputs"))
  | "ec_mul" => pure (.ecMul (← ident j "output") (← operand j "a") (← operand j "scalar"))
  | "ec_mul_generator" => pure (.ecMulGenerator (← ident j "output") (← operand j "scalar"))
  | "hash_to_curve" => pure (.hashToCurve (← ident j "output") (← operands j "inputs"))
  | "into_coordinates" =>
    pure (.intoCoordinates (← pair2 "outputs" (← idents j "outputs")) (← operand j "point"))
  | "from_coordinates" =>
    pure (.fromCoordinates (← ident j "output") (← pair2 "inputs" (← operands j "inputs")))
  | "into_bytes32" => pure (.intoBytes32 (← ident j "output") (← operand j "input"))
  | "from_bytes32" =>
    pure (.fromBytes32 (← IrType.ofName (← str j "type")) (← ident j "output") (← operand j "bytes"))
  | "reverse_bytes" => pure (.reverseBytes (← ident j "output") (← operand j "bytes"))
  | "bytes32_into_low_high" =>
    pure (.bytes32IntoLowHigh (← pair2 "outputs" (← idents j "outputs")) (← operand j "bytes"))
  | "bytes32_from_low_high" =>
    pure (.bytes32FromLowHigh (← ident j "output") (← pair2 "inputs" (← operands j "inputs")))
  | "div_mod_power_of_two" =>
    pure (.divModPowerOfTwo (← idents j "outputs") (← operand j "val") (← nat j "bits"))
  | "reconstitute_field" =>
    pure (.reconstituteField (← ident j "output") (← operand j "divisor") (← operand j "modulus")
      (← nat j "bits"))
  | "transient_hash" => pure (.transientHash (← ident j "output") (← operands j "inputs"))
  | "persistent_hash" =>
    pure (.persistentHash (← ident j "output") (← alignment j) (← operands j "inputs"))
  | "keccak256" => pure (.keccak256 (← ident j "output") (← alignment j) (← operands j "inputs"))
  | "test_eq" => pure (.testEq (← ident j "output") (← operand j "a") (← operand j "b"))
  | "add" => pure (.add (← ident j "output") (← operand j "a") (← operand j "b"))
  | "mul" => pure (.mul (← ident j "output") (← operand j "a") (← operand j "b"))
  | "neg" => pure (.neg (← ident j "output") (← operand j "a"))
  | "inv" => pure (.inv (← ident j "output") (← operand j "a"))
  | "not" => pure (.not (← ident j "output") (← operand j "a"))
  | "less_than" =>
    pure (.lessThan (← ident j "output") (← operand j "a") (← operand j "b") (← nat j "bits"))
  | "jubjub_scalar_from_native" =>
    pure (.jubjubScalarFromNative (← ident j "output") (← operand j "native"))
  | "public_input" =>
    pure (.publicInput (← IrType.ofName (← str j "type")) (← ident j "output") (← guard j))
  | "private_input" =>
    pure (.privateInput (← IrType.ofName (← str j "type")) (← ident j "output") (← guard j))
  | "output" => pure (.output (← operands j "vals"))
  | op => throw s!"unknown op {op}"

/-- The on-disk major version, read before anything else so a v2 file
is reported as such rather than as a decode failure. -/
def majorOf (j : Json) : P Nat := do nat (← key j "version") "major"

/-- ir.rs:977-1011 `IrSource::load`, major 3 only. -/
def Program.decode (j : Json) : P Program := do
  let ver ← key j "version"
  let major ← nat ver "major"
  let minor ← nat ver "minor"
  unless major = 3 ∧ minor = 0 do throw s!"Unhandled version: {major}.{minor}"
  let inputs ← (← arr j "inputs").mapM fun x => do
    pure ((← str x "name"), (← IrType.ofName (← str x "type")))
  let outputs ← (← arr j "outputs").mapM fun x => do IrType.ofName (← x.getStr?)
  let instructions ← (← arr j "instructions").mapM Instr.decode
  pure { minor, doCommunicationsCommitment := ← (← key j "do_communications_commitment").getBool?
       , inputs, outputs, instructions }

/-- Text → Program. -/
def Program.parse (s : String) : P Program := do Program.decode (← Json.parse s)

end MinocrabZkir
