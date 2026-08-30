/-
The printer — compactc's, transcribed (M27 rung 1; notes/zkir-semantics.org
§1.3). Two layers, both cited line by line:

1. `printCompact` is `help-print-json` with `compact? = #t`
   (compact/compiler/json.ss:399-472): a depth-driven layout whose
   every space and newline this file reproduces.
2. `Program.toJ` is `print-zkir-v3.ss` (`Instruction`, `Input`,
   `Output`, `alignment-atom->alist`, `zkir-field-rep->string`): the
   per-op key order and the immediate spelling.

The Rust reader is key-order-insensitive (serde) and the Rust writer
prints serde's own order in serde's own layout — so nothing on the
Rust side checks this; the corpus does (Roundtrip.lean).
-/
import MinocrabZkir.Syntax

namespace MinocrabZkir

/-- A JSON value with ORDERED object keys — the alist compactc builds. -/
inductive J where
  | str (s : String)
  | int (n : Int)
  | bool (b : Bool)
  | null
  | arr (xs : List J)
  | obj (kvs : List (String × J))
deriving Repr, Inhabited

namespace J

/-- json.ss:400-401 `indent`. -/
def indent (depth : Nat) : String :=
  "\n" ++ String.ofList (List.replicate (2 * depth) ' ')

private def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat ('0'.toNat + n) else Char.ofNat ('a'.toNat + n - 10)

private def hex4 (n : Nat) : String :=
  String.ofList [hexDigit (n / 4096 % 16), hexDigit (n / 256 % 16), hexDigit (n / 16 % 16), hexDigit (n % 16)]

/-- json.ss:402-420 `print-string`. The control-character arm prints
`u` + four hex digits WITHOUT a backslash — compactc's own (unexercised)
behaviour, transcribed rather than corrected. -/
def quote (s : String) : String :=
  let body := s.toList.foldl (init := "") fun acc c =>
    acc ++ match c with
      | '"' => "\\\""
      | '\\' => "\\\\"
      | '\x08' => "\\b"
      | '\x0c' => "\\f"
      | '\n' => "\\n"
      | '\r' => "\\r"
      | '\t' => "\\t"
      | c => if c.toNat ≥ 0x20 then String.singleton c else "u" ++ hex4 c.toNat
  "\"" ++ body ++ "\""

mutual
  /-- json.ss:421-464 `f`. -/
  partial def go (j : J) (depth : Nat) : String :=
    match j with
    | .str s => quote s
    | .int n => toString n
    | .bool b => if b then "true" else "false"
    | .null => "null"
    | .arr xs =>
      -- json.ss:424-440. Elements at inner depth d; inline (one space
      -- after each comma) once d > 2, else one per indented line. The
      -- closing bracket is indented only when the vector's own depth
      -- is ≤ 1 — hence the `[\n  ]` of an empty top-level vector.
      let d := depth + 1
      let close := if depth > 1 then "" else indent depth
      "[" ++ goArr xs d true ++ close ++ "]"
    | .obj kvs =>
      -- json.ss:441-459. Pairs inline (leading space) once the inner
      -- depth d > 1, i.e. every object but the top one; the closing
      -- brace is preceded by a space except at the top.
      let d := depth + 1
      let close := if depth > 0 then " " else indent depth
      "{" ++ goObj kvs d true ++ close ++ "}"

  partial def goArr (xs : List J) (d : Nat) (first : Bool) : String :=
    match xs with
    | [] => ""
    | x :: rest =>
      let sep := if first then "" else ","
      let lead := if d > 2 then (if first then "" else " ") else indent d
      sep ++ lead ++ go x d ++ goArr rest d false

  partial def goObj (kvs : List (String × J)) (d : Nat) (first : Bool) : String :=
    match kvs with
    | [] => ""
    | (k, v) :: rest =>
      let sep := if first then "" else ","
      let lead := if d > 1 then " " else indent d
      sep ++ lead ++ "\"" ++ k ++ "\": " ++ go v d ++ goObj rest d false
end

/-- json.ss:465-466: the top value at depth 0, then a newline. -/
def printCompact (j : J) : String := go j 0 ++ "\n"

end J

/-- ir_types.rs:36-88, the serde names. -/
def IrType.name : IrType → String
  | .native => "Scalar<BLS12-381>"
  | .bytes32 => "Bytes<32>"
  | .jubjubPoint => "Point<Jubjub>"
  | .jubjubScalar => "Scalar<Jubjub>"
  | .secp256k1Point => "Point<Secp256k1>"
  | .secp256k1Base => "Base<Secp256k1>"
  | .secp256k1Scalar => "Scalar<Secp256k1>"
  | .secp256r1Point => "Point<Secp256r1>"
  | .secp256r1Base => "Base<Secp256r1>"
  | .secp256r1Scalar => "Scalar<Secp256r1>"
  | .curve25519Point => "Point<Curve25519>"
  | .curve25519Base => "Base<Curve25519>"
  | .curve25519Scalar => "Scalar<Curve25519>"

private def hexByte (b : Nat) : String :=
  let d (n : Nat) : Char :=
    if n < 10 then Char.ofNat ('0'.toNat + n) else Char.ofNat ('a'.toNat + n - 10)
  String.ofList [d (b / 16 % 16), d (b % 16)]

/-- print-zkir-v3.ss:52-61: little-endian bytes, two lowercase hex
digits each, at least one byte. -/
partial def hexLE (v : Nat) : String :=
  if v < 256 then hexByte v else hexByte (v % 256) ++ hexLE (v / 256)

/-- print-zkir-v3.ss:46-61 `zkir-field-rep->string`. -/
def immString (n : Int) : String :=
  (if n < 0 then "-0x" else "0x") ++ hexLE n.natAbs

def Operand.toJ : Operand → J
  | .var name => .str name
  | .imm n => .str (immString n)

private def ops (xs : List Operand) : J := .arr (xs.map Operand.toJ)
private def ids (xs : List Ident) : J := .arr (xs.map J.str)

/-- print-zkir-v3.ss:20-27 `alignment-atom->alist` — note `length`
before `tag` inside a bytes atom. -/
def Segment.toJ : Segment → J
  | .bytes n => .obj [("tag", .str "atom"), ("value", .obj [("length", .int n), ("tag", .str "bytes")])]
  | .field => .obj [("tag", .str "atom"), ("value", .obj [("tag", .str "field")])]
  | .compress => .obj [("tag", .str "atom"), ("value", .obj [("tag", .str "compress")])]

private def guardJ : Option Operand → J
  | none => .null
  | some g => g.toJ

/-- print-zkir-v3.ss:80-166 `Instruction`, one arm per op, keys in
compactc's order. -/
def Instr.toJ : Instr → J
  | .encode outputs input =>
    .obj [("op", .str "encode"), ("outputs", ids outputs), ("input", input.toJ)]
  | .assert cond => .obj [("op", .str "assert"), ("cond", cond.toJ)]
  | .condSelect out bit a b =>
    .obj [("op", .str "cond_select"), ("output", .str out), ("bit", bit.toJ), ("a", a.toJ), ("b", b.toJ)]
  | .constrainBits val bits =>
    .obj [("op", .str "constrain_bits"), ("val", val.toJ), ("bits", .int bits)]
  | .constrainEq a b => .obj [("op", .str "constrain_eq"), ("a", a.toJ), ("b", b.toJ)]
  | .constrainToBoolean val => .obj [("op", .str "constrain_to_boolean"), ("val", val.toJ)]
  | .copy out val => .obj [("op", .str "copy"), ("output", .str out), ("val", val.toJ)]
  | .impact guard inputs => .obj [("op", .str "impact"), ("guard", guard.toJ), ("inputs", ops inputs)]
  | .ecMul out a scalar =>
    .obj [("op", .str "ec_mul"), ("output", .str out), ("a", a.toJ), ("scalar", scalar.toJ)]
  | .ecMulGenerator out scalar =>
    .obj [("op", .str "ec_mul_generator"), ("output", .str out), ("scalar", scalar.toJ)]
  | .hashToCurve out inputs =>
    .obj [("op", .str "hash_to_curve"), ("output", .str out), ("inputs", ops inputs)]
  | .intoCoordinates (o0, o1) point =>
    .obj [("op", .str "into_coordinates"), ("outputs", .arr [.str o0, .str o1]), ("point", point.toJ)]
  | .fromCoordinates out (i0, i1) =>
    .obj [("op", .str "from_coordinates"), ("output", .str out), ("inputs", .arr [i0.toJ, i1.toJ])]
  | .intoBytes32 out input =>
    .obj [("op", .str "into_bytes32"), ("output", .str out), ("input", input.toJ)]
  | .fromBytes32 ty out bytes =>
    .obj [("op", .str "from_bytes32"), ("type", .str ty.name), ("output", .str out), ("bytes", bytes.toJ)]
  | .reverseBytes out bytes =>
    .obj [("op", .str "reverse_bytes"), ("output", .str out), ("bytes", bytes.toJ)]
  | .bytes32IntoLowHigh (o0, o1) bytes =>
    .obj [("op", .str "bytes32_into_low_high"), ("outputs", .arr [.str o0, .str o1]), ("bytes", bytes.toJ)]
  | .bytes32FromLowHigh out (i0, i1) =>
    .obj [("op", .str "bytes32_from_low_high"), ("output", .str out), ("inputs", .arr [i0.toJ, i1.toJ])]
  | .divModPowerOfTwo outputs val bits =>
    .obj [("op", .str "div_mod_power_of_two"), ("outputs", ids outputs), ("val", val.toJ), ("bits", .int bits)]
  | .reconstituteField out divisor modulus bits =>
    .obj [("op", .str "reconstitute_field"), ("output", .str out), ("divisor", divisor.toJ),
          ("modulus", modulus.toJ), ("bits", .int bits)]
  | .transientHash out inputs =>
    .obj [("op", .str "transient_hash"), ("output", .str out), ("inputs", ops inputs)]
  | .persistentHash out alignment inputs =>
    .obj [("op", .str "persistent_hash"), ("output", .str out),
          ("alignment", .arr (alignment.map Segment.toJ)), ("inputs", ops inputs)]
  | .keccak256 out alignment inputs =>
    .obj [("op", .str "keccak256"), ("output", .str out),
          ("alignment", .arr (alignment.map Segment.toJ)), ("inputs", ops inputs)]
  | .testEq out a b => .obj [("op", .str "test_eq"), ("output", .str out), ("a", a.toJ), ("b", b.toJ)]
  | .add out a b => .obj [("op", .str "add"), ("output", .str out), ("a", a.toJ), ("b", b.toJ)]
  | .mul out a b => .obj [("op", .str "mul"), ("output", .str out), ("a", a.toJ), ("b", b.toJ)]
  | .neg out a => .obj [("op", .str "neg"), ("output", .str out), ("a", a.toJ)]
  | .inv out a => .obj [("op", .str "inv"), ("output", .str out), ("a", a.toJ)]
  | .not out a => .obj [("op", .str "not"), ("output", .str out), ("a", a.toJ)]
  | .lessThan out a b bits =>
    .obj [("op", .str "less_than"), ("output", .str out), ("a", a.toJ), ("b", b.toJ), ("bits", .int bits)]
  | .jubjubScalarFromNative out native =>
    .obj [("op", .str "jubjub_scalar_from_native"), ("output", .str out), ("native", native.toJ)]
  | .publicInput ty out guard =>
    .obj [("op", .str "public_input"), ("type", .str ty.name), ("output", .str out), ("guard", guardJ guard)]
  | .privateInput ty out guard =>
    .obj [("op", .str "private_input"), ("type", .str ty.name), ("output", .str out), ("guard", guardJ guard)]
  | .output vals => .obj [("op", .str "output"), ("vals", ops vals)]

/-- print-zkir-v3.ss:70-80: the top-level alist. -/
def Program.toJ (p : Program) : J :=
  .obj [ ("version", .obj [("major", .int 3), ("minor", .int p.minor)])
       , ("do_communications_commitment", .bool p.doCommunicationsCommitment)
       , ("inputs", .arr (p.inputs.map fun (n, t) => .obj [("name", .str n), ("type", .str t.name)]))
       , ("outputs", .arr (p.outputs.map fun t => .str t.name))
       , ("instructions", .arr (p.instructions.map Instr.toJ)) ]

/-- The whole file, byte for byte. -/
def Program.print (p : Program) : String := J.printCompact p.toJ

end MinocrabZkir
