/-
ZKIR v3 syntax — the inductive behind a `.zkir` file as compactc writes
it (M27 rung 1; design of record: notes/zkir-semantics.org §1-2).

WHAT THIS MODELS: `midnight-zkir-v3`'s `IrSource` / `Instruction` /
`Operand` / `IrType` (zkir-v3/src/ir.rs, ir_types.rs at the pinned rev
04c9c5d9), read back from the JSON compactc's `print-zkir-v3.ss` emits.
It is SYNTAX: an immediate is the SIGNED literal the file carries
(`-0x01` and the 31-byte spelling of p−1 are two different trees that
the semantics sends to one field element); an identifier is the string
it is. The gate that keeps this honest is byte-exact round-trip over
the corpus (Roundtrip.lean), not review.

DELIBERATE SUBSET of the Rust type: alignment `Option` segments are not
representable — compactc never prints them and the in-circuit decoder
rejects them (ir_vm.rs:114-119); a file carrying one fails to parse
here, loudly.
-/

namespace MinocrabZkir

/-- The 13 value types (ir_types.rs:36-88), in declaration order. -/
inductive IrType where
  | native | bytes32 | jubjubPoint | jubjubScalar
  | secp256k1Point | secp256k1Base | secp256k1Scalar
  | secp256r1Point | secp256r1Base | secp256r1Scalar
  | curve25519Point | curve25519Base | curve25519Scalar
deriving DecidableEq, Repr, Inhabited

/-- A circuit-memory name. compactc mints `%<sym>.<n>`; the reader
requires the leading `%` (ir.rs:258-265) and nothing more. -/
abbrev Ident := String

/-- An operand: a name, or an immediate as the SIGNED integer the file
spells (`-0x…` allowed; ir.rs:225-267 negates after parsing). -/
inductive Operand where
  | var (name : Ident)
  | imm (value : Int)
deriving DecidableEq, Repr, Inhabited

/-- One FAB alignment segment as compactc prints it (print-zkir-v3.ss
`alignment-atom->alist`): always an `atom`, of one of three kinds. -/
inductive Segment where
  | bytes (length : Nat)
  | field
  | compress
deriving DecidableEq, Repr, Inhabited

/-- The 33 instructions (ir.rs:382-941). Field ORDER here is compactc's
JSON key order (print-zkir-v3.ss `Instruction`), which the printer
follows verbatim; field NAMES are the JSON keys. -/
inductive Instr where
  | encode (outputs : List Ident) (input : Operand)
  | assert (cond : Operand)
  | condSelect (output : Ident) (bit a b : Operand)
  | constrainBits (val : Operand) (bits : Nat)
  | constrainEq (a b : Operand)
  | constrainToBoolean (val : Operand)
  | copy (output : Ident) (val : Operand)
  | impact (guard : Operand) (inputs : List Operand)
  | ecMul (output : Ident) (a scalar : Operand)
  | ecMulGenerator (output : Ident) (scalar : Operand)
  | hashToCurve (output : Ident) (inputs : List Operand)
  | intoCoordinates (outputs : Ident × Ident) (point : Operand)
  | fromCoordinates (output : Ident) (inputs : Operand × Operand)
  | intoBytes32 (output : Ident) (input : Operand)
  | fromBytes32 (type : IrType) (output : Ident) (bytes : Operand)
  | reverseBytes (output : Ident) (bytes : Operand)
  | bytes32IntoLowHigh (outputs : Ident × Ident) (bytes : Operand)
  | bytes32FromLowHigh (output : Ident) (inputs : Operand × Operand)
  | divModPowerOfTwo (outputs : List Ident) (val : Operand) (bits : Nat)
  | reconstituteField (output : Ident) (divisor modulus : Operand) (bits : Nat)
  | transientHash (output : Ident) (inputs : List Operand)
  | persistentHash (output : Ident) (alignment : List Segment) (inputs : List Operand)
  | keccak256 (output : Ident) (alignment : List Segment) (inputs : List Operand)
  | testEq (output : Ident) (a b : Operand)
  | add (output : Ident) (a b : Operand)
  | mul (output : Ident) (a b : Operand)
  | neg (output : Ident) (a : Operand)
  | inv (output : Ident) (a : Operand)
  | not (output : Ident) (a : Operand)
  | lessThan (output : Ident) (a b : Operand) (bits : Nat)
  | jubjubScalarFromNative (output : Ident) (native : Operand)
  | publicInput (type : IrType) (output : Ident) (guard : Option Operand)
  | privateInput (type : IrType) (output : Ident) (guard : Option Operand)
  | output (vals : List Operand)
deriving DecidableEq, Repr, Inhabited

/-- `IrSource` (ir.rs:59-72) with the on-disk version envelope: only
major 3 is ever accepted (ir.rs:990-999), so the major is not stored. -/
structure Program where
  minor : Nat
  doCommunicationsCommitment : Bool
  inputs : List (Ident × IrType)
  outputs : List IrType
  instructions : List Instr
deriving DecidableEq, Repr, Inhabited

end MinocrabZkir
