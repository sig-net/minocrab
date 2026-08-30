/-
Build-time smoke checks for the evaluation reading (`#guard` fails the
build if a check is false). NOT the rung-3 gate — that is sorry-free
theorems plus the rung-4 differential — just the evidence that the walk
in Semantics.lean does what ir_vm.rs does on a hand-traced program:
prologue decoding, an unguarded `public_input` consuming the outputs
stream, arithmetic on `Fin p`, a true-guarded `impact` pushing and
CHECKING against `public_transcript_inputs`, a false-guarded `impact`
pushing zeros and recording a skip, the epilogue's full-consumption
check, and the rejects each of those produce when violated.
-/
import MinocrabZkir.Semantics

namespace MinocrabZkir.Smoke

/-- Every foreign carrier is `Unit`; every intrinsic rejects. -/
def C : Carriers := ⟨Unit, Unit, Unit, Unit, Unit, Unit, Unit, Unit, Unit, Unit, Unit⟩

def M : Model C where
  transientHash _ := 0
  transientCommit _ _ := 0
  sha256 _ := Bytes32.zero
  keccak256 _ := Bytes32.zero
  hashToCurve _ := ()
  jubjubScalarFromNative _ := ()
  addF _ _ := throw "foreign add"
  mulF _ _ := throw "foreign mul"
  negF _ := throw "foreign neg"
  invF _ := throw "foreign inv"
  eqF _ _ := throw "foreign eq"
  ecMul _ _ := throw "ec_mul"
  ecMulGenerator _ := throw "ec_mul_generator"
  intoCoordinates _ := throw "into_coordinates"
  fromCoordinates _ _ := throw "from_coordinates"
  intoBytes32F _ := throw "into_bytes32"
  fromBytes32F _ _ := throw "from_bytes32"
  encodeF _ := []
  decodeF _ _ := throw "decode"
  defaultF _ := .native 0

/-- a := 5 (input); t := next public output (7); s := a + t;
impact[1](s, 7); z := (a == 0) = 0; impact[z](a). -/
def prog : Program :=
  { minor := 0
  , doCommunicationsCommitment := false
  , inputs := [("%a.0", .native)]
  , outputs := []
  , instructions :=
    [ .constrainBits (.var "%a.0") 8
    , .publicInput .native "%t.1" none
    , .add "%s.2" (.var "%a.0") (.var "%t.1")
    , .impact (.imm 1) [.var "%s.2", .imm 7]
    , .testEq "%z.3" (.var "%a.0") (.imm 0)
    , .impact (.var "%z.3") [.var "%a.0"]
    , .output [] ] }

def π : Preimage :=
  { inputs := [Fr.ofNat 5]
  , privateTranscript := []
  , publicTranscriptInputs := [Fr.ofNat 12, Fr.ofNat 7]
  , publicTranscriptOutputs := [Fr.ofNat 7]
  , bindingInput := Fr.ofNat 99
  , communicationsCommitment := none }

def pisOf (r : R (Result C)) : Option (List Nat × List (Option Nat)) :=
  match r with
  | .ok r => some (r.pis.map (·.val), r.piSkips)
  | .error _ => none

def rejects (r : R (Result C)) : Bool :=
  match r with
  | .error _ => true
  | .ok _ => false

-- The honest run: binding input first, then the checked pushes, then the
-- guarded-off zero, with one skip recorded for the second impact.
#guard pisOf (Eval.run M prog π) == some ([99, 12, 7, 0], [none, some 1])

-- A transcript that disagrees with a checked push is a reject
-- (ir_vm.rs:528-540).
#guard rejects (Eval.run M prog { π with publicTranscriptInputs := [Fr.ofNat 12, Fr.ofNat 8] })

-- A transcript with an element left over is a reject (ir_vm.rs:648-661).
#guard rejects (Eval.run M prog { π with publicTranscriptInputs := [Fr.ofNat 12, Fr.ofNat 7, Fr.ofNat 1] })

-- An input above its declared width is a reject (constrain_bits).
#guard rejects (Eval.run M prog { π with inputs := [Fr.ofNat 300] })

-- Too few raw inputs is a reject (prologue).
#guard rejects (Eval.run M prog { π with inputs := [] })

-- A negative immediate resolves to p − |v|: `-0x01` + 1 = 0.
#guard (Fr.ofInt (-1) + 1 : Fr) == 0

-- `inv` is a genuine inverse on a small value.
#guard (Fr.inv (Fr.ofNat 3) * Fr.ofNat 3 : Fr) == 1

end MinocrabZkir.Smoke
