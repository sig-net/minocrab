/-
The CONSTRAINT reading of ZKIR v3 (M27 rung 3; notes/zkir-semantics.org
§4.2) — the solution set, stated beside the evaluation reading.

`Sat M P pis mem` says: the assignment `mem` (one value per wire) and
the public-input vector `pis` satisfy every constraint the in-circuit
walk lays down (ir_vm.rs:705-1200 `circuit`, transcribed arm by arm from
THAT walk, not from `step`). A compute instruction contributes the
functional equation `mem[out] = f(mem[operands])` with the SAME
`Model` symbols the evaluation reading uses; a constraint instruction
contributes its predicate; `impact` contributes equalities against
`pis` at a running cursor; the inputs read from the transcripts are FREE
witnesses (their guards are not constrained in-circuit, ir.rs:894); the
prologue's `pi_push` of the binding input and the commitment fix the
first one or two PI positions as free, and the PI vector's length is
exactly what the pushes produce.

What this is NOT: soundness. The places where a satisfying assignment is
not an honest evaluation are §4.3's list (`assert` on a 2, `less_than`
beyond the width, guarded-off transcript inputs); they are visible here
as clauses weaker than `step`'s checks. `Completeness.lean` proves the
other direction.

Two width facts transcribed from the gadgets, to be confirmed at rung 4
(recorded in §9): `lower_than` at width `max(bits + bits mod 2, 4)` is
taken to range-check both operands at that width; `assigned_to_le_bits`
with `bits ≥ FR_BITS` is taken to constrain nothing beyond canonicity.
-/
import MinocrabZkir.Semantics
import MinocrabZkir.Dataflow

namespace MinocrabZkir
namespace Constraint

open Eval

variable {C : Carriers} (M : Model C)

abbrev Assignment (C : Carriers) := List (Ident × Value C)

/-- `resolve_operand` in-circuit (ir_vm.rs:748-761): a name is looked
up, an immediate is a fixed native cell. -/
def val (mem : Assignment C) : Operand → Option (Value C)
  | .var id => lookup mem id
  | .imm i => some (.native (Fr.ofInt i))

def bound (mem : Assignment C) (id : Ident) (v : Value C) : Prop := lookup mem id = some v

/-- A `convert`ed bit as the native value it must carry. -/
def bitVal (g : Bool) : Value C := .native (if g then 1 else 0)

/-- `std.convert` to `AssignedBit`: the booleanness constraint. -/
def isBit (v : Value C) : Prop := ∃ g : Bool, v = bitVal g

/-- The native-typed operand list an intrinsic consumes. -/
def nats (mem : Assignment C) : List Operand → List Fr → Prop
  | [], [] => True
  | o :: os, x :: xs => val mem o = some (.native x) ∧ nats mem os xs
  | _, _ => False

/-- `impact`: `select(guard, x, 0)` pushed as the public input at each
successive position (ir_vm.rs:877-892). -/
def impactSat (mem : Assignment C) (g : Bool) (pis : List Fr) : Nat → List Operand → Prop
  | _, [] => True
  | k, o :: os =>
    (∃ x, val mem o = some (.native x) ∧ pis[k]? = some (if g then x else 0))
      ∧ impactSat mem g pis (k + 1) os

/-- `lower_than`'s width (ir_vm.rs:959-966): even, and at least 4. -/
def ltWidth (bits : Nat) : Nat := max (bits + bits % 2) 4

/-- How many public inputs an instruction pushes. -/
def advance : Instr → Nat
  | .impact _ inputs => inputs.length
  | _ => 0

/-- One instruction's constraints, over the assignment `mem`, the PI
vector `pis`, and the PI cursor `k` at this instruction. -/
def SatInstr (P : Program) (mem : Assignment C) (pis : List Fr) (k : Nat) : Instr → Prop
  | .encode outs input =>
    ∃ v, val mem input = some v ∧ (encode M v).length = outs.length
      ∧ ∀ ox ∈ outs.zip (encode M v), bound mem ox.1 (.native ox.2)
  | .assert cond => ∃ x, val mem cond = some (.native x) ∧ x ≠ 0
  | .condSelect out bit a b =>
    ∃ (g : Bool) (va vb : Value C), val mem bit = some (bitVal g) ∧ val mem a = some va ∧ val mem b = some vb
      ∧ va.type = vb.type ∧ bound mem out (if g then va else vb)
  | .constrainBits v bits =>
    ∃ x, val mem v = some (.native x) ∧ (frBits ≤ bits ∨ x.val < 2 ^ bits)
  | .constrainEq a b =>
    ∃ va vb, val mem a = some va ∧ val mem b = some vb ∧ eqV M va vb = .ok true
  | .constrainToBoolean v => ∃ g, val mem v = some g ∧ isBit g
  | .copy out v => ∃ x, val mem v = some x ∧ bound mem out x
  | .impact guard inputs =>
    ∃ g : Bool, val mem guard = some (bitVal g) ∧ impactSat mem g pis k inputs
  | .ecMul out a s =>
    ∃ va vs r, val mem a = some va ∧ val mem s = some vs ∧ M.ecMul va vs = .ok r ∧ bound mem out r
  | .ecMulGenerator out s =>
    ∃ vs r, val mem s = some vs ∧ M.ecMulGenerator vs = .ok r ∧ bound mem out r
  | .hashToCurve out inputs =>
    ∃ xs, nats mem inputs xs ∧ bound mem out (.jubjubPoint (M.hashToCurve xs))
  | .intoCoordinates (ox, oy) pt =>
    ∃ v x y, val mem pt = some v ∧ M.intoCoordinates v = .ok (x, y) ∧ bound mem ox x ∧ bound mem oy y
  | .fromCoordinates out (ix, iy) =>
    ∃ x y r, val mem ix = some x ∧ val mem iy = some y ∧ M.fromCoordinates x y = .ok r
      ∧ bound mem out r
  | .intoBytes32 out input =>
    ∃ v b, val mem input = some v ∧ intoBytes32V M v = .ok b ∧ bound mem out (.bytes32 b)
  | .fromBytes32 ty out bytes =>
    ∃ b r, val mem bytes = some (.bytes32 b) ∧ fromBytes32V M ty b = .ok r ∧ bound mem out r
  | .reverseBytes out bytes =>
    ∃ b, val mem bytes = some (.bytes32 b) ∧ bound mem out (.bytes32 b.reverse)
  | .bytes32IntoLowHigh (lo, hi) bytes =>
    ∃ b, val mem bytes = some (.bytes32 b)
      ∧ bound mem lo (.native (Fr.ofNat (leToNat (b.toList.take 31))))
      ∧ bound mem hi (.native (Fr.ofNat (b.toList.getD 31 0).toNat))
  | .bytes32FromLowHigh out (ilo, ihi) =>
    ∃ lo hi, val mem ilo = some (.native lo) ∧ val mem ihi = some (.native hi)
      ∧ lo.val < 2 ^ 248 ∧ hi.val < 256 ∧ bound mem out (.bytes32 (bytesOfLowHigh lo hi))
  | .divModPowerOfTwo outs v bits =>
    ∃ q r x, outs = [q, r] ∧ val mem v = some (.native x)
      ∧ bound mem q (.native (Fr.ofNat (x.val / 2 ^ bits)))
      ∧ bound mem r (.native (Fr.ofNat (x.val % 2 ^ bits)))
  | .reconstituteField out d m bits =>
    ∃ dv mv, val mem d = some (.native dv) ∧ val mem m = some (.native mv)
      ∧ dv.val < 2 ^ (frBits - bits) ∧ mv.val < 2 ^ bits
      ∧ bound mem out (.native (mv + Fr.ofNat (2 ^ bits) * dv))
  | .transientHash out inputs =>
    ∃ xs, nats mem inputs xs ∧ bound mem out (.native (M.transientHash xs))
  | .persistentHash out al inputs =>
    ∃ xs bs, nats mem inputs xs ∧ fabBytes al xs = .ok bs ∧ bound mem out (.bytes32 (M.sha256 bs))
  | .keccak256 out al inputs =>
    ∃ xs bs, nats mem inputs xs ∧ fabBytes al xs = .ok bs ∧ bound mem out (.bytes32 (M.keccak256 bs))
  | .testEq out a b =>
    ∃ va vb e, val mem a = some va ∧ val mem b = some vb ∧ eqV M va vb = .ok e
      ∧ bound mem out (.native (if e then 1 else 0))
  | .add out a b =>
    ∃ va vb r, val mem a = some va ∧ val mem b = some vb ∧ addV M va vb = .ok r ∧ bound mem out r
  | .mul out a b =>
    ∃ va vb r, val mem a = some va ∧ val mem b = some vb ∧ mulV M va vb = .ok r ∧ bound mem out r
  | .neg out a => ∃ va r, val mem a = some va ∧ negV M va = .ok r ∧ bound mem out r
  | .inv out a => ∃ va r, val mem a = some va ∧ invV M va = .ok r ∧ bound mem out r
  | .not out a =>
    ∃ g : Bool, val mem a = some (bitVal g) ∧ bound mem out (bitVal (!g))
  | .lessThan out a b bits =>
    ∃ x y, val mem a = some (.native x) ∧ val mem b = some (.native y)
      ∧ x.val < 2 ^ ltWidth bits ∧ y.val < 2 ^ ltWidth bits
      ∧ bound mem out (.native (if x.val < y.val then 1 else 0))
  | .jubjubScalarFromNative out n =>
    ∃ x, val mem n = some (.native x) ∧ bound mem out (.jubjubScalar (M.jubjubScalarFromNative x))
  | .publicInput _ out _ => ∃ v, bound mem out v
  | .privateInput _ out _ => ∃ v, bound mem out v
  | .output vals =>
    vals.length = P.outputs.length
      ∧ ∀ oty ∈ vals.zip P.outputs, ∃ v, val mem oty.1 = some v ∧ v.type = oty.2

/-- The instruction list with the PI cursor threaded. -/
def SatBody (P : Program) (mem : Assignment C) (pis : List Fr) : Nat → List Instr → Prop
  | _, [] => True
  | k, i :: rest => SatInstr M P mem pis k i ∧ SatBody P mem pis (k + advance i) rest

/-- The prologue's pushes: the binding input, then the commitment if
the program declares one (ir_vm.rs:804-817). -/
def pisBase (P : Program) : Nat := if P.doCommunicationsCommitment then 2 else 1

def totalAdvance : List Instr → Nat
  | [] => 0
  | i :: rest => advance i + totalAdvance rest

/-- Every declared input is assigned (`assign_incircuit` of the witness). -/
def SatInputs (P : Program) (mem : Assignment C) : Prop :=
  ∀ idty ∈ P.inputs, ∃ v, bound mem idty.1 v

/-- THE SOLUTION-SET PREDICATE. -/
def Sat (P : Program) (pis : List Fr) (mem : Assignment C) : Prop :=
  pis.length = pisBase P + totalAdvance P.instructions
    ∧ SatInputs P mem
    ∧ SatBody M P mem pis (pisBase P) P.instructions

/-- The epilogue's commitment constraint (ir_vm.rs:1170-1200): PI
position 1 is `transient_commit` of the encoded INPUT WIRES (read back
from memory, as the circuit does) and the encoded returned values, under
a free randomness witness. Stated separately: its completeness needs
`encode ∘ decode` to be the identity on the raw inputs, a property of
the `Model` (rung 4), not of the walk. -/
def returnedValues (mem : Assignment C) : List Instr → List (Value C)
  | [] => []
  | .output vals :: rest => vals.filterMap (val mem) ++ returnedValues mem rest
  | _ :: rest => returnedValues mem rest

def SatCommitment (P : Program) (pis : List Fr) (mem : Assignment C) : Prop :=
  P.doCommunicationsCommitment = true →
    ∃ rand, pis[1]? = some (M.transientCommit
      (P.inputs.flatMap (fun idty => (lookup mem idty.1).elim [] (encode M))
        ++ (returnedValues mem P.instructions).flatMap (encode M)) rand)

end Constraint
end MinocrabZkir
