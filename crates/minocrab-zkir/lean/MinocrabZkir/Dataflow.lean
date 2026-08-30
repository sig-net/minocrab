/-
Dataflow over the real IR (M27 rung 2; notes/zkir-semantics.org §2, §8):
which operand positions an instruction READS and which identifiers it
DEFINES — the Lean twin of `minocrab_ir::v3::passes::operands_mut` /
`returned_operands` (the reads, split the way the fold pass splits
them) and of `defined_identifiers` (the writes). Every function is one
exhaustive `match` over the 33 constructors, so the kernel checks
coverage the way `passes.rs`'s wildcard-free matches make rustc check
it. GATE: the `zkir-dataflow` dump agrees with the Rust functions on
every corpus instruction (minocrab-ir/tests/lean_dataflow.rs).
-/
import MinocrabZkir.Syntax

namespace MinocrabZkir

/-- The operand positions `operands_mut` lists (passes.rs:316-361), in
its order — every read EXCEPT the `output` terminator's, which the
fold pass deliberately leaves alone (see `returned`). -/
def Instr.operands : Instr → List Operand
  | .encode _ input => [input]
  | .assert cond => [cond]
  | .condSelect _ bit a b => [bit, a, b]
  | .constrainBits val _ => [val]
  | .constrainEq a b => [a, b]
  | .constrainToBoolean val => [val]
  | .copy _ val => [val]
  | .impact guard inputs => guard :: inputs
  | .ecMul _ a scalar => [a, scalar]
  | .ecMulGenerator _ scalar => [scalar]
  | .hashToCurve _ inputs => inputs
  | .intoCoordinates _ point => [point]
  | .fromCoordinates _ (x, y) => [x, y]
  | .intoBytes32 _ input => [input]
  | .fromBytes32 _ _ bytes => [bytes]
  | .reverseBytes _ bytes => [bytes]
  | .bytes32IntoLowHigh _ bytes => [bytes]
  | .bytes32FromLowHigh _ (lo, hi) => [lo, hi]
  | .divModPowerOfTwo _ val _ => [val]
  | .reconstituteField _ divisor modulus _ => [divisor, modulus]
  | .transientHash _ inputs => inputs
  | .persistentHash _ _ inputs => inputs
  | .keccak256 _ _ inputs => inputs
  | .testEq _ a b => [a, b]
  | .add _ a b => [a, b]
  | .mul _ a b => [a, b]
  | .neg _ a => [a]
  | .inv _ a => [a]
  | .not _ a => [a]
  | .lessThan _ a b _ => [a, b]
  | .jubjubScalarFromNative _ native => [native]
  | .publicInput _ _ guard => guard.toList
  | .privateInput _ _ guard => guard.toList
  | .output _ => []

/-- `returned_operands` (passes.rs:270-314): the positions through which
a value LEAVES the circuit named — the terminator's, and nothing else. -/
def Instr.returned : Instr → List Operand
  | .output vals => vals
  | _ => []

/-- Every read: `operands ++ returned`. -/
def Instr.reads (i : Instr) : List Operand := i.operands ++ i.returned

/-- The identifiers an instruction binds (`defined_identifiers`,
passes.rs), in output order. -/
def Instr.defines : Instr → List Ident
  | .encode outputs _ => outputs
  | .assert _ => []
  | .condSelect out _ _ _ => [out]
  | .constrainBits _ _ => []
  | .constrainEq _ _ => []
  | .constrainToBoolean _ => []
  | .copy out _ => [out]
  | .impact _ _ => []
  | .ecMul out _ _ => [out]
  | .ecMulGenerator out _ => [out]
  | .hashToCurve out _ => [out]
  | .intoCoordinates (x, y) _ => [x, y]
  | .fromCoordinates out _ => [out]
  | .intoBytes32 out _ => [out]
  | .fromBytes32 _ out _ => [out]
  | .reverseBytes out _ => [out]
  | .bytes32IntoLowHigh (lo, hi) _ => [lo, hi]
  | .bytes32FromLowHigh out _ => [out]
  | .divModPowerOfTwo outputs _ _ => outputs
  | .reconstituteField out _ _ _ => [out]
  | .transientHash out _ => [out]
  | .persistentHash out _ _ => [out]
  | .keccak256 out _ _ => [out]
  | .testEq out _ _ => [out]
  | .add out _ _ => [out]
  | .mul out _ _ => [out]
  | .neg out _ => [out]
  | .inv out _ => [out]
  | .not out _ => [out]
  | .lessThan out _ _ _ => [out]
  | .jubjubScalarFromNative out _ => [out]
  | .publicInput _ out _ => [out]
  | .privateInput _ out _ => [out]
  | .output _ => []

/-- The wires an instruction reads (immediates dropped). -/
def Instr.readWires (i : Instr) : List Ident :=
  i.reads.filterMap fun | .var n => some n | .imm _ => none

/-- The guard an instruction's stream consumption depends on: `impact`'s
always, an input's when present (§3.1). -/
def Instr.guardOf : Instr → Option Operand
  | .impact guard _ => some guard
  | .publicInput _ _ guard => guard
  | .privateInput _ _ guard => guard
  | _ => none

end MinocrabZkir
