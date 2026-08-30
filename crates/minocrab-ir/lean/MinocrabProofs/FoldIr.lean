/-
`fold_immediate_copies` over the REAL IR — the SYNTACTIC half (M27 rung
3, the pass prong; notes/zkir-semantics.org §4.4). `Fold.lean`'s three
syntactic theorems restated on `MinocrabZkir.Instr`: the model's single
`other touched` arm becomes `mapOperands`, the substitution applied to
exactly the `operands_mut` positions (Dataflow.lean's `operands`) and
never to the terminator's. Immediates are the signed literals the real
syntax carries (`Int`).

The SEMANTIC half (`fold_preserves_observables`) stays on the model for
now: its `WellFormed` hypothesis is what `zkir-wellformed` checks on the
corpus in real-IR form, and its transfer is the next session's task.
-/
import MinocrabZkir.Syntax
import MinocrabZkir.Dataflow

namespace MinocrabProofs.FoldIr

open MinocrabZkir

abbrev Env := List (Ident × Int)

def Env.get : Env → Ident → Option Int
  | [], _ => none
  | (k, v) :: rest, key => if k = key then some v else Env.get rest key

def Env.set : Env → Ident → Int → Env
  | [], key, value => [(key, value)]
  | (k, v) :: rest, key, value =>
    if k = key then (k, value) :: rest else (k, v) :: Env.set rest key value

/-- `f` on every `operands_mut` position (passes.rs:316-361) — every read
except the `output` terminator's, which the fold never rewrites. -/
def mapOperands (f : Operand → Operand) : Instr → Instr
  | .encode outs input => .encode outs (f input)
  | .assert cond => .assert (f cond)
  | .condSelect out bit a b => .condSelect out (f bit) (f a) (f b)
  | .constrainBits val bits => .constrainBits (f val) bits
  | .constrainEq a b => .constrainEq (f a) (f b)
  | .constrainToBoolean val => .constrainToBoolean (f val)
  | .copy out val => .copy out (f val)
  | .impact guard inputs => .impact (f guard) (inputs.map f)
  | .ecMul out a s => .ecMul out (f a) (f s)
  | .ecMulGenerator out s => .ecMulGenerator out (f s)
  | .hashToCurve out inputs => .hashToCurve out (inputs.map f)
  | .intoCoordinates outs point => .intoCoordinates outs (f point)
  | .fromCoordinates out (x, y) => .fromCoordinates out (f x, f y)
  | .intoBytes32 out input => .intoBytes32 out (f input)
  | .fromBytes32 ty out bytes => .fromBytes32 ty out (f bytes)
  | .reverseBytes out bytes => .reverseBytes out (f bytes)
  | .bytes32IntoLowHigh outs bytes => .bytes32IntoLowHigh outs (f bytes)
  | .bytes32FromLowHigh out (lo, hi) => .bytes32FromLowHigh out (f lo, f hi)
  | .divModPowerOfTwo outs val bits => .divModPowerOfTwo outs (f val) bits
  | .reconstituteField out d m bits => .reconstituteField out (f d) (f m) bits
  | .transientHash out inputs => .transientHash out (inputs.map f)
  | .persistentHash out al inputs => .persistentHash out al (inputs.map f)
  | .keccak256 out al inputs => .keccak256 out al (inputs.map f)
  | .testEq out a b => .testEq out (f a) (f b)
  | .add out a b => .add out (f a) (f b)
  | .mul out a b => .mul out (f a) (f b)
  | .neg out a => .neg out (f a)
  | .inv out a => .inv out (f a)
  | .not out a => .not out (f a)
  | .lessThan out a b bits => .lessThan out (f a) (f b) bits
  | .jubjubScalarFromNative out n => .jubjubScalarFromNative out (f n)
  | .publicInput ty out guard => .publicInput ty out (guard.map f)
  | .privateInput ty out guard => .privateInput ty out (guard.map f)
  | .output vals => .output vals

theorem mapOperands_mapOperands (f g : Operand → Operand) (i : Instr) :
    mapOperands f (mapOperands g i) = mapOperands (f ∘ g) i := by
  cases i <;> simp [mapOperands, List.map_map, Option.map_map]

/-- `immediate_copies`, transcribed (passes.rs:232-246). -/
def namedOf : Env → List Instr → Env
  | named, [] => named
  | named, .copy dst (.imm v) :: rest => namedOf (named.set dst v) rest
  | named, .copy dst (.var s) :: rest =>
    match named.get s with
    | some v => namedOf (named.set dst v) rest
    | none => namedOf named rest
  | named, _ :: rest => namedOf named rest

def varsOf : List Operand → List Ident
  | [] => []
  | .var n :: rest => n :: varsOf rest
  | .imm _ :: rest => varsOf rest

/-- `returned_identifiers`: every name an `output` terminator lists. -/
def returnedOf : List Instr → List Ident
  | [] => []
  | .output vals :: rest => varsOf vals ++ returnedOf rest
  | _ :: rest => returnedOf rest

def substOp (folded : Env) : Operand → Operand
  | .var n =>
    match folded.get n with
    | some v => .imm v
    | none => .var n
  | .imm v => .imm v

/-- The walk: drop a copy whose output is folded; substitute everywhere
else (`mapOperands` leaves the terminator alone by definition). -/
def foldRun (folded : Env) : List Instr → List Instr
  | [] => []
  | .copy dst src :: rest =>
    if (folded.get dst).isSome then foldRun folded rest
    else .copy dst (substOp folded src) :: foldRun folded rest
  | i :: rest => mapOperands (substOp folded) i :: foldRun folded rest

def fold (l : List Instr) : List Instr :=
  let named := namedOf [] l
  let returned := returnedOf l
  let folded := named.filter (fun kv => !returned.contains kv.1)
  foldRun folded l

/-! ## Theorem 1: `output` operand lists are preserved verbatim. -/

def outputs : List Instr → List (List Operand)
  | [] => []
  | .output vals :: rest => vals :: outputs rest
  | _ :: rest => outputs rest

theorem foldRun_outputs (folded : Env) (l : List Instr) :
    outputs (foldRun folded l) = outputs l := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases i <;> simp only [foldRun, mapOperands] <;> (try split) <;> simp [outputs, ih]

theorem fold_outputs (l : List Instr) : outputs (fold l) = outputs l :=
  foldRun_outputs _ l

/-! ## Theorem 2: the non-copy skeleton — every instruction with its
operands erased, copies dropped — is preserved in kind and order. -/

def isCopy : Instr → Bool
  | .copy _ _ => true
  | _ => false

/-- Operands erased: what survives any substitution. -/
def erase : Instr → Instr := mapOperands (fun _ => .imm 0)

def skeleton : List Instr → List Instr
  | [] => []
  | i :: rest => if isCopy i then skeleton rest else erase i :: skeleton rest

theorem erase_mapOperands (g : Operand → Operand) (i : Instr) :
    erase (mapOperands g i) = erase i := by
  simp only [erase, mapOperands_mapOperands]
  rfl

theorem isCopy_mapOperands (g : Operand → Operand) (i : Instr) :
    isCopy (mapOperands g i) = isCopy i := by
  cases i <;> rfl

theorem foldRun_skeleton (folded : Env) (l : List Instr) :
    skeleton (foldRun folded l) = skeleton l := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases i <;> simp only [foldRun] <;> (try split)
      <;> first
        | (simp only [skeleton, isCopy_mapOperands, erase_mapOperands, ih]; done)
        | simp [skeleton, isCopy, ih]

theorem fold_skeleton (l : List Instr) : skeleton (fold l) = skeleton l :=
  foldRun_skeleton _ l

/-! ## Theorem 3: the fold is exactly filter-then-substitute. -/

def keeps (folded : Env) : Instr → Bool
  | .copy dst _ => !(folded.get dst).isSome
  | _ => true

theorem foldRun_is_filter_map (folded : Env) (l : List Instr) :
    foldRun folded l = (l.filter (keeps folded)).map (mapOperands (substOp folded)) := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases i <;> simp only [foldRun] <;> (try split) <;> simp [keeps, mapOperands, ih, *]

theorem fold_is_filter_map (l : List Instr) :
    ∃ folded, fold l = (l.filter (keeps folded)).map (mapOperands (substOp folded)) :=
  ⟨_, foldRun_is_filter_map _ l⟩

end MinocrabProofs.FoldIr
