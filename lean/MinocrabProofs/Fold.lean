/-
The Lean model of `minocrab_ir::v3::passes::fold_immediate_copies` —
the SYNTACTIC half (M25's ZKIR-pass prong; notes/lean-port.org §4).

THE MODEL GAP: as in `Passes.lean` — these theorems warrant the
algorithm as transcribed; the Rust-implements-it claim rests on review
plus the Rust-side instruments.

THE MODEL: `copy dst src`; `output vals` (the terminator, whose operands
the fold must never rewrite — the all-or-nothing rule that keeps a
returned constant named); and `other touched` for every ordinary
instruction, whose operand list is exactly what `operands_mut` exposes.
Immediates are `Nat`.

SCOPE, stated honestly: this file proves the SYNTACTIC contract —
`output` lists verbatim, only provably-immediate copies dropped, the
non-copy skeleton preserved in kind and order, and the substitution maps
only folded names to their immediates. The SEMANTIC theorem (observable
operand-VALUES preserved under the copy environment) needs an SSA
well-formedness apparatus (defs-before-uses, no rebinding) and is the
next session's task; its statement lives at the bottom as a comment so
the goal is fixed before the machinery exists.
-/

namespace MinocrabProofs.Fold

/-- An operand: a named wire or an immediate value. -/
inductive Operand where
  | var (name : String)
  | imm (value : Nat)
deriving DecidableEq

/-- The fold's-eye view of an instruction stream. -/
inductive Instr where
  | copy (dst : String) (src : Operand)
  | output (vals : List Operand)
  | other (touched : List Operand)
deriving DecidableEq

/-- Association list, as in `Passes.lean` — `AssocMap`'s literal shape. -/
abbrev Env := List (String × Nat)

def Env.get : Env → String → Option Nat
  | [], _ => none
  | (k, v) :: rest, key => if k = key then some v else Env.get rest key

def Env.set : Env → String → Nat → Env
  | [], key, value => [(key, value)]
  | (k, v) :: rest, key, value =>
    if k = key then (k, value) :: rest else (k, v) :: Env.set rest key value

/-- `immediate_copies`, transcribed: the names bound by a `Copy` of an
immediate, chased through chains (a copy of an already-named copy is
itself an immediate). -/
def namedOf : Env → List Instr → Env
  | named, [] => named
  | named, .copy dst (.imm v) :: rest => namedOf (named.set dst v) rest
  | named, .copy dst (.var s) :: rest =>
    match named.get s with
    | some v => namedOf (named.set dst v) rest
    | none => namedOf named rest
  | named, _ :: rest => namedOf named rest

/-- `returned_identifiers`: every name an `output` terminator lists. -/
def returnedOf : List Instr → List String
  | [] => []
  | .output vals :: rest =>
    (vals.filterMap fun | .var n => some n | .imm _ => none) ++ returnedOf rest
  | _ :: rest => returnedOf rest

/-- One operand under the fold's substitution. -/
def substOp (folded : Env) : Operand → Operand
  | .var n =>
    match folded.get n with
    | some v => .imm v
    | none => .var n
  | .imm v => .imm v

/-- The walk: substitute in every `operands_mut` position (copies and
ordinary instructions — never the terminator), and drop a copy whose
output is folded. -/
def foldRun (folded : Env) : List Instr → List Instr
  | [] => []
  | .copy dst src :: rest =>
    if (folded.get dst).isSome then foldRun folded rest
    else .copy dst (substOp folded src) :: foldRun folded rest
  | .output vals :: rest => .output vals :: foldRun folded rest
  | .other touched :: rest =>
    .other (touched.map (substOp folded)) :: foldRun folded rest

/-- `fold_immediate_copies`: fold every named-immediate copy except the
returned ones. -/
def fold (l : List Instr) : List Instr :=
  let named := namedOf [] l
  let returned := returnedOf l
  let folded := named.filter (fun kv => ¬ returned.contains kv.1)
  foldRun folded l

/-! ## Theorem 1: `output` operand lists are preserved VERBATIM — the
all-or-nothing rule. A returned constant stays named on both sides. -/

def outputs : List Instr → List (List Operand)
  | [] => []
  | .output vals :: rest => vals :: outputs rest
  | _ :: rest => outputs rest

theorem foldRun_outputs (folded : Env) (l : List Instr) :
    outputs (foldRun folded l) = outputs l := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases i with
    | copy dst src =>
      simp only [foldRun]
      split
      · simpa [outputs] using ih
      · simpa [outputs] using ih
    | output vals => simpa [foldRun, outputs] using ih
    | other touched => simpa [foldRun, outputs] using ih

theorem fold_outputs (l : List Instr) : outputs (fold l) = outputs l :=
  foldRun_outputs _ l

/-! ## Theorem 2: the non-copy SKELETON — every instruction's
constructor, in order, with copies erased — is preserved: the fold drops
only copies and rewrites only operands. -/

/-- The stream with operands erased and copies dropped: what must
survive any fold, whatever it substitutes. -/
def skeleton : List Instr → List Nat
  | [] => []
  | .copy _ _ :: rest => skeleton rest
  | .output vals :: rest => (0 :: [vals.length]) ++ skeleton rest
  | .other touched :: rest => (1 :: [touched.length]) ++ skeleton rest

theorem foldRun_skeleton (folded : Env) (l : List Instr) :
    skeleton (foldRun folded l) = skeleton l := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases i with
    | copy dst src =>
      simp only [foldRun]
      split
      · simpa [skeleton] using ih
      · simpa [skeleton] using ih
    | output vals => simpa [foldRun, skeleton] using ih
    | other touched => simpa [foldRun, skeleton, List.length_map] using ih

theorem fold_skeleton (l : List Instr) : skeleton (fold l) = skeleton l :=
  foldRun_skeleton _ l

/-! ## Theorem 3: only immediate-named copies are dropped, and every
kept instruction is the original with `substOp` applied to its
`operands_mut` positions — i.e. the fold is exactly "substitute and
drop", nothing more. -/

/-- What one instruction becomes if kept. -/
def substInstr (folded : Env) : Instr → Instr
  | .copy dst src => .copy dst (substOp folded src)
  | .output vals => .output vals
  | .other touched => .other (touched.map (substOp folded))

/-- Keep-or-drop, per instruction. -/
def keeps (folded : Env) : Instr → Bool
  | .copy dst _ => !(folded.get dst).isSome
  | _ => true

theorem foldRun_is_filter_map (folded : Env) (l : List Instr) :
    foldRun folded l
      = (l.filter (keeps folded)).map (substInstr folded) := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases i with
    | copy dst src =>
      simp only [foldRun]
      split
      · rename_i h
        have hk : keeps folded (Instr.copy dst src) = false := by
          simp [keeps, h]
        simp [List.filter_cons, hk, ih]
      · rename_i h
        have hk : keeps folded (Instr.copy dst src) = true := by
          simp only [keeps, Bool.not_eq_true']
          simpa using h
        simp [List.filter_cons, hk, substInstr, ih]
    | output vals =>
      have hk : keeps folded (Instr.output vals) = true := rfl
      simp [foldRun, List.filter_cons, hk, substInstr, ih]
    | other touched =>
      have hk : keeps folded (Instr.other touched) = true := rfl
      simp [foldRun, List.filter_cons, hk, substInstr, ih]

/-! The SEMANTIC statement, fixed now, proved next (needs the SSA
well-formedness apparatus — defs-before-uses for copy destinations, no
rebinding):

  theorem fold_preserves_observables (l : List Instr) (wf : WellFormed l) :
      observe [] (fold l) = observe [] l

where `observe` walks the stream maintaining the copy environment and
records, for every non-copy instruction, its constructor and the
EVALUATION of each operand. -/

end MinocrabProofs.Fold
