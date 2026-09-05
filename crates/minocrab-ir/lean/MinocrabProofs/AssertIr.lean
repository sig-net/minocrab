/-
`drop_true_asserts` over the REAL IR (M37; notes/ir-passes.org §12,
notes/evm-calls.org §3.2): an `assert` whose operand is the IMMEDIATE 1
is deleted, because it passes on every preimage.

STATED ON THE EVALUATION SEMANTICS, not on a bespoke `observe`. The two
older pass files could only reach an abstraction of meaning — `FoldIr`'s
`observe`, `DedupIr`'s `streamBound` — because a fold that renames wires
and a dedup that removes constraints are not equalities of `run`. This
rule IS one: the deleted instruction steps to `pure st`, so
`MinocrabZkir.Eval.run` — memory, `pis`, `piSkips`, `outputs`, and
accept-vs-reject with its message — is EQUAL before and after, for every
model, every carrier assignment and every preimage. That is the strongest
form the contract has, and it is what makes the deletion safe to ship on
every circuit.

The unsound direction is closed twice over: `dropTrueAsserts_preserves_run`
says no preimage changes verdict at all, and
`dropTrueAsserts_keeps_failing_asserts` says syntactically that an assert
on any OTHER immediate — an always-REJECTING circuit — is kept with
multiplicity.

THE REMAINING GAP is the one every Lean file here states: this warrants
the algorithm as transcribed; that `passes.rs` implements it rests on
review and the Rust-side instruments.
-/
import MinocrabZkir.Syntax
import MinocrabZkir.Semantics

namespace MinocrabProofs.AssertIr

open MinocrabZkir

/-- `passes.rs`'s `is_true_assert`: an `assert` on an immediate whose field
value is 1, and nothing else. The Rust holds an already-reduced `Fr` in the
operand where the syntax holds the file's signed literal, so the condition
here is `Fr.ofInt v = 1` — `resolve`'s own reading of that literal
(Semantics.lean, ir_vm.rs:238). -/
def isTrueAssert : Instr → Bool
  | .assert (.imm v) => decide (Fr.ofInt v = 1)
  | _ => false

/-- The pass: keep everything that is not a true assert, in order. -/
def dropTrueAsserts (l : List Instr) : List Instr :=
  l.filter (fun i => !isTrueAssert i)

theorem dropTrueAsserts_cons_true {i : Instr} {rest : List Instr}
    (h : isTrueAssert i = true) :
    dropTrueAsserts (i :: rest) = dropTrueAsserts rest := by
  simp [dropTrueAsserts, h]

theorem dropTrueAsserts_cons_false {i : Instr} {rest : List Instr}
    (h : isTrueAssert i = false) :
    dropTrueAsserts (i :: rest) = i :: dropTrueAsserts rest := by
  simp [dropTrueAsserts, h]

/-! ## Theorem 1: the output is a SUBSEQUENCE of the input — nothing is
added, nothing reordered, nothing rewritten. -/

theorem dropTrueAsserts_sublist (l : List Instr) : (dropTrueAsserts l).Sublist l :=
  List.filter_sublist

/-! ## Theorem 2: everything that is not a true assert survives, with
multiplicity and in order. -/

def passthrough (l : List Instr) : List Instr :=
  l.filter (fun i => !isTrueAssert i)

theorem dropTrueAsserts_passthrough (l : List Instr) :
    passthrough (dropTrueAsserts l) = passthrough l := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases h : isTrueAssert i with
    | true =>
      rw [dropTrueAsserts_cons_true h, ih]
      simp [passthrough, h]
    | false =>
      rw [dropTrueAsserts_cons_false h]
      simp only [passthrough, List.filter_cons, h, Bool.not_false, if_pos]
      simpa [passthrough] using ih

/-! ## Theorem 3: THE UNSOUND DIRECTION, closed syntactically. An `assert`
on an immediate that is not 1 is an always-FAILING circuit; every one of
them is kept, so no rejected circuit can become an accepted one by this
pass removing its check. -/

theorem dropTrueAsserts_count_kept (l : List Instr) (i : Instr)
    (h : isTrueAssert i = false) :
    (dropTrueAsserts l).count i = l.count i := by
  induction l with
  | nil => rfl
  | cons j rest ih =>
    cases hj : isTrueAssert j with
    | true =>
      rw [dropTrueAsserts_cons_true hj, ih, List.count_cons]
      have : ¬ (j = i) := by
        intro he; rw [he, h] at hj; exact Bool.noConfusion hj
      simp [this]
    | false =>
      rw [dropTrueAsserts_cons_false hj, List.count_cons, List.count_cons, ih]

theorem dropTrueAsserts_keeps_failing_asserts (l : List Instr) (v : Int)
    (h : Fr.ofInt v ≠ 1) :
    (dropTrueAsserts l).count (.assert (.imm v)) = l.count (.assert (.imm v)) :=
  dropTrueAsserts_count_kept l _ (by simp [isTrueAssert, h])

/-! ## Theorem 4: idempotence. -/

theorem dropTrueAsserts_idem (l : List Instr) :
    dropTrueAsserts (dropTrueAsserts l) = dropTrueAsserts l := by
  induction l with
  | nil => rfl
  | cons i rest ih =>
    cases h : isTrueAssert i with
    | true => rw [dropTrueAsserts_cons_true h, ih]
    | false => rw [dropTrueAsserts_cons_false h, dropTrueAsserts_cons_false h, ih]

/-! ## Theorem 5: THE SEMANTIC THEOREM — `run` is preserved exactly.

The deleted instruction is a no-op of the evaluation semantics: `resolve`
sends `.imm v` to `Fr.ofInt v`, `resolveBool` accepts 1 as `true`, and the
`assert` arm then returns the state untouched (ir_vm.rs's "Failed direct
assertion" is unreachable on it). Everything downstream — the three
transcript cursors, the PI vector, the skip list, memory, the outputs —
therefore sees exactly the state it saw before. -/

variable {C : Carriers}

/-- `p` is neither 0 nor 1, so the field's 1 is not its 0 — what
`resolveBool` needs to send the immediate 1 to `true` rather than to
`false` or to "Expected boolean". -/
theorem p_ne_one : p ≠ 1 := by decide

theorem step_of_isTrueAssert (M : Model C) (prog : Program) (π : Preimage)
    (st : State C) (i : Instr) (h : isTrueAssert i = true) :
    Eval.step M prog π st i = pure st := by
  cases i with
  | assert cond =>
    cases cond with
    | var n => simp [isTrueAssert] at h
    | imm v =>
      have hv : Fr.ofInt v = 1 := by simpa [isTrueAssert] using h
      simp [Eval.step, Eval.resolveBool, Eval.resolve, Eval.asNative, hv, p_ne_one]
  | _ => simp [isTrueAssert] at h

/-- The walk over the instruction list is unchanged by the deletion — the
statement that carries every observable, since `State` holds them all. -/
theorem foldlM_dropTrueAsserts (M : Model C) (prog : Program) (π : Preimage) :
    ∀ (l : List Instr) (st : State C),
      List.foldlM (Eval.step M prog π) st (dropTrueAsserts l)
        = List.foldlM (Eval.step M prog π) st l := by
  intro l
  induction l with
  | nil => intro st; rfl
  | cons i rest ih =>
    intro st
    cases h : isTrueAssert i with
    | true =>
      rw [dropTrueAsserts_cons_true h, ih st, List.foldlM_cons,
        step_of_isTrueAssert M prog π st i h]
      rfl
    | false =>
      rw [dropTrueAsserts_cons_false h, List.foldlM_cons, List.foldlM_cons]
      cases hs : Eval.step M prog π st i with
      | error e => rfl
      | ok st' => simpa using ih st'

/-- The pass on a whole program: only the instruction list changes. -/
def dropped (prog : Program) : Program :=
  { prog with instructions := dropTrueAsserts prog.instructions }

theorem step_dropped (M : Model C) (prog : Program) (π : Preimage)
    (st : State C) (i : Instr) :
    Eval.step M (dropped prog) π st i = Eval.step M prog π st i := by
  cases i <;> rfl

/-- THE SEMANTIC THEOREM: deleting the always-true asserts leaves
`preprocess` — memory, `pis`, `piSkips`, `outputs`, and accept-vs-reject
with its message — EQUAL, for every model, every carrier assignment and
every preimage. -/
theorem dropTrueAsserts_preserves_run (M : Model C) (prog : Program) (π : Preimage) :
    Eval.run M (dropped prog) π = Eval.run M prog π := by
  have hstep : Eval.step M (dropped prog) π = Eval.step M prog π := by
    funext st i; exact step_dropped M prog π st i
  have hpro : Eval.prologue M (dropped prog) π = Eval.prologue M prog π := rfl
  have hpis : Eval.initialPis (dropped prog) π = Eval.initialPis prog π := rfl
  have hepi : Eval.epilogue M (dropped prog) π = Eval.epilogue M prog π := by
    funext st; rfl
  have hinstr : (dropped prog).instructions = dropTrueAsserts prog.instructions := rfl
  simp only [Eval.run, hpro, hpis, hepi, hstep, hinstr, foldlM_dropTrueAsserts]

end MinocrabProofs.AssertIr
