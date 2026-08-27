/-
The Lean model of `minocrab_ir::v3::passes::dedup_range_constraints`
(M25's ZKIR-pass prong; design of record: notes/lean-port.org §4).

THE MODEL GAP, stated once and inherited by everything here: these
theorems warrant the ALGORITHM as transcribed below; the claim that the
Rust implements this algorithm rests on review (the transcription is
line-for-line against `passes.rs`) plus the Rust-side instruments — the
unit tests and the Kani-bounded twins. Extraction (Aeneas) would close
that gap; nothing else does.

THE MODEL: everything that is not a wire-keyed range constraint is one
`other` constructor carrying no structure, which is FAITHFUL for this
pass: the Rust passes every such instruction through untouched and
unexamined. `constrainBoolean` is the `bits = 1` family (the pass's own
documented equivalence, checked upstream in `ir_vm.rs`).
-/

namespace MinocrabProofs

/-- An instruction operand: a named wire or an immediate. -/
inductive Operand where
  | var (name : String)
  | imm (value : Nat)
deriving DecidableEq

/-- The instruction model: the two wire-keyed range constraints the pass
acts on, and `other` for the entire untouched complement. -/
inductive Instr where
  | constrainBits (val : Operand) (bits : Nat)
  | constrainBoolean (val : Operand)
  | other (tag : Nat)
deriving DecidableEq

/-- The bound an instruction establishes on a WIRE — `passes.rs`'s
`established` match: `constrainBits{bits}` proves `val < 2^bits`,
`constrainBoolean` is the one-bit family. Constraints on immediates
key no wire and are `none` (the pass never touches them). -/
def established : Instr → Option (String × Nat)
  | .constrainBits (.var n) b => some (n, b)
  | .constrainBoolean (.var n) => some (n, 1)
  | _ => none

/-- The passes' `AssocMap`, as the association list it literally is. -/
abbrev Bounds := List (String × Nat)

def Bounds.get : Bounds → String → Option Nat
  | [], _ => none
  | (k, v) :: rest, key => if k = key then some v else Bounds.get rest key

/-- Insert-or-update, `AssocMap::insert`'s semantics. -/
def Bounds.set : Bounds → String → Nat → Bounds
  | [], key, value => [(key, value)]
  | (k, v) :: rest, key, value =>
    if k = key then (k, value) :: rest else (k, v) :: Bounds.set rest key value

/-- `dedup_range_constraints`, transcribed: walk the stream keeping the
tightest proven bound per wire; drop a constraint already implied
(`proven ≤ bits`), keep and record a tighter or first one. -/
def dedupGo (bound : Bounds) : List Instr → List Instr
  | [] => []
  | i :: rest =>
    match established i with
    | some (id, bits) =>
      match bound.get id with
      | some proven =>
        if proven ≤ bits then dedupGo bound rest
        else i :: dedupGo (bound.set id bits) rest
      | none => i :: dedupGo (bound.set id bits) rest
    | none => i :: dedupGo bound rest

def dedup (l : List Instr) : List Instr := dedupGo [] l

/-! ## Theorem 1: the output is a subsequence of the input.
Nothing is added, reordered, or rewritten. -/

theorem dedupGo_sublist (bound : Bounds) (l : List Instr) :
    (dedupGo bound l).Sublist l := by
  induction l generalizing bound with
  | nil => simp [dedupGo]
  | cons i rest ih =>
    unfold dedupGo
    split
    · split
      · split
        · exact List.Sublist.cons i (ih bound)
        · exact List.Sublist.cons_cons i (ih _)
      · exact List.Sublist.cons_cons i (ih _)
    · exact List.Sublist.cons_cons i (ih bound)

theorem dedup_sublist (l : List Instr) : (dedup l).Sublist l :=
  dedupGo_sublist [] l

/-! ## Theorem 2: everything that is not a wire-keyed range constraint
survives verbatim — same members, same multiplicity, same order. -/

def passthrough (l : List Instr) : List Instr :=
  l.filter (fun i => (established i).isNone)

theorem dedupGo_passthrough (bound : Bounds) (l : List Instr) :
    passthrough (dedupGo bound l) = passthrough l := by
  induction l generalizing bound with
  | nil => rfl
  | cons i rest ih =>
    unfold dedupGo
    split
    · rename_i id' bits heq
      have hkeep : ((established i).isNone) = false := by simp [heq]
      split
      · split
        · rw [ih bound]
          simp [passthrough, hkeep]
        · simp [passthrough, hkeep]
          simpa [passthrough] using ih (Bounds.set bound id' bits)
      · simp [passthrough, hkeep]
        simpa [passthrough] using ih (Bounds.set bound id' bits)
    · rename_i heq
      have hkeep : ((established i).isNone) = true := by simp [heq]
      simp [passthrough, hkeep]
      simpa [passthrough] using ih bound

theorem dedup_passthrough (l : List Instr) :
    passthrough (dedup l) = passthrough l :=
  dedupGo_passthrough [] l

/-! ## Theorem 3: the tightest bound per wire — and with it the per-wire
SOLUTION SET, since `{v < 2^b}` sets intersect at the minimum — is
unchanged. Stated relative to the accumulator, as the recursion needs;
at `bound = []` it is exactly "dedup preserves every wire's solution
set". -/

/-- `min` over `Option Nat`, `none` = unbounded. -/
def optMin : Option Nat → Option Nat → Option Nat
  | none, b => b
  | a, none => a
  | some a, some b => some (min a b)

/-- The tightest bound a STREAM proves for `id`. -/
def streamBound (id : String) : List Instr → Option Nat
  | [] => none
  | i :: rest =>
    match established i with
    | some (id', bits) =>
      if id' = id then optMin (some bits) (streamBound id rest)
      else streamBound id rest
    | none => streamBound id rest

theorem optMin_assoc (a b c : Option Nat) :
    optMin (optMin a b) c = optMin a (optMin b c) := by
  cases a <;> cases b <;> cases c <;> simp [optMin, Nat.min_assoc]

theorem optMin_comm (a b : Option Nat) : optMin a b = optMin b a := by
  cases a <;> cases b <;> simp [optMin, Nat.min_comm]

/-- Absorption: with `p ≤ b` already proven, a later `b` adds nothing. -/
theorem optMin_absorb (p b : Nat) (h : p ≤ b) (x : Option Nat) :
    optMin (some p) (optMin (some b) x) = optMin (some p) x := by
  cases x with
  | none => simp [optMin, Nat.min_eq_left h]
  | some v =>
    have hmin : min p (min b v) = min p v := by
      rw [← Nat.min_assoc, Nat.min_eq_left h]
    simp [optMin, hmin]

theorem Bounds.get_set_self (b : Bounds) (k : String) (v : Nat) :
    (b.set k v).get k = some v := by
  induction b with
  | nil => simp [Bounds.set, Bounds.get]
  | cons kv rest ih =>
    by_cases h : kv.1 = k
    · simp [Bounds.set, Bounds.get, h]
    · simp [Bounds.set, Bounds.get, h, ih]

theorem Bounds.get_set_other (b : Bounds) (k k' : String) (v : Nat)
    (h : k ≠ k') : (b.set k v).get k' = b.get k' := by
  induction b with
  | nil => simp [Bounds.set, Bounds.get, h]
  | cons kv rest ih =>
    by_cases hk : kv.1 = k
    · subst hk
      simp [Bounds.set, Bounds.get, h]
    · simp [Bounds.set, Bounds.get, hk, ih]

/-- The invariant: accumulator-plus-output proves exactly what
accumulator-plus-input proves, for every wire. -/
theorem dedupGo_bound (bound : Bounds) (l : List Instr) (id : String) :
    optMin (bound.get id) (streamBound id (dedupGo bound l))
      = optMin (bound.get id) (streamBound id l) := by
  induction l generalizing bound with
  | nil => rfl
  | cons i rest ih =>
    cases heq : established i with
    | none =>
      simp only [dedupGo, streamBound, heq]
      exact ih bound
    | some p =>
      obtain ⟨id', bits⟩ := p
      cases hget : Bounds.get bound id' with
      | some proven =>
        by_cases hle : proven ≤ bits
        · -- DROPPED: the accumulator already proves `proven ≤ bits`.
          simp only [dedupGo, heq, hget, if_pos hle]
          rw [ih bound]
          by_cases hid : id' = id
          · subst hid
            simp only [streamBound, heq, reduceIte]
            rw [hget, optMin_absorb proven bits hle]
          · simp only [streamBound, heq, if_neg hid]
        · -- KEPT, tighter: recurse with the accumulator updated to `bits`.
          simp only [dedupGo, heq, hget, if_neg hle]
          have key := ih (Bounds.set bound id' bits)
          by_cases hid : id' = id
          · subst hid
            rw [Bounds.get_set_self] at key
            simp only [streamBound, heq, reduceIte]
            rw [key]
          · rw [Bounds.get_set_other bound id' id bits hid] at key
            simp only [streamBound, heq, if_neg hid]
            exact key
      | none =>
        -- KEPT, first constraint on this wire.
        simp only [dedupGo, heq, hget]
        have key := ih (Bounds.set bound id' bits)
        by_cases hid : id' = id
        · subst hid
          rw [Bounds.get_set_self] at key
          simp only [streamBound, heq, reduceIte]
          rw [hget]
          simpa [optMin] using key
        · rw [Bounds.get_set_other bound id' id bits hid] at key
          simp only [streamBound, heq, if_neg hid]
          exact key

/-- The headline: `dedup` preserves every wire\'s tightest bound, hence
its solution set. -/
theorem dedup_bound (l : List Instr) (id : String) :
    streamBound id (dedup l) = streamBound id l := by
  have h := dedupGo_bound [] l id
  simp only [Bounds.get, optMin] at h
  show streamBound id (dedupGo [] l) = streamBound id l
  exact h

/-! ## Theorem 4: idempotence — a deduplicated stream has nothing left
to drop. -/

theorem dedupGo_idem (bound : Bounds) (l : List Instr) :
    dedupGo bound (dedupGo bound l) = dedupGo bound l := by
  induction l generalizing bound with
  | nil => rfl
  | cons i rest ih =>
    cases heq : established i with
    | none =>
      simp only [dedupGo, heq]
      rw [ih bound]
    | some p =>
      obtain ⟨id', bits⟩ := p
      cases hget : Bounds.get bound id' with
      | some proven =>
        by_cases hle : proven ≤ bits
        · simp only [dedupGo, heq, hget, if_pos hle]
          exact ih bound
        · simp only [dedupGo, heq, hget, if_neg hle]
          rw [ih (Bounds.set bound id' bits)]
      | none =>
        simp only [dedupGo, heq, hget]
        rw [ih (Bounds.set bound id' bits)]

theorem dedup_idem (l : List Instr) : dedup (dedup l) = dedup l :=
  dedupGo_idem [] l

end MinocrabProofs
