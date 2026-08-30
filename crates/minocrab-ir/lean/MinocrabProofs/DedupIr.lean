/-
`dedup_range_constraints` over the REAL IR (M27 rung 3, the pass prong;
notes/zkir-semantics.org §4.4): the four M25 theorems of `Passes.lean`
restated on `MinocrabZkir.Instr` — the 33-constructor inductive that
round-trips the corpus byte for byte — instead of the three-constructor
model. The algorithm is the same transcription of `passes.rs`; only
`established` now inspects the real constructors, and "everything else
passes through" is a statement about the 31 other constructors rather
than one `other` tag. The proofs are the M25 proofs unchanged: they were
already parametric in what `established` returns `none` for, which is
the model-gap closure this file exists to record.

THE REMAINING GAP is the one every Lean file here states: this warrants
the algorithm as transcribed; that `passes.rs` implements it rests on
review and the Rust-side instruments.
-/
import MinocrabZkir.Syntax

namespace MinocrabProofs.DedupIr

open MinocrabZkir

/-- `passes.rs`'s `established` on the real instruction set: a
wire-keyed `constrain_bits` proves `val < 2^bits`; `constrain_to_boolean`
is the one-bit family; everything else — constraints on immediates
included — keys no wire. -/
def established : Instr → Option (Ident × Nat)
  | .constrainBits (.var n) b => some (n, b)
  | .constrainToBoolean (.var n) => some (n, 1)
  | _ => none

abbrev Bounds := List (Ident × Nat)

def Bounds.get : Bounds → Ident → Option Nat
  | [], _ => none
  | (k, v) :: rest, key => if k = key then some v else Bounds.get rest key

def Bounds.set : Bounds → Ident → Nat → Bounds
  | [], key, value => [(key, value)]
  | (k, v) :: rest, key, value =>
    if k = key then (k, value) :: rest else (k, v) :: Bounds.set rest key value

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

def optMin : Option Nat → Option Nat → Option Nat
  | none, b => b
  | a, none => a
  | some a, some b => some (min a b)

def streamBound (id : Ident) : List Instr → Option Nat
  | [] => none
  | i :: rest =>
    match established i with
    | some (id', bits) =>
      if id' = id then optMin (some bits) (streamBound id rest)
      else streamBound id rest
    | none => streamBound id rest

theorem optMin_absorb (p b : Nat) (h : p ≤ b) (x : Option Nat) :
    optMin (some p) (optMin (some b) x) = optMin (some p) x := by
  cases x with
  | none => simp [optMin, Nat.min_eq_left h]
  | some v =>
    have hmin : min p (min b v) = min p v := by
      rw [← Nat.min_assoc, Nat.min_eq_left h]
    simp [optMin, hmin]

theorem Bounds.get_set_self (b : Bounds) (k : Ident) (v : Nat) :
    (b.set k v).get k = some v := by
  induction b with
  | nil => simp [Bounds.set, Bounds.get]
  | cons kv rest ih =>
    by_cases h : kv.1 = k
    · simp [Bounds.set, Bounds.get, h]
    · simp [Bounds.set, Bounds.get, h, ih]

theorem Bounds.get_set_other (b : Bounds) (k k' : Ident) (v : Nat)
    (h : k ≠ k') : (b.set k v).get k' = b.get k' := by
  induction b with
  | nil => simp [Bounds.set, Bounds.get, h]
  | cons kv rest ih =>
    by_cases hk : kv.1 = k
    · subst hk
      simp [Bounds.set, Bounds.get, h]
    · simp [Bounds.set, Bounds.get, hk, ih]

theorem dedupGo_bound (bound : Bounds) (l : List Instr) (id : Ident) :
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
        · simp only [dedupGo, heq, hget, if_pos hle]
          rw [ih bound]
          by_cases hid : id' = id
          · subst hid
            simp only [streamBound, heq, reduceIte]
            rw [hget, optMin_absorb proven bits hle]
          · simp only [streamBound, heq, if_neg hid]
        · simp only [dedupGo, heq, hget, if_neg hle]
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

theorem dedup_bound (l : List Instr) (id : Ident) :
    streamBound id (dedup l) = streamBound id l := by
  have h := dedupGo_bound [] l id
  simp only [Bounds.get, optMin] at h
  show streamBound id (dedupGo [] l) = streamBound id l
  exact h

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

end MinocrabProofs.DedupIr
