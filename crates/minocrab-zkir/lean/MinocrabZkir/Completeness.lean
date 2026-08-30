/-
COMPLETENESS of the constraint reading (M27 rung 3 gate item;
notes/zkir-semantics.org §4.2): an honest evaluation satisfies the
constraints — `run M P π = .ok r → Sat M P r.pis r.memory` — on SSA
programs (the corpus is, by `zkir-wellformed`) whose `impact` inputs
are native wires (in-circuit resolves and converts them even when the
guard is off; off-circuit never looks — §10 I5). Proved instruction by
instruction (`step_sat`), then along the fold.

NOT soundness: the other direction fails exactly at §4.3's list.
-/
import MinocrabZkir.Constraint

namespace MinocrabZkir.Constraint

open Eval

variable {C : Carriers} (M : Model C)

/-! ## `Except` inversion -/

theorem bind_eq_ok {α β ε} (x : Except ε α) (f : α → Except ε β) (c : β) :
    (x >>= f) = .ok c ↔ ∃ b, x = .ok b ∧ f b = .ok c := by
  cases x <;> simp [Bind.bind, Except.bind]

theorem bind'_eq_ok {α β ε} (x : Except ε α) (f : α → Except ε β) (c : β) :
    Except.bind x f = .ok c ↔ ∃ b, x = .ok b ∧ f b = .ok c := by
  cases x <;> simp [Except.bind]

theorem pure_eq_ok {α ε} (a c : α) : (pure a : Except ε α) = .ok c ↔ a = c := by
  simp [pure, Except.pure]

theorem throw_eq_ok {α ε} (e : ε) (c : α) : (throw e : Except ε α) = .ok c ↔ False := by
  simp [throw, throwThe, MonadExceptOf.throw]

theorem error_eq_ok {α ε} (e : ε) (c : α) : (Except.error e : Except ε α) = .ok c ↔ False := by
  simp

macro "step_simp" h:ident : tactic =>
  `(tactic| simp only [bind_eq_ok, bind'_eq_ok, pure_eq_ok, throw_eq_ok, exists_eq_left,
      exists_eq_left', false_and, and_false, true_and, and_true, exists_false, exists_const,
      Bool.false_eq_true, eq_self_iff_true, ↓reduceIte, if_true, if_false, reduceCtorEq,
      error_eq_ok] at $h:ident)

/-- A branch that must be a reject: close it however the hypothesis reads. -/
macro "close_throw" h:ident : tactic =>
  `(tactic| first | exact ($h:ident).elim | (step_simp $h:ident; done) | (simp at $h:ident; done))

macro "unfold_step" h:ident : tactic =>
  `(tactic| (simp only [step] at $h:ident; try step_simp $h:ident))

/-! ## Assignments -/

theorem lookup_cons (id id' : Ident) (v : Value C) (m : Assignment C) :
    lookup ((id, v) :: m) id' = if id = id' then some v else lookup m id' := by
  unfold lookup
  by_cases h : id = id' <;> simp [List.find?_cons, h]

/-- `m'` sees every binding of `m`. -/
def Sub (m m' : Assignment C) : Prop := ∀ id v, lookup m id = some v → lookup m' id = some v

theorem Sub.rfl (m : Assignment C) : Sub m m := fun _ _ h => h

theorem Sub.trans {a b c : Assignment C} (h1 : Sub a b) (h2 : Sub b c) : Sub a c :=
  fun id v h => h2 id v (h1 id v h)

theorem lookup_cons_self (id : Ident) (v : Value C) (m : Assignment C) :
    lookup ((id, v) :: m) id = some v := by
  rw [lookup_cons, if_pos rfl]

theorem lookup_cons_other (id id' : Ident) (v : Value C) (m : Assignment C) (h : id ≠ id') :
    lookup ((id, v) :: m) id' = lookup m id' := by
  rw [lookup_cons, if_neg h]

theorem Sub.cons (m : Assignment C) (id : Ident) (v : Value C) (hfresh : lookup m id = none) :
    Sub m ((id, v) :: m) := by
  intro id' v' h
  rw [lookup_cons]
  split
  · rename_i he; subst he; rw [hfresh] at h; cases h
  · exact h

/-! ## Resolution under a larger assignment -/

theorem val_of_resolve (st : State C) (o : Operand) (v : Value C) (h : resolve st o = .ok v)
    (m : Assignment C) (hs : Sub st.memory m) : val m o = some v := by
  cases o with
  | var id =>
    simp only [resolve] at h
    split at h
    · rename_i w hw
      simp only [pure_eq_ok] at h
      subst h
      exact hs _ _ hw
    · simp [throw_eq_ok] at h
  | imm i =>
    simp only [resolve, pure_eq_ok] at h
    subst h
    rfl

theorem asNative_ok (v : Value C) (x : Fr) : asNative v = .ok x ↔ v = .native x := by
  cases v <;> simp [asNative, pure_eq_ok, throw_eq_ok]

theorem asBytes32_ok (v : Value C) (b : Bytes32) : asBytes32 v = .ok b ↔ v = .bytes32 b := by
  cases v <;> simp [asBytes32, pure_eq_ok, throw_eq_ok]

theorem resolveBool_ok (st : State C) (o : Operand) (g : Bool)
    (h : resolveBool st o = .ok g) : resolve st o = .ok (bitVal g) := by
  simp only [resolveBool, bind_eq_ok] at h
  obtain ⟨v, hv, x, hx, h⟩ := h
  rw [asNative_ok] at hx
  subst hx
  by_cases h0 : x = 0
  · rw [if_pos h0, pure_eq_ok] at h
    subst h
    rw [h0] at hv
    exact hv
  · by_cases h1 : x = 1
    · rw [if_neg h0, if_pos h1, pure_eq_ok] at h
      subst h
      rw [h1] at hv
      exact hv
    · rw [if_neg h0, if_neg h1, throw_eq_ok] at h
      exact h.elim

theorem checkBits_ok (x : Fr) (n : Nat) {u : Unit} (h : checkBits x n = .ok u) :
    n < frBits ∧ x.val < 2 ^ n := by
  unfold checkBits at h
  by_cases h1 : n ≥ frBits
  · simp [h1, bind_eq_ok, throw_eq_ok] at h
  · by_cases h2 : x.val ≥ 2 ^ n
    · simp [h1, h2, bind_eq_ok, throw_eq_ok] at h
    · omega

theorem nats_of_mapM (st : State C) (m : Assignment C) (hs : Sub st.memory m) :
    ∀ (inputs : List Operand) (xs : List Fr),
      inputs.mapM (fun o => do asNative (← resolve st o)) = .ok xs → nats m inputs xs := by
  intro inputs
  induction inputs with
  | nil =>
    intro xs h
    simp [pure_eq_ok] at h
    subst h
    trivial
  | cons o os ih =>
    intro xs h
    simp only [List.mapM_cons, bind_eq_ok, pure_eq_ok] at h
    obtain ⟨x, hx, ys, hys, h⟩ := h
    subst h
    obtain ⟨v, hv, hx⟩ := hx
    rw [asNative_ok] at hx
    subst hx
    exact ⟨val_of_resolve st o _ hv m hs, ih ys hys⟩

theorem nats_length (m : Assignment C) :
    ∀ (inputs : List Operand) (xs : List Fr), nats m inputs xs → xs.length = inputs.length := by
  intro inputs
  induction inputs with
  | nil => intro xs h; cases xs with | nil => rfl | cons _ _ => exact absurd h (by simp [nats])
  | cons o os ih =>
    intro xs h
    cases xs with
    | nil => exact absurd h (by simp [nats])
    | cons x xs' => simp [ih xs' h.2]

theorem nats_exists (m : Assignment C) :
    ∀ (inputs : List Operand), (∀ o ∈ inputs, ∃ x, val m o = some (.native x)) →
      ∃ xs, nats m inputs xs := by
  intro inputs
  induction inputs with
  | nil => intro _; exact ⟨[], trivial⟩
  | cons o os ih =>
    intro h
    obtain ⟨x, hx⟩ := h o (List.mem_cons_self ..)
    obtain ⟨xs, hxs⟩ := ih (fun o' ho' => h o' (List.mem_cons_of_mem _ ho'))
    exact ⟨x :: xs, hx, hxs⟩

theorem outputs_of_mapM (st : State C) (m : Assignment C) (hs : Sub st.memory m) :
    ∀ (l : List (Operand × IrType)) (vs : List (Value C)),
      l.mapM (fun (o, ty) => do
        let v ← resolve st o
        if v.type ≠ ty then throw "Output: operand type differs from signature"
        pure v) = .ok vs →
      ∀ oty ∈ l, ∃ v, val m oty.1 = some v ∧ v.type = oty.2 := by
  intro l
  induction l with
  | nil => intro vs _ oty h; cases h
  | cons oty rest ih =>
    intro vs h oty' hmem
    obtain ⟨o, ty⟩ := oty
    simp only [List.mapM_cons, bind_eq_ok, pure_eq_ok] at h
    obtain ⟨v, hv, vs', hvs', _⟩ := h
    rcases List.mem_cons.mp hmem with rfl | hmem'
    · obtain ⟨w, hw, hv⟩ := hv
      split at hv
      · step_simp hv
      · rename_i hty
        step_simp hv
        subst hv
        exact ⟨w, val_of_resolve st o w hw m hs, by simpa using hty⟩
    · exact ih vs' hvs' oty' hmem'

/-! ## Closing a step: the memory/PI conclusions from the state shape -/

/-- What every step yields for the fold: nothing already bound changes,
nothing outside the instruction's definitions is touched, the PI vector
only grows. -/
def StepShape (st st' : State C) (defs : List Ident) (n : Nat) : Prop :=
  Sub st.memory st'.memory ∧ (∀ id, id ∉ defs → lookup st'.memory id = lookup st.memory id)
    ∧ st.pis <+: st'.pis ∧ st'.pis.length = st.pis.length + n

theorem close_none (st st' : State C) (defs : List Ident)
    (hm : st'.memory = st.memory) (hp : st'.pis = st.pis) :
    StepShape st st' defs 0 := by
  rw [StepShape, hm, hp]
  exact ⟨Sub.rfl _, fun _ _ => rfl, List.prefix_rfl, rfl⟩

theorem close_one (st st' : State C) (out : Ident) (r : Value C)
    (hm : st'.memory = (out, r) :: st.memory) (hp : st'.pis = st.pis)
    (hfresh : lookup st.memory out = none) :
    StepShape st st' [out] 0 ∧ ∀ m, Sub st'.memory m → bound m out r := by
  rw [StepShape, hm, hp]
  refine ⟨⟨Sub.cons _ _ _ hfresh, ?_, List.prefix_rfl, rfl⟩, ?_⟩
  · intro id hid
    exact lookup_cons_other _ _ _ _ (fun he => hid (he ▸ List.mem_singleton_self _))
  · intro m hs
    exact hs _ _ (lookup_cons_self _ _ _)

/-- `close_one` for the state `step` literally produces. -/
theorem close_insert (st : State C) (out : Ident) (r : Value C)
    (hfresh : lookup st.memory out = none) :
    StepShape st (st.insert out r) [out] 0 ∧ ∀ m, Sub (st.insert out r).memory m → bound m out r :=
  close_one st (st.insert out r) out r rfl rfl hfresh

theorem two_defs (a b : Ident) (h : [a, b].Nodup) : a ≠ b := by
  intro he; subst he; simp at h

theorem close_two (st : State C) (o1 o2 : Ident) (r1 r2 : Value C)
    (hne : o1 ≠ o2) (hf1 : lookup st.memory o1 = none) (hf2 : lookup st.memory o2 = none) :
    StepShape st ((st.insert o1 r1).insert o2 r2) [o1, o2] 0
      ∧ ∀ m, Sub ((st.insert o1 r1).insert o2 r2).memory m → bound m o1 r1 ∧ bound m o2 r2 := by
  show StepShape st _ [o1, o2] 0 ∧ ∀ m, Sub ((o2, r2) :: (o1, r1) :: st.memory) m → _
  have hf2' : lookup ((o1, r1) :: st.memory) o2 = none := by
    rw [lookup_cons_other _ _ _ _ hne]; exact hf2
  refine ⟨⟨(Sub.cons _ _ _ hf1).trans (Sub.cons _ _ _ hf2'), ?_, List.prefix_rfl, rfl⟩, ?_⟩
  · intro id hid
    have h1 : o1 ≠ id := fun e => hid (by simp [e])
    have h2 : o2 ≠ id := fun e => hid (by simp [e])
    show lookup ((o2, r2) :: (o1, r1) :: st.memory) id = lookup st.memory id
    rw [lookup_cons_other _ _ _ _ h2, lookup_cons_other _ _ _ _ h1]
  · intro m hs
    refine ⟨hs _ _ ?_, hs _ _ (lookup_cons_self _ _ _)⟩
    rw [lookup_cons_other _ _ _ _ (Ne.symm hne)]
    exact lookup_cons_self _ _ _

/-- `encode`'s fold of inserts. -/
theorem foldl_insert (st : State C) :
    ∀ (l : List (Ident × Fr)),
      (l.map (·.1)).Nodup → (∀ o ∈ l.map (·.1), lookup st.memory o = none) →
      let st' := l.foldl (fun st (o, x) => st.insert o (.native x)) st
      Sub st.memory st'.memory ∧ (∀ id, id ∉ l.map (·.1) → lookup st'.memory id = lookup st.memory id)
        ∧ st'.pis = st.pis
        ∧ ∀ ox ∈ l, lookup st'.memory ox.1 = some (.native ox.2) := by
  intro l
  induction l generalizing st with
  | nil => intro _ _; exact ⟨Sub.rfl _, fun _ _ => rfl, rfl, by simp⟩
  | cons ox rest ih =>
    intro hnd hfresh
    obtain ⟨o, x⟩ := ox
    simp only [List.foldl_cons]
    simp only [List.map_cons, List.nodup_cons, List.mem_cons, forall_eq_or_imp] at hnd hfresh
    have hfresh' : ∀ o' ∈ rest.map (·.1), lookup (st.insert o (.native x)).memory o' = none := by
      intro o' ho'
      show lookup ((o, .native x) :: st.memory) o' = none
      rw [lookup_cons_other _ _ _ _ (fun he => hnd.1 (by subst he; exact ho'))]
      exact hfresh.2 o' ho'
    obtain ⟨s1, s2, s3, s4⟩ := ih (st.insert o (.native x)) hnd.2 hfresh'
    refine ⟨(Sub.cons _ _ _ hfresh.1).trans s1, ?_, s3, ?_⟩
    · intro id hid
      simp only [List.map_cons, List.mem_cons, not_or] at hid
      rw [s2 id hid.2]
      exact lookup_cons_other _ _ _ _ (Ne.symm hid.1)
    · intro ox' hox'
      rcases List.mem_cons.mp hox' with rfl | hmem
      · exact s1 _ _ (lookup_cons_self _ _ _)
      · exact s4 _ hmem

/-! ## PI facts -/

theorem getElem?_of_prefix (l₁ l₂ : List Fr) (h : l₁ <+: l₂) (k : Nat) (hk : k < l₁.length) :
    l₂[k]? = l₁[k]? := by
  obtain ⟨t, rfl⟩ := h
  rw [List.getElem?_append_left hk]

theorem impactSat_of (m : Assignment C) (g : Bool) (suf : List Fr) :
    ∀ (inputs : List Operand) (xs : List Fr) (pre : List Fr), nats m inputs xs →
      impactSat m g (pre ++ (if g then xs else List.replicate xs.length 0) ++ suf) pre.length inputs := by
  intro inputs
  induction inputs with
  | nil =>
    intro xs pre h
    cases xs with
    | nil => trivial
    | cons _ _ => exact absurd h (by simp [nats])
  | cons o os ih =>
    intro xs pre h
    cases xs with
    | nil => exact absurd h (by simp [nats])
    | cons x xs' =>
      obtain ⟨hx, hrest⟩ := h
      have hsplit : pre ++ (if g then x :: xs' else List.replicate (x :: xs').length 0) ++ suf
          = (pre ++ [if g then x else 0]) ++ (if g then xs' else List.replicate xs'.length 0) ++ suf := by
        cases g <;> simp [List.replicate_succ]
      rw [hsplit]
      refine ⟨⟨x, hx, ?_⟩, ?_⟩
      · rw [List.append_assoc, List.append_assoc, List.getElem?_append_right (Nat.le_refl _)]
        simp
      · have := ih xs' (pre ++ [if g then x else 0]) hrest
        simpa using this

theorem impactSat_mono (m : Assignment C) (g : Bool) :
    ∀ (inputs : List Operand) (k : Nat) (pis pis' : List Fr), pis <+: pis' →
      impactSat m g pis k inputs → impactSat m g pis' k inputs := by
  intro inputs
  induction inputs with
  | nil => intros; trivial
  | cons o os ih =>
    intro k pis pis' hp h
    obtain ⟨⟨x, hx, hk⟩, hrest⟩ := h
    refine ⟨⟨x, hx, ?_⟩, ih _ _ _ hp hrest⟩
    have hlt : k < pis.length := by
      rcases Nat.lt_or_ge k pis.length with hl | hge
      · exact hl
      · rw [List.getElem?_eq_none hge] at hk; cases hk
    rw [getElem?_of_prefix pis pis' hp k hlt]
    exact hk

/-- The `reconstitute_field` identity: the off-circuit composite (a
natural below `p`) is the in-circuit linear combination. -/
theorem ofNat_recon (dv mv : Fr) (bits : Nat) :
    Fr.ofNat (dv.val * 2 ^ bits + mv.val) = mv + Fr.ofNat (2 ^ bits) * dv := by
  apply Fin.ext
  simp only [Fr.ofNat, Fin.val_add, Fin.val_mul]
  conv => rhs; rw [Nat.add_mod, Nat.mul_mod, Nat.mod_mod, Nat.mod_mod]
  conv => lhs; rw [Nat.add_mod, Nat.mul_mod]
  rw [Nat.mul_comm (dv.val % p), Nat.add_comm]

theorem bits_le_ltWidth (bits : Nat) : bits ≤ ltWidth bits :=
  Nat.le_trans (Nat.le_add_right _ _) (Nat.le_max_left _ _)

theorem lt_pow_ltWidth (x : Fr) (bits : Nat) (h : x.val < 2 ^ bits) : x.val < 2 ^ ltWidth bits :=
  Nat.lt_of_lt_of_le h (Nat.pow_le_pow_right (by decide) (bits_le_ltWidth bits))

/-- The operands an `impact` pushes (resolved in-circuit whatever the guard). -/
def impactInputsOf : Instr → List Operand
  | .impact _ inputs => inputs
  | _ => []

/-! ## The per-instruction lemma -/

theorem Sub.of_insert {st : State C} {out : Ident} {r : Value C} {m : Assignment C}
    (hf : lookup st.memory out = none) (hs : Sub (st.insert out r).memory m) : Sub st.memory m :=
  (Sub.cons _ _ _ hf).trans hs

theorem bound_of_insert {st : State C} {out : Ident} {r : Value C} {m : Assignment C}
    (hs : Sub (st.insert out r).memory m) : bound m out r :=
  hs _ _ (lookup_cons_self _ _ _)

theorem step_sat (P : Program) (π : Preimage) (st st' : State C) (i : Instr)
    (h : step M P π st i = .ok st')
    (hnd : i.defines.Nodup) (hfresh : ∀ id ∈ i.defines, lookup st.memory id = none) :
    StepShape st st' i.defines (advance i)
      ∧ ∀ m, Sub st'.memory m → (∀ o ∈ impactInputsOf i, ∃ x, val m o = some (.native x)) →
        ∀ pis, st'.pis <+: pis → SatInstr M P m pis st.pis.length i := by
  cases i with
  | encode outs input =>
    unfold_step h
    obtain ⟨v, hv, h⟩ := h
    split at h
    · close_throw h
    · rename_i hlen
      step_simp h
      subst h
      simp only [Instr.defines] at hnd hfresh ⊢
      have hlen' : outs.length ≤ (encode M v).length := by omega
      obtain ⟨s1, s2, s3, s4⟩ := foldl_insert st (outs.zip (encode M v))
        (by rw [List.map_fst_zip hlen']; exact hnd)
        (by rw [List.map_fst_zip hlen']; exact hfresh)
      refine ⟨⟨s1, ?_, s3 ▸ List.prefix_rfl, by rw [s3]; rfl⟩, ?_⟩
      · intro id hid
        apply s2
        rw [List.map_fst_zip hlen']; exact hid
      · intro m hs _ pis _
        refine ⟨v, val_of_resolve st input v hv m (s1.trans hs), by omega, ?_⟩
        intro ox hox
        exact hs _ _ (s4 ox hox)
  | assert cond =>
    unfold_step h
    obtain ⟨g, hg, h⟩ := h
    have hg' := resolveBool_ok st cond g hg
    revert h
    cases g <;> intro h <;> step_simp h
    subst h
    refine ⟨close_none st st _ rfl rfl, ?_⟩
    intro m hs _ pis _
    exact ⟨1, val_of_resolve st cond _ hg' m hs, by decide⟩
  | condSelect out bit a b =>
    unfold_step h
    obtain ⟨g, hg, va, hva, vb, hvb, h⟩ := h
    split at h
    · close_throw h
    · rename_i hty
      step_simp h
      subst h
      refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
      intro m hs _ pis _
      have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
      have s4 := bound_of_insert hs
      exact ⟨g, va, vb, val_of_resolve st bit _ (resolveBool_ok st bit g hg) m hs',
        val_of_resolve st a _ hva m hs', val_of_resolve st b _ hvb m hs',
        by simpa using hty, s4⟩
  | constrainBits v bits =>
    unfold_step h
    obtain ⟨w, hw, x, hx, u, hu, h⟩ := h
    rw [asNative_ok] at hx
    subst hx
    subst h
    refine ⟨close_none st st _ rfl rfl, ?_⟩
    intro m hs _ pis _
    exact ⟨x, val_of_resolve st v _ hw m hs, Or.inr (checkBits_ok x bits hu).2⟩
  | constrainEq a b =>
    unfold_step h
    obtain ⟨va, hva, vb, hvb, e, he, h⟩ := h
    revert h
    cases e <;> intro h <;> step_simp h
    subst h
    refine ⟨close_none st st _ rfl rfl, ?_⟩
    intro m hs _ pis _
    exact ⟨va, vb, val_of_resolve st a _ hva m hs, val_of_resolve st b _ hvb m hs, he⟩
  | constrainToBoolean v =>
    unfold_step h
    obtain ⟨g, hg, h⟩ := h
    subst h
    refine ⟨close_none st st _ rfl rfl, ?_⟩
    intro m hs _ pis _
    exact ⟨bitVal g, val_of_resolve st v _ (resolveBool_ok st v g hg) m hs, g, rfl⟩
  | copy out v =>
    unfold_step h
    obtain ⟨x, hx, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨x, val_of_resolve st v _ hx m hs', s4⟩
  | impact guard inputs =>
    unfold_step h
    obtain ⟨g, hg, h⟩ := h
    have hg' := resolveBool_ok st guard g hg
    revert h
    cases g <;> intro h <;> step_simp h
    · -- guarded off: n zeros pushed; the inputs are not looked at
      subst h
      refine ⟨⟨Sub.rfl _, fun _ _ => rfl, List.prefix_append _ _, by simp [advance]⟩, ?_⟩
      intro m hs hnat pis hp
      simp only [impactInputsOf] at hnat
      refine ⟨false, val_of_resolve st guard _ hg' m hs, ?_⟩
      obtain ⟨xs, hxs⟩ := nats_exists m inputs hnat
      have hlen := nats_length m inputs xs hxs
      have := impactSat_of m false [] inputs xs st.pis hxs
      simp only [Bool.false_eq_true, ↓reduceIte, List.append_nil, hlen] at this
      exact impactSat_mono m false inputs _ _ _ hp this
    · obtain ⟨xs, hxs, h⟩ := h
      split at h
      · step_simp h
        subst h
        have hn := nats_of_mapM st st.memory (Sub.rfl _) inputs xs hxs
        have hlen := nats_length st.memory inputs xs hn
        refine ⟨⟨Sub.rfl _, fun _ _ => rfl, List.prefix_append _ _, by simp [advance, hlen]⟩, ?_⟩
        intro m hs _ pis hp
        refine ⟨true, val_of_resolve st guard _ hg' m hs, ?_⟩
        have hn' := nats_of_mapM st m hs inputs xs hxs
        have := impactSat_of m true [] inputs xs st.pis hn'
        simp only [↓reduceIte, List.append_nil] at this
        exact impactSat_mono m true inputs _ _ _ hp this
      · close_throw h
  | ecMul out a s =>
    unfold_step h
    obtain ⟨pt, hpt, sc, hsc, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨pt, sc, r, val_of_resolve st a _ hpt m hs',
      val_of_resolve st s _ hsc m hs', hr, s4⟩
  | ecMulGenerator out s =>
    unfold_step h
    obtain ⟨sc, hsc, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨sc, r, val_of_resolve st s _ hsc m hs', hr, s4⟩
  | hashToCurve out inputs =>
    unfold_step h
    obtain ⟨xs, hxs, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨xs, nats_of_mapM st m hs' inputs xs hxs, s4⟩
  | intoCoordinates outs pt =>
    obtain ⟨ox, oy⟩ := outs
    unfold_step h
    obtain ⟨v, hv, xy, hxy, h⟩ := h
    obtain ⟨x, y⟩ := xy
    simp only [pure_eq_ok] at h
    subst h
    simp only [Instr.defines] at hnd hfresh
    obtain ⟨sh, s4⟩ := close_two st ox oy x y (two_defs _ _ hnd) (hfresh ox (by simp)) (hfresh oy (by simp))
    refine ⟨sh, ?_⟩
    intro m hs _ pis _
    exact ⟨v, x, y, val_of_resolve st pt _ hv m (sh.1.trans hs), hxy, (s4 m hs).1, (s4 m hs).2⟩
  | fromCoordinates out ins =>
    obtain ⟨ix, iy⟩ := ins
    unfold_step h
    obtain ⟨x, hx, y, hy, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨x, y, r, val_of_resolve st ix _ hx m hs',
      val_of_resolve st iy _ hy m hs', hr, s4⟩
  | intoBytes32 out input =>
    unfold_step h
    obtain ⟨v, hv, b, hb, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨v, b, val_of_resolve st input _ hv m hs', hb, s4⟩
  | fromBytes32 ty out bytes =>
    unfold_step h
    obtain ⟨w, hw, b, hb, r, hr, h⟩ := h
    rw [asBytes32_ok] at hb
    subst hb
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨b, r, val_of_resolve st bytes _ hw m hs', hr, s4⟩
  | reverseBytes out bytes =>
    unfold_step h
    obtain ⟨w, hw, b, hb, h⟩ := h
    rw [asBytes32_ok] at hb
    subst hb
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨b, val_of_resolve st bytes _ hw m hs', s4⟩
  | bytes32IntoLowHigh outs bytes =>
    obtain ⟨lo, hi⟩ := outs
    unfold_step h
    obtain ⟨w, hw, b, hb, h⟩ := h
    rw [asBytes32_ok] at hb
    subst hb
    subst h
    simp only [Instr.defines] at hnd hfresh
    obtain ⟨sh, s4⟩ := close_two st lo hi _ _ (two_defs _ _ hnd) (hfresh lo (by simp)) (hfresh hi (by simp))
    refine ⟨sh, ?_⟩
    intro m hs _ pis _
    exact ⟨b, val_of_resolve st bytes _ hw m (sh.1.trans hs), (s4 m hs).1, (s4 m hs).2⟩
  | bytes32FromLowHigh out ins =>
    obtain ⟨ilo, ihi⟩ := ins
    unfold_step h
    obtain ⟨wl, hwl, lo, hlo, wh, hwh, hi, hhi, h⟩ := h
    rw [asNative_ok] at hlo hhi
    subst hlo hhi
    split at h
    · close_throw h
    · rename_i hrange
      step_simp h
      subst h
      simp only [not_or, Nat.not_le] at hrange
      refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
      intro m hs _ pis _
      have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
      have s4 := bound_of_insert hs
      exact ⟨lo, hi, val_of_resolve st ilo _ hwl m hs',
        val_of_resolve st ihi _ hwh m hs', hrange.1, hrange.2, s4⟩
  | divModPowerOfTwo outs v bits =>
    unfold_step h
    split at h
    · rename_i q r
      split at h
      · close_throw h
      · step_simp h
        obtain ⟨w, hw, x, hx, h⟩ := h
        rw [asNative_ok] at hx
        subst hx
        subst h
        simp only [Instr.defines] at hnd hfresh
        obtain ⟨sh, s4⟩ := close_two st q r _ _ (two_defs _ _ hnd) (hfresh q (by simp)) (hfresh r (by simp))
        refine ⟨sh, ?_⟩
        intro m hs _ pis _
        exact ⟨q, r, x, rfl, val_of_resolve st v _ hw m (sh.1.trans hs), (s4 m hs).1, (s4 m hs).2⟩
    · close_throw h
  | reconstituteField out d mo bits =>
    unfold_step h
    split at h
    · close_throw h
    · step_simp h
      obtain ⟨wm, hwm, mv, hmv, wd, hwd, dv, hdv, um, hum, ud, hud, h⟩ := h
      rw [asNative_ok] at hmv hdv
      subst hmv hdv
      split at h
      · close_throw h
      · step_simp h
        subst h
        refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
        intro m hs _ pis _
        have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
        have s4 := bound_of_insert hs
        refine ⟨dv, mv, val_of_resolve st d _ hwd m hs',
          val_of_resolve st mo _ hwm m hs', (checkBits_ok _ _ hud).2,
          (checkBits_ok _ _ hum).2, ?_⟩
        rw [← ofNat_recon]
        exact s4
  | transientHash out inputs =>
    unfold_step h
    obtain ⟨xs, hxs, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨xs, nats_of_mapM st m hs' inputs xs hxs, s4⟩
  | persistentHash out al inputs =>
    unfold_step h
    obtain ⟨xs, hxs, bs, hbs, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨xs, bs, nats_of_mapM st m hs' inputs xs hxs, hbs, s4⟩
  | keccak256 out al inputs =>
    unfold_step h
    obtain ⟨xs, hxs, bs, hbs, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨xs, bs, nats_of_mapM st m hs' inputs xs hxs, hbs, s4⟩
  | testEq out a b =>
    unfold_step h
    obtain ⟨va, hva, vb, hvb, e, he, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨va, vb, e, val_of_resolve st a _ hva m hs',
      val_of_resolve st b _ hvb m hs', he, s4⟩
  | add out a b =>
    unfold_step h
    obtain ⟨va, hva, vb, hvb, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨va, vb, r, val_of_resolve st a _ hva m hs',
      val_of_resolve st b _ hvb m hs', hr, s4⟩
  | mul out a b =>
    unfold_step h
    obtain ⟨va, hva, vb, hvb, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨va, vb, r, val_of_resolve st a _ hva m hs',
      val_of_resolve st b _ hvb m hs', hr, s4⟩
  | neg out a =>
    unfold_step h
    obtain ⟨va, hva, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨va, r, val_of_resolve st a _ hva m hs', hr, s4⟩
  | inv out a =>
    unfold_step h
    obtain ⟨va, hva, r, hr, h⟩ := h
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨va, r, val_of_resolve st a _ hva m hs', hr, s4⟩
  | not out a =>
    unfold_step h
    obtain ⟨g, hg, h⟩ := h
    subst h
    have hg' := resolveBool_ok st a g hg
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    refine ⟨g, val_of_resolve st a _ hg' m hs', ?_⟩
    have := s4
    cases g <;> simpa [bitVal] using this
  | lessThan out a b bits =>
    unfold_step h
    obtain ⟨wa, hwa, x, hx, wb, hwb, y, hy, ux, hux, uy, huy, h⟩ := h
    rw [asNative_ok] at hx hy
    subst hx hy
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨x, y, val_of_resolve st a _ hwa m hs', val_of_resolve st b _ hwb m hs',
      lt_pow_ltWidth x bits (checkBits_ok _ _ hux).2, lt_pow_ltWidth y bits (checkBits_ok _ _ huy).2,
      s4⟩
  | jubjubScalarFromNative out n =>
    unfold_step h
    obtain ⟨w, hw, x, hx, h⟩ := h
    rw [asNative_ok] at hx
    subst hx
    subst h
    refine ⟨(close_insert st out _ (hfresh out (by simp [Instr.defines]))).1, ?_⟩
    intro m hs _ pis _
    have hs' := Sub.of_insert (hfresh out (by simp [Instr.defines])) hs
    have s4 := bound_of_insert hs
    exact ⟨x, val_of_resolve st n _ hw m hs', s4⟩
  | publicInput ty out guard =>
    have : ∃ v, st'.memory = (out, v) :: st.memory ∧ st'.pis = st.pis := by
      unfold_step h
      cases guard with
      | none =>
        try step_simp h
        obtain ⟨raw, _, v, _, h⟩ := h
        subst h
        exact ⟨v, rfl, rfl⟩
      | some g =>
        try step_simp h
        obtain ⟨b, _, h⟩ := h
        revert h
        cases b <;> intro h <;> step_simp h
        · subst h; exact ⟨_, rfl, rfl⟩
        · obtain ⟨raw, _, v, _, h⟩ := h
          subst h
          exact ⟨v, rfl, rfl⟩
    obtain ⟨v, hm, hp⟩ := this
    obtain ⟨sh, s4⟩ := close_one st st' out v hm hp (hfresh out (by simp [Instr.defines]))
    exact ⟨sh, fun m hs _ pis _ => ⟨v, s4 m hs⟩⟩
  | privateInput ty out guard =>
    have : ∃ v, st'.memory = (out, v) :: st.memory ∧ st'.pis = st.pis := by
      unfold_step h
      cases guard with
      | none =>
        try step_simp h
        obtain ⟨raw, _, v, _, h⟩ := h
        subst h
        exact ⟨v, rfl, rfl⟩
      | some g =>
        try step_simp h
        obtain ⟨b, _, h⟩ := h
        revert h
        cases b <;> intro h <;> step_simp h
        · subst h; exact ⟨_, rfl, rfl⟩
        · obtain ⟨raw, _, v, _, h⟩ := h
          subst h
          exact ⟨v, rfl, rfl⟩
    obtain ⟨v, hm, hp⟩ := this
    obtain ⟨sh, s4⟩ := close_one st st' out v hm hp (hfresh out (by simp [Instr.defines]))
    exact ⟨sh, fun m hs _ pis _ => ⟨v, s4 m hs⟩⟩
  | output vals =>
    unfold_step h
    split at h
    · close_throw h
    · rename_i hlen
      step_simp h
      obtain ⟨vs, hvs, h⟩ := h
      subst h
      refine ⟨close_none st _ _ rfl rfl, ?_⟩
      intro m hs _ pis _
      exact ⟨by simpa using hlen, outputs_of_mapM st m hs _ vs hvs⟩

/-! ## Along the fold -/

theorem foldl_sat (P : Program) (π : Preimage) :
    ∀ (l : List Instr) (st st' : State C),
      l.foldlM (step M P π) st = .ok st' →
      (l.flatMap Instr.defines).Nodup →
      (∀ id ∈ l.flatMap Instr.defines, lookup st.memory id = none) →
      Sub st.memory st'.memory ∧ st.pis <+: st'.pis
        ∧ st'.pis.length = st.pis.length + totalAdvance l
        ∧ ∀ m, Sub st'.memory m →
            (∀ i ∈ l, ∀ o ∈ impactInputsOf i, ∃ x, val m o = some (.native x)) →
            ∀ pis, st'.pis <+: pis → SatBody M P m pis st.pis.length l := by
  intro l
  induction l with
  | nil =>
    intro st st' h _ _
    simp [pure_eq_ok] at h
    subst h
    exact ⟨Sub.rfl _, List.prefix_rfl, rfl, fun _ _ _ _ _ => trivial⟩
  | cons i rest ih =>
    intro st st' h hnd hfresh
    simp only [List.foldlM_cons, bind_eq_ok] at h
    obtain ⟨st1, h1, h⟩ := h
    simp only [List.flatMap_cons, List.nodup_append, List.mem_append] at hnd hfresh
    obtain ⟨hnd_i, hnd_rest, hdisj⟩ := hnd
    obtain ⟨⟨s1, s2, s3, s4⟩, ssat⟩ :=
      step_sat M P π st st1 i h1 hnd_i (fun id hid => hfresh id (Or.inl hid))
    have hfresh1 : ∀ id ∈ rest.flatMap Instr.defines, lookup st1.memory id = none := by
      intro id hid
      rw [s2 id (fun hi => hdisj id hi id hid rfl)]
      exact hfresh id (Or.inr hid)
    obtain ⟨t1, t2, t3, tsat⟩ := ih st1 st' h hnd_rest hfresh1
    refine ⟨s1.trans t1, s3.trans t2, by rw [t3, s4, totalAdvance, Nat.add_assoc], ?_⟩
    intro m hs hnat pis hp
    refine ⟨ssat m (t1.trans hs) (hnat i (List.mem_cons_self ..)) pis (t2.trans hp), ?_⟩
    have := tsat m hs (fun i' hi' => hnat i' (List.mem_cons_of_mem _ hi')) pis hp
    rw [s4] at this
    exact this

/-! ## The prologue -/

theorem prologueLoop_shape (π : Preimage) :
    ∀ (l : List (Ident × IrType)) (idx : Nat) (mem0 mem : List (Ident × Value C)) (idx' : Nat),
      prologueLoop M π l idx mem0 = .ok (mem, idx') →
      (∀ idty ∈ l, ∃ v, lookup mem idty.1 = some v)
        ∧ (∀ id, id ∉ l.map (·.1) → lookup mem id = lookup mem0 id) := by
  intro l
  induction l with
  | nil =>
    intro idx mem0 mem idx' h
    simp only [prologueLoop, pure_eq_ok, Prod.mk.injEq] at h
    obtain ⟨rfl, _⟩ := h
    exact ⟨fun _ h => (nomatch h), fun _ _ => rfl⟩
  | cons nt rest ih =>
    intro idx mem0 mem idx' h
    obtain ⟨name, ty⟩ := nt
    simp only [prologueLoop] at h
    split at h
    · close_throw h
    · step_simp h
      obtain ⟨v, _, h⟩ := h
      obtain ⟨ih1, ih2⟩ := ih _ _ _ _ h
      refine ⟨?_, ?_⟩
      · intro idty hmem
        rcases List.mem_cons.mp hmem with rfl | hmem'
        · by_cases hin : name ∈ rest.map (·.1)
          · obtain ⟨idty', hidty', heq⟩ := List.mem_map.mp hin
            obtain ⟨w, hw⟩ := ih1 idty' hidty'
            exact ⟨w, heq ▸ hw⟩
          · rw [ih2 name hin]
            exact ⟨v, lookup_cons_self _ _ _⟩
        · exact ih1 idty hmem'
      · intro id hid
        simp only [List.map_cons, List.mem_cons, not_or] at hid
        rw [ih2 id hid.2, lookup_cons_other _ _ _ _ (Ne.symm hid.1)]

theorem prologue_shape (P : Program) (π : Preimage) (mem : List (Ident × Value C))
    (h : prologue M P π = .ok mem) :
    (∀ idty ∈ P.inputs, ∃ v, lookup mem idty.1 = some v)
      ∧ (∀ id, id ∉ P.inputs.map (·.1) → lookup mem id = none) := by
  simp only [prologue, bind_eq_ok] at h
  obtain ⟨⟨mem', idx⟩, hloop, h⟩ := h
  step_simp h
  split at h
  · close_throw h
  · step_simp h
    subst h
    obtain ⟨h1, h2⟩ := prologueLoop_shape M π P.inputs 0 [] mem' idx hloop
    exact ⟨h1, fun id hid => by rw [h2 id hid]; rfl⟩

/-! ## The theorem -/

/-- SSA as the corpus has it (`zkir-wellformed`): input names and every
definition, pairwise distinct. -/
def SSA (P : Program) : Prop :=
  (P.inputs.map (·.1) ++ P.instructions.flatMap Instr.defines).Nodup

/-- The typing fact the in-circuit `impact` arm assumes and the
off-circuit arm never checks (§10 I5): every pushed operand is native. -/
def ImpactsNative (P : Program) (mem : Assignment C) : Prop :=
  ∀ i ∈ P.instructions, ∀ o ∈ impactInputsOf i, ∃ x, val mem o = some (.native x)

theorem initialPis_length (P : Program) (π : Preimage) (pis0 : List Fr)
    (h : initialPis P π = .ok pis0) : pis0.length = pisBase P := by
  unfold initialPis at h
  unfold pisBase
  split at h <;> step_simp h <;> subst h <;> simp_all

theorem epilogue_shape (P : Program) (π : Preimage) (st : State C) (r : Result C)
    (h : epilogue M P π st = .ok r) : r.memory = st.memory ∧ r.pis = st.pis := by
  unfold epilogue at h
  repeat' split at h
  all_goals first
    | close_throw h
    | (step_simp h; subst h; exact ⟨rfl, rfl⟩)

theorem completeness (P : Program) (π : Preimage) (r : Result C)
    (h : run M P π = .ok r) (ssa : SSA P) (hnat : ImpactsNative P r.memory) :
    Sat M P r.pis r.memory := by
  simp only [run, bind_eq_ok] at h
  obtain ⟨mem, hmem, pis0, hpis0, st, hfold, h⟩ := h
  have hbase := initialPis_length P π pis0 hpis0
  have hr := epilogue_shape M P π st r h
  obtain ⟨hp1, hp2⟩ := prologue_shape M P π mem hmem
  unfold SSA at ssa
  rw [List.nodup_append] at ssa
  obtain ⟨_, hnd, hdisj⟩ := ssa
  have hfresh : ∀ id ∈ P.instructions.flatMap Instr.defines, lookup mem id = none :=
    fun id hid => hp2 id (fun hin => hdisj id hin id hid rfl)
  obtain ⟨s1, _, s3, ssat⟩ := foldl_sat M P π P.instructions _ st hfold hnd hfresh
  rw [hr.1, hr.2]
  refine ⟨?_, ?_, ?_⟩
  · show st.pis.length = pisBase P + totalAdvance P.instructions
    rw [s3]; simp [hbase]
  · intro idty hid
    obtain ⟨v, hv⟩ := hp1 idty hid
    exact ⟨v, s1 _ _ hv⟩
  · have := ssat st.memory (Sub.rfl _) (by rw [← hr.1]; exact hnat) st.pis List.prefix_rfl
    simpa [hbase] using this

end MinocrabZkir.Constraint
