/-
`fold_immediate_copies` over the REAL IR (M27 rung 3, the pass prong;
notes/zkir-semantics.org §4.4). `Fold.lean`'s four theorems restated on
`MinocrabZkir.Instr`: the model's single `other touched` arm becomes
`mapOperands`, the substitution applied to exactly the `operands_mut`
positions (Dataflow.lean's `operands`) and never to the terminator's.
Immediates are the signed literals the real syntax carries (`Int`).

The syntactic half (theorems 1-3) and the semantic half
(`fold_preserves_observables`, theorem 4) are both here; the latter's
`WellFormed` hypothesis is what `zkir-wellformed` checks on the corpus
in real-IR form. `Fold.lean` stays as the M25 record.
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

/-! ## Theorem 4: observables preserved — the SEMANTIC half.

The model's `other touched` arm becomes the whole real instruction, its
operands resolved under the running copy environment (`resolve`); the
output terminator's list is resolved too, as in the model. The proof is
the model's, with the per-instruction reasoning packed into
`mapOperands_congr` (33 arms, kernel-checked) and the walk split on
`isCopy` instead of on the constructor. -/

/-- Every name an instruction reads: its `operands_mut` positions plus,
for the terminator, the returned list. -/
def usesOf (i : Instr) : List Ident :=
  varsOf i.operands ++ varsOf (match i with | .output vals => vals | _ => [])

/-- The names the stream's copies DEFINE, in order. -/
def copyDsts : List Instr → List Ident
  | [] => []
  | .copy dst _ :: rest => dst :: copyDsts rest
  | _ :: rest => copyDsts rest

/-- Defs-before-uses: no instruction uses a name that a copy at or after
it defines. A name NO copy defines may appear anywhere. -/
def NoUseBeforeDef : List Instr → Prop
  | [] => True
  | i :: rest => (∀ n ∈ usesOf i, n ∉ copyDsts (i :: rest)) ∧ NoUseBeforeDef rest

/-- The SSA shape `zkir-wellformed` checks on the corpus (and `Builder3`
guarantees): copy destinations bound once, before any use. -/
structure WellFormed (l : List Instr) : Prop where
  nodup : (copyDsts l).Nodup
  nubd : NoUseBeforeDef l

def envStep (e : Env) : Instr → Env
  | .copy dst src =>
    match substOp e src with
    | .imm v => e.set dst v
    | .var _ => e
  | _ => e

/-- An instruction with every operand it reads resolved under `e`. -/
def resolve (e : Env) : Instr → Instr
  | .output vals => .output (vals.map (substOp e))
  | i => mapOperands (substOp e) i

/-- The stream's meaning for the fold's purposes: every non-copy
instruction, operands resolved under the running copy environment. -/
def observe (e : Env) : List Instr → List Instr
  | [] => []
  | i :: rest =>
    if isCopy i then observe (envStep e i) rest else resolve e i :: observe e rest

theorem Env.get_set_self (e : Env) (k : Ident) (v : Int) :
    (e.set k v).get k = some v := by
  induction e with
  | nil => simp [Env.set, Env.get]
  | cons kv rest ih =>
    by_cases h : kv.1 = k
    · simp [Env.set, Env.get, h]
    · simp [Env.set, Env.get, h, ih]

theorem Env.get_set_other (e : Env) (k k' : Ident) (v : Int)
    (h : k ≠ k') : (e.set k v).get k' = e.get k' := by
  induction e with
  | nil => simp [Env.set, Env.get, h]
  | cons kv rest ih =>
    by_cases hk : kv.1 = k
    · subst hk
      simp [Env.set, Env.get, h]
    · simp [Env.set, Env.get, hk, ih]

theorem isCopy_iff (i : Instr) : isCopy i = true ↔ ∃ dst src, i = .copy dst src := by
  cases i <;> simp [isCopy]

theorem envStep_noncopy (e : Env) (i : Instr) (h : isCopy i = false) : envStep e i = e := by
  cases i <;> simp_all [isCopy, envStep]

theorem envStep_copy_imm (e : Env) (dst : Ident) (src : Operand) (v : Int)
    (h : substOp e src = .imm v) : envStep e (.copy dst src) = e.set dst v := by
  simp [envStep, h]

theorem envStep_copy_var (e : Env) (dst : Ident) (src : Operand) (s : Ident)
    (h : substOp e src = .var s) : envStep e (.copy dst src) = e := by
  simp [envStep, h]

theorem envStep_get_other (e : Env) (dst : Ident) (src : Operand)
    (n : Ident) (h : dst ≠ n) :
    (envStep e (.copy dst src)).get n = e.get n := by
  cases hs : substOp e src with
  | imm v => rw [envStep_copy_imm e dst src v hs, Env.get_set_other e dst n v h]
  | var s => rw [envStep_copy_var e dst src s hs]

/-- `namedOf` steps by exactly `envStep`. -/
theorem namedOf_cons (e : Env) (i : Instr) (rest : List Instr) :
    namedOf e (i :: rest) = namedOf (envStep e i) rest := by
  cases i with
  | copy dst src =>
    cases src with
    | imm v => rfl
    | var s =>
      simp only [namedOf, envStep, substOp]
      cases h : e.get s with
      | some v => simp
      | none => simp
  | _ => rfl

theorem copyDsts_noncopy (i : Instr) (rest : List Instr) (h : isCopy i = false) :
    copyDsts (i :: rest) = copyDsts rest := by
  cases i <;> simp_all [isCopy, copyDsts]

theorem returnedOf_cons_sub (i : Instr) (rest : List Instr) (n : Ident)
    (h : n ∈ returnedOf rest) : n ∈ returnedOf (i :: rest) := by
  cases i <;> simp_all [returnedOf]

theorem foldRun_cons (folded : Env) (i : Instr) (rest : List Instr) :
    foldRun folded (i :: rest) =
      if keeps folded i then mapOperands (substOp folded) i :: foldRun folded rest
      else foldRun folded rest := by
  cases i <;> simp only [foldRun, keeps, mapOperands] <;> (try split) <;> simp_all

theorem keeps_noncopy (folded : Env) (i : Instr) (h : isCopy i = false) :
    keeps folded i = true := by
  cases i <;> simp_all [isCopy, keeps]

/-- `namedOf` binds only copy destinations. -/
theorem namedOf_get_notMem (e : Env) (l : List Instr) (n : Ident)
    (h : n ∉ copyDsts l) : (namedOf e l).get n = e.get n := by
  induction l generalizing e with
  | nil => rfl
  | cons i rest ih =>
    rw [namedOf_cons]
    cases hc : isCopy i with
    | true =>
      obtain ⟨dst, src, rfl⟩ := (isCopy_iff i).mp hc
      have hdst : dst ≠ n := fun he => h (by simp [copyDsts, he])
      have hrest : n ∉ copyDsts rest := fun hm => h (by simp [copyDsts, hm])
      rw [ih _ hrest, envStep_get_other e dst src n hdst]
    | false =>
      rw [copyDsts_noncopy i rest hc] at h
      rw [envStep_noncopy e i hc]
      exact ih _ h

/-- A binding `namedOf` produces was either in the seed or belongs to a
copy destination. -/
theorem namedOf_get_mem (e : Env) (l : List Instr) (n : Ident) (v : Int)
    (h : (namedOf e l).get n = some v) :
    n ∈ copyDsts l ∨ e.get n = some v := by
  induction l generalizing e with
  | nil => exact Or.inr h
  | cons i rest ih =>
    rw [namedOf_cons] at h
    cases hc : isCopy i with
    | true =>
      obtain ⟨dst, src, rfl⟩ := (isCopy_iff i).mp hc
      rcases ih _ h with hmem | hget
      · exact Or.inl (List.mem_cons_of_mem _ hmem)
      · by_cases hd : dst = n
        · subst hd
          exact Or.inl (List.mem_cons_self ..)
        · right
          rwa [envStep_get_other e dst src n hd] at hget
    | false =>
      rw [envStep_noncopy e i hc] at h
      rw [copyDsts_noncopy i rest hc]
      exact ih _ h

theorem contains_of_mem (l : List Ident) (n : Ident) (h : n ∈ l) :
    l.contains n = true := by
  induction l with
  | nil => cases h
  | cons a rest ih =>
    cases h with
    | head => simp
    | tail _ hm =>
      simp
      exact Or.inr hm

theorem filter_get_none (returned : List Ident) (n : Ident)
    (h : returned.contains n = true) :
    ∀ named : Env,
      Env.get (named.filter (fun kv => !returned.contains kv.1)) n = none := by
  intro named
  induction named with
  | nil => rfl
  | cons kv rest ih =>
    obtain ⟨k, v⟩ := kv
    rw [List.filter_cons]
    by_cases hk : k = n
    · subst hk
      rw [h, Bool.not_true, if_neg Bool.false_ne_true]
      exact ih
    · cases hb : returned.contains k with
      | true =>
        rw [Bool.not_true, if_neg Bool.false_ne_true]
        exact ih
      | false =>
        rw [Bool.not_false, if_pos rfl]
        simp only [Env.get]
        rw [if_neg hk]
        exact ih

theorem filter_get_some (returned : List Ident) (n : Ident) (v : Int) :
    ∀ named : Env,
      Env.get (named.filter (fun kv => !returned.contains kv.1)) n = some v →
      Env.get named n = some v := by
  intro named
  induction named with
  | nil => exact fun h => h
  | cons kv rest ih =>
    intro h
    obtain ⟨k, v'⟩ := kv
    rw [List.filter_cons] at h
    by_cases hk : k = n
    · subst hk
      cases hb : returned.contains k with
      | true =>
        rw [hb, Bool.not_true, if_neg Bool.false_ne_true,
          filter_get_none returned k hb rest] at h
        cases h
      | false =>
        rw [hb, Bool.not_false, if_pos rfl] at h
        simp [Env.get] at h
        simp [Env.get, h]
    · have hgoal : Env.get ((k, v') :: rest) n = Env.get rest n := by
        simp only [Env.get]
        rw [if_neg hk]
      rw [hgoal]
      cases hb : returned.contains k with
      | true =>
        rw [hb, Bool.not_true, if_neg Bool.false_ne_true] at h
        exact ih h
      | false =>
        rw [hb, Bool.not_false, if_pos rfl] at h
        simp only [Env.get] at h
        rw [if_neg hk] at h
        exact ih h

theorem resolve_of_ne_output (e : Env) (i : Instr) (h : ∀ vals, i ≠ .output vals) :
    resolve e i = mapOperands (substOp e) i := by
  cases i <;> simp_all [resolve]

/-- Substitutions that agree on an instruction's operands give the same
instruction — the 33-arm fact the generic case rests on. -/
theorem mapOperands_congr (f g : Operand → Operand) (i : Instr)
    (h : ∀ op ∈ i.operands, f op = g op) : mapOperands f i = mapOperands g i := by
  cases i <;> simp only [Instr.operands, mapOperands] at h ⊢
    <;> (try rename_i p; obtain ⟨_, _⟩ := p)
    <;> simp_all

theorem varsOf_mem (ops : List Operand) (n : Ident) (h : Operand.var n ∈ ops) :
    n ∈ varsOf ops := by
  induction ops with
  | nil => cases h
  | cons op tail ih =>
    cases op with
    | var m =>
      simp only [varsOf, List.mem_cons]
      rcases List.mem_cons.mp h with hh | ht
      · left; cases hh; rfl
      · exact Or.inr (ih ht)
    | imm _ =>
      simp only [varsOf]
      exact ih (List.mem_cons.mp h |>.resolve_left (by simp))

/-- Map-congruence over an operand list from per-name agreement. -/
theorem map_substOp_congr (f g : Operand → Operand) (ops : List Operand)
    (hvar : ∀ n, Operand.var n ∈ ops → f (.var n) = g (.var n))
    (himm : ∀ v, f (.imm v) = g (.imm v)) :
    ops.map f = ops.map g := by
  apply List.map_congr_left
  intro op hop
  cases op with
  | var n => exact hvar n hop
  | imm v => exact himm v

theorem observe_foldRun (folded : Env) :
    ∀ (l : List Instr) (eo ef : Env),
      (∀ n v, folded.get n = some v → (namedOf eo l).get n = some v) →
      (copyDsts l).Nodup →
      NoUseBeforeDef l →
      (∀ n v, n ∉ copyDsts l → folded.get n = some v → eo.get n = some v) →
      (∀ n, folded.get n = none → ef.get n = eo.get n) →
      (∀ n, n ∈ returnedOf l → folded.get n = none) →
      observe ef (foldRun folded l) = observe eo l := by
  intro l
  induction l with
  | nil => intro eo ef _ _ _ _ _ _; rfl
  | cons i rest ih =>
    intro eo ef hnamed hnodup hnubd hdef hef hret
    have hvar : ∀ n, n ∉ copyDsts (i :: rest) →
        substOp ef (substOp folded (Operand.var n))
          = substOp eo (Operand.var n) := by
      intro n hn
      cases hf : folded.get n with
      | some v =>
        have heo := hdef n v hn hf
        simp [substOp, hf, heo]
      | none =>
        simp [substOp, hf, hef n hf]
    cases hc : isCopy i with
    | false =>
      -- The generic instruction: kept, operands substituted; both walks'
      -- environments stand still.
      have hres : resolve ef (mapOperands (substOp folded) i) = resolve eo i := by
        cases i with
        | output vals =>
          simp only [resolve, mapOperands]
          congr 1
          apply map_substOp_congr
          · intro n hn
            have hr : n ∈ returnedOf (.output vals :: rest) := by
              simp only [returnedOf, List.mem_append]
              exact Or.inl (varsOf_mem vals n hn)
            simp [substOp, hef n (hret n hr)]
          · intro v; rfl
        | _ =>
          rw [resolve_of_ne_output ef _ (by intro vals; simp [mapOperands]),
            resolve_of_ne_output eo _ (by intro vals; simp),
            mapOperands_mapOperands]
          apply mapOperands_congr
          intro op hop
          cases op with
          | var n =>
            exact hvar n (hnubd.1 n (by
              simp only [usesOf, List.mem_append]
              exact Or.inl (varsOf_mem _ n hop)))
          | imm v => rfl
      have htail : observe ef (foldRun folded rest) = observe eo rest := by
        apply ih
        · intro n v h
          have h2 := hnamed n v h
          rwa [namedOf_cons, envStep_noncopy eo i hc] at h2
        · rwa [copyDsts_noncopy i rest hc] at hnodup
        · exact hnubd.2
        · intro n v hn h
          exact hdef n v (by rwa [copyDsts_noncopy i rest hc]) h
        · exact hef
        · exact fun n hm => hret n (returnedOf_cons_sub i rest n hm)
      rw [foldRun_cons, if_pos (keeps_noncopy folded i hc)]
      simp only [observe, isCopy_mapOperands, hc, Bool.false_eq_true, if_false]
      rw [hres, htail]
    | true =>
      obtain ⟨dst, src, rfl⟩ := (isCopy_iff i).mp hc
      have hnodup' := List.nodup_cons.mp hnodup
      cases hf : folded.get dst with
      | some v =>
        have htail : observe ef (foldRun folded rest)
            = observe (envStep eo (.copy dst src)) rest := by
          apply ih
          · intro n v' h
            have h2 := hnamed n v' h
            rwa [namedOf_cons] at h2
          · exact hnodup'.2
          · exact hnubd.2
          · intro n v' hn h
            by_cases hd : n = dst
            · subst hd
              have h2 := hnamed n v' h
              rw [namedOf_cons] at h2
              rwa [namedOf_get_notMem _ _ _ hnodup'.1] at h2
            · have hn' : n ∉ copyDsts (Instr.copy dst src :: rest) := by
                simp only [copyDsts, List.mem_cons, not_or]
                exact ⟨hd, hn⟩
              have heo := hdef n v' hn' h
              rw [envStep_get_other eo dst src n (fun he => hd he.symm)]
              exact heo
          · intro n h
            have hd : n ≠ dst := by
              intro he
              rw [he, hf] at h
              simp at h
            rw [envStep_get_other eo dst src n (fun he => hd he.symm)]
            exact hef n h
          · exact fun n hm => hret n hm
        have hcond : (folded.get dst).isSome = true := by simp [hf]
        simp only [foldRun, observe, isCopy, if_true]
        rw [if_pos hcond]
        exact htail
      | none =>
        have hsrc : substOp ef (substOp folded src) = substOp eo src := by
          cases src with
          | var s => exact hvar s (hnubd.1 s (by simp [usesOf, varsOf, Instr.operands]))
          | imm w => rfl
        have hstep : ∀ n, folded.get n = none →
            (envStep ef (.copy dst (substOp folded src))).get n
              = (envStep eo (.copy dst src)).get n := by
          intro n h
          by_cases hd : dst = n
          · subst hd
            cases hs : substOp eo src with
            | imm w =>
              have hs' : substOp ef (substOp folded src) = .imm w :=
                hsrc.trans hs
              rw [envStep_copy_imm eo dst src w hs,
                envStep_copy_imm ef dst (substOp folded src) w hs',
                Env.get_set_self, Env.get_set_self]
            | var s =>
              have hs' : substOp ef (substOp folded src) = .var s :=
                hsrc.trans hs
              rw [envStep_copy_var eo dst src s hs,
                envStep_copy_var ef dst (substOp folded src) s hs']
              exact hef dst h
          · rw [envStep_get_other ef dst (substOp folded src) n hd,
              envStep_get_other eo dst src n hd]
            exact hef n h
        have htail : observe (envStep ef (.copy dst (substOp folded src)))
              (foldRun folded rest)
            = observe (envStep eo (.copy dst src)) rest := by
          apply ih
          · intro n v h
            have h2 := hnamed n v h
            rwa [namedOf_cons] at h2
          · exact hnodup'.2
          · exact hnubd.2
          · intro n v hn h
            have hd : n ≠ dst := by
              intro he
              rw [he, hf] at h
              simp at h
            have hn' : n ∉ copyDsts (Instr.copy dst src :: rest) := by
              simp only [copyDsts, List.mem_cons, not_or]
              exact ⟨hd, hn⟩
            have heo := hdef n v hn' h
            rw [envStep_get_other eo dst src n (fun he => hd he.symm)]
            exact heo
          · exact hstep
          · exact fun n hm => hret n hm
        have hcond : ¬ (folded.get dst).isSome = true := by simp [hf]
        simp only [foldRun, observe, isCopy, if_true]
        rw [if_neg hcond]
        simp only [observe, isCopy, if_true]
        exact htail

/-- THE SEMANTIC THEOREM over the real IR: on SSA-well-formed streams the
fold preserves every observable — each non-copy instruction consumes the
same resolved operand values, and the circuit returns the same values. -/
theorem fold_preserves_observables (l : List Instr) (wf : WellFormed l) :
    observe [] (fold l) = observe [] l := by
  show observe [] (foldRun ((namedOf [] l).filter
    (fun kv => !(returnedOf l).contains kv.1)) l) = observe [] l
  apply observe_foldRun
  · intro n v h
    exact filter_get_some (returnedOf l) n v (namedOf [] l) h
  · exact wf.nodup
  · exact wf.nubd
  · intro n v hn h
    have h2 := filter_get_some (returnedOf l) n v (namedOf [] l) h
    rcases namedOf_get_mem [] l n v h2 with hmem | hgot
    · exact absurd hmem hn
    · exact hgot
  · intro n _
    rfl
  · intro n hm
    exact filter_get_none (returnedOf l) n (contains_of_mem _ _ hm) (namedOf [] l)

end MinocrabProofs.FoldIr
