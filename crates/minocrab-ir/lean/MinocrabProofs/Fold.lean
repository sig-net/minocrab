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

SCOPE: this file proves BOTH halves. The SYNTACTIC contract — `output`
lists verbatim, only provably-immediate copies dropped, the non-copy
skeleton preserved in kind and order, the substitution maps only folded
names to their immediates — holds of EVERY stream. The SEMANTIC theorem
(`fold_preserves_observables`: observable operand-VALUES preserved under
the copy environment) holds under `WellFormed`, the SSA shape `Builder3`
guarantees — copy destinations bound once and before use — and the fold
NEEDS that hypothesis: it substitutes globally, so a rebound or
use-before-def name really would change meaning.
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

/-- The names an operand list mentions. -/
def varsOf : List Operand → List String
  | [] => []
  | .var n :: rest => n :: varsOf rest
  | .imm _ :: rest => varsOf rest

/-- `returned_identifiers`: every name an `output` terminator lists. -/
def returnedOf : List Instr → List String
  | [] => []
  | .output vals :: rest => varsOf vals ++ returnedOf rest
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
  let folded := named.filter (fun kv => !returned.contains kv.1)
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
        simp [hk, ih]
      · rename_i h
        have hk : keeps folded (Instr.copy dst src) = true := by
          simp only [keeps, Bool.not_eq_true']
          simpa using h
        simp [hk, substInstr, ih]
    | output vals =>
      have hk : keeps folded (Instr.output vals) = true := rfl
      simp [foldRun, hk, substInstr, ih]
    | other touched =>
      have hk : keeps folded (Instr.other touched) = true := rfl
      simp [foldRun, hk, substInstr, ih]

/-! ## The SEMANTIC half: observable operand-VALUES are preserved.

The fold substitutes GLOBALLY — `folded` is computed from the whole
stream and applied at every site — so its soundness rests on the SSA
shape `Builder3` guarantees: every copy destination is bound ONCE (no
rebinding) and bound BEFORE any use. `WellFormed` states exactly that
much, and `fold_preserves_observables` shows it suffices.

The observation model: walk the stream carrying the copy environment —
`envStep` is shared with `namedOf` (`namedOf_cons`), so the observer and
the fold's own name accumulation agree by construction — and record
every non-copy instruction with each operand RESOLVED under the
environment at that point: a name a copy chain proves immediate resolves
to that immediate, any other name stays symbolic. `observe [] (fold l) =
observe [] l` is then precisely: the fold changed no value any
instruction consumes and none the circuit returns. -/

/-- The names an instruction USES: a copy reads its source; `output` and
`other` read their operand lists. A copy's `dst` is a definition, not a
use. -/
def usesOf : Instr → List String
  | .copy _ src => varsOf [src]
  | .output vals => varsOf vals
  | .other touched => varsOf touched

/-- The names the stream's copies DEFINE, in order. -/
def copyDsts : List Instr → List String
  | [] => []
  | .copy dst _ :: rest => dst :: copyDsts rest
  | _ :: rest => copyDsts rest

/-- Defs-before-uses: no instruction uses a name that a copy at or after
it defines. A name NO copy defines (a witness, an ordinary instruction's
output) may appear anywhere — it stays symbolic on both sides. -/
def NoUseBeforeDef : List Instr → Prop
  | [] => True
  | i :: rest => (∀ n ∈ usesOf i, n ∉ copyDsts (i :: rest)) ∧ NoUseBeforeDef rest

/-- The SSA shape `Builder3` guarantees (every wire born of exactly one
instruction, streams emitted in definition order): copy destinations are
bound once, and before any use. All the semantic theorem needs. -/
structure WellFormed (l : List Instr) : Prop where
  nodup : (copyDsts l).Nodup
  nubd : NoUseBeforeDef l

/-- The copy-environment step — shared by `namedOf` (via `namedOf_cons`)
and `observe`, so the two walks agree by construction. -/
def envStep (e : Env) : Instr → Env
  | .copy dst src =>
    match substOp e src with
    | .imm v => e.set dst v
    | .var _ => e
  | .output _ => e
  | .other _ => e

/-- One observation: a non-copy instruction with its operands resolved
under the copy environment at that point. -/
inductive Obs where
  | out (vals : List Operand)
  | oth (vals : List Operand)
deriving DecidableEq

/-- The stream's meaning for the fold's purposes: every non-copy
instruction, operands resolved under the running copy environment. -/
def observe (e : Env) : List Instr → List Obs
  | [] => []
  | .copy dst src :: rest => observe (envStep e (.copy dst src)) rest
  | .output vals :: rest => .out (vals.map (substOp e)) :: observe e rest
  | .other touched :: rest => .oth (touched.map (substOp e)) :: observe e rest

theorem Env.get_set_self (e : Env) (k : String) (v : Nat) :
    (e.set k v).get k = some v := by
  induction e with
  | nil => simp [Env.set, Env.get]
  | cons kv rest ih =>
    by_cases h : kv.1 = k
    · simp [Env.set, Env.get, h]
    · simp [Env.set, Env.get, h, ih]

theorem Env.get_set_other (e : Env) (k k' : String) (v : Nat)
    (h : k ≠ k') : (e.set k v).get k' = e.get k' := by
  induction e with
  | nil => simp [Env.set, Env.get, h]
  | cons kv rest ih =>
    by_cases hk : kv.1 = k
    · subst hk
      simp [Env.set, Env.get, h]
    · simp [Env.set, Env.get, hk, ih]

theorem envStep_output (e : Env) (vals : List Operand) :
    envStep e (.output vals) = e := rfl

theorem envStep_copy_imm (e : Env) (dst : String) (src : Operand) (v : Nat)
    (h : substOp e src = .imm v) : envStep e (.copy dst src) = e.set dst v := by
  simp [envStep, h]

theorem envStep_copy_var (e : Env) (dst : String) (src : Operand) (s : String)
    (h : substOp e src = .var s) : envStep e (.copy dst src) = e := by
  simp [envStep, h]

theorem envStep_get_other (e : Env) (dst : String) (src : Operand)
    (n : String) (h : dst ≠ n) :
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
  | output vals => rfl
  | other touched => rfl

/-- `namedOf` binds only copy destinations. -/
theorem namedOf_get_notMem (e : Env) (l : List Instr) (n : String)
    (h : n ∉ copyDsts l) : (namedOf e l).get n = e.get n := by
  induction l generalizing e with
  | nil => rfl
  | cons i rest ih =>
    rw [namedOf_cons]
    cases i with
    | copy dst src =>
      have hdst : dst ≠ n := fun he => h (by simp [copyDsts, he])
      have hrest : n ∉ copyDsts rest := fun hm => h (by simp [copyDsts, hm])
      rw [ih _ hrest, envStep_get_other e dst src n hdst]
    | output vals => exact ih _ h
    | other touched => exact ih _ h

/-- Conversely: a binding `namedOf` produces was either in the seed or
belongs to a copy destination. -/
theorem namedOf_get_mem (e : Env) (l : List Instr) (n : String) (v : Nat)
    (h : (namedOf e l).get n = some v) :
    n ∈ copyDsts l ∨ e.get n = some v := by
  induction l generalizing e with
  | nil => exact Or.inr h
  | cons i rest ih =>
    rw [namedOf_cons] at h
    rcases ih _ h with hmem | hget
    · left
      cases i with
      | copy dst src => exact List.mem_cons_of_mem _ hmem
      | output vals => exact hmem
      | other touched => exact hmem
    · cases i with
      | copy dst src =>
        by_cases hd : dst = n
        · subst hd
          exact Or.inl (List.mem_cons_self ..)
        · right
          rwa [envStep_get_other e dst src n hd] at hget
      | output vals => exact Or.inr hget
      | other touched => exact Or.inr hget

theorem contains_of_mem (l : List String) (n : String) (h : n ∈ l) :
    l.contains n = true := by
  induction l with
  | nil => cases h
  | cons a rest ih =>
    cases h with
    | head => simp
    | tail _ hm =>
      simp
      exact Or.inr hm

/-- A returned name has NO binding in the filtered map — the predicate
depends only on the key, so every entry for it is dropped. -/
theorem filter_get_none (returned : List String) (n : String)
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

/-- A binding that survives the returned-names filter was in the
original map — with the SAME value, because the predicate depends only
on the key (a key's entries are dropped or kept uniformly). -/
theorem filter_get_some (returned : List String) (n : String) (v : Nat) :
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
        -- every `k` entry is dropped, so the filtered map cannot bind it
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

/-- The induction workhorse, over the SUFFIX with both walks' states
generalized: `eo` is the original side's copy environment, `ef` the
folded side's; the hypotheses are the invariants the walk maintains
(folded names not yet defined are unused; already-defined ones agree
with `eo`; `ef` agrees with `eo` outside `folded`'s domain). -/
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
    -- Resolution at this instruction: for any name it may legally use,
    -- resolving the substituted operand in `ef` equals resolving the
    -- original in `eo`.
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
    -- Lifted to an operand list in a use position the fold substitutes.
    have hops : ∀ ops : List Operand,
        (∀ n, n ∈ varsOf ops → n ∉ copyDsts (i :: rest)) →
        List.map (substOp ef) (List.map (substOp folded) ops)
          = List.map (substOp eo) ops := by
      intro ops h
      induction ops with
      | nil => rfl
      | cons op tail ihop =>
        have htail := ihop (fun n hn => h n (by cases op <;> simp [varsOf, hn]))
        cases op with
        | var n =>
          have hn := h n (by simp [varsOf])
          simp only [List.map_cons]
          rw [htail, hvar n hn]
        | imm v =>
          simp only [List.map_cons]
          rw [htail]
          rfl
    -- And to a list the fold leaves VERBATIM (an `output`).
    have hopsRet : ∀ ops : List Operand,
        (∀ n, n ∈ varsOf ops → folded.get n = none) →
        List.map (substOp ef) ops = List.map (substOp eo) ops := by
      intro ops h
      induction ops with
      | nil => rfl
      | cons op tail ihop =>
        have htail := ihop (fun n hn => h n (by cases op <;> simp [varsOf, hn]))
        cases op with
        | var n =>
          have hn := h n (by simp [varsOf])
          simp only [List.map_cons]
          rw [htail]
          simp [substOp, hef n hn]
        | imm v =>
          simp only [List.map_cons]
          rw [htail]
          rfl
    cases i with
    | output vals =>
      have hhead : List.map (substOp ef) vals = List.map (substOp eo) vals :=
        hopsRet vals (fun n hn => hret n (by simp [returnedOf, hn]))
      have htail : observe ef (foldRun folded rest) = observe eo rest := by
        apply ih
        · intro n v h
          have h2 := hnamed n v h
          rwa [namedOf_cons, envStep_output] at h2
        · exact hnodup
        · exact hnubd.2
        · exact fun n v hn h => hdef n v hn h
        · exact hef
        · exact fun n hm => hret n (by simp [returnedOf, hm])
      simp only [foldRun, observe]
      rw [hhead, htail]
    | other touched =>
      have hhead : List.map (substOp ef) (List.map (substOp folded) touched)
          = List.map (substOp eo) touched :=
        hops touched (fun n hn => hnubd.1 n (by simpa [usesOf] using hn))
      have htail : observe ef (foldRun folded rest) = observe eo rest := by
        apply ih
        · intro n v h
          have h2 := hnamed n v h
          rwa [namedOf_cons] at h2
        · exact hnodup
        · exact hnubd.2
        · exact fun n v hn h => hdef n v hn h
        · exact hef
        · exact fun n hm => hret n hm
      simp only [foldRun, observe]
      rw [hhead, htail]
    | copy dst src =>
      have hnodup' := List.nodup_cons.mp hnodup
      cases hf : folded.get dst with
      | some v =>
        -- The copy is DROPPED. `eo` steps; `ef` does not — but `dst`'s
        -- binding is exactly what `folded` records, via `hnamed`.
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
        simp only [foldRun, observe]
        rw [if_pos hcond]
        exact htail
      | none =>
        -- The copy is KEPT (source substituted). Both walks step, and
        -- they bind `dst` identically because the source resolves
        -- equally on both sides.
        have hsrc : substOp ef (substOp folded src) = substOp eo src := by
          cases src with
          | var s => exact hvar s (hnubd.1 s (by simp [usesOf, varsOf]))
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
        simp only [foldRun, observe]
        rw [if_neg hcond]
        simp only [observe]
        exact htail

/-- THE SEMANTIC THEOREM: on SSA-well-formed streams the fold preserves
every observable — each non-copy instruction consumes the same resolved
operand values, and the circuit returns the same values. Together with
the syntactic half above this is the fold's full preserve-meaning
contract, discharged unbounded (M23 R4's bounded specimen retired). -/
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

end MinocrabProofs.Fold
