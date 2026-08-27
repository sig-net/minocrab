/-
The Lean warrant for the visibility system — M25's construct-loop row 3
(design of record: notes/lean-port.org §3). The Rust constructs it
warrants live in the `minocrab` crate (`Meet`'s four impls, `Wire3`'s
`V` parameter, `Circuit3::disclose` as the single Private→Public gate)
and are re-exported and consumed by every `minocrab-std` leaf; the
proofs ship here because this crate is where circuit code is WRITTEN
against them.

THE MODEL GAP, stated once: these theorems warrant the LATTICE and the
taint discipline as modelled below; the claim that the Rust implements
this discipline rests on review (the `Meet` impls ARE the `meet` table;
`disclose` is the only function `Private → Public` — greppable) plus
the compile_fail doctests and the generated disclosure-set tests.

THE AGDA HONEST GROUND: Compact's checked spec types `disclose` as
TRANSPARENT — `Γ ⊢expr expr ⦂ τ → Γ ⊢expr disclose expr ⦂ τ` — with no
visibility judgment anywhere in the static semantics: nothing marks an
expression as witness-tainted, and no rule forbids an undisclosed
witness reaching public output. So there is NO Agda proof to port:
this module is NEW Lean modelling OUR two-point lattice, which is
STRICTLY STRONGER than the spec's (their compiler implements the
witness-taint check outside the spec; our types carry it, and the
manifests/`label!` layer enforces more still — the SUBSET annotation
in the inventory runs in the strong direction).
-/

namespace MinocrabStdProofs

/-- The two-point visibility lattice. `pub` = derived only from
constants and disclosed/public values; `priv` = tainted by witness
data. -/
inductive Vis where
  | pub
  | priv
deriving DecidableEq

/-- `Meet`'s four impls, as the table they are: public only if both
sides are public. -/
def meet : Vis → Vis → Vis
  | .pub, .pub => .pub
  | _, _ => .priv

/-! ## The lattice laws — `meet` really is a meet -/

theorem meet_comm (a b : Vis) : meet a b = meet b a := by
  cases a <;> cases b <;> rfl

theorem meet_assoc (a b c : Vis) :
    meet (meet a b) c = meet a (meet b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem meet_idem (a : Vis) : meet a a = a := by
  cases a <;> rfl

/-- `Public` is the identity: meeting with a public value never
downgrades. -/
theorem meet_pub (a : Vis) : meet .pub a = a := by
  cases a <;> rfl

/-- `Private` absorbs: one tainted operand taints the result — the
`Private ⊓ Public = Private` the `Operand::meet` docs state. -/
theorem meet_priv (a : Vis) : meet .priv a = .priv := by
  cases a <;> rfl

/-- The characterisation every use site leans on: a meet is public IFF
both operands are. The forward direction is why an untainted result
certifies untainted inputs; the backward is why combining disclosed
values needs no re-disclosure. -/
theorem meet_eq_pub_iff (a b : Vis) :
    meet a b = .pub ↔ a = .pub ∧ b = .pub := by
  cases a <;> cases b <;> simp [meet]

/-- The order (`a ≤ b` as `meet a b = a`, `priv` at bottom): `meet` is
the greatest lower bound, i.e. monotone taint-propagation is the most
permissive sound rule. -/
def le (a b : Vis) : Prop := meet a b = a

theorem le_refl (a : Vis) : le a a := meet_idem a

theorem meet_le_left (a b : Vis) : le (meet a b) a := by
  cases a <;> cases b <;> rfl

theorem meet_le_right (a b : Vis) : le (meet a b) b := by
  cases a <;> cases b <;> rfl

theorem le_meet {a b c : Vis} (hca : le c a) (hcb : le c b) :
    le c (meet a b) := by
  cases a <;> cases b <;> cases c <;> simp_all [le, meet]

/-! ## The taint theorem — "no Private reaches Public without disclose"

A tiny expression model: leaves carry a visibility (a constant or
transcript input is `pub`; a witness is `priv`), every combining
operation meets (which is what `Circuit3`'s arithmetic does through the
`Meet` bounds), and `disclose` — the ONLY constructor producing `pub`
from anything — is the gate. `CircuitOut` being Public-only means a
circuit output is an expression whose `vis` is `pub`; the theorem says
exactly when that can happen. -/

inductive Expr where
  | leaf (v : Vis)
  | op (a b : Expr)
  | disclose (e : Expr)

/-- The visibility the type system assigns. -/
def vis : Expr → Vis
  | .leaf v => v
  | .op a b => meet (vis a) (vis b)
  | .disclose _ => .pub

/-- A `priv` leaf NOT under any `disclose` — the leak the type system
must rule out. -/
def undisclosedPriv : Expr → Bool
  | .leaf .priv => true
  | .leaf .pub => false
  | .op a b => undisclosedPriv a || undisclosedPriv b
  | .disclose _ => false

/-- THE THEOREM: an expression types as `Public` IFF every private leaf
in it sits under a `disclose`. Forward: a `Wire3<_, Public>` cannot
carry undisclosed witness data — the "single, greppable gate" claim as
a proof. Backward: the discipline is not conservative — disclosing
every witness a value uses always suffices to publish it. -/
theorem vis_pub_iff_no_undisclosed_priv (e : Expr) :
    vis e = .pub ↔ undisclosedPriv e = false := by
  induction e with
  | leaf v => cases v <;> simp [vis, undisclosedPriv]
  | op a b iha ihb =>
    simp [vis, undisclosedPriv, meet_eq_pub_iff, iha, ihb]
  | disclose e _ => simp [vis, undisclosedPriv]

/-- The contrapositive, in the shape the API presents it: an expression
holding an undisclosed witness types as `Private` — and `CircuitOut`
(Public-only) then rejects it at compile time. -/
theorem undisclosed_priv_is_private {e : Expr}
    (h : undisclosedPriv e = true) : vis e = .priv := by
  cases hv : vis e with
  | priv => rfl
  | pub =>
    rw [(vis_pub_iff_no_undisclosed_priv e).mp hv] at h
    exact absurd h (by simp)

end MinocrabStdProofs
