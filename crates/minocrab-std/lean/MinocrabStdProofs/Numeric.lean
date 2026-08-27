/-
The Lean warrant for `minocrab_std::v3`'s numeric leaves — `Uint<BITS, V>`
and `BoundedUint<BOUND, V>` — M25's construct-loop rows 1 and 2
(design of record: notes/lean-port.org §3).

THE MODEL GAP, stated once and inherited by everything here: these
theorems warrant the ARITHMETIC RULES the types encode (the inline-const
asserts in `v3.rs` and the free retypes `widen`/`to_uint`); the claim
that the Rust states those rules as written here rests on review — each
theorem names the assert it warrants. Extraction (Aeneas) would close
that gap; nothing else does.

THE AGDA HONEST GROUND (the limitations discussion in one paragraph):
Compact's checked spec DECLARES the numeric hierarchy (`IsNumeric`,
`UIntType`) but its bound computation is a stub — `_⟨+⟩_`, `_⟨*⟩_`,
`_⟨-⟩_` all return `⊢undeclared` ("TODO: define bound computation"),
its subtyping relation has only `refl`/`trans` constructors ("TODO:
define subtyping"), and `Castable` has the single constructor deferring
to that stub. So there is NO Agda proof to port here: these theorems
are NEW Lean stating the rules compactc actually implements
(`infer-types.ss`, decoded in notes/builtin-lowering.org §9), which the
Agda's PROSE describes ("when adding two unsigned integers, we take the
sum of their size bounds") but its formal content does not.

CONVENTION: bounds are EXCLUSIVE, as `BoundedUint`'s are — a value `a`
of `BoundedUint<B>` satisfies `a < B`, and the largest legal value is
`B - 1` (compactc's `maxval`).
-/

namespace MinocrabStdProofs

/-! ## Addition — `BoundedUint::add`'s const assert
`OUT >= BOUND + BOUND2 - 1`, with no check emitted at the op
(compactc's rule: result type `Uint<maxa + maxb>`). -/

/-- The assert admits every sum: values below the operand bounds sum to
below `B1 + B2 - 1`. This is why `add` may emit ONE `add` instruction
and no constraint — the type is the only thing tracking the max, and
this is the fact that makes the type honest. -/
theorem sum_bound_sound {a b B1 B2 : Nat} (hB1 : 1 ≤ B1) (hB2 : 1 ≤ B2)
    (ha : a < B1) (hb : b < B2) : a + b < B1 + B2 - 1 := by omega

/-- And `B1 + B2 - 1` is the NARROWEST bound the assert could demand:
any `OUT` admitting every legal sum is at least it (the extremes
`(B1-1) + (B2-1)` are attainable). So the assert's threshold is exact —
neither unsound nor conservative. -/
theorem sum_bound_minimal {B1 B2 OUT : Nat} (hB1 : 1 ≤ B1) (hB2 : 1 ≤ B2)
    (h : ∀ a b, a < B1 → b < B2 → a + b < OUT) : B1 + B2 - 1 ≤ OUT := by
  have := h (B1 - 1) (B2 - 1) (by omega) (by omega)
  omega

/-! ## Multiplication — `BoundedUint::mul`'s const assert
`OUT >= (BOUND - 1) * (BOUND2 - 1) + 1`, one `mul`, no check at the op
(compactc's rule: result type `Uint<maxa · maxb>`). -/

/-- The assert admits every product: the largest product of in-bound
values is of the two largest. -/
theorem product_bound_sound {a b B1 B2 : Nat} (ha : a < B1) (hb : b < B2) :
    a * b < (B1 - 1) * (B2 - 1) + 1 := by
  have h : a * b ≤ (B1 - 1) * (B2 - 1) :=
    Nat.mul_le_mul (by omega) (by omega)
  omega

/-- And that threshold is the narrowest, by the same extremes. -/
theorem product_bound_minimal {B1 B2 OUT : Nat} (hB1 : 1 ≤ B1) (hB2 : 1 ≤ B2)
    (h : ∀ a b, a < B1 → b < B2 → a * b < OUT) :
    (B1 - 1) * (B2 - 1) + 1 ≤ OUT := by
  have := h (B1 - 1) (B2 - 1) (by omega) (by omega)
  omega

/-! ## Subtraction — the underflow guard (`Uint::sub` / `BoundedUint::sub`)
compactc emits `assert(a >= b)` before every subtraction and the field
negation-addition after; the API's whole reason to own `sub` is that the
raw spelling omits the guard (notes/api-safety-survey.org §B1). The
subtraction itself is FIELD arithmetic — `a + (p - b) mod p` — and the
guard is exactly what makes it agree with the integers. -/

/-- UNDER THE GUARD, field subtraction IS integer subtraction: for
`b ≤ a < p`, `(a + (p − b)) mod p = a − b`. -/
theorem field_sub_eq_nat_sub {a b p : Nat} (hguard : b ≤ a) (hap : a < p) :
    (a + (p - b)) % p = a - b := by
  have h1 : a + (p - b) = (a - b) + p := by omega
  rw [h1, Nat.add_mod_right, Nat.mod_eq_of_lt (by omega)]

/-- WITHOUT THE GUARD, it is the balance-underflow bug: for `a < b`,
the result is `p − (b − a)` — within `B` of the field size whenever
`b < B`, not a small negative. This is the theorem-shaped statement of
why the guard is not optional. -/
theorem field_sub_underflow {a b p B : Nat} (hab : a < b) (hbp : b < p)
    (hB : b < B) : (a + (p - b)) % p = p - (b - a) ∧ p - B < p - (b - a) := by
  have h1 : a + (p - b) = p - (b - a) := by omega
  refine ⟨?_, by omega⟩
  rw [h1]
  exact Nat.mod_eq_of_lt (by omega)

/-- The result keeps the operand bound (compactc's rule: result type
`Uint<maxa>`): under the guard, `a − b ≤ a < B`. This is what lets both
`sub`s return `Self` with no new constraint. -/
theorem sub_result_bound {a b B : Nat} (ha : a < B) : a - b < B := by omega

/-! ## The guard's comparison width
`sub`'s `assert(a >= b)` compares at the width the predicate layer
reads off the type — `max(1, intlen(BOUND − 1))` for `BoundedUint`,
`BITS` for `Uint`. A comparison is only meaningful for operands that
FIT its width, so the width choice carries a soundness obligation:
every in-bound value fits. -/

/-- `Nat.log2 n + 1` is `intlen n` for `n ≠ 0`: every `n` fits in
`log2 n + 1` bits. -/
theorem lt_two_pow_log2_succ {n : Nat} (h : n ≠ 0) :
    n < 2 ^ (Nat.log2 n + 1) :=
  (Nat.log2_lt h).mp (Nat.lt_succ_self _)

/-- The predicate layer's width admits every in-bound operand: for
`B ≥ 2`, `a < B` implies `a` fits in `intlen(B − 1) = log2(B − 1) + 1`
bits. (For `B = 1` the width is `max(1, ·) = 1` and the only legal
value `0` fits trivially.) -/
theorem guard_width_sound {a B : Nat} (hB : 2 ≤ B) (ha : a < B) :
    a < 2 ^ (Nat.log2 (B - 1) + 1) :=
  Nat.lt_of_le_of_lt (by omega : a ≤ B - 1) (lt_two_pow_log2_succ (by omega))

/-! ## Widening and the bridge — the free retypes -/

/-- `BoundedUint::widen`: a value below `BOUND` is below any
`BIGGER ≥ BOUND` — no instruction, no new constraint, because the wider
range is satisfied by construction. -/
theorem widen_sound {a B B' : Nat} (ha : a < B) (h : B ≤ B') : a < B' :=
  Nat.lt_of_lt_of_le ha h

/-- `Uint::widen`: the same fact at power-of-two bounds — `a < 2^n` and
`n ≤ m` give `a < 2^m` (the const assert `WIDER >= BITS` is exactly the
hypothesis `n ≤ m`). -/
theorem uint_widen_sound {a n m : Nat} (ha : a < 2 ^ n) (h : n ≤ m) :
    a < 2 ^ m :=
  Nat.lt_of_lt_of_le ha (Nat.pow_le_pow_right (by omega) h)

/-- `BoundedUint::to_uint`: the free bridge — a value below `BOUND` is a
`BITS`-bit value whenever `2^BITS ≥ BOUND` (the const assert), so
`constrain_bits(BITS)` would be a tautology. -/
theorem to_uint_sound {a B bits : Nat} (ha : a < B) (h : B ≤ 2 ^ bits) :
    a < 2 ^ bits :=
  Nat.lt_of_lt_of_le ha h

end MinocrabStdProofs
