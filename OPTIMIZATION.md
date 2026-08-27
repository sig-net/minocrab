# The optimization cookbook

The levers that make a MinoCrab circuit cost fewer rows than the equivalent
Compact one — the source of the manager port's **−41%** and the vault's
**35–58%**. Written for **gadget authors**: people building a circuit
fragment (a hash, a Merkle path, an ABI encoder) on `minocrab-std` and
publishing it as a crate, no fork required. See
[README.md](README.md#using-minocrab-as-a-library) for how that fits, and
[`notes/`](notes/) (`benchmark.org`, `vault-optimization.org`,
`manager-port.org`) for the measured record behind each entry.

**The one idea under all of them:** the wins come from *instruction
selection in the typed layer* — choosing a cheaper lowering because the eDSL
*knows a value is a `Bytes<32>` with a known alignment*. ZKIR is type-erased,
so an IR pass can never recover this. Optimize where the types still are.

Measure everything with `minocrab_sim::v3::{cost, profile}` (in a `#[test]`
or a criterion bench) or the `minocrab` CLI over a `.zkir`. A lever that
does not move `(k, rows)` on *your* circuit is not helping *your* circuit.

---

### 1. Hash in-chip, don't explode bytes

`c.keccak256(alignment, &limbs)` and `c.persistent_hash(alignment, &limbs)`
pack the preimage into the chip *from the field limbs you already have*. The
naïve lowering — the one Compact emits — explodes every `Bytes<N>` value into
N byte-wires and rebuilds it before hashing, at roughly **8,500 rows per
32-byte word**. Describe the preimage as an `Alignment` of atoms plus the
limbs; the chip does the packing for free. This is the single biggest lever
in any hash-heavy circuit (EIP-712, request-ids, commitments).

### 2. Shift, don't reverse, when you only need a few bytes moved

A big-endian ABI word is a value placed behind a zero prefix. Build it with a
`div_mod_power_of_two` shift (`evm_address_abi_word`, `numeric_abi_word` in
`minocrab-contracts::signet`) rather than casting to a full `Bytes<32>` and
reversing all 32 — you pay for the *variable* bytes only (8 / 16 / 1),
not all 32.

### 3. `reverse_bytes` is one instruction

When you *do* need a full byte reversal, `c.reverse_bytes(typed)` is ZKIR's
native `ReverseBytes` (~150 rows). The stdlib's explode/rebuild chain is
~4,600. Never hand-roll a reversal.

### 4. `Serializer` re-limbs by segment

Packing several values into one byte string? `minocrab_std::v3::Serializer`
emits at most one `div_mod` per output-limb boundary a field straddles,
instead of exploding every input to bytes. Push typed values
(`push_uint`, `push_b32`, `push_bytes_n`, `push_literal`) and `finish::<N>()`.

### 5. A guarded read *is* read-as-zero, for free

`map.lookup_guarded(c, member, k).or_default()` reads the cell under the
`member` guard and hands back the type's default (zero) when the guard is
off — with **no `cond_select`**, because a skipped read's wires already hold
zero. Compact lowers "a missing cell reads 0" as a select; this is the same
semantics for nothing. Use it anywhere you have the `member ? lookup : 0`
shape. (The pattern that exposed the ambient-guard fix — see
`notes/manager-port.org`.)

### 6. Const-generic families monomorphize the size away

Parameterize by size/depth with `const` generics — `BytesN<V, N>`,
`MerkleTreePath<V, T, DEPTH>`, an event `<V, WORDS, LEN_OUT, LEN_RESPOND>`.
`rustc` unrolls each instantiation; there is no runtime size to carry, and
one definition covers every width.

### 7. `.widen()` retypes without re-constraining

`Uint::<BITS, V>::widen::<WIDER>()` returns the same wire at a wider type and
emits **nothing** — a value below `2^BITS` is below `2^WIDER` by
construction, so no second range check. Reach for it instead of a cast when
you're only widening.

### 8. Inline immediates instead of naming them

Every operand position takes `impl Into<Operand>`, so a native Rust value
inlines as a v3 immediate — `c.less_than(0u64, x, 64)`, not
`c.less_than(c.constant(0u64), x, 64)`. The named form emits a `Copy` (zero
rows, but it clutters the stream and the differential); the inline form emits
nothing. Prefer the native value.

### 9. `Uint::sub` carries the underflow guard

`a.sub(c, b)` on a `Uint<BITS>` emits exactly `assert(a >= b)` then the
subtraction — Compact's lowering, at Compact's width. Field arithmetic has no
sign, so an unguarded `add(a, neg(b))` underflows to a value near `2^255`, not
`-1`; `sub` is how you don't hand-write (and forget) the guard.

### 10. Choose `from_field_checked` vs `_unchecked` deliberately

Building a leaf from a raw field wire: `from_field_checked(c, w)` emits the
range constraint; `from_field_unchecked(w)` asserts you already have one. The
`_unchecked` name is greppable on purpose — it marks a soundness obligation
you're carrying. Cheap to leave `checked` (the constraint is often deduped
away); expensive to drop it where it was load-bearing.

---

**Then verify.** Every lever above changes the *instructions*, never the
*meaning* — prove that with the differential / spec harness (same typed I/O
schema + equal `pis`/`pi_skips` on a shared preimage; instruction streams
free to differ). Fewer rows is only a win if the circuit still computes the
same thing.
