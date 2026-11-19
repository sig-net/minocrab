# MPS-0046: make Impact the ADT-definition mechanism, and write the standard ADTs in it

Draft of a comment for https://github.com/midnightntwrk/midnight-improvement-proposals/discussions/391. Written 2026-10-18 against compactc main at 4ee1f447 and the StampedCounter proof of concept (LFDT-Minokawa/compact#775). Not posted.

---

The open question in MPS-0046 is a dedicated ADT versus a general ADT-definition mechanism. I want to argue for the general mechanism, and to point out that it is much closer than it looks: the compiler already *is* that mechanism, internally. The work is to give it a Compact surface and a checker, not to invent it.

## What the compiler does today

Every ledger ADT in Compact is an entry in one table, `compiler/midnight-ledger.ss`, written in a small Scheme DSL (`declare-ledger-adt`, defined in `compiler/ledger.ss`). An entry is: the ADT's name and generic formals (kinds `Type`, `ADT/Type`, `Nat`), an `initial-value` state-value expression, and a list of operations. Each operation is a class (`read`, `update`, `write`, `remove`, or `update-with-coin-check`), typed arguments each with an optional disclosure annotation, a result type, a doc string, and an Impact instruction template written against `f`, the field path the compiler substitutes at the use site.

Everything downstream of that table is generic over it. Type inference finds the op by name and checks argument subtyping (`find-adt-op` in `infer-types.ss`). The disclosure checker reads the per-argument disclosure flags off the op (`track-witness-data.ss`). The sealed-field check uses the op class (`check-sealed-fields.ss`). ZKIR lowering expands the template with `expand-vm-code` and assembles each instruction to opcodes (`reduce-to-zkir.ss`). The TypeScript side expands the *same* template and hands it to `queryLedgerState`, so off-chain reads and the generated ledger accessors interpret the identical Impact that the chain runs. Only three places in the passes name a specific ADT: two `MerkleTree` special cases in type inference and the per-ADT storage descriptor in `extract-contract-info.ss`.

The proof of concept is the measurement. Adding `StampedCounter` took 119 lines in the table and two lines in `extract-contract-info.ss`. No pass changed. `stamp`, `increment` and `raiseTo` are plain Impact over a two-slot array, using `dup`, `idx`, `ins`, `lt`, `branch` and `jmp`, all of which the assembler already emits for `List` and `MerkleTree`.

So the question "can Compact expose Impact ops and build its primitive types on top" has an existence proof inside the compiler. The standard ADTs are *already* built on top of the ops. They are just built in Scheme, by the compiler team, with no checker.

## The suggestion

Give the table a Compact surface. Illustrative spelling, the shape matters more than the keywords:

```compact
export ledger adt StampedCounter<K> {
  state { counter: Counter, stamps: Map<K, Uint<64>> }

  read value(): Uint<64> impact {
    idx [counter]; popeq
  }

  update stamp(key: K): [] impact {
    dup 0; idx [stamps]            // [self, stamps]
    push key                       // [self, stamps, key]
    dup 2; idx [counter]           // [self, stamps, key, counter]
    ins 1                          // [self, stamps']
    push stamps; swap 0; insc 1    // [self']
  }

  update increment(amount: Uint<16>): [] impact {
    dup 0; idx [counter]; addi amount
    push counter; swap 0; insc 1
  }
}
```

The differences from the Scheme DSL are small and all simplifications:

- **The state shape is declared, not spelled as a state value.** `state { ... }` is a record of existing ADTs. The initial value is the array of their initial values, and `[counter]`, `[stamps]` are the sub-paths, so the author never writes `(align 0 1)`.
- **Templates are relative to the ADT's own root.** The compiler supplies the prologue (`idxp f`) and epilogue (`insc (length f)`) for update-class ops and the `dup 0; idx f` for reads. This removes `f`, `f-cached`, `(length f)`, and the `suppress-null` / `suppress-zero` hacks the current table needs so one template can serve every nesting depth.
- **The op classes stay.** They already carry the semantics the rest of the compiler needs: `read` ops produce a `popeq` and a TypeScript getter, `write` ops get `=` sugar, only `read` is allowed on `sealed` fields.
- **Generic formals map onto Compact's existing generics**, with one addition: the `ADT/Type` kind, so a user ADT can be a `Map` value as `Counter` can today.

Then rewrite the standard library's ADTs in this form, in Compact source, and require byte-identical Impact across the compiler's test corpus before and after. That diff is the acceptance test for the mechanism, and the standard ADTs become its first ten clients rather than special cases.

## What is genuinely new

Three things, in order of size.

**A checker for templates.** This is the real work. Today `check-vm-code` verifies only that the names in a template are bound. Stack discipline, path validity and state-value shape are not checked anywhere; a wrong template compiles, proves, and fails at transaction time in the ledger VM. The table already carries a latent instance: `Cell.writeCoin` reaches the context with a `dup` whose operand is computed from the path length, with a comment noting it exceeds the encoding's limit of 15 for deep paths. That is acceptable when the only authors are the compiler team with a test center behind them. It is not acceptable for a user-facing form. But the checker is tractable: Impact's value universe is five shapes (`null`, `cell`, `map`, `array`, bounded Merkle tree), every op except `branch` and `jmp` has a fixed stack effect, and the jumps are forward skips. A linear abstract interpretation over a shape-typed stack, seeded with the declared `state` shape, covers it. It also makes a property the MPS cares about checkable, see below.

**A generic storage descriptor.** `extract-contract-info.ss` has one case per ADT for the JSON the runtime reads. The `state` declaration gives the compiler everything it needs to emit that descriptor for any ADT.

**Iterators and other `js-only` ops.** The current table embeds TypeScript snippets for `iter`. Either the Compact form admits a TypeScript escape for them, or user ADTs get no iterator and the generated `asMap()` / `asArray()` accessors on the state are the off-chain interface. I would start with the latter.

Two things should stay built in: the `Kernel` ops, which reach the context and effects slots beneath the state, and the coin-check ops, which reach the context by counting stack slots. The checker should forbid user templates from touching anything below the ADT's own root, which is also what makes them safe to reason about locally. Named primitives for context access can come later if a use case needs them.

## Non-contention becomes a compile-time property

The reason `stamp` and `increment` do not contend is that their templates contain no `popeq`: the circuit never learns the counter's value, so there is nothing for a concurrent transaction to invalidate. The table already respects this uniformly. No `update`, `write` or `remove` op in `midnight-ledger.ss` contains a `popeq`; only `read` ops do. With a user-facing form, the checker can *enforce* it: a `popeq` is permitted in a `read` op and nowhere else. That turns "non-contentive by construction" from a design discipline into a guarantee, and it is a clearer statement of what the MPS is asking for than any one ADT.

## OrderedSet in this form

The MPS's `OrderedSet<T>` is `StampedCounter<T>` with the two update ops called in sequence: `insert(x)` is `stamp(x)` then `increment(1)`, `remove(x)` is `lookup(x)` then `remove(x)` returning the stamp, `member` and `size` are the reads. Written in the form above it is about thirty lines, every one of them checkable, and it is the acceptance-criterion test case for free: ten `insert` calls in one block touch no shared `popeq`.

## Evidence from outside the compiler

We built MinoCrab (sig-net/minocrab), a Rust front end that compiles to ZKIR and Impact directly, and rebuilt every Compact ledger ADT from Impact ops with the generated instruction streams checked against compactc's own output. The finding was that there is no ADT-specific lowering anywhere, only opcodes: all thirty-one standard ADT operations are the same shape, descend to the field, do the thing, write back or `popeq` the witnessed read. The general form of MPS-0046's requirement, a `Stream` whose writers insert under keys of their own choosing and whose numbering is a fold over one shared cell, needed no ledger support at all. The Impact side of this proposal is done. What remains is the language.
