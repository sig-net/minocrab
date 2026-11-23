# minocrab-compat

**Why this crate exists.** A circuit of [MinoCrab](https://github.com/sig-net/minocrab) that is ported from a Compact contract has to emit compactc's instruction stream byte for byte. That equality is how a port is checked against the compiler's own output (the instruction-level differentials), and it is what keeps an artifact whose verifier key is already deployed from moving. The gadgets here are the compactc-shaped lowerings that equality needs: the Compact standard library transcribed as compactc inlines it, the Merkle default leaf hashed without folding its constants, secp256k1 ECDSA verification as compactc lowers it, the normaliser the differentials apply to both sides, and `profile`, which sets a circuit's lowering to compactc's: one attribute on a ported contract, `#[contract(lowering = minocrab_compat::profile)]`, applies it to every circuit in the block, and a circuit built by hand outside a block calls `minocrab_compat::profile(c)` as its first statement.

**Nothing in it is the cheapest correct lowering.** Each item says what about its shape is compactc's and what the lean form is. A contract with no Compact twin and no deployed key should not use this crate; it should use `minocrab-std`, whose gadgets are free to get cheaper.

| module | what | why it is compactc-shaped |
|---|---|---|
| `kernel` | the Compact standard-library circuits over `kernel`: send / mint / receive unshielded, the negated balance and block-time forms, `mergeCoin`, `sendShielded` | `!b` as `cond_select(b, 0, 1)`, `&&` as `cond_select`, the guard resolved once per op, `sendShielded` hashing one coin commitment twice |
| `merkle` | `insertIndexDefault` | the default leaf's digest is hashed in circuit, constants and all, where it could be folded |
| `secp` | `secp256k1EcdsaVerify` | the identity point built by `ec_mul_generator` of zero, and the x coordinate's round trip through bytes |
| `normalise` | `folded` | the copy fold the instruction-level differentials run over both streams |
| `profile` | one attribute on a ported contract (`#[contract(lowering = …)]`), or the first call of a circuit built by hand | the per-circuit lowering settings no gadget can carry |

Nothing in the core depends on this crate; only the corpus of ports and its tests do.
