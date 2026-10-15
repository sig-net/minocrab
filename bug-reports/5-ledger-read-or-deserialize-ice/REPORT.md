# Internal error on `<ledger read> || deserialize<…>(…)` (regression in 0.35.0)

A short-circuit `||` (or `&&`) whose one side reads a ledger field and whose other side calls `deserialize` crashes the compiler in `check-types/Lflattened`. It is an internal error, not a diagnostic, and the types it names appear in no source type. 0.34.0 compiles the same program; 0.35.0 does not, so this is a language 0.27.0 regression.

It is NOT specific to `--feature-zkir-v3`: the default (v2) backend crashes identically.

## Repro

`ice.compact`, in full:

```compact
pragma language_version >= 0.25;

import CompactStandardLibrary;

export ledger flag: Boolean;

export circuit go(output: Bytes<1>): Boolean {
  return flag || deserialize<Boolean, 1>(output);
}
```

```
$ compactc --skip-zk ice.compact out                     # 0.34.0 -> exit 0
$ compactc --skip-zk ice.compact out                     # 0.35.0 -> exit 254
Internal error (please report): Exception in check-types/Lflattened: detected at compiler/circuit-passes/check-types-Lflattened.ss line 259 char 24: downstream type-check failure:
Exception: ice.compact line 1 char 1:
  incompatible types Uint<0..256> and Uint<0..3> for relational operator
```

Two separate problems: the crash itself, and that a program with no relational operator and no `Uint<0..3>` anywhere is rejected for having both.

## What is and is not required

Established by ablation from the original failing contract down to the nine lines above.

REQUIRED — remove any one of these and it compiles:

- **A short-circuit operator.** `||` and `&&` both crash. Binding the two sides to separate `const`s and returning one of them compiles, so it is the short-circuit lowering, not the two expressions coexisting.
- **A ledger read on one side.** A circuit *parameter* of the same type does not crash; the value has to come from a ledger field. `export ledger flag: Boolean` is enough — no `Map`, no `lookup`.
- **`deserialize` on the other side.** Replacing it with another `Bytes`-valued expression (`output != default<Bytes<1>>`) compiles.

NOT required — each of these varies freely with no effect:

- `--feature-zkir-v3` (crashes on the default v2 backend too).
- `disclose`.
- The ledger field's type: `Boolean` and `Uint<8>` both crash; so does a `Map<Bytes<32>, …>` lookup.
- A comparison: `flag`, `k == 1` and `m.member(k)` all crash.
- `deserialize`'s target: a one-field struct and a bare `Boolean` both crash.
- The byte length: `Bytes<1>` and `Bytes<2>` both crash.
- An enum anywhere. The original contract had one, which is why the reported `Uint<0..3>` looked like a three-member enum's range — it is not. A two-member enum, and no enum at all, both still report `Uint<0..256>` and `Uint<0..3>`. **Those two types are constant across every variant we tried, regardless of the source types involved**, which suggests they are an artifact of the pass rather than a reading of the program.

## How we hit it

A production contract of 29 circuits, of which exactly the two with the shape

```compact
if (outcomeRefunds(record.outputKind) || !deserialize<VaultResponse, 1>(output).success) { … }
```

failed — `record` being a ledger `Map` lookup. The other 27 compiled. The error is reported at the file's first line (or, when the shape arrives through an import, at the `import` line), which is some distance from the code responsible; the location was not usable for finding it.

## Test

`test.sh` asserts the crash is present and is the internal error rather than a clean diagnostic. It passes while the bug is live and starts failing once the compiler either accepts the program or rejects it properly. Needs only `compactc` on PATH.

---
Found on compactc 0.35.0 (debb05f94 2026-09-29), language 0.27.0, runtime 0.20.0, aarch64-darwin. Last good: compactc 0.34.0 (language 0.26.0).
