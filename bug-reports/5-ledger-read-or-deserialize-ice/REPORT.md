# Internal error on `<ledger read> || deserialize<…>(…)`

### Context & versions:

compactc 0.35.0 (debb05f94 2026-09-29), language 0.27.0, runtime 0.20.0, aarch64-darwin. Last good: compactc 0.34.0 (language 0.26.0), so this is a 0.27.0 regression.

Not zkir-v3 specific — the default v2 backend crashes identically.

### Steps to reproduce:

1. Save `ice.compact`:

```compact
pragma language_version >= 0.25;

import CompactStandardLibrary;

export ledger flag: Boolean;

export circuit go(output: Bytes<1>): Boolean {
  return flag || deserialize<Boolean, 1>(output);
}
```

2. `compactc --skip-zk ice.compact out`

Three ingredients, each necessary — dropping any one compiles: a short-circuit operator (`||` or `&&`), a **ledger read** on one side (a circuit parameter of the same type compiles), and a **`deserialize`** on the other. `test.sh` in this directory asserts the crash plus those three controls.

### Actual behavior:

Exit 254:

```
Internal error (please report): Exception in check-types/Lflattened: detected at compiler/circuit-passes/check-types-Lflattened.ss line 259 char 24: downstream type-check failure:
Exception: ice.compact line 1 char 1:
  incompatible types Uint<0..256> and Uint<0..3> for relational operator
```

The program contains no relational operator and no `Uint<0..3>`. Both named types are constant across every variant we tried — two-member enum, `Uint<8>`, `Bytes<2>`, or none of them — so they look like an artifact of the pass, not a reading of the source. The reported location is also unusable: line 1, or the `import` line when the shape arrives through one.

### Expected behavior:

Compiles, as on 0.34.0. Failing that, a diagnostic naming the real construct and location rather than an internal error.
