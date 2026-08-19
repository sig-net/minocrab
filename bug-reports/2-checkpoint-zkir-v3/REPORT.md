# `kernel.checkpoint()` cannot be compiled with `--feature-zkir-v3`

The v2 backend assembles `kernel.checkpoint()`'s `ckpt` instruction; the v3
backend has no case for it, so any contract calling `checkpoint()` fails to
compile under `--feature-zkir-v3` — and it fails with an internal assertion
rather than a diagnostic naming the unsupported construct. Two issues: the
feature gap, and the internal-error crash where a proper error is expected.

## Repro

`checkpoint.compact`:

```compact
import CompactStandardLibrary;

export circuit doCheckpoint(): [] {
  kernel.checkpoint();
}
```

```
$ compactc checkpoint.compact out                    # exit 0
$ compactc --feature-zkir-v3 checkpoint.compact out   # exit 254
unimplemented: #[#{vminstr f5kki0ul5pj8zvc19sy1zpm3n-51092} "ckpt" ()]
Internal error (please report): Exception: failed assertion not-implemented at line 748, char 23 of compiler/zkir-v3-passes.ss
```

`test.sh` in this directory asserts this (v2 compiles, v3 crashes with
`not-implemented`); needs only `compactc`.

---
compactc 0.33.0 (0.33.0-rc.2), language 0.25.0, ledger-9.1.0.0-rc.3.
