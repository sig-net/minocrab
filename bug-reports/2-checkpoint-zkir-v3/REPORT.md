# `kernel.checkpoint()` cannot be compiled with `--feature-zkir-v3`

Corresponds to `notes/compact-findings.org` entry 1. **Verified 2026-08-19.**

## Summary

The v2 backend assembles `kernel.checkpoint()`'s `ckpt` instruction; the v3
backend has no case for it, so any contract calling `checkpoint()` fails to
compile under `--feature-zkir-v3` — and it fails with an internal assertion
rather than a diagnostic naming the unsupported construct and the flag that
made it unsupported.

Two deficiencies in one:

1. **Feature gap** — `kernel.checkpoint()` is unusable on ZKIR v3.
2. **Diagnostic quality** — the failure is an internal-error assertion, not a
   user-facing error saying "checkpoint is not supported with
   --feature-zkir-v3".

## Reproduction

`checkpoint.compact` in this directory:

```compact
import CompactStandardLibrary;

export circuit doCheckpoint(): [] {
  kernel.checkpoint();
}
```

```
$ compactc --skip-zk checkpoint.compact out-v2                    # exit 0
$ compactc --skip-zk --feature-zkir-v3 checkpoint.compact out-v3  # exit 254
unimplemented: #[#{vminstr f5kki0ul5pj8zvc19sy1zpm3n-51092} "ckpt" ()]
Internal error (please report): Exception: failed assertion not-implemented at line 748, char 23 of compiler/zkir-v3-passes.ss
```

(`--skip-zk` is irrelevant to the bug; the failure is in circuit generation,
before proving keys.)

## Self-contained test

`test.sh` in this directory is a runnable assertion of the bug — it needs only
`compactc` on `PATH`:

```
$ ./test.sh
ok: v2 compiles kernel.checkpoint()
ok: v3 crashes with the internal assertion (bug reproduced):
    Internal error (please report): Exception: failed assertion not-implemented at line 748, char 23 of compiler/zkir-v3-passes.ss
PASS: checkpoint compiles on v2 and crashes the v3 backend.
```

It exits 0 while the bug is present (v2 compiles, v3 crashes with
`not-implemented`) and starts failing once v3 either supports `checkpoint` or
rejects it with a proper diagnostic.

## Impact

Any v3 contract using `kernel.checkpoint()`. The v2 path is unaffected.

## Environment

- compactc 0.33.0 (the 0.33.0-rc.2 release bundle), language version 0.25.0,
  ledger-9.1.0.0-rc.3
- macOS 26.5.1, arm64, compactc from the release binary via Nix
