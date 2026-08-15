# MinoCrab

Rust eDSL for Midnight that compiles to ZKIR, replacing the Compact language.
Priorities in order: correctness (and obvious correctness) > performance > idiomatic Rust.

## Session start
1. Read `milestones.org`, find the current milestone.
2. Read only the `notes/*.org` files that milestone links — don't re-survey what's already written down.
3. Write new findings/decisions to `notes/` before ending; tick off tasks in `milestones.org`.

## Hard rules
- Never compile below ZKIR.
- Reuse Midnight's code (fork/import/mechanical translation) before writing our own.
- Nix provides binaries only (toolchain, compactc, dev tools) via the flake +
  direnv. The build itself is plain `cargo` — never wrap the crate build in
  nix (no `nix build` for our code, no crane/naersk).
- Compile errors over panics (dmd 2026-08-15): express API rejections in
  order of preference as missing impl / trait bound > distinct types that
  don't unify > inline-const assert (E0080) for const-known bounds >
  build-time panic only for genuinely value-dependent checks, with a
  prescriptive message, recorded for dmd to review.
- `plan.org` is the vision; don't edit it without asking.
