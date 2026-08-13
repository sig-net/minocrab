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
- Everything reproducible via the nix flake + direnv.
- `plan.org` is the vision; don't edit it without asking.
