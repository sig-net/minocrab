# Publishing to crates.io

Everything except the publish itself is done: metadata, per-crate READMEs, rustdoc
front doors, `include` lists. What remains is one external blocker, below.

## Blocked: the `midnight-*` line is not on crates.io

Every `midnight-*` dependency is declared as a crates.io version (workspace
`Cargo.toml`), and `[patch.crates-io]` (in `Cargo.toml` and, identically,
`.cargo/config.toml`) points each at rev `04c9c5d9…` of
`midnightntwrk/midnight-ledger`, because that rev is what the official compact
flake pins for the zkir binaries our compactc ships with. The registry only
carries the older, incompatible ledger-8 / zkir-2.1 line, and no
`midnight-zkir-v3` or `midnight-ledger-v9` at all, so a publish fails today at
dependency resolution.

The versions are there so that a downstream workspace links our crates under
its own `[patch.crates-io]` (sig-net/mpc links `minocrab-publisher` and
`signet-protocol` against the per-crate ledger tags midnight-node pins): a git
dependency could not be patched to the same repository, and two copies of the
ledger types do not unify. A `[patch]` is never packaged.

**The plan is still to wait for upstream** (dmd, 2026-08-17). Midnight
publishes the ledger-9.1 line to crates.io at our rev; the patch entries go;
this document becomes a checklist. The ask is queued for the upstream team
through the usual feedback channel — see notes/compact-findings.org.

Vendoring the pinned crates under our own names was considered and **rejected**,
not deferred: republishing someone else's crates is a licensing question we do
not get to answer for them, and it buys a permanent maintenance obligation on
every upstream bump.

### The guard that replaces the git-dependency check

The packaged manifest carries the version requirements and no patch. Once
upstream publishes semver-compatible versions, `cargo publish` would go
through and a downstream build would resolve them, which compiles something
silently different from what every test in this repo checks unless those
versions ARE rev `04c9c5d9…`. That is the exact failure class this project
exists to prevent, so before any publish: confirm every `midnight-*` version
the lockfile resolves is published from the pinned rev (or move the pin to
what was published and rerun every gate), then delete the patch entries and
rerun every gate against the registry. Until then, nothing is published.

Path dependencies on our own crates *do* carry versions
(`[workspace.dependencies]`, one place). The path is used for the local build
and the version requirement resolves to the same crate we are publishing.

## Publish order

The dependency DAG, regular dependencies only. Each must be on crates.io before
the next resolves.

```
1. minocrab-zkir            (midnight-* only)
2. minocrab-ir              → zkir
3. minocrab                 → ir
4. minocrab-macros          (syn/quote only; anytime before minocrab-std)
5. minocrab-ledger          → minocrab, ir
6. minocrab-std             → minocrab, ledger, macros
7. minocrab-sim             → minocrab, zkir
8. minocrab-abi             → minocrab, ledger, zkir
9. minocrab-interface-gen   → abi
```

**Dev-dependencies are deliberately versionless** (`{ path = … }`, no version).
Cargo strips a versionless dev-dependency on publish, which is what breaks the
`minocrab-std` ↔ `minocrab-sim` dev-dependency cycle open for a first publish.
It also means no published crate ships a runnable test suite — see `include`
below.

Not published, each carrying `publish = false` with its reason in the manifest:
`minocrab-contracts`, `minocrab-bench`, `signet-signer-interface`,
`xcall-target-interface`.

## Dry run

```sh
# What each crate would ship. Works today.
# (Add --allow-dirty to run it against uncommitted work.)
for c in minocrab-zkir minocrab-ir minocrab minocrab-macros minocrab-ledger \
         minocrab-std minocrab-sim minocrab-abi minocrab-interface-gen; do
  cargo package --list -p "$c"
done

# Docs, as docs.rs would build them.
cargo doc --no-deps -p minocrab-std   # …and each of the nine

# The real thing, once unblocked. --dry-run still runs the full verify build.
cargo publish --dry-run -p minocrab-zkir
```

`cargo package --no-verify` packages today; `cargo package` and
`cargo publish --dry-run` **fail today** when their verify build resolves the
`midnight-*` versions against crates.io. That is the blocker above, not a
defect.

## What each crate ships

`include = ["src/**/*.rs", "README.md", "LICENSE-MIT", "LICENSE-APACHE"]`, plus
`tests/fixtures/**` for `minocrab-zkir` (its unit test embeds one 784-byte
`.zkir`).

Tests are excluded on purpose: the suites read `../../corpus` (788 compactc
artifacts) and `../../spec`, neither of which exists in a downstream checkout,
so a shipped test file could only fail. The warrant for these crates lives in
the repository, not in the package — see
[VERIFICATION.md](VERIFICATION.md).

Both license files are COPIED into every publishable crate directory and named
in every `include` list. The SPDX expression `MIT OR Apache-2.0` in the manifest
is a claim; the `.crate` tarball has to carry the texts that claim points at,
and `include` ships nothing it is not told to. The copies at
`crates/*/LICENSE-{MIT,APACHE}` are the repository root's, byte for byte.

## docs.rs

- **No crate in the workspace has a `build.rs`.** Nothing needs compactc, nix,
  or any binary at build time. The toolchain is a *test* dependency
  (`zkir mock-compile`, the differential suites) and tests are not packaged, so
  a docs.rs build is a plain `cargo doc` over crates.io dependencies.
- `minocrab-std` is the only crate with features (`macros`, default; and
  `borsh-schema`, off — nothing shipping links borsh). Its
  `[package.metadata.docs.rs] all-features = true` documents the schema module
  too. The other eight are featureless and need no metadata.
- No `rustdoc-args` are set. Nothing here uses `#[doc(cfg)]`, so `--cfg docsrs`
  would buy nothing.
- Intra-doc links only reach a crate's own items and its direct dependencies.
  Neighbours across the stack that are not dependencies are named in plain
  backticks in the crate docs — deliberately, not an oversight.
- All nine build warning-free with the link lints denied. Keep them that way:

  ```sh
  RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::invalid_html_tags -D rustdoc::bare_urls" \
    cargo doc --no-deps -p minocrab-zkir -p minocrab-ir -p minocrab -p minocrab-macros \
      -p minocrab-ledger -p minocrab-std -p minocrab-sim -p minocrab-abi -p minocrab-interface-gen
  ```

  Two gotchas this shook out, both worth knowing before writing more docs.
  **`effects[4]` in prose is a markdown link** — rustdoc reports "unresolved
  link to `4`"; write `effects\[4\]`. And a `//!` block in a file whose
  `pub mod` declaration also carries a `///` doc gets resolved in the PARENT
  module's scope, so `v3/hash.rs`, `v3/borsh.rs` and `v3/kernel.rs` spell their
  header links absolutely (`crate::v3::hash::persistent_hash`).

## rust-version

`1.85`, workspace-wide. Our own code's floor is 1.79 (inline
`const { assert!(..) }` in `minocrab-std/src/v3.rs`), but every pinned
`midnight-*` crate is **edition 2024** — `base-crypto`, `transient-crypto`,
`zkir`, `serialize`, `onchain-vm`, `storage` — which rustc accepts from 1.85.
Nothing here can build below that, so claiming 1.79 would be a claim we cannot
honour. Re-derive it when upstream publishes, against whatever they publish.
