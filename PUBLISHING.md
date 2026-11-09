# Publishing to crates.io

Everything except the publish itself is done: metadata, per-crate READMEs, rustdoc
front doors, `include` lists. What remains is one decision, below.

## The `midnight-*` line is on crates.io; `publish = false` stays until lifted

Every `midnight-*` dependency now resolves from crates.io, with no
`[patch.crates-io]`, at the versions midnight-node 2.1.101 locks (ledger
9.1.0.1, the release Mainnet, Preprod and Preview run): `midnight-ledger-v9`
1.0.1, the onchain crates 4.0.1, `midnight-zkir` 3.2.0 (the ZKIR v3 line,
imported as `midnight-zkir-v3`) and the rest named in the workspace
`Cargo.toml`. What a local `cargo package` verifies is therefore what a
downstream build resolves, and every gate in this repo runs against the
registry crates.

The seven crates that depend on the `midnight-*` line (`minocrab-zkir`,
`minocrab-ir`, `minocrab-std`, `minocrab-ledger`, `minocrab-sim`,
`minocrab-abi`, `minocrab-publisher`) still carry `publish = false`, and
everything that depends on them cannot publish either. The guard existed
because a patched build proved nothing about the registry; with the patch
gone, removing those lines is the remaining step, and a deliberate one.

Vendoring the ledger crates under our own names was considered and
**rejected**, not deferred: republishing someone else's crates is a licensing
question we do not get to answer for them, and it buys a permanent
maintenance obligation on every upstream bump.

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

Never published, each carrying `publish = false` with its reason in the
manifest: `minocrab-contracts`, `minocrab-bench`, `signet-signer-interface`,
`xcall-target-interface`. (The seven held crates above carry it too, until
it is lifted.)

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

`cargo publish --dry-run` refuses the seven held crates (`publish = false`);
`cargo package` still packages them, verifying against the registry crates.

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
