# Publishing to crates.io

Nothing is published yet. Everything up to the publish itself is in place: every crate in the set below packages and verifies against the registry with `cargo package`, carries its metadata, README, both license texts and an `include` list, and builds its docs warning-free. Publishing is done by hand by the owner, following the numbered steps below top to bottom.

**A published version cannot be deleted.** `cargo yank` stops new lockfiles from resolving to it; it does not remove the code, and anything already locked to it keeps building against it. A crate name, once taken by a first publish, stays ours and stays taken. Check every step before running it.

## The set

Thirteen crates, the transitive closure (regular and build dependencies) of the core, the compat crate, the EVM and Signet app crates and the signer interface:

| crate | what | stability |
|---|---|---|
| `minocrab-zkir` | L0: read, write and round-trip ZKIR v3 | core |
| `minocrab-ir` | L1: the typed circuit builder | core |
| `minocrab` | the eDSL: wires, visibility, disclosure | core |
| `minocrab-macros` | `#[circuit]`, `#[contract]`, `#[interface]`, the derives | core |
| `minocrab-ledger` | Impact ledger-op emission | core |
| `minocrab-std` | the standard library (re-exports the eDSL and the macros) | core |
| `minocrab-sim` | the native ZKIR simulator and the `minocrab` CLI | core |
| `minocrab-taint` | the byte-atom taint lint | core |
| `minocrab-compat` | the compactc-shaped gadgets parity ports import | follows core |
| `minocrab-evm` | typed EVM calls and the Solidity ABI words | app crate, semver from 0.1.0 |
| `signet-protocol` | the signet signer's protocol facts | app crate, semver from 0.1.0 |
| `signet-signer-interface` | the signet signer's cross-contract interface | its own version, 0.3.0 |
| `minocrab-signet` | the Signet protocol for circuits: records, `Pending`, outbox | app crate, semver from 0.1.0 |

`minocrab-sim` is in the set because every contract author needs it: it is the dev-dependency a circuit's tests run under, `#[circuit(max_k = …)]` expands to a test that calls `minocrab_sim::v3::assert_max_k`, and it carries the `minocrab rows` / `minocrab diff` CLI. Its dependencies are all in the set.

## Stability

- **Core** (`minocrab-zkir`, `minocrab-ir`, `minocrab`, `minocrab-macros`, `minocrab-ledger`, `minocrab-std`, `minocrab-sim`, `minocrab-taint`): semver from 0.1.0, with the usual 0.x reading: a 0.(x+1).0 may break anything, a 0.x.(y+1) does not. The core crates share the workspace version and are released together. Within them, the README's stability tiers say which surface is meant to hold still across minor releases and which layers are internal and expected to move at the next one.
- **Compat** (`minocrab-compat`): follows core, same version, same release. Its gadgets exist to keep a ported circuit byte-identical to compactc's output, so a change that moves a byte of a parity port's stream is breaking even when it type-checks.
- **The experimental crate**, when it exists: published at 0.0.x with no compatibility promise, said in its README and crate docs. No core crate may depend on it, so its churn cannot reach a stable crate.
- **`signet-signer-interface`**: versioned by the deployed contract's wire format, not by the workspace. Any change to `artifact/interface-schema.txt` is a major version; adding a circuit is minor; re-pinning to a same-signature redeploy is a patch (the table and the reasons are in notes/interface-crates.org, "Versioning and publishing conventions").
- **App crates** (`minocrab-evm`, `signet-protocol`, `minocrab-signet`): semver from 0.1.0 on the workspace version. A change to the wire vocabulary they encode is breaking whatever the Rust signature does.

## Deliberately not published

Each carries `publish = false` with its reason in the manifest.

- `minocrab-contracts`: the corpus of ported contracts and the suites that pin MinoCrab to compactc. It reads `corpus/` and `spec/`, which only exist in this repository.
- `minocrab-bench`: the benchmark harness behind BENCHMARK.md.
- `signet-artifacts`: the managed key and artifact directory for the signer circuits; depends on the corpus.
- `xcall-target-interface`: an example generated interface crate, the regeneration fixture for `minocrab-interface-gen`.
- `signet-sim`: the MPC as a pure function for tests; nothing published depends on it.
- `minocrab-abi` and `minocrab-interface-gen`: the artifact-agreement checker and the importer. Nothing published depends on them (an interface crate takes `minocrab-abi` as a dev-dependency only); both have full metadata and can join later as leaves, `minocrab-abi` after `minocrab-ledger` and `minocrab-interface-gen` after it.
- `minocrab-publisher` and `signet-hashing`: the MPC publisher's core and the protocol's off-circuit hashes, consumed by git. Nothing published depends on them; `signet-hashing` could join after `signet-protocol`, `minocrab-publisher` after both.

## How the manifests make this work

- **Regular dependencies on our crates carry a version.** Each goes through `[workspace.dependencies]`, one place, path AND version: the path is used for the local build, the version is what crates.io resolves. `signet-signer-interface`'s entry carries its own version (0.3.0), not the workspace's. `crates/minocrab-contracts/tests/workspace_versions.rs` holds every entry to the version of the crate it names, and holds every published crate to depending on our crates only through those entries and only on published ones.
- **Dev-dependencies on our crates are versionless** (`{ path = … }`). Cargo strips a versionless dev-dependency on publish, which is what breaks the `minocrab-std` ↔ `minocrab-sim` dev-dependency cycle open, and it means no published crate ships a runnable test suite. `cargo publish` verifies a package by building its library and binaries, not by running its tests, so nothing in the set needs another crate's tests to publish.
- **`include` lists** ship `src/**/*.rs`, `README.md`, `LICENSE-MIT` and `LICENSE-APACHE`, plus what the source reads at compile time: the Lean files `lean_proof!` embeds with `include_str!` (`minocrab-zkir`, `minocrab-ir`, `minocrab-std`) and, for `signet-signer-interface`, its `artifact/` pin and frozen schema as reference data. Tests and examples are excluded on purpose: the suites read `../../corpus` (the compactc artifacts) and `../../spec`, neither of which exists in a downstream checkout, so a shipped test could only fail. The warrant for these crates lives in the repository, not in the package; see [VERIFICATION.md](VERIFICATION.md).
- **Both license texts are copied into every published crate's directory** and named in its `include` list. The SPDX expression `MIT OR Apache-2.0` in the manifest is a claim; the `.crate` tarball has to carry the texts it points at. The copies at `crates/*/LICENSE-{MIT,APACHE}` are the repository root's, byte for byte.
- **Every `midnight-*` dependency is on crates.io**, with no `[patch.crates-io]`, at the versions midnight-node 2.1.101 locks (ledger 9.1.0.1). The requirements are caret ranges (`midnight-zkir` is exact, `=3.2.0`), so a downstream build without this lockfile may resolve newer compatible releases.

## Pre-publish checklist

On a clean checkout of the commit being published (`git status` empty, the commit on `main`):

1. `cargo test --workspace --no-fail-fast`: zero failures.
2. `cargo clippy --workspace --all-targets -- -D warnings`.
3. `cargo deny check`.
4. The ZKIR byte-identity check against the last release (or the base of the release branch): dump every circuit with `MINOCRAB_ZKIR_DUMP=<dir> cargo test -p minocrab-contracts --test zkir_dump -- --ignored dump_every_circuits_zkir` at both commits and `diff -rq` the two directories. Every moved byte is explained in the history (CONTRIBUTING.md, "Run the gates").
5. `cargo test --release -p minocrab-contracts --test row_snapshot --test interface_snapshot`.
6. The docs, as docs.rs builds them, warning-free:
   ```sh
   RUSTDOCFLAGS="-D warnings" cargo doc --no-deps \
     -p minocrab-zkir -p minocrab-ir -p minocrab -p minocrab-macros -p minocrab-ledger \
     -p minocrab-std -p minocrab-sim -p minocrab-taint -p minocrab-compat -p minocrab-evm \
     -p signet-protocol -p signet-signer-interface -p minocrab-signet
   ```
7. Package and verify the whole set against the registry. Cargo resolves the set's members against each other through a local overlay, so this works before anything is published:
   ```sh
   cargo package --workspace \
     --exclude minocrab-contracts --exclude minocrab-bench --exclude signet-artifacts \
     --exclude xcall-target-interface --exclude signet-sim --exclude minocrab-abi \
     --exclude minocrab-interface-gen --exclude minocrab-publisher --exclude signet-hashing
   ```
8. The versions: `[workspace.package] version` is the release's, and `cargo test -p minocrab-contracts --test workspace_versions` passes (it fails if a `[workspace.dependencies]` entry still names the old number).
9. `cargo login` with a token for the owning account, scoped to publish.

## Publish order

Each crate must be on crates.io before the next one resolves. `cargo publish` waits until the crate it uploaded is visible in the index before it returns, so the steps can be run one after another; if a step is interrupted after the upload, wait until the crate appears on crates.io before running the next. crates.io rate-limits the publishing of NEW crate names: if a step is refused for that, wait the time the error names and rerun the same step (nothing was uploaded).

1. `cargo publish -p minocrab-zkir` (depends on `midnight-*` only)
2. `cargo publish -p minocrab-macros` (`syn` / `quote` only)
3. `cargo publish -p signet-protocol` (`sha2` only)
4. `cargo publish -p minocrab-ir` (→ zkir)
5. `cargo publish -p minocrab` (→ ir)
6. `cargo publish -p minocrab-taint` (→ ir, zkir)
7. `cargo publish -p minocrab-ledger` (→ minocrab, ir)
8. `cargo publish -p minocrab-std` (→ minocrab, ledger, macros)
9. `cargo publish -p minocrab-sim` (→ minocrab, ir, zkir)
10. `cargo publish -p minocrab-compat` (→ minocrab, std, ledger, ir, zkir)
11. `cargo publish -p minocrab-evm` (→ minocrab, std)
12. `cargo publish -p signet-signer-interface` (→ minocrab, std, ledger)
13. `cargo publish -p minocrab-signet` (→ minocrab, std, ledger, evm, signet-protocol, signet-signer-interface)

The last rehearsal before step 1 is a dry run of the whole set, which resolves the set's members against each other the way step 7 of the checklist does and stops short of every upload:

```sh
cargo publish --dry-run --workspace \
  --exclude minocrab-contracts --exclude minocrab-bench --exclude signet-artifacts \
  --exclude xcall-target-interface --exclude signet-sim --exclude minocrab-abi \
  --exclude minocrab-interface-gen --exclude minocrab-publisher --exclude signet-hashing
```

A single-crate `cargo publish --dry-run -p <crate>` only works once the crates before it are on crates.io (before step 1, for steps 1 to 3 alone). After the last step, tag the commit (`git tag v0.1.0`) and push the tag.

`minocrab-sim` ships a binary, and with it its `Cargo.lock`. That lock currently carries `chacha20 0.10.1`, which is yanked (a transitive dependency of the pinned `midnight-*` crates; `deny.toml` records it), so `cargo install minocrab-sim --locked` warns about it.

## docs.rs

- **No crate in the workspace has a `build.rs`.** Nothing needs compactc, nix, or any binary at build time. The toolchain is a *test* dependency (`zkir mock-compile`, the differential suites) and tests are not packaged, so a docs.rs build is a plain `cargo doc` over crates.io dependencies.
- `minocrab-std` is the only crate whose features change the docs (`macros`, default; and `borsh-schema`, off: nothing shipping links borsh). Its `[package.metadata.docs.rs] all-features = true` documents the schema module too. `minocrab-ir` and `minocrab-sim` carry an empty `unstable` feature, kept as an alias a downstream port names; it gates nothing.
- No `rustdoc-args` are set. Nothing here uses `#[doc(cfg)]`, so `--cfg docsrs` would buy nothing.
- Intra-doc links only reach a crate's own items and its direct dependencies. Neighbours across the stack that are not dependencies are named in plain backticks in the crate docs, deliberately.
- Two gotchas worth knowing before writing more docs. **`effects[4]` in prose is a markdown link**: rustdoc reports "unresolved link to `4`"; write `effects\[4\]`. And a `//!` block in a file whose `pub mod` declaration also carries a `///` doc gets resolved in the PARENT module's scope, so such a file spells its header links absolutely (`crate::v3::hash::persistent_hash`).

## rust-version

`1.85`, workspace-wide. Our own code's floor is 1.79 (inline `const { assert!(..) }`), but every pinned `midnight-*` crate is **edition 2024** (`base-crypto`, `transient-crypto`, `zkir`, `serialize`, `onchain-vm`, `storage`), which rustc accepts from 1.85. Nothing here can build below that, so claiming 1.79 would be a claim we cannot honour. Re-derive it when upstream moves.

## Vendoring was rejected

Vendoring the ledger crates under our own names was considered and **rejected**, not deferred: republishing someone else's crates is a licensing question we do not get to answer for them, and it buys a permanent maintenance obligation on every upstream bump.
