{
  description = "MinoCrab — Rust eDSL for Midnight, compiling to ZKIR";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
        };

        # Pinned Compact toolchain, from the LFDT-Minokawa/compact release
        # binaries (recipe + verified hashes: notes/zkir.org "Option B").
        # 0.34.0 (language 0.26.0, runtime 0.19.0, released 2026-08-25) — the
        # first FULL release of the cross-contract-capable line (ledger 9);
        # latest Mainnet-targeting stable is 0.31.1 (ledger 8, no CCC).
        # Its own flake.lock pins zkir-v3 at 04c9c5d9bceb — EXACTLY our
        # Cargo.toml rev — so this is a compactc-only pin (M31, hazard 1).
        # To bump: change version + hash below; hashes per arch in notes/zkir.org.
        compactcVersion = "0.34.0";
        # The release zips name linux targets `-unknown-linux-musl`.
        compactcTarget = {
          aarch64-darwin = "aarch64-darwin";
          x86_64-darwin = "x86_64-darwin";
          aarch64-linux = "aarch64-unknown-linux-musl";
          x86_64-linux = "x86_64-unknown-linux-musl";
        };
        compactcHashes = {
          aarch64-darwin = "sha256-zkWMQGLxod0pIFkaC7WrZXvgL0q4Qi8tdpiHc/YBA8M=";
          x86_64-darwin = "sha256-Pe4f3Q1crRM146eAdHtkDi90AQ6Pj2MRfz+B9L6lioE=";
          aarch64-linux = "sha256-0+KSxPSOJX3Naz0+PkdD19jqByn0iVPquRo2bUTNAm0=";
          x86_64-linux = "sha256-d1zN31pxOZg1Mpu/dHG6WoxU/Mgl03LHXhm6cEIGlYQ=";
        };
        compactc = pkgs.stdenvNoCC.mkDerivation {
          pname = "compactc";
          version = compactcVersion;
          src = pkgs.fetchurl {
            url = "https://github.com/LFDT-Minokawa/compact/releases/download/compactc-v${compactcVersion}/compactc_v${compactcVersion}_${compactcTarget.${system}}.zip";
            hash = compactcHashes.${system};
          };
          nativeBuildInputs = [ pkgs.unzip ];
          # the zip has no top-level directory
          unpackPhase = "unzip $src -d .";
          installPhase = ''
            mkdir -p $out/bin
            for f in compactc compactc.bin zkir zkir-v3 fixup-compact format-compact; do
              [ -e "$f" ] && install -m755 "$f" $out/bin/
            done
            # keep any support files the launcher script expects
            for d in lib node_modules share; do
              [ -d "$d" ] && cp -R "$d" $out/
            done
            true
          '';
        };
        # NO flake package for the `minocrab` CLI, decided rather than
        # missing (M24 §5; dmd pre-authorised the skip): nixpkgs'
        # importCargoLock cannot vendor this workspace — the two pinned
        # midnight-ledger git revs both export identical crate
        # name-versions (midnight-serialize-macros 1.0.0 et al.), which
        # collide in the vendor directory. The CLI stays a plain cargo
        # binary: `cargo build --release -p minocrab-sim --bin minocrab`.
      in
      {
        packages.compactc = compactc;

        # M6 baseline benchmark, from a clean checkout: `nix run .#bench`.
        # Nix only supplies the binaries (toolchain, compactc); the build
        # itself is plain cargo via ./bench.sh.
        apps.bench = {
          type = "app";
          program = "${pkgs.writeShellApplication {
            name = "minocrab-bench-app";
            runtimeInputs = [ rustToolchain pkgs.stdenv.cc compactc ];
            text = ''exec ./bench.sh'';
          }}/bin/minocrab-bench-app";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.cargo-nextest
            # M34 B: the interface crates' wire-compatibility instrument
            # (`cargo semver-checks`, the `interface-wire-compat-semver` CI
            # job). A tool, not packaging — the nix-light-touch rule.
            pkgs.cargo-semver-checks
            compactc
            # M11 stage 10: the published TypeScript decoder in spec/ts/ and
            # its vector-driven tests. BINARIES ONLY, as ever — node runs the
            # tests (`node --test`, no test framework) and tsc type-checks
            # them; neither the crate build nor the generated TS depends on
            # them, and spec/ts/ has no npm dependencies at all.
            pkgs.nodejs_22
            pkgs.typescript
            # M23 R4: the Kani instrument (`./kani.sh`, opt-in — never part
            # of the routine loop). rustup comes LAST so its proxy shims sit
            # behind rustToolchain on PATH: it exists only to serve Kani's
            # pinned nightly, and the pinned rust above must keep winning
            # for every ordinary `cargo` invocation. The gcc alias serves
            # CBMC, whose preprocessor asks for `gcc` by name — this
            # machine's /usr/bin/gcc is an xcrun shim with no CLT behind it.
            (pkgs.writeShellScriptBin "gcc" ''exec ${pkgs.clang}/bin/clang "$@"'')
            pkgs.rustup
            # M25: the Lean proofs under crates/minocrab-ir/lean/ (passes)
            # and crates/minocrab-std/lean/ (numeric/visibility) —
            # nix-provisioned (no elan).
            pkgs.lean4
          ];
        };
      });
}
