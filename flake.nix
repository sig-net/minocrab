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
        # 0.36.1 (language 0.28.0, runtime 0.21.0), the toolchain Midnight's
        # compatibility matrix lists for ledger 9.1.0.1. It emits ZKIR v3 only
        # and fixes compact#616 and #856.
        # Its own flake.lock pins zkir-v3 at midnight-zkir 7a51b338
        # (zkir-3.2.1, the #616 key-generation fix); our Cargo.toml names the
        # crates.io midnight-zkir 3.2.0 that midnight-node locks
        # (notes/version-bump.org).
        # To bump: change version + hash below; hashes per arch in notes/zkir.org.
        compactcVersion = "0.36.1";
        # The release zips name linux targets `-unknown-linux-musl`.
        compactcTarget = {
          aarch64-darwin = "aarch64-darwin";
          x86_64-darwin = "x86_64-darwin";
          aarch64-linux = "aarch64-unknown-linux-musl";
          x86_64-linux = "x86_64-unknown-linux-musl";
        };
        compactcHashes = {
          aarch64-darwin = "sha256-lu5opZ2eiwk/Bcl0eaTPCMeXYAFdzCbsx5fsAWDKJ/k=";
          x86_64-darwin = "sha256-wz7XXSKCU8j2R5YMyQgslGlswegadBZD/E2iM7Ii1WQ=";
          aarch64-linux = "sha256-fwcwTYGNK6tvlgEyd3ISOLu5aQjti/eSc0BNg6ZFyEQ=";
          x86_64-linux = "sha256-nV/t/smud1oeR9XG94UTCzFMHFxSzRpOufxW0fxh0jo=";
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
        # No flake package for the `minocrab` CLI, deliberately: the crate
        # build is plain cargo, and the CLI stays a cargo binary:
        # `cargo build --release -p minocrab-sim --bin minocrab`.
      in
      {
        packages.compactc = compactc;

        # Baseline benchmark, from a clean checkout: `nix run .#bench`.
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
            # The interface crates' wire-compatibility instrument
            # (`cargo semver-checks`, the `interface-wire-compat-semver` CI job).
            pkgs.cargo-semver-checks
            # The supply-chain gate (`cargo deny check`, the `deny:`
            # CI job) — advisories/licenses/bans/sources per deny.toml.
            pkgs.cargo-deny
            # Pruning target/: cargo never prunes it, so every fingerprint
            # change leaves its old generation behind. `cargo sweep --time 14`
            # collects the stale ones without the full rebuild `cargo clean` costs.
            pkgs.cargo-sweep
            compactc
            # The published TypeScript decoder in spec/ts/ and
            # its vector-driven tests. Binaries only — node runs the
            # tests (`node --test`, no test framework) and tsc type-checks
            # them; neither the crate build nor the generated TS depends on
            # them, and spec/ts/ has no npm dependencies at all.
            pkgs.nodejs_22
            pkgs.typescript
            # The Kani instrument (`./kani.sh`, opt-in — never part
            # of the routine loop). rustup comes last so its proxy shims sit
            # behind rustToolchain on PATH: it exists only to serve Kani's
            # pinned nightly, and the pinned rust above must keep winning
            # for every ordinary `cargo` invocation. The gcc alias serves
            # CBMC, whose preprocessor asks for `gcc` by name — this
            # machine's /usr/bin/gcc is an xcrun shim with no CLT behind it.
            (pkgs.writeShellScriptBin "gcc" ''exec ${pkgs.clang}/bin/clang "$@"'')
            pkgs.rustup
            # The Lean proofs under crates/minocrab-ir/lean/ (passes)
            # and crates/minocrab-std/lean/ (numeric/visibility) —
            # nix-provisioned (no elan).
            pkgs.lean4
          ];
        };
      });
}
