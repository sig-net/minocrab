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
        # 0.33.0-rc.2 = first cross-contract-capable toolchain (ledger 9);
        # latest stable is 0.31.1 (current Mainnet, ledger 8, no CCC).
        # To bump: change version + hash below; hashes per arch in notes/zkir.org.
        compactcVersion = "0.33.0-rc.2";
        compactcHashes = {
          aarch64-darwin = "sha256-NaKACcmlfSCQLk/P0S8MqeqUM4IIlUz4vNM1ZS4k84I=";
        };
        compactc = pkgs.stdenvNoCC.mkDerivation {
          pname = "compactc";
          version = compactcVersion;
          src = pkgs.fetchurl {
            url = "https://github.com/LFDT-Minokawa/compact/releases/download/compactc-v${compactcVersion}/compactc_v${compactcVersion}_${system}.zip";
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
      in
      {
        packages.compactc = compactc;

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.cargo-nextest
            compactc
          ];
        };
      });
}
