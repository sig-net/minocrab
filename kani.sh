#!/bin/zsh
# The Kani instrument (M23 R4): `./kani.sh [cargo-kani args]`.
# Defaults to every harness in minocrab-ir. NEVER part of the routine loop —
# plain `cargo test` compiles none of the #[cfg(kani)] modules.
#
# ONE-TIME SETUP, per machine (notes/formal-verification-options.org
# §"As built — M23 R4"):
#
#   cargo install --locked kani-verifier   # the driver, into ~/.cargo/bin
#   cargo kani setup                       # bundle + pinned nightly, via
#                                          # rustup (the flake provides
#                                          # rustup; nix's pinned rust stays
#                                          # first on PATH, which the
#                                          # devshell ordering guarantees)
#
# TEMPORARY SHIMS, both of which die the day Kani's pinned nightly reaches
# rustc >= 1.95 (Kani 0.67 pins nightly-2025-11-21 = 1.93, and the
# workspace's transitive dep `sysinfo 0.39` — via midnight-storage —
# declares rust-version 1.95 and uses `cfg_select`, stabilized after 1.93):
#
# 1. This script doubles as its own RUSTC_WRAPPER and appends
#    `-Zcrate-attr=feature(cfg_select)` to kani-compiler invocations only
#    (Kani builds under RUSTC_BOOTSTRAP=1, so declaring the feature
#    suffices; the stable host rustc probes pass through untouched).
#
# 2. Kani's toolchain cargo must pass `--ignore-rust-version` — Kani calls
#    that cargo binary DIRECTLY (no $CARGO, no $PATH lookup), so the only
#    lever is a shim at ~/.kani/kani-*/toolchain/bin/cargo. This script
#    checks the shim is in place and prints the recipe if not; it does not
#    install it.

# RUSTC_WRAPPER mode: cargo invokes `$RUSTC_WRAPPER <rustc> <args…>`, where
# <rustc> may be a bare `rustc` (host probes) or the kani-compiler path.
if [[ ${1-} == *kani-compiler* || ${1-} == rustc || ${1-} == */rustc ]]; then
  rustc=$1; shift
  case $rustc in
    *kani-compiler*) exec "$rustc" "$@" -Zcrate-attr='feature(cfg_select)';;
    *) exec "$rustc" "$@";;
  esac
fi

set -euo pipefail

if ! command -v cargo-kani >/dev/null; then
  echo "cargo-kani not installed — see the setup recipe at the top of $0" >&2
  exit 1
fi
if ! gcc --version >/dev/null 2>&1; then
  echo "no working \`gcc\` on PATH (CBMC needs one; the flake devshell provides a clang alias)" >&2
  exit 1
fi

# The toolchain-cargo shim (shim 2 above): present iff cargo-real exists
# beside cargo.
toolchain_cargo=(~/.kani/kani-*/toolchain/bin/cargo(N))
if [[ ${#toolchain_cargo} -eq 0 || ! -e ${toolchain_cargo[1]}-real ]]; then
  cat >&2 <<'RECIPE'
The MSRV shim is missing from Kani's toolchain cargo. Install it with:

  cd ~/.kani/kani-*/toolchain/bin
  mv cargo cargo-real
  printf '%s\n' '#!/bin/zsh' \
    '# MSRV shim: see kani.sh at the MinoCrab repo root.' \
    'real=${0:h}/cargo-real' \
    'sub=$1; shift' \
    'case $sub in' \
    '  build|check|rustc|test) exec "$real" "$sub" --ignore-rust-version "$@";;' \
    '  *) exec "$real" "$sub" "$@";;' \
    'esac' > cargo
  chmod +x cargo
RECIPE
  exit 1
fi

export RUSTC_WRAPPER=${0:A}
if (( $# )); then
  exec cargo kani "$@"
else
  exec cargo kani -p minocrab-ir
fi
