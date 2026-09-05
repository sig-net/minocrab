//! `cargo run -p signet-artifacts -- <out-dir>` — write the managed
//! directory `sig-net/mpc`'s sidecar and the deploy tooling read for the
//! three Signet signer circuits (M29 rungs A+B, notes/mpc-publisher.org §8).
//!
//! `zkir-v3` is located as `$ZKIR_V3` if set, else `zkir-v3` on `PATH` (the
//! flake's pinned copy, the same one compactc invokes).

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(out_dir) = args.next() else {
        eprintln!("usage: signet-artifacts <out-dir>");
        eprintln!("  writes <out-dir>/zkir/*.{{zkir,bzkir}}, <out-dir>/keys/*.{{prover,verifier}},");
        eprintln!("  <out-dir>/MANIFEST.sha256 and <out-dir>/expectedVk.json.");
        eprintln!("  $ZKIR_V3 overrides the `zkir-v3` binary looked up on PATH.");
        return ExitCode::FAILURE;
    };
    let out_dir = PathBuf::from(out_dir);
    let zkir_v3 = signet_artifacts::zkir_v3_binary();

    let start = std::time::Instant::now();
    match signet_artifacts::generate(&out_dir, &zkir_v3) {
        Ok(()) => {
            eprintln!(
                "wrote {} in {:.1}s (zkir-v3: {})",
                out_dir.display(),
                start.elapsed().as_secs_f64(),
                zkir_v3.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("signet-artifacts: {e}");
            ExitCode::FAILURE
        }
    }
}
