//! `minocrab-interface-gen` — generate or check an interface crate.
//!
//! ```text
//! minocrab-interface-gen --crate crates/signet-signer-interface
//! minocrab-interface-gen --crate crates/signet-signer-interface --check
//! ```
//!
//! The crate directory supplies everything: `artifact/generator.json` says
//! how, `artifact/contract-info.json` says what. `--check` regenerates into
//! memory and reports the first line that differs, which is what
//! `tests/regenerate.rs` runs in CI.

use std::path::PathBuf;
use std::process::ExitCode;

use minocrab_interface_gen::{check_crate, first_difference, write_crate, Error};

const USAGE: &str = "\
usage: minocrab-interface-gen --crate <dir> [--check]

  --crate <dir>  an interface crate: artifact/generator.json +
                 artifact/contract-info.json, output at src/lib.rs
  --check        regenerate and diff instead of writing
";

fn main() -> ExitCode {
    let mut dir: Option<PathBuf> = None;
    let mut check = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--crate" => match args.next() {
                Some(value) => dir = Some(PathBuf::from(value)),
                None => return fail("--crate needs a directory"),
            },
            "--check" => check = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument `{other}`")),
        }
    }
    let Some(dir) = dir else { return fail("--crate is required") };

    let result = if check { check_crate(&dir) } else { write_crate(&dir) };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Error::Drift { path, expected, found }) => {
            eprintln!("{path} has drifted from the artifact:\n{}", first_difference(&expected, &found));
            ExitCode::FAILURE
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("minocrab-interface-gen: {message}\n\n{USAGE}");
    ExitCode::FAILURE
}
