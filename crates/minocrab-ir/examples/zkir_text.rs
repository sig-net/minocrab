//! Print any ZKIR v3 `.zkir` as its instruction list — the disassembler
//! upstream's `zkir-v3` binary does not ship. Compiler-agnostic like the
//! `minocrab` CLI: it reads compactc's artifacts too, which is what it was
//! born for (re-checking notes/compact-findings.org against a new compactc
//! release). A v2 file is named and skipped.
//!
//!   cargo run -p minocrab-ir --example zkir_text -- <file.zkir>...

fn main() {
    for path in std::env::args().skip(1) {
        match minocrab_zkir::major_version(&path) {
            Ok(3) => match minocrab_zkir::v3::read_zkir(&path) {
                Ok(ir) => {
                    println!("== {path} (v3, {} instructions)", ir.instructions.len());
                    for (i, ins) in ir.instructions.iter().enumerate() {
                        println!("{i:5}  {ins:?}");
                    }
                }
                Err(e) => eprintln!("{path}: {e}"),
            },
            Ok(major) => eprintln!("{path}: ZKIR v{major}, not read (this workspace targets v3)"),
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
}
