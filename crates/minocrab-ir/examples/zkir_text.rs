//! Print any `.zkir` (v2 or v3) as its instruction list — the disassembler
//! upstream's `zkir`/`zkir-v3` binaries do not ship. Compiler-agnostic like
//! the `minocrab` CLI: it reads compactc's artifacts too, which is what it
//! was born for (re-checking notes/compact-findings.org against a new
//! compactc release).
//!
//!   cargo run -p minocrab-ir --example zkir_text -- <file.zkir>...

fn main() {
    for path in std::env::args().skip(1) {
        match minocrab_zkir::read_any(&path) {
            Ok(minocrab_zkir::AnyIr::V2(ir)) => {
                println!("== {path} (v2, {} instructions)", ir.instructions.len());
                for (i, ins) in ir.instructions.iter().enumerate() {
                    println!("{i:5}  {ins:?}");
                }
            }
            Ok(minocrab_zkir::AnyIr::V3(ir)) => {
                println!("== {path} (v3, {} instructions)", ir.instructions.len());
                for (i, ins) in ir.instructions.iter().enumerate() {
                    println!("{i:5}  {ins:?}");
                }
            }
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
}
