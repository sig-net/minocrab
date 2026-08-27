//! `minocrab` — a light, compiler-agnostic gate-count CLI over ZKIR files.
//!
//! For people NOT using the Rust API. It reads a `.zkir` file — MinoCrab's or
//! compactc's, they share the format — and reports `(k, rows)`: the proving-
//! table size that drives proving time and RAM. So a Compact user who never
//! touches MinoCrab still gets the gate-count value.
//!
//! Region-attributed profiling is deliberately NOT here: it needs the region-
//! annotated `Compiled3` a Rust build produces, which a parsed `.zkir` does
//! not carry. Rust users reach for `minocrab_sim::v3::profile()` in a test or
//! a criterion bench — normal Rust perf tooling, no bespoke wrapper.
//!
//! ```text
//! minocrab rows  <file.zkir>...        # (k, rows) per file, plus a total
//! minocrab diff  <a.zkir> <b.zkir>     # the row/k delta between two circuits
//! ```

use std::path::Path;
use std::process::ExitCode;

use minocrab_sim::v3::cost;
use minocrab_zkir::v3::read_zkir;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((cmd, rest)) if cmd == "rows" => cmd_rows(rest),
        Some((cmd, rest)) if cmd == "diff" => cmd_diff(rest),
        Some((cmd, _)) if cmd == "help" || cmd == "--help" || cmd == "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!(
        "minocrab — gate counts over ZKIR files (MinoCrab's or compactc's)\n\
         \n\
         USAGE:\n\
         \x20 minocrab rows <file.zkir>...      (k, rows) per file, plus a total\n\
         \x20 minocrab diff <a.zkir> <b.zkir>   the row/k delta between two circuits\n\
         \n\
         `rows` reports k (= log2 of the proving-table rows, the number that\n\
         drives proving time and RAM) and the row count itself. Region-attributed\n\
         profiling is a Rust-API feature: minocrab_sim::v3::profile()."
    );
}

/// `(k, rows, instructions)` for one file, or a message on failure.
struct Measured {
    name: String,
    k: u8,
    rows: usize,
    instrs: usize,
    inputs: usize,
    outputs: usize,
}

fn measure(path: &str) -> Result<Measured, String> {
    let ir = read_zkir(path).map_err(|e| format!("{path}: {e}"))?;
    let (k, rows) = cost(&ir);
    let name = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string();
    Ok(Measured {
        name,
        k,
        rows,
        instrs: ir.instructions.len(),
        inputs: ir.inputs.len(),
        outputs: ir.outputs.len(),
    })
}

fn cmd_rows(files: &[String]) -> ExitCode {
    if files.is_empty() {
        eprintln!("minocrab rows: expected at least one <file.zkir>");
        return ExitCode::FAILURE;
    }
    println!(
        "{:<28} {:>3}  {:>10}  {:>7}  {:>3} {:>3}",
        "circuit", "k", "rows", "instr", "in", "out"
    );
    let mut total_rows = 0usize;
    let mut ok = true;
    let mut measured = 0usize;
    for f in files {
        match measure(f) {
            Ok(m) => {
                println!(
                    "{:<28} {:>3}  {:>10}  {:>7}  {:>3} {:>3}",
                    m.name, m.k, m.rows, m.instrs, m.inputs, m.outputs
                );
                total_rows += m.rows;
                measured += 1;
            }
            Err(e) => {
                eprintln!("error: {e}");
                ok = false;
            }
        }
    }
    if measured > 1 {
        println!("{:<28} {:>3}  {:>10}", "TOTAL", "", total_rows);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_diff(files: &[String]) -> ExitCode {
    let [a, b] = files else {
        eprintln!("minocrab diff: expected exactly two files, <a.zkir> <b.zkir>");
        return ExitCode::FAILURE;
    };
    let (ma, mb) = match (measure(a), measure(b)) {
        (Ok(ma), Ok(mb)) => (ma, mb),
        (a, b) => {
            for e in [a, b].into_iter().filter_map(Result::err) {
                eprintln!("error: {e}");
            }
            return ExitCode::FAILURE;
        }
    };
    println!(
        "{:<28} {:>3}  {:>10}",
        "circuit", "k", "rows"
    );
    println!("{:<28} {:>3}  {:>10}", ma.name, ma.k, ma.rows);
    println!("{:<28} {:>3}  {:>10}", mb.name, mb.k, mb.rows);
    let drow = mb.rows as i64 - ma.rows as i64;
    let pct = if ma.rows == 0 {
        0.0
    } else {
        100.0 * drow as f64 / ma.rows as f64
    };
    let dk = mb.k as i16 - ma.k as i16;
    println!(
        "{:<28} {:>+3}  {:>+10}  ({:+.1}%)",
        "delta", dk, drow, pct
    );
    ExitCode::SUCCESS
}
