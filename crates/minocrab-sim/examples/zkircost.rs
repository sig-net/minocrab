//! Print `(k, rows)` for compiled `.zkir` files (v3), via Midnight's own
//! cost model — the same numbers `row_snapshot` freezes for our circuits.
//!
//!     cargo run -p minocrab-sim --example zkircost -- path/a.zkir path/b.zkir

fn main() {
    for path in std::env::args().skip(1) {
        match minocrab_zkir::v3::read_zkir(&path) {
            Ok(ir) => {
                let (k, rows) = minocrab_sim::v3::cost(&ir);
                let name = std::path::Path::new(&path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(&path);
                println!("{name:28} k={k:2} rows={rows}");
            }
            Err(e) => eprintln!("{path}: {e}"),
        }
    }
}
