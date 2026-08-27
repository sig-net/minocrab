//! Throwaway: run the taint lint over every v3 corpus artifact, to compare
//! compactc's own output against our circuits' findings. Not a gate.

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| "corpus".into());
    let mut files = Vec::new();
    collect(std::path::Path::new(&root), &mut files);
    files.sort();
    let (mut v3, mut fired, mut total) = (0usize, 0usize, 0usize);
    for path in files {
        let Ok(ir) = minocrab_zkir::v3::read_zkir(&path) else {
            continue; // v2 or unreadable
        };
        v3 += 1;
        let findings = minocrab_ir::v3::taint::audit(&ir.instructions);
        if !findings.is_empty() {
            fired += 1;
            total += findings.len();
            println!("{}: {} finding(s)", path.display(), findings.len());
            for f in &findings {
                println!("    {f}");
            }
        }
    }
    println!("---\n{v3} v3 artifacts, {fired} fired, {total} findings");
}

fn collect(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "zkir") {
            out.push(path);
        }
    }
}
