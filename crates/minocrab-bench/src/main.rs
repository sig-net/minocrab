//! M6 baseline benchmark harness: the erc20-vault contract and its Signet
//! singleton dependency, proved under each toolchain at the same pinned
//! versions.
//!
//! A run is a matrix of circuits ([`Target`]) × [`Side`]s, and sides are
//! data: a name, where its circuits come from ([`Artifacts`]) and where its
//! `ProofPreimage`s come from ([`Preimages`]). Three are declared:
//! - `minocrab` — the direct ports, built in-process from `minocrab-contracts`;
//! - `compactc` — the corpus `.zkir` goldens;
//! - `opt` — the M10 optimized contract (`minocrab_contracts::erc20_vault_opt`,
//!   M10 §Sequencing step 4). It exists for the nine vault circuits only;
//!   the Signet singleton is a deployed compactc artifact and is not ours to
//!   optimize, so those three targets stay two-sided and the `opt` side
//!   simply drops out of them.
//!
//! `minocrab` and `compactc` prove the SAME preimage per circuit: the
//! differential tests establish PI-equality on these preimages and (with
//! `MINOCRAB_DUMP_PREIMAGES`) dump them for this harness, so those numbers
//! price the identical statement. The optimized side CANNOT share that
//! preimage — a different commitment scheme is a different statement — so it
//! reads its own preimage dump (`preimages/opt/`) and its comparability
//! rests on the harness's symbolic-effect equality instead. Sides carry
//! their preimage source for exactly this reason.
//!
//! Run via `./bench.sh` (dumps preimages, then runs this binary in release
//! mode). Modes:
//! - no args: orchestrate — spawn `--measure` subprocesses (one per
//!   circuit × side, so peak RSS is per-measurement), collect JSON, write
//!   `target/bench/results.json` + `target/bench/report.md`, and dump
//!   the eDSL sides' per-region cost profiles.
//! - `--measure <circuit> <side>`: keygen + prove + verify one artifact,
//!   print a JSON result line. RAM is `getrusage` peak RSS.
//! - `--profiles`: rewrite `target/bench/profiles/` alone (no proving) —
//!   for refreshing region attribution after annotation changes.
//! - `--list`: print the circuit × side matrix this run would measure, with
//!   each cell's artifact and preimage source. A dry run; proves nothing.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_transient_crypto::proofs::{ParamsProverProvider, ProofPreimage, Zkir};
use minocrab_contracts::{erc20_vault, erc20_vault_borsh, erc20_vault_opt, signet_contract};
use minocrab_zkir::v3::IrSource;
use serde::{Deserialize, Serialize};

struct Target {
    /// Circuit name — also the corpus `.zkir` and dumped `.preimage` stem.
    name: &'static str,
    /// Corpus artifact path relative to the repo root.
    corpus: &'static str,
    /// The MinoCrab direct port.
    ours: fn() -> minocrab::v3::Compiled3,
    /// The M10 optimized artifact, where one exists — the nine vault
    /// circuits. `None` for the Signet singleton, which is a deployed
    /// compactc artifact rather than something M10 rewrites.
    opt: Option<fn() -> minocrab::v3::Compiled3>,
    /// The M11 borsh artifact — the optimized vault on the stage-7 wire
    /// format. Benched since the record change crossed swap k16→k15
    /// (superseding stage 4's not-benched decision, which predated the
    /// crossing); `None` outside the nine vault circuits.
    borsh: Option<fn() -> minocrab::v3::Compiled3>,
}

/// Where a side's circuits come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Artifacts {
    /// Built in-process from `minocrab-contracts`' direct ports.
    Port,
    /// compactc's `.zkir` goldens in `corpus/`.
    Corpus,
    /// Built in-process from the M10 optimized contract.
    Optimized,
    /// Built in-process from the M11 borsh contract.
    Borsh,
}

/// Where a side's [`ProofPreimage`]s come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preimages {
    /// The preimages the differential tests dump: compactc and the direct
    /// port are PI-equal on these, so both sides price the identical
    /// statement.
    Shared,
    /// A per-side subdirectory. The optimized artifact cannot share the
    /// port's preimage — it proves its *own* statement for the same logical
    /// operation, so its numbers are comparable only under the
    /// symbolic-effect equality the M10 harness establishes (the
    /// methodology caveat in notes/vault-optimization.org §Sequencing).
    PerSide(&'static str),
}

/// One column of the benchmark.
struct Side {
    /// Name on the command line, in `results.json` and in the report.
    name: &'static str,
    artifacts: Artifacts,
    preimages: Preimages,
}

fn sides() -> Vec<Side> {
    vec![
        Side {
            name: "minocrab",
            artifacts: Artifacts::Port,
            preimages: Preimages::Shared,
        },
        Side {
            name: "compactc",
            artifacts: Artifacts::Corpus,
            preimages: Preimages::Shared,
        },
        Side {
            name: "opt",
            artifacts: Artifacts::Optimized,
            preimages: Preimages::PerSide("opt"),
        },
        Side {
            name: "borsh",
            artifacts: Artifacts::Borsh,
            preimages: Preimages::PerSide("borsh"),
        },
    ]
}

fn side(name: &str) -> Result<Side> {
    sides()
        .into_iter()
        .find(|s| s.name == name)
        .with_context(|| {
            format!(
                "unknown side {name}; known: {}",
                sides()
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join("|")
            )
        })
}

impl Side {
    /// The circuits this side contributes for `target`, or `None` when it
    /// has no artifact for it (an absent side simply drops out of the run).
    fn ir(&self, target: &Target) -> Option<Result<IrSource>> {
        match self.artifacts {
            Artifacts::Port => Some(Ok((target.ours)().ir)),
            Artifacts::Corpus => {
                let path = repo_root().join(target.corpus);
                Some(
                    minocrab_zkir::v3::read_zkir(path.to_str().unwrap())
                        .with_context(|| format!("corpus artifact {}", target.corpus)),
                )
            }
            Artifacts::Optimized => target.opt.map(|build| Ok(build().ir)),
            Artifacts::Borsh => target.borsh.map(|build| Ok(build().ir)),
        }
    }

    /// Profiles are MinoCrab-side only: they need the eDSL's region
    /// annotations, which a parsed `.zkir` does not carry.
    fn profiled(&self, target: &Target) -> Option<minocrab::v3::Compiled3> {
        match self.artifacts {
            Artifacts::Port => Some((target.ours)()),
            Artifacts::Corpus => None,
            Artifacts::Optimized => target.opt.map(|build| build()),
            Artifacts::Borsh => target.borsh.map(|build| build()),
        }
    }

    fn preimage_path(&self, circuit: &str) -> PathBuf {
        match self.preimages {
            Preimages::Shared => preimage_dir().join(format!("{circuit}.preimage")),
            Preimages::PerSide(dir) => preimage_dir().join(dir).join(format!("{circuit}.preimage")),
        }
    }
}

const VAULT: &str =
    "corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir";
const SIGNET: &str =
    "corpus/zkir/signet-midnight-integration/packages/signet-contract/src/signet-contract/zkir";

fn targets() -> Vec<Target> {
    macro_rules! t {
        ($dir:expr, $name:literal, $f:expr) => {
            t!($dir, $name, $f, None, None)
        };
        ($dir:expr, $name:literal, $f:expr, $opt:expr, $borsh:expr) => {
            Target {
                name: $name,
                corpus: constcat($dir, $name),
                ours: $f,
                opt: $opt,
                borsh: $borsh,
            }
        };
    }
    fn constcat(dir: &str, name: &str) -> &'static str {
        Box::leak(format!("{dir}/{name}.zkir").into_boxed_str())
    }
    vec![
        t!(VAULT, "initialize", || erc20_vault::initialize(), Some(erc20_vault_opt::initialize), Some(erc20_vault_borsh::initialize)),
        t!(VAULT, "deposit", || erc20_vault::deposit(), Some(erc20_vault_opt::deposit), Some(erc20_vault_borsh::deposit)),
        t!(VAULT, "claim", || erc20_vault::claim(), Some(erc20_vault_opt::claim), Some(erc20_vault_borsh::claim)),
        t!(VAULT, "approveRouter", || erc20_vault::approve_router(), Some(erc20_vault_opt::approve_router), Some(erc20_vault_borsh::approve_router)),
        t!(VAULT, "withdraw", || erc20_vault::withdraw(), Some(erc20_vault_opt::withdraw), Some(erc20_vault_borsh::withdraw)),
        t!(VAULT, "completeWithdraw", || erc20_vault::complete_withdraw(), Some(erc20_vault_opt::complete_withdraw), Some(erc20_vault_borsh::complete_withdraw)),
        t!(VAULT, "refund", || erc20_vault::refund(), Some(erc20_vault_opt::refund), Some(erc20_vault_borsh::refund)),
        t!(VAULT, "swap", || erc20_vault::swap(), Some(erc20_vault_opt::swap), Some(erc20_vault_borsh::swap)),
        t!(VAULT, "completeSwap", || erc20_vault::complete_swap(), Some(erc20_vault_opt::complete_swap), Some(erc20_vault_borsh::complete_swap)),
        t!(SIGNET, "signBidirectional", || signet_contract::sign_bidirectional()),
        t!(SIGNET, "respond", || signet_contract::respond()),
        t!(SIGNET, "respondBidirectional", || signet_contract::respond_bidirectional()),
    ]
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn bench_dir() -> PathBuf {
    repo_root().join("target/bench")
}

fn preimage_dir() -> PathBuf {
    std::env::var_os("MINOCRAB_PREIMAGES")
        .map(PathBuf::from)
        .unwrap_or_else(|| bench_dir().join("preimages"))
}

fn load_preimage(side: &Side, name: &str) -> Result<ProofPreimage> {
    let path = side.preimage_path(name);
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "no dumped preimage at {} — run the differential tests with \
             MINOCRAB_DUMP_PREIMAGES set (see bench.sh)",
            path.display()
        )
    })?;
    Ok(midnight_serialize::tagged_deserialize(&bytes[..])?)
}

fn load_ir(target: &Target, side: &Side) -> Result<IrSource> {
    side.ir(target).unwrap_or_else(|| {
        bail!(
            "side {} has no artifact for circuit {}",
            side.name,
            target.name
        )
    })
}

fn params_provider() -> Result<MidnightDataProvider> {
    Ok(MidnightDataProvider::new(
        FetchMode::OnDemand,
        OutputMode::Log,
        vec![],
    )?)
}

/// Peak RSS of this process, in bytes.
fn peak_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    assert_eq!(rc, 0, "getrusage failed");
    let raw = ru.ru_maxrss as u64;
    // macOS reports bytes, Linux kilobytes.
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Measurement {
    circuit: String,
    side: String,
    k: u8,
    rows: usize,
    keygen_s: f64,
    prove_s: f64,
    verify_s: f64,
    proof_bytes: usize,
    peak_rss_bytes: u64,
}

async fn measure(name: &str, side_name: &str) -> Result<Measurement> {
    let target_list = targets();
    let target = target_list
        .iter()
        .find(|t| t.name == name)
        .with_context(|| format!("unknown circuit {name}"))?;
    let side = side(side_name)?;

    let ir = load_ir(target, &side)?;
    let pi = load_preimage(&side, name)?;
    let params = params_provider()?;

    let model = ir.model();
    let (k, rows) = (model.k(), model.rows());

    // Warm the params cache so a first-run download never lands in the
    // keygen timing. (keygen/prove re-read the cached file; both sides pay
    // that I/O equally.)
    params.get_params(k).await?;

    let t = Instant::now();
    let (pk, vk) = ir.keygen(&params).await?;
    let keygen_s = t.elapsed().as_secs_f64();

    // Median of N proves (MINOCRAB_PROVE_ITERS, default 3): single-shot
    // wall-clock proved to swing ~3× with machine state.
    let iters: usize = std::env::var("MINOCRAB_PROVE_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3);
    let mut times = Vec::with_capacity(iters);
    let mut last = None;
    for _ in 0..iters {
        let t = Instant::now();
        let (proof, pis, _skips) = ir
            .prove(rand::rngs::OsRng, &params, pk.clone(), &pi)
            .await
            .map_err(|e| anyhow::anyhow!("prove: {e}"))?;
        times.push(t.elapsed().as_secs_f64());
        last = Some((proof, pis));
    }
    times.sort_by(f64::total_cmp);
    let prove_s = times[times.len() / 2];
    let (proof, pis) = last.expect("at least one prove iteration");
    let proof_bytes = proof.0.len();

    // `ParamsProver::as_verifier` is pub(crate); read the verifier params
    // from the provider's cached file instead (same dir resolution).
    let params_file = std::env::var_os("MIDNIGHT_PP")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CACHE_HOME")
                .map(|p| PathBuf::from(p).join("midnight/zk-params"))
        })
        .or_else(|| {
            std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cache/midnight/zk-params"))
        })
        .context("no cache dir")?
        .join(format!("bls_midnight_2p{k}"));
    let verifier_params = midnight_transient_crypto::proofs::ParamsVerifier::read(
        std::io::BufReader::new(std::fs::File::open(&params_file)?),
    )?;
    let t = Instant::now();
    vk.verify(&verifier_params, &proof, pis.iter().copied())
        .map_err(|e| anyhow::anyhow!("verify: {e}"))?;
    let verify_s = t.elapsed().as_secs_f64();

    Ok(Measurement {
        circuit: name.to_string(),
        side: side.name.to_string(),
        k,
        rows,
        keygen_s,
        prove_s,
        verify_s,
        proof_bytes,
        peak_rss_bytes: peak_rss_bytes(),
    })
}

fn orchestrate() -> Result<()> {
    let out_dir = bench_dir();
    std::fs::create_dir_all(&out_dir)?;
    let exe = std::env::current_exe()?;

    // Incremental: one JSON line per finished cell; a restarted run skips
    // what's already measured. Delete results.jsonl for a fresh run.
    let jsonl_path = out_dir.join("results.jsonl");
    let mut results: Vec<Measurement> = match std::fs::read_to_string(&jsonl_path) {
        Ok(s) => s
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?,
        Err(_) => Vec::new(),
    };

    for (target, side) in cells() {
        {
            let side = side.name;
            if results
                .iter()
                .any(|m| m.circuit == target.name && m.side == side)
            {
                continue;
            }
            eprint!("{:>20} {:>8} … ", target.name, side);
            std::io::stderr().flush().ok();
            let t = Instant::now();
            let output = std::process::Command::new(&exe)
                .args(["--measure", target.name, side])
                .output()?;
            if !output.status.success() {
                bail!(
                    "--measure {} {} failed:\n{}",
                    target.name,
                    side,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let line = String::from_utf8(output.stdout)?;
            let m: Measurement = serde_json::from_str(
                line.lines().last().context("no measurement output")?,
            )?;
            eprintln!(
                "k={} prove {:.2}s rss {:.0}MB  ({:.0}s total)",
                m.k,
                m.prove_s,
                m.peak_rss_bytes as f64 / 1e6,
                t.elapsed().as_secs_f64()
            );
            let mut jsonl = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&jsonl_path)?;
            writeln!(jsonl, "{}", serde_json::to_string(&m)?)?;
            results.push(m);
        }
    }

    // Report in target × side order regardless of when each cell was measured.
    let order: Vec<&str> = targets().iter().map(|t| t.name).collect();
    let side_order: Vec<&str> = sides().iter().map(|s| s.name).collect();
    results.sort_by_key(|m| {
        (
            order.iter().position(|n| *n == m.circuit),
            side_order.iter().position(|n| *n == m.side),
        )
    });

    serde_json::to_writer_pretty(
        std::fs::File::create(out_dir.join("results.json"))?,
        &results,
    )?;

    write_profiles(&out_dir)?;

    let report = render_report(&results);
    std::fs::write(out_dir.join("report.md"), &report)?;
    println!("{report}");
    eprintln!(
        "written: {}/results.json, report.md, profiles/",
        out_dir.display()
    );
    Ok(())
}

/// Every (circuit, side) pair the run covers — sides without an artifact
/// for a circuit drop out, so the vault targets are four-sided and the
/// Signet singleton's stay two-sided.
fn cells() -> Vec<(Target, Side)> {
    let mut out = Vec::new();
    for target in targets() {
        for side in sides() {
            if side.ir(&target).is_some() {
                out.push((
                    Target {
                        name: target.name,
                        corpus: target.corpus,
                        ours: target.ours,
                        opt: target.opt,
                        borsh: target.borsh,
                    },
                    side,
                ));
            }
        }
    }
    out
}

/// Per-region cost profiles (the M7 target-picker, now attributed by
/// estimated rows as well as instruction count). Built in-process from the
/// eDSL circuits — no proving, so `--profiles` can refresh them alone after
/// a region-annotation change. compactc's parsed `.zkir` carries no regions,
/// so only the eDSL sides are profiled; a side's files are suffixed with its
/// name (the port keeps the bare `<circuit>.txt` names).
fn write_profiles(out_dir: &std::path::Path) -> Result<()> {
    let profile_dir = out_dir.join("profiles");
    std::fs::create_dir_all(&profile_dir)?;
    for (target, side) in cells() {
        let Some(compiled) = side.profiled(&target) else {
            continue;
        };
        let stem = match side.artifacts {
            Artifacts::Port => target.name.to_string(),
            _ => format!("{}.{}", target.name, side.name),
        };
        let profile = minocrab_sim::v3::profile(&compiled);
        std::fs::write(profile_dir.join(format!("{stem}.txt")), format!("{profile}"))?;
        serde_json::to_writer_pretty(
            std::fs::File::create(profile_dir.join(format!("{stem}.json")))?,
            &profile,
        )?;
    }
    Ok(())
}

/// `--list`: the (circuit, side) matrix this run would measure, with each
/// cell's artifact and preimage source. A dry run — nothing is built or
/// proved beyond reading what is on disk.
fn list_cells() -> Result<()> {
    /// The last two path components, enough to tell the cells apart.
    fn tail(path: &std::path::Path) -> String {
        let parts: Vec<_> = path.components().rev().take(2).collect();
        let tail: PathBuf = parts.into_iter().rev().collect();
        format!("…/{}", tail.display())
    }
    println!("{:>20} {:>10}  {:<28} preimage", "circuit", "side", "artifact");
    for (target, side) in cells() {
        let artifact = match side.artifacts {
            Artifacts::Port => "minocrab-contracts (port)".to_string(),
            Artifacts::Corpus => tail(std::path::Path::new(target.corpus)),
            Artifacts::Optimized => "minocrab-contracts (opt)".to_string(),
            Artifacts::Borsh => "minocrab-contracts (borsh)".to_string(),
        };
        let preimage = side.preimage_path(target.name);
        let present = if preimage.exists() { "" } else { "  [missing]" };
        println!(
            "{:>20} {:>10}  {:<28} {}{}",
            target.name,
            side.name,
            artifact,
            tail(&preimage),
            present
        );
    }
    let absent: Vec<&str> = sides()
        .iter()
        .filter(|s| !cells().iter().any(|(_, c)| c.name == s.name))
        .map(|s| s.name)
        .collect();
    if !absent.is_empty() {
        println!("\nsides with no artifacts yet (skipped): {}", absent.join(", "));
    }
    Ok(())
}

fn render_report(results: &[Measurement]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    writeln!(s, "# MinoCrab vs compactc (same preimage per circuit)\n").unwrap();
    writeln!(
        s,
        "| circuit | side | k | rows | keygen (s) | prove (s) | verify (s) | proof (B) | peak RSS (MB) |"
    )
    .unwrap();
    writeln!(s, "|---|---|---|---|---|---|---|---|---|").unwrap();
    for m in results {
        writeln!(
            s,
            "| {} | {} | {} | {} | {:.2} | {:.2} | {:.3} | {} | {:.0} |",
            m.circuit,
            m.side,
            m.k,
            m.rows,
            m.keygen_s,
            m.prove_s,
            m.verify_s,
            m.proof_bytes,
            m.peak_rss_bytes as f64 / 1e6,
        )
        .unwrap();
    }
    // Deltas of every other side against compactc, the common baseline.
    let by = |c: &str, side: &str| results.iter().find(|m| m.circuit == c && m.side == side);
    let mut names: Vec<&str> = results.iter().map(|m| m.circuit.as_str()).collect();
    names.dedup();
    for side in sides() {
        if side.artifacts == Artifacts::Corpus {
            continue;
        }
        if !results.iter().any(|m| m.side == side.name) {
            continue;
        }
        writeln!(s, "\n## Deltas ({} vs compactc)\n", side.name).unwrap();
        if let Preimages::PerSide(_) = side.preimages {
            writeln!(
                s,
                "This side proves its OWN preimage per circuit — the same logical \
                 operation, not the same statement. Comparability rests on the \
                 symbolic-effect equality of the two contracts, a weaker claim than \
                 the PI-equality the other sides share.\n"
            )
            .unwrap();
        }
        writeln!(s, "| circuit | rows Δ | prove Δ | RSS Δ |").unwrap();
        writeln!(s, "|---|---|---|---|").unwrap();
        for name in &names {
            if let (Some(a), Some(b)) = (by(name, side.name), by(name, "compactc")) {
                let pct = |x: f64, y: f64| if y != 0.0 { (x - y) / y * 100.0 } else { 0.0 };
                writeln!(
                    s,
                    "| {} | {:+.1}% | {:+.1}% | {:+.1}% |",
                    name,
                    pct(a.rows as f64, b.rows as f64),
                    pct(a.prove_s, b.prove_s),
                    pct(a.peak_rss_bytes as f64, b.peak_rss_bytes as f64),
                )
                .unwrap();
            }
        }
    }
    s
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None => orchestrate(),
        Some("--measure") => {
            let name = args.get(2).context("--measure <circuit> <side>")?;
            let side = args.get(3).context("--measure <circuit> <side>")?;
            let m = measure(name, side).await?;
            println!("{}", serde_json::to_string(&m)?);
            Ok(())
        }
        Some("--profiles") => {
            let out_dir = bench_dir();
            write_profiles(&out_dir)?;
            eprintln!("written: {}/profiles/", out_dir.display());
            Ok(())
        }
        Some("--list") => list_cells(),
        Some(other) => bail!("unknown mode {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The optimized side covers the nine vault circuits and nothing else,
    /// and a side with no artifact for a target drops out of the run rather
    /// than failing it.
    #[test]
    fn the_optimized_side_covers_the_vault_targets_only() {
        let vault_targets = targets().iter().filter(|t| t.opt.is_some()).count();
        assert_eq!(vault_targets, 9, "the vault has nine circuits");
        assert_eq!(cells().len(), targets().len() * 2 + vault_targets);

        let opt = side("opt").expect("the side is declared");
        let vault = targets().into_iter().find(|t| t.name == "claim").unwrap();
        assert!(load_ir(&vault, &opt).is_ok());
        // …and asking a target it has no artifact for is an error, not a panic.
        let signet = targets().into_iter().find(|t| t.name == "respond").unwrap();
        assert!(opt.ir(&signet).is_none());
        assert!(load_ir(&signet, &opt).is_err());
    }

    #[test]
    fn unknown_side_is_rejected() {
        assert!(side("nonesuch").is_err());
        assert!(side("minocrab").is_ok());
        assert!(side("compactc").is_ok());
    }

    /// The two statement-identical sides read the shared preimage dump; the
    /// optimized side reads its own, because it cannot share one.
    #[test]
    fn preimages_are_shared_except_for_the_optimized_side() {
        let shared = side("minocrab").unwrap().preimage_path("claim");
        assert_eq!(shared, side("compactc").unwrap().preimage_path("claim"));
        let own = side("opt").unwrap().preimage_path("claim");
        assert_ne!(own, shared);
        assert_eq!(own.parent().unwrap().file_name().unwrap(), "opt");
    }

    /// Both toolchain-independent sides yield an IR for every target, and
    /// only the eDSL ones can be profiled.
    #[test]
    fn every_target_has_a_port_and_a_corpus_artifact() {
        for target in targets() {
            for name in ["minocrab", "compactc"] {
                let side = side(name).unwrap();
                assert!(
                    side.ir(&target).expect("side present").is_ok(),
                    "{} / {name}",
                    target.name
                );
            }
            assert!(side("minocrab").unwrap().profiled(&target).is_some());
            assert!(side("compactc").unwrap().profiled(&target).is_none());
            // Profiles need the eDSL's region annotations, which the
            // optimized side has and the parsed corpus `.zkir` does not.
            assert_eq!(
                side("opt").unwrap().profiled(&target).is_some(),
                target.opt.is_some()
            );
        }
    }
}
