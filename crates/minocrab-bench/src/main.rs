//! M6 baseline benchmark harness: the erc20-vault contract and its Signet
//! singleton dependency, proved under both toolchains at the same pinned
//! versions — MinoCrab's artifacts (built in-process from
//! `minocrab-contracts`) against compactc's (the corpus `.zkir` goldens).
//!
//! Both sides prove the SAME `ProofPreimage` per circuit: the differential
//! tests establish PI-equality on these preimages and (with
//! `MINOCRAB_DUMP_PREIMAGES`) dump them for this harness, so every number
//! below prices the identical statement. Run via `./bench.sh` (dumps
//! preimages, then runs this binary in release mode).
//!
//! Modes:
//! - no args: orchestrate — spawn `--measure` subprocesses (one per
//!   circuit × side, so peak RSS is per-measurement), collect JSON, write
//!   `target/bench/results.json` + `target/bench/report.md`, and dump
//!   MinoCrab's per-region cost profiles.
//! - `--measure <circuit> <side>`: keygen + prove + verify one artifact,
//!   print a JSON result line. RAM is `getrusage` peak RSS.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_transient_crypto::proofs::{ParamsProverProvider, ProofPreimage, Zkir};
use minocrab_contracts::{erc20_vault, signet_contract};
use minocrab_zkir::v3::IrSource;
use serde::{Deserialize, Serialize};

struct Target {
    /// Circuit name — also the corpus `.zkir` and dumped `.preimage` stem.
    name: &'static str,
    /// Corpus artifact path relative to the repo root.
    corpus: &'static str,
    /// The MinoCrab artifact.
    ours: fn() -> minocrab::v3::Compiled3,
}

const VAULT: &str =
    "corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir";
const SIGNET: &str =
    "corpus/zkir/signet-midnight-integration/packages/signet-contract/src/signet-contract/zkir";

fn targets() -> Vec<Target> {
    macro_rules! t {
        ($dir:expr, $name:literal, $f:expr) => {
            Target {
                name: $name,
                corpus: constcat($dir, $name),
                ours: $f,
            }
        };
    }
    fn constcat(dir: &str, name: &str) -> &'static str {
        Box::leak(format!("{dir}/{name}.zkir").into_boxed_str())
    }
    vec![
        t!(VAULT, "initialize", || erc20_vault::initialize()),
        t!(VAULT, "deposit", || erc20_vault::deposit()),
        t!(VAULT, "claim", || erc20_vault::claim()),
        t!(VAULT, "approveRouter", || erc20_vault::approve_router()),
        t!(VAULT, "withdraw", || erc20_vault::withdraw()),
        t!(VAULT, "completeWithdraw", || erc20_vault::complete_withdraw()),
        t!(VAULT, "refund", || erc20_vault::refund()),
        t!(VAULT, "swap", || erc20_vault::swap()),
        t!(VAULT, "completeSwap", || erc20_vault::complete_swap()),
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

fn load_preimage(name: &str) -> Result<ProofPreimage> {
    let path = preimage_dir().join(format!("{name}.preimage"));
    let bytes = std::fs::read(&path).with_context(|| {
        format!(
            "no dumped preimage at {} — run the differential tests with \
             MINOCRAB_DUMP_PREIMAGES set (see bench.sh)",
            path.display()
        )
    })?;
    Ok(midnight_serialize::tagged_deserialize(&bytes[..])?)
}

fn load_ir(target: &Target, side: &str) -> Result<IrSource> {
    match side {
        "minocrab" => Ok((target.ours)().ir),
        "compactc" => {
            let path = repo_root().join(target.corpus);
            minocrab_zkir::v3::read_zkir(path.to_str().unwrap())
                .with_context(|| format!("corpus artifact {}", target.corpus))
        }
        _ => bail!("side must be minocrab|compactc"),
    }
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

async fn measure(name: &str, side: &str) -> Result<Measurement> {
    let target_list = targets();
    let target = target_list
        .iter()
        .find(|t| t.name == name)
        .with_context(|| format!("unknown circuit {name}"))?;

    let ir = load_ir(target, side)?;
    let pi = load_preimage(name)?;
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

    let t = Instant::now();
    let (proof, pis, _skips) = ir
        .prove(rand::rngs::OsRng, &params, pk, &pi)
        .await
        .map_err(|e| anyhow::anyhow!("prove: {e}"))?;
    let prove_s = t.elapsed().as_secs_f64();
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
        side: side.to_string(),
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
    let mut results: Vec<Measurement> = Vec::new();

    for target in &targets() {
        for side in ["minocrab", "compactc"] {
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
            results.push(m);
        }
    }

    serde_json::to_writer_pretty(
        std::fs::File::create(out_dir.join("results.json"))?,
        &results,
    )?;

    // MinoCrab per-region cost profiles (the M7 target-picker).
    let profile_dir = out_dir.join("profiles");
    std::fs::create_dir_all(&profile_dir)?;
    for target in &targets() {
        let profile = minocrab_sim::v3::profile(&(target.ours)());
        std::fs::write(
            profile_dir.join(format!("{}.txt", target.name)),
            format!("{profile}"),
        )?;
        serde_json::to_writer_pretty(
            std::fs::File::create(profile_dir.join(format!("{}.json", target.name)))?,
            &profile,
        )?;
    }

    let report = render_report(&results);
    std::fs::write(out_dir.join("report.md"), &report)?;
    println!("{report}");
    eprintln!(
        "written: {}/results.json, report.md, profiles/",
        out_dir.display()
    );
    Ok(())
}

fn render_report(results: &[Measurement]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    writeln!(s, "# M6 baseline: MinoCrab vs compactc (same preimage per circuit)\n").unwrap();
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
    // Side-by-side deltas.
    writeln!(s, "\n## Deltas (minocrab vs compactc)\n").unwrap();
    writeln!(s, "| circuit | rows Δ | prove Δ | RSS Δ |").unwrap();
    writeln!(s, "|---|---|---|---|").unwrap();
    let by = |c: &str, side: &str| results.iter().find(|m| m.circuit == c && m.side == side);
    let mut names: Vec<&str> = results.iter().map(|m| m.circuit.as_str()).collect();
    names.dedup();
    for name in names {
        if let (Some(a), Some(b)) = (by(name, "minocrab"), by(name, "compactc")) {
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
        Some(other) => bail!("unknown mode {other}"),
    }
}
