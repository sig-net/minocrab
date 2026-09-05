//! L5 — native ZKIR simulator.
//!
//! Executes a circuit in plain Rust for `cargo test` loops: no proving, no
//! keys, instant feedback. Semantics mirror midnight-ledger's reference
//! interpreter (`zkir-v3/src/ir_vm.rs`) instruction for instruction:
//! `v3::simulate` *verifies* a complete `ProofPreimage` — arguments
//! decoded per the input schema, Impact public inputs checked against the
//! transcript as they accumulate — so every run can be cross-checked against
//! the reference VM via `IrSource::check`, and the simulator is never
//! trusted alone (see `tests/`).
//!
//! Crypto primitives (hashes, curves) are Midnight's own — never
//! reimplemented here.
//!
//! # Where this sits
//!
//! The top of the stack and off to the side of it: a dev-dependency, not
//! something a contract links. It takes the [`minocrab::v3::Compiled3`] that
//! the eDSL produces (or a bare [`minocrab_zkir::v3::IrSource`]) and runs
//! it. `minocrab-std`, `minocrab-ledger` and the contract crates all use it
//! the same way — build a circuit, simulate it, assert on the disclosure
//! report and the row cost.
//!
//! # Start here
//!
//! - `v3::simulate` and `v3::Run3` — run a circuit against a preimage
//! - `v3::report` and `v3::DisclosedValue3` — what the run actually
//!   published, label by label
//! - [`v3::cost`] and [`v3::profile`] — `(k, rows)` for a circuit, and
//!   [`Profile`], the per-region breakdown the benchmark charts
//! - [`v3::rowcost`] — the calibrated primitive costs behind [`v3::cost`]
//!
//! # Stability (M24 tier boundary)
//!
//! STABLE TIER (semver commitment): the measurement API — [`v3::cost`],
//! [`v3::profile`], [`v3::assert_max_k`], the calibrated [`v3::rowcost`]
//! tables, [`Profile`]/[`RegionCost`], and the `minocrab` gate-count CLI.
//! INTERNAL TIER, gated behind the `unstable` cargo feature: the simulator
//! VM (`v3::simulate`, `Run3`, the report machinery) — the correctness
//! harness's engine, not a public contract.

pub mod v3;

use std::collections::BTreeMap;

// --- profiling -------------------------------------------------------------------

/// Cost attribution for one [`minocrab::Region`] (or the top level).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegionCost {
    pub label: String,
    pub instructions: usize,
    /// Share of the whole circuit's instructions, in percent.
    pub percent: f64,
    /// Estimated share of the *proving table* — the number k, prove time and
    /// RAM track — from the calibrated [`crate::v3::rowcost`] model. Always
    /// `Some` for a [`v3::profile`]; the `Option` is kept for API stability.
    pub est_rows: Option<usize>,
    /// Share of the circuit's estimated rows, in percent.
    pub est_rows_percent: Option<f64>,
    pub op_counts: BTreeMap<&'static str, u32>,
}

/// Per-region circuit profile plus whole-circuit cost-model numbers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Profile {
    /// log2 of the proving-table rows this circuit needs — the number that
    /// drives proving time and RAM.
    pub k: u8,
    pub rows: usize,
    pub total_instructions: usize,
    /// Sum of the per-region row estimates. It undershoots `rows`: the
    /// difference is the circuit's fixed cost (chip stand-up, the pow2range
    /// table), which belongs to no region. Always `Some` for a
    /// [`v3::profile`]; the `Option` is kept for API stability.
    pub est_rows_total: Option<usize>,
    /// Most expensive region first — by estimated rows where they exist,
    /// else by instruction count.
    pub regions: Vec<RegionCost>,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "circuit: k={} ({} rows), {} instructions",
            self.k, self.rows, self.total_instructions
        )?;
        if let Some(est) = self.est_rows_total {
            writeln!(
                f,
                "rows attributed: {est} of {} ({} unattributed: chip stand-up + fixed tables)",
                self.rows,
                self.rows.saturating_sub(est),
            )?;
            writeln!(f, "  {:>7}  {:>7}  {:<24}", "rows%", "instr%", "region")?;
        }
        for r in &self.regions {
            let mut ops: Vec<(&&str, &u32)> = r.op_counts.iter().collect();
            ops.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let top: Vec<String> = ops
                .iter()
                .take(3)
                .map(|(op, n)| format!("{op}×{n}"))
                .collect();
            match (r.est_rows, r.est_rows_percent) {
                (Some(rows), Some(pct)) => writeln!(
                    f,
                    "  {:>6.1}%  {:>6.1}%  {:<24} ~{} rows, {} instr  ({})",
                    pct,
                    r.percent,
                    r.label,
                    rows,
                    r.instructions,
                    top.join(", "),
                )?,
                _ => writeln!(
                    f,
                    "  {:>5.1}%  {:<24} {} instr  ({})",
                    r.percent,
                    r.label,
                    r.instructions,
                    top.join(", "),
                )?,
            }
        }
        Ok(())
    }
}
