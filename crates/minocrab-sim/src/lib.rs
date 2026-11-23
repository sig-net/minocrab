//! L5 — native ZKIR simulator.
//!
//! Executes a circuit in plain Rust for `cargo test` loops: no proving, no
//! keys, instant feedback. Semantics mirror midnight-zkir's reference
//! interpreter (`src/ir_vm.rs`) instruction for instruction:
//! `simulate` *verifies* a complete `ProofPreimage` — arguments
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
//! something a contract links. It takes the [`minocrab::Compiled`] that
//! the eDSL produces (or a bare [`minocrab_zkir::IrSource`]) and runs
//! it. `minocrab-std`, `minocrab-ledger` and the contract crates all use it
//! the same way — build a circuit, simulate it, assert on the disclosure
//! report and the row cost.
//!
//! # Start here
//!
//! - `simulate` and `Run` — run a circuit against a preimage
//! - `report` and `DisclosedValue` — what the run actually
//!   published, label by label
//! - [`cost`] and [`profile`] — `(k, rows)` for a circuit, and
//!   [`Profile`], the per-region breakdown the benchmark charts
//! - [`rowcost`] — the calibrated primitive costs behind [`cost`]
//!
//! # Stability
//!
//! The measurement API — [`cost`], [`profile`],
//! [`assert_max_k`], the calibrated [`rowcost`] tables,
//! [`Profile`]/[`RegionCost`], and the `minocrab` gate-count CLI — is the
//! public contract. The simulator VM (`simulate`, `Run`, the report
//! machinery) is the correctness harness's engine and carries no stability
//! promise.

mod vm;
pub mod rowcost;
pub mod exec;
pub use vm::*;

// rename-v3: begin shim (tools/rename-v3.sh never rewrites this block)
/// The pre-rename path: everything that was `minocrab_sim::v3::X` is `minocrab_sim::X`.
/// Kept for the downstream pins only; nothing in this workspace uses it.
#[doc(hidden)]
#[deprecated(note = "`minocrab_sim::v3` is gone: the items are at the crate root \
                     (`minocrab_sim::X`) and lose the `3` suffix; this module is removed in the next release")]
pub mod v3 {
    pub use crate::*;
    #[deprecated(note = "renamed to `minocrab_sim::Run`")]
    pub type Run3 = crate::Run;
    #[deprecated(note = "renamed to `minocrab_sim::Report`")]
    pub type Report3 = crate::Report;
    #[deprecated(note = "renamed to `minocrab_sim::DisclosedValue`")]
    pub type DisclosedValue3 = crate::DisclosedValue;
    #[deprecated(note = "renamed to `minocrab_sim::SimError`")]
    pub type Sim3Error = crate::SimError;
}
// rename-v3: end shim

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
    /// RAM track — from the calibrated [`crate::rowcost`] model. Always
    /// `Some` for a [`profile`]; the `Option` is kept for API stability.
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
    /// [`profile`]; the `Option` is kept for API stability.
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
