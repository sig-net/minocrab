//! The simplification pass (notes/ir-passes.org §14) applied, in the
//! test only, to every workspace circuit's finished stream. No contract
//! turns the pass on; this is what it would do if one did.
//!
//! `every_circuit_keeps_its_effects_under_the_pass` (routine): on all
//! circuits, the pass deletes only instructions the purity table allows,
//! keeps every effect in order, keeps every disclosed name defined, and is
//! idempotent.
//!
//! `simplify_row_table` (ignored, an instrument; run under `--release`):
//! prices every circuit with Midnight's own cost model before and after
//! each rule and prints the table notes/ir-passes.org §14 records.
//!
//! The executable evidence (the simplified circuit accepting the same
//! preimages with the same public inputs) is the simulator's
//! `MINOCRAB_CHECK_SIMPLIFY` instrument run over the whole suite; see the
//! note.

mod support;

use minocrab::{Compiled, DisclosedWire};
use minocrab_ir::passes::{native_inputs, simplify, simplify_with, Rules};
use minocrab_zkir::{Identifier, Instruction, IrSource};

/// The names a circuit's disclosure records read the run's memory by.
fn observed(compiled: &Compiled) -> Vec<Identifier> {
    compiled
        .disclosures
        .iter()
        .flat_map(|d| d.values.iter())
        .filter_map(|w| match w {
            DisclosedWire::Named(id) => Some(id.clone()),
            DisclosedWire::Constant(_) => None,
        })
        .collect()
}

/// An instruction's opcode, as the serialized form spells it.
fn op(i: &Instruction) -> String {
    serde_json::to_value(i).expect("serializes")["op"].as_str().expect("an op").to_string()
}

/// The instructions no rule may delete or reorder: everything that is not a
/// computation (constraints, transcript reads, Impact, the terminator).
fn effects(stream: &[Instruction]) -> Vec<String> {
    stream
        .iter()
        .map(op)
        .filter(|o| {
            matches!(
                o.as_str(),
                "assert" | "constrain_bits" | "constrain_eq" | "constrain_to_boolean" | "impact" | "public_input"
                    | "private_input" | "output"
            )
        })
        .collect()
}

fn with(ir: &IrSource, instructions: Vec<Instruction>) -> IrSource {
    IrSource { instructions: std::sync::Arc::new(instructions), ..ir.clone() }
}

#[test]
fn every_circuit_keeps_its_effects_under_the_pass() {
    let circuits = support::circuits();
    let mut changed = 0;
    for (name, build) in &circuits {
        let compiled = build();
        let ir = &compiled.ir;
        let natives = native_inputs(ir);
        let seen = observed(&compiled);
        let before = ir.instructions.to_vec();
        let after = simplify(before.clone(), &natives, &seen);
        assert!(after.len() <= before.len(), "{name}");
        changed += usize::from(after.len() < before.len());
        assert_eq!(effects(&after), effects(&before), "{name}: an effect moved");
        for id in &seen {
            let defined = ir.inputs.iter().any(|t| serde_json::to_value(t).unwrap()["name"] == id.0)
                || after.iter().any(|i| minocrab_ir::passes::defined_identifiers(i).contains(id));
            assert!(defined, "{name}: disclosed {id:?} is no longer defined");
        }
        assert_eq!(simplify(after.clone(), &natives, &seen), after, "{name}: not idempotent");
    }
    println!("{changed} of {} circuits change under the pass", circuits.len());
}

/// MinoCrab-only lineages: no Compact twin, no deployed key. Everything else
/// in the list has a Compact twin (or is the deployed signer) and keeps the
/// pass off through `minocrab_compat::profile`.
const MINOCRAB_ONLY: &[&str] = &["erc20_vault_pending::", "treasury::", "disclosure::"];

#[test]
#[ignore = "instrument: prices every circuit under each rule; run with --release"]
fn simplify_row_table() {
    let mut rows_out = Vec::new();
    let (mut twin, mut only_totals) = ([0i64; 5], [0i64; 5]);
    for (name, build) in support::circuits() {
        let compiled = build();
        let ir = &compiled.ir;
        let natives = native_inputs(ir);
        let seen = observed(&compiled);
        let base = ir.instructions.to_vec();
        let only = |rules: Rules| simplify_with(base.clone(), &natives, &seen, rules);
        let both = simplify(base.clone(), &natives, &seen);
        if both.len() == base.len() {
            continue;
        }
        let price = |stream: Vec<Instruction>| minocrab_sim::cost(&with(ir, stream)).1 as i64;
        let (k0, r0) = minocrab_sim::cost(ir);
        let (k1, r1) = minocrab_sim::cost(&with(ir, both.clone()));
        let r0i = r0 as i64;
        // Each rule alone, then all of them (the parts need not sum to the
        // whole: a merge can leave a value for the dead-code rule).
        let saved = [
            r0i - price(only(Rules { merge_pure: true, ..Rules::NONE })),
            r0i - price(only(Rules { merge_determined: true, ..Rules::NONE })),
            r0i - price(only(Rules { constant_selects: true, ..Rules::NONE })),
            r0i - price(only(Rules { dead_pure: true, ..Rules::NONE })),
            r0i - r1 as i64,
        ];
        let minocrab_only = MINOCRAB_ONLY.iter().any(|p| name.starts_with(p));
        let totals = if minocrab_only { &mut only_totals } else { &mut twin };
        for (t, s) in totals.iter_mut().zip(saved) {
            *t += s;
        }
        rows_out.push((
            saved[4],
            format!(
                "| {name} | {} | {r0} -> {r1} | {k0} -> {k1} | {} | {} | {} | {} | {} | {} |",
                if minocrab_only { "MinoCrab-only" } else { "twin" },
                base.len() - both.len(),
                saved[0],
                saved[1],
                saved[2],
                saved[3],
                saved[4],
            ),
        ));
    }
    rows_out.sort_by_key(|row| std::cmp::Reverse(row.0));
    println!("| circuit | lineage | rows | k | instructions deleted | merge pure | merge determined | constant select | dead pure | all |");
    for (_, line) in &rows_out {
        println!("{line}");
    }
    for (label, t) in [("twin", twin), ("MinoCrab-only", only_totals)] {
        println!("TOTAL {label}: merge pure {} / merge determined {} / constant select {} / dead pure {} / all {}", t[0], t[1], t[2], t[3], t[4]);
    }
}

// ---- rule 3 (constant-operand algebra), measured before deciding -------------------

/// Rows of a circuit built by `build`, as `backend_folding.rs` measures.
fn rows(build: impl FnOnce(&mut minocrab::Circuit)) -> usize {
    let mut c = minocrab::Circuit::new();
    // The builder's own stream, with the M48 C step 3 lean defaults (the
    // simplification and the range dedup) off: this measures what is emitted.
    c.set_lowering(minocrab::Lowering { simplify: false, dedup_range_constraints: false, ..c.lowering() });
    build(&mut c);
    minocrab_sim::cost(&c.finish(true).ir).1
}

const N: usize = 5;

/// The two `cond_select` shapes a constant-operand rule would rewrite, priced
/// against the circuit that does not have them. A rule earns its place only
/// if this is at least a row per instance (notes/ir-passes.org §14).
#[test]
fn constant_operand_selects_cost_what_this_says() {
    use minocrab::FieldT;
    let base = rows(|c| {
        let (x, y) = (c.arg::<FieldT>("x"), c.arg::<FieldT>("y"));
        let mut acc = c.mul(x, y);
        for _ in 0..N {
            acc = c.add(acc, x);
        }
        c.assert(acc);
    });
    // `cond_select 1 x y` in place of `x`.
    let immediate_selector = rows(|c| {
        let (x, y) = (c.arg::<FieldT>("x"), c.arg::<FieldT>("y"));
        let mut acc = c.mul(x, y);
        for _ in 0..N {
            let s = c.cond_select(1u64, x, y);
            acc = c.add(acc, s);
        }
        c.assert(acc);
    });
    // `cond_select g x x` in place of `x`, `g` a bit.
    let same_arms = rows(|c| {
        let (x, y, g) = (c.arg::<FieldT>("x"), c.arg::<FieldT>("y"), c.arg::<FieldT>("g"));
        let g = c.assert_boolean(g);
        let mut acc = c.mul(x, y);
        for _ in 0..N {
            let s = c.cond_select(g, x, x);
            acc = c.add(acc, s);
        }
        c.assert(acc);
    });
    // The same circuit with `g` declared and constrained but no selects.
    let same_arms_base = rows(|c| {
        let (x, y, g) = (c.arg::<FieldT>("x"), c.arg::<FieldT>("y"), c.arg::<FieldT>("g"));
        let _ = c.assert_boolean(g);
        let mut acc = c.mul(x, y);
        for _ in 0..N {
            acc = c.add(acc, x);
        }
        c.assert(acc);
    });
    // Each costs at least a row: the backend does not fold either. The
    // first is the constant-select rule; the second is not a rule, because
    // deleting it drops the constraint that `g` is a bit.
    assert!(immediate_selector >= base + N, "{immediate_selector} vs {base}");
    assert!(same_arms >= same_arms_base + N, "{same_arms} vs {same_arms_base}");
    println!(
        "cond_select 1 x y: {} rows each; cond_select g x x: {} rows each",
        (immediate_selector as f64 - base as f64) / N as f64,
        (same_arms as f64 - same_arms_base as f64) / N as f64
    );
}

/// Every circuit's fingerprint in the simulator's `MINOCRAB_CHECK_SIMPLIFY`
/// log, so a run of the whole suite under the instrument can say which
/// circuits it exercised (notes/ir-passes.org §14).
#[test]
#[ignore = "instrument: prints `<fingerprint> <changed|unchanged> <circuit>` per circuit"]
fn simplify_fingerprints() {
    for (name, build) in support::circuits() {
        let compiled = build();
        let ir = &compiled.ir;
        let changed = simplify(ir.instructions.to_vec(), &native_inputs(ir), &[]).len() < ir.instructions.len();
        println!(
            "FP {:016x} {} {name}",
            minocrab_sim::simplify_check::fingerprint(ir),
            if changed { "changed" } else { "unchanged" }
        );
    }
}
