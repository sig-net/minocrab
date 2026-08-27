//! `passes::dedup_range_constraints`, pinned instruction by instruction.
//!
//! The pass is the opt profile's one member (notes/ir-passes.org §1, §11), so
//! what it does and — more importantly — what it REFUSES to do is stated here
//! rather than left to the circuits that use it: a range constraint removed
//! where it was not implied is a missing range check, which is invisible to
//! every differential on an honest preimage.

use minocrab_ir::v3::{passes::dedup_range_constraints, Builder3, IrType};
use minocrab_zkir::v3::{Identifier, Instruction, Operand};

fn var(name: &str) -> Operand {
    Operand::Variable(Identifier(name.to_string()))
}

fn bits(name: &str, bits: u32) -> Instruction {
    Instruction::ConstrainBits { val: var(name), bits }
}

fn boolean(name: &str) -> Instruction {
    Instruction::ConstrainToBoolean { val: var(name) }
}

/// An instruction the pass has no opinion about, for checking that
/// everything else survives untouched and in order.
fn assert_(name: &str) -> Instruction {
    Instruction::Assert { cond: var(name) }
}

#[test]
fn a_duplicate_is_dropped_and_the_first_kept() {
    let out = dedup_range_constraints(vec![bits("%a", 64), bits("%a", 64)]);
    assert_eq!(out, vec![bits("%a", 64)]);
}

#[test]
fn a_wider_constraint_after_a_tighter_one_is_dropped() {
    let out = dedup_range_constraints(vec![bits("%a", 8), bits("%a", 64), bits("%a", 248)]);
    assert_eq!(out, vec![bits("%a", 8)]);
}

/// THE DIRECTION THAT IS NOT SOUND, and therefore not taken: a tighter bound
/// is new information, so both constraints stay — and a third, wider one
/// after them is then measured against the TIGHTER of the two.
#[test]
fn a_tighter_constraint_after_a_wider_one_is_kept() {
    let out = dedup_range_constraints(vec![bits("%a", 64), bits("%a", 8), bits("%a", 32)]);
    assert_eq!(out, vec![bits("%a", 64), bits("%a", 8)]);
}

#[test]
fn unrelated_wires_are_untouched_and_order_is_preserved() {
    let stream = vec![
        bits("%a", 8),
        assert_("%p"),
        bits("%b", 8),
        assert_("%q"),
        bits("%a", 8),
        bits("%c", 8),
    ];
    let out = dedup_range_constraints(stream);
    assert_eq!(
        out,
        vec![
            bits("%a", 8),
            assert_("%p"),
            bits("%b", 8),
            assert_("%q"),
            bits("%c", 8),
        ]
    );
}

/// THE BOOLEAN FAMILY IS THE `bits = 1` FAMILY. `constrain_to_boolean` and
/// `constrain_bits(_, 1)` are different gadgets — `convert` to an
/// `AssignedBit` against `assert_lower_than_fixed(x, 2)` (`ir_vm.rs`; see
/// the pass's doc) — and the same PREDICATE, `val ∈ {0,1}`, which is
/// what a constraint-system pass reasons about. So the two dedup against
/// each other, in both directions.
#[test]
fn booleanity_and_a_one_bit_range_are_one_family() {
    assert_eq!(
        dedup_range_constraints(vec![boolean("%a"), boolean("%a")]),
        vec![boolean("%a")]
    );
    assert_eq!(
        dedup_range_constraints(vec![bits("%a", 1), boolean("%a")]),
        vec![bits("%a", 1)]
    );
    assert_eq!(
        dedup_range_constraints(vec![boolean("%a"), bits("%a", 1)]),
        vec![boolean("%a")]
    );
    // The case the checked Borsh serializer actually hits: a `Bool` argument
    // constrained as boolean at entry, then serialized as one BYTE.
    assert_eq!(
        dedup_range_constraints(vec![boolean("%a"), bits("%a", 8)]),
        vec![boolean("%a")]
    );
    // …and not the other way: booleanity after an eight-bit range is real
    // information and stays.
    assert_eq!(
        dedup_range_constraints(vec![bits("%a", 8), boolean("%a")]),
        vec![bits("%a", 8), boolean("%a")]
    );
}

/// A constraint on an IMMEDIATE (reachable after `fold_immediate_copies`
/// substitutes a named constant) has no wire to key on, so the pass neither
/// drops it nor lets it establish a bound for anything else.
#[test]
fn an_immediate_operand_is_left_alone() {
    let on_immediate = Instruction::ConstrainBits {
        val: Operand::Immediate(minocrab_ir::Fr::from(3u64)),
        bits: 8,
    };
    let out = dedup_range_constraints(vec![
        on_immediate.clone(),
        on_immediate.clone(),
        bits("%a", 8),
    ]);
    assert_eq!(out, vec![on_immediate.clone(), on_immediate, bits("%a", 8)]);
}

// ---- the flag ----------------------------------------------------------------

fn duplicate_constraint_circuit(dedup: bool) -> Vec<Instruction> {
    let mut b = Builder3::new();
    b.dedup_range_constraints(dedup);
    let x = b.input("x", IrType::Native);
    b.constrain_bits(x, 64);
    b.constrain_bits(x, 64);
    b.finish(false).instructions.to_vec()
}

/// DEFAULT OFF is the hard gate on this change: a genuine duplicate survives
/// `finish` unless the circuit asked for the pass.
#[test]
fn the_flag_is_off_by_default_and_finish_is_unchanged() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    b.constrain_bits(x, 64);
    b.constrain_bits(x, 64);
    let default = b.finish(false).instructions.to_vec();

    assert_eq!(default.len(), 2, "the default must not deduplicate");
    assert_eq!(default, duplicate_constraint_circuit(false));
    assert_eq!(duplicate_constraint_circuit(true).len(), 1);
}

// ---- the Pass trait (M24) --------------------------------------------------

use minocrab_ir::v3::passes::{
    builtin_names, by_name, run_pipeline, DedupRangeConstraints, FoldImmediateCopies, Pass,
};

#[test]
fn the_dedup_wrapper_matches_the_free_function_and_reports() {
    let stream = vec![bits("%a", 64), bits("%a", 64), assert_("%p")];
    let (out, report) = DedupRangeConstraints.run(stream.clone());
    // Same result as calling the free function directly.
    assert_eq!(out, dedup_range_constraints(stream));
    // The report carries before/after and the pass name.
    assert_eq!(report.pass, "dedup_range_constraints");
    assert_eq!(report.before, 3);
    assert_eq!(report.after, 2);
    // It DROPPED an instruction, so the runner auto-warned even though a
    // valid dedup is sound — "make sure they've been warned first".
    assert!(
        report.warnings.iter().any(|w| w.contains("dropped 1 instruction")),
        "the instruction-drop auto-warning must fire: {:?}",
        report.warnings
    );
    // And the pass's own advisory warning is there too.
    assert!(report.warnings.iter().any(|w| w.contains("implied")));
}

#[test]
fn a_pass_that_changes_nothing_produces_no_drop_warning() {
    // No redundant constraints → nothing dropped → no auto-warning.
    let stream = vec![bits("%a", 64), assert_("%p")];
    let (out, report) = DedupRangeConstraints.run(stream.clone());
    assert_eq!(out, stream);
    assert_eq!(report.before, report.after);
    assert!(
        !report.warnings.iter().any(|w| w.contains("dropped")),
        "no drop, so no drop-warning: {:?}",
        report.warnings
    );
}

#[test]
fn the_registry_resolves_the_builtins_and_rejects_the_unknown() {
    for name in builtin_names() {
        assert_eq!(by_name(name).expect("built-in resolves").name(), *name);
    }
    assert!(by_name("no_such_pass").is_none());
    assert_eq!(
        builtin_names(),
        &["fold_immediate_copies", "dedup_range_constraints"]
    );
}

#[test]
fn a_pipeline_threads_the_ir_and_collects_a_report_per_pass() {
    let stream = vec![bits("%a", 64), bits("%a", 64), assert_("%p")];
    let passes: Vec<Box<dyn Pass>> =
        vec![Box::new(FoldImmediateCopies), Box::new(DedupRangeConstraints)];
    let (out, reports) = run_pipeline(&passes, stream);
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].pass, "fold_immediate_copies");
    assert_eq!(reports[1].pass, "dedup_range_constraints");
    // The dedup stage still drops the duplicate after the (no-op here) fold.
    assert_eq!(out, vec![bits("%a", 64), assert_("%p")]);
}
