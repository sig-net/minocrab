//! The builder's per-value definition table, through the queries that read
//! it: where each value is bound, the constant it names, whether it is a
//! read under a given guard, and the transcript reads behind it.

use minocrab_ir::v3::{Arg, Builder3, IrType};
use minocrab_ir::Fr;

#[test]
fn a_circuit_argument_has_no_defining_instruction() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let y = b.input("y", IrType::Bytes(32));
    b.add(x, 1u64);
    assert_eq!(b.instruction_index_of(x), None);
    assert_eq!(b.instruction_index_of(y), None);
}

#[test]
fn each_value_is_defined_by_the_instruction_that_binds_it() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let k = b.imm(5u64); // 0
    b.assert(1u64); // 1: binds nothing
    let (div, modulus) = b.div_mod_power_of_two(x, 8); // 2: two outputs
    let bytes = b.into_bytes32(x); // 3
    let (low, high) = b.bytes32_into_low_high(bytes); // 4: two outputs
    let encoded = b.encode(bytes); // 5: one output per encoded slot
    let sum = b.add(div, k); // 6

    assert_eq!(b.instruction_index_of(k), Some(0));
    assert_eq!(b.instruction_index_of(div), Some(2));
    assert_eq!(b.instruction_index_of(modulus), Some(2));
    assert_eq!(b.instruction_index_of(bytes), Some(3));
    assert_eq!(b.instruction_index_of(low), Some(4));
    assert_eq!(b.instruction_index_of(high), Some(4));
    assert_eq!(encoded.len(), 2);
    for e in encoded {
        assert_eq!(b.instruction_index_of(e), Some(5));
    }
    assert_eq!(b.instruction_index_of(sum), Some(6));
    assert_eq!(b.len(), 7);
}

#[test]
fn a_constant_is_recorded_only_for_a_copy_of_an_immediate() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let k = b.imm(7u64);
    // `copy` of an inline immediate is the same `Copy` instruction `imm`
    // emits, so it names that constant too.
    let copied_imm = b.copy(9u64);
    let copied_name = b.copy(k);
    let sum = b.add(k, 0u64);
    let read = b.public_input(IrType::Native, None);

    assert_eq!(b.immediate_of(k), Some(Fr::from(7u64)));
    assert_eq!(b.immediate_of(copied_imm), Some(Fr::from(9u64)));
    assert_eq!(b.immediate_of(copied_name), None);
    assert_eq!(b.immediate_of(sum), None);
    assert_eq!(b.immediate_of(read), None);
    assert_eq!(b.immediate_of(x), None);
}

#[test]
fn a_read_is_guarded_only_by_its_own_guard_operand() {
    let mut b = Builder3::new();
    let g = b.input("g", IrType::Native);
    let h = b.input("h", IrType::Native);
    let public = b.public_input(IrType::Native, Some(Arg::Val(g)));
    let private = b.private_input(IrType::Native, Some(Arg::Val(g)));
    let unguarded = b.public_input(IrType::Native, None);
    let immediate_guard = b.private_input(IrType::Native, Some(Arg::Imm(1u64.into())));
    let computed = b.add(public, 0u64);

    assert!(b.is_read_guarded_by(public, g));
    assert!(b.is_read_guarded_by(private, g));
    assert!(!b.is_read_guarded_by(public, h));
    assert!(!b.is_read_guarded_by(unguarded, g));
    assert!(!b.is_read_guarded_by(immediate_guard, g));
    assert!(!b.is_read_guarded_by(computed, g));
    assert!(!b.is_read_guarded_by(g, g));
}

#[test]
fn the_provenance_walk_finds_the_public_reads_behind_a_value() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let r1 = b.public_input(IrType::Native, None);
    let r2 = b.public_input(IrType::Native, None);
    let w = b.private_input(IrType::Native, None);
    let a = b.add(r1, w);
    let m = b.mul(a, r2);
    let from_arg = b.add(x, w);
    let shared = b.add(r1, r1);

    // Depth first from the value, operands pushed in order, so the last
    // operand is visited first: `m`'s `r2`, then `a`'s `r1`.
    assert_eq!(b.transcript_reads_behind(m, &|_| false), vec![r2, r1]);
    // A read is its own provenance; a private read and an argument have none.
    assert_eq!(b.transcript_reads_behind(r1, &|_| false), vec![r1]);
    assert_eq!(b.transcript_reads_behind(w, &|_| false), vec![]);
    assert_eq!(b.transcript_reads_behind(from_arg, &|_| false), vec![]);
    // A read reached twice is reported once.
    assert_eq!(b.transcript_reads_behind(shared, &|_| false), vec![r1]);
    // `stop` cuts the walk at a value, and at a read itself.
    assert_eq!(b.transcript_reads_behind(m, &|v| v == a), vec![r2]);
    assert_eq!(b.transcript_reads_behind(m, &|v| v == r2), vec![r1]);
}
