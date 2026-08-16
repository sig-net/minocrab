//! **CHECKED CONSTRUCTION + CONSTRAINT DEDUP == TODAY'S STREAM.**
//!
//! The Borsh layer's injectivity has been a doc comment: "PRECONDITION: every
//! pushed wire must already be constrained to its byte length … without that
//! the packing is not injective and the digest binds nothing"
//! (notes/api-safety-survey.org §B3). `Serializer::constrained` and the
//! `Split` / `WitnessCheck` constrained constructors turn it into a check;
//! `Circuit3::dedup_range_constraints` (notes/ir-passes.org §2 iii, §11)
//! makes the check free where the caller had already discharged it.
//!
//! The claim is the first test's, and it is a byte equality rather than a row
//! count: the checked path's added constraints are exact duplicates of the
//! arguments' entry constraints, and the pass drops precisely them, so the
//! shipped ZKIR is instruction for instruction what it is today.
//!
//! The other tests are the ones that keep that claim honest — the check is
//! REAL when nothing else constrained the leaves, and it costs what it says
//! when the opt profile is off.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::borsh::{
    read_canonical, to_bytes, to_bytes_constrained, CircuitBorsh, Flagged, Split, Tag,
    WitnessCheck,
};
use minocrab_std::v3::{ArgPath, Bool, Bytes, BytesN, CircuitArg, Uint, Vis3, B32};
use minocrab_zkir::v3::to_zkir_string;

/// A representative record: every leaf family the layer has, including the
/// `Bool` whose entry constraint is `constrain_to_boolean` while its Borsh
/// segment is one BYTE — the cross-family case the pass has to get right for
/// any of this to be free.
#[derive(CircuitBorsh)]
struct Record<V: Vis3> {
    version: Uint<8, V>,
    flag: Bool<V>,
    kind: Tag<4, V>,
    amount: Uint<64, V>,
    addr: Bytes<20, V>,
    id: B32<V>,
    payload: BytesN<V, 64>,
    calldata: Flagged<Uint<32, V>, V>,
}

/// `1 + 1 + 1 + 8 + 20 + 32 + 64 + (1 + 4)`.
const LEN: usize = 132;

fn ir_of(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(false).ir).expect("IR serializes")
}

/// Same, with the opt profile on.
fn ir_of_deduped(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    c.dedup_range_constraints(true);
    build(&mut c);
    to_zkir_string(&c.finish(false).ir).expect("IR serializes")
}

fn record(c: &mut Circuit3) -> Record<Private> {
    <Record<Private> as CircuitArg>::declare(c, &ArgPath::root("record"))
}

/// The record's packed bytes arriving as an argument — what a reader reads.
fn buffer(c: &mut Circuit3) -> BytesN<Private, LEN> {
    <BytesN<Private, LEN> as CircuitArg>::declare(c, &ArgPath::root("buffer"))
}

// ---- THE KEY TEST ---------------------------------------------------------------

/// **THE CLAIM.** The same circuit written two ways:
///
/// (a) today's — arguments constrained at entry, `to_bytes` trusting them;
/// (b) checked — the same entry constraints, `to_bytes_constrained`, and the
///     dedup pass on.
///
/// Byte-identical ZKIR. Not "the same rows", not "the same count": the same
/// instructions in the same order with the same wire names, which is the
/// criterion every other equivalence in this workspace uses.
#[test]
fn the_checked_serializer_is_free_when_the_arguments_were_constrained() {
    let today = ir_of(|c| {
        let record = record(c);
        record.constrain(c);
        let _ = to_bytes::<LEN, _, _>(c, &record);
    });
    let checked = ir_of_deduped(|c| {
        let record = record(c);
        record.constrain(c);
        let _ = to_bytes_constrained::<LEN, _, _>(c, &record);
    });
    assert_eq!(today, checked);
}

/// The reader's half, on the shape the reader is FOR: a packed buffer
/// arriving as a circuit argument and constrained at entry. The constrained
/// constructor's buffer constraints are duplicates of the entry ones, and the
/// pass drops them — in both modes.
///
/// STATED DIFFERENTLY FROM THE SERIALIZER'S, and the difference is a finding:
/// this cannot be compared against today's dedup-off stream, because the
/// Split reader ALREADY contains a redundant constraint. A leaf that happens
/// to span exactly one limb comes back as that limb's own wire (`take` splits
/// only where it must), so `constrain_canonical` re-constrains a wire the
/// buffer's `constrain_input` already did. On this path the pass is a saving
/// as well as a discharge, which the last assertion pins.
#[test]
fn the_checked_reader_is_free_when_the_buffer_was_constrained() {
    let split_unchecked = |c: &mut Circuit3| {
        let buffer = buffer(c);
        buffer.constrain_input(c);
        let mut reader = Split::new(&buffer);
        let _: Record<Private> = read_canonical(c, &mut reader);
    };
    let split_checked = |c: &mut Circuit3| {
        let buffer = buffer(c);
        buffer.constrain_input(c);
        let mut reader = Split::constrained(c, &buffer);
        let _: Record<Private> = read_canonical(c, &mut reader);
    };
    assert_eq!(ir_of_deduped(split_unchecked), ir_of_deduped(split_checked));

    // The witness-check mode, whose soundness argument needs the buffer's
    // limbs in range as much as the leaves.
    let witness_unchecked = |c: &mut Circuit3| {
        let buffer = buffer(c);
        buffer.constrain_input(c);
        let mut reader = WitnessCheck::<LEN>::new(&buffer);
        let _: Record<Private> = read_canonical(c, &mut reader);
        reader.finish(c);
    };
    let witness_checked = |c: &mut Circuit3| {
        let buffer = buffer(c);
        buffer.constrain_input(c);
        let mut reader = WitnessCheck::<LEN>::constrained(c, &buffer);
        let _: Record<Private> = read_canonical(c, &mut reader);
        reader.finish(c);
    };
    assert_eq!(ir_of_deduped(witness_unchecked), ir_of_deduped(witness_checked));

    // The Split reader's own redundancy, pinned: the pass removes a
    // constraint that was there before any of this.
    let count = |ir: &str| ir.matches("constrain_bits").count();
    assert!(count(&ir_of(split_unchecked)) > count(&ir_of_deduped(split_unchecked)));
    // The witness mode has none — its leaves are fresh witnesses.
    assert_eq!(
        count(&ir_of(witness_unchecked)),
        count(&ir_of_deduped(witness_unchecked))
    );
}

// ---- what keeps the claim honest ------------------------------------------------

/// THE CHECK IS REAL. With the pass on but nothing else constraining the
/// leaves, the checked serializer's constraints survive — the pass removes
/// what is IMPLIED, and an unconstrained wire implies nothing.
///
/// This is the test a future "optimisation" that widened the dedup rule would
/// fail, which is why it is a separate test and not a remark.
#[test]
fn the_check_is_real_when_nothing_else_constrained_the_leaves() {
    let unchecked = ir_of_deduped(|c| {
        let record = record(c);
        let _ = to_bytes::<LEN, _, _>(c, &record);
    });
    let checked = ir_of_deduped(|c| {
        let record = record(c);
        let _ = to_bytes_constrained::<LEN, _, _>(c, &record);
    });
    assert_ne!(unchecked, checked);

    // And it is exactly the constraints, nothing else: ONE PER SEGMENT —
    // eight leaves, of which the `Bytes<32>` is two segments and the
    // `Bytes<64>` three, and the `Flagged` two.
    let count = |ir: &str| ir.matches("constrain_bits").count();
    assert_eq!(count(&checked) - count(&unchecked), 12);
}

/// THE COST IS REAL TOO, and stated the same way: with the opt profile off,
/// the checked path is the unchecked one PLUS its constraints. That is the
/// price a circuit pays for the check where it cannot afford to diverge from
/// compactc — two rows per segment, per `tests/backend_folding.rs`.
#[test]
fn the_flag_off_keeps_every_added_constraint() {
    let today = ir_of(|c| {
        let record = record(c);
        record.constrain(c);
        let _ = to_bytes::<LEN, _, _>(c, &record);
    });
    let checked_unoptimised = ir_of(|c| {
        let record = record(c);
        record.constrain(c);
        let _ = to_bytes_constrained::<LEN, _, _>(c, &record);
    });
    assert_ne!(today, checked_unoptimised);
    let count = |ir: &str| ir.matches("constrain_bits").count();
    assert_eq!(count(&checked_unoptimised) - count(&today), 12);
}

/// A LITERAL SEGMENT IS NOT RE-PROVEN. `Serializer::push_literal` builds its
/// own constant limbs, which are in range by construction — and after the
/// immediate-copy fold a constraint on one names an immediate, which no pass
/// can remove again. So the constrained mode emits nothing for them.
#[test]
fn literal_segments_carry_no_added_constraint() {
    use minocrab_std::v3::Serializer;

    let build = |constrained: bool| {
        ir_of_deduped(move |c| {
            let mut out: Serializer<minocrab::Public> = if constrained {
                Serializer::constrained()
            } else {
                Serializer::new()
            };
            out.push_literal(c, b"minocrab, the eDSL, packed as a literal");
            let _ = out.finish::<39>(c);
        })
    };
    assert_eq!(build(false), build(true));
}
