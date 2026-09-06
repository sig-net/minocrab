//! THE BATCH, AS A CONTRACT — `Queued<Filing, Env, WORDS, N>` at three batch
//! sizes (M39 rung C, notes/nonce-admin.org §4 and §1.1).
//!
//! What this file is the witness for, none of which could be written before
//! this rung:
//!
//! 1. A request that CHOOSES NO NONCE AND NO FEE. `insert` takes the callee,
//!    the arguments and the key version and nothing else; the nonce is the
//!    contract's, assigned at `flush` from its own counter, and the fee
//!    envelope is the contract's constant one. A requester who could choose
//!    either could file a transaction that never mines, which blocks every
//!    later nonce on the contract's signing path (dmd, 2026-09-06 — the
//!    Pending lineage's prover-chosen `evm_nonce` is what `Queued` REPLACES,
//!    not a second supported path).
//! 2. `flush` at N = 1, 2 and 4: one circuit that reads the two shared
//!    counters ONCE each, files N records, notifies the singleton N times
//!    and advances both counters by N.
//! 3. The settle side, unchanged: `complete` and `refund` on a `Queued` slot
//!    are `Pending`'s over the same two maps, which
//!    `the_settle_side_is_byte_identical_to_pendings` checks against a
//!    `Pending` twin at the same field offsets — the same ZKIR, instruction
//!    for instruction.
//!
//! IT IS A TEST-ONLY CONTRACT, like `tests/evm_no_return.rs`'s: it exercises
//! the API without adding circuits to the crate's frozen snapshots. Nothing
//! here is a deployment.

use minocrab::v3::Circuit3;
use minocrab::Public;
use minocrab_contracts::evm::{erc20, Kinded};
use minocrab_contracts::evm_flow::{
    Contract, Failed, HandleOwned, Inserted, Pending, Queued, Succeeded,
};
use minocrab_contracts::signet_flow::{Requested, Settled, Signet};
use minocrab_sim::v3::cost;
use minocrab_std::v3::{
    circuit, label, Bytes, Disclose, Discloses, Ledger, LedgerRepr, LedgerWidth, Uint,
};
use minocrab_zkir::v3::Instruction as I;

mod leakage;

/// An ERC-20 `transfer`, filed under kind 1.
type Filed = Kinded<erc20::Transfer, 1>;

/// What a settle needs back.
#[derive(LedgerRepr)]
struct Amount {
    amount: Uint<64, Public>,
}

/// Three blocks, one per batch size — a `Queued` slot's `N` is part of its
/// type, so three sizes are three slots (and, here, three contracts, which
/// keeps every field path one byte deep).
#[derive(Ledger)]
struct Batch1 {
    signet: Signet,
    calls: Queued<Filed, HandleOwned<Amount>, 2, 1>,
}

#[derive(Ledger)]
struct Batch2 {
    signet: Signet,
    calls: Queued<Filed, HandleOwned<Amount>, 2, 2>,
}

#[derive(Ledger)]
struct Batch4 {
    signet: Signet,
    calls: Queued<Filed, HandleOwned<Amount>, 2, 4>,
}

/// The UNBATCHED twin: the same filing and the same environment in a
/// `Pending` slot at the same offsets, so that the two settle circuits are
/// comparable instruction for instruction.
#[derive(Ledger)]
struct Unbatched {
    signet: Signet,
    calls: Pending<Filed, HandleOwned<Amount>, 2>,
}

const ONE: Batch1 = Batch1::new();
const TWO: Batch2 = Batch2::new();
const FOUR: Batch4 = Batch4::new();
const PLAIN: Unbatched = Unbatched::new();

label! {
    Sent = "the amount sent";
    Owner = "the requester's refund commitment";
    Recipient = "own public key as refund recipient";
}

// ---- the circuits -------------------------------------------------------------

/// QUEUE A TRANSFER. No nonce argument, no fee argument: the transaction
/// this files is complete except for the number only the contract may
/// choose.
#[circuit]
fn insert_two(
    c: &mut Circuit3,
    key_version: Uint<8>,
    token: Contract<erc20::Erc20>,
    to: Bytes<20>,
    amount: Uint<64>,
) -> Discloses<(Sent, Owner, Inserted)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    TWO.calls.insert_owned::<Owner>(
        c,
        token,
        (to, amount.widen::<128>()),
        key_version,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// The same insert against the N = 1 slot — the same circuit, to show that
/// an insert's cost does not depend on the batch size it will be flushed in.
#[circuit]
fn insert_one(
    c: &mut Circuit3,
    key_version: Uint<8>,
    token: Contract<erc20::Erc20>,
    to: Bytes<20>,
    amount: Uint<64>,
) -> Discloses<(Sent, Owner, Inserted)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    ONE.calls.insert_owned::<Owner>(
        c,
        token,
        (to, amount.widen::<128>()),
        key_version,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// …and against the N = 4 slot.
#[circuit]
fn insert_four(
    c: &mut Circuit3,
    key_version: Uint<8>,
    token: Contract<erc20::Erc20>,
    to: Bytes<20>,
    amount: Uint<64>,
) -> Discloses<(Sent, Owner, Inserted)> {
    let sent = amount.field().disclose_as::<Sent>(c);
    FOUR.calls.insert_owned::<Owner>(
        c,
        token,
        (to, amount.widen::<128>()),
        key_version,
        |_, _| Amount {
            amount: Uint::from_field_unchecked(sent),
        },
    );
    Discloses::of(())
}

/// FLUSH ONE. The degenerate batch: still no prover-chosen nonce.
#[circuit]
fn flush_one(c: &mut Circuit3) -> Discloses<Requested> {
    ONE.calls.flush(c);
    Discloses::of(())
}

/// FLUSH TWO.
#[circuit]
fn flush_two(c: &mut Circuit3) -> Discloses<Requested> {
    TWO.calls.flush(c);
    Discloses::of(())
}

/// FLUSH FOUR.
#[circuit]
fn flush_four(c: &mut Circuit3) -> Discloses<Requested> {
    FOUR.calls.flush(c);
    Discloses::of(())
}

/// SETTLE A SUCCESS — `Pending::complete`, reached through the queued slot.
#[circuit]
fn complete_two(c: &mut Circuit3, ticket: Succeeded<Filed>) -> Discloses<Settled> {
    let outcome = TWO.calls.complete(c, ticket);
    let _amount = outcome.env.inner.amount;
    Discloses::of(())
}

/// The same completion against the UNBATCHED twin: byte for byte the same
/// circuit, which is the claim `the_settle_side_is_byte_identical_to_pendings`
/// checks.
#[circuit]
fn complete_unbatched(c: &mut Circuit3, ticket: Succeeded<Filed>) -> Discloses<Settled> {
    let outcome = PLAIN.calls.complete(c, ticket);
    let _amount = outcome.env.inner.amount;
    Discloses::of(())
}

/// REFUND TO THE REQUESTER — the commitment opens against the HANDLE the
/// requester kept, not against the request id the flush minted.
#[circuit]
fn refund_two(c: &mut Circuit3, ticket: Failed<Filed>) -> Discloses<(Settled, Recipient)> {
    let (_owner, Amount { amount: _amount }, _executed) =
        TWO.calls.refund_to_owner::<Recipient>(c, ticket);
    Discloses::of(())
}

// ---- the tests ----------------------------------------------------------------

fn impacts(ir: &minocrab_zkir::v3::IrSource) -> usize {
    ir.instructions
        .iter()
        .filter(|i| matches!(i, I::Impact { .. }))
        .count()
}

fn asserts_saying(compiled: &minocrab::v3::Compiled3, message: &str) -> usize {
    compiled
        .assert_messages
        .iter()
        .filter(|m| m.message == message)
        .count()
}

fn disclosures_labelled(compiled: &minocrab::v3::Compiled3, label: &str) -> usize {
    compiled
        .disclosures
        .iter()
        .filter(|d| d.label == label)
        .count()
}

/// The block's layout: five Signet fields, then the slot's six.
#[test]
fn the_block_is_laid_out_by_slot_width() {
    for signer in [
        ONE.signet.signer.index(),
        TWO.signet.signer.index(),
        FOUR.signet.signer.index(),
        PLAIN.signet.signer.index(),
    ] {
        assert_eq!(signer, 0);
    }
    assert_eq!(TWO.calls.record_path().as_slice(), &[5]);
    assert_eq!(TWO.calls.record_path().depth(), 1);
    assert_eq!(<Queued<Filed, HandleOwned<Amount>, 2, 2> as LedgerWidth>::WIDTH, 6);
    // The unbatched twin puts its record map at the same index, which is
    // what makes the two settle circuits comparable.
    assert_eq!(PLAIN.calls.record_path().as_slice(), &[5]);
}

/// THE ROW TABLE, printed for the record (a test-only contract has no
/// snapshot): insert is flat in N, flush grows with it.
#[test]
fn the_circuits_build_at_a_finite_cost() {
    let (k_i1, rows_i1) = cost(&insert_one().ir);
    let (k_i2, rows_i2) = cost(&insert_two().ir);
    let (k_i4, rows_i4) = cost(&insert_four().ir);
    let (k_f1, rows_f1) = cost(&flush_one().ir);
    let (k_f2, rows_f2) = cost(&flush_two().ir);
    let (k_f4, rows_f4) = cost(&flush_four().ir);
    let (k_c, rows_c) = cost(&complete_two().ir);
    let (k_r, rows_r) = cost(&refund_two().ir);

    println!("insert N=1: k {k_i1} rows {rows_i1}");
    println!("insert N=2: k {k_i2} rows {rows_i2}");
    println!("insert N=4: k {k_i4} rows {rows_i4}");
    println!("flush  N=1: k {k_f1} rows {rows_f1}");
    println!("flush  N=2: k {k_f2} rows {rows_f2}");
    println!("flush  N=4: k {k_f4} rows {rows_f4}");
    println!("complete:   k {k_c} rows {rows_c}");
    println!("refund:     k {k_r} rows {rows_r}");

    // An insert does not know the batch size it will be flushed in, and its
    // cost says so.
    assert_eq!((k_i1, rows_i1), (k_i2, rows_i2));
    assert_eq!((k_i1, rows_i1), (k_i4, rows_i4));
    // A flush pays per entry, and the growth is linear: the per-flush work
    // (two counter reads, two increments) does not scale.
    assert!(rows_f1 < rows_f2 && rows_f2 < rows_f4, "{rows_f1} {rows_f2} {rows_f4}");
    // Linear to within a couple of rows: the per-entry work is identical
    // entry to entry, and what differs is the handful of range-check rows an
    // immediate `+1` costs where a `+3` costs one more limb.
    let step = rows_f2 - rows_f1;
    let two_steps = rows_f4 - rows_f2;
    assert!(
        two_steps.abs_diff(2 * step) <= 8,
        "flush rows are affine in N: {rows_f1} {rows_f2} {rows_f4}"
    );
    // An insert is cheaper than the filing it defers.
    assert!(rows_i1 < rows_f1, "{rows_i1} {rows_f1}");
}

/// ONE FLUSH, N FILINGS, N NOTIFICATIONS. The cross-call machinery takes N
/// calls from one circuit — the count of communications commitments IS the
/// count of `signBidirectional` calls, and it is N.
#[test]
fn a_flush_notifies_the_singleton_once_per_entry() {
    for (n, compiled) in [(1, flush_one()), (2, flush_two()), (4, flush_four())] {
        assert_eq!(
            disclosures_labelled(&compiled, "xcall communications commitment"),
            n,
            "N = {n}: one notification per filed record"
        );
        assert_eq!(
            disclosures_labelled(&compiled, "xcall entry-point hash"),
            n,
            "N = {n}: one entry point per notification"
        );
        // …and one record id, one record, one freshness assert per entry.
        assert_eq!(disclosures_labelled(&compiled, "request id"), n);
        assert_eq!(disclosures_labelled(&compiled, "request record"), n);
        assert_eq!(asserts_saying(&compiled, "Request already exists"), n);
    }
}

/// THE FLUSH IS A WINDOW, AND IT MUST BE FULL: one presence assert per
/// entry, so a flush of a queue with fewer than N entries has no proof.
#[test]
fn a_flush_requires_every_entry_of_its_window() {
    for (n, compiled) in [(1, flush_one()), (2, flush_two()), (4, flush_four())] {
        assert_eq!(
            asserts_saying(&compiled, "Queued request not found"),
            n,
            "N = {n}: the circuit requires all N entries"
        );
    }
}

/// THE TWO SHARED READS, ONCE EACH. The Impact instruction count is affine
/// in N — `ops(N) = per_flush + N * per_entry` — and the constant term is
/// exactly TWELVE: the two counter reads (`dup 0; idx [field]; popeqc`) and
/// the two increments (`idxp [field]; addi N; insc 1`), three instructions
/// each and no more, whatever N is.
///
/// That is the design's whole claim about contention, stated as arithmetic
/// on the emitted stream rather than as prose: nothing shared is touched a
/// second time however large the batch.
#[test]
fn the_flush_touches_the_two_counters_once_each() {
    let one = impacts(&flush_one().ir);
    let two = impacts(&flush_two().ir);
    let four = impacts(&flush_four().ir);
    let per_entry = two - one;
    assert_eq!(four - two, 2 * per_entry, "{one} {two} {four}");
    assert_eq!(
        one - per_entry,
        3 + 3 + 3 + 3,
        "read flushed_upto, read last_nonce, increment both"
    );
}

/// AN INSERT READS ONE SHARED CELL — the insert counter dmd keeps for now
/// (notes/nonce-admin.org §2.1: the contention-free handle waits for the
/// replacement design). It writes the queue entry and bumps the counter, and
/// it hashes nothing: no record, no request id, no notification.
#[test]
fn an_insert_is_a_write_and_one_counter_read() {
    let compiled = insert_two();
    assert_eq!(disclosures_labelled(&compiled, "xcall communications commitment"), 0);
    assert_eq!(disclosures_labelled(&compiled, "request record"), 0);
    assert_eq!(disclosures_labelled(&compiled, "queued pre-record"), 1);
    assert_eq!(asserts_saying(&compiled, "Queue handle already taken"), 1);
    // FOUR ledger operations and nothing else: read the handle counter
    // (`dup 0; idx; popeqc`), test the key is free (`dup 0; idx; push key;
    // member; popeqc`), insert the entry (`idxp; push key; pushs value; ins;
    // insc`), bump the counter (`idxp; addi 1; insc`).
    assert_eq!(impacts(&compiled.ir), 3 + 5 + 5 + 3);
}

/// THE SETTLE SIDE IS `Pending`'S, BYTE FOR BYTE. The same filing, the same
/// environment, the same offsets — and therefore the same ZKIR: a queued
/// request's completion is not a second implementation of a completion.
#[test]
fn the_settle_side_is_byte_identical_to_pendings() {
    let queued = complete_two();
    let plain = complete_unbatched();
    let a = minocrab_zkir::v3::to_zkir_string(&queued.ir).expect("the ZKIR serializes");
    let b = minocrab_zkir::v3::to_zkir_string(&plain.ir).expect("the ZKIR serializes");
    assert_eq!(a, b, "a queued settle IS a pending settle");
}

/// THE REFUND OPENS AGAINST THE HANDLE. The owner gate witnesses one secret
/// and checks it; the assert that fails for a wrong handle (or a wrong
/// secret) is there, and it is the same one `Pending::refund_to_owner`
/// carries under its request id.
/// A SETTLE BEFORE THE FLUSH HAS NOTHING TO CONSUME. The record a settle
/// looks up is written by the flush and by nothing else, so an attestation
/// presented for a request that is still in the queue fails on the record
/// map's own membership assert — `Pending`'s, inherited whole.
#[test]
fn a_settle_needs_a_flushed_record() {
    assert_eq!(asserts_saying(&complete_two(), "Request not found"), 1);
    assert_eq!(asserts_saying(&refund_two(), "Request not found"), 1);
}

#[test]
fn a_refund_opens_the_requesters_commitment() {
    let compiled = refund_two();
    assert_eq!(asserts_saying(&compiled, "Not the owner"), 1);
    // The completion has no owner gate at all — the Gap 2 property, kept.
    assert_eq!(asserts_saying(&complete_two(), "Not the owner"), 0);
}

/// The library pads this lineage spells as immediates: the MPC signing path
/// (`common::SigningPath::contract_path`, filed by the flush) and the owner
/// commitment's tag pad. The contract names neither.
const LITERALS: &[&str] = &["vault", "vault:refund:"];

/// THE LEAKAGE INVENTORY'S FLUSH LINE (M39's new one — a flush publishes N
/// records at once). Printed rather than frozen: this is a test-only
/// contract, and the frozen tables belong to the two deployed lineages. The
/// gate here is the one the tables assert: nothing witness-dependent reaches
/// the ledger unlabelled.
#[test]
fn the_leakage_walk_runs_over_the_batch() {
    for (name, compiled) in [
        ("insert_two", insert_two()),
        ("flush_one", flush_one()),
        ("flush_two", flush_two()),
        ("flush_four", flush_four()),
        ("complete_two", complete_two()),
        ("refund_two", refund_two()),
    ] {
        let lines = leakage::inventory(name, &compiled, None, LITERALS);
        for line in &lines {
            if line.starts_with("== ") || line.contains("unlabelled witness-dependent") {
                println!("{line}");
            }
            if !line.starts_with("impact #") {
                continue;
            }
            if let Some(rest) = line.split("unlabelled witness-dependent ").nth(1) {
                let n: usize = rest
                    .split_whitespace()
                    .next()
                    .expect("a count follows")
                    .parse()
                    .expect("the count is a number");
                assert_eq!(n, 0, "{name}: {line}");
            }
        }
    }
}
