//! The stale-read backstop on the write path: `minocrab_ledger::emit`
//! refuses a stored value computed from an unacknowledged inline read,
//! whether the write is a typed slot's or written by hand, with the same
//! message; it checks values, never keys; and when it accepts it adds no
//! instruction.

use std::panic::{catch_unwind, AssertUnwindSafe};

use minocrab::{Circuit, Compiled, FieldT, Wire};
use minocrab::Public;
use minocrab_ledger::{
    cell_read, cell_write, emit, list_push_front, map_insert, merkle_tree_insert, ImpactElem,
    LedgerValue,
};
use minocrab_std::{LedgerCell, LedgerMap, LedgerMerkleTree, Uint};
use minocrab_zkir::to_zkir_string;

const U64: minocrab::AlignmentAtom = minocrab::AlignmentAtom::Bytes { length: 8 };

/// Field 0, read through the typed slot the way a contract reads it.
const COUNT: LedgerCell<Uint<64, Public>> = LedgerCell::at(0);
/// Field 1, written by the typed forms of the raw writes below.
const NEXT: LedgerCell<Uint<64, Public>> = LedgerCell::at(1);
const MAP: LedgerMap<Uint<64, Public>, Uint<64, Public>> = LedgerMap::at(1);
const TREE: LedgerMerkleTree<4, Uint<64, Public>> = LedgerMerkleTree::at(1);

/// A `Uint<64>`'s one limb, as the value a raw write stores.
fn value(w: Wire<FieldT, Public>) -> LedgerValue {
    LedgerValue::bytes(8, vec![ImpactElem::Wire(w)])
}

fn zkir(compiled: Compiled) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

/// The panic message of `f`, or `None` if it built.
fn refusal(f: impl FnOnce()) -> Option<String> {
    let err = catch_unwind(AssertUnwindSafe(f)).err()?;
    Some(
        err.downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default(),
    )
}

/// `read(field 0) + 1`: a raw read, unacknowledged, or the typed read
/// acknowledged with `.stale(c)`.
fn bumped(c: &mut Circuit, acknowledged: bool) -> Wire<FieldT, Public> {
    let read = if acknowledged {
        COUNT.read(c).stale(c).field()
    } else {
        cell_read(c, 0, vec![U64])[0]
    };
    c.add(read, 1u64)
}

#[test]
#[should_panic(expected = "a cell write's value descends from a cell read at field 0")]
fn a_raw_write_of_a_value_from_an_unacknowledged_read_is_refused() {
    let mut c = Circuit::new();
    let next = bumped(&mut c, false);
    emit(&mut c, &cell_write(1, &value(next)));
}

/// The same read, written back by hand and through the typed slot: one
/// refusal, word for word.
#[test]
fn the_raw_and_the_typed_write_are_refused_with_the_same_message() {
    let raw = refusal(|| {
        let mut c = Circuit::new();
        let next = bumped(&mut c, false);
        emit(&mut c, &cell_write(1, &value(next)));
    });
    let typed = refusal(|| {
        let mut c = Circuit::new();
        let next = bumped(&mut c, false);
        NEXT.write(&mut c, &Uint::from_field_unchecked(next));
    });
    let raw = raw.expect("the raw write is refused");
    assert!(raw.contains("ASSUMES is still current at landing"), "{raw}");
    assert!(raw.contains("`.stale(c)`") && raw.contains("hook"), "{raw}");
    assert_eq!(Some(raw), typed);
}

type Write = fn(&mut Circuit, &LedgerValue, &LedgerValue);

#[test]
fn the_map_insert_and_the_list_push_are_checked() {
    let writes: [(&str, Write); 2] = [
        ("a map insert's value", |c, k, v| emit(c, &map_insert(1, k, v))),
        ("a list push's value", |c, _, v| emit(c, &list_push_front(1, v))),
    ];
    for (what, write) in writes {
        let message = refusal(|| {
            let mut c = Circuit::new();
            let k = c.arg::<FieldT>("k");
            let k = c.disclose(k, "k");
            let next = bumped(&mut c, false);
            write(&mut c, &value(k), &value(next));
        })
        .unwrap_or_else(|| panic!("{what} from a read is refused"));
        assert!(message.starts_with(&format!("{what} descends from")), "{message}");
    }
}

#[test]
fn an_acknowledged_read_is_accepted_and_the_check_adds_nothing() {
    let raw = {
        let mut c = Circuit::new();
        let next = bumped(&mut c, true);
        emit(&mut c, &cell_write(1, &value(next)));
        c.finish(true)
    };
    let typed = {
        let mut c = Circuit::new();
        let next = bumped(&mut c, true);
        NEXT.write(&mut c, &Uint::from_field_unchecked(next));
        c.finish(true)
    };
    // The elements of the very same ops, handed to the primitive below the
    // check.
    let unchecked = {
        let mut c = Circuit::new();
        let next = bumped(&mut c, true);
        for op in cell_write(1, &value(next)) {
            c.impact_mixed(1u64, &op.0);
        }
        c.finish(true)
    };
    let raw = zkir(raw);
    assert_eq!(raw, zkir(typed));
    assert_eq!(raw, zkir(unchecked));
}

/// A raw read acknowledged by hand, on the wires it returned.
#[test]
fn a_raw_read_is_acknowledged_with_acknowledge_stale() {
    let mut c = Circuit::new();
    let read = cell_read(&mut c, 0, vec![U64]);
    c.acknowledge_stale(&[read[0].val()]);
    let next = c.add(read[0], 1u64);
    emit(&mut c, &cell_write(1, &value(next)));
    let _ = c.finish(true);
}

/// A key derived from an unacknowledged read is accepted, raw and typed
/// alike, and the two are the same circuit.
#[test]
fn a_key_from_a_read_is_accepted_as_a_typed_slot_accepts_it() {
    let raw = {
        let mut c = Circuit::new();
        let v = c.arg::<FieldT>("v");
        let v = c.disclose(v, "v");
        let key = bumped(&mut c, false);
        emit(&mut c, &map_insert(1, &value(key), &value(v)));
        c.finish(true)
    };
    let typed = {
        let mut c = Circuit::new();
        let v = c.arg::<FieldT>("v");
        let v = c.disclose(v, "v");
        let key = bumped(&mut c, false);
        MAP.insert(&mut c, &Uint::from_field_unchecked(key), &Uint::from_field_unchecked(v));
        c.finish(true)
    };
    assert_eq!(zkir(raw), zkir(typed));
}

/// The leaf of a raw Merkle-tree insert is a hash, unchecked as the typed
/// `insert_hash` leaves it; the typed `insert` checks the item it hashes.
#[test]
fn a_merkle_leaf_is_unchecked_and_the_typed_item_is_checked() {
    let mut c = Circuit::new();
    let leaf = bumped(&mut c, false);
    let leaf = LedgerValue::bytes(32, vec![ImpactElem::Wire(leaf), ImpactElem::Wire(leaf)]);
    emit(&mut c, &merkle_tree_insert(1, &leaf));
    let _ = c.finish(true);

    let message = refusal(|| {
        let mut c = Circuit::new();
        let item = bumped(&mut c, false);
        TREE.insert(&mut c, &Uint::from_field_unchecked(item));
    })
    .expect("the typed item from a read is refused");
    assert!(message.starts_with("a merkle-tree insert's item descends from"), "{message}");
}
