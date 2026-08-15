//! The typed ledger block must be pure type-level structure: a circuit
//! written through `#[derive(Ledger)]` + [`LedgerMap`] has to lower to the
//! BYTE-IDENTICAL ZKIR of the same circuit written as explicit
//! `minocrab_ledger` calls with hand-written field indices and hand-written
//! atom lists. That is the "no hidden Impact ops" invariant stated as a test:
//! serialized-ZKIR equality catches an extra op, a missing op, a reordered
//! op, a different atom list and a different field index alike.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{AlignmentAtom, Public};
use minocrab_ledger::{
    cell_read, cell_write, counter_increment, counter_read, emit, map_insert, map_is_empty,
    map_lookup, map_lookup_guarded, map_member, map_member_guarded, map_remove, map_size,
    ImpactElem, LedgerValue,
};
use minocrab_std::v3::{
    Bytes, Ledger, LedgerCell, LedgerCounter, LedgerCounter as Counter, LedgerField, LedgerMap,
    LedgerRepr, Uint, B32,
};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

/// A ledger block in the shape of the vault's: a map of records, an
/// unmodelled field, two counters, two cells, two `Bytes<32>` maps.
#[derive(Ledger)]
struct Demo {
    event_map: LedgerMap<B32<Public>, Record>,
    signer: LedgerField,
    request_nonce: LedgerCounter,
    initialized: Counter,
    evm_address: LedgerCell<Bytes<20, Public>>,
    chain_id: LedgerCell<Uint<64, Public>>,
    refund_commitment: LedgerMap<B32<Public>, B32<Public>>,
}

const DEMO: Demo = Demo::new();

/// A stored record whose atoms are its own — the shape a contract's event
/// record has (a hand-written atom list in ONE place, the type).
struct Record(Vec<Wire3<FieldT, Public>>);

impl Record {
    fn atom_list() -> Vec<AlignmentAtom> {
        vec![
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Bytes { length: 8 },
            AlignmentAtom::Bytes { length: 20 },
        ]
    }
}

impl LedgerRepr for Record {
    fn atoms() -> Vec<AlignmentAtom> {
        Record::atom_list()
    }

    fn push_limbs(&self, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(limbs.len(), 4, "record takes 4 limbs");
        Record(limbs)
    }
}

/// The one fact the derive states.
#[test]
fn the_index_is_the_declaration_order() {
    assert_eq!(DEMO.event_map.index(), 0);
    assert_eq!(DEMO.signer.index(), 1);
    assert_eq!(DEMO.request_nonce.index(), 2);
    assert_eq!(DEMO.initialized.index(), 3);
    assert_eq!(DEMO.evm_address.index(), 4);
    assert_eq!(DEMO.chain_id.index(), 5);
    assert_eq!(DEMO.refund_commitment.index(), 6);
    // `const`, so the block costs nothing at run time and an index can be
    // used where a constant is required.
    const EVENT_MAP: u8 = DEMO.event_map.index();
    assert_eq!(EVENT_MAP, 0);
}

/// A key and a record built from circuit arguments, so the streams under
/// comparison contain real wires rather than immediates.
fn inputs(c: &mut Circuit3) -> (B32<Public>, Record) {
    let key_hi = c.arg::<FieldT>("key_hi");
    let key_lo = c.arg::<FieldT>("key_lo");
    let [key_hi, key_lo] = c.disclose_all("key", [key_hi, key_lo]);
    let key = B32 {
        hi: key_hi,
        lo: key_lo,
    };
    let limbs: Vec<_> = (0..4).map(|i| c.arg::<FieldT>(&format!("r{i}"))).collect();
    let record = Record(c.disclose_slice("record", &limbs));
    (key, record)
}

fn key_value(key: &B32<Public>) -> LedgerValue {
    LedgerValue::bytes(32, vec![ImpactElem::Wire(key.hi), ImpactElem::Wire(key.lo)])
}

fn record_value(record: &Record) -> LedgerValue {
    LedgerValue::new(
        Record::atom_list(),
        record.0.iter().map(|&w| ImpactElem::Wire(w)).collect(),
    )
}

/// Every map method, in one circuit, against the explicit form of the same
/// sequence.
#[test]
fn the_map_methods_are_the_explicit_ops() {
    let typed = {
        let mut c = Circuit3::new();
        let (key, record) = inputs(&mut c);
        let one = c.constant(1u64);
        let exists = DEMO.event_map.member(&mut c, one, &key);
        c.assert(exists.field());
        let record_back = DEMO.event_map.lookup(&mut c, one, &key);
        DEMO.event_map.insert(&mut c, one, &key, &record);
        DEMO.event_map.remove(&mut c, one, &key);
        let size = DEMO.event_map.size(&mut c, one);
        let empty = DEMO.event_map.is_empty(&mut c, one);
        let stored = DEMO.refund_commitment.lookup(&mut c, one, &key);
        c.assert_eq(record_back.0[0], stored.hi);
        c.assert_eq(size.field(), empty.field());
        c.finish(true)
    };

    let explicit = {
        let mut c = Circuit3::new();
        let (key, record) = inputs(&mut c);
        let one = c.constant(1u64);
        let key_val = key_value(&key);
        let exists = map_member(&mut c, one, 0, &key_val);
        c.assert(exists);
        let record_back = map_lookup(&mut c, one, 0, &key_val, Record::atom_list());
        emit(
            &mut c,
            one,
            &map_insert(0, &key_val, &record_value(&record)),
        );
        emit(&mut c, one, &map_remove(0, &key_val));
        let size = map_size(&mut c, one, 0);
        let empty = map_is_empty(&mut c, one, 0);
        let stored = map_lookup(
            &mut c,
            one,
            6,
            &key_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        c.assert_eq(record_back[0], stored[0]);
        c.assert_eq(size, empty);
        c.finish(true)
    };

    assert_eq!(zkir(typed), zkir(explicit));
}

/// The guarded reads (a lookup inside a conditional branch) are the guarded
/// ops, not the straight-line ones.
#[test]
fn the_guarded_map_reads_are_the_guarded_ops() {
    let typed = {
        let mut c = Circuit3::new();
        let (key, _) = inputs(&mut c);
        let one = c.constant(1u64);
        let branch = c.not(one);
        let pending = DEMO.refund_commitment.member_guarded(&mut c, branch, &key);
        let stored = DEMO.refund_commitment.lookup_guarded(&mut c, branch, &key);
        c.assert_eq(pending.field(), stored.hi);
        c.finish(true)
    };

    let explicit = {
        let mut c = Circuit3::new();
        let (key, _) = inputs(&mut c);
        let one = c.constant(1u64);
        let branch = c.not(one);
        let key_val = key_value(&key);
        let pending = map_member_guarded(&mut c, branch, 6, &key_val);
        let stored = map_lookup_guarded(
            &mut c,
            branch,
            6,
            &key_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        c.assert_eq(pending, stored[0]);
        c.finish(true)
    };

    assert_eq!(zkir(typed), zkir(explicit));
}

/// Cells and counters: the same equality, and the same atoms-from-the-type
/// claim (a `LedgerCell<Bytes<20, Public>>` reads a `bytes 20` cell).
#[test]
fn the_cell_and_counter_methods_are_the_explicit_ops() {
    let typed = {
        let mut c = Circuit3::new();
        let one = c.constant(1u64);
        let addr = DEMO.evm_address.read(&mut c, one);
        DEMO.evm_address.write(&mut c, one, &addr);
        let chain = DEMO.chain_id.read(&mut c, one);
        DEMO.chain_id.write(&mut c, one, &chain);
        let count = DEMO.initialized.read(&mut c, one);
        DEMO.request_nonce.increment(&mut c, one, 1);
        let under = DEMO.initialized.less_than(&mut c, one, 7);
        c.assert_eq(count.field(), under.field());
        c.finish(true)
    };

    let explicit = {
        let mut c = Circuit3::new();
        let one = c.constant(1u64);
        let addr = cell_read(&mut c, one, 4, vec![AlignmentAtom::Bytes { length: 20 }]);
        emit(
            &mut c,
            one,
            &cell_write(
                4,
                &LedgerValue::bytes(20, vec![ImpactElem::Wire(addr[0])]),
            ),
        );
        let chain = cell_read(&mut c, one, 5, vec![AlignmentAtom::Bytes { length: 8 }]);
        emit(
            &mut c,
            one,
            &cell_write(5, &LedgerValue::bytes(8, vec![ImpactElem::Wire(chain[0])])),
        );
        let count = counter_read(&mut c, one, 3);
        emit(&mut c, one, &counter_increment(2, 1));
        let under = minocrab_ledger::counter_less_than(
            &mut c,
            one,
            3,
            &LedgerValue::bytes(8, vec![ImpactElem::Imm(minocrab::Fr::from(7u64))]),
        );
        c.assert_eq(count, under);
        c.finish(true)
    };

    assert_eq!(zkir(typed), zkir(explicit));
}
