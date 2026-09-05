//! The typed ledger block must be pure type-level structure: a circuit
//! written through `#[derive(Ledger)]` + [`LedgerMap`] has to lower to the
//! BYTE-IDENTICAL ZKIR of the same circuit written as explicit
//! `minocrab_ledger` calls with hand-written field indices and hand-written
//! atom lists. That is the "no hidden Impact ops" invariant stated as a test:
//! serialized-ZKIR equality catches an extra op, a missing op, a reordered
//! op, a different atom list and a different field index alike.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Secp256k1PointT, Wire3};
use minocrab::{AlignmentAtom, Public};
use minocrab_ledger::{
    cell_read, cell_write, counter_increment, counter_read, emit, map_insert, map_is_empty,
    map_lookup, map_lookup_guarded, map_member, map_member_guarded, map_remove, map_size,
    ImpactElem, LedgerValue,
};
use minocrab_std::v3::{
    Bytes, CircuitAbi, Ledger, LedgerCell, LedgerCounter, LedgerCounter as Counter, LedgerField,
    LedgerMap, LedgerRepr, Secp256k1Point, Uint, B32,
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
    mpc_key: LedgerCell<Secp256k1Point<Public>>,
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

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
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
    assert_eq!(DEMO.mpc_key.index(), 7);
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
        let exists = DEMO.event_map.member_under(&mut c, one, &key);
        c.assert(exists.field());
        let record_back = DEMO.event_map.lookup_under(&mut c, one, &key);
        DEMO.event_map.insert_under(&mut c, one, &key, &record);
        DEMO.event_map.remove_under(&mut c, one, &key);
        let size = DEMO.event_map.size_under(&mut c, one);
        let empty = DEMO.event_map.is_empty_under(&mut c, one);
        let stored = DEMO.refund_commitment.lookup_under(&mut c, one, &key);
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

/// The GUARD-FREE forms (M9 phase 8, candidate 1) are the same ops with the
/// immediate `1` where the guard operand goes — one instruction fewer than
/// the `_under` form, because nothing has to name the `1`, and identical
/// otherwise.
#[test]
fn the_guard_free_methods_are_the_ops_with_an_immediate_guard() {
    let typed = {
        let mut c = Circuit3::new();
        let (key, record) = inputs(&mut c);
        let exists = DEMO.event_map.member(&mut c, &key);
        c.assert(exists.field());
        let record_back = DEMO.event_map.lookup(&mut c, &key);
        DEMO.event_map.insert(&mut c, &key, &record);
        DEMO.event_map.remove(&mut c, &key);
        let size = DEMO.event_map.size(&mut c);
        let empty = DEMO.event_map.is_empty(&mut c);
        let addr = DEMO.evm_address.read(&mut c);
        DEMO.evm_address.write(&mut c, &addr);
        let count = DEMO.initialized.read(&mut c);
        DEMO.request_nonce.increment(&mut c, 1);
        let under = DEMO.initialized.less_than(&mut c, 7);
        c.assert_eq(record_back.0[0], size.field());
        c.assert_eq(empty.field(), count.field());
        c.assert_eq(under.field(), addr.field());
        c.finish(true)
    };

    let explicit = {
        let mut c = Circuit3::new();
        let (key, record) = inputs(&mut c);
        let key_val = key_value(&key);
        let exists = map_member(&mut c, 1u64, 0, &key_val);
        c.assert(exists);
        let record_back = map_lookup(&mut c, 1u64, 0, &key_val, Record::atom_list());
        emit(&mut c, 1u64, &map_insert(0, &key_val, &record_value(&record)));
        emit(&mut c, 1u64, &map_remove(0, &key_val));
        let size = map_size(&mut c, 1u64, 0);
        let empty = map_is_empty(&mut c, 1u64, 0);
        let addr = cell_read(&mut c, 1u64, 4, vec![AlignmentAtom::Bytes { length: 20 }]);
        emit(
            &mut c,
            1u64,
            &cell_write(
                4,
                &LedgerValue::bytes(20, vec![ImpactElem::Wire(addr[0])]),
            ),
        );
        let count = counter_read(&mut c, 1u64, 3);
        emit(&mut c, 1u64, &counter_increment(2, 1));
        let under = minocrab_ledger::counter_less_than(
            &mut c,
            1u64,
            3,
            &LedgerValue::bytes(8, vec![ImpactElem::Imm(minocrab::Fr::from(7u64))]),
        );
        c.assert_eq(record_back[0], size);
        c.assert_eq(empty, count);
        c.assert_eq(under, addr[0]);
        c.finish(true)
    };

    assert_eq!(zkir(typed), zkir(explicit));
}

/// ...and the whole difference between the two forms is the `Copy` that named
/// the guard: the `_under(c, one, ..)` circuit is the guard-free one plus one
/// instruction, and no rows (a `Copy` of an immediate is free).
#[test]
fn the_guard_free_form_is_one_copy_shorter() {
    let count = |guard_free: bool| {
        let mut c = Circuit3::new();
        let (key, _) = inputs(&mut c);
        if guard_free {
            DEMO.event_map.remove(&mut c, &key);
        } else {
            let one = c.constant(1u64);
            DEMO.event_map.remove_under(&mut c, one, &key);
        }
        c.instruction_count()
    };
    assert_eq!(count(false), count(true) + 1);
}

/// A `Secp256k1Point` CELL (M9 phase 8, candidate 2): the limbs are computed
/// in both directions — `encode` on the way out, and a read that mints ONE
/// TYPED gate and encodes it — so the typed cell must equal the hand-written
/// mint/encode/popeq form that `common::cell_read_point` spells out.
#[test]
fn the_point_cell_is_the_hand_written_typed_gate() {
    let atoms = <Secp256k1Point<Public> as CircuitAbi>::atoms();

    let typed = {
        let mut c = Circuit3::new();
        let key = DEMO.mpc_key.read(&mut c);
        DEMO.mpc_key.write(&mut c, &key);
        c.finish(true)
    };

    let explicit = {
        let mut c = Circuit3::new();
        let point = c.public_transcript_input::<Secp256k1PointT>();
        let limbs = c.encode(point);
        let value = LedgerValue::new(
            atoms.clone(),
            limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
        );
        emit(
            &mut c,
            1u64,
            &[
                minocrab_ledger::dup(0),
                minocrab_ledger::idx_field(7),
                minocrab_ledger::popeq(false, &value),
            ],
        );
        let limbs = c.encode(point);
        let value = LedgerValue::new(
            atoms,
            limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
        );
        emit(&mut c, 1u64, &cell_write(7, &value));
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
        // `.or_default()` is the typed layer saying what the raw form below
        // does silently: a guarded-off read IS the type's default. Zero
        // instructions, which is what keeps the two sides equal.
        let pending = DEMO
            .refund_commitment
            .member_guarded(&mut c, branch, &key)
            .or_default();
        let stored = DEMO
            .refund_commitment
            .lookup_guarded(&mut c, branch, &key)
            .or_default();
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

/// The same guarded reads spelled as the SCOPE returning its value —
/// `when(branch, |c| map.lookup(c, &key)).or_default()` — are the same
/// guarded ops: the per-operation `_guarded` parameter and the scope are
/// one lowering.
#[test]
fn the_scoped_map_reads_are_the_guarded_ops() {
    let scoped = {
        let mut c = Circuit3::new();
        let (key, _) = inputs(&mut c);
        let one = c.constant(1u64);
        let branch = c.not(one);
        let pending = c
            .when(branch, |c| DEMO.refund_commitment.member(c, &key))
            .or_default();
        let stored = c
            .when(branch, |c| DEMO.refund_commitment.lookup(c, &key))
            .or_default();
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

    assert_eq!(zkir(scoped), zkir(explicit));
}

/// Cells and counters: the same equality, and the same atoms-from-the-type
/// claim (a `LedgerCell<Bytes<20, Public>>` reads a `bytes 20` cell).
#[test]
fn the_cell_and_counter_methods_are_the_explicit_ops() {
    let typed = {
        let mut c = Circuit3::new();
        let one = c.constant(1u64);
        let addr = DEMO.evm_address.read_under(&mut c, one);
        DEMO.evm_address.write_under(&mut c, one, &addr);
        let chain = DEMO.chain_id.read_under(&mut c, one);
        DEMO.chain_id.write_under(&mut c, one, &chain);
        let count = DEMO.initialized.read_under(&mut c, one);
        DEMO.request_nonce.increment_under(&mut c, one, 1);
        let under = DEMO.initialized.less_than_under(&mut c, one, 7);
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

// ---- #[derive(LedgerRepr)] ---------------------------------------------------

mod derived_repr {
    use minocrab::v3::Circuit3;
    use minocrab::Public;
    use minocrab_std::v3::{repr_limbs, LedgerMap, LedgerRepr, Uint, B32};

    #[derive(LedgerRepr)]
    struct Env {
        id: B32<Public>,
        amount: Uint<64, Public>,
        flag: Uint<8, Public>,
    }

    const ENVS: LedgerMap<B32<Public>, Env> = LedgerMap::at(3);

    /// Atoms concatenate in declaration order, and the limb count is the
    /// sum of the fields'.
    #[test]
    fn atoms_and_limbs_are_the_fields_in_order() {
        let mut expected = B32::<Public>::atoms();
        expected.extend(Uint::<64, Public>::atoms());
        expected.extend(Uint::<8, Public>::atoms());
        assert_eq!(Env::atoms(), expected);
        assert_eq!(
            repr_limbs::<Env>(),
            repr_limbs::<B32<Public>>() + repr_limbs::<Uint<64, Public>>() + 1
        );
    }

    /// A lookup hands back a typed value whose limbs are the read's, in
    /// order; an insert writes them back in the same order.
    #[test]
    fn lookup_then_insert_round_trips_the_limbs() {
        let mut c = Circuit3::new();
        let key = B32 {
            hi: c.constant(1u64),
            lo: c.constant(2u64),
        };
        let env = ENVS.lookup(&mut c, &key);
        let read: Vec<_> = env.limbs(&mut c);
        assert_eq!(read.len(), repr_limbs::<Env>());
        let rebuilt = Env::from_limbs(read.clone());
        let vals = |ws: &[minocrab::v3::Wire3<minocrab::v3::FieldT, Public>]| {
            ws.iter().map(|w| w.val()).collect::<Vec<_>>()
        };
        assert_eq!(vals(&rebuilt.limbs(&mut c)), vals(&read));
        ENVS.insert(&mut c, &key, &rebuilt);
        // The typed fields are the slots they were read into.
        assert_eq!(rebuilt.id.hi.val(), read[0].val());
        assert_eq!(rebuilt.amount.field().val(), read[2].val());
        assert_eq!(rebuilt.flag.field().val(), read[3].val());
    }
}
