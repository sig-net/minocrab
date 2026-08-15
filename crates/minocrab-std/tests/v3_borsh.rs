//! The Borsh (fixed-width subset) layer: the two claims that matter.
//!
//! 1. **IT IS BORSH.** The bytes the circuit hashes and packs are compared,
//!    through the simulator, against `borsh::to_vec` of a plain Rust twin
//!    carrying borsh's own derive — so the oracle is borsh itself, not a
//!    re-statement of our layout logic. The keccak path is checked the same
//!    way, against `Keccak256(borsh::to_vec(v))`.
//! 2. **THE HASH PATH IS FREE.** Every circuit built through
//!    [`CircuitBorsh`] is compared as serialized ZKIR against the same
//!    circuit written by hand over raw wires and a hand-written alignment.
//!    Byte equality is the zero-cost claim, stronger than an instruction
//!    count (the `v3_leaves.rs` / `v3_entry.rs` idiom).
//!
//! Plus the fixed-width property per leaf (`borsh::object_length` of the twin
//! == `LEN` at every value, which is what makes the offsets constants), the
//! layout table, and the rule that `constrain_canonical` is the argument
//! constraint — with `Tag<K>`'s bound as the one documented exception.

use std::borrow::Cow;

use borsh::BorshSerialize;
use midnight_transient_crypto::hash::transient_hash as native_transient_hash;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use minocrab::v3::{Circuit3, FieldT, Prim, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Private};
use minocrab_sim::v3::simulate;
use minocrab_std::v3::borsh::{
    alignment_of, limbs_of, read_split, read_witness_checked, to_bytes, BorshReader, CircuitBorsh,
    CircuitBorshArg, FieldSpec, Flagged, LayoutPath, Limbs, Split, Tag, WitnessCheck,
};
use minocrab_std::v3::{
    hash, ArgPath, Bool, Bytes, BytesN, CircuitAbi, CircuitArg, Serializer, Uint, Vis3, B32,
};
use minocrab_zkir::v3::{to_zkir_string, IrValue};
use sha2::Sha256;
use sha3::{Digest, Keccak256};

// ---- the two declarations of one record ----------------------------------------
//
// THE SPEC TYPE, with borsh's own derive — the oracle. It knows nothing about
// circuits, and the circuit side is never computed from it.

#[derive(BorshSerialize, Clone, Debug)]
struct SpecFlagged<T> {
    is_some: bool,
    value: T,
}

#[derive(BorshSerialize, Clone, Debug)]
struct SpecRecord {
    version: u8,
    flag: bool,
    kind: u8,
    amount: u128,
    addr: [u8; 20],
    id: [u8; 32],
    payload: [u8; 64],
    words: [[u8; 32]; 2],
    calldata: SpecFlagged<u32>,
}

/// THE CIRCUIT TYPE: the same record over wires. Hand-written impls — the
/// derive is stage 3, and its gate is byte-equality against exactly this.
struct Record<V: Vis3> {
    version: Uint<8, V>,
    flag: Bool<V>,
    kind: Tag<4, V>,
    amount: Uint<128, V>,
    addr: Bytes<20, V>,
    id: B32<V>,
    payload: BytesN<V, 64>,
    words: [B32<V>; 2],
    calldata: Flagged<Uint<32, V>, V>,
}

impl<V: Vis3> CircuitAbi for Record<V>
where
    Uint<8, V>: CircuitAbi,
    Bool<V>: CircuitAbi,
    Tag<4, V>: CircuitAbi,
    Uint<128, V>: CircuitAbi,
    Bytes<20, V>: CircuitAbi,
    B32<V>: CircuitAbi,
    BytesN<V, 64>: CircuitAbi,
    [B32<V>; 2]: CircuitAbi,
    Flagged<Uint<32, V>, V>: CircuitAbi,
{
    const SLOTS: usize = 1 + 1 + 1 + 1 + 1 + 2 + 3 + 4 + 2;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Uint<8, V> as CircuitAbi>::push_atoms(atoms);
        <Bool<V> as CircuitAbi>::push_atoms(atoms);
        <Tag<4, V> as CircuitAbi>::push_atoms(atoms);
        <Uint<128, V> as CircuitAbi>::push_atoms(atoms);
        <Bytes<20, V> as CircuitAbi>::push_atoms(atoms);
        <B32<V> as CircuitAbi>::push_atoms(atoms);
        <BytesN<V, 64> as CircuitAbi>::push_atoms(atoms);
        <[B32<V>; 2] as CircuitAbi>::push_atoms(atoms);
        <Flagged<Uint<32, V>, V> as CircuitAbi>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Uint<8, V> as CircuitAbi>::push_prims(prims);
        <Bool<V> as CircuitAbi>::push_prims(prims);
        <Tag<4, V> as CircuitAbi>::push_prims(prims);
        <Uint<128, V> as CircuitAbi>::push_prims(prims);
        <Bytes<20, V> as CircuitAbi>::push_prims(prims);
        <B32<V> as CircuitAbi>::push_prims(prims);
        <BytesN<V, 64> as CircuitAbi>::push_prims(prims);
        <[B32<V>; 2] as CircuitAbi>::push_prims(prims);
        <Flagged<Uint<32, V>, V> as CircuitAbi>::push_prims(prims);
    }
}

impl CircuitArg for Record<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Record {
            version: CircuitArg::declare(c, &path.field("version")),
            flag: CircuitArg::declare(c, &path.field("flag")),
            kind: CircuitArg::declare(c, &path.field("kind")),
            amount: CircuitArg::declare(c, &path.field("amount")),
            addr: CircuitArg::declare(c, &path.field("addr")),
            id: CircuitArg::declare(c, &path.field("id")),
            payload: CircuitArg::declare(c, &path.field("payload")),
            words: CircuitArg::declare(c, &path.field("words")),
            calldata: CircuitArg::declare(c, &path.field("calldata")),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.version.push_slots(slots);
        self.flag.push_slots(slots);
        self.kind.push_slots(slots);
        self.amount.push_slots(slots);
        self.addr.push_slots(slots);
        self.id.push_slots(slots);
        self.payload.push_slots(slots);
        self.words.push_slots(slots);
        self.calldata.push_slots(slots);
    }
}

impl<V: Vis3> CircuitBorsh<V> for Record<V> {
    const LEN: usize = 1 + 1 + 1 + 16 + 20 + 32 + 64 + 64 + (1 + 4);

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        self.version.push_limbs(limbs);
        self.flag.push_limbs(limbs);
        self.kind.push_limbs(limbs);
        self.amount.push_limbs(limbs);
        self.addr.push_limbs(limbs);
        self.id.push_limbs(limbs);
        self.payload.push_limbs(limbs);
        self.words.push_limbs(limbs);
        self.calldata.push_limbs(limbs);
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        self.version.push_segments(out);
        self.flag.push_segments(out);
        self.kind.push_segments(out);
        self.amount.push_segments(out);
        self.addr.push_segments(out);
        self.id.push_segments(out);
        self.payload.push_segments(out);
        self.words.push_segments(out);
        self.calldata.push_segments(out);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.version.constrain_canonical(c);
        self.flag.constrain_canonical(c);
        self.kind.constrain_canonical(c);
        self.amount.constrain_canonical(c);
        self.addr.constrain_canonical(c);
        self.id.constrain_canonical(c);
        self.payload.constrain_canonical(c);
        self.words.constrain_canonical(c);
        self.calldata.constrain_canonical(c);
    }

    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        Record {
            version: CircuitBorsh::read(c, r),
            flag: CircuitBorsh::read(c, r),
            kind: CircuitBorsh::read(c, r),
            amount: CircuitBorsh::read(c, r),
            addr: CircuitBorsh::read(c, r),
            id: CircuitBorsh::read(c, r),
            payload: CircuitBorsh::read(c, r),
            words: CircuitBorsh::read(c, r),
            calldata: CircuitBorsh::read(c, r),
        }
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        <Uint<8, V>>::push_layout(&path.field("version"), offset, out);
        <Bool<V>>::push_layout(&path.field("flag"), offset, out);
        <Tag<4, V>>::push_layout(&path.field("kind"), offset, out);
        <Uint<128, V>>::push_layout(&path.field("amount"), offset, out);
        <Bytes<20, V>>::push_layout(&path.field("addr"), offset, out);
        <B32<V>>::push_layout(&path.field("id"), offset, out);
        <BytesN<V, 64>>::push_layout(&path.field("payload"), offset, out);
        <[B32<V>; 2]>::push_layout(&path.field("words"), offset, out);
        <Flagged<Uint<32, V>, V>>::push_layout(&path.field("calldata"), offset, out);
    }
}

/// A record value, with every leaf distinguishable from every other.
fn spec_record() -> SpecRecord {
    SpecRecord {
        version: 0xA7,
        flag: true,
        kind: 3,
        amount: 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10,
        addr: std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1)),
        id: std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2)),
        payload: std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(3)),
        words: [
            std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(4)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(5)),
        ],
        calldata: SpecFlagged { is_some: true, value: 0xDEAD_BEEF },
    }
}

// ---- native → argument slots ------------------------------------------------------

fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

/// A `Bytes<N>`'s FAB slots: 31-byte chunks from the front, reversed, so slot
/// 0 is the trailing leftover chunk.
fn bytes_n_slots(bytes: &[u8]) -> Vec<Fr> {
    let mut limbs: Vec<Fr> = bytes
        .chunks(31)
        .map(|chunk| Fr::from_le_bytes(chunk).expect("<= 31 bytes fit"))
        .collect();
    limbs.reverse();
    limbs
}

/// The record's argument slots, in `CircuitArg::declare` order.
fn record_slots(spec: &SpecRecord) -> Vec<Fr> {
    let mut slots = vec![
        Fr::from(u64::from(spec.version)),
        Fr::from(u64::from(spec.flag)),
        Fr::from(u64::from(spec.kind)),
        Fr::from_le_bytes(&spec.amount.to_le_bytes()).expect("16 bytes fit"),
        Fr::from_le_bytes(&spec.addr).expect("20 bytes fit"),
    ];
    let (hi, lo) = b32_slots(&spec.id);
    slots.extend([hi, lo]);
    slots.extend(bytes_n_slots(&spec.payload));
    for word in &spec.words {
        let (hi, lo) = b32_slots(word);
        slots.extend([hi, lo]);
    }
    slots.push(Fr::from(u64::from(spec.calldata.is_some)));
    slots.push(Fr::from(u64::from(spec.calldata.value)));
    slots
}

// ---- harness ------------------------------------------------------------------------

/// The ZKIR a circuit body lowers to.
fn ir_of(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(false).ir).expect("IR serializes")
}

fn preimage(inputs: Vec<Fr>) -> ProofPreimage {
    preimage_with(inputs, vec![])
}

fn preimage_with(inputs: Vec<Fr>, private_transcript: Vec<Fr>) -> ProofPreimage {
    ProofPreimage {
        inputs,
        private_transcript,
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-std-v3-borsh")),
    }
}

/// Build, run and read back the native outputs of a circuit over the record.
fn run_record(spec: &SpecRecord, build: impl FnOnce(&mut Circuit3, &Record<Private>)) -> Vec<Fr> {
    let mut c = Circuit3::new();
    let record = <Record<Private> as CircuitArg>::declare(&mut c, &ArgPath::root("record"));
    record.constrain(&mut c);
    build(&mut c, &record);
    let compiled = c.finish(false);
    let run = simulate(&compiled.ir, &preimage(record_slots(spec))).expect("the circuit accepts");
    run.outputs
        .iter()
        .map(|v| match v {
            IrValue::Native(fr) => *fr,
            other => panic!("expected a native output, got {other:?}"),
        })
        .collect()
}

/// The bytes of a `Bytes<N>` read out of the circuit as its FAB slots: slot 0
/// is the leftover (most significant) chunk, so string order is slots
/// reversed.
fn bytes_of_slots<const N: usize>(slots: &[Fr]) -> Vec<u8> {
    assert_eq!(slots.len(), BytesN::<Private, N>::LIMBS);
    let mut bytes = Vec::with_capacity(N);
    for (i, slot) in slots.iter().enumerate().rev() {
        let width = BytesN::<Private, N>::limb_len(i);
        bytes.extend_from_slice(&slot.as_le_bytes()[..width]);
    }
    bytes
}

/// Disclose and output a `Bytes<N>`'s limbs, in slot order.
fn output_bytes<const N: usize>(c: &mut Circuit3, value: &BytesN<Private, N>) {
    for (i, limb) in value.limbs().to_vec().into_iter().enumerate() {
        let public = c.disclose(limb, &format!("limb {i}"));
        c.output(public, &format!("limb {i}"));
    }
}

// ---- (1) IT IS BORSH -------------------------------------------------------------------

/// The packed bytes the circuit produces ARE `borsh::to_vec` of the twin —
/// simulated, byte for byte, all 204 of them.
#[test]
fn packed_bytes_are_canonical_borsh() {
    let spec = spec_record();
    let outputs = run_record(&spec, |c, record| {
        let bytes = to_bytes::<204, _, _>(c, record);
        output_bytes(c, &bytes);
    });
    assert_eq!(
        bytes_of_slots::<204>(&outputs),
        borsh::to_vec(&spec).expect("the twin serializes")
    );
}

/// The same bytes in a padded envelope: `0..LEN` is the Borsh encoding and
/// `LEN..N` is zero — the rule the spec states for fixed containers, and the
/// one the deployed 288-byte `Misc` payload already obeys.
#[test]
fn a_padded_envelope_is_borsh_then_zeros() {
    let spec = spec_record();
    let outputs = run_record(&spec, |c, record| {
        let bytes = to_bytes::<288, _, _>(c, record);
        output_bytes(c, &bytes);
    });
    let bytes = bytes_of_slots::<288>(&outputs);
    let borsh = borsh::to_vec(&spec).expect("the twin serializes");
    assert_eq!(bytes[..borsh.len()], borsh[..]);
    assert!(bytes[borsh.len()..].iter().all(|&b| b == 0), "the pad is not zero");
}

/// The hash path hashes exactly those bytes: the digest the chip produces is
/// `keccak256(borsh::to_vec(v))`, with no packing instruction between.
#[test]
fn the_hash_path_hashes_the_borsh_encoding() {
    let spec = spec_record();
    let outputs = run_record(&spec, |c, record| {
        let digest = limbs_of(record).keccak256(c);
        let pair = B32::from_typed(c, digest);
        let hi = c.disclose(pair.hi, "digest (hi)");
        let lo = c.disclose(pair.lo, "digest (lo)");
        c.output(hi, "digest (hi)");
        c.output(lo, "digest (lo)");
    });
    let mut digest = outputs[1].as_le_bytes()[..31].to_vec();
    digest.push(outputs[0].as_le_bytes()[0]);
    let expected: [u8; 32] = Keccak256::digest(borsh::to_vec(&spec).expect("serializes")).into();
    assert_eq!(digest, expected);
}

// ---- (1b) the fixed-width property -------------------------------------------------------

/// `LEN` is a CONSTANT: `borsh::object_length` of the twin agrees at every
/// value, per leaf and for the whole record. This is the property that makes
/// every offset a compile-time constant — and the one that catches `Option`,
/// which the dual oracle does not (notes/borsh-format.org §"Two corrections").
#[test]
fn every_leaf_is_fixed_width() {
    fn check<T: BorshSerialize>(values: &[T], len: usize, what: &str) {
        for value in values {
            assert_eq!(
                borsh::object_length(value).expect("measures"),
                len,
                "{what} is not fixed-width at this value"
            );
        }
    }

    check(&[0u8, 1, 0xff], <Uint<8, Private> as CircuitBorsh<Private>>::LEN, "u8");
    check(&[0u16, u16::MAX], <Uint<16, Private> as CircuitBorsh<Private>>::LEN, "u16");
    check(&[0u32, u32::MAX], <Uint<32, Private> as CircuitBorsh<Private>>::LEN, "u32");
    check(&[0u64, u64::MAX], <Uint<64, Private> as CircuitBorsh<Private>>::LEN, "u64");
    check(&[0u128, u128::MAX], <Uint<128, Private> as CircuitBorsh<Private>>::LEN, "u128");
    check(&[false, true], <Bool<Private> as CircuitBorsh<Private>>::LEN, "bool");
    check(&[[0u8; 20], [0xff; 20]], <Bytes<20, Private> as CircuitBorsh<Private>>::LEN, "[u8; 20]");
    check(&[[0u8; 32], [0xff; 32]], <B32<Private> as CircuitBorsh<Private>>::LEN, "[u8; 32]");
    check(&[[0u8; 64], [0xff; 64]], <BytesN<Private, 64> as CircuitBorsh<Private>>::LEN, "[u8; 64]");
    check(&[[[0u8; 32]; 2]], <[B32<Private>; 2] as CircuitBorsh<Private>>::LEN, "[[u8; 32]; 2]");
    check(
        &[
            SpecFlagged { is_some: true, value: 7u32 },
            SpecFlagged { is_some: false, value: 0u32 },
        ],
        <Flagged<Uint<32, Private>, Private> as CircuitBorsh<Private>>::LEN,
        "Flagged<u32>",
    );

    let mut spec = spec_record();
    check(&[spec.clone()], <Record<Private> as CircuitBorsh<Private>>::LEN, "Record");
    // The tag being unset changes NOTHING about the width — that is the
    // whole difference between Flagged and Option.
    spec.calldata = SpecFlagged { is_some: false, value: 0 };
    check(&[spec], <Record<Private> as CircuitBorsh<Private>>::LEN, "Record (flag unset)");
}

// ---- (2) THE HASH PATH IS FREE ------------------------------------------------------------

/// `limbs_of(..).keccak256(c)` lowers to the byte-identical ZKIR of a
/// hand-written alignment and a hand-written operand list — the zero-cost
/// claim, and simultaneously the statement that the alignment IS the Borsh
/// layout.
#[test]
fn the_hash_preimage_is_the_hand_written_one() {
    fn atom(length: u32) -> AlignmentSegment {
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length })
    }

    let hand = ir_of(|c| {
        let version: Wire3<FieldT, Private> = c.arg("record_version");
        let flag: Wire3<FieldT, Private> = c.arg("record_flag");
        let kind: Wire3<FieldT, Private> = c.arg("record_kind");
        let amount: Wire3<FieldT, Private> = c.arg("record_amount");
        let addr: Wire3<FieldT, Private> = c.arg("record_addr");
        let id_hi: Wire3<FieldT, Private> = c.arg("record_id_hi");
        let id_lo: Wire3<FieldT, Private> = c.arg("record_id_lo");
        let payload: Vec<Wire3<FieldT, Private>> =
            (0..3).map(|i| c.arg(&format!("record_payload_{i}"))).collect();
        let words: Vec<Wire3<FieldT, Private>> = (0..2)
            .flat_map(|i| {
                [
                    format!("record_words_{i}_hi"),
                    format!("record_words_{i}_lo"),
                ]
            })
            .map(|label| c.arg(&label))
            .collect();
        let is_some: Wire3<FieldT, Private> = c.arg("record_calldata_is_some");
        let calldata: Wire3<FieldT, Private> = c.arg("record_calldata");

        let alignment = Alignment(vec![
            atom(1),
            atom(1),
            atom(1),
            atom(16),
            atom(20),
            atom(32),
            atom(64),
            atom(32),
            atom(32),
            atom(1),
            atom(4),
        ]);
        let mut operands = vec![
            version.erase(),
            flag.erase(),
            kind.erase(),
            amount.erase(),
            addr.erase(),
            id_hi.erase(),
            id_lo.erase(),
        ];
        operands.extend(payload.iter().map(|w| w.erase()));
        operands.extend(words.iter().map(|w| w.erase()));
        operands.extend([is_some.erase(), calldata.erase()]);
        let _ = c.keccak256(alignment, &operands);
    });

    let typed = ir_of(|c| {
        let record = <Record<Private> as CircuitArg>::declare(c, &ArgPath::root("record"));
        let _ = limbs_of(&record).keccak256(c);
    });

    assert_eq!(hand, typed);
}

/// `to_bytes` lowers to the byte-identical ZKIR of the hand-written
/// `Serializer` calls — the packed path adds no cost of its own over the M7
/// segment packing.
#[test]
fn the_packed_path_is_the_hand_written_serializer() {
    let hand = ir_of(|c| {
        let record = <Record<Private> as CircuitArg>::declare(c, &ArgPath::root("record"));
        let mut out = Serializer::new();
        out.push_uint(record.version.field(), 1);
        out.push_uint(record.flag.field(), 1);
        out.push_uint(record.kind.field(), 1);
        out.push_uint(record.amount.field(), 16);
        out.push_uint(record.addr.field(), 20);
        out.push_b32(&record.id);
        out.push_bytes_n(&record.payload);
        for word in &record.words {
            out.push_b32(word);
        }
        out.push_uint(record.calldata.is_some.field(), 1);
        out.push_uint(record.calldata.value.field(), 4);
        let _ = out.finish::<204>(c);
    });

    let typed = ir_of(|c| {
        let record = <Record<Private> as CircuitArg>::declare(c, &ArgPath::root("record"));
        let _ = to_bytes::<204, _, _>(c, &record);
    });

    assert_eq!(hand, typed);
}

/// Describing the preimage emits NOTHING: `limbs_of` and `alignment_of` are
/// bookkeeping over wires that already exist.
#[test]
fn describing_the_preimage_is_free() {
    let mut c = Circuit3::new();
    let record = <Record<Private> as CircuitArg>::declare(&mut c, &ArgPath::root("record"));
    let before = c.instruction_count();
    let limbs = limbs_of(&record);
    let _ = alignment_of(&record);
    assert_eq!(c.instruction_count(), before);
    assert_eq!(limbs.len(), <Record<Private> as CircuitBorsh<Private>>::LEN);
    assert_eq!(limbs.atoms().len(), 11);
    assert_eq!(limbs.wires().len(), <Record<Private> as CircuitAbi>::SLOTS);
}

// ---- (3) canonicity constraints -------------------------------------------------------------

/// `constrain_canonical` IS `CircuitArg::constrain` for every leaf that is
/// both — the same instructions, in the same order — so a value that entered
/// as a circuit argument is already canonical and nothing is emitted twice.
#[test]
fn constrain_canonical_is_the_argument_constraint() {
    macro_rules! same {
        ($ty:ty, $what:literal) => {{
            let as_arg = ir_of(|c| {
                let v = <$ty as CircuitArg>::declare(c, &ArgPath::root("x"));
                CircuitArg::constrain(&v, c);
            });
            let as_borsh = ir_of(|c| {
                let v = <$ty as CircuitArg>::declare(c, &ArgPath::root("x"));
                CircuitBorsh::constrain_canonical(&v, c);
            });
            assert_eq!(as_arg, as_borsh, "{} disagrees", $what);
        }};
    }

    same!(Uint<8, Private>, "Uint<8>");
    same!(Uint<16, Private>, "Uint<16>");
    same!(Uint<32, Private>, "Uint<32>");
    same!(Uint<64, Private>, "Uint<64>");
    same!(Uint<128, Private>, "Uint<128>");
    same!(Bool<Private>, "Bool");
    same!(Bytes<20, Private>, "Bytes<20>");
    same!(B32<Private>, "B32");
    same!(BytesN<Private, 64>, "BytesN<64>");
    same!([B32<Private>; 2], "[B32; 2]");
    same!(Flagged<Uint<32, Private>, Private>, "Flagged<Uint<32>>");
}

/// THE ONE EXCEPTION, and the reason `constrain_canonical` exists at all: a
/// tag's canonicity is `< K`, which no Compact circuit emits. The canonical
/// form is the argument constraint PLUS that bound.
#[test]
fn a_tag_adds_the_bound_compactc_does_not_emit() {
    let as_arg = ir_of(|c| {
        let t = <Tag<4, Private> as CircuitArg>::declare(c, &ArgPath::root("kind"));
        CircuitArg::constrain(&t, c);
    });
    let as_borsh = ir_of(|c| {
        let t = <Tag<4, Private> as CircuitArg>::declare(c, &ArgPath::root("kind"));
        CircuitBorsh::constrain_canonical(&t, c);
    });
    assert_ne!(as_arg, as_borsh, "Tag<4> must range-check the discriminant");

    let hand = ir_of(|c| {
        let t: Wire3<FieldT, Private> = c.arg("kind");
        c.assert_bits(t, 8);
        let bound = c.constant(4u64);
        let ok = c.less_than(t, bound.private(), 8);
        c.assert(ok);
    });
    assert_eq!(hand, as_borsh);

    // A 256-variant tag needs no bound: every byte is a variant.
    let full = ir_of(|c| {
        let t = <Tag<256, Private> as CircuitArg>::declare(c, &ArgPath::root("kind"));
        CircuitBorsh::constrain_canonical(&t, c);
    });
    assert_eq!(full, as_arg);
}

/// The circuit REJECTS a discriminant outside the enum — the bound is a real
/// constraint, not a comment.
#[test]
fn a_tag_out_of_range_is_rejected() {
    let mut c = Circuit3::new();
    let tag = <Tag<4, Private> as CircuitArg>::declare(&mut c, &ArgPath::root("kind"));
    CircuitBorsh::constrain_canonical(&tag, &mut c);
    let ir = c.finish(false).ir;

    for variant in 0..4u64 {
        assert!(
            simulate(&ir, &preimage(vec![Fr::from(variant)])).is_ok(),
            "variant {variant} must be accepted"
        );
    }
    for bad in [4u64, 5, 255] {
        assert!(
            simulate(&ir, &preimage(vec![Fr::from(bad)])).is_err(),
            "{bad} is not a variant of Tag<4>"
        );
    }
}

// ---- (4) the layout table ------------------------------------------------------------------

/// The published offset table: dot-joined SPEC paths, borsh declarations as
/// kinds, offsets that sum to `LEN` — the same four columns stage 0's schema
/// walk produces, which is what stage 3 cross-checks against.
#[test]
fn the_layout_table_is_the_offset_table() {
    let rows: Vec<(String, String, usize, usize)> =
        <Record<Private> as CircuitBorsh<Private>>::layout()
            .into_iter()
            .map(|f| (f.path, f.kind, f.offset, f.width))
            .collect();
    let expected: Vec<(&str, &str, usize, usize)> = vec![
        ("version", "u8", 0, 1),
        ("flag", "bool", 1, 1),
        ("kind", "u8", 2, 1),
        ("amount", "u128", 3, 16),
        ("addr", "[u8; 20]", 19, 20),
        ("id", "[u8; 32]", 39, 32),
        ("payload", "[u8; 64]", 71, 64),
        ("words[0]", "[u8; 32]", 135, 32),
        ("words[1]", "[u8; 32]", 167, 32),
        ("calldata.is_some", "bool", 199, 1),
        ("calldata.value", "u32", 200, 4),
    ];
    assert_eq!(rows.len(), expected.len());
    for (got, want) in rows.iter().zip(expected) {
        assert_eq!(
            (got.0.as_str(), got.1.as_str(), got.2, got.3),
            want,
            "layout row"
        );
    }

    // The offsets are the ones a Borsh decoder computes: each leaf starts
    // where the previous one ended, and the last ends at LEN.
    let last = rows.last().expect("rows");
    assert_eq!(
        last.2 + last.3,
        <Record<Private> as CircuitBorsh<Private>>::LEN
    );
}

// ---- (5) THE READER (stage 2) -------------------------------------------------------------
//
// A library component: no vault circuit uses it. Both modes are proven
// against bytes borsh itself produced, not only against our own writer.

/// The widths the record's `read` takes, in order: a `Bytes<32>` reads as
/// 31 + 1 (the `[lo, hi]` slot pair), a `Bytes<64>` as its limbs in string
/// order. Slicing borsh's own output by this list gives the witness values
/// WitnessCheck mode consumes — the private transcript, straight off the
/// wire format.
const TAKE_WIDTHS: &[usize] = &[1, 1, 1, 16, 20, 31, 1, 31, 31, 2, 31, 1, 31, 1, 1, 4];

fn take_order_values(bytes: &[u8]) -> Vec<Fr> {
    let mut values = Vec::with_capacity(TAKE_WIDTHS.len());
    let mut at = 0usize;
    for &width in TAKE_WIDTHS {
        values.push(Fr::from_le_bytes(&bytes[at..at + width]).expect("<= 31 bytes fit"));
        at += width;
    }
    assert_eq!(at, <Record<Private> as CircuitBorsh<Private>>::LEN);
    values
}

/// Disclose and output a record's leaf wires, in `CircuitArg` slot order —
/// so the outputs are directly comparable with [`record_slots`].
fn output_record_leaves(c: &mut Circuit3, record: &Record<Private>) {
    let mut wires = vec![
        record.version.field(),
        record.flag.field(),
        record.kind.field(),
        record.amount.field(),
        record.addr.field(),
        record.id.hi,
        record.id.lo,
    ];
    wires.extend(record.payload.limbs().iter().copied());
    for word in &record.words {
        wires.extend([word.hi, word.lo]);
    }
    wires.push(record.calldata.is_some.field());
    wires.push(record.calldata.value.field());
    for (i, wire) in wires.into_iter().enumerate() {
        let public = c.disclose(wire, "leaf");
        c.output(public, &format!("leaf {i}"));
    }
}

/// Split mode parses bytes `borsh::to_vec` produced into the right field
/// values — decode correctness against borsh itself, through the simulator.
#[test]
fn split_mode_reads_native_borsh_bytes() {
    let spec = spec_record();
    let bytes = borsh::to_vec(&spec).expect("serializes");

    let mut c = Circuit3::new();
    let packed = BytesN::<Private, 204>::arg(&mut c, "bytes");
    packed.constrain_input(&mut c);
    let record: Record<Private> = read_split(&mut c, &packed);
    output_record_leaves(&mut c, &record);
    let ir = c.finish(false).ir;

    let run = simulate(&ir, &preimage(bytes_n_slots(&bytes))).expect("the reader accepts");
    let outputs: Vec<Fr> = run
        .outputs
        .iter()
        .map(|v| match v {
            IrValue::Native(fr) => *fr,
            other => panic!("expected a native output, got {other:?}"),
        })
        .collect();
    assert_eq!(outputs, record_slots(&spec));
}

/// WitnessCheck mode, same statement: the witnesses it accepts are exactly
/// the fields borsh encoded, and it hands them back in the right slots.
#[test]
fn witness_check_mode_reads_native_borsh_bytes() {
    let spec = spec_record();
    let bytes = borsh::to_vec(&spec).expect("serializes");

    let mut c = Circuit3::new();
    let packed = BytesN::<Private, 204>::arg(&mut c, "bytes");
    packed.constrain_input(&mut c);
    let record: Record<Private> = read_witness_checked(&mut c, &packed);
    output_record_leaves(&mut c, &record);
    let ir = c.finish(false).ir;

    let pi = preimage_with(bytes_n_slots(&bytes), take_order_values(&bytes));
    let run = simulate(&ir, &pi).expect("the reader accepts");
    let outputs: Vec<Fr> = run
        .outputs
        .iter()
        .map(|v| match v {
            IrValue::Native(fr) => *fr,
            other => panic!("expected a native output, got {other:?}"),
        })
        .collect();
    assert_eq!(outputs, record_slots(&spec));
}

/// A lying witness is rejected: the re-pack equality is what makes
/// WitnessCheck a proof rather than a hint. Every leaf is checked, one at a
/// time.
#[test]
fn witness_check_rejects_a_lying_witness() {
    let spec = spec_record();
    let bytes = borsh::to_vec(&spec).expect("serializes");

    let mut c = Circuit3::new();
    let packed = BytesN::<Private, 204>::arg(&mut c, "bytes");
    packed.constrain_input(&mut c);
    let _record: Record<Private> = read_witness_checked(&mut c, &packed);
    let ir = c.finish(false).ir;

    let honest = take_order_values(&bytes);
    assert!(simulate(&ir, &preimage_with(bytes_n_slots(&bytes), honest.clone())).is_ok());
    for leaf in 0..honest.len() {
        let mut lying = honest.clone();
        lying[leaf] = lying[leaf] + Fr::from(1u64);
        assert!(
            simulate(&ir, &preimage_with(bytes_n_slots(&bytes), lying)).is_err(),
            "leaf {leaf} was not checked against the buffer"
        );
    }
}

/// `read(to_bytes(v)) == v`, in circuit, in both modes: the round-trip
/// property, asserted wire by wire and run through the simulator.
#[test]
fn both_modes_round_trip_in_circuit() {
    fn round_trip(witness_check: bool) {
        let spec = spec_record();
        let mut c = Circuit3::new();
        let original = <Record<Private> as CircuitArg>::declare(&mut c, &ArgPath::root("record"));
        original.constrain(&mut c);
        let packed = to_bytes::<204, _, _>(&mut c, &original);
        let back: Record<Private> = if witness_check {
            read_witness_checked(&mut c, &packed)
        } else {
            read_split(&mut c, &packed)
        };
        assert_records_equal(&mut c, &original, &back);
        let ir = c.finish(false).ir;

        let private = if witness_check {
            take_order_values(&borsh::to_vec(&spec).expect("serializes"))
        } else {
            vec![]
        };
        simulate(&ir, &preimage_with(record_slots(&spec), private))
            .expect("the round trip holds");
    }

    round_trip(false);
    round_trip(true);
}

fn assert_records_equal(c: &mut Circuit3, a: &Record<Private>, b: &Record<Private>) {
    c.assert_eq(a.version.field(), b.version.field());
    c.assert_eq(a.flag.field(), b.flag.field());
    c.assert_eq(a.kind.field(), b.kind.field());
    c.assert_eq(a.amount.field(), b.amount.field());
    c.assert_eq(a.addr.field(), b.addr.field());
    c.assert_eq(a.id.hi, b.id.hi);
    c.assert_eq(a.id.lo, b.id.lo);
    for (x, y) in a.payload.limbs().iter().zip(b.payload.limbs()) {
        c.assert_eq(*x, *y);
    }
    for (x, y) in a.words.iter().zip(&b.words) {
        c.assert_eq(x.hi, y.hi);
        c.assert_eq(x.lo, y.lo);
    }
    c.assert_eq(a.calldata.is_some.field(), b.calldata.is_some.field());
    c.assert_eq(a.calldata.value.field(), b.calldata.value.field());
}

/// THE PADDING RULE, enforced by both modes: a 204-byte value read out of a
/// 288-byte envelope accepts a zero tail and rejects a dirty one. (Split
/// asserts it segment by segment; WitnessCheck gets it for free, because the
/// re-pack zero-fills the tail and the equality covers every limb.)
#[test]
fn both_modes_reject_a_dirty_pad() {
    let spec = spec_record();
    let borsh_bytes = borsh::to_vec(&spec).expect("serializes");

    for witness_check in [false, true] {
        let mut c = Circuit3::new();
        let packed = BytesN::<Private, 288>::arg(&mut c, "bytes");
        packed.constrain_input(&mut c);
        let _record: Record<Private> = if witness_check {
            read_witness_checked(&mut c, &packed)
        } else {
            read_split(&mut c, &packed)
        };
        let ir = c.finish(false).ir;

        let private = if witness_check {
            take_order_values(&borsh_bytes)
        } else {
            vec![]
        };

        let mut envelope = vec![0u8; 288];
        envelope[..borsh_bytes.len()].copy_from_slice(&borsh_bytes);
        let pi = preimage_with(bytes_n_slots(&envelope), private.clone());
        assert!(simulate(&ir, &pi).is_ok(), "a zero pad must be accepted");

        for dirty in [204usize, 250, 287] {
            let mut tampered = envelope.clone();
            tampered[dirty] = 0xff;
            let pi = preimage_with(bytes_n_slots(&tampered), private.clone());
            assert!(
                simulate(&ir, &pi).is_err(),
                "pad byte {dirty} must be checked (witness_check = {witness_check})"
            );
        }
    }
}

/// The reader consumes exactly what the writer wrote: `Split` is left with
/// the envelope's pad and nothing else.
#[test]
fn the_reader_consumes_exactly_len_bytes() {
    let mut c = Circuit3::new();
    let packed = BytesN::<Private, 288>::arg(&mut c, "bytes");
    let mut reader = Split::new(&packed);
    assert_eq!(reader.remaining(), 288);
    let _record = <Record<Private> as CircuitBorsh<Private>>::read(&mut c, &mut reader);
    assert_eq!(
        reader.remaining(),
        288 - <Record<Private> as CircuitBorsh<Private>>::LEN
    );
}

/// The two modes are not the same circuit, and the difference is the point:
/// Split spends a ~143-row `div_mod` per field boundary interior to a limb,
/// WitnessCheck spends 2w+1 rows per leaf (w bytes wide) plus one `div_mod`
/// per straddled LIMB boundary in the re-pack — at most one per 31 bytes,
/// whatever the field layout. Measured at this record: 2,587 vs 1,331 rows of
/// reading, 1.9x; per leaf the ratio runs from 2.0x ([[u8; 32]; 2]) to 73x
/// (bool). The table is `minocrab-sim/examples/borshcost.rs`.
#[test]
fn witness_check_is_the_cheaper_mode() {
    fn rows(build: impl FnOnce(&mut Circuit3)) -> usize {
        let mut c = Circuit3::new();
        build(&mut c);
        c.finish(false).ir.model().rows()
    }
    fn buffer(c: &mut Circuit3) -> BytesN<Private, 204> {
        let packed = BytesN::<Private, 204>::arg(c, "bytes");
        packed.constrain_input(c);
        packed
    }

    let baseline = rows(|c| {
        buffer(c);
    });
    let split = rows(|c| {
        let packed = buffer(c);
        let _record: Record<Private> = read_split(c, &packed);
    }) - baseline;
    let witness_check = rows(|c| {
        let packed = buffer(c);
        let _record: Record<Private> = read_witness_checked(c, &packed);
    }) - baseline;
    assert!(
        witness_check * 3 < split * 2,
        "WitnessCheck ({witness_check} rows of reading) should be at least 1.5x \
         cheaper than Split ({split})"
    );
}

/// A partial WitnessCheck read that never calls `finish` constrains nothing
/// — which is why `read_witness_checked` exists and emits it for you.
#[test]
fn a_witness_check_without_finish_proves_nothing() {
    let mut c = Circuit3::new();
    let packed = BytesN::<Private, 204>::arg(&mut c, "bytes");
    packed.constrain_input(&mut c);
    let mut reader = WitnessCheck::<204>::new(&packed);
    let _leaf = <Uint<64, Private> as CircuitBorsh<Private>>::read(&mut c, &mut reader);
    drop(reader);
    let ir = c.finish(false).ir;

    // Any witness at all is accepted: nothing ties it to the buffer.
    let bytes = borsh::to_vec(&spec_record()).expect("serializes");
    assert!(simulate(&ir, &preimage_with(bytes_n_slots(&bytes), vec![Fr::from(9u64)])).is_ok());
}

// ---- the strict extension ---------------------------------------------------------------------

/// Every `Private` leaf and the record are BOTH a circuit argument and Borsh
/// serializable — the "one derive yields both" claim, as a compile-time fact.
#[test]
fn the_leaves_are_arguments_and_borsh() {
    fn assert_both<T: CircuitBorshArg>() {}

    assert_both::<Uint<8, Private>>();
    assert_both::<Uint<16, Private>>();
    assert_both::<Uint<32, Private>>();
    assert_both::<Uint<64, Private>>();
    assert_both::<Uint<128, Private>>();
    assert_both::<Bool<Private>>();
    assert_both::<Bytes<20, Private>>();
    assert_both::<B32<Private>>();
    assert_both::<BytesN<Private, 64>>();
    assert_both::<Tag<4, Private>>();
    assert_both::<[B32<Private>; 2]>();
    assert_both::<Flagged<Uint<32, Private>, Private>>();
    assert_both::<Record<Private>>();
}

// ---- (6) THE HASH FLAVORS (stage 9) -------------------------------------------------------------
//
// `minocrab_std::v3::hash` offers each hash twice: over the value's Borsh
// encoding (the default) and over Compact's FAB representation (`_compact`,
// for digest agreement with a Compact contract). These four tests say what
// each flavor hashes, where they agree and where they do not — so that
// picking one is a decision with a test behind it rather than a habit.

/// THE DEFAULT FLAVOR IS THE SPECIFIED ONE: the digest the chip produces is
/// `SHA-256(borsh::to_vec(value))`, checked through the simulator against
/// borsh's own encoder and a native SHA-256.
#[test]
fn persistent_hash_is_sha256_of_the_borsh_encoding() {
    let spec = spec_record();
    let outputs = run_record(&spec, |c, record| {
        let digest = hash::persistent_hash(c, record);
        let hi = c.disclose(digest.hi, "digest (hi)");
        let lo = c.disclose(digest.lo, "digest (lo)");
        c.output(hi, "digest (hi)");
        c.output(lo, "digest (lo)");
    });
    let mut digest = outputs[1].as_le_bytes()[..31].to_vec();
    digest.push(outputs[0].as_le_bytes()[0]);
    let expected: [u8; 32] = Sha256::digest(borsh::to_vec(&spec).expect("serializes")).into();
    assert_eq!(digest, expected);
}

/// THE TWO PERSISTENT FLAVORS AGREE ON THE SUBSET, as byte-identical ZKIR:
/// for a value whose FAB alignment is all `bytes<n>` atoms, `binary_repr` IS
/// the Borsh encoding (notes/borsh-format.org, finding #1). The two sides are
/// built from independent descriptions — `CircuitBorsh::push_limbs` on one,
/// `CircuitAbi::atoms` plus `CircuitArg::push_slots` on the other — so this
/// is agreement between two statements of the layout, not a tautology.
#[test]
fn the_persistent_flavors_agree_on_the_subset() {
    let borsh_flavor = ir_of(|c| {
        let record = <Record<Private> as CircuitArg>::declare(c, &ArgPath::root("record"));
        let _ = hash::persistent_hash(c, &record);
    });

    let fab_flavor = ir_of(|c| {
        let record = <Record<Private> as CircuitArg>::declare(c, &ArgPath::root("record"));
        let mut slots = Vec::new();
        record.push_slots(&mut slots);
        let slots: Vec<_> = slots.iter().map(|w| w.erase()).collect();
        let alignment = Alignment(
            <Record<Private> as CircuitAbi>::atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        let _ = hash::persistent_hash_compact(c, alignment, &slots);
    });

    assert_eq!(borsh_flavor, fab_flavor);
}

/// The Borsh transient flavor limbs the ENCODED BYTE STRING in 31-byte
/// little-endian chunks IN STRING ORDER — chunk `i` is bytes `31i..31i+31`,
/// the last one short — which a native implementation writes as
/// `borsh::to_vec(v).chunks(31)`. This is the limbing the spec publishes; it
/// is NOT FAB's, whose leftover chunk comes first.
#[test]
fn transient_hash_limbs_the_borsh_bytes_in_string_order() {
    let spec = spec_record();
    let outputs = run_record(&spec, |c, record| {
        let digest = hash::transient_hash(c, record);
        let public = c.disclose(digest, "digest");
        c.output(public, "digest");
    });

    let bytes = borsh::to_vec(&spec).expect("serializes");
    let limbs: Vec<Fr> = bytes
        .chunks(31)
        .map(|chunk| Fr::from_le_bytes(chunk).expect("<= 31 bytes fit"))
        .collect();
    assert_eq!(limbs.len(), 7, "204 bytes is six full chunks and an 18-byte tail");
    assert_eq!(outputs[0], native_transient_hash(&limbs));
}

/// THE TRANSIENT FLAVORS GENUINELY DISAGREE, and the FAB one is Poseidon over
/// the argument slots verbatim. Poseidon absorbs field elements, so the
/// preimage is a limbing and the two limbings are different: Borsh's is the
/// byte string in 31-byte chunks, FAB's is one slot per field with a byte
/// string's leftover chunk first. Choosing between them is therefore a real
/// choice, which is the reason the `_compact` spelling exists.
#[test]
fn the_transient_flavors_disagree() {
    let spec = spec_record();
    let borsh_digest = run_record(&spec, |c, record| {
        let digest = hash::transient_hash(c, record);
        let public = c.disclose(digest, "digest");
        c.output(public, "digest");
    });
    let fab_digest = run_record(&spec, |c, record| {
        let mut slots = Vec::new();
        record.push_slots(&mut slots);
        let digest = hash::transient_hash_compact(c, &slots);
        let public = c.disclose(digest, "digest");
        c.output(public, "digest");
    });

    assert_ne!(borsh_digest, fab_digest);
    assert_eq!(fab_digest[0], native_transient_hash(&record_slots(&spec)));
}
