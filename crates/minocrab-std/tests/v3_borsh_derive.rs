//! `#[derive(CircuitBorsh)]` must be exactly the impls stage 1 wrote by
//! hand — and the gate is not a token comparison but SERIALIZED ZKIR:
//! every circuit the derived type can build (the hash preimage, the packed
//! bytes, the canonicity constraints, both reader modes) is compared
//! byte-for-byte against the same circuit over a hand-written twin.
//!
//! `tests/v3_borsh.rs` proves the hand-written impls are Borsh; this file
//! proves the derive is those impls. Together they say the derive emits
//! canonical Borsh.

use minocrab::v3::{Circuit3, FieldT, Prim, Wire3};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_std::v3::borsh::{
    limbs_of, read_split, read_witness_checked, to_bytes, BorshReader, CircuitBorsh,
    CircuitBorshArg, FieldSpec, Flagged, LayoutPath, Limbs, Tag,
};
use minocrab_std::v3::{
    ArgPath, Bool, Bytes, BytesN, CircuitAbi, CircuitArg, Serializer, Uint, Vis3, B32,
};
use minocrab_zkir::v3::to_zkir_string;

// ---- the same record, twice ------------------------------------------------------

/// The derived declaration — one derive, both families.
#[derive(CircuitBorsh)]
struct Derived<V: Vis3> {
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

/// The hand-written twin, field for field.
struct Hand<V: Vis3> {
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

impl<V: Vis3> CircuitAbi for Hand<V>
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

impl CircuitArg for Hand<Private> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Hand {
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

impl<V: Vis3> CircuitBorsh<V> for Hand<V> {
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
        Hand {
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

// ---- the gate: byte-identical ZKIR -------------------------------------------------

fn ir_of(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(false).ir).expect("IR serializes")
}

/// Both encoders, both reader modes and the canonicity constraints, each
/// built twice and compared as serialized ZKIR — which pins the ARGUMENT
/// LABELS too, since `Builder3` names every value `%label.index`.
#[test]
fn the_derive_is_the_hand_written_impl() {
    macro_rules! both {
        ($what:literal, |$c:ident, $record:ident| $body:expr) => {{
            let derived = ir_of(|$c| {
                let $record =
                    <Derived<Private> as CircuitArg>::declare($c, &ArgPath::root("record"));
                $record.constrain($c);
                $body;
            });
            let hand = ir_of(|$c| {
                let $record = <Hand<Private> as CircuitArg>::declare($c, &ArgPath::root("record"));
                $record.constrain($c);
                $body;
            });
            assert_eq!(derived, hand, "{} differs", $what);
        }};
    }

    both!("the hash preimage", |c, record| {
        let _ = limbs_of(&record).keccak256(c);
    });
    both!("the packed bytes", |c, record| {
        let _ = to_bytes::<204, _, _>(c, &record);
    });
    both!("the canonicity constraints", |c, record| {
        record.constrain_canonical(c);
    });
    both!("a Split read", |c, record| {
        let packed = to_bytes::<204, _, _>(c, &record);
        let _: Derived<Private> = read_split(c, &packed);
    });
    both!("a WitnessCheck read", |c, record| {
        let packed = to_bytes::<204, _, _>(c, &record);
        let _: Derived<Private> = read_witness_checked(c, &packed);
    });
}

/// The public serialization path too: a visibility-generic derive serializes
/// at `Public`, which is what a log payload needs.
#[test]
fn the_derive_serializes_at_public_visibility_as_well() {
    fn build<V: Vis3, T: CircuitBorsh<V>>(c: &mut Circuit3, record: &T) {
        let _ = limbs_of(record).keccak256(c);
        let _ = to_bytes::<204, V, T>(c, record);
    }

    let derived = ir_of(|c| {
        let record = public_derived(c);
        build(c, &record);
    });
    let hand = ir_of(|c| {
        let record = public_hand(c);
        build(c, &record);
    });
    assert_eq!(derived, hand);
}

/// A public record of constants — the shape a log payload has.
fn public_derived(c: &mut Circuit3) -> Derived<Public> {
    Derived {
        version: Uint::constant(c, 7),
        flag: Bool::constant(c, true),
        kind: Tag::constant(c, 3),
        amount: Uint::constant(c, 11),
        addr: Bytes::constant(c, &[9u8; 20]),
        id: B32::pad(c, "id"),
        payload: BytesN::literal(c, &[5u8; 64]),
        words: [B32::pad(c, "w0"), B32::pad(c, "w1")],
        calldata: Flagged {
            is_some: Bool::constant(c, false),
            value: Uint::constant(c, 0),
        },
    }
}

fn public_hand(c: &mut Circuit3) -> Hand<Public> {
    Hand {
        version: Uint::constant(c, 7),
        flag: Bool::constant(c, true),
        kind: Tag::constant(c, 3),
        amount: Uint::constant(c, 11),
        addr: Bytes::constant(c, &[9u8; 20]),
        id: B32::pad(c, "id"),
        payload: BytesN::literal(c, &[5u8; 64]),
        words: [B32::pad(c, "w0"), B32::pad(c, "w1")],
        calldata: Flagged {
            is_some: Bool::constant(c, false),
            value: Uint::constant(c, 0),
        },
    }
}

/// The constants and the layout table: `LEN`, the slot count, the atoms and
/// the published offset rows are the hand-written ones.
#[test]
fn the_derived_constants_and_layout_are_the_hand_written_ones() {
    assert_eq!(
        <Derived<Private> as CircuitBorsh<Private>>::LEN,
        <Hand<Private> as CircuitBorsh<Private>>::LEN
    );
    assert_eq!(
        <Derived<Private> as CircuitAbi>::SLOTS,
        <Hand<Private> as CircuitAbi>::SLOTS
    );
    assert_eq!(
        <Derived<Private> as CircuitAbi>::atoms(),
        <Hand<Private> as CircuitAbi>::atoms()
    );
    assert_eq!(
        <Derived<Private> as CircuitBorsh<Private>>::layout(),
        <Hand<Private> as CircuitBorsh<Private>>::layout()
    );

    // …and the layout paths are the field names verbatim, dot-joined — the
    // SPEC type's paths, not the camelCase argument labels.
    let rows = <Derived<Private> as CircuitBorsh<Private>>::layout();
    let paths: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "version",
            "flag",
            "kind",
            "amount",
            "addr",
            "id",
            "payload",
            "words[0]",
            "words[1]",
            "calldata.is_some",
            "calldata.value",
        ]
    );
}

/// A derived struct is a circuit argument AND Borsh-serializable — the "one
/// derive yields both" claim, as a compile-time fact.
#[test]
fn a_derived_record_is_an_argument_and_borsh() {
    fn assert_both<T: CircuitBorshArg>() {}
    assert_both::<Derived<Private>>();
}

/// A plain (non-generic) struct derives too, at `Private`, and nests inside
/// another derived record like any leaf.
#[derive(CircuitBorsh)]
struct Inner {
    #[arg(name = "lo")]
    low: Uint<64, Private>,
    high: Uint<64, Private>,
}

#[derive(CircuitBorsh)]
struct Outer {
    #[borsh(name = "renamed")]
    inner: Inner,
    tail: Bool<Private>,
}

#[test]
fn a_plain_struct_derives_and_nests() {
    assert_eq!(<Outer as CircuitBorsh<Private>>::LEN, 8 + 8 + 1);
    let rows = <Outer as CircuitBorsh<Private>>::layout();
    let paths: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths, vec!["renamed.low", "renamed.high", "tail"]);

    // The argument labels keep their own namespace and their own override.
    let ir = ir_of(|c| {
        let outer = <Outer as CircuitArg>::declare(c, &ArgPath::root("outer"));
        outer.constrain(c);
    });
    let hand = ir_of(|c| {
        let lo: Wire3<FieldT, Private> = c.arg("outer_inner_lo");
        let hi: Wire3<FieldT, Private> = c.arg("outer_inner_high");
        let tail: Wire3<FieldT, Private> = c.arg("outer_tail");
        c.assert_bits(lo, 64);
        c.assert_bits(hi, 64);
        c.assert_boolean(tail);
    });
    assert_eq!(ir, hand);
}
