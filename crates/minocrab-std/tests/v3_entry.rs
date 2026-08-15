//! The entry-point core must be pure type-level structure, exactly like the
//! typed leaves it builds on: a circuit written as a `CircuitArgs` struct +
//! `entry()` has to lower to the byte-identical ZKIR of the same circuit
//! written as a hand-written `c.arg` block followed by a hand-written
//! `assert_bits` block. Serialized-ZKIR equality also pins the argument
//! LABELS, which appear in the stream as `%name.index`.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Prim, Secp256k1PointT, Wire3};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_std::v3::{
    entry, entry_out, ArgPath, Bool, Bytes, BytesN, CircuitAbi, CircuitArg, CircuitArgs, Either,
    Maybe, Secp256k1Point, Uint, B32,
};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: &Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

// ---- a demo argument list, in the shape the ports use -----------------------

/// A nested struct argument — field order is the wire contract.
struct Request {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

impl CircuitAbi for Request {
    const SLOTS: usize = <Bytes<20> as CircuitAbi>::SLOTS + <Uint<128> as CircuitAbi>::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Bytes<20> as CircuitAbi>::push_atoms(atoms);
        <Uint<128> as CircuitAbi>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Bytes<20> as CircuitAbi>::push_prims(prims);
        <Uint<128> as CircuitAbi>::push_prims(prims);
    }
}

impl CircuitArg for Request {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Request {
            erc20_address: CircuitArg::declare(c, &path.field("erc20Address")),
            amount: CircuitArg::declare(c, &path.field("amount")),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.erc20_address.push_slots(slots);
        self.amount.push_slots(slots);
    }
}

struct DemoArgs {
    nonce: Uint<64>,
    flag: Bool,
    request: Request,
    id: B32<Private>,
    payload: BytesN<Private, 128>,
}

impl CircuitArgs for DemoArgs {
    const SLOTS: usize = <Uint<64> as CircuitAbi>::SLOTS
        + <Bool as CircuitAbi>::SLOTS
        + Request::SLOTS
        + <B32<Private> as CircuitAbi>::SLOTS
        + <BytesN<Private, 128> as CircuitAbi>::SLOTS;

    fn declare(c: &mut Circuit3) -> Self {
        DemoArgs {
            nonce: CircuitArg::declare(c, &ArgPath::root("nonce")),
            flag: CircuitArg::declare(c, &ArgPath::root("flag")),
            request: CircuitArg::declare(c, &ArgPath::root("request")),
            id: CircuitArg::declare(c, &ArgPath::root("id")),
            payload: CircuitArg::declare(c, &ArgPath::root("payload")),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.nonce.constrain(c);
        self.flag.constrain(c);
        self.request.constrain(c);
        self.id.constrain(c);
        self.payload.constrain(c);
    }

    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        <Uint<64> as CircuitAbi>::push_atoms(&mut atoms);
        <Bool as CircuitAbi>::push_atoms(&mut atoms);
        Request::push_atoms(&mut atoms);
        <B32<Private> as CircuitAbi>::push_atoms(&mut atoms);
        <BytesN<Private, 128> as CircuitAbi>::push_atoms(&mut atoms);
        atoms
    }
}

#[test]
fn an_argument_list_lowers_like_the_hand_written_blocks() {
    let typed = entry(|c, a: DemoArgs| {
        let sum = c.add(a.nonce.field(), a.request.amount.field());
        c.assert_bits(sum, 129);
        let gated = c.mul(a.flag.field(), a.id.hi);
        c.assert(gated);
        let e = c.add(a.request.erc20_address.field(), a.payload.limbs()[0]);
        c.assert_bits(e, 161);
    });

    let hand = {
        let mut c = Circuit3::new();
        let nonce: Wire3<FieldT, Private> = c.arg("nonce");
        let flag: Wire3<FieldT, Private> = c.arg("flag");
        let erc20: Wire3<FieldT, Private> = c.arg("request_erc20Address");
        let amount: Wire3<FieldT, Private> = c.arg("request_amount");
        let id_hi: Wire3<FieldT, Private> = c.arg("id_hi");
        let id_lo: Wire3<FieldT, Private> = c.arg("id_lo");
        let payload: Vec<Wire3<FieldT, Private>> =
            (0..5).map(|i| c.arg(&format!("payload_{i}"))).collect();
        c.assert_bits(nonce, 64);
        c.assert_boolean(flag);
        c.assert_bits(erc20, 160);
        c.assert_bits(amount, 128);
        c.assert_bits(id_hi, 8);
        c.assert_bits(id_lo, 248);
        c.assert_bits(payload[0], 32);
        for limb in &payload[1..] {
            c.assert_bits(*limb, 248);
        }

        let sum = c.add(nonce, amount);
        c.assert_bits(sum, 129);
        let gated = c.mul(flag, id_hi);
        c.assert(gated);
        let e = c.add(erc20, payload[0]);
        c.assert_bits(e, 161);
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&typed));
}

#[test]
fn arg_paths_join_segments_with_underscores() {
    let root = ArgPath::root("depositRequest");
    assert_eq!(root.as_str(), "depositRequest");
    assert_eq!(root.field("erc20Address").as_str(), "depositRequest_erc20Address");
    assert_eq!(root.suffix("hi").as_str(), "depositRequest_hi");
    assert_eq!(root.field("payload").index(3).as_str(), "depositRequest_payload_3");
}

#[test]
fn atoms_describe_exactly_the_declared_slots() {
    let bytes = |length| AlignmentAtom::Bytes { length };
    assert_eq!(
        DemoArgs::atoms(),
        vec![
            bytes(8),  // nonce: Uint<64>
            bytes(1),  // flag: Boolean
            bytes(20), // request.erc20Address: Bytes<20>
            bytes(16), // request.amount: Uint<128>
            bytes(32), // id: Bytes<32>
            bytes(128) // payload: Bytes<128>
        ]
    );
    // Atoms are per Compact value, slots are per native wire.
    assert_eq!(DemoArgs::SLOTS, 11);
}

// ---- arrays, Maybe and Either -----------------------------------------------

/// The shapes `claim` needs: an indexed vector, and a `Maybe` of an
/// `Either`, where every arm occupies its slots whichever way the tags
/// point.
struct ShapeArgs {
    words: [Uint<64>; 3],
    recipient: Maybe<Either<B32<Private>, Bytes<20>>>,
}

type Recipient = Maybe<Either<B32<Private>, Bytes<20>>>;

impl CircuitArgs for ShapeArgs {
    const SLOTS: usize = <[Uint<64>; 3] as CircuitAbi>::SLOTS + <Recipient as CircuitAbi>::SLOTS;

    fn declare(c: &mut Circuit3) -> Self {
        ShapeArgs {
            words: CircuitArg::declare(c, &ArgPath::root("words")),
            recipient: CircuitArg::declare(c, &ArgPath::root("recipient")),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.words.constrain(c);
        self.recipient.constrain(c);
    }

    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        <[Uint<64>; 3] as CircuitAbi>::push_atoms(&mut atoms);
        <Recipient as CircuitAbi>::push_atoms(&mut atoms);
        atoms
    }
}

#[test]
fn arrays_maybe_and_either_flatten_like_the_hand_written_block() {
    let typed = entry(|c, a: ShapeArgs| {
        let sum = c.add(a.words[0].field(), a.words[2].field());
        c.assert_bits(sum, 65);
        let tag = c.mul(a.recipient.is_some.field(), a.recipient.value.is_left.field());
        c.assert(tag);
        let arm = c.add(a.recipient.value.left.lo, a.recipient.value.right.field());
        c.assert_bits(arm, 249);
    });

    let hand = {
        let mut c = Circuit3::new();
        let words: Vec<Wire3<FieldT, Private>> =
            (0..3).map(|i| c.arg(&format!("words_{i}"))).collect();
        let is_some: Wire3<FieldT, Private> = c.arg("recipient_is_some");
        let is_left: Wire3<FieldT, Private> = c.arg("recipient_is_left");
        let left_hi: Wire3<FieldT, Private> = c.arg("recipient_left_hi");
        let left_lo: Wire3<FieldT, Private> = c.arg("recipient_left_lo");
        let right: Wire3<FieldT, Private> = c.arg("recipient_right");
        for word in &words {
            c.assert_bits(*word, 64);
        }
        c.assert_boolean(is_some);
        c.assert_boolean(is_left);
        c.assert_bits(left_hi, 8);
        c.assert_bits(left_lo, 248);
        c.assert_bits(right, 160);

        let sum = c.add(words[0], words[2]);
        c.assert_bits(sum, 65);
        let tag = c.mul(is_some, is_left);
        c.assert(tag);
        let arm = c.add(left_lo, right);
        c.assert_bits(arm, 249);
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&typed));
}

#[test]
fn a_tag_costs_a_slot_and_every_arm_costs_its_own() {
    let bytes = |length| AlignmentAtom::Bytes { length };
    assert_eq!(
        ShapeArgs::atoms(),
        vec![
            bytes(8),  // words: Vector<3, Uint<64>>
            bytes(8),
            bytes(8),
            bytes(1),  // recipient.is_some
            bytes(1),  // recipient.value.is_left
            bytes(32), // recipient.value.left: Bytes<32>
            bytes(20), // recipient.value.right: Bytes<20>
        ]
    );
    assert_eq!(<ShapeArgs as CircuitArgs>::SLOTS, 8);
}

// ---- the one slot that is not a field element -------------------------------

/// `initialise(responseKey: Secp256k1Point)` shaped: a point slot in the
/// middle of ordinary ones, so the test pins its POSITION as well as its
/// (absent) constraint.
struct PointArgs {
    chain_id: Uint<64>,
    response_key: Secp256k1Point,
    tag: B32<Private>,
}

impl CircuitArgs for PointArgs {
    const SLOTS: usize = <Uint<64> as CircuitAbi>::SLOTS
        + <Secp256k1Point as CircuitAbi>::SLOTS
        + <B32<Private> as CircuitAbi>::SLOTS;

    fn declare(c: &mut Circuit3) -> Self {
        PointArgs {
            chain_id: CircuitArg::declare(c, &ArgPath::root("chainId")),
            response_key: CircuitArg::declare(c, &ArgPath::root("responseKey")),
            tag: CircuitArg::declare(c, &ArgPath::root("tag")),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.chain_id.constrain(c);
        self.response_key.constrain(c);
        self.tag.constrain(c);
    }

    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        <Uint<64> as CircuitAbi>::push_atoms(&mut atoms);
        <Secp256k1Point as CircuitAbi>::push_atoms(&mut atoms);
        <B32<Private> as CircuitAbi>::push_atoms(&mut atoms);
        atoms
    }
}

#[test]
fn a_point_argument_takes_a_slot_and_no_constraint() {
    let typed = entry(|c, a: PointArgs| {
        let pk = c.disclose(a.response_key.point(), "the key");
        let limbs = c.encode(pk);
        let sum = c.add(a.chain_id.field(), a.tag.lo);
        c.assert_bits(sum, 249);
        c.output(limbs[0], "x");
    });

    let hand = {
        let mut c = Circuit3::new();
        let chain_id: Wire3<FieldT, Private> = c.arg("chainId");
        let response_key = c.arg::<Secp256k1PointT>("responseKey");
        let tag_hi: Wire3<FieldT, Private> = c.arg("tag_hi");
        let tag_lo: Wire3<FieldT, Private> = c.arg("tag_lo");
        c.assert_bits(chain_id, 64);
        // nothing for the point: `(tpoint …)` carries no constraint
        c.assert_bits(tag_hi, 8);
        c.assert_bits(tag_lo, 248);

        let pk = c.disclose(response_key, "the key");
        let limbs = c.encode(pk);
        let sum = c.add(chain_id, tag_lo);
        c.assert_bits(sum, 249);
        c.output(limbs[0], "x");
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&typed));
}

#[test]
fn a_point_is_one_slot_and_five_atoms() {
    let bytes = |length| AlignmentAtom::Bytes { length };
    assert_eq!(
        PointArgs::atoms(),
        vec![
            bytes(8),              // chainId: Uint<64>
            bytes(24),             // responseKey.x, low
            bytes(8),              // responseKey.x, high
            bytes(24),             // responseKey.y, low
            bytes(8),              // responseKey.y, high
            AlignmentAtom::Field,  // responseKey's infinity flag
            bytes(32),             // tag: Bytes<32>
        ]
    );
    assert_eq!(<PointArgs as CircuitArgs>::SLOTS, 4);
    assert_eq!(<Secp256k1Point as CircuitAbi>::prims(), vec![Prim::Point]);
}

// ---- the laws entry() enforces ---------------------------------------------

struct WrongSlots(Uint<64>);

impl CircuitArgs for WrongSlots {
    const SLOTS: usize = 2; // lie: one slot is declared

    fn declare(c: &mut Circuit3) -> Self {
        WrongSlots(CircuitArg::declare(c, &ArgPath::root("x")))
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.0.constrain(c);
    }

    fn atoms() -> Vec<AlignmentAtom> {
        <Uint<64> as CircuitAbi>::atoms()
    }
}

#[test]
#[should_panic(expected = "declare touched 1 argument slots, but SLOTS says 2")]
fn a_slot_miscount_is_caught() {
    entry(|_c, _a: WrongSlots| {});
}

struct DeclaresAnInstruction(Uint<64>);

impl CircuitArgs for DeclaresAnInstruction {
    const SLOTS: usize = 1;

    fn declare(c: &mut Circuit3) -> Self {
        let x: Uint<64> = CircuitArg::declare(c, &ArgPath::root("x"));
        c.constant(1u64); // forbidden: declaration may not compute
        DeclaresAnInstruction(x)
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.0.constrain(c);
    }

    fn atoms() -> Vec<AlignmentAtom> {
        <Uint<64> as CircuitAbi>::atoms()
    }
}

#[test]
#[should_panic(expected = "declaration may only call Circuit3::arg")]
fn computing_during_declaration_is_caught() {
    entry(|_c, _a: DeclaresAnInstruction| {});
}

// ---- outputs ----------------------------------------------------------------

#[test]
fn outputs_are_queued_in_wire_order_with_the_hand_written_labels() {
    let typed = entry_out("event hash", |c, _a: ()| {
        let hi = c.constant(1u64);
        let lo = c.constant(2u64);
        B32::<Public> { hi, lo }
    });

    let hand = {
        let mut c = Circuit3::new();
        let hi = c.constant(1u64);
        let lo = c.constant(2u64);
        c.output(hi, "event hash (hi)");
        c.output(lo, "event hash (lo)");
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&typed));
    let labels: Vec<&str> = typed.disclosures.iter().map(|d| d.label.as_str()).collect();
    assert_eq!(labels, ["event hash (hi)", "event hash (lo)"]);
}
