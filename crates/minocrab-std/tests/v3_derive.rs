//! `#[derive(CircuitArg)]` must generate exactly the impls phase 2 wrote by
//! hand — so the gate is the same one the core itself passes: a circuit
//! whose arguments are a derived struct has to lower to byte-identical ZKIR
//! against the same circuit written over a hand-written impl. Serialized
//! ZKIR pins the argument LABELS too (`%name.index`), so the camelCase rule
//! and the `#[arg(name = "…")]` override are checked by the same equality.

use minocrab::v3::{Circuit3, Compiled3, FieldT};
use minocrab::{AlignmentAtom, Private};
use minocrab_std::v3::{entry, ArgPath, Bool, Bytes, BytesN, CircuitArg, CircuitArgs, Uint, B32};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: &Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

// ---- the derived argument list ----------------------------------------------

#[derive(CircuitArg)]
struct DerivedRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

#[derive(CircuitArg)]
struct DerivedArgs {
    evm_nonce: Uint<64>,
    flag: Bool,
    deposit_request: DerivedRequest,
    #[arg(name = "respond")]
    respond_bidirectional_event: B32<Private>,
    payload: BytesN<Private, 128>,
}

// ---- the same list, hand-written (phase 2's shape) ---------------------------

struct HandRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

impl CircuitArg for HandRequest {
    const SLOTS: usize = <Bytes<20> as CircuitArg>::SLOTS + <Uint<128> as CircuitArg>::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Bytes<20> as CircuitArg>::push_atoms(atoms);
        <Uint<128> as CircuitArg>::push_atoms(atoms);
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        HandRequest {
            erc20_address: CircuitArg::declare(c, &path.field("erc20Address")),
            amount: CircuitArg::declare(c, &path.field("amount")),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.erc20_address.constrain(c);
        self.amount.constrain(c);
    }
}

struct HandArgs {
    evm_nonce: Uint<64>,
    flag: Bool,
    deposit_request: HandRequest,
    respond_bidirectional_event: B32<Private>,
    payload: BytesN<Private, 128>,
}

impl CircuitArgs for HandArgs {
    const SLOTS: usize = <Uint<64> as CircuitArg>::SLOTS
        + <Bool as CircuitArg>::SLOTS
        + HandRequest::SLOTS
        + <B32<Private> as CircuitArg>::SLOTS
        + <BytesN<Private, 128> as CircuitArg>::SLOTS;

    fn declare(c: &mut Circuit3) -> Self {
        HandArgs {
            evm_nonce: CircuitArg::declare(c, &ArgPath::root("evmNonce")),
            flag: CircuitArg::declare(c, &ArgPath::root("flag")),
            deposit_request: CircuitArg::declare(c, &ArgPath::root("depositRequest")),
            respond_bidirectional_event: CircuitArg::declare(c, &ArgPath::root("respond")),
            payload: CircuitArg::declare(c, &ArgPath::root("payload")),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.evm_nonce.constrain(c);
        self.flag.constrain(c);
        self.deposit_request.constrain(c);
        self.respond_bidirectional_event.constrain(c);
        self.payload.constrain(c);
    }

    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        <Uint<64> as CircuitArg>::push_atoms(&mut atoms);
        <Bool as CircuitArg>::push_atoms(&mut atoms);
        HandRequest::push_atoms(&mut atoms);
        <B32<Private> as CircuitArg>::push_atoms(&mut atoms);
        <BytesN<Private, 128> as CircuitArg>::push_atoms(&mut atoms);
        atoms
    }
}

#[test]
fn a_derived_argument_list_lowers_like_the_hand_written_impl() {
    let derived = entry(|c, a: DerivedArgs| {
        let sum = c.add(a.evm_nonce.field(), a.deposit_request.amount.field());
        c.assert_bits(sum, 129);
        let gated = c.mul(a.flag.field(), a.respond_bidirectional_event.hi);
        c.assert(gated);
        let e = c.add(a.deposit_request.erc20_address.field(), a.payload.limbs()[0]);
        c.assert_bits(e, 161);
    });

    let hand = entry(|c, a: HandArgs| {
        let sum = c.add(a.evm_nonce.field(), a.deposit_request.amount.field());
        c.assert_bits(sum, 129);
        let gated = c.mul(a.flag.field(), a.respond_bidirectional_event.hi);
        c.assert(gated);
        let e = c.add(a.deposit_request.erc20_address.field(), a.payload.limbs()[0]);
        c.assert_bits(e, 161);
    });

    assert_eq!(zkir(&hand), zkir(&derived));
}

#[test]
fn the_derived_schema_matches_the_hand_written_one() {
    assert_eq!(
        <DerivedArgs as CircuitArgs>::SLOTS,
        <HandArgs as CircuitArgs>::SLOTS
    );
    assert_eq!(
        <DerivedArgs as CircuitArgs>::atoms(),
        <HandArgs as CircuitArgs>::atoms()
    );
}

/// The labels themselves, spelled out against a raw `c.arg` block: the
/// mechanical camelCase rule, the `_`-joined nested path, and the
/// `#[arg(name = "respond")]` override.
#[test]
fn the_derived_labels_are_the_camel_cased_field_paths() {
    let derived = entry(|c, a: DerivedArgs| {
        let x = c.add(a.evm_nonce.field(), a.flag.field());
        c.assert_bits(x, 65);
    });

    let hand = {
        let mut c = Circuit3::new();
        let evm_nonce = c.arg::<FieldT>("evmNonce");
        let flag = c.arg::<FieldT>("flag");
        let erc20 = c.arg::<FieldT>("depositRequest_erc20Address");
        let amount = c.arg::<FieldT>("depositRequest_amount");
        let respond_hi = c.arg::<FieldT>("respond_hi");
        let respond_lo = c.arg::<FieldT>("respond_lo");
        let payload: Vec<_> = (0..5)
            .map(|i| c.arg::<FieldT>(&format!("payload_{i}")))
            .collect();
        c.assert_bits(evm_nonce, 64);
        c.assert_boolean(flag);
        c.assert_bits(erc20, 160);
        c.assert_bits(amount, 128);
        c.assert_bits(respond_hi, 8);
        c.assert_bits(respond_lo, 248);
        c.assert_bits(payload[0], 32);
        for limb in &payload[1..] {
            c.assert_bits(*limb, 248);
        }
        let x = c.add(evm_nonce, flag);
        c.assert_bits(x, 65);
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&derived));
}

/// A derived struct is usable both ways: as a whole argument list (fields at
/// the root) and as one argument nested under a path.
#[test]
fn a_derived_struct_is_also_an_argument_list() {
    let root = entry(|c, a: DerivedRequest| {
        let x = c.add(a.erc20_address.field(), a.amount.field());
        c.assert_bits(x, 161);
    });

    let hand = {
        let mut c = Circuit3::new();
        let erc20 = c.arg::<FieldT>("erc20Address");
        let amount = c.arg::<FieldT>("amount");
        c.assert_bits(erc20, 160);
        c.assert_bits(amount, 128);
        let x = c.add(erc20, amount);
        c.assert_bits(x, 161);
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&root));
    assert_eq!(<DerivedRequest as CircuitArg>::SLOTS, 2);
}
