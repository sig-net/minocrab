//! THE GATE FOR THE WHOLE QUESTION (notes/disclosure-model.org): a value
//! disclosed on the public ledger by `disclosure::disclose_to` is recovered by
//! the recipient's secret key — in NATIVE Rust, with no circuit, no proof and
//! no transaction — and is NOT recovered by anyone else's.
//!
//! The native half is the point. If decryption needed a circuit the claim
//! would be much weaker: "the recipient can see it" would mean "the recipient
//! can prove something about it", which is not what a DAML stakeholder gets.
//! What a wallet actually runs is `wallet_decrypt` below: one scalar
//! multiplication and two SHA-256s over a ledger read. It is written against
//! Midnight's own off-circuit helpers (`ec_mul_offcircuit`,
//! `encode_offcircuit`, the FAB `binary_repr`) — the same ones the simulator's
//! interpreter calls — so if the circuit's KDF and this one ever disagree, one
//! of them is wrong about Midnight rather than about each other.
//!
//! The contract side runs on the on-chain VM through the executor
//! (`minocrab_sim::v3::exec`), so the registry lookup reads real state and the
//! memo lands in a real post-state.

use group::Group;
use midnight_base_crypto::fab::{
    AlignedValue, Alignment as FabAlignment, AlignmentAtom as FabAtom,
    AlignmentSegment as FabSegment, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::{Fr as JubjubFr, JubjubSubgroup};
use midnight_onchain_state::state::StateValue;
use midnight_storage::db::InMemoryDB;
use midnight_storage::arena::Sp;
use midnight_storage::storage::Array;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::{encode_offcircuit, native_to_jubjub_scalar};
use minocrab::v3::{Compiled3, DisclosedWire};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr};
use minocrab_contracts::disclosure::{self, Disclosure};
use minocrab_sim::v3::exec::{self, Call, ExecError, Executed};
use minocrab_sim::v3::{cost, Run3};
use minocrab_zkir::v3::{IrType, IrValue};
use sha2::{Digest, Sha256};

// ---- the recipient's side, natively -----------------------------------------------

/// A recipient keypair: the secret scalar `ek` and `pk = g^ek`.
///
/// `ek` is derived the way the contract derives its ephemeral scalar — through
/// `native_to_jubjub_scalar`, the reduction `jubjub_scalar_from_native` lowers
/// to — so a seed means the same scalar on both sides.
fn keypair(seed: u64) -> (JubjubFr, JubjubSubgroup) {
    let ek = native_to_jubjub_scalar(&Fr::from(seed));
    (ek, JubjubSubgroup::generator() * ek)
}

/// The witness `register` wants for a key from [`keypair`]: the NATIVE field
/// element, before the reduction. The circuit applies
/// `jubjub_scalar_from_native` itself, exactly as `keypair` does, so the two
/// sides agree on which scalar a seed means.
fn ek_witness(seed: u64) -> Fr {
    Fr::from(seed)
}

/// `encode(point)` off-circuit: the two field limbs the ledger stores.
fn encode_point(p: JubjubSubgroup) -> [Fr; 2] {
    let limbs = encode_offcircuit(&IrValue::JubjubPoint(p));
    let mut out = [Fr::from(0u64); 2];
    assert_eq!(limbs.len(), 2, "a Jubjub point encodes to two field limbs");
    for (slot, limb) in out.iter_mut().zip(limbs) {
        let IrValue::Native(fr) = limb else {
            panic!("encode of a point yields native limbs, got {limb:?}");
        };
        *slot = fr;
    }
    out
}

/// `persistentHash` over a FAB-aligned preimage: `Sha256(binary_repr)`, which
/// is what the ZKIR `persistent_hash` instruction computes
/// (`minocrab_sim::v3`, the `I::PersistentHash` arm).
fn persistent_hash(alignment: &Alignment, slots: &[Fr]) -> [u8; 32] {
    let value = alignment
        .parse_field_repr(slots)
        .expect("the slots match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

/// A `Bytes<32>`'s FAB slots: the leftover (most significant) chunk first —
/// `B32`'s `hi` (byte 31), then `lo` (bytes 0..30 little-endian).
fn b32_slots(bytes: &[u8; 32]) -> [Fr; 2] {
    [
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit a field element"),
    ]
}

fn point_alignment() -> Alignment {
    Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Field),
        AlignmentSegment::Atom(AlignmentAtom::Field),
    ])
}

fn two_b32_alignment() -> Alignment {
    Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ])
}

/// `disclosure::kdf`, natively.
fn kdf(shared: JubjubSubgroup) -> Fr {
    let point_hash = persistent_hash(&point_alignment(), &encode_point(shared));
    let domain = disclosure::domain_fr();
    let mixed = persistent_hash(
        &two_b32_alignment(),
        &[
            b32_slots(&point_hash)[0],
            b32_slots(&point_hash)[1],
            domain.0,
            domain.1,
        ],
    );
    // degradeToTransient: the low 31 bytes.
    Fr::from_le_bytes(&mixed[..31]).expect("31 bytes fit a field element")
}

/// THE WALLET. Given a memo off the ledger and the recipient's secret scalar,
/// recover the disclosed value. No circuit, no proof, no transaction.
fn wallet_decrypt(memo: &[Fr; 3], ek: JubjubFr) -> Fr {
    let ephemeral = decode_point([memo[0], memo[1]]);
    let IrValue::JubjubPoint(shared) =
        ec_mul_offcircuit(&IrValue::JubjubPoint(ephemeral), &IrValue::JubjubScalar(ek))
            .expect("point times scalar")
    else {
        panic!("a Jubjub multiplication yields a Jubjub point");
    };
    memo[2] - kdf(shared)
}

/// The inverse of [`encode_point`] — available OFF-circuit only, which is
/// exactly why the ledger stores limbs rather than a typed point (see
/// `disclosure`'s module docs).
fn decode_point(limbs: [Fr; 2]) -> JubjubSubgroup {
    let IrValue::JubjubPoint(p) =
        midnight_zkir_v3::ir_instructions::encode::decode_offcircuit(&limbs, &IrType::JubjubPoint)
            .expect("the limbs are a subgroup point")
    else {
        panic!("decoding at JubjubPoint yields a point");
    };
    p
}

// ---- driving the contract ---------------------------------------------------------

/// A `u64` ledger cell, as a `Bytes<8>`-aligned value.
fn u64_cell(v: u64) -> StateValue<InMemoryDB> {
    StateValue::Cell(Sp::new(
        AlignedValue::new(
            Value(vec![ValueAtom(v.to_le_bytes().to_vec()).normalize()]),
            FabAlignment(vec![FabSegment::Atom(FabAtom::Bytes { length: 8 })]),
        )
        .expect("a u64 fits"),
    ))
}

/// The empty ledger block: field 0 the key registry, field 1 the memo list.
///
/// A `List<T>` is `Array[3] = {head, tail, length}` (notes/ledger-adts.org), so
/// the empty one is two nulls and a zero — NOT `Null`, which is what the first
/// attempt wrote and what `pushFront`'s `idx [2]` for the length then refused
/// with "tried to idx, only map, array, and bmt are supported".
fn empty_state() -> StateValue<InMemoryDB> {
    StateValue::Array(Array::from(vec![
        StateValue::Map(Default::default()),
        StateValue::Array(Array::from(vec![
            StateValue::Null,
            StateValue::Null,
            u64_cell(0),
        ])),
    ]))
}

fn run(
    compiled: &Compiled3,
    st: StateValue<InMemoryDB>,
    inputs: &[Fr],
) -> Result<Executed, ExecError> {
    run_wit(compiled, st, inputs, &[])
}

/// [`run`] with a private transcript. `register` witnesses the native scalar
/// behind the key it publishes, so its proof of possession needs one.
fn run_wit(
    compiled: &Compiled3,
    st: StateValue<InMemoryDB>,
    inputs: &[Fr],
    wit: &[Fr],
) -> Result<Executed, ExecError> {
    let ctx = exec::context(st, [7u8; 32]);
    exec::execute(
        &compiled.ir,
        &Call::new(inputs, wit).with_comm_rand(Fr::from(5u64)),
        &ctx,
    )
}

/// The field wires a declared disclosure carried in this run, by label — the
/// memo as the circuit computed it, addressed the way the eDSL addresses it.
///
/// EVERY record with the label, concatenated in order, not just the first:
/// `PointLimbs::disclose_as` discloses its two limbs as two separate
/// `disclose` instructions under one label (that is what "one label for both
/// limbs" means in the `label!` block), so the ephemeral key is two records of
/// one wire rather than one record of two.
fn disclosed(compiled: &Compiled3, run: &Run3, label: &str) -> Vec<Fr> {
    let matching: Vec<_> = compiled
        .disclosures
        .iter()
        .filter(|d| d.label == label)
        .collect();
    assert!(
        !matching.is_empty(),
        "no disclosure labelled {label:?}; have {:?}",
        compiled.disclosures.iter().map(|d| &d.label).collect::<Vec<_>>()
    );
    matching
        .iter()
        .flat_map(|d| d.values.iter())
        .map(|w| match w {
            DisclosedWire::Named(id) => match run.memory.get(id).expect("the run computed it") {
                IrValue::Native(fr) => *fr,
                other => panic!("{label}: not a field wire: {other:?}"),
            },
            DisclosedWire::Constant(imm) => *imm,
        })
        .collect()
}

/// `(account_hi, account_lo)` for a 32-byte account id — `B32`'s argument
/// order (hi first).
fn account_slots(id: &[u8; 32]) -> [Fr; 2] {
    [
        Fr::from(u64::from(id[31])),
        Fr::from_le_bytes(&id[..31]).expect("31 bytes fit"),
    ]
}

const ALICE: [u8; 32] = [0xa1; 32];

/// Register Alice's key, then disclose `value` to her. Returns the memo as the
/// ledger holds it.
fn disclose(value: u128, pk: JubjubSubgroup, ek_native: Fr, seed: &[u8; 32]) -> [Fr; 3] {
    let register = Disclosure::register();
    let acct = account_slots(&ALICE);
    let pk_limbs = encode_point(pk);
    let registered = run_wit(
        &register,
        empty_state(),
        &[acct[0], acct[1], pk_limbs[0], pk_limbs[1]],
        &[ek_native],
    )
    .expect("registration applies");

    let disclose_to = Disclosure::disclose_to();
    let seed = account_slots(seed);
    let out = run(
        &disclose_to,
        registered.post,
        &[
            acct[0],
            acct[1],
            pk_limbs[0],
            pk_limbs[1],
            Fr::from(value),
            seed[0],
            seed[1],
        ],
    )
    .expect("the disclosure applies");

    let eph = disclosed(&disclose_to, &out.run, "ephemeral key");
    let ct = disclosed(&disclose_to, &out.run, "masked value");
    assert_eq!(eph.len(), 2, "the ephemeral key is two limbs");
    assert_eq!(ct.len(), 1, "the masked value is one limb");
    [eph[0], eph[1], ct[0]]
}

// ---- the gates --------------------------------------------------------------------

/// THE CLAIM: the recipient, and only the recipient, reads the value.
#[test]
fn the_recipient_recovers_the_value_and_nobody_else_does() {
    let (ek, pk) = keypair(42);
    let (eve_ek, _eve_pk) = keypair(43);

    for value in [0u128, 1, 1_000_000, u128::MAX] {
        let memo = disclose(value, pk, ek_witness(42), &[0x5e; 32]);
        assert_eq!(
            wallet_decrypt(&memo, ek),
            Fr::from(value),
            "the recipient recovers {value}"
        );
        assert_ne!(
            wallet_decrypt(&memo, eve_ek),
            Fr::from(value),
            "a different key does not recover {value}"
        );
    }
}

/// The ciphertext alone says nothing: the same value under two seeds is two
/// unrelated memos. (A one-time pad reused would make these equal, which is
/// the failure `ephemeral_scalar`'s freshness note is about.)
#[test]
fn two_disclosures_of_the_same_value_share_nothing() {
    let (ek, pk) = keypair(42);
    let a = disclose(7_777, pk, ek_witness(42), &[0x01; 32]);
    let b = disclose(7_777, pk, ek_witness(42), &[0x02; 32]);
    assert_ne!(a[0..2], b[0..2], "distinct ephemeral keys");
    assert_ne!(a[2], b[2], "distinct ciphertexts");
    assert_eq!(wallet_decrypt(&a, ek), Fr::from(7_777u64));
    assert_eq!(wallet_decrypt(&b, ek), Fr::from(7_777u64));
}

/// The binding: a sender cannot address a memo to a key of their own choosing
/// and have it counted as a disclosure to Alice. The circuit asserts the
/// supplied point against the registry limb for limb.
#[test]
fn a_memo_cannot_be_addressed_to_an_unregistered_key() {
    let (_ek, pk) = keypair(42);
    let (_mallory_ek, mallory_pk) = keypair(99);

    let register = Disclosure::register();
    let acct = account_slots(&ALICE);
    let alice = encode_point(pk);
    let registered = run_wit(
        &register,
        empty_state(),
        &[acct[0], acct[1], alice[0], alice[1]],
        &[ek_witness(42)],
    )
    .expect("registration applies");

    let mallory = encode_point(mallory_pk);
    let seed = account_slots(&[0x5e; 32]);
    let err = run(
        &Disclosure::disclose_to(),
        registered.post,
        &[
            acct[0],
            acct[1],
            mallory[0],
            mallory[1],
            Fr::from(1u64),
            seed[0],
            seed[1],
        ],
    )
    .expect_err("the registry binding refuses it");
    let shown = format!("{err}");
    assert!(
        shown.contains("Equality constraint failed"),
        "expected the registry binding's constrain_eq to fail, got {shown}"
    );
}

/// PROOF OF POSSESSION: a key whose secret the registrant does not hold
/// cannot be registered. Without this, an attacker could point an account at
/// a key nobody controls and every disclosure to that account would be
/// undecryptable by anyone — and the registry entry is the only thing a
/// sender binds against, so no later transaction could undo it.
#[test]
fn a_key_the_registrant_does_not_hold_cannot_be_registered() {
    let (_ek, pk) = keypair(42);
    let acct = account_slots(&ALICE);
    let limbs = encode_point(pk);

    // Key 42's point, key 43's secret.
    let err = run_wit(
        &Disclosure::register(),
        empty_state(),
        &[acct[0], acct[1], limbs[0], limbs[1]],
        &[ek_witness(43)],
    )
    .expect_err("proof of possession refuses it");
    let shown = format!("{err}");
    assert!(
        shown.contains("Equality constraint failed"),
        "expected the possession binding's constrain_eq to fail, got {shown}"
    );

    // The same point with its OWN secret registers, so the refusal above is
    // the proof talking and not the shape of the call.
    run_wit(
        &Disclosure::register(),
        empty_state(),
        &[acct[0], acct[1], limbs[0], limbs[1]],
        &[ek_witness(42)],
    )
    .expect("the holder of the key may register it");
}

/// THE LIMIT of that proof, pinned so it is never read as more than it is: a
/// squatter may register SOMEONE ELSE'S account id under a key they genuinely
/// hold, and the proof passes, because they really do know that secret.
/// `account` is a caller-supplied `Bytes<32>` and nothing binds it to the
/// caller, so "we check the key" is NOT "accounts are safe". Closing this
/// needs the account bound to the caller — `register`'s docs and
/// notes/disclosure-model.org §6 say which, and it is deliberately not done.
#[test]
fn proof_of_possession_does_not_stop_account_squatting() {
    let (_mallory_ek, mallory_pk) = keypair(99);
    let acct = account_slots(&ALICE);
    let mallory = encode_point(mallory_pk);

    run_wit(
        &Disclosure::register(),
        empty_state(),
        // Alice's account id, Mallory's key, Mallory's own secret.
        &[acct[0], acct[1], mallory[0], mallory[1]],
        &[ek_witness(99)],
    )
    .expect("nothing binds the account to the caller — this is the open rung");
}

/// Encrypting to the identity point is refused: `S = identity` for any `e`,
/// so `mask = KDF(identity)` is a value any observer can recompute and the
/// "ciphertext" opens trivially. The identity IS a valid subgroup point, so
/// nothing below this assert catches it.
#[test]
fn the_identity_key_is_refused() {
    let register = Disclosure::register();
    let acct = account_slots(&ALICE);
    let identity = encode_point(JubjubSubgroup::identity());
    let registered = run_wit(
        &register,
        empty_state(),
        &[acct[0], acct[1], identity[0], identity[1]],
        // `g^0 == identity`, so zero is a genuine proof of possession for it:
        // the identity survives registration and dies at `derive_shared`.
        &[Fr::from(0u64)],
    )
    .expect("registering the identity is allowed — only encrypting to it is not");

    let seed = account_slots(&[0x5e; 32]);
    run(
        &Disclosure::disclose_to(),
        registered.post,
        &[
            acct[0],
            acct[1],
            identity[0],
            identity[1],
            Fr::from(1u64),
            seed[0],
            seed[1],
        ],
    )
    .expect_err("EcdhMask: identity pk");
}

/// What it costs, in the style of notes/nonce-admin.org §11 — the number
/// `notes/disclosure-model.org` §7 quotes. Printed, not asserted, so a
/// row-model change does not fail a correctness suite.
#[test]
fn the_row_and_k_table() {
    println!("| circuit | k | rows |");
    println!("|---------+---+------|");
    for (name, build) in [
        ("register", Disclosure::register as fn() -> Compiled3),
        ("discloseTo", Disclosure::disclose_to),
    ] {
        let (k, rows) = cost(&build().ir);
        println!("| {name} | {k} | {rows} |");
    }
    println!();
    println!("{}", minocrab_sim::v3::profile(&Disclosure::disclose_to()));
}

/// WHY `encrypt` TAKES A `Uint<128>` (upstream PR #913). The 248-bit `kdf` pad
/// cannot hide a plaintext that reaches bit 248, and the failure is total
/// rather than statistical: `mask < 2^248`, so `ct = m + mask` never carries
/// into bit 248, so BIT 248 OF THE CIPHERTEXT IS BIT 248 OF THE PLAINTEXT, for
/// every pad. One ciphertext, one bit, no guessing.
///
/// This is also the proof that the `Uint<128>` bound is load-bearing and not
/// decoration: at 128 bits, bit 248 of `m` is zero whatever `m` is, so the same
/// observation determines nothing. An `encrypt_field` added without OZ's
/// `fieldKdf` (RFC 9380 `hash_to_field`, uniform over the whole field) would
/// publish the top bits of every value it masked.
#[test]
fn the_248_bit_pad_cannot_hide_a_wide_value() {
    /// Bit 248 — byte 31, bit 0 — of a field element's little-endian form.
    fn bit_248(f: &Fr) -> u8 {
        f.as_le_bytes()[31] & 1
    }

    // `m = 2^248`: a plaintext that reaches the bit the pad cannot cover.
    let mut wide = [0u8; 32];
    wide[31] = 1;
    let wide = Fr::from_le_bytes(&wide).expect("2^248 is in the field");

    // Thirty-two unrelated pads, each a genuine KDF output over a fresh DH
    // secret — not a mock, the same `kdf` the circuit computes.
    for seed in 1u64..=32 {
        let (ek, _pk) = keypair(seed);
        let (_e, eph) = keypair(seed + 1_000);
        let IrValue::JubjubPoint(shared) =
            ec_mul_offcircuit(&IrValue::JubjubPoint(eph), &IrValue::JubjubScalar(ek))
                .expect("point times scalar")
        else {
            panic!("a Jubjub multiplication yields a Jubjub point");
        };
        let mask = kdf(shared);

        assert_eq!(bit_248(&mask), 0, "seed {seed}: a 248-bit pad cannot set bit 248");
        assert_eq!(
            bit_248(&(wide + mask)),
            1,
            "seed {seed}: the wide plaintext's top bit survives masking — the leak"
        );
        assert_eq!(
            bit_248(&(Fr::from(0u64) + mask)),
            0,
            "seed {seed}: and a zero plaintext's does not, so the bit distinguishes them"
        );

        // The bound `encrypt` actually works at: every `Uint<128>` leaves bit
        // 248 of the ciphertext equal to the pad's, so it says nothing.
        for value in [0u128, 1, u128::MAX] {
            assert_eq!(
                bit_248(&(Fr::from(value) + mask)),
                bit_248(&mask),
                "seed {seed}: a Uint<128> plaintext determines no top bit"
            );
        }
    }
}
/// WHAT PAYS FOR `derive_shared`'s CONSTANT IDENTITY. Jubjub is a twisted
/// Edwards curve, so its identity is affine `(0, 1)`, and `encode` hands over
/// exactly those two limbs — which is why the circuit can compare against two
/// immediates instead of spending a scalar multiplication on
/// `ecMulGenerator(0)` the way Compact must. If a curve or encoding change ever
/// moved this, the guard would silently compare against the wrong point, so
/// the constant is pinned here rather than asserted in a comment.
#[test]
fn the_identity_point_encodes_to_zero_one() {
    let limbs = encode_point(JubjubSubgroup::identity());
    assert_eq!(limbs[0], Fr::from(0u64), "the identity's x limb");
    assert_eq!(limbs[1], Fr::from(1u64), "the identity's y limb");
}

/// THE PRICE OF AN OBSERVER (notes/disclosure-model.org §7). A DAML observer
/// is free — adding a party to a contract's observer list costs nothing,
/// because the ledger routes the payload rather than encrypting it. Here every
/// additional reader is a scalar multiplication.
///
/// MEASURED: 8290 rows per additional recipient, which is TWO curve operations,
/// not one. `encrypt` recomputes `E = g^e` for every recipient because
/// `derive_shared` owns the ephemeral — but one ephemeral scalar can serve
/// every recipient in a call (`E = g^e` once, then `S_i = pk_i^e` per
/// recipient), so a multi-recipient primitive that hoisted the generator
/// multiplication would pay about half this. That is the first optimisation
/// anyone adding auditors or observers should make, and it is recorded in
/// notes/disclosure-model.org §8 rather than done here: the one-recipient
/// shape is what the exploration is about, and hoisting it would put the
/// ephemeral outside the guarded primitive, which is precisely the factoring
/// mistake upstream PR #1110 is undoing.
#[test]
fn the_marginal_cost_of_an_extra_recipient() {
    use minocrab::v3::{Circuit3, JubjubPointT, JubjubScalarT};
    use minocrab_std::v3::{JubjubPoint, Uint};

    /// A bare circuit encrypting one value to `n` recipients under a shared
    /// ephemeral scalar — the shape, with no ledger and no argument plumbing,
    /// so the difference between two of these is the marginal cost alone.
    fn rows_for(n: usize) -> usize {
        let mut c = Circuit3::new();
        // Every argument is declared before the first instruction.
        let pks: Vec<_> = (0..n)
            .map(|i| JubjubPoint::from_point(c.arg::<JubjubPointT>(&format!("pk{i}"))))
            .collect();
        let value = Uint::<128>::from_field_unchecked(c.arg::<minocrab::v3::FieldT>("value"));
        let e = c.arg::<JubjubScalarT>("e");
        for pk in pks {
            let _memo = disclosure::encrypt(&mut c, pk, value, e);
        }
        c.finish(false).ir.model().rows()
    }

    let one = rows_for(1);
    let two = rows_for(2);
    let three = rows_for(3);
    let marginal = two - one;
    println!("recipients: 1 => {one} rows, 2 => {two}, 3 => {three} (marginal {marginal})");
    // Constant to within the cost model's rounding (8290 then 8292).
    assert!(
        (three - two).abs_diff(marginal) <= 4,
        "the marginal cost is constant per recipient: {marginal} then {}",
        three - two
    );
    assert!(
        marginal > 1_000,
        "a recipient costs a scalar multiplication, not a rounding error: {marginal}"
    );
}
