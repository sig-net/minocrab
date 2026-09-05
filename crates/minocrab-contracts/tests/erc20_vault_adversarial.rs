//! The erc20-vault ADVERSARIAL SWEEPS
//! (notes/vault-optimization.org §"Adversarial sweeps").
//!
//! Where `erc20_vault_spec.rs` asks "does the circuit do what the spec
//! says on well-formed inputs", this file asks "what does a malicious
//! prover get". The families:
//!
//! - **argument tampering** — the communications commitment binds every
//!   argument slot, and the set of genuinely UNREAD slots is pinned;
//! - **witness malleability** — out-of-range secret-key limbs, garbage
//!   `recoveryId`, `s = 0`, `r`/`s` above the curve order, the low-s
//!   partner, an infinite response key;
//! - **wrong branch** — settling a request through another flow's settle
//!   circuit, double-settling, and a FORGED membership answer (which the
//!   circuit cannot see through but the ledger can — the case that
//!   justifies the `run_program` link existing at all);
//! - **re-mapping injectivity** — the security property that changes when
//!   a hash construction changes: every Poseidon commitment the vault
//!   derives is injective on the generated corpus;
//! - the named underflow boundary of `completeSwap`'s
//!   `amountInMaximum - amountIn`, which the analysis calls the most
//!   dangerous arithmetic in the contract.
//!
//! The per-element tamper sweeps of every circuit's transcript and
//! witnesses live in `erc20_vault_differential.rs`, against compactc's
//! artifacts (acceptance AGREEMENT as well as soundness).

use std::collections::HashMap;

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use proptest::prelude::*;

mod vault;

use vault::artifact::Circuit;
use vault::exec;
use vault::gen;
use vault::model::*;
use vault::prims::*;
use vault::spec;
use vault::tamper::{self, Part};

/// secp256k1's group order n, big-endian.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `n - x` over big-endian 32-byte integers.
fn order_minus(x: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(SECP256K1_N[i]) - i16::from(x[i]) - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

/// A little-endian `Bytes<32>` scalar's big-endian form, and back.
fn reversed(x: &[u8; 32]) -> [u8; 32] {
    let mut out = *x;
    out.reverse();
    out
}

// --- family 1: argument tampering --------------------------------------------

/// Perturbing ANY argument must reject — including the slots the
/// verification never reads, because the communications commitment binds
/// the whole argument vector.
#[test]
fn argument_tampering_always_rejects_via_the_commitment() {
    let ours = Circuit::CompleteDeposit.ir();
    let c = CompleteDepositScenario::new();
    let pi = c.preimage();
    assert!(simulate(&ours, &pi).is_ok(), "the baseline accepts");
    for i in 0..pi.inputs.len() {
        assert!(
            !tamper::accepts_with(&ours, &pi, Part::Inputs, i, pi.inputs[i] + Fr::from(1u64)),
            "completeDeposit accepts a tampered argument slot {i}"
        );
    }
}

/// With the commitment re-derived, the picture separates: which argument
/// slots are genuinely UNREAD.
///
/// Two are unread in every case — the attestation's `bigR.y` (inputs 4, 5)
/// and its `recoveryId` (input 8): they are part of the wire shape and are
/// range-constrained, but `verifyRespondBidirectionalEvent` consumes
/// neither, exactly as in the Compact original. The rest depend on the
/// recipient shape, because `Maybe<Either<..>>`'s unselected arm is
/// `cond_select`ed away. Pinning the exact set makes both facts decisions
/// rather than oversights: a port that started reading `bigR.y`, or one
/// that leaked the unselected arm into the coin commitment, fails here.
#[test]
fn unread_argument_slots_are_exactly_the_declared_ones() {
    // Argument layout: 0,1 requestId · 2,3 bigR.x · 4,5 bigR.y · 6,7 s ·
    // 8 recoveryId · 9 serializedOutput · 10,11 mintNonce · 12 is_some ·
    // 13 is_left · 14,15 left(pk) · 16,17 right(contract).
    let other = tagged32(b"other-ct", 0);
    let base = CompleteDepositScenario::new();
    let cases: Vec<(&str, ClaimRecipient, Vec<usize>)> = vec![
        // some(left(pk)): the `right` arm is selected away.
        ("some(left(pk))", ClaimRecipient::Key(other), vec![4, 5, 8, 16, 17]),
        // some(right(self)): auto-receive fires, so `right` is read and
        // the `left` arm is selected away.
        ("some(right(self))", ClaimRecipient::Contract(base.env().self_addr), vec![4, 5, 8, 14, 15]),
        // some(right(other)): same shape, branch off.
        ("some(right(other))", ClaimRecipient::Contract(other), vec![4, 5, 8, 14, 15]),
        // none: the recipient is ownPublicKey(), so is_left and BOTH arms
        // are selected away — only the `is_some` tag itself is read.
        ("none", ClaimRecipient::None(other), vec![4, 5, 8, 13, 14, 15, 16, 17]),
    ];
    let ours = Circuit::CompleteDeposit.ir();
    for (name, recipient, unread) in &cases {
        let mut c = CompleteDepositScenario::new();
        c.recipient = *recipient;
        let pi = c.preimage();
        for i in 0..pi.inputs.len() {
            let v = pi.inputs[i] + Fr::from(1u64);
            let accepted = tamper::accepts_with_rebound_input(&ours, &pi, i, v);
            assert_eq!(
                accepted,
                unread.contains(&i),
                "{name}: argument {i} accepted = {accepted}, expected unread = {}",
                unread.contains(&i)
            );
        }
    }
}

// --- family 2: witness malleability ------------------------------------------

/// A `Bytes<32>` witness is two limbs, `[hi = byte 31, lo = bytes 0..31]`,
/// range-constrained to 8 and 248 bits. Out-of-range limbs must reject:
/// without the bound, two different secrets could share a commitment.
#[test]
fn secret_key_limbs_out_of_range_reject() {
    let ours = Circuit::CompleteDeposit.ir();
    let pi = CompleteDepositScenario::new().preimage();
    // hi is a single byte.
    for v in [256u64, 257, 1 << 32] {
        assert!(
            !tamper::accepts_with(&ours, &pi, Part::Witness, 0, Fr::from(v)),
            "completeDeposit accepts an out-of-range sk hi limb ({v})"
        );
    }
    // lo is 248 bits, so the all-ones 31-byte limb is the largest legal
    // value; one more must not fit.
    let big = Fr::from_le_bytes(&[0xffu8; 31]).unwrap() + Fr::from(1u64);
    assert!(
        !tamper::accepts_with(&ours, &pi, Part::Witness, 1, big),
        "completeDeposit accepts an out-of-range sk lo limb"
    );
}

/// `recoveryId` is declared and `constrain_bits`-ed to 8 bits but never
/// read. Garbage IN RANGE is therefore accepted (it is genuinely unused);
/// garbage OUT of range must still reject, because the range constraint is
/// what makes the argument's on-chain rendering canonical.
#[test]
fn recovery_id_garbage_is_range_bound_but_unread() {
    let ours = Circuit::CompleteDeposit.ir();
    let pi = CompleteDepositScenario::new().preimage();
    for v in [0u64, 1, 27, 28, 255] {
        assert!(
            tamper::accepts_with_rebound_input(&ours, &pi, 8, Fr::from(v)),
            "completeDeposit rejects an in-range recoveryId ({v}) it never reads"
        );
    }
    for v in [256u64, 1 << 20] {
        assert!(
            !tamper::accepts_with_rebound_input(&ours, &pi, 8, Fr::from(v)),
            "completeDeposit accepts an out-of-range recoveryId ({v})"
        );
    }
}

/// Every settle circuit's baseline preimage, for the sweeps that run over
/// all of them (each instantiates the verification at its own output
/// width).
fn settle_baselines() -> Vec<(&'static str, IrSource, ProofPreimage)> {
    vec![
        ("completeDeposit", Circuit::CompleteDeposit.ir(), CompleteDepositScenario::new().preimage()),
        ("completeWithdraw", Circuit::CompleteWithdraw.ir(), CompleteWithdrawScenario::new(1).preimage()),
        ("refundWithdraw", Circuit::RefundWithdraw.ir(), RefundWithdrawScenario::new().preimage()),
        ("completeSwap", Circuit::CompleteSwap.ir(), CompleteSwapScenario::new().preimage()),
        ("refundSwap", Circuit::RefundSwap.ir(), RefundSwapScenario::new().preimage()),
        ("completeSupply", Circuit::CompleteSupply.ir(), CompleteSupplyScenario::new().preimage()),
        ("refundSupply", Circuit::RefundSupply.ir(), RefundSupplyScenario::new().preimage()),
        ("completeRedeem", Circuit::CompleteRedeem.ir(), CompleteRedeemScenario::new().preimage()),
        ("refundRedeem", Circuit::RefundRedeem.ir(), RefundRedeemScenario::new().preimage()),
    ]
}

/// `s = 0` must ABORT, not verify.
///
/// ECDSA verification computes `s^-1`; if the inverse of zero were
/// silently defined as zero the recomputed `R` would be the point at
/// infinity and a comparison could go either way. The circuit must refuse
/// the witness outright. Asserted for all nine settle circuits.
#[test]
fn zero_signature_scalar_aborts() {
    for (name, ir, pi) in settle_baselines() {
        assert!(simulate(&ir, &pi).is_ok(), "{name}: the baseline accepts");
        // s is inputs[6] (hi) and inputs[7] (lo); zero both.
        let mut t = pi.clone();
        t.inputs[6] = Fr::from(0u64);
        t.inputs[7] = Fr::from(0u64);
        let err = simulate(&ir, &t).err();
        assert!(err.is_some(), "{name} accepts s = 0");
        // And it must not be an ordinary "assert failed": the inversion
        // itself is what refuses. Recorded rather than asserted on the
        // message text, which is not a stable interface.
        eprintln!("{name}: s = 0 -> {}", err.unwrap());
    }
}

/// `r` and `s` enter the circuit as LITTLE-endian `Bytes<32>` (the
/// circuit-input form since the protocol move) and are cast to secp256k1
/// scalars. Values at or above the group order must not verify, and the
/// canonical malleability partner `n - s` must not verify either —
/// otherwise a second, different attestation exists for every signed
/// digest.
#[test]
fn signature_scalars_above_the_order_reject() {
    let ours = Circuit::CompleteDeposit.ir();
    let c = CompleteDepositScenario::new();
    let pi = c.preimage();
    let (_r_le, s_le) = c.settle.signature(c.env(), &c.d.request_id(), &c.output_limbs());

    // n itself, in the circuit-input (little-endian) form.
    let n_slots = b32_slots(&reversed(&SECP256K1_N));
    assert!(
        !{
            let mut t = pi.clone();
            t.inputs[6] = n_slots.0;
            t.inputs[7] = n_slots.1;
            simulate(&ours, &t).is_ok()
        },
        "completeDeposit accepts s = n"
    );
    assert!(
        !{
            let mut t = pi.clone();
            t.inputs[2] = n_slots.0;
            t.inputs[3] = n_slots.1;
            simulate(&ours, &t).is_ok()
        },
        "completeDeposit accepts r = n"
    );

    // The malleability partner. `(r, n - s)` verifies against -R, whose
    // x-coordinate is R's, so a verifier that compares only x accepts it.
    // It is a property of ECDSA-as-specified, not a porting bug, and it
    // matters only if an attestation is ever used as a unique identifier
    // (the vault does not — the request id is).
    let alt_s = reversed(&order_minus(&reversed(&s_le)));
    let alt = b32_slots(&alt_s);
    let mut t = pi.clone();
    t.inputs[6] = alt.0;
    t.inputs[7] = alt.1;
    let malleable = simulate(&ours, &t).is_ok();
    assert!(
        !malleable,
        "completeDeposit accepts the low-s malleability partner: an \
         attestation is NOT unique per digest, so nothing may key off it"
    );
}

/// FINDING (kept from M10): an identity `mpcResponseKey` authenticates
/// ANYTHING — and compactc's `initialise` does not reject one, so the
/// compat port does not either.
///
/// With `Q = O` (the point at infinity, i.e. secret key 0), ECDSA
/// verification of a signature made with `d = 0` recomputes
/// `R' = (z/s)G + (r/s)O = (z/s)G`, whose x-coordinate is `r` by
/// construction — so it verifies, and anyone can produce such a signature
/// without knowing any secret. Every settle circuit's ONLY authentication
/// gate would then be open.
///
/// compactc's `initialise` validates the chain id and the three addresses
/// but has no analogous check on `responseKey`, so this is reachable by a
/// deployer mistake (deployer-gated and one-shot, so not by an attacker) —
/// kept, for parity, and pinned here. The `Pending` lineage extracts the
/// key's coordinates in `initialize` (external review §4.5). Recorded in
/// notes/vault-optimization.org §"As built — step 1".
#[test]
fn an_identity_response_key_authenticates_anything() {
    let mut s = InitialiseScenario::new();
    s.point = identity_point();
    assert!(
        simulate(&Circuit::Initialise.ir(), &s.preimage()).is_ok(),
        "the port's initialise must keep compactc's shape (no identity check)"
    );

    // ...and with it STORED, a signature under secret key 0 verifies: the
    // settle circuits trust whatever key is stored.
    let mut c = CompleteDepositScenario::new();
    c.d.env.key_seed = 0;
    assert!(
        simulate(&Circuit::CompleteDeposit.ir(), &c.preimage()).is_ok(),
        "completeDeposit rejects an attestation under an identity response \
         key — the gap is closed, update notes/vault-optimization.org"
    );
}

// --- family 3: wrong branch ---------------------------------------------------

/// Each flow's settle circuits read their OWN maps: a request filed by
/// another flow is "not found" there, and a settled request's entries are
/// consumed, so nothing settles twice.
#[test]
fn settling_without_a_pending_entry_rejects() {
    // A deposit cannot be settled through the withdraw circuits: the
    // withdraw settle view is what they gate on, and deposits never write
    // one.
    let mut cw = CompleteWithdrawScenario::new(1);
    cw.settle.pending = false;
    assert!(simulate(&Circuit::CompleteWithdraw.ir(), &cw.preimage()).is_err());
    let mut rw = RefundWithdrawScenario::new();
    rw.settle.pending = false;
    assert!(simulate(&Circuit::RefundWithdraw.ir(), &rw.preimage()).is_err());

    // A settled deposit's record is gone.
    let mut cd = CompleteDepositScenario::new();
    cd.settle.pending = false;
    assert!(simulate(&Circuit::CompleteDeposit.ir(), &cd.preimage()).is_err());

    // The lending flows likewise.
    let mut cs = CompleteSupplyScenario::new();
    cs.settle.pending = false;
    assert!(simulate(&Circuit::CompleteSupply.ir(), &cs.preimage()).is_err());
    let mut cr = CompleteRedeemScenario::new();
    cr.settle.pending = false;
    assert!(simulate(&Circuit::CompleteRedeem.ir(), &cr.preimage()).is_err());
}

/// THE case the `run_program` link exists for.
///
/// A membership answer is a `Popeq` result: the circuit takes the prover's
/// word for it, and a prover who claims a pending entry exists when it
/// does not gets a perfectly valid PROOF. Only the ledger catches it —
/// `ResultModeVerify::process_read` compares every read against the real
/// state and refuses with `ReadMismatch`.
#[test]
fn a_forged_membership_answer_passes_the_circuit_and_fails_the_ledger() {
    let c = CompleteWithdrawScenario::new(1);
    // The transcript claims the settle view is present...
    assert!(c.settle.pending);
    assert!(simulate(&Circuit::CompleteWithdraw.ir(), &c.preimage()).is_ok());
    // ...but the ledger state does not hold it.
    let mut pre = c.pre_state();
    pre.withdraw_settle_views.clear();
    let err = exec::run(&pre, &c.env().self_addr, &c.ops())
        .expect_err("the ledger accepted a forged membership answer");
    assert!(err.contains("ReadMismatch"), "expected a read mismatch, got: {err}");
}

/// A refund settles only the response that says "the transaction never
/// executed". A success-shaped output must not route a refund — otherwise
/// an executed withdrawal could be refunded as well as delivered. Asserted
/// on all four refund circuits.
#[test]
fn refunds_reject_success_shaped_outputs() {
    for output in [[0u8, 0, 0, 0, 1], [0xde, 0xad, 0xbe, 0xef, 0x00], [0xde, 0xad, 0xbe, 0xee, 0x01], [0u8; 5]] {
        let mut r = RefundWithdrawScenario::new();
        r.serialized_output = output;
        assert!(simulate(&Circuit::RefundWithdraw.ir(), &r.preimage()).is_err(), "refundWithdraw {output:02x?}");
        let mut r = RefundSwapScenario::new();
        r.serialized_output = output;
        assert!(simulate(&Circuit::RefundSwap.ir(), &r.preimage()).is_err(), "refundSwap {output:02x?}");
        let mut r = RefundSupplyScenario::new();
        r.serialized_output = output;
        assert!(simulate(&Circuit::RefundSupply.ir(), &r.preimage()).is_err(), "refundSupply {output:02x?}");
        let mut r = RefundRedeemScenario::new();
        r.serialized_output = output;
        assert!(simulate(&Circuit::RefundRedeem.ir(), &r.preimage()).is_err(), "refundRedeem {output:02x?}");
    }
}

/// THE 0x02 HAZARD, kept by upstream: `completeWithdraw` reads its attested
/// output as `byte == 1`, so `0x02` — or any byte but `0x01` — routes to the
/// REFUND branch and re-mints the surrendered value on a withdrawal that
/// SUCCEEDED. The port keeps compactc's semantics (that is what PI-equality
/// means); the spec models the same, so a change on either side is loud.
/// The `Pending` lineage declares the field a Borsh `bool` and makes the
/// same attestation unprovable.
#[test]
fn a_non_boolean_success_byte_refunds_on_the_port() {
    for outcome in [2u8, 3, 0x80, 0xff] {
        let c = CompleteWithdrawScenario::new(outcome);
        let accepted = simulate(&Circuit::CompleteWithdraw.ir(), &c.preimage()).is_ok();
        assert!(
            accepted,
            "the deployed semantics REFUND on a non-boolean success byte {outcome:#04x} — \
             if that has stopped being true, upstream changed and the port must follow"
        );
        assert_eq!(spec::spec_complete_withdraw(&c).accepts(), accepted);
    }
}

// --- family 4: re-mapping injectivity ----------------------------------------

/// A derived 32-byte value, named by WHAT it is. If two DISTINCT terms ever
/// concretise to the same bytes, the two values they name become
/// interchangeable on chain — a depositor's commitment could be a refund
/// commitment, a domain separator could be a request id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Term {
    UserCommit { sk: [u8; 32] },
    RefundCommit { sk: [u8; 32], request_id: [u8; 32] },
    DomainSep { erc20: [u8; 20] },
    TokenType { erc20: [u8; 20], addr: [u8; 32] },
    RequestId { limbs: Vec<[u8; 32]> },
    CoinCm { nonce: [u8; 32], erc20: [u8; 20], addr: [u8; 32], value: u64, is_left: bool, data: [u8; 32] },
    CoinNul { nonce: [u8; 32], erc20: [u8; 20], addr: [u8; 32], value: u64 },
}

impl Term {
    fn concretize(&self) -> [u8; 32] {
        match self {
            Term::UserCommit { sk } => user_commitment(sk),
            Term::RefundCommit { sk, request_id } => refund_commitment(sk, request_id),
            Term::DomainSep { erc20 } => vault_domain_sep(erc20),
            Term::TokenType { erc20, addr } => vault_color(erc20, addr),
            Term::RequestId { limbs } => {
                let limbs: Vec<Fr> = limbs.iter().map(|b| Fr::from_le_bytes(&b[..31]).unwrap()).collect();
                request_id_of(&limbs)
            }
            Term::CoinCm { nonce, erc20, addr, value, is_left, data } => {
                coin_commitment_of(&b32_slots(nonce), &vault_color(erc20, addr), u128::from(*value), *is_left, data)
            }
            Term::CoinNul { nonce, erc20, addr, value } => {
                coin_nullifier_of(&b32_slots(nonce), &vault_color(erc20, addr), u128::from(*value), addr)
            }
        }
    }
}

fn injectivity_over(terms: Vec<Term>) -> Result<usize, String> {
    let mut seen: HashMap<[u8; 32], Term> = HashMap::new();
    for t in terms {
        let bytes = t.concretize();
        if t.concretize() != bytes {
            return Err(format!("concretization is not deterministic for {t:?}"));
        }
        match seen.get(&bytes) {
            Some(prev) if *prev != t => return Err(format!("collision: {prev:?} and {t:?} share {bytes:02x?}")),
            _ => {
                seen.insert(bytes, t);
            }
        }
    }
    Ok(seen.len())
}

/// Every derived term one generated case produces.
fn terms_of(w: &StartWithdrawScenario, d: &StartDepositScenario, mint_nonce: [u8; 32]) -> Vec<Term> {
    let rid_w = w.request_id();
    let rid_d = d.request_id();
    let self_addr = w.env.self_addr;
    vec![
        Term::UserCommit { sk: w.sk },
        Term::UserCommit { sk: d.sk },
        Term::RefundCommit { sk: w.sk, request_id: rid_w },
        Term::RefundCommit { sk: d.sk, request_id: rid_d },
        Term::DomainSep { erc20: w.erc20 },
        Term::DomainSep { erc20: d.erc20 },
        Term::RequestId { limbs: vec![rid_w, mint_nonce] },
        Term::RequestId { limbs: vec![rid_d, mint_nonce] },
        Term::TokenType { erc20: w.erc20, addr: self_addr },
        Term::CoinCm { nonce: mint_nonce, erc20: w.erc20, addr: self_addr, value: w.amount_u64(), is_left: true, data: [0u8; 32] },
        Term::CoinNul { nonce: mint_nonce, erc20: w.erc20, addr: self_addr, value: w.amount_u64() },
    ]
}

proptest! {
    #![proptest_config(gen::config())]

    /// The Poseidon constructions are injective on everything generation
    /// produces, and distinct constructions never collide with one another
    /// (the domain-separation pads do their job).
    #[test]
    fn concretization_is_injective(
        w in gen::start_withdraw(),
        d in gen::start_deposit(),
        nonce in gen::b32(),
    ) {
        let terms = terms_of(&w, &d, nonce);
        let mut distinct: Vec<Term> = Vec::new();
        for t in &terms {
            if !distinct.contains(t) {
                distinct.push(t.clone());
            }
        }
        let want = distinct.len();
        let got = injectivity_over(terms);
        prop_assert!(got.is_ok(), "{:?}", got);
        prop_assert_eq!(got.unwrap(), want);
    }

    /// The identity commitment and the refund commitment are DIFFERENT
    /// functions of the same secret (the source says so: "reuse would link
    /// settle views to depositor identities"), and the domain separator is
    /// never either of them.
    #[test]
    fn the_three_commitments_never_coincide(sk in gen::b32(), rid in gen::b32(), erc20 in any::<[u8; 20]>()) {
        let user = user_commitment(&sk);
        let refund = refund_commitment(&sk, &rid);
        let sep = vault_domain_sep(&erc20);
        prop_assert_ne!(user, refund);
        prop_assert_ne!(user, sep);
        prop_assert_ne!(refund, sep);
        // And every one of them has byte 31 zero — `upgradeFromTransient`'s
        // shape, which is what lets a `Bytes<32>` cell hold a field element.
        prop_assert_eq!((user[31], refund[31], sep[31]), (0, 0, 0));
    }
}

// --- completeSwap's underflow boundary ----------------------------------------
//
// notes/vault-optimization.org: "completeSwap's amountInMaximum - amountIn
// subtraction is the most dangerous arithmetic in the contract". A wrapped
// subtraction would mint a ~2^64 change coin of tokenIn out of nothing —
// an unbounded over-mint from a single misbehaving attestation. The
// attested amountIn is repacked to uint64 by the MPC, so an
// amountIn > amountInMaximum attestation is entirely constructible.

/// One completeSwap case at a chosen (amountInMaximum, amountIn).
fn complete_swap_at(max: u128, amount_in: u64) -> CompleteSwapScenario {
    let mut c = CompleteSwapScenario::new();
    c.s.amount_in_max = max;
    // amountOut is independent of the subtraction; keep it in range.
    c.s.amount_out = 1;
    c.amount_in = amount_in;
    c
}

fn assert_complete_swap(c: &CompleteSwapScenario, want_accept: bool, why: &str) {
    let ours = Circuit::CompleteSwap.ir();
    let outcome = spec::spec_complete_swap(c);
    assert_eq!(outcome.accepts(), want_accept, "spec disagrees: {why}");
    let accepted = simulate(&ours, &c.preimage()).is_ok();
    assert_eq!(accepted, want_accept, "circuit disagrees: {why}");
    if want_accept {
        let ex = exec::run(&c.pre_state(), &c.env().self_addr, &c.ops()).expect("the ledger accepts");
        spec::check_effects(outcome.effects(), &c.pre_state(), &ex).expect("effects agree");
    }
}

#[test]
fn complete_swap_change_exact_spend_is_a_zero_coin() {
    let c = complete_swap_at(99_999, 99_999);
    assert_complete_swap(&c, true, "amountIn == amountInMaximum: change 0");
    // The zero-value change coin is real and must be declared.
    let outcome = spec::spec_complete_swap(&c);
    assert!(outcome
        .effects()
        .iter()
        .any(|e| matches!(e, spec::Effect::MintShielded { value: 0, .. })));
}

#[test]
fn complete_swap_change_one_below_the_cap() {
    assert_complete_swap(&complete_swap_at(99_999, 99_998), true, "amountIn == amountInMaximum - 1: change 1");
}

#[test]
fn complete_swap_change_underflows_one_above_the_cap() {
    assert_complete_swap(&complete_swap_at(99_999, 100_000), false, "amountIn == amountInMaximum + 1 MUST reject");
}

#[test]
fn complete_swap_change_underflows_at_u64_max() {
    assert_complete_swap(&complete_swap_at(1, u64::MAX), false, "amountIn == u64::MAX against amountInMaximum 1 MUST reject");
}

#[test]
fn complete_swap_change_at_the_smallest_legal_cap() {
    assert_complete_swap(&complete_swap_at(1, 0), true, "cap 1, spend 0: change 1");
    assert_complete_swap(&complete_swap_at(1, 1), true, "cap 1, spend 1: change 0");
    assert_complete_swap(&complete_swap_at(1, 2), false, "cap 1, spend 2 MUST reject");
}

#[test]
fn complete_swap_change_at_the_uint64_ceiling() {
    let max = u64::MAX;
    assert_complete_swap(&complete_swap_at(u128::from(max), max), true, "cap u64::MAX, spend u64::MAX: change 0");
    assert_complete_swap(&complete_swap_at(u128::from(max), 0), true, "cap u64::MAX, spend 0: change u64::MAX");
    assert_complete_swap(&complete_swap_at(u128::from(max) - 1, max), false, "cap u64::MAX - 1, spend u64::MAX MUST reject");
}
