//! M10 step 1: the erc20-vault ADVERSARIAL SWEEPS
//! (notes/vault-optimization.org §"Adversarial sweeps").
//!
//! Where `erc20_vault_spec.rs` asks "does the circuit do what the spec
//! says on well-formed inputs", this file asks "what does a malicious
//! prover get". Four families:
//!
//! - **tamper**, extended to the circuits the differential suite did not
//!   sweep (initialize, approveRouter, swap) and to the argument vectors,
//!   reusing [`vault::tamper`] rather than re-rolling the loops;
//! - **witness malleability** — out-of-range secret-key limbs, garbage
//!   `recoveryId`, `s = 0`, `r`/`s` above the curve order, an infinite
//!   response key;
//! - **wrong branch** — settling a request through the wrong circuit,
//!   double-settling, and a FORGED membership answer (which the circuit
//!   cannot see through but the ledger can — the case that justifies the
//!   `run_program` link existing at all);
//! - **re-mapping injectivity** — the security property that actually
//!   changes when a hash construction changes.
//!
//! Plus the named underflow boundary of `completeSwap`'s
//! `amountInMaximum - amountIn`, which the analysis calls the most
//! dangerous arithmetic in the contract.

use std::collections::HashMap;

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use proptest::prelude::*;

mod vault;

use vault::exec;
use vault::gen;
use vault::model::*;
use vault::prims::*;
use vault::spec::{self, Term};
use vault::tamper::{self, Part};

/// secp256k1's group order `n`, big-endian.
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `n - x` for a big-endian 256-bit `x < n` — the classic ECDSA
/// signature-malleability partner of `s`.
fn order_minus(x: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i32;
    for i in (0..32).rev() {
        let d = i32::from(SECP256K1_N[i]) - i32::from(x[i]) - borrow;
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

// --- family 1: tamper, extended ----------------------------------------------

/// The three circuits the differential suite sweeps for guard failures but
/// not for tampering. Corpus artifact included, so this is an acceptance
/// AGREEMENT sweep as well as a soundness one.
#[test]
fn tamper_sweeps_the_remaining_circuits() {
    let s = Scenario::new();
    tamper::assert_full_sweep(
        &erc20_vault::initialize().ir,
        &corpus_zkir_named("initialize"),
        &s.preimage(0),
    );

    let a = ApproveScenario::new();
    tamper::assert_full_sweep(
        &erc20_vault::approve_router().ir,
        &corpus_zkir_named("approveRouter"),
        &a.preimage(),
    );

    let sw = SwapScenario::new();
    tamper::assert_full_sweep(
        &erc20_vault::swap().ir,
        &corpus_zkir_named("swap"),
        &sw.preimage(),
    );
}

/// Perturbing ANY argument must reject — including the three slots the
/// verification never reads, because the communications commitment binds
/// the whole argument vector.
#[test]
fn argument_tampering_always_rejects_via_the_commitment() {
    let ours = erc20_vault::claim().ir;
    let c = ClaimScenario::new();
    let pi = c.preimage();
    for i in 0..pi.inputs.len() {
        let mut t = pi.clone();
        t.inputs[i] = t.inputs[i] + Fr::from(1u64);
        assert!(
            simulate(&ours, &t).is_err(),
            "claim accepts a perturbed argument {i}"
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
    let ours = erc20_vault::claim().ir;
    // Argument layout: 0,1 requestId · 2,3 bigR.x · 4,5 bigR.y · 6,7 s ·
    // 8 recoveryId · 9 serializedOutput · 10,11 mintNonce · 12 is_some ·
    // 13 is_left · 14,15 left(pk) · 16,17 right(contract).
    let mut other = [0u8; 32];
    other[..8].copy_from_slice(b"other-ct");
    let base = ClaimScenario::new();
    let cases: Vec<(&str, ClaimRecipient, Vec<usize>)> = vec![
        // some(left(pk)): the `right` arm is selected away.
        ("some(left(pk))", ClaimRecipient::Key(other), vec![4, 5, 8, 16, 17]),
        // some(right(self)): auto-receive fires, so `right` is read and
        // the `left` arm is selected away.
        (
            "some(right(self))",
            ClaimRecipient::Contract(base.d.self_addr),
            vec![4, 5, 8, 14, 15],
        ),
        // some(right(other)): same shape, branch off.
        (
            "some(right(other))",
            ClaimRecipient::Contract(other),
            vec![4, 5, 8, 14, 15],
        ),
        // none: the recipient is ownPublicKey(), so is_left and BOTH arms
        // are selected away — only the `is_some` tag itself is read.
        (
            "none",
            ClaimRecipient::None(other),
            vec![4, 5, 8, 13, 14, 15, 16, 17],
        ),
    ];
    for (name, recipient, unread) in cases {
        let mut c = ClaimScenario::new();
        c.recipient = recipient;
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
    let ours = erc20_vault::claim().ir;
    let c = ClaimScenario::new();
    let pi = c.preimage();
    // hi is a single byte.
    for v in [256u64, 257, 1 << 32] {
        assert!(
            !tamper::accepts_with(&ours, &pi, Part::Witness, 0, Fr::from(v)),
            "claim accepts an out-of-range sk hi limb ({v})"
        );
    }
    // lo is 248 bits, so the all-ones 31-byte limb is the largest legal
    // value; one more must not fit.
    let big = Fr::from_le_bytes(&[0xffu8; 31]).unwrap() + Fr::from(1u64);
    assert!(
        !tamper::accepts_with(&ours, &pi, Part::Witness, 1, big),
        "claim accepts an out-of-range sk lo limb"
    );
}

/// `recoveryId` is declared and `constrain_bits`-ed to 8 bits but never
/// read. Garbage IN RANGE is therefore accepted (it is genuinely unused);
/// garbage OUT of range must still reject, because the range constraint is
/// what makes the argument's on-chain rendering canonical.
#[test]
fn recovery_id_garbage_is_range_bound_but_unread() {
    let ours = erc20_vault::claim().ir;
    let c = ClaimScenario::new();
    let pi = c.preimage();
    for v in [0u64, 1, 27, 28, 255] {
        assert!(
            tamper::accepts_with_rebound_input(&ours, &pi, 8, Fr::from(v)),
            "claim rejects an in-range recoveryId ({v}) it never reads"
        );
    }
    for v in [256u64, 1 << 20] {
        assert!(
            !tamper::accepts_with_rebound_input(&ours, &pi, 8, Fr::from(v)),
            "claim accepts an out-of-range recoveryId ({v})"
        );
    }
}

/// `s = 0` must ABORT, not verify.
///
/// ECDSA verification computes `s^-1`; if the inverse of zero were
/// silently defined as zero the recomputed `R` would be the point at
/// infinity and a comparison could go either way. The circuit must refuse
/// the witness outright. Asserted for all four settle circuits, since each
/// instantiates the verification at a different output width.
#[test]
fn zero_signature_scalar_aborts() {
    let cases: Vec<(&str, IrSource, ProofPreimage)> = vec![
        (
            "claim",
            erc20_vault::claim().ir,
            ClaimScenario::new().preimage(),
        ),
        (
            "completeWithdraw",
            erc20_vault::complete_withdraw().ir,
            CompleteWithdrawScenario::new(1).preimage(),
        ),
        (
            "completeSwap",
            erc20_vault::complete_swap().ir,
            CompleteSwapScenario::new().preimage(),
        ),
        (
            "refund",
            erc20_vault::refund().ir,
            RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new())).preimage(),
        ),
    ];
    for (name, ir, pi) in cases {
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

/// `r` and `s` are read out of the attestation as big-endian `Bytes<32>`
/// and cast to secp256k1 scalars. Values at or above the group order must
/// not verify, and the canonical malleability partner `n - s` must not
/// verify either — otherwise a second, different attestation exists for
/// every signed digest.
#[test]
fn signature_scalars_above_the_order_reject() {
    let ours = erc20_vault::claim().ir;
    let c = ClaimScenario::new();
    let pi = c.preimage();
    let (r_be, s_be) = c.signature_be();

    // n itself, and n + 1 mod 2^256, in the stored big-endian form.
    let n_slots = b32_slots(&SECP256K1_N);
    assert!(
        !{
            let mut t = pi.clone();
            t.inputs[6] = n_slots.0;
            t.inputs[7] = n_slots.1;
            simulate(&ours, &t).is_ok()
        },
        "claim accepts s = n"
    );
    assert!(
        !{
            let mut t = pi.clone();
            t.inputs[2] = n_slots.0;
            t.inputs[3] = n_slots.1;
            simulate(&ours, &t).is_ok()
        },
        "claim accepts r = n"
    );

    // The malleability partner. `(r, n - s)` verifies against -R, whose
    // x-coordinate is R's, so a verifier that compares only x accepts it.
    // Recorded either way: it is a property of ECDSA-as-specified, not a
    // porting bug, and it matters only if an attestation is ever used as
    // a unique identifier (the vault does not — the request id is).
    let alt_s = order_minus(&s_be);
    let alt = b32_slots(&alt_s);
    let mut t = pi.clone();
    t.inputs[6] = alt.0;
    t.inputs[7] = alt.1;
    let malleable = simulate(&ours, &t).is_ok();
    eprintln!(
        "claim: (r, n-s) accepted = {malleable} (r = {:02x?}..)",
        &r_be[..4]
    );
    assert!(
        !malleable,
        "claim accepts the low-s malleability partner: an attestation is \
         NOT unique per digest, so nothing may key off it"
    );
}

/// FINDING: an identity `mpcResponseKey` authenticates ANYTHING, and
/// `initialize` does not reject one.
///
/// With `Q = O` (the point at infinity, i.e. secret key 0), ECDSA
/// verification of a signature made with `d = 0` recomputes
/// `R' = (z/s)G + (r/s)O = (z/s)G`, whose x-coordinate is `r` by
/// construction — so it verifies, and anyone can produce such a signature
/// without knowing any secret. Every settle circuit's ONLY authentication
/// gate would then be open: claim would mint on demand, refund would
/// re-mint on demand.
///
/// `initialize` validates `chainId > 0` and `swapRouter != 0` but has no
/// analogous check on `responseKey`, so this is reachable by a deployer
/// mistake (it is deployer-gated and one-shot, so not by an attacker).
/// Recorded in notes/vault-optimization.org §"As built — step 1"; the
/// test asserts the CURRENT behaviour so the day a check is added, this
/// test fails and the note gets updated.
#[test]
fn an_identity_response_key_authenticates_anything() {
    // initialize accepts it: no guard on the response key.
    let mut s = Scenario::new();
    s.point = identity_point();
    assert!(
        simulate(&erc20_vault::initialize().ir, &s.preimage(0)).is_ok(),
        "initialize rejects an identity responseKey — the gap is closed, \
         update notes/vault-optimization.org"
    );

    // ...and with it stored, a signature made under secret key 0 verifies.
    let mut c = ClaimScenario::new();
    c.key_seed = 0;
    assert!(
        simulate(&erc20_vault::claim().ir, &c.preimage()).is_ok(),
        "claim rejects an attestation under an identity response key — \
         the gap is closed, update notes/vault-optimization.org"
    );
}

// --- family 3: wrong branch ---------------------------------------------------

/// A deposit's request never gets a `refundCommitment` marker, so it can
/// never be settled through `completeWithdraw`; a settled withdrawal's
/// marker is consumed, so it can never be settled twice.
#[test]
fn settling_without_a_pending_marker_rejects() {
    let ours = erc20_vault::complete_withdraw().ir;
    let mut c = CompleteWithdrawScenario::new(1);
    c.pending = false;
    assert!(
        simulate(&ours, &c.preimage()).is_err(),
        "completeWithdraw settles a request with no pending marker"
    );

    let ours = erc20_vault::complete_swap().ir;
    let mut c = CompleteSwapScenario::new();
    c.pending = false;
    assert!(
        simulate(&ours, &c.preimage()).is_err(),
        "completeSwap settles a swap with no pending marker"
    );

    let ours = erc20_vault::claim().ir;
    let c = ClaimScenario::new();
    assert!(
        simulate(&ours, &c.preimage_with_member(0)).is_err(),
        "claim settles a request that is not in the map"
    );
}

/// THE case the `run_program` link exists for.
///
/// A membership answer is a `Popeq` result: the circuit takes the prover's
/// word for it, and a prover who claims a pending marker exists when it
/// does not gets a perfectly valid PROOF. Only the ledger catches it —
/// `ResultModeVerify::process_read` compares every read against the real
/// state and refuses with `ReadMismatch`. Before M10 nothing in this
/// repository executed an op stream, so this defence was untested.
#[test]
fn a_forged_membership_answer_passes_the_circuit_and_fails_the_ledger() {
    let ours = erc20_vault::complete_withdraw().ir;
    let c = CompleteWithdrawScenario::new(1);
    // The transcript claims the marker is present...
    assert!(c.pending);
    assert!(simulate(&ours, &c.preimage()).is_ok());
    // ...but the ledger state does not hold it.
    let mut pre = c.pre_state();
    pre.refund_commitment.clear();
    let err = exec::run(&pre, &c.w.self_addr, &c.ops())
        .expect_err("the ledger accepted a forged membership answer");
    assert!(
        err.contains("ReadMismatch"),
        "expected a read mismatch, got: {err}"
    );
}

/// `refund` settles only the protocol's fixed 5-byte failure sentinel. A
/// success-shaped 5-byte output must not route a refund — otherwise an
/// executed withdrawal could be refunded as well as delivered.
#[test]
fn refund_rejects_success_shaped_outputs() {
    let ours = erc20_vault::refund().ir;
    for output in [
        [0u8, 0, 0, 0, 1],
        [0xde, 0xad, 0xbe, 0xef, 0x00],
        [0xde, 0xad, 0xbe, 0xee, 0x01],
        [0u8; 5],
    ] {
        let mut r = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
        r.serialized_output = output;
        assert!(
            simulate(&ours, &r.preimage()).is_err(),
            "refund accepts a non-sentinel output {output:02x?}"
        );
    }
}

/// The two pending-marker maps are disjoint by construction, so routing is
/// unambiguous: an id present in BOTH still takes the withdrawal route,
/// because `refund` branches on `refundCommitment.member` alone.
#[test]
fn refund_routes_on_the_withdrawal_marker_even_when_both_are_set() {
    let ours = erc20_vault::refund().ir;
    let mut r = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    r.also_other_marker = true;
    let outcome = spec::spec_refund(&r);
    assert!(outcome.accepts());
    assert!(simulate(&ours, &r.preimage()).is_ok());
    let ex = exec::run(&r.pre_state(), &r.self_addr(), &r.ops()).expect("the ledger accepts");
    spec::check_effects(outcome.effects(), &r.pre_state(), &ex).expect("effects agree");
}

// --- family 4: re-mapping injectivity ----------------------------------------

/// The security property that changes when a hash construction changes.
///
/// The spec's `Term`s are mapped to bytes by [`Term::concretize`]. If two
/// DISTINCT terms ever concretise to the same 32 bytes, the two values
/// they name become interchangeable on chain — a depositor's commitment
/// could be a refund commitment, a domain separator could be a request id.
/// For the compat artifact the map is SHA-256 and keccak, so this is
/// SHA-injectivity on the generated corpus; for the optimized artifact it
/// is whatever that artifact's concretization is. The sweep is written
/// against `concretize`, so it transfers unchanged.
fn injectivity_over(terms: Vec<Term>) -> Result<usize, String> {
    let mut seen: HashMap<[u8; 32], Term> = HashMap::new();
    for t in terms {
        let bytes = t.concretize();
        // Determinism first: the same term must always concretise the same.
        if t.concretize() != bytes {
            return Err(format!("concretization is not deterministic for {t:?}"));
        }
        match seen.get(&bytes) {
            Some(prev) if *prev != t => {
                return Err(format!("collision: {prev:?} and {t:?} share {bytes:02x?}"))
            }
            _ => {
                seen.insert(bytes, t);
            }
        }
    }
    Ok(seen.len())
}

/// Every derived term one generated case produces.
fn terms_of(w: &WithdrawScenario, d: &DepositScenario, mint_nonce: [u8; 32]) -> Vec<Term> {
    let rid_w = Term::RequestId {
        record: w.event_av(),
    };
    let rid_d = Term::RequestId {
        record: d.event_av(),
    };
    let sep_w = Term::DomainSep { erc20: w.erc20 };
    let sep_d = Term::DomainSep { erc20: d.erc20 };
    let color = Term::TokenType {
        sep: Box::new(sep_w.clone()),
        addr: w.self_addr,
    };
    vec![
        Term::UserCommit { sk: w.sk },
        Term::UserCommit { sk: d.sk },
        Term::RefundCommit {
            sk: w.sk,
            request_id: Box::new(rid_w.clone()),
        },
        Term::RefundCommit {
            sk: d.sk,
            request_id: Box::new(rid_d.clone()),
        },
        sep_w,
        sep_d,
        rid_w,
        rid_d,
        color.clone(),
        Term::ChangeNonce {
            mint_nonce: Box::new(Term::c(mint_nonce)),
        },
        Term::CoinCm {
            nonce: Box::new(Term::c(mint_nonce)),
            color: Box::new(color.clone()),
            value: w.amount_u64(),
            is_left: true,
            data: [0u8; 32],
        },
        Term::CoinNul {
            nonce: Box::new(Term::c(mint_nonce)),
            color: Box::new(color),
            value: w.amount_u64(),
            addr: w.self_addr,
        },
        Term::EvolvedNonce {
            nonce: Box::new(Term::c(mint_nonce)),
        },
    ]
}

proptest! {
    #![proptest_config(gen::config())]

    /// The concretization is injective on everything generation produces.
    #[test]
    fn concretization_is_injective(
        w in gen::withdraw(),
        d in gen::deposit(),
        nonce in any::<[u8; 31]>(),
    ) {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..31].copy_from_slice(&nonce);
        let terms = terms_of(&w, &d, mint_nonce);
        let n = terms.len();
        // `Term` holds an `AlignedValue` and is only `Eq`, so distinctness
        // is counted the quadratic way — n is 13.
        let mut distinct: Vec<Term> = Vec::new();
        for t in &terms {
            if !distinct.contains(t) {
                distinct.push(t.clone());
            }
        }
        let want = distinct.len();
        let got = injectivity_over(terms);
        prop_assert!(got.is_ok(), "{:?}", got);
        prop_assert_eq!(got.unwrap(), want, "term count {}", n);
    }
}

// --- completeSwap's underflow boundary ----------------------------------------
//
// notes/vault-optimization.org: "completeSwap's amountInMaximum - amountIn
// subtraction is the most dangerous arithmetic in the contract". A wrapped
// subtraction would mint a ~2^128 change coin of tokenIn out of nothing —
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
    let ours = erc20_vault::complete_swap().ir;
    let outcome = spec::spec_complete_swap(c);
    assert_eq!(outcome.accepts(), want_accept, "spec disagrees: {why}");
    let accepted = simulate(&ours, &c.preimage()).is_ok();
    assert_eq!(accepted, want_accept, "circuit disagrees: {why}");
    if want_accept {
        let ex = exec::run(&c.pre_state(), &c.s.self_addr, &c.ops()).expect("the ledger accepts");
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
    assert_complete_swap(
        &complete_swap_at(99_999, 99_998),
        true,
        "amountIn == amountInMaximum - 1: change 1",
    );
}

#[test]
fn complete_swap_change_underflows_one_above_the_cap() {
    assert_complete_swap(
        &complete_swap_at(99_999, 100_000),
        false,
        "amountIn == amountInMaximum + 1 MUST reject",
    );
}

#[test]
fn complete_swap_change_underflows_at_u64_max() {
    assert_complete_swap(
        &complete_swap_at(1, u64::MAX),
        false,
        "amountIn == u64::MAX against amountInMaximum 1 MUST reject",
    );
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
    assert_complete_swap(
        &complete_swap_at(u128::from(max), max),
        true,
        "cap u64::MAX, spend u64::MAX: change 0",
    );
    assert_complete_swap(
        &complete_swap_at(u128::from(max), 0),
        true,
        "cap u64::MAX, spend 0: change u64::MAX",
    );
    assert_complete_swap(
        &complete_swap_at(u128::from(max) - 1, max),
        false,
        "cap u64::MAX - 1, spend u64::MAX MUST reject",
    );
}
