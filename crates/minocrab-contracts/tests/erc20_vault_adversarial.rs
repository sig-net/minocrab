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
//!
//! Since M10 step 4 every sweep runs against BOTH artifacts. The compat
//! side keeps its corpus comparisons (acceptance AGREEMENT with compactc);
//! the optimized side is swept for SOUNDNESS alone, because once a circuit
//! diverges compactc has no opinion about it — that is precisely what
//! these sweeps have to replace.

use std::collections::HashMap;

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_contracts::{erc20_vault, erc20_vault_pending};
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use proptest::prelude::*;

mod vault;

use vault::artifact::{Art, Circuit, ARTS};
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
    // The compat side, against the corpus: soundness AND agreement.
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
    for art in ARTS {
        let ours = Circuit::Claim.ir(art);
        let c = ClaimScenario::new().with_art(art);
        let pi = c.preimage();
        for i in 0..pi.inputs.len() {
            let mut t = pi.clone();
            t.inputs[i] = t.inputs[i] + Fr::from(1u64);
            assert!(
                simulate(&ours, &t).is_err(),
                "{art:?}: claim accepts a perturbed argument {i}"
            );
        }
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
    //
    // Under `Art::Borsh` the attested output is TWO declared slots (9 kind,
    // 10 success) rather than one opaque byte, so every slot from mintNonce
    // on shifts by one — the only interface movement M11 stage 5 makes, and
    // the interface snapshot carries it too.
    let slot = |art: Art, i: usize| if art.is_borsh_format() && i >= 10 { i + 1 } else { i };
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
    for art in ARTS {
        let ours = Circuit::Claim.ir(art);
        for (name, recipient, unread) in &cases {
            let unread: Vec<usize> = unread.iter().map(|&i| slot(art, i)).collect();
            let mut c = ClaimScenario::new().with_art(art);
            c.recipient = *recipient;
            let pi = c.preimage();
            for i in 0..pi.inputs.len() {
                let v = pi.inputs[i] + Fr::from(1u64);
                let accepted = tamper::accepts_with_rebound_input(&ours, &pi, i, v);
                assert_eq!(
                    accepted,
                    unread.contains(&i),
                    "{art:?}/{name}: argument {i} accepted = {accepted}, expected unread = {}",
                    unread.contains(&i)
                );
            }
        }
    }
}

// --- family 2: witness malleability ------------------------------------------

/// A `Bytes<32>` witness is two limbs, `[hi = byte 31, lo = bytes 0..31]`,
/// range-constrained to 8 and 248 bits. Out-of-range limbs must reject:
/// without the bound, two different secrets could share a commitment.
#[test]
fn secret_key_limbs_out_of_range_reject() {
    for art in ARTS {
        let ours = Circuit::Claim.ir(art);
        let c = ClaimScenario::new().with_art(art);
        let pi = c.preimage();
        // hi is a single byte.
        for v in [256u64, 257, 1 << 32] {
            assert!(
                !tamper::accepts_with(&ours, &pi, Part::Witness, 0, Fr::from(v)),
                "{art:?}: claim accepts an out-of-range sk hi limb ({v})"
            );
        }
        // lo is 248 bits, so the all-ones 31-byte limb is the largest legal
        // value; one more must not fit.
        let big = Fr::from_le_bytes(&[0xffu8; 31]).unwrap() + Fr::from(1u64);
        assert!(
            !tamper::accepts_with(&ours, &pi, Part::Witness, 1, big),
            "{art:?}: claim accepts an out-of-range sk lo limb"
        );
    }
}

/// `recoveryId` is declared and `constrain_bits`-ed to 8 bits but never
/// read. Garbage IN RANGE is therefore accepted (it is genuinely unused);
/// garbage OUT of range must still reject, because the range constraint is
/// what makes the argument's on-chain rendering canonical.
#[test]
fn recovery_id_garbage_is_range_bound_but_unread() {
    for art in ARTS {
        let ours = Circuit::Claim.ir(art);
        let c = ClaimScenario::new().with_art(art);
        let pi = c.preimage();
        for v in [0u64, 1, 27, 28, 255] {
            assert!(
                tamper::accepts_with_rebound_input(&ours, &pi, 8, Fr::from(v)),
                "{art:?}: claim rejects an in-range recoveryId ({v}) it never reads"
            );
        }
        for v in [256u64, 1 << 20] {
            assert!(
                !tamper::accepts_with_rebound_input(&ours, &pi, 8, Fr::from(v)),
                "{art:?}: claim accepts an out-of-range recoveryId ({v})"
            );
        }
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
    for art in ARTS {
        let cases: Vec<(&str, IrSource, ProofPreimage)> = vec![
            (
                "claim",
                Circuit::Claim.ir(art),
                ClaimScenario::new().with_art(art).preimage(),
            ),
            (
                "completeWithdraw",
                Circuit::CompleteWithdraw.ir(art),
                CompleteWithdrawScenario::new(1).with_art(art).preimage(),
            ),
            (
                "completeSwap",
                Circuit::CompleteSwap.ir(art),
                CompleteSwapScenario::new().with_art(art).preimage(),
            ),
            (
                "refund",
                Circuit::Refund.ir(art),
                RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()))
                    .with_art(art)
                    .preimage(),
            ),
        ];
        for (name, ir, pi) in cases {
            // s is inputs[6] (hi) and inputs[7] (lo); zero both.
            let mut t = pi.clone();
            t.inputs[6] = Fr::from(0u64);
            t.inputs[7] = Fr::from(0u64);
            let err = simulate(&ir, &t).err();
            assert!(err.is_some(), "{art:?}/{name} accepts s = 0");
            // And it must not be an ordinary "assert failed": the inversion
            // itself is what refuses. Recorded rather than asserted on the
            // message text, which is not a stable interface.
            eprintln!("{art:?}/{name}: s = 0 -> {}", err.unwrap());
        }
    }
}

/// `r` and `s` are read out of the attestation as big-endian `Bytes<32>`
/// and cast to secp256k1 scalars. Values at or above the group order must
/// not verify, and the canonical malleability partner `n - s` must not
/// verify either — otherwise a second, different attestation exists for
/// every signed digest.
#[test]
fn signature_scalars_above_the_order_reject() {
    for art in ARTS {
        signature_scalars_above_the_order_reject_for(art);
    }
}

fn signature_scalars_above_the_order_reject_for(art: Art) {
    let ours = Circuit::Claim.ir(art);
    let c = ClaimScenario::new().with_art(art);
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
        "{art:?}: claim accepts s = n"
    );
    assert!(
        !{
            let mut t = pi.clone();
            t.inputs[2] = n_slots.0;
            t.inputs[3] = n_slots.1;
            simulate(&ours, &t).is_ok()
        },
        "{art:?}: claim accepts r = n"
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
        "{art:?}/claim: (r, n-s) accepted = {malleable} (r = {:02x?}..)",
        &r_be[..4]
    );
    assert!(
        !malleable,
        "{art:?}: claim accepts the low-s malleability partner: an \
         attestation is NOT unique per digest, so nothing may key off it"
    );
}

/// FINDING: an identity `mpcResponseKey` authenticates ANYTHING — and
/// compactc's `initialize` does not reject one; ours does, on the three
/// optimised lineages.
///
/// With `Q = O` (the point at infinity, i.e. secret key 0), ECDSA
/// verification of a signature made with `d = 0` recomputes
/// `R' = (z/s)G + (r/s)O = (z/s)G`, whose x-coordinate is `r` by
/// construction — so it verifies, and anyone can produce such a signature
/// without knowing any secret. Every settle circuit's ONLY authentication
/// gate would then be open: claim would mint on demand, refund would
/// re-mint on demand.
///
/// compactc's `initialize` validates `chainId > 0` and `swapRouter != 0`
/// but has no analogous check on `responseKey`, so on the PORT this is
/// reachable by a deployer mistake (deployer-gated and one-shot, so not
/// by an attacker) — kept, for parity, and pinned here. The opt / borsh /
/// modern lineages extract the key's coordinates in `initialize`, which
/// the identity has none of: the prover cannot build the preimage
/// (external review §4.5, review-fixes). Recorded in
/// notes/vault-optimization.org §"As built — step 1".
#[test]
fn an_identity_response_key_authenticates_anything() {
    for art in ARTS {
        let mut s = Scenario::new().with_art(art);
        s.point = identity_point();
        let accepted = simulate(&Circuit::Initialize.ir(art), &s.preimage(0)).is_ok();
        match art {
            Art::Compat => assert!(
                accepted,
                "the port's initialize must keep compactc's shape (no identity check)"
            ),
            _ => assert!(
                !accepted,
                "{art:?}: initialize must reject an identity responseKey — \
                 into_coordinates has no answer for it"
            ),
        }

        // ...and with it STORED (the scenario writes the state directly, so
        // this holds on every lineage), a signature under secret key 0
        // verifies: the settle circuits trust whatever key is stored.
        let mut c = ClaimScenario::new().with_art(art);
        c.key_seed = 0;
        assert!(
            simulate(&Circuit::Claim.ir(art), &c.preimage()).is_ok(),
            "{art:?}: claim rejects an attestation under an identity response \
             key — the gap is closed, update notes/vault-optimization.org"
        );
    }
}

// --- family 3: wrong branch ---------------------------------------------------

/// A deposit's request never gets a `refundCommitment` marker, so it can
/// never be settled through `completeWithdraw`; a settled withdrawal's
/// marker is consumed, so it can never be settled twice.
#[test]
fn settling_without_a_pending_marker_rejects() {
    for art in ARTS {
        let ours = Circuit::CompleteWithdraw.ir(art);
        let mut c = CompleteWithdrawScenario::new(1).with_art(art);
        c.pending = false;
        assert!(
            simulate(&ours, &c.preimage()).is_err(),
            "{art:?}: completeWithdraw settles a request with no pending marker"
        );

        let ours = Circuit::CompleteSwap.ir(art);
        let mut c = CompleteSwapScenario::new().with_art(art);
        c.pending = false;
        assert!(
            simulate(&ours, &c.preimage()).is_err(),
            "{art:?}: completeSwap settles a swap with no pending marker"
        );

        let ours = Circuit::Claim.ir(art);
        let c = ClaimScenario::new().with_art(art);
        assert!(
            simulate(&ours, &c.preimage_with_member(0)).is_err(),
            "{art:?}: claim settles a request that is not in the map"
        );
    }
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
    for art in ARTS {
        let ours = Circuit::CompleteWithdraw.ir(art);
        let c = CompleteWithdrawScenario::new(1).with_art(art);
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
            "{art:?}: expected a read mismatch, got: {err}"
        );
    }
}

/// `refund` settles only the response that says "the transaction never
/// executed". A success-shaped response must not route a refund — otherwise
/// an executed withdrawal could be refunded as well as delivered.
///
/// Each case is that statement in BOTH encodings: the deployed 5-byte output
/// that is not the `0xdeadbeef01` sentinel, and (M11 stage 5) the response
/// KIND that is not the failure kind — including a byte that is no declared
/// kind at all.
#[test]
fn refund_rejects_success_shaped_outputs() {
    for art in ARTS {
        let ours = Circuit::Refund.ir(art);
        for (output, response_kind) in [
            ([0u8, 0, 0, 0, 1], erc20_vault_pending::RESPONSE_KIND_CLAIM),
            (
                [0xde, 0xad, 0xbe, 0xef, 0x00],
                erc20_vault_pending::RESPONSE_KIND_WITHDRAW,
            ),
            (
                [0xde, 0xad, 0xbe, 0xee, 0x01],
                erc20_vault_pending::RESPONSE_KIND_SWAP,
            ),
            ([0u8; 5], 255),
        ] {
            let mut r = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()))
                .with_art(art);
            r.serialized_output = output;
            r.response_kind = u8::try_from(response_kind).expect("a kind is one byte");
            assert!(
                simulate(&ours, &r.preimage()).is_err(),
                "{art:?}: refund accepts a non-failure response \
                 (bytes {output:02x?}, kind {response_kind})"
            );
        }
    }
}

/// The two pending-marker maps are disjoint by construction, so routing is
/// unambiguous: an id present in BOTH still takes the withdrawal route,
/// because `refund` branches on `refundCommitment.member` alone.
#[test]
fn refund_routes_on_the_withdrawal_marker_even_when_both_are_set() {
    for art in ARTS {
        let ours = Circuit::Refund.ir(art);
        let mut r =
            RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new())).with_art(art);
        r.also_other_marker = true;
        let outcome = spec::spec_refund(&r);
        assert!(outcome.accepts(), "{art:?}: the spec rejects");
        if let Err(e) = simulate(&ours, &r.preimage()) {
            panic!("{art:?}: the circuit rejects: {e}");
        }
        let ex = exec::run(&r.pre_state(), &r.self_addr(), &r.ops()).expect("the ledger accepts");
        spec::check_effects(art, outcome.effects(), &r.pre_state(), &ex).expect("effects agree");
    }
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
fn injectivity_over(art: Art, terms: Vec<Term>) -> Result<usize, String> {
    let mut seen: HashMap<[u8; 32], Term> = HashMap::new();
    for t in terms {
        let bytes = t.concretize(art);
        // Determinism first: the same term must always concretise the same.
        if t.concretize(art) != bytes {
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

    /// Rung (iii)'s domain separator, checked as what it now is — a LAYOUT.
    ///
    /// The port's separator was a SHA-256 and its injectivity was a
    /// collision-resistance assumption. The optimized one is an encoding,
    /// so injectivity is a property of the bytes and can simply be
    /// asserted: the ERC-20 address appears verbatim, the tag byte is
    /// where the documentation says, nothing else is set, and two
    /// separators are equal exactly when their addresses are. Also pinned:
    /// the layout the doc comment tabulates, so prose and code cannot
    /// drift.
    #[test]
    fn the_optimized_domain_separator_is_an_injective_encoding(
        a in any::<[u8; 20]>(),
        b in any::<[u8; 20]>(),
    ) {
        let sep = vault_domain_sep(Art::Opt, &a);
        prop_assert_eq!(&sep[..20], &a[..], "bytes 0..19 are the address");
        prop_assert!(sep[20..31].iter().all(|&x| x == 0), "bytes 20..30 are zero");
        prop_assert_eq!(
            sep[31],
            minocrab_contracts::erc20_vault_pending::VAULT_TOKEN_TAG,
            "byte 31 is the kind tag"
        );
        // Injective, both directions.
        prop_assert_eq!(sep == vault_domain_sep(Art::Opt, &b), a == b);
        // And it is a different construction from the port's, which is the
        // whole reason the optimized vault's tokens are its own colour.
        prop_assert_ne!(sep, vault_domain_sep(Art::Compat, &a));
    }

    /// The concretization is injective on everything generation produces.
    #[test]
    fn concretization_is_injective(
        w in gen::withdraw(),
        d in gen::deposit(),
        nonce in any::<[u8; 31]>(),
    ) {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..31].copy_from_slice(&nonce);
        for art in ARTS {
            let w = w.clone().with_art(art);
            let d = d.clone().with_art(art);
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
            let got = injectivity_over(art, terms);
            prop_assert!(got.is_ok(), "{:?}: {:?}", art, got);
            prop_assert_eq!(got.unwrap(), want, "term count {}", n);
        }
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
    for art in ARTS {
        let c = c.clone().with_art(art);
        let ours = Circuit::CompleteSwap.ir(art);
        let outcome = spec::spec_complete_swap(&c);
        assert_eq!(outcome.accepts(), want_accept, "{art:?}: spec disagrees: {why}");
        let accepted = simulate(&ours, &c.preimage()).is_ok();
        assert_eq!(accepted, want_accept, "{art:?}: circuit disagrees: {why}");
        if want_accept {
            let ex =
                exec::run(&c.pre_state(), &c.s.self_addr, &c.ops()).expect("the ledger accepts");
            spec::check_effects(art, outcome.effects(), &c.pre_state(), &ex)
                .expect("effects agree");
        }
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

// --- family 6: the response KIND, and the bool that closes 0x02 ---------------
//
// M11 stage 5. Both properties are about the borsh artifact ONLY, because the
// port and the optimized fork have no kind byte and no `bool` — which is
// exactly the point: these are the two things the format buys, and each test
// says what the other artifacts do instead.

/// CROSS-CIRCUIT ATTESTATION REPLAY IS STRUCTURALLY IMPOSSIBLE.
///
/// THE DELIBERATE DIVERGENCE (deviation D6), pinned in both directions.
///
/// The deployed `completeWithdraw` reads its attested output as `byte == 1`,
/// so `0x02` — or any byte but `0x01` — routes to the REFUND branch and
/// re-mints the surrendered value on a withdrawal that SUCCEEDED. The port and
/// the optimized fork therefore ACCEPT such an attestation and refund on it;
/// the borsh artifact declares the field a Borsh `bool`, whose canonical
/// encoding is 0 or 1 and nothing else, so `assert_boolean` makes the same
/// transaction UNPROVABLE.
///
/// This is the one input on which the three artifacts genuinely disagree, so
/// the harness states it as a test rather than leaving it to a note: the
/// intentional divergence is a checked fact, and an artifact that silently
/// stopped diverging would fail here.
#[test]
fn a_non_boolean_success_byte_refunds_on_the_port_and_is_unprovable_in_borsh() {
    for outcome in [2u8, 3, 0x80, 0xff] {
        for art in ARTS {
            let c = CompleteWithdrawScenario::new(outcome).with_art(art);
            let accepted = simulate(&Circuit::CompleteWithdraw.ir(art), &c.preimage()).is_ok();
            match art {
                Art::Compat | Art::Opt => assert!(
                    accepted,
                    "{art:?}: the deployed semantics REFUND on a non-boolean \
                     success byte {outcome:#04x} — if that has stopped being \
                     true, the M10 finding has been fixed somewhere it should \
                     not have been"
                ),
                Art::Borsh | Art::Modern => assert!(
                    !accepted,
                    "{art:?}: a non-boolean success byte {outcome:#04x} must be \
                     unprovable — that is what declaring the field a Borsh bool buys"
                ),
            }
            // The spec agrees, which is what makes the divergence a modelled
            // one rather than an accident of the circuit.
            assert_eq!(
                spec::spec_complete_withdraw(&c).accepts(),
                accepted,
                "{art:?}: spec and circuit disagree on success byte {outcome:#04x}"
            );
        }
    }
}
