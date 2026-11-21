//! Every gadget this crate copied from `minocrab_std` is checked against
//! std's own, on the same inputs, both at top level and inside a `when` (the
//! manager calls several of them under a guard).
//!
//! Two strengths of check. Where std's gadget is still compactc's shape the
//! two emit the IDENTICAL ZKIR (the `pin_*` tests; M48 C step 1 copied them).
//! Where std's has gone lean (M48 C step 3) they cannot, and they are held to
//! EQUIVALENT BEHAVIOUR instead (the `agree_*` tests): each side is built in
//! the same harness, both are run on the same inputs through the executor
//! (`minocrab_sim::v3::exec`, which settles the transcript against Midnight's
//! on-chain VM and replays it in `ResultModeVerify`), and they must agree on
//! accept or reject (and on which side refused: the circuit or the ledger),
//! and on acceptance on the whole preimage (the transcript in and out, which
//! is what the ledger sees), the public-input vector, the returned values, the
//! call's effects and the post-state; each accepted preimage is also checked
//! by upstream's own `IrSource::check`.

use minocrab::v3::{Circuit3, FieldT, Secp256k1PointT, Secp256k1ScalarT, Wire3};
use minocrab::{Private, Public};
use minocrab_compat::{kernel as compat_kernel, merkle, secp as compat_secp};
use minocrab_std::v3::kernel::{self as std_kernel, UnshieldedRecipient};
use minocrab_std::v3::{
    Bool, CoinColor, CoinNonce, CoinRecipient, ContractAddress, Either, LedgerHistoricMerkleTree,
    LedgerMerkleTree, QualifiedShieldedCoinInfo3, Secp256k1EcdsaSignature, ShieldedCoinInfo3,
    TokenDomainSeparator, Uint, UserAddress, ZswapCoinPublicKey, B32,
};
use minocrab_zkir::v3::to_zkir_string;

use midnight_onchain_state::state::StateValue;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::Array;
use minocrab::v3::Compiled3;
use minocrab::Fr;
use midnight_transient_crypto::proofs::Zkir;
use minocrab_sim::v3::exec::{self, Call, ExecError, Executed};

/// The circuit `f` builds, serialized.
fn build(f: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    f(&mut c);
    to_zkir_string(&c.finish(true).ir).expect("IR serializes")
}

/// The circuit `f` builds, finished without a communications commitment (so
/// a call needs no randomness), for running.
fn compile(f: impl FnOnce(&mut Circuit3)) -> Compiled3 {
    let mut c = Circuit3::new();
    f(&mut c);
    c.finish(false)
}

/// The contract address every run executes as: `kernel.self()`.
const SELF: [u8; 32] = [0x5e; 32];

/// How a run ended, as an observer of the call can tell.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accepted,
    /// The circuit refused: an assert failed, or a value was not of its
    /// type (a selector that is not a bit, say).
    CircuitRefused,
    /// The circuit was satisfied but the ledger would not apply the
    /// transcript.
    LedgerRefused,
}

fn verdict(r: &Result<Executed, ExecError>) -> Verdict {
    match r {
        Ok(_) => Verdict::Accepted,
        Err(ExecError::Rejected { .. } | ExecError::Circuit(_)) => Verdict::CircuitRefused,
        Err(ExecError::Vm(_) | ExecError::NotApplied { .. }) => Verdict::LedgerRefused,
        Err(other) => panic!("a harness failure, not a verdict: {other}"),
    }
}

/// Run both circuits on `inputs` against `state` and require that they
/// agree on everything the module doc lists. Returns the verdict.
fn agree(what: &str, lean: &Compiled3, twin: &Compiled3, state: &StateValue<InMemoryDB>, inputs: &[Fr]) -> Verdict {
    let run = |compiled: &Compiled3| {
        let ctx = exec::context(state.clone(), SELF);
        exec::execute(&compiled.ir, &Call::new(inputs, &[]), &ctx)
    };
    let (a, b) = (run(lean), run(twin));
    let v = verdict(&a);
    assert_eq!(v, verdict(&b), "{what} {inputs:?}: verdicts differ\nlean: {:?}\ncompat: {:?}", a.as_ref().err(), b.as_ref().err());
    if let (Ok(a), Ok(b)) = (a, b) {
        assert_eq!(a.preimage.inputs, b.preimage.inputs, "{what}: inputs");
        assert_eq!(a.preimage.public_transcript_inputs, b.preimage.public_transcript_inputs, "{what} {inputs:?}: transcript (Impact program)");
        assert_eq!(a.preimage.public_transcript_outputs, b.preimage.public_transcript_outputs, "{what} {inputs:?}: transcript (read results)");
        assert_eq!(a.run.pis, b.run.pis, "{what} {inputs:?}: public-input vector");
        assert_eq!(a.run.pi_skips, b.run.pi_skips, "{what} {inputs:?}: guarded-off Impact blocks");
        assert_eq!(a.run.outputs, b.run.outputs, "{what} {inputs:?}: returned values");
        assert!(a.effects == b.effects, "{what} {inputs:?}: effects");
        assert!(a.post == b.post, "{what} {inputs:?}: post-state");
        lean.ir.check(&a.preimage).unwrap_or_else(|e| panic!("{what}: upstream refuses the lean preimage: {e:?}"));
        twin.ir.check(&b.preimage).unwrap_or_else(|e| panic!("{what}: upstream refuses the compat preimage: {e:?}"));
    }
    v
}

/// Twenty public field wires: arguments first (ZKIR wants every input before
/// every instruction), then disclosed.
fn inputs(c: &mut Circuit3) -> Vec<Wire3<FieldT, Public>> {
    let args: Vec<Wire3<FieldT, Private>> = (0..20).map(|i| c.arg::<FieldT>(&format!("x{i}"))).collect();
    args.into_iter().enumerate().map(|(i, w)| c.disclose(w, &format!("x{i}"))).collect()
}

fn b32(w: &[Wire3<FieldT, Public>], at: usize) -> B32<Public> {
    B32 { hi: w[at], lo: w[at + 1] }
}

fn u64_(w: Wire3<FieldT, Public>) -> Uint<64, Public> {
    Uint::from_field_unchecked(w)
}

fn u128_(w: Wire3<FieldT, Public>) -> Uint<128, Public> {
    Uint::from_field_unchecked(w)
}

fn recipient(w: &[Wire3<FieldT, Public>]) -> UnshieldedRecipient<Public> {
    Either {
        is_left: Bool::from_field_unchecked(w[10]),
        left: ContractAddress::from_limbs([w[11], w[12]]),
        right: UserAddress::from_limbs([w[13], w[14]]),
    }
}

fn coin_recipient(w: &[Wire3<FieldT, Public>]) -> CoinRecipient<Public> {
    CoinRecipient {
        is_left: w[10],
        left: ZswapCoinPublicKey(b32(w, 11)),
        right: ContractAddress::from_limbs([w[13], w[14]]),
    }
}

fn qualified(w: &[Wire3<FieldT, Public>], at: usize) -> QualifiedShieldedCoinInfo3<Public> {
    QualifiedShieldedCoinInfo3 {
        nonce: CoinNonce(b32(w, at)),
        color: CoinColor(b32(w, at + 2)),
        value: w[at + 4],
        mt_index: w[at + 5],
    }
}

fn coin(w: &[Wire3<FieldT, Public>], at: usize) -> ShieldedCoinInfo3<Public> {
    ShieldedCoinInfo3 { nonce: CoinNonce(b32(w, at)), color: CoinColor(b32(w, at + 2)), value: w[at + 4] }
}

/// One test per kernel gadget: `$call` is written once against a module
/// alias `k`, and run with `k` bound to std's kernel and then to compat's,
/// at top level and under a guard.
macro_rules! pin_kernel {
    ($test:ident, |$c:ident, $w:ident, $k:ident| $call:expr) => {
        #[test]
        fn $test() {
            for guarded in [false, true] {
                let run = |use_compat: bool| {
                    build(|$c| {
                        let $w = inputs($c);
                        let g = $w[19];
                        let body = |$c: &mut Circuit3| {
                            if use_compat {
                                use compat_kernel as $k;
                                let _ = $call;
                            } else {
                                use std_kernel as $k;
                                let _ = $call;
                            }
                        };
                        if guarded {
                            let _ = $c.when(g, body);
                        } else {
                            body($c);
                        }
                    })
                };
                assert_eq!(run(false), run(true), "{} (guarded: {guarded})", stringify!($test));
            }
        }
    };
}

pin_kernel!(block_time_lt, |c, w, k| k::block_time_lt(c, u64_(w[0])));
pin_kernel!(block_time_gte, |c, w, k| k::block_time_gte(c, u64_(w[0])));
pin_kernel!(block_time_gt, |c, w, k| k::block_time_gt(c, u64_(w[0])));
pin_kernel!(block_time_lte, |c, w, k| k::block_time_lte(c, u64_(w[0])));
pin_kernel!(unshielded_balance, |c, w, k| k::unshielded_balance(c, CoinColor(b32(&w, 0))));
pin_kernel!(unshielded_balance_lt, |c, w, k| k::unshielded_balance_lt(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(unshielded_balance_gte, |c, w, k| k::unshielded_balance_gte(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(unshielded_balance_gt, |c, w, k| k::unshielded_balance_gt(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(unshielded_balance_lte, |c, w, k| k::unshielded_balance_lte(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(receive_unshielded, |c, w, k| k::receive_unshielded(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(send_unshielded, |c, w, k| k::send_unshielded(c, CoinColor(b32(&w, 0)), u128_(w[2]), &recipient(&w)));
pin_kernel!(mint_unshielded_token, |c, w, k| k::mint_unshielded_token(
    c,
    &TokenDomainSeparator(b32(&w, 0)),
    u64_(w[2]),
    &recipient(&w)
));
pin_kernel!(merge_coin, |c, w, k| k::merge_coin(c, &qualified(&w, 0), &qualified(&w, 6)));
pin_kernel!(merge_coin_immediate, |c, w, k| k::merge_coin_immediate(c, &qualified(&w, 0), &coin(&w, 6)));
pin_kernel!(send_shielded, |c, w, k| k::send_shielded(c, &qualified(&w, 0), &coin_recipient(&w), u128_(w[6])));

/// `insertIndexDefault` on both tree types, for a one-limb and a two-limb
/// leaf: compat's free function (the default leaf hashed in circuit) and
/// std's method (the digest folded at build time). Run on the VM from blank
/// trees: the same transcript and the same trees after, at every index in
/// range and refused alike past the end, at top level and under a guard
/// either way.
#[test]
fn agree_insert_index_default() {
    const MT: LedgerMerkleTree<4, B32<Public>> = LedgerMerkleTree::at(0);
    const HMT: LedgerHistoricMerkleTree<6, Uint<64, Public>> = LedgerHistoricMerkleTree::at(1);
    let side = |use_compat: bool| {
        compile(move |c| {
            let w = inputs(c);
            MT.reset_to_default(c);
            HMT.reset_to_default(c);
            if use_compat {
                merkle::insert_index_default(c, &MT, u64_(w[0]));
                merkle::insert_index_default(c, &HMT, u64_(w[1]));
                let _ = c.when(w[19], |c| merkle::insert_index_default(c, &MT, u64_(w[2])));
            } else {
                MT.insert_index_default(c, u64_(w[0]));
                HMT.insert_index_default(c, u64_(w[1]));
                let _ = c.when(w[19], |c| MT.insert_index_default(c, u64_(w[2])));
            }
        })
    };
    let (lean, twin) = (side(false), side(true));
    let blank = StateValue::Array(Array::from(vec![StateValue::Null, StateValue::Null]));
    let mut seen = Vec::new();
    for (mt, hmt, guarded_mt, guard) in [(0, 0, 0, 0), (3, 5, 7, 1), (15, 63, 15, 1), (15, 63, 16, 0), (16, 0, 0, 0), (0, 64, 0, 0), (2, 2, 16, 1)] {
        let mut args = vec![Fr::from(0u64); 20];
        args[0] = Fr::from(mt);
        args[1] = Fr::from(hmt);
        args[2] = Fr::from(guarded_mt);
        args[19] = Fr::from(guard);
        seen.push(agree("insert_index_default", &lean, &twin, &blank, &args));
    }
    assert!(seen.contains(&Verdict::Accepted) && seen.iter().any(|v| *v != Verdict::Accepted), "both verdicts covered: {seen:?}");

    // The fold is the whole saving: the lean side hashes nothing in circuit.
    let hashes = |c: &Compiled3| c.ir.instructions.iter().filter(|i| format!("{i:?}").starts_with("PersistentHash")).count();
    assert_eq!((hashes(&lean), hashes(&twin)), (0, 3));
}

/// `secp256k1EcdsaVerify`, private operands (the attest port's) and public.
#[test]
fn secp256k1_ecdsa_verify() {
    let private = |use_compat: bool| {
        build(|c| {
            let hi = c.arg::<FieldT>("msgHash_hi");
            let lo = c.arg::<FieldT>("msgHash_lo");
            let r = c.arg::<Secp256k1ScalarT>("r");
            let s = c.arg::<Secp256k1ScalarT>("s");
            let pk = c.arg::<Secp256k1PointT>("pk");
            let msg = B32 { hi, lo };
            let sig = Secp256k1EcdsaSignature { r, s };
            let ok = if use_compat {
                compat_secp::secp256k1_ecdsa_verify(c, &msg, &sig, pk)
            } else {
                minocrab_std::v3::secp256k1_ecdsa_verify(c, &msg, &sig, pk)
            };
            c.assert(ok);
        })
    };
    assert_eq!(private(false), private(true));

    let public = |use_compat: bool| {
        build(|c| {
            let hi = c.arg::<FieldT>("msgHash_hi");
            let lo = c.arg::<FieldT>("msgHash_lo");
            let r = c.arg::<Secp256k1ScalarT>("r");
            let s = c.arg::<Secp256k1ScalarT>("s");
            let pk = c.arg::<Secp256k1PointT>("pk");
            let msg = B32 { hi: c.disclose(hi, "hi"), lo: c.disclose(lo, "lo") };
            let sig = Secp256k1EcdsaSignature { r: c.disclose(r, "r"), s: c.disclose(s, "s") };
            let pk = c.disclose(pk, "pk");
            let ok = if use_compat {
                compat_secp::secp256k1_ecdsa_verify(c, &msg, &sig, pk)
            } else {
                minocrab_std::v3::secp256k1_ecdsa_verify(c, &msg, &sig, pk)
            };
            c.assert(ok);
        })
    };
    assert_eq!(public(false), public(true));
}
