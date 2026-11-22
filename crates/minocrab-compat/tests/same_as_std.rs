//! Every gadget this crate copied from `minocrab_std` is checked against
//! std's own, on the same inputs, both at top level and inside a `when` (the
//! manager calls several of them under a guard).
//!
//! Two strengths of check. Where std's gadget is still compactc's shape the
//! two emit the identical ZKIR (the `pin_*` tests).
//! Where std's has gone lean they cannot, and they are held to
//! equivalent behaviour instead (the `agree_*` tests): each side is built in
//! the same harness, both are run on the same inputs through the executor
//! (`minocrab_sim::exec`, which settles the transcript against Midnight's
//! on-chain VM and replays it in `ResultModeVerify`), and they must agree on
//! accept or reject (and on which side refused: the circuit or the ledger),
//! and on acceptance on the whole preimage (the transcript in and out, which
//! is what the ledger sees), the public-input vector, the returned values, the
//! call's effects and the post-state; each accepted preimage is also checked
//! by upstream's own `IrSource::check`.

use minocrab::{Circuit, FieldT, Lowering, SelfAddressReads, Secp256k1PointT, Secp256k1ScalarT, Wire};
use minocrab::{Private, Public};
use minocrab_compat::{kernel as compat_kernel, merkle, secp as compat_secp};
use minocrab_std::kernel::{self as std_kernel, UnshieldedRecipient};
use minocrab_std::{
    Bool, CoinColor, CoinNonce, CoinRecipient, ContractAddress, Either, LedgerHistoricMerkleTree,
    LedgerMerkleTree, QualifiedShieldedCoinInfo, Secp256k1EcdsaSignature, ShieldedCoinInfo,
    TokenDomainSeparator, Uint, UserAddress, ZswapCoinPublicKey, B32,
};
use minocrab_zkir::to_zkir_string;

use midnight_onchain_state::state::StateValue;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::Array;
use minocrab::Compiled;
use minocrab::Fr;
use midnight_transient_crypto::proofs::Zkir;
use minocrab_sim::exec::{self, Call, ExecError, Executed};

/// The circuit `f` builds under compactc's lowering, serialized. Both sides
/// of a `pin_*` comparison are built this way: the pin is about the gadget
/// emitting the same instructions, not about the lowering settings.
fn build(f: impl FnOnce(&mut Circuit)) -> String {
    let mut c = Circuit::new();
    minocrab_compat::profile(&mut c);
    f(&mut c);
    to_zkir_string(&c.finish(true).ir).expect("IR serializes")
}

/// The circuit `f` builds under `lowering` (`None`: the defaults, which is
/// what a MinoCrab-only circuit gets), finished without a communications
/// commitment (so a call needs no randomness), for running.
fn compile_with(lowering: Option<Lowering>, f: impl FnOnce(&mut Circuit)) -> Compiled {
    let mut c = Circuit::new();
    if let Some(l) = lowering {
        c.set_lowering(l);
    }
    f(&mut c);
    c.finish(false)
}

/// compactc's lowering, as every port and the signer state it.
fn compactc() -> Lowering {
    let mut c = Circuit::new();
    minocrab_compat::profile(&mut c);
    c.lowering()
}

/// The two sides of an `agree_*` test as each would be deployed: std's lean
/// gadget under the defaults, compat's twin under compactc's lowering.
fn compile(use_compat: bool, f: impl FnOnce(&mut Circuit)) -> Compiled {
    compile_with(use_compat.then(compactc), f)
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
fn agree(what: &str, lean: &Compiled, twin: &Compiled, state: &StateValue<InMemoryDB>, inputs: &[Fr]) -> Verdict {
    let run = |compiled: &Compiled| {
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
fn inputs(c: &mut Circuit) -> Vec<Wire<FieldT, Public>> {
    let args: Vec<Wire<FieldT, Private>> = (0..20).map(|i| c.arg::<FieldT>(&format!("x{i}"))).collect();
    args.into_iter().enumerate().map(|(i, w)| c.disclose(w, &format!("x{i}"))).collect()
}

fn b32(w: &[Wire<FieldT, Public>], at: usize) -> B32<Public> {
    B32 { hi: w[at], lo: w[at + 1] }
}

fn u64_(w: Wire<FieldT, Public>) -> Uint<64, Public> {
    Uint::from_field_unchecked(w)
}

fn u128_(w: Wire<FieldT, Public>) -> Uint<128, Public> {
    Uint::from_field_unchecked(w)
}

fn recipient(w: &[Wire<FieldT, Public>]) -> UnshieldedRecipient<Public> {
    Either {
        is_left: Bool::from_field_unchecked(w[10]),
        left: ContractAddress::from_limbs([w[11], w[12]]),
        right: UserAddress::from_limbs([w[13], w[14]]),
    }
}

fn coin_recipient(w: &[Wire<FieldT, Public>]) -> CoinRecipient<Public> {
    CoinRecipient {
        is_left: w[10],
        left: ZswapCoinPublicKey(b32(w, 11)),
        right: ContractAddress::from_limbs([w[13], w[14]]),
    }
}

fn qualified(w: &[Wire<FieldT, Public>], at: usize) -> QualifiedShieldedCoinInfo<Public> {
    QualifiedShieldedCoinInfo {
        nonce: CoinNonce(b32(w, at)),
        color: CoinColor(b32(w, at + 2)),
        value: w[at + 4],
        mt_index: w[at + 5],
    }
}

fn coin(w: &[Wire<FieldT, Public>], at: usize) -> ShieldedCoinInfo<Public> {
    ShieldedCoinInfo { nonce: CoinNonce(b32(w, at)), color: CoinColor(b32(w, at + 2)), value: w[at + 4] }
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
                        let body = |$c: &mut Circuit| {
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
pin_kernel!(block_time_gt, |c, w, k| k::block_time_gt(c, u64_(w[0])));
pin_kernel!(unshielded_balance, |c, w, k| k::unshielded_balance(c, CoinColor(b32(&w, 0))));
pin_kernel!(unshielded_balance_lt, |c, w, k| k::unshielded_balance_lt(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(unshielded_balance_gt, |c, w, k| k::unshielded_balance_gt(c, CoinColor(b32(&w, 0)), u128_(w[2])));
pin_kernel!(receive_unshielded, |c, w, k| k::receive_unshielded(c, CoinColor(b32(&w, 0)), u128_(w[2])));
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
        compile(use_compat, move |c| {
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
    let hashes = |c: &Compiled| c.ir.instructions.iter().filter(|i| format!("{i:?}").starts_with("PersistentHash")).count();
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
                minocrab_std::secp256k1_ecdsa_verify(c, &msg, &sig, pk)
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
                minocrab_std::secp256k1_ecdsa_verify(c, &msg, &sig, pk)
            };
            c.assert(ok);
        })
    };
    assert_eq!(public(false), public(true));
}

// ---- the token gadgets std made lean (M48 C step 3) ---------------------------
//
// Each is built twice on the same twenty public field arguments: std's lean
// gadget (under the default lowering, and again under `EveryCall`) and
// compat's twin (under compactc's profile), at top level and inside
// `when(x19)`. Each case runs on the VM through `agree` (under `EveryCall`:
// everything, the transcript included) or `agree_on_effects` (under the
// default `OncePerCircuit`: the lean transcript legitimately carries fewer
// `kernel.self()` reads, so verdict, effects, post-state and returned values).

type W = Wire<FieldT, Public>;

/// What an observer outside the circuit sees, minus the transcript: the
/// verdict and, on acceptance, the returned values, effects and post-state.
fn agree_on_effects(what: &str, lean: &Compiled, twin: &Compiled, state: &StateValue<InMemoryDB>, inputs: &[Fr]) -> Verdict {
    let run = |compiled: &Compiled| {
        let ctx = exec::context(state.clone(), SELF);
        exec::execute(&compiled.ir, &Call::new(inputs, &[]), &ctx)
    };
    let (a, b) = (run(lean), run(twin));
    let v = verdict(&a);
    assert_eq!(v, verdict(&b), "{what} {inputs:?}: verdicts differ\nlean: {:?}\ncompat: {:?}", a.as_ref().err(), b.as_ref().err());
    if let (Ok(a), Ok(b)) = (a, b) {
        assert_eq!(a.run.outputs, b.run.outputs, "{what} {inputs:?}: returned values");
        assert!(a.effects == b.effects, "{what} {inputs:?}: effects");
        assert!(a.post == b.post, "{what} {inputs:?}: post-state");
        assert!(a.reads.len() <= b.reads.len(), "{what} {inputs:?}: the lean side reads more");
        lean.ir.check(&a.preimage).unwrap_or_else(|e| panic!("{what}: upstream refuses the lean preimage: {e:?}"));
        twin.ir.check(&b.preimage).unwrap_or_else(|e| panic!("{what}: upstream refuses the compat preimage: {e:?}"));
    }
    v
}

/// A gadget body: the arguments, and whether to call compat's twin; returns
/// the wires the circuit outputs.
type Body = fn(&mut Circuit, &[W], bool) -> Vec<W>;

fn side(body: Body, use_compat: bool, guarded: bool, lean: Lowering) -> Compiled {
    compile_with(Some(if use_compat { compactc() } else { lean }), move |c| {
        let w = inputs(c);
        let out = if guarded { c.when(w[19], |c| body(c, &w, use_compat)).or_default() } else { body(c, &w, use_compat) };
        for (i, o) in out.into_iter().enumerate() {
            c.output(o, &format!("o{i}"));
        }
    })
}

/// Run every case in `cases` (argument vectors) at top level and under the
/// guard, under both self-address settings; returns every verdict seen.
fn agree_gadget(what: &str, body: Body, cases: &[Vec<Fr>]) -> Vec<Verdict> {
    let state = StateValue::Null;
    let mut seen = Vec::new();
    for guarded in [false, true] {
        let twin = side(body, true, guarded, compactc());
        let every = Lowering { self_address: SelfAddressReads::EveryCall, ..Lowering::default() };
        let (lean_every, lean_once) = (side(body, false, guarded, every), side(body, false, guarded, Lowering::default()));
        for args in cases {
            let what = format!("{what} (guarded: {guarded})");
            let v = agree(&format!("{what}, EveryCall"), &lean_every, &twin, &state, args);
            assert_eq!(v, agree_on_effects(&format!("{what}, OncePerCircuit"), &lean_once, &twin, &state, args));
            seen.push(v);
        }
    }
    seen
}

fn fr(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).expect("below the modulus")
}

/// `kernel.self()`'s two limbs, as a circuit sees them.
fn self_limbs() -> (Fr, Fr) {
    let probe = compile(false, |c| {
        let me = minocrab_std::kernel::self_address(c).bytes();
        c.output(me.hi, "hi");
        c.output(me.lo, "lo");
    });
    let ctx = exec::context(StateValue::Null, SELF);
    let out = exec::execute(&probe.ir, &Call::new(&[], &[]), &ctx).expect("a bare self read runs").run.outputs;
    let limb = |v: &minocrab_zkir::IrValue| match v {
        minocrab_zkir::IrValue::Native(f) => *f,
        other => panic!("not a native limb: {other:?}"),
    };
    (limb(&out[0]), limb(&out[1]))
}

/// Twenty arguments, zero but for `set`.
fn args(set: &[(usize, Fr)]) -> Vec<Fr> {
    let mut a = vec![Fr::from(0u64); 20];
    for &(i, v) in set {
        a[i] = v;
    }
    a
}

/// Both kinds of verdict were exercised.
fn both_verdicts(what: &str, seen: &[Verdict]) {
    assert!(seen.contains(&Verdict::Accepted) && seen.iter().any(|v| *v != Verdict::Accepted), "{what}: both verdicts covered: {seen:?}");
}

/// The four negated forms: `!` is the `not` instruction on the lean side.
#[test]
fn agree_negations() {
    fn bt_gte(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let r = if compat { compat_kernel::block_time_gte(c, u64_(w[0])) } else { std_kernel::block_time_gte(c, u64_(w[0])) };
        vec![(*r).field()]
    }
    fn bt_lte(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let r = if compat { compat_kernel::block_time_lte(c, u64_(w[0])) } else { std_kernel::block_time_lte(c, u64_(w[0])) };
        vec![(*r).field()]
    }
    fn bal_gte(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let r = if compat {
            compat_kernel::unshielded_balance_gte(c, CoinColor(b32(w, 0)), u128_(w[2]))
        } else {
            std_kernel::unshielded_balance_gte(c, CoinColor(b32(w, 0)), u128_(w[2]))
        };
        vec![(*r).field()]
    }
    fn bal_lte(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let r = if compat {
            compat_kernel::unshielded_balance_lte(c, CoinColor(b32(w, 0)), u128_(w[2]))
        } else {
            std_kernel::unshielded_balance_lte(c, CoinColor(b32(w, 0)), u128_(w[2]))
        };
        vec![(*r).field()]
    }
    let (mut times, mut amounts) = (Vec::new(), Vec::new());
    for t in [0u128, 1, 1 << 40] {
        for g in [0u64, 1] {
            times.push(args(&[(0, fr(t)), (19, Fr::from(g))]));
            amounts.push(args(&[(1, Fr::from(9u64)), (2, fr(t)), (19, Fr::from(g))]));
        }
    }
    for (what, body, cases) in [
        ("block_time_gte", bt_gte as Body, &times),
        ("block_time_lte", bt_lte, &times),
        ("unshielded_balance_gte", bal_gte, &amounts),
        ("unshielded_balance_lte", bal_lte, &amounts),
    ] {
        agree_gadget(what, body, cases);
    }
}

fn unshielded_cases() -> Vec<Vec<Fr>> {
    let (me_hi, me_lo) = self_limbs();
    let mut cases = Vec::new();
    for color in [(1u64, 2u64), (3, 4)] {
        for is_left in [0u64, 1, 2] {
            for (l_hi, l_lo) in [(me_hi, me_lo), (Fr::from(7u64), Fr::from(8u64)), (me_hi, Fr::from(8u64))] {
                for amount in [0u128, 7, (1 << 64) - 1] {
                    for g in [0u64, 1] {
                        cases.push(args(&[
                            (0, Fr::from(color.0)),
                            (1, Fr::from(color.1)),
                            (2, fr(amount)),
                            (10, Fr::from(is_left)),
                            (11, l_hi),
                            (12, l_lo),
                            (13, Fr::from(5u64)),
                            (14, Fr::from(6u64)),
                            (19, Fr::from(g)),
                        ]));
                    }
                }
            }
        }
    }
    cases
}

/// `sendUnshielded`: recipient self, another contract, a contract sharing
/// one limb with self, a user, and a recipient tag that is not a bit
/// (refused); zero and non-zero amounts; two token colours.
#[test]
fn agree_send_unshielded() {
    fn body(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        if compat {
            compat_kernel::send_unshielded(c, CoinColor(b32(w, 0)), u128_(w[2]), &recipient(w));
        } else {
            std_kernel::send_unshielded(c, CoinColor(b32(w, 0)), u128_(w[2]), &recipient(w));
        }
        vec![]
    }
    both_verdicts("send_unshielded", &agree_gadget("send_unshielded", body, &unshielded_cases()));
}

/// `mintUnshieldedToken`, over the same recipients and amounts.
#[test]
fn agree_mint_unshielded_token() {
    fn body(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let ds = TokenDomainSeparator(b32(w, 0));
        let color = if compat {
            compat_kernel::mint_unshielded_token(c, &ds, u64_(w[2]), &recipient(w))
        } else {
            std_kernel::mint_unshielded_token(c, &ds, u64_(w[2]), &recipient(w))
        };
        vec![color.bytes().hi, color.bytes().lo]
    }
    both_verdicts("mint_unshielded_token", &agree_gadget("mint_unshielded_token", body, &unshielded_cases()));
}

fn coin_out(coin: &ShieldedCoinInfo<Public>) -> Vec<W> {
    vec![coin.nonce.bytes().hi, coin.nonce.bytes().lo, coin.color.bytes().hi, coin.color.bytes().lo, coin.value]
}

fn merge_cases() -> Vec<Vec<Fr>> {
    let mut cases = Vec::new();
    for (a_color, b_color) in [((1u64, 2u64), (1u64, 2u64)), ((3, 4), (3, 4)), ((1, 2), (1, 3))] {
        for (va, vb) in [(0u128, 0u128), (3, 4), (u128::MAX, 1), (u128::MAX, 0)] {
            for g in [0u64, 1] {
                cases.push(args(&[
                    (0, Fr::from(11u64)),
                    (1, Fr::from(12u64)),
                    (2, Fr::from(a_color.0)),
                    (3, Fr::from(a_color.1)),
                    (4, fr(va)),
                    (5, Fr::from(2u64)),
                    (6, Fr::from(13u64)),
                    (7, Fr::from(14u64)),
                    (8, Fr::from(b_color.0)),
                    (9, Fr::from(b_color.1)),
                    (10, fr(vb)),
                    (11, Fr::from(3u64)),
                    (19, Fr::from(g)),
                ]));
            }
        }
    }
    cases
}

/// `mergeCoin`: same colour (two colours), different colour (refused), sums
/// in range and one past `Uint<128>` (refused).
#[test]
fn agree_merge_coin() {
    fn body(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let (a, b) = (qualified(w, 0), qualified(w, 6));
        coin_out(&if compat { compat_kernel::merge_coin(c, &a, &b) } else { std_kernel::merge_coin(c, &a, &b) })
    }
    both_verdicts("merge_coin", &agree_gadget("merge_coin", body, &merge_cases()));
}

/// `mergeCoinImmediate`, over the same cases.
#[test]
fn agree_merge_coin_immediate() {
    fn body(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let (a, b) = (qualified(w, 0), coin(w, 6));
        coin_out(&if compat { compat_kernel::merge_coin_immediate(c, &a, &b) } else { std_kernel::merge_coin_immediate(c, &a, &b) })
    }
    both_verdicts("merge_coin_immediate", &agree_gadget("merge_coin_immediate", body, &merge_cases()));
}

/// `sendShielded`: to a key, to self, to another contract, to a contract
/// sharing one limb with self, a recipient tag that is not a bit (refused);
/// spending all of the coin, part of it, none of a zero coin, and more than
/// it holds (refused); two colours.
#[test]
fn agree_send_shielded() {
    fn body(c: &mut Circuit, w: &[W], compat: bool) -> Vec<W> {
        let (input, to, value) = (qualified(w, 0), coin_recipient(w), u128_(w[6]));
        let r = if compat { compat_kernel::send_shielded(c, &input, &to, value) } else { std_kernel::send_shielded(c, &input, &to, value) };
        let mut out = vec![r.change.is_some.field()];
        out.extend(coin_out(&r.change.value));
        out.extend(coin_out(&r.sent));
        out
    }
    let (me_hi, me_lo) = self_limbs();
    let mut cases = Vec::new();
    for color in [(1u64, 2u64), (3, 4)] {
        for is_left in [0u64, 1, 2] {
            for (r_hi, r_lo) in [(me_hi, me_lo), (Fr::from(7u64), Fr::from(8u64)), (me_hi, Fr::from(8u64))] {
                for (have, send) in [(10u128, 10u128), (10, 3), (0, 0), (3, 10), (u128::MAX, 1)] {
                    for g in [0u64, 1] {
                        cases.push(args(&[
                            (0, Fr::from(11u64)),
                            (1, Fr::from(12u64)),
                            (2, Fr::from(color.0)),
                            (3, Fr::from(color.1)),
                            (4, fr(have)),
                            (5, Fr::from(2u64)),
                            (6, fr(send)),
                            (10, Fr::from(is_left)),
                            (11, Fr::from(21u64)),
                            (12, Fr::from(22u64)),
                            (13, r_hi),
                            (14, r_lo),
                            (19, Fr::from(g)),
                        ]));
                    }
                }
            }
        }
    }
    both_verdicts("send_shielded", &agree_gadget("send_shielded", body, &cases));
}

/// Rows of each gadget pair, std's lean form under the defaults against
/// compat's twin under the profile (the table in notes/op-costs.org §4).
/// Every lean form costs no more.
#[test]
fn lean_gadgets_cost_no_more_than_their_twins() {
    fn send_u(c: &mut Circuit, w: &[W], k: bool) -> Vec<W> {
        if k { compat_kernel::send_unshielded(c, CoinColor(b32(w, 0)), u128_(w[2]), &recipient(w)) } else { std_kernel::send_unshielded(c, CoinColor(b32(w, 0)), u128_(w[2]), &recipient(w)) }
        vec![]
    }
    fn mint_u(c: &mut Circuit, w: &[W], k: bool) -> Vec<W> {
        let ds = TokenDomainSeparator(b32(w, 0));
        let col = if k { compat_kernel::mint_unshielded_token(c, &ds, u64_(w[2]), &recipient(w)) } else { std_kernel::mint_unshielded_token(c, &ds, u64_(w[2]), &recipient(w)) };
        vec![col.bytes().hi, col.bytes().lo]
    }
    fn merge(c: &mut Circuit, w: &[W], k: bool) -> Vec<W> {
        let (a, b) = (qualified(w, 0), qualified(w, 6));
        coin_out(&if k { compat_kernel::merge_coin(c, &a, &b) } else { std_kernel::merge_coin(c, &a, &b) })
    }
    fn merge_i(c: &mut Circuit, w: &[W], k: bool) -> Vec<W> {
        let (a, b) = (qualified(w, 0), coin(w, 6));
        coin_out(&if k { compat_kernel::merge_coin_immediate(c, &a, &b) } else { std_kernel::merge_coin_immediate(c, &a, &b) })
    }
    fn send_s(c: &mut Circuit, w: &[W], k: bool) -> Vec<W> {
        let (input, to, value) = (qualified(w, 0), coin_recipient(w), u128_(w[6]));
        let r = if k { compat_kernel::send_shielded(c, &input, &to, value) } else { std_kernel::send_shielded(c, &input, &to, value) };
        coin_out(&r.sent)
    }
    fn bt_gte(c: &mut Circuit, w: &[W], k: bool) -> Vec<W> {
        let r = if k { compat_kernel::block_time_gte(c, u64_(w[0])) } else { std_kernel::block_time_gte(c, u64_(w[0])) };
        vec![(*r).field()]
    }
    let base = minocrab_sim::cost(&compile_with(None, |c| {
        let _ = inputs(c);
    }).ir).1;
    for (what, body) in [("send_unshielded", send_u as Body), ("mint_unshielded_token", mint_u), ("merge_coin", merge), ("merge_coin_immediate", merge_i), ("send_shielded", send_s), ("block_time_gte", bt_gte)] {
        for guarded in [false, true] {
            let rows = |k: bool| minocrab_sim::cost(&side(body, k, guarded, if k { compactc() } else { Lowering::default() }).ir).1 - base;
            let (lean, twin) = (rows(false), rows(true));
            println!("{what} (guarded: {guarded}): compat {twin}, std {lean}");
            assert!(lean <= twin, "{what} (guarded: {guarded}): lean {lean} > compat {twin}");
        }
    }
}
