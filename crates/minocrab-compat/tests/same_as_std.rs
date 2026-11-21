//! Every gadget this crate copied from `minocrab_std` emits the IDENTICAL
//! ZKIR to std's own, on the same inputs, both at top level and inside a
//! `when` (the manager calls several of them under a guard).
//!
//! This pins the copy (M48 C, step 1). When std's gadgets go lean (step 3)
//! these assertions change, deliberately, to public-input equality: the two
//! must then agree on what they prove, not on how.

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

/// The circuit `f` builds, serialized.
fn build(f: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    f(&mut c);
    to_zkir_string(&c.finish(true).ir).expect("IR serializes")
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
/// leaf: compat's free function and std's method.
#[test]
fn insert_index_default() {
    const MT: LedgerMerkleTree<4, B32<Public>> = LedgerMerkleTree::at(0);
    const HMT: LedgerHistoricMerkleTree<6, Uint<64, Public>> = LedgerHistoricMerkleTree::at(1);
    let std_side = build(|c| {
        let w = inputs(c);
        MT.insert_index_default(c, u64_(w[0]));
        HMT.insert_index_default(c, u64_(w[1]));
        let _ = c.when(w[19], |c| MT.insert_index_default(c, u64_(w[2])));
    });
    let compat_side = build(|c| {
        let w = inputs(c);
        merkle::insert_index_default(c, &MT, u64_(w[0]));
        merkle::insert_index_default(c, &HMT, u64_(w[1]));
        let _ = c.when(w[19], |c| merkle::insert_index_default(c, &MT, u64_(w[2])));
    });
    assert_eq!(std_side, compat_side);
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
