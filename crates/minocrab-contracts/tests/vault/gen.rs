//! Generation strategies, per notes/vault-optimization.org §"Generation
//! strategies": BRANCH-AWARE and equal-weight, not uniform.
//!
//! Uniform sampling over a 128-bit amount would spend every case in the
//! "far above every guard" band and never once hit `amount == 0` or the
//! `u64::MAX`/`u64::MAX + 1` step. Each dimension is therefore a
//! `prop_oneof!` over the boundary values the analysis named, plus one
//! arm of ordinary random values so the interior is covered too — every
//! arm at equal weight.
//!
//! Case count scales with `PROPTEST_CASES` (see [`config`]), the same knob
//! crates/minocrab-sim/tests/property.rs uses.

use proptest::prelude::*;

use super::model::*;

/// Default cases per property. Deliberately modest: the settle circuits
/// simulate an in-circuit secp256k1 ECDSA verification per case, so this
/// is the knee of the CI-time curve. `PROPTEST_CASES=1000000` is the
/// gating run.
pub const DEFAULT_CASES: u32 = 48;

/// `PROPTEST_CASES`-scaled config.
pub fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CASES);
    ProptestConfig {
        cases,
        // The scenarios are large and shrinking them is not informative
        // (a shrunk 128-bit amount is just a different boundary case);
        // the failure message carries the whole scenario anyway.
        max_shrink_iters: 64,
        ..ProptestConfig::default()
    }
}

/// The `Uint<128>` amount band: every guard boundary the analysis lists,
/// plus one interior arm.
pub fn amount() -> impl Strategy<Value = u128> {
    const U64MAX: u128 = u64::MAX as u128;
    prop_oneof![
        Just(0u128),
        Just(1u128),
        Just(U64MAX - 1),
        Just(U64MAX),
        Just(U64MAX + 1),
        Just(u128::MAX),
        (1u64..u64::MAX).prop_map(u128::from),
    ]
}

/// An amount a request circuit would actually have accepted — the only
/// kind a settle circuit ever reads back out of a stored view.
pub fn valid_amount() -> impl Strategy<Value = u128> {
    const U64MAX: u128 = u64::MAX as u128;
    prop_oneof![
        Just(1u128),
        Just(U64MAX - 1),
        Just(U64MAX),
        (1u64..u64::MAX).prop_map(u128::from),
    ]
}

/// `gasLimit`: the `> 0` guard's boundary.
pub fn gas_limit() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX), any::<u64>()]
}

/// `keyVersion`: `Uint<8>`, guarded `>= 1`.
pub fn key_version() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0u8), Just(1u8), Just(255u8), any::<u8>()]
}

/// `evmNonce`: `Uint<64>`, unguarded, so only its extremes matter.
pub fn evm_nonce() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(u64::MAX), any::<u64>()]
}

/// A `Bytes<20>` EVM address, including the zero address every request
/// circuit rejects.
pub fn address20() -> impl Strategy<Value = [u8; 20]> {
    prop_oneof![Just([0u8; 20]), any::<[u8; 20]>()]
}

/// A non-zero address — what a configured cell holds.
fn nonzero20() -> impl Strategy<Value = [u8; 20]> {
    any::<[u8; 20]>().prop_map(|a| if a == [0u8; 20] { [1u8; 20] } else { a })
}

/// A counter's pre-state value: the analysis calls out `u64::MAX - 1`
/// (one increment from wrapping) and `0` (the not-initialised gate).
pub fn counter_value() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(u64::MAX - 1),
        Just(u64::MAX),
        any::<u64>(),
    ]
}

/// `initialised`: 0 is the "Not initialised" guard, >= 1 passes.
pub fn initialised() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX)]
}

pub fn b32() -> impl Strategy<Value = [u8; 32]> {
    // `Bytes<32>` splits into [hi = byte 31, lo = bytes 0..31], and `lo`
    // must be a valid field element — the top byte is therefore kept
    // small so `Fr::from_le_bytes` never overflows.
    any::<[u8; 31]>().prop_map(|b| {
        let mut out = [0u8; 32];
        out[..31].copy_from_slice(&b);
        out
    })
}

/// A coin's presented colour: the vault token's (`None`) most of the time,
/// sometimes another.
fn coin_color() -> impl Strategy<Value = Option<[u8; 32]>> {
    prop_oneof![3 => Just(None), 1 => b32().prop_map(Some)]
}

/// A coin's presented value relative to the requested amount: equal most
/// of the time, sometimes off by one either way.
fn coin_value(amount: u128) -> impl Strategy<Value = Option<u128>> {
    prop_oneof![
        3 => Just(None),
        1 => Just(Some(amount.wrapping_add(1))),
        1 => Just(Some(amount.wrapping_sub(1))),
    ]
}

/// The pre-state cells a request circuit reads: an `Env` with generated
/// counters and addresses.
fn env() -> impl Strategy<Value = Env> {
    (initialised(), counter_value(), nonzero20(), nonzero20(), nonzero20(), nonzero20(), b32()).prop_map(
        |(init, nonce, vault_evm, router, underlying, token, caip2)| Env {
            initialised: init,
            request_nonce: nonce,
            vault_evm,
            router,
            stata_underlying: underlying,
            stata_token: token,
            caip2,
            ..Env::new()
        },
    )
}

/// An `Env` a SETTLE reads: initialised or not, the rest configured.
fn settle_env() -> impl Strategy<Value = Env> {
    (initialised(), nonzero20(), nonzero20()).prop_map(|(init, underlying, token)| Env {
        initialised: init,
        stata_underlying: underlying,
        stata_token: token,
        ..Env::new()
    })
}

/// The caller's secret for a settle: the requester's own (the gate
/// passes), or a stranger's.
fn claimant(requester: [u8; 32], wrong: bool) -> Option<[u8; 32]> {
    if wrong {
        let mut sk = requester;
        sk[0] ^= 0x5a;
        Some(sk)
    } else {
        None
    }
}

fn settle() -> impl Strategy<Value = Settle> {
    (b32(), b32(), any::<bool>(), any::<u64>()).prop_map(|(mint_nonce, own_pk, pending, seed)| Settle {
        pending,
        mint_nonce,
        own_pk,
        claimant_sk: None,
        nonce_seed: seed | 1,
    })
}

// --- initialise -----------------------------------------------------------------------------

pub fn initialise() -> impl Strategy<Value = InitialiseScenario> {
    (
        b32(),
        address20(),
        address20(),
        address20(),
        address20(),
        prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX), any::<u64>()],
        b32(),
        prop_oneof![Just(0u64), Just(1u64), any::<u64>()],
        any::<bool>(),
    )
        .prop_map(
            |(sk, vault_evm, swap_router, underlying, token, chain_id, caip2, count, right_sk)| {
                let mut s = InitialiseScenario::new();
                s.vault_evm = vault_evm;
                s.swap_router = swap_router;
                s.stata_underlying = underlying;
                s.stata_token = token;
                s.chain_id = chain_id;
                s.caip2 = caip2;
                s.env.initialised = count;
                // Half the cases present the deployer's own secret (the
                // gate passes), half present someone else's.
                s.sk = sk;
                if right_sk {
                    s.env.deployer_sk = sk;
                }
                s
            },
        )
}

// --- the allowances --------------------------------------------------------------------------

pub fn approve_stata() -> impl Strategy<Value = ApproveStataScenario> {
    (env(), evm_nonce(), key_version(), any::<bool>()).prop_map(|(env, nonce, kv, exists)| {
        let mut a = ApproveStataScenario::new();
        a.env = env;
        a.evm_nonce = nonce;
        a.key_version = kv;
        a.request_exists = exists;
        a
    })
}

pub fn approve_router() -> impl Strategy<Value = ApproveRouterScenario> {
    (env(), address20(), evm_nonce(), key_version(), any::<bool>()).prop_map(
        |(env, erc20, nonce, kv, exists)| {
            let mut a = ApproveRouterScenario::new();
            a.env = env;
            a.erc20 = erc20;
            a.evm_nonce = nonce;
            a.key_version = kv;
            a.request_exists = exists;
            a
        },
    )
}

// --- deposit -----------------------------------------------------------------------------------

pub fn start_deposit() -> impl Strategy<Value = StartDepositScenario> {
    (
        env(),
        evm_nonce(),
        gas_limit(),
        key_version(),
        address20(),
        amount(),
        any::<bool>(),
        b32(),
    )
        .prop_map(|(env, nonce, gas, kv, erc20, amt, exists, sk)| {
            let mut d = StartDepositScenario::new();
            d.env = env;
            d.evm_nonce = nonce;
            d.gas_limit = gas;
            d.key_version = kv;
            d.erc20 = erc20;
            d.amount = amt;
            d.request_exists = exists;
            d.sk = sk;
            d
        })
}

/// A deposit whose record a settle could actually be settling: every
/// request guard satisfied, so the stored amount is a real `Uint<64>`.
fn settled_deposit() -> impl Strategy<Value = StartDepositScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, nonzero20(), valid_amount(), b32()).prop_map(
        |(env, nonce, kv, erc20, amt, sk)| {
            let mut d = StartDepositScenario::new();
            d.env = env;
            d.evm_nonce = nonce;
            d.key_version = kv;
            d.erc20 = erc20;
            d.amount = amt;
            d.sk = sk;
            d
        },
    )
}

/// `completeDeposit` — ALL FOUR recipient shapes at equal weight: `none`,
/// `some(left(pk))`, `some(right(self))` (the auto-receive branch FIRES),
/// `some(right(other))`.
pub fn complete_deposit() -> impl Strategy<Value = CompleteDepositScenario> {
    (
        settled_deposit(),
        settle(),
        0u8..=4,
        prop_oneof![Just(0u8), Just(1u8), Just(2u8), any::<u8>()],
        any::<bool>(),
        b32(),
    )
        .prop_map(|(d, settle, shape, output, wrong_sk, other)| {
            let mut c = CompleteDepositScenario::new();
            let self_addr = d.env.self_addr;
            c.settle = settle;
            c.settle.claimant_sk = claimant(d.sk, wrong_sk);
            c.d = d;
            c.serialized_output = output;
            c.recipient = match shape {
                0 => ClaimRecipient::None(other),
                1 => ClaimRecipient::Key(other),
                2 => ClaimRecipient::Contract(self_addr),
                _ => ClaimRecipient::Contract(other),
            };
            c
        })
}

// --- withdraw ---------------------------------------------------------------------------------

pub fn start_withdraw() -> impl Strategy<Value = StartWithdrawScenario> {
    (
        env(),
        evm_nonce(),
        key_version(),
        address20(),
        amount(),
        address20(),
        any::<bool>(),
        b32(),
        b32(),
        coin_color(),
    )
        .prop_flat_map(|(env, nonce, kv, erc20, amt, dest, exists, sk, coin_nonce, color)| {
            coin_value(amt).prop_map(move |value| {
                let mut w = StartWithdrawScenario::new();
                w.env = env.clone();
                w.evm_nonce = nonce;
                w.key_version = kv;
                w.erc20 = erc20;
                w.amount = amt;
                w.dest = dest;
                w.request_exists = exists;
                w.sk = sk;
                w.coin_nonce = coin_nonce;
                w.coin_color = color;
                w.coin_value = value;
                w
            })
        })
}

/// A withdraw whose record a settle could be reading back.
fn settled_withdraw() -> impl Strategy<Value = StartWithdrawScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, nonzero20(), valid_amount(), b32()).prop_map(
        |(env, nonce, kv, erc20, amt, sk)| {
            let mut w = StartWithdrawScenario::new();
            w.env = env;
            w.evm_nonce = nonce;
            w.key_version = kv;
            w.erc20 = erc20;
            w.amount = amt;
            w.sk = sk;
            w
        },
    )
}

/// `completeWithdraw` — the attested outcome byte at equal weight over
/// `{0x00, 0x01, other}`. "other" is NOT a rejection: it routes to the
/// refund branch exactly as `0x00` does, and this strategy is what pins
/// that.
pub fn complete_withdraw() -> impl Strategy<Value = CompleteWithdrawScenario> {
    (
        settled_withdraw(),
        settle(),
        prop_oneof![Just(0u8), Just(1u8), 2u8..=255],
        any::<bool>(),
    )
        .prop_map(|(w, settle, outcome, wrong_sk)| {
            let mut c = CompleteWithdrawScenario::new(outcome);
            c.settle = settle;
            c.settle.claimant_sk = claimant(w.sk, wrong_sk);
            c.w = w;
            c
        })
}

/// The 5-byte output a refund circuit sees: the sentinel, and three shapes
/// that are not it.
fn failure_output() -> impl Strategy<Value = [u8; 5]> {
    prop_oneof![
        3 => Just(minocrab_contracts::erc20_vault::MPC_FAILURE_OUTPUT),
        1 => Just([0u8; 5]),
        1 => Just([0xde, 0xad, 0xbe, 0xef, 0x00]),
        1 => any::<[u8; 5]>(),
    ]
}

pub fn refund_withdraw() -> impl Strategy<Value = RefundWithdrawScenario> {
    (settled_withdraw(), settle(), failure_output(), any::<bool>()).prop_map(|(w, settle, output, wrong_sk)| {
        let mut r = RefundWithdrawScenario::new();
        r.settle = settle;
        r.settle.claimant_sk = claimant(w.sk, wrong_sk);
        r.w = w;
        r.serialized_output = output;
        r
    })
}

// --- swap ---------------------------------------------------------------------------------------

pub fn start_swap() -> impl Strategy<Value = StartSwapScenario> {
    (
        env(),
        evm_nonce(),
        key_version(),
        address20(),
        address20(),
        prop_oneof![Just(0u32), Just(500u32), Just(3000u32), Just(0xff_ffffu32)],
        amount(),
        amount(),
        any::<bool>(),
        b32(),
        b32(),
        coin_color(),
    )
        .prop_flat_map(
            |(env, nonce, kv, token_in, token_out, fee, amount_out, amount_in_max, exists, sk, coin_nonce, color)| {
                coin_value(amount_in_max).prop_map(move |value| {
                    let mut s = StartSwapScenario::new();
                    s.env = env.clone();
                    s.evm_nonce = nonce;
                    s.key_version = kv;
                    s.token_in = token_in;
                    s.token_out = token_out;
                    s.fee = fee;
                    s.amount_out = amount_out;
                    s.amount_in_max = amount_in_max;
                    s.request_exists = exists;
                    s.sk = sk;
                    s.coin_nonce = coin_nonce;
                    s.coin_color = color;
                    s.coin_value = value;
                    s
                })
            },
        )
}

/// A swap whose record a settle could be reading back.
fn settled_swap() -> impl Strategy<Value = StartSwapScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, nonzero20(), nonzero20(), valid_amount(), valid_amount(), b32()).prop_map(
        |(env, nonce, kv, tin, tout, aout, ainmax, sk)| {
            let mut s = StartSwapScenario::new();
            s.env = env;
            s.evm_nonce = nonce;
            s.key_version = kv;
            s.token_in = tin;
            s.token_out = tout;
            s.amount_out = aout;
            s.amount_in_max = ainmax;
            s.sk = sk;
            s
        },
    )
}

/// `completeSwap` — `amountIn ∈ {0, 1, max−1, max, max+1, random}` at equal
/// weight. `max` is the exact spend (change 0, a harmless 0-value coin);
/// `max + 1` is THE underflow boundary and must reject. The change nonce is
/// distinct from the mint nonce most of the time, equal sometimes.
pub fn complete_swap() -> impl Strategy<Value = CompleteSwapScenario> {
    (settled_swap(), settle(), 0u8..=5, any::<bool>(), any::<u64>(), b32(), any::<bool>()).prop_map(
        |(s, settle, band, wrong_sk, rand, change_nonce, same_nonce)| {
            let mut c = CompleteSwapScenario::new();
            let max = s.amount_in_max_u64();
            c.settle = settle;
            c.settle.claimant_sk = claimant(s.sk, wrong_sk);
            c.s = s;
            c.amount_in = match band {
                0 => 0,
                1 => 1,
                2 => max.saturating_sub(1),
                3 => max,
                4 => max.saturating_add(1),
                _ => rand,
            };
            c.change_nonce = if same_nonce { c.settle.mint_nonce } else { change_nonce };
            c
        },
    )
}

pub fn refund_swap() -> impl Strategy<Value = RefundSwapScenario> {
    (settled_swap(), settle(), failure_output(), any::<bool>()).prop_map(|(s, settle, output, wrong_sk)| {
        let mut r = RefundSwapScenario::new();
        r.settle = settle;
        r.settle.claimant_sk = claimant(s.sk, wrong_sk);
        r.s = s;
        r.serialized_output = output;
        r
    })
}

// --- supply ----------------------------------------------------------------------------------

pub fn start_supply() -> impl Strategy<Value = StartSupplyScenario> {
    (env(), evm_nonce(), key_version(), amount(), any::<bool>(), b32(), b32(), coin_color()).prop_flat_map(
        |(env, nonce, kv, amt, exists, sk, coin_nonce, color)| {
            coin_value(amt).prop_map(move |value| {
                let mut s = StartSupplyScenario::new();
                s.env = env.clone();
                s.evm_nonce = nonce;
                s.key_version = kv;
                s.amount = amt;
                s.request_exists = exists;
                s.sk = sk;
                s.coin_nonce = coin_nonce;
                s.coin_color = color;
                s.coin_value = value;
                s
            })
        },
    )
}

fn settled_supply() -> impl Strategy<Value = StartSupplyScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, valid_amount(), b32()).prop_map(|(env, nonce, kv, amt, sk)| {
        let mut s = StartSupplyScenario::new();
        s.env = env;
        s.evm_nonce = nonce;
        s.key_version = kv;
        s.amount = amt;
        s.sk = sk;
        s
    })
}

pub fn complete_supply() -> impl Strategy<Value = CompleteSupplyScenario> {
    (settled_supply(), settle(), any::<u64>(), any::<bool>()).prop_map(|(s, settle, shares, wrong_sk)| {
        let mut c = CompleteSupplyScenario::new();
        c.settle = settle;
        c.settle.claimant_sk = claimant(s.sk, wrong_sk);
        c.s = s;
        c.shares = shares;
        c
    })
}

pub fn refund_supply() -> impl Strategy<Value = RefundSupplyScenario> {
    (settled_supply(), settle(), failure_output(), any::<bool>()).prop_map(|(s, settle, output, wrong_sk)| {
        let mut r = RefundSupplyScenario::new();
        r.settle = settle;
        r.settle.claimant_sk = claimant(s.sk, wrong_sk);
        r.s = s;
        r.serialized_output = output;
        r
    })
}

// --- redeem ----------------------------------------------------------------------------------

pub fn start_redeem() -> impl Strategy<Value = StartRedeemScenario> {
    (env(), evm_nonce(), key_version(), amount(), any::<bool>(), b32(), b32(), coin_color()).prop_flat_map(
        |(env, nonce, kv, shares, exists, sk, coin_nonce, color)| {
            coin_value(shares).prop_map(move |value| {
                let mut s = StartRedeemScenario::new();
                s.env = env.clone();
                s.evm_nonce = nonce;
                s.key_version = kv;
                s.shares = shares;
                s.request_exists = exists;
                s.sk = sk;
                s.coin_nonce = coin_nonce;
                s.coin_color = color;
                s.coin_value = value;
                s
            })
        },
    )
}

fn settled_redeem() -> impl Strategy<Value = StartRedeemScenario> {
    (settle_env(), evm_nonce(), 1u8..=255, valid_amount(), b32()).prop_map(|(env, nonce, kv, shares, sk)| {
        let mut s = StartRedeemScenario::new();
        s.env = env;
        s.evm_nonce = nonce;
        s.key_version = kv;
        s.shares = shares;
        s.sk = sk;
        s
    })
}

pub fn complete_redeem() -> impl Strategy<Value = CompleteRedeemScenario> {
    (settled_redeem(), settle(), any::<u64>(), any::<bool>()).prop_map(|(s, settle, assets, wrong_sk)| {
        let mut c = CompleteRedeemScenario::new();
        c.settle = settle;
        c.settle.claimant_sk = claimant(s.sk, wrong_sk);
        c.s = s;
        c.assets = assets;
        c
    })
}

pub fn refund_redeem() -> impl Strategy<Value = RefundRedeemScenario> {
    (settled_redeem(), settle(), failure_output(), any::<bool>()).prop_map(|(s, settle, output, wrong_sk)| {
        let mut r = RefundRedeemScenario::new();
        r.settle = settle;
        r.settle.claimant_sk = claimant(s.sk, wrong_sk);
        r.s = s;
        r.serialized_output = output;
        r
    })
}
