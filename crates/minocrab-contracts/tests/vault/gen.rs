//! Generation strategies, exactly per notes/vault-optimization.org
//! §"Generation strategies": BRANCH-AWARE and equal-weight, not uniform.
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
/// kind a settle circuit ever reads back out of a stored record.
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

/// A counter's pre-state value: the analysis calls out `u64::MAX - 1`
/// (one increment from wrapping) and `0` (the not-initialized gate).
pub fn counter_value() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1u64),
        Just(u64::MAX - 1),
        Just(u64::MAX),
        any::<u64>(),
    ]
}

/// `initialized`: 0 is the "Not initialized" guard, >= 1 passes.
pub fn initialized() -> impl Strategy<Value = u64> {
    prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX)]
}

fn b32() -> impl Strategy<Value = [u8; 32]> {
    // `Bytes<32>` splits into [hi = byte 31, lo = bytes 0..31], and `lo`
    // must be a valid field element — the top byte is therefore kept
    // small so `Fr::from_le_bytes` never overflows.
    any::<[u8; 31]>().prop_map(|b| {
        let mut out = [0u8; 32];
        out[..31].copy_from_slice(&b);
        out
    })
}

// --- per-circuit scenarios ----------------------------------------------------

/// `initialize`, with the pre-state's `initialized` counter alongside.
pub fn initialize() -> impl Strategy<Value = (Scenario, u64)> {
    (
        b32(),
        address20(),
        address20(),
        prop_oneof![Just(0u64), Just(1u64), Just(u64::MAX), any::<u64>()],
        b32(),
        prop_oneof![Just(0u64), Just(1u64), any::<u64>()],
        any::<bool>(),
    )
        .prop_map(
            |(sk, vault_evm, swap_router, chain_id, caip2, count, right_sk)| {
                let mut s = Scenario::new();
                s.vault_evm = vault_evm;
                s.swap_router = swap_router;
                s.chain_id = chain_id;
                s.caip2 = caip2;
                // Half the cases present the deployer's own secret (the
                // gate passes), half present someone else's.
                s.sk = sk;
                if right_sk {
                    // The caller IS the deployer: the gate passes.
                    s.deployer_sk = sk;
                }
                // Otherwise the stored commitment stays the ORIGINAL
                // deployer's and the gate rejects.
                (s, count)
            },
        )
}

/// `deposit`.
pub fn deposit() -> impl Strategy<Value = DepositScenario> {
    (
        evm_nonce(),
        gas_limit(),
        key_version(),
        address20(),
        amount(),
        initialized(),
        counter_value(),
        any::<bool>(),
        b32(),
    )
        .prop_map(
            |(nonce, gas, kv, erc20, amt, init, req_nonce, exists, sk)| {
                let mut d = DepositScenario::new();
                d.evm_nonce = nonce;
                d.gas_limit = gas;
                d.key_version = kv;
                d.erc20 = erc20;
                d.amount = amt;
                d.initialized = init;
                d.request_nonce = req_nonce;
                d.request_exists = exists;
                d.sk = sk;
                d
            },
        )
}

/// `approveRouter`.
pub fn approve() -> impl Strategy<Value = ApproveScenario> {
    (
        address20(),
        evm_nonce(),
        key_version(),
        initialized(),
        counter_value(),
        any::<bool>(),
        address20(),
    )
        .prop_map(|(erc20, nonce, kv, init, req_nonce, exists, router)| {
            let mut a = ApproveScenario::new();
            a.erc20 = erc20;
            a.evm_nonce = nonce;
            a.key_version = kv;
            a.initialized = init;
            a.request_nonce = req_nonce;
            a.request_exists = exists;
            a.router = router;
            a
        })
}

/// `withdraw`.
pub fn withdraw() -> impl Strategy<Value = WithdrawScenario> {
    (
        evm_nonce(),
        key_version(),
        address20(),
        amount(),
        address20(),
        initialized(),
        counter_value(),
        any::<bool>(),
        b32(),
        b32(),
    )
        .prop_map(
            |(nonce, kv, erc20, amt, dest, init, req_nonce, exists, sk, coin_nonce)| {
                let mut w = WithdrawScenario::new();
                w.evm_nonce = nonce;
                w.key_version = kv;
                w.erc20 = erc20;
                w.amount = amt;
                w.dest = dest;
                w.initialized = init;
                w.request_nonce = req_nonce;
                w.request_exists = exists;
                w.sk = sk;
                w.coin_nonce = coin_nonce;
                w
            },
        )
}

/// `swap`.
pub fn swap() -> impl Strategy<Value = SwapScenario> {
    (
        evm_nonce(),
        key_version(),
        address20(),
        address20(),
        prop_oneof![Just(0u32), Just(500u32), Just(3000u32), Just(0xff_ffffu32)],
        amount(),
        amount(),
        initialized(),
        counter_value(),
        any::<bool>(),
        b32(),
        b32(),
    )
        .prop_map(
            |(
                nonce,
                kv,
                token_in,
                token_out,
                fee,
                amount_out,
                amount_in_max,
                init,
                req_nonce,
                exists,
                sk,
                coin_nonce,
            )| {
                let mut s = SwapScenario::new();
                s.evm_nonce = nonce;
                s.key_version = kv;
                s.token_in = token_in;
                s.token_out = token_out;
                s.fee = fee;
                s.amount_out = amount_out;
                s.amount_in_max = amount_in_max;
                s.initialized = init;
                s.request_nonce = req_nonce;
                s.request_exists = exists;
                s.sk = sk;
                s.coin_nonce = coin_nonce;
                s
            },
        )
}

/// A deposit whose record a claim could actually be settling: every
/// request guard satisfied, so the stored amount is a real `Uint<64>`.
fn settled_deposit() -> impl Strategy<Value = DepositScenario> {
    (
        evm_nonce(),
        1u8..=255,
        any::<[u8; 20]>(),
        valid_amount(),
        b32(),
    )
        .prop_map(|(nonce, kv, erc20, amt, sk)| {
            let mut d = DepositScenario::new();
            d.evm_nonce = nonce;
            d.key_version = kv;
            d.erc20 = if erc20 == [0u8; 20] { [1u8; 20] } else { erc20 };
            d.amount = amt;
            d.sk = sk;
            d
        })
}

/// `claim` — ALL FOUR recipient shapes at equal weight, per the analysis:
/// `none`, `some(left(pk))`, `some(right(self))` (the auto-receive branch
/// FIRES), `some(right(other))`.
pub fn claim() -> impl Strategy<Value = ClaimScenario> {
    (
        settled_deposit(),
        b32(),
        0u8..=4,
        any::<bool>(),
        prop_oneof![Just(0u8), Just(1u8), Just(2u8), any::<u8>()],
        any::<bool>(),
        b32(),
        initialized(),
    )
        .prop_map(
            |(d, mint_nonce, shape, found, output, wrong_sk, other, init)| {
                let mut c = ClaimScenario::new();
                let self_addr = d.self_addr;
                c.d = d;
                c.d.initialized = init;
                c.mint_nonce = mint_nonce;
                c.found = found;
                c.serialized_output = output;
                c.recipient = match shape {
                    0 => ClaimRecipient::None(other),
                    1 => ClaimRecipient::Key(other),
                    2 => ClaimRecipient::Contract(self_addr),
                    _ => ClaimRecipient::Contract(other),
                };
                if wrong_sk {
                    let mut sk = c.d.sk;
                    sk[0] ^= 0x5a;
                    c.claimant_sk = Some(sk);
                }
                c
            },
        )
}

/// A withdraw whose record a settle could be reading back.
fn settled_withdraw() -> impl Strategy<Value = WithdrawScenario> {
    (
        evm_nonce(),
        1u8..=255,
        any::<[u8; 20]>(),
        valid_amount(),
        b32(),
    )
        .prop_map(|(nonce, kv, erc20, amt, sk)| {
            let mut w = WithdrawScenario::new();
            w.evm_nonce = nonce;
            w.key_version = kv;
            w.erc20 = if erc20 == [0u8; 20] { [1u8; 20] } else { erc20 };
            w.amount = amt;
            w.sk = sk;
            w
        })
}

/// `completeWithdraw` — the attested outcome byte at equal weight over
/// `{0x00, 0x01, other}`. NOTE: "other" is NOT a rejection (see the
/// disagreement note in the notes' §"As built — step 1"); it routes to
/// the refund branch exactly as `0x00` does, and this strategy is what
/// pins that.
pub fn complete_withdraw() -> impl Strategy<Value = CompleteWithdrawScenario> {
    (
        settled_withdraw(),
        b32(),
        b32(),
        prop_oneof![Just(0u8), Just(1u8), 2u8..=255],
        any::<bool>(),
        any::<bool>(),
        initialized(),
    )
        .prop_map(|(w, mint_nonce, own_pk, outcome, pending, wrong_sk, init)| {
            let mut c = CompleteWithdrawScenario::new(outcome);
            c.w = w;
            c.w.initialized = init;
            c.mint_nonce = mint_nonce;
            c.own_pk = own_pk;
            c.pending = pending;
            if wrong_sk {
                let mut sk = c.w.sk;
                sk[0] ^= 0x5a;
                c.claimant_sk = Some(sk);
            }
            c
        })
}

/// A swap whose record a settle could be reading back.
fn settled_swap() -> impl Strategy<Value = SwapScenario> {
    (
        evm_nonce(),
        1u8..=255,
        any::<[u8; 20]>(),
        any::<[u8; 20]>(),
        valid_amount(),
        valid_amount(),
        b32(),
    )
        .prop_map(|(nonce, kv, tin, tout, aout, ainmax, sk)| {
            let mut s = SwapScenario::new();
            s.evm_nonce = nonce;
            s.key_version = kv;
            s.token_in = if tin == [0u8; 20] { [1u8; 20] } else { tin };
            s.token_out = if tout == [0u8; 20] { [2u8; 20] } else { tout };
            s.amount_out = aout;
            s.amount_in_max = ainmax;
            s.sk = sk;
            s
        })
}

/// `completeSwap` — `amountIn ∈ {0, 1, max, max−1, max+1}` at equal
/// weight, per the analysis. `max` is the exact spend (change 0, a
/// harmless 0-value coin); `max + 1` is THE underflow boundary and must
/// reject.
pub fn complete_swap() -> impl Strategy<Value = CompleteSwapScenario> {
    (
        settled_swap(),
        b32(),
        b32(),
        0u8..=5,
        any::<bool>(),
        any::<bool>(),
        initialized(),
        any::<u64>(),
    )
        .prop_map(
            |(s, mint_nonce, own_pk, band, pending, wrong_sk, init, rand)| {
                let mut c = CompleteSwapScenario::new();
                let max = s.amount_in_max_u64();
                c.s = s;
                c.s.initialized = init;
                c.mint_nonce = mint_nonce;
                c.own_pk = own_pk;
                c.pending = pending;
                c.amount_in = match band {
                    0 => 0,
                    1 => 1,
                    2 => max.saturating_sub(1),
                    3 => max,
                    4 => max.saturating_add(1),
                    _ => rand,
                };
                if wrong_sk {
                    let mut sk = c.s.sk;
                    sk[0] ^= 0x5a;
                    c.claimant_sk = Some(sk);
                }
                c
            },
        )
}

/// `refund` — BOTH routes at equal weight, plus the cross-route trap of
/// an id present in both pending markers (which must still route by
/// `refundCommitment.member` alone).
pub fn refund() -> impl Strategy<Value = RefundScenario> {
    (
        settled_withdraw(),
        settled_swap(),
        any::<bool>(),
        b32(),
        b32(),
        any::<bool>(),
        any::<bool>(),
        initialized(),
        prop_oneof![
            Just(minocrab_contracts::erc20_vault::MPC_FAILURE_OUTPUT),
            Just([0u8; 5]),
            Just([0xde, 0xad, 0xbe, 0xef, 0x00]),
            any::<[u8; 5]>(),
        ],
    )
        .prop_map(
            |(w, sw, is_withdrawal, mint_nonce, own_pk, wrong_sk, both, init, output)| {
                let route = if is_withdrawal {
                    RefundRoute::Withdrawal(w)
                } else {
                    RefundRoute::Swap(sw)
                };
                let mut r = RefundScenario::new(route);
                r.mint_nonce = mint_nonce;
                r.own_pk = own_pk;
                r.initialized = init;
                r.serialized_output = output;
                r.also_other_marker = both;
                if wrong_sk {
                    let mut sk = r.sk();
                    sk[0] ^= 0x5a;
                    r.claimant_sk = Some(sk);
                }
                r
            },
        )
}
