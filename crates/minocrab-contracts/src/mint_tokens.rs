//! `mint-tokens` (signet-midnight-experiments) — shielded token minting:
//! the first circuits exercising `kernel.self()` and the zswap/kernel
//! effects ops (mintShielded + claimZswapCoinSpend).
//!
//! Compact original:
//! ```text
//! export circuit mintWithRecipientArgument(recipient: ZswapCoinPublicKey,
//!                                          mintNonce: Bytes<32>): [] {
//!   const mintRecipient = disclose(recipient);
//!   mintShieldedToken(pad(32, "testy-test"), 1 as Uint<64>,
//!                     disclose(mintNonce),
//!                     left<ZswapCoinPublicKey, ContractAddress>(mintRecipient));
//! }
//! ```
//! where the stdlib's `mintShieldedToken(domain_sep, value, nonce, recipient)`
//! composes: `color = tokenType(domain_sep, kernel.self())`;
//! `kernel.mintShielded(domain_sep, value)`;
//! `cm = coinCommitment(ShieldedCoinInfo { nonce, color, value }, recipient)`;
//! `kernel.claimZswapCoinSpend(cm)`.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{Fr, Public};
use minocrab_ledger::{
    cell_write, emit, kernel_claim_zswap_coin_spend, kernel_mint_shielded, kernel_self,
    ImpactElem, LedgerValue,
};
use minocrab_std::v3::{
    coin_commitment, own_public_key, token_type, CoinRecipient, ShieldedCoinInfo3, B32,
};

/// Ledger field indices, in declaration order.
pub const VERY_PUBLIC_VALUE: u8 = 0;

/// The mint's domain separator.
pub const DOMAIN_SEP: &str = "testy-test";

/// The stdlib's `mintShieldedToken(pad(32, DOMAIN_SEP), 1, nonce,
/// left(recipient))`: `color = tokenType(domain_sep, kernel.self())`;
/// `kernel.mintShielded(domain_sep, 1)`; `cm = coinCommitment({nonce,
/// color, 1}, left(recipient))`; `kernel.claimZswapCoinSpend(cm)`.
fn mint_shielded_token(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    recipient: &B32<Public>,
) {
    let zero = c.constant(0u64);

    // color = tokenType(domain_sep, kernel.self())
    let me = kernel_self(c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let domain_sep = B32::pad(c, DOMAIN_SEP);
    let color = token_type(c, &domain_sep, &me);

    // kernel.mintShielded(domain_sep, 1)
    let ds_val = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(domain_sep.hi),
            ImpactElem::Wire(domain_sep.lo),
        ],
    );
    let amount = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(1u64))]);
    emit(c, one, &kernel_mint_shielded(&ds_val, &amount));

    // cm = coinCommitment({nonce, color, value: 1}, left(recipient))
    let coin = ShieldedCoinInfo3 {
        nonce: *nonce,
        color,
        value: one,
    };
    let left = CoinRecipient {
        is_left: one,
        left: *recipient,
        right: B32 { hi: zero, lo: zero }, // default<ContractAddress>
    };
    let cm = coin_commitment(c, &coin, &left);

    // kernel.claimZswapCoinSpend(cm)
    let cm_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(cm.hi), ImpactElem::Wire(cm.lo)]);
    emit(c, one, &kernel_claim_zswap_coin_spend(&cm_val));
}

/// `export circuit mintWithRecipientArgument(recipient, mintNonce): []`
pub fn mint_with_recipient_argument() -> Compiled3 {
    let mut c = Circuit3::new();
    let recipient = B32 {
        hi: c.arg::<FieldT>("recipient_hi"),
        lo: c.arg::<FieldT>("recipient_lo"),
    };
    let mint_nonce = B32 {
        hi: c.arg::<FieldT>("mintNonce_hi"),
        lo: c.arg::<FieldT>("mintNonce_lo"),
    };
    recipient.constrain_input(&mut c);
    mint_nonce.constrain_input(&mut c);
    let one = c.constant(1u64);

    let recipient = B32 {
        hi: c.disclose(recipient.hi, "mint recipient (hi)"),
        lo: c.disclose(recipient.lo, "mint recipient (lo)"),
    };
    let nonce = B32 {
        hi: c.disclose(mint_nonce.hi, "mint nonce (hi)"),
        lo: c.disclose(mint_nonce.lo, "mint nonce (lo)"),
    };
    mint_shielded_token(&mut c, one, &nonce, &recipient);
    c.finish(true)
}

/// `export circuit mintWithRecipientOwnPublicKey(recipient, mintNonce): []`
/// — the `recipient` argument is declared but unused; the mint goes to
/// `ownPublicKey()`, which is also written to `veryPublicValue`.
pub fn mint_with_recipient_own_public_key() -> Compiled3 {
    let mut c = Circuit3::new();
    let recipient = B32 {
        hi: c.arg::<FieldT>("recipient_hi"),
        lo: c.arg::<FieldT>("recipient_lo"),
    };
    let mint_nonce = B32 {
        hi: c.arg::<FieldT>("mintNonce_hi"),
        lo: c.arg::<FieldT>("mintNonce_lo"),
    };
    recipient.constrain_input(&mut c);
    mint_nonce.constrain_input(&mut c);
    let one = c.constant(1u64);

    // const mintRecipient = ownPublicKey();
    let mint_recipient = own_public_key(&mut c);
    let mint_recipient = B32 {
        hi: c.disclose(mint_recipient.hi, "own public key as mint recipient (hi)"),
        lo: c.disclose(mint_recipient.lo, "own public key as mint recipient (lo)"),
    };

    // veryPublicValue = ownPublicKey();
    let very_public = own_public_key(&mut c);
    let very_public = B32 {
        hi: c.disclose(very_public.hi, "own public key on the ledger (hi)"),
        lo: c.disclose(very_public.lo, "own public key on the ledger (lo)"),
    };
    let value = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(very_public.hi),
            ImpactElem::Wire(very_public.lo),
        ],
    );
    emit(&mut c, one, &cell_write(VERY_PUBLIC_VALUE, &value));

    let nonce = B32 {
        hi: c.disclose(mint_nonce.hi, "mint nonce (hi)"),
        lo: c.disclose(mint_nonce.lo, "mint nonce (lo)"),
    };
    mint_shielded_token(&mut c, one, &nonce, &mint_recipient);
    c.finish(true)
}
