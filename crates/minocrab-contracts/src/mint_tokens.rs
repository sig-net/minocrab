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

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{label, Fr, Private, Public};
use minocrab_ledger::{
    cell_write, emit, kernel_claim_zswap_coin_spend, kernel_mint_shielded,
    ImpactElem, LedgerValue,
};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    CoinNonce, ContractAddress, TokenDomainSeparator, ZswapCoinPublicKey,
    circuit, coin_commitment, own_public_key, token_type, CoinRecipient, Disclose, Discloses,
    ShieldedCoinInfo3, B32,
};

/// Ledger field indices, in declaration order.
pub const VERY_PUBLIC_VALUE: u8 = 0;

label! {
    MintRecipient = "mint recipient";
    MintNonce = "mint nonce";
    OwnKeyAsMintRecipient = "own public key as mint recipient";
    OwnKeyOnLedger = "own public key on the ledger";
}

/// The mint's domain separator.
pub const DOMAIN_SEP: &str = "testy-test";

/// The stdlib's `mintShieldedToken(pad(32, DOMAIN_SEP), 1, nonce,
/// left(recipient))`: `color = tokenType(domain_sep, kernel.self())`;
/// `kernel.mintShielded(domain_sep, 1)`; `cm = coinCommitment({nonce,
/// color, 1}, left(recipient))`; `kernel.claimZswapCoinSpend(cm)`.
fn mint_shielded_token(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    nonce: &CoinNonce<Public>,
    recipient: &ZswapCoinPublicKey<Public>,
) {
    let zero = c.constant(0u64);

    // color = tokenType(domain_sep, kernel.self())
    let me = kernel::self_address(c).bytes();
    let domain_sep = TokenDomainSeparator(B32::pad(c, DOMAIN_SEP));
    let color = token_type(c, &domain_sep, &me);
    let domain_sep = domain_sep.bytes();

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
        right: ContractAddress(B32 { hi: zero, lo: zero }), // default<ContractAddress>
    };
    let cm = coin_commitment(c, &coin, &left);

    // kernel.claimZswapCoinSpend(cm)
    let cm_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(cm.hi), ImpactElem::Wire(cm.lo)]);
    emit(c, one, &kernel_claim_zswap_coin_spend(&cm_val));
}

/// `export circuit mintWithRecipientArgument(recipient: ZswapCoinPublicKey,
/// mintNonce: Bytes<32>): []`
#[circuit]
pub fn mint_with_recipient_argument(
    c: &mut Circuit3,
    recipient: ZswapCoinPublicKey<Private>,
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(MintRecipient, MintNonce)> {
    let one = c.constant(1u64);

    let recipient = recipient.disclose_as::<MintRecipient>(c);
    let nonce = mint_nonce.disclose_as::<MintNonce>(c);
    mint_shielded_token(c, one, &nonce, &recipient);
    Discloses::of(())
}

/// `export circuit mintWithRecipientOwnPublicKey(recipient: ZswapCoinPublicKey,
/// mintNonce: Bytes<32>): []` — the `recipient` argument is declared but
/// unused (a slot that exists for the wire shape alone, hence the leading
/// underscore); the mint goes to `ownPublicKey()`, which is also written to
/// `veryPublicValue`.
#[circuit]
pub fn mint_with_recipient_own_public_key(
    c: &mut Circuit3,
    _recipient: B32<Private>,
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(OwnKeyAsMintRecipient, OwnKeyOnLedger, MintNonce)> {
    let one = c.constant(1u64);

    // const mintRecipient = ownPublicKey();
    let mint_recipient = own_public_key(c).disclose_as::<OwnKeyAsMintRecipient>(c);

    // veryPublicValue = ownPublicKey();
    let very_public = own_public_key(c).disclose_as::<OwnKeyOnLedger>(c);
    let value = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(very_public.bytes().hi),
            ImpactElem::Wire(very_public.bytes().lo),
        ],
    );
    emit(c, one, &cell_write(VERY_PUBLIC_VALUE, &value));

    let nonce = mint_nonce.disclose_as::<MintNonce>(c);
    mint_shielded_token(c, one, &nonce, &mint_recipient);
    Discloses::of(())
}
