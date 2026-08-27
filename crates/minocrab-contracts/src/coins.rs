//! `coins.compact` — the three COIN ARMS of the collection ADTs, one circuit
//! each (M22 stage A, notes/coin-arms-nested-adts.org §1).
//!
//! `Set.insertCoin`, `Map.insertCoin` and `List.pushFrontCoin` exist only
//! under `(when (= value_type QualifiedShieldedCoinInfo))` in
//! midnight-ledger.ss, which is why all three collections here hold that one
//! element type. The fourth member of the family, `Cell.writeCoin`, is M5's
//! and is differential-checked against xcall-with-payment's `notify.zkir`.
//!
//! ALL FOUR ARE ONE SUBSEQUENCE. Each is its plain twin — `insert`,
//! `insert`, `pushFront`, `write` — with one push replaced by the QUALIFY
//! DANCE, six instructions that resolve the coin's Merkle-tree index in the
//! transaction context and concatenate it on (`minocrab_ledger`'s
//! `qualify_coin`). What differs between them is the `dup` reach — 4, 5, 7
//! and 3 — and `List.pushFrontCoin`'s extra eight instructions, which exist
//! because a list node cannot be pushed with a value that does not yet exist.
//!
//! Not a corpus contract, for the fifth milestone running and a sharper
//! reason than usual: the three arms have REAL third-party demand
//! (OpenZeppelin's `ShieldedTreasury` keeps its coins in a
//! `Map<Bytes<32>, QualifiedShieldedCoinInfo>`), but OZ's artifacts are ZKIR
//! v2, and across the three `--feature-zkir-v3` corpus sources the three arms
//! are used ZERO times. So the source is ours, lives beside its differential
//! at `tests/fixtures/coins/`, and is compiled with the PINNED compactc — the
//! invocation is in the fixture's header.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_std::v3::{
    CoinColor, CoinNonce,
    contract, label, CircuitArg, CoinRecipient, ContractAddress, Disclose, Discloses,
    Either, Ledger, LedgerList, LedgerMap, LedgerSet, QualifiedShieldedCoinInfo3,
    ShieldedCoinInfo3, Uint, ZswapCoinPublicKey, B32,
};

label! {
    Key = "key";
    Coin = "coin";
    Recipient = "recipient";
}

/// THE LEDGER BLOCK — declaration order is the field index, matching the
/// fixture's `export ledger` block one for one.
#[derive(Ledger)]
pub struct Coins {
    pub s: LedgerSet<QualifiedShieldedCoinInfo3<Public>>,
    pub m: LedgerMap<B32<Public>, QualifiedShieldedCoinInfo3<Public>>,
    pub l: LedgerList<QualifiedShieldedCoinInfo3<Public>>,
}

/// The contract's ledger block.
pub const COINS: Coins = Coins::new();

/// `ShieldedCoinInfo` as an argument — the UNQUALIFIED coin all three arms
/// take, and qualify on chain.
#[derive(CircuitArg)]
struct ShieldedCoinArg {
    nonce: CoinNonce<Private>,
    color: CoinColor<Private>,
    value: Uint<128>,
}

impl ShieldedCoinArg {
    /// Disclose the whole coin under one label — a coin is one logical value,
    /// and every field of it reaches the transcript together.
    fn disclose<L: minocrab_std::v3::DisclosureLabel>(
        self,
        c: &mut Circuit3,
    ) -> ShieldedCoinInfo3<Public> {
        ShieldedCoinInfo3 {
            nonce: self.nonce.disclose_as::<L>(c),
            color: self.color.disclose_as::<L>(c),
            value: self.value.disclose_as::<L>(c).field(),
        }
    }
}

/// `Either<ZswapCoinPublicKey, ContractAddress>` as an argument — Compact's
/// `ShieldedRecipient`, the second argument of every coin arm.
type RecipientArg = Either<ZswapCoinPublicKey<Private>, ContractAddress<Private>, Private>;

/// Disclose a recipient into the tag-and-two-arms shape `coinCommitment`
/// selects over.
fn recipient(c: &mut Circuit3, r: RecipientArg) -> CoinRecipient<Public> {
    let r = r.disclose_as::<Recipient>(c);
    CoinRecipient {
        is_left: r.is_left.field(),
        left: r.left,
        right: r.right,
    }
}

#[contract]
impl Coins {
    /// `export circuit setInsertCoin(coin: ShieldedCoinInfo, recipient:
    /// Either<ZswapCoinPublicKey, ContractAddress>): []
    /// { s.insertCoin(disclose(coin), disclose(recipient)); }`
    #[circuit]
    pub fn set_insert_coin(
        c: &mut Circuit3,
        coin: ShieldedCoinArg,
        r: RecipientArg,
    ) -> Discloses<(Coin, Recipient)> {
        let coin = coin.disclose::<Coin>(c);
        let r = recipient(c, r);
        COINS.s.insert_coin(c, &coin, &r);
        Discloses::of(())
    }

    /// `export circuit mapInsertCoin(k: Bytes<32>, coin: ShieldedCoinInfo,
    /// recipient: Either<ZswapCoinPublicKey, ContractAddress>): []
    /// { m.insertCoin(disclose(k), disclose(coin), disclose(recipient)); }`
    #[circuit]
    pub fn map_insert_coin(
        c: &mut Circuit3,
        k: B32<Private>,
        coin: ShieldedCoinArg,
        r: RecipientArg,
    ) -> Discloses<(Key, Coin, Recipient)> {
        let k = k.disclose_as::<Key>(c);
        let coin = coin.disclose::<Coin>(c);
        let r = recipient(c, r);
        COINS.m.insert_coin(c, &k, &coin, &r);
        Discloses::of(())
    }

    /// `export circuit listPushFrontCoin(coin: ShieldedCoinInfo, recipient:
    /// Either<ZswapCoinPublicKey, ContractAddress>): []
    /// { l.pushFrontCoin(disclose(coin), disclose(recipient)); }`
    #[circuit]
    pub fn list_push_front_coin(
        c: &mut Circuit3,
        coin: ShieldedCoinArg,
        r: RecipientArg,
    ) -> Discloses<(Coin, Recipient)> {
        let coin = coin.disclose::<Coin>(c);
        let r = recipient(c, r);
        COINS.l.push_front_coin(c, &coin, &r);
        Discloses::of(())
    }
}
