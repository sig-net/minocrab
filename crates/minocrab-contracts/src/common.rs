//! Shapes shared across the sig-net contracts.

use minocrab::{Circuit, FieldT, Wire};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_experimental::impact::raw::{
    cell_write_coin, counter_read, emit, kernel_claim_zswap_coin_receive,
    kernel_claim_zswap_coin_spend, kernel_claim_zswap_nullifier, kernel_mint_shielded, ImpactElem,
    LedgerValue,
};
use minocrab_std::kernel;
use minocrab_std::kernel::SelfAddress;
use minocrab_std::{
    CoinNonce, TokenDomainSeparator,
    coin_commitment, coin_nullifier_contract, token_type, CircuitAbi, CoinRecipient,
    ContractAddress, Secp256k1Point, ShieldedCoinInfo, Uint, B32,
};

pub use minocrab_signet::common::{
    witness_sk, Caip2Id, RefundCommitment, SecretKey, SigningPath, UserCommitment, VAULT_PATH,
};

/// A `Secp256k1Point`'s FAB alignment: x as b24+b8, y as b24+b8, plus a
/// native field element (notes/ledger-abi.org §3) — 5 limbs, matching
/// `encode`'s output.
///
/// The table itself lives on the argument type, because a
/// point's alignment is one fact: the same five atoms describe the value
/// entering a circuit and the value written to a `Secp256k1Point` cell.
pub fn secp256k1_point_atoms() -> Vec<AlignmentAtom> {
    Secp256k1Point::<Public>::atoms()
}

/// `userCommitment(sk) = upgradeFromTransient(transientHash([pad(32,
/// "vault:user:"), sk]))` — the vault's identity commitment since
/// signet-midnight-examples `0d9c1660` (the protocol move to Poseidon;
/// upstream accepted that a transientHash change at a fork re-keys derived
/// accounts). Four limbs in, one field element out, 31 bytes kept: a few
/// hundred rows where the SHA-256 forms cost ~1,500.
pub fn commitment_transient(c: &mut Circuit, sk: &SecretKey<Private>) -> UserCommitment<Private> {
    let sk = sk.bytes();
    c.region("identity commitment (transientHash)", |c| {
        let pad = minocrab_std::B32::pad(c, "vault:user:");
        let f = c.transient_hash(&[pad.hi.private(), pad.lo.private(), sk.hi, sk.lo]);
        UserCommitment(minocrab_std::hash::upgrade_from_transient(c, f))
    })
}

/// `right<ZswapCoinPublicKey, ContractAddress>(kernel.self())` — a fresh
/// kernel.self read packaged as a coin recipient (`is_left` = 0, the
/// unused left arm `default<ZswapCoinPublicKey>`).
fn self_recipient(c: &mut Circuit) -> CoinRecipient<Public> {
    let me = kernel::self_address(c);
    contract_recipient(c, me)
}

/// [`self_recipient`] against an address the caller already read.
fn contract_recipient(c: &mut Circuit, me: SelfAddress) -> CoinRecipient<Public> {
    let zero = c.constant(0u64);
    CoinRecipient {
        is_left: zero,
        left: minocrab_std::ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
        right: me.address(),
    }
}

fn b32_value(b: &B32<Public>) -> LedgerValue {
    LedgerValue::bytes(32, vec![ImpactElem::Wire(b.hi), ImpactElem::Wire(b.lo)])
}

/// The stdlib's `receiveShielded(coin)` (standard-library.compact:152-156):
/// `recipient = right(kernel.self());` `createZswapOutput(coin, recipient)`
/// (a Void witness — off-circuit only, nothing emitted);
/// `kernel.claimZswapCoinReceive(coinCommitment(coin, recipient))`.
pub fn receive_shielded(c: &mut Circuit, coin: &ShieldedCoinInfo<Public>) {
    c.region("coin: receive", |c| {
        let recipient = self_recipient(c);
        claim_receive(c, coin, &recipient);
    });
}

/// `kernel.claimZswapCoinReceive(coinCommitment(coin, recipient))`.
fn claim_receive(
    c: &mut Circuit,
    coin: &ShieldedCoinInfo<Public>,
    recipient: &CoinRecipient<Public>,
) {
    let cm = coin_commitment(c, coin, recipient);
    emit(c, &kernel_claim_zswap_coin_receive(&b32_value(&cm)));
}

/// `<field>.writeCoin(coin, right(kernel.self()))` on a top-level
/// `Cell<QualifiedShieldedCoinInfo>`: a fresh kernel.self read, the
/// runtime coin commitment (`rt-coin-commit`, the same coinCommitment
/// preimage), and the writeCoin op sequence resolving the Merkle-tree
/// index on chain.
pub fn write_coin_to_self(c: &mut Circuit, field: u8, coin: &ShieldedCoinInfo<Public>) {
    c.region("coin: write", |c| {
        let recipient = self_recipient(c);
        let cm = coin_commitment(c, coin, &recipient);
        let coin_val = LedgerValue::new(
            vec![
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 16 },
            ],
            vec![
                ImpactElem::Wire(coin.nonce.bytes().hi),
                ImpactElem::Wire(coin.nonce.bytes().lo),
                ImpactElem::Wire(coin.color.bytes().hi),
                ImpactElem::Wire(coin.color.bytes().lo),
                ImpactElem::Wire(coin.value),
            ],
        );
        emit(c, &cell_write_coin(field, &b32_value(&cm), &coin_val));
    });
}

/// The stdlib's full `mintShieldedToken(domain_sep, value, nonce,
/// recipient)` with a DYNAMIC recipient (claim.zkir:433-495): `color =
/// tokenType(domain_sep, kernel.self())`; `kernel.mintShielded(domain_sep,
/// value)`; `cm = coinCommitment({nonce, color, value}, recipient)`;
/// `kernel.claimZswapCoinSpend(cm)`; and the auto-receive branch — a
/// kernel.self read guarded by `!recipient.is_left`, the receive claim
/// guarded by `!is_left && recipient.right == self`. (mint_tokens keeps
/// its own constant-folded copy: compactc folds the branch away when the
/// recipient is a static `left`, and a constant-false-guarded op stream
/// would break PI equality there.)
pub fn mint_shielded_token(
    c: &mut Circuit,
    domain_sep: &TokenDomainSeparator<Public>,
    value: Uint<64, Public>,
    nonce: &CoinNonce<Public>,
    recipient: &CoinRecipient<Public>,
) {
    c.region("coin: mint", |c| {
        // color = tokenType(domain_sep, kernel.self())
        let me = kernel::self_address(c).bytes();
        let color = token_type(c, domain_sep, &me);

        // kernel.mintShielded(domain_sep, value)
        let ds_val = b32_value(&domain_sep.bytes());
        let amount_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(value.field())]);
        emit(c, &kernel_mint_shielded(&ds_val, &amount_val));

        // cm = coinCommitment({nonce, color, value}, recipient)
        let coin = ShieldedCoinInfo {
            nonce: *nonce,
            color,
            value: value.field(),
        };
        let cm = coin_commitment(c, &coin, recipient);
        let cm_val = b32_value(&cm);

        // kernel.claimZswapCoinSpend(cm)
        emit(c, &kernel_claim_zswap_coin_spend(&cm_val));

        // Auto-receive when minting to this contract itself.
        let not_left = c.not(recipient.is_left);
        let self2 = c.when(not_left, kernel::self_address).or_default().bytes();
        let eq_hi = c.test_eq(recipient.right.bytes().hi, self2.hi);
        let eq_lo = c.test_eq(recipient.right.bytes().lo, self2.lo);
        let eq = c.mul(eq_hi, eq_lo);
        let receive = c.mul(not_left, eq);
        c.when(receive, |c| emit(c, &kernel_claim_zswap_coin_receive(&cm_val)));
    });
}

/// A full-value burn that claims a nullifier: the contract spends a coin it
/// owns, so the spend is authorised by nullifying it.
///
/// The other burn is [`burn_spend`], and the difference is protocol rather
/// than cost — it emits a spend claim without nullifying, and its
/// well-formedness had to be proved against the pinned ledger before it could
/// be used (`tests/erc20_vault_opt_burn_wellformed.rs`). Neither is a cheaper
/// spelling of the other and they are not interchangeable.
///
/// `sendImmediateShielded(coin, shieldedBurnAddress(), coin.value)` as
/// compactc folds it for a full-value burn (withdraw.zkir:185-209): the
/// change is identically zero and the burn recipient is a static
/// `left(default)`, so only the spend path remains — a kernel.self read,
/// the nullifier claim, the nonce evolution, the output commitment to the
/// zero key, and the spend claim. (`createZswapInput`/`Output` are Void
/// witness natives — off-circuit only.)
pub fn burn_coin(
    c: &mut Circuit,
    one: Wire<FieldT, Public>,
    coin: &ShieldedCoinInfo<Public>,
) {
    c.region("coin: burn", |c| {
        // const selfAddr = kernel.self(); claimZswapNullifier(coinNullifier(...))
        let me = kernel::self_address(c);
        burn_body(c, one, me, coin);
    });
}

/// Everything [`burn_coin`] does after reading `kernel.self()`.
fn burn_body(
    c: &mut Circuit,
    one: Wire<FieldT, Public>,
    me: SelfAddress,
    coin: &ShieldedCoinInfo<Public>,
) {
    {
        let nul = coin_nullifier_contract(c, coin, &me.bytes());
        emit(c, &kernel_claim_zswap_nullifier(&b32_value(&nul)));

        // nonce' = upgradeFromTransient(transientHash([
        //   "midnight:kernel:nonce_evolve" as Field, degradeToTransient(nonce)
        // ])) — degrade takes the low limb; upgrade is [hi: 0, lo: mod 2^248].
        let tag = c.constant(
            minocrab::Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").expect("28 bytes fit"),
        );
        let evolved = c.transient_hash(&[tag, coin.nonce.bytes().lo]);
        let (_overflow, lo) = c.div_mod_power_of_two(evolved, 248);
        let zero = c.constant(0u64);
        let output = ShieldedCoinInfo {
            nonce: CoinNonce(B32 { hi: zero, lo }),
            color: coin.color,
            value: coin.value,
        };

        // cm = coinCommitment(output, shieldedBurnAddress()) — left(default).
        let burn = CoinRecipient {
            is_left: one,
            left: minocrab_std::ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
            right: ContractAddress(B32 { hi: zero, lo: zero }),
        };
        let cm = coin_commitment(c, &output, &burn);
        emit(c, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
    }
}

/// The optimized burn: the surrendered coin is
/// destroyed by a single claimed shielded spend of the burn-address output —
/// no `receiveShielded` custody claim and no nullifier. The user funds the
/// burn Output directly (`createZswapOutput(coin, shieldedBurnAddress())`, a
/// Void witness — off-circuit — with NO `createZswapInput` preceding it), and
/// the vault claims exactly that output's commitment as its spend. A claimed
/// shielded spend needs only "the commitment exists in this segment's offer,
/// unclaimed by another contract" (verify.rs:1559,1596-1608); the receive and
/// nullifier equalities are satisfied vacuously because `shieldedBurnAddress()`
/// is `left(default)` = `Recipient::User` (contract_address None), so the burn
/// output/input are not contract-associated. Value destruction is enforced by
/// the offer's Pedersen balance plus this circuit's colour/value constraints;
/// replay is the global `CommitmentAlreadyPresent` (the same gate as before,
/// now the only one). Well-formedness of exactly this shape against the pinned
/// ledger is proven in tests/erc20_vault_opt_burn_wellformed.rs.
///
/// A full-value burn as one claimed spend, with no nullifier claim and no
/// `kernel.self()` read — the burn recipient is `left(default)` rather than
/// self, so there is no owned coin to nullify. See [`burn_coin`] for the twin
/// that does nullify, and why the two names are not a cost distinction.
///
/// The burn Output keeps the port's evolved nonce (the transientHash +
/// div_mod, ~165 rows), so its commitment is byte-identical to the one the
/// compat burn already builds and the off-chain twin already constructs; only
/// the receive coinCommitment and the nullifier — two SHA-256 pair hashes,
/// ~11,280 rows — are removed. `me` is not read (the burn recipient is
/// `left(default)`, not `self`), so it is not a parameter.
pub fn burn_spend(
    c: &mut Circuit,
    one: Wire<FieldT, Public>,
    coin: &ShieldedCoinInfo<Public>,
) {
    c.region("coin: burn", |c| {
        // nonce' = upgradeFromTransient(transientHash([
        //   "midnight:kernel:nonce_evolve" as Field, degradeToTransient(nonce)
        // ])) — degrade takes the low limb; upgrade is [hi: 0, lo: mod 2^248].
        let tag = c.constant(
            minocrab::Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").expect("28 bytes fit"),
        );
        let evolved = c.transient_hash(&[tag, coin.nonce.bytes().lo]);
        let (_overflow, lo) = c.div_mod_power_of_two(evolved, 248);
        let zero = c.constant(0u64);
        let output = ShieldedCoinInfo {
            nonce: CoinNonce(B32 { hi: zero, lo }),
            color: coin.color,
            value: coin.value,
        };
        // cm = coinCommitment(output, shieldedBurnAddress()) — left(default).
        let burn = CoinRecipient {
            is_left: one,
            left: minocrab_std::ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
            right: ContractAddress(B32 { hi: zero, lo: zero }),
        };
        let cm = coin_commitment(c, &output, &burn);
        emit(c, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
    });
}

/// `mintShieldedToken(domain_sep, value, nonce, left(pk))` straight-line —
/// the shared body of the static-`left(pk)` mints: compactc folds the
/// recipient selects and the auto-receive branch.
///
/// One name for every artifact: the `kernel.self()` read comes from
/// [`kernel::self_address`], so a compat circuit gets its per-mint read
/// (compactc parity) and an opt-lineage circuit that opened with
/// [`kernel::cache_self_address`] gets the cached wires — a circuit that
/// mints twice (completeSwap) or on either of two branches (refund) states
/// "one read" once at its top instead of threading `me` through a `_with`
/// twin.
pub fn mint_shielded_token_to_key(
    c: &mut Circuit,
    domain_sep: &TokenDomainSeparator<Public>,
    value: Uint<64, Public>,
    nonce: &CoinNonce<Public>,
    pk: &minocrab_std::ZswapCoinPublicKey<Public>,
) {
    let me = kernel::self_address(c);
    c.region("coin: mint", |c| {
        let color = token_type(c, domain_sep, &me.bytes());

        let ds_val = b32_value(&domain_sep.bytes());
        let amount_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(value.field())]);
        emit(c, &kernel_mint_shielded(&ds_val, &amount_val));

        let one = c.constant(1u64);
        let zero = c.constant(0u64);
        let coin = ShieldedCoinInfo {
            nonce: *nonce,
            color,
            value: value.field(),
        };
        let left = CoinRecipient {
            is_left: one,
            left: *pk,
            right: ContractAddress(B32 { hi: zero, lo: zero }),
        };
        let cm = coin_commitment(c, &coin, &left);
        emit(c, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
    });
}

/// The one-shot gate: `assert(<counter at field> == 0)`.
pub fn assert_counter_zero(c: &mut Circuit, field: u8) {
    let count = counter_read(c, field);
    let zero = c.constant(0u64);
    let unset = c.test_eq(count, zero);
    c.assert(unset);
}

