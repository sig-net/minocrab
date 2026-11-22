//! The 32-byte protocol values a Signet request is built from, and the
//! contract's own signing path.

use minocrab::{Circuit, FieldT};
use minocrab::{Private, Public};
use minocrab_std::{b32_newtype, B32};

/// The vault's MPC derivation path, `pad(32, "vault")` — the constant
/// [`SigningPath::contract_path`] pads.
pub const VAULT_PATH: &str = "vault";

b32_newtype! {
    /// The witnessed vault secret key (`witness …SecretKey(): Bytes<32>`) —
    /// what an identity commitment is derived from, and the first
    /// preimage limb of every refund commitment. Constructed only by [`witness_sk`], so nothing but a
    /// witnessed secret key can reach those derivations: any other private
    /// `B32` in scope (a nonce, a colour, a request id) does not
    /// type-check there (newtype-survey hazard A2).
    SecretKey,
    /// An identity commitment — the MPC's key-derivation path, i.e. the
    /// value that decides which EVM account is derived. Produced only by
    /// the vault's `commitment_transient`; the stored
    /// deployer and every depositor/caller comparison carry this type, so
    /// no other 32-byte value (a nonce, a colour, a request id, a refund
    /// commitment) can be compared against or written as one —
    /// newtype-survey hazard A3, the family whose near-unification would
    /// have "silently restranded every derived account"
    /// (notes/vault-vocabulary.org §0).
    UserCommitment,
    /// A refund commitment — `refundCommitment(sk, requestId)`, one
    /// derivation for the withdraw, swap, supply and redeem flows (the
    /// settle-view maps distinguish which flow holds one). Produced only by
    /// `erc20_vault::refund_commitment` and the `Pending` lineage's
    /// `Commit::to`, stored and looked up as this type, so a
    /// [`UserCommitment`] (or any other 32-byte value) cannot satisfy
    /// a withdrawer/swapper gate — newtype-survey hazard A4.
    RefundCommitment,
    /// The MPC's signing path — slot 5 of the sign-bidirectional event
    /// record, the value the MPC derives its signing key from. Genuinely
    /// polymorphic (deposit signs from the depositor's [`UserCommitment`];
    /// withdraw/swap/approveRouter from the constant vault path), which is
    /// why it is one type with exactly two constructors —
    /// `SigningPath::from(user_commitment)` and [`SigningPath::vault_path`]
    /// — rather than four: nothing else fits the slot, so the
    /// sender/path/caip2 transposition of newtype-survey hazard A7 no
    /// longer compiles.
    SigningPath,
    /// A CAIP-2 chain id — slot 7 of the event record and the vault's
    /// `caip2Id` cell. Distinct from [`SigningPath`] so the MPC can never
    /// be asked to derive a signing key from a chain id (hazard A7's
    /// sharpest transposition).
    Caip2Id,
}

/// A depositor's identity commitment is a signing path — deposit's event
/// signs from it. The only conversion into [`SigningPath`] besides
/// [`SigningPath::vault_path`].
impl<V: minocrab_std::Vis> From<UserCommitment<V>> for SigningPath<V> {
    fn from(commitment: UserCommitment<V>) -> Self {
        SigningPath(commitment.bytes())
    }
}

impl SigningPath<Public> {
    /// `pad(32, "vault")` — the contract-authored path the non-deposit
    /// circuits sign from.
    ///
    /// The vault's spelling of [`Self::contract_path`], kept because the
    /// deployed lineage names it (and because its pad is the vault's).
    pub fn vault_path(c: &mut Circuit) -> Self {
        Self::contract_path(c)
    }

    /// The contract's own signing path — the constant the MPC derives this
    /// contract's EVM account from, and the value `evm_flow::Pending::request`
    /// files without asking the caller for it.
    ///
    /// It is a constant of the contract, not an input: a request that could
    /// name its own path could ask the MPC to sign from somebody else's
    /// account. Every lineage in this workspace derives from the same
    /// pad ([`VAULT_PATH`], `pad(32, "vault")`), so this is that
    /// pad under a name that does not say "vault"; making the pad
    /// per-contract is queued with the nonce and the gas policy
    /// (notes/evm-calls.org §7).
    pub fn contract_path(c: &mut Circuit) -> Self {
        SigningPath(B32::pad(c, VAULT_PATH))
    }
}

/// Witness a secret key (`witness …SecretKey(): Bytes<32>`), input-constrained.
/// The only [`SecretKey`] constructor.
pub fn witness_sk(c: &mut Circuit) -> SecretKey<Private> {
    let sk = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    sk.constrain_input(c);
    SecretKey(sk)
}
