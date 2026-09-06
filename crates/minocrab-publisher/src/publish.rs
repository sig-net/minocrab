//! M30 rung B — build → prove → balance → sign → seal, as four steps and one
//! pipeline.
//!
//! Each step is a free function taking what it needs, so a caller can stop
//! after any of them (mpc's `IntentClient` builds and returns an intent
//! without proving it, for one) and so each is unit-testable on its own. The
//! pipeline is [`publish`].
//!
//! # The purity claim, spelled out
//!
//! Everything a chain would tell the publisher arrives in [`ChainContext`]:
//! the contract's state, the chain's `LedgerParameters` and cost model, the
//! network id and the segment. The funding keys arrive in [`FundingKeys`] and
//! the dust state lives behind [`crate::dust::DustBalancer`]. Nothing in this
//! module opens a socket, and the only files it touches are the ones the
//! prover reads: the managed key directory, and the KZG parameter cache.

use std::ops::Deref;

use midnight_base_crypto::rng::SplittableRng;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger::structure::{
    LedgerParameters, ProofKind, SigningKey, Signature, StandardTransaction, Transaction,
};
use midnight_onchain_runtime::cost_model::CostModel;
use midnight_onchain_state::state::ChargedState;
use midnight_storage::db::DB;
use midnight_transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::ProvingProvider;
use rand::{CryptoRng, Rng};

use crate::call::SignerCall;
use crate::dust::DustBalancer;
use crate::error::PublishError;
use crate::intent::{build_intent, preimage_tx, PreimageTx, ProvenTx, SealedTx};

/// Everything the chain tells the publisher, and nothing it invents.
///
/// `parameters` is the CHAIN's — `LedgerState::parameters`, fetched from the
/// node — and not `INITIAL_PARAMETERS`: see [`crate::call`]'s header for the
/// 2.208 ms vs 1.303 ms measurement that makes this a correctness matter
/// rather than a tidiness one.
pub struct ChainContext<D: DB> {
    /// The singleton's state at the block the publisher pinned. Empty for the
    /// three signer circuits ([`crate::call::empty_state`]), but supplied
    /// rather than assumed, because the transcript is partitioned against it.
    pub contract_state: ChargedState<D>,
    pub parameters: LedgerParameters,
    /// The Impact VM cost model `Transaction::prove` charges the transcript
    /// against (`INITIAL_COST_MODEL` unless the chain says otherwise).
    pub cost_model: CostModel,
    pub network_id: String,
    /// The segment the intent sits in. Never 0 — that is the guaranteed
    /// segment and the ledger refuses an intent there.
    pub segment: u16,
    /// The block time the publisher pinned its read of the chain at. DUST is
    /// valued at a time (`DustOutput::updated_value`), so the dust seam gets
    /// this rather than inventing a clock.
    pub tblock: Timestamp,
}

/// The keys that sign an intent.
///
/// All three lists are empty for a respond intent as it stands today: it
/// carries no unshielded offer and no dust registration, so `Intent::sign`
/// has nothing to sign and the transaction's authority is its proof. They are
/// here because M30 rung C's dust registrations are signed by the third list,
/// and because "the funding seed is a hot key either way"
/// (notes/mpc-publisher.org §5.3) is a fact about this struct.
#[derive(Default)]
pub struct FundingKeys {
    pub guaranteed: Vec<SigningKey>,
    pub fallible: Vec<SigningKey>,
    pub dust_registration: Vec<SigningKey>,
}

/// BUILD: one signer call, one intent, one transaction — not yet proved.
pub fn build<D: DB, R: Rng + CryptoRng + ?Sized>(
    ctx: &ChainContext<D>,
    call: &SignerCall<D>,
    comm_rand: Fr,
    ttl: Timestamp,
    rng: &mut R,
) -> Result<PreimageTx<D>, PublishError> {
    let proto = call.prototype(&ctx.contract_state, &ctx.parameters, comm_rand)?;
    let intent = build_intent(rng, vec![proto], ttl);
    Ok(preimage_tx(&ctx.network_id, ctx.segment, intent))
}

/// PROVE: in process, through `prover`.
pub async fn prove<D: DB>(
    ctx: &ChainContext<D>,
    tx: &PreimageTx<D>,
    prover: impl ProvingProvider,
) -> Result<ProvenTx<D>, PublishError> {
    tx.prove(prover, &ctx.cost_model)
        .await
        .map_err(|e| PublishError::Proving(format!("{e:?}")))
}

/// SIGN: `Intent::sign` for every intent in the transaction, at its own
/// segment id.
///
/// Generic over the proof kind so that the step is the same one whether it
/// runs on a proved transaction or on a preimage one — `data_to_sign` erases
/// proofs and signatures before hashing, so the signature does not depend on
/// which.
pub fn sign<P: ProofKind<D>, D: DB>(
    tx: Transaction<Signature, P, PedersenRandomness, D>,
    keys: &FundingKeys,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<Transaction<Signature, P, PedersenRandomness, D>, PublishError> {
    let stx = match tx {
        Transaction::Standard(stx) => stx,
        // A `ClaimRewards` transaction has no intents to sign; nothing a
        // publisher builds is one, and passing it through unchanged is the
        // honest answer rather than an error about a shape we did not ask for.
        other => return Ok(other),
    };
    let mut signed = midnight_storage::storage::HashMap::new();
    for seg_x_intent in stx.intents.iter() {
        let segment = *seg_x_intent.0.deref();
        let intent = seg_x_intent.1.deref().clone();
        let intent = intent
            .sign(rng, segment, &keys.guaranteed, &keys.fallible, &keys.dust_registration)
            .map_err(|e| PublishError::Signing(format!("{e:?}")))?;
        signed = signed.insert(segment, intent);
    }
    Ok(Transaction::Standard(StandardTransaction {
        network_id: stx.network_id.clone(),
        intents: signed,
        guaranteed_coins: stx.guaranteed_coins.clone(),
        fallible_coins: stx.fallible_coins.clone(),
        binding_randomness: stx.binding_randomness,
    }))
}

/// SEAL: `PedersenRandomness` → `PureGeneratorPedersen`, the only binding
/// shape `well_formed` accepts. Must come last: it closes over every intent's
/// contents, so anything merged in afterwards would invalidate it.
pub fn seal<P: ProofKind<D>, D: DB>(
    tx: &Transaction<Signature, P, PedersenRandomness, D>,
    rng: impl CryptoRng + SplittableRng,
) -> Transaction<Signature, P, PureGeneratorPedersen, D> {
    tx.seal(rng)
}

/// The whole pipeline, in the order the steps are forced into
/// ([`crate::dust`] has the argument): build, prove, balance, sign, seal.
///
/// `rng` is split per step, so each step's randomness is reproducible from the
/// one seed a caller supplies.
#[allow(clippy::too_many_arguments)]
pub async fn publish<D: DB>(
    ctx: &ChainContext<D>,
    call: &SignerCall<D>,
    comm_rand: Fr,
    ttl: Timestamp,
    prover: impl ProvingProvider,
    dust: &mut impl DustBalancer<D>,
    keys: &FundingKeys,
    mut rng: impl CryptoRng + SplittableRng,
) -> Result<SealedTx<D>, PublishError> {
    let built = build(ctx, call, comm_rand, ttl, &mut rng.split())?;
    let proven = prove(ctx, &built, prover).await?;
    let balanced = dust.balance(proven, &ctx.parameters, ctx.tblock).await?;
    let signed = sign(balanced, keys, &mut rng.split())?;
    Ok(seal(&signed, rng.split()))
}
