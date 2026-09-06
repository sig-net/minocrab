//! THE DUST SEAM — where M30 rung C plugs in, and nothing more.
//!
//! A transaction on Midnight pays its fee in DUST. Every primitive for that
//! exists in `midnight_ledger::dust` — `DustLocalState::{replay_events, spend,
//! process_ttls, wallet_balance}`, `Transaction::balance`, `DustActions` — and
//! no wallet has been written around them in Rust anywhere
//! (notes/mpc-publisher.org §2: the one GAP). Writing that wallet is M30 rung
//! C and is deliberately NOT in this crate yet.
//!
//! What is here is the shape of the hole, so that the rest of the pipeline is
//! finished rather than pending: [`DustBalancer`] is the one call the publish
//! path makes, and [`NoDust`] is the implementation the tests run.
//!
//! # What rung C's implementation has to do
//!
//! `midnight_ledger::test_utilities`' `balance_tx` (`test_utilities.rs:479-640`)
//! is the reference for the shape, though not for the policy:
//!
//! 1. `tx.balance(Some(tx.fees_with_impl(parameters, …)))` → the DUST deficit
//!    at segment 0. Fees depend on the transaction's own size, so this runs on
//!    the PROVEN transaction and iterates until the deficit closes.
//! 2. Pick UTXOs out of a `DustLocalState` replayed from ledger events, value
//!    each with `DustOutput::updated_value(gen_info, now, &parameters.dust)`,
//!    and `spend` them.
//! 3. Put the spends in a `DustActions { spends, registrations, ctime }` on a
//!    fresh intent, prove that intent, and `merge` it.
//! 4. `process_ttls`, and only report ready when the replayed state has caught
//!    up past the block the publisher pinned.
//!
//! and the policies it does NOT settle, which the milestone names: the state
//! must be persisted and REBUILDABLE FROM GENESIS (the event source is
//! untrusted — §5.3), one submit at a time while there is a single DUST UTXO,
//! and the funding seed is a hot key either way.
//!
//! # Why the seam is here and not at the call site
//!
//! Because the ORDER matters and this is where it is decided: build, prove,
//! balance, sign, seal. Balancing after proving is what the sidecar does
//! (`prove` then `balanceUnboundTransaction`) and it is forced — the fee
//! depends on the proof sizes. Signing after balancing is forced too: a dust
//! registration added by the wallet is signed by `Intent::sign`'s third key
//! list. Sealing last is forced by the type: `well_formed` only accepts a
//! `PureGeneratorPedersen` binding.

use midnight_base_crypto::time::Timestamp;
use midnight_ledger::structure::LedgerParameters;
use midnight_storage::db::DB;

use crate::error::PublishError;
use crate::intent::ProvenTx;

/// The one call the publish path makes into a DUST wallet.
///
/// `async` because a real implementation proves the dust spend, which is an
/// async call; `&mut self` because spending advances the wallet's own state.
#[allow(
    async_fn_in_trait,
    reason = "the same shape the ledger's own ProvingProvider/Resolver traits \
              have; a publisher holds its wallet on one task"
)]
pub trait DustBalancer<D: DB> {
    /// Return `tx` with enough DUST spent to cover its fee under
    /// `parameters`, valued at `ctime`.
    async fn balance(
        &mut self,
        tx: ProvenTx<D>,
        parameters: &LedgerParameters,
        ctime: Timestamp,
    ) -> Result<ProvenTx<D>, PublishError>;
}

/// The balancer that does not balance: it hands the transaction straight back.
///
/// Everything downstream of it works — signing, sealing, `well_formed`,
/// `apply` — as long as `WellFormedStrictness::enforce_balancing` is OFF. On a
/// real chain it is on, so a transaction published through [`NoDust`] pays no
/// fee and is rejected. That is exactly the gap M30 rung C closes, and it is
/// named in the type rather than left as a comment somewhere.
pub struct NoDust;

impl<D: DB> DustBalancer<D> for NoDust {
    async fn balance(
        &mut self,
        tx: ProvenTx<D>,
        _parameters: &LedgerParameters,
        _ctime: Timestamp,
    ) -> Result<ProvenTx<D>, PublishError> {
        Ok(tx)
    }
}
