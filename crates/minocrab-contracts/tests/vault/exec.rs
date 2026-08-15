//! The reference EXECUTOR: the missing link between MinoCrab's Impact op
//! streams and ledger semantics.
//!
//! Until M10 the whole workspace only ever *encoded* ops (`Op::field_repr`
//! into a `ProofPreimage`) and compared encodings. Nothing ever ran them.
//! This module runs them, on a real contract state, through Midnight's own
//! driver — [`QueryContext::query`], which owns the `[context, effects,
//! state]` stack convention, the nine-map `Effects` encode/decode and the
//! charged-state gas accounting (onchain-runtime/src/context.rs:922-979).
//! We reuse it rather than re-deriving any of that.
//!
//! What running buys that encoding never could:
//!
//! - the op stream is well-formed at all (stack discipline, cache
//!   discipline, `Idx` paths that exist, `Popeq` results that MATCH the
//!   real state — `ResultModeVerify::process_read` errors on mismatch);
//! - the declared `Effects` are the ones the ledger would compute, which
//!   is exactly the equality `semantics.rs:1441-1447` enforces when a
//!   transaction is applied;
//! - the post-state is a real post-state, so a spec's state assertions are
//!   checked against the ledger's own state machine.

use std::ops::Deref;

use midnight_base_crypto::fab::AlignedValue;
use midnight_coin_structure::contract::ContractAddress;
use midnight_base_crypto::hash::HashOutput;
use midnight_onchain_runtime::context::{Effects, QueryContext, QueryResults};
use midnight_onchain_state::state::{ChargedState, StateValue};
use midnight_onchain_vm::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_vm::ops::{Op, VersionedLogItem};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap};

use super::prims::{bytesn_value, cell, VmOp};

/// The vault's ledger state, one field per Compact declaration. Field
/// indices are [`minocrab_contracts::erc20_vault`]'s constants; the array
/// order here IS that numbering, so a mis-numbered circuit read fails at
/// `Popeq` rather than silently reading a neighbour.
#[derive(Clone, Debug, Default)]
pub struct PreState {
    /// field 0 — `signBidirectionalEventMap: requestId -> record`.
    pub sign_event_map: Vec<([u8; 32], AlignedValue)>,
    /// field 1 — `signetSigner`.
    pub signet_signer: [u8; 32],
    /// field 2 — `mpcResponseKey` (a `Secp256k1Point`, 5 FAB limbs).
    pub mpc_response_key: Option<AlignedValue>,
    /// field 3 — `signetRequestNonce: Counter`.
    pub request_nonce: u64,
    /// field 4 — `initialized: Counter`.
    pub initialized: u64,
    /// field 5 — `vaultEvmAddress`.
    pub vault_evm: [u8; 20],
    /// field 6 — `evmChainId`.
    pub chain_id: u64,
    /// field 7 — `caip2Id`.
    pub caip2: [u8; 32],
    /// field 8 — `deployer`.
    pub deployer: [u8; 32],
    /// field 9 — `refundCommitment: requestId -> commitment`.
    pub refund_commitment: Vec<([u8; 32], [u8; 32])>,
    /// field 10 — `uniswapRouter`.
    pub uniswap_router: [u8; 20],
    /// field 11 — `swapEventMap: requestId -> record`.
    pub swap_event_map: Vec<([u8; 32], AlignedValue)>,
    /// field 12 — `swapRefundCommitment: requestId -> commitment`.
    pub swap_refund_commitment: Vec<([u8; 32], [u8; 32])>,
}

fn map_of(entries: impl IntoIterator<Item = (AlignedValue, StateValue<InMemoryDB>)>) -> StateValue {
    let mut m: HashMap<AlignedValue, StateValue<InMemoryDB>, InMemoryDB> = HashMap::new();
    for (k, v) in entries {
        m = m.insert(k, v);
    }
    StateValue::Map(m)
}

impl PreState {
    /// The 13-field state tree the circuits index into.
    pub fn state(&self) -> StateValue {
        let key = |k: &[u8; 32]| bytesn_value(32, k);
        let fields: Vec<StateValue> = vec![
            map_of(
                self.sign_event_map
                    .iter()
                    .map(|(k, v)| (key(k), cell(v.clone()))),
            ),
            cell(bytesn_value(32, &self.signet_signer)),
            match &self.mpc_response_key {
                Some(av) => cell(av.clone()),
                None => StateValue::Null,
            },
            cell(bytesn_value(8, &self.request_nonce.to_le_bytes())),
            cell(bytesn_value(8, &self.initialized.to_le_bytes())),
            cell(bytesn_value(20, &self.vault_evm)),
            cell(bytesn_value(8, &self.chain_id.to_le_bytes())),
            cell(bytesn_value(32, &self.caip2)),
            cell(bytesn_value(32, &self.deployer)),
            map_of(
                self.refund_commitment
                    .iter()
                    .map(|(k, v)| (key(k), cell(bytesn_value(32, v)))),
            ),
            cell(bytesn_value(20, &self.uniswap_router)),
            map_of(
                self.swap_event_map
                    .iter()
                    .map(|(k, v)| (key(k), cell(v.clone()))),
            ),
            map_of(
                self.swap_refund_commitment
                    .iter()
                    .map(|(k, v)| (key(k), cell(bytesn_value(32, v)))),
            ),
        ];
        StateValue::Array(Array::from(fields))
    }
}

/// What the reference VM produced for one call.
#[derive(Debug)]
pub struct Executed {
    /// The state after the op stream applied.
    pub post: StateValue,
    /// The ledger effects the transcript declares — the exact value
    /// `semantics.rs:1441` compares a transaction's declared effects to.
    pub effects: Effects<InMemoryDB>,
    /// Log items the program emitted (none of the vault's circuits log).
    pub events: Vec<VersionedLogItem<InMemoryDB>>,
}

/// Run `ops` against `pre` with `self_addr` as the contract's own address
/// (what `kernel.self()` reads back).
///
/// Verify mode, not gather: the vault's op streams already carry their
/// `Popeq` results, so `ResultModeVerify::process_read` checks each read
/// against the real state and errors `ReadMismatch` when the model and the
/// state disagree. That check is the point — it is what makes the model's
/// claimed pre-state real rather than asserted.
pub fn run(pre: &PreState, self_addr: &[u8; 32], ops: &[VmOp]) -> Result<Executed, String> {
    assert_normalized(ops)?;
    let ctx = QueryContext::new(
        ChargedState::new(pre.state()),
        ContractAddress(HashOutput(*self_addr)),
    );
    let res: QueryResults<ResultModeVerify, InMemoryDB> = ctx
        .query(ops, None, &INITIAL_COST_MODEL)
        .map_err(|e| format!("{e:?}"))?;
    Ok(Executed {
        post: res.context.state.get_ref().clone(),
        effects: res.context.effects,
        events: res.events,
    })
}

/// The trap notes/vault-optimization.org flags: `prove.rs:291-327` merges
/// adjacent `Noop`s (summing their `n`) when a transaction is proved, and
/// `verify.rs:1889-1894` REJECTS any transcript still holding two adjacent
/// `Noop`s (`MalformedTransaction::NotNormalized`). A reference op stream
/// that is compared to a circuit's must therefore be normalised the same
/// way, or the comparison is against a program the ledger would never
/// accept.
///
/// The vault's nine circuits emit no `Noop` at all — a single contract call
/// with no inactive sibling segments — so this is a guard against
/// regression rather than a live concern, and it is cheap enough to run on
/// every case.
pub fn assert_normalized(ops: &[VmOp]) -> Result<(), String> {
    for (i, w) in ops.windows(2).enumerate() {
        if matches!((&w[0], &w[1]), (Op::Noop { .. }, Op::Noop { .. })) {
            return Err(format!(
                "unnormalised transcript: adjacent Noops at {i}/{}",
                i + 1
            ));
        }
    }
    Ok(())
}

/// [`normalize`]'s inverse test: merge adjacent `Noop`s exactly as
/// `prove.rs:291-327` does, so a model that ever grows inactive segments
/// can be brought into the shape `verify.rs` accepts.
pub fn normalize(ops: &[VmOp]) -> Vec<VmOp> {
    let mut out: Vec<VmOp> = Vec::with_capacity(ops.len());
    let mut n: u32 = 0;
    for op in ops {
        match op {
            Op::Noop { n: n2 } => n += n2,
            other => {
                if n != 0 {
                    out.push(Op::Noop { n });
                    n = 0;
                }
                out.push(other.clone());
            }
        }
    }
    if n != 0 {
        out.push(Op::Noop { n });
    }
    out
}

/// Read a `Bytes<32>` cell out of a post-state map field, or `None` when
/// the key is absent. Used by the spec assertions.
pub fn map_get_b32(state: &StateValue, field: usize, key: &[u8; 32]) -> Option<[u8; 32]> {
    let StateValue::Array(arr) = state else {
        return None;
    };
    let StateValue::Map(m) = arr.get(field)? else {
        return None;
    };
    let entry = m.get(&bytesn_value(32, key))?;
    let StateValue::Cell(av) = entry.deref() else {
        return None;
    };
    let bytes = av.value.0.first()?.0.clone();
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(&bytes);
    Some(out)
}

/// Is `key` present in the map at `field` of `state`?
pub fn map_member(state: &StateValue, field: usize, key: &[u8; 32]) -> bool {
    let StateValue::Array(arr) = state else {
        return false;
    };
    match arr.get(field) {
        Some(StateValue::Map(m)) => m.get(&bytesn_value(32, key)).is_some(),
        _ => false,
    }
}

/// Read a counter field (a `Bytes<8>` cell) out of a state tree.
pub fn counter(state: &StateValue, field: usize) -> Option<u64> {
    let StateValue::Array(arr) = state else {
        return None;
    };
    let StateValue::Cell(av) = arr.get(field)? else {
        return None;
    };
    let bytes = av.value.0.first()?.0.clone();
    let mut le = [0u8; 8];
    le[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    Some(u64::from_le_bytes(le))
}
