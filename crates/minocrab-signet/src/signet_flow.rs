//! The Signet round trip's shared machinery — the block's configuration,
//! the record a request files, and the attested output a settle verifies.
//!
//! Every Sig Network operation a Midnight contract makes is one future split
//! across two transactions. A request circuit files a signing record and
//! cross-calls the signet signer so the MPC comes to read it; a settle
//! circuit, in a later transaction, verifies the MPC's attestation over the
//! typed response and consumes the record. The ledger map entry is the
//! suspended continuation; the attestation is the value the future resolves
//! with. (notes/signet-async.org is the design of record.)
//!
//! The vocabulary is V1 — `@sig-net/midnight` 0.24.1, the
//! protocol the deployed flush-pattern vault speaks ([`crate::signet_v1`]).
//! What that means here, for what a contract author writes:
//!
//! - There is no request nonce. The V1 request id hashes a preimage whose
//!   transaction enters as a digest, and the transaction's own EVM nonce is
//!   what makes two otherwise identical requests distinct — so no protocol
//!   counter is in the record, and a `Pending` request makes no contended read.
//! - There is no CAIP2 cell. `executionDest` is the constant
//!   [`crate::signet_v1::ethereum_caip2_id`] — the MPC's routing key for
//!   every Ethereum network it watches, with the transaction's own chain id
//!   picking the network — so a cell that could be set wrong at deployment
//!   is a constant in the circuit instead.
//! - The key version is a cell, not an argument. No circuit takes one, so no
//!   caller can file a request against a key version the contract did not
//!   choose.
//! - There is no response kind byte, in the record or in the
//!   attestation. A V1 attestation carries the MPC's verdict instead
//!   ([`crate::signet_v1::output_kind`]: executed, failed, unviable), and a
//!   slot is bound to its attestations by its own record map and by its
//!   ticket's type rather than by a byte a deployment allocated by hand.
//!
//! # What lives here, and why
//!
//! The typed slot is
//! [`crate::evm_flow::Pending<Call, Env, WORDS>`], which is keyed by the call
//! ([`minocrab_evm::EvmCall`]) and derives the response type, the ABI words,
//! the selector, the gas envelope, the output schema and the signing path
//! from it. What is left in this module is what the typed slot is built on,
//! and it is here rather than there because it is the wire — the MPC's side
//! of the protocol, which no contract-facing API gets to reshape:
//!
//! - [`Signet`] — the block's one configuration slot (signer address, MPC
//!   response key, MPC key version, EVM chain id). Four ledger fields a
//!   contract declares once; `#[derive(Ledger)]` threads its offset into
//!   every `Pending`, `Fired` and `Outbox` slot, which is why a typed
//!   request takes no `&SELF.signet`.
//! - `file_request` — the filing every request does, whatever the slot:
//!   read the context, assemble the V1 record, hash its id, assert
//!   freshness, store it, store the environment beside it, notify the
//!   signet signer with the record map's own path. `evm_flow`'s request methods
//!   are this function plus a transaction.
//! - [`EvmTx`], [`Signing`] and [`SignRequest`] — the transaction shape the
//!   record holds, whose key signs it, and the request that files both.
//!   `evm::build_tx` builds the first from a call type; nothing outside this
//!   crate writes any of them by hand.
//! - [`Outcome`] — what a settle hands back.
//! - The three disclosure labels and the [`Requested`] / [`Settled`] label
//!   sets a request and a settle publish.
//!
//! [`crate::evm_flow::Commit<T, Tag>`] takes its domain as a type, so a `to`
//! and an `open` that disagree do not compile.
//!
//! Types constrain the author, asserts constrain the prover: nothing in
//! either module removes an in-circuit check on untrusted input.
//!
//! No timeout, by decision: a request with no response
//! stays pending; a refund happens only on an attested non-success
//! ([`crate::evm_flow::Pending::refund`]).
//!
//! # What does not compile
//!
//! An environment with a private field (`#[derive(LedgerRepr)]` has no impl
//! at `Private`, so a secret cannot be captured across the suspension by
//! accident — what Rust's own `async` would silently do):
//!
//! ```compile_fail,E0277
//! use minocrab::{Private, Public};
//! use minocrab_std::{LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)]
//! struct Env { amount: Uint<64, Public>, secret: B32<Private> }
//! ```
//!
//! The same code with the one change reverted compiles:
//!
//! ```
//! use minocrab::Public;
//! use minocrab_std::{LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)]
//! struct Env { amount: Uint<64, Public>, secret: B32<Public> }
//! ```

use minocrab::{Circuit, FieldT, Wire};
use minocrab::{Private, Public};
use minocrab_ledger::XcallCommitment;
use minocrab_std::Assumed;
use minocrab_std::{
    is_true, kernel, label, not, Disclose, LedgerCell, LedgerField, LedgerMap, LedgerRepr,
    LedgerWidth, Secp256k1Point, Uint,
};
use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::{RequestId, SignetSigner};

use crate::common::SigningPath;
use crate::signet_v1::{self, EventRecordV1, EvmType2TxParams, OutputSchema};

// ---- the shared configuration slot ------------------------------------------------

/// The block's one Signet configuration: four consecutive ledger fields a
/// contract declares once (`signet: Signet` in its `#[derive(Ledger)]`
/// block) and every typed slot reads through.
///
/// Holding these together is what lets a request take the sender, the chain
/// id and the key version from context and a settle the MPC key — none of
/// them is an argument a circuit can pass wrongly. The `signer` cell is
/// `sealed` (written at deployment, never by a circuit).
///
/// Four fields: there is no request nonce or caip2 id, and `mpcKeyVersion`
/// is a cell (the module header explains). The width is read through
/// [`LedgerWidth`], so `#[derive(Ledger)]` computes every slot's offset
/// from the type without being told.
pub struct Signet {
    /// `sealed ledger signetSigner: SignetSigner` — the signet signer's address.
    pub signer: LedgerField,
    /// `mpcResponseKey: Secp256k1Point` — the key every attestation is
    /// verified under.
    pub mpc_response_key: LedgerCell<Secp256k1Point<Public>>,
    /// `mpcKeyVersion: Uint<8>` — which generation of the MPC's root key
    /// signs. A cell, not a circuit argument: the version is in the record
    /// and therefore in the request id, so letting a caller choose it would
    /// let a caller file a request no MPC epoch will answer.
    pub mpc_key_version: LedgerCell<Uint<8, Public>>,
    /// `evmChainId: Uint<64>` — the destination chain, in the signed
    /// transaction.
    pub evm_chain_id: LedgerCell<Uint<64, Public>>,
}

impl Signet {
    /// The four fields from flat index `start` of a block of `total` fields
    /// (what `#[derive(Ledger)]` calls).
    pub const fn at_block(total: usize, start: usize) -> Self {
        Signet {
            signer: LedgerField::at_block(total, start),
            mpc_response_key: LedgerCell::at_block(total, start + 1),
            mpc_key_version: LedgerCell::at_block(total, start + 2),
            evm_chain_id: LedgerCell::at_block(total, start + 3),
        }
    }

    /// [`Self::at_block`], under the name `#[derive(Ledger)]` calls on every
    /// field. `Signet` IS the anchor, so the anchor offset is its own.
    pub const fn at_block_anchored(total: usize, start: usize, _anchor: usize) -> Self {
        Self::at_block(total, start)
    }

    /// The deployment's writes, for a contract's `initialize`: the MPC key,
    /// its version and the destination chain id. The signer cell is sealed
    /// and set at deployment.
    pub fn initialize(
        &self,
        c: &mut Circuit,
        mpc_response_key: &Secp256k1Point<Public>,
        mpc_key_version: &Uint<8, Public>,
        evm_chain_id: &Uint<64, Public>,
    ) {
        self.mpc_response_key.write(c, mpc_response_key);
        self.mpc_key_version.write(c, mpc_key_version);
        self.evm_chain_id.write(c, evm_chain_id);
    }

    /// The signet signer's calling handle, by the sealed cell's path.
    fn signer(&self) -> SignetSigner {
        SignetSigner::at_field_path(self.signer.field_path().as_slice())
    }
}

/// The block's anchor: every `evm_flow` slot (`Pending`, `Fired`, `Outbox`)
/// is built against the block's one `Signet`, so a block has at most one and
/// needs one if it has any of those.
impl LedgerWidth for Signet {
    const WIDTH: usize = 4;
    const IS_ANCHOR: bool = true;
}

// ---- the request ---------------------------------------------------------------------

/// The EVM transaction a request asks the MPC to sign, without its chain
/// id: that is the block's ([`Signet::evm_chain_id`]), read by
/// `file_request`, so a request cannot name another chain than the one the
/// contract is configured for.
pub struct EvmTx<const WORDS: usize> {
    pub nonce: Wire<FieldT, Private>,
    pub max_priority_fee_per_gas: Wire<FieldT, Private>,
    pub max_fee_per_gas: Wire<FieldT, Private>,
    pub gas_limit: Wire<FieldT, Private>,
    pub to: Wire<FieldT, Private>,
    pub value: Wire<FieldT, Private>,
    /// `Maybe<EvmCalldata>`: the flag then the (always-present, zero-filled
    /// when absent) calldata.
    pub calldata_is_some: Wire<FieldT, Private>,
    pub calldata: signet_v1::EvmCalldata<Private, WORDS>,
}

/// Whose key signs, and whether the reserved-path assert is emitted.
///
/// `constructSignBidirectionalEventV1` refuses a request whose derivation
/// path is `pad(32, "midnight response key")` — the path the MPC's own
/// attestation key lives under, which a contract that could name it could
/// make the MPC sign arbitrary attestations with. compactc folds that assert
/// away when the path is a constant of the contract (two constants compared),
/// and must not fold it when the path came from an input.
///
/// That distinction is a type here rather than a `bool`, because getting it
/// wrong in the unsafe direction is the hole above and not a cosmetic
/// difference in instruction count:
///
/// - [`Signing::contract`] — the contract's own `pad(32, "")` path. The
///   assert is over two constants and is not emitted, exactly as compactc's
///   artifact does not emit it.
/// - [`Signing::derived`] — a path this circuit derived from its inputs (a
///   deposit's depositor commitment). The assert is emitted.
pub enum Signing {
    /// A constant of the contract: the assert folds.
    Constant(SigningPath<Private>),
    /// Derived from inputs: the assert is emitted.
    Derived(SigningPath<Private>),
}

impl Signing {
    /// The contract's own key — `pad(32, "")`, the path
    /// [`SigningPath::contract_path`] names.
    pub fn contract(c: &mut Circuit) -> Self {
        Signing::Constant(SigningPath::contract_path(c).private())
    }

    /// A path this circuit derived from its inputs — a per-user commitment,
    /// typically. The reserved-path assert is emitted for it.
    pub fn derived(path: SigningPath<Private>) -> Self {
        Signing::Derived(path)
    }
}

/// What a request circuit supplies: whose key signs and what it signs. The
/// key version is not here — it is the block's cell, read inside
/// `file_request`.
pub struct SignRequest<const WORDS: usize> {
    pub signing: Signing,
    pub tx: EvmTx<WORDS>,
}

label! {
    /// The request id, disclosed on filing: the map key.
    pub RequestIdFiled = "request id";
    /// The whole signing record, disclosed on filing: what the MPC reads.
    pub RequestRecordFiled = "request record";
    /// The request id, disclosed on settling: which entry is consumed.
    pub RequestIdSettled = "settle request id";
    /// The attested block height, disclosed on settling: the height the MPC
    /// saw the transaction at, which an outbox's last-seen check consumes.
    pub BlockHeightSettled = "settle block height";
}

/// Everything `Pending::request` discloses — the label set a request
/// circuit declares, as one type.
pub type Requested = (
    RequestIdFiled,
    RequestRecordFiled,
    XcallCommitment,
);

/// Everything `Pending::settle` discloses.
pub type Settled = (RequestIdSettled, BlockHeightSettled);

/// What a settle hands back: the consumed entry, typed.
///
/// It does not carry the signing record: what a settle might want off it
/// (the EVM nonce, the signing path) is either the outbox's own
/// snapshot or a value the environment carried.
pub struct Outcome<Env, R> {
    /// The request id, disclosed.
    pub request_id: RequestId<Public>,
    /// The attested block height, disclosed — the height the MPC observed
    /// the transaction at (V1's `blockHeight`, spec M2), which is what an
    /// [`crate::evm_flow::Outbox`]'s last-seen check compares against.
    pub block_height: Uint<64, Public>,
    /// The environment the request filed — an inline read of the entry
    /// written at the request, so an assumption: the proof uses it
    /// freely; writing it back is `.stale(c)`.
    pub env: Assumed<Env>,
    /// The attested output, decoded — verified, its verdict checked, its
    /// narrowing range-checked.
    pub output: R,
}

/// The filing every request does, whatever the slot: read the context,
/// assemble the V1 record under `S`'s output schema, hash its id, assert
/// freshness, store the record, run `after_insert` (a `Pending` stores its
/// environment there), notify the MPC with the record map's own path.
///
/// `words_used` is the calldata's word count when the circuit knows it — the
/// typed API always does, because the count is `<Call::Args as
/// AbiTuple>::WORDS`, a literal — so the transaction digest hashes exactly
/// those words with no per-slot select
/// ([`signet_v1::calculate_evm_type2_tx_params_digest_v1`]).
pub(crate) fn file_request<const WORDS: usize, S: OutputSchema>(
    c: &mut Circuit,
    signet: &Signet,
    records: &LedgerMap<RequestId<Public>, EventRecordV1<WORDS, S::At<Public>>>,
    req: SignRequest<WORDS>,
    words_used: usize,
    after_insert: impl FnOnce(&mut Circuit, RequestId<Public>),
) -> RequestId<Public> {
    let zero = c.constant(0u64);
    let me = kernel::cache_self_address(c);
    // Three stable reads, in the order the deployed `send*` circuits make
    // them: the chain id into the transaction, then the key version and the
    // constant destination into the record. None is a read-modify-write any
    // more — the counter that was is gone with the V1 vocabulary.
    let chain_id = signet.evm_chain_id.read(c).stale(c);
    let tx = req.tx;
    let tx_params = EvmType2TxParams::<Private, WORDS> {
        chain_id: chain_id.field().private(),
        nonce: tx.nonce,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        gas_limit: tx.gas_limit,
        to: tx.to,
        value: tx.value,
        calldata_is_some: tx.calldata_is_some,
        calldata: tx.calldata,
        access_list_entry_count: zero.private(),
    };
    let key_version = signet.mpc_key_version.read(c).stale(c);
    let dest = signet_v1::ethereum_caip2_id::<Private>(c);
    let kv = key_version.field().private();
    let record: signet_v1::SignBidirectionalEventV1<Private, WORDS, S::At<Private>> =
        match req.signing {
            // The reserved-path assert folds for a constant path and is
            // emitted for a derived one — `Signing`'s whole reason to exist.
            Signing::Constant(path) => signet_v1::construct_sign_bidirectional_event_v1_const_path(
                c,
                kv,
                me.private(),
                path,
                tx_params,
                dest,
                S::BYTES,
            ),
            Signing::Derived(path) => signet_v1::construct_sign_bidirectional_event_v1(
                c,
                kv,
                me.private(),
                path,
                tx_params,
                dest,
                S::BYTES,
            ),
        };

    let request_id = c.region("signet flow: file", |c| {
        let request_id =
            signet_v1::calculate_evm_type2_request_id_v1(c, &record, Some(words_used))
                .disclose_as::<RequestIdFiled>(c);
        let exists = records.member(c, &request_id);
        c.assert(not(is_true(exists)).message("Request already exists"));
        let stored = EventRecordV1::<WORDS, S::At<Public>>::from_limbs(
            record.limbs().disclose_as::<RequestRecordFiled>(c),
        );
        records.insert(c, &request_id, &stored);
        after_insert(c, request_id);
        request_id
    });

    c.region("signet flow: notify", |c| {
        // Receiver first (compactc's order; the argument below emits).
        let signer = signet.signer().pin(c);
        let path = records.field_path();
        let mut bytes = [0u8; 4];
        bytes[..path.as_slice().len()].copy_from_slice(path.as_slice());
        let notification = construct_notification_v1::<Public>(c, &me.bytes(), path.depth(), bytes);
        signer.sign_bidirectional(c, request_id, notification);
    });
    request_id
}
