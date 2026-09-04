//! The Signet round trip as a typed future: `Pending<Env, Resp>`.
//!
//! Every Sig Network operation a Midnight contract makes is one future split
//! across two transactions. A REQUEST circuit files a signing record, and
//! cross-calls the Signet singleton so the MPC comes to read it; a SETTLE
//! circuit, in a later transaction, verifies the MPC's attestation over the
//! typed response and consumes the record. The ledger map entry IS the
//! suspended continuation; the attestation is the value the future
//! resolves with. (notes/signet-async.org is the design of record — M35.)
//!
//! This module owns the suspension so a contract does not:
//!
//! - [`Pending<Env, Resp>`] is ONE ledger slot (two consecutive fields: the
//!   MPC-facing record map and the caller's environment map) whose type
//!   names the response it settles under. [`Pending::request`] is the only
//!   constructor of a request id; [`Pending::settle`] is the only
//!   constructor of a typed response. Both do every step, in one order.
//! - [`Env`](LedgerRepr) is the continuation state, EXPLICIT and PUBLIC by
//!   construction: `#[derive(LedgerRepr)]` has no impl at `Private`, so a
//!   secret cannot be captured across the suspension by accident (what
//!   Rust's `async` would silently do). What must survive privately is a
//!   commitment, opened on the settle side with a fresh witness.
//! - [`Response::KIND`] is the response-kind byte, written once on the type.
//!   A `Settle<Env, Resp>` ticket only fits the `Pending<Env, Resp>` slot
//!   it names, so pairing a withdrawal environment with a claim response
//!   is a type error; two slots of one block claiming one kind is E0080
//!   (`assert_distinct_kinds`, from `#[derive(Ledger)]`).
//! - The notification the MPC follows to the record is DERIVED from the
//!   slot's ledger path, never spelled by hand.
//! - The sender, chain id, caip2 id, nonce, record format version and MPC
//!   key all come from context ([`Signet`], the block's one shared
//!   configuration slot), so a request always binds the calling contract
//!   and chain, and an attestation for contract A cannot settle at B.
//!
//! TYPES CONSTRAIN THE AUTHOR, ASSERTS CONSTRAIN THE PROVER: nothing here
//! removes an in-circuit check on untrusted input. The ticket's kind byte,
//! signature, record membership, record kind and record version are all
//! asserted inside [`Pending::settle`]; what the types add is that a
//! circuit cannot forget one of them or pair them wrongly.
//!
//! What stays in the circuit, deliberately: the initialization gate, the
//! authorization with a FRESH witness (the depositor gate re-witnesses the
//! secret key rather than capturing it — it must, since the settle half is
//! proven by another transaction), and the business guards.
//!
//! NO TIMEOUT, by decision (dmd, 2026-09-05): a request with no response
//! stays pending; refund happens only on an ATTESTED failure
//! ([`Pending::settle_failed`]).
//!
//! # What does not compile
//!
//! A ticket declared against one slot handed to another (E0308 — the
//! phantom `Env` and the `Resp` both have to match):
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Public;
//! use minocrab_contracts::signet_flow::{Pending, Response, Settle, Signet};
//! use minocrab_std::v3::borsh::CircuitBorsh;
//! use minocrab_std::v3::{Bool, Ledger, LedgerRepr, Uint};
//!
//! #[derive(LedgerRepr)] struct DepositEnv { amount: Uint<64, Public> }
//! #[derive(LedgerRepr)] struct WithdrawEnv { amount: Uint<64, Public> }
//! #[derive(CircuitBorsh)] struct ClaimResponse { success: Bool }
//! impl Response for ClaimResponse { const KIND: u8 = 0; }
//! #[derive(CircuitBorsh)] struct WithdrawResponse { success: Bool }
//! impl Response for WithdrawResponse { const KIND: u8 = 1; }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     deposits: Pending<DepositEnv, ClaimResponse>,
//!     withdrawals: Pending<WithdrawEnv, WithdrawResponse>,
//! }
//! const BLOCK: Block = Block::new();
//!
//! fn settle(c: &mut Circuit3, ticket: Settle<WithdrawEnv, WithdrawResponse>) {
//!     BLOCK.deposits.settle(c, &BLOCK.signet, ticket);
//! }
//! ```
//!
//! Two slots of one block settling under the same kind (E0080, from the
//! derive's `assert_distinct_kinds`):
//!
//! ```compile_fail
//! use minocrab::Public;
//! use minocrab_contracts::signet_flow::{Pending, Response, Signet};
//! use minocrab_std::v3::borsh::CircuitBorsh;
//! use minocrab_std::v3::{Bool, Ledger, LedgerRepr, Uint};
//!
//! #[derive(LedgerRepr)] struct Env { amount: Uint<64, Public> }
//! #[derive(CircuitBorsh)] struct A { success: Bool }
//! impl Response for A { const KIND: u8 = 0; }
//! #[derive(CircuitBorsh)] struct B { success: Bool }
//! impl Response for B { const KIND: u8 = 0; }
//!
//! #[derive(Ledger)]
//! struct Block {
//!     signet: Signet,
//!     first: Pending<Env, A>,
//!     second: Pending<Env, B>,
//! }
//! const BLOCK: Block = Block::new();
//! const _: usize = BLOCK.first.record_path().depth() as usize;
//! ```
//!
//! An environment with a private field (no `LedgerRepr` at `Private`):
//!
//! ```compile_fail
//! use minocrab::{Private, Public};
//! use minocrab_std::v3::{LedgerRepr, Uint, B32};
//!
//! #[derive(LedgerRepr)]
//! struct Env { amount: Uint<64, Public>, secret: B32<Private> }
//! ```
//!
//! A response type that is not a Borsh record (no `Response` without
//! `CircuitBorsh`, so no canonical decode can be skipped):
//!
//! ```compile_fail
//! use minocrab_contracts::signet_flow::Response;
//! use minocrab_std::v3::{Bool, CircuitArg};
//!
//! #[derive(CircuitArg)] struct Loose { success: Bool }
//! impl Response for Loose { const KIND: u8 = 0; }
//! ```

use core::marker::PhantomData;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_ledger::{XcallCommitment, XcallEntryPointHash};
use minocrab_std::v3::borsh::{BorshReader, CircuitBorsh, FieldSpec, LayoutPath, Limbs};
use minocrab_std::v3::Serializer;
use minocrab_std::v3::{
    eq, is_true, kernel, label, not, ArgPath, CircuitAbi, CircuitArg, Disclose, FieldPath,
    LedgerCell, LedgerCounter, LedgerField, LedgerMap, LedgerRepr, LedgerWidth, Prim,
    Secp256k1Point, Uint, B32,
};
use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::{RequestId, Signature, SignetSigner};

use crate::common::{Caip2Id, SigningPath};
use crate::signet::{
    self, EventRecordV2, EvmCalldata, EvmType2TxParams, Secp256k1SigLimbs, RECORD_FORMAT_VERSION,
};

// ---- the response types ------------------------------------------------------

/// An attested output the MPC signs back: a Borsh record whose KIND byte
/// (byte 0 of every attested output, and the last byte of every request
/// record) is this type's.
///
/// The kind is an associated const, not a field: it is written once, on the
/// type, and a `Pending<_, Resp>` slot settles under `Resp::KIND` and nothing
/// else. The `CircuitBorsh` bound is what makes a `Bool` field 0/1 by
/// construction (the `0x02` hazard the vault harness found closes here, one
/// level below any circuit).
pub trait Response: CircuitArg + CircuitBorsh<Private> {
    /// The response-kind byte.
    const KIND: u8;
}

/// The MPC's "never executed" output: a response every pending request can
/// receive, whatever it asked for. Marked so [`Pending::settle_failed`] can
/// take it without the slot claiming its kind (`KINDS` lists success kinds
/// only, so a shared failure kind does not trip the uniqueness assert).
pub trait FailureResponse: Response {}

/// `serializedOutput` on the wire: the kind byte then the response body.
///
/// What the MPC signs is `keccak256(requestId ‖ borsh(Attested))`, and
/// [`Pending::settle`] asserts `kind == R::KIND` before verifying — so an
/// attestation issued for another settle circuit fails the kind check, and
/// one with a forged kind fails the signature.
pub struct Attested<R> {
    pub kind: Uint<8>,
    pub output: R,
}

impl<R: CircuitAbi> CircuitAbi for Attested<R> {
    const SLOTS: usize = <Uint<8>>::SLOTS + R::SLOTS;

    fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
        <Uint<8>>::push_atoms(atoms);
        R::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Uint<8>>::push_prims(prims);
        R::push_prims(prims);
    }
}

impl<R: CircuitArg> CircuitArg for Attested<R> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Attested {
            kind: <Uint<8>>::declare(c, &path.field("kind")),
            output: R::declare(c, &path.field("output")),
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.kind.push_slots(slots);
        self.output.push_slots(slots);
    }
}

impl<R: CircuitBorsh<Private>> CircuitBorsh<Private> for Attested<R> {
    const LEN: usize = 1 + R::LEN;

    fn read<Rd: BorshReader<Private>>(c: &mut Circuit3, r: &mut Rd) -> Self {
        Attested {
            kind: <Uint<8>>::read(c, r),
            output: R::read(c, r),
        }
    }

    fn push_limbs(&self, limbs: &mut Limbs<Private>) {
        self.kind.push_limbs(limbs);
        self.output.push_limbs(limbs);
    }

    fn push_segments(&self, out: &mut Serializer<Private>) {
        self.kind.push_segments(out);
        self.output.push_segments(out);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.kind.constrain_canonical(c);
        self.output.constrain_canonical(c);
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        <Uint<8>>::push_layout(&path.field("kind"), offset, out);
        R::push_layout(&path.field("output"), offset, out);
    }
}

// ---- the ticket -----------------------------------------------------------------

/// The settle circuit's argument block: `(requestId, respond, serializedOutput)`
/// in that WIRE ORDER, one `CircuitArg`, named for the slot it fits.
///
/// `Env` is phantom — the ticket carries no environment; the slot does — and
/// it is there so `VAULT.deposits.settle(c, &signet, ticket)` only accepts
/// the ticket type declared against `deposits`. Pairing another slot's
/// ticket does not compile.
pub struct Settle<Env, Resp> {
    pub request_id: RequestId<Private>,
    /// The MPC's signature (`bigR.y` and `recoveryId` are part of the wire
    /// shape and read by nothing, as in the Compact original).
    pub respond: Signature<Private>,
    pub serialized_output: Attested<Resp>,
    _env: PhantomData<fn() -> Env>,
}

impl<Env, Resp: CircuitAbi> CircuitAbi for Settle<Env, Resp> {
    const SLOTS: usize =
        <RequestId<Private>>::SLOTS + <Signature<Private>>::SLOTS + <Attested<Resp>>::SLOTS;

    fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
        <RequestId<Private>>::push_atoms(atoms);
        <Signature<Private>>::push_atoms(atoms);
        <Attested<Resp>>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <RequestId<Private>>::push_prims(prims);
        <Signature<Private>>::push_prims(prims);
        <Attested<Resp>>::push_prims(prims);
    }
}

impl<Env, Resp: CircuitArg> CircuitArg for Settle<Env, Resp> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Settle {
            request_id: <RequestId<Private>>::declare(c, &path.field("requestId")),
            respond: <Signature<Private>>::declare(c, &path.field("respond")),
            serialized_output: <Attested<Resp>>::declare(c, &path.field("serializedOutput")),
            _env: PhantomData,
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.request_id.push_slots(slots);
        self.respond.push_slots(slots);
        self.serialized_output.push_slots(slots);
    }
}

// ---- the shared configuration slot ------------------------------------------------

/// The block's ONE Signet configuration: five consecutive ledger fields a
/// contract declares once (`signet: Signet` in its `#[derive(Ledger)]`
/// block) and every [`Pending`] slot reads through.
///
/// Holding these together is what lets [`Pending::request`] take the sender,
/// chain id, caip2 id and nonce from CONTEXT and [`Pending::settle`] the MPC
/// key — none of them is an argument a circuit can pass wrongly. The
/// `signer` cell is `sealed` (written at deployment, never by a circuit).
pub struct Signet {
    /// `sealed ledger signetSigner: SignetSigner` — the singleton's address.
    pub signer: LedgerField,
    /// `mpcResponseKey: Secp256k1Point` — the key every attestation is
    /// verified under.
    pub mpc_response_key: LedgerCell<Secp256k1Point<Public>>,
    /// `signetRequestNonce: Counter` — one per contract, so two requests
    /// with identical parameters still hash to distinct ids.
    pub request_nonce: LedgerCounter,
    /// `caip2Id: Bytes<32>` — the destination chain, in the record.
    pub caip2_id: LedgerCell<Caip2Id<Public>>,
    /// `evmChainId: Uint<64>` — the destination chain, in the signed
    /// transaction.
    pub evm_chain_id: LedgerCell<Uint<64, Public>>,
}

impl Signet {
    /// The five fields from flat index `start` of a block of `total` fields
    /// (what `#[derive(Ledger)]` calls).
    pub const fn at_block(total: usize, start: usize) -> Self {
        Signet {
            signer: LedgerField::at_block(total, start),
            mpc_response_key: LedgerCell::at_block(total, start + 1),
            request_nonce: LedgerCounter::at_block(total, start + 2),
            caip2_id: LedgerCell::at_block(total, start + 3),
            evm_chain_id: LedgerCell::at_block(total, start + 4),
        }
    }

    /// The deployment's writes, for a contract's `initialize`: the MPC key
    /// and the two chain identifiers. The signer cell is sealed and set at
    /// deployment; the nonce starts at zero.
    pub fn initialize(
        &self,
        c: &mut Circuit3,
        mpc_response_key: &Secp256k1Point<Public>,
        caip2_id: &Caip2Id<Public>,
        evm_chain_id: &Uint<64, Public>,
    ) {
        self.mpc_response_key.write(c, mpc_response_key);
        self.caip2_id.write(c, caip2_id);
        self.evm_chain_id.write(c, evm_chain_id);
    }

    /// The singleton's calling handle, by the sealed cell's path.
    fn signer(&self) -> SignetSigner {
        SignetSigner::at_field_path(self.signer.field_path().as_slice())
    }
}

impl LedgerWidth for Signet {
    const WIDTH: usize = 5;
}

// ---- the request ---------------------------------------------------------------------

/// The EVM transaction a request asks the MPC to sign, WITHOUT its chain
/// id: that is the block's ([`Signet::evm_chain_id`]), read by
/// [`Pending::request`], so a request cannot name another chain than the
/// one the contract is configured for.
pub struct EvmTx<const WORDS: usize> {
    pub nonce: Wire3<FieldT, Private>,
    pub max_priority_fee_per_gas: Wire3<FieldT, Private>,
    pub max_fee_per_gas: Wire3<FieldT, Private>,
    pub gas_limit: Wire3<FieldT, Private>,
    pub to: Wire3<FieldT, Private>,
    pub value: Wire3<FieldT, Private>,
    /// `Maybe<EvmCalldata>`: the flag then the (always-present, zero-filled
    /// when absent) calldata.
    pub calldata_is_some: Wire3<FieldT, Private>,
    pub calldata: EvmCalldata<Private, WORDS>,
}

/// What a request circuit supplies: whose key signs (the version and the
/// derivation path) and what it signs.
pub struct SignRequest<const WORDS: usize> {
    pub key_version: Uint<8>,
    pub path: SigningPath<Private>,
    pub tx: EvmTx<WORDS>,
}

label! {
    /// The request id, disclosed on filing: the map key.
    pub RequestIdFiled = "request id";
    /// The whole signing record, disclosed on filing: what the MPC reads.
    pub RequestRecordFiled = "request record";
    /// The request id, disclosed on settling: which entry is consumed.
    pub RequestIdSettled = "settle request id";
}

/// Everything [`Pending::request`] discloses — the label set a request
/// circuit declares, as one type.
pub type Requested = (
    RequestIdFiled,
    RequestRecordFiled,
    XcallEntryPointHash,
    XcallCommitment,
);

/// Everything [`Pending::settle`] discloses.
pub type Settled = (RequestIdSettled,);

// ---- the slot ------------------------------------------------------------------------

/// A suspended Sig Network operation: the ledger slot a request files into
/// and a settle consumes from. See the module docs.
///
/// Two consecutive ledger fields: the record map the MPC walks to (its
/// format is the MPC's, frozen — `EventRecordV2`) and the environment map
/// holding the caller's own typed continuation state, both keyed by the
/// request id. `WORDS` is the calldata capacity of the record, as in
/// `EvmType2TxParams`.
pub struct Pending<Env, Resp, const WORDS: usize = 2> {
    records: LedgerMap<RequestId<Public>, EventRecordV2<WORDS>>,
    envs: LedgerMap<RequestId<Public>, Env>,
    _resp: PhantomData<fn() -> Resp>,
}

impl<Env, Resp, const WORDS: usize> Pending<Env, Resp, WORDS> {
    /// The slot's two fields from flat index `start` of a block of `total`
    /// fields (what `#[derive(Ledger)]` calls).
    pub const fn at_block(total: usize, start: usize) -> Self {
        Pending {
            records: LedgerMap::at_block(total, start),
            envs: LedgerMap::at_block(total, start + 1),
            _resp: PhantomData,
        }
    }

    /// The record map's ledger path: the notification's `depth ‖ path`.
    pub const fn record_path(&self) -> FieldPath {
        self.records.field_path()
    }
}

impl<Env, Resp: Response, const WORDS: usize> LedgerWidth for Pending<Env, Resp, WORDS> {
    const WIDTH: usize = 2;
    const KINDS: &'static [u8] = &[Resp::KIND];
}

/// What a settle hands back: the consumed entry, typed.
pub struct Outcome<Env, R, const WORDS: usize> {
    /// The request id, disclosed.
    pub request_id: RequestId<Public>,
    /// The environment the request filed.
    pub env: Env,
    /// The attested output — verified, its kind checked, its fields
    /// canonical.
    pub output: R,
    /// The signing record the MPC read, should the settle logic need a
    /// field of it (the request nonce, say).
    pub record: EventRecordV2<WORDS>,
}

impl<Env: LedgerRepr, Resp: Response, const WORDS: usize> Pending<Env, Resp, WORDS> {
    /// File a request and notify the MPC. Returns the disclosed request id.
    ///
    /// In order: the sender (`kernel.self`), nonce, caip2 id and chain id
    /// are read; the record is assembled with this slot's kind; its id is
    /// the keccak of the whole record (what the MPC recomputes); freshness
    /// is asserted; the nonce is incremented; the record is stored, then
    /// the environment `env` builds from the disclosed id is stored beside
    /// it; the singleton is called with a notification carrying THIS
    /// slot's ledger path. Discloses [`Requested`], plus whatever `env`
    /// discloses (a [`Commit`]'s label, typically).
    pub fn request(
        &self,
        c: &mut Circuit3,
        signet: &Signet,
        req: SignRequest<WORDS>,
        env: impl FnOnce(&mut Circuit3, RequestId<Public>) -> Env,
    ) -> RequestId<Public> {
        let one = c.constant(1u64);
        let zero = c.constant(0u64);
        let me = kernel::cache_self_address(c);
        let nonce = signet.request_nonce.read(c);
        let caip2 = signet.caip2_id.read(c);
        let chain_id = signet.evm_chain_id.read(c);
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
        let record = signet::construct_sign_bidirectional_event_v2(
            c,
            me.private(),
            nonce.field().private(),
            req.key_version.field(),
            req.path,
            tx_params,
            caip2.private(),
            Resp::KIND,
        );

        let request_id = c.region("signet flow: file", |c| {
            let request_id = signet::calculate_request_id_v2(c, &record)
                .disclose_as::<RequestIdFiled>(c);
            let exists = self.records.member(c, &request_id);
            c.assert(not(is_true(exists)).message("Request already exists"));
            signet.request_nonce.increment(c, 1);
            let stored = EventRecordV2::from_limbs(
                record.limbs().disclose_as::<RequestRecordFiled>(c),
            );
            self.records.insert(c, &request_id, &stored);
            // The environment is built AFTER the id exists, so a
            // [`Commit`] in it can bind to this request and no other.
            let env = env(c, request_id);
            self.envs.insert(c, &request_id, &env);
            request_id
        });

        c.region("signet flow: notify", |c| {
            // Receiver first (compactc's order; the argument below emits).
            let signer = signet.signer().pin(c, one);
            let path = self.records.field_path();
            let mut bytes = [0u8; 4];
            bytes[..path.as_slice().len()].copy_from_slice(path.as_slice());
            let notification =
                construct_notification_v1::<Public>(c, &me.bytes(), path.depth(), bytes);
            signer.sign_bidirectional(c, one, request_id, notification);
        });
        request_id
    }

    /// Settle under this slot's response: verify the attestation, consume
    /// the entry, hand back the typed environment and output.
    ///
    /// In order: the id is disclosed; `kind == Resp::KIND`; the signature
    /// over `keccak256(id ‖ borsh(kind ‖ output))` verifies under the MPC
    /// key; the entry exists; record and environment are read and removed;
    /// the record's own kind and format version are this slot's. Discloses
    /// [`Settled`].
    pub fn settle(
        &self,
        c: &mut Circuit3,
        signet: &Signet,
        ticket: Settle<Env, Resp>,
    ) -> Outcome<Env, Resp, WORDS> {
        self.consume(c, signet, ticket)
    }

    /// Settle under the MPC's failure response ("never executed"): the same
    /// verification and consumption, against a ticket whose output is the
    /// failure kind. The record still has to be THIS slot's (its kind byte
    /// is `Resp::KIND`), so a failure attested for one flow cannot refund
    /// another.
    pub fn settle_failed<F: FailureResponse>(
        &self,
        c: &mut Circuit3,
        signet: &Signet,
        ticket: Settle<Env, F>,
    ) -> Outcome<Env, F, WORDS> {
        self.consume(c, signet, ticket)
    }

    fn consume<R: Response>(
        &self,
        c: &mut Circuit3,
        signet: &Signet,
        ticket: Settle<Env, R>,
    ) -> Outcome<Env, R, WORDS> {
        let request_id = ticket.request_id.disclose_as::<RequestIdSettled>(c);
        let attested = ticket.serialized_output;

        c.region("signet flow: attestation", |c| {
            c.assert(
                eq(attested.kind.field(), u64::from(R::KIND)).message("Wrong response kind"),
            );
            let key = signet.mpc_response_key.read(c);
            let valid = signet::verify_respond_bidirectional_event_borsh(
                c,
                &request_id.private(),
                &attested,
                &Secp256k1SigLimbs {
                    big_r_x: ticket.respond.big_r.x,
                    s: ticket.respond.s,
                },
                key.point().private(),
            );
            c.assert(valid);
        });

        let (record, env) = c.region("signet flow: consume", |c| {
            let found = self.records.member(c, &request_id);
            c.assert(is_true(found).message("Request not found"));
            let record = self.records.lookup(c, &request_id);
            self.records.remove(c, &request_id);
            let env = self.envs.lookup(c, &request_id);
            self.envs.remove(c, &request_id);
            // The record binds: it was filed by THIS slot, in this format.
            let kind_ok = c.test_eq(record.response_kind(), u64::from(Resp::KIND));
            c.assert(kind_ok);
            let version_ok = c.test_eq(record.format_version(), u64::from(RECORD_FORMAT_VERSION));
            c.assert(version_ok);
            (record, env)
        });

        Outcome {
            request_id,
            env,
            output: attested.output,
            record,
        }
    }
}

// ---- what survives privately ------------------------------------------------------------

/// A commitment to a private value, stored in an environment and OPENED on
/// the settle side with a fresh witness — the one way a secret crosses the
/// suspension.
///
/// `transientHash([pad(32, domain), value, requestId])`: Poseidon over the
/// domain pad, the value's slots and the request id, split into a
/// `Bytes<32>` exactly as the vault's refund commitments are. Binding the
/// REQUEST ID in is what keeps two requests by one withdrawer unlinkable
/// (the same secret commits to different values), which is why the
/// environment builder receives the id.
///
/// `domain` is a caller-chosen literal, deliberately: a domain derived from
/// a type name would move under a compiler change and strand every open
/// request. Two flows in one contract should use two literals.
///
/// Poseidon is curve-stable-EXEMPT, which is harmless here for the reason
/// `erc20_vault_modern::withdraw_refund_commitment` records: the commitment
/// is contract-internal and lives from one transaction to the next inside
/// one deployment.
pub struct Commit<T> {
    digest: B32<Public>,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for Commit<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Commit<T> {}

impl<T: CircuitArg> Commit<T> {
    fn digest_of(
        c: &mut Circuit3,
        domain: &str,
        value: &T,
        request_id: RequestId<Public>,
    ) -> B32<Private> {
        c.region("signet flow: commitment", |c| {
            let pad = B32::pad(c, domain);
            let mut inputs = vec![pad.hi.private(), pad.lo.private()];
            value.push_slots(&mut inputs);
            let id = request_id.bytes();
            inputs.push(id.hi.private());
            inputs.push(id.lo.private());
            let f = c.transient_hash(&inputs);
            let (hi, lo) = c.div_mod_power_of_two(f, 248);
            B32 { hi, lo }
        })
    }

    /// Commit to `value` for this request, disclosing the digest under `L`
    /// (it is stored, so it is public — the label names it in the
    /// disclosure inventory).
    pub fn to<L: minocrab::v3::DisclosureLabel>(
        c: &mut Circuit3,
        domain: &str,
        value: &T,
        request_id: RequestId<Public>,
    ) -> Self {
        let digest = Self::digest_of(c, domain, value, request_id).disclose_as::<L>(c);
        Commit {
            digest,
            _t: PhantomData,
        }
    }

    /// Assert that `value` (a FRESH witness on the settle side) is what
    /// this commitment was made to, for this request. The authorization
    /// gate of a settle circuit, as one call.
    pub fn open(
        &self,
        c: &mut Circuit3,
        domain: &str,
        value: &T,
        request_id: RequestId<Public>,
        message: &'static str,
    ) {
        let recomputed = Self::digest_of(c, domain, value, request_id);
        let stored = self.digest.private();
        c.assert(
            eq(recomputed.hi, stored.hi)
                .and(eq(recomputed.lo, stored.lo))
                .message(message),
        );
    }
}

impl<T> LedgerRepr for Commit<T> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        <B32<Public> as LedgerRepr>::atoms()
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.digest, c, limbs)
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        Commit {
            digest: B32::from_limbs(limbs),
            _t: PhantomData,
        }
    }
}
