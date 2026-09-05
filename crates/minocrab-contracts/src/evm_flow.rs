//! The typed EVM call as a ledger slot: `Pending<Call, Env, WORDS>`
//! (M37 rungs B and C, notes/evm-calls.org §§3-4).
//!
//! [`crate::evm`] made the CALL a type — its name, its argument list, its
//! return, its kind byte, its gas limit and (rung B) the rule by which its
//! return says "it worked". This module makes the SLOT a type over that one:
//!
//! ```ignore
//! #[derive(Ledger)]
//! pub struct Treasury {
//!     pub signet: Signet,
//!     pub transfers: Pending<Erc20Transfer, Owned<Amount>, 2>,
//! }
//! ```
//!
//! and everything else follows. What a contract author no longer writes:
//! the selector, the ABI words, the response type, the schema strings, the
//! gas envelope, the signing path, the notification path, the record format
//! version, the `&SELF.signet` argument (`#[derive(Ledger)]` threads the
//! block's Signet offset into every `Pending` field) and — with [`Owned`] —
//! the owner commitment's construction and opening.
//!
//! # The two tickets are SYMMETRIC
//!
//! [`Succeeded<Call>`] and [`Failed<Call>`], and nothing else settles a
//! request:
//!
//! - [`Pending::complete`] takes a `Succeeded`, asserts the attestation is
//!   this slot's kind, verifies it, consumes the entry — and then asserts
//!   the call's own [`OutcomeRule`] predicate. A mined ERC-20 `transfer`
//!   that returned `false` therefore CANNOT complete, whoever presents it
//!   (notes/evm-calls.org §3: the spurious-completion hole the deployed
//!   vault leaves open by putting a refund branch inside its
//!   `completeWithdraw`).
//! - [`Pending::refund`] takes a `Failed`, and accepts EITHER the MPC's
//!   failure kind (reverted, never mined, or an undecodable return — §3.1)
//!   OR this slot's own kind with the success predicate false.
//!
//! So the two non-successes are one ticket, the success is the other, and
//! neither stands in for the other.
//!
//! # HAZARD, carried forward from §3.1
//!
//! The MPC resolves a request as FAILED when the receipt reverted, when the
//! transaction never mined, AND when the return data does not decode into
//! the declared output schema. A non-conforming ERC-20 that returns NOTHING
//! (USDT and friends) therefore produces an attested failure for a transfer
//! that MOVED the tokens — a spurious refund this API cannot see from the
//! attestation alone. Until the callee's return shape is declared per token
//! (a `Contract<Erc20NoReturn>` marker) or success is read off the
//! `Transfer` event, **a contract using this module needs a callee
//! allow-list**, exactly as the deployed vault has one in effect through its
//! configured ERC-20 addresses.
//!
//! # What `Failed<Call>` costs
//!
//! The two accepted attestations have DIFFERENT PREIMAGES: the MPC's
//! failure output is one byte (the kind alone — `FailureResponse { kind: u8
//! }`, spec/borsh-subset.md §5), where an executed `transfer`'s is two (the
//! kind and the flag). Poseidon is not a stream, so one hash cannot cover
//! both lengths: [`Pending::refund`] hashes the preimage BOTH ways, selects
//! the field element by the kind byte and verifies ONCE. The extra cost is
//! one `transient_hash` and one `cond_select` beside the ~30k rows of the
//! ECDSA verification that follows — measured in
//! `tests/treasury.rs::the_refund_pays_one_extra_digest`.
//! (notes/evm-calls.org §3 predicted "cost: nil" on the belief that both
//! payloads are one limb; they are not — §10 records the correction.)

use core::marker::PhantomData;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::borsh::{CircuitBorsh, Limbs};
use minocrab_std::v3::hash::upgrade_from_transient;
use minocrab_std::v3::{
    eq, is_true, not, own_public_key, repr_limbs, ArgPath, Bytes, CircuitAbi, CircuitArg, Disclose,
    DisclosureLabel, FieldPath, LedgerMap, LedgerRepr, LedgerWidth, Prim, Uint, Vis3,
    ZswapCoinPublicKey, B32,
};
use signet_signer_interface::{RequestId, Signature};

use crate::common::{self, SecretKey, SigningPath};
use crate::erc20_vault::REFUND_PAD;
use crate::evm::{build_tx, AbiTuple, AbiType, EvmCall, OutcomeRule};
use crate::signet::{self, EventRecordV2, Secp256k1SigLimbs, RECORD_FORMAT_VERSION};
use crate::signet_flow::{
    file_request, Attested, Outcome, RequestIdSettled, SignRequest, Signet,
};

/// THE MPC'S FAILURE KIND — byte 0 of the fixed output it attests when a
/// request reverted, never mined, or came back undecodable
/// (spec/borsh-subset.md §5, kind 3).
///
/// Response-only: no request is ever filed under it, so no slot claims it in
/// `LedgerWidth::KINDS` and every slot of a block may receive it.
pub const FAILURE_KIND: u8 = 3;

/// What an attested value must be: a circuit argument (it arrives on the
/// ticket) and a Borsh record (its limbs ARE the signed preimage).
///
/// `Copy` on top, because [`Pending::refund`] needs the value twice: once
/// for the outcome rule's predicate and once inside the digest it may or may
/// not hash it into. Every circuit leaf in this workspace is `Copy` — a wire
/// is a handle — so the bound costs nothing.
pub trait Attestable: Copy + CircuitArg + CircuitBorsh<Private> {}
impl<T: Copy + CircuitArg + CircuitBorsh<Private>> Attestable for T {}

/// A call's attested return value, as a circuit wire.
pub type Ret<C> = <<C as EvmCall>::Return as AbiType>::Wire<Private>;

/// What [`Pending::complete`] hands the author for `C`.
pub type SuccessOf<C> = <<C as EvmCall>::Outcome as OutcomeRule<<C as EvmCall>::Return>>::Success;

/// What [`Pending::refund`] hands the author for an EXECUTED-but-failed `C`.
pub type FailureOf<C> = <<C as EvmCall>::Outcome as OutcomeRule<<C as EvmCall>::Return>>::Failure;

// ---- the callee ---------------------------------------------------------------

/// THE ADDRESS OF A CONTRACT THAT ANSWERS `C` — a `Bytes<20>` that knows
/// which call it is for.
///
/// A callee and a recipient are both twenty bytes and mean opposite things;
/// `Contract<Erc20Transfer>` and `Bytes<20>` do not unify, so the two cannot
/// be swapped in a `request` call. The WIRE shape is a bare `Bytes<20>` —
/// one argument slot, the same schema — so the marker costs nothing.
pub struct Contract<C> {
    address: Bytes<20, Private>,
    _call: PhantomData<fn() -> C>,
}

impl<C> Clone for Contract<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Contract<C> {}

impl<C> Contract<C> {
    /// The callee from an address the contract already holds — a ledger
    /// cell's value, typically (the vault keeps its `stataToken` in one).
    ///
    /// `c` is taken and unused: reinterpreting a limb emits nothing, and the
    /// parameter is here so that adding a check (a non-zero assert, an
    /// allow-list membership) later does not move every call site.
    pub fn from_address<V: Vis3>(_c: &mut Circuit3, address: Bytes<20, V>) -> Self {
        Contract {
            address: Bytes::from_field_unchecked(address.field().private()),
            _call: PhantomData,
        }
    }

    /// The twenty address bytes.
    pub fn address(&self) -> Bytes<20, Private> {
        self.address
    }
}

impl<C> CircuitAbi for Contract<C> {
    const SLOTS: usize = <Bytes<20, Private>>::SLOTS;

    fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
        <Bytes<20, Private>>::push_atoms(atoms);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        <Bytes<20, Private>>::push_prims(prims);
    }
}

impl<C> CircuitArg for Contract<C> {
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Contract {
            address: <Bytes<20, Private>>::declare(c, path),
            _call: PhantomData,
        }
    }

    fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
        self.address.push_slots(slots);
    }
}

// ---- the tickets --------------------------------------------------------------

/// Both tickets carry `(requestId, respond, serializedOutput)` — the wire
/// block `signet_flow::Settle` has, named for the CALL rather than for an
/// environment/response pair.
macro_rules! ticket {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        pub struct $name<C: EvmCall>
        where
            Ret<C>: Attestable,
        {
            /// The entry being settled.
            pub request_id: RequestId<Private>,
            /// The MPC's signature in circuit-input form (`bigR.x` and `s`
            /// little-endian; the reversal is the transaction builder's).
            pub respond: Signature<Private>,
            /// `serializedOutput`: the kind byte, then the attested value.
            pub output: Attested<Ret<C>>,
            _call: PhantomData<fn() -> C>,
        }

        impl<C: EvmCall> CircuitAbi for $name<C>
        where
            Ret<C>: Attestable,
        {
            const SLOTS: usize = <RequestId<Private>>::SLOTS
                + <Signature<Private>>::SLOTS
                + <Attested<Ret<C>>>::SLOTS;

            fn push_atoms(atoms: &mut Vec<minocrab::AlignmentAtom>) {
                <RequestId<Private>>::push_atoms(atoms);
                <Signature<Private>>::push_atoms(atoms);
                <Attested<Ret<C>>>::push_atoms(atoms);
            }

            fn push_prims(prims: &mut Vec<Prim>) {
                <RequestId<Private>>::push_prims(prims);
                <Signature<Private>>::push_prims(prims);
                <Attested<Ret<C>>>::push_prims(prims);
            }
        }

        impl<C: EvmCall> CircuitArg for $name<C>
        where
            Ret<C>: Attestable,
        {
            fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
                $name {
                    request_id: <RequestId<Private>>::declare(c, &path.field("requestId")),
                    respond: <Signature<Private>>::declare(c, &path.field("respond")),
                    output: <Attested<Ret<C>>>::declare(c, &path.field("serializedOutput")),
                    _call: PhantomData,
                }
            }

            fn push_slots(&self, slots: &mut Vec<Wire3<FieldT, Private>>) {
                self.request_id.push_slots(slots);
                self.respond.push_slots(slots);
                self.output.push_slots(slots);
            }
        }
    };
}

ticket!(
    Succeeded,
    "THE CALL EXECUTED AND SUCCEEDED — the only ticket [`Pending::complete`] \
     takes.\n\n\
     The claim is CHECKED, not believed: `complete` asserts the kind, the \
     signature, the record's own kind and version, and then the call's \
     [`OutcomeRule`] predicate. What the ticket's TYPE buys is that a ticket \
     for call `X` cannot be handed to a slot for call `Y`, and that a \
     [`Failed`] cannot be handed to `complete` at all."
);

ticket!(
    Failed,
    "THE CALL DID NOT SUCCEED — the only ticket [`Pending::refund`] takes, \
     for both non-successes.\n\n\
     Either the MPC attested its failure kind ([`FAILURE_KIND`]: reverted, \
     never mined, or an undecodable return), or it attested THIS call's kind \
     with a return the call's [`OutcomeRule`] says is not a success (an \
     ERC-20 `transfer` that mined and returned `false`). The wire shape is \
     [`Succeeded`]'s; in the first case the output slots carry the MPC's \
     padding and are not part of the signed preimage."
);

// ---- what survives privately, with a TYPED domain -----------------------------

/// A commitment's DOMAIN, as a type.
///
/// `signet_flow::Commit` takes the domain as a `&str` at both ends, so a
/// `to` and an `open` that disagree is a proof that never verifies — a
/// runtime symptom for a spelling mistake. Here the pad is carried by a
/// marker type, so the disagreement does not compile.
pub trait CommitTag {
    /// The 32-byte pad the digest starts with.
    const PAD: &'static str;
}

/// The owner commitment's domain: the vault's `"vault:refund:"`, so a record
/// and an environment written through [`Owned`] are byte-identical to the
/// ones the deployed lineage writes.
pub struct OwnerTag;

impl CommitTag for OwnerTag {
    const PAD: &'static str = REFUND_PAD;
}

/// A commitment to a private value, stored in an environment and OPENED on
/// the settle side with a fresh witness — the one way a secret crosses the
/// suspension.
///
/// `transientHash([pad(32, Tag::PAD), value, requestId])`, split into a
/// `Bytes<32>`: the construction `signet_flow::Commit` performs, with the
/// domain moved from an argument to a type parameter. Binding the REQUEST ID
/// in is what keeps two requests by one owner unlinkable.
///
/// # What does not compile
///
/// Opening a commitment under another tag — the two are different types:
///
/// ```compile_fail
/// use minocrab::v3::Circuit3;
/// use minocrab_contracts::common::{witness_sk, SecretKey};
/// use minocrab_contracts::evm_flow::{Commit, CommitTag};
/// use minocrab::Private;
/// use minocrab_std::v3::label;
///
/// struct Owner;
/// impl CommitTag for Owner { const PAD: &'static str = "a:"; }
/// struct Beneficiary;
/// impl CommitTag for Beneficiary { const PAD: &'static str = "b:"; }
/// label! { Digest = "digest"; }
///
/// fn f(c: &mut Circuit3, id: signet_signer_interface::RequestId<minocrab::Public>) {
///     let sk = witness_sk(c);
///     let made: Commit<SecretKey<Private>, Owner> = Commit::to::<Digest>(c, &sk, id);
///     // ERROR: expected `Commit<_, Beneficiary>`, found `Commit<_, Owner>`
///     let opened: Commit<SecretKey<Private>, Beneficiary> = made;
///     opened.open(c, &sk, id, "nope");
/// }
/// ```
pub struct Commit<T, Tag> {
    digest: B32<Public>,
    _t: PhantomData<fn() -> (T, Tag)>,
}

impl<T, Tag> Clone for Commit<T, Tag> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, Tag> Copy for Commit<T, Tag> {}

impl<T: CircuitArg, Tag: CommitTag> Commit<T, Tag> {
    fn digest_of(c: &mut Circuit3, value: &T, request_id: RequestId<Public>) -> B32<Private> {
        c.region("signet flow: commitment", |c| {
            let pad = B32::pad(c, Tag::PAD);
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
    /// (it is stored, so it is public — the label names it in the disclosure
    /// inventory).
    pub fn to<L: DisclosureLabel>(
        c: &mut Circuit3,
        value: &T,
        request_id: RequestId<Public>,
    ) -> Self {
        let digest = Self::digest_of(c, value, request_id).disclose_as::<L>(c);
        Commit {
            digest,
            _t: PhantomData,
        }
    }

    /// Assert that `value` (a FRESH witness on the settle side) is what this
    /// commitment was made to, for this request.
    pub fn open(
        &self,
        c: &mut Circuit3,
        value: &T,
        request_id: RequestId<Public>,
        message: &'static str,
    ) {
        let recomputed = Self::digest_of(c, value, request_id);
        let stored = self.digest.private();
        c.assert(
            eq(recomputed.hi, stored.hi)
                .and(eq(recomputed.lo, stored.lo))
                .message(message),
        );
    }
}

impl<T, Tag> LedgerRepr for Commit<T, Tag> {
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

// ---- the owned environment ----------------------------------------------------

/// "ONLY THE ORIGINAL CALLER MAY REFUND", as an environment wrapper.
///
/// [`Pending::request_owned`] witnesses the caller's secret key and commits
/// it bound to the request id; [`Pending::refund_to_owner`] witnesses a
/// FRESH secret and opens the commitment. [`Pending::complete`] has no
/// method that consumes a secret at all — which is the point: the deployed
/// vault's Gap 2 (a `completeWithdraw` that hoists a secret witness for a
/// refund branch it may not take) is not writable on this API.
pub struct Owned<E> {
    /// The caller, as a commitment bound to this request.
    pub owner: Commit<SecretKey<Private>, OwnerTag>,
    /// Whatever else the settle side needs.
    pub inner: E,
}

impl<E: LedgerRepr> LedgerRepr for Owned<E> {
    fn atoms() -> Vec<minocrab::AlignmentAtom> {
        let mut atoms = <Commit<SecretKey<Private>, OwnerTag> as LedgerRepr>::atoms();
        atoms.extend(E::atoms());
        atoms
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        LedgerRepr::push_limbs(&self.owner, c, limbs);
        LedgerRepr::push_limbs(&self.inner, c, limbs);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        let mut limbs = limbs.into_iter();
        let owner = <Commit<SecretKey<Private>, OwnerTag> as LedgerRepr>::from_limbs(
            limbs
                .by_ref()
                .take(repr_limbs::<Commit<SecretKey<Private>, OwnerTag>>())
                .collect(),
        );
        Owned {
            owner,
            inner: E::from_limbs(limbs.collect()),
        }
    }
}

// ---- the slot -----------------------------------------------------------------

/// A suspended EVM CALL: two ledger fields (the MPC-facing record map and
/// the caller's environment map) plus the block's [`Signet`] configuration,
/// typed by the call it makes.
///
/// `WORDS` is the record's calldata capacity. Stable Rust cannot write
/// `EventRecordV2<{ <Call::Args as AbiTuple>::WORDS }>`
/// (`generic_const_exprs`), so the number is NAMED and CHECKED — an
/// inline-`const` assert in the constructor makes a mismatch an
/// `error[E0080]` (notes/evm-calls.org §3).
///
/// The `Signet` handle is built by `#[derive(Ledger)]`, which finds the
/// block's one `Signet` field and threads its offset in
/// ([`Self::at_block_with_signet`]). That is why `request`, `complete` and
/// `refund` take no `&SELF.signet`.
pub struct Pending<Call, Env, const WORDS: usize = 2> {
    records: LedgerMap<RequestId<Public>, EventRecordV2<WORDS>>,
    envs: LedgerMap<RequestId<Public>, Env>,
    signet: Signet,
    _call: PhantomData<fn() -> Call>,
}

impl<Call: EvmCall, Env, const WORDS: usize> Pending<Call, Env, WORDS> {
    /// The slot's two fields from flat index `start`, against the block's
    /// `Signet` at `signet_start` — what `#[derive(Ledger)]` emits for a
    /// field whose type is spelled `Pending`.
    pub const fn at_block_with_signet(total: usize, start: usize, signet_start: usize) -> Self {
        const {
            assert!(
                WORDS == <Call::Args as AbiTuple>::WORDS,
                "`Pending<Call, Env, WORDS>` needs WORDS == <Call::Args as \
                 AbiTuple>::WORDS — the record's calldata capacity IS the \
                 call's argument-word count. Stable Rust cannot infer it \
                 (generic_const_exprs), so name the number the argument \
                 tuple encodes to."
            )
        }
        Pending {
            records: LedgerMap::at_block(total, start),
            envs: LedgerMap::at_block(total, start + 1),
            signet: Signet::at_block(total, signet_start),
            _call: PhantomData,
        }
    }

    /// The record map's ledger path: the notification's `depth ‖ path`.
    pub const fn record_path(&self) -> FieldPath {
        self.records.field_path()
    }
}

impl<Call: EvmCall, Env, const WORDS: usize> LedgerWidth for Pending<Call, Env, WORDS> {
    const WIDTH: usize = 2;
    const KINDS: &'static [u8] = &[Call::KIND];
}

impl<Call: EvmCall, Env: LedgerRepr, const WORDS: usize> Pending<Call, Env, WORDS>
where
    Ret<Call>: Attestable,
{
    /// FILE THE CALL. Builds `Call`'s transaction from the callee and the
    /// argument tuple, files the signing record under `Call::KIND`, stores
    /// the environment beside it and notifies the singleton with this slot's
    /// own ledger path. Returns the disclosed request id, and discloses
    /// `signet_flow::Requested` plus whatever `env` discloses.
    ///
    /// `key_version` and `nonce` are still the CALLER'S (the prover picks
    /// the EVM nonce; the MPC's key owns the sequence). Both want a home in
    /// the block or in an administrator-set policy cell — notes/evm-calls.org
    /// §7, the conversation queued after this build.
    pub fn request(
        &self,
        c: &mut Circuit3,
        callee: Contract<Call>,
        args: <Call::Args as AbiTuple>::Wires<Private>,
        key_version: Uint<8>,
        nonce: Uint<64>,
        env: impl FnOnce(&mut Circuit3, RequestId<Public>) -> Env,
    ) -> RequestId<Public> {
        let tx = build_tx::<Call, WORDS>(c, callee.address, args, nonce.field());
        let path = SigningPath::contract_path(c).private();
        file_request(
            c,
            &self.signet,
            &self.records,
            SignRequest {
                key_version,
                path,
                tx,
            },
            Call::KIND,
            |c, request_id| {
                // The environment is built AFTER the id exists, so a
                // `Commit` in it binds to this request and no other.
                let env = env(c, request_id);
                self.envs.insert(c, &request_id, &env);
            },
        )
    }

    /// SETTLE A SUCCESS. Asserts the attestation's kind is this slot's,
    /// verifies the MPC's signature over the Poseidon digest of
    /// `(requestId ‖ borsh(kind ‖ output))`, consumes record and
    /// environment, checks the record's own kind and format version — and
    /// then asserts the call's [`OutcomeRule`] predicate.
    ///
    /// ANYONE MAY CALL IT: the attestation is the gate, and no secret is
    /// witnessed. Discloses `signet_flow::Settled`.
    pub fn complete(
        &self,
        c: &mut Circuit3,
        ticket: Succeeded<Call>,
    ) -> Outcome<Env, SuccessOf<Call>, WORDS> {
        let request_id = ticket.request_id.disclose_as::<RequestIdSettled>(c);
        let attested = ticket.output;

        c.region("signet flow: attestation", |c| {
            c.assert(
                eq(attested.kind.field(), u64::from(Call::KIND)).message("Wrong response kind"),
            );
            let key = self.signet.mpc_response_key.read(c);
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

        let (record, env) = self.consume(c, request_id);
        let split = <Call::Outcome as OutcomeRule<Call::Return>>::split(c, attested.output);
        c.assert(split.succeeded.message("The attested call did not succeed"));

        Outcome {
            request_id,
            env,
            output: split.success,
            record,
        }
    }

    /// SETTLE A NON-SUCCESS. Accepts [`FAILURE_KIND`] (reverted, never
    /// mined, undecodable) OR this slot's kind with the [`OutcomeRule`]
    /// predicate false. Discloses `signet_flow::Settled`.
    ///
    /// The two accepted attestations have different preimage LENGTHS (see
    /// the module docs), so the digest is hashed both ways and selected by
    /// the kind byte before the single signature check.
    pub fn refund(
        &self,
        c: &mut Circuit3,
        ticket: Failed<Call>,
    ) -> Outcome<Env, FailureOf<Call>, WORDS> {
        let request_id = ticket.request_id.disclose_as::<RequestIdSettled>(c);
        let attested = ticket.output;

        let split = <Call::Outcome as OutcomeRule<Call::Return>>::split(c, attested.output);

        c.region("signet flow: attestation", |c| {
            // BOTH kinds are legal here, and they sign DIFFERENT preimages:
            // the MPC's failure output is the kind byte alone, this call's
            // output is the kind byte and the return value.
            let is_failure = c.test_eq(attested.kind.field(), u64::from(FAILURE_KIND));

            let mut executed = Limbs::<Private>::new();
            request_id.private().push_limbs(&mut executed);
            attested.push_limbs(&mut executed);
            let executed_digest = executed.transient_hash(c);

            let mut failed = Limbs::<Private>::new();
            request_id.private().push_limbs(&mut failed);
            attested.kind.push_limbs(&mut failed);
            let failed_digest = failed.transient_hash(c);

            let digest = c.cond_select(is_failure, failed_digest, executed_digest);
            let digest = upgrade_from_transient(c, digest);

            let key = self.signet.mpc_response_key.read(c);
            let valid = signet::verify_attestation_signature(
                c,
                &digest,
                &Secp256k1SigLimbs {
                    big_r_x: ticket.respond.big_r.x,
                    s: ticket.respond.s,
                },
                key.point().private(),
            );
            c.assert(valid);

            // …and the kind is one of the two this slot accepts, with the
            // EXECUTED one accepted only when the call did not succeed.
            let failure_kind = eq(attested.kind.field(), u64::from(FAILURE_KIND));
            let this_kind = eq(attested.kind.field(), u64::from(Call::KIND));
            c.assert(
                failure_kind
                    .or(this_kind.and(not(split.succeeded)))
                    .message("Not a refundable outcome"),
            );
        });

        let (record, env) = self.consume(c, request_id);
        Outcome {
            request_id,
            env,
            output: split.failure,
            record,
        }
    }

    /// Read and remove the record and the environment, and bind the record
    /// to THIS slot (its kind byte and its format version).
    fn consume(
        &self,
        c: &mut Circuit3,
        request_id: RequestId<Public>,
    ) -> (EventRecordV2<WORDS>, Env) {
        c.region("signet flow: consume", |c| {
            let found = self.records.member(c, &request_id);
            c.assert(is_true(found).message("Request not found"));
            let record = self.records.lookup(c, &request_id);
            self.records.remove(c, &request_id);
            let env = self.envs.lookup(c, &request_id);
            self.envs.remove(c, &request_id);
            let kind_ok = c.test_eq(record.response_kind(), u64::from(Call::KIND));
            c.assert(kind_ok);
            let version_ok = c.test_eq(record.format_version(), u64::from(RECORD_FORMAT_VERSION));
            c.assert(version_ok);
            (record, env)
        })
    }
}

impl<Call: EvmCall, E: LedgerRepr, const WORDS: usize> Pending<Call, Owned<E>, WORDS>
where
    Ret<Call>: Attestable,
{
    /// [`Pending::request`] with the caller's identity committed into the
    /// environment: the secret key is witnessed here and bound to the
    /// request id, and only a prover who can re-witness it may
    /// [`Self::refund_to_owner`].
    ///
    /// `L` labels the commitment in the disclosure inventory (it is stored,
    /// so it is public).
    pub fn request_owned<L: DisclosureLabel>(
        &self,
        c: &mut Circuit3,
        callee: Contract<Call>,
        args: <Call::Args as AbiTuple>::Wires<Private>,
        key_version: Uint<8>,
        nonce: Uint<64>,
        inner: impl FnOnce(&mut Circuit3, RequestId<Public>) -> E,
    ) -> RequestId<Public> {
        let sk = common::witness_sk(c);
        self.request(c, callee, args, key_version, nonce, |c, request_id| Owned {
            owner: Commit::to::<L>(c, &sk, request_id),
            inner: inner(c, request_id),
        })
    }

    /// [`Pending::refund`] with the OWNER GATE: a fresh secret is witnessed
    /// and the stored commitment is opened against it, and the caller's own
    /// public key comes back as the recipient.
    ///
    /// `L` labels that public key. There is deliberately no `complete`
    /// counterpart — a completion never opens the commitment and never
    /// witnesses a secret.
    pub fn refund_to_owner<L: DisclosureLabel>(
        &self,
        c: &mut Circuit3,
        ticket: Failed<Call>,
    ) -> (ZswapCoinPublicKey<Public>, E, FailureOf<Call>) {
        let outcome = self.refund(c, ticket);
        let sk = common::witness_sk(c);
        outcome
            .env
            .owner
            .open(c, &sk, outcome.request_id, "Not the owner");
        let owner = own_public_key(c).disclose_as::<L>(c);
        (owner, outcome.env.inner, outcome.output)
    }
}
