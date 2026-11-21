//! How a Signet deployment FILES a typed EVM call: the [`Filing`] (the call
//! plus the output schema the MPC decodes its return under), the fee
//! [`Envelope`], and the `build_tx*` family that turns a call into the
//! [`EvmTx`] a request files (M37 rung A, notes/evm-calls.org §§1-2).
//!
//! The call itself — [`EvmCall`], its argument tuple and its return — is
//! the EVM ABI layer's and knows nothing about Signet.
//! [`Filing`] — HOW ONE SLOT FILES ONE CALL: the OUTPUT SCHEMA the MPC
//! decodes the return under, which carries the deployed record's name for
//! the attested value. That is a fact about a DEPLOYMENT's protocol, not
//! about the Solidity function (the same `transfer` is decoded for its
//! flag by a vault and not decoded at all by a protocol that only wants
//! the verdict), so it sits here rather than on the call.
//! [`Filed<Call, Schema>`](Filed) is the one-line impl.
//!
//! [`build_tx`] is where they meet: it turns a callee, an argument
//! tuple and a nonce into the [`EvmTx`] a request files, with the selector,
//! the words, the word count, the gas limit and the fixed fee envelope all
//! read off the call type.
//!
//! # What compiles
//!
//! A `transfer(to, amount)`, whole. The selector, the word count, the fee
//! envelope and the gas limit are not written down anywhere here:
//!
//! ```
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! let tx = build_tx::<erc20::Transfer, 2>(&mut c, token, (to, amount), nonce);
//! ```
//!
//! THE TWO BLOCKS BELOW ARE THAT SAME CODE, changed in one place each —
//! which is what makes them evidence: the surrounding lines compile, so the
//! rejection is the swap and the number, not a typo.
//!
//! # What does not compile
//!
//! The argument tuple in the wrong order — `transfer` takes the recipient
//! FIRST, and swapping the two is a type error, not a transaction that
//! sends tokens to an address made out of an amount:
//!
//! ```compile_fail,E0308
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // ERROR: expected `(Bytes<20>, Uint<128>)`, found `(Uint<128>, Bytes<20>)`
//! let tx = build_tx::<erc20::Transfer, 2>(&mut c, token, (amount, to), nonce);
//! ```
//!
//! A `WORDS` that is not the argument tuple's word count — stable Rust
//! cannot INFER the number (notes/evm-calls.org §3), but it can reject a
//! wrong one, and an inline-`const` assert makes that an `error[E0080]` at
//! the call site:
//!
//! ```compile_fail,E0080
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // error[E0080]: `build_tx::<C, WORDS>` needs WORDS == <C::Args>::WORDS …
//! let tx = build_tx::<erc20::Transfer, 3>(&mut c, token, (to, amount), nonce);
//! ```
//!
//!
//! ETHER ON A CALL THAT CANNOT TAKE IT. [`build_tx_payable`] is the only
//! way a non-zero `value` reaches an [`EvmTx`], and its `C: Payable` bound
//! is a missing impl for every call but WETH's `deposit()`:
//!
//! ```compile_fail,E0277
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx_payable, erc20};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let value = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("value"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // ERROR: the trait bound `erc20::Transfer: Payable` is not satisfied
//! let tx = build_tx_payable::<erc20::Transfer, 2>(&mut c, token, (to, amount), value, nonce);
//! ```
//!
//! THE SAME CODE FOR THE CALL THAT IS PAYABLE — `weth::Deposit`, whose
//! ether IS its argument, so the tuple is empty and the word count is zero:
//!
//! ```
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx_payable, weth};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let value = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("value"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let weth9 = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("weth"));
//! let tx = build_tx_payable::<weth::Deposit, 0>(&mut c, weth9, (), value, nonce);
//! ```

use core::marker::PhantomData;

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Private};
use minocrab_std::v3::{Bytes, Uint, B32};

use crate::evm_abi::{AbiArgs, AbiTuple, EvmCall, Payable};
use crate::signet_flow::EvmTx;
use crate::signet_v1::{EvmCalldata, OutputSchema};

/// The CONTRACT-FIXED fee envelope the typed-call lineage files under
/// (`Envelope::Fixed`): the priority fee and fee cap the seventeen-circuit
/// vault pinned in its source (1 gwei / 30 gwei). The flush-pattern vault
/// (M44) keeps its envelope in ledger cells instead, so these live here now.
pub const FIXED_PRIORITY_FEE: u64 = 1_000_000_000;
pub const FIXED_MAX_FEE: u64 = 30_000_000_000;

// ---- the filing ---------------------------------------------------------------

/// HOW ONE SLOT FILES ITS CALL — the call plus the facts that are about a
/// DEPLOYMENT's protocol rather than about the Solidity function
/// (notes/evm-interfaces.org §1).
///
/// [`EvmCall`] carries what `transfer` IS. What it cannot carry is what the
/// MPC is asked to DECODE out of the return (`[{"name":"success","type":
/// "bool"}]` for a vault, `[]` for a protocol that only wants the verdict),
/// or what a particular deployed record calls the value that comes back.
/// Those are facts about the SLOT, and this is where a slot states them.
///
/// WHAT WENT, IN M44 RUNG D: the response KIND byte. The V1 record carries
/// none — a request is identified by its id alone, and an attestation is
/// bound to a slot by the slot's own record map (the entry is there or it is
/// not) and by the ticket's TYPE. So two slots of one block may file the
/// same call with the same schema and still not swap tickets, and there is
/// no byte left to allocate by hand.
///
/// [`Filed`] is the off-the-shelf impl, and for most slots it is the whole
/// declaration. A deployment writes the impl out by hand when it needs TWO
/// slots that file the same call under the same schema — the tickets are
/// typed by the filing, so two distinct types are what keep a deposit's
/// `Succeeded` from settling a withdrawal:
///
/// ```
/// use minocrab_contracts::evm::{erc20, Filing};
/// use minocrab_contracts::signet_v1::schema;
///
/// /// `transfer` as this protocol's withdrawal.
/// pub struct Withdrawal;
/// impl Filing for Withdrawal {
///     type Call = erc20::Transfer;
///     type Schema = schema::Success;
/// }
/// ```
pub trait Filing: 'static {
    /// The call this slot files.
    type Call: EvmCall;

    /// THE OUTPUT SCHEMA this slot's records carry — what the MPC decodes
    /// the EVM return under before it attests it
    /// ([`signet_v1::OutputSchema`](crate::signet_v1::OutputSchema), the library's five in
    /// [`signet_v1::schema`](crate::signet_v1::schema)).
    ///
    /// It is a wire commitment in the strongest sense: the schema string is
    /// inside the record, so it is inside the request id, so a slot that
    /// files the wrong schema files a DIFFERENT request — and the attested
    /// width it implies is inside the signed digest, so an output of the
    /// wrong width cannot verify.
    ///
    /// The schema and the call's [`AbiReturn`](crate::evm_abi::AbiReturn) narrowing have to agree, and
    /// nothing here checks that they do: a `[]` schema with a `Bool` return
    /// asks the MPC for no output and then looks for a byte, which fails at
    /// the digest. Pair them the way [`Filed`]'s doc table does.
    ///
    /// IT CARRIES THE RETURN'S NAME, which is why `RETURN_FIELD` went with
    /// the kind byte in M44 rung D: a V1 attestation's `serializedOutput` is
    /// a flat `Bytes<LEN>` argument, so there is no named field inside it for
    /// a filing to spell — the name the deployed records use (`success`,
    /// `amountIn`, `shares`, `assets`) is inside this schema string, where
    /// the MPC reads it.
    type Schema: OutputSchema;

    /// THE GAS LIMIT THIS SLOT FILES WITH, if it differs from the call's own
    /// default ([`EvmCall::GAS_LIMIT`]).
    ///
    /// A gas limit is a fact about the FUNCTION by default (§2.3) — but a
    /// deployment sometimes knows more than the library's per-function
    /// number does (a route through a proxy, a token with an unusually
    /// expensive hook), and that knowledge is the SLOT's, not the call's. A
    /// `Filing` that leaves this at the default emits exactly what
    /// [`EvmCall::GAS_LIMIT`] does — no filing needed one until this rung,
    /// which is why every filing before it still takes the default
    /// (notes/evm-interfaces.org §10).
    const GAS_LIMIT: u64 = <Self::Call as EvmCall>::GAS_LIMIT;
}

/// THE ONE-LINE FILING: this call, decoded under this schema.
///
/// `type Transfer = Filed<erc20::Transfer, schema::Success>;` and the slot,
/// both tickets and both settle signatures are that one name
/// (notes/evm-interfaces.org §2.2).
///
/// THE PAIRS THAT MAKE SENSE — the schema says what the MPC decodes, the
/// call's [`EvmCall::Return`] says what this contract then narrows, and they
/// have to be the same thing:
///
/// | `Return`             | `Schema`                                 | attested |
/// |----------------------|------------------------------------------|----------|
/// | [`Bool`](crate::evm_abi::Bool)             | [`schema::Success`](crate::signet_v1::schema::Success) | 1 byte |
/// | [`U64`](crate::evm_abi::U64) / [`U128`](crate::evm_abi::U128) / [`U256`](crate::evm_abi::U256) | [`schema::AmountIn`](crate::signet_v1::schema::AmountIn), `Shares`, `Assets` | 32 bytes |
/// | [`Unit`](crate::evm_abi::Unit)             | [`schema::NoReturn`](crate::signet_v1::schema::NoReturn) | nothing |
///
/// WHY A WRAPPER RATHER THAN A PARAMETER ON THE SLOT: the schema is consumed
/// by the TICKETS too (the attested width is the call's, and `refund`
/// selects between that width and zero), so a slot parameter would put
/// `Succeeded<Call, Schema>` on every settle signature.
///
/// WHAT WENT WITH THE KIND BYTE: the second parameter used to be the
/// protocol's response kind (`Kinded<erc20::Transfer, 1>`), a byte a
/// deployment had to allocate by hand and the Ledger derive had to check was
/// unique per block. V1 records carry no kind, so the parameter is the
/// schema instead — a fact a deployment reads off its own ABI rather than
/// one it invents.
pub struct Filed<Call, Schema>(PhantomData<fn() -> (Call, Schema)>);

impl<Call: EvmCall + 'static, Schema: OutputSchema> Filing for Filed<Call, Schema> {
    type Call = Call;
    type Schema = Schema;
}

// ---- the transaction ---------------------------------------------------------

/// The [`EvmTx`] a request files for `C`, from a callee, an argument tuple
/// and a nonce — the future `Pending::request` body's core.
///
/// What it reads off the call type: the selector (an immediate), the gas
/// limit, the word count. What it fixes: `value = 0` (these are token
/// calls, never ether transfers), `calldata_is_some = 1`, and the
/// contract-FIXED fee envelope — 1 gwei priority, 30 gwei cap, the same two
/// numbers `erc20_vault::FIXED_PRIORITY_FEE` / `FIXED_MAX_FEE` name and the
/// vault's `FixedGas` emits. What it does NOT read: the chain id, which is
/// the Signet block's (`Pending::request` supplies it, so a request cannot
/// name another chain than the one the contract is configured for).
///
/// `WORDS` IS NAMED BY THE CALLER because stable Rust cannot write
/// `EvmTx<{ <C::Args as AbiTuple>::WORDS }>` — that needs
/// `generic_const_exprs` (notes/evm-calls.org §3). What it CAN do is reject
/// a wrong one, which is the inline-`const` assert below and an
/// `error[E0080]` at the call site.
///
/// Instruction order is the vault's: the words first (the caller has
/// already built the argument wires), then the fee envelope, then the
/// transaction's constants — so a vault circuit moving onto this emits the
/// same stream it emits today.
pub fn build_tx<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS> {
    build_tx_at::<C, WORDS>(c, callee, args, nonce, C::GAS_LIMIT)
}

/// [`build_tx`], but the fee envelope's gas limit is [`Filing::GAS_LIMIT`]
/// rather than the call's own default — what
/// [`Pending::request`](crate::evm_flow::Pending::request) builds a
/// `Pending<F, …>` slot's transaction from (notes/evm-interfaces.org §10).
///
/// `Filing::GAS_LIMIT`'s default is `Self::Call::GAS_LIMIT`, so an
/// unoverridden filing emits exactly what [`build_tx`] does — ZERO
/// MOVEMENT for every filing that does not name this const.
pub fn build_tx_filed<F: Filing, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <<F::Call as EvmCall>::Args as AbiTuple>::Wires<Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS> {
    build_tx_at::<F::Call, WORDS>(c, callee, args, nonce, F::GAS_LIMIT)
}

/// The shared body of [`build_tx`] and [`build_tx_filed`]: `gas_limit` is
/// the only thing that differs between the two callers.
fn build_tx_at<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx::<C, WORDS>` needs WORDS == <C::Args as AbiTuple>::WORDS — \
             the record's calldata capacity IS the argument list's word count. \
             Stable Rust cannot infer it (generic_const_exprs), so name the \
             number the tuple actually encodes to."
        )
    };

    let words = <C::Args as AbiTuple>::words(c, args);
    finish_tx::<C, WORDS>(c, words, Envelope::fixed(), |_| callee, nonce, gas_limit)
}

/// [`build_tx`] FROM WORDS THAT ARE ALREADY ENCODED — what an outbox EMIT
/// has, and all it has: the argument words were encoded at the CALL, from
/// typed wires, and have been sitting in the outbox as stored limbs ever
/// since ([`crate::evm_flow::Outbox`]).
///
/// Everything else is [`build_tx`]: the same const-checked `WORDS`, the same
/// emission order through `finish_tx`. Two things the emit supplies rather
/// than the stored entry, because supplying them IS the emit
/// (notes/nonce-admin.org §4, §1.1): the NONCE, which the contract assigned
/// blind at the call and the emit reads off the snapshot, and the ENVELOPE,
/// which is the contract's — neither is ever a requester's argument.
///
/// The words are a LEDGER READ privatized, not a prover's value: nothing
/// re-encodes them here and nothing needs to, because the read's `popeq`
/// binds them to the stored entry [`AbiTuple::words`] encoded at insert.
pub fn build_tx_from_words<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    words: [B32<Private>; WORDS],
    envelope: Envelope,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx_from_words::<C, WORDS>` needs WORDS == <C::Args as \
             AbiTuple>::WORDS — the record's calldata capacity IS the \
             argument list's word count. Stable Rust cannot infer it \
             (generic_const_exprs), so name the number the tuple actually \
             encodes to."
        )
    };

    finish_tx::<C, WORDS>(c, words.to_vec(), envelope, |_| callee, nonce, gas_limit)
}

/// [`build_tx`] FOR A CALL THAT CARRIES ETHER — the transaction's `value`
/// field is a real amount rather than the constant zero.
///
/// `C: Payable` is the whole gate: WETH's `deposit()` has the impl and an
/// ERC-20 `transfer` does not, so an amount cannot be attached to a call
/// that would ignore it. Everything else is [`build_tx`] — the same
/// envelope, the same emission order, the same const-checked `WORDS`.
pub fn build_tx_payable<C: Payable, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    value: Uint<128, Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS> {
    build_tx_payable_at::<C, WORDS>(c, callee, args, value, nonce, C::GAS_LIMIT)
}

/// [`build_tx_filed`] for a [`Payable`] call —
/// [`Pending::request_payable`](crate::evm_flow::Pending::request_payable)'s
/// counterpart to [`build_tx_payable`], reading the slot's
/// [`Filing::GAS_LIMIT`] instead of the call's.
pub fn build_tx_payable_filed<F: Filing, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <<F::Call as EvmCall>::Args as AbiTuple>::Wires<Private>,
    value: Uint<128, Private>,
    nonce: Wire3<FieldT, Private>,
) -> EvmTx<WORDS>
where
    F::Call: Payable,
{
    build_tx_payable_at::<F::Call, WORDS>(c, callee, args, value, nonce, F::GAS_LIMIT)
}

/// The shared body of [`build_tx_payable`] and [`build_tx_payable_filed`].
fn build_tx_payable_at<C: Payable, const WORDS: usize>(
    c: &mut Circuit3,
    callee: Bytes<20, Private>,
    args: <C::Args as AbiTuple>::Wires<Private>,
    value: Uint<128, Private>,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx_payable::<C, WORDS>` needs WORDS == <C::Args as AbiTuple>::WORDS \
             — the record's calldata capacity IS the argument list's word count. \
             Stable Rust cannot infer it (generic_const_exprs), so name the \
             number the tuple actually encodes to."
        )
    };

    let words = <C::Args as AbiTuple>::words(c, args);
    finish_tx::<C, WORDS>(
        c,
        words,
        Envelope::fixed().ether(value),
        |_| callee,
        nonce,
        gas_limit,
    )
}

/// WHO PAYS, AND HOW THE TRANSACTION'S CONSTANTS ARE SPELLED — everything
/// about the request that is neither the callee, the arguments nor the nonce.
///
/// Two independent answers, in one value because they are the two things a
/// [`build_tx_with`] caller ever has to say:
///
/// - THE FEES ([`Envelope::fixed`] / [`Envelope::caller`]). The fixed
///   envelope is the contract's own constant one — 1 gwei priority, 30 gwei
///   cap (`erc20_vault::FIXED_PRIORITY_FEE` / `FIXED_MAX_FEE`) and
///   [`EvmCall::GAS_LIMIT`]. The caller's envelope is the shape the vault's
///   `deposit` has: the transaction is paid from the DEPOSITOR's own EVM
///   account, so the depositor picks all three, and they are circuit
///   arguments (notes/evm-calls.org §9's second rung-A finding; §7 is the
///   conversation about giving them an administrator-set home instead).
/// - THE SPELLING ([`Envelope::literal`]). See that method.
pub struct Envelope {
    fees: Fees,
    tail: Tail,
}

enum Fees {
    Fixed,
    Caller {
        max_priority_fee_per_gas: Uint<128, Private>,
        max_fee_per_gas: Uint<128, Private>,
        gas_limit: Uint<64, Private>,
    },
}

enum Tail {
    Named {
        /// The ether the transaction carries, for a [`Payable`] call.
        /// `None` — every non-payable call — is the constant zero, named
        /// where it has always been named.
        value: Option<Wire3<FieldT, Private>>,
    },
    Literal {
        value: Option<Wire3<FieldT, Private>>,
        calldata_is_some: Wire3<FieldT, Private>,
    },
}

impl Envelope {
    /// The contract's own fee envelope: 1 gwei priority, 30 gwei cap, the
    /// call's [`EvmCall::GAS_LIMIT`].
    pub fn fixed() -> Self {
        Envelope {
            fees: Fees::Fixed,
            tail: Tail::Named { value: None },
        }
    }

    /// THE CALLER'S fee envelope — all three numbers as circuit arguments,
    /// for a transaction paid from the caller's own EVM account rather than
    /// the contract's.
    pub fn caller(
        max_priority_fee_per_gas: Uint<128, Private>,
        max_fee_per_gas: Uint<128, Private>,
        gas_limit: Uint<64, Private>,
    ) -> Self {
        Envelope {
            fees: Fees::Caller {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
            },
            tail: Tail::Named { value: None },
        }
    }

    /// THE HAND-WRITTEN SPELLING of the transaction's constant fields, for a
    /// circuit whose artifact must not move.
    ///
    /// `value = 0` (a token call carries no ether — [`build_tx_payable`] is
    /// the one exception) and `calldata_is_some = 1` (there is always
    /// calldata) are constants of every call this API
    /// builds, and by default [`build_tx_with`] NAMES them, after the fee
    /// envelope and the callee and before the word count and the selector —
    /// the order the vault's `erc20_call` helper named them in, and the order
    /// five of its seven request circuits emit.
    ///
    /// The other two — `swap` and `redeem` — spell their `EvmTx` out as a
    /// struct literal, which named the selector and the word count FIRST and
    /// took `value` and `calldata_is_some` from a zero and a one the circuit
    /// already held (for a `sqrtPriceLimitX96` word and a coin burn). This
    /// selects that spelling: selector, word count, callee, fees, then
    /// `value` only if it is not supplied.
    ///
    /// IT CHANGES NO INSTRUCTION. Every one of these is a `Copy` of an
    /// immediate, and `minocrab_ir::v3::passes::fold_immediate_copies` folds
    /// each into its consumers and deletes it inside `Builder3::finish`, so
    /// the two spellings execute identically and cost identical rows. What
    /// they do not share is the SEQUENTIAL NAMES the surviving instructions
    /// get, because the counter runs over every emitted instruction including
    /// the folded ones. A deployed artifact is compared byte for byte, so a
    /// lineage that spells its transaction the second way keeps saying so.
    /// (notes/evm-calls.org §11 — recorded for dmd: the alternative is to
    /// renumber after folding, which would move every circuit in the tree.)
    pub fn literal(
        self,
        value: Option<Wire3<FieldT, Private>>,
        calldata_is_some: Wire3<FieldT, Private>,
    ) -> Self {
        Envelope {
            fees: self.fees,
            tail: Tail::Literal {
                value,
                calldata_is_some,
            },
        }
    }

    /// THE ETHER — private, and reachable only through
    /// [`build_tx_payable`], whose `C: Payable` bound is the gate. A public
    /// `with_value` on this type could not name the call it will build, so
    /// it could not tell a WETH `deposit` from a `transfer`; the bound goes
    /// where the call is known instead (notes/evm-interfaces.org §5).
    fn ether(self, value: Uint<128, Private>) -> Self {
        Envelope {
            fees: self.fees,
            tail: Tail::Named {
                value: Some(value.field()),
            },
        }
    }

    /// The three fee fields, in wire order. `gas_limit` is the [`Fees::Fixed`]
    /// case's immediate — [`build_tx`] and [`build_tx_payable`] pass the
    /// call's own [`EvmCall::GAS_LIMIT`]; [`build_tx_filed`] and
    /// [`build_tx_payable_filed`] pass the slot's [`Filing::GAS_LIMIT`]
    /// instead (notes/evm-interfaces.org §10). [`Fees::Caller`] ignores it —
    /// its own wire is already the caller's number.
    fn fee_wires(fees: Fees, gas_limit: u64, c: &mut Circuit3) -> [Wire3<FieldT, Private>; 3] {
        match fees {
            Fees::Fixed => {
                let priority_fee = c.constant(FIXED_PRIORITY_FEE);
                let max_fee = c.constant(FIXED_MAX_FEE);
                let gas_limit = c.constant(gas_limit);
                [
                    priority_fee.private(),
                    max_fee.private(),
                    gas_limit.private(),
                ]
            }
            Fees::Caller {
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas_limit,
            } => [
                max_priority_fee_per_gas.field(),
                max_fee_per_gas.field(),
                gas_limit.field(),
            ],
        }
    }
}

/// [`build_tx`] for a caller who has to control WHEN each piece emits: the
/// arguments as builders ([`AbiArgs`]), the fee envelope, and the callee as a
/// builder too.
///
/// The emission order is the deployed vault's, and that is the whole point of
/// the shape: each argument is built and encoded before the next is built,
/// then the envelope, then the callee, then the transaction's own four
/// constants. A request circuit that reads `vaultEvmAddress` between its two
/// words, or its callee cell after the gas constants, keeps its stream.
///
/// `gas_limit` is the [`Envelope::fixed`] case's immediate — [`build_tx`]'s
/// callers pass [`EvmCall::GAS_LIMIT`], and
/// [`Pending::request_with`](crate::evm_flow::Pending::request_with) /
/// [`Fired::request_with`](crate::evm_flow::Fired::request_with) pass the
/// slot's [`Filing::GAS_LIMIT`] instead (notes/evm-interfaces.org §10). An
/// [`Envelope::caller`] envelope ignores it — its own wire is already the
/// caller's number.
pub fn build_tx_with<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    callee: impl FnOnce(&mut Circuit3) -> Bytes<20, Private>,
    args: impl AbiArgs<C::Args>,
    envelope: Envelope,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    const {
        assert!(
            WORDS == <C::Args as AbiTuple>::WORDS,
            "`build_tx_with::<C, WORDS>` needs WORDS == <C::Args as AbiTuple>::WORDS — \
             the record's calldata capacity IS the argument list's word count. \
             Stable Rust cannot infer it (generic_const_exprs), so name the \
             number the tuple actually encodes to."
        )
    };

    let words = args.words(c);
    finish_tx::<C, WORDS>(c, words, envelope, callee, nonce, gas_limit)
}

/// The shared tail of [`build_tx`] and [`build_tx_with`]: envelope, callee,
/// then `value = 0`, `calldata_is_some = 1`, the word count and the selector.
fn finish_tx<C: EvmCall, const WORDS: usize>(
    c: &mut Circuit3,
    words: Vec<B32<Private>>,
    envelope: Envelope,
    callee: impl FnOnce(&mut Circuit3) -> Bytes<20, Private>,
    nonce: Wire3<FieldT, Private>,
    gas_limit: u64,
) -> EvmTx<WORDS> {
    let words: [B32<Private>; WORDS] = match words.try_into() {
        Ok(words) => words,
        // Unreachable: the const asserts above pin WORDS to the tuple's
        // count, and both word builders yield exactly that many.
        Err(_) => unreachable!("the argument list yields <C::Args>::WORDS words"),
    };

    let selector_imm =
        || Fr::from_le_bytes(&C::selector()).expect("four bytes fit a field element");
    let Envelope { fees, tail } = envelope;

    // The two spellings differ only in the ORDER these immediates are named
    // and in which of them the caller already holds — see `Envelope::literal`.
    let ([priority_fee, max_fee, gas_limit], to, value, calldata_is_some, no_words, selector) =
        match tail {
            Tail::Named { value } => {
                let fees = Envelope::fee_wires(fees, gas_limit, c);
                let to = callee(c).field();
                // `None` is every non-payable call: the immediate zero,
                // named exactly where it has always been named.
                let value = value.unwrap_or_else(|| c.constant(0u64).private());
                let calldata_is_some = c.constant(1u64).private();
                let no_words = c.constant(WORDS as u64).private();
                let selector = c.constant(selector_imm()).private();
                (fees, to, value, calldata_is_some, no_words, selector)
            }
            Tail::Literal {
                value,
                calldata_is_some,
            } => {
                let selector = c.constant(selector_imm()).private();
                let no_words = c.constant(WORDS as u64).private();
                let to = callee(c).field();
                let fees = Envelope::fee_wires(fees, gas_limit, c);
                let value = value.unwrap_or_else(|| c.constant(0u64).private());
                (fees, to, value, calldata_is_some, no_words, selector)
            }
        };

    EvmTx {
        nonce,
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit,
        to,
        value,
        calldata_is_some,
        calldata: EvmCalldata {
            selector,
            no_words,
            words,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_abi::erc20;

    /// A `Filed` filing IS its call under its schema, and the gas limit is
    /// the call's own default.
    #[test]
    fn filed_files_the_call_under_the_named_schema() {
        use crate::signet_v1::{schema, OutputSchema};
        type Transfer = Filed<erc20::Transfer, schema::Success>;

        assert_eq!(
            <<Transfer as Filing>::Schema as OutputSchema>::BYTES,
            br#"[{"name":"success","type":"bool"}]"#
        );
        assert_eq!(<Transfer as Filing>::GAS_LIMIT, erc20::CALL_GAS);
        assert_eq!(
            <<Transfer as Filing>::Call as EvmCall>::signature(),
            "transfer(address,uint256)"
        );
    }
}
