//! Typed EVM calls — the call as a type, the slot infers the rest
//! (M37 rung A, notes/evm-calls.org §§1-2).
//!
//! Today a contract that wants `transfer(to, amount)` on the far side writes
//! out the four-byte selector, encodes each ABI word by hand, counts the
//! words, names a gas envelope and picks a response type. Every one of those
//! is DERIVABLE from one thing: which call it is. This module makes that one
//! thing a type.
//!
//! Three layers:
//!
//! 1. [`AbiType`] — one Rust unit type per Solidity leaf ([`Address`],
//!    [`Bool`], [`Bytes32`], [`U24`], [`U64`], [`U128`], [`U160`],
//!    [`U256`]). It carries the leaf's spelling in a selector signature
//!    ([`AbiType::SOLIDITY`]), its spelling in the attested-output schema
//!    the MPC narrows to ([`AbiType::RESPOND`]), the CIRCUIT VALUE that
//!    stands for it ([`AbiType::Wire`]) and the encoder from that value to
//!    a canonical 32-byte ABI word ([`AbiType::word`]).
//! 2. [`AbiTuple`] — the argument list, for `()` and 1- to 8-tuples of
//!    `AbiType`s. It knows the WORD COUNT, the comma-joined signature and
//!    how to encode a tuple of wires into words, in order.
//! 3. [`EvmCall`] — the call: a name, an argument tuple, a return type, the
//!    protocol kind byte and a gas limit. [`EvmCall::selector`] is the first
//!    four bytes of `keccak256("name(argtypes)")`, computed IN RUST at
//!    circuit-build time and embedded as an immediate. Nothing hashes
//!    keccak in-circuit; in-circuit hashing stays Poseidon throughout
//!    (dmd, 2026-09-05: *"Do we actually need a const fn Keccak? Why not
//!    just run it when we run the eDSL?"* — we do not).
//!
//! [`build_tx`] is where the three meet: it turns a callee, an argument
//! tuple and a nonce into the [`EvmTx`] a request files, with the selector,
//! the words, the word count, the gas limit and the fixed fee envelope all
//! read off the call type.
//!
//! # Zero movement
//!
//! The two word encoders ([`address_word`], [`numeric_word`]) are the
//! bodies that used to live in [`crate::signet`], moved here unchanged;
//! `signet::evm_address_abi_word` and `signet::numeric_abi_word` are now
//! one-line delegations to them. `tests/evm_abi.rs` asserts a circuit built
//! through either spelling serializes to byte-identical ZKIR, and the
//! 209-circuit dump is unchanged by the move.
//!
//! # What compiles
//!
//! A `transfer(to, amount)`, whole. The selector, the word count, the fee
//! envelope and the gas limit are not written down anywhere here:
//!
//! ```
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, Erc20Transfer};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! let tx = build_tx::<Erc20Transfer, 2>(&mut c, token, (to, amount), nonce);
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
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, Erc20Transfer};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // ERROR: expected `(Bytes<20>, Uint<128>)`, found `(Uint<128>, Bytes<20>)`
//! let tx = build_tx::<Erc20Transfer, 2>(&mut c, token, (amount, to), nonce);
//! ```
//!
//! A `WORDS` that is not the argument tuple's word count — stable Rust
//! cannot INFER the number (notes/evm-calls.org §3), but it can reject a
//! wrong one, and an inline-`const` assert makes that an `error[E0080]` at
//! the call site:
//!
//! ```compile_fail
//! use minocrab::v3::{Circuit3, FieldT};
//! use minocrab::Private;
//! use minocrab_contracts::evm::{build_tx, Erc20Transfer};
//! use minocrab_std::v3::{Bytes, Uint};
//!
//! let mut c = Circuit3::new();
//! let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
//! let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
//! let nonce = c.arg::<FieldT>("nonce");
//! let token = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("token"));
//! // error[E0080]: `build_tx::<C, WORDS>` needs WORDS == <C::Args>::WORDS …
//! let tx = build_tx::<Erc20Transfer, 3>(&mut c, token, (to, amount), nonce);
//! ```
//!
//! A call type that does not say whether its return means success. There
//! is NO DEFAULT for [`EvmCall::succeeded`], on purpose: "executed ⇒
//! succeeded" is right for most calls and wrong for an ERC-20 `transfer`,
//! and a default would make the dangerous case the one nobody types:
//!
//! ```compile_fail
//! use minocrab_contracts::evm::{Address, EvmCall, U64};
//! use minocrab_std::v3::Uint;
//! use minocrab::Private;
//!
//! struct Balance;
//! // ERROR: not all trait items implemented, missing: `succeeded`
//! impl EvmCall for Balance {
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     type Success = Uint<64, Private>;
//!     const KIND: u8 = 9;
//!     const GAS_LIMIT: u64 = 50_000;
//! }
//! ```
//!
//! A projection the return value cannot produce — `()` is [`FromReturn`]
//! for a `Bool` return and for nothing else, so a numeric call cannot
//! quietly throw its answer away:
//!
//! ```compile_fail
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, Address, EvmCall, U64};
//! use minocrab_std::v3::{Check, Uint};
//!
//! struct Balance;
//! impl EvmCall for Balance {
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     // ERROR: the trait bound `(): FromReturn<Uint<64>>` is not satisfied
//!     type Success = ();
//!     const KIND: u8 = 9;
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles, so each rejection
//! above is the missing item and the mapping rather than a typo:
//!
//! ```
//! use minocrab::v3::Circuit3;
//! use minocrab::Private;
//! use minocrab_contracts::evm::{always, Address, EvmCall, U64};
//! use minocrab_std::v3::{Check, Uint};
//!
//! struct Balance;
//! impl EvmCall for Balance {
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     type Success = Uint<64, Private>;
//!     const KIND: u8 = 9;
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Balance::signature(), "balanceOf(address)");
//! assert_eq!(Balance::selector(), [0x70, 0xa0, 0x82, 0x31]);
//! ```

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Private};
use minocrab_std::v3::{is_true, pow2_const, Bool as BoolWire, Bytes, Check, Uint, Vis3, B32};
use sha3::{Digest as _, Keccak256};

use crate::erc20_vault::{ERC20_CALL_GAS, FIXED_MAX_FEE, FIXED_PRIORITY_FEE, LENDING_GAS, SWAP_GAS};
use crate::erc20_vault_pending::{
    RESPONSE_KIND_APPROVE, RESPONSE_KIND_REDEEM, RESPONSE_KIND_SUPPLY, RESPONSE_KIND_SWAP,
    RESPONSE_KIND_WITHDRAW,
};
use crate::signet::{reverse_bytes32, EvmCalldata};
use crate::signet_flow::EvmTx;

// ---- the encoders (moved from `signet`, unchanged) ---------------------------

/// `evmAddressAbiWord(addr)` — 12 zero bytes then the 20 display-order
/// address bytes. `addr` is the `Bytes<20>` single limb.
///
/// MOVED HERE from `signet` (M37 rung A): this is the body,
/// `signet::evm_address_abi_word` is now a delegation to it, and
/// [`Address::word`] is the typed spelling. Byte-for-byte the same
/// instructions in all three.
pub fn address_word<V: Vis3>(c: &mut Circuit3, addr: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // The word is addr·2^96 (a 12-byte shift), so split the 160-bit
        // limb at bit 152: hi byte = addr >> 152, lo = the rest shifted.
        let (hi, low152) = c.div_mod_power_of_two(addr, 152);
        let shift96 = V::from_public(pow2_const(c, 12));
        let lo = c.mul(low152, shift96);
        B32 { hi, lo }
    })
}

/// `numericAbiWord(value)` — an integer limb as a 32-byte big-endian ABI
/// word: the value's little-endian bytes reversed into the tail.
///
/// MOVED HERE from `signet` (M37 rung A) — see [`address_word`]. The
/// typed spellings are [`Bool::word`], [`U24::word`], [`U64::word`] and
/// [`U128::word`], which differ only in the RANGE their wire type claims:
/// the encoding is the same reversal for all of them, and correct for any
/// limb below `2^248`.
pub fn numeric_word<V: Vis3>(c: &mut Circuit3, value: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // value's 16 LE bytes sit at string positions 0..15 of
        // `B32 { lo: value, hi: 0 }`; the native reversal moves them,
        // reversed, to positions 16..31 — exactly the BE ABI rendering.
        let zero = V::from_public(c.constant(0u64));
        let padded = B32 { hi: zero, lo: value };
        reverse_bytes32(c, &padded)
    })
}

// ---- the ABI type layer ------------------------------------------------------

/// One Solidity leaf: how it is SPELLED, what CIRCUIT VALUE stands for it,
/// and how that value becomes a canonical 32-byte ABI word.
///
/// The implementors are unit types ([`Address`], [`Bool`], …), never
/// instantiated: they exist to be named in an [`EvmCall::Args`] tuple.
pub trait AbiType {
    /// The spelling inside the selector signature — what
    /// `keccak256("transfer(address,uint256)")` sees. `U64`, `U128` and
    /// `U256` all spell `"uint256"`: the ABI word is always 32 bytes, and
    /// the Rust type states the RANGE the contract accepts, not the width
    /// on the wire.
    const SOLIDITY: &'static str;

    /// The spelling in the ATTESTED-OUTPUT schema — the narrowing the MPC
    /// applies before it signs (`SUPPLY_RESPOND_SCHEMA`'s `"uint64"`
    /// against `SUPPLY_OUTPUT_SCHEMA`'s `"uint256"`). This is where `U64`
    /// and `U256` part company.
    const RESPOND: &'static str;

    /// The circuit value that stands for this leaf.
    type Wire<V: Vis3>;

    /// The canonical big-endian ABI word for a value of this leaf.
    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V>;
}

/// Solidity `address` — a `Bytes<20>` limb, left-padded into the word.
pub struct Address;

impl AbiType for Address {
    const SOLIDITY: &'static str = "address";
    const RESPOND: &'static str = "address";
    type Wire<V: Vis3> = Bytes<20, V>;

    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        address_word(c, w.field())
    }
}

/// Solidity `bool` — 0 or 1 right-aligned in the word.
pub struct Bool;

impl AbiType for Bool {
    const SOLIDITY: &'static str = "bool";
    const RESPOND: &'static str = "bool";
    type Wire<V: Vis3> = BoolWire<V>;

    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `bytes32` — the word IS the value; encoding it is the identity
/// and emits no instruction.
pub struct Bytes32;

impl AbiType for Bytes32 {
    const SOLIDITY: &'static str = "bytes32";
    const RESPOND: &'static str = "bytes32";
    type Wire<V: Vis3> = B32<V>;

    fn word<V: Vis3>(_c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

/// NO RETURN AT ALL — the shape a non-conforming ERC-20 actually has.
///
/// USDT, BNB and other pre-EIP-20-final tokens omit the `bool` their
/// `transfer` is supposed to return. Declaring such a callee's calls with
/// `Return = Unit` is what stops the MPC being asked to decode a `bool`
/// from empty return data — a terminal extraction failure, which it
/// resolves as its FAILURE kind, which would refund a transfer that MOVED
/// the tokens (notes/evm-calls.org §3.1, the dangerous direction).
///
/// `Wire<V> = ()`: no slot, no word, no verdict to read — [`Self::success`]
/// is [`always`], because for a call with nothing to say, executing IS
/// succeeding and there is no flag to be fooled by.
///
/// A RETURN TYPE ONLY. It has no ABI word, and [`Self::word`] says so
/// rather than encoding a zero: a `Unit` in an argument tuple is a mistake,
/// and one that would otherwise put a silent zero word on the wire.
/// (Recorded for dmd: a build-time panic where the hard rule prefers a
/// compile error — making it one needs `Args` and `Return` to be separate
/// traits, which re-types every call. notes/evm-calls.org §10.)
pub struct Unit;

impl AbiType for Unit {
    const SOLIDITY: &'static str = "";
    const RESPOND: &'static str = "";
    type Wire<V: Vis3> = ();

    fn word<V: Vis3>(_c: &mut Circuit3, _w: &Self::Wire<V>) -> B32<V> {
        panic!(
            "`Unit` has no ABI word: it is an EvmCall::Return for a callee that \
             returns nothing, never an EvmCall::Args element. Drop it from the \
             argument tuple."
        )
    }
}

/// Solidity `uint24` — Uniswap's pool fee tier, the one sub-word integer
/// the corpus actually passes (`SwapRequest::fee`).
pub struct U24;

impl AbiType for U24 {
    const SOLIDITY: &'static str = "uint24";
    const RESPOND: &'static str = "uint24";
    type Wire<V: Vis3> = Uint<24, V>;

    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint256` carried by a `Uint<64>` — the range a Midnight-side
/// amount actually occupies (every vault mint is the `Uint<64>` API), and
/// the width the MPC narrows an attested `uint256` OUTPUT to.
pub struct U64;

impl AbiType for U64 {
    const SOLIDITY: &'static str = "uint256";
    const RESPOND: &'static str = "uint64";
    type Wire<V: Vis3> = Uint<64, V>;

    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint256` carried by a `Uint<128>` — the width the deployed
/// vault's amounts have on entry (`DepositRequest::amount` and friends).
///
/// A `Uint<64>` reaches it for free (`.widen::<128>()`, no instruction);
/// the other direction is a range check, which is why the vault's own call
/// types take the wider one.
pub struct U128;

impl AbiType for U128 {
    const SOLIDITY: &'static str = "uint256";
    const RESPOND: &'static str = "uint128";
    type Wire<V: Vis3> = Uint<128, V>;

    fn word<V: Vis3>(c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint160` carried by an ALREADY-ENCODED word.
///
/// The only `uint160` in the corpus is Uniswap's `sqrtPriceLimitX96`, which
/// the vault passes as a literal zero word — no encoder, no instruction.
/// A wire of that width does not fit a `Uint<160>`'s useful operations
/// anyway, so the honest type is "the caller supplies the word".
pub struct U160;

impl AbiType for U160 {
    const SOLIDITY: &'static str = "uint160";
    const RESPOND: &'static str = "uint160";
    type Wire<V: Vis3> = B32<V>;

    fn word<V: Vis3>(_c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

/// Solidity `uint256` at its full width — an ALREADY-ENCODED word, since no
/// single field element holds 256 bits.
///
/// The corpus's one full-width value is the unlimited allowance
/// (`2^128 - 1` as a raw word, `unlimited_allowance_word`), built as a
/// constant `B32` and passed straight through.
pub struct U256;

impl AbiType for U256 {
    const SOLIDITY: &'static str = "uint256";
    const RESPOND: &'static str = "uint256";
    type Wire<V: Vis3> = B32<V>;

    fn word<V: Vis3>(_c: &mut Circuit3, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

// ---- the argument list -------------------------------------------------------

/// An [`EvmCall`]'s argument list: `()` or a 1- to 8-tuple of [`AbiType`]s.
///
/// Implemented by a declarative `macro_rules!` over the arities — tooling
/// walks into it (notes/evm-calls.org §6: *"macros that don't completely
/// break tooling"*), and there is no attribute macro rewriting anyone's
/// item.
pub trait AbiTuple {
    /// How many ABI words the list encodes to — one per element, since
    /// every leaf here is a static single word.
    const WORDS: usize;

    /// The tuple of circuit values, one [`AbiType::Wire`] per element.
    type Wires<V: Vis3>;

    /// The comma-joined [`AbiType::SOLIDITY`] spellings — the inside of the
    /// selector signature's parentheses. Built at CIRCUIT-BUILD TIME, in
    /// Rust, like the keccak that consumes it.
    fn signature() -> String;

    /// The words, in argument order. The length is always [`Self::WORDS`].
    fn words<V: Vis3>(c: &mut Circuit3, wires: Self::Wires<V>) -> Vec<B32<V>>;
}

impl AbiTuple for () {
    const WORDS: usize = 0;
    type Wires<V: Vis3> = ();

    fn signature() -> String {
        String::new()
    }

    fn words<V: Vis3>(_c: &mut Circuit3, _wires: ()) -> Vec<B32<V>> {
        Vec::new()
    }
}

macro_rules! abi_tuple {
    ($n:literal; $($t:ident => $idx:tt),+) => {
        impl<$($t: AbiType),+> AbiTuple for ($($t,)+) {
            const WORDS: usize = $n;
            type Wires<V: Vis3> = ($(<$t as AbiType>::Wire<V>,)+);

            fn signature() -> String {
                [$(<$t as AbiType>::SOLIDITY),+].join(",")
            }

            fn words<V: Vis3>(c: &mut Circuit3, wires: Self::Wires<V>) -> Vec<B32<V>> {
                // Left to right, which is argument order, which is word order.
                vec![$(<$t as AbiType>::word(c, &wires.$idx)),+]
            }
        }
    };
}

abi_tuple!(1; A => 0);
abi_tuple!(2; A => 0, B => 1);
abi_tuple!(3; A => 0, B => 1, C => 2);
abi_tuple!(4; A => 0, B => 1, C => 2, D => 3);
abi_tuple!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
abi_tuple!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
abi_tuple!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
abi_tuple!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);

// ---- the call ----------------------------------------------------------------

/// A named EVM function call: what it is called, what it takes, what it
/// returns, which protocol kind its response carries and what it may spend.
///
/// Everything else — the selector, the word count, the response type, the
/// schema spellings — is DERIVED from these five, which is the whole point
/// (notes/evm-calls.org §2).
pub trait EvmCall {
    /// The Solidity function name, without parentheses.
    const NAME: &'static str;

    /// The argument list.
    type Args: AbiTuple;

    /// The attested return value. `Attested<Return::Wire>` at [`Self::KIND`]
    /// is the response a settle circuit consumes.
    type Return: AbiType;

    /// The protocol kind byte the response carries — explicit, a wire
    /// commitment, and the one thing the type layer will not guess.
    const KIND: u8;

    /// The gas LIMIT (not a price; the fee envelope is [`build_tx`]'s).
    const GAS_LIMIT: u64;

    /// The full signature the selector is hashed over.
    ///
    /// The default is `NAME(comma-joined argument types)`. It is overridable
    /// for the one shape the flat join cannot spell: a call whose arguments
    /// are a Solidity STRUCT, which the ABI renders as a nested tuple —
    /// `exactOutputSingle((address,address,…))`. See [`ExactOutputSingle`].
    fn signature() -> String {
        format!("{}({})", Self::NAME, <Self::Args as AbiTuple>::signature())
    }

    /// The four-byte selector: `keccak256(signature())[..4]`.
    ///
    /// Hashed HERE, in Rust, when the circuit is built — a selector is a
    /// build-time constant, and the artifact only ever sees the immediate.
    /// No `keccak256` instruction is emitted by anything in this module.
    fn selector() -> [u8; 4] {
        let digest = Keccak256::digest(Self::signature().as_bytes());
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// WHAT A SETTLE CIRCUIT IS HANDED once success has been asserted —
    /// the identity by default ([`FromReturn`]), `()` for a call whose
    /// whole return was the flag [`Self::succeeded`] just checked.
    ///
    /// Stable Rust has no associated-type defaults, so every call names it;
    /// it is one line, and it is the line where "does the caller get to see
    /// this?" is answered.
    type Success: FromReturn<<Self::Return as AbiType>::Wire<Private>>;

    /// DID IT WORK? — the predicate [`crate::evm_flow::Pending::complete`]
    /// asserts and [`crate::evm_flow::Pending::refund`] negates, over the
    /// attested return value (notes/evm-calls.org §3.2).
    ///
    /// NO DEFAULT, deliberately. "Executed ⇒ succeeded" is the answer for
    /// most calls and the WRONG one for an ERC-20 `transfer`, which mines
    /// happily and returns `false`; a default would make the dangerous case
    /// the one nobody has to type. So every call type answers, and the two
    /// answers already in the vocabulary are [`always`] (a number came back,
    /// so it executed — the constant-true assert folds away) and
    /// [`is_true`] (the returned flag IS the verdict).
    ///
    /// A call with a business notion of success writes it here — an
    /// ERC-4626 `deposit` that minted zero shares executed perfectly and
    /// achieved nothing:
    ///
    /// ```
    /// # use minocrab::v3::Circuit3;
    /// # use minocrab::Private;
    /// # use minocrab_contracts::evm::{Address, AbiType, EvmCall, U128, U64};
    /// # use minocrab_std::v3::{Check, Uint};
    /// struct StrictDeposit;
    /// impl EvmCall for StrictDeposit {
    ///     const NAME: &'static str = "deposit";
    ///     type Args = (U128, Address);
    ///     type Return = U64;
    ///     type Success = Uint<64, Private>;
    ///     const KIND: u8 = 5;
    ///     const GAS_LIMIT: u64 = 500_000;
    ///
    ///     fn succeeded(_c: &mut Circuit3, shares: &Uint<64, Private>) -> Check<Private> {
    ///         shares.gt(0u64)
    ///     }
    /// }
    /// ```
    ///
    /// The vault's own calls deliberately keep "executed": their deployed
    /// semantics are that, and tightening them is a protocol change rather
    /// than a refactor.
    fn succeeded(
        c: &mut Circuit3,
        output: &<Self::Return as AbiType>::Wire<Private>,
    ) -> Check<Private>;

    /// The projection, applied AFTER [`Self::succeeded`] has been asserted.
    /// The default is [`Self::Success`]'s own [`FromReturn`]; override it
    /// for a projection that needs the circuit (a decode, a range check).
    fn map(
        c: &mut Circuit3,
        output: <Self::Return as AbiType>::Wire<Private>,
    ) -> Self::Success {
        Self::Success::from_return(c, output)
    }
}

/// `transfer(address,uint256) -> bool` — selector `a9059cbb`.
///
/// The vault files this for both a deposit (`CLAIM`) and a withdrawal
/// (`WITHDRAW`); the kind here is `WITHDRAW`, since a call type carries
/// exactly one kind. A second unit type with the same `NAME`/`Args` and
/// `KIND = RESPONSE_KIND_CLAIM` is what the deposit slot needs — rung D's
/// business, recorded in notes/evm-calls.org §9.
pub struct Erc20Transfer;

impl EvmCall for Erc20Transfer {
    const NAME: &'static str = "transfer";
    type Args = (Address, U128);
    type Return = Bool;
    type Success = ();
    const KIND: u8 = RESPONSE_KIND_WITHDRAW as u8;
    const GAS_LIMIT: u64 = ERC20_CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

/// `approve(address,uint256) -> bool` — selector `095ea7b3`.
///
/// The allowance is a [`U256`] (an already-encoded word) because that is
/// what an approval IS in the wild and what the vault passes: the constant
/// unlimited-allowance word, no encoder.
pub struct Erc20Approve;

impl EvmCall for Erc20Approve {
    const NAME: &'static str = "approve";
    type Args = (Address, U256);
    type Return = Bool;
    type Success = ();
    const KIND: u8 = RESPONSE_KIND_APPROVE as u8;
    const GAS_LIMIT: u64 = ERC20_CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

/// Uniswap V3's
/// `exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))`
/// — selector `5023b4df`, seven words:
/// `(tokenIn, tokenOut, fee, recipient, amountOut, amountInMaximum,
/// sqrtPriceLimitX96)`.
///
/// The arguments are a Solidity STRUCT, which the ABI renders as a nested
/// tuple, so this is the one call that overrides [`EvmCall::signature`] to
/// wrap the joined list in a second pair of parentheses. The word ENCODING
/// is unaffected — a static struct is its fields' words, in order, exactly
/// as a flat argument list would be.
pub struct ExactOutputSingle;

impl EvmCall for ExactOutputSingle {
    const NAME: &'static str = "exactOutputSingle";
    type Args = (Address, Address, U24, Address, U128, U128, U160);
    type Return = U64;
    type Success = Uint<64, Private>;
    const KIND: u8 = RESPONSE_KIND_SWAP as u8;
    const GAS_LIMIT: u64 = SWAP_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        // EXECUTED IS SUCCEEDED here: the number IS the outcome, and the
        // constant-true assert this makes is removed by `drop_true_asserts`.
        always(c)
    }

    fn signature() -> String {
        format!("{}(({}))", Self::NAME, <Self::Args as AbiTuple>::signature())
    }
}

/// ERC-4626 `deposit(uint256,address) -> uint256` — selector `6e553f65`,
/// `(assets, receiver)`. The attested share count comes back narrowed to
/// `uint64` ([`U64::RESPOND`]), which is `SUPPLY_RESPOND_SCHEMA`.
pub struct Erc4626Deposit;

impl EvmCall for Erc4626Deposit {
    const NAME: &'static str = "deposit";
    type Args = (U128, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const KIND: u8 = RESPONSE_KIND_SUPPLY as u8;
    const GAS_LIMIT: u64 = LENDING_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        // EXECUTED IS SUCCEEDED here: the number IS the outcome, and the
        // constant-true assert this makes is removed by `drop_true_asserts`.
        always(c)
    }
}

/// ERC-4626 `redeem(uint256,address,address) -> uint256` — selector
/// `ba087652`, `(shares, receiver, owner)`. The attested asset count comes
/// back narrowed to `uint64` (`REDEEM_RESPOND_SCHEMA`).
pub struct Erc4626Redeem;

impl EvmCall for Erc4626Redeem {
    const NAME: &'static str = "redeem";
    type Args = (U128, Address, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const KIND: u8 = RESPONSE_KIND_REDEEM as u8;
    const GAS_LIMIT: u64 = LENDING_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        // EXECUTED IS SUCCEEDED here: the number IS the outcome, and the
        // constant-true assert this makes is removed by `drop_true_asserts`.
        always(c)
    }
}

// ---- did it work? ------------------------------------------------------------

/// A `Check` that is CONSTANTLY TRUE — what [`AbiType::success`] returns for
/// a return type with no failure signal of its own.
///
/// It lowers to `assert` on the IMMEDIATE 1, which
/// `minocrab_ir::v3::passes::drop_true_asserts` removes in
/// `Builder3::finish` (notes/ir-passes.org §11). So "executed is succeeded"
/// costs exactly nothing in the artifact, and it costs it by FOLDING rather
/// than by a branch in this API that an author could take wrongly (dmd,
/// 2026-09-05: *"I'm inclined to just use the fold"*).
pub fn always(c: &mut Circuit3) -> Check<Private> {
    is_true(BoolWire::from_field_unchecked(c.constant(1u64).private()))
}

/// THE PROJECTION [`EvmCall::map`] applies to an attested return value —
/// what a settle circuit is handed once success has been asserted.
///
/// The default is the IDENTITY (the blanket impl below), so a call that
/// wants the number back writes `type Success = Uint<64, Private>` and
/// nothing else. The one other impl is the interesting one: a `Bool` return
/// maps to `()`, because a flag [`EvmCall::succeeded`] has already asserted
/// carries no information a caller could act on, and handing it back is an
/// invitation to re-read it as data (notes/evm-calls.org §3.2, the
/// filter-map).
///
/// A domain projection — an amount into a newtype, a raw word into a
/// decoded value — is an impl of this trait plus an override of
/// [`EvmCall::map`].
pub trait FromReturn<W> {
    /// Build the projection from the attested wire.
    fn from_return(c: &mut Circuit3, w: W) -> Self;
}

/// THE IDENTITY: hand back exactly what the MPC attested.
impl<W> FromReturn<W> for W {
    fn from_return(_c: &mut Circuit3, w: W) -> W {
        w
    }
}

/// A `bool` return that `succeeded` has already asserted says nothing more.
impl<V: Vis3> FromReturn<BoolWire<V>> for () {
    fn from_return(_c: &mut Circuit3, _w: BoolWire<V>) {}
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
    let words: [B32<Private>; WORDS] = match words.try_into() {
        Ok(words) => words,
        // Unreachable: the const assert above pins WORDS to the tuple's
        // count, and `AbiTuple::words` yields exactly that many.
        Err(_) => unreachable!("AbiTuple::words yields <C::Args>::WORDS words"),
    };

    let priority_fee = c.constant(FIXED_PRIORITY_FEE);
    let max_fee = c.constant(FIXED_MAX_FEE);
    let gas_limit = c.constant(C::GAS_LIMIT);

    let zero = c.constant(0u64).private();
    let one = c.constant(1u64).private();
    let no_words = c.constant(WORDS as u64).private();
    let selector = c
        .constant(Fr::from_le_bytes(&C::selector()).expect("four bytes fit a field element"))
        .private();

    EvmTx {
        nonce,
        max_priority_fee_per_gas: priority_fee.private(),
        max_fee_per_gas: max_fee.private(),
        gas_limit: gas_limit.private(),
        to: callee.field(),
        value: zero,
        calldata_is_some: one,
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

    /// The selector signatures, spelled out. `tests/evm_abi.rs` pins the
    /// HASHES against the vault's constants (which the differential suite
    /// pins against compactc's own calldata); this pins the strings that go
    /// into them, where a typo would otherwise only show as four wrong bytes.
    #[test]
    fn signatures_read_as_solidity() {
        assert_eq!(Erc20Transfer::signature(), "transfer(address,uint256)");
        assert_eq!(Erc20Approve::signature(), "approve(address,uint256)");
        assert_eq!(
            ExactOutputSingle::signature(),
            "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        );
        assert_eq!(Erc4626Deposit::signature(), "deposit(uint256,address)");
        assert_eq!(Erc4626Redeem::signature(), "redeem(uint256,address,address)");
    }

    /// The empty argument list is a real one: `f()`, not `f(())`.
    #[test]
    fn the_empty_tuple_signs_as_nothing() {
        struct Noop;
        impl EvmCall for Noop {
            const NAME: &'static str = "noop";
            type Args = ();
            type Return = Bool;
            type Success = ();
            const KIND: u8 = 0;
            const GAS_LIMIT: u64 = 21_000;

            fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
                is_true(*ok)
            }
        }
        assert_eq!(Noop::signature(), "noop()");
        assert_eq!(<() as AbiTuple>::WORDS, 0);
    }

    /// Word counts are arities, all the way to eight.
    #[test]
    fn word_counts_are_arities() {
        assert_eq!(<(Address,) as AbiTuple>::WORDS, 1);
        assert_eq!(<<Erc20Transfer as EvmCall>::Args as AbiTuple>::WORDS, 2);
        assert_eq!(<<Erc4626Redeem as EvmCall>::Args as AbiTuple>::WORDS, 3);
        assert_eq!(<<ExactOutputSingle as EvmCall>::Args as AbiTuple>::WORDS, 7);
        assert_eq!(
            <(Address, Address, Address, Address, Address, Address, Address, Address) as AbiTuple>::WORDS,
            8
        );
    }

    /// The kinds are the vault's, unchanged — so rung D can re-express the
    /// vault's slots without moving a byte of the wire protocol.
    #[test]
    fn kinds_are_the_vaults() {
        assert_eq!(u32::from(Erc20Transfer::KIND), RESPONSE_KIND_WITHDRAW);
        assert_eq!(u32::from(Erc20Approve::KIND), RESPONSE_KIND_APPROVE);
        assert_eq!(u32::from(ExactOutputSingle::KIND), RESPONSE_KIND_SWAP);
        assert_eq!(u32::from(Erc4626Deposit::KIND), RESPONSE_KIND_SUPPLY);
        assert_eq!(u32::from(Erc4626Redeem::KIND), RESPONSE_KIND_REDEEM);
    }

    /// The narrowing the MPC applies, as the schema literals spell it.
    #[test]
    fn respond_spellings_are_the_schemas() {
        assert_eq!(<Erc4626Deposit as EvmCall>::Return::RESPOND, "uint64");
        assert_eq!(<Erc4626Deposit as EvmCall>::Return::SOLIDITY, "uint256");
        assert_eq!(<Erc20Transfer as EvmCall>::Return::RESPOND, "bool");
    }
}
