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
//!    [`Bool`], [`Bytes32`], [`U8`], [`U16`], [`U24`], [`U64`], [`U128`],
//!    [`U160`], [`U256`]), plus [`Unit`] for a callee that returns NOTHING. It
//!    carries the leaf's spelling in a selector signature
//!    ([`AbiType::SOLIDITY`]), its spelling in the attested-output schema
//!    the MPC narrows to ([`AbiType::RESPOND`]) and the CIRCUIT VALUE that
//!    stands for it ([`AbiType::Wire`]). [`AbiArg`] adds the encoder from
//!    that value to a canonical 32-byte ABI word ([`AbiArg::word`]) and is
//!    implemented by every leaf EXCEPT `Unit` — which is how "an argument
//!    that returns nothing" stops being expressible (M38 rung B).
//! 2. [`AbiTuple`] — the argument list, for `()` and 1- to 8-tuples of
//!    `AbiArg`s. It knows the WORD COUNT, the comma-joined signature and
//!    how to encode a tuple of wires into words, in order.
//! 3. [`EvmCall`] — the call: a name, an argument tuple, a return type, the
//!    [`Interface`] that exposes it and a gas limit. [`EvmCall::selector`]
//!    is the first four bytes of `keccak256("name(argtypes)")`, computed IN
//!    RUST at circuit-build time and embedded as an immediate. Nothing
//!    hashes keccak in-circuit; in-circuit hashing stays Poseidon throughout
//!    (dmd, 2026-09-05: *"Do we actually need a const fn Keccak? Why not
//!    just run it when we run the eDSL?"* — we do not). The library's calls
//!    live one module per interface: [`erc20`], [`erc4626`], [`erc721`],
//!    [`uniswap_v3`], [`aave_v3`], [`weth`] and [`usdt`]. [`Payable`] marks
//!    the one that carries ether.
//!
//! Nothing here knows about Signet: how a deployment FILES a call (the output
//! schema the MPC decodes its return under, the fee envelope, the transaction
//! a request files) is the Signet layer's.
//!
//! # Zero movement
//!
//! The two word encoders ([`address_word`], [`numeric_word`]) are the
//! bodies the Signet module ports used to carry, moved here unchanged.
//! `tests/evm_abi.rs` asserts a circuit built through either the untyped
//! encoder or its typed spelling serializes to byte-identical ZKIR.
//!
//! # What does not compile
//!
//! A call type that does not say whether its return means success. There
//! is NO DEFAULT for [`EvmCall::succeeded`], on purpose: "executed ⇒
//! succeeded" is right for most calls and wrong for an ERC-20 `transfer`,
//! and a default would make the dangerous case the one nobody types:
//!
//! ```compile_fail,E0046
//! use minocrab_evm::{erc20, Address, EvmCall, U64};
//! use minocrab_std::Uint;
//! use minocrab::Private;
//!
//! struct Balance;
//! // ERROR: not all trait items implemented, missing: `succeeded`
//! impl EvmCall for Balance {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     type Success = Uint<64, Private>;
//!     const GAS_LIMIT: u64 = 50_000;
//! }
//! ```
//!
//! A [`Unit`] IN AN ARGUMENT TUPLE — "this callee returns nothing" is a
//! RETURN, and it has no ABI word, so it is an [`AbiType`] and not an
//! [`AbiArg`] and a tuple containing it is not an [`AbiTuple`] (M38 rung B;
//! until then this type-checked and reached a build-time panic inside
//! `Unit::word`, notes/evm-calls.org §10 item 3):
//!
//! ```compile_fail,E0277
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{always, erc20, EvmCall, Unit};
//! use minocrab_std::Check;
//!
//! struct Nothing;
//! impl EvmCall for Nothing {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "nothing";
//!     // error[E0277]: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Unit,);
//!     type Return = Unit;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 21_000;
//!     fn succeeded(c: &mut Circuit, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! …and in any position, not just alone — a trailing `Unit` beside real
//! arguments is the shape a "this one returns nothing" note would take if
//! it were written in the wrong place:
//!
//! ```compile_fail,E0277
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{always, erc20, Address, EvmCall, Unit};
//! use minocrab_std::Check;
//!
//! struct Nothing;
//! impl EvmCall for Nothing {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "nothing";
//!     // error[E0277]: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Address, Unit);
//!     type Return = Unit;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 21_000;
//!     fn succeeded(c: &mut Circuit, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE `Unit` LEFT IN THE ONE PLACE IT BELONGS compiles
//! — as the RETURN, which is what a call to a callee that answers nothing
//! actually has (ERC-2612 `permit`, WETH `deposit`, a USDT `transfer`):
//!
//! ```
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{always, erc20, Address, EvmCall, Unit};
//! use minocrab_std::Check;
//!
//! struct Nothing;
//! impl EvmCall for Nothing {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "nothing";
//!     type Args = (Address,);
//!     type Return = Unit;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 21_000;
//!     fn succeeded(c: &mut Circuit, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Nothing::signature(), "nothing(address)");
//! ```
//!
//! A projection the return value cannot produce — `()` is [`FromReturn`]
//! for a `Bool` return and for nothing else, so a numeric call cannot
//! quietly throw its answer away:
//!
//! ```compile_fail,E0277
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{always, erc20, Address, EvmCall, U64};
//! use minocrab_std::{Check, Uint};
//!
//! struct Balance;
//! impl EvmCall for Balance {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     // ERROR: the trait bound `(): FromReturn<Uint<64>>` is not satisfied
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles, so each rejection
//! above is the missing item and the mapping rather than a typo:
//!
//! ```
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{always, erc20, Address, EvmCall, U64};
//! use minocrab_std::{Check, Uint};
//!
//! struct Balance;
//! impl EvmCall for Balance {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "balanceOf";
//!     type Args = (Address,);
//!     type Return = U64;
//!     type Success = Uint<64, Private>;
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Balance::signature(), "balanceOf(address)");
//! assert_eq!(Balance::selector(), [0x70, 0xa0, 0x82, 0x31]);
//! ```
//!
//! A `Unit` IN AN ARGUMENT TUPLE. [`Unit`] is the leaf that means "this
//! callee returns NOTHING"; an argument that is nothing has no 32-byte word
//! to encode, so it is an [`AbiType`] and not an [`AbiArg`], and
//! [`AbiTuple`] is over `AbiArg`:
//!
//! ```compile_fail,E0277
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{erc20, Address, Bool, EvmCall, Unit};
//! use minocrab_std::{is_true, Bool as BoolWire, Check};
//!
//! struct Poke;
//! impl EvmCall for Poke {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "poke";
//!     // ERROR: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Address, Unit);
//!     type Return = Bool;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(_c: &mut Circuit, ok: &BoolWire<Private>) -> Check<Private> {
//!         is_true(*ok)
//!     }
//! }
//! ```
//!
//! …and alone, where the tuple is nothing else:
//!
//! ```compile_fail,E0277
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{erc20, Bool, EvmCall, Unit};
//! use minocrab_std::{is_true, Bool as BoolWire, Check};
//!
//! struct Poke;
//! impl EvmCall for Poke {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "poke";
//!     // ERROR: the trait bound `Unit: AbiArg` is not satisfied
//!     type Args = (Unit,);
//!     type Return = Bool;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(_c: &mut Circuit, ok: &BoolWire<Private>) -> Check<Private> {
//!         is_true(*ok)
//!     }
//! }
//! ```
//!
//! THE SAME CODE WITH THE ONE CHANGE REVERTED compiles — and `Unit` in the
//! position it IS for, the RETURN, compiles beside it. That pair is the
//! whole of the split: one leaf, legal in one position and rejected in the
//! other, with no runtime check anywhere:
//!
//! ```
//! use minocrab::Circuit;
//! use minocrab::Private;
//! use minocrab_evm::{always, erc20, Address, Bool, EvmCall, Unit};
//! use minocrab_std::{is_true, Bool as BoolWire, Check};
//!
//! struct Poke;
//! impl EvmCall for Poke {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "poke";
//!     type Args = (Address,);
//!     type Return = Bool;
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(_c: &mut Circuit, ok: &BoolWire<Private>) -> Check<Private> {
//!         is_true(*ok)
//!     }
//! }
//!
//! struct Shout;
//! impl EvmCall for Shout {
//!     type Callee = erc20::Erc20;
//!     const NAME: &'static str = "shout";
//!     type Args = (Address,);
//!     type Return = Unit;               // the position `Unit` is FOR
//!     type Success = ();
//!     const GAS_LIMIT: u64 = 50_000;
//!     fn succeeded(c: &mut Circuit, _out: &()) -> Check<Private> {
//!         always(c)
//!     }
//! }
//! assert_eq!(Shout::signature(), "shout(address)");
//! ```

use minocrab::{Circuit, FieldT, Wire};
use minocrab::Private;
use minocrab_std::{
    is_true, pow2_const, Bool as BoolWire, Bytes, Bytes0, Check, CircuitArg, Uint, Vis, B32,
};
use sha3::{Digest as _, Keccak256};

pub mod aave_v3;
pub mod erc20;
pub mod erc4626;
pub mod erc721;
pub mod uniswap_v3;
pub mod usdt;
pub mod weth;

// ---- the encoders --------------------------------------------------------------

/// `evmAddressAbiWord(addr)` — 12 zero bytes then the 20 display-order
/// address bytes. `addr` is the `Bytes<20>` single limb.
///
/// The untyped-limb encoder; [`Address::word`] is the typed spelling, and
/// the Signet module ports name this one `evm_address_abi_word`.
/// Byte-for-byte the same instructions in all of them.
pub fn address_word<V: Vis>(c: &mut Circuit, addr: Wire<FieldT, V>) -> B32<V> {
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
/// The untyped-limb encoder, as [`address_word`] is. The typed spellings are [`Bool::word`], [`U24::word`], [`U64::word`] and
/// [`U128::word`], which differ only in the RANGE their wire type claims:
/// the encoding is the same reversal for all of them, and correct for any
/// limb below `2^248`.
pub fn numeric_word<V: Vis>(c: &mut Circuit, value: Wire<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // value's 16 LE bytes sit at string positions 0..15 of
        // `B32 { lo: value, hi: 0 }`; the native reversal moves them,
        // reversed, to positions 16..31 — exactly the BE ABI rendering.
        let zero = V::from_public(c.constant(0u64));
        let padded = B32 { hi: zero, lo: value };
        reverse_bytes32(c, &padded)
    })
}

/// `reverseBytes32(b)` — byte-order adapter (stored records and ABI words
/// are big-endian, the scalar casts read little-endian). ZKIR's native
/// `Reverse` instruction (~150 rows) replaces the Compact stdlib's
/// explode/rebuild chain (~4600 rows, what compactc emits).
pub fn reverse_bytes32<V: Vis>(c: &mut Circuit, b: &B32<V>) -> B32<V> {
    let typed = b.to_typed(c);
    let rev = c.reverse_bytes(typed);
    B32::from_typed(c, rev)
}

/// `checkedTruncationU128(x: Bytes<32>): Uint<128>` — an attested uint256
/// (32 little-endian bytes) narrowed to `Uint<128>`: byte 31 must be zero
/// (the source's "seems pointless but is important" check — without it the
/// `as Uint<128>` cast of a 32-byte string reads a value mod the field),
/// then the low 31 bytes are range-checked to 128 bits.
pub fn checked_truncation_u128<V: Vis>(c: &mut Circuit, x: &B32<V>) -> Uint<128, V> {
    let zero = V::from_public(c.constant(0u64));
    let top_zero = c.test_eq(x.hi, zero);
    c.assert_with(top_zero, Some("Value exceeds Uint<128>"));
    Uint::<128, V>::from_field_checked(c, x.lo)
}

// ---- the ABI type layer ------------------------------------------------------

/// One Solidity leaf: how it is SPELLED and what CIRCUIT VALUE stands for
/// it.
///
/// The implementors are unit types ([`Address`], [`Bool`], …), never
/// instantiated: they exist to be named in an [`EvmCall::Args`] tuple or as
/// an [`EvmCall::Return`].
///
/// THE WORD IS NOT HERE. Encoding a value into a 32-byte ABI word is
/// [`AbiArg`]'s, because the one leaf that is a return and not an argument
/// — [`Unit`], "this callee returns nothing" — has no word to encode.
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
    type Wire<V: Vis>;
}

/// A LEAF THAT CAN STAND IN AN ARGUMENT LIST — an [`AbiType`] that HAS an
/// ABI word, which is every one of them except [`Unit`].
///
/// THE ARGS/RETURN SPLIT (M38 rung B). [`AbiType`] is the RETURN position's
/// bound: a call may return a `bool`, a number, or NOTHING AT ALL, and
/// [`Unit`] is that nothing. This trait is the ARGUMENT position's: an
/// argument is a value that becomes a 32-byte word, and `Unit` has no word
/// to become. So [`AbiTuple`] is over `AbiArg` and `Unit` has no impl,
/// which makes `type Args = (Unit,)` a MISSING TRAIT IMPL —
/// `error[E0277]`, the first rung of the project's ladder — where until
/// this rung it type-checked and reached a build-time panic inside
/// `Unit::word` (notes/evm-calls.org §10 item 3, recorded for dmd).
///
/// The encoder lives here rather than on [`AbiType`] so that `Unit` does
/// not implement it at all: there is no unreachable body and no panic to
/// keep prescriptive.
pub trait AbiArg: AbiType {
    /// The canonical big-endian ABI word for a value of this leaf.
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V>;
}

/// Solidity `address` — a `Bytes<20>` limb, left-padded into the word.
pub struct Address;

impl AbiType for Address {
    const SOLIDITY: &'static str = "address";
    const RESPOND: &'static str = "address";
    type Wire<V: Vis> = Bytes<20, V>;
}

impl AbiArg for Address {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
        address_word(c, w.field())
    }
}

/// Solidity `bool` — 0 or 1 right-aligned in the word.
pub struct Bool;

impl AbiType for Bool {
    const SOLIDITY: &'static str = "bool";
    const RESPOND: &'static str = "bool";
    type Wire<V: Vis> = BoolWire<V>;
}

impl AbiArg for Bool {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `bytes32` — the word IS the value; encoding it is the identity
/// and emits no instruction.
pub struct Bytes32;

impl AbiType for Bytes32 {
    const SOLIDITY: &'static str = "bytes32";
    const RESPOND: &'static str = "bytes32";
    type Wire<V: Vis> = B32<V>;
}

impl AbiArg for Bytes32 {
    fn word<V: Vis>(_c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
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
/// `Wire<V> = ()`: no slot, no word, no verdict to read. A call returning
/// it writes [`always`] for its [`EvmCall::succeeded`], because for a call
/// with nothing to say, executing IS succeeding and there is no flag to be
/// fooled by.
///
/// A RETURN TYPE ONLY, and the type system says so: `Unit` is an
/// [`AbiType`] and NOT an [`AbiArg`], so it can be named as an
/// [`EvmCall::Return`] and cannot be named in an [`EvmCall::Args`] tuple.
///
/// `type Args = (Unit,)` is `error[E0277]` — "the trait bound `Unit:
/// AbiArg` is not satisfied" (the module docs carry the gate). Until M38
/// rung B it type-checked and put a build-time panic inside `Unit::word`
/// where the hard rule prefers a compile error — notes/evm-calls.org §10
/// item 3, recorded for dmd and now closed.
pub struct Unit;

impl AbiType for Unit {
    const SOLIDITY: &'static str = "";
    const RESPOND: &'static str = "";
    type Wire<V: Vis> = ();
}

/// Solidity `uint8` — ERC-2612 `permit`'s signature parity byte `v`, the
/// narrowest integer the library passes.
///
/// The encoding is [`numeric_word`], exactly as [`U24`] and [`U64`]: a
/// 32-byte word is a 32-byte word, and the Rust type states the RANGE the
/// wire claims (`Uint<8>`) rather than a different encoder.
pub struct U8;

impl AbiType for U8 {
    const SOLIDITY: &'static str = "uint8";
    const RESPOND: &'static str = "uint8";
    type Wire<V: Vis> = Uint<8, V>;
}

impl AbiArg for U8 {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint16` — Aave v3's `referralCode`, the argument every one of
/// its Pool functions carries and every caller passes zero for.
///
/// The encoding is [`numeric_word`], exactly as [`U8`] and [`U24`]: the
/// three differ only in the RANGE the Rust type claims and in the spelling
/// that goes into the selector — and the spelling is the whole point,
/// because `supply(address,uint256,address,uint16)` and
/// `supply(address,uint256,address,uint256)` are different functions.
pub struct U16;

impl AbiType for U16 {
    const SOLIDITY: &'static str = "uint16";
    const RESPOND: &'static str = "uint16";
    type Wire<V: Vis> = Uint<16, V>;
}

impl AbiArg for U16 {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
        numeric_word(c, w.field())
    }
}

/// Solidity `uint24` — Uniswap's pool fee tier, the one sub-word integer
/// the corpus actually passes (`SwapRequest::fee`).
pub struct U24;

impl AbiType for U24 {
    const SOLIDITY: &'static str = "uint24";
    const RESPOND: &'static str = "uint24";
    type Wire<V: Vis> = Uint<24, V>;
}

impl AbiArg for U24 {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
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
    type Wire<V: Vis> = Uint<64, V>;
}

impl AbiArg for U64 {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
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
    type Wire<V: Vis> = Uint<128, V>;
}

impl AbiArg for U128 {
    fn word<V: Vis>(c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
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
    type Wire<V: Vis> = B32<V>;
}

impl AbiArg for U160 {
    fn word<V: Vis>(_c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
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
    type Wire<V: Vis> = B32<V>;
}

impl AbiArg for U256 {
    fn word<V: Vis>(_c: &mut Circuit, w: &Self::Wire<V>) -> B32<V> {
        *w
    }
}

// ---- the attested return -----------------------------------------------------

/// WHAT THE MPC ATTESTS FOR A RETURN TYPE — `serializedOutput`: its byte
/// width, its circuit shape, and how a circuit reads the ABI value back out
/// of it (M44 rung D).
///
/// A V1 attestation signs the output as BYTES at a width the digest commits
/// to (`signet_v1::calculate_attestation_digest_v1`), not as a decoded
/// value: the MPC decodes the EVM return under the record's
/// `outputDeserializationSchema`, re-serializes it with Borsh and signs
/// `[tag, requestId, blockHeight, outputKind, LEN, output]`. So a settle
/// circuit takes the BYTES and narrows them itself, which is where the
/// `Bytes<32> as Uint<128>` hazard lives (bug report 4) — and why the
/// narrowing is written ONCE, here, rather than per settle circuit:
///
/// - a `bool` is one byte that must be 0 or 1, and "true" is `byte == 1`,
///   as compactc 0.36 lowers `deserialize<_, 1>(output).success`;
/// - a `uint256` is 32 little-endian bytes, narrowed by
///   [`checked_truncation_u128`], whose byte-31 check is what
///   stops a 32-byte string being read modulo the field;
/// - nothing at all is [`Bytes0`] — no slot, no limb, and the verdict
///   (`signet_v1::output_kind`) is the whole answer.
///
/// SEPARATE FROM [`AbiArg`] in both directions. An argument has a word and
/// may have no attested form ([`Address`] is never a return in the
/// library); a return has an attested form and may have no word
/// ([`Unit`]). A return type with no impl here cannot be named by a slot at
/// all — the missing impl is the rejection, so a call whose attested
/// narrowing nobody has written down does not compile into a `Pending`.
pub trait AbiReturn: AbiType {
    /// `serializedOutput`'s byte width — the `LEN` the attestation digest
    /// commits to.
    const LEN: usize;

    /// The serialized output as a circuit value. Private: it arrives on a
    /// settle ticket.
    type Serialized: CircuitArg + Copy;

    /// Its FAB limbs, in slot order — the tail of the signed preimage.
    fn limbs(out: &Self::Serialized) -> Vec<Wire<FieldT, Private>>;

    /// The decoded value an [`EvmCall::succeeded`] predicate reads, with
    /// whatever range check the narrowing owes.
    fn decode(c: &mut Circuit, out: &Self::Serialized) -> Self::Wire<Private>;
}

/// Nothing attested: zero bytes, zero limbs, nothing to decode.
impl AbiReturn for Unit {
    const LEN: usize = 0;
    type Serialized = Bytes0<Private>;

    fn limbs(_out: &Bytes0<Private>) -> Vec<Wire<FieldT, Private>> {
        Vec::new()
    }

    fn decode(_c: &mut Circuit, _out: &Bytes0<Private>) {}
}

/// A Borsh `bool`: one byte, which must be 0 or 1, true iff it is `1`.
///
/// compactc 0.36 lowers `deserialize<VaultResponse, 1>(output).success` to
/// `constrain_to_boolean` on the byte, then `byte == 1`, so a byte of 2 is a
/// proof failure, not FALSE; this lineage says the same thing.
impl AbiReturn for Bool {
    const LEN: usize = 1;
    type Serialized = Bytes<1, Private>;

    fn limbs(out: &Bytes<1, Private>) -> Vec<Wire<FieldT, Private>> {
        vec![out.field()]
    }

    fn decode(c: &mut Circuit, out: &Bytes<1, Private>) -> BoolWire<Private> {
        let byte = c.assert_boolean(out.field());
        let one = c.constant(1u64).private();
        BoolWire::from_field_unchecked(c.test_eq(byte, one))
    }
}

/// A Borsh `uint256` narrowed to a `Uint<64>` — the width a shielded mint
/// takes, so the narrowing is TWO checks: byte 31 zero and the low 31 bytes
/// under 2^128 ([`checked_truncation_u128`]), then the 64-bit
/// range check the deployed source's `as Uint<64>` emits.
impl AbiReturn for U64 {
    const LEN: usize = 32;
    type Serialized = B32<Private>;

    fn limbs(out: &B32<Private>) -> Vec<Wire<FieldT, Private>> {
        vec![out.hi, out.lo]
    }

    fn decode(c: &mut Circuit, out: &B32<Private>) -> Uint<64, Private> {
        let narrowed = checked_truncation_u128(c, out);
        Uint::<64, Private>::from_field_checked(c, narrowed.field())
    }
}

/// A Borsh `uint256` narrowed to a `Uint<128>` — one
/// [`checked_truncation_u128`] and no more.
impl AbiReturn for U128 {
    const LEN: usize = 32;
    type Serialized = B32<Private>;

    fn limbs(out: &B32<Private>) -> Vec<Wire<FieldT, Private>> {
        vec![out.hi, out.lo]
    }

    fn decode(c: &mut Circuit, out: &B32<Private>) -> Uint<128, Private> {
        checked_truncation_u128(c, out)
    }
}

/// A Borsh `uint256` AT ITS FULL WIDTH — the 32 bytes unnarrowed, for a
/// settle that compares them rather than counting with them. No check is
/// owed because nothing is cast.
impl AbiReturn for U256 {
    const LEN: usize = 32;
    type Serialized = B32<Private>;

    fn limbs(out: &B32<Private>) -> Vec<Wire<FieldT, Private>> {
        vec![out.hi, out.lo]
    }

    fn decode(_c: &mut Circuit, out: &B32<Private>) -> B32<Private> {
        *out
    }
}

// ---- the argument list -------------------------------------------------------

/// An [`EvmCall`]'s argument list: `()` or a 1- to 8-tuple of [`AbiArg`]s.
///
/// [`AbiArg`] and not [`AbiType`]: [`Unit`] is a return and not an
/// argument, so a tuple containing it has no `AbiTuple` impl.
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
    type Wires<V: Vis>;

    /// The comma-joined [`AbiType::SOLIDITY`] spellings — the inside of the
    /// selector signature's parentheses. Built at CIRCUIT-BUILD TIME, in
    /// Rust, like the keccak that consumes it.
    fn signature() -> String;

    /// The words, in argument order. The length is always [`Self::WORDS`].
    fn words<V: Vis>(c: &mut Circuit, wires: Self::Wires<V>) -> Vec<B32<V>>;
}

impl AbiTuple for () {
    const WORDS: usize = 0;
    type Wires<V: Vis> = ();

    fn signature() -> String {
        String::new()
    }

    fn words<V: Vis>(_c: &mut Circuit, _wires: ()) -> Vec<B32<V>> {
        Vec::new()
    }
}

macro_rules! abi_tuple {
    ($n:literal; $($t:ident => $idx:tt),+) => {
        impl<$($t: AbiArg),+> AbiTuple for ($($t,)+) {
            const WORDS: usize = $n;
            type Wires<V: Vis> = ($(<$t as AbiType>::Wire<V>,)+);

            fn signature() -> String {
                [$(<$t as AbiType>::SOLIDITY),+].join(",")
            }

            fn words<V: Vis>(c: &mut Circuit, wires: Self::Wires<V>) -> Vec<B32<V>> {
                // Left to right, which is argument order, which is word order.
                vec![$(<$t as AbiArg>::word(c, &wires.$idx)),+]
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

// ---- the arguments, built one at a time ---------------------------------------

/// THE ARGUMENTS OF A CALL, BUILT ONE AT A TIME — a tuple of closures, one
/// per element of [`EvmCall::Args`], each run immediately before its own word
/// is encoded.
///
/// [`AbiTuple::words`] takes the VALUES, which means every argument exists
/// before the first encoder runs. That is the right shape for a caller whose
/// arguments are already in hand, and the wrong one for a caller whose second
/// argument comes from a ledger read: the read would emit before the first
/// argument's word instead of between the two, and the deployed lineages'
/// instruction streams have it between (the vault's `supply` reads
/// `vaultEvmAddress` after encoding `amount`, and `approveStata` builds its
/// constant allowance word after encoding the spender). So
/// `evm_flow::Pending::request_with` takes BUILDERS, and the order
/// they emit in is the order the words come out.
///
/// ```
/// # use minocrab::{Circuit, FieldT};
/// # use minocrab::Private;
/// # use minocrab_evm::{AbiArgs, Address, U128};
/// # use minocrab_std::{Bytes, Uint};
/// let mut c = Circuit::new();
/// let to = Bytes::<20, Private>::from_field_unchecked(c.arg::<FieldT>("to"));
/// let amount = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("amount"));
/// let words = AbiArgs::<(Address, U128)>::words(
///     (|_c: &mut Circuit| to, |_c: &mut Circuit| amount),
///     &mut c,
/// );
/// assert_eq!(words.len(), 2);
/// ```
pub trait AbiArgs<T: AbiTuple> {
    /// The words, in argument order, each argument built just before it is
    /// encoded. The length is always `T::WORDS`.
    fn words(self, c: &mut Circuit) -> Vec<B32<Private>>;
}

impl AbiArgs<()> for () {
    fn words(self, _c: &mut Circuit) -> Vec<B32<Private>> {
        Vec::new()
    }
}

macro_rules! abi_args {
    ($($t:ident / $f:ident => $idx:tt),+) => {
        impl<$($t: AbiArg,)+ $($f: FnOnce(&mut Circuit) -> <$t as AbiType>::Wire<Private>,)+>
            AbiArgs<($($t,)+)> for ($($f,)+)
        {
            fn words(self, c: &mut Circuit) -> Vec<B32<Private>> {
                // Build, encode, move on: the emission order a request
                // circuit's ledger reads interleave with.
                vec![$({
                    let w = (self.$idx)(c);
                    <$t as AbiArg>::word(c, &w)
                }),+]
            }
        }
    };
}

abi_args!(A / FA => 0);
abi_args!(A / FA => 0, B / FB => 1);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4);
abi_args!(A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4, F / FF => 5);
abi_args!(
    A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4, F / FF => 5, G / FG => 6
);
abi_args!(
    A / FA => 0, B / FB => 1, C / FC => 2, D / FD => 3, E / FE => 4, F / FF => 5, G / FG => 6,
    H / FH => 7
);

// ---- the callee's interface --------------------------------------------------

/// A CALLEE INTERFACE: a set of functions an EVM contract claims to expose.
///
/// It is what a `Contract<I>` is typed by, and
/// what [`EvmCall::Callee`] names. The library's own set is
/// [`erc20::Erc20`], [`erc4626::Erc4626`] and
/// [`uniswap_v3::UniswapV3Router`] today (`Weth`, `AaveV3Pool`, `Erc721`,
/// `UsdtLike` in rungs B and C); the trait is OPEN, so a contract calling a
/// deployment of its own declares a marker in one line:
///
/// ```
/// use minocrab_evm::Interface;
///
/// /// The MPC's integration target.
/// pub struct SignetEvmTarget;
/// impl Interface for SignetEvmTarget {}
/// ```
///
/// `'static` because a marker is a unit type and the
/// `Contract` built over it lives in a `const`
/// ledger block.
pub trait Interface: 'static {}

/// INTERFACE INHERITANCE: `I: Extends<Base>` says a `Contract<I>` may be
/// handed a `Base` call.
///
/// Reflexive by the blanket impl below, so an interface always takes its own
/// calls and the common case needs no impl at all. The one inheritance rung
/// A carries is the real one: an ERC-4626 vault IS an ERC-20 (its shares are
/// a token), so `impl Extends<Erc20> for Erc4626` is what lets the deployed
/// vault's `approve_stata` file an [`erc20::Approve`] against its
/// `Contract<Erc4626>` stata-token cell.
///
/// COHERENCE: a downstream crate may write `impl Extends<Erc20> for MyToken`
/// for its OWN marker, and may not write `impl Extends<Erc20> for Erc4626`
/// (the orphan rule). The library decides its own inheritance, which is
/// right — inheritance here is a claim about a deployed contract's ABI.
pub trait Extends<Base: Interface>: Interface {}

/// Every interface takes its own calls.
impl<I: Interface> Extends<I> for I {}

// ---- the call ----------------------------------------------------------------

/// A named EVM function call: what it is called, what it takes, what it
/// returns, WHICH INTERFACE EXPOSES IT and what it may spend.
///
/// Everything else — the selector, the word count, the response type, the
/// schema spellings — is DERIVED from these, which is the whole point
/// (notes/evm-calls.org §2).
///
/// WHAT IS NOT HERE, since M38 rung A: the OUTPUT SCHEMA the MPC decodes the
/// return under, and with it the deployed record's name for the attested
/// value. Neither is a fact about the Solidity function — the same
/// `transfer` is decoded for its flag by a vault and left undecoded by a
/// protocol that wants only the verdict — so both live on the SLOT's
/// `Filing` (notes/evm-interfaces.org §1).
pub trait EvmCall {
    /// THE INTERFACE THAT EXPOSES THIS FUNCTION.
    ///
    /// A call may be filed only against a `Contract<I>` whose `I`
    /// [`Extends`] this — so a `transfer` cannot be sent to a
    /// [`uniswap_v3::UniswapV3Router`], and an [`erc20::Approve`] can be
    /// sent to an [`erc4626::Erc4626`], which is the deployed vault's stata
    /// token.
    type Callee: Interface;

    /// The Solidity function name, without parentheses.
    const NAME: &'static str;

    /// The argument list.
    type Args: AbiTuple;

    /// The attested return value. `Attested<Return::Wire>`, decoded under
    /// the slot's `Filing::Schema`, is the response a settle circuit
    /// consumes.
    type Return: AbiType;

    /// The gas LIMIT (not a price; the fee envelope is `build_tx`'s).
    ///
    /// A PER-FUNCTION DEFAULT — a `transfer` costs what a transfer costs —
    /// which is why it stayed here when the kind left (§2.3). The library's
    /// values ARE the deployed vault's: [`erc20::CALL_GAS`],
    /// [`erc4626::CALL_GAS`], [`uniswap_v3::SWAP_GAS`]. A deployment that
    /// needs another limit passes `Envelope::caller` today.
    const GAS_LIMIT: u64;

    /// The full signature the selector is hashed over.
    ///
    /// The default is `NAME(comma-joined argument types)`. It is overridable
    /// for the one shape the flat join cannot spell: a call whose arguments
    /// are a Solidity STRUCT, which the ABI renders as a nested tuple —
    /// `exactOutputSingle((address,address,…))`. See
    /// [`uniswap_v3::ExactOutputSingle`].
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

    /// DID IT WORK? — the predicate `evm_flow::Pending::complete`
    /// asserts and `evm_flow::Pending::refund` negates, over the
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
    /// # use minocrab::Circuit;
    /// # use minocrab::Private;
    /// # use minocrab_evm::{erc4626, Address, AbiType, EvmCall, U128, U64};
    /// # use minocrab_std::{Check, Uint};
    /// struct StrictDeposit;
    /// impl EvmCall for StrictDeposit {
    ///     type Callee = erc4626::Erc4626;
    ///     const NAME: &'static str = "deposit";
    ///     type Args = (U128, Address);
    ///     type Return = U64;
    ///     type Success = Uint<64, Private>;
    ///     const GAS_LIMIT: u64 = 500_000;
    ///
    ///     fn succeeded(_c: &mut Circuit, shares: &Uint<64, Private>) -> Check<Private> {
    ///         shares.gt(0u64)
    ///     }
    /// }
    /// ```
    ///
    /// The vault's own calls deliberately keep "executed": their deployed
    /// semantics are that, and tightening them is a protocol change rather
    /// than a refactor.
    fn succeeded(
        c: &mut Circuit,
        output: &<Self::Return as AbiType>::Wire<Private>,
    ) -> Check<Private>;

    /// The projection, applied AFTER [`Self::succeeded`] has been asserted.
    /// The default is [`Self::Success`]'s own [`FromReturn`]; override it
    /// for a projection that needs the circuit (a decode, a range check).
    fn map(
        c: &mut Circuit,
        output: <Self::Return as AbiType>::Wire<Private>,
    ) -> Self::Success {
        Self::Success::from_return(c, output)
    }
}

// ---- ether ---------------------------------------------------------------------

/// A PAYABLE FUNCTION — one that may be called WITH ETHER ATTACHED.
///
/// Every other call this library builds fixes the transaction's `value`
/// field at zero: a token call moves tokens, not ether. WETH's `deposit()`
/// is the exception — the ether IS the argument, and a `deposit` with
/// `value = 0` wraps nothing.
///
/// A MARKER, not a field, because that is the top rung of the project's
/// ladder (CLAUDE.md: missing impl > distinct types > inline-const assert >
/// panic). `build_tx_payable` and
/// `Pending::request_payable`
/// are the only ways to put a non-zero `value` on the wire and both are
/// bounded by this trait, so handing ether to an [`erc20::Transfer`] is
/// `error[E0277]` — "the trait bound `Transfer: Payable` is not satisfied"
/// — rather than an amount that silently goes nowhere. Nothing about a non-payable call changes: it has
/// no impl, no extra field and no extra instruction.
///
/// The converse is NOT enforced and is not a mistake: a payable call may be
/// made through the ordinary `build_tx`, which is a call with no ether —
/// which is what Solidity means by payable.
pub trait Payable: EvmCall {}

// ---- did it work? ------------------------------------------------------------

/// A `Check` that is CONSTANTLY TRUE — the [`EvmCall::succeeded`] of a call
/// whose return carries no failure signal of its own.
///
/// It lowers to `assert` on the IMMEDIATE 1, which
/// `minocrab_ir::passes::drop_true_asserts` removes in
/// `Builder::finish` (notes/ir-passes.org §11). So "executed is succeeded"
/// costs exactly nothing in the artifact, and it costs it by FOLDING rather
/// than by a branch in this API that an author could take wrongly (dmd,
/// 2026-09-05: *"I'm inclined to just use the fold"*).
pub fn always(c: &mut Circuit) -> Check<Private> {
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
    fn from_return(c: &mut Circuit, w: W) -> Self;
}

/// THE IDENTITY: hand back exactly what the MPC attested.
impl<W> FromReturn<W> for W {
    fn from_return(_c: &mut Circuit, w: W) -> W {
        w
    }
}

/// A `bool` return that `succeeded` has already asserted says nothing more.
impl<V: Vis> FromReturn<BoolWire<V>> for () {
    fn from_return(_c: &mut Circuit, _w: BoolWire<V>) {}
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
        assert_eq!(erc20::Transfer::signature(), "transfer(address,uint256)");
        assert_eq!(erc20::Approve::signature(), "approve(address,uint256)");
        assert_eq!(
            uniswap_v3::ExactOutputSingle::signature(),
            "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
        );
        assert_eq!(erc4626::Deposit::signature(), "deposit(uint256,address)");
        assert_eq!(erc4626::Redeem::signature(), "redeem(uint256,address,address)");
    }

    /// The empty argument list is a real one: `f()`, not `f(())`.
    #[test]
    fn the_empty_tuple_signs_as_nothing() {
        struct Noop;
        impl EvmCall for Noop {
            type Callee = erc20::Erc20;
            const NAME: &'static str = "noop";
            type Args = ();
            type Return = Bool;
            type Success = ();
            const GAS_LIMIT: u64 = 21_000;

            fn succeeded(_c: &mut Circuit, ok: &BoolWire<Private>) -> Check<Private> {
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
        assert_eq!(<<erc20::Transfer as EvmCall>::Args as AbiTuple>::WORDS, 2);
        assert_eq!(<<erc4626::Redeem as EvmCall>::Args as AbiTuple>::WORDS, 3);
        assert_eq!(
            <<uniswap_v3::ExactOutputSingle as EvmCall>::Args as AbiTuple>::WORDS,
            7
        );
        assert_eq!(
            <(Address, Address, Address, Address, Address, Address, Address, Address) as AbiTuple>::WORDS,
            8
        );
    }

    /// THE GAS DEFAULTS ARE THE DEPLOYED VAULT'S, re-homed (§2.3): the
    /// numbers moved into this library and the vault's own constants are
    /// aliases of them, so no request circuit's gas immediate can move.
    #[test]
    fn the_gas_defaults_are_the_vaults() {
        use super::{erc20::CALL_GAS as ERC20_CALL_GAS, erc4626::CALL_GAS as LENDING_GAS, uniswap_v3::SWAP_GAS};

        assert_eq!(erc20::Transfer::GAS_LIMIT, ERC20_CALL_GAS);
        assert_eq!(erc20::Approve::GAS_LIMIT, ERC20_CALL_GAS);
        assert_eq!(uniswap_v3::ExactOutputSingle::GAS_LIMIT, SWAP_GAS);
        assert_eq!(erc4626::Deposit::GAS_LIMIT, LENDING_GAS);
        assert_eq!(erc4626::Redeem::GAS_LIMIT, LENDING_GAS);
    }


    /// THE ATTESTED WIDTHS: what the MPC's Borsh of each return type takes,
    /// which is the `LEN` inside the attestation digest and therefore the
    /// width a settle circuit must verify at.
    #[test]
    fn the_attested_widths_are_the_borsh_widths() {
        assert_eq!(<Unit as AbiReturn>::LEN, 0);
        assert_eq!(<Bool as AbiReturn>::LEN, 1);
        assert_eq!(<U64 as AbiReturn>::LEN, 32);
        assert_eq!(<U128 as AbiReturn>::LEN, 32);
        assert_eq!(<U256 as AbiReturn>::LEN, 32);
    }

    /// The narrowing the MPC applies, as the schema literals spell it.
    #[test]
    fn respond_spellings_are_the_schemas() {
        assert_eq!(<erc4626::Deposit as EvmCall>::Return::RESPOND, "uint64");
        assert_eq!(<erc4626::Deposit as EvmCall>::Return::SOLIDITY, "uint256");
        assert_eq!(<erc20::Transfer as EvmCall>::Return::RESPOND, "bool");
    }
}
