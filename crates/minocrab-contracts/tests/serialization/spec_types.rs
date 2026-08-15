//! The SPEC TYPES: plain Rust declarations of the payloads the DEPLOYED
//! protocol already puts on the wire (M11 stage 0, notes/borsh-format.org).
//!
//! Nothing here is a circuit, and nothing here is an encoder. Each type is a
//! declaration of a byte layout — canonical Borsh restricted to the
//! fixed-width subset the design of record specifies — expressed once and
//! handed to TWO independent oracles:
//!
//! - `#[derive(BorshSerialize)]`, and
//! - `#[derive(serde::Serialize)]` + bincode's fixint/little-endian config.
//!
//! The conformance suite asserts the two agree with each other and with the
//! bytes the deployed circuits hash and log. Between them, the oracle
//! equality and the fixed-width property are the subset checker: a Rust
//! enum and a `Vec` make the two ENCODERS disagree, and an `Option` — which
//! both encoders spell identically — makes the WIDTH value-dependent. All
//! three are pinned as negative controls in `serialization_conformance.rs`'s
//! `subset_boundary` module, so the suite can never be vacuous.
//!
//! Deliberately NOT here: any `Vec`, `String`, `Option` or data-carrying
//! enum. Compact's `Maybe` is [`Flagged`] — a 1-byte tag with an
//! ALWAYS-PRESENT payload — never `Option`, whose Borsh encoding omits the
//! payload on `None` and so has data-dependent offsets.
//!
//! These are TODAY's shapes, not the shapes stage 5 proposes: the attested
//! outputs carry no kind tag and `claim`/`completeWithdraw` carry a `u8`
//! rather than a `bool`, because that is what is deployed (see
//! [`ClaimOutput`]).

use borsh::schema::{BorshSchemaContainer, Declaration, Definition};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::ser::SerializeTuple;
use serde::{Serialize, Serializer};

/// The fixed serialized width of a spec type.
///
/// Every offset in the subset is a compile-time constant, so every LEN is
/// too. The conformance suite proves the constant three ways: against
/// `borsh::object_length` over generated values (no value-dependent
/// branching), against the deployed FAB alignment's `bin_len`, and against
/// the schema walk.
pub trait FixedLen {
    const LEN: usize;
}

/// The subset's LEAF TABLE, as code: the only primitives a spec type may be
/// built from, and their widths. `Uint<BITS>` for BITS outside these widths
/// is a range constraint on the next width up, never a narrower field.
macro_rules! fixed_len_primitives {
    ($($ty:ty => $len:literal),+ $(,)?) => {
        $(impl FixedLen for $ty { const LEN: usize = $len; })+
    };
}

fixed_len_primitives!(bool => 1, u8 => 1, u16 => 2, u32 => 4, u64 => 8, u128 => 16);

impl<const N: usize> FixedLen for [u8; N] {
    const LEN: usize = N;
}

// ---- `Bytes<N>` for N > 32 ---------------------------------------------------

/// A fixed byte array whose length exceeds serde's blanket `[T; N]` impls
/// (which stop at N = 32) and whose Borsh schema declaration must not lose
/// the length.
///
/// The wrapper is TRANSPARENT under both oracles:
/// - Borsh: a newtype struct with one field serializes as that field, and
///   [`BorshSchema`] is delegated to `[u8; N]` verbatim (the derive would
///   name every instantiation `ByteArray`, which collides in a container
///   holding two different N).
/// - serde: [`Serialize`] is serde's own array impl verbatim —
///   `serialize_tuple(N)` and N elements.
///
/// `byte_array_wrapper_is_transparent` pins that claim for the N ≤ 32 where
/// the native impls exist and can be compared against.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for ByteArray<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(N)?;
        for byte in &self.0 {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
}

impl<const N: usize> BorshSchema for ByteArray<N> {
    fn declaration() -> Declaration {
        <[u8; N] as BorshSchema>::declaration()
    }

    fn add_definitions_recursively(
        definitions: &mut std::collections::BTreeMap<Declaration, Definition>,
    ) {
        <[u8; N] as BorshSchema>::add_definitions_recursively(definitions);
    }
}

impl<const N: usize> FixedLen for ByteArray<N> {
    const LEN: usize = N;
}

impl<const N: usize> Default for ByteArray<N> {
    fn default() -> Self {
        ByteArray([0u8; N])
    }
}

// ---- Maybe ------------------------------------------------------------------

/// Compact's `Maybe<T>`: a 1-byte tag and an ALWAYS-PRESENT payload.
///
/// This is what `Maybe` already compiles to (the FAB record carries
/// `calldata.is_some` as its own `bytes<1>` atom followed by the full
/// calldata atoms whether or not the tag is set), and it is ordinary
/// canonical Borsh AND ordinary serde of this struct — not a dialect. The
/// single most important line of the spec for the TS side: **Maybe ↦
/// Flagged, never Option**.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flagged<T> {
    pub is_some: bool,
    pub value: T,
}

impl<T: FixedLen> FixedLen for Flagged<T> {
    const LEN: usize = 1 + T::LEN;
}

// ---- the request record: `SignBidirectionalEvent` ----------------------------
//
// Field order, widths and nesting are read off the deployed shape:
// `signet::SignBidirectionalEvent::atoms()` (the alignment
// `calculateRequestId` hands to keccak256) and `signet::layout`. The vault's
// two instantiations are `<2, 34, 34>` (deposit / approveRouter / withdraw
// and the claim / completeWithdraw settlements that read the record back)
// and `<7, 38, 37>` (swap / completeSwap).

/// `struct EvmCalldata<#maxWords>` — the ABI calldata of the EVM
/// transaction the MPC is asked to sign.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmCalldata2 {
    /// `Bytes<4>` — the 4-byte function selector, in string order.
    pub selector: [u8; 4],
    /// `Uint<16>` — how many of `words` are used.
    pub no_words: u16,
    /// `Bytes<32>[2]` — the canonical big-endian ABI words.
    pub words: [[u8; 32]; 2],
}

impl FixedLen for EvmCalldata2 {
    const LEN: usize = 4 + 2 + 2 * 32;
}

/// [`EvmCalldata2`] with the swap instantiation's seven words.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmCalldata7 {
    pub selector: [u8; 4],
    pub no_words: u16,
    pub words: [[u8; 32]; 7],
}

impl FixedLen for EvmCalldata7 {
    const LEN: usize = 4 + 2 + 7 * 32;
}

/// `struct EvmType2TxParams<#maxCalldataWords, 0, 0>` — the EIP-1559
/// envelope with an empty access list, for the 2-word instantiation.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmType2TxParams2 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    /// `Bytes<20>` — the destination EVM address, in display order.
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: Flagged<EvmCalldata2>,
    /// `maxAccessListEntries = 0`, so no entries follow the count.
    pub access_list_entry_count: u8,
}

impl FixedLen for EvmType2TxParams2 {
    const LEN: usize = 8 + 8 + 16 + 16 + 8 + 20 + 16 + Flagged::<EvmCalldata2>::LEN + 1;
}

/// [`EvmType2TxParams2`] with the swap instantiation's seven calldata words.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvmType2TxParams7 {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    pub calldata: Flagged<EvmCalldata7>,
    pub access_list_entry_count: u8,
}

impl FixedLen for EvmType2TxParams7 {
    const LEN: usize = 8 + 8 + 16 + 16 + 8 + 20 + 16 + Flagged::<EvmCalldata7>::LEN + 1;
}

/// The vault's request record: `SignBidirectionalEvent<EvmType2TxParams<2,
/// 0, 0>, 34, 34>`, the value `signBidirectionalEventMap` stores and the
/// keccak256 preimage of the request id.
///
/// `deposit`, `approveRouter` and `withdraw` write one; `claim`,
/// `completeWithdraw` and `refund` read one back.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultEvent {
    /// The requesting contract's address (`kernel.self`).
    pub sender: [u8; 32],
    pub request_nonce: u64,
    /// Guarded `>= 1` by `constructSignBidirectionalEvent`.
    pub key_version: u8,
    /// The MPC key-derivation path — `userCommitment(sk)` for a deposit,
    /// the fixed vault path for the vault's own EVM account.
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm` — a fieldless enum, 1 byte. A Rust `enum`
    /// would leave the subset: bincode-fixint writes a 4-byte variant
    /// index where Borsh writes one (`fieldless_enum_leaves_the_subset`).
    pub algo: u8,
    /// `MPCDestination`, same rule as `algo`.
    pub dest: u8,
    /// `Bytes<64>` — `pad(64, "")` at every deployed site.
    pub params: ByteArray<64>,
    /// `TxParamType`, same rule as `algo`.
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams2,
    pub caip2_id: [u8; 32],
    /// The in-band ABI-JSON schema strings. Stage 7 replaces both with a
    /// 1-byte kind tag; today they are 34 bytes each.
    pub output_deserialization_schema: ByteArray<34>,
    pub respond_serialization_schema: ByteArray<34>,
}

impl FixedLen for VaultEvent {
    const LEN: usize = 32 + 8 + 1 + 32 + 1 + 1 + 64 + 1 + EvmType2TxParams2::LEN + 32 + 34 + 34;
}

/// The swap request record: `SignBidirectionalEvent<EvmType2TxParams<7, 0,
/// 0>, 38, 37>` — `swap` writes one, `completeSwap` and `refund` read it
/// back. 571 bytes, the number the design of record's stage-7 estimate is
/// built on.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapEvent {
    pub sender: [u8; 32],
    pub request_nonce: u64,
    pub key_version: u8,
    pub path: [u8; 32],
    pub algo: u8,
    pub dest: u8,
    pub params: ByteArray<64>,
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams7,
    pub caip2_id: [u8; 32],
    pub output_deserialization_schema: ByteArray<38>,
    pub respond_serialization_schema: ByteArray<37>,
}

impl FixedLen for SwapEvent {
    const LEN: usize = 32 + 8 + 1 + 32 + 1 + 1 + 64 + 1 + EvmType2TxParams7::LEN + 32 + 38 + 37;
}

// ---- the attested outputs ----------------------------------------------------
//
// What the MPC signs alongside the request id, exactly as deployed: four
// shapes, no kind tag. Stage 5's kind byte and `bool` are NOT here.

/// `claim`'s `serializedOutput: Bytes<1>` — the attested EVM result byte.
///
/// A `u8`, not a `bool`: today ANY byte is accepted and everything other
/// than `0x01` routes to the failure branch (the 0x02 hazard, M10's harness
/// finding). Stage 5 makes this a Borsh `bool`, which is `0|1` and nothing
/// else; until then the deployed type is a byte.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimOutput {
    pub success: u8,
}

impl FixedLen for ClaimOutput {
    const LEN: usize = 1;
}

/// `completeWithdraw`'s `serializedOutput: Bytes<1>` — the same shape as
/// [`ClaimOutput`] at a different site. That the two are structurally
/// indistinguishable is exactly why stage 5 proposes a kind tag: today only
/// which map holds the request id separates them.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteWithdrawOutput {
    pub success: u8,
}

impl FixedLen for CompleteWithdrawOutput {
    const LEN: usize = 1;
}

/// `refund`'s `serializedOutput: Bytes<5>` — the MPC's fixed failure
/// sentinel `0xdeadbeef01`, asserted equal in-circuit.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefundOutput {
    pub failure: [u8; 5],
}

impl FixedLen for RefundOutput {
    const LEN: usize = 5;
}

/// `completeSwap`'s `serializedOutput: Bytes<8>` — the attested `amountIn`
/// actually spent. Already a Borsh `u64`: the deployed preimage is
/// `amount_in.to_le_bytes()`.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteSwapOutput {
    pub amount_in: u64,
}

impl FixedLen for CompleteSwapOutput {
    const LEN: usize = 8;
}

// ---- the attested outputs, M11 stage 5 ----------------------------------------
//
// What the BORSH artifact signs: the same four sites with a response KIND at
// byte 0 and declared payload types. These are not deployed anywhere — the
// MPC has never settled on Midnight — so they are a SPECIFICATION, and this
// is where its byte layout is pinned against borsh's own encoder and schema.
// The circuit-side declarations are `erc20_vault_borsh::{VaultResponse,
// SwapResponse, FailureResponse}`; these are the independent second
// statement of them, which is the whole point of a spec type.

/// `claim` (kind 0) and `completeWithdraw` (kind 1): the kind byte and the
/// EVM outcome as a Borsh `bool`.
///
/// ONE TYPE FOR TWO SITES, unlike [`ClaimOutput`]/[`CompleteWithdrawOutput`]:
/// the two are now separated by the KIND VALUE rather than by being
/// structurally identical types at different sites, which is what makes a
/// cross-circuit replay a signature failure instead of a state-machine
/// question. And `success` is a `bool`, not a `u8` — the 0x02 hazard closing.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultResponse {
    pub kind: u8,
    pub success: bool,
}

impl FixedLen for VaultResponse {
    const LEN: usize = 1 + 1;
}

/// `completeSwap` (kind 2): the kind byte and the attested `amountIn`.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapResponse {
    pub kind: u8,
    pub amount_in: u64,
}

impl FixedLen for SwapResponse {
    const LEN: usize = 1 + 8;
}

/// `refund` (kind 3): the kind byte, and nothing else — the whole content of
/// the deployed 5-byte `0xdeadbeef01` sentinel, in the byte position every
/// response type puts its kind.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailureResponse {
    pub kind: u8,
}

impl FixedLen for FailureResponse {
    const LEN: usize = 1;
}

/// `calculateSignetAttestationDigest(requestId, serializedOutput)`'s
/// preimage — the raw concatenation the MPC signs.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationPreimage<T> {
    pub request_id: [u8; 32],
    pub output: T,
}

impl<T: FixedLen> FixedLen for AttestationPreimage<T> {
    const LEN: usize = 32 + T::LEN;
}

// ---- the Signet singleton's Misc payloads -------------------------------------
//
// `Misc` is event tag 10: `name: Bytes<32>` ‖ `payload: Bytes<256>`, 288
// serialized bytes. The spec types below are the PAYLOAD's leading bytes;
// the envelope rule (name, then these bytes, then zeros to 288) is
// `deployed::misc_envelope`.

/// `signBidirectional`'s payload: the notification version, the request id
/// and the 128-byte V1 notification payload — 161 bytes, then 95 zero bytes
/// of `Bytes<256>` pad.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignBidirectionalMisc {
    pub version: u8,
    pub request_id: [u8; 32],
    pub payload: ByteArray<128>,
}

impl FixedLen for SignBidirectionalMisc {
    const LEN: usize = 1 + 32 + 128;
}

/// `respond`'s and `respondBidirectional`'s payload — the two circuits are
/// the same body under different event names. 129 bytes (borsh-identical to
/// `[[u8; 32]; 4] ‖ u8`, spelled as named fields), then 127 zero bytes of
/// pad.
#[derive(BorshSerialize, BorshDeserialize, BorshSchema, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RespondMisc {
    pub request_id: [u8; 32],
    pub big_r_x: [u8; 32],
    pub big_r_y: [u8; 32],
    pub s: [u8; 32],
    pub recovery_id: u8,
}

impl FixedLen for RespondMisc {
    const LEN: usize = 4 * 32 + 1;
}

/// Every spec type's Borsh schema container, for the frozen layout table.
/// Kept beside the declarations so a new spec type that is never snapshotted
/// is a visible omission.
pub fn schema_containers() -> Vec<(&'static str, BorshSchemaContainer)> {
    vec![
        ("VaultEvent", BorshSchemaContainer::for_type::<VaultEvent>()),
        ("SwapEvent", BorshSchemaContainer::for_type::<SwapEvent>()),
        ("ClaimOutput", BorshSchemaContainer::for_type::<ClaimOutput>()),
        (
            "CompleteWithdrawOutput",
            BorshSchemaContainer::for_type::<CompleteWithdrawOutput>(),
        ),
        ("RefundOutput", BorshSchemaContainer::for_type::<RefundOutput>()),
        (
            "CompleteSwapOutput",
            BorshSchemaContainer::for_type::<CompleteSwapOutput>(),
        ),
        (
            "AttestationPreimage<ClaimOutput>",
            BorshSchemaContainer::for_type::<AttestationPreimage<ClaimOutput>>(),
        ),
        (
            "AttestationPreimage<CompleteWithdrawOutput>",
            BorshSchemaContainer::for_type::<AttestationPreimage<CompleteWithdrawOutput>>(),
        ),
        (
            "AttestationPreimage<RefundOutput>",
            BorshSchemaContainer::for_type::<AttestationPreimage<RefundOutput>>(),
        ),
        (
            "AttestationPreimage<CompleteSwapOutput>",
            BorshSchemaContainer::for_type::<AttestationPreimage<CompleteSwapOutput>>(),
        ),
        // M11 stage 5: the specified (not yet deployed) attested outputs.
        ("VaultResponse", BorshSchemaContainer::for_type::<VaultResponse>()),
        ("SwapResponse", BorshSchemaContainer::for_type::<SwapResponse>()),
        (
            "FailureResponse",
            BorshSchemaContainer::for_type::<FailureResponse>(),
        ),
        (
            "AttestationPreimage<VaultResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<VaultResponse>>(),
        ),
        (
            "AttestationPreimage<SwapResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<SwapResponse>>(),
        ),
        (
            "AttestationPreimage<FailureResponse>",
            BorshSchemaContainer::for_type::<AttestationPreimage<FailureResponse>>(),
        ),
        (
            "SignBidirectionalMisc",
            BorshSchemaContainer::for_type::<SignBidirectionalMisc>(),
        ),
        ("RespondMisc", BorshSchemaContainer::for_type::<RespondMisc>()),
    ]
}
