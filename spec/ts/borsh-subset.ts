/**
 * GENERATED — do not edit. Every offset below is walked out of the same Borsh
 * schema that produced `spec/borsh-subset.md` §9's tables and
 * `spec/vectors/*.json`.
 *
 * Regenerate with:
 * `cargo test --release -p minocrab-contracts --test serialization_conformance -- \
 *      --ignored regenerate_spec`
 * (generator: `crates/minocrab-contracts/tests/serialization/ts_codegen.rs`).
 *
 * This IS Borsh, restricted to the fixed-width subset: every type here has a
 * width that does not depend on its value, so every offset is a constant and
 * a reader is a `DataView` at that constant. That is why this file imports
 * nothing but `./primitives.ts` and needs no package installed.
 *
 * `borsh-js` remains the alternative: the declarations in
 * `spec/borsh-subset.md` are ordinary Borsh declarations, so a library decodes
 * these same bytes. Use whichever you prefer — this file exists so that a
 * dependency is a CHOICE, not a requirement, and so that the offsets are
 * generated rather than transcribed.
 *
 * Integers are LITTLE-ENDIAN (Borsh's rule). `Maybe` is `Flagged`, never
 * `Option`: the payload is ALWAYS present, so the offsets after it do not
 * move — see `spec/borsh-subset.md` §4.
 */

import {
  checkedView,
  getBool,
  getBytes,
  getU8,
  getU16,
  getU32,
  getU64,
  getU128,
  setBool,
  setBytes,
  setU8,
  setU16,
  setU32,
  setU64,
  setU128,
  type AnyCodec,
  type Codec,
  type FieldSpec,
  type LeafValue,
} from './primitives.ts';

// ---- the record format version -------------------------------------------------

/**
 * `formatVersion` — the byte at offset 0 of every stage-7 record
 * (`spec/borsh-subset.md` §6). `0x80` is the byte with only the high bit
 * set, so "this is not a small version number" is a single bit test.
 */
export const RECORD_FORMAT_VERSION = 0x80;

// ---- bool ------------------------------------------------------------------------

/** The fixed serialized width of `bool`. */
export const BOOL_LEN = 1;

/** `bool`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const BOOL_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: 'bool', offset: 0, width: 1 },
];

export type Bool = boolean;

/** Read a `bool` from `bytes` at `offset` — 1 byte, fixed. */
export function readBool(bytes: Uint8Array, offset = 0): Bool {
  const view = checkedView(bytes, offset, BOOL_LEN);
  return getBool(view, 0);
}

/** Write a `bool` into `out` at `offset`, and return `out`. */
export function writeBool(
  value: Bool,
  out = new Uint8Array(BOOL_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, BOOL_LEN);
  setBool(view, 0, value);
  return out;
}

/** `bool`'s leaves, in declaration order — one per `BOOL_FIELDS` entry. */
export function boolLeaves(value: Bool): readonly LeafValue[] {
  return [
    value,
  ];
}

export const boolCodec: Codec<Bool> = {
  name: 'bool',
  byteLength: BOOL_LEN,
  fields: BOOL_FIELDS,
  read: readBool,
  write: writeBool,
  leaves: boolLeaves,
};

// ---- u8 --------------------------------------------------------------------------

/** The fixed serialized width of `u8`. */
export const U8_LEN = 1;

/** `u8`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const U8_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: 'u8', offset: 0, width: 1 },
];

export type U8 = number;

/** Read a `u8` from `bytes` at `offset` — 1 byte, fixed. */
export function readU8(bytes: Uint8Array, offset = 0): U8 {
  const view = checkedView(bytes, offset, U8_LEN);
  return getU8(view, 0);
}

/** Write a `u8` into `out` at `offset`, and return `out`. */
export function writeU8(
  value: U8,
  out = new Uint8Array(U8_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, U8_LEN);
  setU8(view, 0, value);
  return out;
}

/** `u8`'s leaves, in declaration order — one per `U8_FIELDS` entry. */
export function u8Leaves(value: U8): readonly LeafValue[] {
  return [
    value,
  ];
}

export const u8Codec: Codec<U8> = {
  name: 'u8',
  byteLength: U8_LEN,
  fields: U8_FIELDS,
  read: readU8,
  write: writeU8,
  leaves: u8Leaves,
};

// ---- u16 -------------------------------------------------------------------------

/** The fixed serialized width of `u16`. */
export const U16_LEN = 2;

/** `u16`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const U16_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: 'u16', offset: 0, width: 2 },
];

export type U16 = number;

/** Read a `u16` from `bytes` at `offset` — 2 bytes, fixed. */
export function readU16(bytes: Uint8Array, offset = 0): U16 {
  const view = checkedView(bytes, offset, U16_LEN);
  return getU16(view, 0);
}

/** Write a `u16` into `out` at `offset`, and return `out`. */
export function writeU16(
  value: U16,
  out = new Uint8Array(U16_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, U16_LEN);
  setU16(view, 0, value);
  return out;
}

/** `u16`'s leaves, in declaration order — one per `U16_FIELDS` entry. */
export function u16Leaves(value: U16): readonly LeafValue[] {
  return [
    value,
  ];
}

export const u16Codec: Codec<U16> = {
  name: 'u16',
  byteLength: U16_LEN,
  fields: U16_FIELDS,
  read: readU16,
  write: writeU16,
  leaves: u16Leaves,
};

// ---- u32 -------------------------------------------------------------------------

/** The fixed serialized width of `u32`. */
export const U32_LEN = 4;

/** `u32`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const U32_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: 'u32', offset: 0, width: 4 },
];

export type U32 = number;

/** Read a `u32` from `bytes` at `offset` — 4 bytes, fixed. */
export function readU32(bytes: Uint8Array, offset = 0): U32 {
  const view = checkedView(bytes, offset, U32_LEN);
  return getU32(view, 0);
}

/** Write a `u32` into `out` at `offset`, and return `out`. */
export function writeU32(
  value: U32,
  out = new Uint8Array(U32_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, U32_LEN);
  setU32(view, 0, value);
  return out;
}

/** `u32`'s leaves, in declaration order — one per `U32_FIELDS` entry. */
export function u32Leaves(value: U32): readonly LeafValue[] {
  return [
    value,
  ];
}

export const u32Codec: Codec<U32> = {
  name: 'u32',
  byteLength: U32_LEN,
  fields: U32_FIELDS,
  read: readU32,
  write: writeU32,
  leaves: u32Leaves,
};

// ---- u64 -------------------------------------------------------------------------

/** The fixed serialized width of `u64`. */
export const U64_LEN = 8;

/** `u64`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const U64_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: 'u64', offset: 0, width: 8 },
];

export type U64 = bigint;

/** Read a `u64` from `bytes` at `offset` — 8 bytes, fixed. */
export function readU64(bytes: Uint8Array, offset = 0): U64 {
  const view = checkedView(bytes, offset, U64_LEN);
  return getU64(view, 0);
}

/** Write a `u64` into `out` at `offset`, and return `out`. */
export function writeU64(
  value: U64,
  out = new Uint8Array(U64_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, U64_LEN);
  setU64(view, 0, value);
  return out;
}

/** `u64`'s leaves, in declaration order — one per `U64_FIELDS` entry. */
export function u64Leaves(value: U64): readonly LeafValue[] {
  return [
    value,
  ];
}

export const u64Codec: Codec<U64> = {
  name: 'u64',
  byteLength: U64_LEN,
  fields: U64_FIELDS,
  read: readU64,
  write: writeU64,
  leaves: u64Leaves,
};

// ---- u128 ------------------------------------------------------------------------

/** The fixed serialized width of `u128`. */
export const U128_LEN = 16;

/** `u128`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const U128_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: 'u128', offset: 0, width: 16 },
];

export type U128 = bigint;

/** Read a `u128` from `bytes` at `offset` — 16 bytes, fixed. */
export function readU128(bytes: Uint8Array, offset = 0): U128 {
  const view = checkedView(bytes, offset, U128_LEN);
  return getU128(view, 0);
}

/** Write a `u128` into `out` at `offset`, and return `out`. */
export function writeU128(
  value: U128,
  out = new Uint8Array(U128_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, U128_LEN);
  setU128(view, 0, value);
  return out;
}

/** `u128`'s leaves, in declaration order — one per `U128_FIELDS` entry. */
export function u128Leaves(value: U128): readonly LeafValue[] {
  return [
    value,
  ];
}

export const u128Codec: Codec<U128> = {
  name: 'u128',
  byteLength: U128_LEN,
  fields: U128_FIELDS,
  read: readU128,
  write: writeU128,
  leaves: u128Leaves,
};

// ---- [u8; 20] --------------------------------------------------------------------

/** The fixed serialized width of `[u8; 20]`. */
export const BYTES20_LEN = 20;

/** `[u8; 20]`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const BYTES20_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: '[u8; 20]', offset: 0, width: 20 },
];

export type Bytes20 = Uint8Array;

/** Read a `[u8; 20]` from `bytes` at `offset` — 20 bytes, fixed. */
export function readBytes20(bytes: Uint8Array, offset = 0): Bytes20 {
  const view = checkedView(bytes, offset, BYTES20_LEN);
  return getBytes(view, 0, 20);
}

/** Write a `[u8; 20]` into `out` at `offset`, and return `out`. */
export function writeBytes20(
  value: Bytes20,
  out = new Uint8Array(BYTES20_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, BYTES20_LEN);
  setBytes(view, 0, 20, value);
  return out;
}

/** `[u8; 20]`'s leaves, in declaration order — one per `BYTES20_FIELDS` entry. */
export function bytes20Leaves(value: Bytes20): readonly LeafValue[] {
  return [
    value,
  ];
}

export const bytes20Codec: Codec<Bytes20> = {
  name: '[u8; 20]',
  byteLength: BYTES20_LEN,
  fields: BYTES20_FIELDS,
  read: readBytes20,
  write: writeBytes20,
  leaves: bytes20Leaves,
};

// ---- [u8; 32] --------------------------------------------------------------------

/** The fixed serialized width of `[u8; 32]`. */
export const BYTES32_LEN = 32;

/** `[u8; 32]`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const BYTES32_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: '[u8; 32]', offset: 0, width: 32 },
];

export type Bytes32 = Uint8Array;

/** Read a `[u8; 32]` from `bytes` at `offset` — 32 bytes, fixed. */
export function readBytes32(bytes: Uint8Array, offset = 0): Bytes32 {
  const view = checkedView(bytes, offset, BYTES32_LEN);
  return getBytes(view, 0, 32);
}

/** Write a `[u8; 32]` into `out` at `offset`, and return `out`. */
export function writeBytes32(
  value: Bytes32,
  out = new Uint8Array(BYTES32_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, BYTES32_LEN);
  setBytes(view, 0, 32, value);
  return out;
}

/** `[u8; 32]`'s leaves, in declaration order — one per `BYTES32_FIELDS` entry. */
export function bytes32Leaves(value: Bytes32): readonly LeafValue[] {
  return [
    value,
  ];
}

export const bytes32Codec: Codec<Bytes32> = {
  name: '[u8; 32]',
  byteLength: BYTES32_LEN,
  fields: BYTES32_FIELDS,
  read: readBytes32,
  write: writeBytes32,
  leaves: bytes32Leaves,
};

// ---- [u8; 64] --------------------------------------------------------------------

/** The fixed serialized width of `[u8; 64]`. */
export const BYTES64_LEN = 64;

/** `[u8; 64]`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const BYTES64_FIELDS: readonly FieldSpec[] = [
  { path: '(the value)', type: '[u8; 64]', offset: 0, width: 64 },
];

export type Bytes64 = Uint8Array;

/** Read a `[u8; 64]` from `bytes` at `offset` — 64 bytes, fixed. */
export function readBytes64(bytes: Uint8Array, offset = 0): Bytes64 {
  const view = checkedView(bytes, offset, BYTES64_LEN);
  return getBytes(view, 0, 64);
}

/** Write a `[u8; 64]` into `out` at `offset`, and return `out`. */
export function writeBytes64(
  value: Bytes64,
  out = new Uint8Array(BYTES64_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, BYTES64_LEN);
  setBytes(view, 0, 64, value);
  return out;
}

/** `[u8; 64]`'s leaves, in declaration order — one per `BYTES64_FIELDS` entry. */
export function bytes64Leaves(value: Bytes64): readonly LeafValue[] {
  return [
    value,
  ];
}

export const bytes64Codec: Codec<Bytes64> = {
  name: '[u8; 64]',
  byteLength: BYTES64_LEN,
  fields: BYTES64_FIELDS,
  read: readBytes64,
  write: writeBytes64,
  leaves: bytes64Leaves,
};

// ---- Flagged<u32> ----------------------------------------------------------------

/** The fixed serialized width of `Flagged<u32>`. */
export const FLAGGED_U32_LEN = 5;

/** `Flagged<u32>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const FLAGGED_U32_FIELDS: readonly FieldSpec[] = [
  { path: 'is_some', type: 'bool', offset: 0, width: 1 },
  { path: 'value', type: 'u32', offset: 1, width: 4 },
];

export interface FlaggedU32 {
  readonly isSome: boolean;
  readonly value: number;
}

/** Read a `Flagged<u32>` from `bytes` at `offset` — 5 bytes, fixed. */
export function readFlaggedU32(bytes: Uint8Array, offset = 0): FlaggedU32 {
  const view = checkedView(bytes, offset, FLAGGED_U32_LEN);
  return {
    isSome: getBool(view, 0),
    value: getU32(view, 1),
  };
}

/** Write a `Flagged<u32>` into `out` at `offset`, and return `out`. */
export function writeFlaggedU32(
  value: FlaggedU32,
  out = new Uint8Array(FLAGGED_U32_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, FLAGGED_U32_LEN);
  setBool(view, 0, value.isSome);
  setU32(view, 1, value.value);
  return out;
}

/** `Flagged<u32>`'s leaves, in declaration order — one per `FLAGGED_U32_FIELDS` entry. */
export function flaggedU32Leaves(value: FlaggedU32): readonly LeafValue[] {
  return [
    value.isSome,
    value.value,
  ];
}

export const flaggedU32Codec: Codec<FlaggedU32> = {
  name: 'Flagged<u32>',
  byteLength: FLAGGED_U32_LEN,
  fields: FLAGGED_U32_FIELDS,
  read: readFlaggedU32,
  write: writeFlaggedU32,
  leaves: flaggedU32Leaves,
};

// ---- VaultEvent ------------------------------------------------------------------

/** The fixed serialized width of `VaultEvent`. */
export const VAULT_EVENT_LEN = 404;

/** `VaultEvent`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const VAULT_EVENT_FIELDS: readonly FieldSpec[] = [
  { path: 'sender', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'request_nonce', type: 'u64', offset: 32, width: 8 },
  { path: 'key_version', type: 'u8', offset: 40, width: 1 },
  { path: 'path', type: '[u8; 32]', offset: 41, width: 32 },
  { path: 'algo', type: 'u8', offset: 73, width: 1 },
  { path: 'dest', type: 'u8', offset: 74, width: 1 },
  { path: 'params', type: '[u8; 64]', offset: 75, width: 64 },
  { path: 'tx_param_type', type: 'u8', offset: 139, width: 1 },
  { path: 'tx_params.chain_id', type: 'u64', offset: 140, width: 8 },
  { path: 'tx_params.nonce', type: 'u64', offset: 148, width: 8 },
  { path: 'tx_params.max_priority_fee_per_gas', type: 'u128', offset: 156, width: 16 },
  { path: 'tx_params.max_fee_per_gas', type: 'u128', offset: 172, width: 16 },
  { path: 'tx_params.gas_limit', type: 'u64', offset: 188, width: 8 },
  { path: 'tx_params.to', type: '[u8; 20]', offset: 196, width: 20 },
  { path: 'tx_params.value', type: 'u128', offset: 216, width: 16 },
  { path: 'tx_params.calldata.is_some', type: 'bool', offset: 232, width: 1 },
  { path: 'tx_params.calldata.value.selector', type: '[u8; 4]', offset: 233, width: 4 },
  { path: 'tx_params.calldata.value.no_words', type: 'u16', offset: 237, width: 2 },
  { path: 'tx_params.calldata.value.words[0]', type: '[u8; 32]', offset: 239, width: 32 },
  { path: 'tx_params.calldata.value.words[1]', type: '[u8; 32]', offset: 271, width: 32 },
  { path: 'tx_params.access_list_entry_count', type: 'u8', offset: 303, width: 1 },
  { path: 'caip2_id', type: '[u8; 32]', offset: 304, width: 32 },
  { path: 'output_deserialization_schema', type: '[u8; 34]', offset: 336, width: 34 },
  { path: 'respond_serialization_schema', type: '[u8; 34]', offset: 370, width: 34 },
];

export interface VaultEvent {
  readonly sender: Uint8Array;
  readonly requestNonce: bigint;
  readonly keyVersion: number;
  readonly path: Uint8Array;
  readonly algo: number;
  readonly dest: number;
  readonly params: Uint8Array;
  readonly txParamType: number;
  readonly txParams: {
    readonly chainId: bigint;
    readonly nonce: bigint;
    readonly maxPriorityFeePerGas: bigint;
    readonly maxFeePerGas: bigint;
    readonly gasLimit: bigint;
    readonly to: Uint8Array;
    readonly value: bigint;
    readonly calldata: {
      readonly isSome: boolean;
      readonly value: {
        readonly selector: Uint8Array;
        readonly noWords: number;
        readonly words: readonly [Uint8Array, Uint8Array];
      };
    };
    readonly accessListEntryCount: number;
  };
  readonly caip2Id: Uint8Array;
  readonly outputDeserializationSchema: Uint8Array;
  readonly respondSerializationSchema: Uint8Array;
}

/** Read a `VaultEvent` from `bytes` at `offset` — 404 bytes, fixed. */
export function readVaultEvent(bytes: Uint8Array, offset = 0): VaultEvent {
  const view = checkedView(bytes, offset, VAULT_EVENT_LEN);
  return {
    sender: getBytes(view, 0, 32),
    requestNonce: getU64(view, 32),
    keyVersion: getU8(view, 40),
    path: getBytes(view, 41, 32),
    algo: getU8(view, 73),
    dest: getU8(view, 74),
    params: getBytes(view, 75, 64),
    txParamType: getU8(view, 139),
    txParams: {
      chainId: getU64(view, 140),
      nonce: getU64(view, 148),
      maxPriorityFeePerGas: getU128(view, 156),
      maxFeePerGas: getU128(view, 172),
      gasLimit: getU64(view, 188),
      to: getBytes(view, 196, 20),
      value: getU128(view, 216),
      calldata: {
        isSome: getBool(view, 232),
        value: {
          selector: getBytes(view, 233, 4),
          noWords: getU16(view, 237),
          words: [
            getBytes(view, 239, 32),
            getBytes(view, 271, 32),
          ],
        },
      },
      accessListEntryCount: getU8(view, 303),
    },
    caip2Id: getBytes(view, 304, 32),
    outputDeserializationSchema: getBytes(view, 336, 34),
    respondSerializationSchema: getBytes(view, 370, 34),
  };
}

/** Write a `VaultEvent` into `out` at `offset`, and return `out`. */
export function writeVaultEvent(
  value: VaultEvent,
  out = new Uint8Array(VAULT_EVENT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, VAULT_EVENT_LEN);
  setBytes(view, 0, 32, value.sender);
  setU64(view, 32, value.requestNonce);
  setU8(view, 40, value.keyVersion);
  setBytes(view, 41, 32, value.path);
  setU8(view, 73, value.algo);
  setU8(view, 74, value.dest);
  setBytes(view, 75, 64, value.params);
  setU8(view, 139, value.txParamType);
  setU64(view, 140, value.txParams.chainId);
  setU64(view, 148, value.txParams.nonce);
  setU128(view, 156, value.txParams.maxPriorityFeePerGas);
  setU128(view, 172, value.txParams.maxFeePerGas);
  setU64(view, 188, value.txParams.gasLimit);
  setBytes(view, 196, 20, value.txParams.to);
  setU128(view, 216, value.txParams.value);
  setBool(view, 232, value.txParams.calldata.isSome);
  setBytes(view, 233, 4, value.txParams.calldata.value.selector);
  setU16(view, 237, value.txParams.calldata.value.noWords);
  setBytes(view, 239, 32, value.txParams.calldata.value.words[0]);
  setBytes(view, 271, 32, value.txParams.calldata.value.words[1]);
  setU8(view, 303, value.txParams.accessListEntryCount);
  setBytes(view, 304, 32, value.caip2Id);
  setBytes(view, 336, 34, value.outputDeserializationSchema);
  setBytes(view, 370, 34, value.respondSerializationSchema);
  return out;
}

/** `VaultEvent`'s leaves, in declaration order — one per `VAULT_EVENT_FIELDS` entry. */
export function vaultEventLeaves(value: VaultEvent): readonly LeafValue[] {
  return [
    value.sender,
    value.requestNonce,
    value.keyVersion,
    value.path,
    value.algo,
    value.dest,
    value.params,
    value.txParamType,
    value.txParams.chainId,
    value.txParams.nonce,
    value.txParams.maxPriorityFeePerGas,
    value.txParams.maxFeePerGas,
    value.txParams.gasLimit,
    value.txParams.to,
    value.txParams.value,
    value.txParams.calldata.isSome,
    value.txParams.calldata.value.selector,
    value.txParams.calldata.value.noWords,
    value.txParams.calldata.value.words[0],
    value.txParams.calldata.value.words[1],
    value.txParams.accessListEntryCount,
    value.caip2Id,
    value.outputDeserializationSchema,
    value.respondSerializationSchema,
  ];
}

export const vaultEventCodec: Codec<VaultEvent> = {
  name: 'VaultEvent',
  byteLength: VAULT_EVENT_LEN,
  fields: VAULT_EVENT_FIELDS,
  read: readVaultEvent,
  write: writeVaultEvent,
  leaves: vaultEventLeaves,
};

// ---- SwapEvent -------------------------------------------------------------------

/** The fixed serialized width of `SwapEvent`. */
export const SWAP_EVENT_LEN = 571;

/** `SwapEvent`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const SWAP_EVENT_FIELDS: readonly FieldSpec[] = [
  { path: 'sender', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'request_nonce', type: 'u64', offset: 32, width: 8 },
  { path: 'key_version', type: 'u8', offset: 40, width: 1 },
  { path: 'path', type: '[u8; 32]', offset: 41, width: 32 },
  { path: 'algo', type: 'u8', offset: 73, width: 1 },
  { path: 'dest', type: 'u8', offset: 74, width: 1 },
  { path: 'params', type: '[u8; 64]', offset: 75, width: 64 },
  { path: 'tx_param_type', type: 'u8', offset: 139, width: 1 },
  { path: 'tx_params.chain_id', type: 'u64', offset: 140, width: 8 },
  { path: 'tx_params.nonce', type: 'u64', offset: 148, width: 8 },
  { path: 'tx_params.max_priority_fee_per_gas', type: 'u128', offset: 156, width: 16 },
  { path: 'tx_params.max_fee_per_gas', type: 'u128', offset: 172, width: 16 },
  { path: 'tx_params.gas_limit', type: 'u64', offset: 188, width: 8 },
  { path: 'tx_params.to', type: '[u8; 20]', offset: 196, width: 20 },
  { path: 'tx_params.value', type: 'u128', offset: 216, width: 16 },
  { path: 'tx_params.calldata.is_some', type: 'bool', offset: 232, width: 1 },
  { path: 'tx_params.calldata.value.selector', type: '[u8; 4]', offset: 233, width: 4 },
  { path: 'tx_params.calldata.value.no_words', type: 'u16', offset: 237, width: 2 },
  { path: 'tx_params.calldata.value.words[0]', type: '[u8; 32]', offset: 239, width: 32 },
  { path: 'tx_params.calldata.value.words[1]', type: '[u8; 32]', offset: 271, width: 32 },
  { path: 'tx_params.calldata.value.words[2]', type: '[u8; 32]', offset: 303, width: 32 },
  { path: 'tx_params.calldata.value.words[3]', type: '[u8; 32]', offset: 335, width: 32 },
  { path: 'tx_params.calldata.value.words[4]', type: '[u8; 32]', offset: 367, width: 32 },
  { path: 'tx_params.calldata.value.words[5]', type: '[u8; 32]', offset: 399, width: 32 },
  { path: 'tx_params.calldata.value.words[6]', type: '[u8; 32]', offset: 431, width: 32 },
  { path: 'tx_params.access_list_entry_count', type: 'u8', offset: 463, width: 1 },
  { path: 'caip2_id', type: '[u8; 32]', offset: 464, width: 32 },
  { path: 'output_deserialization_schema', type: '[u8; 38]', offset: 496, width: 38 },
  { path: 'respond_serialization_schema', type: '[u8; 37]', offset: 534, width: 37 },
];

export interface SwapEvent {
  readonly sender: Uint8Array;
  readonly requestNonce: bigint;
  readonly keyVersion: number;
  readonly path: Uint8Array;
  readonly algo: number;
  readonly dest: number;
  readonly params: Uint8Array;
  readonly txParamType: number;
  readonly txParams: {
    readonly chainId: bigint;
    readonly nonce: bigint;
    readonly maxPriorityFeePerGas: bigint;
    readonly maxFeePerGas: bigint;
    readonly gasLimit: bigint;
    readonly to: Uint8Array;
    readonly value: bigint;
    readonly calldata: {
      readonly isSome: boolean;
      readonly value: {
        readonly selector: Uint8Array;
        readonly noWords: number;
        readonly words: readonly [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
      };
    };
    readonly accessListEntryCount: number;
  };
  readonly caip2Id: Uint8Array;
  readonly outputDeserializationSchema: Uint8Array;
  readonly respondSerializationSchema: Uint8Array;
}

/** Read a `SwapEvent` from `bytes` at `offset` — 571 bytes, fixed. */
export function readSwapEvent(bytes: Uint8Array, offset = 0): SwapEvent {
  const view = checkedView(bytes, offset, SWAP_EVENT_LEN);
  return {
    sender: getBytes(view, 0, 32),
    requestNonce: getU64(view, 32),
    keyVersion: getU8(view, 40),
    path: getBytes(view, 41, 32),
    algo: getU8(view, 73),
    dest: getU8(view, 74),
    params: getBytes(view, 75, 64),
    txParamType: getU8(view, 139),
    txParams: {
      chainId: getU64(view, 140),
      nonce: getU64(view, 148),
      maxPriorityFeePerGas: getU128(view, 156),
      maxFeePerGas: getU128(view, 172),
      gasLimit: getU64(view, 188),
      to: getBytes(view, 196, 20),
      value: getU128(view, 216),
      calldata: {
        isSome: getBool(view, 232),
        value: {
          selector: getBytes(view, 233, 4),
          noWords: getU16(view, 237),
          words: [
            getBytes(view, 239, 32),
            getBytes(view, 271, 32),
            getBytes(view, 303, 32),
            getBytes(view, 335, 32),
            getBytes(view, 367, 32),
            getBytes(view, 399, 32),
            getBytes(view, 431, 32),
          ],
        },
      },
      accessListEntryCount: getU8(view, 463),
    },
    caip2Id: getBytes(view, 464, 32),
    outputDeserializationSchema: getBytes(view, 496, 38),
    respondSerializationSchema: getBytes(view, 534, 37),
  };
}

/** Write a `SwapEvent` into `out` at `offset`, and return `out`. */
export function writeSwapEvent(
  value: SwapEvent,
  out = new Uint8Array(SWAP_EVENT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, SWAP_EVENT_LEN);
  setBytes(view, 0, 32, value.sender);
  setU64(view, 32, value.requestNonce);
  setU8(view, 40, value.keyVersion);
  setBytes(view, 41, 32, value.path);
  setU8(view, 73, value.algo);
  setU8(view, 74, value.dest);
  setBytes(view, 75, 64, value.params);
  setU8(view, 139, value.txParamType);
  setU64(view, 140, value.txParams.chainId);
  setU64(view, 148, value.txParams.nonce);
  setU128(view, 156, value.txParams.maxPriorityFeePerGas);
  setU128(view, 172, value.txParams.maxFeePerGas);
  setU64(view, 188, value.txParams.gasLimit);
  setBytes(view, 196, 20, value.txParams.to);
  setU128(view, 216, value.txParams.value);
  setBool(view, 232, value.txParams.calldata.isSome);
  setBytes(view, 233, 4, value.txParams.calldata.value.selector);
  setU16(view, 237, value.txParams.calldata.value.noWords);
  setBytes(view, 239, 32, value.txParams.calldata.value.words[0]);
  setBytes(view, 271, 32, value.txParams.calldata.value.words[1]);
  setBytes(view, 303, 32, value.txParams.calldata.value.words[2]);
  setBytes(view, 335, 32, value.txParams.calldata.value.words[3]);
  setBytes(view, 367, 32, value.txParams.calldata.value.words[4]);
  setBytes(view, 399, 32, value.txParams.calldata.value.words[5]);
  setBytes(view, 431, 32, value.txParams.calldata.value.words[6]);
  setU8(view, 463, value.txParams.accessListEntryCount);
  setBytes(view, 464, 32, value.caip2Id);
  setBytes(view, 496, 38, value.outputDeserializationSchema);
  setBytes(view, 534, 37, value.respondSerializationSchema);
  return out;
}

/** `SwapEvent`'s leaves, in declaration order — one per `SWAP_EVENT_FIELDS` entry. */
export function swapEventLeaves(value: SwapEvent): readonly LeafValue[] {
  return [
    value.sender,
    value.requestNonce,
    value.keyVersion,
    value.path,
    value.algo,
    value.dest,
    value.params,
    value.txParamType,
    value.txParams.chainId,
    value.txParams.nonce,
    value.txParams.maxPriorityFeePerGas,
    value.txParams.maxFeePerGas,
    value.txParams.gasLimit,
    value.txParams.to,
    value.txParams.value,
    value.txParams.calldata.isSome,
    value.txParams.calldata.value.selector,
    value.txParams.calldata.value.noWords,
    value.txParams.calldata.value.words[0],
    value.txParams.calldata.value.words[1],
    value.txParams.calldata.value.words[2],
    value.txParams.calldata.value.words[3],
    value.txParams.calldata.value.words[4],
    value.txParams.calldata.value.words[5],
    value.txParams.calldata.value.words[6],
    value.txParams.accessListEntryCount,
    value.caip2Id,
    value.outputDeserializationSchema,
    value.respondSerializationSchema,
  ];
}

export const swapEventCodec: Codec<SwapEvent> = {
  name: 'SwapEvent',
  byteLength: SWAP_EVENT_LEN,
  fields: SWAP_EVENT_FIELDS,
  read: readSwapEvent,
  write: writeSwapEvent,
  leaves: swapEventLeaves,
};

// ---- VaultEventV2 ----------------------------------------------------------------

/** The fixed serialized width of `VaultEventV2`. */
export const VAULT_EVENT_V2_LEN = 338;

/** `VaultEventV2`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const VAULT_EVENT_V2_FIELDS: readonly FieldSpec[] = [
  { path: 'format_version', type: 'u8', offset: 0, width: 1 },
  { path: 'sender', type: '[u8; 32]', offset: 1, width: 32 },
  { path: 'request_nonce', type: 'u64', offset: 33, width: 8 },
  { path: 'key_version', type: 'u8', offset: 41, width: 1 },
  { path: 'path', type: '[u8; 32]', offset: 42, width: 32 },
  { path: 'algo', type: 'u8', offset: 74, width: 1 },
  { path: 'dest', type: 'u8', offset: 75, width: 1 },
  { path: 'params', type: '[u8; 64]', offset: 76, width: 64 },
  { path: 'tx_param_type', type: 'u8', offset: 140, width: 1 },
  { path: 'tx_params.chain_id', type: 'u64', offset: 141, width: 8 },
  { path: 'tx_params.nonce', type: 'u64', offset: 149, width: 8 },
  { path: 'tx_params.max_priority_fee_per_gas', type: 'u128', offset: 157, width: 16 },
  { path: 'tx_params.max_fee_per_gas', type: 'u128', offset: 173, width: 16 },
  { path: 'tx_params.gas_limit', type: 'u64', offset: 189, width: 8 },
  { path: 'tx_params.to', type: '[u8; 20]', offset: 197, width: 20 },
  { path: 'tx_params.value', type: 'u128', offset: 217, width: 16 },
  { path: 'tx_params.calldata.is_some', type: 'bool', offset: 233, width: 1 },
  { path: 'tx_params.calldata.value.selector', type: '[u8; 4]', offset: 234, width: 4 },
  { path: 'tx_params.calldata.value.no_words', type: 'u16', offset: 238, width: 2 },
  { path: 'tx_params.calldata.value.words[0]', type: '[u8; 32]', offset: 240, width: 32 },
  { path: 'tx_params.calldata.value.words[1]', type: '[u8; 32]', offset: 272, width: 32 },
  { path: 'tx_params.access_list_entry_count', type: 'u8', offset: 304, width: 1 },
  { path: 'caip2_id', type: '[u8; 32]', offset: 305, width: 32 },
  { path: 'response_kind', type: 'u8', offset: 337, width: 1 },
];

export interface VaultEventV2 {
  readonly formatVersion: number;
  readonly sender: Uint8Array;
  readonly requestNonce: bigint;
  readonly keyVersion: number;
  readonly path: Uint8Array;
  readonly algo: number;
  readonly dest: number;
  readonly params: Uint8Array;
  readonly txParamType: number;
  readonly txParams: {
    readonly chainId: bigint;
    readonly nonce: bigint;
    readonly maxPriorityFeePerGas: bigint;
    readonly maxFeePerGas: bigint;
    readonly gasLimit: bigint;
    readonly to: Uint8Array;
    readonly value: bigint;
    readonly calldata: {
      readonly isSome: boolean;
      readonly value: {
        readonly selector: Uint8Array;
        readonly noWords: number;
        readonly words: readonly [Uint8Array, Uint8Array];
      };
    };
    readonly accessListEntryCount: number;
  };
  readonly caip2Id: Uint8Array;
  readonly responseKind: number;
}

/** Read a `VaultEventV2` from `bytes` at `offset` — 338 bytes, fixed. */
export function readVaultEventV2(bytes: Uint8Array, offset = 0): VaultEventV2 {
  const view = checkedView(bytes, offset, VAULT_EVENT_V2_LEN);
  // The version byte FIRST — `spec/borsh-subset.md` §6: a decoder reads byte 0
  // and rejects a record whose format it does not know, BY NAME, before it
  // reads a single offset that format may have moved.
  const version = getU8(view, 0);
  if (version !== RECORD_FORMAT_VERSION) {
    throw new Error(
      'record-version: expected 0x80, got 0x' + version.toString(16).padStart(2, '0'),
    );
  }
  return {
    formatVersion: getU8(view, 0),
    sender: getBytes(view, 1, 32),
    requestNonce: getU64(view, 33),
    keyVersion: getU8(view, 41),
    path: getBytes(view, 42, 32),
    algo: getU8(view, 74),
    dest: getU8(view, 75),
    params: getBytes(view, 76, 64),
    txParamType: getU8(view, 140),
    txParams: {
      chainId: getU64(view, 141),
      nonce: getU64(view, 149),
      maxPriorityFeePerGas: getU128(view, 157),
      maxFeePerGas: getU128(view, 173),
      gasLimit: getU64(view, 189),
      to: getBytes(view, 197, 20),
      value: getU128(view, 217),
      calldata: {
        isSome: getBool(view, 233),
        value: {
          selector: getBytes(view, 234, 4),
          noWords: getU16(view, 238),
          words: [
            getBytes(view, 240, 32),
            getBytes(view, 272, 32),
          ],
        },
      },
      accessListEntryCount: getU8(view, 304),
    },
    caip2Id: getBytes(view, 305, 32),
    responseKind: getU8(view, 337),
  };
}

/** Write a `VaultEventV2` into `out` at `offset`, and return `out`. */
export function writeVaultEventV2(
  value: VaultEventV2,
  out = new Uint8Array(VAULT_EVENT_V2_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, VAULT_EVENT_V2_LEN);
  setU8(view, 0, value.formatVersion);
  setBytes(view, 1, 32, value.sender);
  setU64(view, 33, value.requestNonce);
  setU8(view, 41, value.keyVersion);
  setBytes(view, 42, 32, value.path);
  setU8(view, 74, value.algo);
  setU8(view, 75, value.dest);
  setBytes(view, 76, 64, value.params);
  setU8(view, 140, value.txParamType);
  setU64(view, 141, value.txParams.chainId);
  setU64(view, 149, value.txParams.nonce);
  setU128(view, 157, value.txParams.maxPriorityFeePerGas);
  setU128(view, 173, value.txParams.maxFeePerGas);
  setU64(view, 189, value.txParams.gasLimit);
  setBytes(view, 197, 20, value.txParams.to);
  setU128(view, 217, value.txParams.value);
  setBool(view, 233, value.txParams.calldata.isSome);
  setBytes(view, 234, 4, value.txParams.calldata.value.selector);
  setU16(view, 238, value.txParams.calldata.value.noWords);
  setBytes(view, 240, 32, value.txParams.calldata.value.words[0]);
  setBytes(view, 272, 32, value.txParams.calldata.value.words[1]);
  setU8(view, 304, value.txParams.accessListEntryCount);
  setBytes(view, 305, 32, value.caip2Id);
  setU8(view, 337, value.responseKind);
  return out;
}

/** `VaultEventV2`'s leaves, in declaration order — one per `VAULT_EVENT_V2_FIELDS` entry. */
export function vaultEventV2Leaves(value: VaultEventV2): readonly LeafValue[] {
  return [
    value.formatVersion,
    value.sender,
    value.requestNonce,
    value.keyVersion,
    value.path,
    value.algo,
    value.dest,
    value.params,
    value.txParamType,
    value.txParams.chainId,
    value.txParams.nonce,
    value.txParams.maxPriorityFeePerGas,
    value.txParams.maxFeePerGas,
    value.txParams.gasLimit,
    value.txParams.to,
    value.txParams.value,
    value.txParams.calldata.isSome,
    value.txParams.calldata.value.selector,
    value.txParams.calldata.value.noWords,
    value.txParams.calldata.value.words[0],
    value.txParams.calldata.value.words[1],
    value.txParams.accessListEntryCount,
    value.caip2Id,
    value.responseKind,
  ];
}

export const vaultEventV2Codec: Codec<VaultEventV2> = {
  name: 'VaultEventV2',
  byteLength: VAULT_EVENT_V2_LEN,
  fields: VAULT_EVENT_V2_FIELDS,
  read: readVaultEventV2,
  write: writeVaultEventV2,
  leaves: vaultEventV2Leaves,
};

// ---- SwapEventV2 -----------------------------------------------------------------

/** The fixed serialized width of `SwapEventV2`. */
export const SWAP_EVENT_V2_LEN = 498;

/** `SwapEventV2`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const SWAP_EVENT_V2_FIELDS: readonly FieldSpec[] = [
  { path: 'format_version', type: 'u8', offset: 0, width: 1 },
  { path: 'sender', type: '[u8; 32]', offset: 1, width: 32 },
  { path: 'request_nonce', type: 'u64', offset: 33, width: 8 },
  { path: 'key_version', type: 'u8', offset: 41, width: 1 },
  { path: 'path', type: '[u8; 32]', offset: 42, width: 32 },
  { path: 'algo', type: 'u8', offset: 74, width: 1 },
  { path: 'dest', type: 'u8', offset: 75, width: 1 },
  { path: 'params', type: '[u8; 64]', offset: 76, width: 64 },
  { path: 'tx_param_type', type: 'u8', offset: 140, width: 1 },
  { path: 'tx_params.chain_id', type: 'u64', offset: 141, width: 8 },
  { path: 'tx_params.nonce', type: 'u64', offset: 149, width: 8 },
  { path: 'tx_params.max_priority_fee_per_gas', type: 'u128', offset: 157, width: 16 },
  { path: 'tx_params.max_fee_per_gas', type: 'u128', offset: 173, width: 16 },
  { path: 'tx_params.gas_limit', type: 'u64', offset: 189, width: 8 },
  { path: 'tx_params.to', type: '[u8; 20]', offset: 197, width: 20 },
  { path: 'tx_params.value', type: 'u128', offset: 217, width: 16 },
  { path: 'tx_params.calldata.is_some', type: 'bool', offset: 233, width: 1 },
  { path: 'tx_params.calldata.value.selector', type: '[u8; 4]', offset: 234, width: 4 },
  { path: 'tx_params.calldata.value.no_words', type: 'u16', offset: 238, width: 2 },
  { path: 'tx_params.calldata.value.words[0]', type: '[u8; 32]', offset: 240, width: 32 },
  { path: 'tx_params.calldata.value.words[1]', type: '[u8; 32]', offset: 272, width: 32 },
  { path: 'tx_params.calldata.value.words[2]', type: '[u8; 32]', offset: 304, width: 32 },
  { path: 'tx_params.calldata.value.words[3]', type: '[u8; 32]', offset: 336, width: 32 },
  { path: 'tx_params.calldata.value.words[4]', type: '[u8; 32]', offset: 368, width: 32 },
  { path: 'tx_params.calldata.value.words[5]', type: '[u8; 32]', offset: 400, width: 32 },
  { path: 'tx_params.calldata.value.words[6]', type: '[u8; 32]', offset: 432, width: 32 },
  { path: 'tx_params.access_list_entry_count', type: 'u8', offset: 464, width: 1 },
  { path: 'caip2_id', type: '[u8; 32]', offset: 465, width: 32 },
  { path: 'response_kind', type: 'u8', offset: 497, width: 1 },
];

export interface SwapEventV2 {
  readonly formatVersion: number;
  readonly sender: Uint8Array;
  readonly requestNonce: bigint;
  readonly keyVersion: number;
  readonly path: Uint8Array;
  readonly algo: number;
  readonly dest: number;
  readonly params: Uint8Array;
  readonly txParamType: number;
  readonly txParams: {
    readonly chainId: bigint;
    readonly nonce: bigint;
    readonly maxPriorityFeePerGas: bigint;
    readonly maxFeePerGas: bigint;
    readonly gasLimit: bigint;
    readonly to: Uint8Array;
    readonly value: bigint;
    readonly calldata: {
      readonly isSome: boolean;
      readonly value: {
        readonly selector: Uint8Array;
        readonly noWords: number;
        readonly words: readonly [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
      };
    };
    readonly accessListEntryCount: number;
  };
  readonly caip2Id: Uint8Array;
  readonly responseKind: number;
}

/** Read a `SwapEventV2` from `bytes` at `offset` — 498 bytes, fixed. */
export function readSwapEventV2(bytes: Uint8Array, offset = 0): SwapEventV2 {
  const view = checkedView(bytes, offset, SWAP_EVENT_V2_LEN);
  // The version byte FIRST — `spec/borsh-subset.md` §6: a decoder reads byte 0
  // and rejects a record whose format it does not know, BY NAME, before it
  // reads a single offset that format may have moved.
  const version = getU8(view, 0);
  if (version !== RECORD_FORMAT_VERSION) {
    throw new Error(
      'record-version: expected 0x80, got 0x' + version.toString(16).padStart(2, '0'),
    );
  }
  return {
    formatVersion: getU8(view, 0),
    sender: getBytes(view, 1, 32),
    requestNonce: getU64(view, 33),
    keyVersion: getU8(view, 41),
    path: getBytes(view, 42, 32),
    algo: getU8(view, 74),
    dest: getU8(view, 75),
    params: getBytes(view, 76, 64),
    txParamType: getU8(view, 140),
    txParams: {
      chainId: getU64(view, 141),
      nonce: getU64(view, 149),
      maxPriorityFeePerGas: getU128(view, 157),
      maxFeePerGas: getU128(view, 173),
      gasLimit: getU64(view, 189),
      to: getBytes(view, 197, 20),
      value: getU128(view, 217),
      calldata: {
        isSome: getBool(view, 233),
        value: {
          selector: getBytes(view, 234, 4),
          noWords: getU16(view, 238),
          words: [
            getBytes(view, 240, 32),
            getBytes(view, 272, 32),
            getBytes(view, 304, 32),
            getBytes(view, 336, 32),
            getBytes(view, 368, 32),
            getBytes(view, 400, 32),
            getBytes(view, 432, 32),
          ],
        },
      },
      accessListEntryCount: getU8(view, 464),
    },
    caip2Id: getBytes(view, 465, 32),
    responseKind: getU8(view, 497),
  };
}

/** Write a `SwapEventV2` into `out` at `offset`, and return `out`. */
export function writeSwapEventV2(
  value: SwapEventV2,
  out = new Uint8Array(SWAP_EVENT_V2_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, SWAP_EVENT_V2_LEN);
  setU8(view, 0, value.formatVersion);
  setBytes(view, 1, 32, value.sender);
  setU64(view, 33, value.requestNonce);
  setU8(view, 41, value.keyVersion);
  setBytes(view, 42, 32, value.path);
  setU8(view, 74, value.algo);
  setU8(view, 75, value.dest);
  setBytes(view, 76, 64, value.params);
  setU8(view, 140, value.txParamType);
  setU64(view, 141, value.txParams.chainId);
  setU64(view, 149, value.txParams.nonce);
  setU128(view, 157, value.txParams.maxPriorityFeePerGas);
  setU128(view, 173, value.txParams.maxFeePerGas);
  setU64(view, 189, value.txParams.gasLimit);
  setBytes(view, 197, 20, value.txParams.to);
  setU128(view, 217, value.txParams.value);
  setBool(view, 233, value.txParams.calldata.isSome);
  setBytes(view, 234, 4, value.txParams.calldata.value.selector);
  setU16(view, 238, value.txParams.calldata.value.noWords);
  setBytes(view, 240, 32, value.txParams.calldata.value.words[0]);
  setBytes(view, 272, 32, value.txParams.calldata.value.words[1]);
  setBytes(view, 304, 32, value.txParams.calldata.value.words[2]);
  setBytes(view, 336, 32, value.txParams.calldata.value.words[3]);
  setBytes(view, 368, 32, value.txParams.calldata.value.words[4]);
  setBytes(view, 400, 32, value.txParams.calldata.value.words[5]);
  setBytes(view, 432, 32, value.txParams.calldata.value.words[6]);
  setU8(view, 464, value.txParams.accessListEntryCount);
  setBytes(view, 465, 32, value.caip2Id);
  setU8(view, 497, value.responseKind);
  return out;
}

/** `SwapEventV2`'s leaves, in declaration order — one per `SWAP_EVENT_V2_FIELDS` entry. */
export function swapEventV2Leaves(value: SwapEventV2): readonly LeafValue[] {
  return [
    value.formatVersion,
    value.sender,
    value.requestNonce,
    value.keyVersion,
    value.path,
    value.algo,
    value.dest,
    value.params,
    value.txParamType,
    value.txParams.chainId,
    value.txParams.nonce,
    value.txParams.maxPriorityFeePerGas,
    value.txParams.maxFeePerGas,
    value.txParams.gasLimit,
    value.txParams.to,
    value.txParams.value,
    value.txParams.calldata.isSome,
    value.txParams.calldata.value.selector,
    value.txParams.calldata.value.noWords,
    value.txParams.calldata.value.words[0],
    value.txParams.calldata.value.words[1],
    value.txParams.calldata.value.words[2],
    value.txParams.calldata.value.words[3],
    value.txParams.calldata.value.words[4],
    value.txParams.calldata.value.words[5],
    value.txParams.calldata.value.words[6],
    value.txParams.accessListEntryCount,
    value.caip2Id,
    value.responseKind,
  ];
}

export const swapEventV2Codec: Codec<SwapEventV2> = {
  name: 'SwapEventV2',
  byteLength: SWAP_EVENT_V2_LEN,
  fields: SWAP_EVENT_V2_FIELDS,
  read: readSwapEventV2,
  write: writeSwapEventV2,
  leaves: swapEventV2Leaves,
};

// ---- ClaimOutput -----------------------------------------------------------------

/** The fixed serialized width of `ClaimOutput`. */
export const CLAIM_OUTPUT_LEN = 1;

/** `ClaimOutput`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const CLAIM_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'success', type: 'u8', offset: 0, width: 1 },
];

export interface ClaimOutput {
  readonly success: number;
}

/** Read a `ClaimOutput` from `bytes` at `offset` — 1 byte, fixed. */
export function readClaimOutput(bytes: Uint8Array, offset = 0): ClaimOutput {
  const view = checkedView(bytes, offset, CLAIM_OUTPUT_LEN);
  return {
    success: getU8(view, 0),
  };
}

/** Write a `ClaimOutput` into `out` at `offset`, and return `out`. */
export function writeClaimOutput(
  value: ClaimOutput,
  out = new Uint8Array(CLAIM_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, CLAIM_OUTPUT_LEN);
  setU8(view, 0, value.success);
  return out;
}

/** `ClaimOutput`'s leaves, in declaration order — one per `CLAIM_OUTPUT_FIELDS` entry. */
export function claimOutputLeaves(value: ClaimOutput): readonly LeafValue[] {
  return [
    value.success,
  ];
}

export const claimOutputCodec: Codec<ClaimOutput> = {
  name: 'ClaimOutput',
  byteLength: CLAIM_OUTPUT_LEN,
  fields: CLAIM_OUTPUT_FIELDS,
  read: readClaimOutput,
  write: writeClaimOutput,
  leaves: claimOutputLeaves,
};

// ---- CompleteWithdrawOutput ------------------------------------------------------

/** The fixed serialized width of `CompleteWithdrawOutput`. */
export const COMPLETE_WITHDRAW_OUTPUT_LEN = 1;

/** `CompleteWithdrawOutput`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const COMPLETE_WITHDRAW_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'success', type: 'u8', offset: 0, width: 1 },
];

export interface CompleteWithdrawOutput {
  readonly success: number;
}

/** Read a `CompleteWithdrawOutput` from `bytes` at `offset` — 1 byte, fixed. */
export function readCompleteWithdrawOutput(bytes: Uint8Array, offset = 0): CompleteWithdrawOutput {
  const view = checkedView(bytes, offset, COMPLETE_WITHDRAW_OUTPUT_LEN);
  return {
    success: getU8(view, 0),
  };
}

/** Write a `CompleteWithdrawOutput` into `out` at `offset`, and return `out`. */
export function writeCompleteWithdrawOutput(
  value: CompleteWithdrawOutput,
  out = new Uint8Array(COMPLETE_WITHDRAW_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, COMPLETE_WITHDRAW_OUTPUT_LEN);
  setU8(view, 0, value.success);
  return out;
}

/** `CompleteWithdrawOutput`'s leaves, in declaration order — one per `COMPLETE_WITHDRAW_OUTPUT_FIELDS` entry. */
export function completeWithdrawOutputLeaves(value: CompleteWithdrawOutput): readonly LeafValue[] {
  return [
    value.success,
  ];
}

export const completeWithdrawOutputCodec: Codec<CompleteWithdrawOutput> = {
  name: 'CompleteWithdrawOutput',
  byteLength: COMPLETE_WITHDRAW_OUTPUT_LEN,
  fields: COMPLETE_WITHDRAW_OUTPUT_FIELDS,
  read: readCompleteWithdrawOutput,
  write: writeCompleteWithdrawOutput,
  leaves: completeWithdrawOutputLeaves,
};

// ---- RefundOutput ----------------------------------------------------------------

/** The fixed serialized width of `RefundOutput`. */
export const REFUND_OUTPUT_LEN = 5;

/** `RefundOutput`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const REFUND_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'failure', type: '[u8; 5]', offset: 0, width: 5 },
];

export interface RefundOutput {
  readonly failure: Uint8Array;
}

/** Read a `RefundOutput` from `bytes` at `offset` — 5 bytes, fixed. */
export function readRefundOutput(bytes: Uint8Array, offset = 0): RefundOutput {
  const view = checkedView(bytes, offset, REFUND_OUTPUT_LEN);
  return {
    failure: getBytes(view, 0, 5),
  };
}

/** Write a `RefundOutput` into `out` at `offset`, and return `out`. */
export function writeRefundOutput(
  value: RefundOutput,
  out = new Uint8Array(REFUND_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, REFUND_OUTPUT_LEN);
  setBytes(view, 0, 5, value.failure);
  return out;
}

/** `RefundOutput`'s leaves, in declaration order — one per `REFUND_OUTPUT_FIELDS` entry. */
export function refundOutputLeaves(value: RefundOutput): readonly LeafValue[] {
  return [
    value.failure,
  ];
}

export const refundOutputCodec: Codec<RefundOutput> = {
  name: 'RefundOutput',
  byteLength: REFUND_OUTPUT_LEN,
  fields: REFUND_OUTPUT_FIELDS,
  read: readRefundOutput,
  write: writeRefundOutput,
  leaves: refundOutputLeaves,
};

// ---- CompleteSwapOutput ----------------------------------------------------------

/** The fixed serialized width of `CompleteSwapOutput`. */
export const COMPLETE_SWAP_OUTPUT_LEN = 8;

/** `CompleteSwapOutput`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const COMPLETE_SWAP_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'amount_in', type: 'u64', offset: 0, width: 8 },
];

export interface CompleteSwapOutput {
  readonly amountIn: bigint;
}

/** Read a `CompleteSwapOutput` from `bytes` at `offset` — 8 bytes, fixed. */
export function readCompleteSwapOutput(bytes: Uint8Array, offset = 0): CompleteSwapOutput {
  const view = checkedView(bytes, offset, COMPLETE_SWAP_OUTPUT_LEN);
  return {
    amountIn: getU64(view, 0),
  };
}

/** Write a `CompleteSwapOutput` into `out` at `offset`, and return `out`. */
export function writeCompleteSwapOutput(
  value: CompleteSwapOutput,
  out = new Uint8Array(COMPLETE_SWAP_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, COMPLETE_SWAP_OUTPUT_LEN);
  setU64(view, 0, value.amountIn);
  return out;
}

/** `CompleteSwapOutput`'s leaves, in declaration order — one per `COMPLETE_SWAP_OUTPUT_FIELDS` entry. */
export function completeSwapOutputLeaves(value: CompleteSwapOutput): readonly LeafValue[] {
  return [
    value.amountIn,
  ];
}

export const completeSwapOutputCodec: Codec<CompleteSwapOutput> = {
  name: 'CompleteSwapOutput',
  byteLength: COMPLETE_SWAP_OUTPUT_LEN,
  fields: COMPLETE_SWAP_OUTPUT_FIELDS,
  read: readCompleteSwapOutput,
  write: writeCompleteSwapOutput,
  leaves: completeSwapOutputLeaves,
};

// ---- AttestationPreimage<ClaimOutput> --------------------------------------------

/** The fixed serialized width of `AttestationPreimage<ClaimOutput>`. */
export const ATTESTATION_PREIMAGE_CLAIM_OUTPUT_LEN = 33;

/** `AttestationPreimage<ClaimOutput>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_CLAIM_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.success', type: 'u8', offset: 32, width: 1 },
];

export interface AttestationPreimageClaimOutput {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly success: number;
  };
}

/** Read a `AttestationPreimage<ClaimOutput>` from `bytes` at `offset` — 33 bytes, fixed. */
export function readAttestationPreimageClaimOutput(bytes: Uint8Array, offset = 0): AttestationPreimageClaimOutput {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_CLAIM_OUTPUT_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      success: getU8(view, 32),
    },
  };
}

/** Write a `AttestationPreimage<ClaimOutput>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageClaimOutput(
  value: AttestationPreimageClaimOutput,
  out = new Uint8Array(ATTESTATION_PREIMAGE_CLAIM_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_CLAIM_OUTPUT_LEN);
  setBytes(view, 0, 32, value.requestId);
  setU8(view, 32, value.output.success);
  return out;
}

/** `AttestationPreimage<ClaimOutput>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_CLAIM_OUTPUT_FIELDS` entry. */
export function attestationPreimageClaimOutputLeaves(value: AttestationPreimageClaimOutput): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.success,
  ];
}

export const attestationPreimageClaimOutputCodec: Codec<AttestationPreimageClaimOutput> = {
  name: 'AttestationPreimage<ClaimOutput>',
  byteLength: ATTESTATION_PREIMAGE_CLAIM_OUTPUT_LEN,
  fields: ATTESTATION_PREIMAGE_CLAIM_OUTPUT_FIELDS,
  read: readAttestationPreimageClaimOutput,
  write: writeAttestationPreimageClaimOutput,
  leaves: attestationPreimageClaimOutputLeaves,
};

// ---- AttestationPreimage<CompleteWithdrawOutput> ---------------------------------

/** The fixed serialized width of `AttestationPreimage<CompleteWithdrawOutput>`. */
export const ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_LEN = 33;

/** `AttestationPreimage<CompleteWithdrawOutput>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.success', type: 'u8', offset: 32, width: 1 },
];

export interface AttestationPreimageCompleteWithdrawOutput {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly success: number;
  };
}

/** Read a `AttestationPreimage<CompleteWithdrawOutput>` from `bytes` at `offset` — 33 bytes, fixed. */
export function readAttestationPreimageCompleteWithdrawOutput(bytes: Uint8Array, offset = 0): AttestationPreimageCompleteWithdrawOutput {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      success: getU8(view, 32),
    },
  };
}

/** Write a `AttestationPreimage<CompleteWithdrawOutput>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageCompleteWithdrawOutput(
  value: AttestationPreimageCompleteWithdrawOutput,
  out = new Uint8Array(ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_LEN);
  setBytes(view, 0, 32, value.requestId);
  setU8(view, 32, value.output.success);
  return out;
}

/** `AttestationPreimage<CompleteWithdrawOutput>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_FIELDS` entry. */
export function attestationPreimageCompleteWithdrawOutputLeaves(value: AttestationPreimageCompleteWithdrawOutput): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.success,
  ];
}

export const attestationPreimageCompleteWithdrawOutputCodec: Codec<AttestationPreimageCompleteWithdrawOutput> = {
  name: 'AttestationPreimage<CompleteWithdrawOutput>',
  byteLength: ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_LEN,
  fields: ATTESTATION_PREIMAGE_COMPLETE_WITHDRAW_OUTPUT_FIELDS,
  read: readAttestationPreimageCompleteWithdrawOutput,
  write: writeAttestationPreimageCompleteWithdrawOutput,
  leaves: attestationPreimageCompleteWithdrawOutputLeaves,
};

// ---- AttestationPreimage<RefundOutput> -------------------------------------------

/** The fixed serialized width of `AttestationPreimage<RefundOutput>`. */
export const ATTESTATION_PREIMAGE_REFUND_OUTPUT_LEN = 37;

/** `AttestationPreimage<RefundOutput>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_REFUND_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.failure', type: '[u8; 5]', offset: 32, width: 5 },
];

export interface AttestationPreimageRefundOutput {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly failure: Uint8Array;
  };
}

/** Read a `AttestationPreimage<RefundOutput>` from `bytes` at `offset` — 37 bytes, fixed. */
export function readAttestationPreimageRefundOutput(bytes: Uint8Array, offset = 0): AttestationPreimageRefundOutput {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_REFUND_OUTPUT_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      failure: getBytes(view, 32, 5),
    },
  };
}

/** Write a `AttestationPreimage<RefundOutput>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageRefundOutput(
  value: AttestationPreimageRefundOutput,
  out = new Uint8Array(ATTESTATION_PREIMAGE_REFUND_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_REFUND_OUTPUT_LEN);
  setBytes(view, 0, 32, value.requestId);
  setBytes(view, 32, 5, value.output.failure);
  return out;
}

/** `AttestationPreimage<RefundOutput>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_REFUND_OUTPUT_FIELDS` entry. */
export function attestationPreimageRefundOutputLeaves(value: AttestationPreimageRefundOutput): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.failure,
  ];
}

export const attestationPreimageRefundOutputCodec: Codec<AttestationPreimageRefundOutput> = {
  name: 'AttestationPreimage<RefundOutput>',
  byteLength: ATTESTATION_PREIMAGE_REFUND_OUTPUT_LEN,
  fields: ATTESTATION_PREIMAGE_REFUND_OUTPUT_FIELDS,
  read: readAttestationPreimageRefundOutput,
  write: writeAttestationPreimageRefundOutput,
  leaves: attestationPreimageRefundOutputLeaves,
};

// ---- AttestationPreimage<CompleteSwapOutput> -------------------------------------

/** The fixed serialized width of `AttestationPreimage<CompleteSwapOutput>`. */
export const ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_LEN = 40;

/** `AttestationPreimage<CompleteSwapOutput>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.amount_in', type: 'u64', offset: 32, width: 8 },
];

export interface AttestationPreimageCompleteSwapOutput {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly amountIn: bigint;
  };
}

/** Read a `AttestationPreimage<CompleteSwapOutput>` from `bytes` at `offset` — 40 bytes, fixed. */
export function readAttestationPreimageCompleteSwapOutput(bytes: Uint8Array, offset = 0): AttestationPreimageCompleteSwapOutput {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      amountIn: getU64(view, 32),
    },
  };
}

/** Write a `AttestationPreimage<CompleteSwapOutput>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageCompleteSwapOutput(
  value: AttestationPreimageCompleteSwapOutput,
  out = new Uint8Array(ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_LEN);
  setBytes(view, 0, 32, value.requestId);
  setU64(view, 32, value.output.amountIn);
  return out;
}

/** `AttestationPreimage<CompleteSwapOutput>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_FIELDS` entry. */
export function attestationPreimageCompleteSwapOutputLeaves(value: AttestationPreimageCompleteSwapOutput): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.amountIn,
  ];
}

export const attestationPreimageCompleteSwapOutputCodec: Codec<AttestationPreimageCompleteSwapOutput> = {
  name: 'AttestationPreimage<CompleteSwapOutput>',
  byteLength: ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_LEN,
  fields: ATTESTATION_PREIMAGE_COMPLETE_SWAP_OUTPUT_FIELDS,
  read: readAttestationPreimageCompleteSwapOutput,
  write: writeAttestationPreimageCompleteSwapOutput,
  leaves: attestationPreimageCompleteSwapOutputLeaves,
};

// ---- VaultResponse ---------------------------------------------------------------

/** The fixed serialized width of `VaultResponse`. */
export const VAULT_RESPONSE_LEN = 2;

/** `VaultResponse`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const VAULT_RESPONSE_FIELDS: readonly FieldSpec[] = [
  { path: 'kind', type: 'u8', offset: 0, width: 1 },
  { path: 'success', type: 'bool', offset: 1, width: 1 },
];

export interface VaultResponse {
  readonly kind: number;
  readonly success: boolean;
}

/** Read a `VaultResponse` from `bytes` at `offset` — 2 bytes, fixed. */
export function readVaultResponse(bytes: Uint8Array, offset = 0): VaultResponse {
  const view = checkedView(bytes, offset, VAULT_RESPONSE_LEN);
  return {
    kind: getU8(view, 0),
    success: getBool(view, 1),
  };
}

/** Write a `VaultResponse` into `out` at `offset`, and return `out`. */
export function writeVaultResponse(
  value: VaultResponse,
  out = new Uint8Array(VAULT_RESPONSE_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, VAULT_RESPONSE_LEN);
  setU8(view, 0, value.kind);
  setBool(view, 1, value.success);
  return out;
}

/** `VaultResponse`'s leaves, in declaration order — one per `VAULT_RESPONSE_FIELDS` entry. */
export function vaultResponseLeaves(value: VaultResponse): readonly LeafValue[] {
  return [
    value.kind,
    value.success,
  ];
}

export const vaultResponseCodec: Codec<VaultResponse> = {
  name: 'VaultResponse',
  byteLength: VAULT_RESPONSE_LEN,
  fields: VAULT_RESPONSE_FIELDS,
  read: readVaultResponse,
  write: writeVaultResponse,
  leaves: vaultResponseLeaves,
};

// ---- SwapResponse ----------------------------------------------------------------

/** The fixed serialized width of `SwapResponse`. */
export const SWAP_RESPONSE_LEN = 9;

/** `SwapResponse`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const SWAP_RESPONSE_FIELDS: readonly FieldSpec[] = [
  { path: 'kind', type: 'u8', offset: 0, width: 1 },
  { path: 'amount_in', type: 'u64', offset: 1, width: 8 },
];

export interface SwapResponse {
  readonly kind: number;
  readonly amountIn: bigint;
}

/** Read a `SwapResponse` from `bytes` at `offset` — 9 bytes, fixed. */
export function readSwapResponse(bytes: Uint8Array, offset = 0): SwapResponse {
  const view = checkedView(bytes, offset, SWAP_RESPONSE_LEN);
  return {
    kind: getU8(view, 0),
    amountIn: getU64(view, 1),
  };
}

/** Write a `SwapResponse` into `out` at `offset`, and return `out`. */
export function writeSwapResponse(
  value: SwapResponse,
  out = new Uint8Array(SWAP_RESPONSE_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, SWAP_RESPONSE_LEN);
  setU8(view, 0, value.kind);
  setU64(view, 1, value.amountIn);
  return out;
}

/** `SwapResponse`'s leaves, in declaration order — one per `SWAP_RESPONSE_FIELDS` entry. */
export function swapResponseLeaves(value: SwapResponse): readonly LeafValue[] {
  return [
    value.kind,
    value.amountIn,
  ];
}

export const swapResponseCodec: Codec<SwapResponse> = {
  name: 'SwapResponse',
  byteLength: SWAP_RESPONSE_LEN,
  fields: SWAP_RESPONSE_FIELDS,
  read: readSwapResponse,
  write: writeSwapResponse,
  leaves: swapResponseLeaves,
};

// ---- FailureResponse -------------------------------------------------------------

/** The fixed serialized width of `FailureResponse`. */
export const FAILURE_RESPONSE_LEN = 1;

/** `FailureResponse`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const FAILURE_RESPONSE_FIELDS: readonly FieldSpec[] = [
  { path: 'kind', type: 'u8', offset: 0, width: 1 },
];

export interface FailureResponse {
  readonly kind: number;
}

/** Read a `FailureResponse` from `bytes` at `offset` — 1 byte, fixed. */
export function readFailureResponse(bytes: Uint8Array, offset = 0): FailureResponse {
  const view = checkedView(bytes, offset, FAILURE_RESPONSE_LEN);
  return {
    kind: getU8(view, 0),
  };
}

/** Write a `FailureResponse` into `out` at `offset`, and return `out`. */
export function writeFailureResponse(
  value: FailureResponse,
  out = new Uint8Array(FAILURE_RESPONSE_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, FAILURE_RESPONSE_LEN);
  setU8(view, 0, value.kind);
  return out;
}

/** `FailureResponse`'s leaves, in declaration order — one per `FAILURE_RESPONSE_FIELDS` entry. */
export function failureResponseLeaves(value: FailureResponse): readonly LeafValue[] {
  return [
    value.kind,
  ];
}

export const failureResponseCodec: Codec<FailureResponse> = {
  name: 'FailureResponse',
  byteLength: FAILURE_RESPONSE_LEN,
  fields: FAILURE_RESPONSE_FIELDS,
  read: readFailureResponse,
  write: writeFailureResponse,
  leaves: failureResponseLeaves,
};

// ---- AttestationPreimage<VaultResponse> ------------------------------------------

/** The fixed serialized width of `AttestationPreimage<VaultResponse>`. */
export const ATTESTATION_PREIMAGE_VAULT_RESPONSE_LEN = 34;

/** `AttestationPreimage<VaultResponse>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_VAULT_RESPONSE_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.kind', type: 'u8', offset: 32, width: 1 },
  { path: 'output.success', type: 'bool', offset: 33, width: 1 },
];

export interface AttestationPreimageVaultResponse {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly kind: number;
    readonly success: boolean;
  };
}

/** Read a `AttestationPreimage<VaultResponse>` from `bytes` at `offset` — 34 bytes, fixed. */
export function readAttestationPreimageVaultResponse(bytes: Uint8Array, offset = 0): AttestationPreimageVaultResponse {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_VAULT_RESPONSE_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      kind: getU8(view, 32),
      success: getBool(view, 33),
    },
  };
}

/** Write a `AttestationPreimage<VaultResponse>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageVaultResponse(
  value: AttestationPreimageVaultResponse,
  out = new Uint8Array(ATTESTATION_PREIMAGE_VAULT_RESPONSE_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_VAULT_RESPONSE_LEN);
  setBytes(view, 0, 32, value.requestId);
  setU8(view, 32, value.output.kind);
  setBool(view, 33, value.output.success);
  return out;
}

/** `AttestationPreimage<VaultResponse>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_VAULT_RESPONSE_FIELDS` entry. */
export function attestationPreimageVaultResponseLeaves(value: AttestationPreimageVaultResponse): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.kind,
    value.output.success,
  ];
}

export const attestationPreimageVaultResponseCodec: Codec<AttestationPreimageVaultResponse> = {
  name: 'AttestationPreimage<VaultResponse>',
  byteLength: ATTESTATION_PREIMAGE_VAULT_RESPONSE_LEN,
  fields: ATTESTATION_PREIMAGE_VAULT_RESPONSE_FIELDS,
  read: readAttestationPreimageVaultResponse,
  write: writeAttestationPreimageVaultResponse,
  leaves: attestationPreimageVaultResponseLeaves,
};

// ---- AttestationPreimage<SwapResponse> -------------------------------------------

/** The fixed serialized width of `AttestationPreimage<SwapResponse>`. */
export const ATTESTATION_PREIMAGE_SWAP_RESPONSE_LEN = 41;

/** `AttestationPreimage<SwapResponse>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_SWAP_RESPONSE_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.kind', type: 'u8', offset: 32, width: 1 },
  { path: 'output.amount_in', type: 'u64', offset: 33, width: 8 },
];

export interface AttestationPreimageSwapResponse {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly kind: number;
    readonly amountIn: bigint;
  };
}

/** Read a `AttestationPreimage<SwapResponse>` from `bytes` at `offset` — 41 bytes, fixed. */
export function readAttestationPreimageSwapResponse(bytes: Uint8Array, offset = 0): AttestationPreimageSwapResponse {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_SWAP_RESPONSE_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      kind: getU8(view, 32),
      amountIn: getU64(view, 33),
    },
  };
}

/** Write a `AttestationPreimage<SwapResponse>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageSwapResponse(
  value: AttestationPreimageSwapResponse,
  out = new Uint8Array(ATTESTATION_PREIMAGE_SWAP_RESPONSE_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_SWAP_RESPONSE_LEN);
  setBytes(view, 0, 32, value.requestId);
  setU8(view, 32, value.output.kind);
  setU64(view, 33, value.output.amountIn);
  return out;
}

/** `AttestationPreimage<SwapResponse>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_SWAP_RESPONSE_FIELDS` entry. */
export function attestationPreimageSwapResponseLeaves(value: AttestationPreimageSwapResponse): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.kind,
    value.output.amountIn,
  ];
}

export const attestationPreimageSwapResponseCodec: Codec<AttestationPreimageSwapResponse> = {
  name: 'AttestationPreimage<SwapResponse>',
  byteLength: ATTESTATION_PREIMAGE_SWAP_RESPONSE_LEN,
  fields: ATTESTATION_PREIMAGE_SWAP_RESPONSE_FIELDS,
  read: readAttestationPreimageSwapResponse,
  write: writeAttestationPreimageSwapResponse,
  leaves: attestationPreimageSwapResponseLeaves,
};

// ---- AttestationPreimage<FailureResponse> ----------------------------------------

/** The fixed serialized width of `AttestationPreimage<FailureResponse>`. */
export const ATTESTATION_PREIMAGE_FAILURE_RESPONSE_LEN = 33;

/** `AttestationPreimage<FailureResponse>`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const ATTESTATION_PREIMAGE_FAILURE_RESPONSE_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'output.kind', type: 'u8', offset: 32, width: 1 },
];

export interface AttestationPreimageFailureResponse {
  readonly requestId: Uint8Array;
  readonly output: {
    readonly kind: number;
  };
}

/** Read a `AttestationPreimage<FailureResponse>` from `bytes` at `offset` — 33 bytes, fixed. */
export function readAttestationPreimageFailureResponse(bytes: Uint8Array, offset = 0): AttestationPreimageFailureResponse {
  const view = checkedView(bytes, offset, ATTESTATION_PREIMAGE_FAILURE_RESPONSE_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    output: {
      kind: getU8(view, 32),
    },
  };
}

/** Write a `AttestationPreimage<FailureResponse>` into `out` at `offset`, and return `out`. */
export function writeAttestationPreimageFailureResponse(
  value: AttestationPreimageFailureResponse,
  out = new Uint8Array(ATTESTATION_PREIMAGE_FAILURE_RESPONSE_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, ATTESTATION_PREIMAGE_FAILURE_RESPONSE_LEN);
  setBytes(view, 0, 32, value.requestId);
  setU8(view, 32, value.output.kind);
  return out;
}

/** `AttestationPreimage<FailureResponse>`'s leaves, in declaration order — one per `ATTESTATION_PREIMAGE_FAILURE_RESPONSE_FIELDS` entry. */
export function attestationPreimageFailureResponseLeaves(value: AttestationPreimageFailureResponse): readonly LeafValue[] {
  return [
    value.requestId,
    value.output.kind,
  ];
}

export const attestationPreimageFailureResponseCodec: Codec<AttestationPreimageFailureResponse> = {
  name: 'AttestationPreimage<FailureResponse>',
  byteLength: ATTESTATION_PREIMAGE_FAILURE_RESPONSE_LEN,
  fields: ATTESTATION_PREIMAGE_FAILURE_RESPONSE_FIELDS,
  read: readAttestationPreimageFailureResponse,
  write: writeAttestationPreimageFailureResponse,
  leaves: attestationPreimageFailureResponseLeaves,
};

// ---- SignBidirectionalMisc -------------------------------------------------------

/** The fixed serialized width of `SignBidirectionalMisc`. */
export const SIGN_BIDIRECTIONAL_MISC_LEN = 161;

/** `SignBidirectionalMisc`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const SIGN_BIDIRECTIONAL_MISC_FIELDS: readonly FieldSpec[] = [
  { path: 'version', type: 'u8', offset: 0, width: 1 },
  { path: 'request_id', type: '[u8; 32]', offset: 1, width: 32 },
  { path: 'payload', type: '[u8; 128]', offset: 33, width: 128 },
];

export interface SignBidirectionalMisc {
  readonly version: number;
  readonly requestId: Uint8Array;
  readonly payload: Uint8Array;
}

/** Read a `SignBidirectionalMisc` from `bytes` at `offset` — 161 bytes, fixed. */
export function readSignBidirectionalMisc(bytes: Uint8Array, offset = 0): SignBidirectionalMisc {
  const view = checkedView(bytes, offset, SIGN_BIDIRECTIONAL_MISC_LEN);
  return {
    version: getU8(view, 0),
    requestId: getBytes(view, 1, 32),
    payload: getBytes(view, 33, 128),
  };
}

/** Write a `SignBidirectionalMisc` into `out` at `offset`, and return `out`. */
export function writeSignBidirectionalMisc(
  value: SignBidirectionalMisc,
  out = new Uint8Array(SIGN_BIDIRECTIONAL_MISC_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, SIGN_BIDIRECTIONAL_MISC_LEN);
  setU8(view, 0, value.version);
  setBytes(view, 1, 32, value.requestId);
  setBytes(view, 33, 128, value.payload);
  return out;
}

/** `SignBidirectionalMisc`'s leaves, in declaration order — one per `SIGN_BIDIRECTIONAL_MISC_FIELDS` entry. */
export function signBidirectionalMiscLeaves(value: SignBidirectionalMisc): readonly LeafValue[] {
  return [
    value.version,
    value.requestId,
    value.payload,
  ];
}

export const signBidirectionalMiscCodec: Codec<SignBidirectionalMisc> = {
  name: 'SignBidirectionalMisc',
  byteLength: SIGN_BIDIRECTIONAL_MISC_LEN,
  fields: SIGN_BIDIRECTIONAL_MISC_FIELDS,
  read: readSignBidirectionalMisc,
  write: writeSignBidirectionalMisc,
  leaves: signBidirectionalMiscLeaves,
};

// ---- RespondMisc -----------------------------------------------------------------

/** The fixed serialized width of `RespondMisc`. */
export const RESPOND_MISC_LEN = 129;

/** `RespondMisc`'s offset table — `spec/borsh-subset.md` §9, as data. */
export const RESPOND_MISC_FIELDS: readonly FieldSpec[] = [
  { path: 'request_id', type: '[u8; 32]', offset: 0, width: 32 },
  { path: 'big_r_x', type: '[u8; 32]', offset: 32, width: 32 },
  { path: 'big_r_y', type: '[u8; 32]', offset: 64, width: 32 },
  { path: 's', type: '[u8; 32]', offset: 96, width: 32 },
  { path: 'recovery_id', type: 'u8', offset: 128, width: 1 },
];

export interface RespondMisc {
  readonly requestId: Uint8Array;
  readonly bigRX: Uint8Array;
  readonly bigRY: Uint8Array;
  readonly s: Uint8Array;
  readonly recoveryId: number;
}

/** Read a `RespondMisc` from `bytes` at `offset` — 129 bytes, fixed. */
export function readRespondMisc(bytes: Uint8Array, offset = 0): RespondMisc {
  const view = checkedView(bytes, offset, RESPOND_MISC_LEN);
  return {
    requestId: getBytes(view, 0, 32),
    bigRX: getBytes(view, 32, 32),
    bigRY: getBytes(view, 64, 32),
    s: getBytes(view, 96, 32),
    recoveryId: getU8(view, 128),
  };
}

/** Write a `RespondMisc` into `out` at `offset`, and return `out`. */
export function writeRespondMisc(
  value: RespondMisc,
  out = new Uint8Array(RESPOND_MISC_LEN),
  offset = 0,
): Uint8Array {
  const view = checkedView(out, offset, RESPOND_MISC_LEN);
  setBytes(view, 0, 32, value.requestId);
  setBytes(view, 32, 32, value.bigRX);
  setBytes(view, 64, 32, value.bigRY);
  setBytes(view, 96, 32, value.s);
  setU8(view, 128, value.recoveryId);
  return out;
}

/** `RespondMisc`'s leaves, in declaration order — one per `RESPOND_MISC_FIELDS` entry. */
export function respondMiscLeaves(value: RespondMisc): readonly LeafValue[] {
  return [
    value.requestId,
    value.bigRX,
    value.bigRY,
    value.s,
    value.recoveryId,
  ];
}

export const respondMiscCodec: Codec<RespondMisc> = {
  name: 'RespondMisc',
  byteLength: RESPOND_MISC_LEN,
  fields: RESPOND_MISC_FIELDS,
  read: readRespondMisc,
  write: writeRespondMisc,
  leaves: respondMiscLeaves,
};

// ---- the registry --------------------------------------------------------------

/**
 * Every codec, under the SPEC's name for its type — the key a vector's
 * `type` carries once its parenthetical annotation is stripped
 * (`'VaultResponse (kind 0, CLAIM, success)'` ↦ `'VaultResponse'`).
 */
export const CODECS: Readonly<Record<string, AnyCodec>> = {
  'bool': boolCodec,
  'u8': u8Codec,
  'u16': u16Codec,
  'u32': u32Codec,
  'u64': u64Codec,
  'u128': u128Codec,
  '[u8; 20]': bytes20Codec,
  '[u8; 32]': bytes32Codec,
  '[u8; 64]': bytes64Codec,
  'Flagged<u32>': flaggedU32Codec,
  'VaultEvent': vaultEventCodec,
  'SwapEvent': swapEventCodec,
  'VaultEventV2': vaultEventV2Codec,
  'SwapEventV2': swapEventV2Codec,
  'ClaimOutput': claimOutputCodec,
  'CompleteWithdrawOutput': completeWithdrawOutputCodec,
  'RefundOutput': refundOutputCodec,
  'CompleteSwapOutput': completeSwapOutputCodec,
  'AttestationPreimage<ClaimOutput>': attestationPreimageClaimOutputCodec,
  'AttestationPreimage<CompleteWithdrawOutput>': attestationPreimageCompleteWithdrawOutputCodec,
  'AttestationPreimage<RefundOutput>': attestationPreimageRefundOutputCodec,
  'AttestationPreimage<CompleteSwapOutput>': attestationPreimageCompleteSwapOutputCodec,
  'VaultResponse': vaultResponseCodec,
  'SwapResponse': swapResponseCodec,
  'FailureResponse': failureResponseCodec,
  'AttestationPreimage<VaultResponse>': attestationPreimageVaultResponseCodec,
  'AttestationPreimage<SwapResponse>': attestationPreimageSwapResponseCodec,
  'AttestationPreimage<FailureResponse>': attestationPreimageFailureResponseCodec,
  'SignBidirectionalMisc': signBidirectionalMiscCodec,
  'RespondMisc': respondMiscCodec,
};
