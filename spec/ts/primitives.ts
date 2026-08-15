/**
 * The leaf layer of the circuit-safe Borsh subset: a `DataView` and nothing
 * else.
 *
 * Every offset in `spec/borsh-subset.md` §9 is a compile-time constant, so a
 * decoder for this format is a `DataView` at a published offset — that is
 * what this file is, and it is why `borsh-subset.ts` has no dependencies to
 * install. Borsh integers are LITTLE-ENDIAN, always; the EVM ABI words
 * carried inside these payloads are big-endian by the EVM's own rules and
 * travel as `[u8; 32]` byte arrays, which Borsh does not touch.
 *
 * If you would rather use a library, use one: this IS Borsh, restricted to
 * the fixed-width subset, so `borsh-js` decodes the same bytes from the same
 * declarations (`spec/borsh-subset.md` §12). Nothing here is a dialect.
 *
 * The GETTERS enforce the reject rules the spec lists (§7): a `bool` is
 * `0x00` or `0x01` and nothing else, a buffer must be long enough. The
 * SETTERS enforce the same rules on the way out, at runtime, because these
 * types are erased and a JavaScript caller has none of them.
 */

/** The value of one leaf: the four shapes the subset's leaf table admits. */
export type LeafValue = boolean | number | bigint | Uint8Array;

/**
 * One leaf of a type's layout — a row of the offset table in
 * `spec/borsh-subset.md` §9, and of the `fields` array of every vector in
 * `spec/vectors/*.json`.
 */
export interface FieldSpec {
  /** The declaration path, exactly as the spec prints it (`(the value)` for a bare leaf). */
  readonly path: string;
  /** The leaf type, as the spec's tables spell it: `u64`, `bool`, `[u8; 32]`. */
  readonly type: string;
  readonly offset: number;
  readonly width: number;
}

/** A generated reader/writer pair, with the offset table it was generated from. */
export interface Codec<T> {
  /** The spec's name for the type. */
  readonly name: string;
  /** The fixed serialized width — the whole point of the subset. */
  readonly byteLength: number;
  /** The offset table, in declaration order. */
  readonly fields: readonly FieldSpec[];
  read(bytes: Uint8Array, offset?: number): T;
  write(value: T, out?: Uint8Array, offset?: number): Uint8Array;
  /** The value's leaves, in declaration order — one per entry of `fields`. */
  leaves(value: T): readonly LeafValue[];
}

/** A codec whose type is not statically known, as the registry holds them. */
export type AnyCodec = Codec<any>;

export function fail(message: string): never {
  throw new RangeError(`borsh-subset: ${message}`);
}

/**
 * A `DataView` over exactly the `length` bytes of `bytes` at `offset`, so
 * every accessor below indexes with the SPEC's offset and a read past the end
 * of the value is impossible rather than merely unlikely.
 */
export function checkedView(bytes: Uint8Array, offset: number, length: number): DataView {
  if (!Number.isInteger(offset) || offset < 0) {
    fail(`offset ${offset} is not a non-negative integer`);
  }
  const available = bytes.length - offset;
  if (available < length) {
    fail(`the buffer holds ${available} bytes at offset ${offset}, the value is ${length}`);
  }
  return new DataView(bytes.buffer, bytes.byteOffset + offset, length);
}

// ---- getters -----------------------------------------------------------------

export function getBool(view: DataView, at: number): boolean {
  const byte = view.getUint8(at);
  if (byte > 1) {
    fail(`bool at ${at} is 0x${byte.toString(16).padStart(2, '0')} — a Borsh bool is 0x00 or 0x01`);
  }
  return byte === 1;
}

export function getU8(view: DataView, at: number): number {
  return view.getUint8(at);
}

export function getU16(view: DataView, at: number): number {
  return view.getUint16(at, true);
}

export function getU32(view: DataView, at: number): number {
  return view.getUint32(at, true);
}

export function getU64(view: DataView, at: number): bigint {
  return view.getBigUint64(at, true);
}

export function getU128(view: DataView, at: number): bigint {
  const low = view.getBigUint64(at, true);
  const high = view.getBigUint64(at + 8, true);
  return (high << 64n) | low;
}

/** A COPY of the `width` bytes at `at`, in string order. */
export function getBytes(view: DataView, at: number, width: number): Uint8Array {
  return new Uint8Array(view.buffer, view.byteOffset + at, width).slice();
}

// ---- setters -----------------------------------------------------------------

export function setBool(view: DataView, at: number, value: boolean): void {
  if (typeof value !== 'boolean') fail(`bool at ${at} is ${typeof value}, not a boolean`);
  view.setUint8(at, value ? 1 : 0);
}

function checkNumber(at: number, value: number, bits: number): void {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    fail(`u${bits} at ${at} is not an integer`);
  }
  if (value < 0 || value > 2 ** bits - 1) {
    fail(`u${bits} at ${at} is ${value}, outside 0..2^${bits}`);
  }
}

export function setU8(view: DataView, at: number, value: number): void {
  checkNumber(at, value, 8);
  view.setUint8(at, value);
}

export function setU16(view: DataView, at: number, value: number): void {
  checkNumber(at, value, 16);
  view.setUint16(at, value, true);
}

export function setU32(view: DataView, at: number, value: number): void {
  checkNumber(at, value, 32);
  view.setUint32(at, value, true);
}

function checkBig(at: number, value: bigint, bits: number): void {
  if (typeof value !== 'bigint') fail(`u${bits} at ${at} is ${typeof value}, not a bigint`);
  if (value < 0n || value >= 1n << BigInt(bits)) {
    fail(`u${bits} at ${at} is ${value}, outside 0..2^${bits}`);
  }
}

export function setU64(view: DataView, at: number, value: bigint): void {
  checkBig(at, value, 64);
  view.setBigUint64(at, value, true);
}

export function setU128(view: DataView, at: number, value: bigint): void {
  checkBig(at, value, 128);
  view.setBigUint64(at, value & 0xffff_ffff_ffff_ffffn, true);
  view.setBigUint64(at + 8, value >> 64n, true);
}

export function setBytes(view: DataView, at: number, width: number, value: Uint8Array): void {
  if (!(value instanceof Uint8Array)) fail(`[u8; ${width}] at ${at} is not a Uint8Array`);
  if (value.length !== width) {
    fail(`[u8; ${width}] at ${at} was given ${value.length} bytes — this format is fixed-width`);
  }
  new Uint8Array(view.buffer, view.byteOffset + at, width).set(value);
}

// ---- leaves, generically -------------------------------------------------------

/** `true` for the leaf types whose bytes ARE their value. */
function byteArrayWidth(type: string): number | undefined {
  const match = /^\[u8; (\d+)\]$/.exec(type);
  return match === null ? undefined : Number(match[1]);
}

/**
 * One leaf's bytes, from its [`FieldSpec`] and its value — the same encoding
 * the generated writers use, reached by the field's declared TYPE rather than
 * by its position. Used to check a decoded value leaf by leaf against
 * `spec/vectors/*.json`.
 */
export function encodeLeaf(field: FieldSpec, value: LeafValue): Uint8Array {
  const bytes = new Uint8Array(field.width);
  const view = new DataView(bytes.buffer);
  const width = byteArrayWidth(field.type);
  if (width !== undefined) {
    setBytes(view, 0, width, value as Uint8Array);
    return bytes;
  }
  switch (field.type) {
    case 'bool':
      setBool(view, 0, value as boolean);
      return bytes;
    case 'u8':
      setU8(view, 0, value as number);
      return bytes;
    case 'u16':
      setU16(view, 0, value as number);
      return bytes;
    case 'u32':
      setU32(view, 0, value as number);
      return bytes;
    case 'u64':
      setU64(view, 0, value as bigint);
      return bytes;
    case 'u128':
      setU128(view, 0, value as bigint);
      return bytes;
    default:
      return fail(`${field.path}: ${field.type} is not a leaf of the subset`);
  }
}

// ---- hex ------------------------------------------------------------------------

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) fail(`hex string of odd length ${hex.length}`);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
    if (Number.isNaN(byte)) fail(`hex string has a non-hex digit at ${2 * i}`);
    bytes[i] = byte;
  }
  return bytes;
}

// ---- the padded envelope ---------------------------------------------------------

/**
 * The `Misc` log envelope (`spec/borsh-subset.md` §6): `pad(32, eventName)`
 * then the Borsh payload then ZEROS to 288 bytes. The one layout in the spec
 * that is not itself a Borsh struct — the deployed circuit hashes all 288
 * bytes, so the trailing zeros are REQUIRED, not optional.
 */
export const MISC_ENVELOPE_LEN = 288;
export const MISC_NAME_LEN = 32;

/**
 * The event name and the payload of a 288-byte `Misc` value, with the padding
 * rule CHECKED: bytes `32 + payloadLength .. 288` must be zero.
 */
export function unwrapMiscEnvelope(
  envelope: Uint8Array,
  payloadLength: number,
): { name: Uint8Array; payload: Uint8Array } {
  if (envelope.length !== MISC_ENVELOPE_LEN) {
    fail(`a Misc value is ${MISC_ENVELOPE_LEN} bytes, this one is ${envelope.length}`);
  }
  const end = MISC_NAME_LEN + payloadLength;
  if (end > MISC_ENVELOPE_LEN) fail(`a ${payloadLength}-byte payload does not fit a Misc value`);
  for (let i = end; i < MISC_ENVELOPE_LEN; i += 1) {
    if (envelope[i] !== 0) fail(`the Misc pad is non-zero at ${i} — the pad is part of the preimage`);
  }
  return {
    name: envelope.slice(0, MISC_NAME_LEN),
    payload: envelope.slice(MISC_NAME_LEN, end),
  };
}
