/**
 * The vector-driven conformance tests for the generated decoder.
 *
 * Every vector in `spec/vectors/*.json` is decoded by the GENERATED codec for
 * its type, checked leaf by leaf against the vector's ordered field list, and
 * re-serialized back to the vector's bytes. The vectors' `hex` is
 * authoritative: it is what the Rust circuits and the two Rust oracles
 * (borsh, serde+bincode-fixint) agree on, byte for byte.
 *
 * Run (from the repository root, inside `nix develop`):
 *     node --test spec/ts/vectors.test.ts
 * Type-check:
 *     tsc --noEmit -p spec/ts
 *
 * No test framework, no `@types/node`, no `node_modules`: `node:test` is
 * node's own runner and `node-builtins.d.ts` declares the handful of node
 * APIs this file uses. The published decoder itself
 * (`borsh-subset.ts` + `primitives.ts`) imports nothing at all.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  CODECS,
  FLAGGED_U32_LEN,
  RECORD_FORMAT_VERSION,
  readFlaggedU32,
  readVaultResponse,
  writeSwapResponse,
  writeVaultResponse,
} from './borsh-subset.ts';
import {
  encodeLeaf,
  fromHex,
  toHex,
  unwrapMiscEnvelope,
  type AnyCodec,
  type LeafValue,
} from './primitives.ts';

// ---- the vector files -----------------------------------------------------------

interface VectorField {
  readonly path: string;
  readonly type: string;
  readonly offset: number;
  readonly width: number;
  readonly hex: string;
  readonly number?: number;
}

interface Vector {
  readonly type: string;
  readonly len: number;
  readonly hex: string;
  readonly sha256: string;
  readonly keccak256: string;
  readonly envelope_hex?: string;
  readonly fields: readonly VectorField[];
}

interface VectorFile {
  readonly format: string;
  readonly spec: string;
  readonly about: string;
  readonly vectors: readonly Vector[];
}

const VECTORS_DIR = join(import.meta.dirname, '..', 'vectors');

const FILES = readdirSync(VECTORS_DIR)
  .filter((name) => name.endsWith('.json'))
  .sort();

function load(file: string): VectorFile {
  return JSON.parse(readFileSync(join(VECTORS_DIR, file), 'utf8')) as VectorFile;
}

/**
 * The registry key for a vector: its type with the parenthetical annotation
 * stripped. `'VaultResponse (kind 0, CLAIM, success)'` is a VALUE of
 * `VaultResponse`, not a type of its own.
 */
function baseName(type: string): string {
  const at = type.indexOf(' (');
  return at === -1 ? type : type.slice(0, at);
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** A leaf's value as an integer, for the vectors' decoded `number`. */
function asBigInt(leaf: LeafValue): bigint {
  if (typeof leaf === 'boolean') return leaf ? 1n : 0n;
  if (typeof leaf === 'number') return BigInt(leaf);
  if (typeof leaf === 'bigint') return leaf;
  throw new TypeError('a byte array has no decoded number');
}

// ---- the checks ------------------------------------------------------------------

function checkVector(codec: AnyCodec, vector: Vector): void {
  const bytes = fromHex(vector.hex);
  assert.equal(bytes.length, vector.len, 'hex is len bytes');
  assert.equal(codec.byteLength, vector.len, 'the generated width is the vector length');
  assert.equal(sha256(bytes), vector.sha256, 'sha256 of the vector bytes');

  // THE OFFSET TABLE: the generated code's fields ARE the vector's field list.
  assert.equal(codec.fields.length, vector.fields.length, 'leaf count');

  const value: unknown = codec.read(bytes);
  const leaves = codec.leaves(value);
  assert.equal(leaves.length, codec.fields.length, 'one leaf per field');

  vector.fields.forEach((expected, i) => {
    const field = codec.fields[i];
    const where = `${vector.type}: field ${i} (${expected.path})`;
    assert.deepEqual(
      { path: field.path, type: field.type, offset: field.offset, width: field.width },
      {
        path: expected.path,
        type: expected.type,
        offset: expected.offset,
        width: expected.width,
      },
      where,
    );
    assert.equal(
      expected.hex,
      vector.hex.slice(2 * expected.offset, 2 * (expected.offset + expected.width)),
      `${where}: the field's hex is the value's own slice`,
    );
    assert.equal(toHex(encodeLeaf(field, leaves[i])), expected.hex, `${where}: decoded leaf`);
    if (expected.number !== undefined) {
      const decoded = asBigInt(leaves[i]);
      // `Number(...)` on both sides because a u128 vector's `number` is past
      // the range JSON numbers hold exactly; the hex above is the real check.
      assert.equal(Number(decoded), expected.number, `${where}: decoded number`);
      if (Number.isSafeInteger(expected.number)) {
        assert.equal(decoded, BigInt(expected.number), `${where}: decoded number, exactly`);
      }
    }
  });

  // RE-SERIALIZATION: write(read(bytes)) is the same bytes.
  assert.equal(toHex(codec.write(value)), vector.hex, 'round trip');

  // …including into the middle of somebody else's buffer.
  const framed = new Uint8Array(vector.len + 5).fill(0xaa);
  codec.write(value, framed, 3);
  assert.equal(toHex(framed.slice(3, 3 + vector.len)), vector.hex, 'round trip at an offset');
  assert.equal(toHex(framed.slice(0, 3)), 'aaaaaa', 'the writer stays inside its own bytes');
  assert.deepEqual(codec.read(framed, 3), value, 'read back at an offset');

  // The 288-byte Misc envelope, where the vector carries one: the payload sits
  // at 32 and the pad is zero, which `unwrapMiscEnvelope` enforces.
  if (vector.envelope_hex !== undefined) {
    const { payload } = unwrapMiscEnvelope(fromHex(vector.envelope_hex), vector.len);
    assert.equal(toHex(payload), vector.hex, 'the envelope carries this payload');
  }
}

// ---- the suite -------------------------------------------------------------------

test('spec/vectors holds vector files', () => {
  assert.ok(FILES.length > 0, 'no vector files found');
});

for (const file of FILES) {
  const parsed = load(file);

  test(`${file}: is a borsh-subset vector file`, () => {
    assert.equal(parsed.format, 'borsh-subset-vectors/1');
    assert.equal(parsed.spec, 'spec/borsh-subset.md');
    assert.ok(parsed.vectors.length > 0, 'the file carries no vectors');
  });

  for (const vector of parsed.vectors) {
    test(`${file}: ${vector.type}`, () => {
      const codec = CODECS[baseName(vector.type)];
      assert.ok(codec, `no generated codec for ${baseName(vector.type)}`);
      checkVector(codec, vector);
    });
  }
}

// ---- the reject rules (spec/borsh-subset.md §7) ------------------------------------

test('reject: a non-boolean success byte (the 0x02 hazard)', () => {
  assert.deepEqual(readVaultResponse(fromHex('0001')), { kind: 0, success: true });
  assert.deepEqual(readVaultResponse(fromHex('0100')), { kind: 1, success: false });
  assert.throws(() => readVaultResponse(fromHex('0002')), /bool at 1 is 0x02/);
});

test('reject: a buffer shorter than the fixed width', () => {
  assert.throws(() => readVaultResponse(fromHex('00')), /the buffer holds 1 bytes/);
  assert.throws(() => readFlaggedU32(fromHex('01deadbe')), /the buffer holds 4 bytes/);
});

test('reject: an out-of-range integer, on the way out', () => {
  assert.throws(() => writeSwapResponse({ kind: 2, amountIn: 1n << 64n }), /outside 0\.\.2\^64/);
  assert.throws(() => writeVaultResponse({ kind: 256, success: true }), /outside 0\.\.2\^8/);
});

test('Flagged<T> is fixed width at BOTH tags — Maybe is never Option', () => {
  assert.equal(FLAGGED_U32_LEN, 5);
  assert.deepEqual(readFlaggedU32(fromHex('01efbeadde')), { isSome: true, value: 0xdeadbeef });
  assert.deepEqual(readFlaggedU32(fromHex('0000000000')), { isSome: false, value: 0 });
});

// ---- the version byte (spec/borsh-subset.md §6) — GENERATED -----------------------
//
// One test per VERSIONED record reader, emitted by
// `crates/minocrab-contracts/tests/serialization/ts_codegen.rs` from the same
// schema walk the readers themselves are walked out of: a record format that
// gains a version byte gains its rejection test in the same regeneration.
//
// Nothing above reaches this rule — every committed vector carries a
// well-formed record, so the version check is only ever satisfied there.

test('reject: readVaultEventV2 on a record whose format version is not 0x80', () => {
  const codec = CODECS['VaultEventV2'];
  const bytes = new Uint8Array(codec.byteLength);
  bytes[0] = RECORD_FORMAT_VERSION;
  assert.equal(codec.read(bytes).formatVersion, RECORD_FORMAT_VERSION);
  for (const wrong of [0x00, 0x01, 0x7f, 0x81, 0xff]) {
    bytes[0] = wrong;
    const hex = wrong.toString(16).padStart(2, '0');
    assert.throws(
      () => codec.read(bytes),
      new RegExp(`record-version: expected 0x80, got 0x${hex}`),
      `version 0x${hex} must be rejected by name`,
    );
  }
});

test('reject: readSwapEventV2 on a record whose format version is not 0x80', () => {
  const codec = CODECS['SwapEventV2'];
  const bytes = new Uint8Array(codec.byteLength);
  bytes[0] = RECORD_FORMAT_VERSION;
  assert.equal(codec.read(bytes).formatVersion, RECORD_FORMAT_VERSION);
  for (const wrong of [0x00, 0x01, 0x7f, 0x81, 0xff]) {
    bytes[0] = wrong;
    const hex = wrong.toString(16).padStart(2, '0');
    assert.throws(
      () => codec.read(bytes),
      new RegExp(`record-version: expected 0x80, got 0x${hex}`),
      `version 0x${hex} must be rejected by name`,
    );
  }
});

test('reject: readRedeemEventV2 on a record whose format version is not 0x80', () => {
  const codec = CODECS['RedeemEventV2'];
  const bytes = new Uint8Array(codec.byteLength);
  bytes[0] = RECORD_FORMAT_VERSION;
  assert.equal(codec.read(bytes).formatVersion, RECORD_FORMAT_VERSION);
  for (const wrong of [0x00, 0x01, 0x7f, 0x81, 0xff]) {
    bytes[0] = wrong;
    const hex = wrong.toString(16).padStart(2, '0');
    assert.throws(
      () => codec.read(bytes),
      new RegExp(`record-version: expected 0x80, got 0x${hex}`),
      `version 0x${hex} must be rejected by name`,
    );
  }
});
