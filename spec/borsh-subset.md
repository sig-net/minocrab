# The Borsh fixed-width subset — Signet on Midnight

**THIS IS A SUBSET OF BORSH. IT IS NOT A SEPARATE FORMAT.**

Every byte described here is valid canonical [Borsh](https://borsh.io) for the
declared types. Any Borsh implementation — `borsh-js`, `borsh-rs`, `borsh-go`,
`borsh-py` — parses these payloads from the same type declarations. Nothing is
redefined, no framing is added, no field is reordered, and no length or tag is
invented. If you already have a Borsh library, you already have a decoder: write
the struct declarations in this document and call it.

The subset exists for exactly one reason: **a circuit cannot have
data-dependent layout.** A zero-knowledge circuit's instruction stream is fixed
before any value exists, so every field offset has to be a compile-time
constant. The subset is therefore the part of Borsh whose encodings are
fixed-width — and Borsh's own value-dependent shapes (`Vec`, `String`,
`Option`, data-carrying enums) are spelled with fixed-width ones instead.

**Audience.** Anyone implementing the other side of this wire: the TypeScript
indexer/tx-builder, and the MPC node that reads request records and signs
attestations.

---

## 1. The subset

A type is in the subset if its Borsh encoding has the same width at every
value. Concretely:

```
value   ::= leaf | array | struct
leaf    ::= bool | u8 | u16 | u32 | u64 | u128 | [u8; N]
array   ::= [T; K]          -- K a compile-time constant, elements concatenated
struct  ::= field*          -- fields concatenated in DECLARATION ORDER
```

### Leaf table

| type | width | encoding |
|---|---:|---|
| `bool` | 1 | `0x00` = false, `0x01` = true; **no other byte is valid** |
| `u8` | 1 | the byte |
| `u16` | 2 | little-endian |
| `u32` | 4 | little-endian |
| `u64` | 8 | little-endian |
| `u128` | 16 | little-endian |
| `[u8; N]` | N | the bytes, in string order, no length prefix |
| `[T; K]` | K·width(T) | element 0 first |
| `struct` | Σ widths | fields in declaration order, no padding between them |
| fieldless enum over K variants | 1 | the variant index, which MUST be `< K` |

A struct is the plain concatenation of its fields: there is no alignment
padding anywhere in Borsh, so a `u8` followed by a `u64` occupies bytes 0 and
1..9.

**Integers are little-endian everywhere.** Note that EVM ABI words carried
*inside* these payloads (`words[i]: [u8; 32]`) are **big-endian by the EVM's
own rules** — they are `[u8; 32]` byte arrays here and Borsh does not touch
their contents.

### What is excluded, and what replaces it

| excluded | why it cannot be in a circuit | write this instead |
|---|---|---|
| `Vec<T>`, `String`, maps, sets | a `u32` length prefix makes every following offset depend on the value | `[T; K]` plus a separate count field (the request record does exactly this: `words: [[u8; 32]; K]` with `no_words: u16`) |
| `Option<T>` | Borsh omits the payload on `None`, so the width depends on the tag | **`Flagged<T>`** — see §2 |
| data-carrying enums | the payload width follows the tag | one struct type per kind (that is why `VaultEvent` and `SwapEvent` are separate types), or `{tag, widest payload}` |
| `u24`, `u48`, … | not Borsh primitives | the next width up, with a range check on the value |
| trailing padding | not Borsh at all | see the envelope rule, §3 |

---

## 2. `Maybe` ↦ `Flagged`, never `Option`

**This is the single most important line in this document for an implementer.**

Compact's `Maybe<T>` is not Borsh's `Option<T>`. It is an ordinary struct:

```rust
struct Flagged<T> {   // Compact's Maybe<T>
    is_some: bool,    // 1 byte, 0 or 1
    value: T,         // ALWAYS PRESENT, whatever is_some says
}
```

The payload occupies its bytes whether or not the flag is set. `Flagged<u32>`
is **five** bytes at every value; `Option<u32>` is one byte or five. If you
decode a `Maybe` field as an `Option`, every offset after it will be wrong on
half your inputs.

When `is_some` is `0`, the payload bytes are still there and are conventionally
zero, but a decoder MUST NOT rely on that: skip `width(T)` bytes and ignore
them.

---

## 3. The zero-pad envelope rule

Some fields are fixed-size containers larger than the payload they carry — the
Signet singleton logs a 288-byte `Misc` value whose payloads are 161 and 129
bytes. Trailing padding is **not** Borsh and is not claimed to be. The rule is
stated explicitly instead:

> Bytes `0..LEN` are the canonical Borsh encoding of the declared type. Bytes
> `LEN..N` MUST be zero.

Both halves are enforced in-circuit today — the deployed contract hashes all
288 bytes, so a non-zero pad is a different digest — and a decoder MUST check
the tail rather than merely skipping it: slice to `LEN`, decode, assert the
remainder is zero, reject otherwise.

---

## 4. Reject rules

The malformed classes are FINITE, and this is the complete list. A decoder that
rejects exactly these accepts exactly the encodings this specification defines.
There are no duplicate encodings in the subset: every value has exactly one
byte string, and every byte string of the right length decodes to at most one
value.

| # | class | rule |
|---|---|---|
| 1 | wrong length | the input's length is not the type's `LEN` ⇒ reject. Every type here has a constant width. |
| 2 | non-boolean `bool` | a byte outside `{0x00, 0x01}` in a `bool` position ⇒ reject |
| 3 | tag out of range | an enum/kind byte `≥ K` ⇒ reject |
| 4 | non-zero pad | a non-zero byte in `LEN..N` of a fixed envelope (§3) ⇒ reject |
| 5 | out-of-range leaf | a value wider than its declared field (only reachable when re-encoding) ⇒ reject |

**The in-circuit asymmetry, stated deliberately.** Off-chain, these are
rejections with a reason. In-circuit there is no "reject": a malformed
attestation simply produces a different hash preimage, so the signature check
fails and the transaction is unprovable. Same outcome, different mechanism —
and it is why the circuit does not need a parser (§7).

---

## 5. Attested outputs — the response kinds

What the MPC signs back to the vault. **Byte 0 of every attested output is the
response kind**, which makes cross-circuit replay structurally impossible: a
signature attesting a claim is not a valid signature for a withdrawal, because
the two preimages differ in their first byte.

| kind | name | settles | attested output | LEN |
|---:|---|---|---|---:|
| 0 | `CLAIM` | `claim` | `VaultResponse { kind: u8, success: bool }` | 2 |
| 1 | `WITHDRAW` | `completeWithdraw` | `VaultResponse { kind: u8, success: bool }` | 2 |
| 2 | `SWAP` | `completeSwap` | `SwapResponse { kind: u8, amount_in: u64 }` | 9 |
| 3 | `FAILURE` | `refund` | `FailureResponse { kind: u8 }` | 1 |

Each settle circuit accepts **exactly one** kind and asserts equality with its
own — which is strictly stronger than a `kind < 4` range check, and is the
anti-replay property.

### The signed digest

```
attestationDigest = keccak256(borsh(AttestationPreimage { request_id: [u8; 32], output: T }))
```

Since a Borsh struct is the concatenation of its fields, that is simply the
request id's 32 bytes followed by `borsh(output)`. Preimage widths: **34**
bytes for claim/withdraw, **41** for swap, **33** for refund. The signature over
that digest is unchanged from today: secp256k1 ECDSA under `mpcResponseKey`,
with `bigR.x` and `s` big-endian on the wire.

`amount_in` is little-endian, as Borsh's `u64` always is — which is
byte-for-byte what the deployed 8-byte output already was.

**Two things are gone, on purpose.** The 5-byte `0xdeadbeef01` failure sentinel
(a response *kind* says the same thing, in the byte position every response
puts its kind, without a magic constant agreed out of band); and the acceptance
of a non-boolean success byte (today any byte other than `0x01` routes a
*successful* withdrawal to the refund branch — Borsh's `bool` is `0|1` and
nothing else).

---

## 6. The request record and the request id

The vault stores a request record per pending request, and

```
requestId = keccak256(borsh(record))
```

This is not a new rule: it is what the deployed contract already computes,
proven byte-for-byte against the deployed encoding. The MPC recomputes it and
drops any request whose id does not match, so an implementation that gets one
offset wrong fails closed rather than signing the wrong transaction.

The two instantiations differ only in their calldata word count and schema
string widths: `VaultEvent` (2 words, 404 bytes) for deposit / approveRouter /
withdraw, `SwapEvent` (7 words, 571 bytes) for swap. Their field-by-field
layouts are in §9.

Decoder note, load-bearing: `words` MUST be declared as a fixed array
`[[u8; 32]; K]` with the separate `no_words: u16` count. A `Vec` would add a
4-byte length prefix and every following offset would be wrong.

## 7. The notification payload

`signBidirectional` logs a `Misc` event whose payload is

```rust
struct SignBidirectionalMisc {
    version: u8,          // 1
    request_id: [u8; 32],
    payload: [u8; 128],   // the V1 notification payload, below
}
```

The 128-byte V1 notification payload is built by the callee's own constructor
(`constructSignBidirectionalEventNotificationV1`) and is **not** itself a Borsh
struct — it is a fixed byte block with this layout, stated here because a
reader of the log needs it:

| offset | width | field |
|---:|---:|---|
| 0 | 32 | `callerAddress` — the requesting contract's address |
| 32 | 1 | `requestsPathDepth` |
| 33 | 4 | `requestsPath[0..4]` |
| 37 | 91 | zero |

`respond` and `respondBidirectional` log `RespondMisc` (§9): the request id,
the signature's `bigR.x`, `bigR.y` and `s`, and the recovery id — 129 bytes.

Both payloads sit inside the 288-byte `Misc` envelope: `pad(32, eventName) ‖
payload ‖ zeros`, per §3. `spec/vectors/misc-payloads.json` carries both the
payload and the full envelope.

---

## 8. Two oracles, and a third way to read it

For this subset, **serde + bincode in fixed-int little-endian mode emits
byte-identical output to Borsh**. That is not a coincidence to rely on
casually, but it is useful: it gives an independent second implementation to
test against, and it is how these payloads are checked in CI (a type that
strays outside the subset makes the two encoders disagree — a fieldless enum,
for instance, is 1 byte under Borsh and 4 under bincode-fixint).

A **dependency-free reader is equally valid** and, for a fixed layout, often
simpler: every offset in §9 is a constant, so a `DataView` (or a Go
`encoding/binary` read, or a Rust `from_le_bytes` on a slice) at the published
offset is a complete decoder. Nothing in this format requires a Borsh library —
it requires the offsets, and they are constants.

Whichever you choose, the rejection rules of §4 are part of the format, not
optional hardening.

---

## 9. Byte offsets, per type

**Generated** from the same schema walk the conformance suite checks — this
section is not hand-maintained, and a test fails if the committed tables stop
matching the format. `AttestationPreimage<T>` rows show the whole signed
preimage; the `output.*` rows are the attested output at offset 32.

<!-- BEGIN GENERATED: offset tables -->
### `VaultEvent` — 404 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `sender` | `[u8; 32]` |
| 32 | 8 | `request_nonce` | `u64` |
| 40 | 1 | `key_version` | `u8` |
| 41 | 32 | `path` | `[u8; 32]` |
| 73 | 1 | `algo` | `u8` |
| 74 | 1 | `dest` | `u8` |
| 75 | 64 | `params` | `[u8; 64]` |
| 139 | 1 | `tx_param_type` | `u8` |
| 140 | 8 | `tx_params.chain_id` | `u64` |
| 148 | 8 | `tx_params.nonce` | `u64` |
| 156 | 16 | `tx_params.max_priority_fee_per_gas` | `u128` |
| 172 | 16 | `tx_params.max_fee_per_gas` | `u128` |
| 188 | 8 | `tx_params.gas_limit` | `u64` |
| 196 | 20 | `tx_params.to` | `[u8; 20]` |
| 216 | 16 | `tx_params.value` | `u128` |
| 232 | 1 | `tx_params.calldata.is_some` | `bool` |
| 233 | 4 | `tx_params.calldata.value.selector` | `[u8; 4]` |
| 237 | 2 | `tx_params.calldata.value.no_words` | `u16` |
| 239 | 32 | `tx_params.calldata.value.words[0]` | `[u8; 32]` |
| 271 | 32 | `tx_params.calldata.value.words[1]` | `[u8; 32]` |
| 303 | 1 | `tx_params.access_list_entry_count` | `u8` |
| 304 | 32 | `caip2_id` | `[u8; 32]` |
| 336 | 34 | `output_deserialization_schema` | `[u8; 34]` |
| 370 | 34 | `respond_serialization_schema` | `[u8; 34]` |

### `SwapEvent` — 571 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `sender` | `[u8; 32]` |
| 32 | 8 | `request_nonce` | `u64` |
| 40 | 1 | `key_version` | `u8` |
| 41 | 32 | `path` | `[u8; 32]` |
| 73 | 1 | `algo` | `u8` |
| 74 | 1 | `dest` | `u8` |
| 75 | 64 | `params` | `[u8; 64]` |
| 139 | 1 | `tx_param_type` | `u8` |
| 140 | 8 | `tx_params.chain_id` | `u64` |
| 148 | 8 | `tx_params.nonce` | `u64` |
| 156 | 16 | `tx_params.max_priority_fee_per_gas` | `u128` |
| 172 | 16 | `tx_params.max_fee_per_gas` | `u128` |
| 188 | 8 | `tx_params.gas_limit` | `u64` |
| 196 | 20 | `tx_params.to` | `[u8; 20]` |
| 216 | 16 | `tx_params.value` | `u128` |
| 232 | 1 | `tx_params.calldata.is_some` | `bool` |
| 233 | 4 | `tx_params.calldata.value.selector` | `[u8; 4]` |
| 237 | 2 | `tx_params.calldata.value.no_words` | `u16` |
| 239 | 32 | `tx_params.calldata.value.words[0]` | `[u8; 32]` |
| 271 | 32 | `tx_params.calldata.value.words[1]` | `[u8; 32]` |
| 303 | 32 | `tx_params.calldata.value.words[2]` | `[u8; 32]` |
| 335 | 32 | `tx_params.calldata.value.words[3]` | `[u8; 32]` |
| 367 | 32 | `tx_params.calldata.value.words[4]` | `[u8; 32]` |
| 399 | 32 | `tx_params.calldata.value.words[5]` | `[u8; 32]` |
| 431 | 32 | `tx_params.calldata.value.words[6]` | `[u8; 32]` |
| 463 | 1 | `tx_params.access_list_entry_count` | `u8` |
| 464 | 32 | `caip2_id` | `[u8; 32]` |
| 496 | 38 | `output_deserialization_schema` | `[u8; 38]` |
| 534 | 37 | `respond_serialization_schema` | `[u8; 37]` |

### `ClaimOutput` — 1 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `success` | `u8` |

### `CompleteWithdrawOutput` — 1 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `success` | `u8` |

### `RefundOutput` — 5 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 5 | `failure` | `[u8; 5]` |

### `CompleteSwapOutput` — 8 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 8 | `amount_in` | `u64` |

### `AttestationPreimage<ClaimOutput>` — 33 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.success` | `u8` |

### `AttestationPreimage<CompleteWithdrawOutput>` — 33 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.success` | `u8` |

### `AttestationPreimage<RefundOutput>` — 37 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 5 | `output.failure` | `[u8; 5]` |

### `AttestationPreimage<CompleteSwapOutput>` — 40 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 8 | `output.amount_in` | `u64` |

### `VaultResponse` — 2 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `kind` | `u8` |
| 1 | 1 | `success` | `bool` |

### `SwapResponse` — 9 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `kind` | `u8` |
| 1 | 8 | `amount_in` | `u64` |

### `FailureResponse` — 1 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `kind` | `u8` |

### `AttestationPreimage<VaultResponse>` — 34 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.kind` | `u8` |
| 33 | 1 | `output.success` | `bool` |

### `AttestationPreimage<SwapResponse>` — 41 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.kind` | `u8` |
| 33 | 8 | `output.amount_in` | `u64` |

### `AttestationPreimage<FailureResponse>` — 33 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.kind` | `u8` |

### `SignBidirectionalMisc` — 161 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `version` | `u8` |
| 1 | 32 | `request_id` | `[u8; 32]` |
| 33 | 128 | `payload` | `[u8; 128]` |

### `RespondMisc` — 129 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 32 | `big_r_x` | `[u8; 32]` |
| 64 | 32 | `big_r_y` | `[u8; 32]` |
| 96 | 32 | `s` | `[u8; 32]` |
| 128 | 1 | `recovery_id` | `u8` |
<!-- END GENERATED: offset tables -->

---

## 10. Golden vectors

`spec/vectors/*.json` — committed, generated, and checked in CI against
regeneration.

| file | contents |
|---|---|
| `leaves.json` | one vector per leaf type, including `Flagged<u32>` set and unset (same width) |
| `records.json` | `VaultEvent` and `SwapEvent`; their `keccak256` IS the request id |
| `attested-outputs.json` | the kind-tagged responses of §5 and their signed digest preimages |
| `attested-outputs-deployed.json` | what the deployed contract accepts TODAY, for reference |
| `misc-payloads.json` | the singleton's logged payloads, with the 288-byte envelope |

Each vector carries:

- `type`, `len` — the declared type and its constant width;
- `hex` — **the authoritative bytes**, the canonical Borsh encoding;
- `sha256` — SHA-256 of those bytes (Midnight's `persistentHash` of this
  preimage);
- `keccak256` — Keccak-256 of those bytes: the **request id** for a record, the
  **signed digest** for an `AttestationPreimage`, and a checksum otherwise;
- `fields` — the value field by field, in declaration order, each with its
  `offset`, `width`, own `hex` and (for scalars) its decoded `number`. The
  fields tile the value exactly, which is itself a committed test.

The value is given as an ordered array rather than a JSON object on purpose:
the format is ordered and JSON objects are not.

---

## 11. Status — what is deployed and what is specified

Read this before implementing.

- **The request record, the request id, and the singleton's log payloads are
  DEPLOYED and unchanged.** This document specifies what is already on the
  wire; it was verified byte-for-byte against the deployed encoding, including
  by handing the bytes to the compiled contract itself.
- **The response kinds of §5 are SPECIFIED, not deployed.** The MPC has never
  settled a transaction on Midnight (its Midnight publisher is unimplemented),
  so there is no legacy response format to migrate: §5 defines it.
  `attested-outputs-deployed.json` records what the currently deployed vault
  would accept, for reference only.
- A `format_version` byte in the record is recommended and not yet present; it
  would turn an unknown shape into a named rejection rather than a silent one.

## 12. Provenance

Every offset and every byte in this document is generated from the same type
declarations the circuits are built from and the conformance suite checks. To
regenerate after an intentional change:

```
cargo test --release -p minocrab-contracts --test serialization_conformance -- \
    --ignored --nocapture regenerate_spec
```

and commit the diff. Three tests fail if the committed artifact stops being the
generator's output, so this document cannot drift from the format:
`the_committed_offset_tables_are_generated`,
`the_committed_vectors_are_generated`, `every_vector_is_tiled_by_its_fields`.

Design of record and the measurements behind these decisions:
`notes/borsh-format.org`.
