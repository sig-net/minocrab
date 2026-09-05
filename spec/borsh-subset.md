# The Borsh fixed-width subset — Signet on Midnight

**THIS IS A SUBSET OF BORSH. IT IS NOT A SEPARATE FORMAT.**

Every byte described here is valid canonical [Borsh](https://borsh.io) for the
declared types. Any Borsh implementation — `borsh-js`, `borsh-rs`, `borsh-go`,
`borsh-py` — parses these payloads from the same type declarations. Nothing is
redefined, no framing is added, no field is reordered, and no length or tag is
invented. If you already have a Borsh library, you already have a decoder: write
the struct declarations in this document and call it.

And if you would rather not: [`spec/ts/`](ts/) is a **generated**,
dependency-free TypeScript reader and writer for every type below, walked out
of the same layout these tables are (§8, §12).

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

<!-- BEGIN GENERATED: response kinds -->
| kind | name | requested by | settles | ABI types to decode | attested output | LEN |
|---:|---|---|---|---|---|---:|
| 0 | `CLAIM` | `deposit` | `claim` | `[bool success]` | `VaultResponse { kind: u8, success: bool }` | 2 |
| 1 | `WITHDRAW` | `withdraw` | `completeWithdraw` | `[bool success]` | `VaultResponse { kind: u8, success: bool }` | 2 |
| 2 | `SWAP` | `swap` | `completeSwap` | `[uint256 amountIn]` | `SwapResponse { kind: u8, amount_in: u64 }` | 9 |
| 3 | `FAILURE` | — | `refund` | — (never executed) | `FailureResponse { kind: u8 }` | 1 |
| 4 | `APPROVE` | `approveRouter` | — | `[bool success]` | `VaultResponse { kind: u8, success: bool }` | 2 |
| 5 | `SUPPLY` | `supply` | `completeSupply` | `[uint256 shares]` | `SupplyResponse { kind: u8, shares: u64 }` | 9 |
| 6 | `REDEEM` | `redeem` | `completeRedeem` | `[uint256 assets]` | `RedeemResponse { kind: u8, assets: u64 }` | 9 |
<!-- END GENERATED: response kinds -->

This table is generated from the contract's own `RESPONSE_KIND_*` constants and
the response types' widths; it is exactly `RESPONSE_KINDS` rows long, numbered
`0..n`, and the generator fails rather than publishing a lookup that is one row
short of the enumeration the circuits use.

Each settle circuit accepts **exactly one** kind and asserts equality with its
own — which is strictly stronger than a `kind < 5` range check, and is the
anti-replay property.

**This table is also the record's lookup table.** The request record carries the
kind it expects (§6), so `kind ↦ (ABI types, response shape)` is what replaced
the two in-band ABI-JSON schema strings the record used to carry. The two ends
of the table are the asymmetries: `FAILURE` is response-only (an outcome, not a
request — any request can get it back), and `APPROVE` is request-only, because
an approve is fire-and-forget and no circuit settles it. Giving the approve its
own kind is what makes that *structural* rather than incidental.

### The signed digest

```
attestationDigest = upgradeFromTransient(transientHash(fieldElements(AttestationPreimage { request_id: [u8; 32], output: T })))
```

The preimage's LAYOUT is the Borsh struct — the request id's 32 bytes followed
by `borsh(output)`; preimage widths **34** bytes for claim/withdraw, **41** for
swap, **33** for refund — and its offset tables are in §9. The HASH over it is
not a byte hash: it is Midnight's Poseidon (`transientHash`) over the preimage's
**field elements**, under the rule of §6a, then upgraded to 32 bytes. (Until
signet-midnight-integration `fff3421c`, 2026-09-03, the digest was
`keccak256` of the Borsh bytes; the protocol moved every in-circuit hash to
Poseidon and this document followed on 2026-09-05.)

The signature over that digest is secp256k1 ECDSA under `mpcResponseKey`. On
the wire (`RespondMisc`, §7) `bigR.x` and `s` are big-endian, unchanged; the
settle circuits take them in **little-endian** "circuit-input form" — the
reversal is the transaction builder's, off-chain.

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
requestId = upgradeFromTransient(transientHash(fieldElements(record)))
```

The record's LAYOUT is the Borsh struct below, byte for byte. Its IDENTITY is
Poseidon over the record's field elements (§6a), not a hash of its bytes — so
an implementation needs both halves: the Borsh declarations to read and write
the record, and the field-element rule to recompute its id. The MPC recomputes
the id from the stored record (its `compact-hashing` crate, reading the ledger
cell's field-aligned representation) and drops any request whose id does not
match, so an implementation that gets one offset or one limb wrong fails closed
rather than signing the wrong transaction. (Before `fff3421c` the id was
`keccak256(borsh(record))`; the layout did not change.)

### 6a. The field-element rule (`fieldElements`)

Every leaf of the subset maps to a fixed number of BLS12-381 scalar field
elements, and a struct or array is the concatenation of its members' elements
in declaration order — the same order as the bytes, so the two views of one
value line up field for field:

| leaf | elements | value |
|---|---|---|
| `bool`, `u8`, `u16`, `u32`, `u64`, `u128` | 1 | the integer |
| `[u8; N]`, N ≤ 31 | 1 | the N bytes as a little-endian integer |
| `[u8; N]`, N > 31 | ⌈N/31⌉ | the **trailing** `N mod 31` bytes first (as a little-endian integer; the whole N-byte string is one 31-byte-chunked little-endian number and this is its top chunk), then each preceding 31-byte chunk in turn |

So `[u8; 32]` is two elements — byte 31, then bytes 0..30 — which is why every
32-byte circuit argument appears as two scalars constrained to 8 and 248 bits;
a 34-byte schema string is bytes 31..33 then bytes 0..30; the 64-byte `params`
is bytes 62..63, bytes 31..61, bytes 0..30. This is Midnight's own
field-aligned-binary rule (`transient-crypto/src/fab.rs`, `field_repr`), stated
here because the id depends on it.

`transientHash` is Midnight's Poseidon sponge over those elements
(`midnight_transient_crypto::hash::transient_hash`). `upgradeFromTransient`
renders the resulting field element as 32 bytes: its canonical little-endian
bytes 0..30, and **byte 31 = 0** (the value reduced modulo 2^248). Every
request id and every commitment in the vault therefore has a zero last byte.

The reference implementation is the vault model's `request_id_of` /
`attestation_digest` (`crates/minocrab-contracts/tests/vault/prims.rs`),
pinned to compactc's own artifacts on every circuit by the differential
suite, and the MPC's `compact-hashing` crate agrees with it on the captured
fixtures (`crates/signet-sim`).

There are TWO record formats, and this document specifies both.

**The current format** — `VaultEvent` (2 calldata words, 404 bytes) for deposit
/ approveRouter / withdraw, `SwapEvent` (7 words, 571 bytes) for swap — is what
the deployed contract writes, verified byte-for-byte against the deployed
encoding.

**The V2 format** — `VaultEventV2` (338 bytes) and `SwapEventV2` (498 bytes) —
is what the contracts of this specification write. It changes the record at its
two ENDS and nowhere in between:

| | current | V2 |
|---|---|---|
| first field | `sender: [u8; 32]` | `format_version: u8` = **`0x80`**, then `sender` |
| last fields | `output_deserialization_schema: [u8; L]` + `respond_serialization_schema: [u8; L']` (68 bytes on a vault record, 75 on a swap record) | `response_kind: u8` — the §5 kind, one byte |

Everything between is identical, field for field, so every V2 offset is the old
one **plus one**. Both layouts are in §9.

`format_version = 0x80` is the byte with only the high bit set: "this is not a
small version number" is a single bit test, and every value below `0x80` stays
available to Compact and Midnight, whose largest version number anywhere in the
stack is 33. A decoder MUST read byte 0 first and reject a record whose version
it does not know, by name. The on-chain reader does not check the version
byte today — records in the map are all this contract's own writes, so the
byte protects off-chain readers and future formats; an in-circuit version
assert is queued alongside the record-kind bind below.

`response_kind` is the §5 enumeration: the record declares which response kind
will settle it. The settle circuit asserts the ATTESTED OUTPUT's kind against
its own constant; the RECORD's kind is read by the MPC, not (yet) by any
circuit — the in-circuit `record.kind == output.kind` bind is queued as a
hardening stage. An implementer MUST NOT assume the chain enforces the
record/output kind match today. What the two schema strings used to carry — which ABI types
to decode the destination-chain return data with, and what shape to serialize
the response in — is the lookup table in §5.

The V2 record was designed when the id was keccak, where it took the swap
record's preimage from five blocks to four; under Poseidon its saving is the
four fewer field elements per hash, and its purpose is the kind byte and the
version byte, not the rows.

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

You do not have to write that reader either: [`spec/ts/`](ts/) is one, for
every type in §9, **generated from the same layout** — `readVaultEvent`,
`writeVaultEvent`, an offset table per type as data, and a codec registry keyed
by the names §9 uses. It imports nothing, there is no `package.json`, and its
tests decode every vector in §10 and re-encode it to byte equality
(`node --test spec/ts/vectors.test.ts`). `borsh-js` remains an equally correct
choice; the point is that the dependency is a choice.

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

### `VaultEventV2` — 338 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `format_version` | `u8` |
| 1 | 32 | `sender` | `[u8; 32]` |
| 33 | 8 | `request_nonce` | `u64` |
| 41 | 1 | `key_version` | `u8` |
| 42 | 32 | `path` | `[u8; 32]` |
| 74 | 1 | `algo` | `u8` |
| 75 | 1 | `dest` | `u8` |
| 76 | 64 | `params` | `[u8; 64]` |
| 140 | 1 | `tx_param_type` | `u8` |
| 141 | 8 | `tx_params.chain_id` | `u64` |
| 149 | 8 | `tx_params.nonce` | `u64` |
| 157 | 16 | `tx_params.max_priority_fee_per_gas` | `u128` |
| 173 | 16 | `tx_params.max_fee_per_gas` | `u128` |
| 189 | 8 | `tx_params.gas_limit` | `u64` |
| 197 | 20 | `tx_params.to` | `[u8; 20]` |
| 217 | 16 | `tx_params.value` | `u128` |
| 233 | 1 | `tx_params.calldata.is_some` | `bool` |
| 234 | 4 | `tx_params.calldata.value.selector` | `[u8; 4]` |
| 238 | 2 | `tx_params.calldata.value.no_words` | `u16` |
| 240 | 32 | `tx_params.calldata.value.words[0]` | `[u8; 32]` |
| 272 | 32 | `tx_params.calldata.value.words[1]` | `[u8; 32]` |
| 304 | 1 | `tx_params.access_list_entry_count` | `u8` |
| 305 | 32 | `caip2_id` | `[u8; 32]` |
| 337 | 1 | `response_kind` | `u8` |

### `SwapEventV2` — 498 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `format_version` | `u8` |
| 1 | 32 | `sender` | `[u8; 32]` |
| 33 | 8 | `request_nonce` | `u64` |
| 41 | 1 | `key_version` | `u8` |
| 42 | 32 | `path` | `[u8; 32]` |
| 74 | 1 | `algo` | `u8` |
| 75 | 1 | `dest` | `u8` |
| 76 | 64 | `params` | `[u8; 64]` |
| 140 | 1 | `tx_param_type` | `u8` |
| 141 | 8 | `tx_params.chain_id` | `u64` |
| 149 | 8 | `tx_params.nonce` | `u64` |
| 157 | 16 | `tx_params.max_priority_fee_per_gas` | `u128` |
| 173 | 16 | `tx_params.max_fee_per_gas` | `u128` |
| 189 | 8 | `tx_params.gas_limit` | `u64` |
| 197 | 20 | `tx_params.to` | `[u8; 20]` |
| 217 | 16 | `tx_params.value` | `u128` |
| 233 | 1 | `tx_params.calldata.is_some` | `bool` |
| 234 | 4 | `tx_params.calldata.value.selector` | `[u8; 4]` |
| 238 | 2 | `tx_params.calldata.value.no_words` | `u16` |
| 240 | 32 | `tx_params.calldata.value.words[0]` | `[u8; 32]` |
| 272 | 32 | `tx_params.calldata.value.words[1]` | `[u8; 32]` |
| 304 | 32 | `tx_params.calldata.value.words[2]` | `[u8; 32]` |
| 336 | 32 | `tx_params.calldata.value.words[3]` | `[u8; 32]` |
| 368 | 32 | `tx_params.calldata.value.words[4]` | `[u8; 32]` |
| 400 | 32 | `tx_params.calldata.value.words[5]` | `[u8; 32]` |
| 432 | 32 | `tx_params.calldata.value.words[6]` | `[u8; 32]` |
| 464 | 1 | `tx_params.access_list_entry_count` | `u8` |
| 465 | 32 | `caip2_id` | `[u8; 32]` |
| 497 | 1 | `response_kind` | `u8` |

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

### `SupplyResponse` — 9 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `kind` | `u8` |
| 1 | 8 | `shares` | `u64` |

### `AttestationPreimage<SupplyResponse>` — 41 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.kind` | `u8` |
| 33 | 8 | `output.shares` | `u64` |

### `RedeemResponse` — 9 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 1 | `kind` | `u8` |
| 1 | 8 | `assets` | `u64` |

### `AttestationPreimage<RedeemResponse>` — 41 bytes

| offset | width | field | type |
|---:|---:|---|---|
| 0 | 32 | `request_id` | `[u8; 32]` |
| 32 | 1 | `output.kind` | `u8` |
| 33 | 8 | `output.assets` | `u64` |

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
| `records.json` | `VaultEvent` / `SwapEvent` (current) and `VaultEventV2` / `SwapEventV2` (§6) at the SAME field values; the request id is §6a's Poseidon over their field elements, not a hash of these bytes |
| `attested-outputs.json` | the kind-tagged responses of §5 and their signed digest preimages |
| `attested-outputs-deployed.json` | what the deployed contract accepts TODAY, for reference |
| `misc-payloads.json` | the singleton's logged payloads, with the 288-byte envelope |

**Which record a file's request ids come from**, because two record formats are
specified here and the ids differ: `attested-outputs.json` uses the **V2**
record's id (`VaultEventV2` in `records.json`) — V2 records are what these
responses settle; `attested-outputs-deployed.json` and `misc-payloads.json` use
the **deployed** record's id (`VaultEvent`), because the deployed outputs and
the singleton's log payloads are what is on the wire today and stage 7 does not
change either.

Each vector carries:

- `type`, `len` — the declared type and its constant width;
- `hex` — **the authoritative bytes**, the canonical Borsh encoding;
- `sha256` — SHA-256 of those bytes (Midnight's `persistentHash` of this
  preimage);
- `keccak256` — Keccak-256 of those bytes, a checksum of the vector (NOT the
  request id or the signed digest, which are Poseidon over the field elements,
  §6a);
- `fields` — the value field by field, in declaration order, each with its
  `offset`, `width`, own `hex` and (for scalars) its decoded `number`. The
  fields tile the value exactly, which is itself a committed test.

The value is given as an ordered array rather than a JSON object on purpose:
the format is ordered and JSON objects are not.

---

## 11. Status — what is deployed and what is specified

Read this before implementing.

- **The singleton's log payloads are DEPLOYED and unchanged.** This document
  specifies what is already on the wire; it was verified byte-for-byte against
  the deployed encoding, including by handing the bytes to the compiled
  contract itself.
- **`VaultEvent` / `SwapEvent` are what the DEPLOYED vault writes**, likewise
  verified byte-for-byte, and their request ids are §6a's Poseidon over the
  field elements (signet-midnight-examples `0d9c1660`). The deployed vault's
  two lending flows (`startSupply`, `startRedeem`) write the same record shape
  at other instantiations — 2 and 3 calldata words, 36/35-byte schema strings
  — which this document does not yet tabulate in §9; they follow §6a and the
  §9 layout rule unchanged (`crates/minocrab-contracts/src/erc20_vault.rs`,
  `SupplyEvent` / `RedeemEvent`).
- **`VaultEventV2` / `SwapEventV2` (§6) and the response kinds of §5 are
  SPECIFIED, not deployed.** The MPC has never settled a transaction on
  Midnight (its Midnight publisher is unimplemented) and nothing has been
  deployed in the V2 shape, so there is no legacy format to migrate and no
  dual-format window to support: an implementation targets one or the other,
  and the version byte tells it which record it is holding.
  `attested-outputs-deployed.json` records what the currently deployed vault
  would accept, for reference only.
- **The format-version byte is now present** (V2 only, and in the record only —
  an attested output carries a kind and a signed digest, which is enough).

## 12. Provenance

Every offset and every byte in this document — and every line of the
TypeScript in `spec/ts/` — is generated from the same type declarations the
circuits are built from and the conformance suite checks. To regenerate after
an intentional change:

```
cargo test --release -p minocrab-contracts --test serialization_conformance -- \
    --ignored --nocapture regenerate_spec
```

and commit the diff. Six tests fail if the committed artifact stops being the
generator's output, so neither this document nor the code that reads it can
drift from the format: `the_committed_offset_tables_are_generated`,
`the_committed_kind_table_is_generated`, `the_committed_vectors_are_generated`,
`every_vector_is_tiled_by_its_fields`,
`the_committed_typescript_is_generated`,
`every_vector_type_has_a_typescript_codec`.

Design of record and the measurements behind these decisions:
`notes/borsh-format.org`.
