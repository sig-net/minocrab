<!-- GENERATED — do not edit; source: crates/minocrab-contracts/tests/serialization/ts/README.md -->

# `spec/ts` — the circuit-safe Borsh subset, in TypeScript

A reader and a writer for every type in [`../borsh-subset.md`](../borsh-subset.md),
**generated** from the same Borsh schema that produced §9's offset tables and
the vectors in [`../vectors`](../vectors). No dependencies: `borsh-subset.ts`
imports `primitives.ts` and `primitives.ts` imports nothing. There is no
`package.json`, no `node_modules`, and nothing to install.

That is possible because this format is fixed-width by construction — every
offset is a compile-time constant, so a decoder is a `DataView` at a published
offset. The generated readers say exactly that:

```ts
export function readVaultResponse(bytes: Uint8Array, offset = 0): VaultResponse {
  const view = checkedView(bytes, offset, VAULT_RESPONSE_LEN);
  return {
    kind: getU8(view, 0),
    success: getBool(view, 1),
  };
}
```

## borsh-js is the alternative, and it is a fine one

This IS Borsh, restricted to the fixed-width subset — not a dialect. Every
byte these functions produce is canonical Borsh for the declared type, so
[`borsh-js`](https://github.com/near/borsh-js) (or any other implementation)
decodes the same bytes from the same declarations, and
`../borsh-subset.md` §12 says so explicitly. Use a library if you want one.
This directory exists so that the dependency is a **choice** rather than a
requirement, and so that the offsets you decode at are *generated* from the
circuit's own layout rather than transcribed from a table by hand.

Two rules to carry across either way:

- **Integers are little-endian.** The EVM ABI words carried *inside* these
  payloads are big-endian by the EVM's own rules; they travel as `[u8; 32]`
  and Borsh does not touch their contents.
- **`Maybe` is `Flagged`, never `Option`.** `Flagged<u32>` is five bytes at
  every value; `Option<u32>` is one or five. Decode one as the other and
  every offset after it is wrong on half your inputs.

## What is here

| file | what it is |
|---|---|
| `borsh-subset.ts` | GENERATED: types, offset tables, readers, writers and the codec registry |
| `primitives.ts` | the `DataView` leaf layer and the reject rules |
| `vectors.test.ts` | the vector-driven conformance tests |
| `node-builtins.d.ts` | ambient declarations for the node APIs the tests use (so no `@types/node`) |
| `tsconfig.json` | strict, `erasableSyntaxOnly` — the code node can run by stripping types |

## Running the tests

From the repository root, inside `nix develop` (which supplies node and tsc):

```sh
node --test spec/ts/vectors.test.ts    # the vectors, decoded and re-encoded
tsc --noEmit -p spec/ts                # type-check
```

or, to run the node suite from cargo beside the Rust ones:

```sh
cargo test --release -p minocrab-contracts --test serialization_conformance -- \
    --ignored the_typescript_vectors_pass
```

Every vector in `../vectors/*.json` is decoded by the generated codec for its
type, checked leaf by leaf against the vector's ordered field list (path,
type, offset, width, bytes and decoded number), re-serialized to byte
equality, and — where the vector carries one — unwrapped from its 288-byte
`Misc` envelope with the zero-pad rule enforced.

## Regenerating

Everything in this directory is written by one `--ignored` Rust test, and a
checked-in file that stops being its output fails
`spec_document::the_committed_typescript_is_generated`:

```sh
cargo test --release -p minocrab-contracts --test serialization_conformance -- \
    --ignored regenerate_spec
```

The generator is `crates/minocrab-contracts/tests/serialization/ts_codegen.rs`;
the hand-written files above are edited in
`crates/minocrab-contracts/tests/serialization/ts/` and copied here verbatim by
that test.

## Types the decoder covers

| spec type | TypeScript | bytes |
|---|---|---:|
| `bool` | `readBool` / `writeBool` | 1 |
| `u8` | `readU8` / `writeU8` | 1 |
| `u16` | `readU16` / `writeU16` | 2 |
| `u32` | `readU32` / `writeU32` | 4 |
| `u64` | `readU64` / `writeU64` | 8 |
| `u128` | `readU128` / `writeU128` | 16 |
| `[u8; 20]` | `readBytes20` / `writeBytes20` | 20 |
| `[u8; 32]` | `readBytes32` / `writeBytes32` | 32 |
| `[u8; 64]` | `readBytes64` / `writeBytes64` | 64 |
| `Flagged<u32>` | `readFlaggedU32` / `writeFlaggedU32` | 5 |
| `VaultEvent` | `readVaultEvent` / `writeVaultEvent` | 404 |
| `SwapEvent` | `readSwapEvent` / `writeSwapEvent` | 571 |
| `ClaimOutput` | `readClaimOutput` / `writeClaimOutput` | 1 |
| `CompleteWithdrawOutput` | `readCompleteWithdrawOutput` / `writeCompleteWithdrawOutput` | 1 |
| `RefundOutput` | `readRefundOutput` / `writeRefundOutput` | 5 |
| `CompleteSwapOutput` | `readCompleteSwapOutput` / `writeCompleteSwapOutput` | 8 |
| `AttestationPreimage<ClaimOutput>` | `readAttestationPreimageClaimOutput` / `writeAttestationPreimageClaimOutput` | 33 |
| `AttestationPreimage<CompleteWithdrawOutput>` | `readAttestationPreimageCompleteWithdrawOutput` / `writeAttestationPreimageCompleteWithdrawOutput` | 33 |
| `AttestationPreimage<RefundOutput>` | `readAttestationPreimageRefundOutput` / `writeAttestationPreimageRefundOutput` | 37 |
| `AttestationPreimage<CompleteSwapOutput>` | `readAttestationPreimageCompleteSwapOutput` / `writeAttestationPreimageCompleteSwapOutput` | 40 |
| `VaultResponse` | `readVaultResponse` / `writeVaultResponse` | 2 |
| `SwapResponse` | `readSwapResponse` / `writeSwapResponse` | 9 |
| `FailureResponse` | `readFailureResponse` / `writeFailureResponse` | 1 |
| `AttestationPreimage<VaultResponse>` | `readAttestationPreimageVaultResponse` / `writeAttestationPreimageVaultResponse` | 34 |
| `AttestationPreimage<SwapResponse>` | `readAttestationPreimageSwapResponse` / `writeAttestationPreimageSwapResponse` | 41 |
| `AttestationPreimage<FailureResponse>` | `readAttestationPreimageFailureResponse` / `writeAttestationPreimageFailureResponse` | 33 |
| `SignBidirectionalMisc` | `readSignBidirectionalMisc` / `writeSignBidirectionalMisc` | 161 |
| `RespondMisc` | `readRespondMisc` / `writeRespondMisc` | 129 |
