### Summary

`deserialize<Boolean, N>` does not constrain the decoded byte to `{0, 1}`. It lowers to `byte == 1`, so any byte `!= 0x01` is accepted and read as `false` — `false` has 255 valid encodings instead of one. A prover can pick a different encoding of `false` each time to defeat any nullifier/commitment that hashes the raw byte, e.g. redeeming a single-use voucher 255 times.

### Details

The `tboolean` case of `build-deserialize` lowers the byte to `byte == 1` ([`expand-serialize.ss#L280-L286`](https://github.com/LFDT-Minokawa/compact/blob/56c3b7796f78de582bee907318737077fb6e210f/compiler/analysis-passes/expand-serialize.ss#L280-L286)) — it reads the byte as a `Uint<8>` and tests equality with `1`, with only an 8-bit range check and no `{0,1}` constraint. Compiled ZKIR:

```json
{"op":"constrain_bits","val":"%payload.0","bits":8}
{"op":"test_eq","output":"%b.5","a":"%t.4","b":"0x01"}
```

Operations on the decoded bool are fine, 0x02 and 0xFF are indistinguishable from 0x00 in boolean operations. The issue is when an operation like persistent_hash observes the boolean byte itself.

`redeem.compact` is a shrunken version of our EVM deposit redemption code. Each voucher is redeemable once per `(flag, tag)`:

```compact
export ledger used: Set<Bytes<32>>;
export circuit redeem(flag: Bytes<1>, tag: Bytes<32>): [] {
  const flag_bool = disclose(deserialize<Boolean, 1>(flag));
  if (!flag_bool) {                                                 // 255 bytes reach here
    const nul = disclose(persistentHash<[Bytes<1>, Bytes<32>]>([flag, tag]));
    assert(!used.member(nul), "tag already redeemed");// double spend guard
    used.insert(nul);
    // ... pay out `tag` ...
  }
}
```

The branch decodes `flag` to a bool (all 255 bytes `!= 0x01` → `false` → payout), while the nullifier hashes the *raw* `flag` byte (`persistent_hash` over `[%flag.0, tag…]` in `redeem.zkir`). So 255 encodings of `false` mint 255 distinct nullifiers for one `tag`, allowing the same deposit to be spent multiple times.

### PoC

Reproducible entirely with Compact's own tooling.

**Compiler only (`compactc`, no proving).** Compile and inspect the gate:

```
compactc --skip-zk --feature-zkir-v3 redeem.compact out
grep -E 'constrain_bits|constrain_to_boolean|test_eq' out/zkir/redeem.zkir
```

The deserialized `flag` is `constrain_bits …8` then `test_eq …0x01` — **no `constrain_to_boolean`**, so `0x02..=0xFF` are accepted as `false`. Changing the parameter to `flag: Boolean` instead emits `constrain_to_boolean %flag.0` (pinning it to `{0,1}`) and the exploit disappears — confirming the gap is specific to `deserialize<Boolean>`, not to `Boolean` values in general.

**Runtime (reference VM).** Feed `flag = 0x02` to the compiled circuit and run `<IrSource as Zkir>::check` (`midnight-zkir-v3`): it is accepted. `flag = 0x00` and `flag = 0x02` on the same `tag` yield two distinct nullifiers, so the `used` set admits both, one deposit spent twice. We have a self-contained Rust harness that demonstrates this using only Midnight crates (`compactc` + `midnight-zkir-v3` + `midnight-transient-crypto`), it can be shared privately or reproduced in-repo.

### Impact

Soundness bug (missing input validation) in the compiler. Any circuit that branches a deserialized bool as `false` while committing/hashing/keying the underlying bytes, nullifiers, spent-sets, commitments, is exploitable by any contract user. The 255 non-canonical encodings of `false` bypass single-use and uniqueness guards (double-spend / replay).

Fix: `deserialize<Boolean>` should emit `constrain_to_boolean` on the decoded byte (or reject bytes outside `{0, 1}`).

---
compactc 0.33.0 (0.33.0-rc.2), language 0.25.0, ledger-9.1.0.0-rc.3.
