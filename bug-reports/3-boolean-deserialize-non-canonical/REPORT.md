# `deserialize<Boolean, 1>` accepts non-canonical bytes

`deserialize<Boolean, N>` does not constrain the deserialized byte to `{0, 1}`.
The `tboolean` case of `build-deserialize` lowers the byte to `byte == 1`
([`compiler/analysis-passes/expand-serialize.ss#L266-L272`](https://github.com/LFDT-Minokawa/compact/blob/56c3b7796f78de582bee907318737077fb6e210f/compiler/analysis-passes/expand-serialize.ss#L266-L272)),
with no `{0,1}` constraint on the byte. So the byte is only range-checked to 8
bits and any value `!= 0x01` (including `0x02`..`0xFF`) is accepted by the
circuit and read as `false`. A prover can supply a non-canonical byte, produce
a valid proof, and have it routed to the `false` branch — where a canonical
decoder would reject it.

## Repro

`bool-deserialize.compact`:

```compact
import CompactStandardLibrary;

export ledger touched: Counter;

export circuit routeAssertFalse(payload: Bytes<1>): [] {
  touched.increment(1);
  const b = disclose(deserialize<Boolean, 1>(payload));
  assert(!b, "payload deserialized to false");   // holds iff byte != 1
}
```

```
compactc --skip-zk --feature-zkir-v3 bool-deserialize.compact out
```

The compiled `out/zkir/routeAssertFalse.zkir` range-checks the byte to 8 bits
and then does `test_eq ... 0x01` — no `{0,1}` constraint:

```json
{"op":"constrain_bits","val":"%payload.0","bits":8}
{"op":"test_eq","output":"%b.5","a":"%t.4","b":"0x01"}
{"op":"cond_select","output":"%t.6","bit":"%b.5","a":"0x00","b":"0x01"}
{"op":"assert","cond":"%t.6"}
```

Running the compiled circuit through Midnight's reference VM
(`<IrSource as Zkir>::check`) over the byte input confirms acceptance:

| payload | canonical meaning | reference VM |
|---------|-------------------|--------------|
| `0x00`  | `false`           | accepts      |
| `0x01`  | `true`            | rejects (`assert(!b)` fails) |
| `0x02`  | *not a Boolean*   | **accepts, read as `false`** |

Full runnable test (upstream `midnight-zkir-v3` +
`midnight-transient-crypto`): `test.rs` in this directory.

## Exploitability

The soundness gap is real at the circuit level, but whether it is *live*
depends on whether the byte is otherwise pinned:

- **Live** where a contract branches on a deserialized bool whose bytes aren't
  independently constrained to `{0,1}` — the prover forces the `false` branch
  with a non-canonical byte.
- **Latent** where the bytes are pinned by a separate in-circuit check (e.g. a
  signature or hash over the serialized payload, as in the erc20-vault). There
  the safety rests entirely on that external check, *not* on `deserialize`
  rejecting non-canonical input — because it doesn't.

Suggested fix: constrain a deserialized Boolean to `{0, 1}` (or reject
out-of-range bytes) so a non-canonical byte cannot satisfy the circuit.

---
compactc 0.33.0 (0.33.0-rc.2), language 0.25.0, ledger-9.1.0.0-rc.3.
