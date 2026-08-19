# `deserialize<Boolean, 1>` accepts non-canonical bytes

Corresponds to `notes/compact-findings.org` entry 2. **Verified 2026-08-19,
with a runnable test against Midnight's own reference VM.**

## Summary

`deserialize<Boolean, N>` does not constrain the deserialized Boolean to
`{0, 1}`. The payload byte is range-checked only to 8 bits; nothing pins it to
one bit. The lowering then decides truthiness with `test_eq byte, 0x01`, so
**every byte other than `0x01` — including `0x02`, `0xff`, etc. — is accepted
by the circuit and treated as `false`**. A canonical Boolean decoder would
reject a byte outside `{0, 1}`; this one does not.

This is a soundness hazard for any contract that branches on a Boolean
deserialized from attacker-influenceable bytes: 254 distinct witnesses satisfy
a circuit whose author believes the input is one bit. In the erc20-vault
example it meant any attested result byte `!= 1` routed `completeWithdraw`
into the REFUND branch — a re-mint on a successful withdrawal.

## Reproduction circuit

`bool-deserialize.compact` in this directory (circuit `routeAssertFalse`)
deserializes a witnessed `Bytes<1>` to a Boolean and **asserts the result is
false**:

```compact
import CompactStandardLibrary;

export ledger touched: Counter;

export circuit routeAssertFalse(payload: Bytes<1>): [] {
  touched.increment(1);
  const b = disclose(deserialize<Boolean, 1>(payload));
  assert(!b, "payload deserialized to false");
}
```

Compiled (`compactc --skip-zk --feature-zkir-v3 bool-deserialize.compact
out`), the circuit range-checks `payload` to 8 bits and decides truthiness
with `test_eq ... 0x01` — no `{0,1}` constraint:

```json
{"op":"constrain_bits","val":"%payload.0","bits":8}
... (touched.increment impact ops) ...
{"op":"div_mod_power_of_two","outputs":["%quo.1","%ignore.2"],"val":"%payload.0","bits":0}
{"op":"div_mod_power_of_two","outputs":["%ignore.3","%t.4"],"val":"%quo.1","bits":8}
{"op":"test_eq","output":"%b.5","a":"%t.4","b":"0x01"}
{"op":"cond_select","output":"%t.6","bit":"%b.5","a":"0x00","b":"0x01"}
{"op":"assert","cond":"%t.6"}
```

`%t.4` is the raw 8-bit byte; `%b.5` is `byte == 0x01`; the assert holds iff
`byte != 1`. Nothing forces `payload ∈ {0, 1}`.

## Self-contained test

Because acceptance is a property of the constraint system (not of the JS
runtime), the demonstration runs the compiled circuit through Midnight's OWN
reference VM — `<IrSource as Zkir>::check`, the off-circuit `preprocess` that
evaluates every `assert` — over payloads `0x00`, `0x01`, `0x02`:

| payload | canonical meaning | reference VM result | why |
|---------|-------------------|---------------------|-----|
| `0x00`  | `false`           | **accepts**         | `assert(!b)` holds |
| `0x01`  | `true`            | **rejects**         | `assert(!b)` fails |
| `0x02`  | *not a Boolean*   | **accepts**         | the bug: `0x02` is accepted and is `false` |

If the deserialize canonicalized (or a `{0,1}` constraint were added), `0x02`
would be rejected and the `0x02` row would flip to *rejects*.

The test is committed at
`crates/minocrab-sim/tests/bool_deserialize_non_canonical.rs`. Its acceptance
check uses only upstream `midnight-zkir-v3` and `midnight-transient-crypto`
(so it drops straight into the ledger repo's own zkir-v3 tests); here it also
cross-checks the result against `minocrab_sim::v3::simulate`, so the finding
never rests on one interpreter. Run:

```
$ cargo test -p minocrab-sim --test bool_deserialize_non_canonical
test non_canonical_boolean_is_accepted_and_falsy ... ok
```

The single test asserts the buggy acceptance pattern, so it is also a
tripwire: it starts failing the moment `0x02` stops being accepted as a
Boolean.

## Impact

Any contract branching on a Boolean deserialized from bytes an adversary can
choose. No canonicalization means a caller controls which branch runs beyond
the intended two-valued domain.

## Environment

- compactc 0.33.0 (the 0.33.0-rc.2 release bundle), language version 0.25.0,
  ledger-9.1.0.0-rc.3
- macOS 26.5.1, arm64
