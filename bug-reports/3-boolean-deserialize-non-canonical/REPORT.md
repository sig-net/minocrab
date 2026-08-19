# `deserialize<Boolean, 1>` accepts non-canonical bytes

Corresponds to `notes/compact-findings.org` entry 2. **Verified 2026-08-19.**

## Summary

`deserialize<Boolean, N>` does not constrain the deserialized Boolean to
`{0, 1}`. The payload byte is range-checked only to 8 bits; nothing pins it
to one bit. The lowering then decides truthiness with `test_eq b, 0x01`, so
**every byte other than `0x01` — including `0x02`, `0xff`, etc. — is treated
as `false`**, and a byte of `0x02` is accepted by the circuit rather than
rejected.

This is a soundness hazard for any contract that branches on a Boolean
deserialized from attacker-influenceable bytes. In the erc20-vault example it
meant any attested result byte `!= 1` routed `completeWithdraw` into the
REFUND branch — a re-mint on a successful withdrawal.

Because the byte is compared for equality with `0x01` (rather than the low
bit being extracted), the practical effect is "anything but exactly 1 is
false" rather than "0x02 is true". Either way the deserialized value is not
canonicalized and non-`{0,1}` inputs are silently accepted — the byte should
be constrained to `{0, 1}` (or the deserialize should reject out-of-range
bytes) so it cannot pass.

## Reproduction

`bool-deserialize.compact` in this directory:

```compact
import CompactStandardLibrary;

export ledger trueBranch: Counter;
export ledger falseBranch: Counter;

export circuit route(payload: Bytes<1>): [] {
  const flag = disclose(deserialize<Boolean, 1>(payload));
  if (flag) {
    trueBranch.increment(1);
  } else {
    falseBranch.increment(1);
  }
}
```

```
$ compactc --skip-zk --feature-zkir-v3 bool-deserialize.compact out
```

The generated `out/zkir/route.zkir` — the payload byte gets an 8-bit range
check and then a `test_eq ... 0x01`, with no `{0,1}` constraint:

```json
{"op":"constrain_bits","val":"%payload.0","bits":8}
{"op":"div_mod_power_of_two","outputs":["%quo.1","%ignore.2"],"val":"%payload.0","bits":0}
{"op":"div_mod_power_of_two","outputs":["%ignore.3","%t.4"],"val":"%quo.1","bits":8}
{"op":"test_eq","output":"%flag.5","a":"%t.4","b":"0x01"}
{"op":"cond_select","output":"%t.6","bit":"%flag.5","a":"0x00","b":"0x01"}
...
```

`%t.4` is the raw 8-bit byte; the branch selector `%flag.5` is
`byte == 0x01`. A prover supplying `payload = 0x02` satisfies every
constraint and lands in the `false` branch. Nothing forces `payload` into
`{0, 1}`.

## Impact

Any contract branching on a Boolean deserialized from bytes an adversary can
choose. No canonicalization means a caller controls which branch runs beyond
the intended two-valued domain.

## Environment

- compactc 0.33.0 (the 0.33.0-rc.2 release bundle), language version 0.25.0,
  ledger-9.1.0.0-rc.3
- macOS 26.5.1, arm64
