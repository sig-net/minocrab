# minocrab-experimental

**This crate is published with NO backwards-compatibility guarantee.** Any release, a patch release included, may rename, change or remove any item in it. It holds what is experimental in [MinoCrab](https://github.com/sig-net/minocrab), or an escape hatch beneath the typed API of `minocrab-std`. No MinoCrab core crate depends on it, so its churn cannot reach a stable crate. The version says the same: it is 0.0.x, and under Cargo's semver rules every 0.0.x release is incompatible with every other.

## What is in it, and why not in `minocrab-std`

| module | what | why it is here |
|---|---|---|
| `impact` | Impact ledger operations written by hand: the op builders and `emit` (`impact::raw`) | it bypasses checks the typed ledger slots of `minocrab-std` make |

A typed slot knows its field index and its value's layout; an op written by hand knows neither, so nothing checks that a field index is written with its declared type's layout. What still applies is the stale-read backstop (`impact::raw::emit` refuses at build time a cell write, map insert or list push whose value is computed from an inline ledger read that was not acknowledged, exactly as a typed slot's write is refused), disclosure (every element of an op is a public wire and is recorded as a disclosure) and the ambient `when` guard.

The primitives themselves stay public in `minocrab` and `minocrab-ledger`, because `minocrab-std` and `minocrab-compat` are other crates and lower to them. This crate is the one place a contract author imports them from, with what they give up written down beside them.
