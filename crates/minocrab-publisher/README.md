# minocrab-publisher

**The MPC's Midnight publisher, pure core** — part of [MinoCrab](https://github.com/sig-net/minocrab).

`sig-net/mpc` publishes an MPC signature to Midnight by building a `respond`
call, proving it, paying its DUST fee and submitting it. A Node 22 sidecar
does the first three today, for one stated reason — "the compiled contract's
bindings and executor are JavaScript". This crate is the claim that this is
no longer true, in a form `chain-midnight` can link:

```
 (request id, signature)                       call.rs — the public surface
           │                       arguments as an AlignedValue,
           ▼                       the Impact program, the key location
     SignerCall ──prototype(state, parameters, rand)──▶ ContractCallPrototype
           │
           ▼                                            intent.rs, keys.rs
     build ─▶ Intent (with TTL) ─▶ Transaction            prove.rs, publish.rs
           │
           ├─ prove   in process: no proof server, no child process, and
           │          no network once the KZG parameters are on disk
           ├─ balance the DUST seam — dust::DustBalancer
           ├─ sign    Intent::sign
           └─ seal    PedersenRandomness ─▶ PureGeneratorPedersen
```

Nothing here talks to a node: every input a chain would supply — contract
state, `LedgerParameters`, cost model, network id, segment, block time — is an
argument, gathered in `publish::ChainContext`. The only files read are the
managed key directory (`keys::ManagedDir`) and the KZG parameter cache.

The Misc envelope constants, the three signer circuit/event names and
`hashVerifierKey` are read from [`signet-protocol`](https://github.com/sig-net/minocrab/tree/main/crates/signet-protocol), the one publishable
crate the contract that emits these events and the artifact pipeline that
hashes the keys also read — this crate does not depend on the corpus crate
(`minocrab-contracts`) at all except as a dev-dependency of its own real-proof
gate, which needs an actual circuit to keygen against.

[Repository README](https://github.com/sig-net/minocrab#readme) · [notes/mpc-publisher.org](https://github.com/sig-net/minocrab/blob/main/notes/mpc-publisher.org)

Licensed under MIT OR Apache-2.0.
