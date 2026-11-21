# minocrab-taint

**The taint lint of [MinoCrab](https://github.com/sig-net/minocrab).** `minocrab_taint::audit(&[Instruction]) -> Vec<Finding>` checks a ZKIR v3 instruction stream: every byte-atom hash-preimage limb must be provably bounded to its own byte width, or constant. Without that bound the limb packing is not injective and the digest binds nothing, a hazard no test on honest preimages can see.

It reads any ZKIR v3 stream, MinoCrab's or compactc's. The marking rules, their warrants and the lint's stated limitations are in the crate docs; the design record is `notes/taint-lint.org` in the repository.

```
cargo run -p minocrab-taint --example taint_corpus -- <dir>   # audit every .zkir under <dir>
```
