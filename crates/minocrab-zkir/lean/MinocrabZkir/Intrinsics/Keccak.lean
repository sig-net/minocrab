/-
Keccak-256 as a pure byte algorithm, in the ORIGINAL Keccak padding.

This is what Ethereum and the Rust `sha3::Keccak256` type compute: the
multi-rate padding starts with the domain byte `0x01`, NOT the `0x06` that
NIST's SHA3-256 (FIPS 202) prepends. The two differ in that one byte and in
nothing else, so the vectors at the bottom of this file are the only thing
distinguishing them — do not "fix" the padding to match FIPS 202.

Mathlib-free and dependency-free: this file imports nothing but Lean core,
so it can be read (and audited) on its own, and so the ZKIR intrinsic model
can consult it without dragging the rest of `MinocrabZkir` in.

Everything here is total and structural: the only recursion is `List.range`
folds, so the equation compiler never needs a termination argument, and no
definition is `partial`, `sorry`, or `panic!`. State lives in `Array`s read
with `Array.getD` and written with `Array.setIfInBounds`, both total; every
index below is in range by construction (the sizes are fixed at 5, 24, 25),
so neither fallback ever fires.

Shift note: on `UIntN` Lean reduces the shift amount modulo `N`
(`(1 : UInt64) <<< (64 : UInt64) = 1`). `rotl` is called with `0 ≤ n ≤ 63`;
for `1 ≤ n ≤ 63` no reduction happens, and at `n = 0` both halves reduce to
`x`, whose disjunction is `x` — the identity rotation, as required.
-/

namespace MinocrabZkir.Keccak

/-! ## Parameters

Keccak-f[1600] over 25 lanes of 64 bits. Keccak-256 takes capacity 512, so
the rate is `1600 - 512 = 1088` bits = 136 bytes = 17 lanes, and the digest
is 32 bytes = 4 lanes — short enough that one squeeze suffices.
-/

/-- The rate in bytes (`136`). -/
def rateBytes : Nat := 136

/-- The rate in 64-bit lanes (`17`). -/
def rateLanes : Nat := 17

/-! ## Primitive word operations -/

/-- Rotate a 64-bit lane left by `n` bits (`0 ≤ n < 64`). -/
@[inline] def rotl (x : UInt64) (n : UInt64) : UInt64 :=
  (x <<< n) ||| (x >>> (64 - n))

/-! ## Constants -/

/-- The ρ rotation offsets, flattened to lane index `x + 5 * y`. -/
def rhoOffsets : Array UInt64 := #[
   0,  1, 62, 28, 27,
  36, 44,  6, 55, 20,
   3, 10, 43, 25, 39,
  41, 45, 15, 21,  8,
  18,  2, 61, 56, 14]

/-- The 24 ι round constants. -/
def roundConstants : Array UInt64 := #[
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

/-- The all-zero 1600-bit state. -/
def emptyState : Array UInt64 := Array.replicate 25 (0 : UInt64)

/-! ## The permutation -/

/-- One round of Keccak-f[1600]: θ, then ρ fused with π, then χ, then ι. -/
def round (a : Array UInt64) (rnd : Nat) : Array UInt64 :=
  -- θ: column parities, then the mixing term for each column.
  let c := (List.range 5).foldl (fun c x =>
    c.push (a.getD x 0 ^^^ a.getD (x + 5) 0 ^^^ a.getD (x + 10) 0
              ^^^ a.getD (x + 15) 0 ^^^ a.getD (x + 20) 0)) #[]
  let d := (List.range 5).foldl (fun d x =>
    d.push (c.getD ((x + 4) % 5) 0 ^^^ rotl (c.getD ((x + 1) % 5) 0) 1)) #[]
  let a := (List.range 25).foldl (fun acc i => acc.push (a.getD i 0 ^^^ d.getD (i % 5) 0)) #[]
  -- ρ ∘ π: lane (x, y) rotates by `rhoOffsets` and lands at (y, 2x + 3y).
  let b := (List.range 25).foldl (fun b src =>
    let x := src % 5
    let y := src / 5
    let dst := y + 5 * ((2 * x + 3 * y) % 5)
    b.setIfInBounds dst (rotl (a.getD src 0) (rhoOffsets.getD src 0))) emptyState
  -- χ: the nonlinear step, applied along each row.
  let a := (List.range 25).foldl (fun acc i =>
    let x := i % 5
    let y := i / 5
    acc.push (b.getD i 0 ^^^ ((~~~ b.getD ((x + 1) % 5 + 5 * y) 0) &&& b.getD ((x + 2) % 5 + 5 * y) 0))) #[]
  -- ι: break the round symmetry.
  a.setIfInBounds 0 (a.getD 0 0 ^^^ roundConstants.getD rnd 0)

/-- Keccak-f[1600]: 24 rounds. -/
def permute (st : Array UInt64) : Array UInt64 :=
  (List.range 24).foldl round st

/-! ## Padding -/

/-- Original Keccak multi-rate padding (`pad10*1` with domain byte `0x01`):
append `0x01`, then zeros, then set the top bit of the final byte, so the
result is a whole number of 136-byte blocks. A message whose length is
already a multiple of the rate gains a full extra block; a message one byte
short of a block gains the single byte `0x81`. -/
def padMessage (msg : List UInt8) : Array UInt8 :=
  let bytes := msg.toArray
  -- `1 ≤ padLen ≤ 136`, so there is always room for both pad bits.
  let padLen := rateBytes - (bytes.size % rateBytes)
  let padded := (bytes.push 0x01) ++ Array.replicate (padLen - 1) (0 : UInt8)
  padded.setIfInBounds (padded.size - 1) (padded.getD (padded.size - 1) 0 ||| 0x80)

/-! ## Absorbing -/

/-- The little-endian 64-bit lane at byte offset `off`. -/
def leLane (bytes : Array UInt8) (off : Nat) : UInt64 :=
  (List.range 8).foldl (fun acc i =>
    acc ||| (UInt64.ofNat (bytes.getD (off + i) 0).toNat <<< UInt64.ofNat (8 * i))) 0

/-- XOR one rate-sized block into the state, then permute. -/
def absorbBlock (st : Array UInt64) (bytes : Array UInt8) (off : Nat) : Array UInt64 :=
  permute <| (List.range rateLanes).foldl (fun s i =>
    s.setIfInBounds i (s.getD i 0 ^^^ leLane bytes (off + 8 * i))) st

/-- The state after absorbing the whole padded message. -/
def absorb (msg : List UInt8) : Array UInt64 :=
  let bytes := padMessage msg
  (List.range (bytes.size / rateBytes)).foldl
    (fun st bi => absorbBlock st bytes (bi * rateBytes)) emptyState

/-! ## Squeezing -/

/-- The eight little-endian bytes of a lane. -/
def laneBytes (x : UInt64) : Array UInt8 :=
  (List.range 8).foldl (fun acc i =>
    acc.push (UInt8.ofNat (x >>> UInt64.ofNat (8 * i)).toNat)) #[]

/-- The 32 digest bytes as a plain array: the first four lanes of the final
state, little-endian. 32 ≤ 136, so no further permutation is needed. -/
def digestBytes (msg : List UInt8) : Array UInt8 :=
  let st := absorb msg
  (List.range 4).foldl (fun acc i => acc ++ laneBytes (st.getD i 0)) #[]

/-- Keccak-256 in the ORIGINAL Keccak padding (0x01 domain byte), i.e. what
Ethereum / the `sha3::Keccak256` Rust crate computes — NOT NIST SHA3-256. -/
def hash (msg : List UInt8) : Vector UInt8 32 :=
  let bs := digestBytes msg
  Vector.ofFn fun i => bs.getD i.val 0

/-! ## Build-time test vectors

`#guard` runs at elaboration time and fails the build when its argument
evaluates to `false`, so the vectors below are a compile gate, not a
comment. Every expectation was cross-checked against the Rust
`sha3::Keccak256` implementation.
-/

/-- Lowercase hex of one byte. -/
def hexByte (b : UInt8) : String :=
  let digit (n : Nat) : Char :=
    if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)
  String.ofList [digit (b.toNat / 16), digit (b.toNat % 16)]

/-- Lowercase hex of a digest, for comparison against published vectors. -/
def toHex (v : Vector UInt8 32) : String :=
  v.toArray.foldl (fun s b => s ++ hexByte b) ""

/-- The digest of a UTF-8 string, as hex. -/
def hashStrHex (s : String) : String := toHex (hash s.toUTF8.toList)

-- The three standard Keccak-256 vectors.
#guard hashStrHex "" ==
  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

#guard hashStrHex "abc" ==
  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"

#guard hashStrHex "testing" ==
  "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"

-- 135 × 'b' (cross-checked with `sha3::Keccak256`): one byte short of the
-- rate, so the whole pad collapses to the single byte 0x81.
#guard toHex (hash (List.replicate 135 (0x62 : UInt8))) ==
  "4cc4e6a6deebdec4c9c6d68f91082ef4e5c608215f017742d4d90cdc77860650"

-- 136 × 'b' (cross-checked with `sha3::Keccak256`): exactly the rate, so
-- the padding must add a whole extra block.
#guard toHex (hash (List.replicate 136 (0x62 : UInt8))) ==
  "121b76d0b19f3c2c7632310b92c54cddd59d16a6b5aafe84696426f10e5733bf"

-- 1000 × 'a' (cross-checked with `sha3::Keccak256`): several blocks, with a
-- length that is not a multiple of the rate.
#guard toHex (hash (List.replicate 1000 (0x61 : UInt8))) ==
  "b6a4ac1f51884d71f30fa397a5e155de3099e11fc0edef5d08b646e621e19de9"

-- Guard against silently becoming NIST SHA3-256, whose only difference is
-- the 0x06 domain byte: that function maps "" to a7ffc6f8bf1e…
#guard hashStrHex "" !=
  "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"

-- The digest is always 32 bytes and is the byte-for-byte image of
-- `digestBytes`; `Vector.ofFn` makes the length a type-level fact, this
-- checks the contents agree.
#guard (hash "abc".toUTF8.toList).toArray == digestBytes "abc".toUTF8.toList

end MinocrabZkir.Keccak
