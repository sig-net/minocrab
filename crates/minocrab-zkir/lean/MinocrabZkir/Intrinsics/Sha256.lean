/-
SHA-256 (FIPS 180-4) as a pure byte algorithm.

Mathlib-free and dependency-free: this file imports nothing but Lean core,
so it can be read (and audited) on its own, and so the ZKIR intrinsic model
can consult it without dragging the rest of `MinocrabZkir` in.

Everything here is total and structural: the only recursion is `List.range`
folds, so the equation compiler never needs a termination argument, and no
definition is `partial`, `sorry`, or `panic!`.

State lives in `Array`s indexed with `Array.getD`, which is total; every
index used below is in range by construction (the sizes are fixed at 8, 16,
25, 64), so the default never fires. The `#guard`s at the bottom are the
gate: they run at build time, and a `#guard` that evaluates to `false`
fails the build.

Shift note: on `UIntN` Lean reduces the shift amount modulo `N`
(`(1 : UInt32) <<< (32 : UInt32) = 1`). `rotr` below is only ever called
with `1 ≤ n ≤ 31`, where `32 - n` is likewise in `1 ≤ · ≤ 31`, so the
modular reduction is never reached.
-/

namespace MinocrabZkir.Sha256

/-! ## Primitive word operations -/

/-- Rotate a 32-bit word right by `n` bits (`0 ≤ n < 32`). -/
@[inline] def rotr (x : UInt32) (n : UInt32) : UInt32 :=
  (x >>> n) ||| (x <<< (32 - n))

/-! ## Constants -/

/-- The 64 round constants: the first 32 bits of the fractional parts of the
cube roots of the first 64 primes (FIPS 180-4 §4.2.2). -/
def kConst : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

/-! ## The compression state -/

/-- The eight working variables `a … h` (FIPS 180-4 §6.2.2). -/
structure St where
  a : UInt32
  b : UInt32
  c : UInt32
  d : UInt32
  e : UInt32
  f : UInt32
  g : UInt32
  h : UInt32
  deriving Inhabited

/-- `H^(0)`: the first 32 bits of the fractional parts of the square roots of
the first eight primes (FIPS 180-4 §5.3.3). -/
def initState : St :=
  { a := 0x6a09e667, b := 0xbb67ae85, c := 0x3c6ef372, d := 0xa54ff53a,
    e := 0x510e527f, f := 0x9b05688c, g := 0x1f83d9ab, h := 0x5be0cd19 }

/-! ## Padding -/

/-- The eight big-endian bytes of `n` (used for the 64-bit length field;
`UInt8.ofNat` truncates, so only the low 64 bits of `n` are read). -/
def be64 (n : Nat) : Array UInt8 :=
  (List.range 8).foldl (fun acc i => acc.push (UInt8.ofNat (n >>> (8 * (7 - i))))) #[]

/-- FIPS 180-4 §5.1.1 padding: append `0x80`, then the fewest zero bytes that
leave room for the 8-byte big-endian bit length in a whole 64-byte block. -/
def padMessage (msg : List UInt8) : Array UInt8 :=
  let bytes := msg.toArray
  let len := bytes.size
  let rem := (len + 9) % 64
  let zeros := if rem == 0 then 0 else 64 - rem
  (bytes.push 0x80) ++ Array.replicate zeros (0 : UInt8) ++ be64 (len * 8)

/-! ## Message schedule -/

/-- The first sixteen schedule words: the block at `off`, big-endian. -/
def blockWords (bytes : Array UInt8) (off : Nat) : Array UInt32 :=
  (List.range 16).foldl (fun acc i =>
    let j := off + 4 * i
    acc.push <|
      (UInt32.ofNat (bytes.getD j 0).toNat <<< 24)
        ||| (UInt32.ofNat (bytes.getD (j + 1) 0).toNat <<< 16)
        ||| (UInt32.ofNat (bytes.getD (j + 2) 0).toNat <<< 8)
        ||| UInt32.ofNat (bytes.getD (j + 3) 0).toNat) #[]

/-- Extend sixteen words to sixty-four (FIPS 180-4 §6.2.2 step 1). -/
def schedule (w0 : Array UInt32) : Array UInt32 :=
  (List.range 48).foldl (fun w t =>
    let i := t + 16
    let x15 := w.getD (i - 15) 0
    let x2 := w.getD (i - 2) 0
    let s0 := rotr x15 7 ^^^ rotr x15 18 ^^^ (x15 >>> 3)
    let s1 := rotr x2 17 ^^^ rotr x2 19 ^^^ (x2 >>> 10)
    w.push (w.getD (i - 16) 0 + s0 + w.getD (i - 7) 0 + s1)) w0

/-! ## Compression -/

/-- One 64-byte block, given its expanded schedule (FIPS 180-4 §6.2.2). -/
def compress (st : St) (w : Array UInt32) : St :=
  let fin := (List.range 64).foldl (fun s i =>
    let s1 := rotr s.e 6 ^^^ rotr s.e 11 ^^^ rotr s.e 25
    let ch := (s.e &&& s.f) ^^^ ((~~~ s.e) &&& s.g)
    let t1 := s.h + s1 + ch + kConst.getD i 0 + w.getD i 0
    let s0 := rotr s.a 2 ^^^ rotr s.a 13 ^^^ rotr s.a 22
    let maj := (s.a &&& s.b) ^^^ (s.a &&& s.c) ^^^ (s.b &&& s.c)
    let t2 := s0 + maj
    { a := t1 + t2, b := s.a, c := s.b, d := s.c,
      e := s.d + t1, f := s.e, g := s.f, h := s.g }) st
  { a := st.a + fin.a, b := st.b + fin.b, c := st.c + fin.c, d := st.d + fin.d,
    e := st.e + fin.e, f := st.f + fin.f, g := st.g + fin.g, h := st.h + fin.h }

/-- The final chaining value after absorbing every padded block. -/
def finalState (msg : List UInt8) : St :=
  let bytes := padMessage msg
  (List.range (bytes.size / 64)).foldl
    (fun st bi => compress st (schedule (blockWords bytes (bi * 64)))) initState

/-! ## Digest -/

/-- The four big-endian bytes of a word. -/
def u32be (x : UInt32) : Array UInt8 :=
  #[UInt8.ofNat (x >>> 24).toNat, UInt8.ofNat (x >>> 16).toNat,
    UInt8.ofNat (x >>> 8).toNat, UInt8.ofNat x.toNat]

/-- The 32 digest bytes as a plain array. -/
def digestBytes (msg : List UInt8) : Array UInt8 :=
  let s := finalState msg
  u32be s.a ++ u32be s.b ++ u32be s.c ++ u32be s.d ++
  u32be s.e ++ u32be s.f ++ u32be s.g ++ u32be s.h

/-- SHA-256 of `msg`. -/
def hash (msg : List UInt8) : Vector UInt8 32 :=
  let bs := digestBytes msg
  Vector.ofFn fun i => bs.getD i.val 0

/-! ## Build-time test vectors

`#guard` runs at elaboration time and fails the build when its argument
evaluates to `false`, so the vectors below are a compile gate, not a
comment. Expectations were cross-checked against `shasum -a 256`.
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

-- "" (FIPS/NIST empty-string vector)
#guard hashStrHex "" ==
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

-- "abc" (FIPS 180-4 §D.1)
#guard hashStrHex "abc" ==
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

-- The 56-byte two-block vector (FIPS 180-4 §D.2): exercises the padding
-- overflow into a second block.
#guard hashStrHex "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ==
  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

-- 1000 × 'a' (cross-checked with `shasum -a 256`): a multi-block input
-- whose length is not a multiple of the 64-byte block size.
#guard toHex (hash (List.replicate 1000 (0x61 : UInt8))) ==
  "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"

-- 64 × 'a' (cross-checked with `shasum -a 256`): exactly one block, so the
-- padding must add a whole second block.
#guard toHex (hash (List.replicate 64 (0x61 : UInt8))) ==
  "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"

-- 55 × 'a' (cross-checked with `shasum -a 256`): the largest single-block
-- message — one more byte would spill the length field.
#guard toHex (hash (List.replicate 55 (0x61 : UInt8))) ==
  "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"

-- The digest is always 32 bytes and is the byte-for-byte image of
-- `digestBytes`; `Vector.ofFn` makes the length a type-level fact, this
-- checks the contents agree.
#guard (hash "abc".toUTF8.toList).toArray == digestBytes "abc".toUTF8.toList

end MinocrabZkir.Sha256
