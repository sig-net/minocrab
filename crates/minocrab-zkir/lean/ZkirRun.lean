/-
Rung 4's gate executable (notes/zkir-semantics.org §6,
notes/zkir-rung4.org). Two modes:

  lake exe zkir-run <file.zkir> <record>
      Parse the artifact, read the run record's preimage, evaluate it
      with the CONCRETE model (MinocrabZkir.Concrete), and print the
      result block in exactly the format the record's expected block
      uses — `result accept|reject`, then `pis`, `pi_skips`, `outputs`,
      keys repeated to wrap at eight values a line.

  lake exe zkir-run --kat <known-answers.txt>
      Recompute every known-answer vector the Rust reference printed for
      the ported primitives, and report any that differ. This is what
      validates Poseidon / SHA-256 / Keccak-256 / secp256k1 ON THEIR OWN,
      so a whole-circuit disagreement is never the first thing that
      tells you a primitive is wrong.

Both exit non-zero on any failure. `crates/minocrab-zkir/tests/lean_run.rs`
drives both and is the `cargo test` gate; CI's `lean` job runs them beside
`zkir-roundtrip`.
-/
import MinocrabZkir

open MinocrabZkir
open MinocrabZkir.Concrete (C model)

/-! ## Lexemes, shared with the Rust side

A field element is `0x` + little-endian hex bytes, minimal length — the
artifact's own immediate spelling (`MinocrabZkir.immString`). A byte
string is `#` + hex in stream order. -/

private def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

/-- Hex digit pairs, in order. -/
private def hexBytes (s : String) : Option (List UInt8) :=
  let rec go : List Char → Option (List UInt8)
    | [] => some []
    | [_] => none
    | a :: b :: rest => do
      let hi ← hexVal a
      let lo ← hexVal b
      let tl ← go rest
      pure (UInt8.ofNat (hi * 16 + lo) :: tl)
  go s.toList

/-- The text after a literal prefix, or `none` if it is absent. -/
private def afterPrefix (pre s : String) : Option String :=
  if s.startsWith pre then some (String.ofList (s.toList.drop pre.length)) else none

/-- `0x…`, little-endian. -/
private def parseFr (s : String) : Option Fr := do
  let body ← afterPrefix "0x" s
  let bs ← hexBytes body
  if bs.isEmpty then none else pure (Fr.ofNat (leToNat bs))

/-- `#…`, stream order (a bare `#` is the empty string). -/
private def parseBytes (s : String) : Option (List UInt8) := do
  let body ← afterPrefix "#" s
  hexBytes body

private def parseBytes32 (s : String) : Option Bytes32 := do
  let bs ← parseBytes s
  if h : bs.length = 32 then some ⟨bs.toArray, by simp [h]⟩ else none

private def frLexeme (x : Fr) : String := immString (Int.ofNat x.val)

private def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat ('0'.toNat + n) else Char.ofNat ('a'.toNat + n - 10)

private def bytesLexeme (bs : List UInt8) : String :=
  "#" ++ String.ofList (bs.flatMap fun b =>
    [hexDigit (b.toNat / 16), hexDigit (b.toNat % 16)])

/-- `xs` in runs of `n`, structurally (the fuel is the length). -/
private def chunksOf (n : Nat) (xs : List String) : List (List String) :=
  go xs xs.length
where
  go : List String → Nat → List (List String)
    | _, 0 => []
    | [], _ => []
    | xs, f + 1 => xs.take n :: go (xs.drop n) f

/-- The record format's line wrapping: one key line per eight values, a
bare key line for an empty stream. The Rust side writes exactly this. -/
private def wrapped (key : String) (vs : List String) : String :=
  if vs.isEmpty then key ++ "\n"
  else String.join ((chunksOf 8 vs).map fun chunk =>
    key ++ String.join (chunk.map (" " ++ ·)) ++ "\n")

/-! ## The run record -/

structure Record where
  artifact : String := ""
  variant : String := ""
  π : Preimage
  expected : String

private def emptyPreimage : Preimage :=
  { inputs := [], privateTranscript := [], publicTranscriptInputs := []
    publicTranscriptOutputs := [], bindingInput := 0, communicationsCommitment := none }

/-- Parse a record. Everything from the `result` line on is the EXPECTED
block, kept verbatim so the caller can diff it. -/
def parseRecord (text : String) : Except String Record := do
  let mut r : Record := { π := emptyPreimage, expected := "" }
  let mut inExpected := false
  for line in text.splitOn "\n" do
    if inExpected then
      if line ≠ "" || r.expected ≠ "" then
        r := { r with expected := r.expected ++ line ++ "\n" }
      continue
    let trimmed := line.trimAscii.toString
    if trimmed = "" || trimmed.startsWith "#" then continue
    let toks := trimmed.splitOn " " |>.filter (· ≠ "")
    match toks with
    | [] => continue
    | key :: rest =>
      let frs : Except String (List Fr) := rest.mapM fun t =>
        match parseFr t with
        | some x => .ok x
        | none => .error s!"bad field lexeme: {t}"
      match key with
      | "artifact" => r := { r with artifact := rest.headD "" }
      | "variant" => r := { r with variant := String.intercalate " " rest }
      | "inputs" =>
        r := { r with π := { r.π with inputs := r.π.inputs ++ (← frs) } }
      | "private_transcript" =>
        r := { r with π := { r.π with privateTranscript := r.π.privateTranscript ++ (← frs) } }
      | "public_transcript_inputs" =>
        r := { r with π := { r.π with
          publicTranscriptInputs := r.π.publicTranscriptInputs ++ (← frs) } }
      | "public_transcript_outputs" =>
        r := { r with π := { r.π with
          publicTranscriptOutputs := r.π.publicTranscriptOutputs ++ (← frs) } }
      | "binding_input" =>
        match ← frs with
        | [x] => r := { r with π := { r.π with bindingInput := x } }
        | _ => throw "binding_input takes exactly one value"
      | "comm_comm" =>
        if rest = ["none"] then
          r := { r with π := { r.π with communicationsCommitment := none } }
        else match ← frs with
          | [c, rand] =>
            r := { r with π := { r.π with communicationsCommitment := some (c, rand) } }
          | _ => throw "comm_comm takes `none` or two values"
      | "result" =>
        inExpected := true
        r := { r with expected := line ++ "\n" }
      | k => throw s!"unknown record key `{k}`"
  pure r

/-! ## The result block -/

def resultBlock (prog : Program) (π : Preimage) : String :=
  match Eval.run model prog π with
  | .error _ => "result reject\n"
  | .ok res =>
    "result accept\n"
      ++ wrapped "pis" (res.pis.map frLexeme)
      ++ wrapped "pi_skips" (res.piSkips.map fun
          | none => "-"
          | some n => toString n)
      ++ wrapped "outputs" (res.outputs.map fun v =>
          v.type.name ++ ":" ++ String.intercalate "," ((Eval.encode model v).map frLexeme))

/-! ## The known-answer mode -/

private structure Kat where
  op : String
  args : List String
  want : List String

private def parseKat (line : String) : Option Kat :=
  let toks := line.splitOn " " |>.filter (· ≠ "")
  match toks.span (· ≠ "=>") with
  | (lhs, _ :: want) => match lhs with
    | op :: args => some { op, args, want }
    | [] => none
  | _ => none

private def katFrs (args : List String) : Option (List Fr) := args.mapM parseFr

/-- Recompute one vector's right-hand side. `none` means the operation
name is not one this build knows — which is itself a failure, since the
Rust generator and this file are meant to move together. -/
private def evalKat (k : Kat) : Option (List String) :=
  match k.op with
  | "poseidon" => do
    let xs ← katFrs k.args
    pure [frLexeme (Poseidon.hash xs)]
  | "poseidon_commit" => do
    let xs ← katFrs k.args
    match xs.reverse with
    | opening :: revValue => pure [frLexeme (Poseidon.commit revValue.reverse opening)]
    | [] => none
  | "sha256" => do
    let bs ← parseBytes (k.args.headD "")
    pure [bytesLexeme (Sha256.hash bs).toList]
  | "keccak256" => do
    let bs ← parseBytes (k.args.headD "")
    pure [bytesLexeme (Keccak.hash bs).toList]
  | "fab_bytes" => do
    -- The alignment decode `preprocess` runs before SHA-256 / Keccak-256
    -- (Semantics.fabAtom). `reject` covers both ways it fails: too few
    -- limbs, and a limb carrying a byte above its slot.
    let len ← (k.args.headD "").toNat?
    let limbs ← katFrs (k.args.drop 1)
    match Eval.fabAtom (.bytes len) limbs with
    | .ok (bs, _) => pure [bytesLexeme bs]
    | .error _ => pure ["reject"]
  | "fab_field" => do
    let limbs ← katFrs k.args
    match Eval.fabAtom .field limbs with
    | .ok (bs, _) => pure [bytesLexeme bs]
    | .error _ => pure ["reject"]
  | "k256_gen_mul" => do
    let limbs ← katFrs k.args
    let s ← Secp256k1.decodeFq limbs
    pure ((Secp256k1.encodePoint (Secp256k1.mul Secp256k1.generator s)).map frLexeme)
  | "k256_gen_mul_x" => do
    let limbs ← katFrs k.args
    let s ← Secp256k1.decodeFq limbs
    let (x, _) ← Secp256k1.coordinates (Secp256k1.mul Secp256k1.generator s)
    pure [bytesLexeme (Secp256k1.bytesOfFp x).toList]
  | "k256_add" => do
    let limbs ← katFrs k.args
    let p ← Secp256k1.decodePoint (limbs.take 5)
    let q ← Secp256k1.decodePoint (limbs.drop 5)
    pure ((Secp256k1.encodePoint (Secp256k1.add p q)).map frLexeme)
  | "k256_scalar_from_bytes32" => do
    let b ← parseBytes32 (k.args.headD "")
    pure ((Secp256k1.encodeFq (Secp256k1.fqOfBytes b)).map frLexeme)
  | "k256_base_from_bytes32" => do
    let b ← parseBytes32 (k.args.headD "")
    pure ((Secp256k1.encodeFp (Secp256k1.fpOfBytes b)).map frLexeme)
  | "k256_point_decode" => do
    let limbs ← katFrs k.args
    match Secp256k1.decodePoint limbs with
    | some p => pure ((Secp256k1.encodePoint p).map frLexeme)
    | none => pure ["reject"]
  | _ => none

def runKat (text : String) : IO UInt32 := do
  let mut total := 0
  let mut bad := 0
  for line in text.splitOn "\n" do
    let t := line.trimAscii.toString
    if t = "" || t.startsWith "#" then continue
    let some k := parseKat t | do
      IO.eprintln s!"KAT: unparseable line: {t}"
      bad := bad + 1
      continue
    total := total + 1
    match evalKat k with
    | none =>
      IO.eprintln s!"KAT {k.op}: this build cannot evaluate it (args: {k.args})"
      bad := bad + 1
    | some got =>
      if got ≠ k.want then
        bad := bad + 1
        IO.eprintln s!"KAT {k.op} MISMATCH\n  args: {k.args}\n  rust: {k.want}\n  lean: {got}"
  IO.println s!"{total - bad} of {total} known-answer vectors reproduced"
  return if bad = 0 then 0 else 1

/-! ## Main -/

def runRecord (artifact record : System.FilePath) : IO UInt32 := do
  let text ← IO.FS.readFile artifact
  let json ← match Lean.Json.parse text with
    | .ok j => pure j
    | .error e => do IO.eprintln s!"{artifact}: {e}"; return 2
  match majorOf json with
  | .ok 3 => pure ()
  | .ok m => do IO.eprintln s!"{artifact}: ZKIR major {m}, expected 3"; return 2
  | .error e => do IO.eprintln s!"{artifact}: {e}"; return 2
  let prog ← match Program.decode json with
    | .ok p => pure p
    | .error e => do IO.eprintln s!"{artifact}: {e}"; return 2
  -- The honesty guard (Intrinsics/Concrete.lean): refuse rather than
  -- compute with a placeholder for an uninterpreted type.
  if let some why := Concrete.unsupported prog then
    IO.eprintln s!"{artifact}: uninterpreted at rung 4 — {why}"
    return 3
  let rec ← match parseRecord (← IO.FS.readFile record) with
    | .ok r => pure r
    | .error e => do IO.eprintln s!"{record}: {e}"; return 2
  IO.print (resultBlock prog rec.π)
  return 0

def main (args : List String) : IO UInt32 := do
  match args with
  | ["--kat", path] => runKat (← IO.FS.readFile path)
  | [artifact, record] => runRecord artifact record
  | _ => do
    IO.eprintln "usage: zkir-run <file.zkir> <record>\n       zkir-run --kat <known-answers.txt>"
    return 2
