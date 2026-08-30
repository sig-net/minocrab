/-
Rung 1's gate (notes/zkir-semantics.org §8): for every `.zkir` under the
given directory, parse → print → compare BYTE FOR BYTE with the file.
v2 files (major ≠ 3) are counted and skipped by decision (§1.4). Exit
status is non-zero on any parse error or any differing byte; the first
differing line of each failure is shown.

  lake exe zkir-roundtrip ../../../corpus/zkir
-/
import MinocrabZkir

open MinocrabZkir

/-- First line index where two texts differ, with both lines. -/
private def firstDiff (a b : String) : Option (Nat × String × String) :=
  let la := a.splitOn "\n"
  let lb := b.splitOn "\n"
  let rec go (i : Nat) : List String → List String → Option (Nat × String × String)
    | [], [] => none
    | x :: xs, y :: ys => if x = y then go (i + 1) xs ys else some (i, x, y)
    | x :: _, [] => some (i, x, "<end of output>")
    | [], y :: _ => some (i, "<end of file>", y)
  go 1 la lb

def main (args : List String) : IO UInt32 := do
  let some dir := args.head? | do
    IO.eprintln "usage: zkir-roundtrip <directory>"
    return 2
  let files ← System.FilePath.walkDir dir
  let zkirs := (files.filter fun f => f.extension = some "zkir").qsort fun a b => a.toString < b.toString
  let mut ok := 0
  let mut v2 := 0
  let mut bad := 0
  for f in zkirs do
    let text ← IO.FS.readFile f
    match Lean.Json.parse text with
    | .error e =>
      bad := bad + 1
      IO.eprintln s!"PARSE {f}: {e}"
    | .ok json =>
      match majorOf json with
      | .ok m =>
        if m ≠ 3 then
          v2 := v2 + 1
          continue
      | .error e =>
        bad := bad + 1
        IO.eprintln s!"VERSION {f}: {e}"
        continue
      match Program.decode json with
      | .error e =>
        bad := bad + 1
        IO.eprintln s!"DECODE {f}: {e}"
      | .ok p =>
        let out := p.print
        if out = text then
          ok := ok + 1
        else
          bad := bad + 1
          match firstDiff text out with
          | some (i, want, got) =>
            IO.eprintln s!"DIFF {f} at line {i}\n  file:    {want}\n  printed: {got}"
          | none => IO.eprintln s!"DIFF {f}: same lines, different bytes"
  IO.println s!"{ok} ok, {bad} failed, {v2} v2 skipped ({zkirs.size} files under {dir})"
  return if bad = 0 then 0 else 1
