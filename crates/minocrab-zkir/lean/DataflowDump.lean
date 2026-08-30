/-
Rung 2's dump (notes/zkir-semantics.org §8): one line per instruction of
every v3 `.zkir` under the directory —
  <path>\t<index>\t<operands>\t<returned>\t<defines>
with operands comma-joined (`%name` for a wire, `#` for an immediate —
the VALUE of an immediate is the semantics' business, rung 3) and
identifiers comma-joined. `minocrab-ir/tests/lean_dataflow.rs` produces
the same text from the Rust functions and compares.

  lake exe zkir-dataflow ../../../corpus/zkir
-/
import MinocrabZkir

open MinocrabZkir

private def opStr : Operand → String
  | .var n => n
  | .imm _ => "#"

private def join (xs : List String) : String := String.intercalate "," xs

def main (args : List String) : IO UInt32 := do
  let some dir := args.head? | do
    IO.eprintln "usage: zkir-dataflow <directory>"
    return 2
  let files ← System.FilePath.walkDir dir
  let zkirs := (files.filter fun f => f.extension = some "zkir").qsort fun a b => a.toString < b.toString
  let out ← IO.getStdout
  for f in zkirs do
    let text ← IO.FS.readFile f
    let json ← IO.ofExcept (Lean.Json.parse text)
    if (← IO.ofExcept (majorOf json)) ≠ 3 then continue
    let p ← IO.ofExcept (Program.decode json)
    let mut idx := 0
    for i in p.instructions do
      out.putStrLn s!"{f}\t{idx}\t{join (i.operands.map opStr)}\t{join (i.returned.map opStr)}\t{join i.defines}"
      idx := idx + 1
  return 0
