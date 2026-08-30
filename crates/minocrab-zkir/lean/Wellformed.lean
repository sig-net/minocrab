/-
SSA well-formedness of the corpus (M27, rung 3's precondition; see
notes/zkir-semantics.org §2 "Memory" and Fold.lean's `WellFormed`): for
every v3 `.zkir` under the directory, check that
  (a) input names are distinct and no instruction redefines one,
  (b) no identifier is defined twice, and
  (c) every wire an instruction reads (operands, returned, guards) is an
      input or was defined by an EARLIER instruction.
Reports each violation with file, index and name; exit 1 on any.
taint.rs and dedup argue from (b)+(c) ("ZKIR v3 is SSA"); this makes
the corpus half of that claim a checked fact.

  lake exe zkir-wellformed ../../../corpus/zkir
-/
import MinocrabZkir

open MinocrabZkir

/-- Violations for one program. -/
def check (p : Program) : List String := Id.run do
  let mut defined : List Ident := []
  let mut bad : List String := []
  for (name, _) in p.inputs do
    if defined.contains name then bad := bad ++ [s!"input {name} declared twice"]
    defined := name :: defined
  let mut idx := 0
  for i in p.instructions do
    for w in i.readWires do
      if !defined.contains w then bad := bad ++ [s!"instruction {idx} reads {w} before any definition"]
    for d in i.defines do
      if defined.contains d then bad := bad ++ [s!"instruction {idx} redefines {d}"]
      defined := d :: defined
    idx := idx + 1
  return bad

def main (args : List String) : IO UInt32 := do
  let some dir := args.head? | do
    IO.eprintln "usage: zkir-wellformed <directory>"
    return 2
  let files ← System.FilePath.walkDir dir
  let zkirs := (files.filter fun f => f.extension = some "zkir").qsort fun a b => a.toString < b.toString
  let mut ok := 0
  let mut bad := 0
  let mut instrs := 0
  for f in zkirs do
    let text ← IO.FS.readFile f
    let json ← IO.ofExcept (Lean.Json.parse text)
    if (← IO.ofExcept (majorOf json)) ≠ 3 then continue
    let p ← IO.ofExcept (Program.decode json)
    instrs := instrs + p.instructions.length
    match check p with
    | [] => ok := ok + 1
    | vs =>
      bad := bad + 1
      for v in vs do IO.eprintln s!"{f}: {v}"
  IO.println s!"{ok} well-formed, {bad} violating ({instrs} instructions)"
  return if bad = 0 then 0 else 1
