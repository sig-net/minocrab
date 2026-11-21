#!/bin/sh
# rename-v3: skip-file
#
# tools/rename-v3.sh — move every crate's `v3` module to the crate root and
# drop the `3` suffixes (M48 rung K). Usage: rename-v3.sh <worktree>
#
# IDEMPOTENT: a second run on the renamed tree changes nothing (every rule
# keys on an old name or an old path, and the moves run only for paths that
# exist). Written to be re-run on any branch of this repository that
# predates the rename, including files it has never seen: it works from
# patterns over the tracked files, not from a file list.
#
# What it does, in order:
#  1. git mv: in each of minocrab, minocrab-ir, minocrab-std, minocrab-sim
#     and minocrab-zkir, src/v3.rs -> src/<name>.rs (the name says what the
#     file holds: circuit, builder, leaves, vm, io) and src/v3/** -> src/**;
#     crates/*/{tests,examples}/v3_*.rs lose the prefix (skipped, with a
#     message, where the unprefixed name exists).
#  2. Structure, for each crate whose src/v3.rs it moved: the out-of-line
#     `mod x;` declarations (with their doc comments and attributes) move
#     from src/<name>.rs to lib.rs, in place of `pub mod v3;`, beside
#     `mod <name>; pub use <name>::*;`; relative `x::` paths left in
#     src/<name>.rs become `crate::x::`; the few items of src/<name>.rs its
#     former child modules reach become `pub(crate)`; string paths that
#     climbed out of src/v3/ (include_str!, lean_proof!) lose one `../`;
#     and the deprecated `pub mod v3` compatibility shim is written into
#     lib.rs between `rename-v3: begin shim` / `end shim` markers.
#  3. Text, over every tracked *.rs *.toml *.md *.org *.sh *.yml *.lean
#     outside corpus/, bug-reports/, plan.org, CLAUDE.md, notes/ and
#     milestones.org: the `v3` path segment goes from `crate::v3::`,
#     `super::v3::`, `$crate::v3::`, `minocrab{,_std,_ir,_sim,_zkir}::v3`
#     (also token-spaced `:: v3 ::`) and bare `v3::`; source paths follow
#     the moves; the renamed items lose the `3` (explicit table below, word
#     boundaries); the renamed tests' names lose the `v3_`.
#     `midnight_zkir_v3`, `zkir-v3`, "ZKIR v3" and corpus file names are
#     never matched.
#  4. notes/: only the reference notes in NOTE_PATHS get the source-path
#     renames (so their file references do not dangle); the other notes and
#     milestones.org are history and are left alone.
#
# Text between `rename-v3: begin shim` and `rename-v3: end shim`, and any
# file carrying `rename-v3: skip-file`, is never rewritten: that is where
# the old names are kept on purpose.
set -eu
wt="${1:?usage: rename-v3.sh <worktree>}"
cd "$wt"
exec python3 -I - "$wt" <<'PY'
import os, re, subprocess, sys

def git(*args, capture=True):
    r = subprocess.run(["git", *args], check=True, text=True,
                       stdout=subprocess.PIPE if capture else None)
    return r.stdout if capture else ""

# --- the tables ---------------------------------------------------------------

# crate dir -> (crate ident, name of the file src/v3.rs becomes)
CRATES = {
    "minocrab": ("minocrab", "circuit"),
    "minocrab-ir": ("minocrab_ir", "builder"),
    "minocrab-std": ("minocrab_std", "leaves"),
    "minocrab-sim": ("minocrab_sim", "vm"),
    "minocrab-zkir": ("minocrab_zkir", "io"),
}

# old -> new, word-bounded. Built from the definitions
# (`pub struct|enum|trait|type|fn ...3`) in the five crates; nothing else
# that ends in a digit is touched.
ITEMS = [
    ("QualifiedShieldedCoinInfo3", "QualifiedShieldedCoinInfo"),
    ("ShieldedCoinInfo3", "ShieldedCoinInfo"),
    ("DisclosedValue3", "DisclosedValue"),
    ("Disclosure3", "Disclosure"),
    ("Compiled3", "Compiled"),
    ("Circuit3", "Circuit"),
    ("AnyWire3", "AnyWire"),
    ("Wire3", "Wire"),
    ("Builder3", "Builder"),
    ("Report3", "Report"),
    ("Run3", "Run"),
    ("Vis3", "Vis"),
    ("Sim3Error", "SimError"),
    ("bounded_by_vis3", "bounded_by_vis"),   # minocrab-macros, pub(crate)
    ("std_v3", "std_root"),                  # minocrab-macros, a local naming ::minocrab_std::v3
]

# The shim's deprecated aliases, per crate: (old, new, generics, kind).
ALIASES = {
    "minocrab": [("Circuit3", "Circuit", "", "type"), ("Wire3", "Wire", "<T, V>", "type"),
                 ("AnyWire3", "AnyWire", "<V>", "type"), ("Compiled3", "Compiled", "", "type"),
                 ("Disclosure3", "Disclosure", "", "type")],
    "minocrab-ir": [("Builder3", "Builder", "", "type")],
    "minocrab-std": [("Vis3", "Vis", "", "trait"),
                     ("ShieldedCoinInfo3", "ShieldedCoinInfo", "<V>", "type"),
                     ("QualifiedShieldedCoinInfo3", "QualifiedShieldedCoinInfo", "<V>", "type")],
    "minocrab-sim": [("Run3", "Run", "", "type"), ("Report3", "Report", "", "type"),
                     ("DisclosedValue3", "DisclosedValue", "", "type"),
                     ("Sim3Error", "SimError", "", "type")],
    "minocrab-zkir": [],
}

# What a former child module reaches in src/<name>.rs: private while the
# children were children, `pub(crate)` now they are siblings. Per crate, a
# regex of a top-level definition line's start, or (struct as it is named
# BEFORE the rename, [its private fields]). A no-op where absent; a branch
# whose children reach more fails to build with E0616/E0603 naming the item
# to add here. Access is unchanged in practice: the whole crate was `v3`.
WIDEN = {
    "minocrab-std": [r"fn short_literal_imm\b"],
    "minocrab": [("Circuit3", ["b", "lowering", "guards", "deferred", "witnesses", "private_scopes",
                              "assert_messages"])],
}

# Reference notes (design of record / procedure) whose source paths are
# kept pointing at real files. Every other note, and milestones.org, is a
# dated record and keeps the names it was written with.
NOTE_PATHS = ["notes/contract-api.org", "notes/ir-passes.org", "notes/bounded-integers.org",
              "notes/borsh-format.org", "notes/trust-base.org", "notes/library-api.org",
              "notes/version-bump.org", "notes/zkir-semantics.org", "notes/taint-lint.org",
              "notes/stream-design.org", "notes/hooks-design.org"]

EXTS = (".rs", ".toml", ".md", ".org", ".sh", ".yml", ".lean")
EXCLUDE_PREFIX = ("corpus/", "bug-reports/", "notes/")
EXCLUDE_FILE = {"plan.org", "CLAUDE.md", "milestones.org"}

SHIM_BEGIN = "rename-v3: begin shim"
SHIM_END = "rename-v3: end shim"
SKIP_FILE = "rename-v3: skip-file"

def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()

def write(p, s):
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)

# --- 1. moves -------------------------------------------------------------------

tracked = git("ls-files", "-z").split("\0")
tracked = [t for t in tracked if t]

moved_up = []       # files that climbed out of src/v3/
restructure = []    # crates whose src/v3.rs moved this run
for cdir, (ident, name) in CRATES.items():
    src = f"crates/{cdir}/src"
    if os.path.exists(f"{src}/v3.rs"):
        dst = f"{src}/{name}.rs"
        if os.path.exists(dst):
            sys.exit(f"rename-v3: {dst} exists; choose another name for {src}/v3.rs")
        git("mv", f"{src}/v3.rs", dst)
        restructure.append(cdir)
    for t in sorted(x for x in tracked if x.startswith(f"{src}/v3/")):
        if not os.path.exists(t):
            continue
        dst = f"{src}/" + t[len(f"{src}/v3/"):]
        if os.path.exists(dst):
            sys.exit(f"rename-v3: {dst} exists; {t} cannot move onto it")
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        git("mv", t, dst)
        moved_up.append(dst)
    if os.path.isdir(f"{src}/v3") and not os.listdir(f"{src}/v3"):
        os.rmdir(f"{src}/v3")

renamed_tests = []  # bare names, e.g. "ledger" for v3_ledger
test_re = re.compile(r"^crates/[^/]+/(tests|examples)/v3_([A-Za-z0-9_]+)\.rs$")
for t in tracked:
    m = test_re.match(t)
    if not m or not os.path.exists(t):
        continue
    dst = os.path.join(os.path.dirname(t), m.group(2) + ".rs")
    if os.path.exists(dst):
        print(f"rename-v3: KEPT {t}: {dst} exists (give it a distinguishing name by hand)")
        continue
    git("mv", t, dst)
    renamed_tests.append(m.group(2))
# Directories of a test target (tests/v3_x/mod.rs) move too.
for t in tracked:
    m = re.match(r"^(crates/[^/]+/(tests|examples))/v3_([A-Za-z0-9_]+)/", t)
    if m and os.path.isdir(f"{m.group(1)}/v3_{m.group(3)}"):
        dst = f"{m.group(1)}/{m.group(3)}"
        if os.path.exists(dst):
            print(f"rename-v3: KEPT {m.group(1)}/v3_{m.group(3)}/: {dst} exists")
            continue
        git("mv", f"{m.group(1)}/v3_{m.group(3)}", dst)
        renamed_tests.append(m.group(3))
renamed_tests = sorted(set(renamed_tests))

# --- 2. structure ------------------------------------------------------------------

MOD_DECL = re.compile(r"^(pub(\([a-z]+\))? )?mod ([A-Za-z_][A-Za-z0-9_]*);\s*$")

def shim(cdir):
    ident, _ = CRATES[cdir]
    lines = [
        f"// {SHIM_BEGIN} (tools/rename-v3.sh never rewrites this block)",
        f"/// The pre-rename path: everything that was `{ident}::v3::X` is `{ident}::X`.",
        "/// Kept for the downstream pins only; nothing in this workspace uses it.",
        "#[doc(hidden)]",
        f"#[deprecated(note = \"`{ident}::v3` is gone: the items are at the crate root \\",
        "                     (`{0}::X`) and lose the `3` suffix; this module is removed in the next release\")]".format(ident),
        "pub mod v3 {",
        "    pub use crate::*;",
    ]
    for old, new, gen, kind in ALIASES[cdir]:
        if kind == "trait":
            lines.append(f"    pub use crate::{new} as {old};")
        else:
            lines.append(f"    #[deprecated(note = \"renamed to `{ident}::{new}`\")]")
            lines.append(f"    pub type {old}{gen} = crate::{new}{gen};")
    lines += ["}", f"// {SHIM_END}"]
    return "\n".join(lines) + "\n"

for cdir in restructure:
    ident, name = CRATES[cdir]
    src = f"crates/{cdir}/src"
    body = read(f"{src}/{name}.rs").split("\n")
    out, moved_decls, mods = [], [], []
    for line in body:
        m = MOD_DECL.match(line)
        if m and (os.path.exists(f"{src}/{m.group(3)}.rs") or os.path.exists(f"{src}/{m.group(3)}/mod.rs")):
            # carry the doc comments and attributes directly above it
            carried = []
            while out and (out[-1].startswith("///") or out[-1].startswith("#[")):
                carried.insert(0, out.pop())
            if carried and moved_decls:
                moved_decls.append("")
            moved_decls += carried + [line]
            mods.append(m.group(3))
            continue
        out.append(line)
    text = "\n".join(out)
    # collapse the blank runs the removed declarations leave
    text = re.sub(r"\n{3,}", "\n\n", text)
    # relative paths to the former children, in code (not comments)
    if mods:
        alt = "|".join(sorted(mods, key=len, reverse=True))
        rel = re.compile(r"(?<![\w:$.])(" + alt + r")::(?!<)")
        lines = text.split("\n")
        doclink = re.compile(r"\[`((?:" + alt + r")(?:::[\w:]+)?)`\](?![(\[])")
        for i, line in enumerate(lines):
            if line.lstrip().startswith(("///", "//!")):
                # an intra-doc link to a former child keeps its text and resolves at the root
                line = doclink.sub(lambda m: f"[`{m.group(1)}`](crate::{m.group(1)})", line)
                lines[i] = re.sub(r"\]\((" + alt + r")::", r"](crate::\1::", line)
                continue
            if line.lstrip().startswith("//"):
                continue
            lines[i] = rel.sub(r"crate::\1::", line)
        text = "\n".join(lines)
    # `pub use crate::m;` of a #[macro_export] macro put it under `v3`; at the
    # root, where the macro already is, it is an unused import.
    for mac in re.findall(r"(?m)^#\[macro_export\]\s*\nmacro_rules! (\w+)", text):
        text = re.sub(r"(?m)(^///.*\n)*^pub use crate::" + mac + r";\n\n?", "", text)
    for w in WIDEN.get(cdir, []):
        if isinstance(w, tuple):   # (struct, [private fields])
            st, fields = w
            m = re.search(r"(?m)^pub struct " + re.escape(st) + r"\b[^{;]*\{\n(.*?)^\}", text, re.S)
            if m:
                body = m.group(1)
                for fl in fields:
                    body = re.sub(r"(?m)^(    )(" + re.escape(fl) + r":)", r"\1pub(crate) \2", body)
                text = text[:m.start(1)] + body + text[m.end(1):]
        else:                      # a top-level item, by the start of its definition line
            text = re.sub(r"(?m)^(" + w + r")", r"pub(crate) \1", text)
    write(f"{src}/{name}.rs", text)

    lib = read(f"{src}/lib.rs")
    block = f"mod {name};\n" + ("\n".join(moved_decls) + "\n" if moved_decls else "") + \
            f"pub use {name}::*;\n\n" + shim(cdir)
    new_lib, n = re.subn(r"(?m)^pub mod v3;\n", lambda _: block, lib, count=1)
    if n != 1:
        sys.exit(f"rename-v3: no `pub mod v3;` line in {src}/lib.rs")
    write(f"{src}/lib.rs", new_lib)

# paths that climbed one directory out of src/v3/
for p in moved_up:
    lines = read(p).split("\n")
    for i, line in enumerate(lines):
        if line.lstrip().startswith("//"):
            continue
        if "include_str!(" in line or "include_bytes!(" in line or re.match(r"\s*file:", line):
            lines[i] = re.sub(r"\"\.\./", "\"", line, count=1)
    write(p, "\n".join(lines))

# --- 3. text -----------------------------------------------------------------------------

PREFIX = r"(?:\$crate|crate|super|self|minocrab|minocrab_std|minocrab_ir|minocrab_sim|minocrab_zkir)"
item_re = [(re.compile(r"\b" + re.escape(o) + r"\b"), n) for o, n in ITEMS]
test_res = [(re.compile(r"(?<![\w-])v3_" + re.escape(t) + r"\b"), t) for t in renamed_tests]

def path_rules(text, cdir):
    """Source-path renames: crate-qualified everywhere, bare inside a crate."""
    for c, (_, name) in CRATES.items():
        text = re.sub(r"(?<![\w-])(" + re.escape(c) + r"/src/)v3\.rs\b", r"\g<1>" + name + ".rs", text)
        text = re.sub(r"(?<![\w-])(" + re.escape(c) + r"/src/)v3/", r"\1", text)
    text = re.sub(r"(?<![\w-])(tests|examples)/v3_([A-Za-z0-9_]+)(\.rs|/)",
                  lambda m: f"{m.group(1)}/{m.group(2)}{m.group(3)}" if m.group(2) in renamed_tests else m.group(0),
                  text)
    # a Markdown link whose text was the old file name: `[v3.rs](crates/minocrab-std/src/leaves.rs)`
    text = re.sub(r"\[v3\.rs\]\((crates/[\w-]+/src/)(\w+)\.rs\)", r"[\2.rs](\1\2.rs)", text)
    text = re.sub(r"\[v3/([\w/]+\.rs)\]\((crates/[\w-]+/src/)\1\)", r"[\1](\2\1)", text)
    # a relative rustdoc URL into an old module page (`../../../minocrab_std/v3/trait.X.html`)
    text = re.sub(r"\.\./((?:\.\./)*)(minocrab(?:_std|_ir|_sim|_zkir)?)/v3/", r"\1\2/", text)
    if cdir in CRATES:
        name = CRATES[cdir][1]
        text = re.sub(r"(?<![\w/-])src/v3\.rs\b", f"src/{name}.rs", text)
        text = re.sub(r"(?<![\w/-])src/v3/", "src/", text)
        text = re.sub(r"(?<![\w/.-])v3\.rs\b", f"{name}.rs", text)
        text = re.sub(r"(?<![\w/.-])v3/([A-Za-z0-9_]+(/[A-Za-z0-9_]+)*\.rs)\b", r"\1", text)
    return text

def code_rules(text):
    # the macro expansion tests' bare `v3 :: entry (` is `::minocrab_std::v3 :: entry (`
    text = text.replace("\"v3 :: entry (", "\"minocrab_std :: entry (")
    # path segment: `minocrab_std::v3::X` -> `minocrab_std::X`, `::minocrab_std::v3)` -> `::minocrab_std)`
    text = re.sub(r"(?<![\w-])(" + PREFIX + r")(\s*)::(\s*)v3\b(?!\w)", r"\1", text)
    # bare `v3::X` (our module, from inside its crate or in prose)
    text = re.sub(r"(?<![\w:$\-])v3(\s*)::\s*(?=[A-Za-z_{*])", "", text)
    for r, n in item_re:
        text = r.sub(n, text)
    for r, n in test_res:
        text = r.sub(n, text)
    return text

def protected_apply(text, fn):
    """Apply fn outside the shim blocks."""
    if SKIP_FILE in text[:400]:
        return text
    parts = re.split(r"(?s)(" + re.escape("// " + SHIM_BEGIN) + r".*?" + re.escape(SHIM_END) + r")", text)
    return "".join(p if i % 2 else fn(p) for i, p in enumerate(parts))

def crate_of(path):
    m = re.match(r"^crates/([^/]+)/", path)
    return m.group(1) if m else None

files = [f for f in git("ls-files", "-z").split("\0") if f]
changed = 0
for f in files:
    if not f.endswith(EXTS) or not os.path.isfile(f):
        continue
    if f in EXCLUDE_FILE or f.startswith(EXCLUDE_PREFIX):
        if f in NOTE_PATHS:
            old = read(f)
            new = protected_apply(old, lambda t: path_rules(t, None))
            if new != old:
                write(f, new); changed += 1
        continue
    old = read(f)
    cdir = crate_of(f)
    new = protected_apply(old, lambda t: code_rules(path_rules(t, cdir)))
    if new != old:
        write(f, new); changed += 1
# The derives recognise a circuit's `&mut Circuit` and a struct's `V: Vis`
# by the last path segment; downstream code pinned to the shim still writes
# `Circuit3` / `Vis3`, so the macros accept both spellings while the shim
# lives.
MACROS = "crates/minocrab-macros/src"
if os.path.isdir(MACROS):
    for fname, new in (("circuit.rs", "Circuit"), ("circuit_arg.rs", "Vis")):
        p = f"{MACROS}/{fname}"
        if os.path.exists(p):
            old = read(p)
            txt = re.sub(r'(segment\.ident == "' + new + r'")(?! \|\|)',
                         r"\1 || segment.ident == crate::OLD_" + new.upper(), old)
            if txt != old:
                write(p, txt); changed += 1
    p = f"{MACROS}/lib.rs"
    old = read(p)
    if "OLD_CIRCUIT" not in old:
        block = (f"\n// {SHIM_BEGIN} (tools/rename-v3.sh never rewrites this block)\n"
                 "/// The pre-rename spellings of `&mut Circuit` and `V: Vis`, which code\n"
                 "/// pinned to the deprecated `v3` shims still writes: the derives accept\n"
                 "/// both while the shims live.\n"
                 "const OLD_CIRCUIT: &str = \"Circuit3\";\n"
                 "const OLD_VIS: &str = \"Vis3\";\n"
                 f"// {SHIM_END}\n")
        txt, n = re.subn(r"(?m)^(mod value;\n)", lambda m: m.group(1) + block, old, count=1)
        if n == 1:
            write(p, txt); changed += 1

print(f"rename-v3: {len(restructure)} module(s) moved, {len(moved_up)} file(s) out of src/v3/, "
      f"{len(renamed_tests)} test(s) renamed, {changed} file(s) rewritten")
PY
