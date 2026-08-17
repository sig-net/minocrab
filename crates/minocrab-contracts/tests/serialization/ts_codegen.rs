//! The PUBLISHED TypeScript decoder: `spec/ts/` (M11 stage 10,
//! notes/borsh-format.org).
//!
//! Stage 8 published the offset tables and the vectors; this generates the
//! CODE that reads them, from the same schema walk, so a TS implementer does
//! not transcribe a table by hand. `spec/ts/borsh-subset.ts` is walked out of
//! `borsh::schema_container_of` exactly as §9's tables are — every offset in
//! it is a literal from the same rows — and the rest of the directory is
//! copied from `tests/serialization/ts/`, which is where those files are
//! EDITED. Two of them carry a substituted region walked out of the same
//! schema: the README's type table, and `vectors.test.ts`'s
//! version-rejection tests.
//!
//! Everything committed under `spec/ts/` is this module's output, byte for
//! byte, and `spec_document::the_committed_typescript_is_generated` fails if
//! it stops being: the code cannot drift from the format any more than the
//! document can.
//!
//! Regenerate with:
//! `cargo test --release -p minocrab-contracts --test serialization_conformance -- \
//!      --ignored --nocapture regenerate_spec`

use std::fmt::Write as _;

use borsh::schema::BorshSchemaContainer;
use borsh::BorshSchema;
use minocrab_std::v3::borsh::schema::{layout_rows, Row};

use super::spec_types::{schema_containers, ByteArray, Flagged, RECORD_FORMAT_VERSION};

// ---- the types the decoder covers -------------------------------------------------

fn container<T: BorshSchema>() -> BorshSchemaContainer {
    BorshSchemaContainer::for_type::<T>()
}

/// Every type `spec/ts/borsh-subset.ts` gets a reader and a writer for: the
/// LEAF TABLE as types (`spec/vectors/leaves.json`) followed by every type
/// the spec's offset tables cover (`schema_containers`, which is §9's list).
///
/// The names are the spec's own, so a vector's `type` — with its parenthetical
/// annotation stripped — indexes the generated registry directly, and
/// `every_vector_type_has_a_typescript_codec` fails the day one does not.
pub fn ts_types() -> Vec<(&'static str, BorshSchemaContainer)> {
    let mut types: Vec<(&'static str, BorshSchemaContainer)> = vec![
        ("bool", container::<bool>()),
        ("u8", container::<u8>()),
        ("u16", container::<u16>()),
        ("u32", container::<u32>()),
        ("u64", container::<u64>()),
        ("u128", container::<u128>()),
        ("[u8; 20]", container::<[u8; 20]>()),
        ("[u8; 32]", container::<[u8; 32]>()),
        ("[u8; 64]", container::<ByteArray<64>>()),
        ("Flagged<u32>", container::<Flagged<u32>>()),
    ];
    types.extend(schema_containers());
    let mut names: Vec<&str> = types.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    let unique = names.len();
    names.dedup();
    assert_eq!(unique, names.len(), "two spec types share a name");
    types
}

// ---- names ------------------------------------------------------------------------

/// The spec's name for a type as a TypeScript identifier: `Flagged<u32>` ↦
/// `FlaggedU32`, `[u8; 20]` ↦ `Bytes20`, `u64` ↦ `U64`.
fn ts_name(spec_name: &str) -> String {
    if let Some(width) = byte_array_width(spec_name) {
        return format!("Bytes{width}");
    }
    spec_name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(pascal)
        .collect()
}

/// `[u8; N]` ↦ `N`.
fn byte_array_width(kind: &str) -> Option<usize> {
    kind.strip_prefix("[u8; ")?.strip_suffix(']')?.parse().ok()
}

fn pascal(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// `FlaggedU32` ↦ `FLAGGED_U32`, for the `_LEN` and `_FIELDS` constants.
fn screaming(name: &str) -> String {
    let mut out = String::new();
    let mut previous = '_';
    for c in name.chars() {
        if c.is_ascii_uppercase() && (previous.is_ascii_lowercase() || previous.is_ascii_digit()) {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
        previous = c;
    }
    out
}

/// A Rust field name as a TypeScript one: `no_words` ↦ `noWords`. The
/// generated `FieldSpec` keeps the SPEC's path, so the two spellings sit
/// beside each other in the published file.
fn camel(snake: &str) -> String {
    let mut words = snake.split('_');
    let first = words.next().unwrap_or_default().to_string();
    first + &words.map(pascal).collect::<String>()
}

// ---- the versioned records ------------------------------------------------------------

/// Is this type a stage-7 record — a `format_version: u8` leaf at offset 0?
///
/// DERIVED from the schema walk, not listed: a third versioned record gets its
/// version check and its rejection test without anybody editing this file, and
/// a record that loses the byte loses both, loudly.
fn is_versioned(rows: &[Row]) -> bool {
    matches!(
        rows.first(),
        Some(row) if row.offset == 0 && row.path == "format_version" && row.kind == "u8"
    )
}

/// Every versioned record as `(the spec's name — which is the `CODECS` key —
/// and the TypeScript one)`, in `ts_types` order.
fn versioned_records() -> Vec<(&'static str, String)> {
    ts_types()
        .into_iter()
        .filter(|(_, container)| is_versioned(&layout_rows(container)))
        .map(|(spec_name, _)| (spec_name, ts_name(spec_name)))
        .collect()
}

// ---- the layout as a tree -----------------------------------------------------------

/// One path segment of a leaf's declaration path: `tx_params.calldata.value.words[0]`.
enum Seg {
    Name(String),
    Index(usize),
}

fn segments(path: &str) -> Vec<Seg> {
    let mut segs = Vec::new();
    for part in path.split('.') {
        let (name, mut rest) = match part.find('[') {
            Some(at) => (&part[..at], &part[at..]),
            None => (part, ""),
        };
        segs.push(Seg::Name(name.to_string()));
        while !rest.is_empty() {
            let end = rest.find(']').expect("an index segment closes");
            let index: usize = rest[1..end].parse().expect("an index segment is a number");
            segs.push(Seg::Index(index));
            rest = &rest[end + 1..];
        }
    }
    segs
}

/// The layout rows, re-nested: the shape the TypeScript type has.
enum Node {
    Leaf(Row),
    Struct(Vec<(String, Node)>),
    Array(Vec<Node>),
}

fn build(rows: &[Row]) -> Node {
    if let [row] = rows {
        if row.path.is_empty() {
            return Node::Leaf(row.clone());
        }
    }
    let mut root = Node::Struct(Vec::new());
    for row in rows {
        assert!(!row.path.is_empty(), "a struct's leaf has a path");
        insert(&mut root, &segments(&row.path), row);
    }
    root
}

fn child_for(rest: &[Seg], row: &Row) -> Node {
    match rest.first() {
        None => Node::Leaf(row.clone()),
        Some(Seg::Index(_)) => Node::Array(Vec::new()),
        Some(Seg::Name(_)) => Node::Struct(Vec::new()),
    }
}

fn insert(parent: &mut Node, segs: &[Seg], row: &Row) {
    let (seg, rest) = segs.split_first().expect("a leaf under a struct has a segment");
    match (parent, seg) {
        (Node::Struct(fields), Seg::Name(name)) => {
            let at = match fields.iter().position(|(existing, _)| existing == name) {
                Some(at) => at,
                None => {
                    fields.push((name.clone(), child_for(rest, row)));
                    fields.len() - 1
                }
            };
            if !rest.is_empty() {
                insert(&mut fields[at].1, rest, row);
            }
        }
        (Node::Array(elements), Seg::Index(index)) => {
            assert!(*index <= elements.len(), "{}: array indices arrive in order", row.path);
            if *index == elements.len() {
                elements.push(child_for(rest, row));
            }
            if !rest.is_empty() {
                insert(&mut elements[*index], rest, row);
            }
        }
        _ => panic!("{}: the path disagrees with the shape built so far", row.path),
    }
}

// ---- emitting the type ---------------------------------------------------------------

fn leaf_ts_type(kind: &str) -> &'static str {
    if byte_array_width(kind).is_some() {
        return "Uint8Array";
    }
    match kind {
        "bool" => "boolean",
        "u8" | "u16" | "u32" => "number",
        "u64" | "u128" => "bigint",
        other => panic!("{other} is not a leaf of the fixed-width subset"),
    }
}

fn indent(depth: usize) -> String {
    "  ".repeat(depth)
}

fn emit_type(node: &Node, depth: usize) -> String {
    match node {
        Node::Leaf(row) => leaf_ts_type(&row.kind).to_string(),
        Node::Struct(fields) => {
            let mut out = String::from("{\n");
            for (name, child) in fields {
                let _ = writeln!(
                    out,
                    "{}readonly {}: {};",
                    indent(depth + 1),
                    camel(name),
                    emit_type(child, depth + 1)
                );
            }
            let _ = write!(out, "{}}}", indent(depth));
            out
        }
        Node::Array(elements) => {
            let inner: Vec<String> = elements.iter().map(|e| emit_type(e, depth)).collect();
            // Fixed length, in the type: this format has no length prefix to
            // read, so a `T[]` would be the wrong statement.
            format!("readonly [{}]", inner.join(", "))
        }
    }
}

// ---- emitting the reader, the writer and the leaf list --------------------------------

/// The `DataView` call that reads one leaf at its published offset.
fn leaf_getter(row: &Row) -> String {
    match byte_array_width(&row.kind) {
        Some(width) => format!("getBytes(view, {}, {width})", row.offset),
        None => {
            let getter = match row.kind.as_str() {
                "bool" => "getBool",
                "u8" => "getU8",
                "u16" => "getU16",
                "u32" => "getU32",
                "u64" => "getU64",
                "u128" => "getU128",
                other => panic!("{other} is not a leaf of the fixed-width subset"),
            };
            format!("{getter}(view, {})", row.offset)
        }
    }
}

fn leaf_setter(row: &Row, access: &str) -> String {
    match byte_array_width(&row.kind) {
        Some(width) => format!("setBytes(view, {}, {width}, {access});", row.offset),
        None => {
            let setter = match row.kind.as_str() {
                "bool" => "setBool",
                "u8" => "setU8",
                "u16" => "setU16",
                "u32" => "setU32",
                "u64" => "setU64",
                "u128" => "setU128",
                other => panic!("{other} is not a leaf of the fixed-width subset"),
            };
            format!("{setter}(view, {}, {access});", row.offset)
        }
    }
}

fn emit_read(node: &Node, depth: usize) -> String {
    match node {
        Node::Leaf(row) => leaf_getter(row),
        Node::Struct(fields) => {
            let mut out = String::from("{\n");
            for (name, child) in fields {
                let _ = writeln!(
                    out,
                    "{}{}: {},",
                    indent(depth + 1),
                    camel(name),
                    emit_read(child, depth + 1)
                );
            }
            let _ = write!(out, "{}}}", indent(depth));
            out
        }
        Node::Array(elements) => {
            let mut out = String::from("[\n");
            for element in elements {
                let _ = writeln!(out, "{}{},", indent(depth + 1), emit_read(element, depth + 1));
            }
            let _ = write!(out, "{}]", indent(depth));
            out
        }
    }
}

fn emit_write(node: &Node, access: &str, out: &mut String) {
    match node {
        Node::Leaf(row) => {
            let _ = writeln!(out, "  {}", leaf_setter(row, access));
        }
        Node::Struct(fields) => {
            for (name, child) in fields {
                emit_write(child, &format!("{access}.{}", camel(name)), out);
            }
        }
        Node::Array(elements) => {
            for (i, element) in elements.iter().enumerate() {
                emit_write(element, &format!("{access}[{i}]"), out);
            }
        }
    }
}

fn emit_leaves(node: &Node, access: &str, out: &mut Vec<String>) {
    match node {
        Node::Leaf(_) => out.push(access.to_string()),
        Node::Struct(fields) => {
            for (name, child) in fields {
                emit_leaves(child, &format!("{access}.{}", camel(name)), out);
            }
        }
        Node::Array(elements) => {
            for (i, element) in elements.iter().enumerate() {
                emit_leaves(element, &format!("{access}[{i}]"), out);
            }
        }
    }
}

// ---- the generated module --------------------------------------------------------------

const MODULE_HEADER: &str = "\
/**
 * GENERATED — do not edit. Every offset below is walked out of the same Borsh
 * schema that produced `spec/borsh-subset.md` §9's tables and
 * `spec/vectors/*.json`.
 *
 * Regenerate with:
 * `cargo test --release -p minocrab-contracts --test serialization_conformance -- \\
 *      --ignored regenerate_spec`
 * (generator: `crates/minocrab-contracts/tests/serialization/ts_codegen.rs`).
 *
 * This IS Borsh, restricted to the fixed-width subset: every type here has a
 * width that does not depend on its value, so every offset is a constant and
 * a reader is a `DataView` at that constant. That is why this file imports
 * nothing but `./primitives.ts` and needs no package installed.
 *
 * `borsh-js` remains the alternative: the declarations in
 * `spec/borsh-subset.md` are ordinary Borsh declarations, so a library decodes
 * these same bytes. Use whichever you prefer — this file exists so that a
 * dependency is a CHOICE, not a requirement, and so that the offsets are
 * generated rather than transcribed.
 *
 * Integers are LITTLE-ENDIAN (Borsh's rule). `Maybe` is `Flagged`, never
 * `Option`: the payload is ALWAYS present, so the offsets after it do not
 * move — see `spec/borsh-subset.md` §4.
 */

import {
  checkedView,
  getBool,
  getBytes,
  getU8,
  getU16,
  getU32,
  getU64,
  getU128,
  setBool,
  setBytes,
  setU8,
  setU16,
  setU32,
  setU64,
  setU128,
  type AnyCodec,
  type Codec,
  type FieldSpec,
  type LeafValue,
} from './primitives.ts';
";

/// `spec/ts/borsh-subset.ts`: a reader, a writer, an offset table and a codec
/// for every type in [`ts_types`].
pub fn module_source() -> String {
    let mut out = String::from(MODULE_HEADER);
    let mut registry: Vec<(String, String)> = Vec::new();

    let _ = writeln!(out, "\n// ---- the record format version {}\n", "-".repeat(49));
    let _ = writeln!(
        out,
        "/**\n \
         * `formatVersion` — the byte at offset 0 of every stage-7 record\n \
         * (`spec/borsh-subset.md` §6). `0x80` is the byte with only the high bit\n \
         * set, so \"this is not a small version number\" is a single bit test.\n \
         */"
    );
    let _ = writeln!(
        out,
        "export const RECORD_FORMAT_VERSION = 0x{RECORD_FORMAT_VERSION:02x};"
    );

    for (spec_name, container) in ts_types() {
        let rows = layout_rows(&container);
        let len: usize = rows.iter().map(|r| r.width).sum();
        let node = build(&rows);
        let name = ts_name(spec_name);
        let upper = screaming(&name);
        let lower = lower_first(&name);

        let _ = write!(out, "\n// ---- {spec_name} ");
        let _ = writeln!(out, "{}\n", "-".repeat(76usize.saturating_sub(spec_name.len())));

        let _ = writeln!(out, "/** The fixed serialized width of `{spec_name}`. */");
        let _ = writeln!(out, "export const {upper}_LEN = {len};\n");

        let _ = writeln!(
            out,
            "/** `{spec_name}`'s offset table — `spec/borsh-subset.md` §9, as data. */"
        );
        let _ = writeln!(out, "export const {upper}_FIELDS: readonly FieldSpec[] = [");
        for row in &rows {
            let path = if row.path.is_empty() { "(the value)" } else { &row.path };
            let _ = writeln!(
                out,
                "  {{ path: '{path}', type: '{}', offset: {}, width: {} }},",
                row.kind, row.offset, row.width
            );
        }
        let _ = writeln!(out, "];\n");

        let ts_type = emit_type(&node, 0);
        match node {
            Node::Leaf(_) => {
                let _ = writeln!(out, "export type {name} = {ts_type};\n");
            }
            _ => {
                let _ = writeln!(out, "export interface {name} {ts_type}\n");
            }
        }

        let bytes = if len == 1 { "1 byte".to_string() } else { format!("{len} bytes") };
        let _ = writeln!(
            out,
            "/** Read a `{spec_name}` from `bytes` at `offset` — {bytes}, fixed. */"
        );
        let _ = writeln!(
            out,
            "export function read{name}(bytes: Uint8Array, offset = 0): {name} {{"
        );
        let _ = writeln!(out, "  const view = checkedView(bytes, offset, {upper}_LEN);");
        if is_versioned(&rows) {
            // THE NAMED REJECTION `spec/borsh-subset.md` §6 requires: byte 0
            // first, before any offset that a format change may have moved.
            let _ = writeln!(
                out,
                "  // The version byte FIRST — `spec/borsh-subset.md` §6: a decoder reads byte 0"
            );
            let _ = writeln!(
                out,
                "  // and rejects a record whose format it does not know, BY NAME, before it"
            );
            let _ = writeln!(out, "  // reads a single offset that format may have moved.");
            let _ = writeln!(out, "  const version = getU8(view, 0);");
            let _ = writeln!(out, "  if (version !== RECORD_FORMAT_VERSION) {{");
            let _ = writeln!(out, "    throw new Error(");
            let _ = writeln!(
                out,
                "      'record-version: expected 0x{RECORD_FORMAT_VERSION:02x}, got 0x' + \
                 version.toString(16).padStart(2, '0'),"
            );
            let _ = writeln!(out, "    );");
            let _ = writeln!(out, "  }}");
        }
        let _ = writeln!(out, "  return {};", emit_read(&node, 1));
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(
            out,
            "/** Write a `{spec_name}` into `out` at `offset`, and return `out`. */"
        );
        let _ = writeln!(out, "export function write{name}(");
        let _ = writeln!(out, "  value: {name},");
        let _ = writeln!(out, "  out = new Uint8Array({upper}_LEN),");
        let _ = writeln!(out, "  offset = 0,");
        let _ = writeln!(out, "): Uint8Array {{");
        let _ = writeln!(out, "  const view = checkedView(out, offset, {upper}_LEN);");
        emit_write(&node, "value", &mut out);
        let _ = writeln!(out, "  return out;");
        let _ = writeln!(out, "}}\n");

        let mut leaves = Vec::new();
        emit_leaves(&node, "value", &mut leaves);
        assert_eq!(leaves.len(), rows.len(), "{spec_name}: a leaf went missing");
        let _ = writeln!(
            out,
            "/** `{spec_name}`'s leaves, in declaration order — one per `{upper}_FIELDS` entry. */"
        );
        let _ = writeln!(
            out,
            "export function {lower}Leaves(value: {name}): readonly LeafValue[] {{"
        );
        let _ = writeln!(out, "  return [");
        for leaf in &leaves {
            let _ = writeln!(out, "    {leaf},");
        }
        let _ = writeln!(out, "  ];");
        let _ = writeln!(out, "}}\n");

        let _ = writeln!(out, "export const {lower}Codec: Codec<{name}> = {{");
        let _ = writeln!(out, "  name: '{spec_name}',");
        let _ = writeln!(out, "  byteLength: {upper}_LEN,");
        let _ = writeln!(out, "  fields: {upper}_FIELDS,");
        let _ = writeln!(out, "  read: read{name},");
        let _ = writeln!(out, "  write: write{name},");
        let _ = writeln!(out, "  leaves: {lower}Leaves,");
        let _ = writeln!(out, "}};");

        registry.push((spec_name.to_string(), format!("{lower}Codec")));
    }

    let _ = writeln!(
        out,
        "\n// ---- the registry {}\n",
        "-".repeat(62)
    );
    let _ = writeln!(
        out,
        "/**\n \
         * Every codec, under the SPEC's name for its type — the key a vector's\n \
         * `type` carries once its parenthetical annotation is stripped\n \
         * (`'VaultResponse (kind 0, CLAIM, success)'` ↦ `'VaultResponse'`).\n \
         */"
    );
    let _ = writeln!(out, "export const CODECS: Readonly<Record<string, AnyCodec>> = {{");
    for (spec_name, codec) in &registry {
        let _ = writeln!(out, "  '{spec_name}': {codec},");
    }
    let _ = writeln!(out, "}};");
    out
}

// ---- the whole published directory ----------------------------------------------------

/// The static files of `spec/ts/`, copied from `tests/serialization/ts/` —
/// THE PLACE THEY ARE EDITED — verbatim but for their `{{…}}` placeholders
/// (the README's type table, `vectors.test.ts`'s rejection tests). Published as
/// generator output like everything else in the directory, so the committed
/// tree is checkable with one rule: `spec/ts/` is what the generator says it
/// is, byte for byte.
const README_TEMPLATE: &str = include_str!("ts/README.md");
const PRIMITIVES: &str = include_str!("ts/primitives.ts");
const VECTOR_TESTS: &str = include_str!("ts/vectors.test.ts");
const NODE_BUILTINS: &str = include_str!("ts/node-builtins.d.ts");
const TSCONFIG: &str = include_str!("ts/tsconfig.json");

/// The README's generated table of what the decoder covers.
fn readme_types_table() -> String {
    let mut out = String::from("| spec type | TypeScript | bytes |\n|---|---|---:|\n");
    for (spec_name, container) in ts_types() {
        let len: usize = layout_rows(&container).iter().map(|r| r.width).sum();
        let name = ts_name(spec_name);
        let _ = writeln!(out, "| `{spec_name}` | `read{name}` / `write{name}` | {len} |");
    }
    out
}

/// `vectors.test.ts`'s generated section: one version-rejection test per
/// versioned record reader.
///
/// The vectors only ever carry a WELL-FORMED record, so nothing in the
/// vector-driven half of the suite exercises the §6 rejection; these are the
/// negative cases, and they are generated from [`versioned_records`] so the
/// set of readers under test cannot fall behind the set of readers that check.
///
/// The reader is reached through `CODECS`, which the template already imports
/// — a generated test that needed a generated import line would put the
/// hand-written and the generated halves of the file back in step with each
/// other, which is the thing this arrangement is for.
fn version_reject_tests() -> String {
    let mut out = String::new();
    let expected = format!("0x{RECORD_FORMAT_VERSION:02x}");
    for (i, (spec_name, name)) in versioned_records().iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let _ = writeln!(
            out,
            "test('reject: read{name} on a record whose format version is not {expected}', () => {{"
        );
        let _ = writeln!(out, "  const codec = CODECS['{spec_name}'];");
        let _ = writeln!(out, "  const bytes = new Uint8Array(codec.byteLength);");
        let _ = writeln!(out, "  bytes[0] = RECORD_FORMAT_VERSION;");
        let _ = writeln!(
            out,
            "  assert.equal(codec.read(bytes).formatVersion, RECORD_FORMAT_VERSION);"
        );
        let _ = writeln!(out, "  for (const wrong of [0x00, 0x01, 0x7f, 0x81, 0xff]) {{");
        let _ = writeln!(out, "    bytes[0] = wrong;");
        let _ = writeln!(out, "    const hex = wrong.toString(16).padStart(2, '0');");
        let _ = writeln!(out, "    assert.throws(");
        let _ = writeln!(out, "      () => codec.read(bytes),");
        let _ = writeln!(
            out,
            "      new RegExp(`record-version: expected {expected}, got 0x${{hex}}`),"
        );
        let _ = writeln!(out, "      `version 0x${{hex}} must be rejected by name`,");
        let _ = writeln!(out, "    );");
        let _ = writeln!(out, "  }}");
        let _ = writeln!(out, "}});");
    }
    out
}

/// Every committed file of `spec/ts/`: `(file name, contents)`.
pub fn ts_files() -> Vec<(&'static str, String)> {
    vec![
        ("README.md", README_TEMPLATE.replace("{{TYPES}}\n", &readme_types_table())),
        ("primitives.ts", PRIMITIVES.to_string()),
        ("borsh-subset.ts", module_source()),
        (
            "vectors.test.ts",
            VECTOR_TESTS.replace("{{VERSION_REJECTS}}\n", &version_reject_tests()),
        ),
        ("node-builtins.d.ts", NODE_BUILTINS.to_string()),
        ("tsconfig.json", TSCONFIG.to_string()),
    ]
}
