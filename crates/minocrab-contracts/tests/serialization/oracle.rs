//! The two conformance oracles and the schema walk.
//!
//! The format is Borsh, restricted to the fixed-width subset
//! (notes/borsh-format.org): every byte emitted is valid canonical Borsh for
//! the declared types. serde + bincode's fixint/little-endian mode emits the
//! same bytes for that subset, which makes it a second, INDEPENDENT witness:
//! a spec type that stays inside the subset makes the two agree byte for
//! byte, and one that strays (a data-carrying tag, a length-prefixed
//! sequence) makes them disagree. Running both is how the suite tells
//! "conformant" from "borsh happens to encode whatever I wrote".

use borsh::schema::{BorshSchemaContainer, Declaration, Definition, Fields};
use borsh::BorshSerialize;
use serde::Serialize;

/// Oracle 1: canonical Borsh.
pub fn borsh_bytes<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("spec types serialize infallibly")
}

/// Oracle 2: serde through bincode in FIXED-WIDTH LITTLE-ENDIAN mode.
///
/// Spelled out rather than taken from `config::legacy()`: fixed integers
/// (bincode's default is varint, which would make every offset
/// value-dependent — the very thing the subset excludes), little-endian, no
/// length limit.
pub fn bincode_fixint_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let config = bincode::config::standard()
        .with_fixed_int_encoding()
        .with_little_endian()
        .with_no_limit();
    bincode::serde::encode_to_vec(value, config).expect("spec types serialize infallibly")
}

/// One leaf of a type's layout: where a primitive field sits and how wide it
/// is. Walked out of the Borsh schema container, so it is derived from
/// borsh's own view of the type rather than from our declarations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub path: String,
    pub kind: String,
    pub offset: usize,
    pub width: usize,
}

/// Walk a schema container into `(path, kind, offset, width)` leaf rows.
///
/// PANICS on anything outside the fixed-width subset — a length-tagged
/// sequence (`Vec`, `String`), a tagged union (`Option`, any data-carrying
/// enum) or a variable-length range. That panic is a feature: it is the
/// subset check at the schema level, complementing the byte-level one the
/// dual oracle performs.
pub fn layout_rows(container: &BorshSchemaContainer) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut offset = 0usize;
    walk(container, container.declaration(), "", &mut offset, &mut rows);
    rows
}

/// The total fixed width of a schema container — the sum of its leaf widths.
pub fn schema_len(container: &BorshSchemaContainer) -> usize {
    layout_rows(container).iter().map(|r| r.width).sum()
}

fn walk(
    container: &BorshSchemaContainer,
    declaration: &Declaration,
    path: &str,
    offset: &mut usize,
    rows: &mut Vec<Row>,
) {
    let definition = container
        .get_definition(declaration)
        .unwrap_or_else(|| panic!("schema container has no definition for {declaration}"));
    match definition {
        Definition::Primitive(width) => {
            rows.push(Row {
                path: path.to_string(),
                kind: declaration.clone(),
                offset: *offset,
                width: *width as usize,
            });
            *offset += *width as usize;
        }
        Definition::Sequence {
            length_width,
            length_range,
            elements,
        } => {
            assert_eq!(
                *length_width, 0,
                "{path}: {declaration} is length-tagged — outside the fixed-width subset"
            );
            assert_eq!(
                length_range.start(),
                length_range.end(),
                "{path}: {declaration} has a variable length — outside the fixed-width subset"
            );
            let count = *length_range.start() as usize;
            if elements == "u8" {
                // A byte array is one leaf, not N of them.
                rows.push(Row {
                    path: path.to_string(),
                    kind: declaration.clone(),
                    offset: *offset,
                    width: count,
                });
                *offset += count;
            } else {
                for i in 0..count {
                    walk(container, elements, &format!("{path}[{i}]"), offset, rows);
                }
            }
        }
        Definition::Struct { fields } => match fields {
            Fields::NamedFields(fields) => {
                for (name, declaration) in fields {
                    walk(container, declaration, &join(path, name), offset, rows);
                }
            }
            Fields::UnnamedFields(fields) => {
                for (i, declaration) in fields.iter().enumerate() {
                    walk(container, declaration, &join(path, &i.to_string()), offset, rows);
                }
            }
            Fields::Empty => {}
        },
        Definition::Tuple { elements } => {
            for (i, declaration) in elements.iter().enumerate() {
                walk(container, declaration, &join(path, &i.to_string()), offset, rows);
            }
        }
        Definition::Enum { .. } => panic!(
            "{path}: {declaration} is a tagged union — outside the fixed-width subset \
             (Maybe ↦ Flagged, never Option)"
        ),
    }
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{path}.{name}")
    }
}
