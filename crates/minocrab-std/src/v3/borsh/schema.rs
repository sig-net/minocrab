//! Borsh's own schema, walked into the same offset table
//! [`CircuitBorsh::layout`] produces — the drift alarm between the two
//! declarations of one format.
//!
//! A circuit type and its SPEC type are deliberately two statements of the
//! same layout: the spec type is a plain Rust struct carrying borsh's own
//! derives, so the oracle cannot be a re-derivation of our layout logic. This
//! module is what makes the pair checkable — it walks
//! `borsh::schema_container_of::<Spec>()` into `(path, kind, offset, width)`
//! rows, which is exactly the shape of a [`FieldSpec`], and
//! [`assert_matches_schema`] compares them.
//!
//! Feature-gated on `borsh-schema`, which is OFF by default: `borsh` is a
//! dev-dependency posture, and this module is the only thing in the crate
//! that would link it. Enable it from a `[dev-dependencies]` entry (as
//! minocrab-contracts does), so test builds have it and shipping builds
//! never do.
//!
//! The walk itself came from the M11 stage-0 conformance suite
//! (`minocrab-contracts/tests/serialization/oracle.rs`), which now delegates
//! here rather than keeping a second copy.

use borsh::schema::{BorshSchemaContainer, Declaration, Definition, Fields};
use borsh::BorshSchema;

use super::FieldSpec;

/// One leaf of a spec type's layout, as borsh's schema describes it.
///
/// The same four columns as [`FieldSpec`], deliberately: the cross-check is a
/// plain equality.
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
/// subset check at the schema level, complementing the byte-level ones.
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

/// The layout rows of a spec type.
pub fn rows_of<S: BorshSchema>() -> Vec<Row> {
    layout_rows(&BorshSchemaContainer::for_type::<S>())
}

/// Assert that a circuit type's [`CircuitBorsh::layout`] IS borsh's own
/// schema of its spec type: same paths, same kinds, same offsets, same
/// widths.
///
/// This is what `#[derive(CircuitBorsh)]`'s `#[borsh(spec = …)]` generates a
/// test for. The failure message names the row that moved, because every
/// offset here is a wire commitment.
///
/// [`CircuitBorsh::layout`]: super::CircuitBorsh::layout
pub fn assert_matches_schema<S: BorshSchema>(name: &str, ours: &[FieldSpec]) {
    let theirs = rows_of::<S>();
    let mismatches: Vec<String> = ours
        .iter()
        .map(Some)
        .chain(std::iter::repeat(None))
        .zip(theirs.iter().map(Some).chain(std::iter::repeat(None)))
        .take(ours.len().max(theirs.len()))
        .filter_map(|(ours, theirs)| match (ours, theirs) {
            (Some(a), Some(b))
                if a.path == b.path
                    && a.kind == b.kind
                    && a.offset == b.offset
                    && a.width == b.width =>
            {
                None
            }
            (a, b) => Some(format!("  circuit: {a:?}\n  spec:    {b:?}")),
        })
        .collect();
    assert!(
        mismatches.is_empty(),
        "{name}'s layout is not its spec type's Borsh schema — every offset \
         here is a wire commitment:\n{}",
        mismatches.join("\n")
    );
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
