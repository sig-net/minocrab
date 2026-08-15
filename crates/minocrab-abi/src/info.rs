//! `contract-info.json`, as compactc writes it — and the FLATTENING of its
//! typed tree into the native slots a ZKIR circuit actually declares.
//!
//! This is the artifact side of the agreement check. The MinoCrab side is a
//! [`CircuitAbi`](minocrab::v3::CircuitAbi) impl, which reports the same two
//! lists ([`atoms`](minocrab::v3::CircuitAbi::atoms) and
//! [`prims`](minocrab::v3::CircuitAbi::prims)); agreement is those lists
//! being equal.
//!
//! THE FLATTENING RULES ARE NOT INVENTED HERE — each is the rule the leaf
//! types in `minocrab_std::v3` already implement, written once more against
//! compactc's own vocabulary so the two can be compared. Where a rule was
//! not already implied by a leaf it is justified from a compiled artifact
//! (see [`CompactType::flatten`]).

use minocrab::v3::Prim;
use minocrab::AlignmentAtom;
use serde::Deserialize;

/// A parsed `contract-info.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct ContractInfo {
    #[serde(rename = "compiler-version")]
    pub compiler_version: String,
    #[serde(rename = "language-version")]
    pub language_version: String,
    #[serde(rename = "runtime-version")]
    pub runtime_version: String,
    /// The contract's OWN circuits, fully typed with argument names.
    pub circuits: Vec<Circuit>,
    /// The interfaces this contract CALLS (`contract Target { … }`
    /// declarations). A caller's artifact is therefore a second source for
    /// a callee's ABI — one without argument names, which is what
    /// `minocrab-interface-gen --from-caller` reads.
    #[serde(default)]
    pub contracts: Vec<ContractDecl>,
}

impl ContractInfo {
    /// Parse `contract-info.json` text.
    pub fn parse(text: &str) -> Result<ContractInfo, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// The circuit called `name`.
    pub fn circuit(&self, name: &str) -> Option<&Circuit> {
        self.circuits.iter().find(|c| c.name == name)
    }

    /// The declared interface called `name` from this contract's
    /// `contracts[]`.
    pub fn declared(&self, name: &str) -> Option<&ContractDecl> {
        self.contracts.iter().find(|c| c.name == name)
    }
}

/// One exported circuit.
#[derive(Debug, Clone, Deserialize)]
pub struct Circuit {
    pub name: String,
    #[serde(default)]
    pub pure: bool,
    /// Whether this circuit is PROVED. A `proof: false` circuit has no
    /// verifier key and no `.zkir`, so it cannot be the target of a
    /// cross-contract call — the whole `Signet` module is `proof: false`,
    /// which is why this is a real check and not a formality.
    #[serde(default)]
    pub proof: bool,
    pub arguments: Vec<Argument>,
    #[serde(rename = "result-type")]
    pub result_type: CompactType,
}

/// One named circuit parameter.
#[derive(Debug, Clone, Deserialize)]
pub struct Argument {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: CompactType,
}

/// A `contract Name { … }` declaration inside someone's source.
#[derive(Debug, Clone, Deserialize)]
pub struct ContractDecl {
    pub name: String,
    pub circuits: Vec<DeclaredCircuit>,
}

/// A circuit of a DECLARED interface: same shape as [`Circuit`] minus the
/// argument names (a declaration lists types only) and minus `proof`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DeclaredCircuit {
    pub name: String,
    #[serde(default)]
    pub pure: bool,
    #[serde(rename = "argument-types")]
    pub argument_types: Vec<CompactType>,
    #[serde(rename = "result-type")]
    pub result_type: CompactType,
}

/// A Compact type, in compactc's own JSON vocabulary.
///
/// Every `type-name` that occurs anywhere in the 312-artifact corpus is a
/// variant here, so a parse failure means a NEW compactc type rather than a
/// gap in this list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactType {
    /// `Bytes<length>`.
    Bytes { length: usize },
    /// Compact's `Uint<0..maxval + 1>`: `maxval` is the INCLUSIVE largest
    /// legal value (compactc's `(tunsigned nat)`), while the range end the
    /// source writes is exclusive (notes/bounded-integers.org §0).
    Uint { maxval: u128 },
    Boolean,
    Field,
    Struct { name: String, elements: Vec<Element> },
    Tuple { types: Vec<CompactType> },
    Vector { length: usize, ty: Box<CompactType> },
    Alias { name: String, ty: Box<CompactType> },
    Enum { name: String, elements: Vec<String> },
    Opaque { ts_type: String },
    Contract { name: String, circuits: Vec<DeclaredCircuit> },
}

/// HAND-WRITTEN, for ONE field: a `Uint<128>`'s `maxval` is 2^128 − 1,
/// which `serde_json`'s `Number` cannot hold — it degrades to `f64` and
/// silently loses the low bits, which would make a `Uint<128>` argument
/// compare unequal to itself. `#[serde(tag = …)]` cannot help either: an
/// internally-tagged enum BUFFERS its input, and the buffer is where the
/// precision goes.
///
/// So each type node is taken as RAW JSON TEXT and dispatched by hand;
/// `maxval` is then parsed from its own digits and is exact. Every other
/// field goes back through `serde_json` (and so, recursively, through this
/// impl).
impl<'de> serde::Deserialize<'de> for CompactType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let raw = <Box<serde_json::value::RawValue>>::deserialize(deserializer)?;
        parse_type(raw.get()).map_err(D::Error::custom)
    }
}

type RawFields = std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>;

fn parse_type(text: &str) -> Result<CompactType, serde_json::Error> {
    use serde::de::Error;
    let fields: RawFields = serde_json::from_str(text)?;
    let type_name: String = field(&fields, "type-name")?;
    Ok(match type_name.as_str() {
        "Bytes" => CompactType::Bytes { length: field(&fields, "length")? },
        "Uint" => CompactType::Uint { maxval: raw_u128(&fields, "maxval")? },
        "Boolean" => CompactType::Boolean,
        "Field" => CompactType::Field,
        "Struct" => CompactType::Struct {
            name: field(&fields, "name")?,
            elements: field(&fields, "elements")?,
        },
        "Tuple" => CompactType::Tuple { types: field(&fields, "types")? },
        "Vector" => CompactType::Vector {
            length: field(&fields, "length")?,
            ty: field(&fields, "type")?,
        },
        "Alias" => CompactType::Alias {
            name: field(&fields, "name")?,
            ty: field(&fields, "type")?,
        },
        "Enum" => CompactType::Enum {
            name: field(&fields, "name")?,
            elements: field(&fields, "elements")?,
        },
        "Opaque" => CompactType::Opaque { ts_type: field(&fields, "tsType")? },
        "Contract" => CompactType::Contract {
            name: field(&fields, "name")?,
            circuits: field(&fields, "circuits")?,
        },
        other => {
            return Err(serde_json::Error::custom(format!(
                "unknown Compact type-name `{other}` — compactc grew a type this crate does not model"
            )))
        }
    })
}

fn field<T: serde::de::DeserializeOwned>(
    fields: &RawFields,
    name: &str,
) -> Result<T, serde_json::Error> {
    use serde::de::Error;
    let raw = fields
        .get(name)
        .ok_or_else(|| serde_json::Error::custom(format!("missing field `{name}`")))?;
    serde_json::from_str(raw.get())
}

/// The one field that must not go through `serde_json::Number`.
fn raw_u128(fields: &RawFields, name: &str) -> Result<u128, serde_json::Error> {
    use serde::de::Error;
    let raw = fields
        .get(name)
        .ok_or_else(|| serde_json::Error::custom(format!("missing field `{name}`")))?;
    raw.get()
        .trim()
        .parse::<u128>()
        .map_err(|e| serde_json::Error::custom(format!("{name} `{}`: {e}", raw.get())))
}

/// One field of a `Struct`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Element {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: CompactType,
}

/// A type flattened to what a circuit declares: the FAB atoms of the value,
/// and the flattened primitive type of each native slot.
///
/// The two lists have different lengths on purpose — a `Bytes<32>` is one
/// atom (`bytes 32`) across two slots — which is the same split
/// [`CircuitAbi`](minocrab::v3::CircuitAbi) makes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Flattened {
    pub atoms: Vec<AlignmentAtom>,
    pub prims: Vec<Prim>,
}

impl Flattened {
    /// Native slots — `prims.len()`.
    pub fn slots(&self) -> usize {
        self.prims.len()
    }

    fn extend(&mut self, other: Flattened) {
        self.atoms.extend(other.atoms);
        self.prims.extend(other.prims);
    }
}

/// A Compact type an interface crate cannot express.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TypeError {
    /// `Opaque` is a TypeScript-side value with no circuit representation.
    #[error("`Opaque<{ts_type}>` has no in-circuit representation, so it cannot cross a contract boundary")]
    Opaque { ts_type: String },
    /// A `Contract` reference as a VALUE (a contract handle passed as data).
    #[error("a `Contract` value (`{name}`) cannot cross a contract boundary: an interface names circuits, not handles")]
    ContractValue { name: String },
}

impl CompactType {
    /// The type's native slots and FAB atoms.
    ///
    /// Rule by rule, with where each one comes from:
    ///
    /// - `Bytes<n>` → one `bytes n` atom over `⌈n/31⌉` slots, the first
    ///   holding the leftover `n mod 31` bytes and the rest 31 each
    ///   (`minocrab_std::v3::BytesN`; `Bytes<32>` is the familiar
    ///   `[8, 248]`).
    /// - `Uint<0..maxval + 1>` → one slot, [`Prim::unsigned`] — compactc's
    ///   own partition of the bound — over a `bytes ⌈bits/8⌉` atom. The
    ///   `maxval` this ABI publishes is INCLUSIVE, while the range end
    ///   Compact writes is exclusive (notes/bounded-integers.org §0), so
    ///   the source spelling of `maxval: 69999` is `Uint<0..70000>`.
    /// - `Boolean` → one slot, `Uint { bits: 1 }`, `bytes 1`.
    /// - `Field` → one slot, no constraint, the `field` atom.
    /// - `Struct` / `Tuple` / `Vector` → their members back to back, in
    ///   declaration order. Compact structs FLATTEN: they add no slot of
    ///   their own, which is why `ContractAddress` and its inner
    ///   `Bytes<32>` have the same layout.
    /// - `Alias` → the aliased type, unchanged.
    /// - `Enum` with `k` variants → `Uint<0..k>`, i.e. `Prim::unsigned(k
    ///   - 1)`. NOT assumed: `compact/examples/casts/advanced_casts`'s
    ///   `test17` takes two `enum TestEnum { A, B, C }` arguments and its
    ///   compiled `.zkir` opens with `less_than tmp arg 3 bits=2; assert`
    ///   twice — exactly `Prim::unsigned(2).constraint()`.
    /// - `Opaque` / a `Contract` value → [`TypeError`].
    pub fn flatten(&self) -> Result<Flattened, TypeError> {
        let mut out = Flattened::default();
        self.push_flat(&mut out)?;
        Ok(out)
    }

    fn push_flat(&self, out: &mut Flattened) -> Result<(), TypeError> {
        match self {
            CompactType::Bytes { length } => {
                out.atoms.push(AlignmentAtom::Bytes { length: *length as u32 });
                for len in bytes_limb_lens(*length) {
                    out.prims.push(Prim::Uint { bits: 8 * len as u32 });
                }
            }
            CompactType::Uint { maxval } => {
                out.atoms.push(AlignmentAtom::Bytes { length: uint_bytes(*maxval) });
                out.prims.push(Prim::unsigned(*maxval));
            }
            CompactType::Boolean => {
                out.atoms.push(AlignmentAtom::Bytes { length: 1 });
                out.prims.push(Prim::Uint { bits: 1 });
            }
            CompactType::Field => {
                out.atoms.push(AlignmentAtom::Field);
                out.prims.push(Prim::Field);
            }
            CompactType::Struct { elements, .. } => {
                for element in elements {
                    element.ty.push_flat(out)?;
                }
            }
            CompactType::Tuple { types } => {
                for ty in types {
                    ty.push_flat(out)?;
                }
            }
            CompactType::Vector { length, ty } => {
                for _ in 0..*length {
                    ty.push_flat(out)?;
                }
            }
            CompactType::Alias { ty, .. } => ty.push_flat(out)?,
            CompactType::Enum { elements, .. } => {
                let maxval = elements.len().saturating_sub(1) as u128;
                out.atoms.push(AlignmentAtom::Bytes { length: uint_bytes(maxval) });
                out.prims.push(Prim::unsigned(maxval));
            }
            CompactType::Opaque { ts_type } => {
                return Err(TypeError::Opaque { ts_type: ts_type.clone() })
            }
            CompactType::Contract { name, .. } => {
                return Err(TypeError::ContractValue { name: name.clone() })
            }
        }
        Ok(())
    }

    /// Look through `Alias` wrappers.
    pub fn resolved(&self) -> &CompactType {
        match self {
            CompactType::Alias { ty, .. } => ty.resolved(),
            other => other,
        }
    }
}

/// Every argument in declaration order, flattened into one list — the
/// callee's whole wire layout.
pub fn flatten_all<'a>(
    types: impl IntoIterator<Item = &'a CompactType>,
) -> Result<Flattened, TypeError> {
    let mut out = Flattened::default();
    for ty in types {
        out.extend(ty.flatten()?);
    }
    Ok(out)
}

/// Bytes per native slot of a `Bytes<len>`, slot order (the leftover chunk
/// first). Mirrors `minocrab_std::v3`'s limbing rule, which is compactc's.
pub fn bytes_limb_lens(len: usize) -> Vec<usize> {
    if len <= 31 {
        return vec![len];
    }
    let limbs = len.div_ceil(31);
    (0..limbs)
        .map(|i| {
            if i == 0 {
                match len % 31 {
                    0 => 31,
                    leftover => leftover,
                }
            } else {
                31
            }
        })
        .collect()
}

/// The FAB byte width of a `(tunsigned maxval)` slot — `⌈bits/8⌉`, matching
/// `minocrab_std::v3::Uint<BITS>`'s and `BoundedUint<BOUND>`'s atoms.
///
/// One statement of the rule, in the frontend beside the constraint table
/// it belongs with (notes/bounded-integers.org §2).
fn uint_bytes(maxval: u128) -> u32 {
    minocrab::v3::uint_atom_bytes(maxval)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> CompactType {
        serde_json::from_str(json).expect("type parses")
    }

    /// The bound that motivates the raw-text deserializer.
    #[test]
    fn a_uint128_bound_survives_parsing() {
        let ty = parse(r#"{"type-name":"Uint","maxval":340282366920938463463374607431768211455}"#);
        assert_eq!(ty, CompactType::Uint { maxval: u128::MAX });
        let flat = ty.flatten().unwrap();
        assert_eq!(flat.prims, vec![Prim::Uint { bits: 128 }]);
        assert_eq!(flat.atoms, vec![AlignmentAtom::Bytes { length: 16 }]);
    }

    /// `Bytes<32>` is one atom across two slots; `Bytes<128>` one atom
    /// across five, leftover first.
    #[test]
    fn bytes_flatten_to_the_limbing_rule() {
        let b32 = parse(r#"{"type-name":"Bytes","length":32}"#).flatten().unwrap();
        assert_eq!(b32.atoms, vec![AlignmentAtom::Bytes { length: 32 }]);
        assert_eq!(b32.prims, vec![Prim::Uint { bits: 8 }, Prim::Uint { bits: 248 }]);

        let b128 = parse(r#"{"type-name":"Bytes","length":128}"#).flatten().unwrap();
        assert_eq!(b128.atoms, vec![AlignmentAtom::Bytes { length: 128 }]);
        assert_eq!(
            b128.prims,
            vec![
                Prim::Uint { bits: 32 },
                Prim::Uint { bits: 248 },
                Prim::Uint { bits: 248 },
                Prim::Uint { bits: 248 },
                Prim::Uint { bits: 248 },
            ]
        );

        assert_eq!(bytes_limb_lens(31), vec![31]);
        assert_eq!(bytes_limb_lens(62), vec![31, 31]);
        assert_eq!(bytes_limb_lens(63), vec![1, 31, 31]);
    }

    /// A struct adds no slot of its own — Compact structs flatten.
    #[test]
    fn structs_flatten_into_their_fields() {
        let ty = parse(
            r#"{"type-name":"Struct","name":"P","elements":[
                 {"name":"a","type":{"type-name":"Boolean"}},
                 {"name":"b","type":{"type-name":"Bytes","length":32}}]}"#,
        );
        let flat = ty.flatten().unwrap();
        assert_eq!(flat.slots(), 3);
        assert_eq!(
            flat.atoms,
            vec![AlignmentAtom::Bytes { length: 1 }, AlignmentAtom::Bytes { length: 32 }]
        );
    }

    /// `enum TestEnum { A, B, C }` → `Uint<0..2>`, which compactc lowers to
    /// `less_than tmp arg 3 bits=2; assert` — read off
    /// `compact/examples/casts/advanced_casts/zkir/test17.zkir`.
    #[test]
    fn an_enum_is_a_bounded_uint() {
        let ty = parse(r#"{"type-name":"Enum","name":"TestEnum","elements":["A","B","C"]}"#);
        let flat = ty.flatten().unwrap();
        assert_eq!(flat.prims, vec![Prim::UintMax { maxval: 2 }]);
        assert_eq!(
            flat.prims[0].constraint(),
            minocrab::v3::LimbConstraint::Bounded { bound: 3, bits: 2 }
        );
    }

    #[test]
    fn opaque_and_contract_values_are_rejected() {
        let opaque = parse(r#"{"type-name":"Opaque","tsType":"JubjubPoint"}"#);
        assert_eq!(
            opaque.flatten(),
            Err(TypeError::Opaque { ts_type: "JubjubPoint".into() })
        );
        let contract = parse(r#"{"type-name":"Contract","name":"Inner","circuits":[]}"#);
        assert!(matches!(contract.flatten(), Err(TypeError::ContractValue { .. })));
    }

    /// `Tuple { types: [] }` is Compact's `[]` — the empty return type.
    #[test]
    fn the_empty_tuple_is_no_slots() {
        let ty = parse(r#"{"type-name":"Tuple","types":[]}"#);
        assert_eq!(ty.flatten().unwrap(), Flattened::default());
    }

    #[test]
    fn vectors_repeat_and_aliases_are_transparent() {
        let ty = parse(
            r#"{"type-name":"Alias","name":"Words","type":
                 {"type-name":"Vector","length":3,"type":{"type-name":"Field"}}}"#,
        );
        let flat = ty.flatten().unwrap();
        assert_eq!(flat.prims, vec![Prim::Field; 3]);
        assert_eq!(flat.atoms, vec![AlignmentAtom::Field; 3]);
        assert!(matches!(ty.resolved(), CompactType::Vector { .. }));
    }
}
