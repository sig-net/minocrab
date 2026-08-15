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
/// Every `type-name` that occurs in a position THIS CRATE PARSES — a
/// circuit's arguments and result, and the same for a declared `contract`
/// interface — is a variant here, so a parse failure in one of those means a
/// NEW compactc type rather than a gap in this list.
///
/// The qualifier is load-bearing and was once missing (this doc claimed the
/// whole corpus). Scanning every `type-name` in all 312 artifacts gives
/// sixteen distinct names, and four are NOT modelled: `Map`, `Counter`,
/// `List`, and — before M15 — `JubjubScalar`. All four occur only under
/// `ledger`, which [`ContractInfo`] does not deserialize at all, so nothing
/// breaks. But "the corpus covers it" was the wrong warrant: no corpus
/// contract takes a `JubjubScalar` ARGUMENT and one perfectly well could, so
/// the three curve scalar/base names are modelled below on the strength of a
/// compiled fixture rather than of corpus frequency
/// (notes/opaque-bridging.org §0c).
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
    /// `Opaque<'ts-type'>` — and ALSO, under an [`CompactType::Alias`] of the
    /// same name, compactc's spelling for the two curve POINT types. See
    /// [`CompactType::curve_point`].
    Opaque { ts_type: String },
    /// `JubjubScalar` — one native `Scalar<Jubjub>` slot, one `field` atom.
    JubjubScalar,
    /// `Secp256k1Base` — one native `Base<Secp256k1>` slot, atoms `b24, b8`.
    Secp256k1Base,
    /// `Secp256k1Scalar` — one native `Scalar<Secp256k1>` slot, atoms `b24, b8`.
    Secp256k1Scalar,
    Contract { name: String, circuits: Vec<DeclaredCircuit> },
}

/// Which curve type an `Opaque` spelling denotes, if any — the two POINT
/// types, which compactc publishes as `Opaque` and which have perfectly
/// ordinary in-circuit representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurvePoint {
    /// `Point<Secp256k1>`: one slot, atoms `b24, b8, b24, b8, field`.
    Secp256k1,
    /// `Point<Jubjub>`: one slot, atoms `field, field`.
    Jubjub,
}

impl CurvePoint {
    /// The FAB atoms the point's `encode` produces (notes/ledger-abi.org §3),
    /// matching `minocrab_std::v3::{Secp256k1Point, JubjubPoint}`'s
    /// `CircuitAbi::push_atoms` one for one.
    pub fn atoms(self) -> Vec<AlignmentAtom> {
        match self {
            CurvePoint::Secp256k1 => vec![
                AlignmentAtom::Bytes { length: 24 }, // x, low 24 bytes
                AlignmentAtom::Bytes { length: 8 },  // x, high 8 bytes
                AlignmentAtom::Bytes { length: 24 }, // y, low 24 bytes
                AlignmentAtom::Bytes { length: 8 },  // y, high 8 bytes
                AlignmentAtom::Field,                // the infinity flag
            ],
            CurvePoint::Jubjub => vec![AlignmentAtom::Field, AlignmentAtom::Field],
        }
    }
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
        "JubjubScalar" => CompactType::JubjubScalar,
        "Secp256k1Base" => CompactType::Secp256k1Base,
        "Secp256k1Scalar" => CompactType::Secp256k1Scalar,
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
///
/// There used to be an `Opaque` variant here, saying that an `Opaque` "has no
/// in-circuit representation, so it cannot cross a contract boundary". It was
/// wrong twice over — an opaque is one unconstrained slot and does cross a
/// boundary, and half the corpus's `Opaque` nodes are curve points — and the
/// concrete cost was that the erc20-vault's own `initialize` could not be
/// flattened. M15 DELETED the variant rather than rewording it: there is no
/// longer a Compact type spelled `Opaque` that cannot cross a boundary, and a
/// variant nothing constructs is worse than no variant at all
/// (notes/opaque-bridging.org §0b).
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TypeError {
    /// A `Contract` reference as a VALUE (a contract handle passed as data).
    #[error("a `Contract` value (`{name}`) cannot cross a contract boundary: an interface names circuits, not handles")]
    ContractValue { name: String },
    /// A Compact type that IS a native ZKIR value but has no
    /// `minocrab_std::v3` leaf yet, so nothing can name its slot.
    ///
    /// The three curve scalar/base types. They are modelled as
    /// [`CompactType`] variants — a `JubjubScalar` circuit argument compiles,
    /// so meeting one should say what it is rather than "compactc grew a type
    /// this crate does not model" — and refused here, because flattening one
    /// means giving it a [`Prim`], and the only honest `Prim` for a slot whose
    /// wire is not a field element is a new variant with a leaf behind it.
    /// M15 declined to invent that row for a type no corpus artifact takes as
    /// an argument (notes/opaque-bridging.org §6, corrected as built).
    #[error("`{compact_type}` is a native ZKIR value with no MinoCrab leaf type yet, so an interface cannot name its slot")]
    NoLeaf { compact_type: &'static str },
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
    /// - `Alias` → the aliased type, unchanged — EXCEPT the two curve-point
    ///   spellings, which [`CompactType::curve_point`] catches first.
    /// - `Opaque<'ts'>` → one slot, [`Prim::Opaque`] (so no constraint at all,
    ///   which is compactc's `[(topaque …) instr*]` line) over one `compress`
    ///   atom. NOT an error: an opaque enters circuits, it just carries no
    ///   range (notes/opaque-bridging.org §0a).
    /// - `Alias { name, Opaque { tsType: name } }` for `Secp256k1Point` /
    ///   `JubjubPoint` → one slot, [`Prim::Point`], over that point's `encode`
    ///   atoms. This is compactc's ABI spelling for a native curve type, which
    ///   is why the arm must precede the generic `Alias` one.
    /// - `JubjubScalar` / `Secp256k1Base` / `Secp256k1Scalar` → one native
    ///   slot each, no constraint, over their `anative` expansions (`field`
    ///   resp. `b24, b8` — read off the fixture's `encode` outputs).
    /// - `Enum` with `k` variants → `Uint<0..k>`, i.e. `Prim::unsigned(k
    ///   - 1)`. NOT assumed: `compact/examples/casts/advanced_casts`'s
    ///   `test17` takes two `enum TestEnum { A, B, C }` arguments and its
    ///   compiled `.zkir` opens with `less_than tmp arg 3 bits=2; assert`
    ///   twice — exactly `Prim::unsigned(2).constraint()`.
    /// - a `Contract` value → [`TypeError::ContractValue`], the only one left.
    pub fn flatten(&self) -> Result<Flattened, TypeError> {
        let mut out = Flattened::default();
        self.push_flat(&mut out)?;
        Ok(out)
    }

    /// The curve POINT type this spelling denotes, if it is one.
    ///
    /// compactc publishes `Secp256k1Point` and `JubjubPoint` as
    /// `Alias { name, type: Opaque { tsType: name } }` — the ts-type is how the
    /// runtime names the value, and the alias name is the Compact type. Both
    /// halves are required to match, and the name must be one of the two: an
    /// `Opaque<"Secp256k1Point">` under a DIFFERENT alias, or a bare one, is a
    /// user-declared opaque that happens to share a string and must stay one.
    ///
    /// Only the two POINT types get this treatment, because only they are
    /// spelled `Opaque`. `JubjubScalar` and the secp256k1 base/scalar types
    /// publish under their own `type-name` (verified against a compiled
    /// fixture), so they are ordinary variants.
    pub fn curve_point(&self) -> Option<CurvePoint> {
        let CompactType::Alias { name, ty } = self else {
            return None;
        };
        let CompactType::Opaque { ts_type } = &**ty else {
            return None;
        };
        if name != ts_type {
            return None;
        }
        match name.as_str() {
            "Secp256k1Point" => Some(CurvePoint::Secp256k1),
            "JubjubPoint" => Some(CurvePoint::Jubjub),
            _ => None,
        }
    }

    fn push_flat(&self, out: &mut Flattened) -> Result<(), TypeError> {
        // The curve-point spellings, BEFORE the generic `Alias` arm below
        // would look through to a bare `Opaque`.
        if let Some(point) = self.curve_point() {
            out.atoms.extend(point.atoms());
            out.prims.push(Prim::Point);
            return Ok(());
        }
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
            // One slot, one `compress` atom, and NO constraint — the prim
            // says so, not this arm. The `ts_type` does not enter the
            // flattening at all: two opaques of different TS types have the
            // same layout, and it is the Rust type parameter that keeps them
            // from being interchangeable.
            CompactType::Opaque { .. } => {
                out.atoms.push(AlignmentAtom::Compress);
                out.prims.push(Prim::Opaque);
            }
            // PARSED so the error can name the type, but NOT flattened — see
            // `TypeError::NoLeaf`. Their atoms are known
            // (notes/ledger-abi.org §3: `field` resp. `b24, b8`) and are
            // deliberately not written here, because atoms without a `Prim`
            // are half a row and half a row is how a wrong one gets in.
            CompactType::JubjubScalar => {
                return Err(TypeError::NoLeaf { compact_type: "JubjubScalar" })
            }
            CompactType::Secp256k1Base => {
                return Err(TypeError::NoLeaf { compact_type: "Secp256k1Base" })
            }
            CompactType::Secp256k1Scalar => {
                return Err(TypeError::NoLeaf { compact_type: "Secp256k1Scalar" })
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
    fn contract_values_are_rejected() {
        let contract = parse(r#"{"type-name":"Contract","name":"Inner","circuits":[]}"#);
        assert!(matches!(contract.flatten(), Err(TypeError::ContractValue { .. })));
    }

    /// A genuine `Opaque` is one `compress` atom over one unconstrained slot.
    #[test]
    fn an_opaque_is_one_unconstrained_compress_slot() {
        let ty = parse(r#"{"type-name":"Opaque","tsType":"string"}"#);
        let flat = ty.flatten().unwrap();
        assert_eq!(flat.atoms, vec![AlignmentAtom::Compress]);
        assert_eq!(flat.prims, vec![Prim::Opaque]);
        assert_eq!(flat.prims[0].constraint(), minocrab::v3::LimbConstraint::None);

        // The ts-type does not enter the layout: two opaques of different TS
        // types flatten identically, and it is the Rust type parameter that
        // keeps them apart.
        let other = parse(r#"{"type-name":"Opaque","tsType":"Uint8Array"}"#);
        assert_eq!(other.flatten().unwrap(), flat);
    }

    /// The two curve POINT types, which compactc spells `Opaque` under an
    /// `Alias` of the same name — the erc20-vault's `initialize` shape.
    #[test]
    fn the_curve_point_spellings_are_points() {
        let secp = parse(
            r#"{"type-name":"Alias","name":"Secp256k1Point",
                 "type":{"type-name":"Opaque","tsType":"Secp256k1Point"}}"#,
        );
        assert_eq!(secp.curve_point(), Some(CurvePoint::Secp256k1));
        let flat = secp.flatten().unwrap();
        assert_eq!(flat.prims, vec![Prim::Point]);
        assert_eq!(flat.atoms, CurvePoint::Secp256k1.atoms());
        assert_eq!(flat.atoms.len(), 5);

        let jubjub = parse(
            r#"{"type-name":"Alias","name":"JubjubPoint",
                 "type":{"type-name":"Opaque","tsType":"JubjubPoint"}}"#,
        );
        assert_eq!(jubjub.curve_point(), Some(CurvePoint::Jubjub));
        let flat = jubjub.flatten().unwrap();
        assert_eq!(flat.prims, vec![Prim::Point]);
        assert_eq!(
            flat.atoms,
            vec![AlignmentAtom::Field, AlignmentAtom::Field]
        );
    }

    /// BOTH halves of the curve spelling must match, or it is a user's opaque
    /// that happens to share a string. This is the test that stops the
    /// recognition from being a substring match on a name we like.
    #[test]
    fn only_the_exact_curve_spelling_is_a_point() {
        // Right ts-type, different alias name.
        let renamed = parse(
            r#"{"type-name":"Alias","name":"MpcKey",
                 "type":{"type-name":"Opaque","tsType":"Secp256k1Point"}}"#,
        );
        assert_eq!(renamed.curve_point(), None);
        assert_eq!(renamed.flatten().unwrap().prims, vec![Prim::Opaque]);

        // Bare, with no alias at all.
        let bare = parse(r#"{"type-name":"Opaque","tsType":"Secp256k1Point"}"#);
        assert_eq!(bare.curve_point(), None);
        assert_eq!(bare.flatten().unwrap().prims, vec![Prim::Opaque]);

        // An alias whose name matches its ts-type but is not a curve.
        let neither = parse(
            r#"{"type-name":"Alias","name":"Handle",
                 "type":{"type-name":"Opaque","tsType":"Handle"}}"#,
        );
        assert_eq!(neither.curve_point(), None);
        assert_eq!(neither.flatten().unwrap().prims, vec![Prim::Opaque]);
    }

    /// The three curve scalar/base names parse (so the error names the type)
    /// and do not flatten (so nothing invents a `Prim` for them).
    #[test]
    fn curve_scalars_parse_but_have_no_leaf() {
        for (json, name) in [
            (r#"{"type-name":"JubjubScalar"}"#, "JubjubScalar"),
            (r#"{"type-name":"Secp256k1Base"}"#, "Secp256k1Base"),
            (r#"{"type-name":"Secp256k1Scalar"}"#, "Secp256k1Scalar"),
        ] {
            let ty = parse(json);
            assert_eq!(ty.flatten(), Err(TypeError::NoLeaf { compact_type: name }));
        }
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
