//! THE IMPORTER: a compactc artifact becomes an interface crate.
//!
//! This is the package-manager answer for the contracts that already
//! exist. Any deployed Midnight contract publishes a `contract-info.json`
//! with every circuit's fully typed signature, so any deployed Midnight
//! contract can be turned into an ordinary Rust crate that a MinoCrab
//! contract imports and calls — Compact-authored or not, ported or not.
//!
//! A CLI, not a `build.rs`. Generated source that nobody can read is a
//! worse interface than a hand-written one: the output is committed,
//! reviewable, and docs.rs-able, and `--check` regenerates it and diffs, so
//! drift between the artifact and the crate is a test failure. (That check
//! is wired as `tests/regenerate.rs` here, over every generated crate in
//! the workspace.)
//!
//! It reads the SAME parse the agreement checker reads
//! (`minocrab_abi::info`), so the generator and the test that validates its
//! output cannot disagree about what the artifact says.
//!
//! ```text
//! minocrab-interface-gen --crate crates/signet-signer-interface
//! minocrab-interface-gen --crate crates/xcall-target-interface --check
//! ```
//!
//! Each generated crate commits `artifact/generator.json`, which records
//! exactly how it was produced — the interface name, the source artifact,
//! the one-sentence summary, and any HAND-WRITTEN modules the crate also
//! carries (a constructor is Compact source, and no artifact has one).

use std::collections::BTreeSet;
use std::path::Path;

use minocrab_abi::info::{Circuit, CompactType, ContractInfo, DeclaredCircuit, Element};
use serde::{Deserialize, Serialize};

pub mod names;

use names::{lower_camel_case, snake_case};

/// `artifact/generator.json` — how this crate was generated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    /// The handle type's name, which is also the crate's subject. Compact's
    /// `contract Foo { … }` block names it; `contract-info.json` does not
    /// carry the contract's own name, so it is recorded here.
    pub interface: String,
    /// One sentence completing "`Interface` — …", for the crate docs.
    pub summary: String,
    /// The artifact directory, relative to the workspace root.
    pub source: String,
    /// Read the CALLER's `contracts[]` declaration of this name instead of
    /// the artifact's own `circuits[]` — how a contract becomes importable
    /// from a caller's artifact alone. Declarations carry no argument
    /// names, so parameters are named `arg0`, `arg1`, …
    #[serde(default, rename = "from-caller", skip_serializing_if = "Option::is_none")]
    pub from_caller: Option<String>,
    /// Hand-written modules the crate declares alongside the generated
    /// items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,
    /// Generate only these circuits (in this order). `None` takes every
    /// circuit the artifact exports, in artifact order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuits: Option<Vec<String>>,
}

impl Options {
    /// Read `<crate_dir>/artifact/generator.json`.
    pub fn read(crate_dir: &Path) -> Result<Options, Error> {
        let path = crate_dir.join("artifact/generator.json");
        let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
            path: path.display().to_string(),
            source,
        })?;
        serde_json::from_str(&text).map_err(|source| Error::Parse {
            path: path.display().to_string(),
            source,
        })
    }
}

/// A type or circuit an interface crate cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported(pub String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Generating, reading or writing.
#[derive(Debug)]
pub enum Error {
    Io { path: String, source: std::io::Error },
    Parse { path: String, source: serde_json::Error },
    Unsupported(Unsupported),
    /// `--check` found a difference.
    Drift { path: String, expected: String, found: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io { path, source } => write!(f, "{path}: {source}"),
            Error::Parse { path, source } => write!(f, "{path}: {source}"),
            Error::Unsupported(u) => write!(f, "{u}"),
            Error::Drift { path, .. } => write!(
                f,
                "{path} is not what the artifact generates — rerun \
                 `minocrab-interface-gen --crate <dir>`"
            ),
        }
    }
}

impl std::error::Error for Error {}

// ---- the type-mapping table -------------------------------------------------

/// One declared item of the generated crate, in emission order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// `pub type Name<V> = Target<V>;`
    Alias { name: String, target: String, doc: String },
    /// `pub struct Name<V: Vis3> { … }`
    Struct { name: String, fields: Vec<(String, String)>, doc: String },
}

impl Item {
    fn name(&self) -> &str {
        match self {
            Item::Alias { name, .. } | Item::Struct { name, .. } => name,
        }
    }
}

/// What the walk accumulates: the generated items (in first-encounter
/// order, definitions before uses) and the stdlib names to import.
#[derive(Default)]
struct Registry {
    items: Vec<Item>,
    std_imports: BTreeSet<&'static str>,
}

impl Registry {
    /// The Rust type of a Compact type, at visibility parameter `V`,
    /// registering whatever it needs along the way.
    ///
    /// THE TABLE:
    /// | Compact                 | Rust                    |
    /// |-------------------------|-------------------------|
    /// | `Bytes<n>`, n ≤ 31      | `Bytes<n, V>`           |
    /// | `Bytes<32>`             | `B32<V>`                |
    /// | `Bytes<n>`, n > 32      | `BytesN<V, n>`          |
    /// | `Uint<0..2^k>`          | `Uint<k, V>`            |
    /// | `Uint<0..n>`, other n   | `BoundedUint<n, V>`     |
    /// | `Boolean`               | `Bool<V>`               |
    /// | `Vector<n, T>`          | `[T; n]`                |
    /// | `ContractAddress`       | `ContractAddress<V>`    |
    /// | `Maybe<T>`              | `Maybe<T, V>`           |
    /// | `Either<A, B>`          | `Either<A, B, V>`       |
    /// | other `struct`          | a generated struct      |
    /// | `Alias`                 | a generated `pub type`  |
    /// | `Enum` over k names     | the `Uint<0..k>` row    |
    ///
    /// The two unsigned rows are one decision (`unsigned_type`), and the
    /// range end is EXCLUSIVE: compactc's `maxval` is `n − 1`, so a
    /// `maxval` of 69999 generates `BoundedUint<70000, V>`
    /// (notes/bounded-integers.org §0). An `enum` of k names is
    /// `Uint<0..k>`, so it takes whichever unsigned row k lands on.
    ///
    /// What remains an error, with a reason: a bare `Field` (every MinoCrab
    /// leaf is range-constrained and a `Field` carries no range), an
    /// `Opaque` (no in-circuit representation at all), a `Contract` handle
    /// passed as data, or a `Tuple` other than Compact's empty `[]`.
    fn rust_type(&mut self, ty: &CompactType) -> Result<String, Unsupported> {
        Ok(match ty {
            CompactType::Bytes { length } => match length {
                0..=31 => {
                    self.std_imports.insert("Bytes");
                    format!("Bytes<{length}, V>")
                }
                32 => {
                    self.std_imports.insert("B32");
                    "B32<V>".to_string()
                }
                _ => {
                    self.std_imports.insert("BytesN");
                    format!("BytesN<V, {length}>")
                }
            },
            CompactType::Uint { maxval } => unsigned_type(*maxval, &mut self.std_imports),
            CompactType::Boolean => {
                self.std_imports.insert("Bool");
                "Bool<V>".to_string()
            }
            CompactType::Vector { length, ty } => {
                format!("[{}; {length}]", self.rust_type(ty)?)
            }
            CompactType::Struct { name, elements } => self.rust_struct(name, elements)?,
            CompactType::Alias { name, ty } => {
                let target = self.rust_type(ty)?;
                let name = pascal(name);
                self.declare(Item::Alias {
                    doc: format!("Compact `{name} = {}`.", render(ty)),
                    target: target.clone(),
                    name: name.clone(),
                })?;
                format!("{name}<V>")
            }
            // A fieldless `enum` of k names is Compact's `Uint<0..k>`
            // (maxval k − 1, the range end exclusive), so it is the same
            // two-way choice an unsigned type is: a bit width where k is a
            // power of two, a bounded leaf otherwise. `_name` is the
            // Compact type's name, which has no Rust representation — the
            // variant INDEX is the whole value.
            CompactType::Enum { name: _name, elements } => {
                unsigned_type(elements.len().saturating_sub(1) as u128, &mut self.std_imports)
            }
            CompactType::Field => {
                return Err(Unsupported(
                    "a bare Compact `Field` argument carries no range constraint, and no \
                     MinoCrab leaf type describes one yet"
                        .into(),
                ))
            }
            CompactType::Tuple { types } if types.is_empty() => {
                return Err(Unsupported("Compact's `[]` is not a value type".into()))
            }
            CompactType::Tuple { .. } => {
                return Err(Unsupported(
                    "a tuple argument has no MinoCrab spelling: name the fields with a \
                     Compact struct"
                        .into(),
                ))
            }
            CompactType::Opaque { ts_type } => {
                return Err(Unsupported(format!(
                    "`Opaque<{ts_type}>` has no in-circuit representation, so it cannot \
                     cross a contract boundary"
                )))
            }
            CompactType::Contract { name, .. } => {
                return Err(Unsupported(format!(
                    "a `Contract` value (`{name}`) cannot cross a contract boundary: an \
                     interface names circuits, not handles"
                )))
            }
        })
    }

    /// A Compact struct: the three the stdlib already has, matched by NAME
    /// AND SHAPE, and everything else generated.
    fn rust_struct(&mut self, name: &str, elements: &[Element]) -> Result<String, Unsupported> {
        let fields: Vec<String> = elements.iter().map(|e| e.name.clone()).collect();
        let names: Vec<&str> = fields.iter().map(String::as_str).collect();
        match (name, names.as_slice()) {
            // `struct ContractAddress { bytes: Bytes<32> }` — Compact's own.
            ("ContractAddress", ["bytes"])
                if matches!(elements[0].ty.resolved(), CompactType::Bytes { length: 32 }) =>
            {
                self.std_imports.insert("ContractAddress");
                return Ok("ContractAddress<V>".to_string());
            }
            ("Maybe", ["is_some", "value"])
                if matches!(elements[0].ty.resolved(), CompactType::Boolean) =>
            {
                self.std_imports.insert("Maybe");
                let inner = self.rust_type(&elements[1].ty)?;
                return Ok(format!("Maybe<{inner}, V>"));
            }
            ("Either", ["is_left", "left", "right"])
                if matches!(elements[0].ty.resolved(), CompactType::Boolean) =>
            {
                self.std_imports.insert("Either");
                let left = self.rust_type(&elements[1].ty)?;
                let right = self.rust_type(&elements[2].ty)?;
                return Ok(format!("Either<{left}, {right}, V>"));
            }
            _ => {}
        }

        // Children first, so a definition precedes its uses.
        let mut rust_fields = Vec::with_capacity(elements.len());
        for element in elements {
            rust_fields.push((snake_case(&element.name), self.rust_type(&element.ty)?));
        }
        let name = pascal(name);
        self.std_imports.insert("CircuitArg");
        self.std_imports.insert("Vis3");
        self.declare(Item::Struct {
            doc: format!(
                "Compact `struct {name} {{ {} }}`.",
                elements
                    .iter()
                    .map(|e| format!("{}: {}", e.name, render(&e.ty)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            fields: rust_fields,
            name: name.clone(),
        })?;
        Ok(format!("{name}<V>"))
    }

    /// Register an item, deduplicating by name. The same name with a
    /// different shape is an ERROR rather than a silent pick: two Compact
    /// structs that share a name and not a layout cannot both be this
    /// crate's `Foo`.
    fn declare(&mut self, item: Item) -> Result<(), Unsupported> {
        if let Some(existing) = self.items.iter().find(|i| i.name() == item.name()) {
            if existing != &item {
                return Err(Unsupported(format!(
                    "`{}` is declared twice with different shapes:\n  {existing:?}\n  {item:?}",
                    item.name()
                )));
            }
            return Ok(());
        }
        self.items.push(item);
        Ok(())
    }
}

/// `2^k − 1` → `k`; anything else is a bound no SIZED leaf type carries, and
/// becomes a [`minocrab_std::v3::BoundedUint`] instead (M14).
///
/// `Err` here is not a rejection any more, it is the fork in
/// [`Gen::rust_type`]: the error text survives only as the reason a bound
/// cannot be a `Uint<BITS>`.
fn power_of_two_bits(maxval: u128) -> Result<u32, Unsupported> {
    if maxval == 0 || maxval & maxval.wrapping_add(1) != 0 {
        return Err(Unsupported(format!(
            "`Uint<0..{}>` is bounded by a `less_than`, not by a bit width",
            maxval.wrapping_add(1)
        )));
    }
    Ok(u128::BITS - maxval.leading_zeros())
}

/// The Rust spelling of an unsigned Compact type with inclusive `maxval`:
/// the sized leaf where the bound is a bit width, the bounded leaf
/// otherwise.
///
/// The BOUND in the generated type is `maxval + 1`, because Compact's range
/// end is EXCLUSIVE (notes/bounded-integers.org §0) — `maxval = 69999` is
/// `Uint<0..70000>` is `BoundedUint<70000, V>`.
fn unsigned_type(maxval: u128, std_imports: &mut BTreeSet<&'static str>) -> String {
    match power_of_two_bits(maxval) {
        Ok(bits) => {
            std_imports.insert("Uint");
            format!("Uint<{bits}, V>")
        }
        Err(_) => {
            std_imports.insert("BoundedUint");
            format!("BoundedUint<{}, V>", maxval + 1)
        }
    }
}

/// The trait's signatures are the item types at `Public`. The
/// substitution is on the IDENTIFIER `V`, not on the letter: a generated
/// `VaultRecord<V>` must not become `PublicaultRecord<Public>`.
fn at_public(ty: &str) -> String {
    let bytes: Vec<char> = ty.chars().collect();
    let mut out = String::with_capacity(ty.len());
    let mut i = 0;
    while i < bytes.len() {
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        let starts = i == 0 || !is_ident(bytes[i - 1]);
        let ends = i + 1 == bytes.len() || !is_ident(bytes[i + 1]);
        if bytes[i] == 'V' && starts && ends {
            out.push_str("Public");
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    out
}

/// A Compact type as Compact writes it — the doc-comment rendering.
fn render(ty: &CompactType) -> String {
    match ty {
        CompactType::Bytes { length } => format!("Bytes<{length}>"),
        // Compact source writes the bit width where there is one
        // (`Uint<128>`), and the range otherwise — 2^128 − 1 spelled out is
        // 39 digits of noise.
        // The range end Compact writes is EXCLUSIVE, so it is `maxval + 1`
        // (notes/bounded-integers.org §0).
        CompactType::Uint { maxval } => match power_of_two_bits(*maxval) {
            Ok(bits) => format!("Uint<{bits}>"),
            Err(_) => format!("Uint<0..{}>", maxval + 1),
        },
        CompactType::Boolean => "Boolean".into(),
        CompactType::Field => "Field".into(),
        CompactType::Struct { name, .. } | CompactType::Enum { name, .. } => name.clone(),
        CompactType::Alias { name, .. } => name.clone(),
        CompactType::Vector { length, ty } => format!("Vector<{length}, {}>", render(ty)),
        CompactType::Tuple { types } if types.is_empty() => "[]".into(),
        CompactType::Tuple { types } => format!(
            "[{}]",
            types.iter().map(render).collect::<Vec<_>>().join(", ")
        ),
        CompactType::Opaque { ts_type } => format!("Opaque<{ts_type}>"),
        CompactType::Contract { name, .. } => name.clone(),
    }
}

fn pascal(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

// ---- generation -------------------------------------------------------------

/// One circuit, however it was declared.
struct Declared {
    name: String,
    /// `(compact name, type)` per parameter, in wire order.
    arguments: Vec<(String, CompactType)>,
    result: CompactType,
}

impl From<&Circuit> for Declared {
    fn from(circuit: &Circuit) -> Declared {
        Declared {
            name: circuit.name.clone(),
            arguments: circuit
                .arguments
                .iter()
                .map(|a| (a.name.clone(), a.ty.clone()))
                .collect(),
            result: circuit.result_type.clone(),
        }
    }
}

impl From<&DeclaredCircuit> for Declared {
    fn from(circuit: &DeclaredCircuit) -> Declared {
        Declared {
            name: circuit.name.clone(),
            arguments: circuit
                .argument_types
                .iter()
                .enumerate()
                .map(|(i, ty)| (format!("arg{i}"), ty.clone()))
                .collect(),
            result: circuit.result_type.clone(),
        }
    }
}

/// THE GENERATOR: an artifact and its options become one `src/lib.rs`.
pub fn generate(info: &ContractInfo, options: &Options) -> Result<String, Error> {
    let declared = select(info, options).map_err(Error::Unsupported)?;
    let mut registry = Registry::default();

    // The trait's own signatures, which is also the walk that registers
    // every type they mention.
    let mut methods = Vec::with_capacity(declared.len());
    for circuit in &declared {
        let mut params = Vec::with_capacity(circuit.arguments.len());
        for (name, ty) in &circuit.arguments {
            let rust = registry.rust_type(ty).map_err(Error::Unsupported)?;
            params.push((snake_case(name), at_public(&rust)));
        }
        let result = match &circuit.result {
            CompactType::Tuple { types } if types.is_empty() => None,
            ty => Some(at_public(&registry.rust_type(ty).map_err(Error::Unsupported)?)),
        };
        methods.push((circuit, params, result));
    }

    let mut out = String::new();
    out.push_str(&header(info, options));
    if !options.modules.is_empty() {
        out.push('\n');
        for module in &options.modules {
            out.push_str(&format!("pub mod {module};\n"));
        }
    }
    out.push('\n');
    out.push_str("use minocrab::Public;\n");
    out.push_str(&format!(
        "use minocrab_std::v3::{{{}}};\n",
        import_list(&registry.std_imports)
    ));

    for item in &registry.items {
        out.push('\n');
        match item {
            Item::Alias { name, target, doc } => {
                out.push_str(&format!("/// {doc}\npub type {name}<V> = {target};\n"));
            }
            Item::Struct { name, fields, doc } => {
                out.push_str(&format!(
                    "/// {doc}\n#[derive(Clone, CircuitArg)]\npub struct {name}<V: Vis3> {{\n"
                ));
                for (field, ty) in fields {
                    out.push_str(&format!("    pub {field}: {ty},\n"));
                }
                out.push_str("}\n");
            }
        }
    }

    // The `contract { … }` block the trait stands for, then the trait.
    out.push_str("\n/// ```text\n");
    out.push_str(&format!("/// contract {} {{\n", options.interface));
    for circuit in &declared {
        out.push_str(&format!("///   {}\n", compact_signature(circuit)));
    }
    out.push_str("/// }\n/// ```\n#[interface]\n");
    out.push_str(&format!("pub trait {} {{\n", options.interface));
    for (i, (circuit, params, result)) in methods.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("    /// `{}`\n", compact_signature(circuit).trim_end_matches(';')));
        let method = snake_case(&circuit.name);
        if lower_camel_case(&method) != circuit.name {
            // The mechanical name would hash to a different entry point.
            out.push_str(&format!("    #[entry_point(name = \"{}\")]\n", circuit.name));
        }
        let params: Vec<String> = params.iter().map(|(n, t)| format!("{n}: {t}")).collect();
        let ret = result.as_ref().map(|r| format!(" -> {r}")).unwrap_or_default();
        let one_line = format!("    fn {method}({}){ret};", params.join(", "));
        if one_line.len() <= 96 {
            out.push_str(&one_line);
            out.push('\n');
        } else {
            out.push_str(&format!("    fn {method}(\n"));
            for param in &params {
                out.push_str(&format!("        {param},\n"));
            }
            out.push_str(&format!("    ){ret};\n"));
        }
    }
    out.push_str("}\n");
    Ok(out)
}

/// The circuits to generate, in order.
fn select(info: &ContractInfo, options: &Options) -> Result<Vec<Declared>, Unsupported> {
    let all: Vec<Declared> = match &options.from_caller {
        None => info.circuits.iter().map(Declared::from).collect(),
        Some(name) => info
            .declared(name)
            .ok_or_else(|| {
                Unsupported(format!("the caller's artifact declares no `contract {name}`"))
            })?
            .circuits
            .iter()
            .map(Declared::from)
            .collect(),
    };
    match &options.circuits {
        None => Ok(all),
        Some(wanted) => wanted
            .iter()
            .map(|name| {
                all.iter()
                    .find(|c| &c.name == name)
                    .map(|c| Declared {
                        name: c.name.clone(),
                        arguments: c.arguments.clone(),
                        result: c.result.clone(),
                    })
                    .ok_or_else(|| Unsupported(format!("the artifact exports no circuit `{name}`")))
            })
            .collect(),
    }
}

/// `circuit deposit(recipient: Bytes<32>, amount: Uint<0..…>): [];`
fn compact_signature(circuit: &Declared) -> String {
    format!(
        "circuit {}({}): {};",
        circuit.name,
        circuit
            .arguments
            .iter()
            .map(|(name, ty)| format!("{name}: {}", render(ty)))
            .collect::<Vec<_>>()
            .join(", "),
        render(&circuit.result)
    )
}

/// rustfmt's ordering for a `use` list, reproduced so the generated file
/// is fmt-clean without shelling out to rustfmt (which would make byte
/// reproducibility depend on a toolchain version).
///
/// Three groups, each alphabetical: names with no uppercase letter
/// (`interface`), then mixed-case names (`BytesN`, `Vis3`), then names with
/// no lowercase letter (`B32`) — which is why `B32` lands last rather than
/// first.
fn import_list(names: &BTreeSet<&'static str>) -> String {
    let mut sorted: Vec<&str> = std::iter::once("interface").chain(names.iter().copied()).collect();
    sorted.sort_by_key(|name| (rustfmt_case_group(name), name.to_string()));
    sorted.join(", ")
}

fn rustfmt_case_group(name: &str) -> u8 {
    match (
        name.chars().any(|c| c.is_uppercase()),
        name.chars().any(|c| c.is_lowercase()),
    ) {
        (false, _) => 0,
        (true, true) => 1,
        (true, false) => 2,
    }
}

/// The crate documentation. Everything but the first paragraph and the
/// source line is fixed text; the wrapping is this function's, so the file
/// is byte-reproducible.
fn header(info: &ContractInfo, options: &Options) -> String {
    let interface = &options.interface;
    let paragraphs = [
        format!("`{interface}` — {}", options.summary),
        "GENERATED by `minocrab-interface-gen` from the callee's own compactc artifact. \
         Edit the artifact or the generator, never this file: \
         `cargo test -p minocrab-interface-gen` regenerates it and fails on any difference."
            .to_string(),
        format!(
            "Source artifact: `{}` (compiler {}, language {}, runtime {}), pinned by \
             `artifact/pin.json` and checked by `tests/artifact_agreement.rs`.",
            options.source, info.compiler_version, info.language_version, info.runtime_version
        ),
        "DECLARATION ORDER IS THE WIRE CONTRACT. A circuit's parameters and a struct's \
         fields flatten, in order, into the limbs hashed into the communications commitment \
         the ledger matches — so reordering or retyping either changes the commitment and \
         breaks every deployed caller. `artifact/interface-schema.txt` freezes that layout; \
         its diff is the semver decision (notes/interface-crates.org §\"Versioning and \
         publishing\")."
            .to_string(),
        "EVERY ARGUMENT AND RESULT IS `Public`, because passing a value to another contract \
         discloses it: it enters the commitment in the clear. A private value must \
         `c.disclose(…)` first, and forgetting is a compile error."
            .to_string(),
        format!(
            "THE INTERFACE CONTAINS NO ADDRESS. `{interface}::at_field(index)` names the \
             sealed ledger cell a deployment keeps the address in, and \
             `{interface}::at(address)` takes one as data."
        ),
    ];
    paragraphs
        .iter()
        .map(|p| wrap(p, 72))
        .collect::<Vec<_>>()
        .join("//!\n")
}

/// Greedy word wrap into `//! ` lines of at most `width` content
/// characters. A single word longer than `width` (a path, a URL) is left
/// alone rather than broken.
fn wrap(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.chars().count() + 1 + word.chars().count() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push_str(&format!("//! {line}\n"));
            line = word.to_string();
        }
    }
    if !line.is_empty() {
        out.push_str(&format!("//! {line}\n"));
    }
    out
}

// ---- the CLI's two verbs ----------------------------------------------------

/// Generate `<crate_dir>/src/lib.rs` from `<crate_dir>/artifact/`.
///
/// The artifact's `contract-info.json` is read from the crate's own
/// `artifact/` directory — the copy the agreement test checks — so the
/// generator and the checker see the same bytes.
pub fn render_crate(crate_dir: &Path) -> Result<String, Error> {
    let options = Options::read(crate_dir)?;
    let path = crate_dir.join("artifact/contract-info.json");
    let text = std::fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    let info = ContractInfo::parse(&text).map_err(|source| Error::Parse {
        path: path.display().to_string(),
        source,
    })?;
    generate(&info, &options)
}

/// Write the generated source.
pub fn write_crate(crate_dir: &Path) -> Result<(), Error> {
    let source = render_crate(crate_dir)?;
    let path = crate_dir.join("src/lib.rs");
    std::fs::write(&path, source).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })
}

/// `--check`: regenerate and diff. THE CODEGEN SNAPSHOT GUARD.
pub fn check_crate(crate_dir: &Path) -> Result<(), Error> {
    let expected = render_crate(crate_dir)?;
    let path = crate_dir.join("src/lib.rs");
    let found = std::fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    if found == expected {
        return Ok(());
    }
    Err(Error::Drift {
        path: path.display().to_string(),
        expected,
        found,
    })
}

/// The first differing line, for a readable failure.
pub fn first_difference(expected: &str, found: &str) -> String {
    for (i, (e, f)) in expected.lines().zip(found.lines()).enumerate() {
        if e != f {
            return format!("line {}:\n  generated: {e}\n  committed: {f}", i + 1);
        }
    }
    format!(
        "the files agree for {} lines; generated has {}, committed {}",
        expected.lines().count().min(found.lines().count()),
        expected.lines().count(),
        found.lines().count()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(interface: &str) -> Options {
        Options {
            interface: interface.into(),
            summary: "a test.".into(),
            source: "somewhere".into(),
            from_caller: None,
            modules: Vec::new(),
            circuits: None,
        }
    }

    fn ty(json: &str) -> CompactType {
        serde_json::from_str(json).expect("type parses")
    }

    fn rust(json: &str) -> Result<String, Unsupported> {
        Registry::default().rust_type(&ty(json))
    }

    /// THE TABLE, row by row.
    #[test]
    fn the_type_mapping_is_the_documented_table() {
        assert_eq!(rust(r#"{"type-name":"Bytes","length":4}"#).unwrap(), "Bytes<4, V>");
        assert_eq!(rust(r#"{"type-name":"Bytes","length":31}"#).unwrap(), "Bytes<31, V>");
        assert_eq!(rust(r#"{"type-name":"Bytes","length":32}"#).unwrap(), "B32<V>");
        assert_eq!(rust(r#"{"type-name":"Bytes","length":256}"#).unwrap(), "BytesN<V, 256>");
        assert_eq!(rust(r#"{"type-name":"Boolean"}"#).unwrap(), "Bool<V>");
        assert_eq!(
            rust(r#"{"type-name":"Uint","maxval":340282366920938463463374607431768211455}"#).unwrap(),
            "Uint<128, V>"
        );
        assert_eq!(rust(r#"{"type-name":"Uint","maxval":255}"#).unwrap(), "Uint<8, V>");
        assert_eq!(
            rust(r#"{"type-name":"Vector","length":3,"type":{"type-name":"Bytes","length":32}}"#)
                .unwrap(),
            "[B32<V>; 3]"
        );
        // `enum E { A, B }` — two variants, so the bound IS a bit width.
        assert_eq!(
            rust(r#"{"type-name":"Enum","name":"E","elements":["A","B"]}"#).unwrap(),
            "Uint<1, V>"
        );
    }

    /// The three stdlib types matched by NAME AND SHAPE.
    #[test]
    fn the_stdlib_structs_are_matched_not_regenerated() {
        assert_eq!(
            rust(
                r#"{"type-name":"Struct","name":"ContractAddress","elements":[
                     {"name":"bytes","type":{"type-name":"Bytes","length":32}}]}"#
            )
            .unwrap(),
            "ContractAddress<V>"
        );
        assert_eq!(
            rust(
                r#"{"type-name":"Struct","name":"Maybe","elements":[
                     {"name":"is_some","type":{"type-name":"Boolean"}},
                     {"name":"value","type":{"type-name":"Bytes","length":32}}]}"#
            )
            .unwrap(),
            "Maybe<B32<V>, V>"
        );
        assert_eq!(
            rust(
                r#"{"type-name":"Struct","name":"Either","elements":[
                     {"name":"is_left","type":{"type-name":"Boolean"}},
                     {"name":"left","type":{"type-name":"Bytes","length":32}},
                     {"name":"right","type":{"type-name":"Bytes","length":32}}]}"#
            )
            .unwrap(),
            "Either<B32<V>, B32<V>, V>"
        );
        // A matched struct declares NOTHING — it is the stdlib's.
        let mut matched = Registry::default();
        matched
            .rust_type(&ty(
                r#"{"type-name":"Struct","name":"ContractAddress","elements":[
                     {"name":"bytes","type":{"type-name":"Bytes","length":32}}]}"#,
            ))
            .unwrap();
        assert!(matched.items.is_empty(), "a matched struct must not be regenerated");

        // The NAME alone is not enough: a struct that merely calls itself
        // `ContractAddress` and holds 20 bytes is a DIFFERENT type, and is
        // generated like any other.
        let mut mismatched = Registry::default();
        mismatched
            .rust_type(&ty(
                r#"{"type-name":"Struct","name":"ContractAddress","elements":[
                     {"name":"bytes","type":{"type-name":"Bytes","length":20}}]}"#,
            ))
            .unwrap();
        assert_eq!(mismatched.items.len(), 1, "a same-named different shape is generated");
    }

    /// Everything an interface crate cannot express, and why.
    #[test]
    fn the_inexpressible_types_are_refused_with_a_reason() {
        for (json, wanted) in [
            (r#"{"type-name":"Opaque","tsType":"JubjubPoint"}"#, "no in-circuit representation"),
            (r#"{"type-name":"Field"}"#, "no range constraint"),
            (r#"{"type-name":"Contract","name":"Inner","circuits":[]}"#, "names circuits, not handles"),
            (
                r#"{"type-name":"Tuple","types":[{"type-name":"Boolean"},{"type-name":"Boolean"}]}"#,
                "name the fields",
            ),
        ] {
            let err = rust(json).expect_err(json);
            assert!(err.0.contains(wanted), "for {json}: {err}");
        }
    }

    /// A bound that is not a bit width is no longer a refusal: it is the
    /// bounded leaf, carrying the EXCLUSIVE range end compactc's source
    /// spelling uses (M14, notes/bounded-integers.org §0 — `maxval: 999` is
    /// `Uint<0..1000>`). An `enum` of k names is `Uint<0..k>`, so it takes
    /// whichever unsigned row k lands on.
    #[test]
    fn a_bound_that_is_not_a_bit_width_is_the_bounded_leaf() {
        for (json, wanted) in [
            (r#"{"type-name":"Uint","maxval":999}"#, "BoundedUint<1000, V>"),
            (r#"{"type-name":"Uint","maxval":69999}"#, "BoundedUint<70000, V>"),
            (r#"{"type-name":"Uint","maxval":9}"#, "BoundedUint<10, V>"),
            // 254 is one BELOW a power of two minus one: `Uint<0..255>`.
            (r#"{"type-name":"Uint","maxval":254}"#, "BoundedUint<255, V>"),
            // …and 255 IS one less than a power of two, so it stays sized.
            (r#"{"type-name":"Uint","maxval":255}"#, "Uint<8, V>"),
            // A 3-name enum is `Uint<0..3>`; a 4-name one is `Uint<2>`.
            (
                r#"{"type-name":"Enum","name":"E","elements":["A","B","C"]}"#,
                "BoundedUint<3, V>",
            ),
            (
                r#"{"type-name":"Enum","name":"E","elements":["A","B","C","D"]}"#,
                "Uint<2, V>",
            ),
        ] {
            assert_eq!(rust(json).unwrap(), wanted, "for {json}");
        }
        // The doc-comment rendering of a Compact type uses the same
        // exclusive spelling.
        assert_eq!(render(&ty(r#"{"type-name":"Uint","maxval":69999}"#)), "Uint<0..70000>");
        assert_eq!(render(&ty(r#"{"type-name":"Uint","maxval":255}"#)), "Uint<8>");
    }

    /// One name, two shapes, is an error rather than a silent pick.
    #[test]
    fn a_name_collision_with_different_shapes_is_an_error() {
        let mut registry = Registry::default();
        registry
            .rust_type(&ty(
                r#"{"type-name":"Struct","name":"P","elements":[
                     {"name":"a","type":{"type-name":"Boolean"}}]}"#,
            ))
            .expect("first shape");
        let err = registry
            .rust_type(&ty(
                r#"{"type-name":"Struct","name":"P","elements":[
                     {"name":"a","type":{"type-name":"Bytes","length":32}}]}"#,
            ))
            .expect_err("second shape must be refused");
        assert!(err.0.contains("declared twice with different shapes"), "{err}");
    }

    /// A struct reached twice is declared once.
    #[test]
    fn a_shared_struct_is_declared_once() {
        let mut registry = Registry::default();
        let shape = r#"{"type-name":"Struct","name":"P","elements":[
                        {"name":"a","type":{"type-name":"Boolean"}}]}"#;
        registry.rust_type(&ty(shape)).unwrap();
        registry.rust_type(&ty(shape)).unwrap();
        assert_eq!(registry.items.len(), 1);
    }

    /// A Compact circuit whose name does not round-trip gets an explicit
    /// `#[entry_point]`, because the mechanical name would hash to a
    /// different entry point.
    #[test]
    fn a_non_round_tripping_circuit_name_is_pinned_explicitly() {
        let info: ContractInfo = serde_json::from_str(
            r#"{"compiler-version":"0","language-version":"0","runtime-version":"0",
                "circuits":[{"name":"sign_bidirectional","proof":true,"arguments":[],
                             "result-type":{"type-name":"Tuple","types":[]}}]}"#,
        )
        .expect("parses");
        let source = generate(&info, &options("S")).expect("generates");
        assert!(source.contains(r#"#[entry_point(name = "sign_bidirectional")]"#), "{source}");
        assert!(source.contains("fn sign_bidirectional();"), "{source}");
    }

    /// `--from-caller`: the caller's `contracts[]` declaration is enough,
    /// and the parameters are positional because a declaration has no
    /// names.
    #[test]
    fn a_callers_declaration_is_enough_to_generate_from() {
        let info: ContractInfo = serde_json::from_str(
            r#"{"compiler-version":"0","language-version":"0","runtime-version":"0",
                "circuits":[],
                "contracts":[{"name":"Target","circuits":[
                  {"name":"deposit",
                   "argument-types":[{"type-name":"Bytes","length":32},
                                     {"type-name":"Uint","maxval":255}],
                   "result-type":{"type-name":"Tuple","types":[]}}]}]}"#,
        )
        .expect("parses");
        let mut options = options("Target");
        options.from_caller = Some("Target".into());
        let source = generate(&info, &options).expect("generates");
        assert!(
            source.contains("fn deposit(arg0: B32<Public>, arg1: Uint<8, Public>);"),
            "{source}"
        );
    }
}
