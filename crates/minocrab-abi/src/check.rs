//! The agreement check: does this interface crate describe THAT artifact?
//!
//! [`Artifact::assert_interface_matches`] is the whole point of the crate.
//! Given a callee circuit's declared argument list `A` and result type `R`
//! — the very types an `#[interface]` trait names, so nothing is written
//! twice — it runs six checks against the pinned artifact:
//!
//! 1. the entry point EXISTS among the artifact's circuits;
//! 2. it is `proof: true` (a `proof: false` circuit has no verifier key, so
//!    it can never be a callee — the whole `Signet` module is `proof:
//!    false`, which is what makes this a real check);
//! 3. the arguments' typed tree, flattened, equals `A`'s atoms and per-slot
//!    primitives;
//! 4. the result type, flattened, equals `R`'s;
//! 5. the circuit compiles a communications commitment (without one there
//!    is nothing for `claimContractCall` to match);
//! 6. the compiled `.zkir`'s opening CONSTRAINT PREFIX equals the
//!    constraints `Prim::constraint` derives from `A` — slot for slot, on
//!    the declared input of that slot — whenever the `.zkir` is reachable,
//!    and against the distilled `pin.json` copy of it always.
//!
//! Check 6 is the one that cannot be faked by a mistake in our own
//! flattening: it compares against the instruction stream the prover runs.

use std::path::{Path, PathBuf};

use minocrab::v3::{CallArgs, CallResult, Prim};
use minocrab::AlignmentAtom;
use minocrab_ledger::EntryPoint;

use crate::info::{flatten_all, ContractInfo, Flattened};
use crate::pin::{sha256, Pin};
use crate::zkir::{constraint_key, ZkirFacts};

/// A pinned artifact: the committed `contract-info.json` and `pin.json`,
/// plus the `.zkir` tree if it is reachable.
#[derive(Debug, Clone)]
pub struct Artifact {
    /// The parsed `contract-info.json`.
    pub info: ContractInfo,
    /// SHA-256 of the `contract-info.json` bytes as committed.
    pub info_sha256: String,
    /// The parsed `pin.json`.
    pub pin: Pin,
    /// The directory holding `<circuit>.zkir`, when one was found.
    pub zkir_dir: Option<PathBuf>,
}

impl Artifact {
    /// Open an interface crate's `artifact/` directory
    /// (`contract-info.json` + `pin.json`), and locate the `.zkir` tree.
    ///
    /// `crate_dir` is normally `env!("CARGO_MANIFEST_DIR")`. The `.zkir`
    /// tree is looked for, in order, at `$MINOCRAB_ARTIFACT_DIR/zkir` and
    /// at `<workspace root>/<pin.source>/zkir`; if neither exists the
    /// offline half of the check still runs against `pin.json`.
    pub fn open(crate_dir: impl AsRef<Path>) -> Result<Artifact, Error> {
        let dir = crate_dir.as_ref().join("artifact");
        let info_path = dir.join("contract-info.json");
        let info_text = read(&info_path)?;
        let info = ContractInfo::parse(&info_text)
            .map_err(|source| Error::Parse { path: display(&info_path), source })?;
        let pin_path = dir.join("pin.json");
        let pin_text = read(&pin_path)?;
        let pin = Pin::parse(&pin_text)
            .map_err(|source| Error::Parse { path: display(&pin_path), source })?;

        let zkir_dir = locate_zkir(crate_dir.as_ref(), &pin.source);
        Ok(Artifact {
            info_sha256: sha256(info_text.into_bytes()),
            info,
            pin,
            zkir_dir,
        })
    }

    /// Build one from parts, verifying nothing — how the mutation test
    /// injects the damage the checker has to notice.
    pub fn from_parts(info: ContractInfo, pin: Pin, zkir_dir: Option<PathBuf>) -> Artifact {
        Artifact {
            info_sha256: String::new(),
            info,
            pin,
            zkir_dir,
        }
    }

    /// The `.zkir` of one circuit, if the tree was found.
    pub fn zkir(&self, name: &str) -> Option<Result<ZkirFacts, Error>> {
        let path = self.zkir_dir.as_ref()?.join(format!("{name}.zkir"));
        if !path.exists() {
            return None;
        }
        Some(ZkirFacts::read(&path).map_err(Error::Zkir))
    }

    /// THE DIGEST CHECK: the committed `contract-info.json` and every
    /// reachable `.zkir` hash to what `pin.json` says, and the pin's
    /// distilled per-circuit facts are the artifact's.
    pub fn verify_pin(&self) -> Result<(), Problems> {
        let mut problems = Problems::default();
        if !self.info_sha256.is_empty() && self.info_sha256 != self.pin.contract_info_sha256 {
            problems.push(format!(
                "contract-info.json digest {} does not match the pin's {}",
                self.info_sha256, self.pin.contract_info_sha256
            ));
        }
        for (name, pinned) in &self.pin.circuits {
            match self.info.circuit(name) {
                None => problems.push(format!("pin.json pins `{name}`, which the artifact does not export")),
                Some(circuit) if circuit.proof != pinned.proof => problems.push(format!(
                    "`{name}`: pin says proof={}, contract-info.json says proof={}",
                    pinned.proof, circuit.proof
                )),
                Some(_) => {}
            }
            let Some(dir) = &self.zkir_dir else { continue };
            let path = dir.join(format!("{name}.zkir"));
            let Ok(bytes) = std::fs::read(&path) else { continue };
            let digest = sha256(bytes);
            if digest != pinned.zkir_sha256 {
                problems.push(format!(
                    "{}: digest {digest} does not match the pin's {}",
                    display(&path),
                    pinned.zkir_sha256
                ));
            }
        }
        problems.into_result()
    }

    /// The six checks, for one circuit.
    ///
    /// `A` is the callee's argument list (a tuple of the `#[interface]`
    /// method's parameter types) and `R` its result type — the SAME types
    /// the generated call passes, so agreement here is agreement about the
    /// call.
    pub fn check<A: CallArgs, R: CallResult>(&self, entry_point: EntryPoint) -> Result<(), Problems> {
        let name = entry_point.name();
        let mut problems = Problems::default();

        // 1. the entry point exists.
        let Some(circuit) = self.info.circuit(name) else {
            let known: Vec<&str> = self.info.circuits.iter().map(|c| c.name.as_str()).collect();
            problems.push(format!(
                "the artifact exports no circuit `{name}` (it exports {known:?})"
            ));
            return problems.into_result();
        };

        // 2. it is proved.
        if !circuit.proof {
            problems.push(format!(
                "`{name}` is `proof: false`: it has no verifier key, so no \
                 cross-contract call can name it"
            ));
        }

        // 3. the arguments agree, slot for slot.
        match flatten_all(circuit.arguments.iter().map(|a| &a.ty)) {
            Err(e) => problems.push(format!("`{name}` arguments: {e}")),
            Ok(flat) => compare(&mut problems, name, "argument", &flat, &abi_of::<A>()),
        }

        // 4. the result agrees.
        match circuit.result_type.flatten() {
            Err(e) => problems.push(format!("`{name}` result: {e}")),
            Ok(flat) => {
                let ours = Flattened { atoms: R::atoms(), prims: R::prims() };
                compare(&mut problems, name, "result", &flat, &ours);
            }
        }

        // 5 + 6: the distilled facts, and the compiled prefix itself.
        let expected = expected_prefix::<A>();
        match self.pin.circuits.get(name) {
            None => problems.push(format!(
                "pin.json carries no distilled facts for `{name}` — re-pin the artifact"
            )),
            Some(pinned) => {
                if !pinned.do_communications_commitment {
                    problems.push(format!(
                        "`{name}` does not compile a communications commitment, so \
                         `claimContractCall` has nothing to match"
                    ));
                }
                if pinned.inputs != A::SLOTS {
                    problems.push(format!(
                        "`{name}` declares {} inputs, the interface's arguments occupy {}",
                        pinned.inputs,
                        A::SLOTS
                    ));
                }
                let keys: Vec<&String> = expected.iter().map(|(_, key)| key).collect();
                if pinned.constraints.iter().collect::<Vec<_>>() != keys {
                    problems.push(format!(
                        "`{name}` pinned constraint prefix {:?} != the interface's {keys:?}",
                        pinned.constraints
                    ));
                }
            }
        }

        if let Some(facts) = self.zkir(name) {
            match facts {
                Err(e) => problems.push(format!("`{name}`: {e}")),
                Ok(facts) => self.check_zkir(&mut problems, name, &facts, &expected, A::SLOTS),
            }
        }

        problems.into_result()
    }

    /// Check 6 against the compiled circuit itself: input count,
    /// communications commitment, and the constraint prefix slot for slot
    /// — each constraint on the declared input of ITS slot.
    fn check_zkir(
        &self,
        problems: &mut Problems,
        name: &str,
        facts: &ZkirFacts,
        expected: &[(usize, String)],
        slots: usize,
    ) {
        if !facts.do_communications_commitment {
            problems.push(format!("{name}.zkir does not compile a communications commitment"));
        }
        if facts.inputs.len() != slots {
            problems.push(format!(
                "{name}.zkir declares {} inputs, the interface's arguments occupy {slots}",
                facts.inputs.len()
            ));
        }
        if facts.prefix.len() != expected.len() {
            problems.push(format!(
                "{name}.zkir opens with {} constraints, the interface derives {}: {:?} vs {:?}",
                facts.prefix.len(),
                expected.len(),
                facts.prefix.iter().map(|c| &c.key).collect::<Vec<_>>(),
                expected.iter().map(|(_, k)| k).collect::<Vec<_>>(),
            ));
            return;
        }
        for (actual, (slot, key)) in facts.prefix.iter().zip(expected) {
            if &actual.key != key {
                problems.push(format!(
                    "{name}.zkir slot {slot}: constraint {} != the interface's {key}",
                    actual.key
                ));
            }
            match facts.inputs.get(*slot) {
                Some(input) if input == &actual.input => {}
                Some(input) => problems.push(format!(
                    "{name}.zkir slot {slot}: the constraint is on `{}`, not on input `{input}`",
                    actual.input
                )),
                None => problems.push(format!("{name}.zkir has no input for slot {slot}")),
            }
        }
    }

    /// [`Artifact::check`], as an assertion.
    pub fn assert_interface_matches<A: CallArgs, R: CallResult>(&self, entry_point: EntryPoint) {
        if let Err(problems) = self.check::<A, R>(entry_point) {
            panic!("{} does not match the pinned artifact:\n{problems}", entry_point.name());
        }
    }
}

/// The interface's own view of an argument list.
fn abi_of<A: CallArgs>() -> Flattened {
    let mut prims = Vec::with_capacity(A::SLOTS);
    A::push_prims(&mut prims);
    Flattened { atoms: A::atoms(), prims }
}

/// `(slot index, constraint key)` for every slot that carries a
/// constraint. Unconstrained slots emit no instruction, so they are absent
/// from a compiled prefix and absent here.
fn expected_prefix<A: CallArgs>() -> Vec<(usize, String)> {
    let mut prims = Vec::with_capacity(A::SLOTS);
    A::push_prims(&mut prims);
    prims
        .into_iter()
        .enumerate()
        .filter_map(|(slot, prim)| constraint_key(prim.constraint()).map(|key| (slot, key)))
        .collect()
}

fn compare(problems: &mut Problems, name: &str, what: &str, artifact: &Flattened, ours: &Flattened) {
    if artifact.prims != ours.prims {
        problems.push(format!(
            "`{name}` {what} slots: artifact {} != interface {}",
            prims(&artifact.prims),
            prims(&ours.prims)
        ));
    }
    if artifact.atoms != ours.atoms {
        problems.push(format!(
            "`{name}` {what} alignment: artifact {} != interface {}",
            atoms(&artifact.atoms),
            atoms(&ours.atoms)
        ));
    }
}

/// A [`Prim`] as it is written in a schema snapshot.
pub fn prim_name(prim: Prim) -> String {
    match prim {
        Prim::Opaque => "opaque".to_string(),
        Prim::Field => "field".to_string(),
        Prim::Point => "point".to_string(),
        Prim::Uint { bits } => format!("uint<{bits}>"),
        Prim::UintMax { maxval } => format!("uint<0..{maxval}>"),
    }
}

/// An [`AlignmentAtom`] as it is written in a schema snapshot.
pub fn atom_name(atom: &AlignmentAtom) -> String {
    match atom {
        AlignmentAtom::Bytes { length } => format!("bytes {length}"),
        AlignmentAtom::Field => "field".to_string(),
        AlignmentAtom::Compress => "compress".to_string(),
    }
}

fn prims(prims: &[Prim]) -> String {
    format!("[{}]", prims.iter().map(|&p| prim_name(p)).collect::<Vec<_>>().join(", "))
}

fn atoms(atoms: &[AlignmentAtom]) -> String {
    format!("[{}]", atoms.iter().map(atom_name).collect::<Vec<_>>().join(", "))
}

/// Everything that disagrees, so one failure reports all of it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Problems(pub Vec<String>);

impl Problems {
    fn push(&mut self, problem: String) {
        self.0.push(problem);
    }

    fn into_result(self) -> Result<(), Problems> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl std::fmt::Display for Problems {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for problem in &self.0 {
            writeln!(f, "  - {problem}")?;
        }
        Ok(())
    }
}

/// `$MINOCRAB_ARTIFACT_DIR/zkir`, else `<workspace root>/<source>/zkir`.
fn locate_zkir(crate_dir: &Path, source: &str) -> Option<PathBuf> {
    let candidates = [
        std::env::var_os("MINOCRAB_ARTIFACT_DIR").map(|dir| PathBuf::from(dir).join("zkir")),
        workspace_root(crate_dir).map(|root| root.join(source).join("zkir")),
    ];
    candidates.into_iter().flatten().find(|dir| dir.is_dir())
}

/// The nearest ancestor whose `Cargo.toml` declares `[workspace]`.
fn workspace_root(from: &Path) -> Option<PathBuf> {
    let mut dir = Some(from);
    while let Some(candidate) = dir {
        let manifest = candidate.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(candidate.to_path_buf());
            }
        }
        dir = candidate.parent();
    }
    None
}

/// Reading or parsing a pinned artifact.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{path}: {source}")]
    Parse { path: String, source: serde_json::Error },
    #[error(transparent)]
    Zkir(minocrab_zkir::Error),
}

fn read(path: &Path) -> Result<String, Error> {
    std::fs::read_to_string(path).map_err(|source| Error::Io { path: display(path), source })
}

fn display(path: &Path) -> String {
    path.display().to_string()
}
