//! The dataflow walk behind the LEAKAGE INVENTORIES — ONE walk, run over
//! either lineage.
//!
//! `tests/leakage_inventory.rs` (the compat vault, against compactc's
//! artifact) and `tests/leakage_inventory_pending.rs` (the API lineage on
//! `evm_flow::Pending`) each hold their own frozen table; the provenance
//! walk, the label taint, the witness inventory and the literal counting
//! that DERIVE those tables are here, so the two tables say the same kind
//! of thing about the two artifacts and neither can drift in method.
//!
//! What the walk computes, and why it is sound in the direction it is used,
//! is documented at the head of `tests/leakage_inventory.rs`. Everything
//! that differs per lineage is a parameter of [`inventory`]: the circuit's
//! name, the lineage's literal pads, and compactc's twin artifact where one
//! exists.
//!
//! Compiled into every test binary that declares `mod leakage`, each of
//! which uses only the part it needs — hence the blanket `dead_code`
//! allowance, as in `tests/support` and `tests/vault`.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use minocrab::v3::{Compiled3, DisclosedWire};
use minocrab::DisclosureKind;
use minocrab_ir::v3::passes::{defined_identifiers, operands};
use minocrab_zkir::v3::{Instruction as I, IrSource, Operand};

// ---- provenance --------------------------------------------------------------------

/// Where a wire's value ultimately comes from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    /// A circuit input, by its declared name.
    Input(String),
    /// The `k`-th `private_input` of the stream.
    Witness(usize),
    /// The `k`-th `public_input` of the stream.
    PublicInput(usize),
}

impl Source {
    fn render(&self) -> String {
        match self {
            Source::Input(name) => format!("in:{name}"),
            Source::Witness(k) => format!("w{k}"),
            Source::PublicInput(k) => format!("pi{k}"),
        }
    }
}

fn render_sources(sources: &BTreeSet<Source>) -> String {
    if sources.is_empty() {
        return "const".to_string();
    }
    sources.iter().map(Source::render).collect::<Vec<_>>().join(",")
}

fn has_witness(sources: &BTreeSet<Source>) -> bool {
    sources.iter().any(|s| matches!(s, Source::Witness(_)))
}

/// A `private_input` / `public_input` / `impact` with a VARIABLE guard is
/// conditional; an immediate guard (or none) is not.
fn is_guarded(guard: Option<&Operand>) -> bool {
    matches!(guard, Some(Operand::Variable(_)))
}

fn immediate_hex(op: &Operand) -> Option<String> {
    match op {
        Operand::Immediate(_) => {
            let s = serde_json::to_string(op).expect("an operand serializes");
            Some(s.trim_matches('"').to_string())
        }
        Operand::Variable(_) => None,
    }
}

/// The LE-trimmed hex `Operand` prints for a `B32::pad` low limb whose
/// bytes are `text` — the form the artifact spells the literal in.
fn pad_literal(text: &str) -> String {
    let mut s = String::from("0x");
    for b in text.bytes() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

struct Witness {
    guarded: bool,
    output: String,
}

struct Check {
    op: &'static str,
    sources: BTreeSet<Source>,
}

struct Impact {
    guarded: bool,
    /// Per operand: `None` for an immediate, else the wire name.
    operands: Vec<Option<String>>,
}

struct Digest {
    op: &'static str,
    output: String,
    inputs: Vec<BTreeSet<Source>>,
}

/// The dataflow walk's result for one artifact.
struct Walk {
    inputs: Vec<String>,
    provenance: HashMap<String, BTreeSet<Source>>,
    witnesses: Vec<Witness>,
    public_inputs: usize,
    guarded_public_inputs: usize,
    checks: Vec<Check>,
    impacts: Vec<Impact>,
    digests: Vec<Digest>,
    outputs: Vec<BTreeSet<Source>>,
    /// One count per entry of the caller's literal list, in its order.
    literals: Vec<usize>,
}

fn input_names(ir: &IrSource) -> Vec<String> {
    ir.inputs
        .iter()
        .map(|ti| {
            let v = serde_json::to_value(ti).expect("a typed identifier serializes");
            v["name"]
                .as_str()
                .expect("a typed identifier has a name")
                .to_string()
        })
        .collect()
}

fn walk(ir: &IrSource, literals: &[&str]) -> Walk {
    let inputs = input_names(ir);
    let mut provenance: HashMap<String, BTreeSet<Source>> = HashMap::new();
    for name in &inputs {
        provenance.insert(name.clone(), BTreeSet::from([Source::Input(name.clone())]));
    }
    let literal_hex: Vec<String> = literals.iter().map(|text| pad_literal(text)).collect();
    let mut literal_counts: Vec<usize> = vec![0; literals.len()];

    let sources_of = |provenance: &HashMap<String, BTreeSet<Source>>, ops: &[Operand]| {
        let mut set = BTreeSet::new();
        for op in ops {
            if let Operand::Variable(id) = op {
                if let Some(s) = provenance.get(&id.0) {
                    set.extend(s.iter().cloned());
                }
            }
        }
        set
    };

    let mut w = Walk {
        inputs,
        provenance: HashMap::new(),
        witnesses: Vec::new(),
        public_inputs: 0,
        guarded_public_inputs: 0,
        checks: Vec::new(),
        impacts: Vec::new(),
        digests: Vec::new(),
        outputs: Vec::new(),
        literals: Vec::new(),
    };

    for ins in ir.instructions.iter() {
        let ops = operands(ins);
        for op in &ops {
            if let Some(hex) = immediate_hex(op) {
                for (k, lit) in literal_hex.iter().enumerate() {
                    if hex == *lit {
                        literal_counts[k] += 1;
                    }
                }
            }
        }
        let read = sources_of(&provenance, &ops);
        match ins {
            I::PrivateInput { guard, output, .. } => {
                let k = w.witnesses.len();
                provenance.insert(output.0.clone(), BTreeSet::from([Source::Witness(k)]));
                w.witnesses.push(Witness {
                    guarded: is_guarded(guard.as_ref()),
                    output: output.0.clone(),
                });
            }
            I::PublicInput { guard, output, .. } => {
                let k = w.public_inputs;
                w.public_inputs += 1;
                if is_guarded(guard.as_ref()) {
                    w.guarded_public_inputs += 1;
                }
                provenance.insert(output.0.clone(), BTreeSet::from([Source::PublicInput(k)]));
            }
            I::Impact { guard, inputs } => {
                w.impacts.push(Impact {
                    guarded: is_guarded(Some(guard)),
                    operands: inputs
                        .iter()
                        .map(|op| match op {
                            Operand::Variable(id) => Some(id.0.clone()),
                            Operand::Immediate(_) => None,
                        })
                        .collect(),
                });
            }
            I::Assert { .. } => w.checks.push(Check { op: "assert", sources: read }),
            I::ConstrainEq { .. } => w.checks.push(Check { op: "constrain_eq", sources: read }),
            I::ConstrainBits { .. } => w.checks.push(Check { op: "constrain_bits", sources: read }),
            I::ConstrainToBoolean { .. } => {
                w.checks.push(Check { op: "constrain_to_boolean", sources: read })
            }
            I::Output { vals } => {
                for op in vals {
                    w.outputs.push(sources_of(&provenance, std::slice::from_ref(op)));
                }
            }
            _ => {
                let digest_op = match ins {
                    I::TransientHash { .. } => Some("transient_hash"),
                    I::PersistentHash { .. } => Some("persistent_hash"),
                    I::Keccak256 { .. } => Some("keccak256"),
                    I::HashToCurve { .. } => Some("hash_to_curve"),
                    _ => None,
                };
                let defined = defined_identifiers(ins);
                if let Some(op) = digest_op {
                    w.digests.push(Digest {
                        op,
                        output: defined
                            .first()
                            .map(|id| id.0.clone())
                            .unwrap_or_default(),
                        inputs: ops
                            .iter()
                            .map(|o| sources_of(&provenance, std::slice::from_ref(o)))
                            .collect(),
                    });
                }
                for id in defined {
                    provenance.insert(id.0, read.clone());
                }
            }
        }
    }
    w.provenance = provenance;
    w.literals = literal_counts;
    w
}

// ---- labels ---------------------------------------------------------------------------

/// Every wire's DECLARED labels in its ancestry: seeded at the wires the
/// `Disclosed` records name, propagated forward by the same operand rule.
fn label_taint(compiled: &Compiled3) -> HashMap<String, BTreeSet<String>> {
    let mut seeds: HashMap<String, BTreeSet<String>> = HashMap::new();
    for d in &compiled.disclosures {
        if !matches!(d.kind, DisclosureKind::Disclosed | DisclosureKind::DisclosedUntyped) {
            continue;
        }
        for wire in &d.values {
            if let DisclosedWire::Named(id) = wire {
                seeds
                    .entry(id.0.clone())
                    .or_default()
                    .insert(d.label.clone());
            }
        }
    }
    let mut taint: HashMap<String, BTreeSet<String>> = HashMap::new();
    for ins in compiled.ir.instructions.iter() {
        let mut inherited: BTreeSet<String> = BTreeSet::new();
        // A label travels along DATA operands only. `cond_select`'s bit
        // chooses between `a` and `b` and contributes no bytes of its own,
        // so the outcome flag's label must not "cover" whichever secret the
        // selected arm carries — that is precisely the accidental coverage
        // the completeness gate exists to refuse.
        let data_operands: Vec<Operand> = match ins {
            I::CondSelect { a, b, .. } => vec![a.clone(), b.clone()],
            _ => operands(ins),
        };
        for op in data_operands {
            if let Operand::Variable(id) = op {
                if let Some(t) = taint.get(&id.0) {
                    inherited.extend(t.iter().cloned());
                }
            }
        }
        for id in defined_identifiers(ins) {
            let mut set = inherited.clone();
            if let Some(own) = seeds.get(&id.0) {
                set.extend(own.iter().cloned());
            }
            taint.insert(id.0, set);
        }
    }
    // Circuit inputs can be disclosed too (a label on a public argument).
    for name in input_names(&compiled.ir) {
        if let Some(own) = seeds.get(&name) {
            taint.entry(name).or_default().extend(own.iter().cloned());
        }
    }
    taint
}

// ---- the inventory ---------------------------------------------------------------------

/// One circuit's inventory, as the frozen lines.
///
/// `name` heads the block, `literals` is the lineage's pad list (counted in
/// its own order), and `twin` is compactc's artifact for the same circuit
/// where one exists — the API lineage proves its own statement and has
/// none, so its twin line says so instead of comparing.
pub fn inventory(
    name: &str,
    compiled: &Compiled3,
    twin: Option<&IrSource>,
    literals: &[&str],
) -> Vec<String> {
    let ours = walk(&compiled.ir, literals);
    let twin = twin.map(|ir| walk(ir, literals));
    let taint = label_taint(compiled);
    let mut lines = Vec::new();

    let guarded_witnesses = |w: &Walk| w.witnesses.iter().filter(|x| x.guarded).count();
    let guarded_impacts = |w: &Walk| w.impacts.iter().filter(|x| x.guarded).count();
    let impact_wires = |w: &Walk| w.impacts.iter().map(|x| x.operands.len()).sum::<usize>();
    let digest_summary = |w: &Walk| {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for d in &w.digests {
            *counts.entry(d.op).or_default() += 1;
        }
        if counts.is_empty() {
            "none".to_string()
        } else {
            counts
                .iter()
                .map(|(op, n)| format!("{op} {n}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    };
    let literal_summary = |w: &Walk| {
        literals
            .iter()
            .zip(&w.literals)
            .map(|(text, n)| format!("{text:?} x{n}"))
            .collect::<Vec<_>>()
            .join(" ")
    };

    lines.push(format!(
        "== {} | inputs {} ({}) | witnesses {} (guarded {}) | public_inputs {} (guarded {}) | impact {} (guarded {}) wires {} | digests {} | outputs {}",
        name,
        ours.inputs.len(),
        ours.inputs.iter().map(|s| s.trim_start_matches('%').to_string()).collect::<Vec<_>>().join(","),
        ours.witnesses.len(),
        guarded_witnesses(&ours),
        ours.public_inputs,
        ours.guarded_public_inputs,
        ours.impacts.len(),
        guarded_impacts(&ours),
        impact_wires(&ours),
        digest_summary(&ours),
        ours.outputs.len(),
    ));
    lines.push(format!("literals | {}", literal_summary(&ours)));
    lines.push(match &twin {
        Some(twin) => format!(
            "corpus twin | witnesses {} (guarded {}) | public_inputs {} (guarded {}) | impact {} (guarded {}) wires {} | digests {} | literals {}",
            twin.witnesses.len(),
            guarded_witnesses(twin),
            twin.public_inputs,
            twin.guarded_public_inputs,
            twin.impacts.len(),
            guarded_impacts(twin),
            impact_wires(twin),
            digest_summary(twin),
            literal_summary(twin),
        ),
        None => "corpus twin | none — this lineage proves its own statement, so there is no \
                 compactc artifact to compare its surface with"
            .to_string(),
    });

    // The declared components and what each is a function of.
    for d in &compiled.disclosures {
        if !matches!(d.kind, DisclosureKind::Disclosed | DisclosureKind::DisclosedUntyped) {
            continue;
        }
        let mut sources = BTreeSet::new();
        let mut constants = 0usize;
        for wire in &d.values {
            match wire {
                DisclosedWire::Named(id) => {
                    if let Some(s) = ours.provenance.get(&id.0) {
                        sources.extend(s.iter().cloned());
                    }
                }
                DisclosedWire::Constant(_) => constants += 1,
            }
        }
        let kind = match d.kind {
            DisclosureKind::Disclosed => "disclosed",
            _ => "disclosed (untyped)",
        };
        lines.push(format!(
            "component | {} | {kind} | wires {} (const {constants}) | {}",
            d.label,
            d.values.len(),
            render_sources(&sources)
        ));
    }

    // The witness inventory: guard, the labels it reaches, the checks.
    for (k, wit) in ours.witnesses.iter().enumerate() {
        let labels: BTreeSet<String> = taint
            .iter()
            .filter(|(wire, _)| {
                ours.provenance
                    .get(*wire)
                    .is_some_and(|s| s.contains(&Source::Witness(k)))
            })
            .flat_map(|(_, t)| t.iter().cloned())
            .collect();
        let _ = &wit.output;
        let reaching: Vec<&Check> = ours
            .checks
            .iter()
            .filter(|c| c.sources.contains(&Source::Witness(k)))
            .collect();
        let mut also: BTreeSet<Source> = BTreeSet::new();
        let mut by_op: BTreeMap<&str, usize> = BTreeMap::new();
        for c in &reaching {
            *by_op.entry(c.op).or_default() += 1;
            also.extend(c.sources.iter().filter(|s| **s != Source::Witness(k)).cloned());
        }
        let checks = if by_op.is_empty() {
            "unchecked".to_string()
        } else {
            format!(
                "{} (also on {})",
                by_op
                    .iter()
                    .map(|(op, n)| format!("{op} {n}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                render_sources(&also)
            )
        };
        let reaches_impact: Vec<String> = ours
            .impacts
            .iter()
            .enumerate()
            .filter(|(_, imp)| {
                imp.operands.iter().flatten().any(|wire| {
                    ours.provenance
                        .get(wire)
                        .is_some_and(|s| s.contains(&Source::Witness(k)))
                })
            })
            .map(|(i, imp)| format!("#{i}{}", if imp.guarded { "g" } else { "" }))
            .collect();
        lines.push(format!(
            "witness w{k} | {} | reaches labels: {} | reaches impact: {} | checks: {checks}",
            if wit.guarded { "guarded" } else { "unguarded" },
            if labels.is_empty() {
                "none".to_string()
            } else {
                labels.into_iter().collect::<Vec<_>>().join("; ")
            },
            if reaches_impact.is_empty() {
                "none".to_string()
            } else {
                reaches_impact.join(" ")
            }
        ));
    }

    // Digests: component = H(operands), by provenance class.
    for d in &ours.digests {
        let all: BTreeSet<Source> = d.inputs.iter().flatten().cloned().collect();
        let labels = taint.get(&d.output).cloned().unwrap_or_default();
        lines.push(format!(
            "digest {} | {} inputs | over {} | under labels: {}",
            d.op,
            d.inputs.len(),
            render_sources(&all),
            if labels.is_empty() {
                "none".to_string()
            } else {
                labels.into_iter().collect::<Vec<_>>().join("; ")
            }
        ));
    }

    // The public statement, op by op: how each operand is accounted for.
    let mut unlabelled: Vec<String> = Vec::new();
    for (i, imp) in ours.impacts.iter().enumerate() {
        let mut immediates = 0usize;
        let mut public = 0usize;
        let mut labelled: BTreeSet<String> = BTreeSet::new();
        let mut leaks = 0usize;
        for op in &imp.operands {
            let Some(wire) = op else {
                immediates += 1;
                continue;
            };
            let sources = ours.provenance.get(wire).cloned().unwrap_or_default();
            let labels = taint.get(wire).cloned().unwrap_or_default();
            if !labels.is_empty() {
                labelled.extend(labels);
            } else if has_witness(&sources) {
                leaks += 1;
                unlabelled.push(format!("impact #{i} {wire} <- {}", render_sources(&sources)));
            } else {
                public += 1;
            }
        }
        lines.push(format!(
            "impact #{i} | {} | wires {}: immediate {immediates}, public-derived {public}, labelled {} | unlabelled witness-dependent {leaks}{}",
            if imp.guarded { "guarded" } else { "unguarded" },
            imp.operands.len(),
            imp.operands.len() - immediates - public - leaks,
            if labelled.is_empty() {
                String::new()
            } else {
                format!(" | labels: {}", labelled.into_iter().collect::<Vec<_>>().join("; "))
            }
        ));
    }
    for (i, out) in ours.outputs.iter().enumerate() {
        lines.push(format!("output #{i} | {}", render_sources(out)));
    }
    lines.push(format!(
        "unlabelled witness-dependent public components | {}",
        if unlabelled.is_empty() {
            "none".to_string()
        } else {
            unlabelled.join(" ; ")
        }
    ));
    lines
}
