//! The vault's LEAKAGE INVENTORY (M27, the vault prong): for each of the
//! seventeen circuits, what the artifact publishes, what each published
//! component is a function of, which secrets the circuit consumes and what
//! checks them — GENERATED from the artifact by a dataflow walk, and frozen
//! below like every other snapshot in this crate.
//!
//! What the analysis draft (notes/zkir-semantics.org §7, §7.1) states by
//! hand in its per-circuit tables, this file derives:
//!
//! - COMPLETENESS: the public statement is the `impact` operand stream (plus
//!   the binding input and the communications commitment, which are the
//!   proof system's own). Every `impact` operand wire is classified — an
//!   immediate, a wire that depends on no secret, or a wire that carries a
//!   DECLARED disclosure label in its ancestry. A witness-dependent operand
//!   with no label in its ancestry is an UNLABELLED LEAK, listed by name;
//!   `no_unlabelled_witness_dependent_public_component` asserts there are
//!   none.
//! - DEPENDENCY CLASSIFICATION: every declared disclosure's provenance —
//!   which circuit inputs, which witness ordinals, which public inputs — and
//!   every digest's (the "component c = H(operands)" statements).
//! - WITNESS INVENTORY: each `private_input` with its guard, the labels it
//!   flows into, and the checks (`assert` / `constrain_*`) it reaches with
//!   what ELSE those checks depend on — which is how "the secret is asserted
//!   only on the refund branch" reads mechanically: its one check also
//!   depends on the attested outcome input.
//! - LITERAL CONSTANCY: how many times the `"vault"` signing path, the
//!   `"vault:user:"` and `"vault:refund:"` commitment pads appear as
//!   immediates.
//! - THE CORPUS TWIN: the same structural counts on compactc's own artifact
//!   for the same circuit (witnesses and guards, `impact` ops and guards,
//!   operand wires, digests, literals). The two lowerings are PI-equal
//!   (tests/erc20_vault_differential.rs); this line says the leakage
//!   SURFACE is the same shape too, so the inventory describes both.
//!
//! The walk is static — no preimage, no run. Provenance is the transitive
//! closure of `minocrab_ir::v3::passes::operands` (rung 2's `Instr.operands`
//! in Lean, gate-equal on the corpus) seeded at the circuit inputs, the
//! `private_input`s and the `public_input`s; labels are seeded at the wires
//! `Compiled3::disclosures` names and propagated the same way. Provenance
//! over-approximates (a hash of a secret "depends on" the secret, which is
//! exactly the claim the inventory wants to make), never under-approximates.
//!
//! Regenerate after an INTENTIONAL change to a circuit's leakage surface:
//! `cargo test -p minocrab-contracts --test leakage_inventory -- --ignored
//! regenerate_leakage_inventory`. The diff names the moved component.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use minocrab::v3::{Compiled3, DisclosedWire};
use minocrab::DisclosureKind;
use minocrab_ir::v3::passes::{defined_identifiers, operands};
use minocrab_zkir::v3::{Instruction as I, IrSource, Operand};

mod support;
mod vault;
use support::{rewrite_generated_region, test_source};
use vault::artifact::Circuit;

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
    literals: BTreeMap<&'static str, usize>,
}

const LITERALS: [(&str, &str); 3] = [
    ("vault", "\"vault\""),
    ("vault:user:", "\"vault:user:\""),
    ("vault:refund:", "\"vault:refund:\""),
];

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

fn walk(ir: &IrSource) -> Walk {
    let inputs = input_names(ir);
    let mut provenance: HashMap<String, BTreeSet<Source>> = HashMap::new();
    for name in &inputs {
        provenance.insert(name.clone(), BTreeSet::from([Source::Input(name.clone())]));
    }
    let literal_hex: Vec<(&'static str, String)> =
        LITERALS.iter().map(|(text, _)| (*text, pad_literal(text))).collect();
    let mut literals: BTreeMap<&'static str, usize> =
        LITERALS.iter().map(|(text, _)| (*text, 0)).collect();

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
        literals: BTreeMap::new(),
    };

    for ins in ir.instructions.iter() {
        let ops = operands(ins);
        for op in &ops {
            if let Some(hex) = immediate_hex(op) {
                for (text, lit) in &literal_hex {
                    if hex == *lit {
                        *literals.get_mut(text).expect("seeded") += 1;
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
    w.literals = literals;
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
fn inventory(circuit: Circuit) -> Vec<String> {
    let compiled = circuit.build();
    let ours = walk(&compiled.ir);
    let twin = walk(circuit.corpus());
    let taint = label_taint(&compiled);
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
        LITERALS
            .iter()
            .map(|(text, quoted)| format!("{quoted} x{}", w.literals[text]))
            .collect::<Vec<_>>()
            .join(" ")
    };

    lines.push(format!(
        "== {} | inputs {} ({}) | witnesses {} (guarded {}) | public_inputs {} (guarded {}) | impact {} (guarded {}) wires {} | digests {} | outputs {}",
        circuit.zkir_name(),
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
    lines.push(format!(
        "corpus twin | witnesses {} (guarded {}) | public_inputs {} (guarded {}) | impact {} (guarded {}) wires {} | digests {} | literals {}",
        twin.witnesses.len(),
        guarded_witnesses(&twin),
        twin.public_inputs,
        twin.guarded_public_inputs,
        twin.impacts.len(),
        guarded_impacts(&twin),
        impact_wires(&twin),
        digest_summary(&twin),
        literal_summary(&twin),
    ));

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

fn build_inventory() -> Vec<String> {
    Circuit::ALL.iter().flat_map(|c| inventory(*c)).collect()
}

/// The frozen inventory, one line per fact, in `Circuit::ALL` order.
const INVENTORY: &[&str] = &[
    // GENERATED BEGIN — rewritten by `regenerate_leakage_inventory`
    "== initialise | inputs 8 (vaultEvm.0,swapRouter.1,stataUnderlyingAddr.2,stataTokenAddr.3,chainId.4,chainCaip2Id_hi.5,chainCaip2Id_lo.6,responseKey.7) | witnesses 2 (guarded 0) | public_inputs 3 (guarded 0) | impact 44 (guarded 0) wires 156 | digests transient_hash 1 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x1 \"vault:refund:\" x0",
    "corpus twin | witnesses 2 (guarded 0) | public_inputs 3 (guarded 0) | impact 44 (guarded 0) wires 156 | digests transient_hash 1 | literals \"vault\" x0 \"vault:user:\" x1 \"vault:refund:\" x0",
    "component | the vault's derived EVM address | disclosed | wires 1 (const 0) | in:%vaultEvm.0",
    "component | the Uniswap router address | disclosed | wires 1 (const 0) | in:%swapRouter.1",
    "component | the Aave underlying ERC20 (USDC) | disclosed | wires 1 (const 0) | in:%stataUnderlyingAddr.2",
    "component | the Aave stata wrapper (ERC-4626) | disclosed | wires 1 (const 0) | in:%stataTokenAddr.3",
    "component | the EVM chain id | disclosed | wires 1 (const 0) | in:%chainId.4",
    "component | the CAIP-2 chain id | disclosed | wires 2 (const 0) | in:%chainCaip2Id_hi.5,in:%chainCaip2Id_lo.6",
    "component | the MPC response key | disclosed | wires 1 (const 0) | in:%responseKey.7",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on w1,pi1,pi2)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on w0,pi1,pi2)",
    "digest transient_hash | 4 inputs | over w0,w1 | under labels: none",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #9 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: the vault's derived EVM address",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: the Uniswap router address",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #21 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: the Aave underlying ERC20 (USDC)",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: the Aave stata wrapper (ERC-4626)",
    "impact #27 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: the EVM chain id",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: the CAIP-2 chain id",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 5: immediate 5, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 13: immediate 8, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== approveStata | inputs 2 (evmNonce.0,keyVersion.1) | witnesses 3 (guarded 0) | public_inputs 14 (guarded 0) | impact 49 (guarded 0) wires 234 | digests transient_hash 2 | outputs 0",
    "literals | \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x0",
    "corpus twin | witnesses 3 (guarded 0) | public_inputs 14 (guarded 0) | impact 49 (guarded 0) wires 234 | digests transient_hash 2 | literals \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x0",
    "component | request id | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi8",
    "component | request record | disclosed | wires 33 (const 22) | in:%evmNonce.0,in:%keyVersion.1,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi8",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w1,w2",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%evmNonce.0,in:%keyVersion.1,w0,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi8,pi12,pi13",
    "witness w0 | unguarded | reaches labels: request id; request record; xcall communications commitment | reaches impact: #44 | checks: unchecked",
    "witness w1 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #44 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #44 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 33 inputs | over in:%evmNonce.0,in:%keyVersion.1,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi8 | under labels: request record",
    "digest transient_hash | 9 inputs | over in:%evmNonce.0,in:%keyVersion.1,w0,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi8,pi12,pi13 | under labels: request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #24 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #31 | unguarded | wires 60: immediate 49, public-derived 0, labelled 11 | unlabelled witness-dependent 0 | labels: request record",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #45 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== approveRouter | inputs 3 (erc20Address.0,evmNonce.1,keyVersion.2) | witnesses 3 (guarded 0) | public_inputs 13 (guarded 0) | impact 46 (guarded 0) wires 222 | digests transient_hash 2 | outputs 0",
    "literals | \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x0",
    "corpus twin | witnesses 3 (guarded 0) | public_inputs 13 (guarded 0) | impact 46 (guarded 0) wires 222 | digests transient_hash 2 | literals \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x0",
    "component | the approved ERC20 | disclosed | wires 1 (const 0) | in:%erc20Address.0",
    "component | request id | disclosed | wires 2 (const 1) | in:%erc20Address.0,in:%evmNonce.1,in:%keyVersion.2,pi1,pi2,pi3,pi4,pi5,pi6,pi7",
    "component | request record | disclosed | wires 33 (const 22) | in:%erc20Address.0,in:%evmNonce.1,in:%keyVersion.2,pi1,pi2,pi3,pi4,pi5,pi6,pi7",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w1,w2",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%erc20Address.0,in:%evmNonce.1,in:%keyVersion.2,w0,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi11,pi12",
    "witness w0 | unguarded | reaches labels: request id; request record; xcall communications commitment | reaches impact: #41 | checks: unchecked",
    "witness w1 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #41 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #41 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 33 inputs | over in:%erc20Address.0,in:%evmNonce.1,in:%keyVersion.2,pi1,pi2,pi3,pi4,pi5,pi6,pi7 | under labels: request record",
    "digest transient_hash | 9 inputs | over in:%erc20Address.0,in:%evmNonce.1,in:%keyVersion.2,w0,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi11,pi12 | under labels: request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #28 | unguarded | wires 60: immediate 49, public-derived 0, labelled 11 | unlabelled witness-dependent 0 | labels: request record; the approved ERC20",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #42 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== startDeposit | inputs 7 (evmNonce.0,gasLimit.1,maxFeePerGas.2,maxPriorityFeePerGas.3,keyVersion.4,depositRequest_erc20Address.5,depositRequest_amount.6) | witnesses 5 (guarded 0) | public_inputs 13 (guarded 0) | impact 51 (guarded 0) wires 247 | digests transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x1 \"vault:refund:\" x0",
    "corpus twin | witnesses 5 (guarded 0) | public_inputs 13 (guarded 0) | impact 51 (guarded 0) wires 247 | digests transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x1 \"vault:refund:\" x0",
    "component | depositor identity commitment | disclosed | wires 2 (const 1) | w0,w1",
    "component | request id | disclosed | wires 2 (const 1) | in:%depositRequest_amount.6,in:%depositRequest_erc20Address.5,in:%evmNonce.0,in:%gasLimit.1,in:%keyVersion.4,in:%maxFeePerGas.2,in:%maxPriorityFeePerGas.3,w0,w1,pi1,pi2,pi3,pi4,pi5,pi6,pi7",
    "component | request record | disclosed | wires 33 (const 16) | in:%depositRequest_amount.6,in:%depositRequest_erc20Address.5,in:%evmNonce.0,in:%gasLimit.1,in:%keyVersion.4,in:%maxFeePerGas.2,in:%maxPriorityFeePerGas.3,w0,w1,pi1,pi2,pi3,pi4,pi5,pi6,pi7",
    "component | the deposited ERC20 | disclosed | wires 1 (const 0) | in:%depositRequest_erc20Address.5",
    "component | the deposited amount | disclosed | wires 1 (const 0) | in:%depositRequest_amount.6",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w3,w4",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%depositRequest_amount.6,in:%depositRequest_erc20Address.5,in:%evmNonce.0,in:%gasLimit.1,in:%keyVersion.4,in:%maxFeePerGas.2,in:%maxPriorityFeePerGas.3,w0,w1,w2,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi11,pi12",
    "witness w0 | unguarded | reaches labels: depositor identity commitment; request id; request record; xcall communications commitment | reaches impact: #20 #27 #28 #32 #33 #46 | checks: constrain_bits 1 (also on const)",
    "witness w1 | unguarded | reaches labels: depositor identity commitment; request id; request record; xcall communications commitment | reaches impact: #20 #27 #28 #32 #33 #46 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: depositor identity commitment; request id; request record; xcall communications commitment | reaches impact: #46 | checks: unchecked",
    "witness w3 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #46 | checks: constrain_bits 1 (also on const)",
    "witness w4 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #46 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 4 inputs | over w0,w1 | under labels: none",
    "digest transient_hash | 33 inputs | over in:%depositRequest_amount.6,in:%depositRequest_erc20Address.5,in:%evmNonce.0,in:%gasLimit.1,in:%keyVersion.4,in:%maxFeePerGas.2,in:%maxPriorityFeePerGas.3,w0,w1,pi1,pi2,pi3,pi4,pi5,pi6,pi7 | under labels: depositor identity commitment; request record",
    "digest transient_hash | 9 inputs | over in:%depositRequest_amount.6,in:%depositRequest_erc20Address.5,in:%evmNonce.0,in:%gasLimit.1,in:%keyVersion.4,in:%maxFeePerGas.2,in:%maxPriorityFeePerGas.3,w0,w1,w2,pi1,pi2,pi3,pi4,pi5,pi6,pi7,pi11,pi12 | under labels: depositor identity commitment; request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: depositor identity commitment; request id; request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: depositor identity commitment; request id; request record",
    "impact #28 | unguarded | wires 60: immediate 43, public-derived 0, labelled 17 | unlabelled witness-dependent 0 | labels: depositor identity commitment; request record; the deposited ERC20",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: depositor identity commitment; request id; request record",
    "impact #33 | unguarded | wires 10: immediate 7, public-derived 0, labelled 3 | unlabelled witness-dependent 0 | labels: depositor identity commitment; request record; the deposited ERC20; the deposited amount",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: depositor identity commitment; request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #47 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== completeDeposit | inputs 18 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11,recipient_is_some.12,recipient_is_left.13,recipient_left_hi.14,recipient_left_lo.15,recipient_right_hi.16,recipient_right_lo.17) | witnesses 4 (guarded 2) | public_inputs 11 (guarded 2) | impact 57 (guarded 9) wires 183 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x1 \"vault:refund:\" x0",
    "corpus twin | witnesses 4 (guarded 2) | public_inputs 11 (guarded 2) | impact 57 (guarded 9) wires 183 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x1 \"vault:refund:\" x0",
    "component | claim request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | claim recipient tag | disclosed | wires 1 (const 0) | in:%recipient_is_some.12",
    "component | claim recipient side | disclosed | wires 1 (const 0) | in:%recipient_is_left.13",
    "component | own public key as claim recipient | disclosed | wires 2 (const 0) | w2,w3",
    "component | claim recipient key | disclosed | wires 2 (const 0) | in:%recipient_left_hi.14,in:%recipient_left_lo.15",
    "component | claim recipient contract | disclosed | wires 2 (const 0) | in:%recipient_right_hi.16,in:%recipient_right_lo.17",
    "component | claim mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on w0,pi3,pi4)",
    "witness w2 | guarded | reaches labels: own public key as claim recipient | reaches impact: #44 #53g | checks: constrain_bits 1 (also on const)",
    "witness w3 | guarded | reaches labels: own public key as claim recipient | reaches impact: #44 #53g | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 4 inputs | over w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi5 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi5,pi7,pi8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,in:%recipient_is_left.13,in:%recipient_is_some.12,in:%recipient_left_hi.14,in:%recipient_left_lo.15,in:%recipient_right_hi.16,in:%recipient_right_lo.17,w2,w3,pi5,pi6,pi7,pi8 | under labels: own public key as claim recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: claim request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: claim request id",
    "impact #13 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: claim request id",
    "impact #18 | unguarded | wires 9: immediate 5, public-derived 4, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: claim request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as claim recipient",
    "impact #45 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | guarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | guarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #51 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #52 | guarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #53 | guarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as claim recipient",
    "impact #54 | guarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #55 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #56 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== startWithdraw | inputs 10 (evmNonce.0,keyVersion.1,withdrawRequest_erc20Address.2,withdrawRequest_amount.3,withdrawRequest_destEvmAddress.4,coin_nonce_hi.5,coin_nonce_lo.6,coin_color_hi.7,coin_color_lo.8,coin_value.9) | witnesses 5 (guarded 0) | public_inputs 18 (guarded 0) | impact 75 (guarded 0) wires 310 | digests persistent_hash 4 transient_hash 5 | outputs 0",
    "literals | \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 5 (guarded 0) | public_inputs 18 (guarded 0) | impact 75 (guarded 0) wires 310 | digests persistent_hash 4 transient_hash 5 | literals \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | the withdrawn ERC20 | disclosed | wires 1 (const 0) | in:%withdrawRequest_erc20Address.2",
    "component | request id | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,pi3,pi4,pi5,pi6,pi7,pi8",
    "component | surrendered coin nonce | disclosed | wires 2 (const 0) | in:%coin_nonce_hi.5,in:%coin_nonce_lo.6",
    "component | surrendered coin color | disclosed | wires 2 (const 0) | in:%coin_color_hi.7,in:%coin_color_lo.8",
    "component | surrendered coin value | disclosed | wires 1 (const 0) | in:%coin_value.9",
    "component | request record | disclosed | wires 33 (const 20) | in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,pi3,pi4,pi5,pi6,pi7,pi8",
    "component | withdrawer refund commitment | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,w0,w1,pi3,pi4,pi5,pi6,pi7,pi8",
    "component | the withdrawn amount | disclosed | wires 1 (const 0) | in:%withdrawRequest_amount.3",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w3,w4",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,w2,pi3,pi4,pi5,pi6,pi7,pi8,pi16,pi17",
    "witness w0 | unguarded | reaches labels: request id; request record; withdrawer refund commitment | reaches impact: #57 | checks: constrain_bits 1 (also on const)",
    "witness w1 | unguarded | reaches labels: request id; request record; withdrawer refund commitment | reaches impact: #57 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: request id; request record; xcall communications commitment | reaches impact: #70 | checks: unchecked",
    "witness w3 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #70 | checks: constrain_bits 1 (also on const)",
    "witness w4 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #70 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 4 inputs | over in:%withdrawRequest_erc20Address.2 | under labels: none",
    "digest persistent_hash | 6 inputs | over in:%withdrawRequest_erc20Address.2,pi1,pi2 | under labels: none",
    "digest transient_hash | 33 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,pi3,pi4,pi5,pi6,pi7,pi8 | under labels: request record",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.7,in:%coin_color_lo.8,in:%coin_nonce_hi.5,in:%coin_nonce_lo.6,in:%coin_value.9,pi10,pi11 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.7,in:%coin_color_lo.8,in:%coin_nonce_hi.5,in:%coin_nonce_lo.6,in:%coin_value.9,pi12,pi13 | under labels: none",
    "digest transient_hash | 2 inputs | over in:%coin_nonce_lo.6 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.7,in:%coin_color_lo.8,in:%coin_nonce_lo.6,in:%coin_value.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,w0,w1,pi3,pi4,pi5,pi6,pi7,pi8 | under labels: request id; request record",
    "digest transient_hash | 9 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%withdrawRequest_amount.3,in:%withdrawRequest_destEvmAddress.4,in:%withdrawRequest_erc20Address.2,w2,pi3,pi4,pi5,pi6,pi7,pi8,pi16,pi17 | under labels: request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #51 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #52 | unguarded | wires 60: immediate 47, public-derived 0, labelled 13 | unlabelled witness-dependent 0 | labels: request record; the withdrawn ERC20",
    "impact #53 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #54 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #55 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #56 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #57 | unguarded | wires 10: immediate 7, public-derived 0, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; the withdrawn ERC20; the withdrawn amount; withdrawer refund commitment",
    "impact #58 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #59 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #60 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #61 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #62 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #63 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #64 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #65 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #66 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #67 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #68 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #69 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #70 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #71 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #72 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #73 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #74 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== completeWithdraw | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 2) | public_inputs 9 (guarded 2) | impact 48 (guarded 25) wires 158 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 2) | public_inputs 9 (guarded 2) | impact 48 (guarded 25) wires 158 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | withdrawal EVM outcome | disclosed | wires 1 (const 0) | in:%serializedOutput.9",
    "component | refund mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "component | own public key as refund recipient | disclosed | wires 2 (const 0) | w2,w3",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9,w0,pi3,pi4)",
    "witness w2 | guarded | reaches labels: own public key as refund recipient; withdrawal EVM outcome | reaches impact: #40g | checks: constrain_bits 1 (also on const)",
    "witness w3 | guarded | reaches labels: own public key as refund recipient; withdrawal EVM outcome | reaches impact: #40g | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi5 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi5,pi7,pi8 | under labels: withdrawal EVM outcome",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,w2,w3,pi5,pi6,pi7,pi8 | under labels: own public key as refund recipient; withdrawal EVM outcome",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #14 | unguarded | wires 9: immediate 5, public-derived 4, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | guarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #21 | guarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: withdrawal EVM outcome",
    "impact #22 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | guarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | guarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | guarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | guarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | guarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | guarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | guarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as refund recipient; withdrawal EVM outcome",
    "impact #41 | guarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | guarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== refundWithdraw | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 48 (guarded 0) wires 158 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 48 (guarded 0) wires 158 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | refund mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "component | own public key as refund recipient | disclosed | wires 2 (const 0) | w2,w3",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #44 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #44 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi5 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi5,pi7,pi8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,w2,w3,pi5,pi6,pi7,pi8 | under labels: own public key as refund recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #14 | unguarded | wires 9: immediate 5, public-derived 4, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as refund recipient",
    "impact #45 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== startSwap | inputs 12 (evmNonce.0,keyVersion.1,swapRequest_tokenIn.2,swapRequest_tokenOut.3,swapRequest_fee.4,swapRequest_amountOut.5,swapRequest_amountInMaximum.6,coin_nonce_hi.7,coin_nonce_lo.8,coin_color_hi.9,coin_color_lo.10,coin_value.11) | witnesses 5 (guarded 0) | public_inputs 20 (guarded 0) | impact 81 (guarded 0) wires 353 | digests persistent_hash 4 transient_hash 5 | outputs 0",
    "literals | \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 5 (guarded 0) | public_inputs 20 (guarded 0) | impact 81 (guarded 0) wires 353 | digests persistent_hash 4 transient_hash 5 | literals \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | the sold ERC20 | disclosed | wires 1 (const 0) | in:%swapRequest_tokenIn.2",
    "component | the bought ERC20 | disclosed | wires 1 (const 0) | in:%swapRequest_tokenOut.3",
    "component | request id | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10",
    "component | surrendered coin nonce | disclosed | wires 2 (const 0) | in:%coin_nonce_hi.7,in:%coin_nonce_lo.8",
    "component | surrendered coin color | disclosed | wires 2 (const 0) | in:%coin_color_hi.9,in:%coin_color_lo.10",
    "component | surrendered coin value | disclosed | wires 1 (const 0) | in:%coin_value.11",
    "component | request record | disclosed | wires 43 (const 22) | in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10",
    "component | swapper refund commitment | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,w0,w1,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10",
    "component | the swap's amountOut | disclosed | wires 1 (const 0) | in:%swapRequest_amountOut.5",
    "component | the swap's amountInMaximum | disclosed | wires 1 (const 0) | in:%swapRequest_amountInMaximum.6",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w3,w4",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,w2,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi18,pi19",
    "witness w0 | unguarded | reaches labels: request id; request record; swapper refund commitment | reaches impact: #63 | checks: constrain_bits 1 (also on const)",
    "witness w1 | unguarded | reaches labels: request id; request record; swapper refund commitment | reaches impact: #63 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: request id; request record; xcall communications commitment | reaches impact: #76 | checks: unchecked",
    "witness w3 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #76 | checks: constrain_bits 1 (also on const)",
    "witness w4 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #76 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 4 inputs | over in:%swapRequest_tokenIn.2 | under labels: none",
    "digest persistent_hash | 6 inputs | over in:%swapRequest_tokenIn.2,pi1,pi2 | under labels: none",
    "digest transient_hash | 43 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10 | under labels: request record",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.9,in:%coin_color_lo.10,in:%coin_nonce_hi.7,in:%coin_nonce_lo.8,in:%coin_value.11,pi12,pi13 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.9,in:%coin_color_lo.10,in:%coin_nonce_hi.7,in:%coin_nonce_lo.8,in:%coin_value.11,pi14,pi15 | under labels: none",
    "digest transient_hash | 2 inputs | over in:%coin_nonce_lo.8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.9,in:%coin_color_lo.10,in:%coin_nonce_lo.8,in:%coin_value.11 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,w0,w1,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10 | under labels: request id; request record",
    "digest transient_hash | 9 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%swapRequest_amountInMaximum.6,in:%swapRequest_amountOut.5,in:%swapRequest_fee.4,in:%swapRequest_tokenIn.2,in:%swapRequest_tokenOut.3,w2,pi3,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi18,pi19 | under labels: request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #24 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #27 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #51 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #52 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #53 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #54 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #55 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #56 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #57 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #58 | unguarded | wires 75: immediate 54, public-derived 0, labelled 21 | unlabelled witness-dependent 0 | labels: request record",
    "impact #59 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #60 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #61 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #62 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #63 | unguarded | wires 14: immediate 9, public-derived 0, labelled 5 | unlabelled witness-dependent 0 | labels: request id; request record; swapper refund commitment; the bought ERC20; the sold ERC20; the swap's amountInMaximum; the swap's amountOut",
    "impact #64 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #65 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #66 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #67 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #68 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #69 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #70 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #71 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #72 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #73 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #74 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #75 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #76 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #77 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #78 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #79 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #80 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== completeSwap | inputs 14 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11,changeNonce_hi.12,changeNonce_lo.13) | witnesses 4 (guarded 0) | public_inputs 13 (guarded 0) | impact 73 (guarded 0) wires 217 | digests persistent_hash 4 transient_hash 4 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 13 (guarded 0) | impact 73 (guarded 0) wires 217 | digests persistent_hash 4 transient_hash 4 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | own public key as swap recipient | disclosed | wires 2 (const 0) | w2,w3",
    "component | swap mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "component | attested amountIn spent | disclosed | wires 1 (const 0) | in:%serializedOutput.9",
    "component | swap change nonce | disclosed | wires 2 (const 0) | in:%changeNonce_hi.12,in:%changeNonce_lo.13",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as swap recipient | reaches impact: #44 #69 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as swap recipient | reaches impact: #44 #69 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi6 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi6,pi9,pi10 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,w2,w3,pi6,pi7,pi9,pi10 | under labels: own public key as swap recipient",
    "digest transient_hash | 4 inputs | over pi5 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi5,pi11,pi12 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%changeNonce_hi.12,in:%changeNonce_lo.13,in:%serializedOutput.9,w2,w3,pi5,pi8,pi11,pi12 | under labels: own public key as swap recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #14 | unguarded | wires 13: immediate 7, public-derived 6, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as swap recipient",
    "impact #45 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #51 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #52 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #53 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #54 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #55 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #56 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #57 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #58 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #59 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #60 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #61 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #62 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #63 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #64 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #65 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #66 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #67 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #68 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #69 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as swap recipient",
    "impact #70 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #71 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #72 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== refundSwap | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 0) | public_inputs 11 (guarded 0) | impact 48 (guarded 0) wires 162 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 11 (guarded 0) | impact 48 (guarded 0) wires 162 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | refund mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "component | own public key as refund recipient | disclosed | wires 2 (const 0) | w2,w3",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #44 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #44 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi5 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi5,pi9,pi10 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,w2,w3,pi5,pi8,pi9,pi10 | under labels: own public key as refund recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #14 | unguarded | wires 13: immediate 7, public-derived 6, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as refund recipient",
    "impact #45 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== startSupply | inputs 8 (evmNonce.0,keyVersion.1,amount.2,coin_nonce_hi.3,coin_nonce_lo.4,coin_color_hi.5,coin_color_lo.6,coin_value.7) | witnesses 5 (guarded 0) | public_inputs 21 (guarded 0) | impact 84 (guarded 0) wires 344 | digests persistent_hash 4 transient_hash 5 | outputs 0",
    "literals | \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 5 (guarded 0) | public_inputs 21 (guarded 0) | impact 84 (guarded 0) wires 344 | digests persistent_hash 4 transient_hash 5 | literals \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | request id | disclosed | wires 2 (const 1) | in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11",
    "component | surrendered coin nonce | disclosed | wires 2 (const 0) | in:%coin_nonce_hi.3,in:%coin_nonce_lo.4",
    "component | surrendered coin color | disclosed | wires 2 (const 0) | in:%coin_color_hi.5,in:%coin_color_lo.6",
    "component | surrendered coin value | disclosed | wires 1 (const 0) | in:%coin_value.7",
    "component | request record | disclosed | wires 33 (const 20) | in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11",
    "component | supplier refund commitment | disclosed | wires 2 (const 1) | in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,w0,w1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11",
    "component | the supplied amount | disclosed | wires 1 (const 0) | in:%amount.2",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w3,w4",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,w2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi19,pi20",
    "witness w0 | unguarded | reaches labels: request id; request record; supplier refund commitment | reaches impact: #66 | checks: constrain_bits 1 (also on const)",
    "witness w1 | unguarded | reaches labels: request id; request record; supplier refund commitment | reaches impact: #66 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: request id; request record; xcall communications commitment | reaches impact: #79 | checks: unchecked",
    "witness w3 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #79 | checks: constrain_bits 1 (also on const)",
    "witness w4 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #79 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 4 inputs | over pi1 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi1,pi2,pi3 | under labels: none",
    "digest transient_hash | 33 inputs | over in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11 | under labels: request record",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.5,in:%coin_color_lo.6,in:%coin_nonce_hi.3,in:%coin_nonce_lo.4,in:%coin_value.7,pi13,pi14 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.5,in:%coin_color_lo.6,in:%coin_nonce_hi.3,in:%coin_nonce_lo.4,in:%coin_value.7,pi15,pi16 | under labels: none",
    "digest transient_hash | 2 inputs | over in:%coin_nonce_lo.4 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.5,in:%coin_color_lo.6,in:%coin_nonce_lo.4,in:%coin_value.7 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,w0,w1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11 | under labels: request id; request record",
    "digest transient_hash | 9 inputs | over in:%amount.2,in:%evmNonce.0,in:%keyVersion.1,w2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi19,pi20 | under labels: request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #24 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #27 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #51 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #52 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #53 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #54 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #55 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #56 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #57 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #58 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #59 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #60 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #61 | unguarded | wires 60: immediate 47, public-derived 0, labelled 13 | unlabelled witness-dependent 0 | labels: request record",
    "impact #62 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #63 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #64 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #65 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #66 | unguarded | wires 8: immediate 6, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request id; request record; supplier refund commitment; the supplied amount",
    "impact #67 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #68 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #69 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #70 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #71 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #72 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #73 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #74 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #75 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #76 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #77 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #78 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #79 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #80 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #81 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #82 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #83 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== completeSupply | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | attested shares minted | disclosed | wires 1 (const 0) | in:%serializedOutput.9",
    "component | own public key as supply recipient | disclosed | wires 2 (const 0) | w2,w3",
    "component | supply mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as supply recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as supply recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi6 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi6,pi7,pi8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,in:%serializedOutput.9,w2,w3,pi6,pi7,pi8 | under labels: own public key as supply recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #13 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #18 | unguarded | wires 7: immediate 4, public-derived 3, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: attested shares minted",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as supply recipient",
    "impact #48 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== refundSupply | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | refund mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "component | own public key as refund recipient | disclosed | wires 2 (const 0) | w2,w3",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi6 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi6,pi7,pi8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,w2,w3,pi5,pi6,pi7,pi8 | under labels: own public key as refund recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #14 | unguarded | wires 7: immediate 4, public-derived 3, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as refund recipient",
    "impact #48 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== startRedeem | inputs 8 (evmNonce.0,keyVersion.1,shares.2,coin_nonce_hi.3,coin_nonce_lo.4,coin_color_hi.5,coin_color_lo.6,coin_value.7) | witnesses 5 (guarded 0) | public_inputs 22 (guarded 0) | impact 87 (guarded 0) wires 359 | digests persistent_hash 4 transient_hash 5 | outputs 0",
    "literals | \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 5 (guarded 0) | public_inputs 22 (guarded 0) | impact 87 (guarded 0) wires 359 | digests persistent_hash 4 transient_hash 5 | literals \"vault\" x2 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | request id | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12",
    "component | surrendered coin nonce | disclosed | wires 2 (const 0) | in:%coin_nonce_hi.3,in:%coin_nonce_lo.4",
    "component | surrendered coin color | disclosed | wires 2 (const 0) | in:%coin_color_hi.5,in:%coin_color_lo.6",
    "component | surrendered coin value | disclosed | wires 1 (const 0) | in:%coin_value.7",
    "component | request record | disclosed | wires 35 (const 20) | in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12",
    "component | redeemer refund commitment | disclosed | wires 2 (const 1) | in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,w0,w1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12",
    "component | the redeemed shares | disclosed | wires 1 (const 0) | in:%shares.2",
    "component | xcall entry-point hash | disclosed | wires 2 (const 0) | w3,w4",
    "component | xcall communications commitment | disclosed | wires 1 (const 0) | in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,w2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12,pi20,pi21",
    "witness w0 | unguarded | reaches labels: redeemer refund commitment; request id; request record | reaches impact: #69 | checks: constrain_bits 1 (also on const)",
    "witness w1 | unguarded | reaches labels: redeemer refund commitment; request id; request record | reaches impact: #69 | checks: constrain_bits 1 (also on const)",
    "witness w2 | unguarded | reaches labels: request id; request record; xcall communications commitment | reaches impact: #82 | checks: unchecked",
    "witness w3 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #82 | checks: constrain_bits 1 (also on const)",
    "witness w4 | unguarded | reaches labels: xcall entry-point hash | reaches impact: #82 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 4 inputs | over pi1 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi1,pi2,pi3 | under labels: none",
    "digest transient_hash | 35 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12 | under labels: request record",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.5,in:%coin_color_lo.6,in:%coin_nonce_hi.3,in:%coin_nonce_lo.4,in:%coin_value.7,pi14,pi15 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.5,in:%coin_color_lo.6,in:%coin_nonce_hi.3,in:%coin_nonce_lo.4,in:%coin_value.7,pi16,pi17 | under labels: none",
    "digest transient_hash | 2 inputs | over in:%coin_nonce_lo.4 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%coin_color_hi.5,in:%coin_color_lo.6,in:%coin_nonce_lo.4,in:%coin_value.7 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,w0,w1,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12 | under labels: request id; request record",
    "digest transient_hash | 9 inputs | over in:%evmNonce.0,in:%keyVersion.1,in:%shares.2,w2,pi4,pi5,pi6,pi7,pi8,pi9,pi10,pi11,pi12,pi20,pi21 | under labels: request id; request record; xcall communications commitment",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 4: immediate 3, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request record",
    "impact #24 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #27 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: request record",
    "impact #30 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #48 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #51 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #52 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #53 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #54 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #55 | unguarded | wires 6: immediate 4, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #56 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #57 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #58 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #59 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #60 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #61 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #62 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #63 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #64 | unguarded | wires 63: immediate 48, public-derived 0, labelled 15 | unlabelled witness-dependent 0 | labels: request record",
    "impact #65 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #66 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #67 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #68 | unguarded | wires 6: immediate 5, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: request id; request record",
    "impact #69 | unguarded | wires 8: immediate 6, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: redeemer refund commitment; request id; request record; the redeemed shares",
    "impact #70 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #71 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #72 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #73 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #74 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #75 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #76 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #77 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #78 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #79 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #80 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #81 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #82 | unguarded | wires 11: immediate 6, public-derived 2, labelled 3 | unlabelled witness-dependent 0 | labels: request id; request record; xcall communications commitment; xcall entry-point hash",
    "impact #83 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #84 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #85 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #86 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== completeRedeem | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | attested assets redeemed | disclosed | wires 1 (const 0) | in:%serializedOutput.9",
    "component | own public key as redeem recipient | disclosed | wires 2 (const 0) | w2,w3",
    "component | redeem mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as redeem recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as redeem recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi6 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi6,pi7,pi8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,in:%serializedOutput.9,w2,w3,pi6,pi7,pi8 | under labels: own public key as redeem recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #13 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #14 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #17 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #18 | unguarded | wires 7: immediate 4, public-derived 3, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 5: immediate 4, public-derived 0, labelled 1 | unlabelled witness-dependent 0 | labels: attested assets redeemed",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as redeem recipient",
    "impact #48 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    "== refundRedeem | inputs 12 (requestId_hi.0,requestId_lo.1,respond_bigR_x_hi.2,respond_bigR_x_lo.3,respond_bigR_y_hi.4,respond_bigR_y_lo.5,respond_s_hi.6,respond_s_lo.7,respond_recoveryId.8,serializedOutput.9,mintNonce_hi.10,mintNonce_lo.11) | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | outputs 0",
    "literals | \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "corpus twin | witnesses 4 (guarded 0) | public_inputs 9 (guarded 0) | impact 51 (guarded 0) wires 168 | digests persistent_hash 2 transient_hash 3 | literals \"vault\" x0 \"vault:user:\" x0 \"vault:refund:\" x1",
    "component | settle request id | disclosed | wires 2 (const 0) | in:%requestId_hi.0,in:%requestId_lo.1",
    "component | refund mint nonce | disclosed | wires 2 (const 0) | in:%mintNonce_hi.10,in:%mintNonce_lo.11",
    "component | own public key as refund recipient | disclosed | wires 2 (const 0) | w2,w3",
    "witness w0 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w1,pi3,pi4)",
    "witness w1 | unguarded | reaches labels: none | reaches impact: none | checks: assert 1 constrain_bits 1 (also on in:%requestId_hi.0,in:%requestId_lo.1,w0,pi3,pi4)",
    "witness w2 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "witness w3 | unguarded | reaches labels: own public key as refund recipient | reaches impact: #47 | checks: constrain_bits 1 (also on const)",
    "digest transient_hash | 3 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,in:%serializedOutput.9 | under labels: none",
    "digest transient_hash | 6 inputs | over in:%requestId_hi.0,in:%requestId_lo.1,w0,w1 | under labels: none",
    "digest transient_hash | 4 inputs | over pi6 | under labels: none",
    "digest persistent_hash | 6 inputs | over pi6,pi7,pi8 | under labels: none",
    "digest persistent_hash | 9 inputs | over in:%mintNonce_hi.10,in:%mintNonce_lo.11,w2,w3,pi5,pi6,pi7,pi8 | under labels: own public key as refund recipient",
    "impact #0 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #1 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #2 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #3 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #4 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #5 | unguarded | wires 12: immediate 7, public-derived 5, labelled 0 | unlabelled witness-dependent 0",
    "impact #6 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #7 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #8 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #9 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #10 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #11 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #12 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #13 | unguarded | wires 5: immediate 3, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #14 | unguarded | wires 7: immediate 4, public-derived 3, labelled 0 | unlabelled witness-dependent 0",
    "impact #15 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #16 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #17 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #18 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #19 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #20 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: settle request id",
    "impact #21 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #22 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #23 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #24 | unguarded | wires 7: immediate 7, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #25 | unguarded | wires 4: immediate 3, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #26 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #27 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #28 | unguarded | wires 5: immediate 3, public-derived 2, labelled 0 | unlabelled witness-dependent 0",
    "impact #29 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #30 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #31 | unguarded | wires 6: immediate 5, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #32 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #33 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #34 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #35 | unguarded | wires 5: immediate 4, public-derived 1, labelled 0 | unlabelled witness-dependent 0",
    "impact #36 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #37 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #38 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #39 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #40 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #41 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #42 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #43 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #44 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #45 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #46 | unguarded | wires 4: immediate 4, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #47 | unguarded | wires 6: immediate 4, public-derived 0, labelled 2 | unlabelled witness-dependent 0 | labels: own public key as refund recipient",
    "impact #48 | unguarded | wires 2: immediate 2, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #49 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "impact #50 | unguarded | wires 1: immediate 1, public-derived 0, labelled 0 | unlabelled witness-dependent 0",
    "unlabelled witness-dependent public components | none",
    // GENERATED END
];

#[test]
fn the_leakage_inventory_is_frozen() {
    let built = build_inventory();
    let frozen: Vec<String> = INVENTORY.iter().map(|s| s.to_string()).collect();
    if built != frozen {
        let mut diff = Vec::new();
        for (i, (b, f)) in built.iter().zip(&frozen).enumerate() {
            if b != f {
                diff.push(format!("line {i}:\n  frozen: {f}\n  built:  {b}"));
            }
        }
        if built.len() != frozen.len() {
            diff.push(format!("frozen has {} lines, built has {}", frozen.len(), built.len()));
        }
        panic!(
            "the vault's leakage surface moved — regenerate with `--ignored \
             regenerate_leakage_inventory` and REVIEW the diff:\n{}",
            diff.join("\n")
        );
    }
}

/// COMPLETENESS, as a hard gate: every witness-dependent wire that reaches
/// the public statement carries a declared label in its ancestry.
#[test]
fn no_unlabelled_witness_dependent_public_component() {
    let offenders: Vec<String> = build_inventory()
        .into_iter()
        .filter(|l| l.starts_with("unlabelled witness-dependent public components | "))
        .filter(|l| !l.ends_with("| none"))
        .collect();
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// The corpus twin has the same leakage SURFACE: same witness and guard
/// counts, same `impact` op and guard counts, same operand-wire count, same
/// digest counts, same literal counts.
#[test]
fn the_corpus_twin_has_the_same_surface() {
    let mut mismatches = Vec::new();
    for c in Circuit::ALL {
        let lines = inventory(c);
        let head = &lines[0];
        let twin = &lines[2];
        // Compare the shared tail of the header (from `witnesses` on,
        // dropping the inputs and outputs fields ours alone reports).
        let ours_tail = head
            .split(" | ")
            .filter(|f| {
                f.starts_with("witnesses")
                    || f.starts_with("public_inputs")
                    || f.starts_with("impact")
                    || f.starts_with("digests")
            })
            .collect::<Vec<_>>()
            .join(" | ");
        let twin_tail = twin
            .split(" | ")
            .filter(|f| {
                f.starts_with("witnesses")
                    || f.starts_with("public_inputs")
                    || f.starts_with("impact")
                    || f.starts_with("digests")
            })
            .collect::<Vec<_>>()
            .join(" | ");
        let ours_lit = lines[1].trim_start_matches("literals | ").to_string();
        let twin_lit = twin
            .split(" | literals ")
            .nth(1)
            .unwrap_or_default()
            .to_string();
        if ours_tail != twin_tail || ours_lit != twin_lit {
            mismatches.push(format!(
                "{}:\n  ours: {ours_tail} | {ours_lit}\n  twin: {twin_tail} | {twin_lit}",
                c.zkir_name()
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
#[ignore]
fn regenerate_leakage_inventory() {
    let body: String = build_inventory()
        .iter()
        .map(|l| format!("    {l:?},\n"))
        .collect();
    rewrite_generated_region(&test_source("leakage_inventory.rs"), &body);
}
