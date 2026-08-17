//! `wide.compact` — THE SIXTEEN-FIELD LEDGER BLOCK, against compactc (M22
//! stage B2; notes/coin-arms-nested-adts.org, stage B1 correction (ii)).
//!
//! WHAT THIS PINS, and why it is a CORRECTNESS test rather than a feature
//! one. A ledger block is not a flat list of fields: `determine-ledger-paths.
//! ss` batches it into segments of fifteen (`maximum-ledger-segment-length`,
//! langs.ss:851) and gives every field the path of segment indices that
//! reaches it. Below sixteen fields that path is `[i]` — the bare index
//! `#[derive(Ledger)]` emitted for eleven milestones — and at sixteen it is
//! two elements for EVERY field, `f0` included. A sixteen-field contract
//! built before stage B2 would therefore have written its state to the wrong
//! slots, silently, with nothing in the workspace to catch it: the widest
//! ledger block here is `Vault`'s THIRTEEN.
//!
//! Stage B1 fixed the EMISSION layer (every builder takes a path) and pinned
//! it with `a_sixteen_field_contract_makes_every_cell_write_nested`, which
//! hands `cell_write_at` a two-element path by hand. This pins the DERIVE:
//! the paths come from the declaration, nobody writes them, and the resulting
//! circuit is compactc's byte for byte.
//!
//! The contract block lives in this file rather than in `src/` for the reason
//! `nested_typed.rs` gives: it is a probe of the derive, not a circuit the
//! workspace ships, and the frozen snapshots are a statement about the
//! latter.

use minocrab::v3::{Circuit3, Compiled3};
use minocrab::{Private, Public};
use minocrab_std::v3::{contract, label, Disclose, Discloses, Ledger, LedgerCell, Uint};
use minocrab_zkir::v3::{to_zkir_string, IrSource};

label! {
    Val = "value";
}

/// Sixteen `Uint<64>` cells — one more than a segment holds.
///
/// NOTHING here says "path": the fields are declared in order, as in every
/// other contract, and the derive computes what compactc computes.
#[derive(Ledger)]
#[allow(dead_code)] // fourteen of the sixteen exist to make the block wide
struct Wide {
    f0: LedgerCell<Uint<64, Public>>,
    f1: LedgerCell<Uint<64, Public>>,
    f2: LedgerCell<Uint<64, Public>>,
    f3: LedgerCell<Uint<64, Public>>,
    f4: LedgerCell<Uint<64, Public>>,
    f5: LedgerCell<Uint<64, Public>>,
    f6: LedgerCell<Uint<64, Public>>,
    f7: LedgerCell<Uint<64, Public>>,
    f8: LedgerCell<Uint<64, Public>>,
    f9: LedgerCell<Uint<64, Public>>,
    f10: LedgerCell<Uint<64, Public>>,
    f11: LedgerCell<Uint<64, Public>>,
    f12: LedgerCell<Uint<64, Public>>,
    f13: LedgerCell<Uint<64, Public>>,
    f14: LedgerCell<Uint<64, Public>>,
    f15: LedgerCell<Uint<64, Public>>,
}

const WIDE: Wide = Wide::new();

struct WideContract;

#[contract]
impl WideContract {
    /// `f0 = disclose(v); f15 = disclose(v);` — the fixture's one circuit.
    ///
    /// Ten instructions rather than six: each write is FIVE, not three,
    /// because the leading `idxp` over the segment and the closing `insc 1`
    /// that a one-element path suppresses are both live here.
    #[circuit]
    pub fn w(c: &mut Circuit3, v: Uint<64, Private>) -> Discloses<(Val,)> {
        let v = v.disclose_as::<Val>(c);
        WIDE.f0.write(c, &v);
        WIDE.f15.write(c, &v);
        Discloses::of(())
    }
}

/// compactc's artifact for the fixture's one circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/wide/out/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the pinned compactc's artifact parses")
}

/// Serialized ZKIR with every `%name.index` identifier replaced by
/// `%<order of first appearance>` — the canonicalization every differential
/// here uses, over both sides' folded IR.
fn canonical(ir: &IrSource) -> String {
    let ir = &minocrab_ir::v3::passes::folded(ir);
    let text = to_zkir_string(ir).expect("serializes");
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let next = renames.len();
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{next}");
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// THE HEADLINE: the derive's paths are compactc's, on the wire.
#[test]
fn identical_instruction_streams() {
    let ours: fn() -> Compiled3 = WideContract::w;
    assert_eq!(
        canonical(&ours().ir),
        canonical(&theirs("w")),
        "w: the derive's field paths differ from compactc's segmentation"
    );
}

/// CLAIM 2 — the SEGMENTATION is visible in the operands, and it is the only
/// thing that could be wrong.
///
/// The headline would pass if both sides agreed on a wrong-but-consistent
/// numbering (they cannot — one side is compactc — but the shape is worth
/// stating). This reads the two writes' operands straight out of compactc's
/// own artifact: the leading `idxp` carries the SEGMENT, the pushed cell
/// carries the field's position INSIDE it, and the closing `insc 1` is the
/// suppression coming back to life.
#[test]
fn the_first_field_leads_a_remainder_segment_of_its_own() {
    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/wide/out/zkir/w.zkir",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture is compiled");
    let json: serde_json::Value = serde_json::from_str(&text).expect("the artifact is JSON");
    let impacts: Vec<Vec<String>> = json["instructions"]
        .as_array()
        .expect("instructions")
        .iter()
        .filter(|i| i["op"] == "impact")
        .map(|i| {
            i["inputs"]
                .as_array()
                .expect("operands")
                .iter()
                .map(|v| v.as_str().unwrap_or("%wire").to_string())
                .collect()
        })
        .collect();

    // f0: idxp over the path [0] — segment 0, the REMAINDER segment — then
    // the cell key 0, its position inside that segment.
    assert_eq!(impacts[0], ["0x70", "0x01", "0x01", "0x00"], "f0's idxp");
    assert_eq!(
        impacts[1],
        ["0x10", "0x01", "0x01", "0x01", "0x00"],
        "f0's pushed key"
    );
    assert_eq!(impacts[3], ["0x91"], "ins 1");
    assert_eq!(impacts[4], ["0xa1"], "the insc a depth-1 write suppresses");

    // f15: segment 1, position 14 — the full segment renumbers from zero.
    assert_eq!(impacts[5], ["0x70", "0x01", "0x01", "0x01"], "f15's idxp");
    assert_eq!(
        impacts[6],
        ["0x10", "0x01", "0x01", "0x01", "0x0e"],
        "f15's pushed key"
    );
}

/// CLAIM 3 — and the derive says the same thing without the compiler.
///
/// `index()` is the one-element accessor, so on a segmented block it is not
/// available at all: every field here has a two-element path, and asking for
/// a single index is an assert rather than a wrong answer.
#[test]
fn the_derive_gives_every_field_a_two_element_path() {
    // The paths themselves are private to the slot types; what is observable
    // from outside is that the WRITES agree with compactc, which the headline
    // asserts, and that no field pretends to have a bare index. The macro
    // crate's `a_sixteen_field_block_expands_to_two_element_paths` pins the
    // expansion itself.
    let ours: fn() -> Compiled3 = WideContract::w;
    let text = to_zkir_string(&ours().ir).expect("serializes");
    assert_eq!(
        text.matches("0xa1").count(),
        2,
        "each write closes with the `insc 1` a segmented block makes live:\n{text}"
    );
}
