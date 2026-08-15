//! The PUBLISHED artifact: `spec/borsh-subset.md`'s offset tables and
//! `spec/vectors/*.json`, generated from the same layout machinery the
//! conformance suite checks (M11 stage 8, notes/borsh-format.org).
//!
//! Everything a reader of the spec could implement against is generated
//! here, from `borsh`'s own schema of the spec types — never typed by hand —
//! so the document cannot drift from the format. What is hand-written in
//! `spec/borsh-subset.md` is PROSE: the subset rule, the reject rules, the
//! padding rule, the response-kind table and the rationale. Everything
//! between the generated markers is this module's output, and
//! `spec_document::the_committed_offset_tables_are_generated` fails if the
//! committed file disagrees.
//!
//! Regenerate with:
//! `cargo test --release -p minocrab-contracts --test serialization_conformance -- \
//!      --ignored --nocapture regenerate_spec`

use std::fmt::Write as _;
use std::path::PathBuf;

use borsh::schema::BorshSchemaContainer;
use borsh::{BorshSchema, BorshSerialize};
use minocrab_contracts::erc20_vault;
use serde::Serialize;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

use super::deployed;
use super::oracle::{borsh_bytes, layout_rows};
use super::spec_types::*;

/// The marker pair the generated offset tables live between in
/// `spec/borsh-subset.md`. Prose outside them is hand-written and is never
/// touched by the regenerator.
pub const TABLES_BEGIN: &str = "<!-- BEGIN GENERATED: offset tables -->";
pub const TABLES_END: &str = "<!-- END GENERATED: offset tables -->";

/// The repository's `spec/` directory.
pub fn spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("spec")
}

// ---- the offset tables ---------------------------------------------------------

/// Every spec type's byte-offset table, as the markdown the document
/// publishes. Walked out of `borsh::schema_container_of` — the same rows the
/// frozen `LAYOUT_SNAPSHOT` pins.
pub fn offset_tables_markdown() -> String {
    let mut out = String::new();
    for (name, container) in schema_containers() {
        let rows = layout_rows(&container);
        let len: usize = rows.iter().map(|r| r.width).sum();
        let _ = writeln!(out, "\n### `{name}` — {len} bytes\n");
        let _ = writeln!(out, "| offset | width | field | type |");
        let _ = writeln!(out, "|---:|---:|---|---|");
        for row in rows {
            let path = if row.path.is_empty() {
                "(the value)".to_string()
            } else {
                format!("`{}`", row.path)
            };
            let _ = writeln!(
                out,
                "| {} | {} | {path} | `{}` |",
                row.offset, row.width, row.kind
            );
        }
    }
    out
}

// ---- the golden vectors ----------------------------------------------------------

/// One leaf of a vector's value, in DECLARATION ORDER — which is why the
/// value is an array and not a JSON object: the format is ordered and JSON
/// objects are not.
#[derive(Serialize)]
pub struct VectorField {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: usize,
    pub width: usize,
    /// The field's own bytes, in string order.
    pub hex: String,
    /// The little-endian integer those bytes decode to, for the leaves that
    /// are numbers (`bool` decodes to 0 or 1). Absent for byte arrays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u128>,
}

/// One golden vector: a value, its bytes, its digests and its fields.
#[derive(Serialize)]
pub struct Vector {
    #[serde(rename = "type")]
    pub kind: String,
    pub len: usize,
    /// The canonical Borsh encoding — THE AUTHORITATIVE BYTES of the vector.
    pub hex: String,
    /// `SHA-256(hex)` — what Midnight's `persistentHash` computes over this
    /// preimage.
    pub sha256: String,
    /// `keccak256(hex)`. For a request record this IS the request id; for an
    /// `AttestationPreimage` it IS the digest the MPC signs. Elsewhere it is
    /// a checksum an implementation can compare against.
    pub keccak256: String,
    /// The 288-byte `Misc` envelope these bytes are logged inside, where
    /// there is one: `pad(32, eventName) ‖ hex ‖ zeros`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_hex: Option<String>,
    pub fields: Vec<VectorField>,
}

/// A committed vector file: a header saying it is generated, and the
/// vectors.
#[derive(Serialize)]
pub struct VectorFile {
    #[serde(rename = "$comment")]
    pub comment: &'static str,
    pub format: &'static str,
    pub spec: &'static str,
    pub about: &'static str,
    pub vectors: Vec<Vector>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The little-endian integer a scalar leaf's bytes decode to; `None` for a
/// byte array, whose bytes are its value.
fn number(kind: &str, bytes: &[u8]) -> Option<u128> {
    match kind {
        "bool" | "u8" | "u16" | "u32" | "u64" | "u128" => {
            let mut buf = [0u8; 16];
            buf[..bytes.len()].copy_from_slice(bytes);
            Some(u128::from_le_bytes(buf))
        }
        _ => None,
    }
}

/// A vector of `value`, with its fields walked out of borsh's own schema.
pub fn vector<T: BorshSerialize + BorshSchema>(name: &str, value: &T) -> Vector {
    let bytes = borsh_bytes(value);
    let rows = layout_rows(&BorshSchemaContainer::for_type::<T>());
    assert_eq!(
        rows.iter().map(|r| r.width).sum::<usize>(),
        bytes.len(),
        "{name}: the schema walk and the encoding disagree on the width"
    );
    let fields = rows
        .into_iter()
        .map(|row| {
            let slice = &bytes[row.offset..row.offset + row.width];
            VectorField {
                path: if row.path.is_empty() {
                    "(the value)".to_string()
                } else {
                    row.path.clone()
                },
                number: number(&row.kind, slice),
                kind: row.kind,
                offset: row.offset,
                width: row.width,
                hex: hex(slice),
            }
        })
        .collect();
    Vector {
        kind: name.to_string(),
        len: bytes.len(),
        sha256: hex(&Sha256::digest(&bytes)),
        keccak256: hex(&Keccak256::digest(&bytes)),
        hex: hex(&bytes),
        envelope_hex: None,
        fields,
    }
}

/// A vector for a payload the singleton logs, carrying the 288-byte `Misc`
/// envelope the deployed contract emits around it.
fn misc_vector<T: BorshSerialize + BorshSchema>(name: &str, event: &str, value: &T) -> Vector {
    let mut v = vector(name, value);
    v.envelope_hex = Some(hex(&deployed::misc_envelope(event, &borsh_bytes(value))));
    v
}

// ---- the values the vectors carry ------------------------------------------------
//
// Fixed and deterministic, and realistic where the protocol fixes a value:
// the schema strings and selectors are the DEPLOYED constants
// (`erc20_vault::*`), the enum tags are the first members every deployed
// site uses, and every free byte is a visible pattern so that a wrong offset
// shows up as a wrong byte rather than as a plausible one.

/// `byte i = start + i·step`, the pattern every array in the vectors uses.
fn pattern<const N: usize>(start: u8, step: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add((i as u8).wrapping_mul(step)))
}

fn word(tag: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = tag;
    w
}

fn schema<const N: usize>(bytes: &[u8]) -> ByteArray<N> {
    ByteArray(bytes.try_into().expect("schema literal has its declared width"))
}

/// The 2-word request record, in the shape `deposit` writes: a
/// `transfer(to, amount)` calldata signed under a depositor's derived path.
pub fn vault_event() -> VaultEvent {
    VaultEvent {
        sender: pattern(0x10, 1),
        request_nonce: 7,
        key_version: 1,
        path: pattern(0x40, 3),
        algo: 0,
        dest: 0,
        params: ByteArray::default(),
        tx_param_type: 0,
        tx_params: EvmType2TxParams2 {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 100_000,
            to: pattern(0xa0, 1),
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::TRANSFER_SELECTOR,
                    no_words: 2,
                    words: [pattern(0xb0, 1), word(0xff)],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: pattern(0x01, 2),
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// The 7-word swap record, in the shape `swap` writes.
pub fn swap_event() -> SwapEvent {
    SwapEvent {
        sender: pattern(0x10, 1),
        request_nonce: 9,
        key_version: 1,
        path: pattern(0x40, 3),
        algo: 0,
        dest: 0,
        params: ByteArray::default(),
        tx_param_type: 0,
        tx_params: EvmType2TxParams7 {
            chain_id: 1,
            nonce: 43,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 700_000,
            to: pattern(0xa0, 1),
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata7 {
                    selector: erc20_vault::EXACT_OUTPUT_SINGLE_SELECTOR,
                    no_words: 7,
                    words: [
                        word(1),
                        word(2),
                        word(3),
                        word(4),
                        word(5),
                        word(6),
                        pattern(0xc0, 1),
                    ],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: pattern(0x01, 2),
        output_deserialization_schema: schema(erc20_vault::SWAP_OUTPUT_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::SWAP_RESPOND_SCHEMA),
    }
}

/// The request id a vector's record hashes to — the value the MPC recomputes
/// and drops the request on mismatch.
fn request_id_of<T: BorshSerialize>(value: &T) -> [u8; 32] {
    Keccak256::digest(borsh_bytes(value)).into()
}

// ---- the four files ---------------------------------------------------------------

const COMMENT: &str = "GENERATED — do not edit. Regenerate with: cargo test --release \
                       -p minocrab-contracts --test serialization_conformance -- --ignored \
                       regenerate_spec";
const FORMAT: &str = "borsh-subset-vectors/1";
const SPEC: &str = "spec/borsh-subset.md";

fn file(about: &'static str, vectors: Vec<Vector>) -> String {
    let file = VectorFile {
        comment: COMMENT,
        format: FORMAT,
        spec: SPEC,
        about,
        vectors,
    };
    let mut text = serde_json::to_string_pretty(&file).expect("vectors serialize");
    text.push('\n');
    text
}

/// The leaf table, as values: one vector per primitive the subset admits,
/// plus the two shapes that replace Borsh's variable-width ones.
fn leaves() -> String {
    file(
        "The leaf table as values — one vector per primitive the subset admits. \
         Flagged<T> is the Maybe replacement: a bool tag and an ALWAYS-PRESENT payload, \
         so its width does not depend on the tag (both vectors are 5 bytes).",
        vec![
            vector("bool (false)", &false),
            vector("bool (true)", &true),
            vector("u8", &0xA7u8),
            vector("u16", &0xBEEFu16),
            vector("u32", &0xDEAD_BEEFu32),
            vector("u64", &0x0102_0304_0506_0708u64),
            vector("u128", &0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10u128),
            vector("[u8; 20]", &pattern::<20>(0x01, 7)),
            vector("[u8; 32]", &pattern::<32>(0x02, 11)),
            vector("[u8; 64]", &ByteArray(pattern::<64>(0x03, 13))),
            vector(
                "Flagged<u32> (set)",
                &Flagged {
                    is_some: true,
                    value: 0xDEAD_BEEFu32,
                },
            ),
            vector(
                "Flagged<u32> (unset)",
                &Flagged {
                    is_some: false,
                    value: 0u32,
                },
            ),
        ],
    )
}

/// The two request records, and the request ids they hash to.
fn records() -> String {
    file(
        "The two request-record instantiations. keccak256 of these bytes IS the request id \
         the vault stores and the MPC recomputes (it drops the request on mismatch).",
        vec![
            vector("VaultEvent", &vault_event()),
            vector("SwapEvent", &swap_event()),
        ],
    )
}

/// The attested outputs THIS SPEC defines (M11 stage 5), with their signed
/// digest preimages.
fn attested_outputs() -> String {
    let request_id = request_id_of(&vault_event());
    file(
        "The kind-tagged attested outputs and their digest preimages. keccak256 of an \
         AttestationPreimage IS the digest the MPC signs; request_id here is the request id of \
         the VaultEvent vector in records.json.",
        vec![
            vector(
                "VaultResponse (kind 0, CLAIM, success)",
                &VaultResponse {
                    kind: 0,
                    success: true,
                },
            ),
            vector(
                "VaultResponse (kind 1, WITHDRAW, failure)",
                &VaultResponse {
                    kind: 1,
                    success: false,
                },
            ),
            vector(
                "SwapResponse (kind 2, SWAP)",
                &SwapResponse {
                    kind: 2,
                    amount_in: 1_234_567_890,
                },
            ),
            vector("FailureResponse (kind 3, FAILURE)", &FailureResponse { kind: 3 }),
            vector(
                "AttestationPreimage<VaultResponse>",
                &AttestationPreimage {
                    request_id,
                    output: VaultResponse {
                        kind: 0,
                        success: true,
                    },
                },
            ),
            vector(
                "AttestationPreimage<SwapResponse>",
                &AttestationPreimage {
                    request_id,
                    output: SwapResponse {
                        kind: 2,
                        amount_in: 1_234_567_890,
                    },
                },
            ),
            vector(
                "AttestationPreimage<FailureResponse>",
                &AttestationPreimage {
                    request_id,
                    output: FailureResponse { kind: 3 },
                },
            ),
        ],
    )
}

/// The attested outputs the DEPLOYED contract accepts today — kept because
/// the deployed vault is still running, and because the difference is the
/// point.
fn deployed_attested_outputs() -> String {
    let request_id = request_id_of(&vault_event());
    file(
        "TODAY'S deployed attested outputs, for reference only: no kind byte, success as a \
         raw u8 (any byte is accepted — the 0x02 hazard), and a 5-byte 0xdeadbeef01 failure \
         sentinel. New implementations use attested-outputs.json.",
        vec![
            vector("ClaimOutput", &ClaimOutput { success: 1 }),
            vector("CompleteWithdrawOutput", &CompleteWithdrawOutput { success: 1 }),
            vector(
                "RefundOutput",
                &RefundOutput {
                    failure: [0xde, 0xad, 0xbe, 0xef, 0x01],
                },
            ),
            vector(
                "CompleteSwapOutput",
                &CompleteSwapOutput {
                    amount_in: 1_234_567_890,
                },
            ),
            vector(
                "AttestationPreimage<ClaimOutput>",
                &AttestationPreimage {
                    request_id,
                    output: ClaimOutput { success: 1 },
                },
            ),
            vector(
                "AttestationPreimage<CompleteSwapOutput>",
                &AttestationPreimage {
                    request_id,
                    output: CompleteSwapOutput {
                        amount_in: 1_234_567_890,
                    },
                },
            ),
        ],
    )
}

/// The singleton's logged payloads, inside the envelope they are logged in.
fn misc_payloads() -> String {
    let request_id = request_id_of(&vault_event());
    let mut payload = [0u8; 128];
    // callerAddress ‖ depth ‖ path[0..4] ‖ zeros — the V1 notification
    // payload `construct_notification_v1` packs.
    payload[..32].copy_from_slice(&pattern::<32>(0x10, 1));
    payload[32] = 2;
    payload[33..37].copy_from_slice(b"reqs");
    file(
        "The Signet singleton's Misc log payloads. `hex` is the payload; `envelope_hex` is the \
         288-byte Misc value actually logged — pad(32, eventName) ‖ payload ‖ zeros — and the \
         trailing zeros are REQUIRED, not optional (the deployed circuit hashes them).",
        vec![
            misc_vector(
                "SignBidirectionalMisc",
                "SignBidirectionalEvent",
                &SignBidirectionalMisc {
                    version: 1,
                    request_id,
                    payload: ByteArray(payload),
                },
            ),
            misc_vector(
                "RespondMisc",
                "SignatureRespondedEvent",
                &RespondMisc {
                    request_id,
                    big_r_x: pattern(0x20, 5),
                    big_r_y: pattern(0x30, 7),
                    s: pattern(0x50, 3),
                    recovery_id: 1,
                },
            ),
        ],
    )
}

/// Every committed vector file: `(file name, contents)`.
pub fn vector_files() -> Vec<(&'static str, String)> {
    vec![
        ("leaves.json", leaves()),
        ("records.json", records()),
        ("attested-outputs.json", attested_outputs()),
        ("attested-outputs-deployed.json", deployed_attested_outputs()),
        ("misc-payloads.json", misc_payloads()),
    ]
}
