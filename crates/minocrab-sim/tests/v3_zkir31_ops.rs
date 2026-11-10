//! The ZKIR 3.1 instructions and the deprecated 3.0 byte instructions,
//! simulated by `minocrab_sim::v3::simulate` and checked by midnight-zkir
//! 3.2.0's own `IrSource::check` on the same IR and preimage: both accept
//! or both reject, and on acceptance the outputs agree, compared through
//! the communications commitment (upstream accepts it only if ITS outputs
//! encode to the same limbs as ours). Every rejection path below is one the
//! corpus never reaches, since compactc writes only valid instances.

use std::borrow::Cow;

use midnight_curves::{k256, p256};
use midnight_transient_crypto::curve::Fr as TFr;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::{parse_zkir, IrSource, IrValue, Operand};
use minocrab_zkir::Fr;
use serde_json::{json, Value};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn imm(fr: Fr) -> Value {
    serde_json::to_value(Operand::Immediate(fr)).expect("an immediate serializes")
}

fn ir(inputs: &[(&str, &str)], outputs: &[&str], ins: Vec<Value>, comm: bool) -> IrSource {
    let j = json!({
        "version": {"major": 3, "minor": 1},
        "do_communications_commitment": comm,
        "inputs": inputs.iter().map(|(n, t)| json!({"name": n, "type": t})).collect::<Vec<_>>(),
        "outputs": outputs,
        "instructions": ins,
    });
    let s = serde_json::to_string(&j).unwrap();
    parse_zkir(s.as_bytes(), "v3_zkir31_ops").unwrap_or_else(|e| panic!("parse: {e:?}\n{s}"))
}

fn pre(inputs: &[Fr], cc: Option<(Fr, Fr)>) -> ProofPreimage {
    ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: cc,
        key_location: KeyLocation(Cow::Borrowed("v3_zkir31_ops")),
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Accept(Vec<IrValue>),
    Reject,
}

/// Run both; panic on disagreement; return the outcome.
fn diff(
    inputs: &[(&str, &str)],
    outputs: &[&str],
    ins: Vec<Value>,
    raw: &[Fr],
    label: &str,
) -> Outcome {
    let plain = ir(inputs, outputs, ins.clone(), false);
    let ours = simulate(&plain, &pre(raw, None));
    let theirs = plain.check(&pre(raw, None));
    match (&ours, &theirs) {
        (Err(_), Err(_)) => return Outcome::Reject,
        (Ok(_), Ok(_)) => {}
        _ => panic!("[{label}] acceptance disagrees:\n ours={ours:?}\n theirs={theirs:?}"),
    }
    let run = ours.unwrap();
    assert_eq!(&run.pi_skips, theirs.as_ref().unwrap(), "[{label}] pi_skips");
    // Commit to OUR outputs; upstream re-derives its own and must match.
    let mut cc_in: Vec<TFr> = raw.to_vec();
    for v in &run.outputs {
        for e in encode_offcircuit(v) {
            cc_in.push(e.try_into().unwrap());
        }
    }
    let rand: Fr = 0x5eed.into();
    let c = transient_commit(&cc_in[..], rand);
    let committed = ir(inputs, outputs, ins, true);
    let pi = pre(raw, Some((c, rand)));
    let ours2 = simulate(&committed, &pi);
    let theirs2 = committed.check(&pi);
    assert!(ours2.is_ok(), "[{label}] ours rejects own commitment: {ours2:?}");
    assert!(
        theirs2.is_ok(),
        "[{label}] upstream's outputs differ from ours (commitment rejected): {theirs2:?}; ours={:?}",
        run.outputs
    );
    Outcome::Accept(run.outputs)
}

fn bytes_raw(bs: &[u8]) -> Vec<Fr> {
    encode_offcircuit(&IrValue::Bytes(bs.to_vec()))
        .into_iter()
        .map(|v| v.try_into().unwrap())
        .collect()
}

fn limb_from(bs: &[u8]) -> Fr {
    let mut buf = [0u8; 32];
    buf[..bs.len()].copy_from_slice(bs);
    Fr::from_le_bytes(&buf).unwrap()
}

fn btype(n: usize) -> String {
    format!("Bytes<{n}>")
}

#[test]
fn bytes_from_into_natives_every_length() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    let mut accepts = 0;
    let mut rejects = 0;
    for len in (1usize..=96).chain([124, 125, 155, 200]) {
        let nb = len.div_ceil(31);
        for variant in 0..4 {
            // variant 0: valid; 1: last limb one byte too wide; 2: a middle/first limb >= 2^248
            // (only when nb > 1); 3: wrong limb count.
            let bs = rng.bytes(len);
            let mut limbs: Vec<Fr> = bs.chunks(31).map(limb_from).collect();
            let mut n_inputs = nb;
            match variant {
                1 => {
                    let last_len = len - 31 * (nb - 1);
                    let mut b = vec![0u8; last_len + 1];
                    b[last_len] = 1 + rng.below(255) as u8;
                    if last_len < 31 {
                        limbs[nb - 1] = limb_from(&b);
                    } else {
                        continue;
                    }
                }
                2 => {
                    if nb < 2 {
                        continue;
                    }
                    let mut b = rng.bytes(31);
                    b.push(1);
                    limbs[0] = limb_from(&b);
                }
                3 => n_inputs = nb + 1,
                _ => {}
            }
            let names: Vec<String> = (0..n_inputs).map(|i| format!("%l.{i}")).collect();
            let inputs: Vec<(&str, &str)> =
                names.iter().map(|n| (n.as_str(), "Scalar<BLS12-381>")).collect();
            let mut raw = limbs.clone();
            if n_inputs > nb {
                raw.push(Fr::from(0u64));
            }
            let outs: Vec<String> = (0..nb).map(|i| format!("%o.{i}")).collect();
            let ins = vec![
                json!({"op": "bytes_from_natives", "inputs": names, "len": len, "output": "%b"}),
                json!({"op": "reverse", "bytes": "%b", "output": "%r"}),
                json!({"op": "bytes_into_natives", "bytes": "%r", "outputs": outs}),
                json!({"op": "output", "vals": ["%b", "%r"]}),
            ];
            let bt = btype(len);
            let out = diff(&inputs, &[&bt, &bt], ins, &raw, &format!("bfn len={len} v={variant}"));
            match (variant, &out) {
                (0, Outcome::Accept(vals)) => {
                    assert_eq!(vals[0], IrValue::Bytes(bs.clone()));
                    accepts += 1;
                }
                (0, Outcome::Reject) => panic!("valid len={len} rejected"),
                (_, Outcome::Reject) => rejects += 1,
                (v, o) => panic!("invalid variant {v} len={len} accepted: {o:?}"),
            }
        }
    }
    eprintln!("bytes_from/into_natives: {accepts} accepts, {rejects} rejects agree");
}

#[test]
fn slice_nth_concat_agree() {
    let mut rng = Rng(42);
    let mut n = 0;
    for len in [1usize, 2, 31, 32, 33, 62, 63, 64, 65, 100] {
        let bs = rng.bytes(len);
        let raw = bytes_raw(&bs);
        let bt = btype(len);
        for _ in 0..12 {
            let start = rng.below(len as u64 + 2);
            let slen = rng.below(len as u64 + 2);
            let idx = rng.below(len as u64 + 1);
            let total = slen as usize + 1 + len;
            let ins = vec![
                json!({"op": "slice", "bytes": "%b", "start": start, "len": slen, "output": "%s"}),
                json!({"op": "nth", "bytes": "%b", "index": idx, "output": "%n"}),
                json!({"op": "concat", "inputs": ["%s", "%n", "%b"], "output": "%c"}),
                json!({"op": "output", "vals": ["%s", "%n", "%c"]}),
            ];
            let st = btype(slen.max(1) as usize);
            let ct = btype(total);
            let out = diff(&[("%b", &bt)], &[&st, "Byte", &ct], ins, &raw, &format!("slice len={len} s={start} l={slen} i={idx}"));
            let valid = slen >= 1 && (start + slen) as usize <= len && (idx as usize) < len;
            match out {
                Outcome::Accept(v) => {
                    assert!(valid);
                    let s = &bs[start as usize..(start + slen) as usize];
                    assert_eq!(v[0], IrValue::Bytes(s.to_vec()));
                    assert_eq!(v[1], IrValue::Byte(bs[idx as usize]));
                }
                Outcome::Reject => assert!(!valid, "valid slice rejected len={len} s={start} l={slen} i={idx}"),
            }
            n += 1;
        }
    }
    // Concat edge cases: a Native operand, an immediate, no operands.
    let raw = bytes_raw(&[7, 8, 9]);
    for (label, inputs) in [
        ("native", json!(["%b", "%x"])),
        ("immediate", json!(["%b", "0x01"])),
        ("empty", json!([])),
    ] {
        let ins = vec![
            json!({"op": "concat", "inputs": inputs, "output": "%c"}),
            json!({"op": "output", "vals": []}),
        ];
        let mut raw2 = raw.clone();
        raw2.push(Fr::from(5u64));
        let out = diff(&[("%b", "Bytes<3>"), ("%x", "Scalar<BLS12-381>")], &[], ins, &raw2, label);
        assert_eq!(out, Outcome::Reject, "concat {label}");
    }
    eprintln!("slice/nth/concat: {n} cases agree");
}

#[test]
fn load_constant_agrees() {
    let p_minus_1 = Fr::from(0u64) - Fr::from(1u64);
    let cases: Vec<(&str, Vec<Fr>, bool)> = vec![
        ("Scalar<BLS12-381>", vec![p_minus_1], true),
        ("Bool", vec![Fr::from(1u64)], true),
        ("Bool", vec![Fr::from(2u64)], false),
        ("Byte", vec![Fr::from(255u64)], true),
        ("Byte", vec![Fr::from(256u64)], false),
        ("Bytes<32>", bytes_raw(&[0xab; 32]), true),
        ("Bytes<32>", vec![Fr::from(1u64), Fr::from(256u64)], false),
        ("Bytes<5>", vec![Fr::from(1u64) + Fr::from(1u64 << 40)], false),
        ("Bytes<40>", bytes_raw(&[3; 40]), true),
        ("Bytes<40>", vec![Fr::from(1u64)], false),
        ("Point<Jubjub>", vec![Fr::from(0u64), Fr::from(1u64)], true),
        ("Point<Jubjub>", vec![Fr::from(1u64), Fr::from(1u64)], false),
        ("Scalar<Secp256k1>", vec![Fr::from(1u64), Fr::from(0u64)], true),
    ];
    for (t, enc, valid) in cases {
        let ins = vec![
            json!({"op": "load_constant", "type": t, "encoding": enc.iter().map(|f| imm(*f)).collect::<Vec<_>>(), "output": "%k"}),
            json!({"op": "output", "vals": ["%k"]}),
        ];
        let out = diff(&[], &[t], ins, &[], &format!("load_constant {t} {enc:?}"));
        assert_eq!(matches!(out, Outcome::Accept(_)), valid, "load_constant {t} {enc:?}: {out:?}");
    }
}

#[test]
fn boolean_gates_agree() {
    let mut n = 0;
    for a in [0u64, 1] {
        for b in [0u64, 1] {
            for c in [0u64, 1] {
                for op in ["and", "or", "xor"] {
                    let ins = vec![
                        json!({"op": op, "inputs": ["%a", "%b", "%c"], "output": "%r"}),
                        json!({"op": op, "inputs": ["%a"], "output": "%r1"}),
                        json!({"op": "output", "vals": ["%r", "%r1"]}),
                    ];
                    let out = diff(
                        &[("%a", "Bool"), ("%b", "Bool"), ("%c", "Bool")],
                        &["Bool", "Bool"],
                        ins,
                        &[a.into(), b.into(), c.into()],
                        &format!("{op} {a}{b}{c}"),
                    );
                    let exp = match op {
                        "and" => a & b & c,
                        "or" => a | b | c,
                        _ => a ^ b ^ c,
                    } == 1;
                    assert_eq!(out, Outcome::Accept(vec![IrValue::Bool(exp), IrValue::Bool(a == 1)]));
                    n += 1;
                }
            }
        }
    }
    // Non-Bool operands (an immediate, a Native) and an empty list reject.
    for (label, inputs) in [("imm", json!(["%a", "0x01"])), ("native", json!(["%a", "%x"])), ("empty", json!([]))] {
        let ins = vec![json!({"op": "and", "inputs": inputs, "output": "%r"}), json!({"op": "output", "vals": []})];
        let out = diff(&[("%a", "Bool"), ("%x", "Scalar<BLS12-381>")], &[], ins, &[1u64.into(), 1u64.into()], label);
        assert_eq!(out, Outcome::Reject, "{label}");
    }
    // A Bool input decoded from 2 rejects (canonicity).
    let ins = vec![json!({"op": "output", "vals": []})];
    assert_eq!(diff(&[("%a", "Bool")], &[], ins, &[2u64.into()], "bool=2"), Outcome::Reject);
    eprintln!("boolean gates: {n} cases agree");
}

#[test]
fn sha512_agrees() {
    let align = json!([{ "tag": "atom", "value": { "tag": "field" } }, { "tag": "atom", "value": { "length": 40, "tag": "bytes" } }]);
    let mut rng = Rng(7);
    for _ in 0..4 {
        let bs = rng.bytes(40);
        let mut raw = vec![Fr::from(rng.next())];
        // FAB bytes<40>: stray (9) limb first, then 31-byte chunk (see fab_decode_to_bytes_atom).
        raw.push(limb_from(&bs[31..]));
        raw.push(limb_from(&bs[..31]));
        let ins = vec![
            json!({"op": "sha512", "alignment": align, "inputs": ["%x", "%l1", "%l2"], "output": "%h"}),
            json!({"op": "bytes_into_natives", "bytes": "%h", "outputs": ["%h0", "%h1", "%h2"]}),
            json!({"op": "output", "vals": ["%h", "%h2"]}),
        ];
        let out = diff(
            &[("%x", "Scalar<BLS12-381>"), ("%l1", "Scalar<BLS12-381>"), ("%l2", "Scalar<BLS12-381>")],
            &["Bytes<64>", "Scalar<BLS12-381>"],
            ins,
            &raw,
            "sha512",
        );
        assert!(matches!(out, Outcome::Accept(_)), "{out:?}");
    }
}

#[test]
fn to_from_bytes_agree() {
    // Native round-trip, foreign scalar, secp point (33 bytes), jubjub point (32 bytes),
    // from_bytes of non-32 lengths, and an immediate to_bytes.
    let sk: Vec<Fr> = encode_offcircuit(&IrValue::Secp256k1Scalar(k256::Fq::from(12345u64)))
        .into_iter()
        .map(|v| v.try_into().unwrap())
        .collect();
    let mut raw = vec![Fr::from(0xdead_beefu64), Fr::from(77u64)];
    raw.extend(sk.iter().copied());
    let ins = vec![
        json!({"op": "to_bytes", "input": "%x", "output": "%xb"}),
        json!({"op": "from_bytes", "type": "Scalar<BLS12-381>", "bytes": "%xb", "output": "%x2"}),
        json!({"op": "constrain_eq", "a": "%x", "b": "%x2"}),
        json!({"op": "to_bytes", "input": "0x05", "output": "%ib"}),
        json!({"op": "ec_mul_generator", "scalar": "%s", "output": "%P"}),
        json!({"op": "to_bytes", "input": "%P", "output": "%Pb"}),
        json!({"op": "bytes_into_natives", "bytes": "%Pb", "outputs": ["%p0", "%p1"]}),
        json!({"op": "jubjub_scalar_from_native", "native": "%y", "output": "%js"}),
        json!({"op": "ec_mul_generator", "scalar": "%js", "output": "%J"}),
        json!({"op": "to_bytes", "input": "%J", "output": "%Jb"}),
        json!({"op": "to_bytes", "input": "%s", "output": "%sb"}),
        json!({"op": "from_bytes", "type": "Scalar<Secp256k1>", "bytes": "%sb", "output": "%s2"}),
        json!({"op": "constrain_eq", "a": "%s", "b": "%s2"}),
        json!({"op": "slice", "bytes": "%Pb", "start": 0, "len": 7, "output": "%p7"}),
        json!({"op": "from_bytes", "type": "Scalar<BLS12-381>", "bytes": "%p7", "output": "%f7"}),
        json!({"op": "concat", "inputs": ["%Pb", "%Jb"], "output": "%PJ"}),
        json!({"op": "from_bytes", "type": "Scalar<BLS12-381>", "bytes": "%PJ", "output": "%f65"}),
        json!({"op": "from_bytes", "type": "Scalar<Secp256k1>", "bytes": "%PJ", "output": "%g65"}),
        json!({"op": "output", "vals": ["%xb", "%ib", "%Pb", "%Jb", "%sb", "%f7", "%f65", "%g65", "%p1"]}),
    ];
    let out = diff(
        &[("%x", "Scalar<BLS12-381>"), ("%y", "Scalar<BLS12-381>"), ("%s", "Scalar<Secp256k1>")],
        &["Bytes<32>", "Bytes<32>", "Bytes<33>", "Bytes<32>", "Bytes<32>", "Scalar<BLS12-381>", "Scalar<BLS12-381>", "Scalar<Secp256k1>", "Scalar<BLS12-381>"],
        ins,
        &raw,
        "to/from bytes",
    );
    assert!(matches!(out, Outcome::Accept(_)), "to/from bytes: {out:?}");
    // The deprecated fixed-size ops on a 33-byte point reject in both.
    let ins = vec![
        json!({"op": "ec_mul_generator", "scalar": "%s", "output": "%P"}),
        json!({"op": "into_bytes32", "input": "%P", "output": "%Pb"}),
        json!({"op": "output", "vals": []}),
    ];
    assert_eq!(diff(&[("%s", "Scalar<Secp256k1>")], &[], ins, &sk, "into_bytes32 point"), Outcome::Reject);
    // reverse_bytes (3.0 name) on a non-32 length.
    let ins = vec![
        json!({"op": "reverse_bytes", "bytes": "%b", "output": "%r"}),
        json!({"op": "output", "vals": ["%r"]}),
    ];
    let out = diff(&[("%b", "Bytes<5>")], &["Bytes<5>"], ins, &bytes_raw(&[1, 2, 3, 4, 5]), "reverse_bytes 5");
    assert_eq!(out, Outcome::Accept(vec![IrValue::Bytes(vec![5, 4, 3, 2, 1])]));
    // A guarded-off private Bytes(40) read yields zeros in both.
    let ins = vec![
        json!({"op": "private_input", "type": "Bytes<40>", "output": "%q", "guard": "0x00"}),
        json!({"op": "output", "vals": ["%q"]}),
    ];
    let out = diff(&[], &["Bytes<40>"], ins, &[], "guarded bytes40");
    assert_eq!(out, Outcome::Accept(vec![IrValue::Bytes(vec![0; 40])]));
    // Output type mismatch rejects in both.
    let ins = vec![json!({"op": "output", "vals": ["%b"]})];
    assert_eq!(diff(&[("%b", "Bytes<5>")], &["Bytes<6>"], ins, &bytes_raw(&[1, 2, 3, 4, 5]), "out mismatch"), Outcome::Reject);
}

/// The five deprecated ZKIR 3.0 byte instructions, which minocrab-sim still
/// runs for 3.0 artifacts: valid `Bytes(32)` round trips, and the limb
/// bounds `bytes32_from_low_high` refuses.
#[test]
fn deprecated_bytes32_instructions_agree() {
    let mut rng = Rng(0x0dd_ba11);
    for _ in 0..8 {
        let bs = rng.bytes(32);
        let lo = limb_from(&bs[..31]);
        let hi = Fr::from(u64::from(bs[31]));
        let ins = vec![
            json!({"op": "bytes32_from_low_high", "inputs": ["%lo", "%hi"], "output": "%b"}),
            json!({"op": "reverse_bytes", "bytes": "%b", "output": "%r"}),
            json!({"op": "bytes32_into_low_high", "bytes": "%r", "outputs": ["%l2", "%h2"]}),
            json!({"op": "from_bytes32", "type": "Scalar<BLS12-381>", "bytes": "%b", "output": "%f"}),
            json!({"op": "into_bytes32", "input": "%f", "output": "%fb"}),
            json!({"op": "output", "vals": ["%b", "%r", "%l2", "%h2", "%fb"]}),
        ];
        let out = diff(
            &[("%lo", "Scalar<BLS12-381>"), ("%hi", "Scalar<BLS12-381>")],
            &["Bytes<32>", "Bytes<32>", "Scalar<BLS12-381>", "Scalar<BLS12-381>", "Bytes<32>"],
            ins,
            &[lo, hi],
            "deprecated bytes32 round trip",
        );
        let Outcome::Accept(vals) = out else { panic!("valid Bytes<32> rejected") };
        assert_eq!(vals[0], IrValue::Bytes(bs.clone()));
        let mut rev = bs.clone();
        rev.reverse();
        assert_eq!(vals[1], IrValue::Bytes(rev));
    }
    // low >= 2^248 or high >= 256 is refused by both.
    let mut wide = vec![0u8; 31];
    wide.push(1);
    for (label, lo, hi) in [
        ("low over 31 bytes", limb_from(&wide), Fr::from(0u64)),
        ("high over a byte", Fr::from(1u64), Fr::from(256u64)),
    ] {
        let ins = vec![
            json!({"op": "bytes32_from_low_high", "inputs": ["%lo", "%hi"], "output": "%b"}),
            json!({"op": "output", "vals": []}),
        ];
        let out = diff(&[("%lo", "Scalar<BLS12-381>"), ("%hi", "Scalar<BLS12-381>")], &[], ins, &[lo, hi], label);
        assert_eq!(out, Outcome::Reject, "{label}");
    }
}

/// Shapes compactc never writes, refused by both: `bytes_into_natives` with
/// the wrong output count or a non-`Bytes` input, and `from_bytes32` of a
/// `Bytes` that is not 32 long.
#[test]
fn malformed_byte_instructions_reject() {
    let b40 = bytes_raw(&[9; 40]);
    let seven = [Fr::from(7u64)];
    let cases: Vec<(&str, (&str, &str), Value, &[Fr])> = vec![
        (
            "bytes_into_natives one output for 40 bytes",
            ("%b", "Bytes<40>"),
            json!({"op": "bytes_into_natives", "bytes": "%b", "outputs": ["%o0"]}),
            &b40,
        ),
        (
            "bytes_into_natives three outputs for 40 bytes",
            ("%b", "Bytes<40>"),
            json!({"op": "bytes_into_natives", "bytes": "%b", "outputs": ["%o0", "%o1", "%o2"]}),
            &b40,
        ),
        (
            "bytes_into_natives of a native",
            ("%b", "Scalar<BLS12-381>"),
            json!({"op": "bytes_into_natives", "bytes": "%b", "outputs": ["%o0"]}),
            &seven,
        ),
        (
            "from_bytes32 of 40 bytes",
            ("%b", "Bytes<40>"),
            json!({"op": "from_bytes32", "type": "Scalar<BLS12-381>", "bytes": "%b", "output": "%f"}),
            &b40,
        ),
    ];
    for (label, input, op, raw) in cases {
        let ins = vec![op, json!({"op": "output", "vals": []})];
        assert_eq!(diff(&[input], &[], ins, raw, label), Outcome::Reject, "{label}");
    }
}

/// More shapes compactc never writes, refused by both: `bytes_from_natives`
/// of length 0 (upstream's limb count refuses it; an empty value would
/// otherwise decode), and a zero-length slice no output type check masks.
#[test]
fn empty_byte_strings_reject() {
    let ins = vec![
        json!({"op": "bytes_from_natives", "inputs": [], "len": 0, "output": "%b"}),
        json!({"op": "output", "vals": []}),
    ];
    assert_eq!(diff(&[], &[], ins, &[], "bytes_from_natives len 0"), Outcome::Reject);
    let ins = vec![
        json!({"op": "slice", "bytes": "%b", "start": 0, "len": 0, "output": "%s"}),
        json!({"op": "output", "vals": []}),
    ];
    assert_eq!(diff(&[("%b", "Bytes<3>")], &[], ins, &bytes_raw(&[1, 2, 3]), "slice len 0"), Outcome::Reject);
}

/// `ec_mul_generator` on a secp256r1 scalar.
#[test]
fn secp256r1_generator_agrees() {
    let sk: Vec<Fr> = encode_offcircuit(&IrValue::Secp256r1Scalar(p256::Fq::from(12345u64)))
        .into_iter()
        .map(|v| v.try_into().unwrap())
        .collect();
    let ins = vec![
        json!({"op": "ec_mul_generator", "scalar": "%s", "output": "%P"}),
        json!({"op": "output", "vals": ["%P"]}),
    ];
    let out = diff(&[("%s", "Scalar<Secp256r1>")], &["Point<Secp256r1>"], ins, &sk, "secp256r1 generator");
    assert!(matches!(out, Outcome::Accept(_)), "{out:?}");
}

/// A point's `to_bytes` is 33 bytes, so splitting it costs what the model
/// says a `Bytes(33)` costs.
#[test]
fn point_to_bytes_split_estimate_matches_the_model() {
    use minocrab_sim::v3::{cost, rowcost::est_rows};
    let ins = vec![
        json!({"op": "to_bytes", "input": "%P", "output": "%Pb"}),
        json!({"op": "bytes_into_natives", "bytes": "%Pb", "outputs": ["%p0", "%p1"]}),
        json!({"op": "output", "vals": []}),
    ];
    let inputs = [("%P", "Point<Secp256k1>")];
    let est = est_rows(&ir(&inputs, &[], ins.clone(), false))[1];
    let with = cost(&ir(&inputs, &[], ins.clone(), false)).1;
    let without = cost(&ir(&inputs, &[], vec![ins[0].clone(), ins[2].clone()], false)).1;
    assert_eq!(est, with - without);
}

/// `rowcost`'s estimate for the limb conversions is the model's own row count.
#[test]
fn limb_conversion_estimates_match_the_model() {
    use minocrab_sim::v3::{cost, rowcost::est_rows};
    let rows = |inputs: &[(&str, &str)], ins: Vec<Value>| cost(&ir(inputs, &[], ins, false)).1;
    let done = json!({"op": "output", "vals": []});
    for len in [1usize, 2, 8, 30, 31, 32, 33, 62, 63, 64, 93, 94] {
        let names: Vec<String> = (0..len.div_ceil(31)).map(|i| format!("%l.{i}")).collect();
        let limbs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "Scalar<BLS12-381>")).collect();
        let from = json!({"op": "bytes_from_natives", "inputs": names, "len": len, "output": "%b"});
        let model = rows(&limbs, vec![from.clone(), done.clone()]) - rows(&limbs, vec![done.clone()]);
        assert_eq!(est_rows(&ir(&limbs, &[], vec![from, done.clone()], false))[0], model, "from len={len}");

        let bt = btype(len);
        let bytes = [("%b", bt.as_str())];
        let into = json!({"op": "bytes_into_natives", "bytes": "%b", "outputs": names});
        let model = rows(&bytes, vec![into.clone(), done.clone()]) - rows(&bytes, vec![done.clone()]);
        assert_eq!(est_rows(&ir(&bytes, &[], vec![into, done.clone()], false))[0], model, "into len={len}");
    }
}
