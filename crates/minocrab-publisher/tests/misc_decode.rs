//! `decode_misc` against the encoders and against the compiled circuit.
//!
//! The encoders' layouts are pinned elsewhere (the construction gate and the
//! captured on-chain transactions in `minocrab-contracts`), so a decoder
//! that inverts them exactly reads what the singleton emits. The one input
//! here that no encoder of ours produced is the fixture's `responseEvent`:
//! the `respondBidirectional` emission of the COMPILED circuit (compactc
//! 0.33.0-rc.2, `@sig-net/midnight@0.25.0-rc.1`), with its fields beside it.

use minocrab_publisher::call::{
    decode_misc, respond_bidirectional_misc, respond_misc, sign_bidirectional_misc, Attestation,
    EcdsaSignature, Notification, SignerEvent,
};
use minocrab_publisher::hashing::OutputKind;
use minocrab_publisher::PublishError;
use signet_protocol::circuits::{
    RESPOND, RESPOND_BIDIRECTIONAL, RESPOND_BIDIRECTIONAL_EVENT, RESPOND_BIDIRECTIONAL_EVENT_NAME,
    SIGNATURE_RESPONDED_EVENT, SIGN_BIDIRECTIONAL,
};
use signet_protocol::misc::MISC_SIZE;

fn fill<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_mul(13) | 1;
    }
    out
}

fn signature() -> EcdsaSignature {
    EcdsaSignature { big_r_x: fill(0x11), big_r_y: fill(0x47), s: fill(0xa3), recovery_id: 1 }
}

fn attestation(request_id: &[u8; 32]) -> Attestation {
    Attestation::over(request_id, 0x0102_0304_0506_0708, OutputKind::Executed, &[0xab; 32]).unwrap()
}

#[test]
fn each_event_round_trips_through_its_encoder() {
    let request_id = fill::<32>(0x5a);
    let events = [
        SignerEvent::SignBidirectional {
            request_id,
            notification: Notification { version: 1, payload: fill(0x03) },
        },
        SignerEvent::SignatureResponded { request_id, signature: signature() },
        SignerEvent::RespondBidirectional {
            request_id,
            attestation: attestation(&request_id),
            signature: signature(),
        },
    ];
    for event in events {
        let misc = event.misc();
        assert_eq!(misc.len(), MISC_SIZE);
        let decoded = decode_misc(&misc).unwrap_or_else(|e| panic!("{}: {e}", event.circuit()));
        assert_eq!(decoded, event);
        assert_eq!(decoded.request_id(), &request_id);
    }
    // And the encoders by name, as the construction gate calls them.
    let notification = Notification { version: 1, payload: fill(0x03) };
    assert_eq!(
        decode_misc(&sign_bidirectional_misc(&request_id, &notification)).unwrap().circuit(),
        SIGN_BIDIRECTIONAL
    );
    assert_eq!(
        decode_misc(&respond_misc(SIGNATURE_RESPONDED_EVENT, &request_id, &signature())).unwrap().circuit(),
        RESPOND
    );
    assert_eq!(
        decode_misc(&respond_bidirectional_misc(
            RESPOND_BIDIRECTIONAL_EVENT,
            &request_id,
            &attestation(&request_id),
            &signature()
        ))
        .unwrap()
        .circuit(),
        RESPOND_BIDIRECTIONAL
    );
}

#[test]
fn the_compiled_circuits_emission_decodes_to_its_fields() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../signet-hashing/tests/fixtures/api-parity-vectors.json"
    ))
    .unwrap();
    let event = &fixture["responseEvent"];
    let text = |key: &str| event[key].as_str().unwrap().to_owned();
    let hex32 = |s: String| -> [u8; 32] { hex_decode(&s).try_into().unwrap() };

    // The fixture carries the 256 payload bytes; the envelope is the padded
    // name before them.
    let mut misc = RESPOND_BIDIRECTIONAL_EVENT_NAME.to_vec();
    misc.extend(hex_decode(&text("payload")));
    assert_eq!(misc.len(), MISC_SIZE);

    let SignerEvent::RespondBidirectional { request_id, attestation, signature } =
        decode_misc(&misc).unwrap()
    else {
        panic!("a RespondBidirectionalEvent")
    };
    assert_eq!(request_id, hex32(text("requestId")));
    assert_eq!(attestation.block_height, text("blockHeight").parse::<u64>().unwrap());
    assert_eq!(u64::from(attestation.output_kind), event["outputKind"].as_u64().unwrap());
    assert_eq!(
        attestation.serialized_output_length,
        text("serializedOutputLength").parse::<u64>().unwrap()
    );
    assert_eq!(attestation.output_hash, hex32(text("outputHash")));
    assert_eq!(attestation.digest, hex32(text("digest")));
    let sig = &event["signature"];
    assert_eq!(signature.big_r_x, hex32(sig["bigR"]["x"].as_str().unwrap().to_owned()));
    assert_eq!(signature.big_r_y, hex32(sig["bigR"]["y"].as_str().unwrap().to_owned()));
    assert_eq!(signature.s, hex32(sig["s"].as_str().unwrap().to_owned()));
    assert_eq!(u64::from(signature.recovery_id), sig["recoveryId"].as_u64().unwrap());

    // The digest the circuit emitted is the digest over the other fields.
    let typed = attestation.typed().expect("outputKind below 3");
    assert!(typed.digest_is_consistent(&request_id));
    // And re-encoding gives the circuit's bytes back.
    assert_eq!(
        respond_bidirectional_misc(RESPOND_BIDIRECTIONAL_EVENT, &request_id, &attestation, &signature),
        misc
    );
}

#[test]
fn anything_but_a_signer_envelope_is_refused() {
    let request_id = fill::<32>(0x5a);
    let misc = respond_misc(SIGNATURE_RESPONDED_EVENT, &request_id, &signature());

    // Wrong length.
    assert!(matches!(
        decode_misc(&misc[..MISC_SIZE - 1]),
        Err(PublishError::MiscSize { got: 287, want: MISC_SIZE })
    ));

    // A name of another spelling.
    let mut renamed = misc.clone();
    renamed[0] = b's';
    let err = decode_misc(&renamed).unwrap_err();
    assert!(matches!(err, PublishError::NotASignerEvent(_)), "{err}");

    // Another contract's Misc, same size.
    let mut foreign = vec![0u8; MISC_SIZE];
    foreign[..7].copy_from_slice(b"Deposit");
    assert!(matches!(decode_misc(&foreign), Err(PublishError::NotASignerEvent(_))));

    // Bytes where the layout has zeros: the first byte after respond's
    // recoveryId (offset 161) and the last byte of the envelope.
    for at in [161, MISC_SIZE - 1] {
        let mut dirty = misc.clone();
        dirty[at] = 0xff;
        let err = decode_misc(&dirty).unwrap_err();
        assert!(
            matches!(&err, PublishError::NotASignerEvent(m) if m.contains(&format!("byte {at} "))),
            "{err}"
        );
    }

    // And the same for the other two layouts' first padding byte.
    let notification = Notification { version: 1, payload: fill(0x03) };
    let mut sign = sign_bidirectional_misc(&request_id, &notification);
    sign[193] = 1;
    assert!(matches!(decode_misc(&sign), Err(PublishError::NotASignerEvent(_))));
    let mut bidir = respond_bidirectional_misc(
        RESPOND_BIDIRECTIONAL_EVENT,
        &request_id,
        &attestation(&request_id),
        &signature(),
    );
    bidir[242] = 1;
    assert!(matches!(decode_misc(&bidir), Err(PublishError::NotASignerEvent(_))));
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "even-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
