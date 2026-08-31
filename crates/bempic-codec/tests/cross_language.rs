use bempic_codec::{ExperimentalCodecV0, RepresentationCodec as _};
use bempic_model::{LogicalId, Message};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[test]
fn python_and_rust_vector_is_exact() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/experimental-v0/tiny-message.json");
    let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(vector["normative"], false);
    let value = &vector["message"];
    let logical: [u8; 16] = hex::decode(vector["logical_id_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let message = Message {
        logical_id: LogicalId(logical),
        created_at: value["created_at"].as_u64().unwrap(),
        sender: value["sender"].as_str().unwrap().into(),
        recipients: value["recipients"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap().into())
            .collect(),
        subject: value["subject"].as_str().map(Into::into),
        body: value["body"].as_str().unwrap().into(),
        attachments: Vec::new(),
    };
    let codec = ExperimentalCodecV0;
    let prepared = codec.prepare(&message).unwrap();
    assert_eq!(hex::encode(&prepared.bytes), vector["encoded_hex"]);
    assert_eq!(prepared.size(), vector["encoded_size"].as_u64().unwrap());
    assert_eq!(prepared.id.to_string(), vector["representation_id_hex"]);
    assert_eq!(prepared.digest.to_string(), vector["sha256_hex"]);
    assert_eq!(
        hex::encode(prepared.schema_fingerprint),
        vector["schema_fingerprint_hex"]
    );
    assert_eq!(codec.decode(&prepared.bytes).unwrap(), message);
}
