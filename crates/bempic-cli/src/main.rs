#![forbid(unsafe_code)]
//! Reference demonstration, inspection, and vector command-line interface.

use bempic_codec::{ExperimentalCodecV0, RepresentationCodec};
use bempic_model::{prepare_attachment, LogicalId, Message};
use bempic_sim::{run_until_complete, CarrierConfig};
use serde::Serialize;
use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct DemoReport {
    status: &'static str,
    architecture: &'static str,
    experimental_wire_format: bool,
    representation_id: String,
    schema_fingerprint: String,
    representation_bytes: u64,
    contacts: usize,
    simulated_reopens: usize,
    bempic_bytes: u64,
    carrier_bytes: u64,
    payload_bytes: u64,
    duplicate_payload_bytes: u64,
    useful_committed_bytes: u64,
    elapsed_ms: u64,
    lost_records_at_disconnect: u64,
    lost_bempic_bytes_at_disconnect: u64,
    exact_reconstruction: bool,
}

fn fixture_message() -> Result<Message, bempic_model::ModelError> {
    let (descriptor, _) = prepare_attachment(
        "route-weather.csv",
        "text/csv",
        b"UTC,wind_knots\n2026-08-30T20:00Z,12\n".repeat(24),
    )?;
    Ok(Message {
        logical_id: LogicalId::derive(b"bempic-reference-demo-message-1"),
        created_at: 1_788_112_800,
        sender: "shore@example.test".into(),
        recipients: vec!["sea-witch@example.test".into()],
        subject: Some("BEMPIC interrupted-link proof".into()),
        body: concat!(
            "This tiny message crosses constrained contact windows. ",
            "The receiver is reopened from disk and requests only the missing suffix."
        )
        .into(),
        attachments: vec![descriptor],
    })
}

fn contact(
    byte_budget: u64,
    bandwidth_bps: u64,
    latency_ms: u64,
    disconnect_after_ms: Option<u64>,
) -> CarrierConfig {
    CarrierConfig {
        byte_budget,
        bandwidth_bps,
        latency_ms,
        disconnect_after_ms,
        max_record_bytes: 128,
        carrier_overhead_bytes: 6,
        reliable: true,
    }
}

fn demo(state_dir: Option<&Path>) -> Result<(), Box<dyn Error>> {
    let codec = ExperimentalCodecV0;
    let message = fixture_message()?;
    let representation = codec.prepare(&message)?;
    let temporary = tempfile::tempdir()?;
    let root = state_dir.unwrap_or_else(|| temporary.path());
    let contacts = [
        contact(128, 300, 900, Some(2_800)),
        contact(172, 1_200, 350, None),
        contact(96, 600, 700, None),
        contact(220, 2_400, 120, None),
    ];
    let run = run_until_complete(root, &representation, &contacts, 100)?;
    let decoded = codec.decode(&run.reconstructed)?;
    let report = DemoReport {
        status: if decoded == message {
            "complete"
        } else {
            "decode-mismatch"
        },
        architecture: "OceanMail -> BEMPIC -> M4P -> DataLink",
        experimental_wire_format: true,
        representation_id: representation.id.to_string(),
        schema_fingerprint: hex::encode(representation.schema_fingerprint),
        representation_bytes: representation.size(),
        contacts: run.contacts.len(),
        simulated_reopens: run.contacts.len().saturating_sub(1),
        bempic_bytes: run.accounting.total_bempic_bytes(),
        carrier_bytes: run.carrier.carrier_bytes,
        payload_bytes: run.accounting.representation_payload_bytes,
        duplicate_payload_bytes: run.accounting.duplicate_payload_bytes,
        useful_committed_bytes: run.accounting.useful_committed_bytes,
        elapsed_ms: run.carrier.elapsed_ms,
        lost_records_at_disconnect: run.carrier.lost_records,
        lost_bempic_bytes_at_disconnect: run.carrier.lost_bempic_bytes,
        exact_reconstruction: run.reconstructed == representation.bytes,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn inspect(encoded_hex: &str) -> Result<(), Box<dyn Error>> {
    let bytes = hex::decode(encoded_hex)?;
    let message = ExperimentalCodecV0.decode(&bytes)?;
    println!("{}", serde_json::to_string_pretty(&message)?);
    Ok(())
}

fn vectors() -> Result<(), Box<dyn Error>> {
    let codec = ExperimentalCodecV0;
    let message = Message {
        logical_id: LogicalId::derive(b"cross-language-vector-tiny-v0"),
        created_at: 1_788_112_800,
        sender: "shore@example.test".into(),
        recipients: vec!["vessel@example.test".into()],
        subject: Some("Weather".into()),
        body: "Wind 12 kt — café".into(),
        attachments: vec![],
    };
    let prepared = codec.prepare(&message)?;
    let value = serde_json::json!({
        "schema": "bempic-experimental-cross-language-v0",
        "normative": false,
        "codec": codec.name(),
        "schema_fingerprint_hex": hex::encode(prepared.schema_fingerprint),
        "logical_id_hex": hex::encode(message.logical_id.0),
        "representation_id_hex": prepared.id.to_string(),
        "sha256_hex": prepared.digest.to_string(),
        "encoded_size": prepared.size(),
        "encoded_hex": hex::encode(&prepared.bytes),
        "message": message,
    });
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn usage() {
    eprintln!("usage: bempic-cli <demo [state-dir]|inspect <hex>|vectors>");
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("demo") => {
            let state_dir = args.next().map(PathBuf::from);
            demo(state_dir.as_deref())
        }
        Some("inspect") => {
            let encoded = args.next().ok_or("inspect requires encoded hex")?;
            inspect(&encoded)
        }
        Some("vectors") => vectors(),
        _ => {
            usage();
            Err("unknown or missing command".into())
        }
    }
}
