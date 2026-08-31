#![forbid(unsafe_code)]
//! Deterministic synthetic-corpus byte and elapsed-time benchmark runner.

use bempic_codec::{ExperimentalCodecV0, RepresentationCodec};
use bempic_model::{prepare_attachment, LogicalId, Message, PreparedRepresentation};
use bempic_sim::{run_until_complete, CarrierConfig};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::error::Error;

struct Fixture {
    name: &'static str,
    message: Message,
    attachments: Vec<PreparedRepresentation>,
}

#[derive(Serialize)]
struct FixtureResult {
    name: &'static str,
    manifest_representation_bytes: u64,
    attachment_representation_bytes: u64,
    metadata_attachment_payload_bytes: u64,
    selected_attachment_payload_bytes: u64,
    full_exchange_bytes: u64,
    carrier_bytes: u64,
    contacts: usize,
    elapsed_ms: u64,
    duplicate_payload_bytes: u64,
    exact_reconstruction: bool,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    version: &'static str,
    normative_wire_format: bool,
    fixture_count: usize,
    total_representation_bytes: u64,
    total_bempic_bytes: u64,
    total_carrier_bytes: u64,
    total_elapsed_ms: u64,
    fixtures: Vec<FixtureResult>,
}

fn noise(size: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(size);
    for counter in 0_u64.. {
        output.extend_from_slice(&Sha256::digest(format!("noise:{counter}").as_bytes()));
        if output.len() >= size {
            output.truncate(size);
            return output;
        }
    }
    unreachable!("unbounded counter")
}

fn fixture(
    name: &'static str,
    subject: &str,
    body: String,
    attachment_specs: Vec<(&str, &str, Vec<u8>)>,
) -> Result<Fixture, bempic_model::ModelError> {
    let mut descriptors = Vec::new();
    let mut attachments = Vec::new();
    for (filename, media_type, content) in attachment_specs {
        let (descriptor, representation) = prepare_attachment(filename, media_type, content)?;
        descriptors.push(descriptor);
        attachments.push(representation);
    }
    Ok(Fixture {
        name,
        message: Message {
            logical_id: LogicalId::derive(format!("bempic-fixture:{name}").as_bytes()),
            created_at: 1_788_112_800,
            sender: "shore@example.test".into(),
            recipients: vec!["vessel@example.test".into()],
            subject: Some(subject.into()),
            body,
            attachments: descriptors,
        },
        attachments,
    })
}

fn fixtures() -> Result<Vec<Fixture>, bempic_model::ModelError> {
    Ok(vec![
        fixture(
            "tiny_plain",
            "Watch change",
            "Please take the 2000 UTC watch.".into(),
            vec![],
        )?,
        fixture(
            "typical_plain",
            "Arrival update",
            "Forecast and arrival notes. ".repeat(48),
            vec![],
        )?,
        fixture(
            "international_text",
            "Météo — Καλημέρα",
            "Café winds: 北東 12 kt. ".repeat(28),
            vec![],
        )?,
        fixture(
            "reply_chain",
            "Re: Watch schedule",
            "> Previous watch schedule\nThanks, confirmed.\n".repeat(20),
            vec![],
        )?,
        fixture(
            "compressible_attachment",
            "Optional route table",
            "Fetch the route table only if needed.".into(),
            vec![(
                "route.csv",
                "text/csv",
                b"utc,wind\n2026-08-30,12\n".repeat(400),
            )],
        )?,
        fixture(
            "already_compressed_attachment",
            "Optional sensor archive",
            "Fetch the sensor archive only if needed.".into(),
            vec![("sensor.bin", "application/octet-stream", noise(10_240))],
        )?,
    ])
}

fn config() -> CarrierConfig {
    CarrierConfig {
        byte_budget: 65_535,
        bandwidth_bps: 9_600,
        latency_ms: 250,
        disconnect_after_ms: None,
        max_record_bytes: 4_096,
        carrier_overhead_bytes: 8,
        reliable: true,
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let codec = ExperimentalCodecV0;
    let root = tempfile::tempdir()?;
    let mut results = Vec::new();
    let mut total_representation_bytes = 0;
    let mut total_bempic_bytes = 0;
    let mut total_carrier_bytes = 0;
    let mut total_elapsed_ms = 0;
    for fixture in fixtures()? {
        let manifest = codec.prepare(&fixture.message)?;
        let fixture_root = root.path().join(fixture.name);
        let manifest_run = run_until_complete(&fixture_root, &manifest, &[config()], 100)?;
        let decoded = codec.decode(&manifest_run.reconstructed)?;
        let metadata_attachment_payload_bytes = 0;
        let mut selected_attachment_payload_bytes = 0;
        let mut full_exchange_bytes = manifest_run.accounting.total_bempic_bytes();
        let mut carrier_bytes = manifest_run.carrier.carrier_bytes;
        let mut contacts = manifest_run.contacts.len();
        let mut elapsed_ms = manifest_run.carrier.elapsed_ms;
        let mut duplicate_payload_bytes = manifest_run.accounting.duplicate_payload_bytes;
        let mut exact_reconstruction = decoded == fixture.message;
        for attachment in &fixture.attachments {
            let run = run_until_complete(&fixture_root, attachment, &[config()], 100)?;
            selected_attachment_payload_bytes += run.accounting.representation_payload_bytes;
            full_exchange_bytes += run.accounting.total_bempic_bytes();
            carrier_bytes += run.carrier.carrier_bytes;
            contacts += run.contacts.len();
            elapsed_ms += run.carrier.elapsed_ms;
            duplicate_payload_bytes += run.accounting.duplicate_payload_bytes;
            exact_reconstruction &= run.reconstructed == attachment.bytes;
        }
        let attachment_representation_bytes = fixture
            .attachments
            .iter()
            .map(PreparedRepresentation::size)
            .sum::<u64>();
        let representation_bytes = manifest.size() + attachment_representation_bytes;
        total_representation_bytes += representation_bytes;
        total_bempic_bytes += full_exchange_bytes;
        total_carrier_bytes += carrier_bytes;
        total_elapsed_ms += elapsed_ms;
        results.push(FixtureResult {
            name: fixture.name,
            manifest_representation_bytes: manifest.size(),
            attachment_representation_bytes,
            metadata_attachment_payload_bytes,
            selected_attachment_payload_bytes,
            full_exchange_bytes,
            carrier_bytes,
            contacts,
            elapsed_ms,
            duplicate_payload_bytes,
            exact_reconstruction,
        });
    }
    let report = Report {
        schema: "bempic-reference-benchmark-v0",
        version: env!("CARGO_PKG_VERSION"),
        normative_wire_format: false,
        fixture_count: results.len(),
        total_representation_bytes,
        total_bempic_bytes,
        total_carrier_bytes,
        total_elapsed_ms,
        fixtures: results,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
