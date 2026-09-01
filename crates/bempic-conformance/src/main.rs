#![forbid(unsafe_code)]
//! Deterministic malformed-input and exact-size property runner.

use bempic_model::v01::{
    fingerprint_from_hex, PreparedRepresentation, OPAQUE_SCHEMA_FINGERPRINT_HEX,
    SPECIFICATION_COMMIT,
};
use bempic_sync::v01::{
    collection_checkpoint, Capabilities, CodecPreference, Data, Failure, FailureCode, Operation,
    ProtocolGeneration, Record, RepresentationDataRequest, RepresentationSelection, Request,
    SecurityClass,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

const TOOL_NAME: &str = "bempic-deterministic-malformed-runner";
const TOOL_VERSION: &str = "0.1.0";
const RANDOM_CASES: u64 = 50_000;

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    implementation_version: &'static str,
    specification_commit: &'static str,
    tool_name: &'static str,
    tool_version: &'static str,
    methodology: &'static str,
    deterministic_seed: u64,
    duration_ms: u128,
    random_cases: u64,
    structured_malformed_cases: u64,
    exact_size_property_cases: u64,
    seed_corpus_sha256: String,
    panics: u64,
    malformed_unexpected_accepts: u64,
    round_trip_failures: u64,
    unresolved_findings: u64,
}

fn prepared() -> PreparedRepresentation {
    PreparedRepresentation::prepare(
        b"conformance payload".to_vec(),
        None,
        fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).expect("published fingerprint"),
        0xffff_0001,
        1,
        Vec::new(),
        None,
    )
    .expect("bounded fixture")
}

fn seed_records() -> Vec<Record> {
    let representation = prepared();
    vec![
        Record {
            operation: Operation::Request(Request::RepresentationData(RepresentationDataRequest {
                budget_id: [0x42; 16],
                max_total_bempic_bytes: 4_096,
                max_sender_to_receiver_bytes: 3_900,
                max_receiver_to_sender_bytes: 196,
                selections: vec![RepresentationSelection {
                    representation_id: representation.descriptor.representation_id,
                    durable_prefix_offset: 0,
                    max_desired_payload_octets: representation.descriptor.encoded_length,
                }],
            })),
            extensions: Vec::new(),
        },
        Record {
            operation: Operation::Data(Data {
                representation_id: representation.descriptor.representation_id,
                offset: 0,
                payload: representation.bytes,
            }),
            extensions: Vec::new(),
        },
        Record {
            operation: Operation::Failure(Failure {
                code: FailureCode::MalformedOperation,
                scope: Vec::new(),
                retryable: false,
                detail: None,
            }),
            extensions: Vec::new(),
        },
    ]
}

fn next_random(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn run() -> Result<Report, Box<dyn Error>> {
    let started = Instant::now();
    let supported = BTreeSet::new();
    let seeds = seed_records()
        .into_iter()
        .map(|record| record.encode())
        .collect::<Result<Vec<_>, _>>()?;
    let mut corpus_hasher = Sha256::new();
    let mut structured_malformed_cases = 0_u64;
    let mut malformed_unexpected_accepts = 0_u64;
    let mut panics = 0_u64;

    for seed in &seeds {
        corpus_hasher.update((seed.len() as u64).to_be_bytes());
        corpus_hasher.update(seed);
        for length in 0..seed.len() {
            structured_malformed_cases += 1;
            let truncated = &seed[..length];
            let outcome = catch_unwind(AssertUnwindSafe(|| Record::decode(truncated, &supported)));
            match outcome {
                Ok(Ok(_)) => malformed_unexpected_accepts += 1,
                Ok(Err(_)) => {}
                Err(_) => panics += 1,
            }
        }
        let mut trailing = seed.clone();
        trailing.push(0);
        structured_malformed_cases += 1;
        match catch_unwind(AssertUnwindSafe(|| Record::decode(&trailing, &supported))) {
            Ok(Ok(_)) => malformed_unexpected_accepts += 1,
            Ok(Err(_)) => {}
            Err(_) => panics += 1,
        }
        let mut false_length = seed.clone();
        false_length[6] ^= 1;
        structured_malformed_cases += 1;
        match catch_unwind(AssertUnwindSafe(|| {
            Record::decode(&false_length, &supported)
        })) {
            Ok(Ok(_)) => malformed_unexpected_accepts += 1,
            Ok(Err(_)) => {}
            Err(_) => panics += 1,
        }
    }

    let deterministic_seed = 0x4245_4d50_4943_0001_u64;
    let mut random_state = deterministic_seed;
    for case in 0..RANDOM_CASES {
        let length = usize::try_from(next_random(&mut random_state) % 2_049)?;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            bytes.push(
                u8::try_from(next_random(&mut random_state) & 0xff)
                    .expect("masked random byte fits u8"),
            );
        }
        if case < 256 {
            corpus_hasher.update((bytes.len() as u64).to_be_bytes());
            corpus_hasher.update(&bytes);
        }
        if catch_unwind(AssertUnwindSafe(|| Record::decode(&bytes, &supported))).is_err() {
            panics += 1;
        }
    }

    let representation = prepared();
    let mut exact_size_property_cases = 0_u64;
    let mut round_trip_failures = 0_u64;
    for payload_length in (1..=4_096).chain([8_191, 16_383, 32_767, 65_535]) {
        let record = Record {
            operation: Operation::Data(Data {
                representation_id: representation.descriptor.representation_id,
                offset: 0,
                payload: vec![0xa5; payload_length],
            }),
            extensions: Vec::new(),
        };
        exact_size_property_cases += 1;
        let expected = record.exact_encoded_size()?;
        let bytes = record.encode()?;
        if bytes.len() != expected || Record::decode(&bytes, &supported)? != record {
            round_trip_failures += 1;
        }
    }

    let unresolved_findings = panics + malformed_unexpected_accepts + round_trip_failures;
    Ok(Report {
        schema: "bempic-conformance-fuzz-report-v0.1",
        implementation_version: env!("CARGO_PKG_VERSION"),
        specification_commit: SPECIFICATION_COMMIT,
        tool_name: TOOL_NAME,
        tool_version: TOOL_VERSION,
        methodology: "deterministic LCG arbitrary records; every strict truncation, trailing-byte, and false-envelope-length mutation of three valid seeds; exact-size/round-trip payload sweep",
        deterministic_seed,
        duration_ms: started.elapsed().as_millis(),
        random_cases: RANDOM_CASES,
        structured_malformed_cases,
        exact_size_property_cases,
        seed_corpus_sha256: hex::encode(corpus_hasher.finalize()),
        panics,
        malformed_unexpected_accepts,
        round_trip_failures,
        unresolved_findings,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    if env::args().nth(1).as_deref() == Some("vector") {
        let representation = prepared();
        let record = seed_records().remove(0);
        let encoded = record.encode()?;
        let value = serde_json::json!({
            "name": "representation-data-explicit-selection",
            "operation": "REQUEST",
            "request_variant": "REPRESENTATION_DATA",
            "budget_id_hex": hex::encode([0x42; 16]),
            "representation_id_hex": representation.descriptor.representation_id.to_string(),
            "durable_prefix_offset": "0",
            "max_desired_payload_octets": representation.descriptor.encoded_length.to_string(),
            "max_total_bempic_bytes": "4096",
            "max_sender_to_receiver_bytes": "3900",
            "max_receiver_to_sender_bytes": "196",
            "expected_encoded_hex": hex::encode(&encoded),
            "expected_encoded_length": encoded.len(),
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    if env::args().nth(1).as_deref() == Some("measurements") {
        let representation = prepared();
        let capabilities = Record {
            operation: Operation::Capabilities(Capabilities {
                protocol_generations: vec![ProtocolGeneration { major: 0, minor: 1 }],
                schema_fingerprints: vec![representation.descriptor.schema_fingerprint],
                codec_preferences: vec![CodecPreference {
                    codec_id: representation.descriptor.codec_id,
                    revision: representation.descriptor.codec_revision,
                    schema_fingerprint: representation.descriptor.schema_fingerprint,
                }],
                max_operation_octets: 1_048_576,
                max_data_payload_octets: 1_000_000,
                receipt_levels: 0b1111,
                security_class: SecurityClass::Public,
                extensions: Vec::new(),
            }),
            extensions: Vec::new(),
        };
        let summary = Record {
            operation: Operation::Summary(collection_checkpoint([0; 32], 0, &[])?),
            extensions: Vec::new(),
        };
        let capability_octets = capabilities.exact_encoded_size()?;
        let warm_no_change_octets = summary.exact_encoded_size()?;
        let cold_no_change_octets = capability_octets * 2 + warm_no_change_octets;
        let value = serde_json::json!({
            "schema": "bempic-v01-acceptance-measurements",
            "specification_commit": SPECIFICATION_COMMIT,
            "codec_status": "experimental-unregistered",
            "capability_operation_octets": capability_octets,
            "warm_no_change_octets": warm_no_change_octets,
            "warm_gate_maximum_octets": 64,
            "warm_gate_pass": warm_no_change_octets <= 64,
            "cold_no_change_octets": cold_no_change_octets,
            "cold_gate_maximum_octets": 128,
            "cold_gate_pass": cold_no_change_octets <= 128,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let report = run()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.unresolved_findings > 0 {
        Err("unresolved malformed-input or property finding".into())
    } else {
        Ok(())
    }
}
