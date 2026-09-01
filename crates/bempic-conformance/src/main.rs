#![forbid(unsafe_code)]
//! Deterministic malformed-input and exact-size property runner.

use bempic_model::v01::{
    fingerprint_from_hex, PreparedRepresentation, OPAQUE_SCHEMA_FINGERPRINT_HEX,
    SPECIFICATION_COMMIT,
};
use bempic_sim::{
    v01::{
        run_until_complete, AuthorizedSource, ContactPlan, DeliveredDataMutation, EndpointRestart,
    },
    CarrierConfig,
};
use bempic_sync::v01::{
    collection_checkpoint, maximum_size_analysis, Capabilities, CodecPreference, Data, Failure,
    FailureCode, Operation, OperationKind, ProtocolGeneration, Record, RepresentationDataRequest,
    RepresentationSelection, Request, SecurityClass,
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

fn prepared_body(size: usize) -> PreparedRepresentation {
    PreparedRepresentation::prepare(
        (0_u8..=255).cycle().take(size).collect(),
        None,
        fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).expect("published fingerprint"),
        0xffff_0001,
        1,
        Vec::new(),
        None,
    )
    .expect("bounded deterministic body fixture")
}

fn contact_plan(
    representation: &PreparedRepresentation,
    byte_budget: u64,
    max_record_bytes: usize,
    restart_before: EndpointRestart,
) -> ContactPlan {
    ContactPlan {
        carrier: CarrierConfig {
            byte_budget,
            bandwidth_bps: 9_600,
            latency_ms: 20,
            disconnect_after_ms: None,
            max_record_bytes,
            carrier_overhead_bytes: 8,
            reliable: true,
        },
        restart_before,
        discard_receiver_state: false,
        source: AuthorizedSource {
            source_id: [0x21; 32],
            representation_id: representation.descriptor.representation_id,
        },
        data_mutation: DeliveredDataMutation::None,
        replay_data_records: 0,
    }
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

#[allow(clippy::too_many_lines)]
fn tranche_two_measurements() -> Result<serde_json::Value, Box<dyn Error>> {
    let representation = prepared_body(2_048);
    let integrated_root = tempfile::tempdir()?;
    let integrated_plans = [
        contact_plan(&representation, 700, 512, EndpointRestart::Neither),
        contact_plan(&representation, 700, 512, EndpointRestart::SenderOnly),
        contact_plan(&representation, 700, 512, EndpointRestart::ReceiverOnly),
        contact_plan(&representation, 700, 512, EndpointRestart::Both),
    ];
    let integrated = run_until_complete(
        integrated_root.path(),
        &representation,
        &integrated_plans,
        64,
    )?;

    let restart_representation = prepared_body(900);
    let mut partial = contact_plan(&restart_representation, 1_200, 2_048, EndpointRestart::Both);
    let mut finishing = contact_plan(&restart_representation, 5_000, 2_048, EndpointRestart::Both);
    let persistent_root = tempfile::tempdir()?;
    let persistent = run_until_complete(
        persistent_root.path(),
        &restart_representation,
        &[partial, finishing],
        8,
    )?;
    partial.discard_receiver_state = true;
    finishing.discard_receiver_state = true;
    let full_restart_root = tempfile::tempdir()?;
    let full_restart = run_until_complete(
        full_restart_root.path(),
        &restart_representation,
        &[partial, finishing],
        8,
    )?;

    let size_analyses = OperationKind::ALL
        .into_iter()
        .map(maximum_size_analysis)
        .collect::<Vec<_>>();
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
    let empty_summary = Record {
        operation: Operation::Summary(collection_checkpoint([0; 32], 0, &[])?),
        extensions: Vec::new(),
    };
    let capability_octets = capabilities.exact_encoded_size()?;
    let warm_no_change_octets = empty_summary.exact_encoded_size()?;
    let cold_no_change_octets = capability_octets * 2 + warm_no_change_octets;
    Ok(serde_json::json!({
        "schema": "bempic-reference-v0.1-conformance-tranche-2-measurements",
        "specification_commit": SPECIFICATION_COMMIT,
        "codec_status": "experimental-unregistered-disposable",
        "integrated_body_fixture": {
            "representation_octets": representation.descriptor.encoded_length,
            "contacts": integrated.contacts.len(),
            "bempic_octets": integrated.accounting.total_bempic_octets(),
            "sender_to_receiver_bempic_octets": integrated.accounting.sender_to_receiver_bempic_octets,
            "receiver_to_sender_bempic_octets": integrated.accounting.receiver_to_sender_bempic_octets,
            "carrier_octets": integrated.accounting.total_carrier_octets(),
            "sender_to_receiver_carrier_octets": integrated.accounting.carrier_sender_to_receiver_octets,
            "receiver_to_sender_carrier_octets": integrated.accounting.carrier_receiver_to_sender_octets,
            "protocol_overhead_octets": integrated.accounting.protocol_overhead_octets(),
            "representation_payload_submitted_octets": integrated.accounting.representation_payload_submitted_octets,
            "representation_payload_delivered_octets": integrated.accounting.representation_payload_delivered_octets,
            "useful_committed_octets": integrated.accounting.useful_committed_octets,
            "duplicate_payload_octets": integrated.accounting.duplicate_payload_octets,
            "bempic_octets_before_first_body_payload": integrated.accounting.bempic_octets_before_first_body_payload,
            "bempic_octets_through_first_body_payload": integrated.accounting.bempic_octets_through_first_body_payload,
            "carrier_octets_before_first_body_payload": integrated.accounting.carrier_octets_before_first_body_payload,
            "carrier_octets_through_first_body_payload": integrated.accounting.carrier_octets_through_first_body_payload,
            "first_body_payload_octets": integrated.accounting.first_body_payload_octets,
            "predicted_bempic_octets": integrated.accounting.predicted_bempic_octets,
            "quote_prediction_error_octets": integrated.accounting.quote_prediction_error_octets,
            "deterministic_size_checks": integrated.accounting.deterministic_size_checks,
            "operation_octets": integrated.accounting.operation_octets,
            "elapsed_ms": integrated.carrier.elapsed_ms,
            "sender_restarts": integrated.sender_restarts,
            "receiver_restarts": integrated.receiver_restarts,
            "exact_reconstruction": integrated.reconstructed == representation.bytes,
            "link_cost_precision": integrated.carrier.link_cost_precision,
            "carrier_cost_precision": integrated.carrier.carrier_cost_precision,
        },
        "restart_comparison": {
            "representation_octets": restart_representation.descriptor.encoded_length,
            "persistent_resume": {
                "contacts": persistent.contacts.len(),
                "bempic_octets": persistent.accounting.total_bempic_octets(),
                "carrier_octets": persistent.accounting.total_carrier_octets(),
                "payload_submitted_octets": persistent.accounting.representation_payload_submitted_octets,
                "protocol_overhead_octets": persistent.accounting.protocol_overhead_octets(),
            },
            "full_restart": {
                "contacts": full_restart.contacts.len(),
                "bempic_octets": full_restart.accounting.total_bempic_octets(),
                "carrier_octets": full_restart.accounting.total_carrier_octets(),
                "payload_submitted_octets": full_restart.accounting.representation_payload_submitted_octets,
                "protocol_overhead_octets": full_restart.accounting.protocol_overhead_octets(),
            },
            "persistent_resume_saves_payload_octets": full_restart.accounting.representation_payload_submitted_octets - persistent.accounting.representation_payload_submitted_octets,
            "persistent_resume_saves_carrier_octets": full_restart.accounting.total_carrier_octets() - persistent.accounting.total_carrier_octets(),
        },
        "no_change_transactions": {
            "capability_operation_octets": capability_octets,
            "warm_no_change_octets": warm_no_change_octets,
            "warm_gate_maximum_octets": 64,
            "warm_gate_pass": warm_no_change_octets <= 64,
            "cold_no_change_octets": cold_no_change_octets,
            "cold_gate_maximum_octets": 128,
            "cold_gate_pass": cold_no_change_octets <= 128,
        },
        "experimental_codec_maximum_size_proofs": size_analyses,
    }))
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
    if env::args().nth(1).as_deref() == Some("tranche2-measurements") {
        println!(
            "{}",
            serde_json::to_string_pretty(&tranche_two_measurements()?)?
        );
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
