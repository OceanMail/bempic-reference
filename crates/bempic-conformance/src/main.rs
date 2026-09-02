#![forbid(unsafe_code)]
//! Deterministic malformed-input and exact-size property runner.

mod tranche3;

use bempic_model::v01::{
    fingerprint_from_hex, ContentDigest, MessageManifest, ObjectId, PartDescriptor, PartRole,
    PreparedRepresentation, RepresentationDescriptor, RepresentationId, MAX_OPERATION_OCTETS,
    MAX_REPRESENTATION_OCTETS, MESSAGE_SCHEMA_FINGERPRINT_HEX, OPAQUE_SCHEMA_FINGERPRINT_HEX,
    SPECIFICATION_COMMIT,
};
use bempic_sim::{
    v01::{
        run_until_complete, AuthorizedSource, ContactPlan, DeliveredDataMutation, EndpointRestart,
    },
    CarrierConfig,
};
use bempic_sync::v01::{
    collection_checkpoint, maximum_size_analysis, Capabilities, CodecPreference, CollectionEntry,
    Cursor, Data, Extension, ExtensionDeclaration, Failure, FailureCode, Offer, OfferMode,
    Operation, OperationKind, ProtocolGeneration, Receipt, ReceiptStatus, Record,
    RepresentationDataRequest, RepresentationSelection, Request, SecurityClass, Summary,
};
use bempic_sync::v01_compact::{
    self as compact, Context as CompactContext, EXPERIMENTAL_CODEC_ID, EXPERIMENTAL_CODEC_REVISION,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Instant;

const TOOL_NAME: &str = "bempic-deterministic-malformed-runner";
const TOOL_VERSION: &str = "0.1.0";
const RANDOM_CASES: u64 = 50_000;
const COMPACT_SPECIFICATION_COMMIT: &str = "7d29453c87b6f08f1abf6214c4ca64dd82030e99";
const COMPACT_PROFILE_SHA256: &str =
    "bc82364f7ac2f563bbdc0ea15f3d9b1f9127d6ac88376bf19a6dc642dc731127";
const COMPACT_ARTIFACT_PATH: &str =
    "benchmarks/results/compact-codec-public-evidence-2026-09-02.json";
const COMPACT_VECTOR_PATH: &str = "test-vectors/v0.1-public-experimental-codec/vectors.json";

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
    compact_structured_malformed_cases: u64,
    exact_size_property_cases: u64,
    compact_exact_size_property_cases: u64,
    seed_corpus_sha256: String,
    panics: u64,
    malformed_unexpected_accepts: u64,
    round_trip_failures: u64,
    compact_round_trip_failures: u64,
    unresolved_findings: u64,
}

fn prepared() -> PreparedRepresentation {
    PreparedRepresentation::prepare(
        b"conformance payload".to_vec(),
        None,
        fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).expect("published fingerprint"),
        EXPERIMENTAL_CODEC_ID,
        EXPERIMENTAL_CODEC_REVISION,
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
        EXPERIMENTAL_CODEC_ID,
        EXPERIMENTAL_CODEC_REVISION,
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

#[allow(clippy::too_many_lines)]
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
    let mut compact_structured_malformed_cases = 0_u64;
    let mut compact_malformed_unexpected_accepts = 0_u64;
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

    let compact_seeds = seed_records()
        .into_iter()
        .map(|record| compact::encode(&record, CompactContext::default()))
        .collect::<Result<Vec<_>, _>>()?;
    for seed in &compact_seeds {
        corpus_hasher.update((seed.len() as u64).to_be_bytes());
        corpus_hasher.update(seed);
        for length in 0..seed.len() {
            compact_structured_malformed_cases += 1;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                compact::decode(&seed[..length], &supported, CompactContext::default())
            }));
            match outcome {
                Ok(Ok(_)) => compact_malformed_unexpected_accepts += 1,
                Ok(Err(_)) => {}
                Err(_) => panics += 1,
            }
        }
        let mut trailing = seed.clone();
        trailing.push(0);
        compact_structured_malformed_cases += 1;
        match catch_unwind(AssertUnwindSafe(|| {
            compact::decode(&trailing, &supported, CompactContext::default())
        })) {
            Ok(Ok(_)) => compact_malformed_unexpected_accepts += 1,
            Ok(Err(_)) => {}
            Err(_) => panics += 1,
        }
        let mut false_length = seed.clone();
        false_length[1] ^= 1;
        compact_structured_malformed_cases += 1;
        match catch_unwind(AssertUnwindSafe(|| {
            compact::decode(&false_length, &supported, CompactContext::default())
        })) {
            Ok(Ok(_)) => compact_malformed_unexpected_accepts += 1,
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
        if catch_unwind(AssertUnwindSafe(|| {
            compact::decode(&bytes, &supported, CompactContext::default())
        }))
        .is_err()
        {
            panics += 1;
        }
    }

    let representation = prepared();
    let mut exact_size_property_cases = 0_u64;
    let mut round_trip_failures = 0_u64;
    let mut compact_exact_size_property_cases = 0_u64;
    let mut compact_round_trip_failures = 0_u64;
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
        compact_exact_size_property_cases += 1;
        let compact_expected = compact::exact_encoded_size(&record, CompactContext::default())?;
        let compact_bytes = compact::encode(&record, CompactContext::default())?;
        if compact_bytes.len() != compact_expected
            || compact::decode(&compact_bytes, &supported, CompactContext::default())? != record
        {
            compact_round_trip_failures += 1;
        }
    }

    let unresolved_findings = panics
        + malformed_unexpected_accepts
        + compact_malformed_unexpected_accepts
        + round_trip_failures
        + compact_round_trip_failures;
    Ok(Report {
        schema: "bempic-conformance-fuzz-report-v0.1",
        implementation_version: env!("CARGO_PKG_VERSION"),
        specification_commit: SPECIFICATION_COMMIT,
        tool_name: TOOL_NAME,
        tool_version: TOOL_VERSION,
        methodology: "deterministic LCG arbitrary records against B1 and public experimental compact codec; every strict truncation, trailing-byte, and false-envelope-length mutation of three valid seeds per codec; exact-size/round-trip payload sweep for both codecs",
        deterministic_seed,
        duration_ms: started.elapsed().as_millis(),
        random_cases: RANDOM_CASES,
        structured_malformed_cases,
        compact_structured_malformed_cases,
        exact_size_property_cases,
        compact_exact_size_property_cases,
        seed_corpus_sha256: hex::encode(corpus_hasher.finalize()),
        panics,
        malformed_unexpected_accepts,
        round_trip_failures,
        compact_round_trip_failures,
        unresolved_findings,
    })
}

fn prescribed_v01_summary() -> Result<Summary, Box<dyn Error>> {
    const CREATED_AT_2026_01_01: u64 = 1_767_225_600;
    let mut entries = Vec::with_capacity(100);
    for index in 0_u32..100 {
        let mut object_hasher = Sha256::new();
        object_hasher.update(b"BEMPIC-V01-OBJECT\0");
        object_hasher.update(index.to_be_bytes());
        let object_id = ObjectId(object_hasher.finalize().into());
        let body = format!("message-{index:03}\n").into_bytes();
        let prepared = PreparedRepresentation::prepare(
            body,
            None,
            compact::PROFILE_SCHEMA_FINGERPRINT,
            EXPERIMENTAL_CODEC_ID,
            EXPERIMENTAL_CODEC_REVISION,
            Vec::new(),
            None,
        )?;
        let manifest = MessageManifest {
            object_id,
            created_at: CREATED_AT_2026_01_01 + u64::from(index),
            sender: "sender@example.test".into(),
            recipients: vec!["recipient@example.test".into()],
            subject: Some(format!("Message {index:03}")),
            parts: vec![PartDescriptor {
                part_id: 0,
                role: PartRole::Body,
                media_type: "text/plain".into(),
                filename: None,
                representations: vec![prepared.descriptor.clone()],
            }],
        };
        manifest.validate()?;
        entries.push(CollectionEntry {
            sequence: u64::from(index) + 1,
            object_id,
            part_id: 0,
            descriptor: prepared.descriptor,
        });
    }
    let collection_id: [u8; 32] = Sha256::digest(b"BEMPIC-V01-COLLECTION\0").into();
    Ok(collection_checkpoint(collection_id, 100, &entries)?)
}

fn maximum_record_extensions() -> Vec<Extension> {
    (0_u32..32)
        .map(|id| Extension {
            id,
            critical: false,
            value: vec![0xa5; 1_024],
        })
        .collect()
}

fn maximum_offer_entries() -> Vec<CollectionEntry> {
    (0_u8..128)
        .map(|index| CollectionEntry {
            sequence: u64::from(index) + 1,
            object_id: ObjectId([index; 32]),
            part_id: u32::from(index),
            descriptor: RepresentationDescriptor {
                representation_id: RepresentationId([index.wrapping_add(128); 32]),
                schema_fingerprint: compact::PROFILE_SCHEMA_FINGERPRINT,
                codec_id: EXPERIMENTAL_CODEC_ID,
                codec_revision: EXPERIMENTAL_CODEC_REVISION,
                codec_parameters: Vec::new(),
                encoded_length: MAX_REPRESENTATION_OCTETS,
                decoded_length: Some(MAX_REPRESENTATION_OCTETS),
                content_digest: ContentDigest([index; 32]),
                usefulness_expiry: Some(u64::MAX),
            },
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn maximum_witness_records() -> Vec<(OperationKind, Record)> {
    let extensions = maximum_record_extensions();
    let schemas = vec![compact::PROFILE_SCHEMA_FINGERPRINT];
    let capabilities = Record {
        operation: Operation::Capabilities(Capabilities {
            protocol_generations: (0_u16..8)
                .map(|major| ProtocolGeneration {
                    major,
                    minor: u16::MAX,
                })
                .collect(),
            schema_fingerprints: schemas.clone(),
            codec_preferences: schemas
                .iter()
                .map(|schema_fingerprint| CodecPreference {
                    codec_id: EXPERIMENTAL_CODEC_ID,
                    revision: EXPERIMENTAL_CODEC_REVISION,
                    schema_fingerprint: *schema_fingerprint,
                })
                .collect(),
            max_operation_octets: u32::try_from(MAX_OPERATION_OCTETS)
                .expect("core operation maximum fits u32"),
            max_data_payload_octets: MAX_REPRESENTATION_OCTETS,
            receipt_levels: u8::MAX,
            security_class: SecurityClass::Confidential,
            extensions: (0_u32..32)
                .map(|id| ExtensionDeclaration {
                    id,
                    critical: id % 2 == 0,
                })
                .collect(),
        }),
        extensions: extensions.clone(),
    };
    let summary = Record {
        operation: Operation::Summary(Summary {
            collection_id: [0xff; 32],
            generation: u64::MAX,
            item_count: 1_000_000,
            collection_digest: [0xff; 32],
        }),
        extensions: extensions.clone(),
    };
    let offer_entries = maximum_offer_entries();
    let offer = Record {
        operation: Operation::Offer(Offer {
            collection_id: [0xff; 32],
            mode: OfferMode::Full,
            base_generation: 0,
            target_generation: 128,
            first_cursor: Cursor::Full(offer_entries[0].key()),
            last_cursor: Cursor::Full(offer_entries[127].key()),
            descriptors: offer_entries,
            more: true,
        }),
        extensions: extensions.clone(),
    };
    let request = Record {
        operation: Operation::Request(Request::RepresentationData(RepresentationDataRequest {
            budget_id: [0xff; 16],
            max_total_bempic_bytes: u64::MAX,
            max_sender_to_receiver_bytes: u64::MAX,
            max_receiver_to_sender_bytes: u64::MAX,
            selections: (0_u8..128)
                .map(|index| RepresentationSelection {
                    representation_id: RepresentationId([index; 32]),
                    durable_prefix_offset: MAX_REPRESENTATION_OCTETS,
                    max_desired_payload_octets: MAX_REPRESENTATION_OCTETS,
                })
                .collect(),
        })),
        extensions: extensions.clone(),
    };
    let legacy_data_maximum = maximum_size_analysis(OperationKind::Data);
    let data_payload_octets = legacy_data_maximum.maximum_encoded_octets
        - legacy_data_maximum.envelope_octets
        - legacy_data_maximum.record_extension_octets
        - (32 + 8 + 4);
    let data = Record {
        operation: Operation::Data(Data {
            representation_id: RepresentationId([0xff; 32]),
            offset: 0,
            payload: vec![0xa5; data_payload_octets],
        }),
        extensions: extensions.clone(),
    };
    let receipt = Record {
        operation: Operation::Receipt(Receipt {
            subject_id: [0xff; 32],
            status: ReceiptStatus::RepresentationCommitted,
            verified_digest: Some(ContentDigest([0xff; 32])),
            idempotency_id: [0xff; 16],
            reason: Some("x".repeat(256)),
        }),
        extensions: extensions.clone(),
    };
    let failure = Record {
        operation: Operation::Failure(Failure {
            code: FailureCode::LimitExceeded,
            scope: vec![0xff; 64],
            retryable: true,
            detail: Some("x".repeat(256)),
        }),
        extensions,
    };
    vec![
        (OperationKind::Capabilities, capabilities),
        (OperationKind::Summary, summary),
        (OperationKind::Offer, offer),
        (OperationKind::Request, request),
        (OperationKind::Data, data),
        (OperationKind::Receipt, receipt),
        (OperationKind::Failure, failure),
    ]
}

#[allow(clippy::too_many_lines)]
fn compact_codec_evidence() -> Result<serde_json::Value, Box<dyn Error>> {
    let summary = prescribed_v01_summary()?;
    let capabilities = Record {
        operation: Operation::Capabilities(compact::profile_capabilities()),
        extensions: Vec::new(),
    };
    let summary_record = Record {
        operation: Operation::Summary(summary),
        extensions: Vec::new(),
    };
    let warm_context = CompactContext {
        cached_summary: Some(&summary),
    };
    let legacy_capabilities = capabilities.encode()?;
    let legacy_summary = summary_record.encode()?;
    let compact_capabilities = compact::encode(&capabilities, CompactContext::default())?;
    let compact_cold_summary = compact::encode(&summary_record, CompactContext::default())?;
    let compact_warm_summary = compact::encode(&summary_record, warm_context)?;
    if compact::decode(&compact_warm_summary, &BTreeSet::new(), warm_context)? != summary_record {
        return Err("compact cached summary did not round trip".into());
    }
    let mut corrupted_warm_summary = compact_warm_summary.clone();
    let final_octet = corrupted_warm_summary
        .last_mut()
        .ok_or("compact cached summary was empty")?;
    *final_octet ^= 1;
    if compact::decode(&corrupted_warm_summary, &BTreeSet::new(), warm_context).is_ok() {
        return Err("compact cached summary accepted a mismatched binding".into());
    }
    let supported_extensions = (0_u32..32).collect::<BTreeSet<_>>();
    let mut witnesses = Vec::new();
    for (kind, record) in maximum_witness_records() {
        let analysis = compact::maximum_size_analysis(kind);
        let exact = compact::exact_encoded_size(&record, CompactContext::default())?;
        let encoded = compact::encode(&record, CompactContext::default())?;
        if exact != encoded.len()
            || exact != analysis.maximum_encoded_octets
            || compact::decode(&encoded, &supported_extensions, CompactContext::default())?
                != record
        {
            return Err(format!("compact maximum witness failed for {}", kind.name()).into());
        }
        witnesses.push(serde_json::json!({
            "kind": kind.name(),
            "analysis": analysis,
            "encoded_length": encoded.len(),
            "sha256": hex::encode(Sha256::digest(&encoded)),
            "legacy_encoded_length": record.exact_encoded_size()?,
        }));
    }
    let warm = compact_warm_summary.len();
    let cold = compact_capabilities.len() * 2 + compact_cold_summary.len();
    Ok(serde_json::json!({
        "schema": "bempic-reference-v0.1-compact-codec-evidence",
        "specification_commit": COMPACT_SPECIFICATION_COMMIT,
        "codec": {
            "id": EXPERIMENTAL_CODEC_ID,
            "revision": EXPERIMENTAL_CODEC_REVISION,
            "status": "public-experimental-not-approved-not-mandatory",
            "registry_allocation": "experimental",
            "approved": false,
            "mandatory": false,
            "stable_wire_promise": false,
            "production_security_promise": false,
            "canonical_parameters_hex": "",
            "profile": "docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md",
            "normative_profile_sha256": COMPACT_PROFILE_SHA256,
        },
        "prescribed_v01_fixture": {
            "messages": 100,
            "collection_id": hex::encode(summary.collection_id),
            "generation": summary.generation,
            "item_count": summary.item_count,
            "collection_digest": hex::encode(summary.collection_digest),
            "object_id_rule": "SHA-256(BEMPIC-V01-OBJECT\\0 || U32(index))",
            "first_index": 0,
            "last_index": 99,
            "collection_entry_semantics": "opaque-body-surrogate-not-canonical-manifest-representation",
            "mandatory_vector_status": "blocked-no-normative-manifest-instance-encoding",
        },
        "before_b1": {
            "capability_operation_octets": legacy_capabilities.len(),
            "warm_no_change_octets": legacy_summary.len(),
            "cold_no_change_octets": legacy_capabilities.len() * 2 + legacy_summary.len(),
            "capabilities_hex": hex::encode(&legacy_capabilities),
            "summary_hex": hex::encode(&legacy_summary),
            "capabilities_segments": [
                {"range": "0..2", "octets": 2, "field": "B1 magic"},
                {"range": "2..3", "octets": 1, "field": "CAPABILITIES tag"},
                {"range": "3..7", "octets": 4, "field": "payload length"},
                {"range": "7..12", "octets": 5, "field": "one protocol count and U16/U16 tuple"},
                {"range": "12..45", "octets": 33, "field": "one schema count and full 32-octet fingerprint"},
                {"range": "45..86", "octets": 41, "field": "one codec count, U32 ID, U32 revision, repeated full fingerprint"},
                {"range": "86..100", "octets": 14, "field": "operation/data maxima, receipt levels, security class"},
                {"range": "100..102", "octets": 2, "field": "empty capability-extension and record-extension counts"}
            ],
            "summary_segments": [
                {"range": "0..2", "octets": 2, "field": "B1 magic"},
                {"range": "2..3", "octets": 1, "field": "SUMMARY tag"},
                {"range": "3..7", "octets": 4, "field": "payload length"},
                {"range": "7..39", "octets": 32, "field": "full collection ID"},
                {"range": "39..47", "octets": 8, "field": "U64 generation"},
                {"range": "47..55", "octets": 8, "field": "U64 item count"},
                {"range": "55..87", "octets": 32, "field": "full collection digest"},
                {"range": "87..88", "octets": 1, "field": "empty record-extension count"}
            ]
        },
        "after_public_experimental_codec": {
            "capability_operation_octets": compact_capabilities.len(),
            "warm_no_change_octets": warm,
            "warm_gate_maximum_octets": 64,
            "warm_gate_pass": warm <= 64,
            "cold_full_summary_octets": compact_cold_summary.len(),
            "cold_no_change_octets": cold,
            "cold_gate_maximum_octets": 128,
            "cold_gate_pass": cold <= 128,
            "capabilities_hex": hex::encode(&compact_capabilities),
            "warm_summary_hex": hex::encode(&compact_warm_summary),
            "cold_summary_hex": hex::encode(&compact_cold_summary),
            "capabilities_segments": [
                {"range": "0..1", "octets": 1, "field": "experimental codec marker and CAPABILITIES tag"},
                {"range": "1..2", "octets": 1, "field": "canonical body length"},
                {"range": "2..3", "octets": 1, "field": "exact static profile alias"}
            ],
            "warm_summary_segments": [
                {"range": "0..1", "octets": 1, "field": "experimental codec marker and SUMMARY tag"},
                {"range": "1..2", "octets": 1, "field": "canonical body length"},
                {"range": "2..3", "octets": 1, "field": "exact durable-checkpoint alias"},
                {"range": "3..35", "octets": 32, "field": "full SHA-256 binding of the exact cached summary"}
            ],
            "cold_summary_segments": [
                {"range": "0..1", "octets": 1, "field": "experimental codec marker and SUMMARY tag"},
                {"range": "1..2", "octets": 1, "field": "canonical body length"},
                {"range": "2..3", "octets": 1, "field": "full-summary form"},
                {"range": "3..35", "octets": 32, "field": "full collection ID"},
                {"range": "35..36", "octets": 1, "field": "minimal generation varint (100)"},
                {"range": "36..37", "octets": 1, "field": "minimal item-count varint (100)"},
                {"range": "37..69", "octets": 32, "field": "full collection digest"}
            ]
        },
        "maximum_witnesses": witnesses,
        "boundary_vectors": [
            {"name": "profile-capabilities", "kind": "valid", "encoded_hex": hex::encode(&compact_capabilities), "encoded_length": compact_capabilities.len()},
            {"name": "cold-full-summary-100", "kind": "valid-boundary", "encoded_hex": hex::encode(&compact_cold_summary), "encoded_length": compact_cold_summary.len()},
            {"name": "warm-cached-summary-100", "kind": "valid-boundary", "encoded_hex": hex::encode(&compact_warm_summary), "encoded_length": compact_warm_summary.len(), "requires_exact_cached_summary": true},
            {"name": "truncated-capabilities", "kind": "invalid-truncated", "input_hex": "b101", "expected_error": "truncated"},
            {"name": "false-envelope-length", "kind": "invalid-malformed", "input_hex": "b10201", "expected_error": "compact envelope length"},
            {"name": "overlong-body-length-varint", "kind": "invalid-noncanonical", "input_hex": "b1810001", "expected_error": "non-canonical varint"},
            {"name": "cached-summary-without-context", "kind": "invalid-context", "input_hex": hex::encode(&compact_warm_summary), "expected_error": "cached summary context"},
            {"name": "cached-summary-binding-mismatch", "kind": "invalid-context", "input_hex": hex::encode(&corrupted_warm_summary), "expected_error": "cached summary binding", "requires_exact_cached_summary": true},
            {"name": "full-summary-when-cache-matches", "kind": "invalid-noncanonical", "input_hex": hex::encode(&compact_cold_summary), "expected_error": "non-canonical full cached summary"},
            {"name": "one-past-outer-maximum", "kind": "invalid-one-past", "symbolic_octets": compact::MAX_COMPACT_RECORD_OCTETS + 1, "expected_error": "compact operation size before body allocation"}
        ],
        "tuple_validation_vectors": [
            {"name": "allocated-public-experimental", "codec_id": EXPERIMENTAL_CODEC_ID, "revision": EXPERIMENTAL_CODEC_REVISION, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "accept"},
            {"name": "reserved-zero", "codec_id": 0, "revision": 1, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "reserved-maximum", "codec_id": u32::MAX, "revision": 1, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "historical-private-use", "codec_id": 0xffff_0001_u32, "revision": 2, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "revision-zero-downgrade", "codec_id": EXPERIMENTAL_CODEC_ID, "revision": 0, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "unknown-public-id", "codec_id": EXPERIMENTAL_CODEC_ID + 1, "revision": 1, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "unsupported-revision", "codec_id": EXPERIMENTAL_CODEC_ID, "revision": EXPERIMENTAL_CODEC_REVISION + 1, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "message-manifest-schema-unsupported", "codec_id": EXPERIMENTAL_CODEC_ID, "revision": EXPERIMENTAL_CODEC_REVISION, "schema_fingerprint": MESSAGE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "", "expected": "UNSUPPORTED_CODEC-before-mutation"},
            {"name": "non-empty-parameters", "codec_id": EXPERIMENTAL_CODEC_ID, "revision": EXPERIMENTAL_CODEC_REVISION, "schema_fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX, "parameters_hex": "00", "expected": "UNSUPPORTED_CODEC-before-mutation"}
        ],
        "manifest_codec": {
            "status": "blocked-no-normative-instance-encoding",
            "schema_fingerprint": MESSAGE_SCHEMA_FINGERPRINT_HEX,
            "public_revision_1_supports_schema": false,
            "pretty_json_fixture_is_conforming_codec_bytes": false
        },
        "numeric_precision_vectors": {"status": "not-applicable", "reason": "profile has no approximate numeric fields"},
        "security": {"class": "public", "authentication": false, "confidentiality": false},
    }))
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
        "codec_status": "comparison-b1-experimental-unregistered-disposable",
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

fn verify_compact_codec_artifact() -> Result<(), Box<dyn Error>> {
    let generated = compact_codec_evidence()?;
    let committed: serde_json::Value = serde_json::from_str(include_str!(
        "../../../benchmarks/results/compact-codec-public-evidence-2026-09-02.json"
    ))?;
    if generated != committed {
        return Err("committed compact-codec evidence differs from deterministic output".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": "pass",
            "warm_no_change_octets": generated["after_public_experimental_codec"]["warm_no_change_octets"],
            "cold_no_change_octets": generated["after_public_experimental_codec"]["cold_no_change_octets"],
            "maximum_witnesses": generated["maximum_witnesses"].as_array().map_or(0, Vec::len),
        }))?
    );
    Ok(())
}

fn write_compact_codec_artifacts() -> Result<(), Box<dyn Error>> {
    let artifact = compact_codec_evidence()?;
    let mut artifact_bytes = serde_json::to_vec_pretty(&artifact)?;
    artifact_bytes.push(b'\n');
    let artifact_sha256 = hex::encode(Sha256::digest(&artifact_bytes));
    let vector_pack = serde_json::json!({
        "schema": "bempic-reference-v0.1-public-experimental-codec-vectors",
        "specification_commit": COMPACT_SPECIFICATION_COMMIT,
        "codec": artifact["codec"].clone(),
        "evidence_artifact": {"path": COMPACT_ARTIFACT_PATH, "sha256": artifact_sha256},
        "vectors": artifact["boundary_vectors"].clone(),
        "tuple_validation_vectors": artifact["tuple_validation_vectors"].clone(),
        "maximum_witnesses": artifact["maximum_witnesses"].clone(),
    });
    let mut vector_bytes = serde_json::to_vec_pretty(&vector_pack)?;
    vector_bytes.push(b'\n');
    for (path, bytes) in [
        (COMPACT_ARTIFACT_PATH, artifact_bytes),
        (COMPACT_VECTOR_PATH, vector_bytes),
    ] {
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn Error>> {
    if env::args().nth(1).as_deref() == Some("write-tranche3-evidence") {
        return tranche3::write_artifacts(std::path::Path::new("."));
    }
    if env::args().nth(1).as_deref() == Some("verify-tranche3-evidence") {
        return tranche3::verify_artifacts(std::path::Path::new("."));
    }
    if env::args().nth(1).as_deref() == Some("tranche3-evidence") {
        println!("{}", serde_json::to_string_pretty(&tranche3::evidence()?)?);
        return Ok(());
    }
    if env::args().nth(1).as_deref() == Some("verify-compact-codec-evidence") {
        return verify_compact_codec_artifact();
    }
    if env::args().nth(1).as_deref() == Some("write-compact-codec-evidence") {
        return write_compact_codec_artifacts();
    }
    if env::args().nth(1).as_deref() == Some("compact-codec-evidence") {
        println!(
            "{}",
            serde_json::to_string_pretty(&compact_codec_evidence()?)?
        );
        return Ok(());
    }
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
            "codec_status": "public-experimental-not-approved-not-mandatory",
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
    if env::args().nth(1).as_deref() == Some("write-fuzz-report") {
        let report = run()?;
        let mut bytes = serde_json::to_vec_pretty(&report)?;
        bytes.push(b'\n');
        fs::write("conformance/fuzz-report.json", bytes)?;
        if report.unresolved_findings > 0 {
            return Err("unresolved malformed-input or property finding".into());
        }
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
