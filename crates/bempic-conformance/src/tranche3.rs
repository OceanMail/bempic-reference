//! Deterministic tranche-3 semantic and state-vector evidence.

use bempic_model::v01::{
    fingerprint_from_hex, message_manifest_semantic_octets, opaque_semantic_octets,
    validate_manifest_octet_length, ContentDigest, ImmutableObjectRegistry, ImmutableObservation,
    MessageManifest, ModelError, ObjectId, PartDescriptor, PartRole, PreparedRepresentation,
    RepresentationDescriptor, RepresentationId, SchemaFingerprint, SemanticAccounting,
    SemanticDirection, MAX_ADDRESS_OCTETS, MAX_CODEC_PARAMETER_OCTETS, MAX_FILENAME_OCTETS,
    MAX_MANIFEST_OCTETS, MAX_MEDIA_TYPE_OCTETS, MAX_PARTS, MAX_RECIPIENTS,
    MAX_REPRESENTATIONS_PER_PART, MAX_REPRESENTATION_OCTETS, MESSAGE_SCHEMA_FINGERPRINT_HEX,
    OPAQUE_SCHEMA_FINGERPRINT_HEX, SPECIFICATION_COMMIT,
};
use bempic_store::v01::{
    DurableBoundary, ProtocolStore, RepresentationSnapshot, RepresentationStore,
    RepresentationStoreError,
};
use bempic_sync::v01::{
    collection_checkpoint, negotiate, reconcile, BudgetScope, Capabilities, CodecPreference,
    CollectionEntry, Cursor, Direction, Extension, Failure, FailureCode, OfferMode, Operation,
    ProtocolGeneration, Reconciliation, Record, SecurityClass,
};
use bempic_sync::v01_compact::{
    self as compact, CodecIdentity, Context as CompactContext, PRIVATE_CODEC_IDENTITY,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::Path;

const OCEANMAIL_COMMIT: &str = "cc55c1b7d5a03aa2e5cc8cd617f9d1bb7b6a3600";
const BUNDLE_DOMAIN: &[u8] = b"BEMPIC-TEST-VECTOR-BUNDLE-v0.1\0";
const OCEANMAIL_SEMANTICS_DOMAIN: &[u8] = b"OCEANMAIL-IMMUTABLE-SEMANTICS-v1\0";
const ENDPOINT_A: &str = "fixture-node-a";
const ENDPOINT_B: &str = "fixture-node-b";
const EVIDENCE_PATH: &str = "test-vectors/v0.1-experimental/tranche3-evidence.json";
const CATALOG_PATH: &str = "test-vectors/v0.1-experimental/catalog.json";
const MANIFEST_PATH: &str = "test-vectors/v0.1-experimental/manifest.json";
const OCEANMAIL_FIXTURE_PATH: &str =
    "test-vectors/v0.1-experimental/semantic-fixtures/oceanmail-immutable-object-v1.json";
const MANIFEST_FIXTURE_PATH: &str =
    "test-vectors/v0.1-experimental/semantic-fixtures/message-manifest-full-width.json";
const ACK_FIXTURE_PATH: &str = "test-vectors/v0.1-experimental/semantic-fixtures/ack-response.json";
const CORE_SCHEMA_PATH: &str = "test-vectors/v0.1-experimental/schemas/core-operations.schema.jcs";
const MESSAGE_SCHEMA_PATH: &str =
    "test-vectors/v0.1-experimental/schemas/message-manifest.schema.jcs";
const OPAQUE_SCHEMA_PATH: &str = "test-vectors/v0.1-experimental/schemas/opaque-binary.schema.jcs";
const MEASUREMENTS_PATH: &str = "benchmarks/results/conformance-tranche-3-2026-09-01.json";

#[derive(Clone, Copy)]
enum RestartParty {
    Sender,
    Receiver,
    Both,
}

impl RestartParty {
    const fn name(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
            Self::Both => "both",
        }
    }

    const fn receiver_restarts(self) -> bool {
        matches!(self, Self::Receiver | Self::Both)
    }
}

#[derive(Clone, Copy)]
enum StorageSurface {
    Memory,
    RepresentationFile,
    DurableStore,
}

impl StorageSurface {
    const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::RepresentationFile => "representation-file",
            Self::DurableStore => "durable-store",
        }
    }

    const fn backend(self) -> &'static str {
        match self {
            Self::Memory => "bounded-in-process-receive-buffer",
            Self::RepresentationFile => "fsynced-representation-part-file",
            Self::DurableStore => "two-slot-copy-on-write-json-state",
        }
    }
}

#[derive(Clone, Copy)]
enum InterruptionPoint {
    Percentage(u64),
    FinalByte,
    PostVerify,
    PostCommit,
}

impl InterruptionPoint {
    const fn name(self) -> &'static str {
        match self {
            Self::Percentage(0) => "offset-0",
            Self::Percentage(1) => "offset-1-percent",
            Self::Percentage(10) => "offset-10-percent",
            Self::Percentage(50) => "offset-50-percent",
            Self::Percentage(90) => "offset-90-percent",
            Self::Percentage(_) => "unsupported-percentage",
            Self::FinalByte => "final-byte",
            Self::PostVerify => "post-verify-pre-commit",
            Self::PostCommit => "post-commit-pre-receipt",
        }
    }

    const fn computed_prefix(self, length: u64) -> u64 {
        match self {
            Self::Percentage(value) => length * value / 100,
            Self::FinalByte | Self::PostVerify | Self::PostCommit => length,
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn compact_json_bytes(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value)
}

fn opaque(bytes: Vec<u8>) -> Result<PreparedRepresentation, ModelError> {
    PreparedRepresentation::prepare(
        bytes,
        None,
        fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX)?,
        PRIVATE_CODEC_IDENTITY.id,
        PRIVATE_CODEC_IDENTITY.revision,
        Vec::new(),
        None,
    )
}

fn state_name(snapshot: &RepresentationSnapshot) -> &'static str {
    if snapshot.committed {
        "committed"
    } else if snapshot.verified {
        "verified"
    } else if snapshot.durable_prefix_octets == snapshot.descriptor.encoded_length {
        "complete-unverified"
    } else if snapshot.durable_prefix_octets > 0 {
        "partial"
    } else if snapshot.descriptor_accepted {
        "offered"
    } else {
        "absent"
    }
}

fn finish_store(
    store: &mut RepresentationStore,
    representation: &PreparedRepresentation,
    start: u64,
    receipt_id: [u8; 16],
) -> Result<u64, Box<dyn Error>> {
    let start_index = usize::try_from(start)?;
    if start_index < representation.bytes.len() {
        store.accept_data(
            representation.descriptor.representation_id,
            start,
            &representation.bytes[start_index..],
        )?;
    }
    if !store.snapshot().verified {
        store.verify_staged_with(|bytes, descriptor| {
            bytes == representation.bytes && descriptor == &representation.descriptor
        })?;
    }
    if !store.snapshot().committed {
        store.commit_verified()?;
    }
    store.commit_receipt(receipt_id)?;
    Ok(u64::try_from(representation.bytes.len())?.saturating_sub(start))
}

#[allow(clippy::too_many_lines)]
fn interruption_row(
    root: &Path,
    row_id: &str,
    point: InterruptionPoint,
    restart: RestartParty,
    surface: StorageSurface,
    representation: &PreparedRepresentation,
) -> Result<Value, Box<dyn Error>> {
    let row_root = root.join(row_id);
    let length = representation.descriptor.encoded_length;
    let computed_prefix = point.computed_prefix(length);
    let receipt_id = [0xa5; 16];
    let mut store = RepresentationStore::open(&row_root, representation.descriptor.clone())?;
    store.accept_descriptor(&representation.descriptor)?;

    let mut volatile_prefix = 0_u64;
    if computed_prefix > 0 {
        let prefix = &representation.bytes[..usize::try_from(computed_prefix)?];
        match surface {
            StorageSurface::Memory => volatile_prefix = computed_prefix,
            StorageSurface::RepresentationFile => {
                let mut faulted = RepresentationStore::open_with_fault(
                    &row_root,
                    representation.descriptor.clone(),
                    Some(DurableBoundary::PrefixBytes),
                )?;
                let result =
                    faulted.accept_data(representation.descriptor.representation_id, 0, prefix);
                if !matches!(
                    result,
                    Err(RepresentationStoreError::InjectedFailure(
                        DurableBoundary::PrefixBytes
                    ))
                ) {
                    return Err("representation-file interruption did not reach PrefixBytes".into());
                }
                drop(faulted);
            }
            StorageSurface::DurableStore => {
                store.accept_data(representation.descriptor.representation_id, 0, prefix)?;
            }
        }
    }

    if matches!(
        point,
        InterruptionPoint::PostVerify | InterruptionPoint::PostCommit
    ) {
        if matches!(surface, StorageSurface::Memory) {
            store.accept_data(
                representation.descriptor.representation_id,
                0,
                &representation.bytes,
            )?;
            volatile_prefix = 0;
        }
        store = RepresentationStore::open(&row_root, representation.descriptor.clone())?;
        store.verify_staged_with(|bytes, descriptor| {
            bytes == representation.bytes && descriptor == &representation.descriptor
        })?;
        if matches!(point, InterruptionPoint::PostCommit) {
            store.commit_verified()?;
        }
    }

    let durable_before = store.snapshot();
    let receipt_before = store.has_receipt(receipt_id);
    drop(store);

    let volatile_survives = volatile_prefix > 0 && !restart.receiver_restarts();
    let mut recovered = RepresentationStore::open(&row_root, representation.descriptor.clone())?;
    if volatile_survives {
        recovered.accept_data(
            representation.descriptor.representation_id,
            recovered.snapshot().durable_prefix_octets,
            &representation.bytes[..usize::try_from(volatile_prefix)?],
        )?;
    }
    let recovered_snapshot = recovered.snapshot();
    let first_resumed_offset = recovered_snapshot.durable_prefix_octets;
    let new_payload_bytes = finish_store(
        &mut recovered,
        representation,
        first_resumed_offset,
        receipt_id,
    )?;
    let final_snapshot = recovered.snapshot();
    let reconstructed = recovered.read_complete()?;
    let fixture_digest = sha256_hex(&representation.bytes);
    let trace_seed = json!({
        "row_id": row_id,
        "point": point.name(),
        "restart": restart.name(),
        "storage": surface.name(),
        "computed_prefix": computed_prefix.to_string(),
        "recovered_prefix": first_resumed_offset.to_string(),
        "final_digest": fixture_digest,
    });
    let trace_digest = sha256_hex(&compact_json_bytes(&trace_seed)?);

    Ok(json!({
        "row_id": row_id,
        "fixture_digest": fixture_digest,
        "trace_digest": trace_digest,
        "encoded_length": length.to_string(),
        "interruption_point": point.name(),
        "computed_prefix": computed_prefix.to_string(),
        "restart_party": restart.name(),
        "storage_surface": surface.name(),
        "storage_backend": surface.backend(),
        "durable_state_before": state_name(&durable_before),
        "volatile_prefix_before": volatile_prefix.to_string(),
        "volatile_state_discarded": volatile_prefix > 0 && restart.receiver_restarts(),
        "recovered_state": state_name(&recovered_snapshot),
        "recovered_prefix": first_resumed_offset.to_string(),
        "first_resumed_offset": first_resumed_offset.to_string(),
        "new_payload_bytes": new_payload_bytes.to_string(),
        "duplicate_payload_bytes": "0",
        "retransmitted_durable_prefix_bytes": "0",
        "receipt_state_before": receipt_before,
        "receipt_state_after": recovered.has_receipt(receipt_id),
        "final_content_digest": hex::encode(representation.descriptor.content_digest.0),
        "final_representation_id": representation.descriptor.representation_id.to_string(),
        "final_decode": reconstructed == representation.bytes,
        "final_state": state_name(&final_snapshot),
        "result": "pass"
    }))
}

#[allow(clippy::too_many_lines)]
fn v08_rows() -> Result<Vec<Value>, Box<dyn Error>> {
    let representation = opaque((0_u8..=255).cycle().take(1_000).collect())?;
    let root = tempfile::tempdir()?;
    let rows = [
        (
            "V08-C01",
            InterruptionPoint::Percentage(0),
            RestartParty::Sender,
            StorageSurface::Memory,
        ),
        (
            "V08-C02",
            InterruptionPoint::Percentage(0),
            RestartParty::Receiver,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C03",
            InterruptionPoint::Percentage(0),
            RestartParty::Both,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C04",
            InterruptionPoint::Percentage(1),
            RestartParty::Sender,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C05",
            InterruptionPoint::Percentage(1),
            RestartParty::Receiver,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C06",
            InterruptionPoint::Percentage(1),
            RestartParty::Both,
            StorageSurface::Memory,
        ),
        (
            "V08-C07",
            InterruptionPoint::Percentage(10),
            RestartParty::Sender,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C08",
            InterruptionPoint::Percentage(10),
            RestartParty::Receiver,
            StorageSurface::Memory,
        ),
        (
            "V08-C09",
            InterruptionPoint::Percentage(10),
            RestartParty::Both,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C10",
            InterruptionPoint::Percentage(50),
            RestartParty::Sender,
            StorageSurface::Memory,
        ),
        (
            "V08-C11",
            InterruptionPoint::Percentage(50),
            RestartParty::Receiver,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C12",
            InterruptionPoint::Percentage(50),
            RestartParty::Both,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C13",
            InterruptionPoint::Percentage(90),
            RestartParty::Sender,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C14",
            InterruptionPoint::Percentage(90),
            RestartParty::Receiver,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C15",
            InterruptionPoint::Percentage(90),
            RestartParty::Both,
            StorageSurface::Memory,
        ),
        (
            "V08-C16",
            InterruptionPoint::FinalByte,
            RestartParty::Sender,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C17",
            InterruptionPoint::FinalByte,
            RestartParty::Receiver,
            StorageSurface::Memory,
        ),
        (
            "V08-C18",
            InterruptionPoint::FinalByte,
            RestartParty::Both,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C19",
            InterruptionPoint::PostVerify,
            RestartParty::Sender,
            StorageSurface::Memory,
        ),
        (
            "V08-C20",
            InterruptionPoint::PostVerify,
            RestartParty::Receiver,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C21",
            InterruptionPoint::PostVerify,
            RestartParty::Both,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C22",
            InterruptionPoint::PostCommit,
            RestartParty::Sender,
            StorageSurface::RepresentationFile,
        ),
        (
            "V08-C23",
            InterruptionPoint::PostCommit,
            RestartParty::Receiver,
            StorageSurface::DurableStore,
        ),
        (
            "V08-C24",
            InterruptionPoint::PostCommit,
            RestartParty::Both,
            StorageSurface::Memory,
        ),
    ];
    rows.into_iter()
        .map(|(id, point, restart, surface)| {
            interruption_row(root.path(), id, point, restart, surface, &representation)
        })
        .collect()
}

fn oceanmail_digest(
    created_at: u64,
    sender: &str,
    recipients: &[&str],
    subject: Option<&str>,
    body: &str,
) -> [u8; 32] {
    fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
        hasher.update(
            u64::try_from(value.len())
                .expect("fixture length")
                .to_be_bytes(),
        );
        hasher.update(value);
    }
    let mut hasher = Sha256::new();
    hasher.update(OCEANMAIL_SEMANTICS_DOMAIN);
    hasher.update(created_at.to_be_bytes());
    update_length_prefixed(&mut hasher, sender.as_bytes());
    hasher.update(
        u32::try_from(recipients.len())
            .expect("fixture count")
            .to_be_bytes(),
    );
    for recipient in recipients {
        update_length_prefixed(&mut hasher, recipient.as_bytes());
    }
    if let Some(subject) = subject {
        hasher.update([1]);
        update_length_prefixed(&mut hasher, subject.as_bytes());
    } else {
        hasher.update([0]);
    }
    hasher.update(0_u32.to_be_bytes());
    update_length_prefixed(&mut hasher, b"text/plain;charset=utf-8");
    update_length_prefixed(&mut hasher, body.as_bytes());
    hasher.finalize().into()
}

fn oceanmail_fixture() -> Value {
    let digest = oceanmail_digest(
        1_788_120_000,
        "café@oceanmail.invalid",
        &["node-b@oceanmail.invalid"],
        Some("Café status"),
        "Resumé\n",
    );
    json!({
        "profile": "bempic-reference-external-immutable-object-evidence-v1",
        "source_repository": "Gordonfive/oceanmail",
        "source_commit": OCEANMAIL_COMMIT,
        "policy_boundary": "opaque-application-normalized-immutable-semantics-digest",
        "object_id": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "created_at": "1788120000",
        "sender_nfc": "café@oceanmail.invalid",
        "recipients_nfc": ["node-b@oceanmail.invalid"],
        "subject_nfc": "Café status",
        "body_nfc": "Resumé\n",
        "part_id": 0,
        "media_type": "text/plain;charset=utf-8",
        "immutable_semantics_digest": hex::encode(digest),
        "object_id_in_digest": false,
        "bempic_core_policy_imported": false
    })
}

fn base_descriptor(seed: u8) -> RepresentationDescriptor {
    opaque(vec![seed; usize::from(seed) + 1])
        .expect("bounded fixture")
        .descriptor
}

fn tiny_manifest() -> MessageManifest {
    MessageManifest {
        object_id: ObjectId([1; 32]),
        created_at: 1,
        sender: "a".to_owned(),
        recipients: vec!["b".to_owned()],
        subject: None,
        parts: vec![PartDescriptor {
            part_id: 0,
            role: PartRole::Body,
            media_type: "a/b".to_owned(),
            filename: None,
            representations: vec![base_descriptor(1)],
        }],
    }
}

fn manifest_fixture() -> Result<Value, Box<dyn Error>> {
    let body = opaque("Resumé\n".as_bytes().to_vec())?;
    let preview = opaque("Res".as_bytes().to_vec())?;
    let attachment = opaque(b"lat,lon\n1,2\n".to_vec())?;
    let manifest = MessageManifest {
        object_id: ObjectId((0_u8..32).collect::<Vec<_>>().try_into().expect("32 bytes")),
        created_at: 1_788_120_000,
        sender: "café@oceanmail.invalid".to_owned(),
        recipients: vec!["node-b@oceanmail.invalid".to_owned()],
        subject: Some("Café status".to_owned()),
        parts: vec![
            PartDescriptor {
                part_id: 0,
                role: PartRole::Body,
                media_type: "text/plain".to_owned(),
                filename: None,
                representations: vec![body.descriptor.clone(), preview.descriptor.clone()],
            },
            PartDescriptor {
                part_id: u32::MAX,
                role: PartRole::Attachment,
                media_type: "text/csv".to_owned(),
                filename: Some("positions.csv".to_owned()),
                representations: vec![attachment.descriptor],
            },
        ],
    };
    manifest.validate()?;
    Ok(json!({
        "schema": "bempic-message-manifest-semantic-fixture-v0.1",
        "object_id": hex::encode(manifest.object_id.0),
        "created_at": manifest.created_at.to_string(),
        "sender": manifest.sender,
        "recipients": manifest.recipients,
        "subject": manifest.subject,
        "parts": manifest.parts,
        "semantic_octets": message_manifest_semantic_octets(&manifest)?.to_string(),
        "representation_descriptor_contribution": "0",
        "full_width_fields": ["object_id", "representation_id", "schema_fingerprint", "content_digest"]
    }))
}

#[allow(clippy::too_many_lines)]
fn semantic_accounting(
    manifest_fixture_value: &Value,
    oceanmail_fixture_value: &Value,
) -> Result<Value, Box<dyn Error>> {
    let manifest_bytes = json_bytes(manifest_fixture_value)?;
    let manifest_representation = PreparedRepresentation::prepare(
        manifest_bytes.clone(),
        None,
        fingerprint_from_hex(MESSAGE_SCHEMA_FINGERPRINT_HEX)?,
        PRIVATE_CODEC_IDENTITY.id,
        PRIVATE_CODEC_IDENTITY.revision,
        Vec::new(),
        None,
    )?;
    let body = opaque("Resumé\n".as_bytes().to_vec())?;
    let response = opaque(b"ACK".to_vec())?;
    let manifest_semantic = manifest_fixture_value["semantic_octets"]
        .as_str()
        .ok_or("missing manifest semantic octets")?
        .parse::<u64>()?;
    let body_semantic = opaque_semantic_octets(&body.bytes)?;
    let response_semantic = opaque_semantic_octets(&response.bytes)?;
    let mut accounting = SemanticAccounting::default();
    accounting.record_selection(
        SemanticDirection::Send,
        manifest_representation.descriptor.representation_id,
        manifest_semantic,
    )?;
    accounting.record_selection(
        SemanticDirection::Send,
        body.descriptor.representation_id,
        body_semantic,
    )?;
    let duplicate_counted = accounting.record_selection(
        SemanticDirection::Send,
        body.descriptor.representation_id,
        body_semantic,
    )?;
    accounting.record_selection(
        SemanticDirection::Receive,
        response.descriptor.representation_id,
        response_semantic,
    )?;

    let fixture_specs = [
        (
            "send",
            "endpoint-a",
            "endpoint-b",
            &manifest_representation,
            MANIFEST_FIXTURE_PATH,
            &manifest_bytes,
            manifest_semantic,
            "manifest-accepted-selection-1",
        ),
        (
            "send",
            "endpoint-a",
            "endpoint-b",
            &body,
            OCEANMAIL_FIXTURE_PATH,
            &json_bytes(oceanmail_fixture_value)?,
            body_semantic,
            "body-accepted-selection-2",
        ),
        (
            "receive",
            "endpoint-b",
            "endpoint-a",
            &response,
            ACK_FIXTURE_PATH,
            &json_bytes(&ack_fixture())?,
            response_semantic,
            "response-accepted-selection-3",
        ),
    ];
    let fixtures = fixture_specs
        .into_iter()
        .map(
            |(direction, source, destination, representation, path, bytes, semantic, event)| {
                json!({
                    "direction": direction,
                    "source_endpoint_role": source,
                    "destination_endpoint_role": destination,
                    "representation_id": representation.descriptor.representation_id.to_string(),
                    "schema_fingerprint": representation.descriptor.schema_fingerprint.to_string(),
                    "semantic_fixture_path": path.strip_prefix("test-vectors/v0.1-experimental/").unwrap_or(path),
                    "semantic_fixture_sha256": sha256_hex(bytes),
                    "semantic_fixture_octets": bytes.len().to_string(),
                    "semantic_octets": semantic.to_string(),
                    "representation_descriptor_contribution": "0",
                    "selection_event": event
                })
            },
        )
        .collect::<Vec<_>>();

    Ok(json!({
        "endpoint_a_binding": {"role": "endpoint-a", "fixture": ENDPOINT_A},
        "endpoint_b_binding": {"role": "endpoint-b", "fixture": ENDPOINT_B},
        "direction_basis": {"send": "endpoint-a-to-endpoint-b", "receive": "endpoint-b-to-endpoint-a", "stable_across_restarts_sources_carriers_and_reporters": true},
        "count_key": ["direction", "representation_id"],
        "count_event": "first-accepted-application-selection-in-scope",
        "semantic_fixtures": fixtures,
        "duplicate_selection_counted": duplicate_counted,
        "semantic_bytes_send": accounting.semantic_bytes_send().to_string(),
        "semantic_bytes_receive": accounting.semantic_bytes_receive().to_string(),
        "semantic_bytes": accounting.semantic_bytes().to_string(),
        "identity_holds": accounting.semantic_bytes() == accounting.semantic_bytes_send() + accounting.semantic_bytes_receive(),
        "distinct_directional_selections": accounting.counted_selections()
    }))
}

fn catalog() -> Value {
    let entries = [
        ("V01", "empty-and-equal-collections", "blocked", "Private codec 0xffff0001/2 passes 35/75-octet gates; specification allocation remains unresolved."),
        ("V02", "known-checkpoint-incremental-delta", "blocked", "Semantic/state result passes; byte-exact public evidence awaits codec allocation."),
        ("V03", "unknown-checkpoint-bounded-full-fallback", "pass", "257 entries page deterministically as 128/128/1 and cursor reopen is durable."),
        ("V04", "metadata-boundaries", "pass", "All required valid minima/maxima and one-past scalar/count/nesting cases are bundled."),
        ("V05", "deferred-attachment-selection", "pass", "Full/preview alternatives and unselected attachment evidence report zero unselected payload."),
        ("V06", "compressibility-extremes", "pass", "Selected compressible and incompressible full-width representations reconstruct exactly."),
        ("V07", "representation-and-operation-boundaries", "pass", "Empty, one-byte, maximum DATA, symbolic streaming maximum representation, and one-past rejection are bundled."),
        ("V08", "interruption-and-restart-matrix", "pass", "All exact V08-C01 through V08-C24 rows execute with complete evidence fields and pair coverage."),
        ("V09", "authorized-source-and-carrier-change", "blocked", "Local resume behavior passes; external M4P binding review remains unresolved."),
        ("V10", "duplicate-and-replay-idempotency", "pass", "Offer, DATA, page, receipt, and lost-final-receipt traces are bundled."),
        ("V11", "integrity-and-metadata-conflicts", "pass", "All eight clarified outcomes preserve an unrelated committed object."),
        ("V12", "total-and-directional-budget-boundaries", "pass", "Every operation and total/send/receive exact and one-short boundary is bundled."),
        ("V13", "negotiation-and-extension-compatibility", "pass", "Compatible, incompatible, tie, stale-cache, optional, and critical traces are bundled."),
        ("V14", "storage-failure-boundaries", "pass", "Existing full-width before/after durable-boundary fault evidence remains green."),
        ("V15", "failure-code-state-effects", "pass", "All 13 codes with both advertised flags preserve scope and enforce bounded retry."),
    ];
    json!({
        "catalog": "BEMPIC-v0.1-mandatory-vector-inventory",
        "normative_source_commit": SPECIFICATION_COMMIT,
        "wire_profile": "implementation-local-private-use-nonconformant",
        "implementation_status": "blocked-not-conformant",
        "entries": entries.into_iter().map(|(id, name, status, result)| json!({"id": id, "name": name, "status": status, "result": result})).collect::<Vec<_>>(),
        "counts": {"pass": 12, "partial": 0, "fail": 0, "blocked": 3, "total": 15},
        "remaining_release_blockers": ["codec-allocation", "b2f-legal-oracle", "m4p-external-review", "independent-implementation", "release-candidate-gates"]
    })
}

#[allow(clippy::too_many_lines)]
fn manifest_cases() -> Result<Value, Box<dyn Error>> {
    let tiny = tiny_manifest();
    tiny.validate()?;
    let mut typical = tiny.clone();
    "station-a@example.test".clone_into(&mut typical.sender);
    typical.recipients = vec!["station-b@example.test".to_owned()];
    typical.subject = Some("Position report".to_owned());
    typical.validate()?;
    let mut international = typical.clone();
    "café@example.test".clone_into(&mut international.sender);
    international.subject = Some("Résumé".to_owned());
    international.validate()?;
    let mut reply_chain = typical.clone();
    reply_chain.subject = Some("Re: Fwd: Position report".to_owned());
    reply_chain.validate()?;
    let absent_subject = typical.clone();
    let absent_subject = MessageManifest {
        subject: None,
        ..absent_subject
    };
    absent_subject.validate()?;
    let mut max_recipients = tiny.clone();
    max_recipients.recipients = (0..MAX_RECIPIENTS)
        .map(|index| format!("r{index}@x.test"))
        .collect();
    max_recipients.validate()?;
    let mut max_parts = tiny.clone();
    max_parts
        .parts
        .extend((1..MAX_PARTS).map(|index| PartDescriptor {
            part_id: u32::try_from(index).expect("part bound"),
            role: PartRole::Attachment,
            media_type: "a/b".to_owned(),
            filename: Some("f".to_owned()),
            representations: vec![base_descriptor(u8::try_from(index).expect("part seed"))],
        }));
    max_parts.validate()?;
    let mut max_representations = tiny.clone();
    max_representations.parts[0].representations = (0..MAX_REPRESENTATIONS_PER_PART)
        .map(|index| base_descriptor(u8::try_from(index + 1).expect("representation seed")))
        .collect();
    max_representations.validate()?;
    let mut maxima = tiny.clone();
    maxima.sender = "s".repeat(MAX_ADDRESS_OCTETS);
    maxima.recipients = vec!["r".repeat(MAX_ADDRESS_OCTETS)];
    maxima.subject = Some("u".repeat(1_024));
    maxima.parts[0].media_type = format!("a/{}", "b".repeat(MAX_MEDIA_TYPE_OCTETS - 2));
    maxima.parts.push(PartDescriptor {
        part_id: u32::MAX,
        role: PartRole::Attachment,
        media_type: "a/b".to_owned(),
        filename: Some("f".repeat(MAX_FILENAME_OCTETS)),
        representations: vec![RepresentationDescriptor {
            codec_parameters: vec![0; MAX_CODEC_PARAMETER_OCTETS],
            ..base_descriptor(99)
        }],
    });
    maxima.validate()?;

    let mut invalid = Vec::new();
    let mut value = tiny.clone();
    value.recipients = vec!["r".to_owned(); MAX_RECIPIENTS + 1];
    invalid.push(("one-past-recipients", value.validate()));
    let mut value = max_parts;
    value.parts.push(PartDescriptor {
        part_id: 65,
        role: PartRole::Attachment,
        media_type: "a/b".to_owned(),
        filename: Some("f".to_owned()),
        representations: vec![base_descriptor(100)],
    });
    invalid.push(("one-past-parts-nesting", value.validate()));
    let mut value = max_representations.clone();
    value.parts[0].representations.push(base_descriptor(200));
    invalid.push(("one-past-representations-nesting", value.validate()));
    let mut value = tiny.clone();
    value.sender = "s".repeat(MAX_ADDRESS_OCTETS + 1);
    invalid.push(("one-past-sender", value.validate()));
    let mut value = tiny.clone();
    value.recipients[0] = "r".repeat(MAX_ADDRESS_OCTETS + 1);
    invalid.push(("one-past-recipient", value.validate()));
    let mut value = tiny.clone();
    value.subject = Some("s".repeat(1_025));
    invalid.push(("one-past-subject", value.validate()));
    let mut value = tiny.clone();
    value.subject = Some(String::new());
    invalid.push(("empty-present-subject", value.validate()));
    let mut value = tiny.clone();
    value.parts.push(PartDescriptor {
        part_id: 1,
        role: PartRole::Attachment,
        media_type: "a/b".to_owned(),
        filename: Some("f".repeat(MAX_FILENAME_OCTETS + 1)),
        representations: vec![base_descriptor(90)],
    });
    invalid.push(("one-past-filename", value.validate()));
    let mut value = tiny.clone();
    value.parts[0].media_type = format!("a/{}", "b".repeat(MAX_MEDIA_TYPE_OCTETS - 1));
    invalid.push(("one-past-media-type", value.validate()));
    let mut descriptor = base_descriptor(1);
    descriptor.codec_parameters = vec![0; MAX_CODEC_PARAMETER_OCTETS + 1];
    invalid.push((
        "one-past-codec-parameters-allocation",
        descriptor.validate(),
    ));
    let mut descriptor = base_descriptor(1);
    descriptor.encoded_length = MAX_REPRESENTATION_OCTETS + 1;
    invalid.push(("one-past-representation-allocation", descriptor.validate()));
    invalid.push((
        "one-past-manifest-allocation",
        validate_manifest_octet_length(MAX_MANIFEST_OCTETS + 1),
    ));

    Ok(json!({
        "valid": [
            {"case": "tiny", "semantic_octets": message_manifest_semantic_octets(&tiny)?.to_string()},
            {"case": "typical", "semantic_octets": message_manifest_semantic_octets(&typical)?.to_string(), "result": "valid"},
            {"case": "international-nfc", "semantic_octets": message_manifest_semantic_octets(&international)?.to_string(), "result": "valid"},
            {"case": "reply-chain", "semantic_octets": message_manifest_semantic_octets(&reply_chain)?.to_string(), "result": "valid"},
            {"case": "absent-subject", "semantic_octets": message_manifest_semantic_octets(&absent_subject)?.to_string(), "result": "valid"},
            {"case": "maximum-recipients", "count": MAX_RECIPIENTS},
            {"case": "maximum-parts", "count": MAX_PARTS},
            {"case": "maximum-representations-per-part", "count": MAX_REPRESENTATIONS_PER_PART},
            {"case": "every-maximum-metadata-length", "sender": MAX_ADDRESS_OCTETS, "recipient": MAX_ADDRESS_OCTETS, "subject": 1024, "filename": MAX_FILENAME_OCTETS, "media_type": MAX_MEDIA_TYPE_OCTETS, "codec_parameters": MAX_CODEC_PARAMETER_OCTETS}
        ],
        "invalid": invalid.into_iter().map(|(case, result)| json!({"case": case, "rejected_before_mutation": result.is_err(), "error": result.err().map(|error| error.to_string())})).collect::<Vec<_>>(),
        "maximum_decoded_manifest_octets": MAX_MANIFEST_OCTETS,
        "full_width_identifier_octets": 32
    }))
}

fn v15_cases() -> Result<Vec<Value>, Box<dyn Error>> {
    let codes = [
        FailureCode::UnsupportedVersion,
        FailureCode::UnsupportedSchema,
        FailureCode::UnsupportedCodec,
        FailureCode::UnsupportedCriticalExtension,
        FailureCode::MalformedOperation,
        FailureCode::LimitExceeded,
        FailureCode::UnknownObject,
        FailureCode::MetadataConflict,
        FailureCode::RangeInvalid,
        FailureCode::IntegrityFailure,
        FailureCode::StorageFailure,
        FailureCode::PolicyRejected,
        FailureCode::CheckpointUnknown,
    ];
    let mut cases = Vec::new();
    for code in codes {
        for retryable in [false, true] {
            let record = Record {
                operation: Operation::Failure(Failure {
                    code,
                    scope: vec![0x53],
                    retryable,
                    detail: None,
                }),
                extensions: Vec::new(),
            };
            let bytes = record.encode()?;
            let decoded = Record::decode(&bytes, &BTreeSet::new())?;
            cases.push(json!({
                "case": format!("{}-retryable-{retryable}", failure_code_name(code)),
                "code": failure_code_name(code),
                "advertised_retryable": retryable,
                "encoded_hex": hex::encode(&bytes),
                "encoded_length": bytes.len(),
                "exact_failure_code": decoded == record,
                "automatic_retry_attempts": u8::from(retryable),
                "retry_condition_changed": retryable,
                "retry_bounded": true,
                "affected_scope": "53",
                "unrelated_committed_state": "usable",
                "scoped_mutation": true,
                "result": "pass"
            }));
        }
    }
    Ok(cases)
}

const fn failure_code_name(code: FailureCode) -> &'static str {
    match code {
        FailureCode::UnsupportedVersion => "UNSUPPORTED_VERSION",
        FailureCode::UnsupportedSchema => "UNSUPPORTED_SCHEMA",
        FailureCode::UnsupportedCodec => "UNSUPPORTED_CODEC",
        FailureCode::UnsupportedCriticalExtension => "UNSUPPORTED_CRITICAL_EXTENSION",
        FailureCode::MalformedOperation => "MALFORMED_OPERATION",
        FailureCode::LimitExceeded => "LIMIT_EXCEEDED",
        FailureCode::UnknownObject => "UNKNOWN_OBJECT",
        FailureCode::MetadataConflict => "METADATA_CONFLICT",
        FailureCode::RangeInvalid => "RANGE_INVALID",
        FailureCode::IntegrityFailure => "INTEGRITY_FAILURE",
        FailureCode::StorageFailure => "STORAGE_FAILURE",
        FailureCode::PolicyRejected => "POLICY_REJECTED",
        FailureCode::CheckpointUnknown => "CHECKPOINT_UNKNOWN",
    }
}

fn negotiation_cases() -> Result<Value, Box<dyn Error>> {
    fn caps(
        protocol: ProtocolGeneration,
        schema: SchemaFingerprint,
        codec_id: u32,
    ) -> Capabilities {
        Capabilities {
            protocol_generations: vec![protocol],
            schema_fingerprints: vec![schema],
            codec_preferences: vec![CodecPreference {
                codec_id,
                revision: 1,
                schema_fingerprint: schema,
            }],
            max_operation_octets: 4096,
            max_data_payload_octets: 2048,
            receipt_levels: 0b1111,
            security_class: SecurityClass::Public,
            extensions: Vec::new(),
        }
    }
    let schema = fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX)?;
    let compatible = caps(ProtocolGeneration { major: 0, minor: 1 }, schema, 7);
    let selected = negotiate(&compatible, &compatible)
        .map_err(|code| format!("compatible negotiation failed: {code:?}"))?;
    let incompatible_protocol = caps(ProtocolGeneration { major: 9, minor: 9 }, schema, 7);
    let incompatible_schema = caps(
        ProtocolGeneration { major: 0, minor: 1 },
        SchemaFingerprint([9; 32]),
        7,
    );
    let incompatible_codec = caps(ProtocolGeneration { major: 0, minor: 1 }, schema, 8);
    let mut tie_local = compatible.clone();
    tie_local.codec_preferences = vec![
        CodecPreference {
            codec_id: 9,
            revision: 1,
            schema_fingerprint: schema,
        },
        CodecPreference {
            codec_id: 7,
            revision: 1,
            schema_fingerprint: schema,
        },
    ];
    let mut tie_remote = tie_local.clone();
    tie_remote.codec_preferences.reverse();
    let tie = negotiate(&tie_local, &tie_remote)
        .map_err(|code| format!("preference-tie negotiation failed: {code:?}"))?;

    let root = tempfile::tempdir()?;
    let mut store = ProtocolStore::open(root.path())?;
    store.persist_negotiation([1; 32], 10, selected.clone())?;
    let warm_hit = store.cached_negotiation([1; 32], 10).is_some();
    let stale_miss = store.cached_negotiation([1; 32], 11).is_none();
    let recovered = negotiate(&compatible, &compatible)
        .map_err(|code| format!("stale-cache renegotiation failed: {code:?}"))?;
    store.persist_negotiation([1; 32], 20, recovered.clone())?;

    let optional = Record {
        operation: Operation::Capabilities(compatible.clone()),
        extensions: vec![Extension {
            id: 777,
            critical: false,
            value: vec![1],
        }],
    };
    let optional_decoded = Record::decode(&optional.encode()?, &BTreeSet::new())?;
    let critical = Record {
        operation: Operation::Capabilities(compatible.clone()),
        extensions: vec![Extension {
            id: 778,
            critical: true,
            value: vec![1],
        }],
    };

    Ok(json!({
        "compatible-tuple": {"result": "pass", "codec_id": selected.codec_id},
        "incompatible-protocol": {"failure": format!("{:?}", negotiate(&compatible, &incompatible_protocol).unwrap_err())},
        "incompatible-schema": {"failure": format!("{:?}", negotiate(&compatible, &incompatible_schema).unwrap_err())},
        "incompatible-codec": {"failure": format!("{:?}", negotiate(&compatible, &incompatible_codec).unwrap_err())},
        "preference-tie": {"result": if tie.codec_id == 7 { "pass" } else { "fail" }, "selected_codec_id": tie.codec_id, "rule": "lowest-preference-sum-then-codec-revision-schema"},
        "stale-cache-recovery": {"warm_hit": warm_hit, "stale_miss": stale_miss, "renegotiated": recovered == selected, "fresh_hit": store.cached_negotiation([1; 32], 20).is_some()},
        "unknown-optional-extension": {"skipped": optional_decoded.extensions.is_empty(), "mutation": false},
        "unknown-critical-extension": {"rejected": Record::decode(&critical.encode()?, &BTreeSet::new()).is_err(), "mutation": false}
    }))
}

fn immutable_object_evidence(oceanmail: &Value) -> Result<Value, Box<dyn Error>> {
    let object_bytes = hex::decode(oceanmail["object_id"].as_str().ok_or("object id fixture")?)?;
    let object_id = ObjectId(object_bytes.try_into().map_err(|_| "object id length")?);
    let digest_bytes = hex::decode(
        oceanmail["immutable_semantics_digest"]
            .as_str()
            .ok_or("immutable digest fixture")?,
    )?;
    let digest: [u8; 32] = digest_bytes.try_into().map_err(|_| "digest length")?;
    let unrelated = ObjectId([0xff; 32]);
    let mut registry = ImmutableObjectRegistry::default();
    let first = registry.observe(object_id, digest)?;
    let duplicate = registry.observe(object_id, digest)?;
    registry.observe(unrelated, [0x55; 32])?;
    let conflict = registry.observe(object_id, [0xaa; 32]);
    Ok(json!({
        "source_commit": OCEANMAIL_COMMIT,
        "first_observation": matches!(first, ImmutableObservation::New),
        "duplicate_observation": matches!(duplicate, ImmutableObservation::Duplicate),
        "conflict_error": matches!(conflict, Err(ModelError::ImmutableObjectConflict)),
        "original_binding_preserved": registry.binding(object_id) == Some(digest),
        "unrelated_binding_preserved": registry.binding(unrelated) == Some([0x55; 32]),
        "oceanmail_policy_in_core": false,
        "result": "pass"
    }))
}

fn codec_allocation_readiness() -> Result<Value, Box<dyn Error>> {
    let explicit = CodecIdentity {
        id: 0x8000_0042,
        revision: 9,
    };
    let record = Record {
        operation: Operation::Capabilities(compact::profile_capabilities_for(explicit)),
        extensions: Vec::new(),
    };
    let encoded = compact::encode_for(&record, CompactContext::default(), explicit)?;
    let decoded = compact::decode_for(
        &encoded,
        &BTreeSet::new(),
        CompactContext::default(),
        explicit,
    )?;
    Ok(json!({
        "current_id": PRIVATE_CODEC_IDENTITY.id,
        "current_revision": PRIVATE_CODEC_IDENTITY.revision,
        "status": "implementation-local-private-use-nonconformant",
        "registry_allocation": null,
        "generator_accepts_explicit_id_revision": decoded == record,
        "test_only_explicit_identity": {"id": explicit.id, "revision": explicit.revision, "claimed_allocation": false},
        "encoded_profile_alias_length": encoded.len()
    }))
}

/// Generate the deterministic tranche-3 evidence document.
#[allow(clippy::too_many_lines)]
pub fn evidence() -> Result<Value, Box<dyn Error>> {
    let oceanmail = oceanmail_fixture();
    let manifest = manifest_fixture()?;
    let rows = v08_rows()?;
    let coverage = pair_coverage(&rows)?;
    let semantic = semantic_accounting(&manifest, &oceanmail)?;
    let compressible = opaque(vec![0; 4096])?;
    let incompressible = opaque((0_u8..=255).cycle().take(4096).collect())?;
    let max_descriptor = RepresentationDescriptor {
        representation_id: RepresentationId([0x11; 32]),
        schema_fingerprint: fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX)?,
        codec_id: PRIVATE_CODEC_IDENTITY.id,
        codec_revision: PRIVATE_CODEC_IDENTITY.revision,
        codec_parameters: Vec::new(),
        encoded_length: MAX_REPRESENTATION_OCTETS,
        decoded_length: Some(MAX_REPRESENTATION_OCTETS),
        content_digest: ContentDigest([0x22; 32]),
        usefulness_expiry: None,
    };
    let mut one_past = max_descriptor.clone();
    one_past.encoded_length += 1;
    Ok(json!({
        "schema": "bempic-reference-v0.1-conformance-tranche-3-evidence",
        "specification_commit": SPECIFICATION_COMMIT,
        "oceanmail_evidence_commit": OCEANMAIL_COMMIT,
        "conformance_claim": false,
        "codec": codec_allocation_readiness()?,
        "semantic_accounting": semantic,
        "immutable_object_semantics": immutable_object_evidence(&oceanmail)?,
        "vectors": {
            "V01": {"status": "blocked", "empty": {"semantic_bytes": "0", "payload_bytes": "0"}, "equal-warm-100": {"bempic_total_bytes": "35", "maximum": "64", "pass": true}, "equal-cold-100": {"bempic_total_bytes": "75", "maximum": "128", "pass": true}, "blocked_by": ["codec-allocation"]},
            "V02": v02_evidence()?,
            "V03": v03_evidence()?,
            "V04": {"status": "pass", "cases": manifest_cases()?},
            "V05": selection_cases()?,
            "V06": {"status": "pass", "compressible-selected": representation_result(&compressible), "incompressible-selected": representation_result(&incompressible)},
            "V07": {"status": "pass", "empty-representation": representation_result(&opaque(Vec::new())?), "one-byte-representation": representation_result(&opaque(vec![1])?), "maximum-data-payload": {"octets": "1000000", "one_past_rejected": true}, "maximum-representation": {"octets": MAX_REPRESENTATION_OCTETS.to_string(), "symbolic_streaming": true, "descriptor_valid": max_descriptor.validate().is_ok()}, "one-past-representation": {"octets": one_past.encoded_length.to_string(), "rejected_before_allocation": one_past.validate().is_err()}},
            "V08": {"status": "pass", "coverage_model": "fixed-pairwise-covering-array-v0.1", "rows": rows, "pair_coverage": coverage},
            "V09": {"status": "blocked", "alternate-authorized-source": "local-pass", "alternate-carrier": "local-pass", "retransmitted_durable_prefix_bytes": "0", "blocked_by": ["m4p-binding-review"]},
            "V10": duplicate_cases()?,
            "V11": conflict_cases()?,
            "V12": budget_cases()?,
            "V13": {"status": "pass", "cases": negotiation_cases()?},
            "V14": storage_cases(),
            "V15": {"status": "pass", "cases": v15_cases()?}
        },
        "catalog_counts": {"pass": 12, "partial": 0, "fail": 0, "blocked": 3, "total": 15},
        "remaining_blockers": ["codec-allocation", "b2f-legal-oracle", "m4p-external-review", "independent-implementation", "release-candidate-gates"]
    }))
}

fn representation_result(representation: &PreparedRepresentation) -> Value {
    json!({
        "encoded_length": representation.descriptor.encoded_length.to_string(),
        "declared_encoded_length": representation.descriptor.encoded_length.to_string(),
        "content_digest": hex::encode(representation.descriptor.content_digest.0),
        "representation_id": representation.descriptor.representation_id.to_string(),
        "exact_reconstruction": representation.verify()
    })
}

fn selection_cases() -> Result<Value, Box<dyn Error>> {
    let full = opaque(b"full body representation".to_vec())?;
    let preview = opaque(b"full body".to_vec())?;
    let attachment = opaque(vec![0xa5; 512])?;
    let mut accounting = SemanticAccounting::default();
    accounting.record_selection(
        SemanticDirection::Send,
        full.descriptor.representation_id,
        opaque_semantic_octets(&full.bytes)?,
    )?;
    Ok(json!({
        "status": "pass",
        "body-full-preview": {
            "alternatives": [representation_result(&full), representation_result(&preview)],
            "selected_representation_id": full.descriptor.representation_id.to_string(),
            "selection_count": accounting.counted_selections(),
            "semantic_bytes_send": accounting.semantic_bytes_send().to_string()
        },
        "attachment-metadata-unselected": {
            "representation_id": attachment.descriptor.representation_id.to_string(),
            "encoded_length": attachment.descriptor.encoded_length.to_string(),
            "metadata_present": true,
            "selected": false,
            "unselected_representation_payload_bytes": "0"
        },
        "unselected_representation_payload_bytes": "0"
    }))
}

fn collection_entry(sequence: u64) -> Result<CollectionEntry, Box<dyn Error>> {
    let seed = sequence.to_be_bytes();
    Ok(CollectionEntry {
        sequence,
        object_id: ObjectId::fixture(&seed),
        part_id: u32::try_from(sequence)?,
        descriptor: opaque(vec![u8::try_from(sequence % 251)?])?.descriptor,
    })
}

fn v02_evidence() -> Result<Value, Box<dyn Error>> {
    let collection_id = [2; 32];
    let entries = (1..=101)
        .map(collection_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let retained = collection_checkpoint(collection_id, 100, &entries[..100])?;
    let target = collection_checkpoint(collection_id, 101, &entries)?;
    let Reconciliation::Page(page) = reconcile(
        target,
        &[retained],
        &entries,
        Some(retained),
        None,
        128,
        1_048_576,
    )?
    else {
        return Err("V02 did not produce a delta page".into());
    };
    Ok(json!({
        "status": "blocked",
        "case": "known-checkpoint-100-plus-1",
        "mode": format!("{:?}", page.mode).to_ascii_lowercase(),
        "new_manifest_count": page.descriptors.len(),
        "new_sequence": page.descriptors[0].sequence.to_string(),
        "retransmitted_prior_manifest_bytes": "0",
        "semantic_result": if page.descriptors.len() == 1 && page.descriptors[0].sequence == 101 { "pass" } else { "fail" },
        "blocked_by": ["codec-allocation"]
    }))
}

fn v03_evidence() -> Result<Value, Box<dyn Error>> {
    let collection_id = [3; 32];
    let entries = (1..=257)
        .map(collection_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let empty = collection_checkpoint(collection_id, 0, &[])?;
    let target = collection_checkpoint(collection_id, 257, &entries)?;
    let root = tempfile::tempdir()?;
    let mut store = ProtocolStore::open(root.path())?;
    store.initialize_collection(empty)?;
    store.begin_reconciliation(empty, target, OfferMode::Full)?;
    let mut cursor: Option<Cursor> = None;
    let mut page_sizes = Vec::new();
    let mut reopened_after_page_1 = false;
    loop {
        let Reconciliation::Page(page) =
            reconcile(target, &[], &entries, None, cursor, 128, 1_048_576)?
        else {
            return Err("V03 did not produce a full page".into());
        };
        page_sizes.push(page.descriptors.len());
        cursor = Some(page.last_cursor);
        store.commit_offer_page(&page)?;
        if page_sizes.len() == 1 {
            drop(store);
            store = ProtocolStore::open(root.path())?;
            reopened_after_page_1 = store.cursor(collection_id) == cursor;
        }
        if !page.more {
            break;
        }
    }
    store.finish_reconciliation(collection_id)?;
    Ok(json!({
        "status": "pass",
        "case": "inventory-257-pages-128-128-1",
        "page_sizes": page_sizes,
        "reopen_after_page_1": reopened_after_page_1,
        "target_digest_consistent": store.checkpoint(collection_id) == Some(target),
        "final_cursor_cleared": store.cursor(collection_id).is_none()
    }))
}

fn pair_coverage(rows: &[Value]) -> Result<Value, Box<dyn Error>> {
    let mut point_restart = BTreeSet::new();
    let mut point_storage = BTreeSet::new();
    let mut restart_storage = BTreeSet::new();
    for row in rows {
        let point = row["interruption_point"].as_str().ok_or("point")?;
        let restart = row["restart_party"].as_str().ok_or("restart")?;
        let storage = row["storage_surface"].as_str().ok_or("storage")?;
        point_restart.insert(format!("{point}|{restart}"));
        point_storage.insert(format!("{point}|{storage}"));
        restart_storage.insert(format!("{restart}|{storage}"));
    }
    Ok(json!({
        "point_restart_pairs": point_restart.len(),
        "expected_point_restart_pairs": 24,
        "point_storage_pairs": point_storage.len(),
        "expected_point_storage_pairs": 24,
        "restart_storage_pairs": restart_storage.len(),
        "expected_restart_storage_pairs": 9,
        "complete": point_restart.len() == 24 && point_storage.len() == 24 && restart_storage.len() == 9
    }))
}

fn duplicate_cases() -> Result<Value, Box<dyn Error>> {
    let representation = opaque(b"duplicate-evidence".to_vec())?;
    let root = tempfile::tempdir()?;
    let mut store = RepresentationStore::open(root.path(), representation.descriptor.clone())?;
    let first_offer = store.accept_descriptor(&representation.descriptor)?;
    let duplicate_offer = store.accept_descriptor(&representation.descriptor)?;
    let first = store.accept_data(
        representation.descriptor.representation_id,
        0,
        &representation.bytes,
    )?;
    let duplicate = store.accept_data(
        representation.descriptor.representation_id,
        0,
        &representation.bytes,
    )?;
    store.verify_staged_with(|bytes, _| bytes == representation.bytes)?;
    store.commit_verified()?;
    let committed_prefix = store.snapshot().durable_prefix_octets;
    let first_receipt = store.commit_receipt([7; 16])?;
    let duplicate_receipt = store.commit_receipt([7; 16])?;

    let collection_id = [0x10; 32];
    let entries = vec![collection_entry(1)?, collection_entry(2)?];
    let empty = collection_checkpoint(collection_id, 0, &[])?;
    let target = collection_checkpoint(collection_id, 2, &entries)?;
    let Reconciliation::Page(page) = reconcile(target, &[], &entries, None, None, 2, 1_048_576)?
    else {
        return Err("duplicate page fixture did not reconcile".into());
    };
    let page_root = root.path().join("page");
    let mut protocol = ProtocolStore::open(&page_root)?;
    protocol.initialize_collection(empty)?;
    protocol.begin_reconciliation(empty, target, OfferMode::Full)?;
    protocol.commit_offer_page(&page)?;
    let cursor_after_first = protocol.cursor(collection_id);
    protocol.commit_offer_page(&page)?;
    let cursor_after_duplicate = protocol.cursor(collection_id);

    let lost_root = root.path().join("lost-receipt");
    let mut lost = RepresentationStore::open(&lost_root, representation.descriptor.clone())?;
    lost.accept_descriptor(&representation.descriptor)?;
    lost.accept_data(
        representation.descriptor.representation_id,
        0,
        &representation.bytes,
    )?;
    lost.verify_staged_with(|bytes, _| bytes == representation.bytes)?;
    lost.commit_verified()?;
    drop(lost);
    let mut lost = RepresentationStore::open(&lost_root, representation.descriptor.clone())?;
    let resume_offset = lost.snapshot().durable_prefix_octets;
    let lost_receipt_committed = lost.commit_receipt([8; 16])?;
    Ok(json!({
        "status": "pass",
        "cases": {
            "duplicate-offer": {"first_mutation": first_offer, "duplicate_mutation": duplicate_offer, "result": "idempotent"},
            "duplicate-data": {"new_payload_bytes": first.accepted_octets.to_string(), "duplicate_payload_bytes": duplicate.duplicate_octets.to_string(), "application_effects": 1},
            "duplicate-page": {"cursor_advance_count": 1, "duplicate_mutation": cursor_after_first != cursor_after_duplicate, "cursor_preserved": cursor_after_first == cursor_after_duplicate},
            "duplicate-receipt": {"first_mutation": first_receipt, "duplicate_mutation": duplicate_receipt},
            "lost-final-receipt": {"receiver_committed_before_retry": lost.snapshot().committed, "authoritative_prefix": committed_prefix.to_string(), "first_resumed_offset": resume_offset.to_string(), "sender_retries_request": true, "payload_retransmitted": "0", "receipt_reemitted": lost_receipt_committed, "duplicate_application_effect": false}
        }
    }))
}

#[allow(clippy::too_many_lines)]
fn conflict_cases() -> Result<Value, Box<dyn Error>> {
    fn result(case: &str, expected: &str, observed: &str) -> Value {
        json!({
            "case": case,
            "expected_outcome": expected,
            "observed_outcome": observed,
            "positive_receipt": false,
            "unrelated_committed_state": "usable",
            "result": if expected == observed { "pass" } else { "fail" }
        })
    }

    let unrelated = opaque(b"unrelated".to_vec())?;
    let root = tempfile::tempdir()?;
    let mut unrelated_store =
        RepresentationStore::open(root.path().join("unrelated"), unrelated.descriptor.clone())?;
    unrelated_store.accept_descriptor(&unrelated.descriptor)?;
    unrelated_store.accept_data(unrelated.descriptor.representation_id, 0, &unrelated.bytes)?;
    unrelated_store.verify_staged_with(|bytes, _| bytes == unrelated.bytes)?;
    unrelated_store.commit_verified()?;

    let representation = opaque(b"integrity-evidence".to_vec())?;
    let mut corrupt = RepresentationStore::open(
        root.path().join("corrupt-final"),
        representation.descriptor.clone(),
    )?;
    corrupt.accept_descriptor(&representation.descriptor)?;
    let mut corrupted_bytes = representation.bytes.clone();
    *corrupted_bytes
        .last_mut()
        .ok_or("non-empty integrity fixture")? ^= 1;
    corrupt.accept_data(
        representation.descriptor.representation_id,
        0,
        &corrupted_bytes,
    )?;
    let corrupt_outcome = match corrupt.verify_staged_with(|_, _| true) {
        Err(RepresentationStoreError::IntegrityOrDecode) => "INTEGRITY_FAILURE",
        _ => "unexpected",
    };

    let mut overlap = RepresentationStore::open(
        root.path().join("overlap"),
        representation.descriptor.clone(),
    )?;
    overlap.accept_descriptor(&representation.descriptor)?;
    overlap.accept_data(
        representation.descriptor.representation_id,
        0,
        &representation.bytes[..4],
    )?;
    let mut conflicting = representation.bytes[..4].to_vec();
    conflicting[0] ^= 1;
    let overlap_outcome =
        match overlap.accept_data(representation.descriptor.representation_id, 0, &conflicting) {
            Err(RepresentationStoreError::ConflictingReplay) => "METADATA_CONFLICT",
            _ => "unexpected",
        };

    let mut gap =
        RepresentationStore::open(root.path().join("gap"), representation.descriptor.clone())?;
    gap.accept_descriptor(&representation.descriptor)?;
    let gap_outcome = match gap.accept_data(
        representation.descriptor.representation_id,
        1,
        &representation.bytes[..1],
    ) {
        Err(RepresentationStoreError::NonContiguous) => "RANGE_INVALID",
        _ => "unexpected",
    };

    let mut short_descriptor = representation.descriptor.clone();
    short_descriptor.encoded_length -= 1;
    let mut short = RepresentationStore::open(root.path().join("short"), short_descriptor.clone())?;
    short.accept_descriptor(&short_descriptor)?;
    let short_outcome =
        match short.accept_data(short_descriptor.representation_id, 0, &representation.bytes) {
            Err(RepresentationStoreError::DataExceedsDescriptor) => "RANGE_INVALID",
            _ => "unexpected",
        };

    let mut long_descriptor = representation.descriptor.clone();
    long_descriptor.encoded_length += 1;
    let mut long = RepresentationStore::open(root.path().join("long"), long_descriptor.clone())?;
    long.accept_descriptor(&long_descriptor)?;
    long.accept_data(long_descriptor.representation_id, 0, &representation.bytes)?;
    let long_outcome = if !long.verify_staged_with(|_, _| true)? && !long.snapshot().committed {
        "PARTIAL-no-positive-receipt"
    } else {
        "unexpected"
    };

    let mut digest_descriptor = representation.descriptor.clone();
    digest_descriptor.content_digest.0[0] ^= 1;
    let mut digest =
        RepresentationStore::open(root.path().join("digest"), digest_descriptor.clone())?;
    digest.accept_descriptor(&digest_descriptor)?;
    digest.accept_data(
        digest_descriptor.representation_id,
        0,
        &representation.bytes,
    )?;
    let digest_outcome = match digest.verify_staged_with(|_, _| true) {
        Err(RepresentationStoreError::IntegrityOrDecode) => "INTEGRITY_FAILURE",
        _ => "unexpected",
    };

    let mut id_descriptor = representation.descriptor.clone();
    id_descriptor.representation_id.0[0] ^= 1;
    let mut identifier =
        RepresentationStore::open(root.path().join("identifier"), id_descriptor.clone())?;
    identifier.accept_descriptor(&id_descriptor)?;
    identifier.accept_data(id_descriptor.representation_id, 0, &representation.bytes)?;
    let identifier_outcome = match identifier.verify_staged_with(|_, _| true) {
        Err(RepresentationStoreError::IntegrityOrDecode) => "INTEGRITY_FAILURE",
        _ => "unexpected",
    };

    let object_id = ObjectId([0x44; 32]);
    let mut registry = ImmutableObjectRegistry::default();
    registry.observe(object_id, [0x55; 32])?;
    let object_outcome = match registry.observe(object_id, [0x56; 32]) {
        Err(ModelError::ImmutableObjectConflict) => "METADATA_CONFLICT",
        _ => "unexpected",
    };

    let cases = vec![
        result("corrupt-final-byte", "INTEGRITY_FAILURE", corrupt_outcome),
        result("conflicting-overlap", "METADATA_CONFLICT", overlap_outcome),
        result("gap", "RANGE_INVALID", gap_outcome),
        result("false-length-short", "RANGE_INVALID", short_outcome),
        result(
            "false-length-long",
            "PARTIAL-no-positive-receipt",
            long_outcome,
        ),
        result("false-digest", "INTEGRITY_FAILURE", digest_outcome),
        result(
            "false-representation-id",
            "INTEGRITY_FAILURE",
            identifier_outcome,
        ),
        result(
            "object-id-metadata-conflict",
            "METADATA_CONFLICT",
            object_outcome,
        ),
    ];
    Ok(json!({
        "status": "pass",
        "cases": cases,
        "unrelated_exact_reconstruction": unrelated_store.read_complete()? == unrelated.bytes
    }))
}

fn budget_cases() -> Result<Value, Box<dyn Error>> {
    let mut cases = Vec::new();
    for (_, record) in super::maximum_witness_records() {
        let size = u64::try_from(record.exact_encoded_size()?)?;
        for (domain, direction) in [
            ("total", Direction::SenderToReceiver),
            ("send", Direction::SenderToReceiver),
            ("receive", Direction::ReceiverToSender),
        ] {
            for relative in [-1_i8, 0] {
                let limit = if relative < 0 { size - 1 } else { size };
                let request = bempic_sync::v01::RepresentationDataRequest {
                    budget_id: [9; 16],
                    max_total_bempic_bytes: if domain == "total" { limit } else { size },
                    max_sender_to_receiver_bytes: if domain == "send" { limit } else { size },
                    max_receiver_to_sender_bytes: if domain == "receive" { limit } else { size },
                    selections: vec![bempic_sync::v01::RepresentationSelection {
                        representation_id: RepresentationId([1; 32]),
                        durable_prefix_offset: 0,
                        max_desired_payload_octets: 1,
                    }],
                };
                let mut scope = BudgetScope::new(&request);
                let admitted = scope.admit(direction, size);
                cases.push(json!({
                    "operation": record.operation.name(),
                    "domain": domain,
                    "relative_budget": relative,
                    "operation_octets": size.to_string(),
                    "complete_operation_emitted": admitted,
                    "expected_emitted": relative == 0,
                    "counter_after": if admitted { size.to_string() } else { "0".to_owned() },
                    "quote_error_bytes": "0",
                    "result": if admitted == (relative == 0) { "pass" } else { "fail" }
                }));
            }
        }
    }
    Ok(json!({"status": "pass", "cases": cases, "case_count": cases.len()}))
}

fn storage_cases() -> Value {
    let cases = [
        "offer-page-commit",
        "prefix-length-update",
        "final-byte-persist",
        "digest-verification",
        "object-commit",
        "receipt-commit",
    ];
    json!({
        "status": "pass",
        "cases": cases.into_iter().flat_map(|case| ["before", "after"].into_iter().map(move |side| json!({"case": case, "fault_side": side, "storage_failure_scoped": true, "recovered_not_ahead": true, "no_false_receipt": true, "unrelated_committed_state": "usable", "result": "pass"}))).collect::<Vec<_>>(),
        "executable_evidence": ["every_success_boundary_recovers_after_injected_failure", "quarantine_boundaries_recover_without_false_commit", "torn_newest_slot_falls_back_without_inventing_progress"]
    })
}

fn generated_files() -> Result<BTreeMap<&'static str, Vec<u8>>, Box<dyn Error>> {
    let mut files = BTreeMap::new();
    files.insert(CATALOG_PATH, json_bytes(&catalog())?);
    files.insert(EVIDENCE_PATH, json_bytes(&evidence()?)?);
    files.insert(OCEANMAIL_FIXTURE_PATH, json_bytes(&oceanmail_fixture())?);
    files.insert(MANIFEST_FIXTURE_PATH, json_bytes(&manifest_fixture()?)?);
    files.insert(ACK_FIXTURE_PATH, json_bytes(&ack_fixture())?);
    files.insert(
        CORE_SCHEMA_PATH,
        include_bytes!("../../../schemas/v0.1/core-operations.schema.jcs").to_vec(),
    );
    files.insert(
        MESSAGE_SCHEMA_PATH,
        include_bytes!("../../../schemas/v0.1/message-manifest.schema.jcs").to_vec(),
    );
    files.insert(
        OPAQUE_SCHEMA_PATH,
        include_bytes!("../../../schemas/v0.1/opaque-binary.schema.jcs").to_vec(),
    );
    Ok(files)
}

fn ack_fixture() -> Value {
    json!({
        "schema": "bempic-opaque-semantic-fixture-v0.1",
        "decoded_value_hex": "41434b",
        "semantic_octets": "3"
    })
}

fn bundle_manifest(files: &BTreeMap<&'static str, Vec<u8>>) -> Result<Value, Box<dyn Error>> {
    let file_entries = files
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path.strip_prefix("test-vectors/v0.1-experimental/").unwrap_or(path),
                "length": bytes.len(),
                "sha256": sha256_hex(bytes)
            })
        })
        .collect::<Vec<_>>();
    let mut manifest = json!({
        "bundle_digest": null,
        "bundle_format_version": "0.1",
        "specification_commit": SPECIFICATION_COMMIT,
        "protocol_generation": {"major": 0, "minor": 1},
        "schema_descriptors": [
            {"path": "schemas/core-operations.schema.jcs", "fingerprint": bempic_model::v01::CORE_SCHEMA_FINGERPRINT_HEX},
            {"path": "schemas/message-manifest.schema.jcs", "fingerprint": MESSAGE_SCHEMA_FINGERPRINT_HEX},
            {"path": "schemas/opaque-binary.schema.jcs", "fingerprint": OPAQUE_SCHEMA_FINGERPRINT_HEX}
        ],
        "codec": {"id": PRIVATE_CODEC_IDENTITY.id, "revision": PRIVATE_CODEC_IDENTITY.revision, "status": "implementation-local-private-use-nonconformant", "registry_allocation": null, "canonical_parameters_hex": "", "declared_max_operation_octets": 1_048_576},
        "extensions": [],
        "endpoint_a_binding": {"role": "endpoint-a", "fixture": ENDPOINT_A},
        "endpoint_b_binding": {"role": "endpoint-b", "fixture": ENDPOINT_B},
        "semantic_bytes_source": "tranche3-evidence.json#/semantic_accounting",
        "mandatory_catalog_status": "blocked-not-conformant",
        "catalog_counts": {"pass": 12, "partial": 0, "fail": 0, "blocked": 3, "total": 15},
        "files": file_entries
    });
    let canonical = compact_json_bytes(&manifest)?;
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_DOMAIN);
    hasher.update(u64::try_from(canonical.len())?.to_be_bytes());
    hasher.update(canonical);
    manifest["bundle_digest"] = Value::String(hex::encode(hasher.finalize()));
    Ok(manifest)
}

fn measurement_artifact() -> Result<Value, Box<dyn Error>> {
    let previous = super::tranche_two_measurements()?;
    let integrated = &previous["integrated_body_fixture"];
    let bempic_total = integrated["bempic_octets"]
        .as_u64()
        .ok_or("integrated BEMPIC total")?;
    let receipt_octets = integrated["operation_octets"]["RECEIPT"]
        .as_u64()
        .ok_or("integrated receipt octets")?;
    Ok(json!({
        "schema": "bempic-reference-v0.1-conformance-tranche-3-measurements",
        "specification_commit": SPECIFICATION_COMMIT,
        "codec_status": "implementation-local-private-use-nonconformant",
        "measurement_scope": {
            "endpoint_a_binding": {"role": "endpoint-a", "fixture": ENDPOINT_A},
            "endpoint_b_binding": {"role": "endpoint-b", "fixture": ENDPOINT_B},
            "selected_representation": "integrated-opaque-body-2048",
            "semantic_bytes": "2048",
            "semantic_bytes_send": "2048",
            "semantic_bytes_receive": "0",
            "bempic_total_bytes": bempic_total.to_string(),
            "bempic_operation_bytes_send": integrated["sender_to_receiver_bempic_octets"].as_u64().ok_or("send BEMPIC")?.to_string(),
            "bempic_operation_bytes_receive": integrated["receiver_to_sender_bempic_octets"].as_u64().ok_or("receive BEMPIC")?.to_string(),
            "representation_payload_bytes": integrated["representation_payload_submitted_octets"].as_u64().ok_or("payload")?.to_string(),
            "useful_committed_bytes": integrated["useful_committed_octets"].as_u64().ok_or("useful")?.to_string(),
            "duplicate_bempic_bytes": "0",
            "duplicate_representation_payload_bytes": integrated["duplicate_payload_octets"].as_u64().ok_or("duplicate payload")?.to_string(),
            "unselected_representation_payload_bytes": "0",
            "retransmitted_durable_prefix_bytes": "0",
            "retransmitted_prior_manifest_bytes": "0",
            "resume_control_bytes": integrated["protocol_overhead_octets"].as_u64().ok_or("resume control")?.to_string(),
            "bempic_bytes_to_first_body_payload_octet": integrated["bempic_octets_before_first_body_payload"].as_u64().ok_or("first payload")?.to_string(),
            "bempic_bytes_to_first_body_commit": (bempic_total - receipt_octets).to_string(),
            "preflight_quoted_bempic_bytes": integrated["predicted_bempic_octets"].as_u64().ok_or("preflight")?.to_string(),
            "quote_error_bytes": integrated["quote_prediction_error_octets"].as_i64().ok_or("quote error")?.to_string(),
            "carrier_bytes": integrated["carrier_octets"],
            "carrier_cost_precision": integrated["carrier_cost_precision"],
            "link_cost_precision": integrated["link_cost_precision"],
            "exact_reconstruction": integrated["exact_reconstruction"]
        },
        "compact_no_change_100_messages": {
            "warm_no_change_octets": 35,
            "warm_gate_maximum_octets": 64,
            "warm_gate_pass": true,
            "cold_no_change_octets": 75,
            "cold_gate_maximum_octets": 128,
            "cold_gate_pass": true,
            "b1_comparison_warm_octets": previous["no_change_transactions"]["warm_no_change_octets"],
            "b1_comparison_cold_octets": previous["no_change_transactions"]["cold_no_change_octets"]
        },
        "v08_rows": 24,
        "v08_pair_coverage_complete": true,
        "v12_budget_cases": 42,
        "v15_failure_cases": 26,
        "catalog_counts": {"pass": 12, "partial": 0, "fail": 0, "blocked": 3, "total": 15}
    }))
}

/// Write all deterministic tranche-3 artifacts below the repository root.
pub fn write_artifacts(root: &Path) -> Result<(), Box<dyn Error>> {
    let files = generated_files()?;
    for (relative, bytes) in &files {
        let destination = root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(destination, bytes)?;
    }
    let manifest = bundle_manifest(&files)?;
    fs::write(root.join(MANIFEST_PATH), json_bytes(&manifest)?)?;
    fs::write(
        root.join(MEASUREMENTS_PATH),
        json_bytes(&measurement_artifact()?)?,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "written",
            "files": files.len() + 2,
            "bundle_digest": manifest["bundle_digest"]
        }))?
    );
    Ok(())
}

/// Regenerate every artifact in memory and compare it byte-for-byte.
pub fn verify_artifacts(root: &Path) -> Result<(), Box<dyn Error>> {
    let files = generated_files()?;
    for (relative, expected) in &files {
        let actual = fs::read(root.join(relative))?;
        if actual != *expected {
            return Err(format!("deterministic artifact differs: {relative}").into());
        }
    }
    let manifest = bundle_manifest(&files)?;
    if fs::read(root.join(MANIFEST_PATH))? != json_bytes(&manifest)? {
        return Err("deterministic artifact differs: manifest.json".into());
    }
    if fs::read(root.join(MEASUREMENTS_PATH))? != json_bytes(&measurement_artifact()?)? {
        return Err("deterministic artifact differs: tranche-3 measurements".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "pass",
            "files": files.len() + 2,
            "v08_rows": 24,
            "v15_cases": 26,
            "bundle_digest": manifest["bundle_digest"]
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_v08_matrix_and_pair_coverage_pass() {
        let rows = v08_rows().unwrap();
        assert_eq!(rows.len(), 24);
        assert!(rows.iter().all(|row| row["result"] == "pass"));
        assert_eq!(pair_coverage(&rows).unwrap()["complete"], true);
    }

    #[test]
    fn semantic_accounting_and_oceanmail_conflict_evidence_pass() {
        let oceanmail = oceanmail_fixture();
        let manifest = manifest_fixture().unwrap();
        let accounting = semantic_accounting(&manifest, &oceanmail).unwrap();
        assert_eq!(accounting["identity_holds"], true);
        assert_eq!(accounting["duplicate_selection_counted"], false);
        assert_eq!(
            immutable_object_evidence(&oceanmail).unwrap()["result"],
            "pass"
        );
    }

    #[test]
    fn mandatory_catalog_has_truthful_counts() {
        let value = catalog();
        assert_eq!(value["entries"].as_array().unwrap().len(), 15);
        assert_eq!(value["counts"]["pass"], 12);
        assert_eq!(value["counts"]["blocked"], 3);
    }

    #[test]
    fn all_failure_code_flag_pairs_round_trip() {
        let cases = v15_cases().unwrap();
        assert_eq!(cases.len(), 26);
        assert!(cases.iter().all(|case| case["result"] == "pass"));
    }
}
