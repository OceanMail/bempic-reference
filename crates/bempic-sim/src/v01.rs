//! Integrated full-width v0.1 descriptor, record, carrier, persistence, and accounting path.
//!
//! The record image remains the unregistered disposable B1 codec. This module
//! connects already specified semantics without assigning a registry ID or
//! claiming a stable wire format.

use super::{CarrierConfig, CarrierMetrics, DeterministicCarrier, SimulationError};
use bempic_carrier::{CarrierDirection, OpaqueRecordCarrier as _};
use bempic_model::v01::{
    fingerprint_from_hex, ObjectId, PreparedRepresentation, RepresentationDescriptor,
    RepresentationId, OPAQUE_SCHEMA_FINGERPRINT_HEX,
};
use bempic_store::v01::{
    DurableBoundary, ProtocolStore, RepresentationSnapshot, RepresentationStore,
    RepresentationStoreError, StoreError as ProtocolStoreError,
};
use bempic_sync::v01::{
    collection_checkpoint, negotiate, BudgetScope, Capabilities, CodecPreference, CollectionEntry,
    Cursor, Data, Direction, FailureCode, NegotiatedProfile, Offer, OfferMode, Operation,
    ProtocolGeneration, Receipt, ReceiptStatus, Record, RepresentationDataRequest,
    RepresentationSelection, Request, SecurityClass, SenderState, Summary,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

const COLLECTION_ID: [u8; 32] = [0x43; 32];
const ENVELOPE_DATA_PAYLOAD_OFFSET: usize = 7 + 32 + 8 + 4;

/// Application-supplied authorization fact for one full-width representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedSource {
    /// Opaque application source identity.
    pub source_id: [u8; 32],
    /// Exact immutable representation this source is authorized to provide.
    pub representation_id: RepresentationId,
}

/// Endpoint process state recreated before a contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointRestart {
    /// Keep both endpoint process objects.
    Neither,
    /// Recreate only the sender from immutable prepared bytes.
    SenderOnly,
    /// Reopen only the receiver from durable state.
    ReceiverOnly,
    /// Recreate the sender and reopen the receiver.
    Both,
}

impl EndpointRestart {
    const fn sender(self) -> bool {
        matches!(self, Self::SenderOnly | Self::Both)
    }

    const fn receiver(self) -> bool {
        matches!(self, Self::ReceiverOnly | Self::Both)
    }
}

/// Deterministic mutation applied after carrier delivery and before strict decode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveredDataMutation {
    /// Deliver exact bytes.
    #[default]
    None,
    /// Remove the final byte, producing a false/truncated complete record.
    TruncateRecord,
    /// Flip the first representation payload byte while retaining a valid envelope.
    CorruptPayload,
}

/// One deterministic contact and endpoint-failure plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContactPlan {
    /// Carrier opportunity.
    pub carrier: CarrierConfig,
    /// Endpoint process restart before this contact.
    pub restart_before: EndpointRestart,
    /// Discard receiver state instead of reopening it, modeling full restart.
    pub discard_receiver_state: bool,
    /// Application-authorized source fact for this contact.
    pub source: AuthorizedSource,
    /// Mutation of the first delivered DATA record.
    pub data_mutation: DeliveredDataMutation,
    /// Number of additional complete DATA replays submitted after delivery.
    pub replay_data_records: u8,
}

/// Exact v0.1 BEMPIC accounting kept separate from carrier cost.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Accounting {
    /// Complete record octets submitted sender-to-receiver.
    pub sender_to_receiver_bempic_octets: u64,
    /// Complete record octets submitted receiver-to-sender.
    pub receiver_to_sender_bempic_octets: u64,
    /// Representation payload octets submitted, including replays/lost records.
    pub representation_payload_submitted_octets: u64,
    /// Representation payload octets delivered to the strict decoder.
    pub representation_payload_delivered_octets: u64,
    /// Matching replayed payload octets already durable.
    pub duplicate_payload_octets: u64,
    /// Exact representation octets atomically committed during this scope.
    pub useful_committed_octets: u64,
    /// Complete record octets predicted before each carrier submission.
    pub predicted_bempic_octets: u64,
    /// Actual minus predicted submitted BEMPIC octets.
    pub quote_prediction_error_octets: i64,
    /// Records whose arithmetic exact size equaled emitted length.
    pub deterministic_size_checks: u64,
    /// Strict operation decode failures before mutation.
    pub strict_decode_failures: u64,
    /// Whole-representation integrity or deterministic decode failures.
    pub integrity_or_representation_decode_failures: u64,
    /// Carrier octets by BEMPIC direction.
    pub carrier_sender_to_receiver_octets: u64,
    /// Carrier octets by BEMPIC direction.
    pub carrier_receiver_to_sender_octets: u64,
    /// Exact encoded record octets grouped by operation name.
    pub operation_octets: BTreeMap<String, u64>,
    /// BEMPIC octets before the first delivered body DATA record.
    pub bempic_octets_before_first_body_payload: Option<u64>,
    /// BEMPIC octets through the first delivered body DATA record.
    pub bempic_octets_through_first_body_payload: Option<u64>,
    /// Carrier octets before the first delivered body DATA record.
    pub carrier_octets_before_first_body_payload: Option<u64>,
    /// Carrier octets through the first delivered body DATA record.
    pub carrier_octets_through_first_body_payload: Option<u64>,
    /// Payload carried by that first body DATA record.
    pub first_body_payload_octets: Option<u64>,
}

impl Accounting {
    /// Total submitted complete-record BEMPIC octets.
    pub const fn total_bempic_octets(&self) -> u64 {
        self.sender_to_receiver_bempic_octets + self.receiver_to_sender_bempic_octets
    }

    /// BEMPIC record overhead excluding representation payload octets.
    pub const fn protocol_overhead_octets(&self) -> u64 {
        self.total_bempic_octets()
            .saturating_sub(self.representation_payload_submitted_octets)
    }

    /// Total lower-layer carrier octets exposed by the deterministic binding.
    pub const fn total_carrier_octets(&self) -> u64 {
        self.carrier_sender_to_receiver_octets + self.carrier_receiver_to_sender_octets
    }

    fn merge(&mut self, other: &Self) {
        let prior_carrier = self.total_carrier_octets();
        let prior_bempic = self.total_bempic_octets();
        self.sender_to_receiver_bempic_octets += other.sender_to_receiver_bempic_octets;
        self.receiver_to_sender_bempic_octets += other.receiver_to_sender_bempic_octets;
        self.representation_payload_submitted_octets +=
            other.representation_payload_submitted_octets;
        self.representation_payload_delivered_octets +=
            other.representation_payload_delivered_octets;
        self.duplicate_payload_octets += other.duplicate_payload_octets;
        self.useful_committed_octets += other.useful_committed_octets;
        self.predicted_bempic_octets += other.predicted_bempic_octets;
        self.quote_prediction_error_octets += other.quote_prediction_error_octets;
        self.deterministic_size_checks += other.deterministic_size_checks;
        self.strict_decode_failures += other.strict_decode_failures;
        self.integrity_or_representation_decode_failures +=
            other.integrity_or_representation_decode_failures;
        self.carrier_sender_to_receiver_octets += other.carrier_sender_to_receiver_octets;
        self.carrier_receiver_to_sender_octets += other.carrier_receiver_to_sender_octets;
        for (name, octets) in &other.operation_octets {
            *self.operation_octets.entry(name.clone()).or_default() += octets;
        }
        if self.carrier_octets_before_first_body_payload.is_none() {
            self.bempic_octets_before_first_body_payload = other
                .bempic_octets_before_first_body_payload
                .map(|value| prior_bempic + value);
            self.bempic_octets_through_first_body_payload = other
                .bempic_octets_through_first_body_payload
                .map(|value| prior_bempic + value);
            self.carrier_octets_before_first_body_payload = other
                .carrier_octets_before_first_body_payload
                .map(|value| prior_carrier + value);
            self.carrier_octets_through_first_body_payload = other
                .carrier_octets_through_first_body_payload
                .map(|value| prior_carrier + value);
            self.first_body_payload_octets = other.first_body_payload_octets;
        }
    }
}

/// One integrated contact report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContactReport {
    /// Contact plan.
    pub plan: ContactPlan,
    /// Receiver prefix at contact start.
    pub durable_prefix_before: u64,
    /// Receiver prefix at contact end.
    pub durable_prefix_after: u64,
    /// Exact bytes atomically committed.
    pub committed: bool,
    /// Positive receipt reached durable state.
    pub receipt_committed: bool,
    /// Exact protocol accounting.
    pub accounting: Accounting,
    /// Lower-layer carrier metrics.
    pub carrier: CarrierMetrics,
    /// Sender's final volatile phase.
    pub sender_state: SenderState,
}

/// Complete multi-contact full-width transfer report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferReport {
    /// Per-contact evidence.
    pub contacts: Vec<ContactReport>,
    /// Aggregate exact BEMPIC accounting.
    pub accounting: Accounting,
    /// Aggregate lower-layer metrics.
    pub carrier: CarrierMetrics,
    /// Exact reconstructed representation.
    pub reconstructed: Vec<u8>,
    /// Sender process recreations.
    pub sender_restarts: u64,
    /// Receiver durable reopens.
    pub receiver_restarts: u64,
    /// Receiver state discards used by full-restart comparison.
    pub receiver_full_restarts: u64,
}

/// Volatile sender endpoint backed by immutable prepared bytes.
pub struct Sender {
    representation: PreparedRepresentation,
    source_id: [u8; 32],
    state: SenderState,
}

impl Sender {
    /// Recreate a sender from exact prepared bytes and an application source identity.
    pub fn new(representation: PreparedRepresentation, source_id: [u8; 32]) -> Self {
        Self {
            representation,
            source_id,
            state: SenderState::Available,
        }
    }

    fn authorize(&self, source: AuthorizedSource) -> Result<(), Error> {
        if source.source_id == self.source_id
            && source.representation_id == self.representation.descriptor.representation_id
        {
            Ok(())
        } else {
            Err(Error::UnauthorizedSource)
        }
    }

    fn prepare_for_request(&mut self) -> Result<(), Error> {
        if self.state == SenderState::Available {
            self.state = self.state.transition(SenderState::Offered)?;
        }
        if self.state == SenderState::Offered {
            self.state = self.state.transition(SenderState::Requested)?;
        }
        Ok(())
    }
}

/// Receiver endpoint combining protocol and representation durable stores.
pub struct Receiver {
    protocol: ProtocolStore,
    representation: RepresentationStore,
}

impl Receiver {
    /// Reopen exact durable endpoint state.
    pub fn open(
        root: impl AsRef<Path>,
        descriptor: RepresentationDescriptor,
    ) -> Result<Self, Error> {
        Self::open_with_fault(root, descriptor, None)
    }

    /// Reopen with one injected representation durable-boundary failure.
    pub fn open_with_fault(
        root: impl AsRef<Path>,
        descriptor: RepresentationDescriptor,
        fail_after: Option<DurableBoundary>,
    ) -> Result<Self, Error> {
        Ok(Self {
            protocol: ProtocolStore::open(root.as_ref().join("protocol"))?,
            representation: RepresentationStore::open_with_fault(
                root.as_ref().join("representations"),
                descriptor,
                fail_after,
            )?,
        })
    }

    /// Durable representation snapshot.
    pub fn snapshot(&self) -> RepresentationSnapshot {
        self.representation.snapshot()
    }

    /// Read exact committed bytes.
    pub fn read_complete(&self) -> Result<Vec<u8>, Error> {
        Ok(self.representation.read_complete()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Delivery {
    NotAdmitted,
    Lost,
    Malformed,
    Delivered(Box<Record>),
}

fn experimental_capabilities(
    descriptor: &RepresentationDescriptor,
    carrier_record_limit: usize,
) -> Capabilities {
    let max_operation_octets =
        u32::try_from(carrier_record_limit.min(bempic_sync::v01::MAX_EXPERIMENTAL_RECORD_OCTETS))
            .expect("experimental maximum fits u32");
    Capabilities {
        protocol_generations: vec![ProtocolGeneration { major: 0, minor: 1 }],
        schema_fingerprints: vec![descriptor.schema_fingerprint],
        codec_preferences: vec![CodecPreference {
            codec_id: descriptor.codec_id,
            revision: descriptor.codec_revision,
            schema_fingerprint: descriptor.schema_fingerprint,
        }],
        max_operation_octets,
        max_data_payload_octets: descriptor.encoded_length.max(1),
        receipt_levels: 0b1111,
        security_class: SecurityClass::Public,
        extensions: Vec::new(),
    }
}

fn collection_entry(descriptor: &RepresentationDescriptor) -> CollectionEntry {
    CollectionEntry {
        sequence: 1,
        object_id: ObjectId::fixture(b"bempic-v01-integrated-body"),
        part_id: 1,
        descriptor: descriptor.clone(),
    }
}

fn summary_and_offer(
    descriptor: &RepresentationDescriptor,
) -> Result<(Summary, Offer), bempic_sync::v01::Error> {
    let entry = collection_entry(descriptor);
    let summary = collection_checkpoint(COLLECTION_ID, 1, std::slice::from_ref(&entry))?;
    let key = entry.key();
    Ok((
        summary,
        Offer {
            collection_id: COLLECTION_ID,
            mode: OfferMode::Full,
            base_generation: 0,
            target_generation: 1,
            first_cursor: Cursor::Full(key),
            last_cursor: Cursor::Full(key),
            descriptors: vec![entry],
            more: false,
        },
    ))
}

fn receipt_id(representation_id: RepresentationId) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"BEMPIC-REFERENCE-RECEIPT-v0.1\0");
    hasher.update(representation_id.0);
    let digest = hasher.finalize();
    digest[..16]
        .try_into()
        .expect("SHA-256 prefix is 16 octets")
}

fn validate_opaque(bytes: &[u8], descriptor: &RepresentationDescriptor) -> bool {
    descriptor.schema_fingerprint
        == fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX)
            .expect("published opaque fingerprint is valid")
        && descriptor.decoded_length.is_none()
        && bytes.len() as u64 == descriptor.encoded_length
}

fn effective_record_limit(
    carrier: &DeterministicCarrier,
    profile: Option<&NegotiatedProfile>,
) -> usize {
    let negotiated = profile.map_or(bempic_sync::v01::MAX_EXPERIMENTAL_RECORD_OCTETS, |value| {
        value.max_operation_octets as usize
    });
    carrier.opportunity().max_record_bytes.min(negotiated)
}

fn submit(
    carrier: &mut DeterministicCarrier,
    profile: Option<&NegotiatedProfile>,
    record: &Record,
    direction: Direction,
    mutation: DeliveredDataMutation,
    accounting: &mut Accounting,
) -> Result<Delivery, Error> {
    let expected = record.exact_encoded_size()?;
    let encoded = record.encode()?;
    if encoded.len() != expected {
        return Err(Error::ExactSizeMismatch);
    }
    if encoded.len() > effective_record_limit(carrier, profile)
        || encoded.len() as u64 > carrier.opportunity().remaining_bempic_bytes
    {
        return Ok(Delivery::NotAdmitted);
    }
    accounting.predicted_bempic_octets += expected as u64;
    accounting.deterministic_size_checks += 1;
    let carrier_direction = match direction {
        Direction::SenderToReceiver => CarrierDirection::SenderToReceiver,
        Direction::ReceiverToSender => CarrierDirection::ReceiverToSender,
    };
    let outcome = carrier.transmit(carrier_direction, &encoded)?;
    let actual = outcome.bempic_bytes;
    match direction {
        Direction::SenderToReceiver => {
            accounting.sender_to_receiver_bempic_octets += actual;
            accounting.carrier_sender_to_receiver_octets += outcome.carrier_bytes;
        }
        Direction::ReceiverToSender => {
            accounting.receiver_to_sender_bempic_octets += actual;
            accounting.carrier_receiver_to_sender_octets += outcome.carrier_bytes;
        }
    }
    *accounting
        .operation_octets
        .entry(record.operation.name().to_owned())
        .or_default() += actual;
    accounting.quote_prediction_error_octets += i64::try_from(actual)
        .and_then(|actual| i64::try_from(expected).map(|expected| actual - expected))
        .map_err(|_| Error::Length)?;
    if let Operation::Data(data) = &record.operation {
        accounting.representation_payload_submitted_octets += data.payload.len() as u64;
    }
    if !outcome.delivered {
        return Ok(Delivery::Lost);
    }
    let mut delivered = encoded;
    match mutation {
        DeliveredDataMutation::None => {}
        DeliveredDataMutation::TruncateRecord => {
            delivered.pop();
        }
        DeliveredDataMutation::CorruptPayload => {
            if delivered.len() > ENVELOPE_DATA_PAYLOAD_OFFSET {
                delivered[ENVELOPE_DATA_PAYLOAD_OFFSET] ^= 0xff;
            }
        }
    }
    if let Ok(decoded) = Record::decode(&delivered, &BTreeSet::new()) {
        if let Operation::Data(data) = &decoded.operation {
            accounting.representation_payload_delivered_octets += data.payload.len() as u64;
        }
        Ok(Delivery::Delivered(Box::new(decoded)))
    } else {
        accounting.strict_decode_failures += 1;
        Ok(Delivery::Malformed)
    }
}

/// Advance one full-width representation through one deterministic contact.
#[allow(clippy::too_many_lines)]
pub fn run_contact(
    sender: &mut Sender,
    receiver: &mut Receiver,
    plan: ContactPlan,
    peer_profile_id: [u8; 32],
    now: u64,
) -> Result<ContactReport, Error> {
    sender.authorize(plan.source)?;
    if sender.representation.descriptor != receiver.snapshot().descriptor {
        return Err(Error::IdentityConflict);
    }
    let mut carrier = DeterministicCarrier::new(plan.carrier)?;
    let mut accounting = Accounting::default();
    let before = receiver.snapshot().durable_prefix_octets;

    let mut profile = receiver
        .protocol
        .cached_negotiation(peer_profile_id, now)
        .cloned();
    if profile.is_none() {
        let local = experimental_capabilities(
            &sender.representation.descriptor,
            plan.carrier.max_record_bytes,
        );
        let remote = local.clone();
        let outbound = Record {
            operation: Operation::Capabilities(local),
            extensions: Vec::new(),
        };
        let Delivery::Delivered(decoded_local) = submit(
            &mut carrier,
            None,
            &outbound,
            Direction::SenderToReceiver,
            DeliveredDataMutation::None,
            &mut accounting,
        )?
        else {
            return Ok(contact_report(
                plan, before, receiver, accounting, &carrier, sender,
            ));
        };
        let inbound = Record {
            operation: Operation::Capabilities(remote),
            extensions: Vec::new(),
        };
        let Delivery::Delivered(decoded_remote) = submit(
            &mut carrier,
            None,
            &inbound,
            Direction::ReceiverToSender,
            DeliveredDataMutation::None,
            &mut accounting,
        )?
        else {
            return Ok(contact_report(
                plan, before, receiver, accounting, &carrier, sender,
            ));
        };
        let (Operation::Capabilities(local), Operation::Capabilities(remote)) =
            (decoded_local.operation, decoded_remote.operation)
        else {
            return Err(Error::OperationMismatch);
        };
        let selected = negotiate(&local, &remote).map_err(Error::Negotiation)?;
        receiver.protocol.persist_negotiation(
            peer_profile_id,
            now.saturating_add(86_400),
            selected.clone(),
        )?;
        profile = Some(selected);
    }
    let profile_ref = profile.as_ref().expect("profile selected above");

    if !receiver.snapshot().descriptor_accepted {
        let (summary, offer) = summary_and_offer(&sender.representation.descriptor)?;
        let summary_record = Record {
            operation: Operation::Summary(summary),
            extensions: Vec::new(),
        };
        if !matches!(
            submit(
                &mut carrier,
                Some(profile_ref),
                &summary_record,
                Direction::SenderToReceiver,
                DeliveredDataMutation::None,
                &mut accounting,
            )?,
            Delivery::Delivered(_)
        ) {
            return Ok(contact_report(
                plan, before, receiver, accounting, &carrier, sender,
            ));
        }
        let offer_record = Record {
            operation: Operation::Offer(offer),
            extensions: Vec::new(),
        };
        let Delivery::Delivered(decoded_offer) = submit(
            &mut carrier,
            Some(profile_ref),
            &offer_record,
            Direction::SenderToReceiver,
            DeliveredDataMutation::None,
            &mut accounting,
        )?
        else {
            return Ok(contact_report(
                plan, before, receiver, accounting, &carrier, sender,
            ));
        };
        let Operation::Offer(decoded_offer) = decoded_offer.operation else {
            return Err(Error::OperationMismatch);
        };
        let descriptor = &decoded_offer
            .descriptors
            .first()
            .ok_or(Error::OperationMismatch)?
            .descriptor;
        receiver.representation.accept_descriptor(descriptor)?;
        sender.state = sender.state.transition(SenderState::Offered)?;
    }

    let snapshot = receiver.snapshot();
    if !snapshot.committed && snapshot.durable_prefix_octets == snapshot.descriptor.encoded_length {
        match receiver.representation.verify_staged_with(validate_opaque) {
            Ok(true) => {
                if receiver.representation.commit_verified()? {
                    accounting.useful_committed_octets += snapshot.descriptor.encoded_length;
                }
            }
            Ok(false) => {}
            Err(RepresentationStoreError::IntegrityOrDecode) => {
                accounting.integrity_or_representation_decode_failures += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let snapshot = receiver.snapshot();
    if !snapshot.committed {
        let remaining = snapshot
            .descriptor
            .encoded_length
            .saturating_sub(snapshot.durable_prefix_octets);
        let opportunity = carrier.opportunity();
        let placeholder = RepresentationDataRequest {
            budget_id: receipt_id(snapshot.descriptor.representation_id),
            max_total_bempic_bytes: opportunity.remaining_bempic_bytes,
            max_sender_to_receiver_bytes: opportunity.remaining_bempic_bytes,
            max_receiver_to_sender_bytes: opportunity.remaining_bempic_bytes,
            selections: vec![RepresentationSelection {
                representation_id: snapshot.descriptor.representation_id,
                durable_prefix_offset: snapshot.durable_prefix_octets,
                max_desired_payload_octets: 1,
            }],
        };
        let placeholder_record = Record {
            operation: Operation::Request(Request::RepresentationData(placeholder)),
            extensions: Vec::new(),
        };
        let request_octets = placeholder_record.exact_encoded_size()? as u64;
        let data_overhead = Record {
            operation: Operation::Data(Data {
                representation_id: snapshot.descriptor.representation_id,
                offset: snapshot.durable_prefix_octets,
                payload: vec![0],
            }),
            extensions: Vec::new(),
        }
        .exact_encoded_size()?
        .saturating_sub(1);
        let payload_limit = remaining
            .min(profile_ref.max_data_payload_octets)
            .min(
                effective_record_limit(&carrier, Some(profile_ref)).saturating_sub(data_overhead)
                    as u64,
            )
            .min(
                opportunity
                    .remaining_bempic_bytes
                    .saturating_sub(request_octets + data_overhead as u64),
            );
        if payload_limit > 0 {
            let request = RepresentationDataRequest {
                selections: vec![RepresentationSelection {
                    representation_id: snapshot.descriptor.representation_id,
                    durable_prefix_offset: snapshot.durable_prefix_octets,
                    max_desired_payload_octets: payload_limit,
                }],
                ..placeholder_record_request(&placeholder_record)?
            };
            let offered = BTreeMap::from([(
                snapshot.descriptor.representation_id,
                snapshot.descriptor.encoded_length,
            )]);
            request.validate(&offered).map_err(Error::Negotiation)?;
            let request_record = Record {
                operation: Operation::Request(Request::RepresentationData(request.clone())),
                extensions: Vec::new(),
            };
            let mut scope = BudgetScope::new(&request);
            let request_size = request_record.exact_encoded_size()? as u64;
            if scope.admit(Direction::ReceiverToSender, request_size) {
                let Delivery::Delivered(decoded_request) = submit(
                    &mut carrier,
                    Some(profile_ref),
                    &request_record,
                    Direction::ReceiverToSender,
                    DeliveredDataMutation::None,
                    &mut accounting,
                )?
                else {
                    return Ok(contact_report(
                        plan, before, receiver, accounting, &carrier, sender,
                    ));
                };
                let Operation::Request(Request::RepresentationData(decoded_request)) =
                    decoded_request.operation
                else {
                    return Err(Error::OperationMismatch);
                };
                decoded_request
                    .validate(&offered)
                    .map_err(Error::Negotiation)?;
                sender.prepare_for_request()?;
                sender.state = sender.state.transition(SenderState::Sending)?;

                let start =
                    usize::try_from(snapshot.durable_prefix_octets).map_err(|_| Error::Length)?;
                let end = start
                    .checked_add(usize::try_from(payload_limit).map_err(|_| Error::Length)?)
                    .ok_or(Error::Length)?;
                let data = Record {
                    operation: Operation::Data(Data {
                        representation_id: snapshot.descriptor.representation_id,
                        offset: snapshot.durable_prefix_octets,
                        payload: sender.representation.bytes[start..end].to_vec(),
                    }),
                    extensions: Vec::new(),
                };
                let data_size = data.exact_encoded_size()? as u64;
                if scope.admit(Direction::SenderToReceiver, data_size) {
                    let carrier_before = carrier.metrics().carrier_bytes;
                    let bempic_before = accounting.total_bempic_octets();
                    let delivery = submit(
                        &mut carrier,
                        Some(profile_ref),
                        &data,
                        Direction::SenderToReceiver,
                        plan.data_mutation,
                        &mut accounting,
                    )?;
                    if matches!(delivery, Delivery::Delivered(_))
                        && accounting
                            .carrier_octets_before_first_body_payload
                            .is_none()
                    {
                        accounting.bempic_octets_before_first_body_payload = Some(bempic_before);
                        accounting.bempic_octets_through_first_body_payload =
                            Some(accounting.total_bempic_octets());
                        accounting.carrier_octets_before_first_body_payload = Some(carrier_before);
                        accounting.carrier_octets_through_first_body_payload =
                            Some(carrier.metrics().carrier_bytes);
                        accounting.first_body_payload_octets = Some(payload_limit);
                    }
                    if let Delivery::Delivered(decoded_data) = delivery {
                        accept_decoded_data(receiver, *decoded_data, &mut accounting)?;
                        for _ in 0..plan.replay_data_records {
                            if !scope.admit(Direction::SenderToReceiver, data_size) {
                                break;
                            }
                            if let Delivery::Delivered(replayed) = submit(
                                &mut carrier,
                                Some(profile_ref),
                                &data,
                                Direction::SenderToReceiver,
                                DeliveredDataMutation::None,
                                &mut accounting,
                            )? {
                                accept_decoded_data(receiver, *replayed, &mut accounting)?;
                            }
                        }
                    }
                }
            }
        }
    }

    let snapshot = receiver.snapshot();
    if !snapshot.committed && snapshot.durable_prefix_octets == snapshot.descriptor.encoded_length {
        match receiver.representation.verify_staged_with(validate_opaque) {
            Ok(true) => {
                if receiver.representation.commit_verified()? {
                    accounting.useful_committed_octets += snapshot.descriptor.encoded_length;
                }
            }
            Ok(false) => {}
            Err(RepresentationStoreError::IntegrityOrDecode) => {
                accounting.integrity_or_representation_decode_failures += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let receipt = receipt_id(sender.representation.descriptor.representation_id);
    if receiver.snapshot().committed && !receiver.representation.has_receipt(receipt) {
        if sender.state == SenderState::Sending {
            sender.state = sender.state.transition(SenderState::AwaitingReceipt)?;
        }
        let record = Record {
            operation: Operation::Receipt(Receipt {
                subject_id: sender.representation.descriptor.representation_id.0,
                status: ReceiptStatus::RepresentationCommitted,
                verified_digest: Some(sender.representation.descriptor.content_digest),
                idempotency_id: receipt,
                reason: None,
            }),
            extensions: Vec::new(),
        };
        if matches!(
            submit(
                &mut carrier,
                Some(profile_ref),
                &record,
                Direction::ReceiverToSender,
                DeliveredDataMutation::None,
                &mut accounting,
            )?,
            Delivery::Delivered(_)
        ) {
            receiver.representation.commit_receipt(receipt)?;
            if sender.state == SenderState::AwaitingReceipt {
                sender.state = sender.state.transition(SenderState::Receipted)?;
            }
        }
    }

    Ok(contact_report(
        plan, before, receiver, accounting, &carrier, sender,
    ))
}

fn placeholder_record_request(record: &Record) -> Result<RepresentationDataRequest, Error> {
    let Operation::Request(Request::RepresentationData(request)) = &record.operation else {
        return Err(Error::OperationMismatch);
    };
    Ok(request.clone())
}

fn accept_decoded_data(
    receiver: &mut Receiver,
    record: Record,
    accounting: &mut Accounting,
) -> Result<(), Error> {
    let Operation::Data(data) = record.operation else {
        return Err(Error::OperationMismatch);
    };
    let outcome =
        receiver
            .representation
            .accept_data(data.representation_id, data.offset, &data.payload)?;
    accounting.duplicate_payload_octets += outcome.duplicate_octets;
    Ok(())
}

fn contact_report(
    plan: ContactPlan,
    before: u64,
    receiver: &Receiver,
    accounting: Accounting,
    carrier: &DeterministicCarrier,
    sender: &Sender,
) -> ContactReport {
    let receipt = receipt_id(receiver.snapshot().descriptor.representation_id);
    ContactReport {
        plan,
        durable_prefix_before: before,
        durable_prefix_after: receiver.snapshot().durable_prefix_octets,
        committed: receiver.snapshot().committed,
        receipt_committed: receiver.representation.has_receipt(receipt),
        accounting,
        carrier: carrier.metrics().clone(),
        sender_state: sender.state,
    }
}

/// Run deterministic contacts with sender-only, receiver-only, both, cold, and full restarts.
pub fn run_until_complete(
    root: impl AsRef<Path>,
    representation: &PreparedRepresentation,
    plans: &[ContactPlan],
    max_contacts: usize,
) -> Result<TransferReport, Error> {
    if plans.is_empty() {
        return Err(Error::NoContacts);
    }
    let persistent_root = root.as_ref().join("persistent");
    let first = plans[0];
    let mut sender = Sender::new(representation.clone(), first.source.source_id);
    let mut receiver = Receiver::open(&persistent_root, representation.descriptor.clone())?;
    let mut reports = Vec::new();
    let mut accounting = Accounting::default();
    let mut carrier = CarrierMetrics::default();
    let mut sender_restarts = 0_u64;
    let mut receiver_restarts = 0_u64;
    let mut receiver_full_restarts = 0_u64;
    let peer_profile_id = [0x50; 32];

    for number in 0..max_contacts {
        let plan = plans[number % plans.len()];
        if number > 0 && plan.restart_before.sender() {
            sender = Sender::new(representation.clone(), plan.source.source_id);
            sender_restarts += 1;
        } else {
            sender.source_id = plan.source.source_id;
        }
        if plan.discard_receiver_state {
            receiver = Receiver::open(
                root.as_ref().join("full-restart").join(number.to_string()),
                representation.descriptor.clone(),
            )?;
            receiver_full_restarts += u64::from(number > 0);
        } else if number > 0 && plan.restart_before.receiver() {
            receiver = Receiver::open(&persistent_root, representation.descriptor.clone())?;
            receiver_restarts += 1;
        }
        let report = run_contact(
            &mut sender,
            &mut receiver,
            plan,
            peer_profile_id,
            number as u64,
        )?;
        accounting.merge(&report.accounting);
        carrier.merge(&report.carrier);
        let complete = report.receipt_committed;
        reports.push(report);
        if complete {
            return Ok(TransferReport {
                contacts: reports,
                accounting,
                carrier,
                reconstructed: receiver.read_complete()?,
                sender_restarts,
                receiver_restarts,
                receiver_full_restarts,
            });
        }
    }
    Err(Error::ContactLimit(max_contacts))
}

/// Integrated v0.1 simulation failure.
#[derive(Debug, Error)]
pub enum Error {
    /// No contact plans were supplied.
    #[error("at least one v0.1 contact plan is required")]
    NoContacts,
    /// Source authorization fact did not match the sender and representation.
    #[error("application source authorization does not match the representation")]
    UnauthorizedSource,
    /// Sender and receiver descriptors differed.
    #[error("sender and receiver representation descriptors differ")]
    IdentityConflict,
    /// Strictly decoded operation did not match the expected phase.
    #[error("decoded operation does not match the expected phase")]
    OperationMismatch,
    /// Exact sizing and emitted bytes differed.
    #[error("deterministic encoded size differs from emitted length")]
    ExactSizeMismatch,
    /// Integer length could not be represented safely.
    #[error("length cannot be represented safely")]
    Length,
    /// Negotiation or request validation failed.
    #[error("v0.1 negotiation/request failed: {0:?}")]
    Negotiation(FailureCode),
    /// Transfer did not complete in the bounded contact count.
    #[error("v0.1 transfer did not finish in {0} contacts")]
    ContactLimit(usize),
    /// Deterministic carrier failed.
    #[error(transparent)]
    Carrier(#[from] bempic_carrier::CarrierError),
    /// Carrier configuration or legacy simulator initialization failed.
    #[error(transparent)]
    Simulation(#[from] SimulationError),
    /// Experimental operation codec failed.
    #[error(transparent)]
    Sync(#[from] bempic_sync::v01::Error),
    /// Protocol-state persistence failed.
    #[error(transparent)]
    ProtocolStore(#[from] ProtocolStoreError),
    /// Representation persistence failed.
    #[error(transparent)]
    RepresentationStore(#[from] RepresentationStoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn prepared(size: usize) -> PreparedRepresentation {
        let bytes = (0_u8..=255).cycle().take(size).collect::<Vec<_>>();
        PreparedRepresentation::prepare(
            bytes,
            None,
            fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).unwrap(),
            0x0001_0000,
            1,
            Vec::new(),
            None,
        )
        .unwrap()
    }

    fn config(
        byte_budget: u64,
        max_record_bytes: usize,
        disconnect_after_ms: Option<u64>,
    ) -> CarrierConfig {
        CarrierConfig {
            byte_budget,
            bandwidth_bps: 9_600,
            latency_ms: 20,
            disconnect_after_ms,
            max_record_bytes,
            carrier_overhead_bytes: 8,
            reliable: true,
        }
    }

    fn plan(
        representation: &PreparedRepresentation,
        source: u8,
        restart_before: EndpointRestart,
        byte_budget: u64,
    ) -> ContactPlan {
        ContactPlan {
            carrier: config(byte_budget, 512, None),
            restart_before,
            discard_receiver_state: false,
            source: AuthorizedSource {
                source_id: [source; 32],
                representation_id: representation.descriptor.representation_id,
            },
            data_mutation: DeliveredDataMutation::None,
            replay_data_records: 0,
        }
    }

    #[test]
    fn full_width_descriptor_records_transport_decode_commit_resume_and_accounting() {
        let root = tempdir().unwrap();
        let representation = prepared(2_048);
        let plans = [
            plan(&representation, 1, EndpointRestart::Neither, 700),
            plan(&representation, 1, EndpointRestart::SenderOnly, 700),
            plan(&representation, 2, EndpointRestart::Both, 700),
        ];
        let run = run_until_complete(root.path(), &representation, &plans, 32).unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert_eq!(
            run.accounting.useful_committed_octets,
            representation.descriptor.encoded_length
        );
        assert_eq!(run.accounting.quote_prediction_error_octets, 0);
        assert_eq!(
            run.accounting.total_bempic_octets(),
            run.accounting.predicted_bempic_octets
        );
        assert!(run.accounting.protocol_overhead_octets() > 0);
        assert!(run.accounting.total_carrier_octets() > run.accounting.total_bempic_octets());
        assert!(run
            .accounting
            .carrier_octets_before_first_body_payload
            .is_some());
        assert!(run.sender_restarts > 0);
        assert!(run.receiver_restarts > 0);
    }

    #[test]
    fn zero_length_full_width_representation_commits_without_data() {
        let root = tempdir().unwrap();
        let representation = prepared(0);
        let run = run_until_complete(
            root.path(),
            &representation,
            &[plan(&representation, 2, EndpointRestart::Neither, 2_000)],
            2,
        )
        .unwrap();
        assert!(run.reconstructed.is_empty());
        assert_eq!(run.accounting.representation_payload_submitted_octets, 0);
        assert_eq!(run.accounting.representation_payload_delivered_octets, 0);
        assert_eq!(run.accounting.useful_committed_octets, 0);
        assert!(run.accounting.operation_octets.contains_key("RECEIPT"));
        assert!(!run.accounting.operation_octets.contains_key("REQUEST"));
        assert!(!run.accounting.operation_octets.contains_key("DATA"));
    }

    #[test]
    fn sender_receiver_and_both_restart_modes_share_one_durable_prefix() {
        let root = tempdir().unwrap();
        let representation = prepared(4_096);
        let plans = [
            plan(&representation, 9, EndpointRestart::Neither, 700),
            plan(&representation, 9, EndpointRestart::SenderOnly, 700),
            plan(&representation, 9, EndpointRestart::ReceiverOnly, 700),
            plan(&representation, 9, EndpointRestart::Both, 700),
        ];
        let run = run_until_complete(root.path(), &representation, &plans, 64).unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert!(run.sender_restarts >= 2);
        assert!(run.receiver_restarts >= 2);
        assert!(run
            .contacts
            .windows(2)
            .all(|pair| pair[0].durable_prefix_after <= pair[1].durable_prefix_after));
    }

    #[test]
    fn repeated_interruptions_and_both_endpoint_cold_restarts_resume() {
        let root = tempdir().unwrap();
        let representation = prepared(1_024);
        let mut interrupted = plan(&representation, 3, EndpointRestart::Both, 700);
        interrupted.carrier.disconnect_after_ms = Some(80);
        let clean = plan(&representation, 4, EndpointRestart::Both, 700);
        let run =
            run_until_complete(root.path(), &representation, &[interrupted, clean], 32).unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert!(run.carrier.lost_records > 0);
        assert!(run.sender_restarts > 0);
        assert!(run.receiver_restarts > 0);
    }

    #[test]
    fn duplicate_replayed_data_is_counted_and_idempotent() {
        let root = tempdir().unwrap();
        let representation = prepared(180);
        let mut replay = plan(&representation, 5, EndpointRestart::Neither, 2_000);
        replay.replay_data_records = 1;
        let run = run_until_complete(root.path(), &representation, &[replay], 4).unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert_eq!(
            run.accounting.duplicate_payload_octets,
            representation.descriptor.encoded_length
        );
        assert_eq!(
            run.accounting.representation_payload_delivered_octets,
            representation.descriptor.encoded_length * 2
        );
    }

    #[test]
    fn truncated_and_corrupt_data_never_commit_and_clean_retry_recovers() {
        let truncated_root = tempdir().unwrap();
        let representation = prepared(240);
        let mut truncated = plan(&representation, 6, EndpointRestart::Neither, 2_000);
        truncated.data_mutation = DeliveredDataMutation::TruncateRecord;
        let clean = plan(&representation, 6, EndpointRestart::Both, 2_000);
        let run = run_until_complete(
            truncated_root.path(),
            &representation,
            &[truncated, clean],
            8,
        )
        .unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert_eq!(run.accounting.strict_decode_failures, 1);

        let corrupt_root = tempdir().unwrap();
        let mut corrupt = plan(&representation, 7, EndpointRestart::Neither, 2_000);
        corrupt.data_mutation = DeliveredDataMutation::CorruptPayload;
        let run =
            run_until_complete(corrupt_root.path(), &representation, &[corrupt, clean], 8).unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert_eq!(
            run.accounting.integrity_or_representation_decode_failures,
            1
        );
    }

    #[test]
    fn full_restart_costs_more_than_persistent_resume() {
        let representation = prepared(900);
        let persistent_root = tempdir().unwrap();
        let mut partial = plan(&representation, 8, EndpointRestart::Both, 1_200);
        partial.carrier.max_record_bytes = 2_048;
        let mut finishing = plan(&representation, 8, EndpointRestart::Both, 5_000);
        finishing.carrier.max_record_bytes = 2_048;
        let plans = [partial, finishing];
        let persistent =
            run_until_complete(persistent_root.path(), &representation, &plans, 8).unwrap();

        let full_root = tempdir().unwrap();
        let mut full_plans = plans;
        full_plans[0].discard_receiver_state = true;
        full_plans[1].discard_receiver_state = true;
        let full = run_until_complete(full_root.path(), &representation, &full_plans, 8).unwrap();
        assert_eq!(persistent.reconstructed, representation.bytes);
        assert_eq!(full.reconstructed, representation.bytes);
        assert!(
            full.accounting.representation_payload_submitted_octets
                > persistent
                    .accounting
                    .representation_payload_submitted_octets
        );
        assert!(
            full.accounting.total_carrier_octets() > persistent.accounting.total_carrier_octets()
        );
        assert!(full.receiver_full_restarts > 0);
    }
}
