//! BEMPIC protocol-generation 0.1 semantics.
//!
//! The binary image in this module is an experimental reference profile. It
//! proves bounds, exact sizing, strict decoding, vectors, and state behavior;
//! it is not a registered or stable BEMPIC wire format.

use bempic_model::v01::{
    ContentDigest, ObjectId, RepresentationDescriptor, RepresentationId, SchemaFingerprint,
    MAX_CODEC_PARAMETER_OCTETS, MAX_OPERATION_OCTETS, MAX_REPRESENTATION_OCTETS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAGIC: &[u8; 2] = b"B1";
const ENVELOPE_OCTETS: usize = 7;
const MAX_CAPABILITY_PROTOCOLS: usize = 8;
const MAX_CAPABILITY_SCHEMAS: usize = 16;
const MAX_CAPABILITY_CODECS: usize = 16;
const MAX_EXTENSIONS: usize = 32;
const MAX_EXTENSION_VALUE_OCTETS: usize = 1_024;
const MAX_OFFER_DESCRIPTORS: usize = 128;
const MAX_REQUEST_SELECTIONS: usize = 128;
const MAX_COLLECTION_ENTRIES: usize = 1_000_000;
const MAX_FAILURE_DETAIL_OCTETS: usize = 256;
const MAX_FAILURE_SCOPE_OCTETS: usize = 64;

/// Maximum encoded record in the disposable generation-0.1 codec profile.
pub const MAX_EXPERIMENTAL_RECORD_OCTETS: usize = 1_048_576;

/// Operation kind used by declared maximum-size analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Capability negotiation.
    Capabilities,
    /// Collection summary.
    Summary,
    /// Offer page.
    Offer,
    /// Either request variant.
    Request,
    /// Representation data.
    Data,
    /// Semantic receipt.
    Receipt,
    /// Scoped failure.
    Failure,
}

/// Proven conservative maximum for each disposable codec operation.
///
/// The analysis includes the seven-byte envelope and the worst permitted set
/// of 32 extension fields of 1,024 octets each. `DATA` uses the global profile
/// maximum because its payload consumes all remaining space.
pub const fn declared_max_encoded_size(kind: OperationKind) -> usize {
    match kind {
        OperationKind::Capabilities => 34_362,
        OperationKind::Summary => 33_080,
        OperationKind::Offer => 186_789,
        OperationKind::Request => 39_186,
        OperationKind::Data => MAX_EXPERIMENTAL_RECORD_OCTETS,
        OperationKind::Receipt => 33_341,
        OperationKind::Failure => 33_326,
    }
}

/// Volatile compatibility state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CompatibilityState {
    /// No active contact negotiation.
    Idle,
    /// Capabilities are being compared.
    Negotiating,
    /// A complete tuple is selected.
    Compatible,
    /// No complete tuple exists.
    Incompatible,
}

impl CompatibilityState {
    /// Apply one legal compatibility transition.
    pub fn transition(self, next: Self) -> Result<Self, Error> {
        if matches!(
            (self, next),
            (Self::Idle, Self::Negotiating)
                | (
                    Self::Negotiating,
                    Self::Compatible | Self::Incompatible | Self::Idle
                )
                | (Self::Compatible | Self::Incompatible, Self::Idle)
        ) {
            Ok(next)
        } else {
            Err(Error::InvalidTransition("compatibility"))
        }
    }
}

/// Durable/volatile collection reconciliation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CollectionState {
    /// Checkpoint has not been compared.
    Unchecked,
    /// Checkpoint equals the authority.
    Equal,
    /// Bounded offer pages are in progress.
    Reconciling,
    /// Target checkpoint is committed; application may select.
    Selecting,
    /// Target generation failed without replacing the prior checkpoint.
    Failed,
}

impl CollectionState {
    /// Apply one legal collection transition.
    pub fn transition(self, next: Self) -> Result<Self, Error> {
        if matches!(
            (self, next),
            (Self::Unchecked, Self::Equal | Self::Reconciling)
                | (
                    Self::Reconciling,
                    Self::Selecting | Self::Reconciling | Self::Failed
                )
                | (Self::Failed, Self::Unchecked)
        ) {
            Ok(next)
        } else {
            Err(Error::InvalidTransition("collection"))
        }
    }
}

/// Durable receiver representation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RepresentationState {
    /// No accepted descriptor.
    Absent,
    /// Descriptor is accepted; no bytes are durable.
    Offered,
    /// A proper contiguous prefix is durable.
    Partial,
    /// Exact advertised length is durable but unverified.
    CompleteUnverified,
    /// Length, digest, ID, schema, and decode checks passed.
    Verified,
    /// Verified bytes were atomically committed.
    Committed,
    /// Representation or application policy rejected the object.
    Rejected,
}

impl RepresentationState {
    /// Apply one legal receiver transition; committed state is immutable.
    pub fn transition(self, next: Self) -> Result<Self, Error> {
        if matches!(
            (self, next),
            (Self::Absent, Self::Offered | Self::Rejected)
                | (
                    Self::Offered | Self::Partial,
                    Self::Partial | Self::CompleteUnverified
                )
                | (
                    Self::Offered | Self::Partial | Self::CompleteUnverified | Self::Verified,
                    Self::Rejected,
                )
                | (Self::CompleteUnverified, Self::Verified)
                | (Self::Verified, Self::Committed)
        ) {
            Ok(next)
        } else {
            Err(Error::InvalidTransition("representation"))
        }
    }
}

/// Sender-observable representation progression.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SenderState {
    /// Prepared bytes are locally available.
    Available,
    /// Descriptor was offered.
    Offered,
    /// Explicit data request was accepted.
    Requested,
    /// Data operations are being emitted.
    Sending,
    /// All authorized data was sent; receipt is pending.
    AwaitingReceipt,
    /// An idempotent receipt was retained.
    Receipted,
}

impl SenderState {
    /// Apply one legal forward transition.
    pub fn transition(self, next: Self) -> Result<Self, Error> {
        if matches!(
            (self, next),
            (Self::Available, Self::Offered)
                | (Self::Offered, Self::Requested)
                | (Self::Requested | Self::Sending, Self::Sending)
                | (Self::Sending, Self::AwaitingReceipt)
                | (Self::AwaitingReceipt, Self::Receipted)
        ) {
            Ok(next)
        } else {
            Err(Error::InvalidTransition("sender"))
        }
    }

    /// Contact interruption returns active transfer states to available.
    #[must_use]
    pub const fn interrupted(self) -> Self {
        match self {
            Self::Requested | Self::Sending | Self::AwaitingReceipt => Self::Available,
            other => other,
        }
    }
}

/// A negotiated semantic protocol generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProtocolGeneration {
    /// Major generation.
    pub major: u16,
    /// Minor generation.
    pub minor: u16,
}

/// One codec/schema preference tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CodecPreference {
    /// Codec registry ID.
    pub codec_id: u32,
    /// Codec revision.
    pub revision: u32,
    /// Exact supported schema.
    pub schema_fingerprint: SchemaFingerprint,
}

/// Security claim negotiated for the exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityClass {
    /// No authentication or confidentiality claim.
    Public = 0,
    /// Separately registered authenticated-public profile.
    AuthenticatedPublic = 1,
    /// Separately registered confidential profile.
    Confidential = 2,
}

impl TryFrom<u8> for SecurityClass {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Public),
            1 => Ok(Self::AuthenticatedPublic),
            2 => Ok(Self::Confidential),
            _ => Err(Error::Malformed("security_class")),
        }
    }
}

/// Extension declaration included in capabilities.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ExtensionDeclaration {
    /// Registry ID.
    pub id: u32,
    /// Whether absence is incompatible.
    pub critical: bool,
}

/// A length-delimited extension attached to one record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Extension {
    /// Registry ID.
    pub id: u32,
    /// Whether an unknown implementation must reject before mutation.
    pub critical: bool,
    /// Opaque extension value.
    pub value: Vec<u8>,
}

/// Complete negotiation advertisement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Supported semantic generations.
    pub protocol_generations: Vec<ProtocolGeneration>,
    /// Supported exact schemas.
    pub schema_fingerprints: Vec<SchemaFingerprint>,
    /// Codec/schema tuples in preference order.
    pub codec_preferences: Vec<CodecPreference>,
    /// Maximum complete encoded operation.
    pub max_operation_octets: u32,
    /// Maximum representation payload inside one data operation.
    pub max_data_payload_octets: u64,
    /// Supported receipt-level bitset.
    pub receipt_levels: u8,
    /// Required security class for this exchange.
    pub security_class: SecurityClass,
    /// Supported/required extensions.
    pub extensions: Vec<ExtensionDeclaration>,
}

impl Capabilities {
    /// Validate all remotely influenced bounds and uniqueness constraints.
    pub fn validate(&self) -> Result<(), Error> {
        validate_nonempty_unique(
            &self.protocol_generations,
            MAX_CAPABILITY_PROTOCOLS,
            "protocol_generations",
        )?;
        validate_nonempty_unique(
            &self.schema_fingerprints,
            MAX_CAPABILITY_SCHEMAS,
            "schema_fingerprints",
        )?;
        validate_nonempty_unique(
            &self.codec_preferences,
            MAX_CAPABILITY_CODECS,
            "codec_preferences",
        )?;
        if self.extensions.len() > MAX_EXTENSIONS
            || self
                .extensions
                .iter()
                .map(|extension| extension.id)
                .collect::<BTreeSet<_>>()
                .len()
                != self.extensions.len()
        {
            return Err(Error::LimitExceeded("extensions"));
        }
        if self.max_operation_octets == 0
            || u64::from(self.max_operation_octets) > MAX_OPERATION_OCTETS
        {
            return Err(Error::LimitExceeded("max_operation_octets"));
        }
        if self.max_data_payload_octets == 0
            || self.max_data_payload_octets > MAX_REPRESENTATION_OCTETS
        {
            return Err(Error::LimitExceeded("max_data_payload_octets"));
        }
        if self.codec_preferences.iter().any(|preference| {
            !self
                .schema_fingerprints
                .contains(&preference.schema_fingerprint)
        }) {
            return Err(Error::Malformed("codec schema preference"));
        }
        Ok(())
    }
}

/// Result of deterministic compatibility negotiation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NegotiatedProfile {
    /// Highest identical semantic generation.
    pub protocol: ProtocolGeneration,
    /// Selected exact schema.
    pub schema_fingerprint: SchemaFingerprint,
    /// Selected codec ID.
    pub codec_id: u32,
    /// Selected codec revision.
    pub codec_revision: u32,
    /// Durable maximum complete operation.
    pub max_operation_octets: u32,
    /// Durable maximum data payload.
    pub max_data_payload_octets: u64,
    /// Common receipt levels.
    pub receipt_levels: u8,
    /// Exact security class.
    pub security_class: SecurityClass,
    /// Common extensions.
    pub extensions: Vec<u32>,
}

/// Select the deterministic highest common protocol/schema/codec tuple.
pub fn negotiate(
    local: &Capabilities,
    remote: &Capabilities,
) -> Result<NegotiatedProfile, FailureCode> {
    local
        .validate()
        .map_err(|_| FailureCode::MalformedOperation)?;
    remote
        .validate()
        .map_err(|_| FailureCode::MalformedOperation)?;
    let protocol = local
        .protocol_generations
        .iter()
        .filter(|generation| remote.protocol_generations.contains(generation))
        .max()
        .copied()
        .ok_or(FailureCode::UnsupportedVersion)?;
    if local.security_class != remote.security_class {
        return Err(FailureCode::PolicyRejected);
    }

    let mut candidates = Vec::new();
    for (local_index, local_preference) in local.codec_preferences.iter().enumerate() {
        for (remote_index, remote_preference) in remote.codec_preferences.iter().enumerate() {
            if local_preference == remote_preference {
                candidates.push((
                    local_index + remote_index,
                    local_preference.codec_id,
                    local_preference.revision,
                    local_preference.schema_fingerprint,
                ));
            }
        }
    }
    candidates.sort_unstable();
    let (_, codec_id, codec_revision, schema_fingerprint) =
        candidates.first().copied().ok_or_else(|| {
            if local
                .schema_fingerprints
                .iter()
                .any(|schema| remote.schema_fingerprints.contains(schema))
            {
                FailureCode::UnsupportedCodec
            } else {
                FailureCode::UnsupportedSchema
            }
        })?;

    for required in local
        .extensions
        .iter()
        .filter(|extension| extension.critical)
    {
        if !remote
            .extensions
            .iter()
            .any(|value| value.id == required.id)
        {
            return Err(FailureCode::UnsupportedCriticalExtension);
        }
    }
    for required in remote
        .extensions
        .iter()
        .filter(|extension| extension.critical)
    {
        if !local.extensions.iter().any(|value| value.id == required.id) {
            return Err(FailureCode::UnsupportedCriticalExtension);
        }
    }
    let mut extensions = local
        .extensions
        .iter()
        .filter(|extension| {
            remote
                .extensions
                .iter()
                .any(|value| value.id == extension.id)
        })
        .map(|extension| extension.id)
        .collect::<Vec<_>>();
    extensions.sort_unstable();
    extensions.dedup();

    Ok(NegotiatedProfile {
        protocol,
        schema_fingerprint,
        codec_id,
        codec_revision,
        max_operation_octets: local.max_operation_octets.min(remote.max_operation_octets),
        max_data_payload_octets: local
            .max_data_payload_octets
            .min(remote.max_data_payload_octets),
        receipt_levels: local.receipt_levels & remote.receipt_levels,
        security_class: local.security_class,
        extensions,
    })
}

/// Durable collection checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Collection authority ID.
    pub collection_id: [u8; 32],
    /// Append-only generation.
    pub generation: u64,
    /// Entries at or before the generation.
    pub item_count: u64,
    /// Exact collection digest.
    pub collection_digest: [u8; 32],
}

/// Canonical full-inventory entry key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct EntryKey {
    /// Logical object ID.
    pub object_id: ObjectId,
    /// Part within the object.
    pub part_id: u32,
    /// Exact representation ID.
    pub representation_id: RepresentationId,
}

/// One append-only collection entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CollectionEntry {
    /// Authority-assigned append sequence, starting at one.
    pub sequence: u64,
    /// Logical object ID.
    pub object_id: ObjectId,
    /// Part within the object.
    pub part_id: u32,
    /// Complete representation descriptor.
    pub descriptor: RepresentationDescriptor,
}

impl CollectionEntry {
    /// Canonical full-inventory key.
    pub const fn key(&self) -> EntryKey {
        EntryKey {
            object_id: self.object_id,
            part_id: self.part_id,
            representation_id: self.descriptor.representation_id,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.sequence == 0 {
            return Err(Error::Malformed("collection sequence"));
        }
        self.descriptor
            .validate()
            .map_err(|_| Error::LimitExceeded("representation descriptor"))
    }
}

/// Reconciliation page mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OfferMode {
    /// Known-checkpoint suffix ordered by authority sequence.
    Delta = 0,
    /// Bounded full inventory ordered by canonical entry key.
    Full = 1,
}

impl TryFrom<u8> for OfferMode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Delta),
            1 => Ok(Self::Full),
            _ => Err(Error::Malformed("offer mode")),
        }
    }
}

/// Durable explicit page cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Cursor {
    /// Last committed delta sequence; zero means before the first item.
    Delta(u64),
    /// Last committed full-inventory key.
    Full(EntryKey),
}

/// One bounded reconciliation offer page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    /// Collection authority ID.
    pub collection_id: [u8; 32],
    /// Delta or bounded full fallback.
    pub mode: OfferMode,
    /// Recognized base, or zero for full fallback.
    pub base_generation: u64,
    /// Authority target generation.
    pub target_generation: u64,
    /// First cursor represented by this page.
    pub first_cursor: Cursor,
    /// Last cursor represented by this page.
    pub last_cursor: Cursor,
    /// Complete descriptors, maximum 128.
    pub descriptors: Vec<CollectionEntry>,
    /// Whether another page exists.
    pub more: bool,
}

impl Offer {
    /// Validate bounds, descriptor uniqueness, ordering, and cursor consistency.
    pub fn validate(&self) -> Result<(), Error> {
        if self.descriptors.is_empty() || self.descriptors.len() > MAX_OFFER_DESCRIPTORS {
            return Err(Error::LimitExceeded("offer descriptors"));
        }
        if self.base_generation > self.target_generation {
            return Err(Error::Malformed("offer generations"));
        }
        let mut sequences = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for descriptor in &self.descriptors {
            descriptor.validate()?;
            if descriptor.sequence > self.target_generation
                || !sequences.insert(descriptor.sequence)
                || !keys.insert(descriptor.key())
            {
                return Err(Error::MetadataConflict);
            }
        }
        match self.mode {
            OfferMode::Delta => {
                if !self
                    .descriptors
                    .windows(2)
                    .all(|pair| pair[0].sequence < pair[1].sequence)
                    || self.first_cursor != Cursor::Delta(self.descriptors[0].sequence)
                    || self.last_cursor
                        != Cursor::Delta(
                            self.descriptors
                                .last()
                                .expect("non-empty descriptors validated above")
                                .sequence,
                        )
                {
                    return Err(Error::NonCanonical("delta offer order"));
                }
            }
            OfferMode::Full => {
                if !self
                    .descriptors
                    .windows(2)
                    .all(|pair| pair[0].key() < pair[1].key())
                    || self.first_cursor != Cursor::Full(self.descriptors[0].key())
                    || self.last_cursor
                        != Cursor::Full(
                            self.descriptors
                                .last()
                                .expect("non-empty descriptors validated above")
                                .key(),
                        )
                {
                    return Err(Error::NonCanonical("full offer order"));
                }
            }
        }
        Ok(())
    }
}

/// Explicit request for the next inventory page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InventoryPageRequest {
    /// Collection authority ID.
    pub collection_id: [u8; 32],
    /// Target generation being reconciled.
    pub target_generation: u64,
    /// Delta or full mode.
    pub mode: OfferMode,
    /// Last durable page cursor.
    pub committed_cursor: Cursor,
    /// Desired descriptors, one through 128.
    pub page_entry_limit: u8,
}

/// One explicitly selected representation suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepresentationSelection {
    /// Exact 32-octet representation identity.
    pub representation_id: RepresentationId,
    /// Durable contiguous prefix in octets.
    pub durable_prefix_offset: u64,
    /// Maximum desired encoded payload octets.
    pub max_desired_payload_octets: u64,
}

impl RepresentationSelection {
    /// Validate types, units, bounds, and invariants against the offered length.
    pub fn validate(&self, offered_encoded_length: u64) -> Result<(), FailureCode> {
        if offered_encoded_length > MAX_REPRESENTATION_OCTETS
            || self.durable_prefix_offset > MAX_REPRESENTATION_OCTETS
            || self.max_desired_payload_octets == 0
            || self.max_desired_payload_octets > MAX_REPRESENTATION_OCTETS
            || self.durable_prefix_offset > offered_encoded_length
            || self.max_desired_payload_octets > offered_encoded_length - self.durable_prefix_offset
        {
            return Err(FailureCode::RangeInvalid);
        }
        Ok(())
    }
}

/// Explicit representation-data authorization and hard byte scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepresentationDataRequest {
    /// Idempotent 16-octet budget ID.
    pub budget_id: [u8; 16],
    /// Maximum encoded BEMPIC bytes in both directions.
    pub max_total_bempic_bytes: u64,
    /// Maximum sender-to-receiver BEMPIC bytes.
    pub max_sender_to_receiver_bytes: u64,
    /// Maximum receiver-to-sender BEMPIC bytes.
    pub max_receiver_to_sender_bytes: u64,
    /// One through 128 unique explicit selections.
    pub selections: Vec<RepresentationSelection>,
}

impl RepresentationDataRequest {
    /// Validate request-wide bounds and every selection against offered lengths.
    pub fn validate(
        &self,
        offered_lengths: &BTreeMap<RepresentationId, u64>,
    ) -> Result<(), FailureCode> {
        if self.selections.is_empty() || self.selections.len() > MAX_REQUEST_SELECTIONS {
            return Err(FailureCode::LimitExceeded);
        }
        let mut identifiers = BTreeSet::new();
        for selection in &self.selections {
            if !identifiers.insert(selection.representation_id) {
                return Err(FailureCode::MetadataConflict);
            }
            let offered = offered_lengths
                .get(&selection.representation_id)
                .copied()
                .ok_or(FailureCode::UnknownObject)?;
            selection.validate(offered)?;
        }
        Ok(())
    }
}

/// The two request variants standardized by v0.1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Request {
    /// Explicit next-page request.
    InventoryPage(InventoryPageRequest),
    /// Explicit selected representation data.
    RepresentationData(RepresentationDataRequest),
}

/// Non-empty representation bytes at an unsigned-octet offset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Data {
    /// Exact representation ID.
    pub representation_id: RepresentationId,
    /// Offset in octets.
    pub offset: u64,
    /// Non-empty encoded representation payload.
    pub payload: Vec<u8>,
}

/// Core semantic receipt status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReceiptStatus {
    /// Exact representation is verified and atomically committed.
    RepresentationCommitted = 0,
    /// Application accepted the logical object.
    ApplicationAccepted = 1,
    /// Application completed profile-defined final delivery.
    ApplicationDelivered = 2,
    /// Application rejected the object.
    ApplicationRejected = 3,
}

impl TryFrom<u8> for ReceiptStatus {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RepresentationCommitted),
            1 => Ok(Self::ApplicationAccepted),
            2 => Ok(Self::ApplicationDelivered),
            3 => Ok(Self::ApplicationRejected),
            _ => Err(Error::Malformed("receipt status")),
        }
    }
}

/// Idempotent semantic receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    /// Full representation or object subject ID.
    pub subject_id: [u8; 32],
    /// Exact core status.
    pub status: ReceiptStatus,
    /// Digest only when semantically applicable.
    pub verified_digest: Option<ContentDigest>,
    /// Durable idempotency ID.
    pub idempotency_id: [u8; 16],
    /// Optional bounded application rejection reason.
    pub reason: Option<String>,
}

/// Core failure code allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FailureCode {
    /// No common protocol generation.
    UnsupportedVersion = 0,
    /// No exact common schema.
    UnsupportedSchema = 1,
    /// No exact common codec/revision.
    UnsupportedCodec = 2,
    /// Required extension is unknown.
    UnsupportedCriticalExtension = 3,
    /// Structural or canonical decode failure.
    MalformedOperation = 4,
    /// Declared core or negotiated bound exceeded.
    LimitExceeded = 5,
    /// Named object/representation is not offered.
    UnknownObject = 6,
    /// Immutable metadata or duplicate bytes conflict.
    MetadataConflict = 7,
    /// Offset, gap, or selection range is invalid.
    RangeInvalid = 8,
    /// Whole representation integrity failed.
    IntegrityFailure = 9,
    /// Durable storage failed.
    StorageFailure = 10,
    /// Application policy rejected the operation.
    PolicyRejected = 11,
    /// Checkpoint is not retained by the authority.
    CheckpointUnknown = 12,
}

impl TryFrom<u8> for FailureCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UnsupportedVersion),
            1 => Ok(Self::UnsupportedSchema),
            2 => Ok(Self::UnsupportedCodec),
            3 => Ok(Self::UnsupportedCriticalExtension),
            4 => Ok(Self::MalformedOperation),
            5 => Ok(Self::LimitExceeded),
            6 => Ok(Self::UnknownObject),
            7 => Ok(Self::MetadataConflict),
            8 => Ok(Self::RangeInvalid),
            9 => Ok(Self::IntegrityFailure),
            10 => Ok(Self::StorageFailure),
            11 => Ok(Self::PolicyRejected),
            12 => Ok(Self::CheckpointUnknown),
            _ => Err(Error::Malformed("failure code")),
        }
    }
}

/// Scoped protocol failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Failure {
    /// Registered core code.
    pub code: FailureCode,
    /// Bounded opaque operation/representation/collection scope.
    pub scope: Vec<u8>,
    /// Whether retry is allowed after the condition changes.
    pub retryable: bool,
    /// Optional bounded UTF-8 diagnostic.
    pub detail: Option<String>,
}

/// All seven v0.1 core operation types.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Operation {
    /// Compatibility advertisement.
    Capabilities(Capabilities),
    /// Durable collection checkpoint.
    Summary(Summary),
    /// Reconciliation page.
    Offer(Offer),
    /// Inventory-page or representation-data request.
    Request(Request),
    /// Offset representation bytes.
    Data(Data),
    /// Semantic receipt.
    Receipt(Receipt),
    /// Scoped failure.
    Failure(Failure),
}

impl Operation {
    /// Stable operation name.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Capabilities(_) => "CAPABILITIES",
            Self::Summary(_) => "SUMMARY",
            Self::Offer(_) => "OFFER",
            Self::Request(_) => "REQUEST",
            Self::Data(_) => "DATA",
            Self::Receipt(_) => "RECEIPT",
            Self::Failure(_) => "FAILURE",
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Capabilities(_) => 1,
            Self::Summary(_) => 2,
            Self::Offer(_) => 3,
            Self::Request(_) => 4,
            Self::Data(_) => 5,
            Self::Receipt(_) => 6,
            Self::Failure(_) => 7,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Capabilities(value) => value.validate(),
            Self::Summary(value) => {
                if value.item_count > MAX_COLLECTION_ENTRIES as u64
                    || value.generation < value.item_count
                {
                    Err(Error::LimitExceeded("summary"))
                } else {
                    Ok(())
                }
            }
            Self::Offer(value) => value.validate(),
            Self::Request(Request::InventoryPage(value)) => {
                if value.page_entry_limit == 0
                    || usize::from(value.page_entry_limit) > MAX_OFFER_DESCRIPTORS
                    || !cursor_matches_mode(value.committed_cursor, value.mode)
                {
                    Err(Error::Malformed("inventory page request"))
                } else {
                    Ok(())
                }
            }
            Self::Request(Request::RepresentationData(value)) => {
                if value.selections.is_empty()
                    || value.selections.len() > MAX_REQUEST_SELECTIONS
                    || value.max_total_bempic_bytes == 0
                    || value.max_sender_to_receiver_bytes > value.max_total_bempic_bytes
                    || value.max_receiver_to_sender_bytes > value.max_total_bempic_bytes
                    || value.selections.iter().any(|selection| {
                        selection.max_desired_payload_octets == 0
                            || selection.max_desired_payload_octets > MAX_REPRESENTATION_OCTETS
                            || selection.durable_prefix_offset > MAX_REPRESENTATION_OCTETS
                    })
                {
                    return Err(Error::LimitExceeded("representation data request"));
                }
                let unique = value
                    .selections
                    .iter()
                    .map(|selection| selection.representation_id)
                    .collect::<BTreeSet<_>>();
                if unique.len() == value.selections.len() {
                    Ok(())
                } else {
                    Err(Error::MetadataConflict)
                }
            }
            Self::Data(value) => {
                let end = value.offset.checked_add(value.payload.len() as u64);
                if value.payload.is_empty()
                    || value.payload.len() as u64 > MAX_REPRESENTATION_OCTETS
                    || match end {
                        Some(end) => end > MAX_REPRESENTATION_OCTETS,
                        None => true,
                    }
                {
                    Err(Error::LimitExceeded("data"))
                } else {
                    Ok(())
                }
            }
            Self::Receipt(value) => {
                validate_optional_text(&value.reason, MAX_FAILURE_DETAIL_OCTETS, "receipt reason")?;
                if value.status == ReceiptStatus::RepresentationCommitted
                    && value.verified_digest.is_none()
                {
                    Err(Error::Malformed("committed receipt digest"))
                } else {
                    Ok(())
                }
            }
            Self::Failure(value) => {
                if value.scope.len() > MAX_FAILURE_SCOPE_OCTETS {
                    return Err(Error::LimitExceeded("failure scope"));
                }
                validate_optional_text(&value.detail, MAX_FAILURE_DETAIL_OCTETS, "failure detail")
            }
        }
    }

    fn payload_size(&self) -> Result<usize, Error> {
        self.validate()?;
        Ok(match self {
            Self::Capabilities(value) => {
                1 + value.protocol_generations.len() * 4
                    + 1
                    + value.schema_fingerprints.len() * 32
                    + 1
                    + value.codec_preferences.len() * 40
                    + 4
                    + 8
                    + 1
                    + 1
                    + 1
                    + value.extensions.len() * 5
            }
            Self::Summary(_) => 32 + 8 + 8 + 32,
            Self::Offer(value) => {
                32 + 1
                    + 8
                    + 8
                    + cursor_size(value.first_cursor)
                    + cursor_size(value.last_cursor)
                    + 1
                    + value.descriptors.iter().map(descriptor_size).sum::<usize>()
                    + 1
            }
            Self::Request(Request::InventoryPage(value)) => {
                1 + 32 + 8 + 1 + cursor_size(value.committed_cursor) + 1
            }
            Self::Request(Request::RepresentationData(value)) => {
                1 + 16 + 8 + 8 + 8 + 1 + value.selections.len() * 48
            }
            Self::Data(value) => 32 + 8 + 4 + value.payload.len(),
            Self::Receipt(value) => {
                32 + 1
                    + 1
                    + usize::from(value.verified_digest.is_some()) * 32
                    + 16
                    + optional_text_size(&value.reason)
            }
            Self::Failure(value) => {
                1 + 1 + value.scope.len() + 1 + optional_text_size(&value.detail)
            }
        })
    }

    fn encode_payload(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        self.validate()?;
        match self {
            Self::Capabilities(value) => {
                put_count(output, value.protocol_generations.len())?;
                for generation in &value.protocol_generations {
                    output.extend_from_slice(&generation.major.to_be_bytes());
                    output.extend_from_slice(&generation.minor.to_be_bytes());
                }
                put_count(output, value.schema_fingerprints.len())?;
                for schema in &value.schema_fingerprints {
                    output.extend_from_slice(&schema.0);
                }
                put_count(output, value.codec_preferences.len())?;
                for preference in &value.codec_preferences {
                    output.extend_from_slice(&preference.codec_id.to_be_bytes());
                    output.extend_from_slice(&preference.revision.to_be_bytes());
                    output.extend_from_slice(&preference.schema_fingerprint.0);
                }
                output.extend_from_slice(&value.max_operation_octets.to_be_bytes());
                output.extend_from_slice(&value.max_data_payload_octets.to_be_bytes());
                output.push(value.receipt_levels);
                output.push(value.security_class as u8);
                put_count(output, value.extensions.len())?;
                for extension in &value.extensions {
                    output.extend_from_slice(&extension.id.to_be_bytes());
                    output.push(u8::from(extension.critical));
                }
            }
            Self::Summary(value) => {
                output.extend_from_slice(&value.collection_id);
                output.extend_from_slice(&value.generation.to_be_bytes());
                output.extend_from_slice(&value.item_count.to_be_bytes());
                output.extend_from_slice(&value.collection_digest);
            }
            Self::Offer(value) => {
                output.extend_from_slice(&value.collection_id);
                output.push(value.mode as u8);
                output.extend_from_slice(&value.base_generation.to_be_bytes());
                output.extend_from_slice(&value.target_generation.to_be_bytes());
                encode_cursor(output, value.first_cursor);
                encode_cursor(output, value.last_cursor);
                put_count(output, value.descriptors.len())?;
                for descriptor in &value.descriptors {
                    encode_descriptor(output, descriptor)?;
                }
                output.push(u8::from(value.more));
            }
            Self::Request(Request::InventoryPage(value)) => {
                output.push(0);
                output.extend_from_slice(&value.collection_id);
                output.extend_from_slice(&value.target_generation.to_be_bytes());
                output.push(value.mode as u8);
                encode_cursor(output, value.committed_cursor);
                output.push(value.page_entry_limit);
            }
            Self::Request(Request::RepresentationData(value)) => {
                output.push(1);
                output.extend_from_slice(&value.budget_id);
                output.extend_from_slice(&value.max_total_bempic_bytes.to_be_bytes());
                output.extend_from_slice(&value.max_sender_to_receiver_bytes.to_be_bytes());
                output.extend_from_slice(&value.max_receiver_to_sender_bytes.to_be_bytes());
                put_count(output, value.selections.len())?;
                for selection in &value.selections {
                    output.extend_from_slice(&selection.representation_id.0);
                    output.extend_from_slice(&selection.durable_prefix_offset.to_be_bytes());
                    output.extend_from_slice(&selection.max_desired_payload_octets.to_be_bytes());
                }
            }
            Self::Data(value) => {
                output.extend_from_slice(&value.representation_id.0);
                output.extend_from_slice(&value.offset.to_be_bytes());
                put_u32_length(output, value.payload.len())?;
                output.extend_from_slice(&value.payload);
            }
            Self::Receipt(value) => {
                output.extend_from_slice(&value.subject_id);
                output.push(value.status as u8);
                output.push(u8::from(value.verified_digest.is_some()));
                if let Some(digest) = value.verified_digest {
                    output.extend_from_slice(&digest.0);
                }
                output.extend_from_slice(&value.idempotency_id);
                put_optional_text(output, &value.reason)?;
            }
            Self::Failure(value) => {
                output.push(value.code as u8);
                put_u8_octets(output, &value.scope)?;
                output.push(u8::from(value.retryable));
                put_optional_text(output, &value.detail)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn decode_payload(tag: u8, reader: &mut Reader<'_>) -> Result<Self, Error> {
        match tag {
            1 => {
                let protocol_count = reader.bounded_count(MAX_CAPABILITY_PROTOCOLS)?;
                let mut protocol_generations = Vec::with_capacity(protocol_count);
                for _ in 0..protocol_count {
                    protocol_generations.push(ProtocolGeneration {
                        major: reader.u16()?,
                        minor: reader.u16()?,
                    });
                }
                let schema_count = reader.bounded_count(MAX_CAPABILITY_SCHEMAS)?;
                let mut schema_fingerprints = Vec::with_capacity(schema_count);
                for _ in 0..schema_count {
                    schema_fingerprints.push(SchemaFingerprint(reader.array()?));
                }
                let codec_count = reader.bounded_count(MAX_CAPABILITY_CODECS)?;
                let mut codec_preferences = Vec::with_capacity(codec_count);
                for _ in 0..codec_count {
                    codec_preferences.push(CodecPreference {
                        codec_id: reader.u32()?,
                        revision: reader.u32()?,
                        schema_fingerprint: SchemaFingerprint(reader.array()?),
                    });
                }
                let max_operation_octets = reader.u32()?;
                let max_data_payload_octets = reader.u64()?;
                let receipt_levels = reader.u8()?;
                let security_class = SecurityClass::try_from(reader.u8()?)?;
                let extension_count = reader.bounded_count(MAX_EXTENSIONS)?;
                let mut extensions = Vec::with_capacity(extension_count);
                for _ in 0..extension_count {
                    extensions.push(ExtensionDeclaration {
                        id: reader.u32()?,
                        critical: reader.boolean()?,
                    });
                }
                Ok(Self::Capabilities(Capabilities {
                    protocol_generations,
                    schema_fingerprints,
                    codec_preferences,
                    max_operation_octets,
                    max_data_payload_octets,
                    receipt_levels,
                    security_class,
                    extensions,
                }))
            }
            2 => Ok(Self::Summary(Summary {
                collection_id: reader.array()?,
                generation: reader.u64()?,
                item_count: reader.u64()?,
                collection_digest: reader.array()?,
            })),
            3 => {
                let collection_id = reader.array()?;
                let mode = OfferMode::try_from(reader.u8()?)?;
                let base_generation = reader.u64()?;
                let target_generation = reader.u64()?;
                let first_cursor = decode_cursor(reader)?;
                let last_cursor = decode_cursor(reader)?;
                let count = reader.bounded_count(MAX_OFFER_DESCRIPTORS)?;
                let mut descriptors = Vec::with_capacity(count);
                for _ in 0..count {
                    descriptors.push(decode_descriptor(reader)?);
                }
                let has_more_pages = reader.boolean()?;
                Ok(Self::Offer(Offer {
                    collection_id,
                    mode,
                    base_generation,
                    target_generation,
                    first_cursor,
                    last_cursor,
                    descriptors,
                    more: has_more_pages,
                }))
            }
            4 => match reader.u8()? {
                0 => Ok(Self::Request(Request::InventoryPage(
                    InventoryPageRequest {
                        collection_id: reader.array()?,
                        target_generation: reader.u64()?,
                        mode: OfferMode::try_from(reader.u8()?)?,
                        committed_cursor: decode_cursor(reader)?,
                        page_entry_limit: reader.u8()?,
                    },
                ))),
                1 => {
                    let budget_id = reader.array()?;
                    let max_total_bempic_bytes = reader.u64()?;
                    let max_sender_to_receiver_bytes = reader.u64()?;
                    let max_receiver_to_sender_bytes = reader.u64()?;
                    let count = reader.bounded_count(MAX_REQUEST_SELECTIONS)?;
                    let mut selections = Vec::with_capacity(count);
                    for _ in 0..count {
                        selections.push(RepresentationSelection {
                            representation_id: RepresentationId(reader.array()?),
                            durable_prefix_offset: reader.u64()?,
                            max_desired_payload_octets: reader.u64()?,
                        });
                    }
                    Ok(Self::Request(Request::RepresentationData(
                        RepresentationDataRequest {
                            budget_id,
                            max_total_bempic_bytes,
                            max_sender_to_receiver_bytes,
                            max_receiver_to_sender_bytes,
                            selections,
                        },
                    )))
                }
                _ => Err(Error::Malformed("request variant")),
            },
            5 => {
                let representation_id = RepresentationId(reader.array()?);
                let offset = reader.u64()?;
                let length = reader.u32_length(MAX_EXPERIMENTAL_RECORD_OCTETS)?;
                let payload = reader.take(length)?.to_vec();
                Ok(Self::Data(Data {
                    representation_id,
                    offset,
                    payload,
                }))
            }
            6 => {
                let subject_id = reader.array()?;
                let status = ReceiptStatus::try_from(reader.u8()?)?;
                let verified_digest = if reader.boolean()? {
                    Some(ContentDigest(reader.array()?))
                } else {
                    None
                };
                let idempotency_id = reader.array()?;
                let reason = reader.optional_text(MAX_FAILURE_DETAIL_OCTETS)?;
                Ok(Self::Receipt(Receipt {
                    subject_id,
                    status,
                    verified_digest,
                    idempotency_id,
                    reason,
                }))
            }
            7 => Ok(Self::Failure(Failure {
                code: FailureCode::try_from(reader.u8()?)?,
                scope: reader.u8_octets(MAX_FAILURE_SCOPE_OCTETS)?,
                retryable: reader.boolean()?,
                detail: reader.optional_text(MAX_FAILURE_DETAIL_OCTETS)?,
            })),
            other => Err(Error::UnknownOperation(other)),
        }
    }
}

/// One complete operation plus optional length-delimited extensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// Core operation.
    pub operation: Operation,
    /// Known or locally emitted extensions.
    pub extensions: Vec<Extension>,
}

impl Record {
    /// Exact encoded size without trial serialization.
    pub fn exact_encoded_size(&self) -> Result<usize, Error> {
        validate_record_extensions(&self.extensions)?;
        let extension_octets = 1 + self
            .extensions
            .iter()
            .map(|extension| 4 + 1 + 2 + extension.value.len())
            .sum::<usize>();
        let size = ENVELOPE_OCTETS
            .checked_add(self.operation.payload_size()?)
            .and_then(|value| value.checked_add(extension_octets))
            .ok_or(Error::LimitExceeded("operation size"))?;
        if size > MAX_EXPERIMENTAL_RECORD_OCTETS {
            return Err(Error::LimitExceeded("operation size"));
        }
        Ok(size)
    }

    /// Encode one complete deterministic experimental record.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let size = self.exact_encoded_size()?;
        let mut output = Vec::with_capacity(size);
        output.extend_from_slice(MAGIC);
        output.push(self.operation.tag());
        output.extend_from_slice(
            &u32::try_from(size - ENVELOPE_OCTETS)
                .map_err(|_| Error::LimitExceeded("operation size"))?
                .to_be_bytes(),
        );
        self.operation.encode_payload(&mut output)?;
        put_count(&mut output, self.extensions.len())?;
        for extension in &self.extensions {
            output.extend_from_slice(&extension.id.to_be_bytes());
            output.push(u8::from(extension.critical));
            let length = u16::try_from(extension.value.len())
                .map_err(|_| Error::LimitExceeded("extension value"))?;
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(&extension.value);
        }
        debug_assert_eq!(output.len(), size);
        Ok(output)
    }

    /// Strictly decode after structural/bound validation and extension checks.
    pub fn decode(record: &[u8], supported_extensions: &BTreeSet<u32>) -> Result<Self, Error> {
        if record.len() < ENVELOPE_OCTETS {
            return Err(Error::Truncated);
        }
        if record.len() > MAX_EXPERIMENTAL_RECORD_OCTETS {
            return Err(Error::LimitExceeded("operation size"));
        }
        if &record[..2] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        let payload_length = usize::try_from(u32::from_be_bytes(
            record[3..7].try_into().map_err(|_| Error::Truncated)?,
        ))
        .map_err(|_| Error::LimitExceeded("operation size"))?;
        if payload_length != record.len() - ENVELOPE_OCTETS {
            return Err(Error::Malformed("envelope length"));
        }
        let mut reader = Reader::new(&record[ENVELOPE_OCTETS..]);
        let operation = Operation::decode_payload(record[2], &mut reader)?;
        let extension_count = reader.bounded_count(MAX_EXTENSIONS)?;
        let mut extensions = Vec::new();
        let mut identifiers = BTreeSet::new();
        for _ in 0..extension_count {
            let id = reader.u32()?;
            let critical = reader.boolean()?;
            let length = usize::from(reader.u16()?);
            if length > MAX_EXTENSION_VALUE_OCTETS || !identifiers.insert(id) {
                return Err(Error::LimitExceeded("extension"));
            }
            let value = reader.take(length)?.to_vec();
            if supported_extensions.contains(&id) {
                extensions.push(Extension {
                    id,
                    critical,
                    value,
                });
            } else if critical {
                return Err(Error::UnsupportedCriticalExtension(id));
            }
        }
        if !reader.is_empty() {
            return Err(Error::TrailingBytes);
        }
        operation.validate()?;
        Ok(Self {
            operation,
            extensions,
        })
    }
}

/// Direction inside an explicit budget scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    /// Sender to receiver.
    SenderToReceiver,
    /// Receiver to sender.
    ReceiverToSender,
}

/// Exact hard total and directional budget state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetScope {
    /// Scope identifier.
    pub budget_id: [u8; 16],
    /// Accepted hard total.
    pub max_total: u64,
    /// Accepted hard sender-to-receiver maximum.
    pub max_sender_to_receiver: u64,
    /// Accepted hard receiver-to-sender maximum.
    pub max_receiver_to_sender: u64,
    /// Exact total used.
    pub used_total: u64,
    /// Exact sender-to-receiver use.
    pub used_sender_to_receiver: u64,
    /// Exact receiver-to-sender use.
    pub used_receiver_to_sender: u64,
}

impl BudgetScope {
    /// Construct an empty accepted scope.
    pub const fn new(request: &RepresentationDataRequest) -> Self {
        Self {
            budget_id: request.budget_id,
            max_total: request.max_total_bempic_bytes,
            max_sender_to_receiver: request.max_sender_to_receiver_bytes,
            max_receiver_to_sender: request.max_receiver_to_sender_bytes,
            used_total: 0,
            used_sender_to_receiver: 0,
            used_receiver_to_sender: 0,
        }
    }

    /// Admit one whole record or leave all counters unchanged.
    pub fn admit(&mut self, direction: Direction, encoded_octets: u64) -> bool {
        let Some(total) = self.used_total.checked_add(encoded_octets) else {
            return false;
        };
        if total > self.max_total {
            return false;
        }
        match direction {
            Direction::SenderToReceiver => {
                let Some(directional) = self.used_sender_to_receiver.checked_add(encoded_octets)
                else {
                    return false;
                };
                if directional > self.max_sender_to_receiver {
                    return false;
                }
                self.used_sender_to_receiver = directional;
            }
            Direction::ReceiverToSender => {
                let Some(directional) = self.used_receiver_to_sender.checked_add(encoded_octets)
                else {
                    return false;
                };
                if directional > self.max_receiver_to_sender {
                    return false;
                }
                self.used_receiver_to_sender = directional;
            }
        }
        self.used_total = total;
        true
    }
}

/// Compute a checkpoint from a valid append-only prefix.
pub fn collection_checkpoint(
    collection_id: [u8; 32],
    generation: u64,
    entries: &[CollectionEntry],
) -> Result<Summary, Error> {
    if entries.len() > MAX_COLLECTION_ENTRIES {
        return Err(Error::LimitExceeded("collection entries"));
    }
    let mut ordered = entries
        .iter()
        .filter(|entry| entry.sequence <= generation)
        .collect::<Vec<_>>();
    ordered.sort_by_key(|entry| entry.sequence);
    if ordered
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Err(Error::MetadataConflict);
    }
    let mut keys = BTreeSet::new();
    for entry in &ordered {
        entry.validate()?;
        if !keys.insert(entry.key()) {
            return Err(Error::MetadataConflict);
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(b"BEMPIC-COLLECTION-v0.1\0");
    hasher.update(collection_id);
    hasher.update(generation.to_be_bytes());
    hasher.update((ordered.len() as u64).to_be_bytes());
    for entry in ordered {
        hasher.update(entry.object_id.0);
        hasher.update(entry.part_id.to_be_bytes());
        hasher.update(entry.descriptor.representation_id.0);
    }
    Ok(Summary {
        collection_id,
        generation,
        item_count: keys.len() as u64,
        collection_digest: hasher.finalize().into(),
    })
}

/// Reconciliation outcome for one receiver checkpoint and durable cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reconciliation {
    /// Receiver checkpoint exactly equals the authority target.
    Equal(Summary),
    /// One bounded deterministic page.
    Page(Offer),
}

/// Build an equal result, known-checkpoint delta page, or bounded full fallback.
pub fn reconcile(
    current: Summary,
    retained_checkpoints: &[Summary],
    entries: &[CollectionEntry],
    receiver: Option<Summary>,
    committed_cursor: Option<Cursor>,
    desired_entries: usize,
    max_record_octets: usize,
) -> Result<Reconciliation, Error> {
    if receiver == Some(current) {
        return Ok(Reconciliation::Equal(current));
    }
    if desired_entries == 0 || desired_entries > MAX_OFFER_DESCRIPTORS {
        return Err(Error::LimitExceeded("page entry limit"));
    }
    let known = receiver.filter(|checkpoint| {
        retained_checkpoints
            .iter()
            .any(|retained| retained == checkpoint)
    });
    let (mode, base_generation, mut candidates) = if let Some(base) = known {
        let mut values = entries
            .iter()
            .filter(|entry| entry.sequence > base.generation)
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|entry| entry.sequence);
        (OfferMode::Delta, base.generation, values)
    } else {
        let mut values = entries.to_vec();
        values.sort_by_key(CollectionEntry::key);
        (OfferMode::Full, 0, values)
    };
    candidates.retain(|entry| match (mode, committed_cursor) {
        (OfferMode::Delta, Some(Cursor::Delta(sequence))) => entry.sequence > sequence,
        (OfferMode::Full, Some(Cursor::Full(key))) => entry.key() > key,
        (_, None) => true,
        _ => false,
    });
    if candidates.is_empty() {
        return Err(Error::Cursor);
    }
    let mut selected = Vec::new();
    for candidate in candidates.iter().take(desired_entries) {
        let mut tentative = selected.clone();
        tentative.push(candidate.clone());
        let offer = make_offer(current, mode, base_generation, tentative, true)?;
        let record = Record {
            operation: Operation::Offer(offer),
            extensions: Vec::new(),
        };
        if record.exact_encoded_size()? > max_record_octets {
            break;
        }
        selected.push(candidate.clone());
    }
    if selected.is_empty() {
        return Err(Error::RecordTooLarge);
    }
    let has_more_pages = selected.len() < candidates.len();
    Ok(Reconciliation::Page(make_offer(
        current,
        mode,
        base_generation,
        selected,
        has_more_pages,
    )?))
}

fn make_offer(
    current: Summary,
    mode: OfferMode,
    base_generation: u64,
    descriptors: Vec<CollectionEntry>,
    has_more_pages: bool,
) -> Result<Offer, Error> {
    let first = descriptors.first().ok_or(Error::Cursor)?;
    let last = descriptors.last().ok_or(Error::Cursor)?;
    let first_cursor = match mode {
        OfferMode::Delta => Cursor::Delta(first.sequence),
        OfferMode::Full => Cursor::Full(first.key()),
    };
    let last_cursor = match mode {
        OfferMode::Delta => Cursor::Delta(last.sequence),
        OfferMode::Full => Cursor::Full(last.key()),
    };
    let offer = Offer {
        collection_id: current.collection_id,
        mode,
        base_generation,
        target_generation: current.generation,
        first_cursor,
        last_cursor,
        descriptors,
        more: has_more_pages,
    };
    offer.validate()?;
    Ok(offer)
}

fn validate_nonempty_unique<T: Ord + Clone>(
    values: &[T],
    maximum: usize,
    field: &'static str,
) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::Malformed(field));
    }
    validate_unique_bounded(values, maximum, field)
}

fn validate_unique_bounded<T: Ord + Clone>(
    values: &[T],
    maximum: usize,
    field: &'static str,
) -> Result<(), Error> {
    if values.len() > maximum
        || values.iter().cloned().collect::<BTreeSet<_>>().len() != values.len()
    {
        Err(Error::LimitExceeded(field))
    } else {
        Ok(())
    }
}

fn validate_record_extensions(extensions: &[Extension]) -> Result<(), Error> {
    if extensions.len() > MAX_EXTENSIONS {
        return Err(Error::LimitExceeded("extensions"));
    }
    let mut identifiers = BTreeSet::new();
    for extension in extensions {
        if extension.value.len() > MAX_EXTENSION_VALUE_OCTETS || !identifiers.insert(extension.id) {
            return Err(Error::LimitExceeded("extension"));
        }
    }
    Ok(())
}

fn validate_optional_text(
    value: &Option<String>,
    maximum: usize,
    field: &'static str,
) -> Result<(), Error> {
    if value.as_ref().is_some_and(|text| {
        text.len() > maximum || text.contains('\0') || text.chars().any(char::is_control)
    }) {
        Err(Error::LimitExceeded(field))
    } else {
        Ok(())
    }
}

fn optional_text_size(value: &Option<String>) -> usize {
    1 + value.as_ref().map_or(0, |text| 2 + text.len())
}

fn put_optional_text(output: &mut Vec<u8>, value: &Option<String>) -> Result<(), Error> {
    output.push(u8::from(value.is_some()));
    if let Some(text) = value {
        let length = u16::try_from(text.len()).map_err(|_| Error::LimitExceeded("text"))?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(text.as_bytes());
    }
    Ok(())
}

fn put_count(output: &mut Vec<u8>, count: usize) -> Result<(), Error> {
    output.push(u8::try_from(count).map_err(|_| Error::LimitExceeded("count"))?);
    Ok(())
}

fn put_u32_length(output: &mut Vec<u8>, length: usize) -> Result<(), Error> {
    output.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| Error::LimitExceeded("length"))?
            .to_be_bytes(),
    );
    Ok(())
}

fn put_u8_octets(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    put_count(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}

fn cursor_matches_mode(cursor: Cursor, mode: OfferMode) -> bool {
    matches!(
        (cursor, mode),
        (Cursor::Delta(_), OfferMode::Delta) | (Cursor::Full(_), OfferMode::Full)
    )
}

const fn cursor_size(cursor: Cursor) -> usize {
    match cursor {
        Cursor::Delta(_) => 1 + 8,
        Cursor::Full(_) => 1 + 32 + 4 + 32,
    }
}

fn encode_cursor(output: &mut Vec<u8>, cursor: Cursor) {
    match cursor {
        Cursor::Delta(sequence) => {
            output.push(0);
            output.extend_from_slice(&sequence.to_be_bytes());
        }
        Cursor::Full(key) => {
            output.push(1);
            output.extend_from_slice(&key.object_id.0);
            output.extend_from_slice(&key.part_id.to_be_bytes());
            output.extend_from_slice(&key.representation_id.0);
        }
    }
}

fn decode_cursor(reader: &mut Reader<'_>) -> Result<Cursor, Error> {
    match reader.u8()? {
        0 => Ok(Cursor::Delta(reader.u64()?)),
        1 => Ok(Cursor::Full(EntryKey {
            object_id: ObjectId(reader.array()?),
            part_id: reader.u32()?,
            representation_id: RepresentationId(reader.array()?),
        })),
        _ => Err(Error::Malformed("cursor")),
    }
}

fn descriptor_size(entry: &CollectionEntry) -> usize {
    8 + 32
        + 4
        + 32
        + 32
        + 4
        + 4
        + 2
        + entry.descriptor.codec_parameters.len()
        + 8
        + 1
        + usize::from(entry.descriptor.decoded_length.is_some()) * 8
        + 32
        + 1
        + usize::from(entry.descriptor.usefulness_expiry.is_some()) * 8
}

fn encode_descriptor(output: &mut Vec<u8>, entry: &CollectionEntry) -> Result<(), Error> {
    entry.validate()?;
    output.extend_from_slice(&entry.sequence.to_be_bytes());
    output.extend_from_slice(&entry.object_id.0);
    output.extend_from_slice(&entry.part_id.to_be_bytes());
    output.extend_from_slice(&entry.descriptor.representation_id.0);
    output.extend_from_slice(&entry.descriptor.schema_fingerprint.0);
    output.extend_from_slice(&entry.descriptor.codec_id.to_be_bytes());
    output.extend_from_slice(&entry.descriptor.codec_revision.to_be_bytes());
    let parameter_length = u16::try_from(entry.descriptor.codec_parameters.len())
        .map_err(|_| Error::LimitExceeded("codec parameters"))?;
    output.extend_from_slice(&parameter_length.to_be_bytes());
    output.extend_from_slice(&entry.descriptor.codec_parameters);
    output.extend_from_slice(&entry.descriptor.encoded_length.to_be_bytes());
    output.push(u8::from(entry.descriptor.decoded_length.is_some()));
    if let Some(length) = entry.descriptor.decoded_length {
        output.extend_from_slice(&length.to_be_bytes());
    }
    output.extend_from_slice(&entry.descriptor.content_digest.0);
    output.push(u8::from(entry.descriptor.usefulness_expiry.is_some()));
    if let Some(expiry) = entry.descriptor.usefulness_expiry {
        output.extend_from_slice(&expiry.to_be_bytes());
    }
    Ok(())
}

fn decode_descriptor(reader: &mut Reader<'_>) -> Result<CollectionEntry, Error> {
    let sequence = reader.u64()?;
    let object_id = ObjectId(reader.array()?);
    let part_id = reader.u32()?;
    let representation_id = RepresentationId(reader.array()?);
    let schema_fingerprint = SchemaFingerprint(reader.array()?);
    let codec_id = reader.u32()?;
    let codec_revision = reader.u32()?;
    let codec_parameters = reader.u16_octets(MAX_CODEC_PARAMETER_OCTETS)?;
    let encoded_length = reader.u64()?;
    let decoded_length = if reader.boolean()? {
        Some(reader.u64()?)
    } else {
        None
    };
    let content_digest = ContentDigest(reader.array()?);
    let usefulness_expiry = if reader.boolean()? {
        Some(reader.u64()?)
    } else {
        None
    };
    let entry = CollectionEntry {
        sequence,
        object_id,
        part_id,
        descriptor: RepresentationDescriptor {
            representation_id,
            schema_fingerprint,
            codec_id,
            codec_revision,
            codec_parameters,
            encoded_length,
            decoded_length,
            content_digest,
            usefulness_expiry,
        },
    };
    entry.validate()?;
    Ok(entry)
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(count).ok_or(Error::Truncated)?;
        let value = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::NonCanonical("boolean")),
        }
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn bounded_count(&mut self, maximum: usize) -> Result<usize, Error> {
        let count = usize::from(self.u8()?);
        if count > maximum {
            Err(Error::LimitExceeded("count"))
        } else {
            Ok(count)
        }
    }

    fn u32_length(&mut self, maximum: usize) -> Result<usize, Error> {
        let length = usize::try_from(self.u32()?).map_err(|_| Error::LimitExceeded("length"))?;
        if length > maximum || length > self.bytes.len().saturating_sub(self.position) {
            Err(Error::LimitExceeded("length"))
        } else {
            Ok(length)
        }
    }

    fn u16_octets(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(Error::LimitExceeded("octets"));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn u8_octets(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let length = self.bounded_count(maximum)?;
        Ok(self.take(length)?.to_vec())
    }

    fn optional_text(&mut self, maximum: usize) -> Result<Option<String>, Error> {
        if !self.boolean()? {
            return Ok(None);
        }
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(Error::LimitExceeded("text"));
        }
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| Error::Malformed("UTF-8"))?
            .to_owned();
        validate_optional_text(&Some(text.clone()), maximum, "text")?;
        Ok(Some(text))
    }
}

/// Strict codec/reconciliation failure before durable mutation.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum Error {
    /// Record ended before a declared field.
    #[error("truncated record")]
    Truncated,
    /// Experimental record marker differed.
    #[error("invalid experimental v0.1 record marker")]
    InvalidMagic,
    /// A field was structurally malformed.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// A canonical representation rule was violated.
    #[error("non-canonical {0}")]
    NonCanonical(&'static str),
    /// Trailing bytes remained after a complete operation.
    #[error("trailing bytes")]
    TrailingBytes,
    /// A mandatory operation tag was unknown.
    #[error("unknown operation {0}")]
    UnknownOperation(u8),
    /// Unknown critical extension prevented mutation.
    #[error("unsupported critical extension {0}")]
    UnsupportedCriticalExtension(u32),
    /// A core or local limit was exceeded.
    #[error("{0} exceeds a limit")]
    LimitExceeded(&'static str),
    /// Immutable collection/representation metadata conflicted.
    #[error("immutable metadata conflict")]
    MetadataConflict,
    /// Durable cursor was invalid for the target.
    #[error("invalid durable cursor")]
    Cursor,
    /// No whole descriptor fits the negotiated operation size.
    #[error("offer page exceeds negotiated record size")]
    RecordTooLarge,
    /// A protocol state transition was not permitted.
    #[error("invalid {0} state transition")]
    InvalidTransition(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bempic_model::v01::{
        fingerprint_from_hex, PreparedRepresentation, OPAQUE_SCHEMA_FINGERPRINT_HEX,
    };

    fn prepared(seed: u8) -> PreparedRepresentation {
        PreparedRepresentation::prepare(
            vec![seed; usize::from(seed) + 1],
            None,
            fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).unwrap(),
            0xffff_0001,
            1,
            Vec::new(),
            None,
        )
        .unwrap()
    }

    fn entry(sequence: u64, seed: u8) -> CollectionEntry {
        CollectionEntry {
            sequence,
            object_id: ObjectId::fixture(&[seed]),
            part_id: u32::from(seed),
            descriptor: prepared(seed).descriptor,
        }
    }

    fn capabilities(codecs: Vec<CodecPreference>) -> Capabilities {
        let schemas = codecs
            .iter()
            .map(|codec| codec.schema_fingerprint)
            .collect();
        Capabilities {
            protocol_generations: vec![ProtocolGeneration { major: 0, minor: 1 }],
            schema_fingerprints: schemas,
            codec_preferences: codecs,
            max_operation_octets: 65_540,
            max_data_payload_octets: 65_000,
            receipt_levels: 0b1111,
            security_class: SecurityClass::Public,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn all_seven_operations_are_exact_and_round_trip() {
        let item = entry(1, 7);
        let schema = item.descriptor.schema_fingerprint;
        let capability = capabilities(vec![CodecPreference {
            codec_id: item.descriptor.codec_id,
            revision: item.descriptor.codec_revision,
            schema_fingerprint: schema,
        }]);
        let summary = collection_checkpoint([3; 32], 1, std::slice::from_ref(&item)).unwrap();
        let offer = make_offer(summary, OfferMode::Delta, 0, vec![item.clone()], false).unwrap();
        let operations = vec![
            Operation::Capabilities(capability),
            Operation::Summary(summary),
            Operation::Offer(offer),
            Operation::Request(Request::InventoryPage(InventoryPageRequest {
                collection_id: [3; 32],
                target_generation: 1,
                mode: OfferMode::Delta,
                committed_cursor: Cursor::Delta(0),
                page_entry_limit: 128,
            })),
            Operation::Request(Request::RepresentationData(RepresentationDataRequest {
                budget_id: [4; 16],
                max_total_bempic_bytes: 1_000,
                max_sender_to_receiver_bytes: 900,
                max_receiver_to_sender_bytes: 100,
                selections: vec![RepresentationSelection {
                    representation_id: item.descriptor.representation_id,
                    durable_prefix_offset: 0,
                    max_desired_payload_octets: item.descriptor.encoded_length,
                }],
            })),
            Operation::Data(Data {
                representation_id: item.descriptor.representation_id,
                offset: 0,
                payload: vec![7; 8],
            }),
            Operation::Receipt(Receipt {
                subject_id: item.descriptor.representation_id.0,
                status: ReceiptStatus::RepresentationCommitted,
                verified_digest: Some(item.descriptor.content_digest),
                idempotency_id: [5; 16],
                reason: None,
            }),
            Operation::Failure(Failure {
                code: FailureCode::RangeInvalid,
                scope: item.descriptor.representation_id.0[..16].to_vec(),
                retryable: true,
                detail: Some("retry from durable prefix".into()),
            }),
        ];
        for operation in operations {
            let record = Record {
                operation,
                extensions: Vec::new(),
            };
            let expected = record.exact_encoded_size().unwrap();
            let bytes = record.encode().unwrap();
            assert_eq!(bytes.len(), expected);
            assert_eq!(Record::decode(&bytes, &BTreeSet::new()).unwrap(), record);
        }
    }

    #[test]
    fn representation_data_selection_enforces_fields_bounds_and_uniqueness() {
        let item = entry(1, 9);
        let mut offered = BTreeMap::new();
        offered.insert(
            item.descriptor.representation_id,
            item.descriptor.encoded_length,
        );
        let selection = RepresentationSelection {
            representation_id: item.descriptor.representation_id,
            durable_prefix_offset: 1,
            max_desired_payload_octets: item.descriptor.encoded_length - 1,
        };
        let mut request = RepresentationDataRequest {
            budget_id: [0; 16],
            max_total_bempic_bytes: 500,
            max_sender_to_receiver_bytes: 400,
            max_receiver_to_sender_bytes: 100,
            selections: vec![selection],
        };
        assert_eq!(request.validate(&offered), Ok(()));
        request.selections.push(selection);
        assert_eq!(
            request.validate(&offered),
            Err(FailureCode::MetadataConflict)
        );
        request.selections.truncate(1);
        request.selections[0].max_desired_payload_octets = item.descriptor.encoded_length;
        assert_eq!(request.validate(&offered), Err(FailureCode::RangeInvalid));
        request.selections[0].durable_prefix_offset = item.descriptor.encoded_length;
        request.selections[0].max_desired_payload_octets = 1;
        assert_eq!(request.validate(&offered), Err(FailureCode::RangeInvalid));
    }

    #[test]
    fn negotiation_uses_preference_sum_ties_and_rejects_critical_extension() {
        let schema_a = prepared(1).descriptor.schema_fingerprint;
        let schema_b = SchemaFingerprint([2; 32]);
        let a = CodecPreference {
            codec_id: 9,
            revision: 1,
            schema_fingerprint: schema_a,
        };
        let b = CodecPreference {
            codec_id: 7,
            revision: 1,
            schema_fingerprint: schema_b,
        };
        let local = capabilities(vec![a, b]);
        let mut remote = capabilities(vec![b, a]);
        let selected = negotiate(&local, &remote).unwrap();
        assert_eq!(selected.codec_id, 7);
        remote.extensions.push(ExtensionDeclaration {
            id: 42,
            critical: true,
        });
        assert_eq!(
            negotiate(&local, &remote),
            Err(FailureCode::UnsupportedCriticalExtension)
        );
    }

    #[test]
    fn unknown_optional_is_skipped_and_unknown_critical_rejected() {
        let record = Record {
            operation: Operation::Failure(Failure {
                code: FailureCode::UnknownObject,
                scope: Vec::new(),
                retryable: false,
                detail: None,
            }),
            extensions: vec![Extension {
                id: 77,
                critical: false,
                value: vec![1, 2, 3],
            }],
        };
        let bytes = record.encode().unwrap();
        let decoded = Record::decode(&bytes, &BTreeSet::new()).unwrap();
        assert!(decoded.extensions.is_empty());
        let mut critical = record;
        critical.extensions[0].critical = true;
        assert_eq!(
            Record::decode(&critical.encode().unwrap(), &BTreeSet::new()),
            Err(Error::UnsupportedCriticalExtension(77))
        );
    }

    #[test]
    fn checkpoints_delta_full_fallback_and_cursors_are_deterministic() {
        let entries = (1_u8..=5)
            .map(|value| entry(u64::from(value), value))
            .collect::<Vec<_>>();
        let base = collection_checkpoint([8; 32], 3, &entries).unwrap();
        let current = collection_checkpoint([8; 32], 5, &entries).unwrap();
        let delta = reconcile(current, &[base], &entries, Some(base), None, 1, 4_096).unwrap();
        let Reconciliation::Page(first) = delta else {
            panic!("expected delta page")
        };
        assert_eq!(first.mode, OfferMode::Delta);
        assert_eq!(first.descriptors[0].sequence, 4);
        assert_eq!(first.last_cursor, Cursor::Delta(4));
        let next = reconcile(
            current,
            &[base],
            &entries,
            Some(base),
            Some(first.last_cursor),
            128,
            4_096,
        )
        .unwrap();
        let Reconciliation::Page(next) = next else {
            panic!("expected second delta page")
        };
        assert_eq!(next.descriptors[0].sequence, 5);

        let unknown = Summary {
            collection_id: [8; 32],
            generation: 2,
            item_count: 2,
            collection_digest: [99; 32],
        };
        let full = reconcile(current, &[base], &entries, Some(unknown), None, 2, 4_096).unwrap();
        let Reconciliation::Page(full) = full else {
            panic!("expected full page")
        };
        assert_eq!(full.mode, OfferMode::Full);
        assert!(full
            .descriptors
            .windows(2)
            .all(|pair| pair[0].key() < pair[1].key()));
    }

    #[test]
    fn budget_one_below_rejects_and_exact_fit_admits_without_mutation() {
        let request = RepresentationDataRequest {
            budget_id: [6; 16],
            max_total_bempic_bytes: 100,
            max_sender_to_receiver_bytes: 80,
            max_receiver_to_sender_bytes: 20,
            selections: vec![RepresentationSelection {
                representation_id: prepared(4).descriptor.representation_id,
                durable_prefix_offset: 0,
                max_desired_payload_octets: 1,
            }],
        };
        let mut scope = BudgetScope::new(&request);
        assert!(scope.admit(Direction::ReceiverToSender, 20));
        let before = scope;
        assert!(!scope.admit(Direction::ReceiverToSender, 1));
        assert_eq!(scope, before);
        assert!(scope.admit(Direction::SenderToReceiver, 80));
        let complete = scope;
        assert!(!scope.admit(Direction::SenderToReceiver, 1));
        assert_eq!(scope, complete);
    }

    #[test]
    fn malformed_corpus_never_panics_or_accepts_trailing_or_noncanonical_values() {
        let supported = BTreeSet::new();
        for length in 0_usize..512 {
            let bytes = (0..length)
                .map(|index| u8::try_from((index * 73 + length * 19) & 0xff).unwrap())
                .collect::<Vec<_>>();
            let _ = Record::decode(&bytes, &supported);
        }
        let mut encoded = Record {
            operation: Operation::Failure(Failure {
                code: FailureCode::MalformedOperation,
                scope: Vec::new(),
                retryable: false,
                detail: None,
            }),
            extensions: Vec::new(),
        }
        .encode()
        .unwrap();
        encoded.push(0);
        assert!(Record::decode(&encoded, &supported).is_err());
    }

    #[test]
    fn protocol_state_transitions_are_explicit_and_fail_closed() {
        assert_eq!(
            CompatibilityState::Idle.transition(CompatibilityState::Negotiating),
            Ok(CompatibilityState::Negotiating)
        );
        assert!(CompatibilityState::Idle
            .transition(CompatibilityState::Compatible)
            .is_err());
        assert_eq!(
            CollectionState::Unchecked.transition(CollectionState::Reconciling),
            Ok(CollectionState::Reconciling)
        );
        assert!(CollectionState::Equal
            .transition(CollectionState::Selecting)
            .is_err());
        assert_eq!(
            RepresentationState::Offered.transition(RepresentationState::CompleteUnverified),
            Ok(RepresentationState::CompleteUnverified)
        );
        assert_eq!(
            RepresentationState::Verified.transition(RepresentationState::Committed),
            Ok(RepresentationState::Committed)
        );
        assert!(RepresentationState::Committed
            .transition(RepresentationState::Rejected)
            .is_err());
        assert_eq!(SenderState::Sending.interrupted(), SenderState::Available);
        assert_eq!(SenderState::Receipted.interrupted(), SenderState::Receipted);
    }

    #[test]
    fn declared_per_operation_maxima_cover_concrete_records() {
        let failure = Record {
            operation: Operation::Failure(Failure {
                code: FailureCode::LimitExceeded,
                scope: vec![0; MAX_FAILURE_SCOPE_OCTETS],
                retryable: false,
                detail: Some("x".repeat(MAX_FAILURE_DETAIL_OCTETS)),
            }),
            extensions: Vec::new(),
        };
        assert!(
            failure.exact_encoded_size().unwrap()
                <= declared_max_encoded_size(OperationKind::Failure)
        );
        let data = Record {
            operation: Operation::Data(Data {
                representation_id: prepared(1).descriptor.representation_id,
                offset: 0,
                payload: vec![0; 65_535],
            }),
            extensions: Vec::new(),
        };
        assert!(
            data.exact_encoded_size().unwrap() <= declared_max_encoded_size(OperationKind::Data)
        );
    }
}
