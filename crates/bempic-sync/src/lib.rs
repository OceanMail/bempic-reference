#![forbid(unsafe_code)]
//! Pure, replaceable synchronization operations for immutable representations.

use bempic_model::{ContentDigest, PreparedRepresentation, RepresentationId, RepresentationKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

const RECORD_MAGIC: &[u8; 2] = b"B0";
const ENVELOPE_SIZE: usize = 5;

/// Maximum experimental record payload encoded by the u16 envelope.
pub const MAX_OPERATION_PAYLOAD: usize = u16::MAX as usize;

/// Cacheable local record capabilities. Generation zero is disposable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// Experimental encoding generation, not a protocol version.
    pub encoding_generation: u8,
    /// Largest complete operation accepted by the endpoint.
    pub max_record_size: u16,
    /// Experimental feature flags.
    pub features: u8,
}

/// Order-independent collection summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    /// Number of indexed representations.
    pub item_count: u64,
    /// Truncated deterministic collection digest.
    pub digest: [u8; 16],
}

/// Exact prepared representation offered before payload transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Offer {
    /// Exact representation identity.
    pub representation_id: RepresentationId,
    /// Semantic decoding kind.
    pub kind: RepresentationKind,
    /// Prepared size in bytes.
    pub size: u64,
    /// Full integrity digest.
    pub digest: ContentDigest,
    /// Fingerprint of the candidate representation schema.
    pub schema_fingerprint: [u8; 16],
}

impl From<&PreparedRepresentation> for Offer {
    fn from(representation: &PreparedRepresentation) -> Self {
        Self {
            representation_id: representation.id,
            kind: representation.kind,
            size: representation.size(),
            digest: representation.digest,
            schema_fingerprint: representation.schema_fingerprint,
        }
    }
}

/// Request for bytes beginning at an already-persisted prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    /// Exact representation identity.
    pub representation_id: RepresentationId,
    /// First needed byte.
    pub offset: u64,
    /// Hard upper bound on response payload bytes.
    pub max_payload_bytes: u32,
}

/// Offset-addressed immutable representation bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Data {
    /// Exact representation identity.
    pub representation_id: RepresentationId,
    /// Byte offset in the prepared representation.
    pub offset: u64,
    /// Complete payload contained by this operation.
    pub payload: Vec<u8>,
}

/// Semantic receipt stage; network forwarding is intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ReceiptStage {
    /// Whole representation digest was verified.
    Verified = 1,
    /// Verified representation is durably stored.
    Stored = 2,
    /// Application accepted the logical object.
    Accepted = 3,
    /// Final application delivery occurred.
    Delivered = 4,
    /// Representation or application rejected the object.
    Rejected = 255,
}

impl TryFrom<u8> for ReceiptStage {
    type Error = SyncError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Verified),
            2 => Ok(Self::Stored),
            3 => Ok(Self::Accepted),
            4 => Ok(Self::Delivered),
            255 => Ok(Self::Rejected),
            other => Err(SyncError::UnknownReceipt(other)),
        }
    }
}

/// End-to-end BEMPIC semantic result for an exact representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    /// Exact representation identity.
    pub representation_id: RepresentationId,
    /// Strongest attained semantic stage.
    pub stage: ReceiptStage,
    /// Digest that was verified or rejected.
    pub digest: ContentDigest,
}

/// Experimental synchronization operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Capability negotiation.
    Capabilities(Capabilities),
    /// Collection comparison.
    Summary(Summary),
    /// Prepared metadata before data.
    Offer(Offer),
    /// Bounded resumption request.
    Request(Request),
    /// Offset data.
    Data(Data),
    /// Semantic completion/result state.
    Receipt(Receipt),
}

/// Direction used by byte accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Sender to receiver.
    SenderToReceiver,
    /// Receiver to sender.
    ReceiverToSender,
}

/// Exact application-protocol byte counters.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Accounting {
    /// Serialized BEMPIC bytes from sender to receiver.
    pub sender_to_receiver_bytes: u64,
    /// Serialized BEMPIC bytes from receiver to sender.
    pub receiver_to_sender_bytes: u64,
    /// Representation payload bytes carried inside data operations.
    pub representation_payload_bytes: u64,
    /// Payload bytes already persisted by the receiver.
    pub duplicate_payload_bytes: u64,
    /// Bytes that became verified and usable.
    pub useful_committed_bytes: u64,
    /// Whole-representation integrity failures.
    pub integrity_failures: u64,
    /// Serialized bytes grouped by operation name.
    pub operation_bytes: BTreeMap<String, u64>,
}

impl Accounting {
    /// Total serialized BEMPIC bytes in both directions.
    pub const fn total_bempic_bytes(&self) -> u64 {
        self.sender_to_receiver_bytes + self.receiver_to_sender_bytes
    }

    /// Record one complete serialized operation.
    pub fn add(&mut self, direction: Direction, operation: &Operation, bytes: usize) {
        let count = u64::try_from(bytes).expect("usize fits u64 on supported targets");
        match direction {
            Direction::SenderToReceiver => self.sender_to_receiver_bytes += count,
            Direction::ReceiverToSender => self.receiver_to_sender_bytes += count,
        }
        *self
            .operation_bytes
            .entry(operation.name().into())
            .or_default() += count;
    }

    /// Merge a contact's counters into a run.
    pub fn merge(&mut self, other: &Self) {
        self.sender_to_receiver_bytes += other.sender_to_receiver_bytes;
        self.receiver_to_sender_bytes += other.receiver_to_sender_bytes;
        self.representation_payload_bytes += other.representation_payload_bytes;
        self.duplicate_payload_bytes += other.duplicate_payload_bytes;
        self.useful_committed_bytes += other.useful_committed_bytes;
        self.integrity_failures += other.integrity_failures;
        for (name, count) in &other.operation_bytes {
            *self.operation_bytes.entry(name.clone()).or_default() += count;
        }
    }
}

impl Operation {
    /// Stable name within this implementation's metrics schema.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Capabilities(_) => "capabilities",
            Self::Summary(_) => "summary",
            Self::Offer(_) => "offer",
            Self::Request(_) => "request",
            Self::Data(_) => "data",
            Self::Receipt(_) => "receipt",
        }
    }

    /// Encode one complete experimental record.
    pub fn encode(&self) -> Result<Vec<u8>, SyncError> {
        let (kind, payload) = match self {
            Self::Capabilities(value) => {
                let mut payload = Vec::with_capacity(4);
                payload.push(value.encoding_generation);
                payload.extend_from_slice(&value.max_record_size.to_be_bytes());
                payload.push(value.features);
                (1, payload)
            }
            Self::Summary(value) => {
                let mut payload = Vec::with_capacity(24);
                payload.extend_from_slice(&value.item_count.to_be_bytes());
                payload.extend_from_slice(&value.digest);
                (2, payload)
            }
            Self::Offer(value) => {
                let mut payload = Vec::with_capacity(73);
                payload.extend_from_slice(&value.representation_id.0);
                payload.push(value.kind as u8);
                payload.extend_from_slice(&value.size.to_be_bytes());
                payload.extend_from_slice(&value.digest.0);
                payload.extend_from_slice(&value.schema_fingerprint);
                (3, payload)
            }
            Self::Request(value) => {
                let mut payload = Vec::with_capacity(28);
                payload.extend_from_slice(&value.representation_id.0);
                payload.extend_from_slice(&value.offset.to_be_bytes());
                payload.extend_from_slice(&value.max_payload_bytes.to_be_bytes());
                (4, payload)
            }
            Self::Data(value) => {
                let mut payload = Vec::with_capacity(24 + value.payload.len());
                payload.extend_from_slice(&value.representation_id.0);
                payload.extend_from_slice(&value.offset.to_be_bytes());
                payload.extend_from_slice(&value.payload);
                (5, payload)
            }
            Self::Receipt(value) => {
                let mut payload = Vec::with_capacity(49);
                payload.extend_from_slice(&value.representation_id.0);
                payload.push(value.stage as u8);
                payload.extend_from_slice(&value.digest.0);
                (6, payload)
            }
        };
        envelope(kind, &payload)
    }

    /// Strictly decode one complete experimental record.
    pub fn decode(record: &[u8]) -> Result<Self, SyncError> {
        if record.len() < ENVELOPE_SIZE {
            return Err(SyncError::Truncated);
        }
        if &record[..2] != RECORD_MAGIC {
            return Err(SyncError::InvalidMagic);
        }
        let payload_length = usize::from(u16::from_be_bytes([record[3], record[4]]));
        let payload = &record[5..];
        if payload.len() != payload_length {
            return Err(SyncError::Length);
        }
        let array16 = |slice: &[u8]| -> Result<[u8; 16], SyncError> {
            slice.try_into().map_err(|_| SyncError::Length)
        };
        let array32 = |slice: &[u8]| -> Result<[u8; 32], SyncError> {
            slice.try_into().map_err(|_| SyncError::Length)
        };
        match record[2] {
            1 if payload.len() == 4 => Ok(Self::Capabilities(Capabilities {
                encoding_generation: payload[0],
                max_record_size: u16::from_be_bytes([payload[1], payload[2]]),
                features: payload[3],
            })),
            2 if payload.len() == 24 => Ok(Self::Summary(Summary {
                item_count: u64::from_be_bytes(
                    payload[..8].try_into().map_err(|_| SyncError::Length)?,
                ),
                digest: array16(&payload[8..])?,
            })),
            3 if payload.len() == 73 => Ok(Self::Offer(Offer {
                representation_id: RepresentationId(array16(&payload[..16])?),
                kind: RepresentationKind::try_from(payload[16])?,
                size: u64::from_be_bytes(
                    payload[17..25].try_into().map_err(|_| SyncError::Length)?,
                ),
                digest: ContentDigest(array32(&payload[25..57])?),
                schema_fingerprint: array16(&payload[57..])?,
            })),
            4 if payload.len() == 28 => Ok(Self::Request(Request {
                representation_id: RepresentationId(array16(&payload[..16])?),
                offset: u64::from_be_bytes(
                    payload[16..24].try_into().map_err(|_| SyncError::Length)?,
                ),
                max_payload_bytes: u32::from_be_bytes(
                    payload[24..].try_into().map_err(|_| SyncError::Length)?,
                ),
            })),
            5 if payload.len() >= 24 => Ok(Self::Data(Data {
                representation_id: RepresentationId(array16(&payload[..16])?),
                offset: u64::from_be_bytes(
                    payload[16..24].try_into().map_err(|_| SyncError::Length)?,
                ),
                payload: payload[24..].to_vec(),
            })),
            6 if payload.len() == 49 => Ok(Self::Receipt(Receipt {
                representation_id: RepresentationId(array16(&payload[..16])?),
                stage: ReceiptStage::try_from(payload[16])?,
                digest: ContentDigest(array32(&payload[17..])?),
            })),
            1..=6 => Err(SyncError::Length),
            other => Err(SyncError::UnknownOperation(other)),
        }
    }
}

/// Record overhead before a data payload.
pub const fn data_record_overhead() -> usize {
    ENVELOPE_SIZE + 16 + 8
}

/// Deterministic, insertion-order-independent collection digest.
pub fn collection_digest<'a>(
    representations: impl IntoIterator<Item = &'a PreparedRepresentation>,
) -> [u8; 16] {
    let mut items = representations.into_iter().collect::<Vec<_>>();
    items.sort_by_key(|item| (item.id, item.digest, item.kind as u8));
    let mut hasher = Sha256::new();
    hasher.update(b"BEMPIC-COLLECTION-SUMMARY0");
    hasher.update(u32::try_from(items.len()).unwrap_or(u32::MAX).to_be_bytes());
    for item in items {
        hasher.update(item.id.0);
        hasher.update(item.digest.0);
        hasher.update([item.kind as u8]);
        hasher.update(item.size().to_be_bytes());
    }
    let digest = hasher.finalize();
    let mut short = [0; 16];
    short.copy_from_slice(&digest[..16]);
    short
}

/// Deterministic bounded page of exact representation offers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferPage {
    /// Complete offers that fit the page budget.
    pub offers: Vec<Offer>,
    /// Index of the next missing representation, or `None` when complete.
    pub next_cursor: Option<usize>,
    /// Exact serialized bytes in this page.
    pub encoded_bytes: u64,
}

/// Return representation-level set difference in identity order.
pub fn missing_representations<'a, 'b>(
    available: impl IntoIterator<Item = &'a PreparedRepresentation>,
    known: impl IntoIterator<Item = &'b PreparedRepresentation>,
) -> Result<Vec<&'a PreparedRepresentation>, SyncError> {
    fn index<'a>(
        values: impl IntoIterator<Item = &'a PreparedRepresentation>,
    ) -> Result<BTreeMap<RepresentationId, &'a PreparedRepresentation>, SyncError> {
        let mut indexed = BTreeMap::new();
        for item in values {
            if indexed
                .insert(item.id, item)
                .is_some_and(|prior| prior != item)
            {
                return Err(SyncError::IdentityCollision);
            }
        }
        Ok(indexed)
    }

    let available = index(available)?;
    let known = index(known)?;
    let mut missing = Vec::new();
    for (id, item) in available {
        match known.get(&id) {
            Some(existing) if *existing != item => return Err(SyncError::IdentityCollision),
            Some(_) => {}
            None => missing.push(item),
        }
    }
    Ok(missing)
}

/// Encode as many whole offers as fit without splitting a record.
pub fn offer_page(
    missing: &[&PreparedRepresentation],
    cursor: usize,
    budget_bytes: u64,
    max_record_size: usize,
) -> Result<OfferPage, SyncError> {
    if cursor > missing.len() {
        return Err(SyncError::Cursor);
    }
    let mut offers = Vec::new();
    let mut encoded_bytes = 0_u64;
    let mut index = cursor;
    while let Some(representation) = missing.get(index) {
        let offer = Offer::from(*representation);
        let size = Operation::Offer(offer.clone()).encode()?.len();
        if size > max_record_size {
            return Err(SyncError::RecordTooLarge);
        }
        let size = u64::try_from(size).map_err(|_| SyncError::TooLarge)?;
        if encoded_bytes.saturating_add(size) > budget_bytes {
            break;
        }
        encoded_bytes += size;
        offers.push(offer);
        index += 1;
    }
    Ok(OfferPage {
        offers,
        next_cursor: (index < missing.len()).then_some(index),
        encoded_bytes,
    })
}

fn envelope(kind: u8, payload: &[u8]) -> Result<Vec<u8>, SyncError> {
    let length = u16::try_from(payload.len()).map_err(|_| SyncError::TooLarge)?;
    let mut output = Vec::with_capacity(ENVELOPE_SIZE + payload.len());
    output.extend_from_slice(RECORD_MAGIC);
    output.push(kind);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

/// Synchronization record failure.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Model field contained an unsupported representation kind.
    #[error(transparent)]
    Model(#[from] bempic_model::ModelError),
    /// Envelope ended early.
    #[error("truncated operation envelope")]
    Truncated,
    /// Envelope marker differed.
    #[error("invalid experimental operation marker")]
    InvalidMagic,
    /// Declared and actual record sizes differed.
    #[error("operation length is invalid")]
    Length,
    /// The u16 experimental envelope cannot carry the payload.
    #[error("operation exceeds the experimental envelope")]
    TooLarge,
    /// Mandatory operation kind was unknown.
    #[error("unknown mandatory experimental operation {0}")]
    UnknownOperation(u8),
    /// Receipt stage was unknown.
    #[error("unknown receipt stage {0}")]
    UnknownReceipt(u8),
    /// A short representation identifier was reused for different metadata/bytes.
    #[error("conflicting representation identity in collection")]
    IdentityCollision,
    /// Pagination cursor was outside the deterministic missing set.
    #[error("offer cursor is outside the missing representation set")]
    Cursor,
    /// One complete offer cannot fit the negotiated record size.
    #[error("offer exceeds negotiated record size")]
    RecordTooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bempic_model::prepare_binary;

    #[test]
    fn all_operations_round_trip() {
        let representation = prepare_binary(b"operation fixture".to_vec());
        let operations = vec![
            Operation::Capabilities(Capabilities {
                encoding_generation: 0,
                max_record_size: 128,
                features: 0,
            }),
            Operation::Summary(Summary {
                item_count: 1,
                digest: representation.id.0,
            }),
            Operation::Offer(Offer::from(&representation)),
            Operation::Request(Request {
                representation_id: representation.id,
                offset: 3,
                max_payload_bytes: 10,
            }),
            Operation::Data(Data {
                representation_id: representation.id,
                offset: 3,
                payload: b"payload".to_vec(),
            }),
            Operation::Receipt(Receipt {
                representation_id: representation.id,
                stage: ReceiptStage::Stored,
                digest: representation.digest,
            }),
        ];
        for operation in operations {
            assert_eq!(
                Operation::decode(&operation.encode().unwrap()).unwrap(),
                operation
            );
        }
    }

    #[test]
    fn data_overhead_is_exact() {
        let representation = prepare_binary(Vec::new());
        let encoded = Operation::Data(Data {
            representation_id: representation.id,
            offset: 0,
            payload: Vec::new(),
        })
        .encode()
        .unwrap();
        assert_eq!(encoded.len(), data_record_overhead());
    }

    #[test]
    fn offer_pages_are_sorted_exact_and_bounded() {
        let values = (0..5)
            .map(|number| prepare_binary(format!("missing-{number}").into_bytes()))
            .collect::<Vec<_>>();
        let missing = missing_representations(values.iter().rev(), []).unwrap();
        assert!(missing.windows(2).all(|pair| pair[0].id < pair[1].id));
        let first = offer_page(&missing, 0, 156, 128).unwrap();
        assert_eq!(first.offers.len(), 2);
        assert_eq!(first.encoded_bytes, 156);
        assert_eq!(first.next_cursor, Some(2));
    }
}
