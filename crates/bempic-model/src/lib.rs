#![forbid(unsafe_code)]
//! Bounded, carrier-independent BEMPIC application objects.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use thiserror::Error;

/// Maximum UTF-8 body size accepted by the experimental v0 model.
pub const MAX_BODY_BYTES: usize = 1 << 20;
/// Maximum bytes in a short text field.
pub const MAX_SHORT_TEXT_BYTES: usize = 65_534;
/// Maximum recipients in one v0 message.
pub const MAX_RECIPIENTS: usize = 255;
/// Maximum attachments in one v0 message.
pub const MAX_ATTACHMENTS: usize = 255;

/// Stable application-level logical message identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct LogicalId(pub [u8; 16]);

impl LogicalId {
    /// Derive a deterministic identifier from an application-stable identity input.
    pub fn derive(identity_input: &[u8]) -> Self {
        Self(prefix16(&Sha256::digest(identity_input)))
    }
}

impl fmt::Display for LogicalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

/// Identity of one exact immutable prepared representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RepresentationId(pub [u8; 16]);

impl fmt::Display for RepresentationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

/// Stable identity of a part within one logical message.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PartId(pub [u8; 16]);

/// Full deterministic content digest used for integrity in the v0 proof.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ContentDigest(pub [u8; 32]);

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

/// Semantic validation class for a prepared representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RepresentationKind {
    /// Experimental compact message manifest.
    Message = 1,
    /// Opaque separately selectable binary part.
    Binary = 2,
}

impl TryFrom<u8> for RepresentationKind {
    type Error = ModelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Message),
            2 => Ok(Self::Binary),
            other => Err(ModelError::UnknownRepresentationKind(other)),
        }
    }
}

/// Metadata for independently retrievable attachment bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttachmentDescriptor {
    /// Identity of this part within the logical message.
    pub part_id: PartId,
    /// Application-supplied filename.
    pub filename: String,
    /// Application-supplied media type.
    pub media_type: String,
    /// Identity of the exact attachment bytes.
    pub representation_id: RepresentationId,
    /// Exact encoded attachment byte count.
    pub size: u64,
    /// Full digest of the exact attachment bytes.
    pub digest: ContentDigest,
}

impl AttachmentDescriptor {
    /// Validate declarative bounds and required fields.
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_required_short(&self.filename, "attachment filename")?;
        validate_required_short(&self.media_type, "attachment media type")
    }
}

/// Minimal immutable messaging model for the v0 proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Stable identity across representations and sessions.
    pub logical_id: LogicalId,
    /// Application ordering input, expressed as Unix seconds in fixtures.
    pub created_at: u64,
    /// Application-normalized sender address.
    pub sender: String,
    /// One or more application-normalized recipients.
    pub recipients: Vec<String>,
    /// Optional subject; absent is distinct from an empty string.
    pub subject: Option<String>,
    /// Normalized UTF-8 body.
    pub body: String,
    /// Descriptors only; content is independently selected.
    pub attachments: Vec<AttachmentDescriptor>,
}

impl Message {
    /// Validate all fixed v0 bounds before size analysis or encoding.
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_required_short(&self.sender, "sender")?;
        if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
            return Err(ModelError::CountOutOfBounds("recipients"));
        }
        for recipient in &self.recipients {
            validate_required_short(recipient, "recipient")?;
        }
        if let Some(subject) = &self.subject {
            validate_short(subject, "subject")?;
        }
        if self.body.len() > MAX_BODY_BYTES {
            return Err(ModelError::TextTooLong("body"));
        }
        if self.attachments.len() > MAX_ATTACHMENTS {
            return Err(ModelError::CountOutOfBounds("attachments"));
        }
        let mut part_ids = self
            .attachments
            .iter()
            .map(|item| item.part_id)
            .collect::<Vec<_>>();
        part_ids.sort_unstable();
        if part_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::DuplicatePartId);
        }
        for attachment in &self.attachments {
            attachment.validate()?;
        }
        Ok(())
    }
}

/// Exact immutable bytes and their identities, prepared before an offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRepresentation {
    /// Short experimental identity of the exact encoded bytes.
    pub id: RepresentationId,
    /// Full digest used for exact reconstruction verification.
    pub digest: ContentDigest,
    /// Immutable bytes supplied to the synchronization engine.
    pub bytes: Vec<u8>,
    /// Semantic decoding class.
    pub kind: RepresentationKind,
    /// Codec schema fingerprint, or the raw-binary profile fingerprint.
    pub schema_fingerprint: [u8; 16],
}

impl PreparedRepresentation {
    /// Construct and validate a representation from exact prepared bytes.
    pub fn new(bytes: Vec<u8>, kind: RepresentationKind, schema_fingerprint: [u8; 16]) -> Self {
        let digest = Sha256::digest(&bytes);
        let mut full = [0; 32];
        full.copy_from_slice(&digest);
        Self {
            id: RepresentationId(prefix16(&digest)),
            digest: ContentDigest(full),
            bytes,
            kind,
            schema_fingerprint,
        }
    }

    /// Exact prepared byte count.
    pub fn size(&self) -> u64 {
        u64::try_from(self.bytes.len()).expect("usize always fits u64 on supported targets")
    }

    /// Recompute and validate both identifiers.
    pub fn verify(&self) -> bool {
        let digest = Sha256::digest(&self.bytes);
        self.id.0 == prefix16(&digest) && self.digest.0.as_slice() == digest.as_slice()
    }
}

/// Prepare an opaque binary representation.
pub fn prepare_binary(bytes: impl Into<Vec<u8>>) -> PreparedRepresentation {
    PreparedRepresentation::new(
        bytes.into(),
        RepresentationKind::Binary,
        schema_fingerprint(b"BEMPIC-EXPERIMENTAL-RAW-BINARY-V0"),
    )
}

/// Build a descriptor and prepared bytes for a selectable attachment.
pub fn prepare_attachment(
    filename: impl Into<String>,
    media_type: impl Into<String>,
    content: impl Into<Vec<u8>>,
) -> Result<(AttachmentDescriptor, PreparedRepresentation), ModelError> {
    let filename = filename.into();
    let media_type = media_type.into();
    validate_required_short(&filename, "attachment filename")?;
    validate_required_short(&media_type, "attachment media type")?;
    let representation = prepare_binary(content);
    let mut input = Vec::new();
    input.extend_from_slice(b"BEMPIC-PART0\0");
    input.extend_from_slice(filename.as_bytes());
    input.push(0);
    input.extend_from_slice(media_type.as_bytes());
    input.push(0);
    input.extend_from_slice(&representation.digest.0);
    let descriptor = AttachmentDescriptor {
        part_id: PartId(prefix16(&Sha256::digest(input))),
        filename,
        media_type,
        representation_id: representation.id,
        size: representation.size(),
        digest: representation.digest,
    };
    Ok((descriptor, representation))
}

/// Deterministic 16-byte fingerprint for an experimental schema declaration.
pub fn schema_fingerprint(declaration: &[u8]) -> [u8; 16] {
    prefix16(&Sha256::digest(declaration))
}

fn prefix16(bytes: &[u8]) -> [u8; 16] {
    let mut output = [0; 16];
    output.copy_from_slice(&bytes[..16]);
    output
}

fn validate_short(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.len() > MAX_SHORT_TEXT_BYTES {
        Err(ModelError::TextTooLong(field))
    } else {
        Ok(())
    }
}

fn validate_required_short(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty() {
        Err(ModelError::Required(field))
    } else {
        validate_short(value, field)
    }
}

/// Model validation failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    /// A required text field was empty.
    #[error("{0} is required")]
    Required(&'static str),
    /// A UTF-8 field exceeded its declarative bound.
    #[error("{0} exceeds the experimental bound")]
    TextTooLong(&'static str),
    /// A repeated field count was outside the supported range.
    #[error("{0} count is outside the experimental bound")]
    CountOutOfBounds(&'static str),
    /// Two attachments reused a part identity.
    #[error("attachment part identifiers must be unique")]
    DuplicatePartId,
    /// A representation kind was not recognized.
    #[error("unknown representation kind {0}")]
    UnknownRepresentationKind(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_identity_is_deterministic() {
        let left = prepare_binary(b"same bytes".to_vec());
        let right = prepare_binary(b"same bytes".to_vec());
        assert_eq!(left, right);
        assert!(left.verify());
    }

    #[test]
    fn attachment_content_is_separate() {
        let (descriptor, representation) =
            prepare_attachment("route.csv", "text/csv", b"a,b\n1,2\n".to_vec()).unwrap();
        assert_eq!(descriptor.size, representation.size());
        assert_eq!(descriptor.representation_id, representation.id);
    }
}

/// Normative-generation semantic types derived from specification commit
/// `10fc1ddca0b16c974d29a24b6ff2bef189663a1f`.
///
/// The root-level types above remain solely for the transitional Python-oracle
/// compatibility profile. New conformance work uses this module's full-width
/// identifiers and v0.1 bounds.
pub mod v01 {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt;
    use thiserror::Error;
    use unicode_normalization::UnicodeNormalization as _;

    /// Specification commit implemented by these semantic definitions.
    pub const SPECIFICATION_COMMIT: &str = "10fc1ddca0b16c974d29a24b6ff2bef189663a1f";
    /// Registered core-operation schema fingerprint, revision 2.
    pub const CORE_SCHEMA_FINGERPRINT_HEX: &str =
        "c4a686e7e9c6a40a5f187259a376b26cfc1d355179fd9fff487e105aeeac7302";
    /// Registered message-manifest schema fingerprint, revision 1.
    pub const MESSAGE_SCHEMA_FINGERPRINT_HEX: &str =
        "0ac001efba42837aade054401d9d307d16ad4715feac288fcb3d1711e4b961da";
    /// Registered opaque-binary schema fingerprint, revision 1.
    pub const OPAQUE_SCHEMA_FINGERPRINT_HEX: &str =
        "d8906a1cefbf89e4f29b4a0f636cfbfa1e9c6301e7e3a4fe213c090066f8e797";

    /// Maximum encoded operation accepted by the semantic core.
    pub const MAX_OPERATION_OCTETS: u64 = 1_048_576;
    /// Maximum encoded or decoded representation size.
    pub const MAX_REPRESENTATION_OCTETS: u64 = 1_073_741_824;
    /// Maximum decoded message-manifest size.
    pub const MAX_MANIFEST_OCTETS: usize = 65_536;
    /// Maximum recipients in a manifest.
    pub const MAX_RECIPIENTS: usize = 32;
    /// Maximum parts in a manifest.
    pub const MAX_PARTS: usize = 64;
    /// Maximum representations per part.
    pub const MAX_REPRESENTATIONS_PER_PART: usize = 16;
    /// Maximum sender/recipient UTF-8 length.
    pub const MAX_ADDRESS_OCTETS: usize = 320;
    /// Maximum subject UTF-8 length.
    pub const MAX_SUBJECT_OCTETS: usize = 1_024;
    /// Maximum filename UTF-8 length.
    pub const MAX_FILENAME_OCTETS: usize = 255;
    /// Maximum media-type ASCII length.
    pub const MAX_MEDIA_TYPE_OCTETS: usize = 127;
    /// Maximum canonical codec-parameter block length.
    pub const MAX_CODEC_PARAMETER_OCTETS: usize = 1_024;

    /// Application-assigned immutable logical object identifier.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
    pub struct ObjectId(pub [u8; 32]);

    impl ObjectId {
        /// Deterministic fixture-only object ID. Applications own production ID policy.
        pub fn fixture(seed: &[u8]) -> Self {
            Self(Sha256::digest(seed).into())
        }
    }

    impl fmt::Display for ObjectId {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&hex::encode(self.0))
        }
    }

    /// Full RFC 8785 schema-descriptor fingerprint.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
    pub struct SchemaFingerprint(pub [u8; 32]);

    impl fmt::Display for SchemaFingerprint {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&hex::encode(self.0))
        }
    }

    /// Full v0.1 representation identifier.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
    pub struct RepresentationId(pub [u8; 32]);

    impl fmt::Display for RepresentationId {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&hex::encode(self.0))
        }
    }

    /// Full SHA-256 digest of exact representation bytes.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
    pub struct ContentDigest(pub [u8; 32]);

    /// Descriptor frozen before any representation payload is offered.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct RepresentationDescriptor {
        /// Full representation identity.
        pub representation_id: RepresentationId,
        /// Exact schema consumed by the codec.
        pub schema_fingerprint: SchemaFingerprint,
        /// Codec registry identifier.
        pub codec_id: u32,
        /// Codec revision.
        pub codec_revision: u32,
        /// Canonical codec parameters.
        pub codec_parameters: Vec<u8>,
        /// Exact encoded length in octets.
        pub encoded_length: u64,
        /// Determinate decoded length, when known.
        pub decoded_length: Option<u64>,
        /// SHA-256 of exact encoded bytes.
        pub content_digest: ContentDigest,
        /// Optional application-usefulness expiry in Unix seconds.
        pub usefulness_expiry: Option<u64>,
    }

    impl RepresentationDescriptor {
        /// Enforce descriptor bounds before allocation or persistence.
        pub fn validate(&self) -> Result<(), ModelError> {
            if self.codec_parameters.len() > MAX_CODEC_PARAMETER_OCTETS {
                return Err(ModelError::BoundExceeded("codec_parameters"));
            }
            if self.encoded_length > MAX_REPRESENTATION_OCTETS {
                return Err(ModelError::BoundExceeded("encoded_length"));
            }
            if self
                .decoded_length
                .is_some_and(|length| length > MAX_REPRESENTATION_OCTETS)
            {
                return Err(ModelError::BoundExceeded("decoded_length"));
            }
            Ok(())
        }
    }

    /// Role of one immutable message part.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum PartRole {
        /// Exactly one body is required.
        Body,
        /// Independently selectable attachment.
        Attachment,
    }

    /// One body or attachment part in a manifest.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct PartDescriptor {
        /// Identifier unique within the object.
        pub part_id: u32,
        /// Body or attachment.
        pub role: PartRole,
        /// Lowercase ASCII type/subtype.
        pub media_type: String,
        /// Optional attachment filename; always absent for a body.
        pub filename: Option<String>,
        /// One or more immutable alternatives.
        pub representations: Vec<RepresentationDescriptor>,
    }

    impl PartDescriptor {
        /// Enforce part bounds and invariants.
        pub fn validate(&self) -> Result<(), ModelError> {
            validate_media_type(&self.media_type)?;
            match (&self.role, &self.filename) {
                (PartRole::Body, Some(_)) => return Err(ModelError::BodyFilename),
                (_, Some(filename)) => {
                    validate_metadata(filename, 1, MAX_FILENAME_OCTETS, "filename")?;
                }
                _ => {}
            }
            if self.representations.is_empty()
                || self.representations.len() > MAX_REPRESENTATIONS_PER_PART
            {
                return Err(ModelError::CountOutOfBounds("representations"));
            }
            let mut ids = BTreeSet::new();
            for representation in &self.representations {
                representation.validate()?;
                if !ids.insert(representation.representation_id) {
                    return Err(ModelError::DuplicateRepresentationId);
                }
            }
            Ok(())
        }
    }

    /// Bounded immutable v0.1 message manifest.
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    pub struct MessageManifest {
        /// Stable application-assigned object ID.
        pub object_id: ObjectId,
        /// Unix seconds.
        pub created_at: u64,
        /// Normalized sender.
        pub sender: String,
        /// Ordered normalized recipients.
        pub recipients: Vec<String>,
        /// Absent or non-empty normalized subject.
        pub subject: Option<String>,
        /// Ordered body and attachment parts.
        pub parts: Vec<PartDescriptor>,
    }

    impl MessageManifest {
        /// Enforce all model bounds and cross-field invariants.
        pub fn validate(&self) -> Result<(), ModelError> {
            validate_manifest_octet_length(manifest_decoded_octets(self)?)?;
            validate_metadata(&self.sender, 1, MAX_ADDRESS_OCTETS, "sender")?;
            if self.recipients.is_empty() || self.recipients.len() > MAX_RECIPIENTS {
                return Err(ModelError::CountOutOfBounds("recipients"));
            }
            for recipient in &self.recipients {
                validate_metadata(recipient, 1, MAX_ADDRESS_OCTETS, "recipient")?;
            }
            if let Some(subject) = &self.subject {
                validate_metadata(subject, 1, MAX_SUBJECT_OCTETS, "subject")?;
            }
            if self.parts.is_empty() || self.parts.len() > MAX_PARTS {
                return Err(ModelError::CountOutOfBounds("parts"));
            }
            let mut part_ids = BTreeSet::new();
            let mut body_count = 0_usize;
            for part in &self.parts {
                part.validate()?;
                if !part_ids.insert(part.part_id) {
                    return Err(ModelError::DuplicatePartId);
                }
                body_count += usize::from(part.role == PartRole::Body);
            }
            if body_count != 1 {
                return Err(ModelError::BodyCount);
            }
            Ok(())
        }
    }

    /// Exact decoded scalar storage represented by a message manifest.
    ///
    /// The formula includes every fixed-width scalar and every variable-length
    /// octet/string member, including representation descriptors. Container
    /// implementation overhead is deliberately excluded so the result is
    /// deterministic across implementations.
    pub fn manifest_decoded_octets(manifest: &MessageManifest) -> Result<usize, ModelError> {
        fn add(total: &mut usize, value: usize) -> Result<(), ModelError> {
            *total = total
                .checked_add(value)
                .ok_or(ModelError::AllocationSizeOverflow)?;
            Ok(())
        }

        let mut total = 32 + 8;
        add(&mut total, manifest.sender.len())?;
        for recipient in &manifest.recipients {
            add(&mut total, recipient.len())?;
        }
        if let Some(subject) = &manifest.subject {
            add(&mut total, subject.len())?;
        }
        for part in &manifest.parts {
            add(&mut total, 4 + 1)?;
            add(&mut total, part.media_type.len())?;
            if let Some(filename) = &part.filename {
                add(&mut total, filename.len())?;
            }
            for representation in &part.representations {
                add(&mut total, 32 + 32 + 4 + 4)?;
                add(&mut total, representation.codec_parameters.len())?;
                add(&mut total, 8 + 1)?;
                if representation.decoded_length.is_some() {
                    add(&mut total, 8)?;
                }
                add(&mut total, 32 + 1)?;
                if representation.usefulness_expiry.is_some() {
                    add(&mut total, 8)?;
                }
            }
        }
        Ok(total)
    }

    /// Stable per-scope orientation for normative semantic-byte accounting.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SemanticDirection {
        /// Endpoint A to endpoint B.
        Send,
        /// Endpoint B to endpoint A.
        Receive,
    }

    /// Normative directional `semantic_bytes` counters for one endpoint-bound scope.
    ///
    /// The scope owner must bind endpoint A and endpoint B once. A selected
    /// representation contributes at most once in each direction, even when it
    /// is contacted, replayed, overlapped, retried, or resumed multiple times.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct SemanticAccounting {
        semantic_bytes_send: u64,
        semantic_bytes_receive: u64,
        selections: BTreeMap<(SemanticDirection, RepresentationId), u64>,
    }

    impl SemanticAccounting {
        /// Record the first accepted application selection in this scope.
        ///
        /// Returns `true` only when the `(direction, representation_id)` key is
        /// new. Repeating a key with a different semantic value fails closed.
        pub fn record_selection(
            &mut self,
            direction: SemanticDirection,
            representation_id: RepresentationId,
            semantic_octets: u64,
        ) -> Result<bool, ModelError> {
            let key = (direction, representation_id);
            if let Some(previous) = self.selections.get(&key) {
                return if *previous == semantic_octets {
                    Ok(false)
                } else {
                    Err(ModelError::SemanticSelectionConflict)
                };
            }
            self.semantic_bytes_send
                .checked_add(self.semantic_bytes_receive)
                .and_then(|total| total.checked_add(semantic_octets))
                .ok_or(ModelError::SemanticBytesOverflow)?;
            let counter = match direction {
                SemanticDirection::Send => &mut self.semantic_bytes_send,
                SemanticDirection::Receive => &mut self.semantic_bytes_receive,
            };
            *counter = counter
                .checked_add(semantic_octets)
                .ok_or(ModelError::SemanticBytesOverflow)?;
            self.selections.insert(key, semantic_octets);
            Ok(true)
        }

        /// Endpoint-A-to-endpoint-B semantic octets.
        pub const fn semantic_bytes_send(&self) -> u64 {
            self.semantic_bytes_send
        }

        /// Endpoint-B-to-endpoint-A semantic octets.
        pub const fn semantic_bytes_receive(&self) -> u64 {
            self.semantic_bytes_receive
        }

        /// Sum of both stable directions.
        pub const fn semantic_bytes(&self) -> u64 {
            self.semantic_bytes_send + self.semantic_bytes_receive
        }

        /// Number of distinct directional selection keys counted in the scope.
        pub fn counted_selections(&self) -> usize {
            self.selections.len()
        }
    }

    /// Compute normative semantic octets for a decoded message manifest.
    ///
    /// Only application fields contribute. The representations container and
    /// all descriptor members contribute zero, including IDs, fingerprints,
    /// codec fields, lengths, digests, and expiry.
    pub fn message_manifest_semantic_octets(manifest: &MessageManifest) -> Result<u64, ModelError> {
        manifest.validate()?;
        let mut total =
            32_u64 // object_id octet string
                .checked_add(8) // created_at u64
                .and_then(|value| value.checked_add(manifest.sender.len() as u64))
                .ok_or(ModelError::SemanticBytesOverflow)?;
        for recipient in &manifest.recipients {
            total = total
                .checked_add(recipient.len() as u64)
                .ok_or(ModelError::SemanticBytesOverflow)?;
        }
        if let Some(subject) = &manifest.subject {
            total = total
                .checked_add(subject.len() as u64)
                .ok_or(ModelError::SemanticBytesOverflow)?;
        }
        for part in &manifest.parts {
            total = total
                .checked_add(4) // part_id u32
                .and_then(|value| value.checked_add(1)) // role enum
                .and_then(|value| value.checked_add(part.media_type.len() as u64))
                .ok_or(ModelError::SemanticBytesOverflow)?;
            if let Some(filename) = &part.filename {
                total = total
                    .checked_add(filename.len() as u64)
                    .ok_or(ModelError::SemanticBytesOverflow)?;
            }
        }
        Ok(total)
    }

    /// Compute semantic octets for an opaque decoded binary value.
    pub fn opaque_semantic_octets(decoded_value: &[u8]) -> Result<u64, ModelError> {
        u64::try_from(decoded_value.len()).map_err(|_| ModelError::SemanticBytesOverflow)
    }

    /// Reject an input envelope before decoding or a decoded aggregate before mutation.
    ///
    /// Byte-oriented decoders must call this with the input envelope length
    /// before constructing the value tree. `MessageManifest::validate` calls it
    /// again with `manifest_decoded_octets` before any durable mutation.
    pub const fn validate_manifest_octet_length(length: usize) -> Result<(), ModelError> {
        if length > MAX_MANIFEST_OCTETS {
            Err(ModelError::BoundExceeded("manifest_octets"))
        } else {
            Ok(())
        }
    }

    /// Result of observing immutable object semantics at the protocol boundary.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ImmutableObservation {
        /// This object identifier was not previously bound in the registry.
        New,
        /// The object identifier was already bound to identical immutable semantics.
        Duplicate,
    }

    /// Policy-free value model for immutable object-ID conflict detection.
    ///
    /// Applications define and normalize the immutable-semantics digest. BEMPIC
    /// stores only the opaque 32-octet binding and never overwrites a conflict.
    /// Durable implementations use `bempic_store::v01::ProtocolStore`.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct ImmutableObjectRegistry {
        bindings: BTreeMap<ObjectId, [u8; 32]>,
    }

    impl ImmutableObjectRegistry {
        /// Observe one object binding idempotently without mutating unrelated state.
        pub fn observe(
            &mut self,
            object_id: ObjectId,
            immutable_semantics_digest: [u8; 32],
        ) -> Result<ImmutableObservation, ModelError> {
            match self.bindings.get(&object_id) {
                Some(existing) if existing == &immutable_semantics_digest => {
                    Ok(ImmutableObservation::Duplicate)
                }
                Some(_) => Err(ModelError::ImmutableObjectConflict),
                None => {
                    self.bindings.insert(object_id, immutable_semantics_digest);
                    Ok(ImmutableObservation::New)
                }
            }
        }

        /// Return the exact opaque binding for inspection or persistence.
        pub fn binding(&self, object_id: ObjectId) -> Option<[u8; 32]> {
            self.bindings.get(&object_id).copied()
        }
    }

    /// Exact immutable bytes and descriptor produced by v0.1 preparation.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PreparedRepresentation {
        /// Frozen descriptor.
        pub descriptor: RepresentationDescriptor,
        /// Frozen encoded bytes.
        pub bytes: Vec<u8>,
    }

    impl PreparedRepresentation {
        /// Prepare exact bytes using a selected schema, codec, and parameters.
        pub fn prepare(
            bytes: Vec<u8>,
            decoded_length: Option<u64>,
            schema_fingerprint: SchemaFingerprint,
            codec_id: u32,
            codec_revision: u32,
            codec_parameters: Vec<u8>,
            usefulness_expiry: Option<u64>,
        ) -> Result<Self, ModelError> {
            let encoded_length = u64::try_from(bytes.len())
                .map_err(|_| ModelError::BoundExceeded("encoded_length"))?;
            if encoded_length > MAX_REPRESENTATION_OCTETS {
                return Err(ModelError::BoundExceeded("encoded_length"));
            }
            if codec_parameters.len() > MAX_CODEC_PARAMETER_OCTETS {
                return Err(ModelError::BoundExceeded("codec_parameters"));
            }
            if decoded_length.is_some_and(|length| length > MAX_REPRESENTATION_OCTETS) {
                return Err(ModelError::BoundExceeded("decoded_length"));
            }
            let content_digest = ContentDigest(Sha256::digest(&bytes).into());
            let representation_id = representation_id(
                schema_fingerprint,
                codec_id,
                codec_revision,
                &codec_parameters,
                encoded_length,
                content_digest,
            )?;
            let descriptor = RepresentationDescriptor {
                representation_id,
                schema_fingerprint,
                codec_id,
                codec_revision,
                codec_parameters,
                encoded_length,
                decoded_length,
                content_digest,
                usefulness_expiry,
            };
            descriptor.validate()?;
            Ok(Self { descriptor, bytes })
        }

        /// Recompute digest and representation identity with a constant-work compare.
        pub fn verify(&self) -> bool {
            if self.descriptor.validate().is_err()
                || self.descriptor.encoded_length != self.bytes.len() as u64
            {
                return false;
            }
            let digest = ContentDigest(Sha256::digest(&self.bytes).into());
            let Ok(identifier) = representation_id(
                self.descriptor.schema_fingerprint,
                self.descriptor.codec_id,
                self.descriptor.codec_revision,
                &self.descriptor.codec_parameters,
                self.descriptor.encoded_length,
                digest,
            ) else {
                return false;
            };
            constant_time_equal(&digest.0, &self.descriptor.content_digest.0)
                && constant_time_equal(&identifier.0, &self.descriptor.representation_id.0)
        }
    }

    /// Compute a schema fingerprint from already RFC 8785-canonical descriptor bytes.
    pub fn schema_fingerprint(
        canonical_descriptor: &[u8],
    ) -> Result<SchemaFingerprint, ModelError> {
        let length = u32::try_from(canonical_descriptor.len())
            .map_err(|_| ModelError::BoundExceeded("schema_descriptor"))?;
        let mut hasher = Sha256::new();
        hasher.update(b"BEMPIC-SCHEMA-FINGERPRINT-v0.1\0");
        hasher.update(length.to_be_bytes());
        hasher.update(canonical_descriptor);
        Ok(SchemaFingerprint(hasher.finalize().into()))
    }

    /// Compute the full representation ID exactly as specified.
    pub fn representation_id(
        fingerprint: SchemaFingerprint,
        codec_id: u32,
        codec_revision: u32,
        parameters: &[u8],
        encoded_length: u64,
        digest: ContentDigest,
    ) -> Result<RepresentationId, ModelError> {
        let parameter_length = u32::try_from(parameters.len())
            .map_err(|_| ModelError::BoundExceeded("codec_parameters"))?;
        if parameters.len() > MAX_CODEC_PARAMETER_OCTETS {
            return Err(ModelError::BoundExceeded("codec_parameters"));
        }
        if encoded_length > MAX_REPRESENTATION_OCTETS {
            return Err(ModelError::BoundExceeded("encoded_length"));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"BEMPIC-REPRESENTATION-ID-v0.1\0");
        hasher.update(fingerprint.0);
        hasher.update(codec_id.to_be_bytes());
        hasher.update(codec_revision.to_be_bytes());
        hasher.update(parameter_length.to_be_bytes());
        hasher.update(parameters);
        hasher.update(encoded_length.to_be_bytes());
        hasher.update(digest.0);
        Ok(RepresentationId(hasher.finalize().into()))
    }

    /// Decode one published lowercase 32-octet hexadecimal value.
    pub fn fingerprint_from_hex(value: &str) -> Result<SchemaFingerprint, ModelError> {
        let bytes = hex::decode(value).map_err(|_| ModelError::FingerprintHex)?;
        let array = bytes.try_into().map_err(|_| ModelError::FingerprintHex)?;
        Ok(SchemaFingerprint(array))
    }

    fn validate_metadata(
        value: &str,
        minimum: usize,
        maximum: usize,
        field: &'static str,
    ) -> Result<(), ModelError> {
        if value.len() < minimum || value.len() > maximum {
            return Err(ModelError::BoundExceeded(field));
        }
        if value.nfc().ne(value.chars()) {
            return Err(ModelError::NotNfc(field));
        }
        if value.chars().any(|character| {
            let scalar = u32::from(character);
            scalar == 0 || scalar <= 0x1f || (0x7f..=0x9f).contains(&scalar)
        }) {
            return Err(ModelError::ControlCharacter(field));
        }
        Ok(())
    }

    fn validate_media_type(value: &str) -> Result<(), ModelError> {
        if value.len() < 3 || value.len() > MAX_MEDIA_TYPE_OCTETS || !value.is_ascii() {
            return Err(ModelError::BoundExceeded("media_type"));
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || byte.is_ascii_control())
            || value.matches('/').count() != 1
            || value.starts_with('/')
            || value.ends_with('/')
        {
            return Err(ModelError::MediaType);
        }
        Ok(())
    }

    fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
        left.iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
    }

    /// v0.1 semantic-model failure.
    #[derive(Debug, Error, Eq, PartialEq)]
    pub enum ModelError {
        /// A declarative bound was violated.
        #[error("{0} violates a v0.1 bound")]
        BoundExceeded(&'static str),
        /// Metadata was not Unicode NFC.
        #[error("{0} is not Unicode NFC")]
        NotNfc(&'static str),
        /// Metadata contained a prohibited control.
        #[error("{0} contains a prohibited control character")]
        ControlCharacter(&'static str),
        /// Media type was not lowercase ASCII type/subtype.
        #[error("media_type is not a lowercase ASCII type/subtype")]
        MediaType,
        /// Body part carried a filename.
        #[error("body filename must be absent")]
        BodyFilename,
        /// Manifest did not contain exactly one body.
        #[error("manifest must contain exactly one body part")]
        BodyCount,
        /// Part ID was reused within one object.
        #[error("part_id values must be unique within an object")]
        DuplicatePartId,
        /// Representation ID was reused within one part.
        #[error("representation_id values must be unique within a part")]
        DuplicateRepresentationId,
        /// A repeated field count was invalid.
        #[error("{0} count violates a v0.1 bound")]
        CountOutOfBounds(&'static str),
        /// Published fingerprint was not exactly 32 lowercase hexadecimal octets.
        #[error("schema fingerprint hexadecimal value is invalid")]
        FingerprintHex,
        /// A repeated directional selection supplied inconsistent semantic content.
        #[error("directional semantic selection conflicts with its first value")]
        SemanticSelectionConflict,
        /// Semantic-byte arithmetic exceeded the u64 evidence domain.
        #[error("semantic byte count overflow")]
        SemanticBytesOverflow,
        /// Decoded allocation arithmetic exceeded the platform size domain.
        #[error("decoded allocation size overflow")]
        AllocationSizeOverflow,
        /// An object ID was reused for different opaque immutable semantics.
        #[error("object ID conflicts with its immutable semantics binding")]
        ImmutableObjectConflict,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn binary(bytes: Vec<u8>) -> PreparedRepresentation {
            PreparedRepresentation::prepare(
                bytes,
                None,
                fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).unwrap(),
                0xffff_0001,
                1,
                Vec::new(),
                None,
            )
            .unwrap()
        }

        #[test]
        fn full_representation_identity_binds_every_descriptor_field() {
            let prepared = binary(b"v0.1 bytes".to_vec());
            assert!(prepared.verify());
            assert_eq!(prepared.descriptor.representation_id.0.len(), 32);
            let mut changed = prepared.clone();
            changed.descriptor.codec_revision = 2;
            assert!(!changed.verify());
        }

        #[test]
        fn semantic_bytes_exclude_descriptors_and_count_directional_selection_once() {
            let representation = binary(b"encoded bytes do not count".to_vec());
            let manifest = MessageManifest {
                object_id: ObjectId([0x11; 32]),
                created_at: 1,
                sender: "a@example.test".to_owned(),
                recipients: vec!["b@example.test".to_owned()],
                subject: Some("Hi".to_owned()),
                parts: vec![PartDescriptor {
                    part_id: 0,
                    role: PartRole::Body,
                    media_type: "text/plain".to_owned(),
                    filename: None,
                    representations: vec![representation.descriptor.clone()],
                }],
            };
            let expected = 32 + 8 + 14 + 14 + 2 + 4 + 1 + 10;
            assert_eq!(message_manifest_semantic_octets(&manifest), Ok(expected));

            let mut changed = manifest.clone();
            changed.parts[0].representations[0] = binary(vec![0xff; 100]).descriptor;
            assert_eq!(message_manifest_semantic_octets(&changed), Ok(expected));

            let mut accounting = SemanticAccounting::default();
            let id = representation.descriptor.representation_id;
            assert_eq!(
                accounting.record_selection(SemanticDirection::Send, id, expected),
                Ok(true)
            );
            assert_eq!(
                accounting.record_selection(SemanticDirection::Send, id, expected),
                Ok(false)
            );
            assert_eq!(
                accounting.record_selection(SemanticDirection::Receive, id, 7),
                Ok(true)
            );
            assert_eq!(accounting.semantic_bytes_send(), expected);
            assert_eq!(accounting.semantic_bytes_receive(), 7);
            assert_eq!(accounting.semantic_bytes(), expected + 7);
            assert_eq!(accounting.counted_selections(), 2);
            assert_eq!(
                accounting.record_selection(SemanticDirection::Send, id, expected + 1),
                Err(ModelError::SemanticSelectionConflict)
            );

            let mut overflow = SemanticAccounting::default();
            assert_eq!(
                overflow.record_selection(SemanticDirection::Send, id, u64::MAX),
                Ok(true)
            );
            assert_eq!(
                overflow.record_selection(SemanticDirection::Receive, id, 1),
                Err(ModelError::SemanticBytesOverflow)
            );
            assert_eq!(overflow.semantic_bytes(), u64::MAX);
            assert_eq!(overflow.counted_selections(), 1);
        }

        #[test]
        fn immutable_object_registry_is_idempotent_and_preserves_unrelated_bindings() {
            let first = ObjectId([1; 32]);
            let unrelated = ObjectId([2; 32]);
            let mut registry = ImmutableObjectRegistry::default();
            assert_eq!(
                registry.observe(first, [3; 32]),
                Ok(ImmutableObservation::New)
            );
            assert_eq!(
                registry.observe(unrelated, [4; 32]),
                Ok(ImmutableObservation::New)
            );
            assert_eq!(
                registry.observe(first, [3; 32]),
                Ok(ImmutableObservation::Duplicate)
            );
            assert_eq!(
                registry.observe(first, [5; 32]),
                Err(ModelError::ImmutableObjectConflict)
            );
            assert_eq!(registry.binding(first), Some([3; 32]));
            assert_eq!(registry.binding(unrelated), Some([4; 32]));
        }

        #[test]
        fn manifest_allocation_bound_rejects_one_past() {
            assert_eq!(validate_manifest_octet_length(MAX_MANIFEST_OCTETS), Ok(()));
            assert_eq!(
                validate_manifest_octet_length(MAX_MANIFEST_OCTETS + 1),
                Err(ModelError::BoundExceeded("manifest_octets"))
            );

            let descriptor = binary(Vec::new()).descriptor;
            let mut manifest = MessageManifest {
                object_id: ObjectId::fixture(b"aggregate-bound"),
                created_at: 0,
                sender: "s".into(),
                recipients: vec!["r".into()],
                subject: None,
                parts: (0..MAX_PARTS)
                    .map(|part_id| PartDescriptor {
                        part_id: u32::try_from(part_id).unwrap(),
                        role: if part_id == 0 {
                            PartRole::Body
                        } else {
                            PartRole::Attachment
                        },
                        media_type: "a/b".into(),
                        filename: (part_id != 0).then(|| "f".into()),
                        representations: vec![descriptor.clone()],
                    })
                    .collect(),
            };
            let baseline = manifest_decoded_octets(&manifest).unwrap();
            let mut remaining = MAX_MANIFEST_OCTETS + 1 - baseline;
            for part in &mut manifest.parts {
                let take = remaining.min(MAX_CODEC_PARAMETER_OCTETS);
                part.representations[0].codec_parameters = vec![0; take];
                remaining -= take;
            }
            assert_eq!(remaining, 0);
            assert_eq!(
                manifest_decoded_octets(&manifest),
                Ok(MAX_MANIFEST_OCTETS + 1)
            );
            assert_eq!(
                manifest.validate(),
                Err(ModelError::BoundExceeded("manifest_octets"))
            );
        }

        #[test]
        fn published_rfc8785_schema_fingerprints_are_exact() {
            let vectors = [
                (
                    include_bytes!("../../../schemas/v0.1/core-operations.schema.jcs").as_slice(),
                    CORE_SCHEMA_FINGERPRINT_HEX,
                ),
                (
                    include_bytes!("../../../schemas/v0.1/message-manifest.schema.jcs").as_slice(),
                    MESSAGE_SCHEMA_FINGERPRINT_HEX,
                ),
                (
                    include_bytes!("../../../schemas/v0.1/opaque-binary.schema.jcs").as_slice(),
                    OPAQUE_SCHEMA_FINGERPRINT_HEX,
                ),
            ];
            for (descriptor, expected) in vectors {
                let canonical = descriptor.strip_suffix(b"\n").unwrap_or(descriptor);
                assert_eq!(schema_fingerprint(canonical).unwrap().to_string(), expected);
            }
        }

        #[test]
        fn manifest_enforces_nfc_controls_counts_and_part_invariants() {
            let representation = binary(Vec::new()).descriptor;
            let valid = MessageManifest {
                object_id: ObjectId::fixture(b"manifest"),
                created_at: 0,
                sender: "shore@example.test".into(),
                recipients: vec!["vessel@example.test".into()],
                subject: None,
                parts: vec![PartDescriptor {
                    part_id: 1,
                    role: PartRole::Body,
                    media_type: "text/plain".into(),
                    filename: None,
                    representations: vec![representation],
                }],
            };
            assert_eq!(valid.validate(), Ok(()));
            let mut decomposed = valid.clone();
            decomposed.subject = Some("cafe\u{301}".into());
            assert_eq!(decomposed.validate(), Err(ModelError::NotNfc("subject")));
            let mut no_body = valid;
            no_body.parts[0].role = PartRole::Attachment;
            assert_eq!(no_body.validate(), Err(ModelError::BodyCount));
        }
    }
}
