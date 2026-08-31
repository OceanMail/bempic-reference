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
