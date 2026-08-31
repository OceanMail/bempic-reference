#![forbid(unsafe_code)]
//! Replaceable candidate representation codecs. No codec here is stable.

use bempic_model::{
    schema_fingerprint, AttachmentDescriptor, ContentDigest, LogicalId, Message, ModelError,
    PartId, PreparedRepresentation, RepresentationId, RepresentationKind, MAX_ATTACHMENTS,
    MAX_BODY_BYTES, MAX_RECIPIENTS, MAX_SHORT_TEXT_BYTES,
};
use thiserror::Error;

const MESSAGE_MAGIC: &[u8; 5] = b"BMSG0";
const SCHEMA_DECLARATION: &[u8] = b"BEMPIC-EXPERIMENTAL-MESSAGE-V0|be-fixed|logical-id:16|created:u64|short:utf8:u16|recipients:u8|body:utf8:u32|max-body:1048576|attachments:u8";

/// Declarative limits advertised by a candidate codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecBounds {
    /// Maximum bytes per short UTF-8 field.
    pub max_short_text_bytes: usize,
    /// Maximum body bytes.
    pub max_body_bytes: usize,
    /// Maximum recipients.
    pub max_recipients: usize,
    /// Maximum attachments.
    pub max_attachments: usize,
    /// Conservative maximum encoded message size.
    pub max_encoded_size: usize,
}

/// A deterministic, bounded, exactly measurable message codec.
pub trait RepresentationCodec {
    /// Human-readable experimental profile name.
    fn name(&self) -> &'static str;
    /// Fingerprint of the full declarative schema.
    fn schema_fingerprint(&self) -> [u8; 16];
    /// Static bounds enforced by the codec.
    fn bounds(&self) -> CodecBounds;
    /// Determine the exact byte count without emitting bytes.
    fn exact_encoded_size(&self, message: &Message) -> Result<usize, CodecError>;
    /// Encode one deterministic message representation.
    fn encode(&self, message: &Message) -> Result<Vec<u8>, CodecError>;
    /// Strictly decode one complete representation.
    fn decode(&self, bytes: &[u8]) -> Result<Message, CodecError>;

    /// Prepare immutable bytes and identities after exact analysis.
    fn prepare(&self, message: &Message) -> Result<PreparedRepresentation, CodecError> {
        let expected = self.exact_encoded_size(message)?;
        let bytes = self.encode(message)?;
        if bytes.len() != expected {
            return Err(CodecError::InternalSizeMismatch {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(PreparedRepresentation::new(
            bytes,
            RepresentationKind::Message,
            self.schema_fingerprint(),
        ))
    }
}

/// The Python-oracle-compatible generation-0 candidate codec.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExperimentalCodecV0;

impl RepresentationCodec for ExperimentalCodecV0 {
    fn name(&self) -> &'static str {
        "experimental-message-v0"
    }

    fn schema_fingerprint(&self) -> [u8; 16] {
        schema_fingerprint(SCHEMA_DECLARATION)
    }

    fn bounds(&self) -> CodecBounds {
        let base = 5 + 16 + 8 + 2 + 1 + 2 + 4 + 1;
        let recipients = MAX_RECIPIENTS * (2 + MAX_SHORT_TEXT_BYTES);
        let attachment = 16 + (2 + MAX_SHORT_TEXT_BYTES) * 2 + 16 + 8 + 32;
        CodecBounds {
            max_short_text_bytes: MAX_SHORT_TEXT_BYTES,
            max_body_bytes: MAX_BODY_BYTES,
            max_recipients: MAX_RECIPIENTS,
            max_attachments: MAX_ATTACHMENTS,
            max_encoded_size: base
                + MAX_SHORT_TEXT_BYTES * 2
                + recipients
                + MAX_BODY_BYTES
                + MAX_ATTACHMENTS * attachment,
        }
    }

    fn exact_encoded_size(&self, message: &Message) -> Result<usize, CodecError> {
        message.validate()?;
        let mut size = MESSAGE_MAGIC.len() + 16 + 8;
        size = checked_add(size, short_size(&message.sender)?)?;
        size = checked_add(size, 1)?;
        for recipient in &message.recipients {
            size = checked_add(size, short_size(recipient)?)?;
        }
        size = checked_add(size, 2)?;
        if let Some(subject) = &message.subject {
            size = checked_add(size, subject.len())?;
        }
        size = checked_add(size, 4 + message.body.len() + 1)?;
        for attachment in &message.attachments {
            size = checked_add(size, 16)?;
            size = checked_add(size, short_size(&attachment.filename)?)?;
            size = checked_add(size, short_size(&attachment.media_type)?)?;
            size = checked_add(size, 16 + 8 + 32)?;
        }
        Ok(size)
    }

    fn encode(&self, message: &Message) -> Result<Vec<u8>, CodecError> {
        let size = self.exact_encoded_size(message)?;
        let mut output = Vec::with_capacity(size);
        output.extend_from_slice(MESSAGE_MAGIC);
        output.extend_from_slice(&message.logical_id.0);
        output.extend_from_slice(&message.created_at.to_be_bytes());
        put_short(&mut output, &message.sender)?;
        output.push(u8::try_from(message.recipients.len()).map_err(|_| CodecError::Length)?);
        for recipient in &message.recipients {
            put_short(&mut output, recipient)?;
        }
        if let Some(subject) = &message.subject {
            put_short(&mut output, subject)?;
        } else {
            output.extend_from_slice(&u16::MAX.to_be_bytes());
        }
        output.extend_from_slice(
            &u32::try_from(message.body.len())
                .map_err(|_| CodecError::Length)?
                .to_be_bytes(),
        );
        output.extend_from_slice(message.body.as_bytes());
        output.push(u8::try_from(message.attachments.len()).map_err(|_| CodecError::Length)?);
        for attachment in &message.attachments {
            output.extend_from_slice(&attachment.part_id.0);
            put_short(&mut output, &attachment.filename)?;
            put_short(&mut output, &attachment.media_type)?;
            output.extend_from_slice(&attachment.representation_id.0);
            output.extend_from_slice(&attachment.size.to_be_bytes());
            output.extend_from_slice(&attachment.digest.0);
        }
        debug_assert_eq!(size, output.len());
        Ok(output)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Message, CodecError> {
        if bytes.len() > self.bounds().max_encoded_size {
            return Err(CodecError::BoundExceeded("encoded message"));
        }
        let mut reader = Reader::new(bytes);
        if reader.take(5)? != MESSAGE_MAGIC {
            return Err(CodecError::InvalidMagic);
        }
        let logical_id = LogicalId(reader.array()?);
        let created_at = reader.u64()?;
        let sender = reader.short("sender", false)?.expect("non-null short");
        let recipient_count = usize::from(reader.u8()?);
        if recipient_count == 0 || recipient_count > MAX_RECIPIENTS {
            return Err(CodecError::BoundExceeded("recipients"));
        }
        let mut recipients = Vec::with_capacity(recipient_count);
        for _ in 0..recipient_count {
            recipients.push(reader.short("recipient", false)?.expect("non-null short"));
        }
        let subject = reader.short("subject", true)?;
        let body_length = usize::try_from(reader.u32()?).map_err(|_| CodecError::Length)?;
        if body_length > MAX_BODY_BYTES {
            return Err(CodecError::BoundExceeded("body"));
        }
        let body = decode_utf8(reader.take(body_length)?, "body")?;
        let attachment_count = usize::from(reader.u8()?);
        if attachment_count > MAX_ATTACHMENTS {
            return Err(CodecError::BoundExceeded("attachments"));
        }
        let mut attachments = Vec::with_capacity(attachment_count);
        for _ in 0..attachment_count {
            attachments.push(AttachmentDescriptor {
                part_id: PartId(reader.array()?),
                filename: reader
                    .short("attachment filename", false)?
                    .expect("non-null short"),
                media_type: reader
                    .short("attachment media type", false)?
                    .expect("non-null short"),
                representation_id: RepresentationId(reader.array()?),
                size: reader.u64()?,
                digest: ContentDigest(reader.array()?),
            });
        }
        if !reader.is_empty() {
            return Err(CodecError::TrailingBytes);
        }
        let message = Message {
            logical_id,
            created_at,
            sender,
            recipients,
            subject,
            body,
            attachments,
        };
        message.validate()?;
        Ok(message)
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, CodecError> {
    left.checked_add(right).ok_or(CodecError::Length)
}

fn short_size(value: &str) -> Result<usize, CodecError> {
    if value.len() > MAX_SHORT_TEXT_BYTES {
        Err(CodecError::BoundExceeded("short text"))
    } else {
        Ok(2 + value.len())
    }
}

fn put_short(output: &mut Vec<u8>, value: &str) -> Result<(), CodecError> {
    let length = u16::try_from(value.len()).map_err(|_| CodecError::Length)?;
    if length == u16::MAX {
        return Err(CodecError::BoundExceeded("short text"));
    }
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_utf8(bytes: &[u8], field: &'static str) -> Result<String, CodecError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| CodecError::InvalidUtf8(field))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self.offset.checked_add(length).ok_or(CodecError::Length)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn short(&mut self, field: &'static str, nullable: bool) -> Result<Option<String>, CodecError> {
        let length = self.u16()?;
        if length == u16::MAX {
            return if nullable {
                Ok(None)
            } else {
                Err(CodecError::InvalidNull(field))
            };
        }
        decode_utf8(self.take(usize::from(length))?, field).map(Some)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Strict codec failure.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Application model validation failed.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// Input ended before a complete field was available.
    #[error("truncated message representation")]
    Truncated,
    /// The candidate marker was not recognized.
    #[error("invalid experimental message marker")]
    InvalidMagic,
    /// Additional bytes followed the complete representation.
    #[error("trailing bytes after message representation")]
    TrailingBytes,
    /// A field was not valid UTF-8.
    #[error("{0} is not valid UTF-8")]
    InvalidUtf8(&'static str),
    /// A non-null field used the null marker.
    #[error("invalid null marker for {0}")]
    InvalidNull(&'static str),
    /// A declared allocation or text bound was exceeded.
    #[error("{0} exceeds a declarative codec bound")]
    BoundExceeded(&'static str),
    /// A size could not be represented safely.
    #[error("representation length is not supported")]
    Length,
    /// Size analysis and actual emission differed.
    #[error("internal exact-size mismatch: predicted {expected}, emitted {actual}")]
    InternalSizeMismatch {
        /// Predicted byte count.
        expected: usize,
        /// Actual emitted byte count.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message() -> Message {
        Message {
            logical_id: LogicalId::derive(b"codec-test"),
            created_at: 1_788_112_800,
            sender: "shore@example.test".into(),
            recipients: vec!["vessel@example.test".into()],
            subject: Some("Weather".into()),
            body: "Wind 12 kt".into(),
            attachments: vec![],
        }
    }

    #[test]
    fn exact_size_and_round_trip() {
        let codec = ExperimentalCodecV0;
        let message = message();
        let encoded = codec.encode(&message).unwrap();
        assert_eq!(codec.exact_encoded_size(&message).unwrap(), encoded.len());
        assert_eq!(codec.decode(&encoded).unwrap(), message);
    }

    #[test]
    fn rejects_trailing_data() {
        let codec = ExperimentalCodecV0;
        let mut encoded = codec.encode(&message()).unwrap();
        encoded.push(1);
        assert!(matches!(
            codec.decode(&encoded),
            Err(CodecError::TrailingBytes)
        ));
    }
}
