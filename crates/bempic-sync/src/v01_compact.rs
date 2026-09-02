//! Public experimental compact operation codec `0x00010000/1`.
//!
//! The tuple is allocated but remains experimental: it is not approved,
//! mandatory, stable, or a production-security promise. It losslessly aliases
//! one exact profile capability value and, only with an exact caller-supplied
//! durable checkpoint, that checkpoint's full `SUMMARY`. An alias never
//! supplies or overrides a different full value.

use crate::v01::{
    declared_max_encoded_size as legacy_declared_max, negotiate, Capabilities, CodecPreference,
    Error, FailureCode, NegotiatedProfile, Operation, OperationKind, ProtocolGeneration, Record,
    SecurityClass, Summary, MAX_EXPERIMENTAL_RECORD_OCTETS,
};
use bempic_model::v01::{RepresentationDescriptor, SchemaFingerprint};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Allocated public experimental codec ID.
pub const EXPERIMENTAL_CODEC_ID: u32 = 0x0001_0000;
/// Allocated public experimental codec revision.
pub const EXPERIMENTAL_CODEC_REVISION: u32 = 1;
/// Public experimental codec identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecIdentity {
    /// Registry codec identifier.
    pub id: u32,
    /// Codec revision.
    pub revision: u32,
}

/// Exact public experimental identity implemented by this module.
pub const EXPERIMENTAL_CODEC_IDENTITY: CodecIdentity = CodecIdentity {
    id: EXPERIMENTAL_CODEC_ID,
    revision: EXPERIMENTAL_CODEC_REVISION,
};
/// Maximum complete record accepted by the candidate decoder.
pub const MAX_COMPACT_RECORD_OCTETS: usize = MAX_EXPERIMENTAL_RECORD_OCTETS;

const HEADER_PREFIX: u8 = 0xb0;
const HEADER_MASK: u8 = 0xf8;
const TAG_MASK: u8 = 0x07;
const GENERIC_FORM: u8 = 0;
const PROFILE_CAPABILITIES_FORM: u8 = 1;
const FULL_SUMMARY_FORM: u8 = 1;
const CACHED_SUMMARY_FORM: u8 = 2;
const LEGACY_ENVELOPE_OCTETS: usize = 7;
const SUMMARY_BINDING_DOMAIN: &[u8] = b"BEMPIC-COMPACT-SUMMARY-CACHE-v0.1\0";

/// Exact opaque-binary schema fingerprint aliased by the profile capability form.
pub const PROFILE_SCHEMA_FINGERPRINT: SchemaFingerprint = SchemaFingerprint([
    0xd8, 0x90, 0x6a, 0x1c, 0xef, 0xbf, 0x89, 0xe4, 0xf2, 0x9b, 0x4a, 0x0f, 0x63, 0x6c, 0xfb, 0xfa,
    0x1e, 0x9c, 0x63, 0x01, 0xe7, 0xe3, 0xa4, 0xfe, 0x21, 0x3c, 0x09, 0x00, 0x66, 0xf8, 0xe7, 0x97,
]);

/// Explicit codec state used by the only dynamic alias.
#[derive(Clone, Copy, Debug, Default)]
pub struct Context<'a> {
    /// Exact durable checkpoint already bound to the peer and collection.
    pub cached_summary: Option<&'a Summary>,
}

/// Candidate maximum-size proof terms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct MaximumSizeAnalysis {
    /// Core operation.
    pub kind: OperationKind,
    /// Maximum accepted B1 operation content, excluding its seven-byte envelope.
    pub inherited_content_octets: usize,
    /// Canonical form selector.
    pub form_octets: usize,
    /// Candidate tag plus canonical length size at the maximum.
    pub envelope_octets: usize,
    /// Exact reachable complete-record maximum.
    pub maximum_encoded_octets: usize,
}

/// Exact single-tuple capability value assigned the static profile alias.
#[must_use]
pub fn profile_capabilities() -> Capabilities {
    profile_capabilities_for(EXPERIMENTAL_CODEC_IDENTITY)
}

/// Construct the exact aliased capability value for an explicit identity.
///
/// Active encode/decode paths accept only [`EXPERIMENTAL_CODEC_IDENTITY`]. This
/// constructor exists so rejection vectors can exercise other identities.
#[must_use]
pub fn profile_capabilities_for(identity: CodecIdentity) -> Capabilities {
    Capabilities {
        protocol_generations: vec![ProtocolGeneration { major: 0, minor: 1 }],
        schema_fingerprints: vec![PROFILE_SCHEMA_FINGERPRINT],
        codec_preferences: vec![CodecPreference {
            codec_id: identity.id,
            revision: identity.revision,
            schema_fingerprint: PROFILE_SCHEMA_FINGERPRINT,
        }],
        max_operation_octets: 1_048_576,
        max_data_payload_octets: 1_000_000,
        receipt_levels: 0b1111,
        security_class: SecurityClass::Public,
        extensions: Vec::new(),
    }
}

/// Validate the exact allocated public experimental tuple.
pub fn validate_identity(identity: CodecIdentity) -> Result<(), Error> {
    if identity.id == 0 || identity.id == u32::MAX {
        return Err(Error::UnsupportedCodec("reserved codec ID"));
    }
    if identity.id >= 0x8000_0000 {
        return Err(Error::UnsupportedCodec("private-use codec ID"));
    }
    if identity.revision == 0 {
        return Err(Error::UnsupportedCodec("codec revision zero"));
    }
    if identity.id != EXPERIMENTAL_CODEC_ID {
        return Err(Error::UnsupportedCodec("unknown codec ID"));
    }
    if identity.revision != EXPERIMENTAL_CODEC_REVISION {
        return Err(Error::UnsupportedCodec("unsupported codec revision"));
    }
    Ok(())
}

/// Validate one representation descriptor before allocation or persistence.
pub fn validate_representation_descriptor(
    descriptor: &RepresentationDescriptor,
) -> Result<(), Error> {
    descriptor
        .validate()
        .map_err(|_| Error::Malformed("representation descriptor"))?;
    validate_identity(CodecIdentity {
        id: descriptor.codec_id,
        revision: descriptor.codec_revision,
    })?;
    if !descriptor.codec_parameters.is_empty() {
        return Err(Error::UnsupportedCodec("non-empty codec parameters"));
    }
    if descriptor.schema_fingerprint != PROFILE_SCHEMA_FINGERPRINT {
        return Err(Error::UnsupportedCodec("unsupported schema fingerprint"));
    }
    Ok(())
}

/// Validate an advertisement as public revision-1 interoperability evidence.
pub fn validate_profile_capabilities(capabilities: &Capabilities) -> Result<(), Error> {
    capabilities.validate()?;
    if capabilities.security_class != SecurityClass::Public {
        return Err(Error::UnsupportedCodec("unsupported security class"));
    }
    if capabilities.schema_fingerprints != [PROFILE_SCHEMA_FINGERPRINT]
        || capabilities.codec_preferences.len() != 1
    {
        return Err(Error::UnsupportedCodec("profile capability set"));
    }
    let preference = &capabilities.codec_preferences[0];
    validate_identity(CodecIdentity {
        id: preference.codec_id,
        revision: preference.revision,
    })?;
    if preference.schema_fingerprint != PROFILE_SCHEMA_FINGERPRINT {
        return Err(Error::UnsupportedCodec("mismatched codec schema"));
    }
    Ok(())
}

/// Validate a selected profile before it can enter a durable cache.
pub fn validate_negotiated_profile(profile: &NegotiatedProfile) -> Result<(), Error> {
    validate_identity(CodecIdentity {
        id: profile.codec_id,
        revision: profile.codec_revision,
    })?;
    if profile.schema_fingerprint != PROFILE_SCHEMA_FINGERPRINT {
        return Err(Error::UnsupportedCodec("mismatched negotiated schema"));
    }
    if profile.security_class != SecurityClass::Public {
        return Err(Error::UnsupportedCodec("unsupported security class"));
    }
    Ok(())
}

/// Negotiate only after both advertisements satisfy the public profile.
pub fn negotiate_profile(
    local: &Capabilities,
    remote: &Capabilities,
) -> Result<NegotiatedProfile, FailureCode> {
    validate_profile_capabilities(local).map_err(|_| FailureCode::UnsupportedCodec)?;
    validate_profile_capabilities(remote).map_err(|_| FailureCode::UnsupportedCodec)?;
    let profile = negotiate(local, remote)?;
    validate_negotiated_profile(&profile).map_err(|_| FailureCode::UnsupportedCodec)?;
    Ok(profile)
}

fn validate_record(record: &Record) -> Result<(), Error> {
    match &record.operation {
        Operation::Capabilities(capabilities) => validate_profile_capabilities(capabilities),
        Operation::Offer(offer) => {
            for entry in &offer.descriptors {
                validate_representation_descriptor(&entry.descriptor)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Exact reachable maximum for one candidate operation kind.
#[must_use]
pub const fn declared_max_encoded_size(kind: OperationKind) -> usize {
    let inherited_content = profile_legacy_max(kind) - LEGACY_ENVELOPE_OCTETS;
    let body = 1 + inherited_content;
    1 + varint_size(body) + body
}

/// Closed proof terms for one candidate operation maximum.
#[must_use]
pub const fn maximum_size_analysis(kind: OperationKind) -> MaximumSizeAnalysis {
    let inherited_content_octets = profile_legacy_max(kind) - LEGACY_ENVELOPE_OCTETS;
    let body = 1 + inherited_content_octets;
    MaximumSizeAnalysis {
        kind,
        inherited_content_octets,
        form_octets: 1,
        envelope_octets: 1 + varint_size(body),
        maximum_encoded_octets: 1 + varint_size(body) + body,
    }
}

const fn profile_legacy_max(kind: OperationKind) -> usize {
    match kind {
        // One supported schema and tuple replace the generic maxima of sixteen
        // schemas and sixteen codec preferences: 15 * 32 + 15 * 40 octets.
        OperationKind::Capabilities => legacy_declared_max(kind) - 1_080,
        // Empty canonical parameters replace 128 generic 1,024-octet blocks.
        OperationKind::Offer => legacy_declared_max(kind) - 131_072,
        _ => legacy_declared_max(kind),
    }
}

/// Exact encoded size without trial serialization.
pub fn exact_encoded_size(record: &Record, context: Context<'_>) -> Result<usize, Error> {
    exact_encoded_size_for(record, context, EXPERIMENTAL_CODEC_IDENTITY)
}

/// Exact encoded size for an explicitly supplied codec identity.
pub fn exact_encoded_size_for(
    record: &Record,
    context: Context<'_>,
    identity: CodecIdentity,
) -> Result<usize, Error> {
    validate_identity(identity)?;
    validate_record(record)?;
    let body_size = exact_body_size(record, context, identity)?;
    let size = 1 + varint_size(body_size) + body_size;
    if size > MAX_COMPACT_RECORD_OCTETS {
        Err(Error::LimitExceeded("compact operation size"))
    } else {
        Ok(size)
    }
}

/// Encode one deterministic complete candidate record.
pub fn encode(record: &Record, context: Context<'_>) -> Result<Vec<u8>, Error> {
    encode_for(record, context, EXPERIMENTAL_CODEC_IDENTITY)
}

/// Encode for an explicitly supplied identity without assigning that identity.
pub fn encode_for(
    record: &Record,
    context: Context<'_>,
    identity: CodecIdentity,
) -> Result<Vec<u8>, Error> {
    validate_identity(identity)?;
    validate_record(record)?;
    let body_size = exact_body_size(record, context, identity)?;
    let size = 1 + varint_size(body_size) + body_size;
    if size > MAX_COMPACT_RECORD_OCTETS {
        return Err(Error::LimitExceeded("compact operation size"));
    }
    let mut output = Vec::with_capacity(size);
    output.push(HEADER_PREFIX | operation_tag(&record.operation));
    put_varint(&mut output, body_size as u64);
    match canonical_form(record, context, identity) {
        Form::ProfileCapabilities => output.push(PROFILE_CAPABILITIES_FORM),
        Form::CachedSummary(summary) => {
            output.push(CACHED_SUMMARY_FORM);
            output.extend_from_slice(&summary_binding(summary));
        }
        Form::FullSummary(summary) => {
            output.push(FULL_SUMMARY_FORM);
            output.extend_from_slice(&summary.collection_id);
            put_varint(&mut output, summary.generation);
            put_varint(&mut output, summary.item_count);
            output.extend_from_slice(&summary.collection_digest);
        }
        Form::Generic => {
            output.push(GENERIC_FORM);
            let legacy = record.encode()?;
            output.extend_from_slice(&legacy[LEGACY_ENVELOPE_OCTETS..]);
        }
    }
    debug_assert_eq!(output.len(), size);
    Ok(output)
}

/// Strictly decode one complete candidate record before protocol mutation.
pub fn decode(
    bytes: &[u8],
    supported_extensions: &BTreeSet<u32>,
    context: Context<'_>,
) -> Result<Record, Error> {
    decode_for(
        bytes,
        supported_extensions,
        context,
        EXPERIMENTAL_CODEC_IDENTITY,
    )
}

/// Strictly decode using the explicitly selected profile identity.
pub fn decode_for(
    bytes: &[u8],
    supported_extensions: &BTreeSet<u32>,
    context: Context<'_>,
    identity: CodecIdentity,
) -> Result<Record, Error> {
    validate_identity(identity)?;
    if bytes.len() < 3 {
        return Err(Error::Truncated);
    }
    if bytes.len() > MAX_COMPACT_RECORD_OCTETS {
        return Err(Error::LimitExceeded("compact operation size"));
    }
    let header = bytes[0];
    if header & HEADER_MASK != HEADER_PREFIX {
        return Err(Error::InvalidMagic);
    }
    let tag = header & TAG_MASK;
    if !(1..=7).contains(&tag) {
        return Err(Error::UnknownOperation(tag));
    }
    let mut position = 1;
    let body_length = take_varint_usize(bytes, &mut position)?;
    if body_length != bytes.len().saturating_sub(position) {
        return Err(Error::Malformed("compact envelope length"));
    }
    let form = *bytes.get(position).ok_or(Error::Truncated)?;
    position += 1;
    match (tag, form) {
        (1, PROFILE_CAPABILITIES_FORM) if position == bytes.len() => Ok(Record {
            operation: Operation::Capabilities(profile_capabilities_for(identity)),
            extensions: Vec::new(),
        }),
        (2, CACHED_SUMMARY_FORM) => {
            let binding = take_array::<32>(bytes, &mut position)?;
            if position != bytes.len() {
                return Err(Error::TrailingBytes);
            }
            let summary = context
                .cached_summary
                .copied()
                .ok_or(Error::Malformed("cached summary context"))?;
            if binding != summary_binding(&summary) {
                return Err(Error::Malformed("cached summary binding"));
            }
            Ok(Record {
                operation: Operation::Summary(summary),
                extensions: Vec::new(),
            })
        }
        (2, FULL_SUMMARY_FORM) => {
            let collection_id = take_array(bytes, &mut position)?;
            let generation = take_varint(bytes, &mut position)?;
            let item_count = take_varint(bytes, &mut position)?;
            let collection_digest = take_array(bytes, &mut position)?;
            if position != bytes.len() {
                return Err(Error::TrailingBytes);
            }
            let summary = Summary {
                collection_id,
                generation,
                item_count,
                collection_digest,
            };
            let record = Record {
                operation: Operation::Summary(summary),
                extensions: Vec::new(),
            };
            record.exact_encoded_size()?;
            if context.cached_summary == Some(&summary) {
                return Err(Error::NonCanonical("full cached summary"));
            }
            Ok(record)
        }
        (_, GENERIC_FORM) => {
            let record = decode_generic(tag, &bytes[position..], supported_extensions)?;
            validate_record(&record)?;
            if record.extensions.is_empty()
                && matches!(
                    &record.operation,
                    Operation::Capabilities(value) if *value == profile_capabilities_for(identity)
                )
            {
                return Err(Error::NonCanonical("profile capabilities alias"));
            }
            if record.extensions.is_empty() && matches!(record.operation, Operation::Summary(_)) {
                return Err(Error::NonCanonical("summary form"));
            }
            Ok(record)
        }
        _ => Err(Error::NonCanonical("compact form")),
    }
}

#[derive(Clone, Copy)]
enum Form<'a> {
    ProfileCapabilities,
    CachedSummary(&'a Summary),
    FullSummary(&'a Summary),
    Generic,
}

fn canonical_form<'a>(
    record: &'a Record,
    context: Context<'_>,
    identity: CodecIdentity,
) -> Form<'a> {
    if record.extensions.is_empty() {
        match &record.operation {
            Operation::Capabilities(value) if *value == profile_capabilities_for(identity) => {
                return Form::ProfileCapabilities;
            }
            Operation::Summary(summary) if context.cached_summary == Some(summary) => {
                return Form::CachedSummary(summary);
            }
            Operation::Summary(summary) => return Form::FullSummary(summary),
            _ => {}
        }
    }
    Form::Generic
}

fn exact_body_size(
    record: &Record,
    context: Context<'_>,
    identity: CodecIdentity,
) -> Result<usize, Error> {
    let legacy_size = record.exact_encoded_size()?;
    Ok(match canonical_form(record, context, identity) {
        Form::ProfileCapabilities => 1,
        Form::CachedSummary(_) => 1 + 32,
        Form::FullSummary(summary) => {
            1 + 32 + varint_size_u64(summary.generation) + varint_size_u64(summary.item_count) + 32
        }
        Form::Generic => 1 + legacy_size - LEGACY_ENVELOPE_OCTETS,
    })
}

fn summary_binding(summary: &Summary) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SUMMARY_BINDING_DOMAIN);
    digest.update(summary.collection_id);
    digest.update(summary.generation.to_be_bytes());
    digest.update(summary.item_count.to_be_bytes());
    digest.update(summary.collection_digest);
    digest.finalize().into()
}

const fn operation_tag(operation: &Operation) -> u8 {
    match operation {
        Operation::Capabilities(_) => 1,
        Operation::Summary(_) => 2,
        Operation::Offer(_) => 3,
        Operation::Request(_) => 4,
        Operation::Data(_) => 5,
        Operation::Receipt(_) => 6,
        Operation::Failure(_) => 7,
    }
}

fn decode_generic(
    tag: u8,
    content: &[u8],
    supported_extensions: &BTreeSet<u32>,
) -> Result<Record, Error> {
    let legacy_size = LEGACY_ENVELOPE_OCTETS
        .checked_add(content.len())
        .ok_or(Error::LimitExceeded("operation size"))?;
    if legacy_size > MAX_EXPERIMENTAL_RECORD_OCTETS {
        return Err(Error::LimitExceeded("operation size"));
    }
    let mut legacy = Vec::with_capacity(legacy_size);
    legacy.extend_from_slice(b"B1");
    legacy.push(tag);
    legacy.extend_from_slice(
        &u32::try_from(content.len())
            .map_err(|_| Error::LimitExceeded("operation size"))?
            .to_be_bytes(),
    );
    legacy.extend_from_slice(content);
    Record::decode(&legacy, supported_extensions)
}

const fn varint_size(value: usize) -> usize {
    if value < 1 << 7 {
        1
    } else if value < 1 << 14 {
        2
    } else if value < 1 << 21 {
        3
    } else if value < 1 << 28 {
        4
    } else {
        5
    }
}

const fn varint_size_u64(mut value: u64) -> usize {
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

fn put_varint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let low = u8::try_from(value & 0x7f).expect("seven bits fit u8");
        value >>= 7;
        if value == 0 {
            output.push(low);
            return;
        }
        output.push(low | 0x80);
    }
}

fn take_varint(bytes: &[u8], position: &mut usize) -> Result<u64, Error> {
    let start = *position;
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *bytes.get(*position).ok_or(Error::Truncated)?;
        *position += 1;
        if shift == 63 && byte > 1 {
            return Err(Error::LimitExceeded("varint"));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            if *position - start != varint_size_u64(value) {
                return Err(Error::NonCanonical("varint"));
            }
            return Ok(value);
        }
    }
    Err(Error::LimitExceeded("varint"))
}

fn take_varint_usize(bytes: &[u8], position: &mut usize) -> Result<usize, Error> {
    usize::try_from(take_varint(bytes, position)?)
        .map_err(|_| Error::LimitExceeded("compact envelope length"))
}

fn take_array<const N: usize>(bytes: &[u8], position: &mut usize) -> Result<[u8; N], Error> {
    let end = position.checked_add(N).ok_or(Error::Truncated)?;
    let value = bytes.get(*position..end).ok_or(Error::Truncated)?;
    *position = end;
    value.try_into().map_err(|_| Error::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v01::{collection_checkpoint, Data, Extension};
    use bempic_model::v01::{
        fingerprint_from_hex, PreparedRepresentation, RepresentationId,
        MESSAGE_SCHEMA_FINGERPRINT_HEX,
    };

    fn summary() -> Summary {
        collection_checkpoint([0x41; 32], 100, &[]).unwrap()
    }

    fn generic_bytes(record: &Record) -> Vec<u8> {
        let legacy = record.encode().unwrap();
        let body_size = 1 + legacy.len() - LEGACY_ENVELOPE_OCTETS;
        let mut output = vec![HEADER_PREFIX | operation_tag(&record.operation)];
        put_varint(&mut output, body_size as u64);
        output.push(GENERIC_FORM);
        output.extend_from_slice(&legacy[LEGACY_ENVELOPE_OCTETS..]);
        output
    }

    #[test]
    fn compact_profile_and_summary_forms_are_exact_and_strict() {
        let capabilities = Record {
            operation: Operation::Capabilities(profile_capabilities()),
            extensions: Vec::new(),
        };
        let cold_summary = Record {
            operation: Operation::Summary(summary()),
            extensions: Vec::new(),
        };
        let empty = BTreeSet::new();
        let capabilities_bytes = encode(&capabilities, Context::default()).unwrap();
        assert_eq!(capabilities_bytes, [0xb1, 0x01, 0x01]);
        assert_eq!(
            exact_encoded_size(&capabilities, Context::default()).unwrap(),
            3
        );
        assert_eq!(
            decode(&capabilities_bytes, &empty, Context::default()).unwrap(),
            capabilities
        );

        let cold_bytes = encode(&cold_summary, Context::default()).unwrap();
        assert_eq!(cold_bytes.len(), 69);
        assert_eq!(
            decode(&cold_bytes, &empty, Context::default()).unwrap(),
            cold_summary
        );

        let checkpoint = summary();
        let warm_context = Context {
            cached_summary: Some(&checkpoint),
        };
        let warm_bytes = encode(&cold_summary, warm_context).unwrap();
        assert_eq!(warm_bytes.len(), 35);
        assert_eq!(
            decode(&warm_bytes, &empty, warm_context).unwrap(),
            cold_summary
        );
        assert!(decode(&warm_bytes, &empty, Context::default()).is_err());
        let mut wrong_checkpoint = checkpoint;
        wrong_checkpoint.generation += 1;
        let wrong_context = Context {
            cached_summary: Some(&wrong_checkpoint),
        };
        assert_eq!(
            decode(&warm_bytes, &empty, wrong_context),
            Err(Error::Malformed("cached summary binding"))
        );
        assert!(decode(&cold_bytes, &empty, warm_context).is_err());
    }

    #[test]
    fn public_identity_is_exact_and_private_identity_is_rejected() {
        let identity = EXPERIMENTAL_CODEC_IDENTITY;
        let record = Record {
            operation: Operation::Capabilities(profile_capabilities_for(identity)),
            extensions: Vec::new(),
        };
        let bytes = encode_for(&record, Context::default(), identity).unwrap();
        assert_eq!(bytes.len(), 3);
        assert_eq!(
            decode_for(&bytes, &BTreeSet::new(), Context::default(), identity).unwrap(),
            record
        );
        let private = CodecIdentity {
            id: 0xffff_0001,
            revision: 2,
        };
        assert_eq!(
            encode_for(&record, Context::default(), private),
            Err(Error::UnsupportedCodec("private-use codec ID"))
        );
    }

    #[test]
    fn reserved_private_zero_unknown_and_mismatched_tuples_fail_closed() {
        let cases = [
            (
                CodecIdentity { id: 0, revision: 1 },
                Error::UnsupportedCodec("reserved codec ID"),
            ),
            (
                CodecIdentity {
                    id: u32::MAX,
                    revision: 1,
                },
                Error::UnsupportedCodec("reserved codec ID"),
            ),
            (
                CodecIdentity {
                    id: 0xffff_0001,
                    revision: 2,
                },
                Error::UnsupportedCodec("private-use codec ID"),
            ),
            (
                CodecIdentity {
                    id: EXPERIMENTAL_CODEC_ID,
                    revision: 0,
                },
                Error::UnsupportedCodec("codec revision zero"),
            ),
            (
                CodecIdentity {
                    id: EXPERIMENTAL_CODEC_ID + 1,
                    revision: 1,
                },
                Error::UnsupportedCodec("unknown codec ID"),
            ),
            (
                CodecIdentity {
                    id: EXPERIMENTAL_CODEC_ID,
                    revision: EXPERIMENTAL_CODEC_REVISION + 1,
                },
                Error::UnsupportedCodec("unsupported codec revision"),
            ),
        ];
        for (identity, expected) in cases {
            assert_eq!(validate_identity(identity), Err(expected));
        }
    }

    #[test]
    fn negotiation_rejects_downgrade_mixed_private_and_unsupported_revision() {
        let local = profile_capabilities();
        assert!(negotiate_profile(&local, &local).is_ok());

        for identity in [
            CodecIdentity {
                id: EXPERIMENTAL_CODEC_ID,
                revision: 0,
            },
            CodecIdentity {
                id: EXPERIMENTAL_CODEC_ID,
                revision: 2,
            },
            CodecIdentity {
                id: 0xffff_0001,
                revision: 2,
            },
        ] {
            let remote = profile_capabilities_for(identity);
            assert_eq!(
                negotiate_profile(&local, &remote),
                Err(FailureCode::UnsupportedCodec)
            );
        }

        let mut mixed = local.clone();
        mixed.codec_preferences.push(CodecPreference {
            codec_id: 0xffff_0001,
            revision: 2,
            schema_fingerprint: PROFILE_SCHEMA_FINGERPRINT,
        });
        assert_eq!(
            negotiate_profile(&local, &mixed),
            Err(FailureCode::UnsupportedCodec)
        );
    }

    #[test]
    fn public_profile_rejects_non_public_security_before_selection_or_decode() {
        let local = profile_capabilities();
        let mut confidential = local.clone();
        confidential.security_class = SecurityClass::Confidential;
        assert_eq!(
            validate_profile_capabilities(&confidential),
            Err(Error::UnsupportedCodec("unsupported security class"))
        );
        assert_eq!(
            negotiate_profile(&local, &confidential),
            Err(FailureCode::UnsupportedCodec)
        );

        let confidential_record = Record {
            operation: Operation::Capabilities(confidential),
            extensions: Vec::new(),
        };
        assert_eq!(
            decode(
                &generic_bytes(&confidential_record),
                &BTreeSet::new(),
                Context::default()
            ),
            Err(Error::UnsupportedCodec("unsupported security class"))
        );

        let mut selected = negotiate_profile(&local, &local).unwrap();
        selected.security_class = SecurityClass::AuthenticatedPublic;
        assert_eq!(
            validate_negotiated_profile(&selected),
            Err(Error::UnsupportedCodec("unsupported security class"))
        );
    }

    #[test]
    fn generic_decode_rejects_invalid_capabilities_before_returning_a_record() {
        let private = Record {
            operation: Operation::Capabilities(profile_capabilities_for(CodecIdentity {
                id: 0xffff_0001,
                revision: 2,
            })),
            extensions: Vec::new(),
        };
        assert_eq!(
            decode(
                &generic_bytes(&private),
                &BTreeSet::new(),
                Context::default()
            ),
            Err(Error::UnsupportedCodec("private-use codec ID"))
        );
    }

    #[test]
    fn descriptor_validation_accepts_only_public_opaque_empty_parameter_profile() {
        let valid = PreparedRepresentation::prepare(
            b"opaque".to_vec(),
            None,
            PROFILE_SCHEMA_FINGERPRINT,
            EXPERIMENTAL_CODEC_ID,
            EXPERIMENTAL_CODEC_REVISION,
            Vec::new(),
            None,
        )
        .unwrap();
        assert!(validate_representation_descriptor(&valid.descriptor).is_ok());

        let mut private = valid.descriptor.clone();
        private.codec_id = 0xffff_0001;
        assert_eq!(
            validate_representation_descriptor(&private),
            Err(Error::UnsupportedCodec("private-use codec ID"))
        );
        let mut parameters = valid.descriptor.clone();
        parameters.codec_parameters.push(0);
        assert_eq!(
            validate_representation_descriptor(&parameters),
            Err(Error::UnsupportedCodec("non-empty codec parameters"))
        );
        let mut manifest = valid.descriptor;
        manifest.schema_fingerprint = fingerprint_from_hex(MESSAGE_SCHEMA_FINGERPRINT_HEX).unwrap();
        assert_eq!(
            validate_representation_descriptor(&manifest),
            Err(Error::UnsupportedCodec("unsupported schema fingerprint"))
        );
    }

    #[test]
    fn generic_form_round_trips_and_rejects_non_minimal_lengths() {
        let record = Record {
            operation: Operation::Data(Data {
                representation_id: RepresentationId([0x77; 32]),
                offset: 1,
                payload: vec![0x88; 128],
            }),
            extensions: Vec::new(),
        };
        let bytes = encode(&record, Context::default()).unwrap();
        assert_eq!(
            bytes.len(),
            exact_encoded_size(&record, Context::default()).unwrap()
        );
        assert_eq!(
            decode(&bytes, &BTreeSet::new(), Context::default()).unwrap(),
            record
        );
        let mut overlong = bytes;
        overlong[1] |= 0x80;
        overlong.insert(2, 0);
        assert_eq!(
            decode(&overlong, &BTreeSet::new(), Context::default()),
            Err(Error::NonCanonical("varint"))
        );
    }

    #[test]
    fn profile_capabilities_with_record_extensions_use_the_generic_form() {
        let record = Record {
            operation: Operation::Capabilities(profile_capabilities()),
            extensions: vec![Extension {
                id: 7,
                critical: true,
                value: vec![0x55],
            }],
        };
        let bytes = encode(&record, Context::default()).unwrap();
        let supported = BTreeSet::from([7]);
        assert_eq!(bytes[2], GENERIC_FORM);
        assert_eq!(
            decode(&bytes, &supported, Context::default()).unwrap(),
            record
        );
    }

    #[test]
    fn every_truncation_and_one_past_outer_record_fail_closed() {
        let record = Record {
            operation: Operation::Summary(summary()),
            extensions: Vec::new(),
        };
        let encoded = encode(&record, Context::default()).unwrap();
        for length in 0..encoded.len() {
            assert!(decode(&encoded[..length], &BTreeSet::new(), Context::default()).is_err());
        }
        let oversized = vec![0; MAX_COMPACT_RECORD_OCTETS + 1];
        assert_eq!(
            decode(&oversized, &BTreeSet::new(), Context::default()),
            Err(Error::LimitExceeded("compact operation size"))
        );
    }

    #[test]
    fn maximum_formulas_transform_every_reachable_b1_maximum() {
        for kind in OperationKind::ALL {
            let analysis = maximum_size_analysis(kind);
            assert_eq!(
                analysis.maximum_encoded_octets,
                declared_max_encoded_size(kind)
            );
            assert!(analysis.maximum_encoded_octets <= MAX_COMPACT_RECORD_OCTETS);
            assert_eq!(
                analysis.inherited_content_octets + LEGACY_ENVELOPE_OCTETS,
                profile_legacy_max(kind)
            );
        }
    }
}
