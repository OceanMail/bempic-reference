//! Private-use compact operation-codec candidate.
//!
//! This codec is an allocation-ready experiment, not a registered BEMPIC
//! profile. It losslessly aliases one exact profile capability value and, only
//! with an exact caller-supplied durable checkpoint, that checkpoint's full
//! `SUMMARY`. An alias never supplies or overrides a different full value.

use crate::v01::{
    declared_max_encoded_size as legacy_declared_max, Capabilities, CodecPreference, Error,
    Operation, OperationKind, ProtocolGeneration, Record, SecurityClass, Summary,
    MAX_EXPERIMENTAL_RECORD_OCTETS,
};
use bempic_model::v01::SchemaFingerprint;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Implementation-local private-use codec ID. This is not a registry allocation.
pub const PRIVATE_CODEC_ID: u32 = 0xffff_0001;
/// Incompatible private candidate revision.
pub const PRIVATE_CODEC_REVISION: u32 = 2;
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
    Capabilities {
        protocol_generations: vec![ProtocolGeneration { major: 0, minor: 1 }],
        schema_fingerprints: vec![PROFILE_SCHEMA_FINGERPRINT],
        codec_preferences: vec![CodecPreference {
            codec_id: PRIVATE_CODEC_ID,
            revision: PRIVATE_CODEC_REVISION,
            schema_fingerprint: PROFILE_SCHEMA_FINGERPRINT,
        }],
        max_operation_octets: 1_048_576,
        max_data_payload_octets: 1_000_000,
        receipt_levels: 0b1111,
        security_class: SecurityClass::Public,
        extensions: Vec::new(),
    }
}

/// Exact reachable maximum for one candidate operation kind.
#[must_use]
pub const fn declared_max_encoded_size(kind: OperationKind) -> usize {
    let inherited_content = legacy_declared_max(kind) - LEGACY_ENVELOPE_OCTETS;
    let body = 1 + inherited_content;
    1 + varint_size(body) + body
}

/// Closed proof terms for one candidate operation maximum.
#[must_use]
pub const fn maximum_size_analysis(kind: OperationKind) -> MaximumSizeAnalysis {
    let inherited_content_octets = legacy_declared_max(kind) - LEGACY_ENVELOPE_OCTETS;
    let body = 1 + inherited_content_octets;
    MaximumSizeAnalysis {
        kind,
        inherited_content_octets,
        form_octets: 1,
        envelope_octets: 1 + varint_size(body),
        maximum_encoded_octets: 1 + varint_size(body) + body,
    }
}

/// Exact encoded size without trial serialization.
pub fn exact_encoded_size(record: &Record, context: Context<'_>) -> Result<usize, Error> {
    let body_size = exact_body_size(record, context)?;
    let size = 1 + varint_size(body_size) + body_size;
    if size > MAX_COMPACT_RECORD_OCTETS {
        Err(Error::LimitExceeded("compact operation size"))
    } else {
        Ok(size)
    }
}

/// Encode one deterministic complete candidate record.
pub fn encode(record: &Record, context: Context<'_>) -> Result<Vec<u8>, Error> {
    let body_size = exact_body_size(record, context)?;
    let size = 1 + varint_size(body_size) + body_size;
    if size > MAX_COMPACT_RECORD_OCTETS {
        return Err(Error::LimitExceeded("compact operation size"));
    }
    let mut output = Vec::with_capacity(size);
    output.push(HEADER_PREFIX | operation_tag(&record.operation));
    put_varint(&mut output, body_size as u64);
    match canonical_form(record, context) {
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
            operation: Operation::Capabilities(profile_capabilities()),
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
            if record.extensions.is_empty()
                && matches!(
                    &record.operation,
                    Operation::Capabilities(value) if *value == profile_capabilities()
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

fn canonical_form<'a>(record: &'a Record, context: Context<'_>) -> Form<'a> {
    if record.extensions.is_empty() {
        match &record.operation {
            Operation::Capabilities(value) if *value == profile_capabilities() => {
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

fn exact_body_size(record: &Record, context: Context<'_>) -> Result<usize, Error> {
    let legacy_size = record.exact_encoded_size()?;
    Ok(match canonical_form(record, context) {
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
    use bempic_model::v01::RepresentationId;

    fn summary() -> Summary {
        collection_checkpoint([0x41; 32], 100, &[]).unwrap()
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
                legacy_declared_max(kind)
            );
        }
    }
}
