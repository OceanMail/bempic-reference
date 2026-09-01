# Experimental compact operation-codec candidate v0.1

## Status and nonconformance warning

This document describes the allocation-ready evidence candidate implemented by
`bempic_sync::v01_compact`. It targets the read-only BEMPIC specification
object `40da35bd150290d039a185fb95388422ede5f1d1`.

The candidate uses implementation-local private-use codec ID `0xffff0001` and
incompatible revision `2`. The ID is not present in the specification registry,
is not public interoperability evidence, and is nonconformant outside an
out-of-band private experiment. Revision 1 is the older disposable B1
comparison image; revision 2 neither accepts nor emits revision-1 framing.
Allocation requires a specification-repository decision and a new experimental
range ID. This repository does not request, reserve, or imply one.

The candidate has no authentication, confidentiality, replay protection,
compression, approximate numeric fields, or DCCL/M4P dependency. DCCL and M4P
were not copied. The security class is `public` and means no security claim.

## Design boundary

The codec maps the existing seven semantic `Operation` variants to complete,
length-delimited records. It changes no collection, selection, budget,
persistence, integrity, receipt, carrier, or failure semantics. Every generic
record reuses the already strict B1 operation-content encoding after replacing
only its outer envelope. The two compact forms are lossless aliases:

1. A static capability alias expands to one exact, fully specified capability
   value, including the full 32-octet schema fingerprint, private codec ID and
   revision, maxima, receipt levels, security class, and empty extension lists.
2. A dynamic warm-summary alias is legal only when the caller supplies the
   exact durable `Summary` expected for the peer/collection context and the
   semantic value equals it byte for byte. The alias carries a full 32-octet
   SHA-256 binding of every cached summary field. Decode without the context,
   or with a context whose binding differs, fails before returning an
   operation. A full form is noncanonical when the exact cache is present.

Aliases do not truncate identifiers or hashes. The cold form carries the full
32-octet collection ID and full 32-octet collection digest. Both aliases
reconstruct the exact full-width semantic values. A short alias never overrides
a full value; cache mismatch, absence, stale context, or alternate full-form
encoding fails closed before protocol mutation.

Encoding is deterministic for `(semantic record, explicit codec context)`.
The empty context is canonical for cold operation encoding. The exact cached
checkpoint is part of the warm encoding input, not hidden process state.

## Complete record format

Every record is:

```text
header:u8 || body_length:canonical-uvarint || body[body_length]
```

`header & 0xf8` is `0xb0`; the low three bits are operation tags 1 through 7 in
the existing semantic order. Tag zero and every other prefix are invalid.
`body_length` is unsigned LEB128 with the shortest possible representation.
The complete record must be at most 1,048,576 octets, and its declared body
length must equal the remaining record length exactly.

The first body octet is a canonical form selector:

| Operation | Form | Meaning |
|---|---:|---|
| `CAPABILITIES` | `0x01` | exact static profile capability; body ends immediately |
| `SUMMARY` | `0x01` | cold full summary: 32-byte collection ID, minimal generation uvarint, minimal item-count uvarint, 32-byte digest |
| `SUMMARY` | `0x02` | exact supplied durable checkpoint followed by its full 32-byte cache binding |
| all operations | `0x00` | B1 operation content after its seven-byte B1 envelope |

Generic `CAPABILITIES` is noncanonical when it decodes to the exact static
alias. Generic extension-free `SUMMARY` is noncanonical because the full form
is available. A `SUMMARY` with record extensions uses the generic form. All
other form/tag combinations are noncanonical.

Unknown optional and critical record extensions retain B1 behavior: optional
unknown values are bounded and skipped without side effects; an unknown
critical extension fails before an operation is returned. Counts, strings,
payloads, nested descriptors, and extensions retain the v0.1/B1 declarative
bounds. The outer decoder checks the 1,048,576-octet ceiling and canonical body
length before allocating the bounded reconstructed B1 envelope used by generic
decode.

### Inherited generic content fields

The generic form copies the B1 operation content beginning immediately after
its seven-byte envelope. All fixed-width integers are unsigned big-endian;
booleans are exactly `0x00` or `0x01`; counts are one octet; payload lengths
are four octets; descriptor/extension-value lengths are two octets where shown.
No alternate or overlong form is accepted.

| Operation/structure | Canonical field order and widths |
|---|---|
| `CAPABILITIES` | protocol count then `(U16 major, U16 minor)`; schema count then 32-byte fingerprints; codec count then `(U32 ID, U32 revision, 32-byte fingerprint)`; U32 max operation; U64 max data payload; U8 receipt levels; U8 security class; extension-declaration count then `(U32 ID, bool critical)` |
| `SUMMARY` | 32-byte collection ID; U64 generation; U64 item count; 32-byte collection digest |
| `OFFER` | 32-byte collection ID; U8 mode; U64 base and target generations; first and last cursors; descriptor count and descriptors; bool `more` |
| inventory `REQUEST` | U8 variant `0`; 32-byte collection ID; U64 target generation; U8 mode; cursor; U8 page limit |
| data `REQUEST` | U8 variant `1`; 16-byte budget ID; three U64 budget limits; selection count; each selection is 32-byte representation ID plus U64 offset and U64 desired payload |
| `DATA` | 32-byte representation ID; U64 offset; U32 payload length; nonempty payload |
| `RECEIPT` | 32-byte subject ID; U8 status; digest-presence bool and optional 32-byte digest; 16-byte idempotency ID; optional text |
| `FAILURE` | U8 code; U8 scope length and scope; bool retryable; optional text |
| delta cursor | U8 variant `0`; U64 sequence |
| full cursor | U8 variant `1`; 32-byte object ID; U32 part ID; 32-byte representation ID |
| descriptor | U64 sequence; 32-byte object ID; U32 part ID; 32-byte representation ID; 32-byte schema fingerprint; U32 codec ID; U32 revision; U16 parameter length and parameters; U64 encoded length; decoded-length presence and optional U64; 32-byte content digest; expiry presence and optional U64 |
| optional text | presence bool; when present, U16 UTF-8 length and bytes |
| record extensions | U8 count; each value is U32 ID, bool critical, U16 value length, and opaque value |

The bounds are the core limits: 8 protocols, 16 schemas, 16 codec preferences,
32 extensions, 1,024 extension-value or codec-parameter octets, 128 offer
descriptors, 128 request selections, 1,000,000 collection entries, 64 failure
scope octets, and 256 diagnostic UTF-8 octets. Nested structure is fixed to the
operation → bounded collection → descriptor/selection/extension depth; there
is no recursive value.

## Exact-size formulas

Let `V(x)` be the octet length of the canonical unsigned LEB128 encoding of
nonnegative integer `x`. Let `L(r)` be the existing arithmetic B1 exact size,
which does not serialize. Let `C(r, context)` be the candidate exact size.

```text
E(b) = 1 + V(b)                         outer header and body length

static capabilities:
  b = 1
  C = E(1) + 1 = 3

exact cached summary:
  binding = SHA-256("BEMPIC-COMPACT-SUMMARY-CACHE-v0.1\0" ||
                   collection_id || U64BE(generation) ||
                   U64BE(item_count) || collection_digest)
  b = 1 + 32
  C = E(33) + 33 = 35

cold full summary s:
  b = 1 + 32 + V(s.generation) + V(s.item_count) + 32
  C = E(b) + b

generic record r:
  b = 1 + (L(r) - 7)
  C = E(b) + b
```

The prescribed generation/count pair `(100, 100)` uses one octet for each
integer, so its full-summary body is 67 octets and its complete record is 69.
`Record::exact_encoded_size` is invoked only for validation and the inherited
closed B1 arithmetic; the candidate size function never performs trial
serialization or allocation proportional to the encoded record.

## Maximum encoded sizes and reaching witnesses

For each operation maximum, `M_B1` is the already reached B1 maximum and the
candidate maximum is:

```text
content = M_B1 - 7
body = 1 + content
M_candidate = 1 + V(body) + body
```

All maxima below have an encoded semantic witness. The deterministic evidence
artifact records each witness SHA-256 and exact length; the conformance command
encodes, strictly decodes, and compares every witness.

| Operation | B1 maximum | Candidate maximum | Outer envelope | Form |
|---|---:|---:|---:|---:|
| `CAPABILITIES` | 34,362 | 34,360 | 4 | generic |
| `SUMMARY` | 33,080 | 33,078 | 4 | generic, with maximum extensions |
| `OFFER` | 186,789 | 186,787 | 4 | generic |
| `REQUEST` | 39,186 | 39,184 | 4 | generic |
| `DATA` | 1,048,576 | 1,048,574 | 4 | generic |
| `RECEIPT` | 33,341 | 33,339 | 4 | generic |
| `FAILURE` | 33,326 | 33,324 | 4 | generic |

The candidate's accepted outer ceiling remains 1,048,576 octets. Its tightest
reachable semantic record maximum is 1,048,574 because the inherited maximum
`DATA` content plus the canonical candidate envelope is two octets smaller than
B1. An outer input of 1,048,577 octets is rejected before body allocation.

No approximate numeric type exists; rounding, NaN, infinity, and negative-zero
vectors are explicitly not applicable.

## Canonical parameters and supported fingerprint

The canonical parameter block is empty. The static capability alias expands to
the exact schema fingerprint:

```text
d8906a1cefbf89e4f29b4a0f636cfbfa1e9c6301e7e3a4fe213c090066f8e797
```

It also expands to protocol generation `0.1`, private-use codec
`0xffff0001/2`, maximum operation 1,048,576, maximum data payload 1,000,000,
receipt levels `0x0f`, public security class, and no extensions. Any different
capability value uses the generic form and carries every field.

The candidate's complete-record semantics are described by the full core
operations fingerprint
`c4a686e7e9c6a40a5f187259a376b26cfc1d355179fd9fff487e105aeeac7302`.
The advertised opaque-binary representation schema above has exact encoded
size `n` for `0 <= n <= 1,073,741,824`; its decoded value is byte-identical and
has the same maximum. The message-manifest fingerprint is not supported by
this candidate, so no manifest-schema maximum or conformance claim is made.

## Prescribed V01 measurements

The deterministic fixture implements all 100 specified object IDs, creation
times, sender, recipient, subject, and body values. Each manifest is validated;
the collection checkpoint is computed over the 100 body-representation entries.
The selected collection ID is the fixture-only value
`SHA-256("BEMPIC-V01-COLLECTION\0")`. The artifact publishes the resulting full
collection ID and digest.

| Case | Operations | B1 revision-1 image | Candidate revision-2 image | Gate |
|---|---|---:|---:|---:|
| warm no-change | exact cached `SUMMARY` | 88 | 35 | <=64: pass |
| cold no-change | two profile `CAPABILITIES` plus cold full `SUMMARY` | 292 | 75 | <=128: pass |

The B1 comparison encodes the same full candidate semantic values; its 102/88
operation sizes equal the current blocker. No carrier, security-handshake, or
required BEMPIC byte is excluded.

## Failure behavior and compatibility

Truncation, false lengths, overlong/nonminimal varints, trailing bytes, unknown
tags/forms, missing or mismatched cache, matching-cache full form, oversized
outer records, and inherited B1 malformed/bound violations all fail before
returning a record.
No partial operation is applied. The decoder's only allocation proportional to
remote input is bounded by the checked one-megabyte outer ceiling.

Revision 2 is intentionally incompatible with B1 revision 1. The old codec is
retained only for fixture comparison and is not a compatibility promise.

## Allocation-ready evidence summary

An experimental allocation request in the specification repository would need
to replace the private-use ID with a reviewed experimental-range ID and update
all bytes, capability values, representation IDs, profile/vector digests, and
compatibility statements that bind the ID. The evidence package supplies:

- this public profile and exact formulas;
- finite maxima and reaching-witness digests for all seven operations;
- valid, boundary, malformed, truncated, noncanonical, context-failure, and
  one-past vectors;
- deterministic Rust malformed/property coverage and exact-size equality;
- an independent Python decoder/verifier for the published compact forms;
- exact 100-message warm/cold byte captures and field breakdowns;
- security/license/compatibility statements; and
- a machine-readable conformance report that remains a non-claim.

The package is still insufficient for allocation or approval by itself: the
specification registry is unchanged, governance has not accepted state-bound
aliases, the mandatory V01-V15 bundle remains incomplete, and the existing
B2F, M4P, object-ID-profile, and release blockers remain.
