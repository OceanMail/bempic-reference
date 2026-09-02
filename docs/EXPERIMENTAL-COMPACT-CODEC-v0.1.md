# Experimental public compact codec `0x00010000/1`

## Status and scope

This document describes the reference implementation of the public
experimental codec tuple `0x00010000/1` at read-only BEMPIC specification
commit `7d29453c87b6f08f1abf6214c4ca64dd82030e99`. The normative profile has
SHA-256
`bc82364f7ac2f563bbdc0ea15f3d9b1f9127d6ac88376bf19a6dc642dc731127`.

The allocation is experimental. It is not approved, mandatory, stable, a
production-security profile, suitable for private traffic, or sufficient for
v0.1.0 conformance. The security class is `public`: there is no authentication,
confidentiality, replay-protection, or traffic-analysis claim. DCCL and M4P
code, tables, protected material, and dependencies are not used.

The former private tuple `0xffff0001/2` is incompatible historical provenance
only. Active encode, decode, negotiation, persistence, vectors, measurements,
and conformance evidence use `0x00010000/1`.

Public revision 1 supports the core-operation fingerprint
`c4a686e7e9c6a40a5f187259a376b26cfc1d355179fd9fff487e105aeeac7302`
and the opaque-binary fingerprint
`d8906a1cefbf89e4f29b4a0f636cfbfa1e9c6301e7e3a4fe213c090066f8e797`.
It explicitly makes no message-manifest schema claim and defines no canonical
manifest-instance encoding. The semantic JSON manifest fixture is therefore
not a codec representation, and V01/V02 remain blocked on a normative manifest
codec decision.

## Semantic boundary

The codec maps all seven semantic `Operation` variants to complete,
length-delimited records without changing collection, selection, budget,
persistence, integrity, receipt, carrier, or failure semantics. Generic forms
reuse the strict B1 operation content after replacing only the envelope.

Two aliases are lossless:

1. The static capability alias expands to the exact public tuple, full
   32-octet opaque schema fingerprint, generation, maxima, receipt levels,
   public security class, and empty extension lists.
2. The warm-summary alias is legal only with the exact durable checkpoint
   supplied by the caller. It carries a full SHA-256 binding of the 32-octet
   collection ID, generation, item count, and 32-octet collection digest.

Aliases never truncate identifiers or hashes. Missing, stale, or mismatched
context fails before an operation is returned. A cold full summary is
noncanonical when the exact cached summary is supplied. Encoding is
deterministic for `(record, explicit context)`; the empty context is canonical
for cold encoding.

## Complete record format

```text
header:u8 || body_length:canonical-uvarint || body[body_length]
```

`header & 0xf8` is `0xb0`; the low three bits are operation tags 1 through 7.
The unsigned LEB128 body length must be shortest-form and exactly equal the
remaining length. A complete record is at most 1,048,576 octets.

The first body octet is the form:

| Operation | Form | Meaning |
|---|---:|---|
| `CAPABILITIES` | `0x01` | exact public experimental capability; body ends |
| `SUMMARY` | `0x01` | full ID, minimal generation/item-count varints, full digest |
| `SUMMARY` | `0x02` | full 32-octet binding of the exact supplied checkpoint |
| all operations | `0x00` | B1 operation content after its seven-octet envelope |

Generic `CAPABILITIES` is noncanonical when it equals the alias. Every
extension-free `SUMMARY` uses a summary form. Optional unknown extensions are
bounded and skipped; unknown critical extensions reject before return.

The inherited fields retain B1 order and widths: fixed integers are unsigned
big-endian, booleans are exactly `0x00` or `0x01`, counts are one octet,
payload lengths are four octets, and descriptor/extension lengths are two
octets. The bounds remain 8 protocols, 16 schemas, 16 codec preferences, 32
extensions, 1,024 extension-value octets, 128 offer descriptors, 128 request
selections, 1,000,000 collection entries, 64 failure-scope octets, and 256
diagnostic UTF-8 octets. Nesting is fixed, not recursive.

## Tuple and schema rejection

The active profile accepts only ID `0x00010000`, revision `1`, the opaque
representation schema, and an empty parameter block. It rejects these before
durable cache, page, descriptor, or payload mutation:

- reserved IDs `0` and `0xffffffff`;
- every private-use ID `0x80000000..0xfffffffe`, including historical
  `0xffff0001/2`;
- revision zero;
- unknown IDs and revision other than 1;
- mixed private/public capability advertisements;
- non-empty codec parameters; and
- unsupported or mismatched schema fingerprints, including the manifest
  fingerprint.

Stale capabilities are never used after expiry. Re-negotiation must reproduce
the exact public tuple before replacing a durable cached profile.

## Exact-size formulas

Let `V(x)` be the length of canonical unsigned LEB128 and `L(r)` the arithmetic
B1 exact size. Let `E(b) = 1 + V(b)` be the compact envelope excluding the body.

```text
static capabilities:
  body = 1
  size = E(1) + 1 = 3

exact cached summary:
  binding = SHA-256("BEMPIC-COMPACT-SUMMARY-CACHE-v0.1\0" ||
                   collection_id || U64BE(generation) ||
                   U64BE(item_count) || collection_digest)
  body = 1 + 32
  size = E(33) + 33 = 35

cold full summary s:
  body = 1 + 32 + V(s.generation) + V(s.item_count) + 32
  size = E(body) + body

generic record r:
  body = 1 + (L(r) - 7)
  size = E(body) + body
```

The `(generation, item_count) = (100, 100)` full summary is 69 octets. Exact
size uses closed arithmetic and never trial serialization.

## Maximum sizes and reaching witnesses

For profile-valid B1 maximum `M`, the generic compact maximum is:

```text
content = M - 7
body = 1 + content
maximum = 1 + V(body) + body
```

CAPABILITIES has exactly one supported schema and tuple, reducing the generic
B1 maximum by `15*32 + 15*40 = 1,080` octets. OFFER descriptors require empty
parameters, reducing its generic maximum by `128*1,024 = 131,072` octets. The
table therefore contains reachable public-profile maxima, not impossible
generic/private combinations.

| Operation | Profile-valid B1 maximum | Public codec maximum | Envelope | Form |
|---|---:|---:|---:|---:|
| `CAPABILITIES` | 33,282 | 33,280 | 4 | generic |
| `SUMMARY` | 33,080 | 33,078 | 4 | generic |
| `OFFER` | 55,717 | 55,715 | 4 | generic |
| `REQUEST` | 39,186 | 39,184 | 4 | generic |
| `DATA` | 1,048,576 | 1,048,574 | 4 | generic |
| `RECEIPT` | 33,341 | 33,339 | 4 | generic |
| `FAILURE` | 33,326 | 33,324 | 4 | generic |

All seven maxima have deterministic encoded reaching witnesses with exact
length and SHA-256 in the public evidence artifact. The accepted outer ceiling
remains 1,048,576; a 1,048,577-octet input rejects before body allocation.
There are no approximate numeric fields, so rounding, NaN, infinity, and
negative-zero cases are not applicable.

Opaque binary has exact encoded and decoded size `n` for
`0 <= n <= 1,073,741,824`; the decoded value is byte-identical.

## Prescribed 100-message measurement

All required BEMPIC operation bytes are included. The public tuple changes
representation IDs and therefore the exact collection digest, while the
operation lengths remain the proven compact values.

| Case | Operations | B1 | Public experimental | Gate |
|---|---|---:|---:|---:|
| warm no-change | cached `SUMMARY` | 88 | 35 | `<=64`, pass |
| cold no-change | two `CAPABILITIES` + full `SUMMARY` | 292 | 75 | `<=128`, pass |

The public collection digest for the prescribed fixture is
`9caad17af629b24b48f0f0c85f8e3490cd09fdd9bb4903c70309c23257051015`.
The measurement does not turn V01 into a complete mandatory-vector pass:
canonical manifest representation bytes remain unspecified.

## Failure behavior and evidence

Truncation, false lengths, overlong varints, trailing bytes, unknown tags or
forms, bad cache context, noncanonical full summaries, invalid tuples,
unsupported schemas/parameters, and one-past records all fail before return or
durable mutation. No partial operation is applied. Allocation proportional to
remote operation input is bounded by the checked one-megabyte ceiling.

The deterministic package publishes valid, boundary, truncated, malformed,
noncanonical, context-failure, and one-past vectors; exact byte breakdowns;
seven maximum witnesses; malformed/property coverage; independent Python
decoding and digest verification; and the 100-message measurement. Historical
private vectors are not active evidence and imply no compatibility.
