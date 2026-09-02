# Release status

## 0.1.0 candidate (not released)

This release proves semantics and measurement. It intentionally does not freeze
a stable or normative wire format. All `BEMPIC-EXPERIMENTAL-*`, `BMSG0`, and
`B0` values can change before a specification wire-freeze decision.

Implemented proof surface:

- deterministic messages, attachments, identifiers, schema fingerprints;
- pluggable codecs with declared bounds and exact size analysis;
- offers, requests, bounded offset data, and semantic receipt states;
- file persistence, interruption, reopen, prefix resume, and verification;
- deterministic carrier budgets, bandwidth, latency, disconnect schedules,
  elapsed time, event logs, and transfer metrics;
- synthetic fixtures and Python/Rust differential vectors.

Explicitly excluded are radios, M4P behavior, Mailcow integration, billing,
product policy, production authentication, and production cryptography.

The clarified semantic specification at
`10fc1ddca0b16c974d29a24b6ff2bef189663a1f` defines stable directional
`semantic_bytes`, the exact 24-row V08 matrix, and complete expected outcomes
for the expanded mandatory catalog. The current candidate implements all
locally decided rows, but must not be tagged or described as conformant. V01
and V02 public bytes still require a specification codec allocation, V09 still
requires external M4P review, no compatible B2F/LZHUF oracle has been selected,
and independent-implementation/release gates remain open. The private compact
revision-2 candidate passes the 64/128-byte no-change limits at 35/75 bytes,
but its private-use ID and state-bound alias do not change release status.
