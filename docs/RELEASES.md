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

The merged semantic specification at `c67a87e9dcc4fb91b25ed4f4ccc0bee46823e401`
adds full-width RFC 8785 schema fingerprints, explicit selection, seven core
operations, reconciliation, crash, accounting, vector, codec, and acceptance
gates. The current candidate implements a substantial executable subset, but
must not be tagged or described as conformant. In particular, no codec is
registered, the mandatory vector catalog is incomplete, a compatible
B2F/LZHUF oracle has not been selected, and external M4P binding review is
pending. The private compact revision-2 candidate passes the 64/128-byte
no-change limits at 35/75 bytes, but its private-use ID and unreviewed
state-bound alias do not change release or conformance status.
