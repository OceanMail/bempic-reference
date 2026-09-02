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
`7d29453c87b6f08f1abf6214c4ca64dd82030e99` defines stable directional
`semantic_bytes`, the exact 24-row V08 matrix, and complete expected outcomes
for the expanded mandatory catalog. The current candidate implements all
locally decided rows, but must not be tagged or described as conformant. The
public experimental tuple `0x00010000/1` passes the 64/128-byte no-change limits
at 35/75 bytes, but it is not approved, mandatory, stable, or production-secure.
V01/V02 still lack normative manifest-instance encoding; V09 still requires
external M4P review; B2F is blocked on a qualified oracle; and independent
implementation, security-profile, and release gates remain open.
