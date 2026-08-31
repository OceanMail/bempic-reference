# Release status

## 0.1.0

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

