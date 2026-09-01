# Contributing

Contributions are accepted under Apache License 2.0 as described by Section 5
of [LICENSE](LICENSE), unless the contributor explicitly states otherwise.

Executable protocol behavior, codecs, persistence adapters, simulators,
vectors, and measurements belong here. Public protocol semantics and registry
allocations belong in the sibling `bempic` specification repository. Routing,
mesh coordination, forwarding, generic fragmentation, network deduplication,
TTL, and DataLink reliability belong in M4P or DataLink projects.

Changes must preserve deterministic behavior, enforce remotely influenced
bounds before allocation or durable mutation, add exact-size and malformed
tests, update conformance evidence, and pass formatting, strict Clippy, all Rust
and Python tests, demos, benchmarks, independent verification, and CI.

Do not contribute private mail, credentials, production keys, or third-party
source/data without documented provenance, notices, and a compatible license.
