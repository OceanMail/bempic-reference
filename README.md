# BEMPIC Reference v0.1.0

BEMPIC is an experimental, deterministic application-synchronization layer for
messaging over severely constrained and intermittently connected carriers.
This repository contains the Apache-2.0 reference implementation, simulator,
fixtures, and cross-language vectors.

> **No stable wire format:** every encoding in v0.1.0 is an experimental
> measurement candidate. The markers, field widths, hashes, record kinds, and
> schema fingerprints may change incompatibly before a wire generation is
> selected by the specification project.

## Architectural boundary

```text
OceanMail       application normalization, policy, UI, service integration
    ↓
BEMPIC          compact representations, sync, budgets, resume, receipts
    ↓
M4P             routing, store-carry-forward, TTL, generic fragmentation
    ↓
DataLink        link/modem reliability, FEC, ARQ, physical-byte accounting
```

BEMPIC does not implement radios, modem protocols, M4P, Mailcow, billing,
production authentication, or production cryptography. Its v0.1.0 SHA-256
digests provide deterministic identity and corruption detection only.

## Workspace

- `bempic-model`: bounded messages, parts, identifiers, prepared bytes.
- `bempic-codec`: pluggable experimental codecs, fingerprints, exact bounds.
- `bempic-sync`: offers, requests, data operations, receipts, accounting.
- `bempic-store`: crash-conscious file persistence and exact reconstruction.
- `bempic-carrier`: minimal opaque-record carrier contract.
- `bempic-sim`: deterministic budgets, bandwidth, latency, disconnects, time.
- `bempic-cli`: inspect, demo, interrupt/reopen/resume, and vector commands.
- `bempic-bench`: deterministic fixture and carrier measurements.
- `prototype`: the original standard-library Python behavioral oracle.

## Run

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo run -p bempic-cli -- demo
cargo run -p bempic-bench --release
python -m unittest prototype.tests.test_proof -v
python -m prototype.demo
python -m prototype.benchmark
```

The committed files under `test-vectors/experimental-v0/` are differential
vectors shared by Rust and Python. They are experimental fixtures, not a
compatibility promise.

## License

Licensed under the [Apache License 2.0](LICENSE).
