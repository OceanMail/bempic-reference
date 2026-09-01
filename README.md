# BEMPIC Reference v0.1.0 candidate

BEMPIC is an experimental, deterministic application-synchronization layer for
messaging over severely constrained and intermittently connected carriers.
This repository contains the Apache-2.0 reference implementation, simulator,
fixtures, and cross-language vectors.

> **Conformance status:** not v0.1.0 conformant and not release-ready. The
> requirement-by-requirement evidence under `conformance/` is authoritative.
> The implementation targets specification commit
> `c67a87e9dcc4fb91b25ed4f4ccc0bee46823e401`, but mandatory codec, vector,
> performance, B2F, interruption, and external M4P-review gates remain open.

> **No stable wire format:** every encoding in v0.1.0 is an experimental
> measurement candidate. The markers, field widths, hashes, record kinds, and
> schema fingerprints may change incompatibly before a wire generation is
> selected by the specification project.

The private-use compact revision-2 evidence candidate now measures the
prescribed 100-message no-change cases at 35 B warm and 75 B cold, versus the B1
comparison's 88/292 B. It remains explicitly nonconformant and unusable as
public interoperability evidence until the specification repository reviews
the state-bound alias and performs an experimental allocation. See
[`docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md`](docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md).

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
- `bempic-conformance`: deterministic malformed-input/property runner and
  v0.1 acceptance measurements.
- `prototype`: the original standard-library Python behavioral oracle.

Generation-0.1 semantic types live in `bempic_model::v01`,
`bempic_sync::v01`, and `bempic_store::v01`. Root-level `BMSG0`/`B0` types are
retained only for prototype parity and review-regression coverage.

## Run

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo run -p bempic-conformance --release
cargo run -p bempic-conformance --release -- tranche2-measurements
cargo run -p bempic-conformance --release -- compact-codec-evidence
cargo run -p bempic-conformance --release -- verify-compact-codec-evidence
cargo run -p bempic-cli -- demo
cargo run -p bempic-bench --release
python -m pip install --require-hashes -r requirements-conformance.txt
python scripts/verify_conformance.py
python scripts/check_docs.py
python -m unittest discover -s prototype/tests -v
python -m prototype.demo
python -m prototype.benchmark
```

The committed files under `test-vectors/experimental-v0/` are differential
vectors shared by Rust and Python. They are experimental fixtures, not a
compatibility promise.

`test-vectors/v0.1-experimental/` uses the merged specification's bundle
contract and an independent Python verifier. Its manifest explicitly marks the
mandatory catalog incomplete; it is evidence, not a conformance claim.
The catalog records all V01–V15 cases, executable evidence, pending vectors,
and precise specification questions without inventing expected values.

## License

Licensed under the [Apache License 2.0](LICENSE).
