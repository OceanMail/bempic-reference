# BEMPIC Reference v0.1.0 candidate

BEMPIC is an experimental, deterministic application-synchronization layer for
messaging over severely constrained and intermittently connected carriers.
This repository contains the Apache-2.0 reference implementation, simulator,
fixtures, and cross-language vectors.

> **Conformance status:** not v0.1.0 conformant and not release-ready. The
> requirement-by-requirement evidence under `conformance/` is authoritative.
> The implementation targets specification commit
> `7d29453c87b6f08f1abf6214c4ca64dd82030e99`. Public codec revision 1
> defines no canonical message-manifest instance encoding; B2F, M4P,
> independent-implementation, security-profile, and release gates also remain
> open.

> **No stable wire format:** every encoding in v0.1.0 is an experimental
> measurement candidate. The markers, field widths, hashes, record kinds, and
> schema fingerprints may change incompatibly before a wire generation is
> selected by the specification project.

The allocated public experimental compact tuple `0x00010000/1` measures the
prescribed 100-message no-change operation exchange at 35 B warm and 75 B cold,
versus B1's 88/292 B. It is not approved, mandatory, stable, production-secure,
or sufficient for conformance; V01/V02 remain blocked because the allocation
defines no canonical manifest-instance encoding. See
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
cargo run -p bempic-conformance --release -- write-compact-codec-evidence
cargo run -p bempic-conformance --release -- verify-compact-codec-evidence
cargo run -p bempic-conformance --release -- verify-tranche3-evidence
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

`test-vectors/v0.1-experimental/` uses the clarified specification's bundle
contract and an independent Python verifier. It contains exact endpoint-bound
semantic accounting, all 24 V08 rows, 42 V12 budget cases, 26 V15 failure
cases, and expanded V04/V05/V06/V10/V11/V13 traces. The catalog reports 12
pass and three blocked rows; it remains evidence, not a conformance claim.

## License

Licensed under the [Apache License 2.0](LICENSE).
