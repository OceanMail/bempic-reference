> [!IMPORTANT]
> **Historical repository — superseded for active OceanMail development.**
> This repository preserves the experimental BEMPIC reference implementation from the OceanMail 0.1 generation. It is not part of the active OceanMail 0.2 implementation path. Current work lives in the active repositories under the [OceanMail organization](https://github.com/OceanMail).

# BEMPIC Reference v0.1.0 candidate — Frozen

BEMPIC Reference is an experimental, deterministic application-synchronization implementation for severely constrained and intermittently connected carriers.

## Status

**Development frozen/halted as of 2026-09-02.**

> **Conformance status:** not v0.1.0 conformant and not release-ready.

> **Wire status:** no stable public wire format. Existing encodings, vectors, field widths, hashes, record kinds, and schema fingerprints remain experimental research evidence.

OceanMail 0.2 has moved to an upstream-first HERMES/Mercury implementation path. BEMPIC and this reference implementation are no longer on the mandatory OceanMail path. Development may resume only if direct comparison against the HERMES `UUCP + uuxcomp` baseline under equivalent constrained-link/modem conditions demonstrates material value worth the additional protocol and maintenance burden.

See [FROZEN-2026-09-02.md](FROZEN-2026-09-02.md). The exact pre-freeze generation is preserved at `archive/v0.1-generation`.

## Historical architectural context

The reference was built for the OceanMail 0.1 intended stack:

```text
OceanMail       application normalization, policy, UI, service integration
    ↓
BEMPIC          compact representations, sync, budgets, resume, receipts
    ↓
M4P             routing, store-carry-forward, TTL, generic fragmentation
    ↓
DataLink        link/modem reliability, FEC, ARQ, physical-byte accounting
```

OceanMail 0.2 no longer requires this stack. The implementation remains useful research into compact synchronization, exact accounting, durable resume, and interruption behavior.

## Workspace

- `bempic-model`: bounded messages, parts, identifiers, prepared bytes.
- `bempic-codec`: pluggable experimental codecs, fingerprints, exact bounds.
- `bempic-sync`: offers, requests, data operations, receipts, accounting.
- `bempic-store`: crash-conscious file persistence and exact reconstruction.
- `bempic-carrier`: minimal opaque-record carrier contract.
- `bempic-sim`: deterministic budgets, bandwidth, latency, disconnects, time.
- `bempic-cli`: inspect, demo, interrupt/reopen/resume, and vector commands.
- `bempic-bench`: deterministic fixture and carrier measurements.
- `bempic-conformance`: deterministic malformed-input/property runner and v0.1 acceptance measurements.
- `prototype`: original standard-library Python behavioral oracle.

Generation-0.1 semantic types live in `bempic_model::v01`, `bempic_sync::v01`, and `bempic_store::v01`. Root-level prototype-parity types remain historical/regression evidence.

## Verification

The existing verification commands remain useful for reproducing the frozen evidence:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo run -p bempic-conformance --release
cargo run -p bempic-conformance --release -- tranche2-measurements
cargo run -p bempic-conformance --release -- compact-codec-evidence
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

Passing these checks does not lift the freeze or establish v0.1.0 conformance.

The committed test-vector directories remain experimental differential/conformance evidence, not compatibility promises.

## License

Licensed under the [Apache License 2.0](LICENSE).
