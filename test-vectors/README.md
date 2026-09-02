# Experimental cross-language vectors

Vectors under `experimental-v0/` are checked by the reproduced Python oracle
and the Rust candidate codec. They prove differential behavior and exact byte
analysis for v0.1.0. They are deliberately marked non-normative and do not
freeze a stable wire format.

Regenerate the Rust view with:

```bash
cargo run -p bempic-cli -- vectors
```

The separate `v0.1-experimental/` bundle targets specification commit
`7d29453c87b6f08f1abf6214c4ca64dd82030e99`, carries exact RFC 8785 schema
fingerprints, full-width semantic fixtures, and executed V01–V15 evidence, and
is verified independently with:

```bash
python scripts/verify_conformance.py
```

Its `mandatory_catalog_status` is `blocked-not-conformant`: twelve rows pass and
V01 and V02 remain blocked by missing normative manifest-instance encoding;
V09 remains blocked by external M4P review. Public experimental expected bytes
do not freeze a stable wire format.

`v0.1-experimental/catalog.json` inventories V01–V15 and the deterministic
`tranche3-evidence.json` records semantic values, exact state traces, and all
remaining blockers without inventing registry or external-review outcomes.

`v0.1-public-experimental-codec/` is the active `0x00010000/1` evidence pack.
`v0.1-compact-candidate/` is frozen historical private-use provenance and is
excluded from active verification and conformance accounting.
