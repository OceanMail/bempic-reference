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
`c67a87e9dcc4fb91b25ed4f4ccc0bee46823e401`, carries the exact RFC 8785 schema
fingerprints and explicit `REPRESENTATION_DATA` selection vector, and is
verified independently with:

```bash
python scripts/verify_conformance.py
```

Its `mandatory_catalog_status` is `incomplete-release-blocker`. Expected bytes
remain an unregistered experimental codec revision and do not freeze a wire
format.
