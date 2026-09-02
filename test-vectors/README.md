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
`10fc1ddca0b16c974d29a24b6ff2bef189663a1f`, carries exact RFC 8785 schema
fingerprints, full-width semantic fixtures, and executed V01–V15 evidence, and
is verified independently with:

```bash
python scripts/verify_conformance.py
```

Its `mandatory_catalog_status` is `blocked-not-conformant`: twelve rows pass and
V01, V02, and V09 remain blocked by codec allocation or external M4P review.
Expected bytes remain a private experimental codec revision and do not freeze a
wire format.

`v0.1-experimental/catalog.json` inventories V01–V15 and the deterministic
`tranche3-evidence.json` records semantic values, exact state traces, and all
remaining blockers without inventing registry or external-review outcomes.

`v0.1-compact-candidate/` is a separate private-use revision-2 evidence pack.
It contains exact valid, boundary, malformed, truncated, noncanonical,
missing-context, and symbolic one-past vectors plus all-operation reaching
witness digests. It is intentionally not folded into the registered-codec
bundle because the specification registry has not allocated the candidate.
