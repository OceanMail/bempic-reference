# Private compact-candidate vectors

These frozen vectors exercise the former implementation-local private-use codec
`0xffff0001/2`. They are historical provenance only: not active evidence, not a
registered BEMPIC vector bundle, not public interoperability evidence, and not
a compatibility promise. Their contemporary profile and results are preserved
in [`../../docs/work-reports/2026-09-01-v0.1-compact-codec-evidence.md`](../../docs/work-reports/2026-09-01-v0.1-compact-codec-evidence.md).

`vectors.json` is retained byte-for-byte for provenance and fixture comparison.
The active verifier and conformance report exclude it.

The active `v0.1-public-experimental-codec/` pack uses `0x00010000/1`. The
private and public tuples are intentionally incompatible.
