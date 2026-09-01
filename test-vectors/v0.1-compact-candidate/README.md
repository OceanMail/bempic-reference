# Private compact-candidate vectors

These vectors exercise implementation-local private-use codec `0xffff0001/2`.
They are allocation-ready evidence, not a registered BEMPIC vector bundle,
public interoperability evidence, or a compatibility promise. The authoritative
profile is [`../../docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md`](../../docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md).

`vectors.json` contains exact valid, boundary, malformed, truncated,
noncanonical, missing-context, and symbolic one-past cases plus reaching-witness
digests for all seven operations. `scripts/verify_conformance.py` independently
recomputes the prescribed V01 checkpoint, decodes every compact form, checks the
failure outcomes and maximum formulas, and verifies the linked artifact digest.

The older `v0.1-experimental/` B1 material remains only for comparison. The two
candidate revisions are intentionally incompatible.
