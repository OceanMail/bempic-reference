# BEMPIC v0.1 conformance evidence matrix

Specification authority: `C:\Projects\OceanMail\bempic`, merge commit
`c67a87e9dcc4fb91b25ed4f4ccc0bee46823e401`.

Implementation status: **blocked; no BEMPIC v0.1.0 conformance claim**. The
machine-readable authority for exact requirement text, evidence, gaps, tool
versions, vector outcomes, and blockers is
[`conformance/v0.1.0-report.json`](../conformance/v0.1.0-report.json).

Status meanings:

- `pass`: implemented and backed by the cited executable evidence;
- `partial`: some required behavior is evidenced, but the recorded gap remains;
- `fail`: implemented evidence demonstrates failure, or mandatory evidence is
  absent where local implementation was required;
- `blocked`: completion requires an unresolved specification/governance,
  licensing, external-review, or delivery dependency.

## Semantic checklist

| ID | Status | Evidence and remaining gap |
|---|---|---|
| SEM-01 | partial | v0.1 model and strict reader enforce principal bounds; exhaustive field/count/nesting allocation vectors remain incomplete. |
| SEM-02 | partial | NFC/control validation and deterministic preparation are tested; the library rejects rather than normalizes non-NFC application input. |
| SEM-03 | pass | Rust and independent RFC 8785 Python verification reproduce all published fingerprints, including core `c4a686e7…`, and full representation IDs. |
| SEM-04 | partial | Representation/collection conflicts fail closed; no durable cross-manifest object-ID semantic registry exists. |
| SEM-05 | pass | Python oracle tests and benchmark report zero unselected/deferred attachment payload. |
| SEM-06 | pass | Equal checkpoint, known delta, and bounded unknown full fallback are implemented and tested. |
| SEM-07 | pass | Two-slot protocol storage retains cursors and rejects target-digest mismatch. |
| SEM-08 | pass | Explicit selection and offset types/invariants are encoded, independently decoded, and enforced by the integrated full-width path. |
| SEM-09 | pass | Matching overlap is idempotent; gaps and conflicting overlap fail closed. |
| SEM-10 | pass | Atomic total/directional `BudgetScope` admission passes exact/one-below tests and is integrated before carrier submission. |
| SEM-11 | pass | Every submitted full-width record is predicted, directionally counted, and reconciled to zero quote error. |
| SEM-12 | pass | `CostPrecision` distinguishes exact, estimated, and unavailable lower-layer domains. |
| SEM-13 | pass | Durable prefix matrix reopens at 0/1/10/50/90/final-byte positions. |
| SEM-14 | pass | Resume through a second application-authorized source and changed carrier is tested. |
| SEM-15 | pass | One full-width path verifies length, digest, ID, schema, and opaque deterministic decode before atomic commit. |
| SEM-16 | pass | Receipt emission is after commit; post-commit/pre-receipt reopen is tested. |
| SEM-17 | partial | Four receipt meanings and idempotency IDs exist; application-profile state integration is absent. |
| SEM-18 | pass | Highest identical generation and preference-sum schema/codec selection with deterministic tie-breaks is tested. |
| SEM-19 | pass | Unknown optional extensions are skipped and critical ones reject before return/mutation. |
| SEM-20 | partial | 50,000 arbitrary, 187 structured malformed, and 4,100 property cases have zero findings; mandatory malformed catalog incomplete. |
| SEM-21 | partial | Stores are scoped per collection/representation; no complete hostile multi-object trace is published. |
| SEM-22 | pass | Contact loss and budget exhaustion remain resumable simulator pauses. |
| SEM-23 | pass | Opaque carrier and mock M4P adapter contain no routing, TTL, fragment, deduplication, or link reliability state. |

## Codec checklist

| ID | Status | Evidence and remaining gap |
|---|---|---|
| CODEC-01 | blocked | Codec `0xffff0001/1` is explicitly implementation-local; the specification registry has no allocation. |
| CODEC-02 | pass | Canonical schema bytes and exact 32-octet fingerprints are published. |
| CODEC-03 | partial | Schema and Rust types cover fields/bounds; a complete profile document and numeric-N/A vector declaration are absent. |
| CODEC-04 | pass | All seven operations use complete length-delimited experimental records. |
| CODEC-05 | pass | Per-operation conservative maxima and schema limits are declared. |
| CODEC-06 | pass | Exact arithmetic sizing agrees with serialization over 4,100 generated payload sizes. |
| CODEC-07 | pass | Arithmetic proof terms and exact valid maximum-size witnesses cover all seven disposable experimental operations. |
| CODEC-08 | pass | Encoding is deterministic; fixed-width scalars, booleans, lengths, tags, and trailing bytes decode strictly. |
| CODEC-09 | pass | Optional/critical extension behavior is executable. |
| CODEC-10 | partial | Reader checks counts/lengths before allocation; exhaustive one-past/nesting vectors are absent. |
| CODEC-11 | fail | Published bundle has one valid and one invalid vector; mandatory catalog is incomplete. |
| CODEC-12 | partial | Independent Python decoder agrees on every published vector, but the bundle itself is incomplete. |

## Persistence and crash cases

| ID | Status | Evidence and remaining gap |
|---|---|---|
| PERSIST-01 | pass | Offer-page cursor commit and duplicate replay survive reopen. |
| PERSIST-02 | pass | Prefix-length updates reopen at exact recoverable bytes. |
| PERSIST-03 | pass | Fully durable final suffix is verified/committed before payload-capacity calculation. |
| PERSIST-04 | pass | Verified staging state reopens and commits without payload. |
| PERSIST-05 | pass | Committed state reopens before receipt without false or lost commit. |
| PERSIST-06 | pass | Required receiver percentages and final byte are deterministic tests. |
| PERSIST-07 | pass | Sender-only, receiver-only, and simultaneous process restarts retain one monotonic durable prefix. |
| PERSIST-08 | pass | A changed authorized source and changed carrier resume identical bytes. |

## Accounting cases

| ID | Status | Evidence and remaining gap |
|---|---|---|
| ACCOUNT-01 | partial | The full-width artifact has directional BEMPIC/carrier, payload/useful/duplicate, and labeled unavailable link cost; normative `semantic_bytes` and a full-width manifest corpus remain absent. |
| ACCOUNT-02 | pass | Python quote error is zero and Rust exact-size properties agree. |
| ACCOUNT-03 | pass | Total and directional admission is atomic and integrated into full-width carrier submission. |
| ACCOUNT-04 | pass | Unselected payload is zero. |
| ACCOUNT-05 | pass | First body DATA begins after 747 BEMPIC/787 carrier octets and carries 460 useful payload octets. |
| ACCOUNT-06 | pass | The tranche-2 artifact records per-operation and protocol-overhead resume-control cost. |
| ACCOUNT-07 | pass | Persistent resume saves 401 payload octets and 1,082 carrier octets against deterministic full restart. |

## `bempic-reference` release gates

| ID | Status | Evidence and remaining gap |
|---|---|---|
| REF-01 | pass | Apache-2.0, contribution terms, NOTICE, locked versions, and third-party license table are committed. |
| REF-02 | partial | v0.1 bounded semantic types exist; conforming manifest codec integration does not. |
| REF-03 | pass | Seven operations and compatibility/collection/receiver/sender transition checks exist. |
| REF-04 | pass | RFC 8785 fingerprints, full IDs, content digest, preparation, validation, and opaque reconstruction pass. |
| REF-05 | pass | Append checkpoints, delta/full reconciliation, and durable cursors pass. |
| REF-06 | pass | Hard total/directional budgets, exact preflight, and accounting are one integrated v0.1 path. |
| REF-07 | pass | Full-width crash/reopen, every endpoint restart mode, nine storage boundaries, source change, replay, quarantine, and retry pass. |
| REF-08 | partial | Negotiation core works; every incompatibility/stale-cache trace is not bundled. |
| REF-09 | blocked | Exact experimental maxima are proven, but no approved codec registry allocation or profile exists. |
| REF-10 | pass | Tool/version/duration/corpus digest and zero findings are published in `conformance/fuzz-report.json`. |
| REF-11 | fail | V01–V15 now have a machine-readable evidence/pending inventory, but the mandatory byte/state bundle remains incomplete. |
| REF-12 | partial | Independent verifier covers only the incomplete published bundle. |
| REF-13 | partial | Oracle and differential tests pass; no maintainer-accepted parity disposition exists. |
| REF-14 | blocked | Raw/MIME/candidate/interruption/persistence/full-restart figures exist; a legal B2F oracle does not. |
| REF-15 | pass | Deferred payload, total budgets, durable final prefix, and deterministic quote tests pass. |
| REF-16 | pass | Opaque trait and one-record mock M4P adapter are tested. |
| REF-17 | blocked | Requires immutable final commit, green CI, and specification-release-PR coordination. |

## Protocol acceptance gates

| ID | Status | Evidence and remaining gap |
|---|---|---|
| ACCEPT-01 | fail | Not all correctness checklist items pass. |
| ACCEPT-02 | fail | Measured v0.1 experimental profile: warm 88 B (limit 64), cold 292 B (limit 128). |
| ACCEPT-03 | pass | Known checkpoint sends only sequences after the retained generation; old entries are not offered. |
| ACCEPT-04 | pass | Integrated preflight predicts every submitted record exactly and no total or directional budget is crossed. |
| ACCEPT-05 | pass | No unselected attachment payload. |
| ACCEPT-06 | pass | Fully durable final prefix is not resent; duplicate bytes are counted. |
| ACCEPT-07 | pass | The integrated path validates length/digest/ID/schema/decode before commit and positive receipt. |
| ACCEPT-08 | blocked | No approved legally compatible B2F/LZHUF oracle; no result is fabricated. |
| ACCEPT-09 | blocked | Mock boundary exists; external M4P maintainer/reviewer confirmation is still required. |

## Published measurements and vectors

- Tranche-2 integrated measurement artifact:
  [`benchmarks/results/conformance-tranche-2-2026-09-01.json`](../benchmarks/results/conformance-tranche-2-2026-09-01.json).
- Malformed/property report:
  [`conformance/fuzz-report.json`](../conformance/fuzz-report.json).
- Incomplete experimental v0.1 bundle:
  [`test-vectors/v0.1-experimental/manifest.json`](../test-vectors/v0.1-experimental/manifest.json),
  digest `2411074bd16b6c3a4073849d6ceae730f0e06e288ed58816a60b1839d6317fb0`.
- V01–V15 inventory and specification questions:
  [`test-vectors/v0.1-experimental/catalog.json`](../test-vectors/v0.1-experimental/catalog.json).
- Independent verifier: [`scripts/verify_conformance.py`](../scripts/verify_conformance.py).

The B2F/LZHUF row is a genuine release blocker. No incompatibly licensed code
or unreviewed benchmark output has been imported, vendored, or substituted.
