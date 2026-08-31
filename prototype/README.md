# BEMPIC Executable Semantic Proof

This directory contains the first runnable BEMPIC artifact. It proves that two local application endpoints can transfer one immutable message through multiple byte-constrained contact windows, persist a received prefix, reopen the receiver between contacts, resume at the retained offset, verify the whole representation, and decode the original message. Message manifests can describe independently retrievable attachments without carrying their content; a later explicit selection runs the same persistent transfer for the binary representation.

It is deliberately **non-normative**:

- the operation names follow the semantic plan, but their byte assignments are disposable;
- `BMSG0` and `B0` are experimental markers, not protocol identifiers;
- the 16-byte identifiers, integer widths, SHA-256 digest, record sizes, and state files are not frozen;
- this is a Python measurement/state-machine proof, not the planned Rust reference implementation;
- it implements no mesh, routing, M4P, modem, generic fragmentation, RF reliability, encryption, or real transport binding.

The proof uses only the Python standard library so it can run without installing dependencies.

## Run

From the repository root:

```bash
python3 -m prototype.demo
```

The JSON report includes separate manifest and selected-attachment transfers, every contact budget and expenditure, the pre-contact prediction and prediction error, application-protocol bytes by direction and operation, representation payload bytes, duplicate payload bytes, integrity failures, useful committed bytes, and final decode status. It also proves that no attachment content file or payload byte exists before selection.

To retain the receiver state for inspection:

```bash
python3 -m prototype.demo --state-dir /tmp/bempic-proof-state
```

## Test

```bash
python3 -m unittest prototype.tests.test_proof -v
```

The tests cover deterministic message encoding, strict decoding, all six abstract proof operations, hard byte-budget enforcement, restart/resume without duplicate payload, idempotent duplicate handling, corruption rejection, and clean retry.

## Benchmark

```bash
python3 -m prototype.benchmark
```

The benchmark generates six deterministic synthetic fixtures: tiny text, typical text, international text, a reply chain, a compressible attachment, and an already-compressed attachment. It measures:

- original RFC 5322/MIME bytes;
- uncompressed experimental representation bytes;
- complete proof-exchange bytes including all six operations;
- side-effect-free pre-contact quotes and actual-versus-predicted error;
- metadata-only attachment discovery;
- independently compressed raw-DEFLATE, zlib, and gzip representation sizes;
- warm and cold collection-summary comparisons;
- bounded incremental discovery after a summary mismatch.

The first recorded run is in [`results/baseline-2026-08-30.json`](results/baseline-2026-08-30.json). On Python 3.12.13, the six uncompressed full exchanges used 24,984 bytes versus 32,052 RFC 5322/MIME bytes. This is not yet a B2F comparison and compression candidates have not been integrated into the exchange.

The detail matters more than the aggregate: the tiny uncompressed proof exchange was 355 B versus 321 B for MIME, and the reply-chain exchange was 1,385 B versus 1,381 B. Attachment deferral is already decisive: the two metadata-only exchanges used 468 B and 483 B while sending zero of the 8,914 B and 10,263 B attachment representations. Warm no-change synchronization costs 58 B and cold costs 76 B, meeting the initial 64 B and 128 B gates. When one of eight representations is new, the proof spends 58 B detecting the mismatch and 62 B offering only the new representation. Pre-contact quotes predicted all 24,984 B of the recorded exchanges with zero-byte error.

## What this proves

- A prepared immutable representation has an exact known byte cost.
- No operation is emitted when it would exceed the current BEMPIC byte budget.
- Before each contact, the harness can quote its exact BEMPIC cost without changing receiver state.
- A lost contact does not restart the application transfer.
- Receiver state survives reopening between every contact.
- On the reliable-carrier profile, there is no per-extent ACK loop; the next contact requests the retained offset.
- A representation is never committed until its whole SHA-256 digest and message decoding succeed.
- The final result is an application completion statement, not a network-hop acknowledgement.
- Attachment descriptors arrive with exact size and digest while content remains absent until selection.
- The same engine resumes and verifies an explicitly selected opaque binary representation.
- Order-independent collection summaries meet the initial warm/cold no-change byte gates and detect a changed set.
- Bounded offer pages never split a record or exceed their budget, and do not resend known entries.
- Reused short identifiers with conflicting representation metadata fail closed.

## What remains

The exact quote currently uses an intentionally expensive clone-and-execute oracle; it establishes an accounting target, not an implementation strategy. The reconciliation cursor is local harness state rather than a serialized protocol field. This proof still postpones compression negotiation and actual compressed transfer, the B2F baseline, security profiles, unreliable-carrier repair, independent decoding, continuation from a different authorized source, and M4P binding. The next implementation phase should create the separate Rust reference repository once its repository and license are established, then port these tested semantics rather than treating this encoding as compatibility authority.

