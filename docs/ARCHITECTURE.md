# Architecture and scope

The dependency direction is fixed:

```text
OceanMail → BEMPIC → M4P → DataLink
```

BEMPIC receives application-normalized objects from OceanMail. It prepares
immutable, exactly measurable representations; discovers differences; quotes
and enforces BEMPIC-byte budgets; transfers selected representations; persists
verified progress across lost contacts; and emits semantic receipts.

M4P remains responsible for addressing, routing, forwarding, TTL, network
deduplication, priorities, and generic fragmentation. DataLink remains
responsible for waveforms and link reliability. The simulator models the
carrier contract and its costs, but it does not implement either lower layer.

## Experimental encoding

`ExperimentalCodecV0` is deliberately named and fingerprinted as disposable.
It uses declarative input bounds, exposes a maximum encoded size, and reports
exact encoded sizes before transfer. The `RepresentationCodec` trait allows
other candidates without changing the application model or sync engine.

The retained root-level `BMSG0`/`B0` profile exists for Python-oracle parity.
The separate Rust `v01` modules implement the merged full-width semantic model
and a second disposable record profile. They consume RFC 8785 descriptor
fingerprints, including core revision 2 fingerprint
`c4a686e7e9c6a40a5f187259a376b26cfc1d355179fd9fff487e105aeeac7302`.
No codec ID is registered, and neither experimental profile is a wire standard.

DCCL is prior art for those design properties only. This project has no DCCL
dependency and does not use or claim compatibility with the DCCL wire format.

## Contact negotiation and resume

Capability exchange records a durable maximum complete-record size before the
corresponding phase is marked complete. Every later contact applies the minimum
of that negotiated ceiling, the current carrier ceiling, and the experimental
operation envelope. A larger later carrier therefore cannot silently enlarge
records previously bounded for the peer. v0.1.0 supports only monotonic
narrowing; increasing the negotiated ceiling requires a future explicit
renegotiation mechanism or a fresh synchronization state.

Generation-0.1 compatibility state persists the entire selected
protocol/schema/codec/security/extension tuple with an exact peer/profile
identity and expiry. The two-slot copy-on-write protocol store also retains
the prior checkpoint, target generation, accepted descriptors, page cursor,
and receipt idempotency IDs; target digest mismatch never replaces the prior
valid checkpoint.

After reopening, a durable prefix whose length equals the representation size
is verified and committed before data payload capacity is calculated. This
covers an interruption after the final suffix was persisted but before commit,
including an empty representation for which no part file has yet been created.

Persistence writes synchronize file contents before advancing state. New
prefix and protocol-slot entries, atomic state/complete promotions, quarantine
moves, and newly created store directories also synchronize their containing
directories on Unix before the corresponding durable boundary can report
success. On Windows, the safe standard-library path validates the parent and
retains file synchronization plus completed rename semantics; it does not claim
a portable directory-handle flush guarantee.

`bempic_sim::v01` is the connected full-width experimental path. It carries the
exact descriptor through capability negotiation, `SUMMARY`, `OFFER`, explicit
`REPRESENTATION_DATA`, `DATA`, strict decode, whole-representation validation,
atomic commit, and `RECEIPT`. Its accounting separates directional BEMPIC
records, representation payload, duplicates, useful committed bytes, and
carrier cost. Sender-only, receiver-only, simultaneous, cold, repeated,
replayed, truncated, corrupt, and deterministic storage-boundary failures are
exercised without adding lower-layer routing or fragmentation behavior.

The committed tranche-3 measurement artifact reports all 18 required counters,
including stable-direction semantic bytes, useful payload to first body and
commit, exact quote error, protocol overhead, warm/cold no-change size, and
persistent-resume evidence. Maximum-size analyses remain arithmetic proofs for
the disposable B1/private implementations only; every declared maximum has a
valid encoded witness in tests, but none is an approved codec.

The private-use compact revision-2 candidate adds a strict, length-delimited
outer image and two lossless aliases. Its static capability alias restores the
exact full profile fields. Its warm-summary alias is valid only with the exact
durable peer/collection checkpoint supplied as explicit codec context; absent,
stale, or mismatched context fails before an operation is returned. Cold
summaries still carry the full 32-octet collection ID and digest. This is
application-state compression, not M4P state, and it changes no persistence or
receipt semantics. The candidate is documented in
[`EXPERIMENTAL-COMPACT-CODEC-v0.1.md`](EXPERIMENTAL-COMPACT-CODEC-v0.1.md) and
remains nonconformant until the specification project reviews the alias model
and performs an experimental allocation.

The compact implementation exposes an explicit codec-ID/revision generation
input so an eventual specification allocation can regenerate the static
capability alias without a source edit. Committed evidence always supplies
private identity `0xffff0001/2`; alternate identities in tests are explicitly
unallocated inputs and make no registry claim.

## Semantic evidence boundary

One measurement scope binds endpoint A and endpoint B once. `send` is always A
to B and `receive` is always B to A across restarts, source/carrier changes,
and ownership reversals. `SemanticAccounting` counts each distinct
`(direction, representation_id)` only at its first accepted application
selection. Manifest application scalars contribute recursively; the complete
representation-descriptor container contributes zero.

OceanMail's pinned fixture supplies normalized immutable application semantics
and a 32-octet opaque comparison digest. BEMPIC stores only the object-ID to
opaque-digest binding needed for idempotent observation and conflict rejection;
normalization, object-ID generation, receipt policy, and mailbox behavior remain
outside BEMPIC core.

The tranche-3 generator drives the actual representation and protocol stores
for the authoritative 24-row V08 covering array. Memory rows model bounded
volatile receive state, representation-file rows interrupt after fsynced prefix
bytes, and durable-store rows advance the two-slot state. Every row reopens at
the authoritative prefix and commits a positive receipt only after exact
reconstruction.

## Security boundary

SHA-256 in v0.1.0 binds identifiers and detects accidental/corrupt bytes. It is
not authentication, confidentiality, authorization, replay protection, or a
production cryptographic profile. Production security remains future
specification work.

`AuthorizedSource` in the simulator is only an application-supplied test fact
used to prove source-change resume. It is not production authentication or an
identity profile.
