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

After reopening, a durable prefix whose length equals the representation size
is verified and committed before data payload capacity is calculated. This
covers an interruption after the final suffix was persisted but before commit,
including an empty representation for which no part file has yet been created.

## Security boundary

SHA-256 in v0.1.0 binds identifiers and detects accidental/corrupt bytes. It is
not authentication, confidentiality, authorization, replay protection, or a
production cryptographic profile. Production security remains future
specification work.
