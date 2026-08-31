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

## Security boundary

SHA-256 in v0.1.0 binds identifiers and detects accidental/corrupt bytes. It is
not authentication, confidentiality, authorization, replay protection, or a
production cryptographic profile. Production security remains future
specification work.

