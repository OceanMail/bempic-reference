# BEMPIC Reference Implementation

This repository is reserved for the open BEMPIC reference implementation, interoperability fixtures, test vectors, and conformance tooling.

## Status

**Pre-implementation.** No wire format has been frozen and production code should not begin until the protocol repository establishes enough normative behavior to test.

## Purpose

The reference implementation exists to prove that the public BEMPIC specification is independently implementable. It must not depend on proprietary OceanMail services or source code.

Planned contents:

```text
/reference-client
/reference-server
/test-vectors
/conformance
/simulator
/examples
```

The simulator should be developed early so protocol choices can be compared using real byte counts, latency, interruption, corruption/loss, and resume behavior.

## Licensing

The intended direction is a permissive open-source license suitable for broad independent and commercial implementation, but no license is adopted until an explicit LICENSE file is committed.

## Source of truth

Protocol semantics belong in the `Gordonfive/bempic` specification repository. This repository implements and tests them; it does not define proprietary extensions by accident.
