# Deterministic fixtures

`corpus-v0.json` is the language-neutral inventory for the synthetic corpus.
The executable fixture builders live in `prototype/fixtures.py` and
`crates/bempic-bench/src/main.rs`. All data is generated, redistributable, and
contains no private email. Exact representation fixtures are committed under
`test-vectors/experimental-v0/`.

Fixture semantics—not candidate wire bytes—should remain stable enough to
compare later codecs. Any corpus change must regenerate and explain benchmark
results.

