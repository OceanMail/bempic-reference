# Experimental cross-language vectors

Vectors under `experimental-v0/` are checked by the reproduced Python oracle
and the Rust candidate codec. They prove differential behavior and exact byte
analysis for v0.1.0. They are deliberately marked non-normative and do not
freeze a stable wire format.

Regenerate the Rust view with:

```bash
cargo run -p bempic-cli -- vectors
```

