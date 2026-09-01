# Third-party notices

`Cargo.lock` is authoritative for exact resolved versions. This repository does
not vendor these crates. The normal (non-development) dependency graph at this
change contains the following crates and published SPDX license choices:

| Packages | Resolved versions | Published license |
|---|---|---|
| `hex` | 0.4.3 | MIT OR Apache-2.0 |
| `serde`, `serde_derive` | 1.0.210 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.128 | MIT OR Apache-2.0 |
| `sha2` | 0.10.8 | MIT OR Apache-2.0 |
| `thiserror`, `thiserror-impl` | 1.0.64 | MIT OR Apache-2.0 |
| `tempfile` | 3.12.0 | MIT OR Apache-2.0 |
| `unicode-normalization` | 0.1.25 | MIT OR Apache-2.0 |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 |
| `digest` | 0.10.7 | MIT OR Apache-2.0 |
| `fastrand` | 2.5.0 | MIT OR Apache-2.0 |
| `generic-array` | 0.14.7 | MIT |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 |
| `memchr` | 2.8.3 | Unlicense OR MIT |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 |
| `quote` | 1.0.47 | MIT OR Apache-2.0 |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 |
| `syn` | 2.0.119 | MIT OR Apache-2.0 |
| `tinyvec` | 1.12.0 | Zlib OR Apache-2.0 OR MIT |
| `tinyvec_macros` | 0.1.1 | Zlib OR Apache-2.0 OR MIT |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 |
| `unicode-ident` | 1.0.24 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `windows-sys`, `windows-targets`, `windows_x86_64_msvc` | 0.59.0, 0.52.6, 0.52.6 | MIT OR Apache-2.0 |

Python conformance validation uses `rfc8785==0.1.4`, Copyright Trail
of Bits, distributed under Apache-2.0. The exact package hashes are pinned in
`requirements-conformance.txt`.

The synthetic fixtures were authored for this project and contain no private
mail or third-party message corpus. B2F/LZHUF source has deliberately not been
imported or vendored; selecting a reproducible legally compatible oracle
remains a release blocker.
