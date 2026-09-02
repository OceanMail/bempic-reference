# BEMPIC Reference development freeze — work report

**Date:** 2026-09-02

## Objective

Owner-authorized halt/freeze of BEMPIC Reference implementation, codec, conformance, and release work while OceanMail 0.2 establishes a measured HERMES-derived communications baseline.

## Preservation

Created `archive/v0.1-generation` from the pre-freeze `main` state. It preserves the complete experimental implementation, tests, vectors, fixtures, evidence, and former active work state.

No v0.1.0 release/conformance claim or stable-wire claim was made.

## Changes on active `main`

- `FROZEN-2026-09-02.md` — records the freeze and reactivation condition; commit `61a0955b4ae1038bd20f5f7f826ae70e4d93bd3b`.
- `README.md` — makes frozen/nonconformant/no-stable-wire status explicit and moves the old OceanMail stack to historical context; commit `ca93994e520203d0d298479dd62316623790e752`.
- `AGENTS.md` — makes the freeze highest-priority authority for future agents; commit `cf9ef81b281e8013105eaffb5e54f5877e682286`.

## Freeze rule

Until BEMPIC itself is explicitly reactivated by the owner after comparative HERMES-baseline evidence:

- no codec stabilization or new wire-format work;
- no conformance/release completion work;
- no new protocol feature work;
- no OceanMail integration merely to complete the 0.1 architecture; and
- no speculative HERMES compatibility work.

Owner-authorized preservation, documentation, security, licensing, or correctness maintenance that does not restart protocol development remains possible.

## Verification

This transition changed repository documentation/authority only. No Rust/Python implementation, vector, fixture, codec, or conformance behavior was modified.

Existing executable verification suite: **not rerun / not applicable to documentation-only freeze changes**.

No release, tag, or package publication occurred.

## Cross-repository notes

The owner explicitly authorized matching changes in `oceanmail`, `oceanmail-server`, `oceanmail-infrastructure`, and `bempic`.

OceanMail 0.2 is now HERMES/Mercury upstream-first. This repository remains independent Apache-2.0 BEMPIC research and must not be rewritten as an HERMES-specific implementation unless a later protocol decision actually requires that.

## Failures and recoveries

None in this repository during the freeze changes.

## Remaining blockers / deferred work

All former codec/conformance/release blockers remain intentionally deferred while frozen. Passing existing tests in the future would not by itself lift the freeze or establish v0.1.0 conformance.

## Final revision note

The latest BEMPIC Reference `main` commit before this report was `cf9ef81b281e8013105eaffb5e54f5877e682286`. The commit containing this report is the next Git history entry and is the authoritative freeze completion record.
