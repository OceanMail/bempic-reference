# Codex repository instructions

## Development freeze — highest priority

BEMPIC Reference development is **frozen/halted as of 2026-09-02** together with the BEMPIC specification project. Read `FROZEN-2026-09-02.md` and `README.md` before changing anything.

The exact pre-freeze state is preserved at `archive/v0.1-generation`.

Unless the owner explicitly lifts the freeze after BEMPIC is reactivated by comparative HERMES-baseline evidence:

- do not continue codec, conformance, feature, release, or M4P-binding work;
- do not claim v0.1.0 conformance, release readiness, or stable-wire compatibility;
- do not add OceanMail integration merely to complete the old clean-sheet architecture; and
- do not modify the implementation to chase HERMES compatibility speculatively.

Permitted work while frozen is limited to owner-authorized preservation, documentation, security, licensing, or correctness maintenance that does not restart protocol implementation.

## Permanent work-report requirement

For every non-trivial implementation, release, migration, or repository-wide maintenance assignment, Codex must create or update a dated Git work report under `docs/work-reports/` before claiming completion. The pushed Git document is authoritative; a chat-only completion summary is not sufficient.

Each report must record:

- assignment scope;
- files and behavior changed;
- architecture and boundary decisions;
- commits and branch;
- every verification command and its exact result;
- GitHub Actions and pull-request status, with links when available;
- unresolved blockers;
- deferred work;
- notes affecting sibling repositories;
- a **Failures and recoveries** section.

The failures section must include every failed command, test, build, CI run, and abandoned implementation attempt. For each, record a UTC timestamp or stable sequence, action, exit code when available, concise error excerpt, root cause, corrective action, verification result, final status (`resolved`, `deferred`, or `blocked`), and an Actions link when applicable. If nothing failed, write `None.` Do not commit enormous raw logs or secrets. If a complete local log is genuinely needed, sanitize it and place it under `docs/work-reports/logs/<task-name>/`.

Commit and push the report with the authorized maintenance. Do not claim completion while required local tests or CI checks are failing. Documentation-only freeze maintenance may record executable checks as not applicable. Update the report with the final pull-request/CI state before handoff when applicable.
