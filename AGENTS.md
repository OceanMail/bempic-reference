# Codex repository instructions

## Permanent work-report requirement

For every non-trivial implementation, release, migration, or repository-wide
maintenance assignment, Codex must create or update a dated Git work report
under `docs/work-reports/` before claiming completion. The pushed Git document
is authoritative; a chat-only completion summary is not sufficient.

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

The failures section must include every failed command, test, build, CI run, and
abandoned implementation attempt. For each, record a UTC timestamp or stable
sequence, action, exit code when available, concise error excerpt, root cause,
corrective action, verification result, final status (`resolved`, `deferred`, or
`blocked`), and an Actions link when applicable. If nothing failed, write
`None.` Do not commit enormous raw logs or secrets. If a complete local log is
genuinely needed, sanitize it and place it under
`docs/work-reports/logs/<task-name>/`.

Commit and push the report with the implementation. Do not claim completion
while required local tests or CI checks are failing. Update the report with the
final pull-request and CI state before handoff.

