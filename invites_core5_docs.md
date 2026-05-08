# Architecture Decision Record
## App 20 — Invites
**Vault OS Group | Document 1 of 5**
**Status: Accepted**

---

## Title
Adopt a strict invite-code state machine with masked CLI output and JSON-backed persistence.

## Date
2026-05-08

## Context

App 20, **Invites**, is the Vault OS one-time access code system. The application creates invite codes, validates whether they are usable, consumes successful uses, revokes unsafe codes, lists code summaries, audits lifecycle history, and persists state to disk.

The app has two intended usage modes:

1. **Library mode** through `InviteManager`, `InviteCode`, persistence helpers, and exported domain exceptions.
2. **CLI mode** through the installed `invites` console script or `python -m invites`.

The key architectural problem is that invite codes are both operational records and secrets. A usable code must be tracked accurately across time, use count, expiry, revocation, and persistence, while the CLI must avoid accidentally exposing raw code values in normal output.

## Decision Drivers

- Preserve a clear lifecycle for invite codes.
- Keep secret output safe by default.
- Use standard-library runtime dependencies only.
- Make state durable through a simple local store file.
- Keep the project small enough for the Vault OS Day 20 scope.
- Provide both programmatic and command-line interfaces.
- Make invalid storage data fail loudly instead of silently loading corrupted records.
- Keep tests focused on domain behavior, persistence, and CLI safety.

## Options Considered

### Option 1 — Simple dictionary of code strings to metadata

**Chosen / Rejected:** Rejected.

**Reason:** A raw dictionary would be quick to build, but lifecycle rules would be scattered across manager, CLI, and persistence code. That would make it easier for a code to be used after revocation, exhausted incorrectly, or saved in an inconsistent state.

### Option 2 — Database-backed invite registry

**Chosen / Rejected:** Rejected.

**Reason:** SQLite or another database could support stronger persistence and querying, but it would exceed the intended educational scope. The app only needs a local durable store and a small set of commands.

### Option 3 — `InviteCode` domain object with a state machine, managed by `InviteManager`

**Chosen / Rejected:** Chosen.

**Reason:** This keeps lifecycle rules close to the invite itself, while the manager handles lookup, generation, listing, validation delegation, and serialization boundaries. It also makes the state machine explicit and testable.

### Option 4 — Print plaintext invite codes by default

**Chosen / Rejected:** Rejected.

**Reason:** The code string is a secret. Printing full invite codes to normal stdout would make them easy to leak through shell history, redirected output, logs, screenshots, and copy/paste mistakes.

### Option 5 — Mask by default and print the full code only when explicitly requested

**Chosen / Rejected:** Chosen.

**Reason:** The CLI prints masked codes by default and only prints the full code when `--show-code` is supplied. When shown, the plaintext code is written to stderr rather than stdout, separating secret delivery from normal command output.

## Decision

The project implements invite codes as domain objects with a strict lifecycle state machine:

```text
GENERATED -> ACTIVE -> EXHAUSTED
GENERATED -> REVOKED
ACTIVE    -> EXPIRED
ACTIVE    -> REVOKED
```

`EXHAUSTED`, `EXPIRED`, and `REVOKED` are terminal states.

The application uses:

- `InviteCode` for state transitions, expiry refresh, usage logs, validation results, audit data, summaries, and record serialization.
- `InviteManager` for generation, lookup, validation, use, revoke, audit, list, and store-level serialization.
- `store.py` for JSON load/save and atomic writes.
- `cli.py` for command routing, persistence loading/saving, secret-safe output, and exit codes.
- `__main__.py` and `[project.scripts]` for executable entry points.

## Rationale

A state-machine design is appropriate because invite-code behavior is primarily about allowed and disallowed transitions. A generated code can become active or revoked. An active code can expire, be exhausted, or be revoked. Terminal states cannot be reversed. Encoding that directly in `InviteCode.TRANSITIONS` makes the business rule visible and central.

The manager layer gives the app a stable public API. It hides the internal dictionary of plaintext code strings and exposes intent-focused operations such as `generate()`, `validate()`, `use()`, `revoke()`, `audit()`, and `list_codes()`.

The CLI intentionally does not expose every internal method. It exposes the operational workflows a user would need: generate, validate, use, revoke, list, and audit. Activation is handled at generation time through default auto-activation or `--inactive`.

JSON persistence is sufficient for the app size. The store layer validates loaded records, wraps storage failures in `StoreError`, and writes atomically to reduce the chance of partially written files.

## Trade-offs Accepted

- The full plaintext code must be stored in JSON so the app can validate later CLI calls.
- The default JSON store is local and unencrypted.
- The app does not implement role-based caller enforcement during `validate` or `use`; `required_access_level` is stored as invite metadata for integration with future Vault OS layers.
- The CLI can generate inactive codes, but it does not expose a separate activation command.
- Code length and alphabet are internal defaults rather than exposed CLI options.
- Expiry is refreshed lazily when invite state, remaining uses, validation, usage, lifecycle, or serialization is accessed.

## Consequences

Positive consequences:

- Invite lifecycle behavior is explicit and easy to test.
- Code summaries and audit records can safely display masked identifiers.
- Storage failures and corrupt persisted records are not ignored.
- CLI behavior is predictable and scriptable.
- Runtime installation remains standard-library only.

Negative consequences:

- JSON persistence is not suitable for concurrent multi-process writes.
- The local store must be protected by file permissions because plaintext codes are persisted.
- Some future integration needs, such as caller access-level checks, activation workflows, and configurable code formats, will require extension.
- Since terminal states are irreversible, operational mistakes require generating a new code rather than repairing an old one.

## Superseded By

Not superseded.

---

# Technical Design Document
## App 20 — Invites
**Vault OS Group | Document 2 of 5**
**Status: Accepted**

---

## Purpose & Scope

The purpose of Invites is to provide a small one-time invite-code subsystem for Vault OS. It generates secure random codes, stores them, validates them, consumes them, revokes them, lists them safely, audits lifecycle history, and persists the manager state to JSON.

In scope:

- Invite-code creation.
- Secure random code generation.
- Invite state transitions.
- Lazy expiry handling.
- Usage counting.
- Revocation with reason.
- Validation without consumption.
- Use with consumption.
- Masked summaries.
- Full audit reports.
- JSON load/save.
- Atomic write behavior.
- CLI command routing.
- Programmatic library API.

Out of scope:

- Encrypted persistence.
- Database-backed storage.
- Network service mode.
- Authentication of CLI users.
- Enforcement of caller access level during `use`.
- Multiple stores or concurrent process coordination.
- Email or notification delivery of generated invites.

## System Context

```text
User / Script
    |
    v
invites CLI
    |
    v
load_manager(path) ---- JSON store file
    |
    v
InviteManager
    |
    v
InviteCode domain objects
    |
    v
save_manager(path) ---- atomic JSON write
```

The CLI loads the current manager from the store file, executes one command, saves the updated manager, and returns an exit code.

The library API allows other Python modules to instantiate `InviteManager` directly and call the same domain operations without going through the CLI.

## Component Breakdown

### `invites.models`

Defines the core domain model:

- `InviteState`
- `UsageOutcome`
- `InviteError`
- `InvalidStateTransitionError`
- `InviteValidationError`
- `InviteNotFoundError`
- `InviteRecordError`
- `UsageLogEntry`
- `AuditEvent`
- `ValidationResult`
- `InviteSummary`
- `InviteAudit`
- `InviteCode`
- `utc_now()`
- `normalize_datetime()`
- `mask_code()`

This module owns state transitions, validation, usage consumption, revocation, lifecycle logging, usage logging, summary rendering, audit construction, and record serialization.

### `invites.manager`

Defines `InviteManager` and `STORE_FORMAT_VERSION`.

The manager owns:

- In-memory mapping of plaintext code strings to `InviteCode` objects.
- Secure random code generation through `secrets.choice`.
- Public operations for generate, validate, use, revoke, audit, and list.
- Manager-level serialization and deserialization.
- Duplicate-code detection during store load.

### `invites.store`

Defines persistence helpers:

- `DEFAULT_STORE_PATH`
- `StoreError`
- `load_manager()`
- `save_manager()`
- `_atomic_write_text()`

The store layer handles JSON parsing, root-shape validation, domain record validation, parent-directory creation, temp-file writes, fsync, atomic replace, and temp-file cleanup.

### `invites.cli`

Defines the command-line interface:

- `build_parser()`
- `main()`
- `_dispatch()`
- `_resolve_expiry()`
- `_format_datetime()`

It supports commands:

- `generate`
- `validate`
- `use`
- `revoke`
- `list`
- `audit`

### `invites.__init__`

Exports the public package API, including manager, models, domain errors, summaries, audit structures, validation structures, usage structures, and `StoreError`.

### `invites.__main__`

Runs `main()` and exits through `SystemExit`, enabling:

```bash
python -m invites
```

## Module Dependency Graph

```text
invites.__main__
    -> invites.cli

invites.cli
    -> argparse
    -> sys
    -> datetime
    -> pathlib.Path
    -> invites.manager.InviteManager
    -> invites.models.InviteError, InviteState, normalize_datetime
    -> invites.store.DEFAULT_STORE_PATH, StoreError, load_manager, save_manager

invites.store
    -> json
    -> os
    -> tempfile
    -> pathlib.Path
    -> invites.manager.InviteManager
    -> invites.models.InviteRecordError

invites.manager
    -> secrets
    -> string
    -> datetime
    -> invites.models

invites.models
    -> dataclasses
    -> datetime
    -> enum
    -> typing
```

## Core Algorithms & Logic

### Secure code generation

`InviteManager._generate_unique_code()` creates 12-character invite strings from uppercase ASCII letters and digits:

```text
alphabet = A-Z + 0-9
code = secrets.choice(alphabet) repeated 12 times
```

It tries up to 10 times to avoid collisions with existing codes. If it cannot find a unique code, it raises `RuntimeError`.

### State-machine transition enforcement

`InviteCode.TRANSITIONS` defines allowed transitions:

```python
GENERATED -> ACTIVE, REVOKED
ACTIVE    -> EXHAUSTED, EXPIRED, REVOKED
EXHAUSTED -> none
EXPIRED   -> none
REVOKED   -> none
```

All transitions go through `_transition()`. If a requested state is not allowed from the current state, the app raises `InvalidStateTransitionError`.

### Lazy expiry

`InviteCode._refresh_expiry()` checks whether an active invite has reached or passed `expires_at`. If so, it transitions the invite to `EXPIRED` and appends a lifecycle event.

Expiry is refreshed by:

- `state`
- `remaining_uses`
- `lifecycle`
- `validate()`
- `use()`
- `revoke()` before attempting transition
- `to_summary()`
- `to_audit()`
- `to_record()`

### Validation without consumption

`InviteCode.validate()` returns a `ValidationResult` with:

- `usable`
- `reason`
- `state`
- `masked_code`
- `remaining_uses`
- `required_access_level`
- `expires_at`

It does not decrement remaining uses.

### Usage with consumption

`InviteCode.use()` refreshes expiry, checks state, logs failed attempts when unusable, decrements remaining uses on success, appends usage and lifecycle entries, and transitions to `EXHAUSTED` when remaining uses reaches zero.

### Revocation

`InviteCode.revoke()` requires a non-blank reason. It refreshes expiry, then attempts a transition to `REVOKED`. If the code is already exhausted, expired, or revoked, the transition is rejected.

### Serialization

`InviteCode.to_record()` produces JSON-compatible data containing code string, creator ID, access level, max uses, expiration timestamp, state, remaining uses, revocation reason, usage log, and lifecycle.

`InviteCode.from_record()` validates record shape and reconstructs usage and lifecycle objects.

### Store loading

`load_manager()` returns an empty manager when the store file does not exist or is blank. It raises `StoreError` when JSON is malformed, the root is not an object, or domain validation fails.

### Atomic store saving

`save_manager()` serializes manager state and writes it using `_atomic_write_text()`:

1. Create parent directories.
2. Create a temp file in the destination directory.
3. Write UTF-8 JSON.
4. Flush and fsync.
5. Atomically replace the target file.
6. Clean up leftover temp files on failure.

## Data Structures

### `InviteCode`

Mutable domain object with:

- `code_string`
- `creator_id`
- `required_access_level`
- `max_use_count`
- `expires_at`
- private state
- private remaining uses
- private revocation reason
- usage log list
- lifecycle list

### `InviteManager`

In-memory dictionary:

```python
dict[str, InviteCode]
```

The key is the plaintext invite code string. This supports O(1) lookup for validation, use, revoke, and audit.

### `UsageLogEntry`

Frozen dataclass recording:

- timestamp
- usage outcome
- detail

### `AuditEvent`

Frozen dataclass recording:

- timestamp
- event name
- detail

### `ValidationResult`

Frozen dataclass used for non-mutating validation responses.

### `InviteSummary`

Frozen dataclass used for list views. It contains masked code data, not raw secrets.

### `InviteAudit`

Frozen dataclass used for full lifecycle and usage reports.

## State Management

Application state lives in `InviteManager._codes` during command execution and in a JSON store between runs.

CLI flow:

```text
parse args
load manager
execute command
save manager
return exit code
```

Domain state lives inside each `InviteCode`. Users cannot set state directly through the public manager API. State changes are caused by:

- generation with auto-activation
- validation/access after expiry
- successful use count exhaustion
- revocation

## Error Handling Strategy

Domain errors are explicit:

- `InviteError` is the base class.
- `InvalidStateTransitionError` covers illegal lifecycle transitions.
- `InviteValidationError` covers unusable invite attempts.
- `InviteNotFoundError` covers missing code lookups for use/revoke/audit.
- `InviteRecordError` covers invalid persisted invite data.
- `StoreError` covers storage-level read/write/load problems.

CLI behavior:

- Store load failure prints `Error: ...` and returns `1`.
- Domain or value failures print `Error: ...`, save current manager state, and return `1`.
- `validate` returns `0` only when a code is usable; otherwise it returns `1`.
- Successful commands return `0`.
- Parser-level usage failures follow argparse behavior.

## External Dependencies

Runtime dependencies:

- Python standard library only.

Development dependencies:

- `pytest>=8.0`
- `hypothesis>=6.100`
- `pytest-cov>=5.0`

The package metadata requires Python `>=3.11`.

## Concurrency Model

The app is synchronous and single-process.

There is no threading, async IO, locking, or multi-process coordination. Atomic writes reduce partial-file corruption, but they do not provide a full concurrency-control model for simultaneous writers.

## Known Limitations

- Store file contains plaintext invite codes.
- No encryption or hashing of persisted code strings.
- No concurrent write protection beyond atomic replacement.
- No separate CLI command to activate an inactive code.
- Code length and alphabet are not CLI-configurable.
- `required_access_level` is stored but not enforced against an actor identity during validation/use.
- `expires_at` parsing has limited timezone UX and no custom date-format validation message beyond Python parsing errors.
- Store format has versioning but no migration system beyond rejecting unsupported versions.
- The app has no networking, user accounts, or notification delivery.

## Design Patterns Used

- **State machine** for invite lifecycle transitions.
- **Manager pattern** for central coordination of domain objects.
- **Repository/persistence helper pattern** for JSON load/save.
- **Data transfer objects** through frozen dataclasses such as `ValidationResult`, `InviteSummary`, and `InviteAudit`.
- **Command dispatcher** in `_dispatch()` for CLI subcommands.
- **Fail-fast validation** for invalid records and illegal transitions.
- **Secret masking** for safe display of sensitive identifiers.

---

# Interface Design Specification
## App 20 — Invites
**Vault OS Group | Document 3 of 5**
**Status: Accepted**

---

## Invocation Syntax

Installed console script:

```bash
invites [--store PATH] COMMAND [COMMAND_OPTIONS]
```

Module entry point:

```bash
python -m invites [--store PATH] COMMAND [COMMAND_OPTIONS]
```

Development entry point:

```bash
python -m invites --store invites_store.json generate --creator-id warden --access-level 2 --max-uses 1 --expires-in-hours 24
```

## Argument Reference Table

### Global Arguments

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `--store` | path | Optional | `invites_store.json` | Any writable/readable filesystem path | JSON store file used by the CLI. |
| `command` | string | Required | None | `generate`, `validate`, `use`, `revoke`, `list`, `audit` | Operation to execute. |

### `generate`

```bash
invites generate --creator-id ID --access-level N --max-uses N (--expires-at ISO | --expires-in-hours HOURS) [--inactive] [--show-code]
```

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `--creator-id` | string | Required | None | Non-empty string | User or system creating the invite. |
| `--access-level` | int | Required | None | Integer `>= 0` | Required access level stored with the code. |
| `--max-uses` | int | Required | None | Integer `>= 1` | Maximum successful uses before exhaustion. |
| `--expires-at` | ISO datetime string | Mutually exclusive with `--expires-in-hours` | None | `datetime.fromisoformat()` compatible string | Absolute expiration timestamp. |
| `--expires-in-hours` | float | Mutually exclusive with `--expires-at` | None | Number `> 0` | Relative expiration offset from current time. |
| `--inactive` | flag | Optional | False | Present / absent | Leave code in `GENERATED` instead of auto-activating. |
| `--show-code` | flag | Optional | False | Present / absent | Print full code once to stderr. |

### `validate`

```bash
invites validate CODE
```

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `code` | string | Required | None | Full invite code string | Checks whether the code is currently usable without consuming a use. |

### `use`

```bash
invites use CODE
```

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `code` | string | Required | None | Full invite code string | Consumes one successful use if the code is active, unexpired, and not exhausted/revoked. |

### `revoke`

```bash
invites revoke CODE --reason TEXT
```

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `code` | string | Required | None | Full invite code string | Invite code to revoke. |
| `--reason` | string | Required | None | Non-empty string | Reason stored in the lifecycle audit. |

### `list`

```bash
invites list [--state STATE]
```

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `--state` | enum string | Optional | None | `GENERATED`, `ACTIVE`, `EXHAUSTED`, `EXPIRED`, `REVOKED` | Filters summaries by lifecycle state. |

### `audit`

```bash
invites audit CODE
```

| Name | Type | Required | Default | Valid Values | Description |
|---|---:|---:|---|---|---|
| `code` | string | Required | None | Full invite code string | Shows lifecycle and usage log for one invite. |

## Input Contract

### Code strings

- Must match a stored plaintext code to be usable.
- Unknown codes validate as not found.
- Unknown codes passed to `use`, `revoke`, or `audit` produce an error.

### Creator ID

- Must be non-empty after stripping whitespace.

### Access level

- Must be an integer greater than or equal to 0.

### Max uses

- Must be an integer greater than or equal to 1.

### Expiry

- `--expires-at` must be parseable by `datetime.fromisoformat()`.
- `--expires-in-hours` must be greater than 0.
- Generated invites store expiration timestamps normalized to UTC.

### Revocation reason

- Must be non-empty after stripping whitespace.

### Store file

- Missing store file means an empty manager is created.
- Blank store file means an empty manager is created.
- Malformed JSON fails with `StoreError`.
- Valid JSON with invalid invite records fails validation.

## Output Contract

### `generate`

Writes to stdout:

```text
Generated invite (masked): ********ABCD
Full code is not printed. Re-run with --show-code to print it once to stderr.
State: ACTIVE
Creator ID: warden
Required access level: 2
Remaining uses: 1/1
Expires at: 2026-05-09T12:00:00+00:00
```

When `--show-code` is present, the full code is printed to stderr once.

### `validate`

Writes to stdout:

```text
Code: ********ABCD
Usable: yes
State: ACTIVE
Remaining uses: 1
Expires at: 2026-05-09T12:00:00+00:00
```

For invalid codes, it also prints a reason.

### `use`

Writes to stdout:

```text
Invite ********ABCD used successfully.
State: EXHAUSTED
Remaining uses: 0
```

### `revoke`

Writes to stdout:

```text
Invite ********ABCD revoked.
Reason: Rotation
State: REVOKED
```

### `list`

Writes masked summaries only:

```text
Code: ********ABCD
  Creator ID: warden
  Access level: 2
  State: ACTIVE
  Remaining uses: 1/1
  Expires at: 2026-05-09T12:00:00+00:00
```

### `audit`

Writes full masked metadata, lifecycle events, and usage log entries:

```text
Invite: ********ABCD
Creator ID: warden
State: ACTIVE
Access level: 2
Remaining uses: 1/1
Expires at: 2026-05-09T12:00:00+00:00
Lifecycle:
  - 2026-05-08T12:00:00+00:00 | created | Invite code generated.
  - 2026-05-08T12:00:00+00:00 | activated | GENERATED -> ACTIVE. Invite code activated and ready for use.
Usage log:
  - No use attempts recorded.
```

## Exit Code Reference

| Code | Meaning |
|---:|---|
| `0` | Command succeeded. For `validate`, the code is usable. |
| `1` | Store error, domain error, value error, failed validation, unusable code, missing code, or invalid operation. |
| `2` | argparse usage error, such as missing required command arguments. |

## Error Output Behavior

Most runtime and domain errors print:

```text
Error: <message>
```

Parser errors follow argparse behavior and may include usage text.

`--show-code` intentionally prints the plaintext secret to stderr, not stdout.

## Environment Variables

None.

## Configuration Files

None.

The JSON store file acts as persisted application state, not a configuration file.

Default store path:

```text
invites_store.json
```

## Side Effects

- Reads from the JSON store path.
- Creates the JSON store if needed.
- Creates parent directories for the store path if needed.
- Writes invite records to disk after commands.
- May create and atomically replace a temporary file during save.
- Prints full invite codes to stderr only when `--show-code` is used.
- Mutates invite lifecycle and usage logs during validation, use, revoke, list, audit, and serialization when lazy expiry is triggered.

## Usage Examples

### Basic: generate an active code

```bash
invites --store ./invites_store.json generate \
  --creator-id warden \
  --access-level 2 \
  --max-uses 1 \
  --expires-in-hours 24
```

### Advanced: generate and reveal the full code once

```bash
invites --store ./invites_store.json generate \
  --creator-id warden \
  --access-level 4 \
  --max-uses 3 \
  --expires-at 2026-05-09T12:00:00+00:00 \
  --show-code
```

### Edge case: generate an inactive code

```bash
invites --store ./invites_store.json generate \
  --creator-id warden \
  --access-level 1 \
  --max-uses 1 \
  --expires-in-hours 2 \
  --inactive
```

The generated code remains in `GENERATED` and will validate as not active.

### Intentional failure: validate a missing code

```bash
invites --store ./invites_store.json validate NOTAREALCODE
```

Expected result:

```text
Code: ********CODE
Usable: no
State: NOT_FOUND
Reason: not found
```

Exit code: `1`.

---

# Runbook
## App 20 — Invites
**Vault OS Group | Document 4 of 5**
**Status: Accepted**

---

## Prerequisites

- Python 3.11 or newer.
- A shell environment with access to the project directory.
- Write permission for the chosen JSON store path.
- Optional development tools installed through the `dev` extra or `requirements.txt`.

## Installation Procedure

### Development install

```bash
python -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows
pip install -e ".[dev]"
```

### Requirements-based install

```bash
pip install -r requirements.txt
```

### Production-style install

```bash
pip install .
```

## Configuration Steps

No configuration file is required.

Choose a store file path before running commands:

```bash
invites --store ./invites_store.json list
```

Without `--store`, the CLI uses:

```text
invites_store.json
```

in the current working directory.

## Standard Operating Procedures

### Generate a code

```bash
invites --store ./invites_store.json generate \
  --creator-id warden \
  --access-level 2 \
  --max-uses 1 \
  --expires-in-hours 24
```

### Generate a code and show plaintext once

```bash
invites --store ./invites_store.json generate \
  --creator-id warden \
  --access-level 2 \
  --max-uses 1 \
  --expires-in-hours 24 \
  --show-code
```

Copy the full code from stderr and store it securely.

### Validate a code

```bash
invites --store ./invites_store.json validate FULLCODEHERE
```

### Use a code

```bash
invites --store ./invites_store.json use FULLCODEHERE
```

### Revoke a code

```bash
invites --store ./invites_store.json revoke FULLCODEHERE --reason "Security rotation"
```

### List active codes

```bash
invites --store ./invites_store.json list --state ACTIVE
```

### Audit a code

```bash
invites --store ./invites_store.json audit FULLCODEHERE
```

## Health Checks

### Check package import

```bash
python - <<'PY'
from invites import InviteManager
print(InviteManager)
PY
```

### Check CLI parser

```bash
python -m invites --help
```

### Check default store behavior

```bash
invites --store ./healthcheck_store.json list
```

Expected if empty:

```text
No invite codes found.
```

### Run tests

```bash
pytest
```

### Run tests with coverage

```bash
pytest --cov=invites --cov-report=term-missing
```

## Expected Output Samples

### Empty list

```text
No invite codes found.
```

### Successful masked generation

```text
Generated invite (masked): ********ABCD
Full code is not printed. Re-run with --show-code to print it once to stderr.
State: ACTIVE
Creator ID: warden
Required access level: 2
Remaining uses: 1/1
Expires at: 2026-05-09T12:00:00+00:00
```

### Successful validation

```text
Code: ********ABCD
Usable: yes
State: ACTIVE
Remaining uses: 1
Expires at: 2026-05-09T12:00:00+00:00
```

### Failed validation

```text
Code: ********ABCD
Usable: no
State: EXPIRED
Reason: expired
Remaining uses: 1
Expires at: 2026-05-09T12:00:00+00:00
```

## Known Failure Modes

### Store file is malformed JSON

Symptom:

```text
Error: Invite store is not valid JSON (...)
```

Cause:

The store file exists but cannot be parsed as JSON.

Recovery:

Restore the file from backup or inspect and repair the JSON manually.

### Store file has invalid records

Symptom:

```text
Error: Invite store failed validation (...)
```

Cause:

The JSON is syntactically valid but violates invite record rules.

Recovery:

Repair invalid fields or remove the broken record after making a backup.

### Code not found

Symptom:

```text
Error: Invite code ********ABCD was not found.
```

Cause:

The provided plaintext code does not exist in the current store file.

Recovery:

Confirm the correct `--store` path and full code string.

### Code is not active

Symptom:

```text
Usable: no
Reason: not active
```

Cause:

The invite was generated with `--inactive` or has not been activated through library code.

Recovery:

Generate a new active invite or activate through library-level workflow if appropriate.

### Code is exhausted

Symptom:

```text
Reason: exhausted
```

Cause:

Successful uses reached `max_use_count`.

Recovery:

Generate a new invite.

### Code is expired

Symptom:

```text
Reason: expired
```

Cause:

Current time is at or after `expires_at`.

Recovery:

Generate a new invite with a future expiration.

### Code is revoked

Symptom:

```text
Reason: revoked
```

Cause:

An operator revoked the invite.

Recovery:

Generate a new invite if access should still be granted.

## Troubleshooting Decision Tree

```text
Command failed?
├── Did argparse print usage text?
│   └── Check command syntax and required arguments.
├── Did it print StoreError?
│   ├── Store missing or blank? Expected: empty manager.
│   ├── Store malformed JSON? Repair or restore backup.
│   └── Store failed validation? Inspect invite records.
├── Did validation return exit 1?
│   ├── State NOT_FOUND? Confirm full code and store path.
│   ├── Reason not active? Code is still GENERATED.
│   ├── Reason expired? Generate a new code.
│   ├── Reason exhausted? Generate a new code.
│   └── Reason revoked? Generate a replacement if appropriate.
├── Did use fail?
│   └── Audit the code to inspect lifecycle and usage log.
└── Did plaintext code not appear?
    └── Use --show-code and check stderr, not stdout.
```

## Dependency Failure Handling

Runtime uses only the Python standard library. Most dependency issues are installation or Python-version problems.

### Python version too old

Symptom:

Install or runtime syntax/import errors.

Recovery:

Use Python 3.11 or newer.

### Missing test dependencies

Symptom:

```text
pytest: command not found
```

Recovery:

```bash
pip install -e ".[dev]"
```

or:

```bash
pip install -r requirements.txt
```

## Recovery Procedures

### Recover from accidental revocation

Revocation is terminal. Generate a new code.

### Recover from exhaustion

Exhaustion is terminal. Generate a new code.

### Recover from expiration

Expiration is terminal. Generate a new code.

### Recover from corrupted store

1. Stop using the damaged store.
2. Copy it for forensic inspection.
3. Restore the last known-good store file.
4. Run `invites --store restored.json list`.
5. Reissue any missing codes.

### Recover from wrong store path

Run list against both likely store files:

```bash
invites --store ./invites_store.json list
invites --store ./other_store.json list
```

Use the store containing the expected masked code.

## Logging Reference

The app does not use a logging framework.

Operational history is stored as domain data:

- `AuditEvent` records lifecycle changes.
- `UsageLogEntry` records successful and failed use attempts.
- `audit` prints both lifecycle and usage records.

## Maintenance Notes

- Protect the JSON store with file permissions because it contains plaintext codes.
- Prefer `--show-code` only when the recipient is ready to copy the value securely.
- Avoid redirecting stderr during `--show-code` unless intentional.
- Back up store files before manual edits.
- Treat terminal states as immutable history, not states to repair.
- Add tests before changing state transitions or persistence validation rules.

---

# Lessons Learned
## App 20 — Invites
**Vault OS Group | Document 5 of 5**
**Status: Accepted**

---

## Project Summary

Invites implements a one-time invite-code manager for Vault OS. It generates secure random code strings, tracks lifecycle state, validates codes, consumes uses, records failed usage attempts, revokes codes, lists masked summaries, audits lifecycle history, and persists the manager state to a JSON file.

The project is larger than a simple CLI exercise because it separates domain state, manager operations, persistence, and command-line behavior. It also handles a security-sensitive concern: avoiding accidental plaintext secret exposure.

## Original Goals vs. Actual Outcome

### Original goals

- Build invite-code generation.
- Track generated, sent/active, used, burned/exhausted, expired, and revoked states.
- Validate codes against a registry.
- Support max uses and expiry.
- Record an audit trail.
- Provide a CLI and library API.

### Actual outcome

The implementation successfully provides a strict state machine, secure random generation, masked summaries, full audit objects, usage logs, JSON persistence, atomic saves, CLI commands, and package exports.

The main deviation is that the CLI does not expose configurable code length/format or a standalone activation command. The domain model supports activation, but CLI operations focus on generate-time activation through default behavior or `--inactive`.

## Technical Decisions That Paid Off

### Explicit state machine

The `TRANSITIONS` map made lifecycle behavior much easier to reason about. Instead of checking dozens of ad hoc conditions, the app centralizes allowed movement from one state to another.

### Masked output by default

Masking invite codes in summaries and CLI output was the right default. It makes the safe behavior the normal behavior and requires intentional action to reveal the secret.

### Full code on stderr only when requested

Printing plaintext codes to stderr with `--show-code` separates secret delivery from normal stdout output. This is useful when stdout is redirected to logs or parsed by scripts.

### Domain-specific errors

Errors such as `InviteValidationError`, `InviteNotFoundError`, `InviteRecordError`, and `InvalidStateTransitionError` make failures easier to interpret and test.

### JSON validation on load

The store loader does not blindly trust saved files. It checks root shape, version, duplicate codes, required keys, enum values, counters, lifecycle/usage list shapes, and logical consistency.

### Atomic writes

Using temp-file write, flush, fsync, and replace is a strong practice for a local JSON store. It reduces the chance of ending up with half-written JSON after interruption.

## Technical Decisions That Created Debt

### Plaintext code storage

The app needs plaintext codes for lookup, but storing them directly in JSON is a security trade-off. A production version would likely store a hash and compare submitted codes through constant-time verification.

### No actor model for `use`

`required_access_level` is stored, but the app does not accept a caller identity or caller access level during validation/use. This means it cannot yet enforce whether a user is allowed to redeem a given invite.

### No activation command

The domain object supports `activate()`, and `generate` supports `--inactive`, but the CLI does not expose `activate`. That makes inactive CLI-generated codes difficult to use without writing Python code.

### Store writes after command errors

The CLI saves after domain/value errors so partial side effects, such as failed usage logs, are preserved. That is honest audit behavior, but it means users must understand that some failures intentionally mutate the store.

### Limited store concurrency

Atomic writes protect against partial files, but not against two processes writing competing versions of the store.

## What Was Harder Than Expected

The hardest part was not generating a random string. The harder part was controlling the lifecycle around that string:

- When should expiry be checked?
- Should failed use attempts be logged?
- Which states are terminal?
- Should an exhausted code be revocable later?
- How should the CLI handle secrets?
- What should happen if persisted JSON is internally inconsistent?

The state machine clarified these questions, but only after the domain rules were made explicit.

## What Was Easier Than Expected

The CLI was straightforward once the manager API was clear. Each subcommand maps naturally onto one domain operation:

- `generate` -> `manager.generate()`
- `validate` -> `manager.validate()`
- `use` -> `manager.use()`
- `revoke` -> `manager.revoke()`
- `list` -> `manager.list_codes()`
- `audit` -> `manager.audit()`

The persistence layer was also manageable because every domain object already knew how to serialize itself into records.

## Python-Specific Learnings

- `secrets.choice()` is the right tool for security-sensitive random tokens.
- `datetime` values should be normalized consistently before storage and comparison.
- `Enum` classes make lifecycle values safer than raw strings.
- Frozen dataclasses are useful for read-only result objects and audit entries.
- `argparse` subcommands provide a clean CLI structure for multi-operation tools.
- `tempfile.mkstemp()`, `os.fsync()`, and `os.replace()` are useful for safer local file writes.
- Returning structured result objects is cleaner than returning loose tuples or dictionaries.

## Architecture Insights

The biggest architecture insight is that secrets need different interface rules than normal records. The app can store and act on full codes internally, but most outputs should use masked codes. That separation is an interface-design decision, not just a formatting detail.

Another important insight is that validation is not always read-only. In this app, validation may cause lazy expiry, which mutates lifecycle state. That is acceptable, but it must be documented because users may not expect a status check to alter the store.

The manager/domain split also worked well. `InviteCode` owns the lifecycle of one code. `InviteManager` owns the collection and lookup behavior. `store.py` owns durability. `cli.py` owns user interaction and exit codes.

## Testing Gaps

Current tests cover many important behaviors:

- auto-activation
- masked summaries
- lazy expiry
- exhaustion
- failed use logging
- revocation
- illegal transition errors
- JSON store round-trip
- corrupt JSON rejection
- duplicate code rejection
- inconsistent active record rejection
- atomic save temp cleanup
- CLI masking by default
- CLI plaintext-to-stderr behavior with `--show-code`

Remaining useful tests would include:

- CLI `validate`, `use`, `revoke`, `list`, and `audit` flows end to end.
- `--inactive` generation behavior through the CLI.
- `--expires-at` parsing with timezone-aware and naive inputs.
- unsupported store version rejection.
- invalid revocation reason through CLI.
- invalid max uses and access level through CLI.
- collision behavior in `_generate_unique_code()` with patched `secrets.choice`.
- validation of malformed nested lifecycle and usage records.

## Reusable Patterns Identified

- State-machine dictionary for lifecycle-heavy objects.
- Masked identifier display for secret-bearing records.
- Manager object wrapping a dictionary of domain objects.
- JSON persistence with explicit record validation.
- Atomic write helper for local CLI data stores.
- CLI command dispatch through subcommands.
- Frozen dataclass result objects for validation, summary, and audit responses.
- Domain exception hierarchy for clear API boundaries.

## If I Built This Again

I would keep the state machine, manager layer, JSON persistence boundary, and secret masking behavior.

I would consider adding:

- hashed code storage instead of plaintext storage.
- an activation CLI command.
- configurable code length and alphabet.
- caller access-level validation during `use`.
- a store-locking strategy for concurrent CLI usage.
- richer CLI tests for every subcommand.
- explicit migration support for future store format versions.
- a `--json` output mode for scripting.

## Open Questions

- Should inactive invites be useful from the CLI without a separate activation command?
- Should `required_access_level` be enforced in this app or deferred to Vault OS integration?
- Should plaintext codes ever be persisted, or should the app move to hashing?
- Should validation be allowed to mutate state through lazy expiry?
- Should revocation be allowed after expiration or exhaustion for administrative labeling, or should terminal-state immutability remain strict?
- Should the CLI offer JSON output for integration with other Vault OS apps?
- Should store writes use file locks if multiple operators may run commands at once?
