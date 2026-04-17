# Schema folder

This folder contains simple JSON Schema files for the `Invites` repository.

## Files
- `store.schema.json` — top-level `invites_store.json` file
- `invite.schema.json` — one persisted invite record
- `usage-log-entry.schema.json` — one usage log item
- `audit-event.schema.json` — one lifecycle/audit event
- `validation-result.schema.json` — output shape for `validate()`
- `invite-summary.schema.json` — output shape for `list_codes()`
- `invite-audit.schema.json` — output shape for `audit()`

## Notes
- These schemas were written to match the current Python models and store format in the repo.
- The store version is fixed to `1`.
- JSON Schema can enforce most of the structure, enums, and required fields.
- A few business rules from Python are still runtime rules, such as:
  - `GENERATED` invites should keep `remaining_uses == max_use_count`
  - `ACTIVE` invites should have `remaining_uses >= 1`
  - duplicate `code_string` values are rejected by `InviteManager.from_record()`

## Suggested repo placement
Put this folder at the repo root as:

```text
Schema/
  README.md
  store.schema.json
  invite.schema.json
  usage-log-entry.schema.json
  audit-event.schema.json
  validation-result.schema.json
  invite-summary.schema.json
  invite-audit.schema.json
```
