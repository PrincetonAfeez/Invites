# vaultos-invites

One-time **invite codes** for **Vault OS**: generate, validate, use, revoke, list, and audit codes with a strict **state machine** (GENERATED → ACTIVE → EXHAUSTED / EXPIRED / REVOKED), JSON persistence, and a small **library API** (`InviteManager`, `InviteCode`).

## Requirements

- **Python 3.11+**
- **Runtime:** standard library only (no extra pip packages to use the library or CLI).

## Install

```bash
pip install .
```

Editable install (development):

```bash
pip install -e ".[dev]"
```

Or use the pinned dev list:

```bash
pip install -r requirements.txt
```

After install, the CLI is available as **`invites`** (see `[project.scripts]`). You can still run **`python -m invites`**.

## CLI

Default store file: **`invites_store.json`** in the current working directory (override with **`--store path`**).

| Command | Purpose |
|--------|---------|
| `generate` | Create a code; optional `--inactive`, `--expires-at` ISO time or `--expires-in-hours`, `--show-code` |
| `validate` | Check if a code is usable (exit `1` if not) |
| `use` | Consume one successful use |
| `revoke` | Revoke with `--reason` |
| `list` | List summaries (masked); optional `--state` |
| `audit` | Lifecycle + usage log for one code |

**Secrets:** by default, **`generate` does not print the full code** (only masked). Use **`--show-code`** to print the plaintext **once on stderr** (safer for shell redirects).

Examples:

```bash
invites --store ./my_store.json generate --creator-id warden --access-level 2 --max-uses 3 --expires-in-hours 48
invites --store ./my_store.json generate ... --show-code
invites validate ABC123FULLCODE
invites use ABC123FULLCODE
invites revoke ABC123FULLCODE --reason "Rotation"
invites list --state ACTIVE
invites audit ABC123FULLCODE
```

## Library

```python
from datetime import datetime, timedelta, timezone
from invites import InviteManager

m = InviteManager()
code = m.generate(
    "creator-1",
    required_access_level=2,
    max_use_count=1,
    expires_at=datetime.now(timezone.utc) + timedelta(days=1),
)
result = m.validate(code.code_string)
```

Load/save JSON (atomic writes, validated load):

```python
from invites.store import load_manager, save_manager

m = load_manager("invites_store.json")
save_manager(m, "invites_store.json")
```

Errors you may catch: `StoreError`, `InviteRecordError`, `InviteNotFoundError`, `InviteValidationError`, `InvalidStateTransitionError` (see `invites` package exports).

## Tests

```bash
pytest
# with coverage
pytest --cov=invites --cov-report=term-missing
```

The Invite Code System

App: One-Time Access Code Generator 

What it does: Build an InviteCode class with lifecycle: generated → sent → used → burned. Generate cryptographically random codes with configurable length and format. Validate codes against the registry. Each code has a max-use, an expiry date/time, a required access level, and a creator ID. A "burned" code can never be reused. Implement InviteManager with generate, validate, use, burn, and audit methods.


The README here focuses on **install and usage**; course specs live with your Vault OS materials.

## License

MIT (see `pyproject.toml`).
