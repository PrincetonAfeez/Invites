from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .manager import InviteManager
from .models import InviteRecordError


DEFAULT_STORE_PATH = Path("invites_store.json")

class StoreError(Exception):
    """Raised when the invite store file cannot be read or written safely."""

def load_manager(path: str | Path = DEFAULT_STORE_PATH) -> InviteManager:
    file_path = Path(path)
    if not file_path.exists():
        return InviteManager()

    raw_text = file_path.read_text(encoding="utf-8")
    if not raw_text.strip():
        return InviteManager()

    try:
        payload: Any = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise StoreError(f"Invite store is not valid JSON ({file_path}): {exc}") from exc

    if not isinstance(payload, dict):
        raise StoreError(f"Invite store root must be a JSON object ({file_path}).")

    try:
        return InviteManager.from_record(payload)
    except InviteRecordError as exc:
        raise StoreError(f"Invite store failed validation ({file_path}): {exc}") from exc

