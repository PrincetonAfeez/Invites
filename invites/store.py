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

def save_manager(manager: InviteManager, path: str | Path = DEFAULT_STORE_PATH) -> None:
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(manager.to_record(), indent=2) + "\n"
    _atomic_write_text(file_path, serialized)

def _atomic_write_text(file_path: Path, text: str) -> None:
    directory = file_path.parent
    fd: int | None = None
    tmp_path: Path | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=directory,
            prefix=f".{file_path.name}.",
            suffix=".tmp",
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, file_path)
        tmp_path = None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
