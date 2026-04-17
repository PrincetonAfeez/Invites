from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar


def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def mask_code(code_string: str) -> str:
    if len(code_string) <= 4:
        return code_string
    return f"{'*' * (len(code_string) - 4)}{code_string[-4:]}"
