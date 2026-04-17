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

class InviteState(str, Enum):
    GENERATED = "GENERATED"
    ACTIVE = "ACTIVE"
    EXHAUSTED = "EXHAUSTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class UsageOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    NOT_ACTIVE = "NOT_ACTIVE"
    EXHAUSTED = "EXHAUSTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class InviteError(Exception):
    """Base exception for invite-code errors."""


class InvalidStateTransitionError(InviteError):
    """Raised when a state transition is not allowed."""


class InviteValidationError(InviteError):
    """Raised when an invite code cannot be used."""


class InviteNotFoundError(InviteError):
    """Raised when an invite code cannot be found."""


class InviteRecordError(InviteError):
    """Raised when persisted invite data fails validation."""

@dataclass(frozen=True)
class UsageLogEntry:
    timestamp: datetime
    outcome: UsageOutcome
    detail: str

    def to_record(self) -> dict[str, str]:
        return {
            "timestamp": normalize_datetime(self.timestamp).isoformat(),
            "outcome": self.outcome.value,
            "detail": self.detail,
        }

    @classmethod
    def from_record(cls, record: dict[str, str]) -> "UsageLogEntry":
        return cls(
            timestamp=datetime.fromisoformat(record["timestamp"]),
            outcome=UsageOutcome(record["outcome"]),
            detail=record["detail"],
        )

