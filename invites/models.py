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

@dataclass(frozen=True)
class AuditEvent:
    timestamp: datetime
    event: str
    detail: str

    def to_record(self) -> dict[str, str]:
        return {
            "timestamp": normalize_datetime(self.timestamp).isoformat(),
            "event": self.event,
            "detail": self.detail,
        }

    @classmethod
    def from_record(cls, record: dict[str, str]) -> "AuditEvent":
        return cls(
            timestamp=datetime.fromisoformat(record["timestamp"]),
            event=record["event"],
            detail=record["detail"],
        )

@dataclass(frozen=True)
class ValidationResult:
    usable: bool
    reason: str | None
    state: InviteState | None
    masked_code: str
    remaining_uses: int | None
    required_access_level: int | None
    expires_at: datetime | None

@dataclass(frozen=True)
class InviteSummary:
    masked_code: str
    creator_id: str
    required_access_level: int
    state: InviteState
    remaining_uses: int
    max_use_count: int
    expires_at: datetime
    revoked_reason: str | None

@dataclass(frozen=True)
class InviteAudit:
    masked_code: str
    creator_id: str
    required_access_level: int
    state: InviteState
    remaining_uses: int
    max_use_count: int
    expires_at: datetime
    revoked_reason: str | None
    usage_log: tuple[UsageLogEntry, ...]
    lifecycle: tuple[AuditEvent, ...]

class InviteCode:
    TRANSITIONS: ClassVar[dict[InviteState, set[InviteState]]] = {
        InviteState.GENERATED: {InviteState.ACTIVE, InviteState.REVOKED},
        InviteState.ACTIVE: {
            InviteState.EXHAUSTED,
            InviteState.EXPIRED,
            InviteState.REVOKED,
        },
        InviteState.EXHAUSTED: set(),
        InviteState.EXPIRED: set(),
        InviteState.REVOKED: set(),
    }

    EVENT_NAMES: ClassVar[dict[InviteState, str]] = {
        InviteState.ACTIVE: "activated",
        InviteState.EXHAUSTED: "exhausted",
        InviteState.EXPIRED: "expired",
        InviteState.REVOKED: "revoked",
    }
    
    def __init__(
        self,
        code_string: str,
        creator_id: str,
        required_access_level: int,
        max_use_count: int,
        expires_at: datetime,
        *,
        created_at: datetime | None = None,
        state: InviteState = InviteState.GENERATED,
        remaining_uses: int | None = None,
        usage_log: list[UsageLogEntry] | None = None,
        lifecycle: list[AuditEvent] | None = None,
        revoked_reason: str | None = None,
    ) -> None:
        if max_use_count < 1:
            raise ValueError("max_use_count must be at least 1.")
        if required_access_level < 0:
            raise ValueError("required_access_level must be 0 or greater.")
        if not creator_id.strip():
            raise ValueError("creator_id cannot be empty.")
        if not code_string.strip():
            raise ValueError("code_string cannot be empty.")

        self.code_string = code_string
        self.creator_id = creator_id.strip()
        self.required_access_level = required_access_level
        self.max_use_count = max_use_count
        self.expires_at = normalize_datetime(expires_at)
        self.__state = state
        self.__remaining_uses = max_use_count if remaining_uses is None else remaining_uses
        self.__revoked_reason = revoked_reason
        self._usage_log = list(usage_log or [])
        self._lifecycle = list(lifecycle or [])

        if not self._lifecycle:
            timestamp = normalize_datetime(created_at or utc_now())
            self._lifecycle.append(
                AuditEvent(timestamp=timestamp, event="created", detail="Invite code generated.")
            )

    @property
    def masked_code(self) -> str:
        return mask_code(self.code_string)

    @property
    def state(self) -> InviteState:
        self._refresh_expiry()
        return self.__state

    @property
    def remaining_uses(self) -> int:
        self._refresh_expiry()
        return self.__remaining_uses

    @property
    def revoked_reason(self) -> str | None:
        return self.__revoked_reason

    @property
    def usage_log(self) -> tuple[UsageLogEntry, ...]:
        return tuple(self._usage_log)

    @property
    def lifecycle(self) -> tuple[AuditEvent, ...]:
        self._refresh_expiry()
        return tuple(self._lifecycle)

    def activate(self, at: datetime | None = None) -> None:
        timestamp = normalize_datetime(at or utc_now())
        self._transition(InviteState.ACTIVE, timestamp, "Invite code activated and ready for use.")
        self._refresh_expiry(timestamp)

    def validate(self, at: datetime | None = None) -> ValidationResult:
        timestamp = normalize_datetime(at or utc_now())
        self._refresh_expiry(timestamp)
        state = self.__state

        if state is InviteState.ACTIVE and self.__remaining_uses > 0:
            reason = None
            usable = True
        elif state is InviteState.GENERATED:
            reason = "not active"
            usable = False
        elif state is InviteState.EXPIRED:
            reason = "expired"
            usable = False
        elif state is InviteState.EXHAUSTED:
            reason = "exhausted"
            usable = False
        elif state is InviteState.REVOKED:
            reason = "revoked"
            usable = False
        else:
            reason = f"unusable ({state.value.lower()})"
            usable = False

        return ValidationResult(
            usable=usable,
            reason=reason,
            state=state,
            masked_code=self.masked_code,
            remaining_uses=self.__remaining_uses,
            required_access_level=self.required_access_level,
            expires_at=self.expires_at,
        )
    
    def use(self, at: datetime | None = None) -> UsageLogEntry:
        timestamp = normalize_datetime(at or utc_now())
        self._refresh_expiry(timestamp)

        if self.__state is not InviteState.ACTIVE:
            entry = self._record_usage(
                timestamp,
                self._usage_outcome_for_state(self.__state),
                self._failure_detail_for_state(self.__state),
            )
            raise InviteValidationError(
                f"Invite code {self.masked_code} cannot be used: {entry.detail}"
            )
        self.__remaining_uses -= 1
        success_entry = self._record_usage(
            timestamp,
            UsageOutcome.SUCCESS,
            f"Use accepted. {self.__remaining_uses} use(s) remaining.",
        )
        self._lifecycle.append(
            AuditEvent(
                timestamp=timestamp,
                event="used",
                detail=f"Invite used successfully. Remaining uses: {self.__remaining_uses}.",
            )
        )

        if self.__remaining_uses == 0:
            self._transition(
                InviteState.EXHAUSTED,
                timestamp,
                "Invite reached its maximum use count.",
            )

        return success_entry
    
    def revoke(self, reason: str, at: datetime | None = None) -> None:
    
        clean_reason = reason.strip()
        if not clean_reason:
            raise ValueError("revoke reason cannot be empty.")

        timestamp = normalize_datetime(at or utc_now())
        self._refresh_expiry(timestamp)
        self._transition(
            InviteState.REVOKED,
            timestamp,
            f"Invite revoked. Reason: {clean_reason}",
            revoked_reason=clean_reason,
        )

    def to_summary(self) -> InviteSummary:
        return InviteSummary(
            masked_code=self.masked_code,
            creator_id=self.creator_id,
            required_access_level=self.required_access_level,
            state=self.state,
            remaining_uses=self.remaining_uses,
            max_use_count=self.max_use_count,
            expires_at=self.expires_at,
            revoked_reason=self.revoked_reason,
        )

    def to_audit(self) -> InviteAudit:
        return InviteAudit(
            masked_code=self.masked_code,
            creator_id=self.creator_id,
            required_access_level=self.required_access_level,
            state=self.state,
            remaining_uses=self.remaining_uses,
            max_use_count=self.max_use_count,
            expires_at=self.expires_at,
            revoked_reason=self.revoked_reason,
            usage_log=tuple(self._usage_log),
            lifecycle=tuple(self.lifecycle),
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "code_string": self.code_string,
            "creator_id": self.creator_id,
            "required_access_level": self.required_access_level,
            "max_use_count": self.max_use_count,
            "expires_at": self.expires_at.isoformat(),
            "state": self.state.value,
            "remaining_uses": self.remaining_uses,
            "revoked_reason": self.revoked_reason,
            "usage_log": [entry.to_record() for entry in self._usage_log],
            "lifecycle": [event.to_record() for event in self._lifecycle],
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "InviteCode":
        cls._validate_record_shape(record)
        try:
            usage_log = [
                UsageLogEntry.from_record(item) for item in record.get("usage_log", [])
            ]
            lifecycle = [
                AuditEvent.from_record(item) for item in record.get("lifecycle", [])
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise InviteRecordError(f"Invalid nested invite record: {exc}") from exc

        return cls(
            code_string=record["code_string"],
            creator_id=record["creator_id"],
            required_access_level=record["required_access_level"],
            max_use_count=record["max_use_count"],
            expires_at=datetime.fromisoformat(record["expires_at"]),
            state=InviteState(record["state"]),
            remaining_uses=record["remaining_uses"],
            revoked_reason=record.get("revoked_reason"),
            usage_log=usage_log,
            lifecycle=lifecycle,
        )

    @staticmethod
    def _validate_record_shape(record: dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise InviteRecordError("Invite record must be a JSON object.")

        required_keys = (
            "code_string",
            "creator_id",
            "required_access_level",
            "max_use_count",
            "expires_at",
            "state",
            "remaining_uses",
        )
        missing = [key for key in required_keys if key not in record]
        if missing:
            raise InviteRecordError(f"Invite record missing keys: {', '.join(missing)}")

        code_string = record["code_string"]
        creator_id = record["creator_id"]
        if not isinstance(code_string, str) or not code_string.strip():
            raise InviteRecordError("code_string must be a non-empty string.")
        if not isinstance(creator_id, str) or not creator_id.strip():
            raise InviteRecordError("creator_id must be a non-empty string.")

        max_use_count = record["max_use_count"]
        required_access_level = record["required_access_level"]
        remaining_uses = record["remaining_uses"]

        if not isinstance(max_use_count, int) or max_use_count < 1:
            raise InviteRecordError("max_use_count must be an integer >= 1.")
        if not isinstance(required_access_level, int) or required_access_level < 0:
            raise InviteRecordError("required_access_level must be an integer >= 0.")
        if not isinstance(remaining_uses, int):
            raise InviteRecordError("remaining_uses must be an integer.")

        if remaining_uses < 0 or remaining_uses > max_use_count:
            raise InviteRecordError(
                "remaining_uses must be between 0 and max_use_count (inclusive)."
            )

        try:
            state = InviteState(record["state"])
        except ValueError as exc:
            raise InviteRecordError(f"Unknown invite state: {record['state']!r}") from exc

        expires_raw = record["expires_at"]
        if not isinstance(expires_raw, str):
            raise InviteRecordError("expires_at must be an ISO-8601 string.")
        try:
            datetime.fromisoformat(expires_raw)
        except ValueError as exc:
            raise InviteRecordError("expires_at is not a valid ISO-8601 timestamp.") from exc

        revoked_reason = record.get("revoked_reason")
        if revoked_reason is not None and not isinstance(revoked_reason, str):
            raise InviteRecordError("revoked_reason must be a string or null.")

        if state is InviteState.GENERATED and remaining_uses != max_use_count:
            raise InviteRecordError(
                "GENERATED invites must have remaining_uses equal to max_use_count."
            )
        if state is InviteState.ACTIVE and not (1 <= remaining_uses <= max_use_count):
            raise InviteRecordError(
                "ACTIVE invites must have remaining_uses between 1 and max_use_count."
            )
        if state is InviteState.EXHAUSTED and remaining_uses != 0:
            raise InviteRecordError("EXHAUSTED invites must have remaining_uses equal to 0.")
        if state is InviteState.REVOKED and not (revoked_reason and revoked_reason.strip()):
            raise InviteRecordError("REVOKED invites must include a non-empty revoked_reason.")

        for key in ("usage_log", "lifecycle"):
            value = record.get(key, [])
            if value is None:
                raise InviteRecordError(f"{key} must be a list, not null.")
            if not isinstance(value, list):
                raise InviteRecordError(f"{key} must be a list.")

    def _refresh_expiry(self, at: datetime | None = None) -> None:
        timestamp = normalize_datetime(at or utc_now())
        if self.__state is InviteState.ACTIVE and timestamp >= self.expires_at:
            self._transition(
                InviteState.EXPIRED,
                timestamp,
                "Invite expired during validation or access.",
            )
