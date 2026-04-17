# Enable postponed evaluation of type annotations for circular references or self-referencing types
from __future__ import annotations

# Import dataclass for boilerplate-free data containers
from dataclasses import dataclass
# Import datetime for handling time-based logic and timezone for UTC enforcement
from datetime import datetime, timezone
# Import Enum to define restricted sets of named constants for states and outcomes
from enum import Enum
# Import Any for flexible typing and ClassVar for class-level shared variables
from typing import Any, ClassVar


# Helper function to get the current system time in a timezone-aware UTC format
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# Utility to ensure a datetime object is timezone-aware and converted to UTC
def normalize_datetime(value: datetime) -> datetime:
    # If the datetime has no timezone info, treat it as UTC
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    # If it has timezone info, convert the existing time to the UTC equivalent
    return value.astimezone(timezone.utc)


# Function to hide sensitive code strings, showing only the last 4 characters for identification
def mask_code(code_string: str) -> str:
    # If the code is too short to mask effectively, return it as is
    if len(code_string) <= 4:
        return code_string
    # Replace all but the last 4 characters with asterisks
    return f"{'*' * (len(code_string) - 4)}{code_string[-4:]}"


# Enumeration defining the lifecycle stages of an invite code
class InviteState(str, Enum):
    GENERATED = "GENERATED"  # Initial state after creation but before activation
    ACTIVE = "ACTIVE"        # State where the code is currently usable
    EXHAUSTED = "EXHAUSTED"  # State reached when use count hits zero
    EXPIRED = "EXPIRED"      # State reached when the current time exceeds expiry
    REVOKED = "REVOKED"      # State reached when manually cancelled by an admin


# Enumeration defining the possible results of an attempted code usage
class UsageOutcome(str, Enum):
    SUCCESS = "SUCCESS"        # The code was valid and successfully consumed
    NOT_ACTIVE = "NOT_ACTIVE"  # Attempted use on a code that isn't activated
    EXHAUSTED = "EXHAUSTED"    # Attempted use on a code with no uses left
    EXPIRED = "EXPIRED"        # Attempted use on a code past its expiration date
    REVOKED = "REVOKED"        # Attempted use on a manually cancelled code


# Base custom exception class for all errors related to the invite system
class InviteError(Exception):
    """Base exception for invite-code errors."""


# Error raised when an invite tries to move between incompatible states (e.g., REVOKED to ACTIVE)
class InvalidStateTransitionError(InviteError):
    """Raised when a state transition is not allowed."""


# Error raised when a code fails validation checks during a 'use' attempt
class InviteValidationError(InviteError):
    """Raised when an invite code cannot be used."""


# Error raised when a specific code string does not exist in the system registry
class InviteNotFoundError(InviteError):
    """Raised when an invite code cannot be found."""


# Error raised when data loaded from storage (JSON) is corrupted or invalid
class InviteRecordError(InviteError):
    """Raised when persisted invite data fails validation."""


# Immutable data container for recording a single attempt to use an invite code
@dataclass(frozen=True)
class UsageLogEntry:
    timestamp: datetime   # When the usage attempt occurred
    outcome: UsageOutcome # The result of the attempt (Success/Failure reason)
    detail: str           # Human-readable explanation of the outcome

    # Converts the log entry into a dictionary for JSON serialization
    def to_record(self) -> dict[str, str]:
        return {
            "timestamp": normalize_datetime(self.timestamp).isoformat(),
            "outcome": self.outcome.value,
            "detail": self.detail,
        }

    # Reconstructs a log entry object from a dictionary (e.g., from a JSON file)
    @classmethod
    def from_record(cls, record: dict[str, str]) -> "UsageLogEntry":
        return cls(
            timestamp=datetime.fromisoformat(record["timestamp"]),
            outcome=UsageOutcome(record["outcome"]),
            detail=record["detail"],
        )


# Immutable data container for tracking administrative changes (lifecycle events)
@dataclass(frozen=True)
class AuditEvent:
    timestamp: datetime # When the event happened
    event: str          # Name of the event (e.g., "created", "activated")
    detail: str         # Descriptive text about the change

    # Serializes the audit event for storage
    def to_record(self) -> dict[str, str]:
        return {
            "timestamp": normalize_datetime(self.timestamp).isoformat(),
            "event": self.event,
            "detail": self.detail,
        }

    # Deserializes the audit event from storage
    @classmethod
    def from_record(cls, record: dict[str, str]) -> "AuditEvent":
        return cls(
            timestamp=datetime.fromisoformat(record["timestamp"]),
            event=record["event"],
            detail=record["detail"],
        )


# Container for the results of a validation check, used by the API to communicate status
@dataclass(frozen=True)
class ValidationResult:
    usable: bool                   # True if the code can be consumed right now
    reason: str | None             # Explanation if the code is not usable
    state: InviteState | None      # The current lifecycle state of the code
    masked_code: str               # The safely hidden version of the code string
    remaining_uses: int | None     # Number of times the code can still be used
    required_access_level: int | None # Security level associated with this code
    expires_at: datetime | None    # The deadline for using this code


# Lightweight summary of an invite, ideal for listing multiple codes in a UI
@dataclass(frozen=True)
class InviteSummary:
    masked_code: str           # The masked version of the code
    creator_id: str            # ID of the user who generated the code
    required_access_level: int # Permission level the code grants
    state: InviteState         # Current status (Active, Revoked, etc.)
    remaining_uses: int        # How many uses are left
    max_use_count: int         # The original total uses allowed
    expires_at: datetime       # Expiration timestamp
    revoked_reason: str | None # Reason for revocation, if applicable


# Comprehensive audit object containing the full history and logs of a code
@dataclass(frozen=True)
class InviteAudit:
    masked_code: str                      # Masked code string
    creator_id: str                       # User who created the code
    required_access_level: int            # Access tier required
    state: InviteState                    # Current state
    remaining_uses: int                   # Current uses left
    max_use_count: int                    # Total uses allowed
    expires_at: datetime                  # Expiry time
    revoked_reason: str | None            # Why it was revoked
    usage_log: tuple[UsageLogEntry, ...]  # History of usage attempts
    lifecycle: tuple[AuditEvent, ...]     # History of state transitions


# The main domain object representing an Invite Code and its business logic
class InviteCode:
    # State Machine definition: maps a state to the set of states it is allowed to move to
    TRANSITIONS: ClassVar[dict[InviteState, set[InviteState]]] = {
        InviteState.GENERATED: {InviteState.ACTIVE, InviteState.REVOKED},
        InviteState.ACTIVE: {
            InviteState.EXHAUSTED,
            InviteState.EXPIRED,
            InviteState.REVOKED,
        },
        InviteState.EXHAUSTED: set(), # Terminal state
        InviteState.EXPIRED: set(),   # Terminal state
        InviteState.REVOKED: set(),   # Terminal state
    }

    # Mapping of states to past-tense event names for audit logging
    EVENT_NAMES: ClassVar[dict[InviteState, str]] = {
        InviteState.ACTIVE: "activated",
        InviteState.EXHAUSTED: "exhausted",
        InviteState.EXPIRED: "expired",
        InviteState.REVOKED: "revoked",
    }

    # Constructor to initialize a new or existing InviteCode instance
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
        # Validation: Ensure code has at least one use allowed
        if max_use_count < 1:
            raise ValueError("max_use_count must be at least 1.")
        # Validation: Access level cannot be negative
        if required_access_level < 0:
            raise ValueError("required_access_level must be 0 or greater.")
        # Validation: Ensure creator ID is not blank
        if not creator_id.strip():
            raise ValueError("creator_id cannot be empty.")
        # Validation: Ensure the actual code string is not blank
        if not code_string.strip():
            raise ValueError("code_string cannot be empty.")

        # Assign core attributes
        self.code_string = code_string
        self.creator_id = creator_id.strip()
        self.required_access_level = required_access_level
        self.max_use_count = max_use_count
        self.expires_at = normalize_datetime(expires_at)
        # Internal state management (private attributes)
        self.__state = state
        self.__remaining_uses = max_use_count if remaining_uses is None else remaining_uses
        self.__revoked_reason = revoked_reason
        self._usage_log = list(usage_log or [])
        self._lifecycle = list(lifecycle or [])

        # If this is a brand new code (no lifecycle yet), record the 'created' event
        if not self._lifecycle:
            timestamp = normalize_datetime(created_at or utc_now())
            self._lifecycle.append(
                AuditEvent(timestamp=timestamp, event="created", detail="Invite code generated.")
            )

    # Property to get the masked version of the code string
    @property
    def masked_code(self) -> str:
        return mask_code(self.code_string)

    # Property to get the current state, triggering an expiry check first
    @property
    def state(self) -> InviteState:
        self._refresh_expiry()
        return self.__state

    # Property to get remaining uses, triggering an expiry check first
    @property
    def remaining_uses(self) -> int:
        self._refresh_expiry()
        return self.__remaining_uses

    # Property to get the reason for revocation
    @property
    def revoked_reason(self) -> str | None:
        return self.__revoked_reason

    # Property to get the usage log as an immutable tuple
    @property
    def usage_log(self) -> tuple[UsageLogEntry, ...]:
        return tuple(self._usage_log)

    # Property to get the lifecycle history as an immutable tuple
    @property
    def lifecycle(self) -> tuple[AuditEvent, ...]:
        self._refresh_expiry()
        return tuple(self._lifecycle)

    # Method to move a code from GENERATED to ACTIVE so it can be used
    def activate(self, at: datetime | None = None) -> None:
        timestamp = normalize_datetime(at or utc_now())
        # Transition the state and log the event
        self._transition(InviteState.ACTIVE, timestamp, "Invite code activated and ready for use.")
        # Check if it was already expired at the moment of activation
        self._refresh_expiry(timestamp)

    # Checks the status of a code without consuming a use
    def validate(self, at: datetime | None = None) -> ValidationResult:
        timestamp = normalize_datetime(at or utc_now())
        self._refresh_expiry(timestamp) # Ensure state is up to date regarding time
        state = self.__state

        # Determine usability based on state and usage count
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

        # Return a structured result object
        return ValidationResult(
            usable=usable,
            reason=reason,
            state=state,
            masked_code=self.masked_code,
            remaining_uses=self.__remaining_uses,
            required_access_level=self.required_access_level,
            expires_at=self.expires_at,
        )

    # Consumes one use of the invite code
    def use(self, at: datetime | None = None) -> UsageLogEntry:
        timestamp = normalize_datetime(at or utc_now())
        self._refresh_expiry(timestamp)

        # If state is not ACTIVE, record the failure and raise an exception
        if self.__state is not InviteState.ACTIVE:
            entry = self._record_usage(
                timestamp,
                self._usage_outcome_for_state(self.__state),
                self._failure_detail_for_state(self.__state),
            )
            raise InviteValidationError(
                f"Invite code {self.masked_code} cannot be used: {entry.detail}"
            )

        # Decrement the use counter
        self.__remaining_uses -= 1
        # Log the successful usage
        success_entry = self._record_usage(
            timestamp,
            UsageOutcome.SUCCESS,
            f"Use accepted. {self.__remaining_uses} use(s) remaining.",
        )
        # Add 'used' event to lifecycle log
        self._lifecycle.append(
            AuditEvent(
                timestamp=timestamp,
                event="used",
                detail=f"Invite used successfully. Remaining uses: {self.__remaining_uses}.",
            )
        )

        # If no uses are left, transition the state to EXHAUSTED
        if self.__remaining_uses == 0:
            self._transition(
                InviteState.EXHAUSTED,
                timestamp,
                "Invite reached its maximum use count.",
            )

        return success_entry
    
    # Manually disables an invite code with a specific reason
    def revoke(self, reason: str, at: datetime | None = None) -> None:
        
        # Clean the input reason and ensure it's not empty
        clean_reason = reason.strip()
        if not clean_reason:
            raise ValueError("revoke reason cannot be empty.")

        timestamp = normalize_datetime(at or utc_now())
        self._refresh_expiry(timestamp)
        # Perform state transition to REVOKED and store the reason
        self._transition(
            InviteState.REVOKED,
            timestamp,
            f"Invite revoked. Reason: {clean_reason}",
            revoked_reason=clean_reason,
        )

    # Creates a compact summary of the invite for quick reference
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

    # Creates a full audit object containing all logs and metadata
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

    # Converts the entire object state into a dictionary for JSON storage
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

    # Factory method to create an InviteCode instance from a dictionary record
    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "InviteCode":
        # Validate the structure of the incoming data first
        cls._validate_record_shape(record)
        try:
            # Reconstruct usage logs and lifecycle events from their nested records
            usage_log = [
                UsageLogEntry.from_record(item) for item in record.get("usage_log", [])
            ]
            lifecycle = [
                AuditEvent.from_record(item) for item in record.get("lifecycle", [])
            ]
        except (KeyError, TypeError, ValueError) as exc:
            # Wrap low-level errors in a domain-specific record error
            raise InviteRecordError(f"Invalid nested invite record: {exc}") from exc

        # Return a fully initialized InviteCode object
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

    # Static helper to verify that a dictionary has all required fields and correct types
    @staticmethod
    def _validate_record_shape(record: dict[str, Any]) -> None:
        # Check if record is a dictionary
        if not isinstance(record, dict):
            raise InviteRecordError("Invite record must be a JSON object.")

        # List of keys that MUST be present in the dictionary
        required_keys = (
            "code_string",
            "creator_id",
            "required_access_level",
            "max_use_count",
            "expires_at",
            "state",
            "remaining_uses",
        )
        # Find any missing keys
        missing = [key for key in required_keys if key not in record]
        if missing:
            raise InviteRecordError(f"Invite record missing keys: {', '.join(missing)}")

        # Validate basic string fields
        code_string = record["code_string"]
        creator_id = record["creator_id"]
        if not isinstance(code_string, str) or not code_string.strip():
            raise InviteRecordError("code_string must be a non-empty string.")
        if not isinstance(creator_id, str) or not creator_id.strip():
            raise InviteRecordError("creator_id must be a non-empty string.")

        # Validate numeric fields
        max_use_count = record["max_use_count"]
        required_access_level = record["required_access_level"]
        remaining_uses = record["remaining_uses"]

        if not isinstance(max_use_count, int) or max_use_count < 1:
            raise InviteRecordError("max_use_count must be an integer >= 1.")
        if not isinstance(required_access_level, int) or required_access_level < 0:
            raise InviteRecordError("required_access_level must be an integer >= 0.")
        if not isinstance(remaining_uses, int):
            raise InviteRecordError("remaining_uses must be an integer.")

        # Logical check: remaining uses cannot exceed the maximum
        if remaining_uses < 0 or remaining_uses > max_use_count:
            raise InviteRecordError(
                "remaining_uses must be between 0 and max_use_count (inclusive)."
            )

        # Validate that the state string matches a known InviteState
        try:
            state = InviteState(record["state"])
        except ValueError as exc:
            raise InviteRecordError(f"Unknown invite state: {record['state']!r}") from exc

        # Validate ISO-8601 date string format
        expires_raw = record["expires_at"]
        if not isinstance(expires_raw, str):
            raise InviteRecordError("expires_at must be an ISO-8601 string.")
        try:
            datetime.fromisoformat(expires_raw)
        except ValueError as exc:
            raise InviteRecordError("expires_at is not a valid ISO-8601 timestamp.") from exc

        # Validate optional revocation reason
        revoked_reason = record.get("revoked_reason")
        if revoked_reason is not None and not isinstance(revoked_reason, str):
            raise InviteRecordError("revoked_reason must be a string or null.")

        # Cross-field logical consistency checks
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

        # Ensure logs are lists, even if empty
        for key in ("usage_log", "lifecycle"):
            value = record.get(key, [])
            if value is None:
                raise InviteRecordError(f"{key} must be a list, not null.")
            if not isinstance(value, list):
                raise InviteRecordError(f"{key} must be a list.")

    # Internal helper to check if an active invite has passed its expiry time
    def _refresh_expiry(self, at: datetime | None = None) -> None:
        timestamp = normalize_datetime(at or utc_now())
        # If active but time is up, transition to EXPIRED
        if self.__state is InviteState.ACTIVE and timestamp >= self.expires_at:
            self._transition(
                InviteState.EXPIRED,
                timestamp,
                "Invite expired during validation or access.",
            )

    # Internal helper to handle the mechanics of state changes and audit logging
    def _transition(
        self,
        new_state: InviteState,
        timestamp: datetime,
        detail: str,
        *,
        revoked_reason: str | None = None,
    ) -> None:
        current_state = self.__state
        # Check the transition map to see if this move is legal
        allowed_states = self.TRANSITIONS[current_state]
        if new_state not in allowed_states:
            raise InvalidStateTransitionError(
                f"Invite code {self.masked_code} cannot transition from "
                f"{current_state.value} to {new_state.value}."
            )

        # Update state and optional revocation reason
        self.__state = new_state
        if revoked_reason is not None:
            self.__revoked_reason = revoked_reason

        # Append the change to the lifecycle history
        self._lifecycle.append(
            AuditEvent(
                timestamp=timestamp,
                event=self.EVENT_NAMES[new_state],
                detail=f"{current_state.value} -> {new_state.value}. {detail}",
            )
        )

    # Internal helper to add an entry to the usage log
    def _record_usage(
        self,
        timestamp: datetime,
        outcome: UsageOutcome,
        detail: str,
    ) -> UsageLogEntry:
        entry = UsageLogEntry(timestamp=timestamp, outcome=outcome, detail=detail)
        self._usage_log.append(entry)
        return entry

    # Internal helper to map an InviteState to a corresponding UsageOutcome code
    @staticmethod
    def _usage_outcome_for_state(state: InviteState) -> UsageOutcome:
        mapping = {
            InviteState.GENERATED: UsageOutcome.NOT_ACTIVE,
            InviteState.EXHAUSTED: UsageOutcome.EXHAUSTED,
            InviteState.EXPIRED: UsageOutcome.EXPIRED,
            InviteState.REVOKED: UsageOutcome.REVOKED,
        }
        return mapping.get(state, UsageOutcome.NOT_ACTIVE)

    # Internal helper to provide a human-friendly error message based on state
    def _failure_detail_for_state(self, state: InviteState) -> str:
        if state is InviteState.GENERATED:
            return "Invite has not been activated yet."
        if state is InviteState.EXHAUSTED:
            return "Invite has no remaining uses."
        if state is InviteState.EXPIRED:
            return "Invite has expired."
        if state is InviteState.REVOKED:
            if self.__revoked_reason:
                return f"Invite was revoked ({self.__revoked_reason})."
            return "Invite was revoked."
        return "Invite is not in a usable state."