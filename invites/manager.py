""" Manager for the invites package. """

# Enable postponed evaluation of annotations to allow using the class name within its own methods
from __future__ import annotations

# Import the secrets module for cryptographically strong random numbers suitable for managing secrets
import secrets
# Import the string module to access collections of ASCII characters and digits
import string
# Import the datetime class to handle time-based operations and expiration logic
from datetime import datetime
# Import Any for flexible typing and Iterable to represent a collection of objects that can be looped over
from typing import Any, Iterable

# Import specific models and exceptions from the local models module to handle invite logic
from .models import (
    InviteAudit,       # Data structure for full lifecycle and usage history
    InviteCode,        # The primary domain object representing an individual invite
    InviteNotFoundError, # Exception raised when a code does not exist in the manager
    InviteRecordError, # Exception raised when stored data fails validation or structure checks
    InviteState,       # Enum defining the possible lifecycle states of an invite
    InviteSummary,     # Lightweight data structure for listing invite metadata
    UsageLogEntry,     # Record of an individual attempt to use a code
    ValidationResult,  # The outcome of checking if a code is currently valid
    mask_code,         # Helper function to obfuscate sensitive code strings
)

# Constant defining the current schema version of the stored JSON data to ensure compatibility
STORE_FORMAT_VERSION = 1


# The central orchestrator class responsible for managing the collection of all invite codes
class InviteManager:
    # Initialize the manager with an optional collection of existing InviteCode objects
    def __init__(self, codes: Iterable[InviteCode] | None = None) -> None:
        # Internal dictionary mapping plaintext code strings to their respective InviteCode objects
        self._codes: dict[str, InviteCode] = {}
        # Iterate through provided codes and populate the internal dictionary for fast lookup
        for code in codes or []:
            # Use the code string itself as the key for O(1) retrieval performance
            self._codes[code.code_string] = code

    # High-level method to create, store, and optionally activate a brand-new invite code
    def generate(
        self,
        creator_id: str, # The identifier of the user or system generating the invite
        required_access_level: int, # The permission tier the code grants upon usage
        max_use_count: int, # Maximum number of successful uses allowed before exhaustion
        expires_at: datetime, # The point in time after which the code becomes invalid
        *,
        auto_activate: bool = True, # Flag to determine if code moves from GENERATED to ACTIVE immediately
    ) -> InviteCode:
        # Create a unique, cryptographically secure random string for the code
        code_string = self._generate_unique_code()
        # Instantiate the domain object with the provided and generated parameters
        invite = InviteCode(
            code_string=code_string,
            creator_id=creator_id,
            required_access_level=required_access_level,
            max_use_count=max_use_count,
            expires_at=expires_at,
        )
        # Register the new invite in the manager's internal storage dictionary
        self._codes[code_string] = invite
        # Perform state transition to ACTIVE if the auto_activate flag is set to True
        if auto_activate:
            invite.activate()
        # Return the fully initialized InviteCode object
        return invite

    # Check if a code is usable at a specific point in time without consuming it
    def validate(self, code_string: str, at: datetime | None = None) -> ValidationResult:
        # Attempt to retrieve the invite object from the internal dictionary
        invite = self._codes.get(code_string)
        # If no invite exists for the given string, return a failure validation result
        if invite is None:
            return ValidationResult(
                usable=False, # Code is not usable because it doesn't exist
                reason="not found", # Specific failure reason for the caller
                state=None, # No state available for a non-existent code
                masked_code=mask_code(code_string), # Safely log the attempted code string
                remaining_uses=None, # Use count is irrelevant for missing codes
                required_access_level=None, # Access level is irrelevant for missing codes
                expires_at=None, # Expiry is irrelevant for missing codes
            )
        # Delegate the actual validation logic to the InviteCode object itself
        return invite.validate(at=at)

    # Attempt to consume one use of an invite code, logging the outcome
    def use(self, code_string: str, at: datetime | None = None) -> UsageLogEntry:
        # Fetch the invite or raise InviteNotFoundError, then call its use method
        return self._get_required(code_string).use(at=at)

    # Manually revoke an invite code to prevent any further usage
    def revoke(self, code_string: str, reason: str, at: datetime | None = None) -> None:
        # Fetch the invite or raise InviteNotFoundError, then call its revoke method with a reason
        self._get_required(code_string).revoke(reason=reason, at=at)

    # Retrieve the full history and metadata for a specific invite code for auditing purposes
    def audit(self, code_string: str) -> InviteAudit:
        # Fetch the invite or raise InviteNotFoundError, then convert it to an audit data structure
        return self._get_required(code_string).to_audit()

    # Retrieve a list of summaries for all managed codes, optionally filtered by their current state
    def list_codes(self, filter_by_state: InviteState | str | None = None) -> list[InviteSummary]:
        # Variable to hold the normalized InviteState enum for filtering
        requested_state = None
        # Normalize the input filter into an InviteState Enum if a filter was provided
        if filter_by_state is not None:
            requested_state = (
                filter_by_state # Use as is if it's already the Enum type
                if isinstance(filter_by_state, InviteState)
                else InviteState(str(filter_by_state).upper()) # Convert string to uppercase Enum
            )

        # Generate lightweight summary objects for every invite in the system
        summaries = [invite.to_summary() for invite in self._codes.values()]
        # If a specific state filter was requested, remove all non-matching summaries
        if requested_state is not None:
            summaries = [summary for summary in summaries if summary.state is requested_state]
        # Return the summaries sorted chronologically by their expiration timestamps
        return sorted(summaries, key=lambda summary: summary.expires_at)

    # Serialize the manager's entire state into a dictionary for JSON persistence
    def to_record(self) -> dict[str, Any]:
        return {
            "version": STORE_FORMAT_VERSION, # Include the version for future migration support
            "codes": [invite.to_record() for invite in self._codes.values()], # Serialize all invites
        }

    # Factory method to create a manager instance from a serialized dictionary record
    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "InviteManager":
        # Ensure the root of the data is a dictionary object
        if not isinstance(record, dict):
            raise InviteRecordError("Store root must be a JSON object.")

        # Extract the version or default to the current one if not present
        version = record.get("version", STORE_FORMAT_VERSION)
        # Verify the data version is compatible with the current manager logic
        if version != STORE_FORMAT_VERSION:
            raise InviteRecordError(
                f"Unsupported store format version {version!r}; "
                f"expected {STORE_FORMAT_VERSION}."
            )

        # Retrieve the list of raw invite records
        codes_raw = record.get("codes", [])
        # Ensure 'codes' is not null in the dictionary
        if codes_raw is None:
            raise InviteRecordError("'codes' must be a list, not null.")
        # Ensure 'codes' is actually a list type
        if not isinstance(codes_raw, list):
            raise InviteRecordError("'codes' must be a list.")

        # Local list to accumulate deserialized InviteCode objects
        codes = []
        # Set used to detect and prevent duplicate code strings during loading
        seen: set[str] = set()
        # Iterate through every raw record and convert it back into an InviteCode object
        for index, item in enumerate(codes_raw):
            # Check that the individual entry is a dictionary
            if not isinstance(item, dict):
                raise InviteRecordError(f"Entry {index} in 'codes' must be an object.")
            # Use InviteCode's deserialization method to reconstruct the object
            invite = InviteCode.from_record(item)
            # Enforce uniqueness of code strings within the manager
            if invite.code_string in seen:
                raise InviteRecordError(
                    f"Duplicate invite code_string in store: {mask_code(invite.code_string)}."
                )
            # Add the string to the seen set and the object to the codes list
            seen.add(invite.code_string)
            codes.append(invite)

        # Return a new instance of InviteManager populated with the deserialized codes
        return cls(codes=codes)

    # Internal helper to find an invite or raise a standardized 'not found' exception
    def _get_required(self, code_string: str) -> InviteCode:
        # Look up the code in the internal dictionary
        invite = self._codes.get(code_string)
        # Raise exception with a masked code string for security if lookup fails
        if invite is None:
            raise InviteNotFoundError(f"Invite code {mask_code(code_string)} was not found.")
        # Return the successfully found invite object
        return invite

    # Internal helper to generate a random string that doesn't collide with existing codes
    def _generate_unique_code(self, length: int = 12) -> str:
        # Define the set of allowed characters (Uppercase letters and digits)
        alphabet = string.ascii_uppercase + string.digits
        # Attempt to generate a unique code up to 10 times to handle potential collisions
        for _ in range(10):
            # Use secrets.choice for cryptographically secure selection of characters
            code_string = "".join(secrets.choice(alphabet) for _ in range(length))
            # If the string is not already in use, return it immediately
            if code_string not in self._codes:
                return code_string
        # Raise an error if we fail to find a unique code after maximum retries
        raise RuntimeError("Could not generate a unique invite code.")