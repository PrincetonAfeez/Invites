from __future__ import annotations

import secrets
import string
from datetime import datetime
from typing import Any, Iterable

from .models import (
    InviteAudit,
    InviteCode,
    InviteNotFoundError,
    InviteRecordError,
    InviteState,
    InviteSummary,
    UsageLogEntry,
    ValidationResult,
    mask_code,
)

STORE_FORMAT_VERSION = 1

class InviteManager:
    def __init__(self, codes: Iterable[InviteCode] | None = None) -> None:
        self._codes: dict[str, InviteCode] = {}
        for code in codes or []:
            self._codes[code.code_string] = code

    def generate(
        self,
        creator_id: str,
        required_access_level: int,
        max_use_count: int,
        expires_at: datetime,
        *,
        auto_activate: bool = True,
    ) -> InviteCode:
        code_string = self._generate_unique_code()
        invite = InviteCode(
            code_string=code_string,
            creator_id=creator_id,
            required_access_level=required_access_level,
            max_use_count=max_use_count,
            expires_at=expires_at,
        )
        self._codes[code_string] = invite
        if auto_activate:
            invite.activate()
        return invite

    def validate(self, code_string: str, at: datetime | None = None) -> ValidationResult:
        invite = self._codes.get(code_string)
        if invite is None:
            return ValidationResult(
                usable=False,
                reason="not found",
                state=None,
                masked_code=mask_code(code_string),
                remaining_uses=None,
                required_access_level=None,
                expires_at=None,
            )
        return invite.validate(at=at)

    def use(self, code_string: str, at: datetime | None = None) -> UsageLogEntry:
        return self._get_required(code_string).use(at=at)

    def revoke(self, code_string: str, reason: str, at: datetime | None = None) -> None:
        self._get_required(code_string).revoke(reason=reason, at=at)

    def audit(self, code_string: str) -> InviteAudit:
        return self._get_required(code_string).to_audit()

    def list_codes(self, filter_by_state: InviteState | str | None = None) -> list[InviteSummary]:
        requested_state = None
        if filter_by_state is not None:
            requested_state = (
                filter_by_state
                if isinstance(filter_by_state, InviteState)
                else InviteState(str(filter_by_state).upper())
            )

        summaries = [invite.to_summary() for invite in self._codes.values()]
        if requested_state is not None:
            summaries = [summary for summary in summaries if summary.state is requested_state]
        return sorted(summaries, key=lambda summary: summary.expires_at)

    def to_record(self) -> dict[str, Any]:
        return {
            "version": STORE_FORMAT_VERSION,
            "codes": [invite.to_record() for invite in self._codes.values()],
        }

    @classmethod 
    def from_record(cls, record: dict[str, Any]) -> "InviteManager":
        if not isinstance(record, dict):
            raise InviteRecordError("Store root must be a JSON object.")

        version = record.get("version", STORE_FORMAT_VERSION)
        if version != STORE_FORMAT_VERSION:
            raise InviteRecordError(
                f"Unsupported store format version {version!r}; "
                f"expected {STORE_FORMAT_VERSION}."
            )

        codes_raw = record.get("codes", [])
        if codes_raw is None:
            raise InviteRecordError("'codes' must be a list, not null.")
        if not isinstance(codes_raw, list):
            raise InviteRecordError("'codes' must be a list.")

        codes = []
        seen: set[str] = set()
        for index, item in enumerate(codes_raw):
            if not isinstance(item, dict):
                raise InviteRecordError(f"Entry {index} in 'codes' must be an object.")
            invite = InviteCode.from_record(item)
            if invite.code_string in seen:
                raise InviteRecordError(
                    f"Duplicate invite code_string in store: {mask_code(invite.code_string)}."
                )
            seen.add(invite.code_string)
            codes.append(invite)

        return cls(codes=codes)

    def _get_required(self, code_string: str) -> InviteCode:
        invite = self._codes.get(code_string)
        if invite is None:
            raise InviteNotFoundError(f"Invite code {mask_code(code_string)} was not found.")
        return invite

    def _generate_unique_code(self, length: int = 12) -> str:
        alphabet = string.ascii_uppercase + string.digits
        for _ in range(10):
            code_string = "".join(secrets.choice(alphabet) for _ in range(length))
            if code_string not in self._codes:
                return code_string
        raise RuntimeError("Could not generate a unique invite code.")
