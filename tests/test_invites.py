from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from invites.cli import main
from invites.manager import InviteManager
from invites.models import (
    InvalidStateTransitionError,
    InviteRecordError,
    InviteState,
    InviteValidationError,
    UsageOutcome,
)
from invites.store import StoreError, load_manager, save_manager


class InviteManagerTests(unittest.TestCase):
    def test_generate_auto_activates_and_masks_listing(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="warden",
            required_access_level=4,
            max_use_count=2,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        )

        summary = manager.list_codes()[0]

        self.assertEqual(invite.state, InviteState.ACTIVE)
        self.assertEqual(summary.state, InviteState.ACTIVE)
        self.assertTrue(summary.masked_code.endswith(invite.code_string[-4:]))
        self.assertNotEqual(summary.masked_code, invite.code_string)

    def test_validate_marks_codes_expired_lazily(self) -> None:
        manager = InviteManager()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        invite = manager.generate(
            creator_id="warden",
            required_access_level=2,
            max_use_count=1,
            expires_at=expires_at,
        )

        result = manager.validate(invite.code_string, at=expires_at + timedelta(seconds=1))

        self.assertFalse(result.usable)
        self.assertEqual(result.reason, "expired")
        self.assertEqual(invite.state, InviteState.EXPIRED)

    def test_use_records_success_and_exhaustion(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="ops",
            required_access_level=3,
            max_use_count=2,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        manager.use(invite.code_string)
        manager.use(invite.code_string)

        with self.assertRaises(InviteValidationError):
            manager.use(invite.code_string)

        self.assertEqual(invite.state, InviteState.EXHAUSTED)
        self.assertEqual(invite.remaining_uses, 0)
        self.assertEqual(len(invite.usage_log), 3)
        self.assertEqual(invite.usage_log[0].outcome, UsageOutcome.SUCCESS)
        self.assertEqual(invite.usage_log[-1].outcome, UsageOutcome.EXHAUSTED)

    def test_revoke_blocks_further_use_and_appears_in_audit(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="ops",
            required_access_level=5,
            max_use_count=3,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        manager.revoke(invite.code_string, "Security rotation")

        with self.assertRaises(InviteValidationError):
            manager.use(invite.code_string)

        audit = manager.audit(invite.code_string)
        self.assertEqual(audit.state, InviteState.REVOKED)
        self.assertEqual(audit.revoked_reason, "Security rotation")
        self.assertEqual(audit.usage_log[-1].outcome, UsageOutcome.REVOKED)
        self.assertEqual(audit.lifecycle[-1].event, "revoked")

    def test_invalid_transition_raises_clear_error(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="ops",
            required_access_level=1,
            max_use_count=1,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        manager.use(invite.code_string)

        with self.assertRaises(InvalidStateTransitionError) as context:
            invite.revoke("Late revocation")

        self.assertIn("cannot transition", str(context.exception))

    def test_store_round_trip_preserves_state_and_logs(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="auditor",
            required_access_level=6,
            max_use_count=2,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        manager.use(invite.code_string)

        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "invites_store.json"
            save_manager(manager, store_path)
            loaded = load_manager(store_path)
            audit = loaded.audit(invite.code_string)

        self.assertEqual(audit.state, InviteState.ACTIVE)
        self.assertEqual(audit.remaining_uses, 1)
        self.assertEqual(len(audit.usage_log), 1)
        self.assertEqual(audit.usage_log[0].outcome, UsageOutcome.SUCCESS)

    def test_load_corrupt_json_raises_store_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "bad.json"
            store_path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(StoreError):
                load_manager(store_path)

    def test_load_duplicate_codes_raises_store_error(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="ops",
            required_access_level=1,
            max_use_count=1,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        record = invite.to_record()
        payload = {"version": 1, "codes": [record, record]}

        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "dup.json"
            store_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(StoreError):
                load_manager(store_path)

    def test_from_record_rejects_inconsistent_active_code(self) -> None:
        manager = InviteManager()
        invite = manager.generate(
            creator_id="ops",
            required_access_level=1,
            max_use_count=2,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        record = invite.to_record()
        record["remaining_uses"] = 0

        with self.assertRaises(InviteRecordError):
            InviteManager.from_record({"version": 1, "codes": [record]})

    def test_atomic_save_leaves_no_temp_files(self) -> None:
        manager = InviteManager()
        manager.generate(
            creator_id="ops",
            required_access_level=1,
            max_use_count=1,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "nested" / "store.json"
            save_manager(manager, store_path)
            leftovers = list(store_path.parent.glob(".store.json.*.tmp"))
            self.assertEqual(leftovers, [])

    def test_cli_generate_masks_secret_by_default(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "cli.json"
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                rc = main(
                    [
                        "--store",
                        str(store_path),
                        "generate",
                        "--creator-id",
                        "warden",
                        "--access-level",
                        "1",
                        "--max-uses",
                        "1",
                        "--expires-in-hours",
                        "1",
                    ]
                )

            self.assertEqual(rc, 0)
            full_code = json.loads(store_path.read_text(encoding="utf-8"))["codes"][0][
                "code_string"
            ]
            out = stdout.getvalue()
            self.assertNotIn(full_code, out)
            self.assertIn("masked", out.lower())

    def test_cli_generate_show_code_prints_secret_to_stderr(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            store_path = Path(temp_dir) / "cli.json"
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                rc = main(
                    [
                        "--store",
                        str(store_path),
                        "generate",
                        "--creator-id",
                        "warden",
                        "--access-level",
                        "1",
                        "--max-uses",
                        "1",
                        "--expires-in-hours",
                        "1",
                        "--show-code",
                    ]
                )

            self.assertEqual(rc, 0)
            full_code = json.loads(store_path.read_text(encoding="utf-8"))["codes"][0][
                "code_string"
            ]
            self.assertIn(full_code, stderr.getvalue())
            self.assertNotIn(full_code, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
