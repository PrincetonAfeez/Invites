""" Test package coverage for the invites package. """

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from invites import __all__ as invites_exports
from invites.cli import _dispatch, _format_datetime, _resolve_expiry, build_parser, main
from invites.manager import InviteManager
from invites.models import (
    AuditEvent,
    InviteCode,
    InviteNotFoundError,
    InviteRecordError,
    InviteState,
    InviteValidationError,
    UsageLogEntry,
    UsageOutcome,
    mask_code,
    normalize_datetime,
    utc_now,
)
from invites.store import StoreError, load_manager, save_manager


class ModelHelpersTests(unittest.TestCase):
    def test_mask_code_short_and_long(self) -> None:
        self.assertEqual(mask_code("AB"), "AB")
        self.assertEqual(mask_code("ABCDE"), "*BCDE")
        long = "ABCDEFGHIJKL"
        self.assertTrue(mask_code(long).endswith(long[-4:]))
        self.assertEqual(len(mask_code(long)), 12)

    def test_normalize_datetime_naive_and_aware(self) -> None:
        naive = datetime(2020, 1, 2, 3, 4, 5)
        self.assertEqual(normalize_datetime(naive).tzinfo, timezone.utc)
        aware = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.assertEqual(normalize_datetime(aware), aware)

    def test_utc_now_is_timezone_aware(self) -> None:
        self.assertIsNotNone(utc_now().tzinfo)

    def test_usage_log_and_audit_round_trip(self) -> None:
        ts = datetime(2021, 6, 7, 8, 9, 10, tzinfo=timezone.utc)
        entry = UsageLogEntry(timestamp=ts, outcome=UsageOutcome.SUCCESS, detail="ok")
        restored = UsageLogEntry.from_record(entry.to_record())
        self.assertEqual(restored, entry)

        event = AuditEvent(timestamp=ts, event="created", detail="hello")
        restored_event = AuditEvent.from_record(event.to_record())
        self.assertEqual(restored_event, event)


class InviteCodeBehaviorTests(unittest.TestCase):
    def _future_expiry(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(hours=1)

    def test_init_validation_errors(self) -> None:
        exp = self._future_expiry()
        with self.assertRaises(ValueError):
            InviteCode("X", "c", 0, 0, exp)
        with self.assertRaises(ValueError):
            InviteCode("X", "c", -1, 1, exp)
        with self.assertRaises(ValueError):
            InviteCode("X", "  ", 0, 1, exp)
        with self.assertRaises(ValueError):
            InviteCode("  ", "c", 0, 1, exp)

    def test_validate_generated_and_use_fails(self) -> None:
        invite = InviteCode(
            "ABCDEFGHIJKL",
            "creator",
            2,
            2,
            self._future_expiry(),
            state=InviteState.GENERATED,
            remaining_uses=2,
        )
        result = invite.validate()
        self.assertFalse(result.usable)
        self.assertEqual(result.reason, "not active")
        with self.assertRaises(InviteValidationError):
            invite.use()

    def test_use_expired_invite_includes_expired_detail(self) -> None:
        invite = InviteCode(
            "ABCDEFGHIJKL",
            "creator",
            1,
            1,
            self._future_expiry(),
            state=InviteState.EXPIRED,
            remaining_uses=1,
        )
        with self.assertRaises(InviteValidationError) as ctx:
            invite.use()
        self.assertIn("expired", str(ctx.exception).lower())

    def test_failure_detail_fallback_for_active_branch(self) -> None:
        invite = InviteCode(
            "ABCDEFGHIJKL",
            "creator",
            1,
            1,
            self._future_expiry(),
            state=InviteState.ACTIVE,
        )
        self.assertEqual(
            invite._failure_detail_for_state(InviteState.ACTIVE),
            "Invite is not in a usable state.",
        )

    def test_validate_expired_exhausted_revoked(self) -> None:
        exp = self._future_expiry()
        for state, reason in (
            (InviteState.EXPIRED, "expired"),
            (InviteState.EXHAUSTED, "exhausted"),
            (InviteState.REVOKED, "revoked"),
        ):
            with self.subTest(state=state):
                invite = InviteCode(
                    "ABCDEFGHIJKL",
                    "creator",
                    1,
                    2,
                    exp,
                    state=state,
                    remaining_uses=0 if state is InviteState.EXHAUSTED else 1,
                    revoked_reason="r" if state is InviteState.REVOKED else None,
                )
                res = invite.validate()
                self.assertFalse(res.usable)
                self.assertEqual(res.reason, reason)

    def test_validate_active_zero_remaining_is_unusable_else_branch(self) -> None:
        invite = InviteCode(
            "ABCDEFGHIJKL",
            "creator",
            1,
            2,
            self._future_expiry(),
            state=InviteState.ACTIVE,
            remaining_uses=0,
        )
        res = invite.validate()
        self.assertFalse(res.usable)
        self.assertIn("unusable", res.reason or "")

    def test_revoke_requires_non_empty_reason(self) -> None:
        invite = InviteCode(
            "ABCDEFGHIJKL",
            "creator",
            1,
            1,
            self._future_expiry(),
            state=InviteState.ACTIVE,
        )
        with self.assertRaises(ValueError):
            invite.revoke("   ")

    def test_use_revoked_without_reason_uses_generic_message(self) -> None:
        invite = InviteCode(
            "ABCDEFGHIJKL",
            "creator",
            0,
            1,
            datetime.now(timezone.utc) + timedelta(hours=1),
            state=InviteState.REVOKED,
            remaining_uses=0,
            revoked_reason=None,
        )
        with self.assertRaises(InviteValidationError) as ctx:
            invite.use()
        self.assertIn("Invite was revoked.", str(ctx.exception))

    def test_from_record_invalid_nested_raises_invite_record_error(self) -> None:
        base = {
            "code_string": "ABCDEFGHIJKL",
            "creator_id": "c",
            "required_access_level": 0,
            "max_use_count": 1,
            "expires_at": self._future_expiry().isoformat(),
            "state": InviteState.ACTIVE.value,
            "remaining_uses": 1,
            "usage_log": [{"bad": "shape"}],
            "lifecycle": [],
        }
        with self.assertRaises(InviteRecordError):
            InviteCode.from_record(base)

    def test_from_record_shape_validation_errors(self) -> None:
        exp = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        def base(**overrides: object) -> dict:
            row: dict = {
                "code_string": "ABCDEFGHIJKL",
                "creator_id": "c",
                "required_access_level": 0,
                "max_use_count": 2,
                "expires_at": exp,
                "state": InviteState.ACTIVE.value,
                "remaining_uses": 1,
                "usage_log": [],
                "lifecycle": [],
            }
            row.update(overrides)
            return row

        cases: list[tuple[dict, str]] = [
            ({"code_string": ""}, "non-empty"),
            ({"creator_id": "  "}, "non-empty"),
            ({"max_use_count": 0}, "max_use_count"),
            ({"required_access_level": -1}, "required_access_level"),
            ({"remaining_uses": "1"}, "integer"),
            ({"remaining_uses": 9}, "between 0 and max"),
            ({"state": "BOGUS"}, "Unknown invite state"),
            ({"expires_at": 123}, "ISO-8601 string"),
            ({"expires_at": "not-a-date"}, "valid ISO-8601"),
            ({"revoked_reason": 99}, "revoked_reason"),
            (
                {
                    "state": InviteState.GENERATED.value,
                    "remaining_uses": 1,
                },
                "GENERATED invites",
            ),
            (
                {
                    "state": InviteState.EXHAUSTED.value,
                    "remaining_uses": 1,
                },
                "EXHAUSTED invites",
            ),
            (
                {
                    "state": InviteState.REVOKED.value,
                    "remaining_uses": 0,
                    "revoked_reason": " ",
                },
                "non-empty revoked_reason",
            ),
            ({"usage_log": None}, "usage_log"),
            ({"lifecycle": None}, "lifecycle"),
            ({"usage_log": "not-a-list"}, "usage_log"),
        ]

        for overrides, fragment in cases:
            with self.subTest(overrides=overrides):
                record = base(**overrides)
                with self.assertRaises(InviteRecordError) as ctx:
                    InviteCode.from_record(record)
                self.assertIn(fragment, str(ctx.exception))

        with self.subTest(case="missing_key"):
            row = base()
            del row["max_use_count"]
            with self.assertRaises(InviteRecordError) as ctx:
                InviteCode.from_record(row)
            self.assertIn("missing keys", str(ctx.exception))

        with self.subTest(case="not_object"):
            with self.assertRaises(InviteRecordError):
                InviteCode.from_record([])  # type: ignore[arg-type]


class InviteManagerEdgeTests(unittest.TestCase):
    def _future_expiry(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(hours=2)

    def test_validate_unknown_code_masks(self) -> None:
        mgr = InviteManager()
        result = mgr.validate("ZZZZZZZZZZZZ")
        self.assertFalse(result.usable)
        self.assertEqual(result.reason, "not found")
        self.assertIsNone(result.state)

    def test_use_unknown_raises(self) -> None:
        with self.assertRaises(InviteNotFoundError):
            InviteManager().use("MISSINGCODE1")

    def test_list_codes_filter_enum_and_string(self) -> None:
        mgr = InviteManager()
        a = mgr.generate("a", 1, 1, self._future_expiry())
        b = mgr.generate("b", 1, 1, self._future_expiry() + timedelta(hours=1), auto_activate=False)
        self.assertEqual(a.state, InviteState.ACTIVE)
        self.assertEqual(b.state, InviteState.GENERATED)
        active_only = mgr.list_codes(filter_by_state=InviteState.ACTIVE)
        self.assertEqual(len(active_only), 1)
        self.assertEqual(active_only[0].masked_code, a.masked_code)
        str_filter = mgr.list_codes(filter_by_state="generated")
        self.assertEqual(len(str_filter), 1)
        self.assertEqual(str_filter[0].masked_code, b.masked_code)

    def test_from_record_store_validation_errors(self) -> None:
        with self.assertRaises(InviteRecordError):
            InviteManager.from_record([])  # type: ignore[arg-type]
        with self.assertRaises(InviteRecordError):
            InviteManager.from_record({"version": 99, "codes": []})
        with self.assertRaises(InviteRecordError):
            InviteManager.from_record({"version": 1, "codes": None})
        with self.assertRaises(InviteRecordError):
            InviteManager.from_record({"version": 1, "codes": "nope"})
        with self.assertRaises(InviteRecordError):
            InviteManager.from_record({"version": 1, "codes": [1, 2]})

    def test_generate_runtime_error_when_exhausting_random_attempts(self) -> None:
        mgr = InviteManager()
        fixed = "A" * 12
        mgr._codes[fixed] = InviteCode(
            fixed,
            "seed",
            0,
            1,
            self._future_expiry(),
            state=InviteState.ACTIVE,
        )
        with patch("invites.manager.secrets.choice", return_value="A"):
            with self.assertRaises(RuntimeError):
                mgr.generate("x", 0, 1, self._future_expiry())


class StoreEdgeTests(unittest.TestCase):
    def test_load_missing_file_returns_empty_manager(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "missing.json"
            self.assertFalse(path.exists())
            mgr = load_manager(path)
            self.assertEqual(len(mgr.list_codes()), 0)

    def test_load_blank_file_returns_empty_manager(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "empty.json"
            path.write_text("   \n  ", encoding="utf-8")
            mgr = load_manager(path)
            self.assertEqual(len(mgr.list_codes()), 0)

    def test_load_non_object_root_raises_store_error(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "arr.json"
            path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
            with self.assertRaises(StoreError):
                load_manager(path)

    def test_atomic_write_cleans_temp_when_replace_fails(self) -> None:
        mgr = InviteManager()
        mgr.generate("a", 0, 1, datetime.now(timezone.utc) + timedelta(hours=1))
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "store.json"
            with patch("invites.store.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    save_manager(mgr, target)
            leftovers = list(Path(d).glob(".store.json.*.tmp"))
            self.assertEqual(leftovers, [])

    def test_atomic_write_suppresses_errors_during_cleanup(self) -> None:
        mgr = InviteManager()
        mgr.generate("a", 0, 1, datetime.now(timezone.utc) + timedelta(hours=1))
        real_unlink = Path.unlink

        def unlink_wrapper(self: Path, *args: object, **kwargs: object) -> None:
            if str(self).endswith(".tmp"):
                raise OSError("unlink failed")
            return real_unlink(self, *args, **kwargs)

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            target = Path(d) / "store.json"
            with patch("invites.store.os.replace", side_effect=OSError("replace failed")):
                with patch.object(Path, "unlink", unlink_wrapper):
                    with self.assertRaises(OSError) as ctx:
                        save_manager(mgr, target)
                    self.assertIn("replace", str(ctx.exception).lower())

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            target = Path(d) / "store.json"
            with patch("invites.store.os.fdopen", side_effect=OSError("fdopen failed")):
                with patch("invites.store.os.close", side_effect=OSError("close failed")):
                    with self.assertRaises(OSError) as ctx:
                        save_manager(mgr, target)
                    self.assertIn("fdopen", str(ctx.exception).lower())


class CliCommandTests(unittest.TestCase):
    def _store(self, temp_dir: str) -> Path:
        return Path(temp_dir) / "cli_store.json"

    def test_build_parser_help_exits_zero(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_cli_generate_expires_at_and_inactive(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            exp = (datetime.now(timezone.utc) + timedelta(hours=3)).replace(microsecond=0)
            argv = [
                "--store",
                str(store),
                "generate",
                "--creator-id",
                "c",
                "--access-level",
                "2",
                "--max-uses",
                "1",
                "--expires-at",
                exp.isoformat(),
                "--inactive",
            ]
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(argv), 0)
            payload = json.loads(store.read_text(encoding="utf-8"))
            self.assertEqual(payload["codes"][0]["state"], InviteState.GENERATED.value)

    def test_cli_validate_use_revoke_list_audit(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(
                    main(
                        [
                            "--store",
                            str(store),
                            "generate",
                            "--creator-id",
                            "c",
                            "--access-level",
                            "1",
                            "--max-uses",
                            "2",
                            "--expires-in-hours",
                            "4",
                            "--show-code",
                        ]
                    ),
                    0,
                )
            full = json.loads(store.read_text(encoding="utf-8"))["codes"][0]["code_string"]

            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "validate", full]), 0)

            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "use", full]), 0)

            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(
                    main(
                        ["--store", str(store), "revoke", full, "--reason", "done"]
                    ),
                    0,
                )

            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "list"]), 0)
                self.assertIn("REVOKED", stdout.getvalue())

            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "list", "--state", "REVOKED"]), 0)
                self.assertIn("Code:", stdout.getvalue())

            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "audit", full]), 0)
                out = stdout.getvalue()
                self.assertIn("Lifecycle:", out)
                self.assertIn("Usage log:", out)

    def test_cli_audit_prints_empty_usage_log_branch(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(
                    main(
                        [
                            "--store",
                            str(store),
                            "generate",
                            "--creator-id",
                            "c",
                            "--access-level",
                            "1",
                            "--max-uses",
                            "1",
                            "--expires-in-hours",
                            "2",
                            "--show-code",
                        ]
                    ),
                    0,
                )
            full = json.loads(store.read_text(encoding="utf-8"))["codes"][0]["code_string"]
            stdout.seek(0)
            stdout.truncate(0)
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "audit", full]), 0)
            self.assertIn("No use attempts recorded.", stdout.getvalue())

    def test_cli_list_empty_store(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            store.write_text(json.dumps({"version": 1, "codes": []}), encoding="utf-8")
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "list"]), 0)
            self.assertIn("No invite codes found.", stdout.getvalue())

    def test_cli_validate_unknown_code_exits_nonzero(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            store.write_text(json.dumps({"version": 1, "codes": []}), encoding="utf-8")
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "validate", "ZZZZZZZZZZZZ"]), 1)

    def test_cli_main_load_failure_returns_one(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{", encoding="utf-8")
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(bad), "list"]), 1)

    def test_cli_use_missing_code_still_saves_store(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            store.write_text(json.dumps({"version": 1, "codes": []}), encoding="utf-8")
            with patch.object(sys, "stdout", stdout), patch.object(sys, "stderr", stderr):
                self.assertEqual(main(["--store", str(store), "use", "ZZZZZZZZZZZZ"]), 1)
            self.assertTrue(store.exists())

    def test_resolve_expiry_and_format_datetime(self) -> None:
        naive = datetime(2030, 1, 2, 3, 4, 5)
        resolved = _resolve_expiry(naive.isoformat(), None)
        self.assertIsNotNone(resolved.tzinfo)
        self.assertIn("T", _format_datetime(resolved))
        with self.assertRaises(ValueError):
            _resolve_expiry(None, 0.0)

    def test_dispatch_unknown_command_raises(self) -> None:
        mgr = InviteManager()
        args = Mock(command="nope")
        with self.assertRaises(ValueError):
            _dispatch(args, mgr)


class ModuleSmokeTests(unittest.TestCase):
    def test_public_exports_are_importable(self) -> None:
        import invites as pkg

        for name in invites_exports:
            self.assertTrue(hasattr(pkg, name), f"missing export: {name}")

    def test_python_m_invites_help(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "invites", "--help"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("generate", proc.stdout)


if __name__ == "__main__":
    unittest.main()
