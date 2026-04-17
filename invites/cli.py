
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from .manager import InviteManager
from .models import InviteError, InviteState, normalize_datetime
from .store import DEFAULT_STORE_PATH, StoreError, load_manager, save_manager

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m invites",
        description="Generate, validate, and audit Vault OS invite codes.",
    )
    parser.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE_PATH,
        help="Path to the JSON store file used by the CLI.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate", help="Generate a new invite code.")
    generate_parser.add_argument("--creator-id", required=True, help="ID of the code creator.")
    generate_parser.add_argument(
        "--access-level",
        type=int,
        required=True,
        help="Required access level for the invite.",
    )
    generate_parser.add_argument(
        "--max-uses",
        type=int,
        required=True,
        help="Maximum number of successful uses allowed.",
    )
    expiry_group = generate_parser.add_mutually_exclusive_group(required=True)
    expiry_group.add_argument(
        "--expires-at",
        help="ISO-8601 timestamp. Naive timestamps are treated as local time.",
    )
    expiry_group.add_argument(
        "--expires-in-hours",
        type=float,
        help="Number of hours from now until the invite expires.",
    )
    generate_parser.add_argument(
        "--inactive",
        action="store_true",
        help="Leave the code in GENERATED instead of activating it immediately.",
    )
    generate_parser.add_argument(
        "--show-code",
        action="store_true",
        help="Print the full invite code once to stderr (default output is masked only).",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate an invite code.")
    validate_parser.add_argument("code", help="Full invite code string.")

    use_parser = subparsers.add_parser("use", help="Use an invite code once.")
    use_parser.add_argument("code", help="Full invite code string.")

    revoke_parser = subparsers.add_parser("revoke", help="Revoke an invite code.")
    revoke_parser.add_argument("code", help="Full invite code string.")
    revoke_parser.add_argument("--reason", required=True, help="Reason for revocation.")

    list_parser = subparsers.add_parser("list", help="List invite codes.")
    list_parser.add_argument(
        "--state",
        choices=[state.value for state in InviteState],
        help="Filter the list by state.",
    )

    audit_parser = subparsers.add_parser("audit", help="Show the lifecycle for one invite.")
    audit_parser.add_argument("code", help="Full invite code string.")

    return parser

def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        manager = load_manager(args.store)
    except StoreError as exc:
        print(f"Error: {exc}")
        return 1

    try:
        exit_code = _dispatch(args, manager)
    except (InviteError, ValueError) as exc:
        save_manager(manager, args.store)
        print(f"Error: {exc}")
        return 1

    save_manager(manager, args.store)
    return exit_code

def _dispatch(args: argparse.Namespace, manager: InviteManager) -> int:
    if args.command == "generate":
        invite = manager.generate(
            creator_id=args.creator_id,
            required_access_level=args.access_level,
            max_use_count=args.max_uses,
            expires_at=_resolve_expiry(args.expires_at, args.expires_in_hours),
            auto_activate=not args.inactive,
        )
        print(f"Generated invite (masked): {invite.masked_code}")
        if args.show_code:
            print(invite.code_string, file=sys.stderr)
            print("(Full code printed once to stderr.)", file=sys.stderr)
        else:
            print("Full code is not printed. Re-run with --show-code to print it once to stderr.")
        print(f"State: {invite.state.value}")
        print(f"Creator ID: {invite.creator_id}")
        print(f"Required access level: {invite.required_access_level}")
        print(f"Remaining uses: {invite.remaining_uses}/{invite.max_use_count}")
        print(f"Expires at: {_format_datetime(invite.expires_at)}")
        return 0

    if args.command == "validate":
        result = manager.validate(args.code)
        print(f"Code: {result.masked_code}")
        print(f"Usable: {'yes' if result.usable else 'no'}")
        print(f"State: {result.state.value if result.state else 'NOT_FOUND'}")
        if result.reason:
            print(f"Reason: {result.reason}")
        if result.remaining_uses is not None:
            print(f"Remaining uses: {result.remaining_uses}")
        if result.expires_at is not None:
            print(f"Expires at: {_format_datetime(result.expires_at)}")
        return 0 if result.usable else 1

    if args.command == "use":
        manager.use(args.code)
        audit = manager.audit(args.code)
        print(f"Invite {audit.masked_code} used successfully.")
        print(f"State: {audit.state.value}")
        print(f"Remaining uses: {audit.remaining_uses}")
        return 0

    if args.command == "revoke":
        manager.revoke(args.code, args.reason)
        audit = manager.audit(args.code)
        print(f"Invite {audit.masked_code} revoked.")
        print(f"Reason: {audit.revoked_reason}")
        print(f"State: {audit.state.value}")
        return 0

    if args.command == "list":
        summaries = manager.list_codes(filter_by_state=args.state)
        if not summaries:
            print("No invite codes found.")
            return 0
        for summary in summaries:
            print(f"Code: {summary.masked_code}")
            print(f"  Creator ID: {summary.creator_id}")
            print(f"  Access level: {summary.required_access_level}")
            print(f"  State: {summary.state.value}")
            print(f"  Remaining uses: {summary.remaining_uses}/{summary.max_use_count}")
            print(f"  Expires at: {_format_datetime(summary.expires_at)}")
            if summary.revoked_reason:
                print(f"  Revoked reason: {summary.revoked_reason}")
        return 0

    if args.command == "audit":
        audit = manager.audit(args.code)
        print(f"Invite: {audit.masked_code}")
        print(f"Creator ID: {audit.creator_id}")
        print(f"State: {audit.state.value}")
        print(f"Access level: {audit.required_access_level}")
        print(f"Remaining uses: {audit.remaining_uses}/{audit.max_use_count}")
        print(f"Expires at: {_format_datetime(audit.expires_at)}")
        if audit.revoked_reason:
            print(f"Revoked reason: {audit.revoked_reason}")
        print("Lifecycle:")
        for event in audit.lifecycle:
            print(f"  - {_format_datetime(event.timestamp)} | {event.event} | {event.detail}")
        print("Usage log:")
        if audit.usage_log:
            for entry in audit.usage_log:
                print(
                    f"  - {_format_datetime(entry.timestamp)} | "
                    f"{entry.outcome.value} | {entry.detail}"
                )
        else:
            print("  - No use attempts recorded.")
        return 0

    raise ValueError(f"Unknown command: {args.command}")
