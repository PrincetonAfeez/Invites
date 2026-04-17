
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

