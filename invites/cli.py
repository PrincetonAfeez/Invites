""" CLI for the invites package. """

# Enable postponed evaluation of annotations to support self-referencing types and modern type hinting
from __future__ import annotations

# Import argparse to handle command-line argument parsing with built-in help and validation
import argparse
# Import sys to gain access to system-specific parameters and standard streams like stderr
import sys
# Import datetime and timedelta to manage time-based logic like expiration dates and offsets
from datetime import datetime, timedelta
# Import Path for robust, cross-platform filesystem path manipulation
from pathlib import Path
# Import Iterable to define type hints for collections that can be looped over
from typing import Iterable

# Import the InviteManager which serves as the central orchestration point for the domain logic
from .manager import InviteManager
# Import domain models and utilities for state management, error handling, and time normalization
from .models import InviteError, InviteState, normalize_datetime
# Import storage utilities and constants for reading/writing the JSON database file
from .store import DEFAULT_STORE_PATH, StoreError, load_manager, save_manager


# Define a function to configure the command-line interface structure and arguments
def build_parser() -> argparse.ArgumentParser:
    # Initialize the main parser with the program name and a high-level description
    parser = argparse.ArgumentParser(
        prog="python -m invites",
        description="Generate, validate, and audit Vault OS invite codes.",
    )
    # Add a global flag to specify a custom location for the JSON database file
    parser.add_argument(
        "--store",
        type=Path,
        default=DEFAULT_STORE_PATH,
        help="Path to the JSON store file used by the CLI.",
    )

    # Create a subparser group to handle different operational modes (generate, validate, etc.)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Configure the 'generate' command for creating new invite entries
    generate_parser = subparsers.add_parser("generate", help="Generate a new invite code.")
    # Require an ID for the user or service creating the invitation
    generate_parser.add_argument("--creator-id", required=True, help="ID of the code creator.")
    # Require a numeric access level to define the permissions granted by this code
    generate_parser.add_argument(
        "--access-level",
        type=int,
        required=True,
        help="Required access level for the invite.",
    )
    # Require the maximum number of times this specific code can be used
    generate_parser.add_argument(
        "--max-uses",
        type=int,
        required=True,
        help="Maximum number of successful uses allowed.",
    )
    # Ensure the user provides either an absolute timestamp or a relative hour offset, but not both
    expiry_group = generate_parser.add_mutually_exclusive_group(required=True)
    # Add option for a specific ISO-8601 date and time string
    expiry_group.add_argument(
        "--expires-at",
        help="ISO-8601 timestamp. Naive timestamps are treated as local time.",
    )
    # Add option for a floating-point number representing hours from the current moment
    expiry_group.add_argument(
        "--expires-in-hours",
        type=float,
        help="Number of hours from now until the invite expires.",
    )
    # Add a toggle to prevent the code from becoming 'ACTIVE' immediately upon generation
    generate_parser.add_argument(
        "--inactive",
        action="store_true",
        help="Leave the code in GENERATED instead of activating it immediately.",
    )
    # Add a toggle to display the raw sensitive code to stderr for the user to copy
    generate_parser.add_argument(
        "--show-code",
        action="store_true",
        help="Print the full invite code once to stderr (default output is masked only).",
    )

    # Configure the 'validate' command to check if a provided code is currently usable
    validate_parser = subparsers.add_parser("validate", help="Validate an invite code.")
    # Accept the raw invite code string as a positional argument
    validate_parser.add_argument("code", help="Full invite code string.")

    # Configure the 'use' command to consume one usage count from a code
    use_parser = subparsers.add_parser("use", help="Use an invite code once.")
    # Accept the raw invite code string as a positional argument
    use_parser.add_argument("code", help="Full invite code string.")

    # Configure the 'revoke' command to manually cancel an invite code
    revoke_parser = subparsers.add_parser("revoke", help="Revoke an invite code.")
    # Accept the raw invite code string as a positional argument
    revoke_parser.add_argument("code", help="Full invite code string.")
    # Require a human-readable reason for the revocation for the audit log
    revoke_parser.add_argument("--reason", required=True, help="Reason for revocation.")

    # Configure the 'list' command to display all known invite codes
    list_parser = subparsers.add_parser("list", help="List invite codes.")
    # Allow filtering the list by specific lifecycle states (e.g., ACTIVE, EXPIRED)
    list_parser.add_argument(
        "--state",
        choices=[state.value for state in InviteState],
        help="Filter the list by state.",
    )

    # Configure the 'audit' command to show the full history and usage of a code
    audit_parser = subparsers.add_parser("audit", help="Show the lifecycle for one invite.")
    # Accept the raw invite code string as a positional argument
    audit_parser.add_argument("code", help="Full invite code string.")

    # Return the fully configured parser object
    return parser


# Define the entry point for the CLI application
def main(argv: Iterable[str] | None = None) -> int:
    # Build the argument parser instance
    parser = build_parser()
    # Parse the provided arguments (or system arguments if none provided)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        # Attempt to initialize the manager by loading the JSON database
        manager = load_manager(args.store)
    # Handle failures in reading or parsing the store file gracefully
    except StoreError as exc:
        print(f"Error: {exc}")
        return 1

    try:
        # Route the parsed command to the appropriate logic handler
        exit_code = _dispatch(args, manager)
    # Handle domain-specific validation or state errors and ensure data is saved
    except (InviteError, ValueError) as exc:
        # Save any changes made before the error occurred
        save_manager(manager, args.store)
        print(f"Error: {exc}")
        return 1

    # Persist the final state of the manager back to the JSON database
    save_manager(manager, args.store)
    # Return the status code determined by the command execution
    return exit_code


# Internal helper to execute logic based on the chosen sub-command
def _dispatch(args: argparse.Namespace, manager: InviteManager) -> int:
    # Logic path for generating a new invitation
    if args.command == "generate":
        # Call the manager to create a new invite with the specified parameters
        invite = manager.generate(
            creator_id=args.creator_id,
            required_access_level=args.access_level,
            max_use_count=args.max_uses,
            expires_at=_resolve_expiry(args.expires_at, args.expires_in_hours),
            auto_activate=not args.inactive,
        )
        # Inform the user of the masked version of the code for their records
        print(f"Generated invite (masked): {invite.masked_code}")
        # If requested, output the sensitive plaintext code to stderr
        if args.show_code:
            print(invite.code_string, file=sys.stderr)
            print("(Full code printed once to stderr.)", file=sys.stderr)
        # Otherwise, explain how to view the full code for security purposes
        else:
            print("Full code is not printed. Re-run with --show-code to print it once to stderr.")
        # Print relevant metadata about the newly created invite
        print(f"State: {invite.state.value}")
        print(f"Creator ID: {invite.creator_id}")
        print(f"Required access level: {invite.required_access_level}")
        print(f"Remaining uses: {invite.remaining_uses}/{invite.max_use_count}")
        print(f"Expires at: {_format_datetime(invite.expires_at)}")
        return 0

    # Logic path for validating an existing invitation
    if args.command == "validate":
        # Check the validity of the provided code string
        result = manager.validate(args.code)
        # Display the results of the validation check
        print(f"Code: {result.masked_code}")
        print(f"Usable: {'yes' if result.usable else 'no'}")
        print(f"State: {result.state.value if result.state else 'NOT_FOUND'}")
        # Provide the reason for failure if the code is not usable
        if result.reason:
            print(f"Reason: {result.reason}")
        # Show remaining usage counts if the code was found
        if result.remaining_uses is not None:
            print(f"Remaining uses: {result.remaining_uses}")
        # Show the expiration timestamp if the code was found
        if result.expires_at is not None:
            print(f"Expires at: {_format_datetime(result.expires_at)}")
        # Return success (0) only if the code is usable, otherwise failure (1)
        return 0 if result.usable else 1

    # Logic path for consuming an invitation
    if args.command == "use":
        # Execute the usage logic within the manager
        manager.use(args.code)
        # Retrieve the updated audit data to show the current state
        audit = manager.audit(args.code)
        # Print confirmation and updated stats
        print(f"Invite {audit.masked_code} used successfully.")
        print(f"State: {audit.state.value}")
        print(f"Remaining uses: {audit.remaining_uses}")
        return 0

    # Logic path for revoking an invitation
    if args.command == "revoke":
        # Instruct the manager to revoke the code with the provided reason
        manager.revoke(args.code, args.reason)
        # Retrieve audit data to verify the change
        audit = manager.audit(args.code)
        # Print confirmation of revocation
        print(f"Invite {audit.masked_code} revoked.")
        print(f"Reason: {audit.revoked_reason}")
        print(f"State: {audit.state.value}")
        return 0

    # Logic path for listing all codes in the system
    if args.command == "list":
        # Fetch the summaries from the manager, applying any state filter provided
        summaries = manager.list_codes(filter_by_state=args.state)
        # Handle the case where no matching codes were found
        if not summaries:
            print("No invite codes found.")
            return 0
        # Iterate through and print formatted details for each summary
        for summary in summaries:
            print(f"Code: {summary.masked_code}")
            print(f"  Creator ID: {summary.creator_id}")
            print(f"  Access level: {summary.required_access_level}")
            print(f"  State: {summary.state.value}")
            print(f"  Remaining uses: {summary.remaining_uses}/{summary.max_use_count}")
            print(f"  Expires at: {_format_datetime(summary.expires_at)}")
            # Show the reason if this specific code was revoked
            if summary.revoked_reason:
                print(f"  Revoked reason: {summary.revoked_reason}")
        return 0

    # Logic path for auditing a specific code's history
    if args.command == "audit":
        # Fetch the comprehensive audit record for the code
        audit = manager.audit(args.code)
        # Print general metadata and current status
        print(f"Invite: {audit.masked_code}")
        print(f"Creator ID: {audit.creator_id}")
        print(f"State: {audit.state.value}")
        print(f"Access level: {audit.required_access_level}")
        print(f"Remaining uses: {audit.remaining_uses}/{audit.max_use_count}")
        print(f"Expires at: {_format_datetime(audit.expires_at)}")
        # Print the revocation reason if applicable
        if audit.revoked_reason:
            print(f"Revoked reason: {audit.revoked_reason}")
        # Display the chronological sequence of lifecycle events
        print("Lifecycle:")
        for event in audit.lifecycle:
            print(f"  - {_format_datetime(event.timestamp)} | {event.event} | {event.detail}")
        # Display the chronological history of usage attempts
        print("Usage log:")
        if audit.usage_log:
            for entry in audit.usage_log:
                print(
                    f"  - {_format_datetime(entry.timestamp)} | "
                    f"{entry.outcome.value} | {entry.detail}"
                )
        # Handle the case where the code has never been used
        else:
            print("  - No use attempts recorded.")
        return 0

    # Fallback to catch internal logic errors regarding command dispatching
    raise ValueError(f"Unknown command: {args.command}")


# Internal helper to calculate a datetime object from CLI inputs
def _resolve_expiry(expires_at: str | None, expires_in_hours: float | None) -> datetime:
    # If an absolute timestamp was provided, parse it directly
    if expires_at is not None:
        parsed = datetime.fromisoformat(expires_at)
        # If the user didn't provide a timezone, assume local system time
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        # Ensure the final timestamp is normalized to UTC
        return normalize_datetime(parsed)

    # If a relative hour offset was provided, ensure it is positive
    if expires_in_hours is None or expires_in_hours <= 0:
        raise ValueError("expires-in-hours must be greater than 0.")
    # Calculate the future time and normalize it to UTC
    return normalize_datetime(datetime.now().astimezone() + timedelta(hours=expires_in_hours))


# Internal helper to consistently format datetime objects as ISO-8601 strings
def _format_datetime(value: datetime) -> str:
    # Normalize the value to UTC and return its string representation
    return normalize_datetime(value).isoformat()