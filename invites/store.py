""" Store for the invites package. """

# Enable postponed evaluation of annotations to allow using types not yet fully defined
from __future__ import annotations

# Import the standard JSON library for parsing and serializing data structures
import json
# Import the OS module for low-level file descriptor operations and file system interaction
import os
# Import tempfile to create secure, unique temporary files for atomic write operations
import tempfile
# Import Path from pathlib for object-oriented filesystem path manipulations
from pathlib import Path
# Import Any for flexible type hinting where specific structures are unknown
from typing import Any

# Import InviteManager to handle the collection of invite codes in memory
from .manager import InviteManager
# Import InviteRecordError to catch data validation issues during the loading process
from .models import InviteRecordError


# Define the standard filename used for persistence if no specific path is provided
DEFAULT_STORE_PATH = Path("invites_store.json")


# Custom exception class for errors specifically related to file I/O or storage integrity
class StoreError(Exception):
    """Raised when the invite store file cannot be read or written safely."""


# Main function to initialize an InviteManager by reading data from a physical file
def load_manager(path: str | Path = DEFAULT_STORE_PATH) -> InviteManager:
    # Convert the input string or path into a Path object for consistent manipulation
    file_path = Path(path)
    # If the file does not exist yet, return a fresh, empty InviteManager instance
    if not file_path.exists():
        return InviteManager()

    # Read the entire contents of the file into a string using UTF-8 encoding
    raw_text = file_path.read_text(encoding="utf-8")
    # If the file exists but is empty or contains only whitespace, return an empty manager
    if not raw_text.strip():
        return InviteManager()

    try:
        # Attempt to decode the raw text string into a Python data structure
        payload: Any = json.loads(raw_text)
    # Catch errors resulting from malformed JSON syntax in the storage file
    except json.JSONDecodeError as exc:
        raise StoreError(f"Invite store is not valid JSON ({file_path}): {exc}") from exc

    # Ensure the top-level JSON structure is a dictionary (JSON object)
    if not isinstance(payload, dict):
        raise StoreError(f"Invite store root must be a JSON object ({file_path}).")

    try:
        # Use the InviteManager's internal logic to reconstruct objects from the record
        return InviteManager.from_record(payload)
    # Catch errors where the JSON is valid but the data violates business rules
    except InviteRecordError as exc:
        raise StoreError(f"Invite store failed validation ({file_path}): {exc}") from exc


# Main function to persist the current state of an InviteManager back to a file
def save_manager(manager: InviteManager, path: str | Path = DEFAULT_STORE_PATH) -> None:
    # Convert the destination into a Path object
    file_path = Path(path)
    # Ensure all parent directories in the path exist, creating them if necessary
    file_path.parent.mkdir(parents=True, exist_ok=True)
    # Convert the manager state to a JSON string with 2-space indentation and a trailing newline
    serialized = json.dumps(manager.to_record(), indent=2) + "\n"
    # Use the internal atomic write helper to ensure data isn't corrupted during a crash
    _atomic_write_text(file_path, serialized)


# Low-level helper to write data to a temporary file before moving it to the final destination
def _atomic_write_text(file_path: Path, text: str) -> None:
    """Write UTF-8 text to ``file_path`` using a temp file and atomic replace."""
    # Identify the parent directory where the temporary file should be staged
    directory = file_path.parent
    # Initialize the file descriptor and path variables for cleanup tracking
    fd: int | None = None
    tmp_path: Path | None = None
    try:
        # Create a temporary file in the same directory to ensure it is on the same filesystem partition
        fd, tmp_name = tempfile.mkstemp(
            dir=directory,
            prefix=f".{file_path.name}.", # Use the original filename as a prefix for visibility
            suffix=".tmp", # Use a .tmp suffix to identify staging files
        )
        # Store the path of the newly created temporary file
        tmp_path = Path(tmp_name)
        # Open the file descriptor for writing with UTF-8 encoding
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # Clear the file descriptor variable as the handle now manages it
            fd = None
            # Write the serialized text to the file buffer
            handle.write(text)
            # Ensure the data is moved from Python's internal buffer to the OS buffer
            handle.flush()
            # Force the OS to synchronize the file's state with the physical storage device
            os.fsync(handle.fileno())
        # Atomically replace the target file with the temporary one (preventing partial writes)
        os.replace(tmp_path, file_path)
        # Reset tmp_path to None to indicate the file has been successfully moved
        tmp_path = None
    finally:
        # If an error occurred and the file descriptor is still open, close it
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        # If an error occurred and a temporary file still exists, delete it
        if tmp_path is not None:
            try:
                # Silently attempt to remove the leftover temporary file
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass