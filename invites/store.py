from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .manager import InviteManager
from .models import InviteRecordError


DEFAULT_STORE_PATH = Path("invites_store.json")

class StoreError(Exception):
    """Raised when the invite store file cannot be read or written safely."""
