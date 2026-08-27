"""Opaque cursors for stable keyset pagination.

api.md s5 requires "a bounded ``limit`` and an opaque cursor derived from a
deterministic sort key; offset pagination is not part of the public contract".
The reason is correctness, not taste: evidence is appended throughout an
investigation, and under ``LIMIT``/``OFFSET`` a row inserted between two page
fetches shifts every later row, so a client silently misses observations and
sees others twice.

A cursor is opaque so that the sort key can change without becoming a
compatibility problem. It is base64 of a JSON array, which is deliberately not
encryption: it carries no authority and nothing secret, only the position of a
row the caller has already been shown.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Sequence
from typing import Any

from acip.errors import ValidationError


def encode_cursor(values: Sequence[Any]) -> str:
    """Encode a sort-key tuple as an opaque cursor."""
    raw = json.dumps(list(values), separators=(",", ":"), default=str)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str, *, expected_length: int) -> list[Any]:
    """Decode an opaque cursor, rejecting anything malformed.

    A bad cursor is a client error, not a reason to fall back to the first page:
    silently restarting pagination is how a caller ends up with duplicates and
    no indication anything went wrong.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValidationError("malformed pagination cursor") from exc

    if not isinstance(values, list) or len(values) != expected_length:
        raise ValidationError("pagination cursor does not match this endpoint's sort key")
    return values
