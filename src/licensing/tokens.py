"""License key token format.

A license key is a compact two-part string:

    base64url(payload_json) . base64url(signature)

This mirrors the JWT shape but is deliberately minimal. The exact payload bytes
that were signed are what get base64-encoded, so the validator verifies the
signature against those same bytes rather than re-serialising (which could
differ and cause spurious failures).
"""

from __future__ import annotations

import base64
import json


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_bytes(payload: dict) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace.

    Two payloads with the same content always produce identical bytes, which is
    what makes signing and verification stable.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encode_token(payload_bytes: bytes, signature: bytes) -> str:
    """Combine signed payload bytes and signature into a license key string."""
    return f"{_b64encode(payload_bytes)}.{_b64encode(signature)}"


def decode_token(token: str) -> tuple[bytes, bytes]:
    """Split a license key back into (payload_bytes, signature).

    Raises ValueError on a malformed token.
    """
    parts = token.strip().split(".")
    if len(parts) != 2:
        raise ValueError("token must have exactly two parts")
    payload_bytes = _b64decode(parts[0])
    signature = _b64decode(parts[1])
    return payload_bytes, signature
