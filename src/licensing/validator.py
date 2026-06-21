"""License validator.

Runs client-side with only the public key. Validation order is deliberate:
the signature is verified before any field of the payload is trusted, because
an unsigned or tampered payload should never be read as authoritative. Only
after the signature passes do we check revocation, HWID binding and expiry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .tokens import decode_token


class Status(str, Enum):
    VALID = "valid"
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    REVOKED = "revoked"
    HWID_MISMATCH = "hwid_mismatch"
    EXPIRED = "expired"


@dataclass
class ValidationResult:
    status: Status
    license: dict | None = None

    @property
    def ok(self) -> bool:
        return self.status == Status.VALID

    @property
    def reason(self) -> str:
        return {
            Status.VALID: "License is valid.",
            Status.MALFORMED: "License key is malformed.",
            Status.BAD_SIGNATURE: "Signature does not verify; license is forged or corrupted.",
            Status.REVOKED: "License has been revoked.",
            Status.HWID_MISMATCH: "License is bound to a different machine.",
            Status.EXPIRED: "License has expired.",
        }[self.status]


class Validator:
    def __init__(
        self,
        public_key: Ed25519PublicKey,
        revoked_ids: set[str] | None = None,
    ):
        self._public_key = public_key
        self._revoked = set(revoked_ids or set())

    def validate(
        self,
        token: str,
        current_hwid: str,
        now: datetime | None = None,
    ) -> ValidationResult:
        now = now or datetime.now(timezone.utc)

        # 1. Decode. A token that will not split/decode is malformed.
        try:
            payload_bytes, signature = decode_token(token)
        except Exception:
            return ValidationResult(Status.MALFORMED)

        # 2. Verify the signature BEFORE trusting any field.
        try:
            self._public_key.verify(signature, payload_bytes)
        except InvalidSignature:
            return ValidationResult(Status.BAD_SIGNATURE)

        # 3. Parse the now-trusted payload.
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError:
            return ValidationResult(Status.MALFORMED)

        # 4. Revocation: a signed but revoked license is dead.
        if payload.get("license_id") in self._revoked:
            return ValidationResult(Status.REVOKED, payload)

        # 5. HWID binding: must match the machine validating.
        if payload.get("hwid") != current_hwid:
            return ValidationResult(Status.HWID_MISMATCH, payload)

        # 6. Expiry: null expires_at means lifetime.
        expires_at = payload.get("expires_at")
        if expires_at is not None:
            try:
                expiry = datetime.fromisoformat(expires_at)
            except (ValueError, TypeError):
                return ValidationResult(Status.MALFORMED, payload)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry < now:
                return ValidationResult(Status.EXPIRED, payload)

        return ValidationResult(Status.VALID, payload)
