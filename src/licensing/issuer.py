"""License issuer.

Holds the private key and mints signed license tokens. In a real deployment
this runs server-side only (e.g. behind a purchase webhook); the private key
never leaves the issuing environment.
"""

from __future__ import annotations

from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import License, Tier
from .tokens import canonical_bytes, encode_token


class Issuer:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    def issue(
        self,
        *,
        product: str,
        tier: Tier,
        hwid: str,
        features: list[str] | None = None,
        now: datetime | None = None,
    ) -> str:
        """Build, sign and encode a license bound to a specific HWID.

        Returns the license key string the end user would activate with.
        """
        license_ = License.build(
            product=product, tier=tier, hwid=hwid, features=features, now=now
        )
        payload_bytes = canonical_bytes(license_.to_dict())
        signature = self._private_key.sign(payload_bytes)
        return encode_token(payload_bytes, signature)
