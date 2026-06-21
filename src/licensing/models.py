"""License model and tiers.

A license is a small, signed payload. Tiers map to durations; LIFETIME never
expires. The model stays serialisation-agnostic: turning it into signed token
bytes lives in tokens.py, and signing lives in issuer.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from uuid import uuid4


class Tier(str, Enum):
    TRIAL = "trial"
    BASIC = "basic"
    PREMIUM = "premium"
    LIFETIME = "lifetime"


# Duration per tier in days. None means it never expires.
TIER_DURATION_DAYS: dict[Tier, int | None] = {
    Tier.TRIAL: 7,
    Tier.BASIC: 30,
    Tier.PREMIUM: 90,
    Tier.LIFETIME: None,
}


@dataclass
class License:
    """The data that gets signed. Field order does not matter; signing uses a
    canonical (sorted-key) form so the same content always signs identically."""

    license_id: str
    product: str
    tier: str
    hwid: str
    issued_at: str
    expires_at: str | None
    features: list[str] = field(default_factory=list)

    @staticmethod
    def build(
        *,
        product: str,
        tier: Tier,
        hwid: str,
        features: list[str] | None = None,
        now: datetime | None = None,
    ) -> "License":
        """Construct a license, computing expiry from the tier."""
        now = now or datetime.now(timezone.utc)
        duration = TIER_DURATION_DAYS[tier]
        expires_at = None if duration is None else (now + timedelta(days=duration)).isoformat()
        return License(
            license_id=str(uuid4()),
            product=product,
            tier=tier.value,
            hwid=hwid,
            issued_at=now.isoformat(),
            expires_at=expires_at,
            features=features or [],
        )

    def to_dict(self) -> dict:
        return {
            "license_id": self.license_id,
            "product": self.product,
            "tier": self.tier,
            "hwid": self.hwid,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "features": list(self.features),
        }

    @staticmethod
    def from_dict(d: dict) -> "License":
        return License(
            license_id=d["license_id"],
            product=d["product"],
            tier=d["tier"],
            hwid=d["hwid"],
            issued_at=d["issued_at"],
            expires_at=d.get("expires_at"),
            features=list(d.get("features", [])),
        )
