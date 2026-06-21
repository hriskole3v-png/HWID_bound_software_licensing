"""HWID-bound licensing demo.

An independent, from-scratch implementation of hardware-bound software
licensing using Ed25519 signatures. Not affiliated with or derived from any
client system.
"""

from .hwid import get_hwid, hwid_components
from .issuer import Issuer
from .keys import (
    generate_private_key,
    load_private_key,
    load_public_key,
    private_key_to_b64,
    public_key_to_b64,
)
from .models import TIER_DURATION_DAYS, License, Tier
from .validator import Status, ValidationResult, Validator

__all__ = [
    "get_hwid",
    "hwid_components",
    "Issuer",
    "Validator",
    "ValidationResult",
    "Status",
    "License",
    "Tier",
    "TIER_DURATION_DAYS",
    "generate_private_key",
    "load_private_key",
    "load_public_key",
    "private_key_to_b64",
    "public_key_to_b64",
]
