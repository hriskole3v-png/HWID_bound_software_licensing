"""Ed25519 keypair helpers.

The issuer holds the private key and is the only party that can mint licenses.
The client ships only the public key and can verify but never forge. This
asymmetry is the whole point: even with the full client source, an attacker
cannot produce a valid license without the private key.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_RAW = serialization.Encoding.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_NO_ENC = serialization.NoEncryption()


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.private_bytes(_RAW, _RAW_PRIV, _NO_ENC)).decode("ascii")


def public_key_to_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(key.public_bytes(_RAW, _RAW_PUB)).decode("ascii")


def load_private_key(b64: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(b64))


def load_public_key(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))
