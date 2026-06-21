"""Tests for the HWID-bound licensing system.

These exercise every validation branch, since the security guarantees are only
as good as the cases that are checked: a valid license passes, and every way a
license can be invalid (forged, foreign machine, expired, revoked, malformed)
is rejected with the right status.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from licensing import (
    Issuer,
    Status,
    Tier,
    Validator,
    generate_private_key,
    get_hwid,
)
from licensing.tokens import decode_token, encode_token

HWID_A = get_hwid({"node": "a", "machine": "x", "system": "linux",
                   "mac": "111111111111", "machine_id": "aaa"})
HWID_B = get_hwid({"node": "b", "machine": "x", "system": "linux",
                   "mac": "222222222222", "machine_id": "bbb"})


@pytest.fixture
def keypair():
    priv = generate_private_key()
    return priv, priv.public_key()


@pytest.fixture
def issuer(keypair):
    return Issuer(keypair[0])


@pytest.fixture
def validator(keypair):
    return Validator(keypair[1])


def test_valid_license_passes(issuer, validator):
    token = issuer.issue(product="App", tier=Tier.PREMIUM, hwid=HWID_A)
    result = validator.validate(token, HWID_A)
    assert result.ok
    assert result.status is Status.VALID
    assert result.license["tier"] == "premium"


def test_license_fails_on_different_machine(issuer, validator):
    token = issuer.issue(product="App", tier=Tier.PREMIUM, hwid=HWID_A)
    result = validator.validate(token, HWID_B)
    assert not result.ok
    assert result.status is Status.HWID_MISMATCH


def test_tampered_payload_fails_signature(issuer, validator):
    token = issuer.issue(product="App", tier=Tier.PREMIUM, hwid=HWID_A)
    payload_bytes, signature = decode_token(token)
    # Flip a byte in the payload, keep the old signature.
    forged_payload = bytearray(payload_bytes)
    forged_payload[10] ^= 0x01
    forged = encode_token(bytes(forged_payload), signature)
    result = validator.validate(forged, HWID_A)
    assert result.status is Status.BAD_SIGNATURE


def test_key_from_other_issuer_fails(issuer):
    # A different issuer's public key must reject this issuer's licenses.
    other_pub = generate_private_key().public_key()
    foreign_validator = Validator(other_pub)
    token = issuer.issue(product="App", tier=Tier.PREMIUM, hwid=HWID_A)
    result = foreign_validator.validate(token, HWID_A)
    assert result.status is Status.BAD_SIGNATURE


def test_expired_license_fails(issuer, validator):
    past = datetime.now(timezone.utc) - timedelta(days=40)
    token = issuer.issue(product="App", tier=Tier.BASIC, hwid=HWID_A, now=past)
    result = validator.validate(token, HWID_A)
    assert result.status is Status.EXPIRED


def test_lifetime_never_expires(issuer, validator):
    long_ago = datetime.now(timezone.utc) - timedelta(days=3650)
    token = issuer.issue(product="App", tier=Tier.LIFETIME, hwid=HWID_A, now=long_ago)
    result = validator.validate(token, HWID_A)
    assert result.ok


def test_revoked_license_fails(issuer, keypair):
    token = issuer.issue(product="App", tier=Tier.PREMIUM, hwid=HWID_A)
    payload, _ = decode_token(token)
    license_id = json.loads(payload)["license_id"]
    validator = Validator(keypair[1], revoked_ids={license_id})
    result = validator.validate(token, HWID_A)
    assert result.status is Status.REVOKED


def test_malformed_token_fails(validator):
    assert validator.validate("not-a-real-token", HWID_A).status is Status.MALFORMED
    assert validator.validate("only.one.too.many", HWID_A).status is Status.MALFORMED


def test_signature_checked_before_fields(validator):
    # A garbage payload with a junk signature must fail on signature, not crash
    # trying to read fields.
    fake = encode_token(b'{"hwid":"x","expires_at":null}', b"\x00" * 64)
    result = validator.validate(fake, HWID_A)
    assert result.status is Status.BAD_SIGNATURE


@pytest.mark.parametrize("tier,expires", [
    (Tier.TRIAL, True),
    (Tier.BASIC, True),
    (Tier.PREMIUM, True),
    (Tier.LIFETIME, False),
])
def test_tiers_set_expiry_correctly(issuer, tier, expires):
    token = issuer.issue(product="App", tier=tier, hwid=HWID_A)
    payload, _ = decode_token(token)
    data = json.loads(payload)
    assert (data["expires_at"] is not None) == expires
