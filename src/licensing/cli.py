"""Command-line interface.

Subcommands:
  keygen            generate an issuer keypair
  issue             mint a license for a HWID (needs the private key)
  validate          validate a license key on this machine (needs public key)
  demo              run the full flow end to end, including failure cases

The demo command needs no setup and is the quickest way to see the system work.
"""

from __future__ import annotations

import argparse
import json
import sys

from .hwid import get_hwid
from .issuer import Issuer
from .keys import (
    generate_private_key,
    load_private_key,
    load_public_key,
    private_key_to_b64,
    public_key_to_b64,
)
from .models import Tier
from .tokens import decode_token
from .validator import Validator


def _cmd_keygen(args: argparse.Namespace) -> int:
    priv = generate_private_key()
    print("PRIVATE_KEY (keep secret, issuer only):")
    print(" ", private_key_to_b64(priv))
    print("PUBLIC_KEY (ship in the client):")
    print(" ", public_key_to_b64(priv.public_key()))
    return 0


def _cmd_issue(args: argparse.Namespace) -> int:
    priv = load_private_key(args.private_key)
    issuer = Issuer(priv)
    token = issuer.issue(product=args.product, tier=Tier(args.tier), hwid=args.hwid)
    print(token)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    pub = load_public_key(args.public_key)
    validator = Validator(pub)
    hwid = args.hwid or get_hwid()
    result = validator.validate(args.token, hwid)
    print(f"status: {result.status.value}")
    print(f"reason: {result.reason}")
    return 0 if result.ok else 1


def _cmd_demo(args: argparse.Namespace) -> int:
    print("=== HWID-bound licensing demo ===\n")

    priv = generate_private_key()
    pub = priv.public_key()
    issuer = Issuer(priv)
    validator = Validator(pub)

    this_machine = get_hwid()
    print(f"This machine HWID: {this_machine[:24]}...\n")

    # Issue a premium license bound to this machine.
    token = issuer.issue(product="ExampleApp", tier=Tier.PREMIUM, hwid=this_machine)
    print("Issued PREMIUM license key:")
    print(f"  {token[:60]}...\n")

    # 1. Valid on this machine.
    r = validator.validate(token, this_machine)
    print(f"[1] validate on this machine     -> {r.status.value}  ({r.reason})")

    # 2. Same key on a different machine.
    other_machine = get_hwid({"node": "other", "machine": "x", "system": "y",
                              "mac": "000000000000", "machine_id": "different"})
    r = validator.validate(token, other_machine)
    print(f"[2] validate on another machine  -> {r.status.value}  ({r.reason})")

    # 3. Tampered key.
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    r = validator.validate(tampered, this_machine)
    print(f"[3] validate a tampered key      -> {r.status.value}  ({r.reason})")

    # 4. Revoked license.
    issued = issuer.issue(product="ExampleApp", tier=Tier.BASIC, hwid=this_machine)
    payload, _ = decode_token(issued)
    license_id = json.loads(payload)["license_id"]
    revoking_validator = Validator(pub, revoked_ids={license_id})
    r = revoking_validator.validate(issued, this_machine)
    print(f"[4] validate a revoked license   -> {r.status.value}  ({r.reason})")

    print("\nThe signature check means a forged or tampered key never validates,")
    print("and the HWID binding means a real key only works on its bound machine.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="licensing", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="generate an issuer keypair")
    p_keygen.set_defaults(func=_cmd_keygen)

    p_issue = sub.add_parser("issue", help="mint a license (issuer)")
    p_issue.add_argument("--private-key", required=True)
    p_issue.add_argument("--product", default="ExampleApp")
    p_issue.add_argument("--tier", choices=[t.value for t in Tier], default="premium")
    p_issue.add_argument("--hwid", required=True)
    p_issue.set_defaults(func=_cmd_issue)

    p_val = sub.add_parser("validate", help="validate a license (client)")
    p_val.add_argument("--public-key", required=True)
    p_val.add_argument("--token", required=True)
    p_val.add_argument("--hwid", default="", help="defaults to this machine")
    p_val.set_defaults(func=_cmd_validate)

    p_demo = sub.add_parser("demo", help="run the full flow end to end")
    p_demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
