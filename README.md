# HWID-Bound Software Licensing

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

A from-scratch implementation of hardware-bound software licensing: signed
license keys that are cryptographically tied to a single machine, with tiers,
expiry, and revocation. Uses Ed25519 signatures, so a client can verify a
license but never forge one.

## Background

I designed and built the licensing and security layer for **SentinelAI**, a
Solana intelligence product, as lead engineer. That work is covered by an NDA,
so none of it appears here. This repository is an independent implementation,
written from scratch, that demonstrates the same class of technique without
touching any client code or confidential detail. It exists to show the
engineering, not to reproduce the original.

## The core idea

Licensing schemes fail when the client can fake a valid license. This design
makes that impossible by construction:

- The **issuer** holds an Ed25519 **private** key and is the only party that can
  mint licenses. In a real system it runs server-side, behind a purchase
  webhook.
- The **client** ships only the **public** key. It can verify a license but has
  no way to produce one, even with full access to the client source.
- The licensed machine's **hardware fingerprint (HWID)** is part of the signed
  payload, so a license minted for one machine fails on any other.

## How a license key works

A license key is a compact two-part token:

```
base64url(payload) . base64url(signature)
```

The payload names the product, tier, bound HWID, issue and expiry timestamps,
and any features. The signature covers the exact payload bytes. Validation
happens in a deliberate order:

1. **Verify the signature first**, before trusting any field. A forged or
   tampered payload never gets read as authoritative.
2. **Check revocation** against a revocation list.
3. **Check the HWID** matches the machine doing the validation.
4. **Check expiry** (a lifetime license simply has no expiry).

## Run it

No setup needed. The demo issues a license and shows it passing on its bound
machine and failing every way it should:

```bash
pip install -r requirements.txt
PYTHONPATH=src python -m licensing demo
```

Output:

```
[1] validate on this machine     -> valid
[2] validate on another machine  -> hwid_mismatch
[3] validate a tampered key      -> bad_signature
[4] validate a revoked license   -> revoked
```

Or with Docker:

```bash
docker build -t hwid-license-demo . && docker run --rm hwid-license-demo
```

## Using the pieces directly

```bash
# Generate an issuer keypair
PYTHONPATH=src python -m licensing keygen

# Mint a license for a machine (issuer side, needs the private key)
PYTHONPATH=src python -m licensing issue \
  --private-key <KEY> --tier premium --hwid <HWID>

# Validate on this machine (client side, needs the public key)
PYTHONPATH=src python -m licensing validate \
  --public-key <KEY> --token <LICENSE_KEY>
```

## Tiers

| Tier | Duration |
|------|----------|
| Trial | 7 days |
| Basic | 30 days |
| Premium | 90 days |
| Lifetime | never expires |

## Design notes and honest limitations

This demonstrates the cryptographic core, not a complete commercial product. A
production system would also need:

- **Online activation** to enforce per-license device limits and immediate
  revocation, since an offline validator can only check a revocation list it
  already has.
- **HWID stability tuning.** Hardware fingerprints trade stability against
  uniqueness; too strict and a hardware change locks a user out, too loose and
  a license is easy to clone. The fingerprint here uses a small, conservative
  component set and exposes it so the trade-off is visible.
- **Tamper-resistant key storage** in the client, since the embedded public key
  and validation path are a target for patching. Defeating that is a
  distribution-and-obfuscation problem on top of the cryptography.

These are called out deliberately: the signature-and-binding core is the part
worth showing cleanly, and the rest is where the real-world hardening goes.

## Project layout

```
src/licensing/
  models.py      license model and tiers
  hwid.py        hardware fingerprinting
  keys.py        Ed25519 keypair helpers
  tokens.py      license key encode/decode
  issuer.py      mints signed licenses (private key)
  validator.py   verifies licenses (public key)
  cli.py         keygen / issue / validate / demo
tests/           full validation-branch coverage
```

## License

MIT
