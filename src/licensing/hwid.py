"""Hardware fingerprinting.

Derives a stable identifier for the current machine by hashing a set of
machine characteristics. The HWID is embedded in the signed license, so a
license issued for one machine will not validate on another.

Note on stability: real-world HWID schemes balance stability against
uniqueness. Too many components and a hardware change (new disk, new network
adapter) breaks the license; too few and it is easy to clone. This demo uses a
small, conservative set and exposes the components so the trade-off is visible.
"""

from __future__ import annotations

import hashlib
import platform
import uuid
from pathlib import Path


def _machine_id() -> str:
    """Linux/systemd stable machine id, if present."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            continue
    return ""


def hwid_components() -> dict[str, str]:
    """Collect the raw components that make up the fingerprint."""
    return {
        "node": platform.node(),
        "machine": platform.machine(),
        "system": platform.system(),
        # uuid.getnode() returns the MAC where available.
        "mac": format(uuid.getnode(), "012x"),
        "machine_id": _machine_id(),
    }


def get_hwid(components: dict[str, str] | None = None) -> str:
    """Return a stable SHA-256 fingerprint for the machine.

    Components can be injected for testing or to simulate a different machine.
    """
    components = components or hwid_components()
    blob = "|".join(f"{key}={components[key]}" for key in sorted(components))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
