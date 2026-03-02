"""Network and string utility helpers."""

from __future__ import annotations

import logging
import random
import socket
import string

log = logging.getLogger("coercex.net")


def get_local_ip(target_ip: str | None = None) -> str:
    """Auto-detect the local IP by opening a UDP socket to a remote address.

    This doesn't actually send traffic -- it just lets the OS pick the
    outbound interface so we can read the local address.

    Args:
        target_ip: The target IP to route-probe for interface selection.
                   If None, uses a dummy public IP (10.255.255.255).
                   When scanning multiple targets, pass the first target IP
                   to ensure the listener binds to the correct interface.
    """
    probe_ip = target_ip if target_ip else "10.255.255.255"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((probe_ip, 1))
            return s.getsockname()[0]
    except OSError:
        log.warning(
            "Failed to detect local IP for target %s, falling back to 127.0.0.1",
            probe_ip,
        )
        return "127.0.0.1"


def random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
