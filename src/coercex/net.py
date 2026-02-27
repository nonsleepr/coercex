"""Network and string utility helpers."""

from __future__ import annotations

import logging
import random
import socket
import string

log = logging.getLogger("coercex.net")


def get_local_ip() -> str:
    """Auto-detect the local IP by opening a UDP socket to a public address.

    This doesn't actually send traffic -- it just lets the OS pick the
    outbound interface so we can read the local address.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
