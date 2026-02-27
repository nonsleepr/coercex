"""Data models and enumerations for coercex."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

log = logging.getLogger("coercex.models")


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
    SENT = "sent"  # Trigger fired (coerce mode -- no classification)


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
    ccache: str = ""  # Path to Kerberos ccache file (or empty to use KRB5CCNAME)

    # Cached TGT/TGS loaded from ccache (populated by load_ccache())
    _tgt: dict[str, Any] | None = field(default=None, repr=False)
    _tgs: dict[str, Any] | None = field(default=None, repr=False)

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

    def load_ccache(self, target_name: str = "") -> None:
        """Load TGT/TGS from a ccache file.

        Sets do_kerberos=True and populates _tgt/_tgs for use by the
        connection pool. If self.ccache is set, it overrides KRB5CCNAME.

        Args:
            target_name: SPN target name for TGS lookup (e.g. 'cifs/dc01.corp.local').
        """
        if self.ccache:
            os.environ["KRB5CCNAME"] = self.ccache
            log.info("Using ccache file: %s", self.ccache)

        ccache_path = os.environ.get("KRB5CCNAME", "")
        if not ccache_path:
            log.warning("No ccache path set (--ccache or KRB5CCNAME)")
            return

        try:
            from impacket.krb5.ccache import CCache

            domain, username, tgt, tgs = CCache.parseFile(
                self.domain, self.username, target_name
            )
            if domain and not self.domain:
                self.domain = domain
            if username and not self.username:
                self.username = username
            if tgt:
                self._tgt = tgt
                log.info("Loaded TGT from ccache for %s@%s", self.username, self.domain)
            if tgs:
                self._tgs = tgs
                log.info("Loaded TGS from ccache for target %s", target_name)

            self.do_kerberos = True
        except Exception as e:
            log.error("Failed to load ccache: %s", e)


@dataclass
class ScanResult:
    """Result of scanning a single method on a single target."""

    target: str
    protocol: str
    method: str
    pipe: str
    uuid: str
    result: TriggerResult
    transport: str = ""  # "smb" or "http"
    path_style: str = ""  # e.g. "share_file", "bare"
    error: str = ""
    callback_received: bool = False
    source_ip: str = ""
    auth_user: str = ""  # DOMAIN\username from NTLM Type 3
    ntlmv2_hash: str = ""  # Net-NTLMv2 hash in John/Hashcat format


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
    sent: int = 0
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
            case TriggerResult.SENT:
                self.sent += 1


class Mode(Enum):
    """Operating mode for the scanner."""

    SCAN = auto()
    COERCE = auto()


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    targets: list[str]
    mode: Mode = Mode.SCAN
    protocols: list[str] | None = None
    methods_filter: list[str] | None = None  # Glob/regex patterns for method names
    pipes_filter: list[str] | None = None  # Pipe names to restrict to
    creds: Credentials | None = None
    listener_host: str = ""  # Attacker IP (empty = no listener)
    http_port: int = 80
    smb_port: int = 445
    transport: set[Transport] = field(
        default_factory=lambda: {Transport.SMB, Transport.HTTP}
    )
    concurrency: int = 50
    timeout: int = 5
    callback_timeout: float = 5.0
    redirect: bool = False
    verbose: bool = False

    @property
    def has_listener(self) -> bool:
        """Whether a listener IP was provided."""
        return bool(self.listener_host)


# Rich status styling for TriggerResult display.
# Shared by cli and scanner modules.
STATUS_STYLE: dict[TriggerResult, tuple[str, str]] = {
    TriggerResult.VULNERABLE: ("bold green", "[+]"),
    TriggerResult.ACCESSIBLE: ("yellow", "[~]"),
    TriggerResult.ACCESS_DENIED: ("red", "[-]"),
    TriggerResult.NOT_AVAILABLE: ("dim", "[ ]"),
    TriggerResult.CONNECT_ERROR: ("bold red", "[!]"),
    TriggerResult.TIMEOUT: ("magenta", "[T]"),
    TriggerResult.UNKNOWN_ERROR: ("dim red", "[?]"),
    TriggerResult.SENT: ("cyan", "[>]"),
}
