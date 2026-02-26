"""Kernel-level port redirection for non-standard listener ports.

When the operator cannot bind standard ports (445/80), the listener
binds on alternate ports (e.g. 4445/8080).  This module sets up
transparent port redirection so that:

  - UNC paths use standard ports (``\\\\host\\share`` → port 445)
  - Kernel rewrites inbound packets: 445 → 4445, 80 → 8080
  - No WebDAV ``@port`` format needed → works without WebClient service

Platform support:

  - **Linux**: ``iptables`` NAT PREROUTING/OUTPUT REDIRECT rules
  - **Windows**: ``pydivert`` (WinDivert kernel driver)

When redirect is active, :func:`build_unc_path` should be called with
the *standard* port (445/80) so the resulting UNC path is a normal SMB
or WebDAV path.  The kernel transparently forwards the traffic to the
actual listener port.
"""

from __future__ import annotations

import atexit
import logging
import shutil
import subprocess
import sys
import threading
from abc import ABC, abstractmethod
from typing import Any

log = logging.getLogger("coercex.redirect")


class PortRedirector(ABC):
    """Abstract kernel-level port redirector."""

    @abstractmethod
    def add_redirect(self, from_port: int, to_port: int) -> None:
        """Redirect inbound traffic from *from_port* to *to_port*.

        Raises :class:`RuntimeError` on failure.
        """

    @abstractmethod
    def cleanup(self) -> None:
        """Remove all redirect rules added by this instance."""


# ── Linux: iptables ─────────────────────────────────────────────────


class IptablesRedirector(PortRedirector):
    """Linux ``iptables`` NAT PREROUTING REDIRECT rules.

    Requires root / ``CAP_NET_ADMIN``.
    """

    def __init__(self) -> None:
        self._rules: list[tuple[int, int]] = []
        iptables = shutil.which("iptables")
        if not iptables:
            raise RuntimeError(
                "iptables not found in PATH — install iptables or use "
                "--no-redirect to fall back to WebDAV @port format"
            )
        self._iptables: str = iptables

    def _run(self, *args: str) -> None:
        result = subprocess.run(
            [self._iptables, *args],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(f"iptables failed: {result.stderr.strip()}")

    def add_redirect(self, from_port: int, to_port: int) -> None:
        if from_port == to_port:
            return
        # PREROUTING: catch packets arriving from the network
        self._run(
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            str(from_port),
            "-j",
            "REDIRECT",
            "--to-port",
            str(to_port),
        )
        # OUTPUT: catch locally-generated traffic (e.g. testing on loopback)
        self._run(
            "-t",
            "nat",
            "-I",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            str(from_port),
            "-j",
            "REDIRECT",
            "--to-port",
            str(to_port),
        )
        self._rules.append((from_port, to_port))
        log.info("iptables redirect: %d → %d", from_port, to_port)

    def cleanup(self) -> None:
        for from_port, to_port in self._rules:
            for chain in ("PREROUTING", "OUTPUT"):
                try:
                    self._run(
                        "-t",
                        "nat",
                        "-D",
                        chain,
                        "-p",
                        "tcp",
                        "--dport",
                        str(from_port),
                        "-j",
                        "REDIRECT",
                        "--to-port",
                        str(to_port),
                    )
                except Exception as exc:
                    log.warning(
                        "Failed to remove iptables %s rule %d→%d: %s",
                        chain,
                        from_port,
                        to_port,
                        exc,
                    )
            log.info("Removed iptables redirect: %d → %d", from_port, to_port)
        self._rules.clear()


# ── Windows: pydivert ───────────────────────────────────────────────


class PydivertRedirector(PortRedirector):
    """Windows port redirection using pydivert (WinDivert kernel driver).

    Each :meth:`add_redirect` call spawns a daemon thread that rewrites
    packets in both directions (like Coercer's ``redirect_smb_packets``).
    """

    def __init__(self) -> None:
        try:
            import pydivert as _  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "pydivert is required for port redirection on Windows. "
                "Install with:  pip install pydivert"
            ) from None
        self._handles: list[Any] = []
        self._threads: list[threading.Thread] = []

    def add_redirect(self, from_port: int, to_port: int) -> None:
        if from_port == to_port:
            return

        import pydivert

        filt = f"tcp.DstPort == {from_port} or tcp.SrcPort == {to_port}"
        handle = pydivert.WinDivert(filt)
        handle.open()
        self._handles.append(handle)

        def _loop() -> None:
            try:
                for packet in handle:
                    if packet.dst_port == from_port and packet.is_inbound:
                        packet.dst_port = to_port
                    if packet.src_port == to_port and packet.is_outbound:
                        packet.src_port = from_port
                    handle.send(packet)
            except Exception:
                pass  # handle closed → exit cleanly

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        self._threads.append(t)
        log.info("pydivert redirect: %d → %d", from_port, to_port)

    def cleanup(self) -> None:
        for h in self._handles:
            try:
                h.close()
            except Exception:
                pass
        self._handles.clear()
        self._threads.clear()
        log.info("Closed all pydivert handles")


# ── Factory ─────────────────────────────────────────────────────────


def create_redirector() -> PortRedirector:
    """Create the appropriate redirector for the current platform.

    Raises :class:`RuntimeError` if the platform is unsupported or the
    required tooling is missing.
    """
    if sys.platform == "win32":
        return PydivertRedirector()
    elif sys.platform.startswith("linux"):
        return IptablesRedirector()
    else:
        raise RuntimeError(
            f"Port redirection not implemented for {sys.platform}. "
            "Use --no-redirect and set up redirection manually, or "
            "use standard ports (445/80) which don't need redirection."
        )


def setup_redirect(smb_port: int, http_port: int) -> PortRedirector:
    """Set up port redirection and register atexit cleanup.

    Redirects standard ports to listener ports:

    - ``445 → smb_port``  (only if smb_port != 445)
    - ``80  → http_port`` (only if http_port != 80)

    Returns the redirector.  Caller should also call
    :meth:`~PortRedirector.cleanup` in a ``finally`` block.

    Raises :class:`RuntimeError` if redirect cannot be established.
    """
    redirector = create_redirector()
    atexit.register(redirector.cleanup)

    if smb_port != 445:
        redirector.add_redirect(445, smb_port)
    if http_port != 80:
        redirector.add_redirect(80, http_port)

    return redirector
