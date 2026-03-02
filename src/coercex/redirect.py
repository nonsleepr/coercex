"""Kernel-level port redirection for non-standard listener ports.

When the operator cannot bind standard ports (445/80), the listener
binds on alternate ports (e.g. 4445/8080).  This module sets up
transparent port redirection so that:

  - UNC paths use standard ports (``\\\\host\\share`` → port 445)
  - Kernel rewrites inbound packets: 445 → 4445, 80 → 8080
  - No WebDAV ``@port`` format needed → works without WebClient service

Platform support:

  - **Windows**: ``pydivert`` (WinDivert kernel driver) — REQUIRED
  - **Linux/macOS**: Not supported (bind directly to 80/445 with sudo)

Rationale for Windows-only:

  On Linux, --redirect adds no value over direct binding:

  - Both require root privileges
  - Port conflicts are rare on pentesting attack boxes
  - iptables adds complexity with no benefit

  On Windows, --redirect solves a real problem:

  - SMB Server service always uses port 445 (can't easily stop)
  - pydivert allows coercion without stopping system services

When redirect is active, :func:`build_unc_path` should be called with
the *standard* port (445/80) so the resulting UNC path is a normal SMB
or WebDAV path.  The kernel transparently forwards the traffic to the
actual listener port.
"""

from __future__ import annotations

import atexit
import logging
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


def create_redirector() -> PortRedirector:
    """Create the appropriate redirector for the current platform.

    Raises :class:`RuntimeError` if the platform is not Windows or pydivert
    is not installed.
    """
    if sys.platform == "win32":
        return PydivertRedirector()
    else:
        raise RuntimeError(
            f"Port redirection is only supported on Windows (via pydivert). "
            f"On {sys.platform}, bind directly to standard ports (445/80) with sudo instead. "
            "Use --no-redirect to disable this feature."
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
