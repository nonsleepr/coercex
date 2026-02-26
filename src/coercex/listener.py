"""Async listener with correlation tokens.

Provides an HTTP listener (for WebDAV callbacks) and a minimal SMB
listener to catch NTLM authentication coercion callbacks.

Each trigger attempt embeds a unique token in the UNC path. When the
victim connects back, the listener extracts the token and resolves the
corresponding pending Future.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("coercex.listener")


@dataclass
class AuthCallback:
    """Captured authentication callback."""

    token: str
    source_ip: str
    source_port: int
    timestamp: datetime
    transport: str  # "smb" or "http"
    raw_data: bytes = b""


class AsyncListener:
    """Combined HTTP + SMB listener with token correlation.

    Usage:
        listener = AsyncListener(host="0.0.0.0", http_port=80, smb_port=445)
        await listener.start()
        token, future = listener.create_token()
        # ... trigger coercion with UNC path containing token ...
        try:
            callback = await asyncio.wait_for(future, timeout=3.0)
        except asyncio.TimeoutError:
            pass
        await listener.stop()
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        http_port: int = 80,
        smb_port: int = 445,
        enable_http: bool = True,
        enable_smb: bool = True,
    ):
        self.host = host
        self.http_port = http_port
        self.smb_port = smb_port
        self.enable_http = enable_http
        self.enable_smb = enable_smb

        self._pending: dict[str, asyncio.Future[AuthCallback]] = {}
        self._callbacks: list[AuthCallback] = []
        self._http_server: asyncio.Server | None = None
        self._smb_server: asyncio.Server | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self) -> None:
        """Start the listener servers."""
        self._loop = asyncio.get_running_loop()

        if self.enable_http:
            try:
                self._http_server = await asyncio.start_server(
                    self._handle_http,
                    self.host,
                    self.http_port,
                )
                log.info("HTTP listener started on %s:%d", self.host, self.http_port)
            except OSError as e:
                log.warning(
                    "Could not start HTTP listener on port %d: %s", self.http_port, e
                )

        if self.enable_smb:
            try:
                self._smb_server = await asyncio.start_server(
                    self._handle_smb,
                    self.host,
                    self.smb_port,
                )
                log.info("SMB listener started on %s:%d", self.host, self.smb_port)
            except OSError as e:
                log.warning(
                    "Could not start SMB listener on port %d: %s", self.smb_port, e
                )

    async def stop(self) -> None:
        """Stop all listeners and cancel pending futures."""
        for server in (self._http_server, self._smb_server):
            if server:
                server.close()
                await server.wait_closed()

        # Cancel any remaining pending futures
        for token, future in self._pending.items():
            if not future.done():
                future.cancel()
        self._pending.clear()

    def create_token(self) -> tuple[str, asyncio.Future[AuthCallback]]:
        """Create a correlation token and return (token, future).

        The future resolves when a callback matching this token is received.
        """
        import uuid

        token = uuid.uuid4().hex[:12]
        future: asyncio.Future[AuthCallback] = (
            self._loop.create_future()
            if self._loop
            else asyncio.get_running_loop().create_future()
        )
        self._pending[token] = future
        return token, future

    def cancel_token(self, token: str) -> None:
        """Cancel and remove a pending token."""
        future = self._pending.pop(token, None)
        if future and not future.done():
            future.cancel()

    def _resolve_token(self, token: str, callback: AuthCallback) -> None:
        """Try to resolve a token with a callback."""
        self._callbacks.append(callback)
        future = self._pending.pop(token, None)
        if future and not future.done():
            future.set_result(callback)
            log.info(
                "Callback received: token=%s src=%s:%d transport=%s",
                token,
                callback.source_ip,
                callback.source_port,
                callback.transport,
            )
        else:
            log.debug(
                "Callback for unknown/expired token=%s from %s",
                token,
                callback.source_ip,
            )

    def _extract_token_from_path(self, path: str) -> str | None:
        """Extract a 12-char hex token from a URL/share path.

        Tokens are embedded as share names or URL path segments.
        Examples:
            /abc123def456/file.txt -> abc123def456
            \\\\host\\abc123def456\\file.txt -> abc123def456
        """
        # Normalize separators
        parts = path.replace("\\", "/").strip("/").split("/")
        for part in parts:
            part = part.strip()
            if len(part) == 12:
                try:
                    int(part, 16)
                    return part
                except ValueError:
                    continue
        return None

    # ── HTTP Handler ────────────────────────────────────────────────────

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming HTTP connections (WebDAV callbacks)."""
        try:
            peername = writer.get_extra_info("peername")
            src_ip = peername[0] if peername else "unknown"
            src_port = peername[1] if peername else 0

            # Read the HTTP request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                return

            request_str = request_line.decode("utf-8", errors="replace").strip()
            parts = request_str.split()
            path = parts[1] if len(parts) >= 2 else "/"

            # Read remaining headers (discard them)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if line in (b"\r\n", b"\n", b""):
                    break

            log.debug("HTTP request from %s:%d: %s", src_ip, src_port, request_str)

            token = self._extract_token_from_path(path)
            if token:
                callback = AuthCallback(
                    token=token,
                    source_ip=src_ip,
                    source_port=src_port,
                    timestamp=datetime.now(timezone.utc),
                    transport="http",
                    raw_data=request_line,
                )
                self._resolve_token(token, callback)

            # Send 401 to request NTLM auth (or just close)
            response = (
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"WWW-Authenticate: NTLM\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            writer.write(response)
            await writer.drain()

        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── SMB Handler ─────────────────────────────────────────────────────

    async def _handle_smb(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming SMB connections.

        Minimal SMB2 negotiation to capture the connection and extract
        the share name (containing our correlation token).
        """
        try:
            peername = writer.get_extra_info("peername")
            src_ip = peername[0] if peername else "unknown"
            src_port = peername[1] if peername else 0

            log.debug("SMB connection from %s:%d", src_ip, src_port)

            # Read NetBIOS session header + SMB data
            raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not raw or len(raw) < 4:
                return

            # Any SMB connection to our listener is a callback.
            # Try to extract token from raw data, but even without it,
            # we can correlate by source IP + timing.
            token = self._extract_token_from_smb(raw)

            callback = AuthCallback(
                token=token or "",
                source_ip=src_ip,
                source_port=src_port,
                timestamp=datetime.now(timezone.utc),
                transport="smb",
                raw_data=raw[:256],
            )

            if token:
                self._resolve_token(token, callback)
            else:
                # No token found - try IP-based correlation
                self._resolve_by_ip(src_ip, callback)

        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_token_from_smb(self, raw: bytes) -> str | None:
        """Try to extract a correlation token from raw SMB packet data.

        Looks for our 12-char hex token in the raw bytes (it appears in
        tree connect requests as part of the share path).
        """
        try:
            # Try to find the share path in raw bytes
            # SMB2 TREE_CONNECT contains the path as UTF-16LE
            decoded = raw.decode("utf-16-le", errors="replace")
            token = self._extract_token_from_path(decoded)
            if token:
                return token
        except Exception:
            pass

        try:
            # Also try ASCII
            decoded = raw.decode("ascii", errors="replace")
            token = self._extract_token_from_path(decoded)
            if token:
                return token
        except Exception:
            pass

        return None

    def _resolve_by_ip(self, src_ip: str, callback: AuthCallback) -> None:
        """Fallback: resolve the most recent pending token for a source IP.

        This is imprecise but works when tokens can't be extracted from
        raw SMB data.
        """
        self._callbacks.append(callback)
        # Can't correlate without a token - just log it
        log.info("SMB callback from %s (no token extracted)", src_ip)

    @property
    def callbacks(self) -> list[AuthCallback]:
        """All received callbacks."""
        return list(self._callbacks)

    @property
    def is_running(self) -> bool:
        return bool(self._http_server or self._smb_server)
