"""SMB2 framing helpers and packet builders.

Provides NetBIOS framing (4-byte length-prefixed read/write) and
functions that build SMB2 NEGOTIATE, SESSION_SETUP, and TREE_CONNECT
response packets using impacket structs.
"""

from __future__ import annotations

import asyncio
import os
import struct

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


async def recv_netbios(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """Read one NetBIOS-framed SMB message.

    4-byte NetBIOS header: 1 byte type (0x00) + 3 bytes big-endian length,
    then *length* bytes of payload.
    """
    hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    length = struct.unpack("!I", hdr)[0] & 0x00FFFFFF  # mask type byte
    payload = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    return payload


def send_netbios(writer: asyncio.StreamWriter, payload: bytes) -> None:
    """Send an SMB message with 4-byte NetBIOS framing."""
    hdr = struct.pack("!I", len(payload))
    writer.write(hdr + payload)


def build_negotiate_response(msg_id: int, challenge_token: bytes) -> bytes:
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


def build_session_setup_response(
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


def build_tree_connect_response(msg_id: int, session_id: int, tree_id: int) -> bytes:
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
