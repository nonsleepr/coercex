"""DCERPC error classification for coercion results."""

from __future__ import annotations

from coercex.models import TriggerResult

# Error codes that indicate the method processed our path (target tried
# to reach the UNC path).  Classified as ACCESSIBLE; only a confirmed
# callback upgrades to COERCED.
ACCESSIBLE_ERROR_CODES = {
    0x00000000,  # SUCCESS
    0x00000035,  # ERROR_BAD_NETPATH (tried to reach our UNC path)
    0x0000003A,  # ERROR_BAD_NET_NAME
    0x00000043,  # ERROR_BAD_NET_NAME
    0x000006D5,  # ERROR_BAD_NET_NAME variant
    0x00000057,  # ERROR_INVALID_PARAMETER (still processed the call)
    0x000006BA,  # RPC_S_SERVER_UNAVAILABLE (tried to call back)
    0x000006BE,  # RPC_S_CALL_FAILED
    0x000006BF,  # RPC_S_CALL_FAILED_DNE
}

ACCESS_DENIED_CODES = {
    0x00000005,  # ERROR_ACCESS_DENIED
    0x00000721,  # ERROR_ACCESS_DENIED variant
    0x000006AD,  # RPC_S_UNKNOWN_AUTHN_TYPE
}

NOT_AVAILABLE_CODES = {
    0x000006D9,  # EPT_S_NOT_REGISTERED
    0x000006E4,  # RPC_S_CANNOT_SUPPORT
}


def classify_error(error: Exception) -> TriggerResult:
    """Classify a DCERPC error into a TriggerResult."""
    try:
        err_str = str(error).lower()
    except Exception:
        # impacket's DCERPCException.__str__ crashes with TypeError when
        # both error_string and error_code are None (%x on None).
        err_str = type(error).__name__.lower()

    # Check for connection/timeout errors
    if any(s in err_str for s in ["timed out", "timeout", "connection refused"]):
        return TriggerResult.TIMEOUT
    if any(
        s in err_str for s in ["connection reset", "connection aborted", "broken pipe"]
    ):
        return TriggerResult.CONNECT_ERROR

    # Try to extract error code
    try:
        from impacket.dcerpc.v5.rpcrt import DCERPCException

        if isinstance(error, DCERPCException) and error.error_code is not None:
            code = error.error_code & 0xFFFFFFFF
            if code in ACCESSIBLE_ERROR_CODES:
                return TriggerResult.ACCESSIBLE
            if code in ACCESS_DENIED_CODES:
                return TriggerResult.ACCESS_DENIED
            if code in NOT_AVAILABLE_CODES:
                return TriggerResult.NOT_AVAILABLE
    except ImportError:
        pass

    # STATUS_PIPE_DISCONNECTED or similar = patched/not available
    if "status_pipe_disconnected" in err_str or "pipe_disconnected" in err_str:
        return TriggerResult.NOT_AVAILABLE

    # Access denied patterns
    if "access_denied" in err_str or "access denied" in err_str:
        return TriggerResult.ACCESS_DENIED

    # Bad netpath = accessible (it tried to reach our UNC path)
    if (
        "bad_netpath" in err_str
        or "bad_net_name" in err_str
        or "bad netpath" in err_str
    ):
        return TriggerResult.ACCESSIBLE

    # If the error message contains object_name_not_found, it processed the path
    if "object_name_not_found" in err_str:
        return TriggerResult.ACCESSIBLE

    # Bad stub data — server rejected NDR encoding (parameter mismatch)
    if "rpc_x_bad_stub_data" in err_str or "bad_stub_data" in err_str:
        return TriggerResult.NOT_AVAILABLE

    # Null parameter errors - method signature incompatibility
    if "cannot be null" in err_str or "pclientinfo cannot be null" in err_str:
        return TriggerResult.NOT_AVAILABLE

    # Module/class attribute errors - impacket version mismatch, missing
    # Request/Response NDRCALL classes, or missing SessionError subclass.
    if "has no attribute" in err_str:
        return TriggerResult.NOT_AVAILABLE

    # Log unknown errors for debugging
    import logging

    log = logging.getLogger("coercex.errors")
    log.warning("Unknown error classification: %s", err_str[:200])

    return TriggerResult.UNKNOWN_ERROR
