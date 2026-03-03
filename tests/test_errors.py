"""Tests for DCERPC error classification (errors.py).

Covers all changes from today:
  - rpc_x_bad_stub_data → NOT_AVAILABLE
  - error_code=None guard (prevents TypeError on bitwise AND)
  - Broadened 'has no attribute' pattern
  - Residual edge case: str(DCERPCException()) when both fields are None
"""

from __future__ import annotations

import pytest

from coercex.errors import (
    ACCESSIBLE_ERROR_CODES,
    ACCESS_DENIED_CODES,
    NOT_AVAILABLE_CODES,
    classify_error,
)
from coercex.models import TriggerResult


# ---------------------------------------------------------------------------
# Helper: create a real DCERPCException
# ---------------------------------------------------------------------------


def _dcerpc_exc(error_code: int | None = None, error_string: str | None = None):
    """Create a real impacket DCERPCException."""
    from impacket.dcerpc.v5.rpcrt import DCERPCException

    return DCERPCException(error_string=error_string, error_code=error_code)


# ---------------------------------------------------------------------------
# rpc_x_bad_stub_data
# ---------------------------------------------------------------------------


class TestBadStubData:
    """rpc_x_bad_stub_data must be classified as NOT_AVAILABLE."""

    def test_bad_stub_data_by_error_code(self):
        """DCERPCException with error_code=0x6F7 → NOT_AVAILABLE."""
        exc = _dcerpc_exc(error_code=0x6F7)
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE

    def test_bad_stub_data_by_error_string(self):
        """DCERPCException with error_string containing 'rpc_x_bad_stub_data'."""
        exc = _dcerpc_exc(error_string="rpc_x_bad_stub_data")
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE

    def test_bad_stub_data_plain_exception(self):
        """Plain Exception with 'rpc_x_bad_stub_data' in message."""
        assert (
            classify_error(Exception("rpc_x_bad_stub_data"))
            == TriggerResult.NOT_AVAILABLE
        )

    def test_bad_stub_data_partial_match(self):
        """The pattern 'bad_stub_data' also matches."""
        assert (
            classify_error(Exception("got bad_stub_data from server"))
            == TriggerResult.NOT_AVAILABLE
        )


# ---------------------------------------------------------------------------
# error_code=None guard
# ---------------------------------------------------------------------------


class TestErrorCodeNoneGuard:
    """The `error.error_code is not None` guard prevents TypeError."""

    def test_error_string_only_no_crash(self):
        """DCERPCException(error_string=..., error_code=None) must not crash."""
        exc = _dcerpc_exc(error_string="access_denied")
        result = classify_error(exc)
        assert result == TriggerResult.ACCESS_DENIED  # matched by string

    def test_error_string_bad_netpath(self):
        """error_code=None with 'bad_netpath' in string → ACCESSIBLE."""
        exc = _dcerpc_exc(error_string="bad_netpath")
        assert classify_error(exc) == TriggerResult.ACCESSIBLE

    def test_both_none_no_crash(self):
        """DCERPCException() with both None must not crash.

        impacket's __str__ does ``%x`` on None, raising TypeError.
        classify_error wraps str() in try/except so it falls through
        to UNKNOWN_ERROR instead of propagating the TypeError.
        """
        exc = _dcerpc_exc()
        result = classify_error(exc)
        assert result == TriggerResult.UNKNOWN_ERROR


# ---------------------------------------------------------------------------
# Broadened 'has no attribute' pattern
# ---------------------------------------------------------------------------


class TestHasNoAttribute:
    """Any 'has no attribute' error → NOT_AVAILABLE (broadened pattern)."""

    def test_sessionerror_variant(self):
        """Original pattern: 'has no attribute' + 'sessionerror'."""
        exc = Exception(
            "module 'impacket.dcerpc.v5.even' has no attribute 'SessionError'"
        )
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE

    def test_response_variant(self):
        """Original pattern: 'has no attribute' + 'response'."""
        exc = Exception(
            "module 'impacket.dcerpc.v5.rprn' has no attribute 'RpcRemoteResponse'"
        )
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE

    def test_generic_attribute_error(self):
        """Broadened: any 'has no attribute' → NOT_AVAILABLE."""
        exc = Exception(
            "module 'impacket.dcerpc.v5.rprn' has no attribute "
            "'RpcRemoteFindFirstPrinterChangeNotification'"
        )
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE

    def test_arbitrary_attribute_name(self):
        """Even unrelated attribute names get NOT_AVAILABLE."""
        exc = Exception("object has no attribute 'foobar'")
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE


# ---------------------------------------------------------------------------
# Error code classification (existing behavior, regression)
# ---------------------------------------------------------------------------


class TestErrorCodeClassification:
    """All error code sets must still classify correctly."""

    @pytest.mark.parametrize("code", sorted(ACCESSIBLE_ERROR_CODES))
    def test_accessible_codes(self, code: int):
        exc = _dcerpc_exc(error_code=code)
        assert classify_error(exc) == TriggerResult.ACCESSIBLE

    @pytest.mark.parametrize("code", sorted(ACCESS_DENIED_CODES))
    def test_access_denied_codes(self, code: int):
        exc = _dcerpc_exc(error_code=code)
        assert classify_error(exc) == TriggerResult.ACCESS_DENIED

    @pytest.mark.parametrize("code", sorted(NOT_AVAILABLE_CODES))
    def test_not_available_codes(self, code: int):
        exc = _dcerpc_exc(error_code=code)
        assert classify_error(exc) == TriggerResult.NOT_AVAILABLE


# ---------------------------------------------------------------------------
# String-based patterns (existing behavior, regression)
# ---------------------------------------------------------------------------


class TestStringPatterns:
    """Verify all string-based classification patterns still work."""

    @pytest.mark.parametrize(
        "msg,expected",
        [
            ("Connection timed out", TriggerResult.TIMEOUT),
            ("Operation timeout", TriggerResult.TIMEOUT),
            ("Connection refused", TriggerResult.TIMEOUT),
            ("Connection reset by peer", TriggerResult.CONNECT_ERROR),
            ("connection aborted", TriggerResult.CONNECT_ERROR),
            ("Broken pipe", TriggerResult.CONNECT_ERROR),
            ("STATUS_PIPE_DISCONNECTED", TriggerResult.NOT_AVAILABLE),
            ("pipe_disconnected", TriggerResult.NOT_AVAILABLE),
            ("access_denied", TriggerResult.ACCESS_DENIED),
            ("Access Denied", TriggerResult.ACCESS_DENIED),
            ("bad_netpath", TriggerResult.ACCESSIBLE),
            ("bad_net_name", TriggerResult.ACCESSIBLE),
            ("bad netpath", TriggerResult.ACCESSIBLE),
            ("object_name_not_found", TriggerResult.ACCESSIBLE),
            ("rpc_x_bad_stub_data", TriggerResult.NOT_AVAILABLE),
            ("cannot be null", TriggerResult.NOT_AVAILABLE),
            ("pClientInfo cannot be null", TriggerResult.NOT_AVAILABLE),
            ("has no attribute", TriggerResult.NOT_AVAILABLE),
        ],
    )
    def test_string_pattern(self, msg: str, expected: TriggerResult):
        assert classify_error(Exception(msg)) == expected

    def test_unknown_falls_through(self):
        assert (
            classify_error(Exception("completely unexpected error"))
            == TriggerResult.UNKNOWN_ERROR
        )
