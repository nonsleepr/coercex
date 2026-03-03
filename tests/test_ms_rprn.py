"""Tests for MS-RPRN NDRCALL classes (opnum 62) and method registration.

Covers changes from this session:
  - Locally-defined RpcRemoteFindFirstPrinterChangeNotification (opnum 62)
  - Response class for opnum 62
  - Both MS-RPRN methods registered with correct priority and path styles
"""

from __future__ import annotations

import pytest

from coercex.methods.ms_rprn import (
    RpcRemoteFindFirstPrinterChangeNotification,
    RpcRemoteFindFirstPrinterChangeNotificationResponse,
    get_methods,
)


# ---------------------------------------------------------------------------
# NDRCALL class structure (opnum 62)
# ---------------------------------------------------------------------------


class TestRpcRemoteFindFirstPrinterChangeNotification:
    """Locally-defined NDRCALL for opnum 62 has correct wire format."""

    def test_opnum(self):
        assert RpcRemoteFindFirstPrinterChangeNotification.opnum == 62

    def test_structure_fields(self):
        """Structure matches [MS-RPRN] section 3.1.4.10.3."""
        field_names = [
            f[0] for f in RpcRemoteFindFirstPrinterChangeNotification.structure
        ]
        assert "hPrinter" in field_names
        assert "fdwFlags" in field_names
        assert "fdwOptions" in field_names
        assert "pszLocalMachine" in field_names
        assert "dwPrinterLocal" in field_names
        assert "cbBuffer" in field_names
        assert "pBuffer" in field_names

    def test_structure_has_seven_fields(self):
        """opnum 62 has 7 fields (vs. opnum 65 which uses pOptions)."""
        assert len(RpcRemoteFindFirstPrinterChangeNotification.structure) == 7

    def test_response_has_error_code(self):
        """Response class contains ErrorCode field."""
        field_names = [
            f[0] for f in RpcRemoteFindFirstPrinterChangeNotificationResponse.structure
        ]
        assert "ErrorCode" in field_names


# ---------------------------------------------------------------------------
# Method registration
# ---------------------------------------------------------------------------


class TestRprnMethodRegistration:
    """Both MS-RPRN methods are registered correctly."""

    def test_returns_two_methods(self):
        methods = get_methods()
        assert len(methods) == 2

    def test_method_names(self):
        methods = get_methods()
        names = {m.function_name for m in methods}
        assert "RpcRemoteFindFirstPrinterChangeNotificationEx" in names
        assert "RpcRemoteFindFirstPrinterChangeNotification" in names

    def test_opnums(self):
        methods = get_methods()
        opnums = {m.opnum for m in methods}
        assert 65 in opnums  # Ex variant
        assert 62 in opnums  # Non-Ex variant

    def test_protocol_short(self):
        methods = get_methods()
        assert all(m.protocol_short == "MS-RPRN" for m in methods)

    def test_priority(self):
        """Both methods should have priority 2 (PrinterBug)."""
        methods = get_methods()
        assert all(m.priority == 2 for m in methods)

    def test_path_styles_are_bare(self):
        """MS-RPRN uses bare path style (no token in share name)."""
        methods = get_methods()
        for m in methods:
            styles = [s[1] for s in m.path_styles]
            assert "bare" in styles

    def test_needs_target_handle(self):
        """Both methods need a printer handle from hRpcOpenPrinter."""
        methods = get_methods()
        assert all(m.needs_target_handle for m in methods)

    def test_trigger_fns_are_not_none(self):
        """Both methods have trigger functions."""
        methods = get_methods()
        assert all(m.trigger_fn is not None for m in methods)

    def test_pipe_bindings(self):
        """Both methods bind to \\PIPE\\spoolss."""
        methods = get_methods()
        for m in methods:
            assert any(b.pipe == r"\PIPE\spoolss" for b in m.pipe_bindings)
