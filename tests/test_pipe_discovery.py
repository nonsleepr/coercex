"""Tests for scanner pipe discovery integration.

Verifies that Scanner._discover_pipes():
  - populates _available_pipes when enabled with credentials
  - is skipped when discover_pipes is False
  - is skipped when pipes_filter is set (--pipes forces explicit pipes)
  - is skipped for anonymous credentials
  - filters pre-flight probe bindings based on discovered pipes
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.models import (
    Credentials,
    Mode,
    ScanConfig,
    Transport,
)
from coercex.scanner import Scanner

TARGET_IP = "10.0.0.5"
LISTENER_IP = "10.0.0.1"


def _make_method(
    name: str = "TestMethod",
    pipe: str = r"\PIPE\test",
    uuid: str = "11111111-1111-1111-1111-111111111111",
) -> CoercionMethod:
    return CoercionMethod(
        protocol_short="MS-TEST",
        protocol_long="Test Protocol",
        function_name=name,
        opnum=1,
        vuln_args=["path"],
        pipe_bindings=[PipeBinding(pipe=pipe, uuid=uuid, version="1.0")],
        path_styles=[("smb", "share_file")],
        trigger_fn=lambda dce, path, target: None,
        priority=1,
    )


def _make_config(**overrides) -> ScanConfig:
    defaults = dict(
        targets=[TARGET_IP],
        mode=Mode.SCAN,
        listener_host=LISTENER_IP,
        transport={Transport.SMB},
        concurrency=10,
        callback_timeout=0.1,
        smb_port=445,
        http_port=80,
        verbose=False,
        discover_pipes=False,
    )
    defaults.update(overrides)
    return ScanConfig(**defaults)


# ---------------------------------------------------------------------------
# _discover_pipes: guard conditions
# ---------------------------------------------------------------------------


class TestDiscoverPipesGuards:
    """_discover_pipes is skipped under the right conditions."""

    @pytest.mark.asyncio
    async def test_skipped_when_disabled(self) -> None:
        """discover_pipes=False → _available_pipes stays empty."""
        config = _make_config(discover_pipes=False)
        scanner = Scanner(config)

        await scanner._discover_pipes()

        assert scanner._available_pipes == {}

    @pytest.mark.asyncio
    async def test_skipped_when_pipes_filter_set(self) -> None:
        """--pipes explicitly set → discovery skipped."""
        config = _make_config(
            discover_pipes=True,
            pipes_filter=[r"\PIPE\spoolss"],
            creds=Credentials(username="admin", password="pass"),
        )
        scanner = Scanner(config)

        await scanner._discover_pipes()

        assert scanner._available_pipes == {}

    @pytest.mark.asyncio
    async def test_skipped_when_no_credentials(self) -> None:
        """Anonymous credentials → discovery skipped with warning."""
        config = _make_config(
            discover_pipes=True,
            creds=Credentials(),  # No username
        )
        scanner = Scanner(config)

        await scanner._discover_pipes()

        assert scanner._available_pipes == {}

    @pytest.mark.asyncio
    @patch("coercex.pipes.enumerate_pipes")
    async def test_runs_when_enabled_with_creds(self, mock_enum: MagicMock) -> None:
        """discover_pipes=True + credentials → enumerate_pipes called."""
        mock_enum.return_value = {r"\PIPE\spoolss", r"\PIPE\efsrpc"}

        config = _make_config(
            discover_pipes=True,
            creds=Credentials(username="admin", password="pass"),
        )
        scanner = Scanner(config)

        await scanner._discover_pipes()

        mock_enum.assert_called_once_with(
            TARGET_IP,
            config.creds,
            config.timeout,
        )
        assert scanner._available_pipes[TARGET_IP] == {
            r"\PIPE\spoolss",
            r"\PIPE\efsrpc",
        }


# ---------------------------------------------------------------------------
# _discover_pipes: filtering effect on pre-flight probe
# ---------------------------------------------------------------------------


class TestDiscoverPipesFiltering:
    """Pipe discovery results filter the pre-flight probe binding set."""

    @pytest.mark.asyncio
    @patch("coercex.pipes.enumerate_pipes")
    async def test_runs_when_enabled_with_creds(self, mock_enum: MagicMock) -> None:
        """Bindings whose pipe was not discovered are not probed."""
        # Only spoolss is discovered — efsrpc should be skipped
        mock_enum.return_value = {r"\PIPE\spoolss"}

        config = _make_config(
            discover_pipes=True,
            creds=Credentials(username="admin", password="pass"),
        )
        scanner = Scanner(config)

        # Mock the pool so we can track which bindings were probed
        mock_pool = AsyncMock()
        mock_pool.get_session = AsyncMock(return_value=MagicMock())
        scanner._pool = mock_pool

        methods = [
            _make_method("SpoolMethod", pipe=r"\PIPE\spoolss", uuid="aaaa"),
            _make_method("EfsMethod", pipe=r"\PIPE\efsrpc", uuid="bbbb"),
        ]

        await scanner._discover_pipes()
        await scanner._probe_endpoints(methods)

        # Only the spoolss binding should have been probed
        probed_pipes = {
            call.args[1].pipe for call in mock_pool.get_session.call_args_list
        }
        assert r"\PIPE\spoolss" in probed_pipes
        assert r"\PIPE\efsrpc" not in probed_pipes

    @pytest.mark.asyncio
    async def test_all_bindings_probed_when_discovery_disabled(self) -> None:
        """Without pipe discovery, all bindings are probed."""
        config = _make_config(discover_pipes=False)
        scanner = Scanner(config)

        mock_pool = AsyncMock()
        mock_pool.get_session = AsyncMock(return_value=MagicMock())
        scanner._pool = mock_pool

        methods = [
            _make_method("SpoolMethod", pipe=r"\PIPE\spoolss", uuid="aaaa"),
            _make_method("EfsMethod", pipe=r"\PIPE\efsrpc", uuid="bbbb"),
        ]

        await scanner._probe_endpoints(methods)

        probed_pipes = {
            call.args[1].pipe for call in mock_pool.get_session.call_args_list
        }
        assert r"\PIPE\spoolss" in probed_pipes
        assert r"\PIPE\efsrpc" in probed_pipes

    @pytest.mark.asyncio
    @patch("coercex.pipes.enumerate_pipes")
    async def test_per_target_pipe_filtering(self, mock_enum: MagicMock) -> None:
        """If discovery runs but returns nothing, fall back to all bindings."""
        mock_enum.return_value = set()  # No pipes found

        config = _make_config(
            discover_pipes=True,
            creds=Credentials(username="admin", password="pass"),
        )
        scanner = Scanner(config)

        mock_pool = AsyncMock()
        mock_pool.get_session = AsyncMock(return_value=MagicMock())
        scanner._pool = mock_pool

        methods = [
            _make_method("SpoolMethod", pipe=r"\PIPE\spoolss", uuid="aaaa"),
        ]

        await scanner._discover_pipes()
        await scanner._probe_endpoints(methods)

        # Empty result means target not in _available_pipes → fallback
        probed_pipes = {
            call.args[1].pipe for call in mock_pool.get_session.call_args_list
        }
        assert r"\PIPE\spoolss" in probed_pipes


# ---------------------------------------------------------------------------
# _discover_pipes: multi-target
# ---------------------------------------------------------------------------


class TestDiscoverPipesMultiTarget:
    """Pipe discovery with multiple targets."""

    @pytest.mark.asyncio
    @patch("coercex.pipes.enumerate_pipes")
    async def test_per_target_pipe_filtering(self, mock_enum: MagicMock) -> None:
        """Each target gets its own set of discovered pipes."""
        target_a = "10.0.0.1"
        target_b = "10.0.0.2"

        def _enum_side_effect(target, creds, timeout):
            if target == target_a:
                return {r"\PIPE\spoolss"}
            elif target == target_b:
                return {r"\PIPE\spoolss", r"\PIPE\efsrpc"}
            return set()

        mock_enum.side_effect = _enum_side_effect

        config = _make_config(
            targets=[target_a, target_b],
            discover_pipes=True,
            creds=Credentials(username="admin", password="pass"),
        )
        scanner = Scanner(config)

        mock_pool = AsyncMock()
        mock_pool.get_session = AsyncMock(return_value=MagicMock())
        scanner._pool = mock_pool

        methods = [
            _make_method("SpoolMethod", pipe=r"\PIPE\spoolss", uuid="aaaa"),
            _make_method("EfsMethod", pipe=r"\PIPE\efsrpc", uuid="bbbb"),
        ]

        await scanner._discover_pipes()
        await scanner._probe_endpoints(methods)

        # Collect probed (target, pipe) pairs
        probed = {
            (call.args[0], call.args[1].pipe)
            for call in mock_pool.get_session.call_args_list
        }

        # target_a: only spoolss
        assert (target_a, r"\PIPE\spoolss") in probed
        assert (target_a, r"\PIPE\efsrpc") not in probed

        # target_b: both
        assert (target_b, r"\PIPE\spoolss") in probed
        assert (target_b, r"\PIPE\efsrpc") in probed
