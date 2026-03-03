"""Tests for scanner _attempt flow and _drain_callbacks.

Covers changes from this session:
  - UNKNOWN_ERROR results now trigger callback waiting (same as ACCESSIBLE)
  - _drain_callbacks sweeps UNKNOWN_ERROR results for late callbacks
  - Three-tier callback resolution: token → IP FIFO → timestamp fallback

These tests mock the DCERPCPool and use a real AsyncListener to exercise
the scanner's _attempt method end-to-end without network access.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from coercex.listener import AsyncListener, AuthCallback
from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.models import (
    Credentials,
    Mode,
    ScanConfig,
    ScanResult,
    ScanStats,
    Transport,
    TriggerResult,
)
from coercex.scanner import Scanner

TARGET_IP = "10.0.0.5"
LISTENER_IP = "10.0.0.1"


def _make_method(name: str = "TestMethod") -> CoercionMethod:
    return CoercionMethod(
        protocol_short="MS-TEST",
        protocol_long="Test Protocol",
        function_name=name,
        opnum=1,
        vuln_args=["path"],
        pipe_bindings=[
            PipeBinding(
                pipe=r"\PIPE\test",
                uuid="11111111-1111-1111-1111-111111111111",
                version="1.0",
            )
        ],
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
        callback_timeout=0.1,  # Short timeout for tests
        smb_port=445,
        http_port=80,
        verbose=False,
    )
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _make_callback(
    *,
    token: str = "",
    src_ip: str = TARGET_IP,
    username: str = "",
    domain: str = "",
    ntlmv2_hash: str = "",
) -> AuthCallback:
    return AuthCallback(
        token=token,
        source_ip=src_ip,
        source_port=49152,
        timestamp=datetime.now(timezone.utc),
        transport="smb",
        username=username,
        domain=domain,
        ntlmv2_hash=ntlmv2_hash,
    )


def _mock_pool_result(result: TriggerResult, error: str = "") -> ScanResult:
    return ScanResult(
        target=TARGET_IP,
        protocol="MS-TEST",
        method="TestMethod",
        pipe=r"\PIPE\test",
        uuid="11111111-1111-1111-1111-111111111111",
        result=result,
        error=error,
    )


# ---------------------------------------------------------------------------
# _attempt: callback waiting on ACCESSIBLE / UNKNOWN_ERROR
# ---------------------------------------------------------------------------


class TestAttemptCallbackWait:
    """_attempt waits for callbacks on ACCESSIBLE and UNKNOWN_ERROR results."""

    @pytest.mark.asyncio
    async def test_accessible_with_token_callback_becomes_vulnerable(self) -> None:
        """ACCESSIBLE + token-based callback → VULNERABLE."""
        config = _make_config()
        scanner = Scanner(config)

        # Set up listener
        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        # Mock pool to return ACCESSIBLE
        mock_pool = AsyncMock()
        mock_pool.trigger_method = AsyncMock(
            return_value=_mock_pool_result(TriggerResult.ACCESSIBLE)
        )
        scanner._pool = mock_pool

        method = _make_method()
        binding = method.pipe_bindings[0]

        # We need to intercept create_token to resolve the future with a callback
        original_create_token = listener.create_token

        def patched_create_token(target_ip=""):
            token, future = original_create_token(target_ip=target_ip)

            # Schedule the token resolution shortly after creation
            async def resolve_later():
                await asyncio.sleep(0.01)
                cb = _make_callback(
                    token=token,
                    username="DC01$",
                    domain="CORP",
                    ntlmv2_hash="DC01$::CORP:hash1",
                )
                listener._resolve_token(token, cb)

            asyncio.create_task(resolve_later())
            return token, future

        listener.create_token = patched_create_token

        await scanner._attempt(
            TARGET_IP,
            method,
            binding,
            transport_override=Transport.SMB,
            path_style_override="share_file",
        )

        # Verify result was upgraded to VULNERABLE
        assert len(scanner.stats.results) == 1
        result = scanner.stats.results[0]
        assert result.result == TriggerResult.VULNERABLE
        assert result.callback_received is True
        assert result.auth_user == "CORP\\DC01$"
        assert result.ntlmv2_hash == "DC01$::CORP:hash1"

    @pytest.mark.asyncio
    async def test_unknown_error_with_callback_becomes_vulnerable(self) -> None:
        """UNKNOWN_ERROR + callback → VULNERABLE (new behavior)."""
        config = _make_config()
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        mock_pool = AsyncMock()
        mock_pool.trigger_method = AsyncMock(
            return_value=_mock_pool_result(
                TriggerResult.UNKNOWN_ERROR, error="weird error"
            )
        )
        scanner._pool = mock_pool

        method = _make_method()
        binding = method.pipe_bindings[0]

        original_create_token = listener.create_token

        def patched_create_token(target_ip=""):
            token, future = original_create_token(target_ip=target_ip)

            async def resolve_later():
                await asyncio.sleep(0.01)
                cb = _make_callback(
                    token=token,
                    username="DC01$",
                    domain="CORP",
                    ntlmv2_hash="DC01$::CORP:hash1",
                )
                listener._resolve_token(token, cb)

            asyncio.create_task(resolve_later())
            return token, future

        listener.create_token = patched_create_token

        await scanner._attempt(
            TARGET_IP,
            method,
            binding,
            transport_override=Transport.SMB,
            path_style_override="share_file",
        )

        assert len(scanner.stats.results) == 1
        result = scanner.stats.results[0]
        assert result.result == TriggerResult.VULNERABLE
        assert result.callback_received is True

    @pytest.mark.asyncio
    async def test_access_denied_cancels_token(self) -> None:
        """ACCESS_DENIED → token cancelled immediately, no callback wait."""
        config = _make_config()
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        mock_pool = AsyncMock()
        mock_pool.trigger_method = AsyncMock(
            return_value=_mock_pool_result(TriggerResult.ACCESS_DENIED)
        )
        scanner._pool = mock_pool

        method = _make_method()
        binding = method.pipe_bindings[0]

        # Track tokens created
        created_tokens: list[str] = []
        original_create_token = listener.create_token

        def patched_create_token(target_ip=""):
            token, future = original_create_token(target_ip=target_ip)
            created_tokens.append(token)
            return token, future

        listener.create_token = patched_create_token

        await scanner._attempt(
            TARGET_IP,
            method,
            binding,
            transport_override=Transport.SMB,
            path_style_override="share_file",
        )

        # Token should be cancelled
        assert len(created_tokens) == 1
        token = created_tokens[0]
        assert token not in listener._pending

        # Result should be ACCESS_DENIED, no callback
        assert len(scanner.stats.results) == 1
        result = scanner.stats.results[0]
        assert result.result == TriggerResult.ACCESS_DENIED
        assert result.callback_received is False

    @pytest.mark.asyncio
    async def test_accessible_no_callback_stays_accessible(self) -> None:
        """ACCESSIBLE + no callback → stays ACCESSIBLE."""
        config = _make_config(callback_timeout=0.05)
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        mock_pool = AsyncMock()
        mock_pool.trigger_method = AsyncMock(
            return_value=_mock_pool_result(TriggerResult.ACCESSIBLE)
        )
        scanner._pool = mock_pool

        method = _make_method()
        binding = method.pipe_bindings[0]

        await scanner._attempt(
            TARGET_IP,
            method,
            binding,
            transport_override=Transport.SMB,
            path_style_override="share_file",
        )

        assert len(scanner.stats.results) == 1
        result = scanner.stats.results[0]
        assert result.result == TriggerResult.ACCESSIBLE
        assert result.callback_received is False


# ---------------------------------------------------------------------------
# _attempt: timestamp fallback path
# ---------------------------------------------------------------------------


class TestAttemptTimestampFallback:
    """_attempt does NOT use timestamp fallback when token resolution times
    out -- this prevents false positives across transports/methods."""

    @pytest.mark.asyncio
    async def test_no_timestamp_fallback_stays_accessible(self) -> None:
        """ACCESSIBLE + timeout + has_connection but no token → stays ACCESSIBLE.

        Previously this would fall back to get_callback_since() and upgrade
        to VULNERABLE, causing cross-transport false positives.
        """
        config = _make_config(callback_timeout=0.05)
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        mock_pool = AsyncMock()
        mock_pool.trigger_method = AsyncMock(
            return_value=_mock_pool_result(TriggerResult.ACCESSIBLE)
        )
        scanner._pool = mock_pool

        method = _make_method()
        binding = method.pipe_bindings[0]

        original_create_token = listener.create_token

        def patched_create_token(target_ip=""):
            token, future = original_create_token(target_ip=target_ip)

            # Don't resolve the future (simulates token extraction failure)
            # But record a partial callback via IP
            async def record_partial():
                await asyncio.sleep(0.01)
                # Record connection timestamp
                listener._ip_callback_times.setdefault(TARGET_IP, []).append(
                    time.monotonic()
                )
                cb = _make_callback(
                    username="DC01$", domain="CORP", ntlmv2_hash="hash1"
                )
                listener._record_partial_callback(cb)

            asyncio.create_task(record_partial())
            return token, future

        listener.create_token = patched_create_token

        # Patch extended timeout to be short for tests
        with patch("coercex.scanner._TREE_CONNECT_EXTENDED_TIMEOUT", 0.1):
            await scanner._attempt(
                TARGET_IP,
                method,
                binding,
                transport_override=Transport.SMB,
                path_style_override="share_file",
            )

        assert len(scanner.stats.results) == 1
        result = scanner.stats.results[0]
        # Result stays ACCESSIBLE — no timestamp fallback upgrade
        assert result.result == TriggerResult.ACCESSIBLE
        assert result.callback_received is False


# ---------------------------------------------------------------------------
# _drain_callbacks
# ---------------------------------------------------------------------------


class TestDrainCallbacks:
    """_drain_callbacks only enriches VULNERABLE results missing auth_user.

    It no longer upgrades ACCESSIBLE/UNKNOWN_ERROR → VULNERABLE because
    timestamp-based correlation cannot distinguish which concurrent trigger
    caused a callback (cross-transport/cross-method false positives).
    """

    @pytest.mark.asyncio
    async def test_drain_does_not_upgrade_accessible(self) -> None:
        """ACCESSIBLE result stays ACCESSIBLE even if callback arrived late."""
        config = _make_config(callback_timeout=0.05)
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        scan_start = time.monotonic()

        # Manually add an ACCESSIBLE result
        result = ScanResult(
            target=TARGET_IP,
            protocol="MS-TEST",
            method="TestMethod",
            pipe=r"\PIPE\test",
            uuid="11111111-1111-1111-1111-111111111111",
            result=TriggerResult.ACCESSIBLE,
        )
        scanner.stats.add(result)

        # Simulate a late callback arriving
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        cb = _make_callback(username="DC01$", domain="CORP", ntlmv2_hash="hash1")
        listener._ip_latest_callback[TARGET_IP] = cb

        await scanner._drain_callbacks(scan_start)

        # No upgrade — result stays ACCESSIBLE
        assert result.result == TriggerResult.ACCESSIBLE
        assert result.callback_received is False
        assert scanner.stats.vulnerable == 0
        assert scanner.stats.accessible == 1

    @pytest.mark.asyncio
    async def test_drain_does_not_upgrade_unknown_error(self) -> None:
        """UNKNOWN_ERROR result stays UNKNOWN_ERROR even if callback arrived late."""
        config = _make_config(callback_timeout=0.05)
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        scan_start = time.monotonic()

        result = ScanResult(
            target=TARGET_IP,
            protocol="MS-TEST",
            method="TestMethod",
            pipe=r"\PIPE\test",
            uuid="11111111-1111-1111-1111-111111111111",
            result=TriggerResult.UNKNOWN_ERROR,
        )
        scanner.stats.add(result)

        # Simulate a late callback
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        cb = _make_callback(username="DC01$", domain="CORP", ntlmv2_hash="hash1")
        listener._ip_latest_callback[TARGET_IP] = cb

        await scanner._drain_callbacks(scan_start)

        # No upgrade — result stays UNKNOWN_ERROR
        assert result.result == TriggerResult.UNKNOWN_ERROR
        assert result.callback_received is False
        assert scanner.stats.vulnerable == 0
        assert scanner.stats.unknown_errors == 1

    @pytest.mark.asyncio
    async def test_drain_skips_when_no_drainable_results(self) -> None:
        """_drain_callbacks returns early if no VULNERABLE results missing auth_user."""
        config = _make_config(callback_timeout=0.05)
        scanner = Scanner(config)

        listener = AsyncListener(enable_http=False, enable_smb=False)
        listener._loop = asyncio.get_running_loop()
        scanner._listener = listener

        # Only ACCESS_DENIED results
        result = ScanResult(
            target=TARGET_IP,
            protocol="MS-TEST",
            method="TestMethod",
            pipe=r"\PIPE\test",
            uuid="11111111-1111-1111-1111-111111111111",
            result=TriggerResult.ACCESS_DENIED,
        )
        scanner.stats.add(result)

        start = time.monotonic()
        await scanner._drain_callbacks(start)

        # No change
        assert result.result == TriggerResult.ACCESS_DENIED

    @pytest.mark.asyncio
    async def test_drain_no_listener(self) -> None:
        """_drain_callbacks returns immediately if no listener."""
        config = _make_config(callback_timeout=0.05)
        scanner = Scanner(config)
        scanner._listener = None

        # Should not crash
        await scanner._drain_callbacks(time.monotonic())
