"""Tests for listener callback flow: _record_partial_callback, get_callback_since, has_connection_from.

Covers changes from this session:
  - _record_partial_callback records in _ip_latest_callback without resolving futures
  - NTLM credential preservation (later partial callbacks don't overwrite earlier credentials)
  - get_callback_since returns the latest callback after a given timestamp
  - has_connection_from checks for any connection after a given timestamp
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from coercex.listener import AsyncListener, AuthCallback

TARGET_IP = "10.0.0.5"
OTHER_IP = "10.0.0.6"


def _make_callback(
    *,
    token: str = "",
    src_ip: str = TARGET_IP,
    src_port: int = 49152,
    username: str = "",
    domain: str = "",
    ntlmv2_hash: str = "",
) -> AuthCallback:
    return AuthCallback(
        token=token,
        source_ip=src_ip,
        source_port=src_port,
        timestamp=datetime.now(timezone.utc),
        transport="smb",
        username=username,
        domain=domain,
        ntlmv2_hash=ntlmv2_hash,
    )


@pytest_asyncio.fixture
async def listener() -> AsyncListener:
    """Create an AsyncListener with the event loop set (no servers started)."""
    lis = AsyncListener(enable_http=False, enable_smb=False)
    lis._loop = asyncio.get_running_loop()
    return lis


# ---------------------------------------------------------------------------
# _record_partial_callback
# ---------------------------------------------------------------------------


class TestRecordPartialCallback:
    """_record_partial_callback records data without resolving pending futures."""

    @pytest.mark.asyncio
    async def test_records_in_callbacks_list(self, listener: AsyncListener) -> None:
        """Partial callback is appended to the callbacks list."""
        cb = _make_callback()
        listener._record_partial_callback(cb)
        assert cb in listener.callbacks

    @pytest.mark.asyncio
    async def test_sets_ip_latest_callback(self, listener: AsyncListener) -> None:
        """Partial callback is stored in _ip_latest_callback."""
        cb = _make_callback()
        listener._record_partial_callback(cb)
        assert listener._ip_latest_callback[TARGET_IP] is cb

    @pytest.mark.asyncio
    async def test_does_not_resolve_future(self, listener: AsyncListener) -> None:
        """Partial callback must NOT resolve a pending future."""
        _token, future = listener.create_token(target_ip=TARGET_IP)
        cb = _make_callback()
        listener._record_partial_callback(cb)
        assert not future.done()

    @pytest.mark.asyncio
    async def test_preserves_credentials_from_earlier_callback(
        self, listener: AsyncListener
    ) -> None:
        """A partial callback without credentials must not overwrite one that has them."""
        # First callback has NTLM credentials
        cb_with_creds = _make_callback(
            username="DC01$", domain="CORP", ntlmv2_hash="hash1"
        )
        listener._record_partial_callback(cb_with_creds)
        assert listener._ip_latest_callback[TARGET_IP].username == "DC01$"

        # Second callback has no credentials (concurrent connection failure)
        cb_no_creds = _make_callback(username="", ntlmv2_hash="")
        listener._record_partial_callback(cb_no_creds)

        # The callback with credentials is preserved
        assert listener._ip_latest_callback[TARGET_IP].username == "DC01$"
        assert listener._ip_latest_callback[TARGET_IP].ntlmv2_hash == "hash1"

    @pytest.mark.asyncio
    async def test_overwrites_when_new_has_credentials(
        self, listener: AsyncListener
    ) -> None:
        """A partial callback WITH credentials overwrites one without."""
        cb_no_creds = _make_callback(username="", ntlmv2_hash="")
        listener._record_partial_callback(cb_no_creds)

        cb_with_creds = _make_callback(
            username="DC01$", domain="CORP", ntlmv2_hash="hash1"
        )
        listener._record_partial_callback(cb_with_creds)

        assert listener._ip_latest_callback[TARGET_IP].username == "DC01$"

    @pytest.mark.asyncio
    async def test_overwrites_when_existing_has_no_username(
        self, listener: AsyncListener
    ) -> None:
        """First record with empty username gets overwritten by any later record."""
        cb1 = _make_callback(username="")
        listener._record_partial_callback(cb1)
        assert listener._ip_latest_callback[TARGET_IP] is cb1

        cb2 = _make_callback(username="")
        listener._record_partial_callback(cb2)
        # Both are empty, so the new one overwrites
        assert listener._ip_latest_callback[TARGET_IP] is cb2


# ---------------------------------------------------------------------------
# has_connection_from
# ---------------------------------------------------------------------------


class TestHasConnectionFrom:
    """has_connection_from checks _ip_callback_times for recent connections."""

    @pytest.mark.asyncio
    async def test_no_connections(self, listener: AsyncListener) -> None:
        """Returns False when no connections have been recorded."""
        assert listener.has_connection_from(TARGET_IP, 0.0) is False

    @pytest.mark.asyncio
    async def test_connection_after_timestamp(self, listener: AsyncListener) -> None:
        """Returns True when a connection arrived after the given timestamp."""
        before = time.monotonic()
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        assert listener.has_connection_from(TARGET_IP, before) is True

    @pytest.mark.asyncio
    async def test_connection_before_timestamp(self, listener: AsyncListener) -> None:
        """Returns False when all connections are before the given timestamp."""
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        after = time.monotonic() + 1.0
        assert listener.has_connection_from(TARGET_IP, after) is False

    @pytest.mark.asyncio
    async def test_wrong_ip(self, listener: AsyncListener) -> None:
        """Returns False for a different IP."""
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        assert listener.has_connection_from(OTHER_IP, 0.0) is False


# ---------------------------------------------------------------------------
# get_callback_since
# ---------------------------------------------------------------------------


class TestGetCallbackSince:
    """get_callback_since returns the latest callback for timestamp fallback."""

    @pytest.mark.asyncio
    async def test_no_callbacks(self, listener: AsyncListener) -> None:
        """Returns None when no callbacks exist."""
        assert listener.get_callback_since(TARGET_IP, 0.0) is None

    @pytest.mark.asyncio
    async def test_callback_after_timestamp(self, listener: AsyncListener) -> None:
        """Returns the latest callback when a connection arrived after timestamp."""
        before = time.monotonic()
        cb = _make_callback(username="DC01$", ntlmv2_hash="hash1")
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        listener._ip_latest_callback[TARGET_IP] = cb

        result = listener.get_callback_since(TARGET_IP, before)
        assert result is not None
        assert result.username == "DC01$"
        assert result.ntlmv2_hash == "hash1"

    @pytest.mark.asyncio
    async def test_callback_before_timestamp(self, listener: AsyncListener) -> None:
        """Returns None when all callbacks are before the given timestamp."""
        cb = _make_callback(username="DC01$")
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        listener._ip_latest_callback[TARGET_IP] = cb

        after = time.monotonic() + 1.0
        assert listener.get_callback_since(TARGET_IP, after) is None

    @pytest.mark.asyncio
    async def test_returns_latest_callback_with_credentials(
        self, listener: AsyncListener
    ) -> None:
        """get_callback_since returns _ip_latest_callback which should have credentials.

        Combined with _record_partial_callback's credential preservation,
        this ensures the scanner gets credentials even via timestamp fallback.
        """
        before = time.monotonic()

        # Record partial callback with credentials
        cb_with_creds = _make_callback(
            username="DC01$", domain="CORP", ntlmv2_hash="hash1"
        )
        listener._record_partial_callback(cb_with_creds)
        # Also record timestamp (normally done by _handle_smb)
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())

        # Later partial callback without credentials should not overwrite
        cb_no_creds = _make_callback(username="")
        listener._record_partial_callback(cb_no_creds)

        result = listener.get_callback_since(TARGET_IP, before)
        assert result is not None
        assert result.username == "DC01$"
        assert result.ntlmv2_hash == "hash1"

    @pytest.mark.asyncio
    async def test_wrong_ip_returns_none(self, listener: AsyncListener) -> None:
        """Returns None for a different IP."""
        cb = _make_callback(username="DC01$")
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())
        listener._ip_latest_callback[TARGET_IP] = cb

        assert listener.get_callback_since(OTHER_IP, 0.0) is None


# ---------------------------------------------------------------------------
# Integration: partial callback + get_callback_since for scanner fallback
# ---------------------------------------------------------------------------


class TestPartialCallbackTimestampFallback:
    """End-to-end: partial callback recorded → scanner uses get_callback_since."""

    @pytest.mark.asyncio
    async def test_partial_callback_visible_via_timestamp_fallback(
        self, listener: AsyncListener
    ) -> None:
        """After _record_partial_callback, get_callback_since can find it.

        This is the core scanner fallback path: trigger fires, future times
        out, but has_connection_from() returns True, so scanner calls
        get_callback_since() and finds the partial callback.
        """
        t_before = time.monotonic()
        _token, future = listener.create_token(target_ip=TARGET_IP)

        # Simulate _handle_smb recording a connection time
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())

        # Handshake failure -> _record_partial_callback with credentials
        cb = _make_callback(username="DC01$", domain="CORP", ntlmv2_hash="hash1")
        listener._record_partial_callback(cb)

        # Future NOT resolved (partial callback doesn't resolve futures)
        assert not future.done()

        # But has_connection_from and get_callback_since work
        assert listener.has_connection_from(TARGET_IP, t_before) is True
        result = listener.get_callback_since(TARGET_IP, t_before)
        assert result is not None
        assert result.username == "DC01$"

    @pytest.mark.asyncio
    async def test_cancel_token_after_partial_callback(
        self, listener: AsyncListener
    ) -> None:
        """cancel_token after _record_partial_callback cleans up properly.

        For ACCESS_DENIED results, the scanner calls cancel_token() to clean
        up. The partial callback data should still be available via
        get_callback_since() since it's stored in _ip_latest_callback, not
        in _pending.
        """
        t_before = time.monotonic()
        token, future = listener.create_token(target_ip=TARGET_IP)

        # Record connection timestamp
        listener._ip_callback_times.setdefault(TARGET_IP, []).append(time.monotonic())

        # Partial callback recorded
        cb = _make_callback(username="DC01$", ntlmv2_hash="hash1")
        listener._record_partial_callback(cb)

        # Scanner cancels the token (e.g., for ACCESS_DENIED result)
        listener.cancel_token(token)
        assert future.cancelled()

        # But callback data is still available via timestamp fallback
        result = listener.get_callback_since(TARGET_IP, t_before)
        assert result is not None
        assert result.username == "DC01$"
