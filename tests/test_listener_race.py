"""Tests for the listener FIFO race condition.

Demonstrates the race condition where multiple SMB connections from the
same target IP cause _resolve_by_ip() to consume a pending token before
_resolve_token() can be called via TREE_CONNECT.

Scenario:
    1. Scanner creates token_A for target 10.0.0.5
    2. Target fires back two simultaneous SMB connections (common behavior
       for PrinterBug/PetitPotam -- Windows often opens multiple SMB
       connections for a single coercion trigger)
    3. Connection 1's handshake fails before TREE_CONNECT (timeout, parse
       error, etc.) -> _resolve_by_ip() is called -> steals token_A's future
    4. Connection 2 completes the full handshake to TREE_CONNECT, extracts
       token_A from the share path -> _resolve_token(token_A, ...) is called
       -> but the future is ALREADY resolved by step 3, so this callback
       (which has the actual NTLM hash and correct token attribution) is
       silently dropped as "unknown/expired token"

The test calls the listener's internal methods directly to avoid needing
real SMB connections.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
import pytest_asyncio

from coercex.listener import AsyncListener, AuthCallback

TARGET_IP = "10.0.0.5"


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


# -- Sanity: token-based resolution works in the happy path ----------------


@pytest.mark.asyncio
async def test_token_resolution_happy_path(listener: AsyncListener) -> None:
    """Token-based resolution works when TREE_CONNECT succeeds."""
    token, future = listener.create_token(target_ip=TARGET_IP)

    callback = _make_callback(token=token, username="DC01$", ntlmv2_hash="aabb...")
    listener._resolve_token(token, callback)

    assert future.done()
    result = future.result()
    assert result.token == token
    assert result.username == "DC01$"
    assert result.ntlmv2_hash == "aabb..."


# -- Sanity: IP-based fallback works when there is one token ---------------


@pytest.mark.asyncio
async def test_ip_fallback_single_token(listener: AsyncListener) -> None:
    """IP-based fallback resolves the correct token when only one exists."""
    token, future = listener.create_token(target_ip=TARGET_IP)

    callback = _make_callback(username="DC01$")
    listener._resolve_by_ip(TARGET_IP, callback)

    assert future.done()
    result = future.result()
    # IP fallback sets the token on the callback
    assert result.token == token
    assert result.username == "DC01$"


# -- THE RACE CONDITION: _resolve_by_ip steals the token -------------------


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="BUG: _resolve_by_ip() steals token before _resolve_token() via TREE_CONNECT",
    strict=True,
)
async def test_race_resolve_by_ip_steals_token(listener: AsyncListener) -> None:
    """_resolve_by_ip() consumes token before _resolve_token() can use it.

    This replicates the real-world scenario where:
    - A single coercion trigger causes 2 SMB connections from the target
    - Connection 1 fails mid-handshake -> _resolve_by_ip() steals the token
    - Connection 2 completes TREE_CONNECT with the real token ->
      _resolve_token() finds the future already resolved

    The result: the future is resolved with a PARTIAL callback (no token
    in the path, no NTLM hash if the failure was early enough), and the
    COMPLETE callback from Connection 2 is silently dropped.
    """
    token, future = listener.create_token(target_ip=TARGET_IP)

    # Connection 1: handshake fails before TREE_CONNECT.
    # _handle_smb() error path calls _resolve_by_ip().
    partial_callback = _make_callback(
        username="",  # no NTLM metadata if failure was early
        ntlmv2_hash="",
    )
    listener._resolve_by_ip(TARGET_IP, partial_callback)

    # The future is now resolved with the PARTIAL callback
    assert future.done(), "Future should be resolved by IP fallback"

    # Connection 2: completes full handshake to TREE_CONNECT.
    # _handle_smb() success path calls _resolve_token().
    complete_callback = _make_callback(
        token=token,
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:aabbccdd...",
    )
    listener._resolve_token(token, complete_callback)

    # DESIRED: The future should contain the COMPLETE callback from
    # Connection 2 (with NTLM hash and username), not the empty partial
    # from Connection 1.
    final_result = future.result()
    assert final_result.username == "DC01$", (
        "Expected the complete callback with NTLM metadata, "
        f"but got username={final_result.username!r}"
    )


# -- RACE with late NTLM metadata: IP fallback gets credentials but wrong attribution


@pytest.mark.asyncio
async def test_race_ip_fallback_late_auth(listener: AsyncListener) -> None:
    """Even when _resolve_by_ip has credentials, token attribution is wrong.

    Scenario with 2 concurrent triggers for the same target:
    - token_A created for Method A, token_B created for Method B
    - Method B's callback arrives first, handshake fails -> _resolve_by_ip()
      consumes token_A (FIFO!) -> Method A's future resolved with wrong callback
    - Method A's callback arrives, completes TREE_CONNECT with token_A ->
      _resolve_token(token_A, ...) finds future already done -> dropped
    - Method B's future is never resolved (its token_B was second in FIFO
      and might be consumed by a later stray connection or left dangling)
    """
    token_a, future_a = listener.create_token(target_ip=TARGET_IP)
    token_b, future_b = listener.create_token(target_ip=TARGET_IP)

    # Method B's callback arrives first but handshake fails.
    # _resolve_by_ip() pops token_A (FIFO first!) -- WRONG token.
    method_b_callback = _make_callback(
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:method_b_hash",
    )
    listener._resolve_by_ip(TARGET_IP, method_b_callback)

    # future_a is resolved (it was FIFO first), but with Method B's callback
    assert future_a.done()
    result_a = future_a.result()
    # BUG: token_a's future has Method B's hash
    assert result_a.ntlmv2_hash == "DC01$::CORP:method_b_hash", (
        "BUG: token_a future resolved with Method B's callback data"
    )

    # future_b is NOT resolved yet
    assert not future_b.done(), "token_b future should not be resolved yet"

    # Now Method A's callback completes TREE_CONNECT with token_A
    method_a_callback = _make_callback(
        token=token_a,
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:method_a_hash",
    )
    listener._resolve_token(token_a, method_a_callback)

    # BUG: _resolve_token finds token_a already consumed, logs
    # "unknown/expired token" and drops method_a_callback.
    # future_a still has Method B's data.
    assert future_a.result().ntlmv2_hash == "DC01$::CORP:method_b_hash", (
        "future_a still has wrong (Method B) data after _resolve_token"
    )

    # Method B's callback with TREE_CONNECT containing token_B
    method_b_tree_callback = _make_callback(
        token=token_b,
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:method_b_real_hash",
    )
    listener._resolve_token(token_b, method_b_tree_callback)

    # future_b should now be resolved correctly via _resolve_token
    assert future_b.done(), "future_b should be resolved via _resolve_token"

    # BUG SUMMARY: In the end:
    # - future_a was resolved by _resolve_by_ip with Method B's partial callback
    #   (wrong attribution -- Method A gets credited with Method B's callback)
    # - future_b was resolved correctly via _resolve_token (if it reaches TREE_CONNECT)
    # - But if Method B's Connection 2 also fails, future_b is NEVER resolved


# -- RACE: Multiple connections from single trigger, only first one counted


@pytest.mark.asyncio
async def test_single_trigger_multiple_connections(listener: AsyncListener) -> None:
    """A single coercion trigger creates one token but multiple callbacks arrive.

    Windows commonly opens 2-3 SMB connections for a single UNC path access.
    Connection 1 may complete TREE_CONNECT. Connections 2+ have no pending
    token left after Connection 1 consumes it -> "no pending tokens" logged.

    This test verifies that at least the first connection's token resolution
    works correctly in the single-trigger case.
    """
    token, future = listener.create_token(target_ip=TARGET_IP)

    # Connection 1 completes TREE_CONNECT successfully
    conn1_callback = _make_callback(
        token=token,
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:hash1",
    )
    listener._resolve_token(token, conn1_callback)

    assert future.done()
    assert future.result().username == "DC01$"
    assert future.result().ntlmv2_hash == "DC01$::CORP:hash1"

    # Connection 2 also completes TREE_CONNECT with the same token.
    # _resolve_token() should handle this gracefully (log + discard).
    conn2_callback = _make_callback(
        token=token,
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:hash2",
    )
    listener._resolve_token(token, conn2_callback)

    # Future still has Connection 1's data (correct behavior)
    assert future.result().ntlmv2_hash == "DC01$::CORP:hash1"

    # Connection 3 fails mid-handshake, _resolve_by_ip called.
    # No pending tokens left -> should not crash.
    conn3_callback = _make_callback(username="DC01$")
    listener._resolve_by_ip(TARGET_IP, conn3_callback)  # should not raise


# -- RACE: _resolve_by_ip before _resolve_token in exception handler ------


@pytest.mark.asyncio
async def test_exception_handler_steals_token(listener: AsyncListener) -> None:
    """Simulates _handle_smb exception handlers calling _resolve_by_ip.

    In _handle_smb(), these exception handlers all call _resolve_by_ip():
    - TimeoutError (recv_netbios timeout)
    - IncompleteReadError (client disconnect)
    - ConnectionError/OSError (network error)
    - Generic Exception (parse error, etc.)

    If ANY of these fire before TREE_CONNECT, they steal the token via
    _resolve_by_ip(), and the scanner gets a callback without NTLM metadata.
    """
    token, future = listener.create_token(target_ip=TARGET_IP)

    # Simulate: Connection arrives, completes NTLM auth (Type 3 parsed),
    # but then recv_netbios for TREE_CONNECT times out.
    # The exception handler has accumulated username/hash from earlier steps
    # but _resolve_by_ip is called with whatever was accumulated.
    timeout_callback = _make_callback(
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:hashfromtype3",
    )
    listener._resolve_by_ip(TARGET_IP, timeout_callback)

    assert future.done()
    result = future.result()
    # At least in this single-connection case, we get the credentials
    assert result.username == "DC01$"
    assert result.ntlmv2_hash == "DC01$::CORP:hashfromtype3"

    # But the callback was attributed via IP, not token extraction.
    # With concurrent triggers, this would steal the wrong token.


# -- Edge case: _ip_fallback_callback used in early handshake failures -----


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="BUG: _ip_fallback_callback() steals token before TREE_CONNECT can deliver it",
    strict=True,
)
async def test_early_handshake_failure_steals_token(listener: AsyncListener) -> None:
    """_ip_fallback_callback() fires for early failures (bad magic, wrong cmd).

    These failures happen BEFORE NTLM auth, so the callback has NO credentials.
    The token is consumed with an empty callback.
    """
    token, future = listener.create_token(target_ip=TARGET_IP)

    # Simulate: Unknown SMB magic -> _ip_fallback_callback() -> _resolve_by_ip()
    # This is what happens at listener/__init__.py:446
    listener._ip_fallback_callback(TARGET_IP, 49152, b"\xde\xad\xbe\xef")

    assert future.done()
    result = future.result()
    assert result.username == ""  # no credentials from early failure
    assert result.ntlmv2_hash == ""  # no hash

    # The token is consumed with NO useful data.
    # A second connection with the actual TREE_CONNECT + NTLM arrives:
    real_callback = _make_callback(
        token=token,
        username="DC01$",
        domain="CORP",
        ntlmv2_hash="DC01$::CORP:realhash",
    )
    listener._resolve_token(token, real_callback)

    # DESIRED: The future should contain the REAL callback, not the empty one.
    assert future.result().username == "DC01$", (
        "Expected real callback with credentials"
    )
    assert future.result().ntlmv2_hash == "DC01$::CORP:realhash", "Expected real hash"
    listener._resolve_token(token, real_callback)

    # BUG: future still has the empty callback from the early failure
    assert future.result().username == "", (
        "BUG: Real callback with credentials was dropped"
    )
    assert future.result().ntlmv2_hash == "", "BUG: Real hash was dropped"
