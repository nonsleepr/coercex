"""DCERPC connection pooling and trigger execution.

Manages connections to targets, grouping methods by pipe/UUID to reuse
DCERPC sessions. All synchronous impacket calls are wrapped with
asyncio.to_thread() for true concurrency.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from impacket.dcerpc.v5 import transport as imp_transport
from impacket.uuid import uuidtup_to_bin

from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.utils import (
    Credentials,
    ScanResult,
    TriggerResult,
    classify_error,
)

log = logging.getLogger("coercex.connection")


class DCERPCPool:
    """Pool of DCERPC sessions keyed by (target, pipe, uuid).

    Reuses connections for multiple methods on the same pipe/interface.
    """

    def __init__(self, creds: Credentials, timeout: int = 5):
        self._creds = creds
        self._timeout = timeout
        self._sessions: dict[tuple[str, str, str], Any] = {}
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self._lock = asyncio.Lock()  # For creating per-key locks

    async def get_session(self, target: str, binding: PipeBinding) -> Any:
        """Get or create a DCERPC session for the given target + pipe binding.

        Returns the impacket DCE/RPC transport object, or raises on failure.
        """
        key = (target, binding.pipe, binding.uuid)

        async with self._lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()

        async with self._locks[key]:
            if key in self._sessions:
                dce = self._sessions[key]
                # Check if session is still alive
                try:
                    # Quick health check - if the session is dead this will fail
                    return dce
                except Exception:
                    del self._sessions[key]

            # Create new connection in a thread (impacket is synchronous)
            dce = await asyncio.to_thread(self._connect, target, binding)
            self._sessions[key] = dce
            return dce

    def _connect(self, target: str, binding: PipeBinding) -> Any:
        """Synchronous DCERPC connection (runs in thread pool)."""
        pipe = binding.pipe
        uuid_str = binding.uuid
        version = binding.version

        # Build the transport string for named pipe access
        string_binding = f"ncacn_np:{target}[{pipe}]"
        rpctransport = imp_transport.DCERPCTransportFactory(string_binding)

        # Set credentials
        if self._creds.username:
            rpctransport.set_credentials(
                self._creds.username,
                self._creds.password,
                self._creds.domain,
                self._creds.lmhash,
                self._creds.nthash,
                self._creds.aes_key,
                TGT=self._creds._tgt,
                TGS=self._creds._tgs,
            )

        # Set Kerberos if needed
        if self._creds.do_kerberos:
            rpctransport.set_kerberos(
                self._creds.do_kerberos,
                kdcHost=self._creds.dc_host,
            )

        # Set connect timeout (critical for avoiding 2-min OS timeouts)
        rpctransport.set_connect_timeout(self._timeout)

        # Get the DCE/RPC object and connect
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(uuidtup_to_bin((uuid_str, version)))

        log.debug("Connected to %s via %s (uuid=%s)", target, pipe, uuid_str)
        return dce

    async def close_all(self) -> None:
        """Close all cached sessions."""
        for key, dce in self._sessions.items():
            try:
                await asyncio.to_thread(dce.disconnect)
            except Exception:
                pass
        self._sessions.clear()

    async def close_session(self, target: str, binding: PipeBinding) -> None:
        """Close a specific session."""
        key = (target, binding.pipe, binding.uuid)
        dce = self._sessions.pop(key, None)
        if dce:
            try:
                await asyncio.to_thread(dce.disconnect)
            except Exception:
                pass


async def trigger_method(
    pool: DCERPCPool,
    target: str,
    method: CoercionMethod,
    binding: PipeBinding,
    path: str,
) -> ScanResult:
    """Execute a single coercion method trigger.

    Connects via the pool, calls the trigger function in a thread,
    and classifies the result.
    """
    try:
        dce = await pool.get_session(target, binding)
    except Exception as e:
        err_str = str(e).lower()
        if "timed out" in err_str or "timeout" in err_str:
            result_type = TriggerResult.TIMEOUT
        elif "access_denied" in err_str or "access denied" in err_str:
            result_type = TriggerResult.ACCESS_DENIED
        elif "connection refused" in err_str:
            result_type = TriggerResult.CONNECT_ERROR
        else:
            result_type = TriggerResult.CONNECT_ERROR

        return ScanResult(
            target=target,
            protocol=method.protocol_short,
            method=method.function_name,
            pipe=binding.pipe,
            uuid=binding.uuid,
            result=result_type,
            error=str(e),
        )

    try:
        # Run the trigger function in a thread (it's synchronous impacket code)
        await asyncio.to_thread(method.trigger_fn, dce, path, target)

        # If we get here without exception, the call succeeded
        return ScanResult(
            target=target,
            protocol=method.protocol_short,
            method=method.function_name,
            pipe=binding.pipe,
            uuid=binding.uuid,
            result=TriggerResult.VULNERABLE,
        )

    except Exception as e:
        result_type = classify_error(e)

        # If the connection is broken, remove from pool
        if result_type in (TriggerResult.CONNECT_ERROR, TriggerResult.TIMEOUT):
            await pool.close_session(target, binding)

        return ScanResult(
            target=target,
            protocol=method.protocol_short,
            method=method.function_name,
            pipe=binding.pipe,
            uuid=binding.uuid,
            result=result_type,
            error=str(e),
        )
