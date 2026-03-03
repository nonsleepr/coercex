"""Rich Live display for scan progress and results.

Two-section live display pinned to the terminal bottom:
  - Top:    Findings table — grows as interesting results arrive
  - Bottom: Per-target progress bars with inline status counters

The display is optional; Scanner falls back to line-by-line output
when no display is attached (e.g. in tests or piped output).
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console, Group
from rich.live import Live
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from coercex.models import ScanResult, STATUS_STYLE, TriggerResult


# -- Per-target progress tracking -------------------------------------------


@dataclass
class _TargetProgress:
    """Per-target scan progress counters."""

    total: int = 0
    completed: int = 0
    vulnerable: int = 0
    accessible: int = 0
    sent: int = 0
    access_denied: int = 0
    not_available: int = 0
    connect_errors: int = 0
    timeouts: int = 0
    unknown_errors: int = 0


# -- Main display class -----------------------------------------------------


class ScanDisplay:
    """Rich Live display combining per-target progress bars and a findings table.

    Phases (in order):
        probe  — pre-flight endpoint probing (single progress bar)
        scan   — trigger attempts (per-target progress bars)
        drain  — waiting for late callbacks
    """

    # Results shown in the live findings table.
    _INTERESTING = frozenset(
        {
            TriggerResult.VULNERABLE,
            TriggerResult.ACCESSIBLE,
            TriggerResult.SENT,
        }
    )

    def __init__(
        self,
        console: Console,
        targets: list[str],
        *,
        verbose: bool = False,
    ) -> None:
        self._console = console
        self._verbose = verbose
        self._targets = targets
        self._target_progress: dict[str, _TargetProgress] = {
            t: _TargetProgress() for t in targets
        }
        self._interesting_results: list[ScanResult] = []
        self._printed_hashes: set[str] = set()

        self._phase: str = "init"

        # Probe progress — single bar for the pre-flight phase
        self._probe_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Probing endpoints"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self._probe_task_id: TaskID | None = None

        # Scan progress — one bar per target
        max_target_len = max((len(t) for t in targets), default=15)
        self._scan_progress = Progress(
            TextColumn(f"  {{task.fields[target]:<{max_target_len}s}}"),
            BarColumn(bar_width=30),
            MofNCompleteColumn(),
            TextColumn("{task.fields[status]}"),
            console=console,
        )
        self._scan_task_ids: dict[str, TaskID] = {}
        for target in targets:
            tid = self._scan_progress.add_task(
                "",
                target=target,
                total=0,
                status="[dim]waiting[/]",
            )
            self._scan_task_ids[target] = tid

        self._live: Live | None = None

    # -- Lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Start the live display."""
        self._live = Live(
            self._build_layout(),
            console=self._console,
            refresh_per_second=4,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live display and restore normal terminal output."""
        if self._live:
            self._live.stop()
            self._live = None

    # -- Phase transitions ---------------------------------------------------

    def start_probe(self, total: int) -> None:
        """Enter the pre-flight probe phase."""
        self._phase = "probe"
        self._probe_task_id = self._probe_progress.add_task("probe", total=total)
        self._refresh()

    def advance_probe(self, advance: int = 1) -> None:
        """Advance the probe progress bar."""
        if self._probe_task_id is not None:
            self._probe_progress.advance(self._probe_task_id, advance)
            self._refresh()

    def finish_probe(
        self,
        reachable: dict[str, int] | None = None,
        total_bindings: int = 0,
    ) -> None:
        """Finish probe phase, print summary, and switch to scan phase."""
        if self._probe_task_id is not None:
            task = self._probe_progress.tasks[0]
            self._probe_progress.update(self._probe_task_id, completed=task.total)

        # Print probe summary above the live display
        if reachable is not None:
            for target in self._targets:
                n = reachable.get(target, 0)
                if n == 0:
                    self._console.print(
                        f"  [dim]{target}: 0/{total_bindings} endpoints reachable[/]"
                    )
                else:
                    self._console.print(
                        f"  {target}: [bold]{n}[/]/{total_bindings} endpoints reachable"
                    )

        self._phase = "scan"
        self._refresh()

    def start_drain(self) -> None:
        """Enter the drain phase (waiting for late callbacks)."""
        self._phase = "drain"
        self._refresh()

    def finish_drain(self) -> None:
        """Leave the drain phase — removes the 'Waiting…' text."""
        self._phase = "done"
        self._refresh()

    # -- Target management ---------------------------------------------------

    def set_target_total(self, target: str, total: int) -> None:
        """Set total expected attempts for a target (after pre-flight)."""
        tp = self._target_progress.get(target)
        if tp:
            tp.total = total
        if target in self._scan_task_ids:
            status = "[dim]no reachable endpoints[/]" if total == 0 else "[dim]...[/]"
            self._scan_progress.update(
                self._scan_task_ids[target],
                total=total,
                status=status,
            )
        self._refresh()

    def mark_target_done(self, target: str, reason: str = "done") -> None:
        """Mark a target as complete (e.g. vulnerable found)."""
        tp = self._target_progress.get(target)
        if tp and target in self._scan_task_ids:
            self._scan_progress.update(
                self._scan_task_ids[target],
                completed=tp.total,
                status=f"[bold green]{reason}[/]",
            )
        self._refresh()

    # -- Result reporting ----------------------------------------------------

    def add_result(self, result: ScanResult) -> None:
        """Record a completed attempt and update the display."""
        target = result.target
        tp = self._target_progress.get(target)
        if tp:
            tp.completed += 1
            self._increment_counter(tp, result.result)

            self._scan_progress.update(
                self._scan_task_ids[target],
                completed=tp.completed,
                status=self._format_counters(tp),
            )

        if result.result in self._INTERESTING:
            self._interesting_results.append(result)

        # Immediate notification for VULNERABLE results above the live display
        if result.result == TriggerResult.VULNERABLE:
            auth = f" [bold magenta]{result.auth_user}[/]" if result.auth_user else ""
            tr = f" [dim]({result.transport})[/]" if result.transport else ""
            self._console.print(
                f"  [bold green][+] VULNERABLE[/] {result.target} "
                f"[blue]{result.protocol}[/]::{result.method}"
                f"{tr}{auth}"
            )

        # Print captured hash above the live display (deduplicate)
        if result.ntlmv2_hash and result.ntlmv2_hash not in self._printed_hashes:
            self._printed_hashes.add(result.ntlmv2_hash)
            self._console.print(
                f"    [bold yellow]Hash:[/] {result.ntlmv2_hash}",
                highlight=False,
            )

        self._refresh()

    def result_upgraded(
        self,
        result: ScanResult,
        old_status: TriggerResult,
    ) -> None:
        """Notify that a previously-reported result was upgraded.

        Called by the drain phase when ACCESSIBLE/UNKNOWN_ERROR results
        are upgraded to VULNERABLE after a late callback arrives.
        Does NOT increment the completed counter.
        """
        target = result.target
        tp = self._target_progress.get(target)
        if tp:
            # Adjust counters: decrement old, increment new
            self._decrement_counter(tp, old_status)
            self._increment_counter(tp, result.result)

            self._scan_progress.update(
                self._scan_task_ids[target],
                status=self._format_counters(tp),
            )

        # Add to interesting list if it wasn't there before
        if old_status not in self._INTERESTING and result.result in self._INTERESTING:
            self._interesting_results.append(result)
        # If it was already interesting (e.g. ACCESSIBLE→VULNERABLE), the
        # table rebuilds from the mutable ScanResult objects, so no action needed.

        # Notifications
        if result.result == TriggerResult.VULNERABLE:
            auth = f" [bold magenta]{result.auth_user}[/]" if result.auth_user else ""
            tr = f" [dim]({result.transport})[/]" if result.transport else ""
            self._console.print(
                f"  [bold green][+] UPGRADED → VULNERABLE[/] {result.target} "
                f"[blue]{result.protocol}[/]::{result.method}"
                f"{tr}{auth}"
            )
        if result.ntlmv2_hash and result.ntlmv2_hash not in self._printed_hashes:
            self._printed_hashes.add(result.ntlmv2_hash)
            self._console.print(
                f"    [bold yellow]Hash:[/] {result.ntlmv2_hash}",
                highlight=False,
            )

        self._refresh()

    # -- Counter helpers -----------------------------------------------------

    @staticmethod
    def _increment_counter(tp: _TargetProgress, status: TriggerResult) -> None:
        match status:
            case TriggerResult.VULNERABLE:
                tp.vulnerable += 1
            case TriggerResult.ACCESSIBLE:
                tp.accessible += 1
            case TriggerResult.SENT:
                tp.sent += 1
            case TriggerResult.ACCESS_DENIED:
                tp.access_denied += 1
            case TriggerResult.NOT_AVAILABLE:
                tp.not_available += 1
            case TriggerResult.CONNECT_ERROR:
                tp.connect_errors += 1
            case TriggerResult.TIMEOUT:
                tp.timeouts += 1
            case TriggerResult.UNKNOWN_ERROR:
                tp.unknown_errors += 1

    @staticmethod
    def _decrement_counter(tp: _TargetProgress, status: TriggerResult) -> None:
        match status:
            case TriggerResult.VULNERABLE:
                tp.vulnerable -= 1
            case TriggerResult.ACCESSIBLE:
                tp.accessible -= 1
            case TriggerResult.SENT:
                tp.sent -= 1
            case TriggerResult.ACCESS_DENIED:
                tp.access_denied -= 1
            case TriggerResult.NOT_AVAILABLE:
                tp.not_available -= 1
            case TriggerResult.CONNECT_ERROR:
                tp.connect_errors -= 1
            case TriggerResult.TIMEOUT:
                tp.timeouts -= 1
            case TriggerResult.UNKNOWN_ERROR:
                tp.unknown_errors -= 1

    # -- Rendering -----------------------------------------------------------

    def _format_counters(self, tp: _TargetProgress) -> str:
        """Format inline status counters for a target's progress bar."""
        parts: list[str] = []
        if tp.vulnerable:
            parts.append(f"[bold green]{tp.vulnerable} vuln[/]")
        if tp.accessible:
            parts.append(f"[yellow]{tp.accessible} acc[/]")
        if tp.sent:
            parts.append(f"[cyan]{tp.sent} sent[/]")
        if tp.access_denied:
            parts.append(f"[red]{tp.access_denied} denied[/]")
        if tp.not_available:
            parts.append(f"[dim]{tp.not_available} n/a[/]")
        if tp.connect_errors:
            parts.append(f"[bold red]{tp.connect_errors} err[/]")
        if tp.timeouts:
            parts.append(f"[magenta]{tp.timeouts} tmout[/]")
        if tp.unknown_errors:
            parts.append(f"[dim red]{tp.unknown_errors} unk[/]")
        return " ".join(parts) if parts else "[dim]...[/]"

    def _build_results_table(self) -> Table | None:
        """Build the findings table from interesting results collected so far."""
        if not self._interesting_results:
            return None

        table = Table(
            title="Findings",
            show_lines=False,
            header_style="bold cyan",
            title_style="bold",
            expand=False,
        )
        table.add_column("Target", style="bold")
        table.add_column("Protocol", style="blue")
        table.add_column("Method")
        table.add_column("Pipe", style="dim")
        table.add_column("Transport", style="magenta")
        table.add_column("Status")
        table.add_column("Auth User", style="magenta")

        for r in self._interesting_results:
            style, sym = STATUS_STYLE.get(r.result, ("dim red", "[?]"))
            table.add_row(
                r.target,
                r.protocol,
                r.method,
                r.pipe,
                r.transport or "",
                f"[{style}]{sym} {r.result.value}[/]",
                r.auth_user or "",
            )

        return table

    def _build_layout(self) -> Group:
        """Build the combined renderable for the live display."""
        parts: list[Table | Progress | Text] = []

        # Results table (grows as interesting findings arrive)
        table = self._build_results_table()
        if table:
            parts.append(table)

        # Phase-specific progress section
        if self._phase == "probe":
            parts.append(self._probe_progress)
        elif self._phase in ("scan", "drain", "done"):
            parts.append(self._scan_progress)
            if self._phase == "drain":
                parts.append(
                    Text("  Waiting for late callbacks\u2026", style="dim italic")
                )
        else:
            parts.append(Text("  Initializing\u2026", style="dim"))

        return Group(*parts)

    def _refresh(self) -> None:
        """Rebuild and push the live display."""
        if self._live:
            self._live.update(self._build_layout())
