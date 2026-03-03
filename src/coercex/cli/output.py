"""Rich output formatters for scan/coerce results."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from coercex.models import ScanStats, STATUS_STYLE, TriggerResult

console = Console(stderr=True)
out_console = Console()


def format_results_table_rich(stats: ScanStats, show_all: bool = False) -> Table:
    """Build a Rich Table of scan results."""
    table = Table(
        title="Coercion Results",
        show_lines=False,
        header_style="bold cyan",
        title_style="bold",
    )
    table.add_column("Target", style="bold")
    table.add_column("Protocol", style="blue")
    table.add_column("Method")
    table.add_column("Pipe", style="dim")
    table.add_column("Transport", style="magenta")
    if show_all:
        table.add_column("Path Style", style="dim")
    table.add_column("Status")
    table.add_column("Auth User", style="magenta")

    results = stats.results
    if not show_all:
        results = [
            r
            for r in results
            if r.result
            in (TriggerResult.COERCED, TriggerResult.ACCESSIBLE, TriggerResult.SENT)
        ]

    for r in results:
        style, sym = STATUS_STYLE.get(r.result, ("dim red", "[?]"))
        row: list[str] = [
            r.target,
            r.protocol,
            r.method,
            r.pipe,
            r.transport or "",
        ]
        if show_all:
            row.append(r.path_style or "")
        row.append(f"[{style}]{sym} {r.result.value}[/]")
        row.append(r.auth_user or "")
        table.add_row(*row)

    return table


def format_results_json(stats: ScanStats, show_all: bool = False) -> str:
    """Format scan results as JSON."""
    import json

    results = stats.results
    if not show_all:
        results = [
            r
            for r in results
            if r.result
            in (TriggerResult.COERCED, TriggerResult.ACCESSIBLE, TriggerResult.SENT)
        ]

    data = {
        "summary": {
            "total_targets": stats.total_targets,
            "total_attempts": stats.total_attempts,
            "coerced": stats.coerced,
            "sent": stats.sent,
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
                "transport": r.transport,
                "path_style": r.path_style,
                "result": r.result.value,
                "callback_received": r.callback_received,
                "source_ip": r.source_ip,
                "auth_user": r.auth_user,
                "ntlmv2_hash": r.ntlmv2_hash,
                "error": r.error,
            }
            for r in results
        ],
    }
    return json.dumps(data, indent=2)


def output_results(
    stats: ScanStats,
    json_output: bool,
    verbose: bool,
    output_file: str,
) -> None:
    """Render results to stdout/file.

    When no ``--json`` or ``--output`` is given the live display already
    shows findings and per-target counters, so nothing extra is printed.
    """
    if json_output:
        output = format_results_json(stats, show_all=verbose)
        if output_file:
            with open(output_file, "w") as f:
                f.write(output + "\n")
            console.print(f"Results written to [bold]{output_file}[/]")
        else:
            out_console.print(output)
    elif output_file:
        table = format_results_table_rich(stats, show_all=verbose)
        file_console = Console(file=open(output_file, "w"), width=200)
        file_console.print(table)
        file_console.file.close()
        console.print(f"Results written to [bold]{output_file}[/]")
