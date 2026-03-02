"""Command-line interface for coercex.

Modern Typer-based CLI with Rich output.  Two subcommands:
  scan   - detect vulnerable methods (all path styles, optional listener)
  coerce - trigger coercion with listener (specific or all methods)
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Annotated

import typer
from rich.console import Console

from coercex import __version__
from coercex.models import (
    Credentials,
    Mode,
    ScanConfig,
    ScanStats,
    Transport,
)
from coercex.cli.options import (
    AesKeyOpt,
    CallbackTimeoutOpt,
    CcacheOpt,
    ConcurrencyOpt,
    DcHostOpt,
    DebugOpt,
    DomainOpt,
    HashesOpt,
    HttpPortOpt,
    JsonOpt,
    KerberosOpt,
    ListenerOpt,
    MethodsOpt,
    OutputFileOpt,
    PasswordOpt,
    PipesOpt,
    ProtocolsOpt,
    RedirectOpt,
    SmbPortOpt,
    StopOnVulnerableOpt,
    TargetOpt,
    TargetsFileOpt,
    TimeoutOpt,
    TransportOpt,
    UsernameOpt,
    VerboseOpt,
)
from coercex.cli.output import output_results

console = Console(stderr=True)
out_console = Console()

app = typer.Typer(
    name="coercex",
    help="Async NTLM authentication coercion scanner",
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
    """Async NTLM authentication coercion scanner."""


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

    None or empty -> both.  Accepts "smb", "http", or both.
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


@app.command()
def scan(
    target: TargetOpt = None,
    targets_file: TargetsFileOpt = None,
    listener: ListenerOpt = None,
    http_port: HttpPortOpt = 80,
    smb_port: SmbPortOpt = 445,
    transport: TransportOpt = None,
    callback_timeout: CallbackTimeoutOpt = 5.0,
    redirect: RedirectOpt = False,
    stop_on_vulnerable: StopOnVulnerableOpt = False,
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
        redirect=redirect,
        stop_on_vulnerable=stop_on_vulnerable,
        concurrency=concurrency,
        timeout=timeout,
        verbose=verbose,
        transport=_parse_transports(transport),
    )

    stats = asyncio.run(_run(config))
    output_results(stats, json_output, verbose, output_file or "")


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
    redirect: RedirectOpt = False,
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
        redirect=redirect,
        concurrency=concurrency,
        timeout=timeout,
        verbose=verbose,
    )

    stats = asyncio.run(_run(config))
    output_results(stats, json_output, verbose, output_file or "")


async def _run(config: ScanConfig) -> ScanStats:
    """Async entry point for the scanner."""
    from coercex.scanner import Scanner

    scanner = Scanner(config, console=console)
    return await scanner.run()


def main() -> None:
    """Entry point wrapper for ``python -m coercex``."""
    app()


if __name__ == "__main__":
    main()
