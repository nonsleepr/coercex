"""Shared Typer option type aliases for CLI commands."""

from __future__ import annotations

from typing import Annotated, Optional

import typer

from coercex.methods import ALL_PROTOCOLS

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
RedirectOpt = Annotated[
    bool,
    typer.Option(
        "--redirect/--no-redirect",
        help=(
            "[Windows only] Redirect standard ports (445/80) to listener ports via "
            "pydivert (WinDivert kernel driver). Allows standard SMB UNC paths when "
            "binding non-standard ports (e.g. to avoid conflicts with SMB Server service). "
            "Requires Administrator privileges and pydivert package. "
            "On Linux/macOS, bind directly to ports 80/445 with sudo instead."
        ),
    ),
]
StopOnVulnerableOpt = Annotated[
    bool,
    typer.Option(
        "--stop-on-vulnerable",
        help=(
            "Stop scanning a target as soon as one vulnerable method is confirmed. "
            "Reduces noise but may miss additional vulnerable methods."
        ),
    ),
]
DelayOpt = Annotated[
    float,
    typer.Option(
        "--delay",
        help=(
            "Seconds to wait between attempts per target (default: 0). "
            "Use for OPSEC stealth (e.g. --delay 2 spreads attempts over time). "
            "Combine with -c 1 --transport http for maximum stealth."
        ),
    ),
]
