"""Base class for coercion methods."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class TriggerFn(Protocol):
    """Signature for RPC trigger functions.

    Args:
        dce: Impacket DCERPC transport session (untyped -- no stubs).
        path: UNC path pointing at the attacker-controlled listener.
        target: Target hostname or IP being coerced.
    """

    def __call__(self, dce: Any, path: str, target: str) -> None: ...


@dataclass
class PipeBinding:
    """A named pipe + interface UUID binding."""

    pipe: str  # e.g. r"\PIPE\efsrpc"
    uuid: str  # e.g. "df1941c5-fe89-4e79-bf10-463657acf44d"
    version: str = "1.0"


@dataclass
class CoercionMethod:
    """Declarative definition of a coercion method.

    Each instance describes one RPC function that can trigger NTLM
    authentication to an attacker-controlled UNC path.
    """

    # Protocol info
    protocol_short: str  # e.g. "MS-EFSR"
    protocol_long: (
        str  # e.g. "[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol"
    )

    # Function info
    function_name: str  # e.g. "EfsRpcOpenFileRaw"
    opnum: int  # e.g. 0
    vuln_args: list[str]  # e.g. ["FileName"]

    # Access bindings (named pipe transport)
    pipe_bindings: list[PipeBinding] = field(default_factory=list)

    # Path styles that work for this method
    # Each is (transport_type, path_style) where transport is "smb"/"http"
    # and path_style is one of: share_file, share_trailing, share, bare, unc_device
    path_styles: list[tuple[str, str]] = field(default_factory=list)

    # The trigger function: (dce, path, target) -> None; raises on error
    trigger_fn: TriggerFn | None = None

    # Optional: requires a pre-step (e.g., RPRN needs hRpcOpenPrinter first)
    needs_target_handle: bool = False

    def __repr__(self) -> str:
        return f"{self.protocol_short}::{self.function_name} (opnum {self.opnum})"

    def __str__(self) -> str:
        return (
            f"{self.protocol_short}──>{self.function_name}({', '.join(self.vuln_args)})"
        )
