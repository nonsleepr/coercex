"""Method registry - loads all coercion methods from protocol modules."""

from __future__ import annotations

from coercex.methods.base import CoercionMethod, PipeBinding
from coercex.methods.ms_efsr import get_methods as _efsr
from coercex.methods.ms_rprn import get_methods as _rprn
from coercex.methods.ms_dfsnm import get_methods as _dfsnm
from coercex.methods.ms_fsrvp import get_methods as _fsrvp
from coercex.methods.ms_even import get_methods as _even
from coercex.methods.ms_par import get_methods as _par
from coercex.methods.ms_tsch import get_methods as _tsch


ALL_PROTOCOL_LOADERS = [_efsr, _rprn, _dfsnm, _fsrvp, _even, _par, _tsch]

# Protocol short names for filtering
ALL_PROTOCOLS = [
    "MS-EFSR",
    "MS-RPRN",
    "MS-DFSNM",
    "MS-FSRVP",
    "MS-EVEN",
    "MS-PAR",
    "MS-TSCH",
]


def get_all_methods(protocols: list[str] | None = None) -> list[CoercionMethod]:
    """Load all coercion methods, optionally filtered by protocol.

    Args:
        protocols: List of protocol short names to include.
                   None = all protocols.

    Returns:
        List of CoercionMethod instances.
    """
    methods: list[CoercionMethod] = []
    for loader in ALL_PROTOCOL_LOADERS:
        loaded = loader()
        if protocols:
            loaded = [m for m in loaded if m.protocol_short in protocols]
        methods.extend(loaded)
    return methods


def group_by_pipe(
    methods: list[CoercionMethod],
) -> dict[tuple[str, str, str], list[CoercionMethod]]:
    """Group methods by (pipe, uuid, version) for connection reuse.

    Returns:
        Dict mapping (pipe, uuid, version) -> list of methods sharing that binding.
    """
    groups: dict[tuple[str, str, str], list[CoercionMethod]] = {}
    for method in methods:
        for binding in method.pipe_bindings:
            key = (binding.pipe, binding.uuid, binding.version)
            groups.setdefault(key, []).append(method)
    return groups


__all__ = [
    "CoercionMethod",
    "PipeBinding",
    "get_all_methods",
    "group_by_pipe",
    "ALL_PROTOCOLS",
]
