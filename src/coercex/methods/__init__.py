"""Method registry - loads all coercion methods from protocol modules."""

from __future__ import annotations

import fnmatch
import re

from coercex.methods.base import CoercionMethod, PipeBinding, TriggerFn
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


def _matches_any_pattern(name: str, patterns: list[str]) -> bool:
    """Check if name matches any of the given glob/regex patterns.

    Matching rules (checked in order):
    1. **Exact match** (case-insensitive) — if the pattern contains no
       glob wildcards (``*``, ``?``, ``[``) and no regex metacharacters,
       it must match the full method name exactly.
    2. **Glob match** — if the pattern contains ``*``, ``?``, or ``[``,
       use ``fnmatch`` (anchored: must match the *whole* name).
    3. **Regex match** — if the pattern contains regex-specific chars
       (``+``, ``{``, ``(``, ``^``, ``$``, ``|``, ``\\``), use
       ``re.fullmatch`` so the pattern must match the *entire* name.
    """
    _GLOB_CHARS = set("*?[")
    _REGEX_CHARS = set(r"+{(^$|\\.")

    for pat in patterns:
        has_glob = bool(_GLOB_CHARS & set(pat))
        has_regex = bool(_REGEX_CHARS & set(pat))

        if not has_glob and not has_regex:
            # Plain string — exact match only
            if name.lower() == pat.lower():
                return True
            continue

        if has_glob:
            # Glob match (fnmatch is already anchored — matches whole string)
            if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(name.lower(), pat.lower()):
                return True

        # Regex match — use fullmatch to prevent substring matching
        try:
            if re.fullmatch(pat, name, re.IGNORECASE):
                return True
        except re.error:
            pass
    return False


def get_all_methods(
    protocols: list[str] | None = None,
    methods_filter: list[str] | None = None,
    pipes_filter: list[str] | None = None,
) -> list[CoercionMethod]:
    """Load all coercion methods, optionally filtered.

    Args:
        protocols: List of protocol short names to include (e.g. ["MS-RPRN"]).
                   None = all protocols.
        methods_filter: Glob/regex patterns for method names.
                        e.g. ["RpcRemote*", "EfsRpc.*Raw"]
                        None = all methods.
        pipes_filter: Pipe names to restrict to (e.g. [r"\\PIPE\\spoolss"]).
                      None = all pipes.

    Returns:
        List of CoercionMethod instances (with pipe_bindings potentially
        filtered down by pipes_filter).
    """
    methods: list[CoercionMethod] = []
    for loader in ALL_PROTOCOL_LOADERS:
        loaded = loader()
        if protocols:
            loaded = [m for m in loaded if m.protocol_short in protocols]
        if methods_filter:
            loaded = [
                m
                for m in loaded
                if _matches_any_pattern(m.function_name, methods_filter)
            ]
        methods.extend(loaded)

    # Filter pipe bindings if pipes_filter is set
    if pipes_filter:
        # Normalize filter: strip backslashes for comparison
        norm_pipes = {p.replace("\\", "").lower() for p in pipes_filter}

        filtered: list[CoercionMethod] = []
        for m in methods:
            kept = [
                b
                for b in m.pipe_bindings
                if b.pipe.replace("\\", "").lower() in norm_pipes
                or b.pipe.lower() in {p.lower() for p in pipes_filter}
            ]
            if kept:
                # Shallow copy with filtered bindings
                from dataclasses import replace

                filtered.append(replace(m, pipe_bindings=kept))
        methods = filtered

    # Sort by priority (lower = higher priority = tried first)
    methods.sort(key=lambda m: m.priority)

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
    "TriggerFn",
    "get_all_methods",
    "group_by_pipe",
    "ALL_PROTOCOLS",
]
