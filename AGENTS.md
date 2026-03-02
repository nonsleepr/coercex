# coercex -- Agent Guidelines

Async NTLM authentication coercion scanner replacing Coercer.  Two modes:
**scan** (detect vulnerable methods, runs local listener) and **coerce**
(fire-and-forget triggers aimed at an external relay).

## Build & Run

```bash
# Install into venv (always use uv, never pip directly)
uv sync

# Run the CLI
uv run coercex scan  TARGET -l LISTENER_IP
uv run coercex coerce TARGET -l RELAY_IP

# Editable install already handled by uv sync; no separate pip install -e.
```

## Lint & Type-check

```bash
# Ruff -- via nix (no local install)
nix run nixpkgs#ruff -- check src/
nix run nixpkgs#ruff -- format --check src/

# mypy -- installed as dev dep
uv run mypy src/coercex/
```

No `[tool.ruff]` or `[tool.mypy]` config exists; tools run with defaults.

## Tests

No test suite exists yet.  When adding tests:

```bash
# Add pytest as a dev dependency
uv add --dev pytest pytest-asyncio

# Run all tests
uv run pytest

# Run a single test
uv run pytest tests/test_foo.py::test_bar -v
```

Place tests under `tests/` at the repo root, mirroring `src/coercex/` layout.
Use `pytest-asyncio` for any async test functions.

## Project Layout

```
src/coercex/
  cli.py          Typer CLI (scan + coerce commands, Rich output)
  connection.py   DCERPCPool, trigger_method(), async connection pooling
  listener.py     SMB2 + HTTP listener, NTLM token correlation, hash capture
  scanner.py      Scan/coerce orchestrator, semaphore-bounded async pipeline
  redirect.py     Port redirect: pydivert (Windows only)
  utils.py        TriggerResult enum, ScanResult, dataclasses, classify_error()
  methods/
    base.py       CoercionMethod dataclass, METHODS registry
    ms_efsr.py    10 methods  (MS-EFSR / EfsRpc*)
    ms_rprn.py    2 methods   (MS-RPRN / RpcRemoteFindFirstPrinterChangeNotification*)
    ms_dfsnm.py   2 methods   (MS-DFSNM / NetrDfsAddStdRoot, NetrDfsRemoveStdRoot)
    ms_fsrvp.py   2 methods   (MS-FSRVP / IsPathSupported, IsPathShadowCopied)
    ms_even.py    1 method    (MS-EVEN / ElfrOpenBELW)
    ms_par.py     1 method    (MS-PAR / RpcAsyncOpenPrinter)
    ms_tsch.py    1 method    (MS-TSCH / SchRpcRegisterTask)
```

## Code Style

### Imports

- Always start with `from __future__ import annotations`.
- Three groups separated by blank lines: stdlib, third-party, local.
- Alphabetical within each group.
- Heavy imports (impacket) should be deferred inside functions to keep
  module-level import time low.

### Formatting & Naming

- Modules: `snake_case`.  Classes: `PascalCase`.  Constants/enum members:
  `SCREAMING_SNAKE`.  Private names: leading `_`.
- Section dividers: `# -- Name --------------------` style.
- Logger: always `log = logging.getLogger("coercex.<module>")` (never `logger`).
- Log calls use `%`-style formatting, never f-strings.

### Types

- PEP 604 unions: `str | None`, not `Optional[str]` (exception: Typer
  `Annotated` signatures where `Optional` is required).
- Lowercase generics: `list[str]`, `dict[str, Any]`.
- Use `Any` for impacket objects that lack type stubs.
- Trigger functions (`_trigger_*` in method files) are currently untyped.

### Data Structures

- Prefer `@dataclass` for all structured data.  No NamedTuple, TypedDict,
  attrs, or Pydantic.

### Error Handling

- String-based classification via `classify_error()` in `utils.py`.
- Layered try/except with increasing generality.
- No custom exception classes.

### Async Patterns

- `asyncio.to_thread()` wraps all synchronous impacket calls.
- `asyncio.Semaphore` for bounded concurrency.
- `asyncio.start_server` for listeners.
- Double-lock pattern (global + per-key) for session pooling in
  `connection.py`.

### Docstrings & Comments

- Module-level docstrings are prose.
- Function docstrings: informal Google-ish style with `Args:` / `Returns:`.
- Use `match/case` for dispatch on enums and string literals.

### Commits

- Imperative mood.  Optional `feat:` / `fix:` / `docs:` prefix.

## OPSEC Considerations

See `research/opsec-smb-handshake.md` for the full analysis.

Key points for developers modifying the listener or trigger pipeline:

- coercex performs a **full SMB2 handshake** (NEGOTIATE, SESSION_SETUP,
  TREE_CONNECT) to capture Net-NTLMv2 hashes via token-based correlation.
- The RPC coercion call itself is the noisiest event; the handshake depth
  adds minimal incremental detection surface.
- SESSION_SETUP generates Windows events 4648/8004 **only** when NTLM
  auditing is explicitly enabled on the victim.
- TREE_CONNECT events (5140/5145) fire on the **listener** (our side), not
  the victim -- they do not increase victim-side noise.
- Completing the full handshake looks more legitimate than dropping the
  connection after NEGOTIATE.
- For high-security environments, prefer `--transport http` to avoid SMB
  event logging entirely.

Do not weaken the handshake (e.g., dropping SESSION_SETUP) without
understanding the detection trade-offs documented in the research file.

## Port Redirect & pydivert

`redirect.py` provides `PortRedirector` (ABC) with a Windows-only backend:

- **`PydivertRedirector`** (Windows) -- uses the WinDivert kernel driver via
  the `pydivert` package with daemon threads that rewrite packet ports in
  real time.

Linux iptables support was removed because it adds no value over direct port
binding (both require root, port conflicts are rare on pentesting boxes).

**Why it exists:** Standard UNC paths (`\\host\share`) always connect to port
445.  When the user cannot bind port 445 (e.g., Windows workstation with SMB
Server running), the listener binds a non-standard port (e.g., 4445) and the
redirector transparently forwards inbound traffic from 445 to 4445.

`pydivert` is a **conditional dependency** (`sys_platform == 'win32'` in
`pyproject.toml`).  Never import it unconditionally at module level.

## Key Design Decisions

- **impacket is synchronous** -- every DCERPC/SMB call goes through
  `asyncio.to_thread()`.  Never call impacket directly from an async
  context.
- **Connection pooling** -- `DCERPCPool` in `connection.py` keys sessions by
  `(target, pipe, uuid)`.  A double-lock pattern prevents duplicate
  connections to the same endpoint.
- **Callback correlation** -- Primary: token-based (embedded in NTLM
  challenge).  Fallback: IP-based FIFO with timestamps.  The fallback
  exists because some targets strip or ignore the token.
- **`--transport` accepts multiple values** -- scan/coerce can try both SMB
  and HTTP simultaneously.
- **19 methods across 7 protocols** -- all defined declaratively in
  `methods/ms_*.py` and registered in `methods/__init__.py`.
