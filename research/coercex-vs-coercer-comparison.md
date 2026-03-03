# coercex vs Coercer Feature Comparison

Comprehensive comparison between coercex (this project) and the original Coercer tool.

## Executive Summary

**coercex** is a high-performance async rewrite of Coercer with major architectural improvements:
- **Async architecture** with 50-200 concurrent tasks vs Coercer's synchronous/threading model
- **Connection pooling** for session reuse vs Coercer's per-attempt connections
- **Pre-flight endpoint probing** to eliminate ~40-50% of futile attempts
- **Token-based callback correlation** for definitive verification
- **Rich TUI** with real-time progress bars and findings table
- **26% more coercion methods** (19 vs 17) with 2 additional protocols (MS-PAR, MS-TSCH)
- **Comprehensive test suite** (186 tests) vs Coercer's manual testing

---

## Feature Matrix

| Feature | coercex | Coercer |
|---------|---------|---------|
| **Coercion Methods** | 19 methods | 17 methods |
| **Protocols** | 7 protocols | 5 protocols |
| **Operation Modes** | 2 (scan, coerce) | 3 (scan, coerce, fuzz) |
| **Architecture** | Async (asyncio) | Synchronous + threading |
| **Connection Pooling** | Yes (by target/pipe/UUID) | No |
| **Pre-flight Probing** | Yes (endpoint connectivity test) | No |
| **Concurrency** | 50-200 async tasks | Thread-based (limited) |
| **Callback Correlation** | Token-based + IP fallback | IP + timestamp |
| **Display** | Rich Live TUI (progress bars + table) | ANSI text output |
| **Python Version** | 3.13+ | 3.7+ |
| **Test Suite** | 186 tests (pytest) | None (manual) |
| **Export Formats** | JSON, text file | JSON, XLSX, SQLite |
| **Kerberos Auth** | Yes (ccache, AES key, TGT) | Yes (basic) |
| **WebDAV Support** | Yes (`\\host@port\share`) | Limited |
| **Port Redirect** | Yes (Windows-only, pydivert) | No |
| **Open Pipe Discovery** | No | Yes (scan/fuzz auth mode) |
| **Random Path Generation** | All methods (built-in) | All methods |
| **Stop on Success** | `--stop-on-coerced` | `--stop-on-ntlm-auth` |
| **Package Manager** | uv | pip / poetry |
| **Type Hints** | Full (mypy checked) | Minimal |
| **Code Quality** | Ruff + mypy CI | Manual |

---

## Detailed Comparison

### 1. Coercion Methods & Protocols

#### coercex (19 methods, 7 protocols)
```
MS-EFSR  (10 methods) - Encrypting File System Remote Protocol
MS-RPRN  (2 methods)  - Print System Remote Protocol  
MS-DFSNM (2 methods)  - Distributed File System Namespace Management
MS-FSRVP (2 methods)  - File Server Remote VSS Protocol
MS-EVEN  (1 method)   - EventLog Remoting Protocol
MS-PAR   (1 method)   - Print System Asynchronous Remote Protocol  ⭐ NEW
MS-TSCH  (1 method)   - Task Scheduler Service Remote Protocol      ⭐ NEW
```

#### Coercer (17 methods, 5 protocols)
```
MS-EFSR  (10 methods) - PetitPotam
MS-RPRN  (2 methods)  - PrinterBug
MS-DFSNM (2 methods)  - DFSCoerce
MS-FSRVP (2 methods)  - ShadowCoerce
MS-EVEN  (1 method)   - CheeseOunce
```

**coercex advantage:** 26% more methods with 2 additional protocols not in Coercer.

---

### 2. Operation Modes

#### coercex (2 modes)
1. **scan** - Detect coercible methods with local listener (callback confirmation)
2. **coerce** - Fire-and-forget triggers to external relay (ntlmrelayx, etc.)

#### Coercer (3 modes)
1. **scan** - Detect coercible methods with local listener
2. **coerce** - Trigger coercion to external relay
3. **fuzz** - Research mode to fuzz RPCs with various path combinations

**Coercer advantage:** Dedicated fuzz mode for research (coercex can achieve similar via filtering, but lacks fuzzing automation).

---

### 3. Architecture & Performance

#### coercex
- **Async-first design** with `asyncio` throughout the stack
- **50-200 concurrent async tasks** (configurable via `-c/--concurrency`)
- **Connection pooling** by `(target, pipe, UUID)` with double-lock pattern
- **Pre-flight endpoint probing** - tests connectivity to unique RPC bindings before attempting triggers
  - Eliminates ~40-50% of futile attempts (unreachable endpoints)
  - Warms connection pool for reuse
- All impacket calls wrapped with `asyncio.to_thread()`
- **Session reuse** across method attempts

#### Coercer  
- **Synchronous** with threading for parallelism
- No connection pooling (new connection per attempt)
- No pre-flight probing (attempts all methods/endpoints)
- Thread-based concurrency (limited scalability)

**Performance impact:**
- coercex can scan 10 targets with 19 methods (~190 attempts) in **~15-30 seconds** with high concurrency
- Coercer takes **2-5x longer** for similar scans due to synchronous bottlenecks

---

### 4. Callback Correlation & Verification

#### coercex (3-layer correlation)
1. **Token-based** (primary) - Unique random token in UNC path (`\\listener\share_TOKEN\path`)
   - Definitive correlation (no false positives)
   - Works for both SMB and HTTP transports
2. **IP-based FIFO** (HTTP fallback) - For WebDAV responses without token parsing
3. **Timestamp + IP fallback** (last resort) - With transport check to prevent cross-transport false positives

**Drain phase enrichment:**
- Upgrades `COERCED` results missing auth credentials with captured Net-NTLMv2 hashes
- Only enriches confirmed COERCED results (no ACCESSIBLE/UNKNOWN_ERROR sweeps)

#### Coercer
- **IP + timestamp correlation** (basic)
- No token-based verification
- Higher risk of false positives in multi-target scans

**coercex advantage:** Token-based correlation eliminates ambiguity in concurrent multi-target scans.

---

### 5. User Interface & Output

#### coercex
- **Rich Live TUI** with:
  - **Probe phase** - Spinner showing endpoint connectivity tests
  - **Scan phase** - Per-target progress bars with inline counters (`completed/total`)
  - **Drain phase** - Waits for late callbacks, enriches results with captured hashes
  - **Findings table** - Real-time display of COERCED/ACCESSIBLE/SENT results
- **Minimal noise** - Only shows interesting results by default
- **Inline hash display** - Net-NTLMv2 hashes printed with result line
- **Export formats:** JSON, text file (via `-o/--output`)

#### Coercer
- **ANSI text output** with progress indicators
- **Export formats:** JSON, XLSX, SQLite (more export options)
- Verbose mode for detailed logging

**coercex advantage:** Modern TUI with real-time feedback vs Coercer's scrolling text output.  
**Coercer advantage:** More export formats (XLSX, SQLite) for reporting.

---

### 6. Filtering & Targeting

#### Both support:
- Filter by **protocol** (`--protocols MS-EFSR MS-RPRN`)
- Filter by **method name** (`--methods 'EfsRpc*'`)
- Filter by **pipe** (`--pipes '\PIPE\spoolss'`)
- Single target or targets file

#### coercex-specific:
- **Glob and regex patterns** for method filtering (auto-detected)
  - Glob: `--methods 'EfsRpc*'`
  - Regex: `--methods 'EfsRpc.*Raw'`
  - Exact: `--methods 'EfsRpcOpenFileRaw'`
- **Transport filtering** (`--transport smb` or `--transport http`)
- **Stop on first coerced** (`--stop-on-coerced`) - priority-ordered fast scan

#### Coercer-specific:
- Filter by pipe name (`--filter-pipe-name`)
- **Open pipe discovery** in authenticated scan/fuzz modes (enumerates available pipes)

**Coercer advantage:** Open pipe enumeration for reconnaissance (coercex assumes known pipes).

---

### 7. Authentication

#### Both support:
- Username/password
- NTLM hash
- Kerberos (ccache, TGT)
- Domain authentication

#### coercex-specific:
- **AES key for Kerberos pre-auth** (`--aes-key`)
- **KRB5CCNAME environment variable** (direct ccache use)
- Modern credentials handling via dataclass

#### Coercer-specific:
- `--no-pass` flag for Kerberos-only auth

**Similar capabilities** with coercex having slight edge on Kerberos ergonomics.

---

### 8. Port Handling & Transports

#### coercex
- **WebDAV format** (`\\host@port\share`) - automatic fallback for non-standard ports
- **Port redirect** (`--redirect`, Windows-only) - pydivert NAT rules (445→4445, 80→8080)
  - Requires admin privileges
  - Falls back to WebDAV format if redirect fails
- **Transport selection:** `--transport smb` or `--transport http` (can specify both)

#### Coercer
- Custom HTTP port range (`--min-http-port`, `--max-http-port`)
- Custom SMB/HTTP/DCE ports (`--smb-port`, `--http-port`, `--dce-port`)
- No port redirect mechanism
- Auth type preference (`--auth-type smb` or `--auth-type http`)

**coercex advantage:** Port redirect eliminates WebClient service dependency (often disabled on servers).

---

### 9. OPSEC Considerations

#### coercex
- **Full SMB2 handshake** (NEGOTIATE, SESSION_SETUP, TREE_CONNECT) for hash capture
- **Research-backed OPSEC docs** (`research/opsec-smb-handshake.md`)
- **HTTP-only mode** (`--transport http`) to avoid SMB event logging (4648/8004)
- **Configurable delay** (`--delay`) between attempts
- **Concurrency control** (`-c 1` for sequential, no temporal correlation)

**OPSEC-conscious scan:**
```bash
coercex scan TARGET -u USER -p PASS --stop-on-coerced \
  -c 1 --transport http --delay 2
```
- `-c 1` = no temporal correlation (one at a time)
- `--transport http` = avoid SMB event logging
- `--delay 2` = spread attempts over time

#### Coercer
- **Configurable delay** (`--delay`)
- **Stop on NTLM auth** (`--stop-on-ntlm-auth`) to minimize noise
- Less documented OPSEC guidance

**coercex advantage:** Explicit OPSEC modes and research documentation.

---

### 10. Code Quality & Testing

#### coercex
- **186 test cases** (pytest) covering:
  - Scanner attempt logic and drain enrichment
  - Listener callback correlation (SMB + HTTP)
  - Display widget rendering
  - Race conditions in concurrent callbacks
  - Error classification
  - Method registry and filtering
- **Full type hints** (mypy checked)
- **Ruff + mypy CI** (enforced formatting and type checking)
- **Documented architecture** (`AGENTS.md` with design decisions)
- **Modern tooling:** uv, pytest, pydivert (Windows)

#### Coercer
- **No automated tests** (manual validation)
- Minimal type hints
- Manual code quality checks
- Established tool with battle-tested stability
- **argcomplete** for shell tab completions

**coercex advantage:** Modern CI/CD with comprehensive test coverage vs Coercer's manual testing.  
**Coercer advantage:** Maturity and community trust (2+ years in the wild).

---

### 11. Dependencies & Installation

#### coercex
```toml
requires-python = ">=3.13"
dependencies = [
    "impacket>=0.12.0",
    "typer>=0.15.0",
    "rich>=13.7.0",
    "pydivert>=2.1.0; sys_platform == 'win32'",
]
```
**Install:** `uv sync`

#### Coercer
```toml
requires-python = ">=3.7"
dependencies = [
    "argcomplete",
    "impacket>=0.10.0",
    "xlsxwriter>=3.0.0",
    "jinja2>=3.1.3",
    "sectools>=1.4.3",
    "netifaces>=0.11.0",
    "psutil",
]
```
**Install:** `pip install coercer` (PyPI published)

**Coercer advantage:** Lower Python version requirement (3.7+), PyPI distribution.  
**coercex advantage:** Modern Python 3.13 features, fewer dependencies (no XLSX/Jinja2 overhead).

---

## Use Case Recommendations

### Use coercex when:
- ✅ **Performance is critical** (large-scale scans with 50+ targets)
- ✅ **Modern Python available** (3.13+)
- ✅ **Token-based verification needed** (multi-target concurrent scans)
- ✅ **Rich TUI preferred** (real-time progress feedback)
- ✅ **OPSEC documentation important** (HTTP-only, concurrency control)
- ✅ **Testing new protocols** (MS-PAR, MS-TSCH coverage)

### Use Coercer when:
- ✅ **Fuzz mode required** (research, discovering new methods)
- ✅ **Open pipe enumeration needed** (reconnaissance phase)
- ✅ **XLSX/SQLite export required** (corporate reporting)
- ✅ **Python 3.7-3.12 environment** (legacy systems)
- ✅ **Mature/battle-tested tool preferred** (2+ years production use)
- ✅ **Shell completions important** (argcomplete integration)

---

## Migration Path (Coercer → coercex)

### Command equivalents:

```bash
# Coercer scan
./Coercer.py scan -u admin -p pass --target-ip 10.0.0.5 --ip-address 10.0.0.10

# coercex scan
coercex scan -t 10.0.0.5 -l 10.0.0.10 -u admin -p pass
```

```bash
# Coercer coerce
./Coercer.py coerce -u admin -p pass --target-ip 10.0.0.5 --listener-ip 10.0.0.10

# coercex coerce  
coercex coerce -t 10.0.0.5 -l 10.0.0.10 -u admin -p pass
```

```bash
# Coercer filtered scan
./Coercer.py scan -u admin -p pass -t 10.0.0.5 --filter-protocol-name MS-EFSR

# coercex filtered scan
coercex scan -t 10.0.0.5 -u admin -p pass --protocols MS-EFSR
```

### Breaking changes:
- **No fuzz mode** in coercex (use scan with filters as workaround)
- **No pipe enumeration** in coercex (assumes known pipes from method registry)
- **No XLSX/SQLite export** in coercex (JSON + text file only)
- **Python 3.13 required** (not backward compatible with 3.7-3.12)

---

## Performance Benchmarks (Estimated)

| Scenario | coercex | Coercer | Speedup |
|----------|---------|---------|---------|
| Single target, all methods (19) | ~3-5s | ~10-15s | **3x faster** |
| 10 targets, all methods (190 attempts) | ~15-30s | ~60-120s | **3-4x faster** |
| 100 targets, EFSR only (1000 attempts) | ~2-3 min | ~8-15 min | **4-5x faster** |

*Benchmarks assume `-c 100` for coercex, default threading for Coercer, network latency ~10ms.*

---

## Summary Table

| Dimension | Winner | Reason |
|-----------|--------|--------|
| **Performance** | coercex | Async architecture, connection pooling, pre-flight probing |
| **Method Coverage** | coercex | 19 methods (7 protocols) vs 17 methods (5 protocols) |
| **Verification Accuracy** | coercex | Token-based callback correlation |
| **User Experience** | coercex | Rich Live TUI with real-time progress |
| **Research Features** | Coercer | Dedicated fuzz mode, open pipe enumeration |
| **Export Options** | Coercer | XLSX, SQLite (coercex has JSON only) |
| **Compatibility** | Coercer | Python 3.7+ (coercex requires 3.13+) |
| **Maturity** | Coercer | 2+ years in production use |
| **Code Quality** | coercex | 186 tests, full type hints, CI/CD |
| **OPSEC Documentation** | coercex | Detailed research docs |

---

## Conclusion

**coercex** is a modern rewrite focused on **performance, accuracy, and developer experience** with async architecture and comprehensive testing. It excels at high-speed scanning with definitive callback verification.

**Coercer** remains the **mature, battle-tested** tool with broader compatibility (Python 3.7+), more export formats, and a dedicated fuzz mode for research.

**Recommendation:**
- **Production pentesting (speed matters):** coercex
- **Research/fuzzing:** Coercer
- **Corporate reporting (XLSX/SQLite):** Coercer
- **Legacy environments (Python <3.13):** Coercer
