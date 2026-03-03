# Coercer: Open Pipe Discovery Technical Analysis

Deep dive into Coercer's "Open Pipe Discovery" feature and how it differs from coercex's approach.

---

## Overview

**Open Pipe Discovery** is a Coercer feature that enumerates SMB named pipes on remote Windows systems. It's **only used in Fuzz mode** to discover which pipes are accessible before testing coercion methods.

**Key distinction from coercex:** Coercer discovers *pipes* (IPC$ share files), while coercex probes *endpoints* (pipe + UUID + version bindings).

---

## Technical Implementation

### Core Function: `list_remote_pipes()`

**Location:** `coercer/network/smb.py` (lines 71-135)

```python
def list_remote_pipes(target, credentials, share="IPC$", maxdepth=-1):
    """
    Enumerates SMB named pipes on a remote target by listing files in the IPC$ share.
    
    Args:
        target: Hostname or IP of target
        credentials: Credentials object (Kerberos or NTLM)
        share: SMB share to enumerate (default: IPC$)
        maxdepth: Max directory depth (-1 = unlimited)
    
    Returns:
        List of pipe names formatted as \\PIPE\\<name>
    """
    pipes = []
    
    # 1. Establish SMB connection
    smbClient = SMBConnection(target, target, sess_port=int(445))
    
    # 2. Authenticate
    if credentials.doKerberos:
        smbClient.kerberosLogin(...)
    else:
        smbClient.login(...)
    
    # 3. Breadth-first search through IPC$ share
    searchdirs = [""]
    depth = 0
    while len(searchdirs) != 0 and ((depth <= maxdepth) or (maxdepth == -1)):
        depth += 1
        next_dirs = []
        
        for sdir in searchdirs:
            # List all files/directories at current path
            for sharedfile in smbClient.listPath(share, sdir + "*", password=None):
                if sharedfile.get_longname() not in [".", ".."]:
                    if sharedfile.is_directory():
                        next_dirs.append(sdir + sharedfile.get_longname() + "/")
                    else:
                        # Only collect files, not directories
                        full_path = sdir + sharedfile.get_longname()
                        pipes.append(full_path)
        
        searchdirs = next_dirs
    
    # 4. Format and deduplicate
    pipes = sorted(list(set(["\\PIPE\\" + f for f in pipes])), key=lambda x: x.lower())
    return pipes
```

### Algorithm Breakdown

1. **SMB Connection** - Uses impacket's `SMBConnection` to connect to port 445
2. **Authentication** - Supports both Kerberos (`kerberosLogin()`) and NTLM (`login()`)
3. **IPC$ Share Access** - Connects to the special `IPC$` share (Inter-Process Communication)
4. **Breadth-First Traversal** - Recursively explores directories using `listPath()` API
5. **File Filtering** - Only collects files (not directories), skipping `.` and `..`
6. **Formatting** - Prepends `\\PIPE\\` to each filename
7. **Deduplication** - Removes duplicates and sorts case-insensitively

---

## Authenticated vs Unauthenticated Discovery

### Authenticated Discovery (With Valid Credentials)

**When it runs:**
- Fuzz mode with `-u username -p password` or `-H hash`
- Scan mode with credentials (but scan mode doesn't use the result)

**Code location:** `coercer/core/modes/fuzz.py` (lines 59-65)

```python
else:
    # User provided credentials - enumerate real pipes
    named_pipe_of_remote_machine = list_remote_pipes(target, credentials)
    reporter.print_info(
        "Found %d SMB named pipes on the remote machine."
        % len(named_pipe_of_remote_machine),
        verbose=True,
    )
```

**How it works:**
1. Authenticates to target using provided credentials
2. Actually enumerates the IPC$ share via SMB
3. Returns the **real, live pipes** currently open on the system
4. Can discover **any pipe** including custom application pipes

**Benefits:**
- ✅ Discovers all accessible pipes (not just common ones)
- ✅ More accurate - tests only what actually exists
- ✅ Can find non-standard pipes (custom RPC services, third-party apps)
- ✅ Reduces wasted attempts on non-existent pipes

**Typical output:**
```
[*] Found 23 SMB named pipes on the remote machine.
    - \PIPE\spoolss
    - \PIPE\lsass
    - \PIPE\netlogon
    - \PIPE\samr
    - \PIPE\efsrpc
    ... (18 more)
```

---

### Unauthenticated Discovery (Anonymous/No Credentials)

**When it runs:**
- Fuzz mode without credentials (anonymous access)
- Scan mode without credentials

**Code location:** `coercer/core/modes/fuzz.py` (lines 30-58)

```python
if credentials.is_anonymous():
    reporter.print_info(
        "Cannot list SMB pipes with anonymous login, using list of known pipes"
    )
    
    # Hardcoded list of 18 common Windows named pipes
    named_pipe_of_remote_machine = [
        r"\PIPE\atsvc",
        r"\PIPE\efsrpc",
        r"\PIPE\epmapper",
        r"\PIPE\eventlog",
        r"\PIPE\InitShutdown",
        r"\PIPE\lsass",
        r"\PIPE\lsarpc",
        r"\PIPE\LSM_API_service",
        r"\PIPE\netdfs",
        r"\PIPE\netlogon",
        r"\PIPE\ntsvcs",
        r"\PIPE\PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER",
        r"\PIPE\scerpc",
        r"\PIPE\spoolss",
        r"\PIPE\srvsvc",
        r"\PIPE\VBoxTrayIPC-Administrator",
        r"\PIPE\W32TIME_ALT",
        r"\PIPE\wkssvc",
    ]
```

**Anonymous detection** (`coercer/structures/Credentials.py` lines 25-40):
```python
def is_anonymous(self):
    """Check if credentials are anonymous (no username)."""
    anonymous = False
    if self.username is None:
        anonymous = True
    elif len(self.username) == 0:
        anonymous = True
    else:
        anonymous = False
    return anonymous
```

**How it works:**
1. Detects anonymous credentials (no username)
2. Uses a **hardcoded list** of 18 common Windows named pipes
3. Does **NOT** actually enumerate the IPC$ share
4. Tests against the known pipe list

**Limitations:**
- ❌ Cannot discover custom/non-standard pipes
- ❌ May test pipes that don't exist (wasted attempts)
- ❌ Limited to 18 hardcoded common pipes
- ❌ Misses target-specific pipe configurations

**Typical output:**
```
[*] Cannot list SMB pipes with anonymous login, using list of known pipes
[*] Using integrated list of 18 SMB named pipes.
```

---

## Where Pipe Discovery is Used

### Fuzz Mode Only

**IMPORTANT:** Pipe discovery is **ONLY used in Fuzz mode**, not Scan or Coerce modes.

#### Fuzz Mode (`coercer/core/modes/fuzz.py`)

**Purpose:** Discover new coercible pipes/methods by testing arbitrary combinations

```python
def fuzz(...):
    # Lines 25-84: Pipe discovery logic
    if credentials.is_anonymous():
        named_pipe_of_remote_machine = [<hardcoded list>]
    else:
        named_pipe_of_remote_machine = list_remote_pipes(target, credentials)
    
    # Line 112: Pass discovered pipes to task executor
    execute_tasks(
        ...,
        named_pipe_of_remote_machine=named_pipe_of_remote_machine,
        ...
    )
```

**Usage in `execute_tasks()`** (`coercer/core/tasks/execute.py` lines 170-180):
```python
if transportType == TransportType.NCAN_NP:
    # Use discovered pipes instead of predefined ones
    iterable = (
        sorted(named_pipe_of_remote_machine)
        if named_pipe_of_remote_machine
        else sorted(transport.keys())
    )
    
    for pipe in iterable:
        # Test each method on each discovered pipe
        for method in methods:
            ...
```

#### Scan Mode (`coercer/core/modes/scan.py`)

- **Does NOT use pipe discovery**
- Uses predefined pipes from method definitions (e.g., MS-EFSR uses `\PIPE\efsrpc`)
- Directly tests known coercible method/pipe combinations

#### Coerce Mode (`coercer/core/modes/coerce.py`)

- **Does NOT use pipe discovery**
- Uses predefined pipes from method definitions
- Fire-and-forget triggers to external relay

---

## Pipe Testing Workflow (After Discovery)

After pipes are discovered, Coercer tests them in stages:

### 1. Connectivity Test

**Function:** `can_connect_to_pipe()` (`coercer/network/smb.py` lines 138-178)

```python
def can_connect_to_pipe(target, pipe, credentials, targetIp=None):
    """Test if we can connect to a named pipe via DCERPC."""
    
    # 1. Create DCERPC transport over named pipe
    ncan_target = r"ncacn_np:%s[%s]" % (target, pipe)
    __rpctransport = transport.DCERPCTransportFactory(ncan_target)
    
    # 2. Set credentials
    if credentials.doKerberos:
        __rpctransport.set_kerberos(credentials.doKerberos, kdcHost=credentials.kdcHost)
    __rpctransport.set_credentials(credentials.username, credentials.password, ...)
    
    # 3. Attempt connection
    try:
        dce = __rpctransport.get_dce_rpc()
        dce.connect()
        return True
    except Exception as e:
        return False
```

**Output:**
```
[+] SMB named pipe '\PIPE\spoolss' is accessible!
```

### 2. Interface Binding

**Function:** `can_bind_to_interface()` (`coercer/network/smb.py` lines 181-257)

```python
def can_bind_to_interface(target, pipe, credentials, uuid, version, targetIp=None):
    """Test if we can bind to a specific RPC interface on a pipe."""
    
    # 1. Connect to pipe
    ncan_target = r"ncacn_np:%s[%s]" % (target, pipe)
    __rpctransport = transport.DCERPCTransportFactory(ncan_target)
    dce = __rpctransport.get_dce_rpc()
    dce.connect()
    
    # 2. Attempt interface binding
    try:
        dce.bind(uuidtup_to_bin((uuid, version)))
        return True
    except Exception as e:
        return False
```

**Output:**
```
   [+] Successful bind to interface (12345678-1234-abcd-ef00-0123456789ab, 1.0)!
```

### 3. Method Triggering

If binding succeeds, iterate through all methods for that UUID/version and call each method's `trigger()` function:

```python
for method in methods_for_this_interface:
    result = method.trigger(
        target=target,
        listener=listener_ip,
        credentials=credentials,
        path_style=path_style
    )
```

---

## Comparison: Coercer vs coercex

| Aspect | Coercer | coercex |
|--------|---------|---------|
| **Discovery Mechanism** | Enumerates IPC$ share files (SMB) | Pre-flight endpoint probing (DCERPC) |
| **What it Discovers** | Named pipes (`\PIPE\*`) | Endpoint bindings (pipe, UUID, version) |
| **When it Runs** | Fuzz mode only | All modes (scan/coerce) |
| **Authenticated Mode** | Full SMB enumeration of IPC$ share | N/A - always uses predefined methods |
| **Unauthenticated Mode** | Hardcoded list of 18 common pipes | N/A |
| **Impacket API** | `smbClient.listPath()` | `dce.bind()` |
| **Purpose** | Discover new coercible pipes/methods | Optimize known method testing |
| **Coverage** | All pipes (if authenticated) | Unique (pipe, UUID) bindings only |
| **Efficiency** | Tests all pipes × all methods | Tests only reachable endpoints (~40-50% reduction) |
| **Research Value** | High (finds unknowns) | Low (validates knowns) |

---

## Example: Pipe Discovery in Action

### Authenticated Discovery Session

```bash
./Coercer.py fuzz -u admin -p 'P@ssw0rd' -t dc01.corp.local -l 10.0.0.5
```

**Output:**
```
       ______
      / ____/___  ___  _____________  _____
     / /   / __ \/ _ \/ ___/ ___/ _ \/ ___/
    / /___/ /_/ /  __/ /  / /__/  __/ /      v2.4.3
    \____/\____/\___/_/   \___/\___/_/       by Remi GASCOU (Podalirius)

[*] Authenticating to dc01.corp.local as corp.local\admin
[*] Enumerating SMB named pipes on dc01.corp.local...
[*] Found 23 SMB named pipes on the remote machine.

[*] Testing pipe '\PIPE\spoolss'...
[+] SMB named pipe '\PIPE\spoolss' is accessible!
   [*] Testing interface (12345678-1234-abcd-ef00-0123456789ab, 1.0)
   [+] Successful bind to interface (12345678-1234-abcd-ef00-0123456789ab, 1.0)!
      [*] Testing method RpcRemoteFindFirstPrinterChangeNotification...
      [+] Received callback from dc01.corp.local! [VULNERABLE]
```

### Unauthenticated Discovery Session

```bash
./Coercer.py fuzz -t dc01.corp.local -l 10.0.0.5
```

**Output:**
```
[*] Cannot list SMB pipes with anonymous login, using list of known pipes
[*] Using integrated list of 18 SMB named pipes.

[*] Testing pipe '\PIPE\spoolss'...
[+] SMB named pipe '\PIPE\spoolss' is accessible!
   ...
```

---

## Why coercex Doesn't Have Pipe Discovery

### Design Philosophy Differences

**Coercer (research-oriented):**
- Goal: **Discover new coercion vectors**
- Strategy: Exhaustive testing (all pipes × all methods)
- Use case: Security research, vulnerability discovery
- Trade-off: Slower, but finds unknowns

**coercex (production-oriented):**
- Goal: **Efficiently test known coercible methods**
- Strategy: Optimized testing (pre-flight probing + connection pooling)
- Use case: Pentesting, red teaming, production scans
- Trade-off: Faster, but only validates knowns

### coercex's Pre-flight Probing (Equivalent Feature)

Instead of enumerating pipes, coercex probes **unique endpoint bindings**:

**Location:** `coercex/scanner.py` `_preflight_probe()` function

```python
async def _preflight_probe(self, targets: list[str], methods: list[CoercionMethod]):
    """
    Pre-flight endpoint probing - tests connectivity to unique RPC bindings
    before attempting triggers.
    
    Eliminates ~40-50% of futile attempts (unreachable endpoints).
    Warms connection pool (sessions cached for reuse).
    """
    # 1. Extract unique (pipe, uuid, version) bindings from methods
    unique_bindings: set[tuple[str, str, str]] = set()
    for method in methods:
        for binding in method.pipe_bindings:
            unique_bindings.add((binding.pipe, binding.uuid, binding.version))
    
    # 2. Test each binding on each target in parallel
    for target in targets:
        for pipe, uuid, version in unique_bindings:
            try:
                # Attempt connection + bind (reuses connection from pool)
                await trigger_method(target, method, listener, ...)
                self.display.update_probe_status(target, pipe, uuid, "reachable")
            except Exception:
                self.display.update_probe_status(target, pipe, uuid, "unreachable")
    
    # 3. Only attempt triggers on reachable endpoints
```

**Key differences from Coercer's pipe discovery:**
- Tests **endpoints** (pipe + UUID + version) not just pipes
- Validates **connectivity + binding** in one step
- Runs in **all modes** (scan/coerce), not just fuzz
- **Warms connection pool** for subsequent reuse
- **Eliminates unreachable endpoints** upfront (~40-50% reduction)

---

## Use Case Recommendations

### Use Coercer's Pipe Discovery When:
- ✅ **Discovering new coercion vectors** (security research)
- ✅ **Enumerating target capabilities** (reconnaissance)
- ✅ **Testing custom/third-party RPC services** (non-standard pipes)
- ✅ **Fuzzing unknown method/pipe combinations**
- ✅ **Documenting all accessible pipes** (reporting)

### Use coercex's Pre-flight Probing When:
- ✅ **Testing known coercible methods** (pentesting)
- ✅ **High-speed scanning** (production environments)
- ✅ **Multi-target concurrent scans** (100+ targets)
- ✅ **Optimizing connection reuse** (efficiency)
- ✅ **Reducing network noise** (OPSEC)

---

## Conclusion

**Coercer's Open Pipe Discovery** is a powerful research feature for discovering new coercion vectors by enumerating all accessible named pipes on remote Windows systems. It shines in fuzzing scenarios where the goal is to test arbitrary method/pipe combinations.

**coercex's Pre-flight Probing** is an optimization feature for efficiently testing known vulnerabilities by validating endpoint reachability upfront. It excels in production pentesting where speed and accuracy are critical.

**Complementary, not competitive:** These features serve different purposes:
- **Coercer:** "What pipes are open?" (discovery)
- **coercex:** "Which known endpoints are reachable?" (validation)

For maximum effectiveness:
- Use **Coercer's fuzz mode** to discover new methods/pipes in R&D phases
- Use **coercex's scan mode** to validate knowns at scale in production engagements
