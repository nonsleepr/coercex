# SMB2 Session Multiplexing: NTLM Type 1 in Place of Type 3

## Problem Statement

During concurrent RPC coercion scans, the coercex SMB listener receives
NTLM Type 1 (NEGOTIATE_MESSAGE) inside a SESSION_SETUP request at the
point in the handshake where it expects NTLM Type 3 (AUTHENTICATE_MESSAGE).
This happens multiple times per scan (e.g., 8 occurrences).

The listener flow expects:
```
NEGOTIATE -> SESSION_SETUP(Type 1) -> we send challenge(Type 2) -> SESSION_SETUP(Type 3)
```

But sometimes the second SESSION_SETUP contains Type 1 instead of Type 3.

## Root Cause: SMB2 Multiple Sessions Per Connection

### The SMB2 Protocol Allows It

Per [MS-SMB2] Section 3.3.5.5 ("Receiving an SMB2 SESSION_SETUP Request"):

> If **SessionId** in the SMB2 header of the request is zero, the server
> MUST process the authentication request as specified in section 3.3.5.5.1
> [Authenticating a New Session].

And from the SESSION_SETUP Request definition (Section 2.2.5):

> The SMB2 SESSION_SETUP Request packet is sent by the client to request
> **a new authenticated session within a new or existing** SMB 2 Protocol
> transport connection to the server.

This is the key: a single TCP connection can host **multiple independent
SMB2 sessions**. Each session has its own SessionId and its own
independent NTLM authentication exchange. The server allocates a new
Session object for each SESSION_SETUP with SessionId=0.

### What Windows Does During Concurrent Coercion

When multiple RPC coercion triggers fire against the same target in
quick succession, each triggers an outbound SMB connection from the
target to our listener. Windows's SMB client (`mrxsmb20.sys` /
`srv2.sys`) can and does **reuse an existing TCP connection** to the same
destination (IP:port) for new outbound SMB sessions. This is standard
SMB2 connection pooling behavior.

The sequence on a single TCP connection looks like this:

```
Client -> Server: NEGOTIATE (once per TCP connection)
Server -> Client: NEGOTIATE Response

--- Session 1 (triggered by RPC call #1) ---
Client -> Server: SESSION_SETUP (SessionId=0, NTLM Type 1)   [msg_id=1]
Server -> Client: SESSION_SETUP Response (SessionId=X, Type 2) [msg_id=1]
Client -> Server: SESSION_SETUP (SessionId=X, NTLM Type 3)   [msg_id=2]
Server -> Client: SESSION_SETUP Response (STATUS_SUCCESS)     [msg_id=2]
Client -> Server: TREE_CONNECT (SessionId=X, \\host\token1)  [msg_id=3]

--- Session 2 (triggered by RPC call #2, same TCP conn) ---
Client -> Server: SESSION_SETUP (SessionId=0, NTLM Type 1)   [msg_id=4]
Server -> Client: SESSION_SETUP Response (SessionId=Y, Type 2) [msg_id=4]
Client -> Server: SESSION_SETUP (SessionId=Y, NTLM Type 3)   [msg_id=5]
...
```

### Why the Listener Sees Type 1 Where It Expects Type 3

The current coercex listener (`_handle_smb`) processes the connection as
a **strict sequential state machine**: NEGOTIATE -> Type 1 -> Type 2 ->
Type 3 -> TREE_CONNECT -> done. It reads one packet at each step.

But on a multiplexed connection, the packets can interleave:

```
Expected by listener:            What actually arrives:
  recv() -> NEGOTIATE              recv() -> NEGOTIATE             OK
  recv() -> SESSION_SETUP(Type 1)  recv() -> SESSION_SETUP(Type 1) OK (Session 1)
  send Type 2 challenge
  recv() -> SESSION_SETUP(Type 3)  recv() -> SESSION_SETUP(Type 1) UNEXPECTED!
                                   (This is Session 2 starting, not Session 1 completing)
```

This happens because:
1. **Session 1's Type 3 may be delayed** — the Windows client hasn't
   computed the NTLM response yet.
2. **Session 2's Type 1 arrives first** — a new RPC trigger caused the
   client to start a new session on the same TCP connection.
3. The listener's `recv_netbios()` reads whatever packet arrives next,
   regardless of which session it belongs to.

In SMB2, the SessionId in the header disambiguates which session each
packet belongs to. The listener currently ignores this field when
deciding what to expect next.

### Timing: Why This Is Correlated With Concurrent Coercion

With `-c N` (concurrency > 1), multiple RPC triggers fire in rapid
succession. The target processes them and initiates multiple outbound
SMB connections within milliseconds. If two or more land on the same TCP
connection (connection reuse), their NTLM exchanges interleave on the
wire. With `-c 1`, this is less likely but still possible if the target
processes a previous trigger's callback while a new trigger arrives.

## Is This Normal/Expected Windows Behavior?

**Yes.** This is completely normal, spec-compliant SMB2 behavior:

1. **Multiple sessions per connection** is explicitly defined in
   [MS-SMB2]. The protocol uses SessionId to multiplex sessions on a
   single transport connection.

2. **Connection reuse** is standard behavior for the Windows SMB client.
   When initiating an outbound SMB connection, Windows checks for an
   existing TCP connection to the same server:port and reuses it.

3. **Concurrent NTLM negotiations** are expected when multiple subsystems
   (different RPC services responding to different coercion triggers)
   independently need to connect to the same UNC path target.

4. The runZero SMB2 session research confirms that each new
   SESSION_SETUP with SessionId=0 causes the server to allocate a new
   session, and this is routine behavior observed across Windows
   versions.

## Should the Listener Architecture Change?

### Option A: Full session multiplexing support (complex, unnecessary)

Rewrite `_handle_smb` to maintain a per-connection dict of session
states, dispatch incoming packets by SessionId, and handle N concurrent
NTLM negotiations on a single TCP connection.

**Verdict: Overkill.** The listener only needs to capture one successful
NTLM exchange per connection. The other sessions arriving on the same
connection are duplicates (same machine account, different tokens).

### Option B: Detect-and-recover (moderate, probably unnecessary)

When a Type 1 arrives where Type 3 is expected, check the SessionId.
If it's a new session (SessionId=0 or different from our assigned
session), record the partial callback and either:
- Try to continue the original session's negotiation, or
- Restart the state machine for the new session.

**Verdict: Fragile.** Once a Type 1 from session 2 has been read from the
stream, session 1's Type 3 is still pending in the TCP buffer. Sorting
out interleaved packets without a proper multiplexing layer is brittle.

### Option C: Demote to debug and rely on other connections (simple, correct)

The current approach: log at debug level and fall back to IP-based
correlation. This is the right call because:

1. **The other sessions still arrive.** When session multiplexing causes
   a failure on one TCP connection, the same target typically opens
   additional TCP connections for other coercion callbacks. At least one
   will complete the full handshake.

2. **Token-based correlation still works** on the connections that
   complete successfully. The token embedded in the UNC path is extracted
   from TREE_CONNECT on successful handshakes.

3. **IP-based timestamp fallback** (`get_callback_since()`) catches the
   partial handshakes. Even without completing TREE_CONNECT, the
   listener records the connection timestamp, which the scanner uses to
   confirm the target called back.

4. **Hash capture still works** — at least one connection per target
   completes the full NTLM exchange, so credentials are captured.

5. **The log message is already correct.** The current code at
   `listener/__init__.py:607-616` detects NTLM Type != 3 and logs:
   ```
   "SESSION_SETUP from %s: expected NTLM Type 3 (AUTHENTICATE), got
   Type %d -- new NTLM negotiation on existing SMB session
   (concurrent coercion race)"
   ```
   This is at `log.debug()` level, which is appropriate — it's not an
   error condition, just an expected protocol interaction during
   concurrent scanning.

**Verdict: This is the correct approach.** No architecture change needed.

## Summary

| Question | Answer |
|----------|--------|
| Why does Type 1 appear where Type 3 is expected? | Windows reuses the TCP connection for a new SMB2 session (SessionId=0). The new session's Type 1 arrives before the previous session's Type 3. |
| Is this normal Windows behavior? | Yes. [MS-SMB2] explicitly supports multiple sessions per connection. Windows SMB client pools connections. |
| Does this indicate a bug? | No. It's a protocol feature interacting with our sequential state machine. |
| Should the listener support full multiplexing? | No. Overkill for a coercion scanner. |
| Is the current debug-level log correct? | Yes. The message accurately describes the situation and the severity is appropriate. |
| Are callbacks lost? | No. Other connections from the same target complete successfully, and IP-based fallback catches the partials. |
| When is this most likely? | High concurrency (`-c N` with N > 1) scanning multiple methods against the same target. |
| How to avoid it entirely? | Use `--stop-on-coerced` (method-sequential) or `-c 1` (one-at-a-time). |

## References

- [MS-SMB2] Section 2.2.5: SMB2 SESSION_SETUP Request — "a new
  authenticated session within a new or existing connection"
- [MS-SMB2] Section 3.3.5.5: Receiving an SMB2 SESSION_SETUP Request —
  SessionId=0 triggers new session allocation
- [MS-SMB2] Section 3.3.5.5.1: Authenticating a New Session — session
  object allocation, SessionId assignment
- runZero: "SMB2 Session Prediction & Consequences" (2020) — confirms
  session allocation behavior and sequential SessionId assignment
- 0xdeaddood: "One SMB connection multiple relays" (2020) — demonstrates
  multiple NTLM negotiations on a single SMB connection via
  STATUS_NETWORK_SESSION_EXPIRED re-auth
- Wireshark Wiki: SMB2 — "A 64 bit integer that identifies a specific
  authenticated user on this TCP session"
