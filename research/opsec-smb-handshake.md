# OPSEC Analysis: SMB2 Handshake Depth in coercex Listener

## Context

coercex's SMB listener implements a full SMB2 handshake (NEGOTIATE →
SESSION_SETUP with NTLM auth → TREE_CONNECT) to reliably extract
correlation tokens and capture Net-NTLMv2 hashes. This document analyzes
the OPSEC implications of each handshake stage from both the **victim's**
perspective (the target machine being coerced) and the **listener's**
perspective (our coercex host).

## Key Insight

**The RPC coercion call is the noisiest part of the entire operation.**
That's what EDR rules, Sysmon EventID 1/3, and YARA signatures detect.
Whether our listener completes the SMB handshake or drops the connection
at NEGOTIATE has no measurable impact on victim-side detection.

## Per-Stage Analysis

### Stage 1: NEGOTIATE (receive only)

**Victim-side events:** None beyond the initial TCP connect. The target
opens an outbound TCP connection to our listener IP:445. If a firewall
or NDR monitors outbound SMB, it sees the SYN.

**Listener-side events:** None (we just receive the packet).

**Credentials on wire:** None.

**OPSEC cost:** Minimal. This is what the old listener did.

### Stage 2–4: SESSION_SETUP (NTLM Type 1/2/3)

**Victim-side events:**
- Possible **Event 4648** ("A logon was attempted using explicit
  credentials") on the target if NTLM audit is enabled — logs the
  outbound NTLM attempt with target server name.
- **Event 8004** on the domain controller if NTLM audit policy
  ("Audit Incoming NTLM Traffic" or "Restrict NTLM") is enabled.
- EDR monitoring outbound NTLM to non-domain destinations gets a signal
  (machine account authenticating to an unknown IP).

**Listener-side events:**
- We see the NTLM Type 3 with the machine account's NTLMv2 hash, plus
  username, domain, and workstation name.

**Credentials on wire:** Machine account Net-NTLMv2 hash crosses the wire.

**OPSEC cost:** Moderate incremental increase. The 4648/8004 events are
the main new signals. However, most environments do not have NTLM
auditing enabled for outbound connections.

### Stage 5–6: TREE_CONNECT

**Victim-side events:** None additional. The relevant Windows Security
events for share access (5140, 5145) fire on the **server** (our listener),
not on the client making the connection. The target machine generates no
new events from TREE_CONNECT.

**Listener-side events:**
- We receive the UNC share path containing our correlation token.
- We could generate events 5140/5145 if we were running Windows
  security auditing (we're not — we're a Python script).

**Credentials on wire:** Just the share path. No additional auth material.

**OPSEC cost:** Negligible incremental increase beyond SESSION_SETUP.
One extra round-trip on the wire, but no new events on the victim.

## Comparison: NEGOTIATE-only vs Full Handshake

```
Aspect                   | NEGOTIATE-only | Full Handshake
─────────────────────────┼────────────────┼────────────────
Token correlation        | IP-based (racy)| Token-based (reliable)
Credentials captured     | None           | Net-NTLMv2 hash
Victim-side 4648 event   | No             | Possible (NTLM audit)
Victim-side 8004 event   | No             | Possible (DC NTLM audit)
Victim-side 5140/5145    | No             | No (fires on server)
Network footprint        | 1 round-trip   | 4 round-trips
Connection appears normal| Abrupt drop    | Completes normally
```

## Conclusion

The incremental OPSEC cost of completing the full SMB2 handshake
(vs dropping at NEGOTIATE) is:

1. **4648/8004 events** that only fire if NTLM auditing is explicitly
   enabled (uncommon in most environments).
2. **3 additional round-trips** on the wire — negligible for NDR but
   technically more data to analyze.

The **benefits** far outweigh the costs:

1. **Reliable token-based correlation** — eliminates the FIFO race
   condition that produced incorrect vulnerability classifications.
2. **Net-NTLMv2 hash capture** — bonus credential material for
   offline cracking or relay (though the primary relay would use
   ntlmrelayx, not coercex's listener).
3. **Normal-looking connection** — completing the handshake looks like
   a legitimate SMB session, whereas dropping at NEGOTIATE is anomalous
   and could actually trigger NDR heuristics for "incomplete handshake"
   patterns.

## Recommendations

- In high-security environments with NTLM auditing, consider using
  HTTP/WebDAV transport instead of SMB to avoid triggering 4648/8004.
- The `--transport http` flag limits coercex to WebDAV-only callbacks,
  which go through HTTP and don't involve NTLM SMB authentication.
- For maximum stealth, use `--transport http` with `--http-port 80`
  (or redirect with `--redirect`).

## References

- [MS-SMB2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- Windows Event 4648: A logon was attempted using explicit credentials
- Windows Event 8004: NTLM authentication (DC-side audit)
- Windows Event 5140/5145: Network share access (server-side only)
