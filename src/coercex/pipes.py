"""IPC$ named pipe discovery via SMB share enumeration.

Enumerates named pipes on a remote Windows target by listing files in the
IPC$ share.  This is a pre-filter for the pre-flight endpoint probe: if a
pipe does not appear in the IPC$ listing, there is no point attempting an
RPC bind to it.

All impacket calls are synchronous; callers should wrap with
``asyncio.to_thread()`` for async usage.
"""

from __future__ import annotations

import logging

from coercex.models import Credentials

log = logging.getLogger("coercex.pipes")


def enumerate_pipes(
    target: str,
    creds: Credentials,
    timeout: int = 5,
) -> set[str]:
    """Enumerate named pipes on a remote target via IPC$ share listing.

    Connects to the target over SMB, authenticates, and performs a
    breadth-first traversal of the IPC$ share to discover available
    named pipes.

    Args:
        target: Hostname or IP of the remote target.
        creds: Authentication credentials (NTLM or Kerberos).
        timeout: Connection timeout in seconds.

    Returns:
        Set of pipe names formatted as ``\\PIPE\\<name>`` (matching the
        format used by ``PipeBinding.pipe``).  Returns an empty set on
        any connection or authentication failure.
    """
    # Defer heavy impacket import to keep module-level import time low.
    from impacket.smbconnection import SMBConnection

    try:
        smb_client = SMBConnection(target, target, sess_port=445, timeout=timeout)
    except Exception as exc:
        log.debug("Pipe discovery: SMB connect to %s failed: %s", target, exc)
        return set()

    # Authenticate
    try:
        if creds.do_kerberos:
            smb_client.kerberosLogin(
                creds.username,
                creds.password,
                creds.domain,
                creds.lmhash,
                creds.nthash,
                creds.aes_key,
                kdcHost=creds.dc_host,
                TGT=creds._tgt,
                TGS=creds._tgs,
            )
        else:
            smb_client.login(
                creds.username,
                creds.password,
                creds.domain,
                creds.lmhash,
                creds.nthash,
            )
    except Exception as exc:
        log.debug("Pipe discovery: auth to %s failed: %s", target, exc)
        try:
            smb_client.close()
        except Exception:
            pass
        return set()

    # Breadth-first traversal of IPC$ share
    pipes: list[str] = []
    try:
        search_dirs = [""]
        while search_dirs:
            next_dirs: list[str] = []
            for sdir in search_dirs:
                try:
                    for entry in smb_client.listPath("IPC$", sdir + "*"):
                        name = entry.get_longname()
                        if name in (".", ".."):
                            continue
                        if entry.is_directory():
                            next_dirs.append(sdir + name + "/")
                        else:
                            pipes.append(sdir + name)
                except Exception as exc:
                    log.debug(
                        "Pipe discovery: listPath %s on %s failed: %s",
                        sdir,
                        target,
                        exc,
                    )
            search_dirs = next_dirs
    finally:
        try:
            smb_client.close()
        except Exception:
            pass

    # Format to match PipeBinding.pipe (e.g. r"\PIPE\spoolss")
    result = {f"\\PIPE\\{p}" for p in pipes}
    log.debug("Pipe discovery on %s: found %d pipes", target, len(result))
    return result
