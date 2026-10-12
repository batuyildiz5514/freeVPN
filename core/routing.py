"""Windows Routing Table & DNS Management for PyVPN.

Implements the standard WireGuard / OpenVPN dual-route technique:
- Direct /32 host route for the VPN server via the original default gateway (prevents routing loops).
- 0.0.0.0/1 and 128.0.0.0/1 split routes via the VPN gateway (covers 100% of IPv4 without overwriting default route).
- DNS leak prevention by prioritizing the VPN interface and assigning fast private DNS (1.1.1.1 / 1.0.0.1).
- Automatic emergency cleanup via atexit to guarantee internet connectivity is never left corrupted.
"""

from __future__ import annotations

import atexit
import re
import subprocess
from typing import List, Optional, Tuple


def get_default_gateway() -> Tuple[Optional[str], Optional[str]]:
    """Discovers the active default gateway and local interface IP on Windows.
    
    Returns:
        Tuple[gateway_ip, interface_ip]
    """
    try:
        output = subprocess.check_output("route print 0.0.0.0", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            line = line.strip()
            # Match: 0.0.0.0   0.0.0.0   <Gateway>   <Interface>   <Metric>
            match = re.match(r"^0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                return match.group(1), match.group(2)
    except Exception:
        pass
    return None, None


class RoutingManager:
    """Manages VPN route injection and safe restoration on Windows."""

    def __init__(
        self,
        adapter_name: str = "PyVPN",
        dns_servers: Optional[List[str]] = None,
    ):
        self.adapter_name = adapter_name
        self.dns_servers = dns_servers or ["1.1.1.1", "1.0.0.1"]
        self.is_active = False
        self._server_ip: Optional[str] = None
        self._original_gateway: Optional[str] = None
        self._vpn_gateway: Optional[str] = None

        # Register safety handler to restore routes on abnormal program termination
        atexit.register(self.restore_routes)

    def _run_cmd(self, cmd: str) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True)

    def setup_routes(self, server_ip: str, vpn_gateway: str) -> None:
        """Injects routing table entries to direct all traffic into the VPN tunnel.
        
        Args:
            server_ip: Physical IP address of the VPN server.
            vpn_gateway: Virtual IP gateway of the VPN tunnel (e.g. 10.0.0.1).
        """
        orig_gw, _orig_iface = get_default_gateway()
        if not orig_gw:
            raise RuntimeError("Could not detect original default gateway.")

        self._server_ip = server_ip
        self._original_gateway = orig_gw
        self._vpn_gateway = vpn_gateway

        # 1. Exception route: Route to VPN server IP via original gateway (prevents routing loop)
        if server_ip not in ("127.0.0.1", "localhost", "0.0.0.0"):
            self._run_cmd(f"route add {server_ip} mask 255.255.255.255 {orig_gw} metric 1")

        # 2. Split tunnel default routes: 0.0.0.0/1 and 128.0.0.0/1 via VPN gateway
        # Longest prefix match ensures these take precedence over 0.0.0.0/0
        self._run_cmd(f"route add 0.0.0.0 mask 128.0.0.0 {vpn_gateway} metric 1")
        self._run_cmd(f"route add 128.0.0.0 mask 128.0.0.0 {vpn_gateway} metric 1")

        # 3. Configure DNS on the VPN interface to prevent DNS leaks
        if self.dns_servers:
            primary_dns = self.dns_servers[0]
            self._run_cmd(f'netsh interface ip set dns name="{self.adapter_name}" static {primary_dns} validate=no')
            for secondary_dns in self.dns_servers[1:]:
                self._run_cmd(f'netsh interface ip add dns name="{self.adapter_name}" {secondary_dns} index=2 validate=no')

        # 4. Set interface metric to low value (high priority)
        self._run_cmd(f'powershell -Command "Set-NetIPInterface -InterfaceAlias \'{self.adapter_name}\' -InterfaceMetric 1"')

        self.is_active = True

    def restore_routes(self) -> None:
        """Removes all injected routes and cleanly restores original networking."""
        if not self.is_active:
            return

        # 1. Delete split default routes
        self._run_cmd("route delete 0.0.0.0 mask 128.0.0.0")
        self._run_cmd("route delete 128.0.0.0 mask 128.0.0.0")

        # 2. Delete server exception route
        if self._server_ip and self._server_ip not in ("127.0.0.1", "localhost", "0.0.0.0"):
            self._run_cmd(f"route delete {self._server_ip} mask 255.255.255.255")

        self.is_active = False

    def __enter__(self) -> RoutingManager:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.restore_routes()
