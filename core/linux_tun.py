"""Linux TUN device and NAT masquerading interface for PyVPN Server."""

from __future__ import annotations

import os
import struct
import subprocess
from typing import Optional

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class LinuxTunDevice:
    """Manages a native Linux TUN device (/dev/net/tun) with kernel NAT masquerade."""

    def __init__(self, dev_name: str = "tun0", ip_cidr: str = "10.0.0.1/24", mtu: int = 1420):
        if not HAS_FCNTL:
            raise OSError("Linux TUN interface requires fcntl (Linux host required).")

        self.dev_name = dev_name
        self.ip_cidr = ip_cidr
        self.mtu = mtu
        self._fd: Optional[int] = os.open("/dev/net/tun", os.O_RDWR)

        # Allocate TUN interface
        ifr = struct.pack("16sH", dev_name.encode("ascii"), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self._fd, TUNSETIFF, ifr)
        self._setup_network()

    def _setup_network(self) -> None:
        """Configures IP address, brings up device, enables IP forwarding and NAT."""
        # 1. Assign IP address and bring interface up
        subprocess.run(f"ip addr add {self.ip_cidr} dev {self.dev_name} 2>/dev/null", shell=True)
        subprocess.run(f"ip link set up dev {self.dev_name}", shell=True)
        subprocess.run(f"ip link set dev {self.dev_name} mtu {self.mtu}", shell=True)

        # 2. Enable kernel IPv4 packet forwarding
        subprocess.run("sysctl -w net.ipv4.ip_forward=1", shell=True, capture_output=True)

        # 3. Detect default physical outgoing network interface (e.g. eth0, enp3s0)
        try:
            out_iface = subprocess.check_output(
                "ip route show default | awk '{print $5}'", shell=True, text=True
            ).strip().splitlines()[0]
        except Exception:
            out_iface = "eth0"

        # 4. Set iptables NAT masquerade rule
        rule_check = f"iptables -t nat -C POSTROUTING -s {self.ip_cidr} -o {out_iface} -j MASQUERADE 2>/dev/null"
        if subprocess.run(rule_check, shell=True).returncode != 0:
            subprocess.run(
                f"iptables -t nat -A POSTROUTING -s {self.ip_cidr} -o {out_iface} -j MASQUERADE",
                shell=True,
            )

        # 5. Allow forward traffic
        subprocess.run(f"iptables -A FORWARD -i {self.dev_name} -j ACCEPT 2>/dev/null", shell=True)
        subprocess.run(f"iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null", shell=True)

    def read_packet(self, max_size: int = 2048) -> bytes:
        """Reads a decrypted raw IP packet from Linux kernel."""
        assert self._fd is not None
        return os.read(self._fd, max_size)

    def write_packet(self, packet: bytes) -> bool:
        """Injects a packet into the Linux kernel for NAT internet forwarding."""
        assert self._fd is not None
        try:
            os.write(self._fd, packet)
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self) -> LinuxTunDevice:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
