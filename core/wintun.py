"""Windows Wintun TUN driver ctypes interface for PyVPN.

Binds the official WireGuard Wintun driver (wintun.dll) to create high-speed
virtual network adapters and perform raw byte-level packet read/write operations.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import sys
from typing import Optional


# --- Windows Types & Structures ---
WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
WINTUN_SESSION_HANDLE = ctypes.c_void_p


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]


class NET_LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_uint64)]


def is_admin() -> bool:
    """Check if the current process is running with Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def request_admin_elevation() -> None:
    """Relaunches the current script with elevated Administrator privileges."""
    if is_admin():
        return
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    if ret <= 32:
        raise PermissionError("Failed to obtain Administrator elevation via UAC prompt.")
    sys.exit(0)


class WintunDriver:
    """Ctypes wrapper around wintun.dll functions."""

    _instance = None
    _dll = None

    @classmethod
    def load(cls, dll_path: Optional[str] = None) -> WintunDriver:
        if cls._instance is not None:
            return cls._instance

        if dll_path is None:
            dll_path = str(Path(__file__).resolve().parent.parent / "wintun.dll")

        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"Wintun DLL not found at: {dll_path}")

        dll = ctypes.CDLL(dll_path)
        cls._setup_function_signatures(dll)
        cls._dll = dll
        cls._instance = cls()
        return cls._instance

    @classmethod
    def _setup_function_signatures(cls, dll: ctypes.CDLL) -> None:
        # WINTUN_ADAPTER_HANDLE WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID)
        dll.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(GUID)]
        dll.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE

        # WINTUN_ADAPTER_HANDLE WintunOpenAdapter(LPCWSTR Name)
        dll.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
        dll.WintunOpenAdapter.restype = WINTUN_ADAPTER_HANDLE

        # VOID WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Adapter)
        dll.WintunCloseAdapter.argtypes = [WINTUN_ADAPTER_HANDLE]
        dll.WintunCloseAdapter.restype = None

        # WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity)
        dll.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, wintypes.DWORD]
        dll.WintunStartSession.restype = WINTUN_SESSION_HANDLE

        # VOID WintunEndSession(WINTUN_SESSION_HANDLE Session)
        dll.WintunEndSession.argtypes = [WINTUN_SESSION_HANDLE]
        dll.WintunEndSession.restype = None

        # HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session)
        dll.WintunGetReadWaitEvent.argtypes = [WINTUN_SESSION_HANDLE]
        dll.WintunGetReadWaitEvent.restype = wintypes.HANDLE

        # BYTE *WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize)
        dll.WintunReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.POINTER(wintypes.DWORD)]
        dll.WintunReceivePacket.restype = ctypes.POINTER(ctypes.c_ubyte)

        # VOID WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet)
        dll.WintunReleaseReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.c_void_p]
        dll.WintunReleaseReceivePacket.restype = None

        # BYTE *WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize)
        dll.WintunAllocateSendPacket.argtypes = [WINTUN_SESSION_HANDLE, wintypes.DWORD]
        dll.WintunAllocateSendPacket.restype = ctypes.c_void_p

        # VOID WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet)
        dll.WintunSendPacket.argtypes = [WINTUN_SESSION_HANDLE, ctypes.c_void_p]
        dll.WintunSendPacket.restype = None

        # VOID WintunGetAdapterLUID(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid)
        dll.WintunGetAdapterLUID.argtypes = [WINTUN_ADAPTER_HANDLE, ctypes.POINTER(NET_LUID)]
        dll.WintunGetAdapterLUID.restype = None

    @property
    def dll(self) -> ctypes.CDLL:
        return self._dll


class WintunSession:
    """Manages active packet I/O session on a Wintun virtual adapter."""

    # Windows WaitForSingleObject constants
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102

    def __init__(self, driver: WintunDriver, handle: WINTUN_SESSION_HANDLE):
        self._driver = driver
        self._handle = handle
        self._wait_event = driver.dll.WintunGetReadWaitEvent(handle)

    def read_packet(self, timeout_ms: int = 100) -> Optional[bytes]:
        """Reads one raw IP packet from the ring buffer.
        
        Args:
            timeout_ms: Timeout in milliseconds to wait for a packet.
            
        Returns:
            bytes: The raw IP packet, or None if timeout expired.
        """
        # Wait for the event signaled by the driver when data is available
        ret = ctypes.windll.kernel32.WaitForSingleObject(self._wait_event, timeout_ms)
        if ret == self.WAIT_TIMEOUT:
            return None

        size = wintypes.DWORD()
        packet_ptr = self._driver.dll.WintunReceivePacket(self._handle, ctypes.byref(size))
        if not packet_ptr:
            return None

        try:
            packet_len = size.value
            return bytes(ctypes.string_at(packet_ptr, packet_len))
        finally:
            self._driver.dll.WintunReleaseReceivePacket(self._handle, packet_ptr)

    def write_packet(self, packet: bytes) -> bool:
        """Injects a raw IP packet into the virtual network adapter.
        
        Args:
            packet: Raw IP packet bytes to inject into Windows networking stack.
            
        Returns:
            bool: True on success, False if allocation failed (e.g. ring buffer full).
        """
        packet_len = len(packet)
        buf_ptr = self._driver.dll.WintunAllocateSendPacket(self._handle, packet_len)
        if not buf_ptr:
            return False

        ctypes.memmove(buf_ptr, packet, packet_len)
        self._driver.dll.WintunSendPacket(self._handle, buf_ptr)
        return True

    def close(self) -> None:
        """Close the active packet session."""
        if self._handle:
            self._driver.dll.WintunEndSession(self._handle)
            self._handle = None

    def __enter__(self) -> WintunSession:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class WintunAdapter:
    """High-level controller for creating and configuring a Wintun TUN device."""

    DEFAULT_RING_CAPACITY = 0x400000  # 4 MB ring buffer capacity

    def __init__(self, name: str = "PyVPN", tunnel_type: str = "PyVPN"):
        if not is_admin():
            raise PermissionError("Administrator privileges required to create or manage Wintun adapters.")

        self.name = name
        self.tunnel_type = tunnel_type
        self.driver = WintunDriver.load()
        self._handle = None
        self._create_or_open()

    def _create_or_open(self) -> None:
        # Try opening existing adapter first
        self._handle = self.driver.dll.WintunOpenAdapter(self.name)
        if not self._handle:
            # Create fresh adapter
            self._handle = self.driver.dll.WintunCreateAdapter(self.name, self.tunnel_type, None)
            if not self._handle:
                error_code = ctypes.windll.kernel32.GetLastError()
                raise RuntimeError(f"Failed to create Wintun adapter '{self.name}'. Win32 Error: {error_code}")

    def configure_ip(self, ip_address: str, subnet_mask: str = "255.255.255.0", gateway: Optional[str] = None, mtu: int = 1420) -> None:
        """Configure IP address, subnet mask, gateway, and MTU on the adapter using netsh."""
        # 1. Set static IP address with gateway
        gw_clause = f"{gateway} 1" if gateway else "none"
        cmd_ip = f'netsh interface ip set address name="{self.name}" static {ip_address} {subnet_mask} {gw_clause}'
        res_ip = subprocess.run(cmd_ip, shell=True, capture_output=True, text=True)
        if res_ip.returncode != 0:
            raise RuntimeError(f"Failed to configure IP on adapter '{self.name}': {res_ip.stderr.strip() or res_ip.stdout.strip()}")

        # 2. Set MTU
        cmd_mtu = f'netsh interface ipv4 set subinterface "{self.name}" mtu={mtu} store=active'
        subprocess.run(cmd_mtu, shell=True, capture_output=True)

    def start_session(self, capacity: int = DEFAULT_RING_CAPACITY) -> WintunSession:
        """Start a packet I/O session."""
        session_handle = self.driver.dll.WintunStartSession(self._handle, capacity)
        if not session_handle:
            error_code = ctypes.windll.kernel32.GetLastError()
            raise RuntimeError(f"Failed to start Wintun session. Win32 Error: {error_code}")
        return WintunSession(self.driver, session_handle)

    def close(self) -> None:
        """Close and release the adapter handle."""
        if self._handle:
            self.driver.dll.WintunCloseAdapter(self._handle)
            self._handle = None

    def __enter__(self) -> WintunAdapter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
