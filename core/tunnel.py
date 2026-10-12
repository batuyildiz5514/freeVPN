"""End-to-End Tunnel Engine for PyVPN.

Connects the Wintun virtual network interface with the Encrypted UDP transport,
running bidirectional packet forwarding across dedicated worker threads with
real-time bandwidth and packet counter metrics.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Optional, Tuple

from core.crypto import CryptoSession, DecryptionError
from core.transport import EncryptedUDPTransport
from core.wintun import WintunAdapter, WintunSession


class TunnelMetrics:
    """Thread-safe real-time metrics tracker for tunnel traffic."""

    def __init__(self):
        self._lock = threading.Lock()
        self.bytes_sent: int = 0
        self.bytes_recv: int = 0
        self.packets_sent: int = 0
        self.packets_recv: int = 0
        self.dropped_packets: int = 0
        self.start_time: float = time.time()
        self._last_snapshot_time: float = time.time()
        self._last_bytes_sent: int = 0
        self._last_bytes_recv: int = 0
        self._instant_upload_kbps: float = 0.0
        self._instant_download_kbps: float = 0.0

    def add_sent(self, size: int) -> None:
        with self._lock:
            self.bytes_sent += size
            self.packets_sent += 1

    def add_recv(self, size: int) -> None:
        with self._lock:
            self.bytes_recv += size
            self.packets_recv += 1

    def add_dropped(self) -> None:
        with self._lock:
            self.dropped_packets += 1

    def snapshot(self) -> dict:
        with self._lock:
            now = time.time()
            dt = now - self._last_snapshot_time
            if dt >= 0.2:
                delta_tx = self.bytes_sent - self._last_bytes_sent
                delta_rx = self.bytes_recv - self._last_bytes_recv
                self._instant_upload_kbps = (delta_tx * 8 / 1024) / dt
                self._instant_download_kbps = (delta_rx * 8 / 1024) / dt
                self._last_bytes_sent = self.bytes_sent
                self._last_bytes_recv = self.bytes_recv
                self._last_snapshot_time = now

            return {
                "bytes_sent": self.bytes_sent,
                "bytes_recv": self.bytes_recv,
                "packets_sent": self.packets_sent,
                "packets_recv": self.packets_recv,
                "dropped_packets": self.dropped_packets,
                "upload_kbps": self._instant_upload_kbps,
                "download_kbps": self._instant_download_kbps,
            }


class ClientTunnel:
    """High-performance bidirectional client tunnel."""

    def __init__(
        self,
        server_host: str,
        server_port: int,
        crypto_session: CryptoSession,
        wintun_adapter: WintunAdapter,
        status_callback: Optional[Callable[[str], None]] = None,
    ):
        self.server_endpoint = (server_host, server_port)
        self.crypto = crypto_session
        self.adapter = wintun_adapter
        self.status_callback = status_callback
        self.metrics = TunnelMetrics()

        self._transport: Optional[EncryptedUDPTransport] = None
        self._wintun_session: Optional[WintunSession] = None
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

    def _log(self, msg: str) -> None:
        if self.status_callback:
            self.status_callback(msg)

    def start(self) -> None:
        """Start the tunnel workers."""
        self._stop_event.clear()
        self._transport = EncryptedUDPTransport(self.crypto)
        self._transport.settimeout(0.05)
        self._wintun_session = self.adapter.start_session()

        # Thread 1: Wintun -> UDP (Outgoing traffic)
        t_out = threading.Thread(target=self._worker_wintun_to_udp, name="Tunnel-Outbound", daemon=True)
        # Thread 2: UDP -> Wintun (Incoming traffic)
        t_in = threading.Thread(target=self._worker_udp_to_wintun, name="Tunnel-Inbound", daemon=True)

        self._threads = [t_out, t_in]
        t_out.start()
        t_in.start()
        self._log(f"Tunnel active. Forwarding to server at {self.server_endpoint[0]}:{self.server_endpoint[1]}")

    def _worker_wintun_to_udp(self) -> None:
        """Reads raw packets from Wintun, encrypts, and transmits via UDP."""
        assert self._wintun_session is not None
        assert self._transport is not None

        while not self._stop_event.is_set():
            try:
                packets = self._wintun_session.read_packets(max_packets=64, timeout_ms=20)
                for packet in packets:
                    self._transport.send_encrypted(packet, self.server_endpoint)
                    self.metrics.add_sent(len(packet))
            except Exception:
                if not self._stop_event.is_set():
                    self.metrics.add_dropped()

    def _worker_udp_to_wintun(self) -> None:
        """Receives encrypted UDP datagrams, decrypts, and injects into Wintun."""
        assert self._wintun_session is not None
        assert self._transport is not None

        while not self._stop_event.is_set():
            try:
                decrypted_payload, _sender = self._transport.recv_encrypted()
                if decrypted_payload:
                    success = self._wintun_session.write_packet(decrypted_payload)
                    if success:
                        self.metrics.add_recv(len(decrypted_payload))
                    else:
                        self.metrics.add_dropped()
            except socket.timeout:
                continue
            except DecryptionError:
                self.metrics.add_dropped()
            except Exception:
                if not self._stop_event.is_set():
                    self.metrics.add_dropped()

    def stop(self) -> None:
        """Gracefully stop tunnel workers and release resources."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()

        if self._wintun_session:
            self._wintun_session.close()
            self._wintun_session = None

        if self._transport:
            self._transport.close()
            self._transport = None

        self._log("Tunnel stopped.")

    def is_running(self) -> bool:
        return not self._stop_event.is_set() and len(self._threads) > 0


class ServerTunnel:
    """Server-side tunnel engine that receives and decapsulates client packets."""

    def __init__(
        self,
        bind_host: str,
        bind_port: int,
        crypto_session: CryptoSession,
        tun_device: Optional[Any] = None,
        status_callback: Optional[Callable[[str], None]] = None,
    ):
        self.bind_address = (bind_host, bind_port)
        self.crypto = crypto_session
        self.tun_device = tun_device
        self.status_callback = status_callback
        self.metrics = TunnelMetrics()

        self._transport: Optional[EncryptedUDPTransport] = None
        self._tun_session: Optional[Any] = None
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []

        # Client routing table: client_vpn_ip -> (client_public_ip, client_public_port)
        self._client_endpoints: dict[str, Tuple[str, int]] = {}
        self._lock = threading.Lock()

    def _log(self, msg: str) -> None:
        if self.status_callback:
            self.status_callback(msg)

    def start(self) -> None:
        self._stop_event.clear()
        self._transport = EncryptedUDPTransport(self.crypto)
        self._transport.bind(self.bind_address[0], self.bind_address[1])
        self._transport.settimeout(0.05)

        if self.tun_device:
            # WintunAdapter requires start_session(), LinuxTunDevice is already active
            if hasattr(self.tun_device, "start_session"):
                self._tun_session = self.tun_device.start_session()
            else:
                self._tun_session = self.tun_device

            t_tun = threading.Thread(target=self._worker_tun_to_clients, name="Server-TunOut", daemon=True)
            self._threads.append(t_tun)
            t_tun.start()

        t_udp = threading.Thread(target=self._worker_udp_listener, name="Server-UDPIn", daemon=True)
        self._threads.append(t_udp)
        t_udp.start()
        self._log(f"Server listening on {self.bind_address[0]}:{self.bind_address[1]}")

    def _worker_udp_listener(self) -> None:
        assert self._transport is not None

        while not self._stop_event.is_set():
            try:
                packet, sender = self._transport.recv_encrypted()
                self.metrics.add_recv(len(packet))

                # Parse IPv4 source IP to map client endpoint
                if len(packet) >= 20 and (packet[0] >> 4) == 4:
                    src_ip = f"{packet[12]}.{packet[13]}.{packet[14]}.{packet[15]}"
                    with self._lock:
                        self._client_endpoints[src_ip] = sender

                if self._tun_session:
                    self._tun_session.write_packet(packet)
                else:
                    # Echo mode if running without server TUN adapter
                    self._transport.send_encrypted(packet, sender)
                    self.metrics.add_sent(len(packet))

            except socket.timeout:
                continue
            except DecryptionError:
                self.metrics.add_dropped()
            except Exception:
                if not self._stop_event.is_set():
                    self.metrics.add_dropped()

    def _worker_tun_to_clients(self) -> None:
        assert self._tun_session is not None
        assert self._transport is not None

        while not self._stop_event.is_set():
            try:
                if hasattr(self._tun_session, "read_packets"):
                    packets = self._tun_session.read_packets(max_packets=64, timeout_ms=20)
                else:
                    pkt = self._tun_session.read_packet(timeout_ms=20)
                    packets = [pkt] if pkt else []

                for packet in packets:
                    # Parse IPv4 destination IP
                    if len(packet) >= 20 and (packet[0] >> 4) == 4:
                        dst_ip = f"{packet[16]}.{packet[17]}.{packet[18]}.{packet[19]}"
                        with self._lock:
                            endpoint = self._client_endpoints.get(dst_ip)
                        if endpoint:
                            self._transport.send_encrypted(packet, endpoint)
                            self.metrics.add_sent(len(packet))
            except Exception as exc:
                if not self._stop_event.is_set():
                    self.metrics.add_dropped()

    def stop(self) -> None:
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()

        if self._tun_session:
            if hasattr(self._tun_session, "close"):
                self._tun_session.close()
            self._tun_session = None

        if self._transport:
            self._transport.close()
            self._transport = None

        self._log("Server stopped.")
