"""Encrypted UDP transport layer for PyVPN."""

from __future__ import annotations

import socket
from typing import Optional, Tuple

from core.crypto import CryptoSession, DecryptionError


class EncryptedUDPTransport:
    """Provides encrypted datagram transmission and reception over UDP."""

    DEFAULT_SOCKET_BUFFER = 4 * 1024 * 1024  # 4 MB buffer for maximum UDP throughput

    def __init__(self, crypto_session: CryptoSession, sock: Optional[socket.socket] = None):
        self.crypto = crypto_session
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Optimize UDP socket buffers to prevent kernel packet drops under load
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.DEFAULT_SOCKET_BUFFER)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.DEFAULT_SOCKET_BUFFER)
        except OSError:
            pass  # Fall back to OS default if high buffer allocation is restricted

    def bind(self, host: str, port: int) -> None:
        """Bind socket to local address (typically used by the server)."""
        self.sock.bind((host, port))

    def settimeout(self, timeout: Optional[float]) -> None:
        """Set blocking socket timeout in seconds."""
        self.sock.settimeout(timeout)

    def send_encrypted(self, payload: bytes, destination: Tuple[str, int]) -> int:
        """Encrypts payload and sends it as a UDP datagram to destination.
        
        Args:
            payload: Raw packet data to encrypt.
            destination: (ip_address, port) tuple.
            
        Returns:
            int: Number of bytes sent over the wire.
        """
        encrypted_packet = self.crypto.encrypt(payload)
        return self.sock.sendto(encrypted_packet, destination)

    def recv_encrypted(self, max_size: int = 2048) -> Tuple[bytes, Tuple[str, int]]:
        """Receives a UDP datagram, authenticates and decrypts it."""
        raw_data, sender = self.sock.recvfrom(max_size)
        plaintext = self.crypto.decrypt(raw_data)
        return plaintext, sender

    def recv_encrypted_batch(self, max_batch: int = 64, max_size: int = 2048) -> list[Tuple[bytes, Tuple[str, int]]]:
        """Receives a batch of available datagrams from the UDP socket.
        
        Blocks for the first datagram up to the configured socket timeout.
        If a datagram is received, drains remaining ready datagrams in a non-blocking loop
        up to max_batch to maximize throughput under heavy load.
        """
        batch: list[Tuple[bytes, Tuple[str, int]]] = []
        try:
            raw_data, sender = self.sock.recvfrom(max_size)
            try:
                plaintext = self.crypto.decrypt(raw_data)
                batch.append((plaintext, sender))
            except DecryptionError:
                pass
        except (socket.timeout, OSError):
            return batch

        # Non-blocking drain of remaining queued datagrams in socket buffer
        self.sock.setblocking(False)
        try:
            while len(batch) < max_batch:
                raw_data, sender = self.sock.recvfrom(max_size)
                try:
                    plaintext = self.crypto.decrypt(raw_data)
                    batch.append((plaintext, sender))
                except DecryptionError:
                    pass
        except (BlockingIOError, socket.error):
            pass
        finally:
            self.sock.settimeout(0.05)

        return batch

    def close(self) -> None:
        """Safely close the underlying UDP socket."""
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> EncryptedUDPTransport:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
