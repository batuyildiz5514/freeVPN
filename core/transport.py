"""Encrypted UDP transport layer for PyVPN."""

from __future__ import annotations

import socket
from typing import Optional, Tuple

from core.crypto import CryptoSession, DecryptionError


class EncryptedUDPTransport:
    """Provides encrypted datagram transmission and reception over UDP."""

    DEFAULT_SOCKET_BUFFER = 2 * 1024 * 1024  # 2 MB buffer for high throughput

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
        """Receives a UDP datagram, authenticates and decrypts it.
        
        Args:
            max_size: Maximum datagram size to read from socket.
            
        Returns:
            Tuple[bytes, Tuple[str, int]]: (Decrypted plaintext payload, sender address tuple)
            
        Raises:
            DecryptionError: If the datagram fails authentication or is tampered with.
            socket.timeout: If socket timeout expires.
        """
        raw_data, sender = self.sock.recvfrom(max_size)
        plaintext = self.crypto.decrypt(raw_data)
        return plaintext, sender

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
