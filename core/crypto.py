"""Cryptographic operations for PyVPN.

Implements ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)
matching the cryptographic foundation used by modern protocols like WireGuard.
"""

from __future__ import annotations

import base64
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class DecryptionError(Exception):
    """Raised when packet decryption or tag verification fails."""
    pass


def generate_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32-byte) symmetric key."""
    return ChaCha20Poly1305.generate_key()


def key_to_base64(key: bytes) -> str:
    """Encode a 32-byte binary key into a base64 string for safe configuration storage."""
    return base64.b64encode(key).decode("ascii")


def key_from_base64(key_b64: str) -> bytes:
    """Decode a base64 string back into a 32-byte binary key."""
    key = base64.b64decode(key_b64.encode("ascii"))
    if len(key) != 32:
        raise ValueError(f"Invalid key length: expected 32 bytes, got {len(key)} bytes.")
    return key


class CryptoSession:
    """Handles AEAD encryption and decryption of VPN tunnel packets.
    
    Wire format for encrypted packets:
        [12-byte Nonce] + [Encrypted Payload] + [16-byte Poly1305 Tag]
    """

    NONCE_SIZE = 12
    TAG_SIZE = 16
    OVERHEAD = NONCE_SIZE + TAG_SIZE  # 28 bytes

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
        self._key = key
        self._cipher = ChaCha20Poly1305(key)

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypts plaintext with a fresh random 12-byte nonce.
        
        Args:
            plaintext: Raw IP packet bytes.
            associated_data: Optional unencrypted metadata to authenticate.
            
        Returns:
            bytes: Nonce prepended to ciphertext (includes 16-byte Poly1305 tag).
        """
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def decrypt(self, packet: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypts and verifies the integrity of an incoming packet.
        
        Args:
            packet: Encrypted packet containing nonce + ciphertext + tag.
            associated_data: Optional associated data that must match what was passed to encrypt.
            
        Returns:
            bytes: Original decrypted plaintext.
            
        Raises:
            DecryptionError: If the packet is truncated or failed authentication tag check.
        """
        if len(packet) < self.OVERHEAD:
            raise DecryptionError(
                f"Packet too short ({len(packet)} bytes). Minimum required is {self.OVERHEAD} bytes."
            )

        nonce = packet[:self.NONCE_SIZE]
        ciphertext = packet[self.NONCE_SIZE:]

        try:
            return self._cipher.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise DecryptionError("Authentication tag validation failed; packet tampered or wrong key.") from exc
