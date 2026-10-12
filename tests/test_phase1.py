"""Automated Verification Suite for Phase 1: Cryptographic UDP Tunnel Core."""

import socket
import threading
import time
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.crypto import (
    CryptoSession,
    DecryptionError,
    generate_key,
    key_from_base64,
    key_to_base64,
)
from core.transport import EncryptedUDPTransport


def test_key_management():
    print("[1/4] Testing Key Generation & Base64 Serialization...")
    key = generate_key()
    assert len(key) == 32, f"Key must be 32 bytes, got {len(key)}"

    b64 = key_to_base64(key)
    restored = key_from_base64(b64)
    assert key == restored, "Restored key must match original key"
    print("      [OK] Key management test passed.")


def test_encryption_roundtrip_and_tampering():
    print("[2/4] Testing ChaCha20-Poly1305 Roundtrip & Tamper Resistance...")
    key = generate_key()
    session = CryptoSession(key)

    original_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    encrypted = session.encrypt(original_payload)

    # Verify overhead (12 byte nonce + payload + 16 byte Poly1305 tag)
    assert len(encrypted) == len(original_payload) + 28, "Encrypted payload has unexpected length"

    # Verify proper decryption
    decrypted = session.decrypt(encrypted)
    assert decrypted == original_payload, "Decrypted text does not match original"

    # Test Tamper Resistance (Bit-flipping attack)
    tampered = bytearray(encrypted)
    tampered[15] ^= 0x01  # Flip 1 bit in ciphertext
    try:
        session.decrypt(bytes(tampered))
        assert False, "Tampered packet must NOT decrypt successfully!"
    except DecryptionError:
        pass  # Expected: Poly1305 tag verification failed!

    # Test Truncated packet
    try:
        session.decrypt(b"short")
        assert False, "Truncated packet must NOT decrypt successfully!"
    except DecryptionError:
        pass

    print("      [OK] Encryption, decryption, and tamper rejection tests passed.")


def test_udp_transport_communication():
    print("[3/4] Testing Encrypted UDP Client-Server Socket Exchange...")
    shared_key = generate_key()
    server_crypto = CryptoSession(shared_key)
    client_crypto = CryptoSession(shared_key)

    server_transport = EncryptedUDPTransport(server_crypto)
    client_transport = EncryptedUDPTransport(client_crypto)

    # Bind server to ephemeral loopback port
    server_transport.bind("127.0.0.1", 0)
    server_port = server_transport.sock.getsockname()[1]
    server_addr = ("127.0.0.1", server_port)

    received_packets = []
    stop_event = threading.Event()

    def server_worker():
        server_transport.settimeout(0.5)
        while not stop_event.is_set():
            try:
                data, sender = server_transport.recv_encrypted()
                received_packets.append(data)
                # Echo back with confirmation prefix
                server_transport.send_encrypted(b"ECHO:" + data, sender)
            except socket.timeout:
                continue

    thread = threading.Thread(target=server_worker, daemon=True)
    thread.start()

    try:
        messages = [
            b"Simulated IP Packet #1 [SYN]",
            b"Simulated IP Packet #2 [SYN-ACK]",
            b"Simulated IP Packet #3 [ACK]",
        ]

        client_transport.settimeout(1.0)
        for msg in messages:
            client_transport.send_encrypted(msg, server_addr)
            echoed, _ = client_transport.recv_encrypted()
            assert echoed == b"ECHO:" + msg, f"Echo response mismatch: {echoed}"

        assert len(received_packets) == len(messages), "Server did not receive all messages"
        print(f"      [OK] Successfully sent & received {len(messages)} encrypted packets via UDP.")

    finally:
        stop_event.set()
        thread.join(timeout=1.0)
        server_transport.close()
        client_transport.close()


def test_benchmark_throughput():
    print("[4/4] Benchmarking Crypto & Socket Throughput (1,000 packets)...")
    key = generate_key()
    session = CryptoSession(key)
    # Typical VPN packet size (1400 bytes MTU payload)
    packet_payload = b"X" * 1400

    count = 1000
    start = time.perf_counter()
    for _ in range(count):
        encrypted = session.encrypt(packet_payload)
        decrypted = session.decrypt(encrypted)
    duration = time.perf_counter() - start

    mb_processed = (count * len(packet_payload) * 2) / (1024 * 1024)
    speed_mbps = (mb_processed * 8) / duration

    print(f"      [OK] Processed {count} 1400-byte packets in {duration:.3f}s")
    print(f"      [OK] Benchmark Speed: ~{speed_mbps:.1f} Mbps (CPU Crypto Roundtrip)")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    print("=" * 60)
    print("  PyVPN Phase 1 Verification: Cryptographic UDP Tunnel Core")
    print("=" * 60)
    test_key_management()
    test_encryption_roundtrip_and_tampering()
    test_udp_transport_communication()
    test_benchmark_throughput()
    print("=" * 60)
    print("  ALL PHASE 1 TESTS PASSED SUCCESSFULLY! [OK]")
    print("=" * 60)
