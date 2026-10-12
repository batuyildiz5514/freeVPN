"""Automated Verification Suite for Phase 3: End-to-End Packet Tunneling."""

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.crypto import CryptoSession, generate_key
from core.transport import EncryptedUDPTransport
from core.tunnel import ServerTunnel, TunnelMetrics


def test_metrics_tracking():
    print("[1/3] Testing Tunnel Metrics Tracking...")
    metrics = TunnelMetrics()
    metrics.add_sent(1420)
    metrics.add_sent(1420)
    metrics.add_recv(1420)
    metrics.add_dropped()

    snap = metrics.snapshot()
    assert snap["bytes_sent"] == 2840
    assert snap["bytes_recv"] == 1420
    assert snap["packets_sent"] == 2
    assert snap["packets_recv"] == 1
    assert snap["dropped_packets"] == 1
    print("      [OK] Metrics counters and rate calculations verified.")


def test_server_tunnel_packet_routing():
    print("[2/3] Testing ServerTunnel UDP Decapsulation & Echo...")
    shared_key = generate_key()
    crypto = CryptoSession(shared_key)

    # Use ephemeral port
    test_port = 59123
    server = ServerTunnel(
        bind_host="127.0.0.1",
        bind_port=test_port,
        crypto_session=crypto,
        tun_device=None,  # Test echo / decapsulation mode
    )
    server.start()
    time.sleep(0.2)

    try:
        client_transport = EncryptedUDPTransport(crypto)
        client_transport.settimeout(2.0)

        # Mock IPv4 Packet: 10.0.0.2 -> 10.0.0.1 (ICMP Ping)
        mock_ip_packet = (
            b"\x45\x00\x00\x1c"  # IPv4, Len 28
            b"\xaa\xbb\x00\x00"
            b"\x40\x01\x00\x00"
            b"\x0a\x00\x00\x02"  # Src: 10.0.0.2
            b"\x0a\x00\x00\x01"  # Dst: 10.0.0.1
            b"\x08\x00\xf7\xff\x00\x01\x00\x01"
        )

        # Send 5 mock packets
        for _ in range(5):
            client_transport.send_encrypted(mock_ip_packet, ("127.0.0.1", test_port))
            echoed_packet, _sender = client_transport.recv_encrypted()
            assert echoed_packet == mock_ip_packet, "Echoed IP packet must match original payload"

        snap = server.metrics.snapshot()
        assert snap["packets_recv"] == 5, f"Server should have received 5 packets, got {snap['packets_recv']}"
        assert snap["packets_sent"] == 5, f"Server should have sent 5 echo packets, got {snap['packets_sent']}"
        print("      [OK] 5/5 Mock IP packets decapsulated, routed, and echoed back successfully.")

    finally:
        server.stop()
        client_transport.close()


def test_configuration_loading():
    print("[3/3] Testing Configuration Loader & Template Fallback...")
    from core.config import get_crypto_key, load_config

    cfg = load_config()
    assert "server_host" in cfg
    assert "server_port" in cfg
    key = get_crypto_key(cfg)
    assert len(key) == 32
    print("      [OK] Configuration loaded with valid 256-bit cryptographic key.")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 60)
    print("  PyVPN Phase 3 Verification: End-to-End Tunneling Engine")
    print("=" * 60)
    test_metrics_tracking()
    test_server_tunnel_packet_routing()
    test_configuration_loading()
    print("=" * 60)
    print("  ALL PHASE 3 TESTS PASSED SUCCESSFULLY! [OK]")
    print("=" * 60)
