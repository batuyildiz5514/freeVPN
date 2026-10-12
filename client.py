"""PyVPN Command-Line Client Runner."""

from __future__ import annotations

import sys
import time

from core.config import get_crypto_key, load_config
from core.crypto import CryptoSession
from core.tunnel import ClientTunnel
from core.wintun import WintunAdapter, is_admin, request_admin_elevation


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 60)
    print("  PyVPN Client - Encrypted High-Performance Tunnel")
    print("=" * 60)

    if not is_admin():
        print("[!] Administrator privileges required. Requesting elevation...")
        request_admin_elevation()
        return

    cfg = load_config()
    server_host = cfg["server_host"]
    server_port = int(cfg["server_port"])
    client_ip = cfg["client_ip"]
    subnet_mask = cfg["subnet_mask"]

    print(f"[*] Target Server: {server_host}:{server_port}")
    print(f"[*] Virtual Client IP: {client_ip} / {subnet_mask}")

    key = get_crypto_key(cfg)
    crypto = CryptoSession(key)

    print("[*] Initializing Wintun virtual adapter...")
    adapter = WintunAdapter(name="PyVPN", tunnel_type="PyVPN")
    try:
        adapter.configure_ip(client_ip, subnet_mask)
        print("[*] Virtual adapter configured successfully.")

        tunnel = ClientTunnel(
            server_host=server_host,
            server_port=server_port,
            crypto_session=crypto,
            wintun_adapter=adapter,
            status_callback=lambda msg: print(f"[TUNNEL] {msg}"),
        )

        tunnel.start()
        print("\n[✓] VPN TUNNEL CONNECTED AND RUNNING! Press Ctrl+C to disconnect.\n")

        while True:
            time.sleep(2.0)
            stats = tunnel.metrics.snapshot()
            up_kbps = stats["upload_kbps"]
            down_kbps = stats["download_kbps"]
            tx_mb = stats["bytes_sent"] / (1024 * 1024)
            rx_mb = stats["bytes_recv"] / (1024 * 1024)
            sys.stdout.write(
                f"\r[STATS] TX: {tx_mb:.2f} MB ({up_kbps:.1f} Kbps) | "
                f"RX: {rx_mb:.2f} MB ({down_kbps:.1f} Kbps) | "
                f"Packets: ↑{stats['packets_sent']} ↓{stats['packets_recv']} "
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n\n[*] Disconnecting VPN tunnel gracefully...")
    finally:
        tunnel.stop()
        adapter.close()
        print("[*] VPN tunnel closed.")


if __name__ == "__main__":
    main()
