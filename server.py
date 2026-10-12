"""PyVPN Server Runner (Supports both Windows and Linux hosts)."""

from __future__ import annotations

import sys
import time

from core.config import get_crypto_key, load_config
from core.crypto import CryptoSession
from core.tunnel import ServerTunnel


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 60)
    print("  PyVPN Server - Secure Gateway Node")
    print("=" * 60)

    cfg = load_config()
    bind_port = int(cfg.get("server_port", 51820))
    bind_host = "0.0.0.0"

    key = get_crypto_key(cfg)
    crypto = CryptoSession(key)

    tun_dev = None
    if sys.platform.startswith("linux"):
        try:
            from core.linux_tun import LinuxTunDevice
            print("[*] Linux detected. Initializing kernel TUN interface (tun0) with NAT masquerading...")
            tun_dev = LinuxTunDevice(dev_name="tun0", ip_cidr="10.8.0.1/24")
            print("[✓] Linux TUN device and iptables NAT configured successfully.")
        except Exception as exc:
            print(f"[!] Warning: Could not initialize Linux TUN ({exc}). Running in relay mode.")

    server = ServerTunnel(
        bind_host=bind_host,
        bind_port=bind_port,
        crypto_session=crypto,
        tun_device=tun_dev,
        status_callback=lambda msg: print(f"[SERVER] {msg}"),
    )

    server.start()
    print(f"\n[✓] PyVPN Server is listening on UDP port {bind_port}! Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(2.0)
            stats = server.metrics.snapshot()
            up_kbps = stats["upload_kbps"]
            down_kbps = stats["download_kbps"]
            rx_mb = stats["bytes_recv"] / (1024 * 1024)
            tx_mb = stats["bytes_sent"] / (1024 * 1024)
            print(
                f"[SERVER STATS] Inbound: {rx_mb:.2f} MB ({down_kbps:.1f} Kbps) | "
                f"Outbound: {tx_mb:.2f} MB ({up_kbps:.1f} Kbps) | "
                f"Packets: In {stats['packets_recv']} / Out {stats['packets_sent']}",
                flush=True
            )
    except KeyboardInterrupt:
        print("\n\n[*] Stopping PyVPN Server...")
    finally:
        server.stop()
        print("[*] Server stopped cleanly.")


if __name__ == "__main__":
    main()
