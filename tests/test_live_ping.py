"""Live verification of the remote PyVPN gateway server."""

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config import get_crypto_key, load_config
from core.crypto import CryptoSession
from core.transport import EncryptedUDPTransport


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def make_icmp_ping(src_ip: str = "10.8.0.2", dst_ip: str = "1.1.1.1") -> bytes:
    # ICMP Echo Request
    icmp_type = 8
    icmp_code = 0
    icmp_id = 0x1234
    icmp_seq = 1
    icmp_payload = b"PyVPN-LiveTest"
    dummy_csum = 0

    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, dummy_csum, icmp_id, icmp_seq)
    csum = checksum(icmp_header + icmp_payload)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, csum, icmp_id, icmp_seq)
    icmp_packet = icmp_header + icmp_payload

    # IPv4 Header
    ip_ver_ihl = (4 << 4) | 5
    ip_tos = 0
    ip_len = 20 + len(icmp_packet)
    ip_id = 54321
    ip_frag = 0
    ip_ttl = 64
    ip_proto = 1  # ICMP
    ip_src = socket.inet_aton(src_ip)
    ip_dst = socket.inet_aton(dst_ip)
    dummy_ip_csum = 0

    ip_hdr = struct.pack("!BBHHHBBH4s4s", ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, dummy_ip_csum, ip_src, ip_dst)
    ip_csum = checksum(ip_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_csum, ip_src, ip_dst)

    return ip_hdr + icmp_packet


def main():
    print("=" * 60)
    print("  Testing End-to-End Live Ping Through Remote PyVPN Server")
    print("=" * 60)

    cfg = load_config()
    server_host = cfg["server_host"]
    server_port = int(cfg["server_port"])
    print(f"[*] Target Server: {server_host}:{server_port}")

    key = get_crypto_key(cfg)
    crypto = CryptoSession(key)
    transport = EncryptedUDPTransport(crypto)
    transport.settimeout(3.0)

    try:
        ping_pkt = make_icmp_ping(src_ip=cfg.get("client_ip", "10.8.0.2"), dst_ip="1.1.1.1")
        print(f"[*] Sending encrypted ICMP ping to 1.1.1.1 via server ({len(ping_pkt)} bytes)...")
        start = time.perf_counter()
        transport.send_encrypted(ping_pkt, (server_host, server_port))

        print("[*] Waiting for encrypted reply from server...")
        reply, sender = transport.recv_encrypted(2048)
        rtt = (time.perf_counter() - start) * 1000.0

        print(f"[OK] SUCCESS! Received {len(reply)} bytes back from {sender} in {rtt:.1f} ms!")
        if len(reply) >= 20:
            src = socket.inet_ntoa(reply[12:16])
            dst = socket.inet_ntoa(reply[16:20])
            print(f"    Reply from: {src} -> {dst}")
            if reply[20] == 0:  # ICMP Echo Reply
                print("    ICMP Echo Reply verified! Internet routing and NAT are WORKING! [OK]")

    except socket.timeout:
        print("[!] Timeout: Server did not reply within 3 seconds.")
    finally:
        transport.close()


if __name__ == "__main__":
    main()
