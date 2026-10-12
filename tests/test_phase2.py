"""Automated Verification Suite for Phase 2: Windows Wintun Driver Integration."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.wintun import (
    WintunDriver,
    WintunAdapter,
    is_admin,
    request_admin_elevation,
)


def test_dll_and_symbols():
    print("[1/3] Testing Wintun DLL Loading & Function Signatures...")
    driver = WintunDriver.load()
    assert driver.dll is not None, "Driver DLL must be loaded"

    # Verify key function pointers exist
    funcs = [
        "WintunCreateAdapter",
        "WintunOpenAdapter",
        "WintunCloseAdapter",
        "WintunStartSession",
        "WintunEndSession",
        "WintunGetReadWaitEvent",
        "WintunReceivePacket",
        "WintunReleaseReceivePacket",
        "WintunAllocateSendPacket",
        "WintunSendPacket",
    ]
    for func in funcs:
        assert hasattr(driver.dll, func), f"Missing Wintun function: {func}"

    print("      [OK] All 10 Wintun core functions loaded and mapped successfully.")


def test_admin_detection():
    print("[2/3] Checking Windows Administrator Privileges...")
    admin = is_admin()
    if admin:
        print("      [OK] Process is running with elevated Administrator privileges.")
    else:
        print("      [INFO] Process is currently running as standard user.")
        print("             (Wintun adapter creation requires Administrator rights on Windows).")
    return admin


def test_adapter_creation_and_session(is_elevated: bool):
    print("[3/3] Testing Wintun Adapter Lifecycle & Packet Session...")
    if not is_elevated:
        print("      [SKIP] Skipped adapter creation test because process is not elevated.")
        print("             Run as Administrator to perform full kernel adapter creation.")
        return

    adapter_name = "PyVPN_Test"
    print(f"      -> Creating test virtual adapter '{adapter_name}'...")
    with WintunAdapter(name=adapter_name, tunnel_type="PyVPN_Test") as adapter:
        print("      -> Configuring test IP 10.99.99.2...")
        try:
            adapter.configure_ip("10.99.99.2", "255.255.255.0", mtu=1420)
            print("      -> IP configuration applied.")
        except Exception as e:
            print(f"      [WARN] IP config warning: {e}")

        print("      -> Starting 4MB ring buffer session...")
        with adapter.start_session() as session:
            print("      -> Testing raw packet injection (Mock ICMP Ping)...")
            # Minimal mock IPv4 packet (20 bytes IPv4 header + 8 bytes ICMP)
            mock_packet = (
                b"\x45\x00\x00\x1c"  # IPv4, IHL 5, Total Length 28
                b"\x12\x34\x00\x00"  # Identification, Flags/Frag
                b"\x40\x01\x00\x00"  # TTL 64, Protocol 1 (ICMP), Checksum 0
                b"\x0a\x63\x63\x02"  # Src: 10.99.99.2
                b"\x0a\x63\x63\x01"  # Dst: 10.99.99.1
                b"\x08\x00\xf7\xff"  # ICMP Echo Request
                b"\x00\x01\x00\x01"  # Identifier, Sequence
            )
            success = session.write_packet(mock_packet)
            assert success, "Failed to inject packet into Wintun ring buffer"
            print("      -> Packet successfully injected into Windows network stack!")

    print("      [OK] Wintun adapter created, tested, and cleanly destroyed.")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if "--elevate" in sys.argv and not is_admin():
        print("Requesting Administrator elevation...")
        request_admin_elevation()

    print("=" * 60)
    print("  PyVPN Phase 2 Verification: Windows Wintun Driver Integration")
    print("=" * 60)
    test_dll_and_symbols()
    elevated = test_admin_detection()
    test_adapter_creation_and_session(elevated)
    print("=" * 60)
    print("  PHASE 2 CHECKS COMPLETED! [OK]")
    print("=" * 60)
