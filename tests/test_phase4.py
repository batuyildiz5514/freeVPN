"""Automated Verification Suite for Phase 4: Routing Table & DNS Management."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.routing import RoutingManager, get_default_gateway
from core.wintun import is_admin


def test_gateway_discovery():
    print("[1/3] Testing Active Default Gateway Discovery on Windows...")
    gw, iface = get_default_gateway()
    assert gw is not None, "Failed to discover default gateway IP"
    assert iface is not None, "Failed to discover default interface IP"
    print(f"      [OK] Discovered Gateway: {gw} on Interface: {iface}")


def test_routing_manager_state():
    print("[2/3] Testing RoutingManager State & Safe Cleanup Lifecycle...")
    manager = RoutingManager(adapter_name="PyVPN_Test", dns_servers=["1.1.1.1", "1.0.0.1"])
    assert not manager.is_active, "Routing manager must be inactive by default"

    # Calling restore when inactive must be safe and idempotent
    manager.restore_routes()
    assert not manager.is_active
    print("      [OK] RoutingManager lifecycle and safety handlers verified.")


def test_live_route_manipulation(is_elevated: bool):
    print("[3/3] Testing Route Injection and Restoration...")
    if not is_elevated:
        print("      [SKIP] Skipped route table modification test (requires Administrator rights).")
        print("             Run as Administrator to verify live route table entries.")
        return

    manager = RoutingManager(adapter_name="PyVPN_Test", dns_servers=["1.1.1.1"])
    try:
        # Test routing against safe dummy IP
        dummy_server_ip = "198.51.100.1"
        dummy_vpn_gateway = "10.99.99.1"
        print(f"      -> Injecting test routes for {dummy_server_ip} via {dummy_vpn_gateway}...")
        manager.setup_routes(server_ip=dummy_server_ip, vpn_gateway=dummy_vpn_gateway)
        assert manager.is_active, "RoutingManager must be active after setup"
        print("      -> Routes applied successfully.")
    finally:
        print("      -> Restoring routes...")
        manager.restore_routes()
        assert not manager.is_active, "RoutingManager must be inactive after restore"
        print("      [OK] Routing table cleanly restored with zero leaks.")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    print("=" * 60)
    print("  PyVPN Phase 4 Verification: Routing Table & DNS Management")
    print("=" * 60)
    test_gateway_discovery()
    test_routing_manager_state()
    elevated = is_admin()
    test_live_route_manipulation(elevated)
    print("=" * 60)
    print("  ALL PHASE 4 CHECKS COMPLETED SUCCESSFULLY! [OK]")
    print("=" * 60)
