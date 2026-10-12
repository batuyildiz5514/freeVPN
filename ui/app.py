"""Modern Desktop GUI for PyVPN using CustomTkinter and Pystray."""

from __future__ import annotations

import threading
import time
from typing import Optional

import customtkinter as ctk
from PIL import Image, ImageDraw
import pystray

from core.config import get_crypto_key, load_config, save_config
from core.crypto import CryptoSession, generate_key, key_to_base64
from core.routing import RoutingManager
from core.tunnel import ClientTunnel
from core.wintun import WintunAdapter, is_admin, request_admin_elevation


def create_tray_icon_image(connected: bool) -> Image.Image:
    """Generate dynamic shield/indicator icon for system tray."""
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    color = (34, 197, 94) if connected else (156, 163, 175)  # Green or Gray
    draw.ellipse([8, 8, 56, 56], fill=color)
    # Inner accent
    draw.ellipse([22, 22, 42, 42], fill=(255, 255, 255, 220))
    return img


class PyVPNApp(ctk.CTk):
    """Main application window for PyVPN."""

    def __init__(self):
        super().__init__()

        # Window configuration
        self.title("PyVPN - Secure Personal Tunnel")
        self.geometry("440x660")
        self.minsize(420, 600)
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.cfg = load_config()
        self.tunnel: Optional[ClientTunnel] = None
        self.adapter: Optional[WintunAdapter] = None
        self.routing: Optional[RoutingManager] = None
        self.is_connected = False
        self.is_connecting = False
        self._smoothed_tx_kbps = 0.0
        self._smoothed_rx_kbps = 0.0

        self._build_ui()
        self._init_tray()

        # Handle window close (minimize to tray)
        self.protocol("WM_DELETE_WINDOW", self._on_close_window)

        # Periodic metric update
        self._poll_metrics()

    def _build_ui(self) -> None:
        # Header frame
        self.header_frame = ctk.CTkFrame(self, corner_radius=12, fg_color="#1e222a")
        self.header_frame.pack(fill="x", padx=16, pady=(16, 8))

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="🛡️ PyVPN",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        self.title_label.pack(side="left", padx=16, pady=12)

        self.status_badge = ctk.CTkLabel(
            self.header_frame,
            text="● DISCONNECTED",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#9ca3af",
            fg_color="#282c34",
            corner_radius=8,
            padx=10,
            pady=4,
        )
        self.status_badge.pack(side="right", padx=16, pady=12)

        # Big Connect / Disconnect Action Card
        self.action_card = ctk.CTkFrame(self, corner_radius=16, fg_color="#181a20")
        self.action_card.pack(fill="x", padx=16, pady=8)

        self.connect_btn = ctk.CTkButton(
            self.action_card,
            text="CONNECT",
            font=ctk.CTkFont(size=18, weight="bold"),
            fg_color="#2563eb",
            hover_color="#1d4ed8",
            height=54,
            corner_radius=27,
            command=self._toggle_connection,
        )
        self.connect_btn.pack(fill="x", padx=24, pady=(20, 12))

        self.info_label = ctk.CTkLabel(
            self.action_card,
            text=f"Server: {self.cfg['server_host']}:{self.cfg['server_port']}",
            font=ctk.CTkFont(size=12),
            text_color="#6b7280",
        )
        self.info_label.pack(pady=(0, 16))

        # Live Traffic Metrics Cards
        self.metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.metrics_frame.pack(fill="x", padx=16, pady=8)
        self.metrics_frame.grid_columnconfigure((0, 1), weight=1)

        # Upload Card
        self.tx_card = ctk.CTkFrame(self.metrics_frame, corner_radius=12, fg_color="#1e222a")
        self.tx_card.grid(row=0, column=0, padx=(0, 6), sticky="nsew")

        ctk.CTkLabel(self.tx_card, text="▲ UPLOAD", font=ctk.CTkFont(size=11, weight="bold"), text_color="#3b82f6").pack(anchor="w", padx=12, pady=(10, 2))
        self.tx_speed_label = ctk.CTkLabel(self.tx_card, text="0.0 Kbps", font=ctk.CTkFont(size=18, weight="bold"))
        self.tx_speed_label.pack(anchor="w", padx=12)
        self.tx_total_label = ctk.CTkLabel(self.tx_card, text="Total: 0.0 MB", font=ctk.CTkFont(size=11), text_color="#9ca3af")
        self.tx_total_label.pack(anchor="w", padx=12, pady=(0, 10))

        # Download Card
        self.rx_card = ctk.CTkFrame(self.metrics_frame, corner_radius=12, fg_color="#1e222a")
        self.rx_card.grid(row=0, column=1, padx=(6, 0), sticky="nsew")

        ctk.CTkLabel(self.rx_card, text="▼ DOWNLOAD", font=ctk.CTkFont(size=11, weight="bold"), text_color="#10b981").pack(anchor="w", padx=12, pady=(10, 2))
        self.rx_speed_label = ctk.CTkLabel(self.rx_card, text="0.0 Kbps", font=ctk.CTkFont(size=18, weight="bold"))
        self.rx_speed_label.pack(anchor="w", padx=12)
        self.rx_total_label = ctk.CTkLabel(self.rx_card, text="Total: 0.0 MB", font=ctk.CTkFont(size=11), text_color="#9ca3af")
        self.rx_total_label.pack(anchor="w", padx=12, pady=(0, 10))

        # Settings Accordion / Tab
        self.settings_frame = ctk.CTkFrame(self, corner_radius=12, fg_color="#1e222a")
        self.settings_frame.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        ctk.CTkLabel(
            self.settings_frame,
            text="Connection Settings",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=16, pady=(12, 8))

        # Server Host & Port row
        row1 = ctk.CTkFrame(self.settings_frame, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=4)
        row1.grid_columnconfigure(0, weight=3)
        row1.grid_columnconfigure(1, weight=1)

        self.server_ip_entry = ctk.CTkEntry(row1, placeholder_text="Server IP (e.g. 1.2.3.4)")
        self.server_ip_entry.insert(0, str(self.cfg.get("server_host", "127.0.0.1")))
        self.server_ip_entry.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.server_port_entry = ctk.CTkEntry(row1, placeholder_text="Port")
        self.server_port_entry.insert(0, str(self.cfg.get("server_port", 51820)))
        self.server_port_entry.grid(row=0, column=1, padx=(6, 0), sticky="ew")

        # Pre-Shared Key Entry
        row2 = ctk.CTkFrame(self.settings_frame, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=4)

        self.key_entry = ctk.CTkEntry(row2, placeholder_text="ChaCha20-Poly1305 Key (Base64)", show="•")
        self.key_entry.insert(0, str(self.cfg.get("pre_shared_key", "")))
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        self.gen_key_btn = ctk.CTkButton(
            row2,
            text="Generate",
            width=70,
            fg_color="#374151",
            hover_color="#4b5563",
            command=self._generate_new_key,
        )
        self.gen_key_btn.pack(side="right")

        # Save Button
        self.save_cfg_btn = ctk.CTkButton(
            self.settings_frame,
            text="Save Settings",
            fg_color="#374151",
            hover_color="#4b5563",
            command=self._save_settings,
        )
        self.save_cfg_btn.pack(fill="x", padx=16, pady=(12, 12))

    def _init_tray(self) -> None:
        """Initializes system tray icon in a background thread."""
        menu = pystray.Menu(
            pystray.MenuItem("Show PyVPN", self._on_tray_show, default=True),
            pystray.MenuItem("Connect / Disconnect", self._tray_toggle),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", self._on_tray_exit),
        )
        self.tray_icon = pystray.Icon(
            "PyVPN",
            create_tray_icon_image(False),
            "PyVPN - Disconnected",
            menu,
        )
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _on_tray_show(self, icon=None, item=None) -> None:
        self.after(0, self._show_window)

    def _show_window(self) -> None:
        self.deiconify()
        self.lift()
        self.focus_force()

    def _on_close_window(self) -> None:
        # Hide to tray instead of quitting
        self.withdraw()

    def _on_tray_exit(self, icon=None, item=None) -> None:
        if self.is_connected:
            self._disconnect_engine()
        self.tray_icon.stop()
        self.after(0, self.destroy)

    def _tray_toggle(self, icon=None, item=None) -> None:
        self.after(0, self._toggle_connection)

    def _generate_new_key(self) -> None:
        new_key = generate_key()
        b64 = key_to_base64(new_key)
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, b64)

    def _save_settings(self) -> None:
        self.cfg["server_host"] = self.server_ip_entry.get().strip()
        self.cfg["server_port"] = int(self.server_port_entry.get().strip() or "51820")
        self.cfg["pre_shared_key"] = self.key_entry.get().strip()
        save_config(self.cfg)
        self.info_label.configure(text=f"Server: {self.cfg['server_host']}:{self.cfg['server_port']}")
        self.save_cfg_btn.configure(text="Settings Saved! ✓")
        self.after(2000, lambda: self.save_cfg_btn.configure(text="Save Settings"))

    def _toggle_connection(self) -> None:
        if self.is_connected:
            self._disconnect_engine()
        else:
            self._connect_engine()

    def _connect_engine(self) -> None:
        if not is_admin():
            request_admin_elevation()
            return

        self._save_settings()
        self.is_connecting = True
        self.connect_btn.configure(text="CONNECTING...", state="disabled")
        self.status_badge.configure(text="● CONNECTING...", text_color="#f59e0b")

        threading.Thread(target=self._worker_connect, daemon=True).start()

    def _worker_connect(self) -> None:
        try:
            self.cfg = load_config()
            key = get_crypto_key(self.cfg)
            crypto = CryptoSession(key)

            client_ip = self.cfg.get("client_ip", "10.8.0.2")
            subnet_mask = self.cfg.get("subnet_mask", "255.255.255.0")
            server_host = self.cfg["server_host"]
            server_port = int(self.cfg["server_port"])
            vpn_gw = self.cfg.get("server_vpn_ip", "10.8.0.1")

            self.adapter = WintunAdapter(name="PyVPN", tunnel_type="PyVPN")
            self.adapter.configure_ip(client_ip, subnet_mask, gateway=None)

            self.routing = RoutingManager(
                adapter_name="PyVPN",
                dns_servers=[self.cfg.get("dns_server", "1.1.1.1")],
            )
            if server_host not in ("127.0.0.1", "localhost", "0.0.0.0"):
                self.routing.setup_routes(server_ip=server_host, vpn_gateway=vpn_gw)

            self.tunnel = ClientTunnel(
                server_host=server_host,
                server_port=server_port,
                crypto_session=crypto,
                wintun_adapter=self.adapter,
            )
            self.tunnel.start()

            self.is_connected = True
            self.after(0, self._on_connected_ui)

        except Exception as exc:
            self.after(0, lambda: self._on_connect_error(str(exc)))

    def _on_connected_ui(self) -> None:
        self.is_connecting = False
        self.connect_btn.configure(text="DISCONNECT", fg_color="#dc2626", hover_color="#b91c1c", state="normal")
        self.status_badge.configure(text="● CONNECTED", text_color="#22c55e")
        self.tray_icon.icon = create_tray_icon_image(True)
        self.tray_icon.title = f"PyVPN - Connected to {self.cfg['server_host']}"

    def _on_connect_error(self, err_msg: str) -> None:
        self.is_connecting = False
        self._disconnect_engine()
        self.connect_btn.configure(text="CONNECT", fg_color="#2563eb", hover_color="#1d4ed8", state="normal")
        self.status_badge.configure(text="● ERROR", text_color="#ef4444")
        self.info_label.configure(text=f"Error: {err_msg[:40]}")

    def _disconnect_engine(self) -> None:
        if self.tunnel:
            try:
                self.tunnel.stop()
            except Exception:
                pass
            self.tunnel = None

        if self.routing:
            try:
                self.routing.restore_routes()
            except Exception:
                pass
            self.routing = None

        if self.adapter:
            try:
                self.adapter.close()
            except Exception:
                pass
            self.adapter = None

        self.is_connected = False
        self.is_connecting = False
        self.connect_btn.configure(text="CONNECT", fg_color="#2563eb", hover_color="#1d4ed8", state="normal")
        self.status_badge.configure(text="● DISCONNECTED", text_color="#9ca3af")
        self.tray_icon.icon = create_tray_icon_image(False)
        self.tray_icon.title = "PyVPN - Disconnected"

    @staticmethod
    def _format_speed(kbps: float) -> str:
        if kbps >= 1000:
            return f"{kbps / 1000:.1f} Mbps"
        return f"{kbps:.1f} Kbps"

    def _poll_metrics(self) -> None:
        if self.is_connected and self.tunnel:
            stats = self.tunnel.metrics.snapshot()
            raw_up = stats["upload_kbps"]
            raw_down = stats["download_kbps"]
            tx_mb = stats["bytes_sent"] / (1024 * 1024)
            rx_mb = stats["bytes_recv"] / (1024 * 1024)

            # Smooth speed gauge using Exponential Moving Average to prevent wild flickering
            alpha = 0.45
            if raw_up > self._smoothed_tx_kbps:
                self._smoothed_tx_kbps = (alpha * raw_up) + ((1.0 - alpha) * self._smoothed_tx_kbps)
            else:
                self._smoothed_tx_kbps = max(0.0, self._smoothed_tx_kbps * 0.6)
                if self._smoothed_tx_kbps < 1.0:
                    self._smoothed_tx_kbps = 0.0

            if raw_down > self._smoothed_rx_kbps:
                self._smoothed_rx_kbps = (alpha * raw_down) + ((1.0 - alpha) * self._smoothed_rx_kbps)
            else:
                self._smoothed_rx_kbps = max(0.0, self._smoothed_rx_kbps * 0.6)
                if self._smoothed_rx_kbps < 1.0:
                    self._smoothed_rx_kbps = 0.0

            self.tx_speed_label.configure(text=self._format_speed(self._smoothed_tx_kbps))
            self.tx_total_label.configure(text=f"Total: {tx_mb:.2f} MB")

            self.rx_speed_label.configure(text=self._format_speed(self._smoothed_rx_kbps))
            self.rx_total_label.configure(text=f"Total: {rx_mb:.2f} MB")
        else:
            self._smoothed_tx_kbps = 0.0
            self._smoothed_rx_kbps = 0.0
            self.tx_speed_label.configure(text="0.0 Kbps")
            self.rx_speed_label.configure(text="0.0 Kbps")

        self.after(500, self._poll_metrics)


def main():
    app = PyVPNApp()
    app.mainloop()


if __name__ == "__main__":
    main()
