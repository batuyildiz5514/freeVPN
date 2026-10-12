# PyVPN (freeVPN) 🛡️

A lightweight, 100% free, and self-hosted personal VPN built from scratch in Python. Designed with a clean, high-performance architecture inspired by WireGuard principles — featuring **ChaCha20-Poly1305** authenticated encryption, **Wintun** virtual network interface, and a modern desktop user interface.

---

## 🌟 Key Highlights

- **Zero-Cost Guarantee:** No paid services, subscriptions, proprietary APIs, or hidden fees. Uses open-source components and free-tier infrastructure.
- **WireGuard Philosophy:** Simple, lightweight, high-performance UDP tunneling without bloat.
- **Robust Cryptography:** Industry-standard **ChaCha20-Poly1305 (AEAD)** for both confidentiality and tamper-proof message integrity.
- **High-Performance TUN Interface:** Native Windows packet capture and injection via the official **Wintun (`wintun.dll`)** driver using Python `ctypes`.
- **Modern Desktop GUI & System Tray:** Clean dark-mode interface built with CustomTkinter, featuring real-time bandwidth metrics, ping latency, connection state toggling, and system tray minimization.
- **Self-Hosted & Privacy-First:** Completely open source. Run the server on your own hardware or an Oracle Cloud Always Free instance.

---

## 📐 Architecture & Workflow

```text
┌────────────────────────────────────────────────────────┐
│ [ USER INTERFACE (CustomTkinter GUI & System Tray) ]   │
│ - 1-Click Connect/Disconnect, Live Speed & Ping Meters │
└───────────────────────────┬────────────────────────────┘
                            │ (Worker Thread Control)
                            ▼
[ Applications / Browser ]
            │ (Raw IP Packets)
            ▼
┌────────────────────────────────────────────────────────┐
│ 1. VIRTUAL NETWORK INTERFACE (Wintun TUN Device)       │
│ - Creates a high-speed virtual TAP/TUN adapter.        │
│ - Captures outgoing IP packets at the byte level.      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. CRYPTOGRAPHY & ENCAPSULATION (Client Engine)        │
│ - ChaCha20-Poly1305 authenticated symmetric encryption │
│ - Encapsulates encrypted payload into standard UDP     │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼ (Encrypted UDP Tunnel)
┌────────────────────────────────────────────────────────┐
│ 3. VPN SERVER (Exit Node / Gateway)                    │
│ - Listens on UDP socket, authenticates & decrypts      │
│ - Injects raw IP packets into network interface        │
│ - NAT / IP Masquerading out to the public internet     │
└────────────────────────────────────────────────────────┘
```

---

## ⚙️ Technical Specifications

1. **Transport Layer:** Strictly **UDP** to eliminate TCP-over-TCP meltdown and packet stalling.
2. **Cipher Suite:** **ChaCha20-Poly1305 (AEAD)** from the `cryptography` library.
3. **MTU Configuration:** Optimized to **1420 bytes** to accommodate encapsulation overhead and prevent packet fragmentation.
4. **Routing Loop Mitigation:** Dedicated `/32` host routes for the VPN server endpoint to ensure tunnel traffic bypasses the virtual interface.
5. **DNS & Leak Protection:** Enforces clean DNS resolution to avert DNS leaks.

---

## 🔒 Privacy & Zero-Leak Policy

This repository is designed from day one to be safely published on GitHub:
- **No Hardcoded Secrets or Paths:** Dynamic relative paths only; no personal filesystem paths (`C:\Users\...`) or sensitive server endpoints.
- **Git Shielded:** Real configurations, IP addresses, private keys, logs, and virtual environments are strictly blocked by `.gitignore`.
- **Configuration Template:** Safe configuration templates are provided via [`config.example.json`](config.example.json).

---

## 🗺️ Roadmap

- [x] **Phase 1: Cryptographic UDP Tunnel Core**
  - Implement and test secure UDP socket exchange with ChaCha20-Poly1305 authenticated encryption.
- [x] **Phase 2: Windows Wintun Driver Integration**
  - Bind `wintun.dll` via Python `ctypes` and initialize ring buffers for raw packet I/O.
- [ ] **Phase 3: End-to-End Packet Tunneling**
  - Bidirectional packet routing between the virtual interface and the encrypted UDP transport.
- [ ] **Phase 4: Routing Table & DNS Management**
  - Automatic default gateway switching and leak-free DNS routing via Windows IP Helper APIs.
- [ ] **Phase 5: Modern GUI & System Tray Integration**
  - Intuitive desktop UI (CustomTkinter) with system tray support (`pystray`), live transfer speed, and connection statistics.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
