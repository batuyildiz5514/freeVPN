#!/bin/bash
# ==============================================================================
# PyVPN 1-Click Server Setup Script for Ubuntu / Debian / Oracle Linux
# ==============================================================================

set -e

echo "============================================================"
echo "  PyVPN Server 1-Click Installer"
echo "============================================================"

# Ensure root privileges
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (use: sudo bash setup_server.sh)"
  exit 1
fi

echo "[1/5] Installing dependencies..."
apt-get update -y
apt-get install -y python3 python3-pip python3-venv iptables curl git

echo "[2/5] Enabling IPv4 packet forwarding in Linux kernel..."
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

INSTALL_DIR="/opt/pyvpn"
echo "[3/5] Setting up PyVPN in $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# If running inside repo, copy files; otherwise clone
if [ -f "server.py" ]; then
    cp -r * "$INSTALL_DIR/"
else
    git clone https://github.com/batuyildiz5514/freeVPN.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Python virtual environment
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install cryptography

# Ensure config.json exists with pre-shared key
if [ ! -f "config.json" ]; then
    ./venv/bin/python3 -c "from core.config import load_config; load_config()"
fi

KEY=$(./venv/bin/python3 -c "import json; print(json.load(open('config.json'))['pre_shared_key'])")
PUBLIC_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "YOUR_SERVER_IP")

echo "[4/5] Opening firewall for UDP port 51820 and configuring high-throughput forwarding..."
# UFW if active
if command -v ufw >/dev/null 2>&1; then
    ufw allow 51820/udp || true
fi
# Oracle Cloud iptables rules
iptables -I INPUT -p udp --dport 51820 -j ACCEPT || true
# Forwarding and TCP MSS clamping for Oracle Cloud (prevents PMTU blackholes on 9000 MTU)
iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT || true
iptables -I FORWARD 2 -i tun0 -j ACCEPT || true
iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 || true

echo "[5/5] Creating and starting systemd background service (pyvpn.service)..."
cat <<EOF > /etc/systemd/system/pyvpn.service
[Unit]
Description=PyVPN Secure Gateway Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pyvpn
systemctl restart pyvpn

echo ""
echo "============================================================"
echo "  🎉 PyVPN SERVER INSTALLED AND RUNNING SUCCESSFULLY!       "
echo "============================================================"
echo ""
echo "Copy and paste these settings into your Windows PyVPN app:"
echo "------------------------------------------------------------"
echo "  Server IP       : $PUBLIC_IP"
echo "  Port            : 51820"
echo "  Pre-Shared Key  : $KEY"
echo "------------------------------------------------------------"
echo ""
echo "To view live server logs: journalctl -u pyvpn -f"
echo "============================================================"
