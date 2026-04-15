#!/usr/bin/env bash
# One-time setup script for wifi-sentinel
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/4] Installing dependencies..."
sudo apt-get install -y openssl curl dnsutils nmap libnotify-bin 2>/dev/null || \
sudo dnf     install -y openssl curl bind-utils nmap libnotify   2>/dev/null || \
echo "  Install manually: openssl curl dig nmap notify-send"

echo "[2/4] Making scripts executable..."
chmod +x "$SCRIPT_DIR/wifi-sentinel.sh"
chmod +x "$SCRIPT_DIR/dispatcher.sh"

echo "[3/4] Installing NetworkManager dispatcher..."
sudo cp "$SCRIPT_DIR/dispatcher.sh" /etc/NetworkManager/dispatcher.d/99-wifi-sentinel
sudo chown root:root /etc/NetworkManager/dispatcher.d/99-wifi-sentinel
sudo chmod 755 /etc/NetworkManager/dispatcher.d/99-wifi-sentinel

echo "[4/4] (Optional) Downloading OUI database for offline vendor lookups..."
# Wireshark's manuf file works well as a local OUI DB
curl -sf https://www.wireshark.org/download/automated/data/manuf -o "$SCRIPT_DIR/oui.txt" && \
    echo "  OUI database saved to oui.txt" || \
    echo "  Skipped — will fall back to online API"

echo ""
echo "Done! Edit trusted_networks.txt to add your home/work SSIDs."
echo "To test manually: bash $SCRIPT_DIR/wifi-sentinel.sh"
