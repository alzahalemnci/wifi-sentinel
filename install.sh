#!/usr/bin/env bash
# One-time setup script for wifi-sentinel
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wifi-sentinel"
CURRENT_USER="${SUDO_USER:-$USER}"

echo "[1/4] Installing dependencies..."
sudo apt-get install -y openssl curl dnsutils nmap libnotify-bin 2>/dev/null || \
sudo dnf     install -y openssl curl bind-utils nmap libnotify   2>/dev/null || \
echo "  Install manually: openssl curl dig nmap notify-send"

echo "[2/4] Copying files to $INSTALL_DIR..."
sudo mkdir -p "$INSTALL_DIR/lib" "$INSTALL_DIR/checks"
sudo cp "$SCRIPT_DIR/wifi-sentinel.sh"  "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/dispatcher.sh"     "$INSTALL_DIR/"
sudo cp "$SCRIPT_DIR/lib/"*.sh          "$INSTALL_DIR/lib/"
sudo cp "$SCRIPT_DIR/checks/"*.sh       "$INSTALL_DIR/checks/"
sudo chmod +x "$INSTALL_DIR/wifi-sentinel.sh"
sudo chmod +x "$INSTALL_DIR/dispatcher.sh"
sudo chown -R root:root "$INSTALL_DIR/lib" "$INSTALL_DIR/checks"
sudo chown root:root "$INSTALL_DIR/wifi-sentinel.sh" "$INSTALL_DIR/dispatcher.sh"

# sentinel.conf — copy if present, create from defaults if not; must be user-editable
if [[ -f "$SCRIPT_DIR/sentinel.conf" ]]; then
    sudo cp "$SCRIPT_DIR/sentinel.conf" "$INSTALL_DIR/"
else
    sudo touch "$INSTALL_DIR/sentinel.conf"
fi
sudo chown "root:$CURRENT_USER" "$INSTALL_DIR/sentinel.conf"
sudo chmod 664 "$INSTALL_DIR/sentinel.conf"

# trusted_networks.txt — create with template comments if it doesn't exist yet.
# Never overwrite an existing file — it contains the user's trusted entries.
if [[ ! -f "$INSTALL_DIR/trusted_networks.txt" ]]; then
    sudo tee "$INSTALL_DIR/trusted_networks.txt" > /dev/null << 'EOF'
# One SSID per line — sentinel will skip these networks entirely.
# Entries are added automatically when you click "Add to Trusted" on a notification.
# To add manually, use the format: SSID|BSSID|GATEWAY_MAC
# Examples:
# MyHomeWiFi
# WorkNetwork
# MyHomeWiFi|AA:BB:CC:DD:EE:FF|11:22:33:44:55:66
EOF
fi
sudo chown "root:$CURRENT_USER" "$INSTALL_DIR/trusted_networks.txt"
sudo chmod 664 "$INSTALL_DIR/trusted_networks.txt"

# sentinel.log and score_history.txt — pre-create so the user can write without root
sudo touch "$INSTALL_DIR/sentinel.log"
sudo chown "root:$CURRENT_USER" "$INSTALL_DIR/sentinel.log"
sudo chmod 664 "$INSTALL_DIR/sentinel.log"

sudo touch "$INSTALL_DIR/score_history.txt"
sudo chown "root:$CURRENT_USER" "$INSTALL_DIR/score_history.txt"
sudo chmod 664 "$INSTALL_DIR/score_history.txt"

echo "[3/4] Installing NetworkManager dispatcher..."
sudo sed \
    -e "s|SENTINEL=.*|SENTINEL=\"$INSTALL_DIR/wifi-sentinel.sh\"|" \
    -e "s|USER=.*|USER=\"$CURRENT_USER\"|" \
    "$INSTALL_DIR/dispatcher.sh" \
    | sudo tee /etc/NetworkManager/dispatcher.d/99-wifi-sentinel > /dev/null
sudo chown root:root /etc/NetworkManager/dispatcher.d/99-wifi-sentinel
sudo chmod 755 /etc/NetworkManager/dispatcher.d/99-wifi-sentinel

echo "[4/4] (Optional) Downloading OUI database for offline vendor lookups..."
# Wireshark's manuf file works well as a local OUI DB
curl -sf https://www.wireshark.org/download/automated/data/manuf -o "$INSTALL_DIR/oui.txt" && \
    echo "  OUI database saved to oui.txt" || \
    echo "  Skipped — will fall back to online API"

echo ""
echo "Done! Edit trusted_networks.txt to add your home/work SSIDs."
echo "To test manually: bash $SCRIPT_DIR/wifi-sentinel.sh"
