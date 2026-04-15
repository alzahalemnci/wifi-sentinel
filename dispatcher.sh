#!/usr/bin/env bash
# NetworkManager dispatcher script
# Install to: /etc/NetworkManager/dispatcher.d/99-wifi-sentinel
# Must be owned by root and chmod 755

INTERFACE="$1"
EVENT="$2"
SENTINEL="/opt/wifi-sentinel/wifi-sentinel.sh"   # update to your install path
USER="your-username"                              # update to your username

# Only act on WiFi up events
[[ "$EVENT" != "up" ]] && exit 0
[[ "$INTERFACE" != wl* ]] && exit 0   # wlan0, wlp3s0, etc.

# Run as your user (not root) so notifications and log paths work correctly
sudo -u "$USER" DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u $USER)/bus" \
    bash "$SENTINEL" &
