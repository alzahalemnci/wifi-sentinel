#!/usr/bin/env bash
# lib/logging.sh — terminal colours, log helpers, desktop notifications
# Sourced by wifi-sentinel.sh. Expects LOG_FILE and NOTIFY to be set.

# ANSI escape codes for terminal colours. NC = No Colour (reset).
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

# tee -a writes to stdout AND appends to the log file at the same time.
log()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info()  { echo -e "${CYN}[INFO]${NC}  $*"; log "INFO  $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; log "WARN  $*"; }
alert() { echo -e "${RED}[ALERT]${NC} $*"; log "ALERT $*"; }
good()  { echo -e "${GRN}[OK]${NC}    $*"; log "OK    $*"; }

notify() {
    local title="$1" body="$2" urgency="${3:-normal}"
    # Only fire if NOTIFY=true AND notify-send is actually installed.
    # The trailing '|| true' prevents set -e from aborting if notify-send fails.
    $NOTIFY && command -v notify-send &>/dev/null && \
        notify-send -u "$urgency" -i network-wireless "WiFi Sentinel: $title" "$body" || true
}

notify_interactive() {
    local title="$1" body="$2" urgency="${3:-normal}"
    $NOTIFY && command -v notify-send &>/dev/null || { echo ""; return; }
    # --wait blocks until the notification is dismissed or an action is clicked.
    # --action adds a button; notify-send prints the action ID ("trust") if clicked,
    # or an empty string if the notification is dismissed without clicking.
    notify-send --wait \
        -u "$urgency" \
        -i network-wireless \
        --action="trust=Add to Trusted" \
        "WiFi Sentinel: $title" "$body" 2>/dev/null || echo ""
}
