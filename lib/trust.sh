#!/usr/bin/env bash
# lib/trust.sh — trusted network management and score history
# Sourced by wifi-sentinel.sh. Expects TRUSTED_NETWORKS and SCORE_HISTORY to be set.
#
# trusted_networks.txt format (one entry per line):
#   SSID                        — trust any AP with this name
#   SSID|BSSID                  — trust only this specific AP (legacy)
#   SSID|BSSID|GATEWAY_MAC      — trust this AP and record its gateway MAC for change detection
#
# score_history.txt format (one entry per scan):
#   SSID|BSSID|EPOCH|SCORE

is_trusted() {
    local ssid="$1" bssid="${2:-}"
    [[ -f "$TRUSTED_NETWORKS" ]] || return 1
    # Match SSID-only line
    grep -qxF "$ssid" "$TRUSTED_NETWORKS" && return 0
    # Match SSID|BSSID line (with or without trailing |GATEWAY_MAC field)
    # awk field-splits on '|' so partial substring matches can't occur
    [[ -n "$bssid" ]] && \
        awk -F'|' -v s="$ssid" -v b="$bssid" '$1==s && $2==b {found=1} END {exit !found}' \
        "$TRUSTED_NETWORKS" 2>/dev/null && return 0
    return 1
}

get_stored_gateway_mac() {
    local ssid="$1" bssid="$2"
    # Returns the stored gateway MAC for this SSID|BSSID entry, or empty if none recorded.
    awk -F'|' -v s="$ssid" -v b="$bssid" '$1==s && $2==b && $3!="" {print $3}' \
        "$TRUSTED_NETWORKS" 2>/dev/null | head -1 || true
}

add_to_trusted() {
    local ssid="$1" bssid="$2" gw_mac="${3:-}"
    if [[ -n "$gw_mac" ]]; then
        # Uppercase the MAC for consistent comparison later.
        echo "$ssid|$bssid|${gw_mac^^}" >> "$TRUSTED_NETWORKS"
    else
        echo "$ssid|$bssid" >> "$TRUSTED_NETWORKS"
    fi
}

# Returns the score from the most recent scan of this SSID|BSSID, or empty if
# no history exists yet.
get_last_score() {
    local ssid="$1" bssid="$2"
    [[ -f "$SCORE_HISTORY" ]] || return 0
    awk -F'|' -v s="$ssid" -v b="$bssid" '$1==s && $2==b {last=$4} END {print last}' \
        "$SCORE_HISTORY" 2>/dev/null || true
}

# Appends the current scan result to score_history.txt.
record_score() {
    local ssid="$1" bssid="$2" score="$3"
    echo "$ssid|$bssid|$(date +%s)|$score" >> "$SCORE_HISTORY"
}
