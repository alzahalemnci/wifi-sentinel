#!/usr/bin/env bash
# lib/trust.sh — trusted network management
# Sourced by wifi-sentinel.sh. Expects TRUSTED_NETWORKS to be set.

is_trusted() {
    local ssid="$1" bssid="${2:-}"
    [[ -f "$TRUSTED_NETWORKS" ]] || return 1
    # Match SSID-only line (trusts any AP with this name)
    grep -qxF "$ssid" "$TRUSTED_NETWORKS" && return 0
    # Match SSID|BSSID line (trusts only this specific AP)
    [[ -n "$bssid" ]] && grep -qxF "$ssid|$bssid" "$TRUSTED_NETWORKS" && return 0
    return 1
}

add_to_trusted() {
    local ssid="$1" bssid="$2"
    # Store as SSID|BSSID so this entry is specific to this physical AP.
    # That way two networks with the same name don't both get trusted.
    echo "$ssid|$bssid" >> "$TRUSTED_NETWORKS"
}
