#!/usr/bin/env bash
# checks/evil_twin.sh — detect multiple APs broadcasting the same SSID
# Sourced by wifi-sentinel.sh. Modifies globals RISK_SCORE and RISK_REASONS.

# Public entry point — called by the main orchestrator with the current SSID.
check_evil_twin() {
    local ssid="$1"
    info "Checking for evil twin APs ..."

    # List all visible APs and collect unique BSSIDs broadcasting this SSID.
    # nmcli -t uses ':' as separator; BSSID values have colons escaped as '\:'
    # so we use the non-terse form and rely on column position instead.
    local bssids
    bssids=$(nmcli -f SSID,BSSID dev wifi 2>/dev/null \
        | awk -v ssid="$ssid" '$1 == ssid {print $2}' \
        | sort -u)

    local count
    count=$(echo "$bssids" | grep -c . || true)

    if (( count > 1 )); then
        # Multiple BSSIDs for the same SSID is suspicious but not conclusive —
        # legitimate mesh networks and enterprise WiFi do the same thing.
        # Flag it as a low-weight indicator and show the full list for context.
        warn "Multiple APs ($count) are broadcasting SSID '$ssid' — possible evil twin"
        while IFS= read -r b; do
            info "  Visible AP: $b"
        done <<< "$bssids"
        RISK_SCORE=$((RISK_SCORE + 15))
        RISK_REASONS+=("Multiple APs with same SSID ($count detected — could be mesh or evil twin)")
        evidence_add "Multiple APs Broadcasting Same SSID" \
            "Found $count devices broadcasting '$ssid'. While mesh networks do this legitimately, it is also how evil twin attacks work — a rogue AP copies your network name to intercept traffic. Compare the BSSIDs below against the label on your router." \
            "$(echo "$bssids" | sed 's/^/  BSSID: /')"
    else
        good "Only one AP broadcasting '$ssid' — no evil twin detected"
    fi
}
