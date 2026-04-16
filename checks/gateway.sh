#!/usr/bin/env bash
# checks/gateway.sh — gateway reachability, MAC vendor lookup
# Sourced by wifi-sentinel.sh. Modifies globals RISK_SCORE and RISK_REASONS.

_get_gateway() {
    # Reads the kernel routing table and pulls out the default gateway IP.
    ip route show default | awk '/default/ {print $3; exit}'
}

_get_gateway_mac() {
    local gw="$1"
    # The ARP cache is only populated after traffic reaches the gateway.
    # One ping ensures it's there before we try to read it.
    ping -c1 -W1 "$gw" &>/dev/null || true
    # 'ip neigh' shows the ARP table; field 5 is the MAC address.
    ip neigh show "$gw" 2>/dev/null | awk '{print $5}' | head -1
}

_oui_lookup() {
    local mac="${1^^}"      # ^^ converts the string to uppercase
    local oui="${mac:0:8}"  # slice the first 8 characters = XX:XX:XX (3 octets)

    # Try local DB first (faster, offline)
    if [[ -f "$OUI_DB" ]]; then
        # The Wireshark manuf file uses dashes (AA-BB-CC), so replace colons.
        local normalized="${oui//:/-}"
        local result
        result=$(grep -i "^$normalized" "$OUI_DB" | head -1 | cut -f3 || true)
        [[ -n "$result" ]] && echo "$result" && return
    fi

    # Fall back to online API
    if command -v curl &>/dev/null; then
        curl -sf --max-time 5 "https://api.macvendors.com/$oui" 2>/dev/null || echo "Unknown"
    fi
}

# Public entry point — called by the main orchestrator.
# Returns 1 if the gateway cannot be determined (fatal, scan cannot continue).
check_gateway() {
    local gateway mac vendor
    gateway=$(_get_gateway)
    if [[ -z "$gateway" ]]; then
        warn "Could not determine default gateway."
        return 1
    fi
    info "Gateway: $gateway"

    mac=$(_get_gateway_mac "$gateway")
    info "Gateway MAC: ${mac:-not found}"

    if [[ -n "$mac" ]]; then
        vendor=$(_oui_lookup "$mac")
        info "OUI Vendor: ${vendor:-unknown}"
        if [[ -z "$vendor" || "$vendor" == "Unknown" ]]; then
            warn "Gateway MAC has no known vendor — could be a cheap/DIY AP"
            RISK_SCORE=$((RISK_SCORE + 20))
            RISK_REASONS+=("Unknown MAC vendor")
        else
            good "MAC vendor identified: $vendor"
        fi
    fi
}
