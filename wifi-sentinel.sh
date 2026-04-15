#!/usr/bin/env bash
# wifi-sentinel.sh — Automatic captive portal & rogue AP detector
# Runs on connect to any network not in your trusted list.

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUSTED_NETWORKS="$SCRIPT_DIR/trusted_networks.txt"
LOG_FILE="$SCRIPT_DIR/sentinel.log"
OUI_DB="$SCRIPT_DIR/oui.txt"           # optional local OUI db (see README)
NOTIFY=true                             # set false to disable desktop notifications
# ─────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
info()  { echo -e "${CYN}[INFO]${NC}  $*"; log "INFO  $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; log "WARN  $*"; }
alert() { echo -e "${RED}[ALERT]${NC} $*"; log "ALERT $*"; }
good()  { echo -e "${GRN}[OK]${NC}    $*"; log "OK    $*"; }

notify() {
    local title="$1" body="$2" urgency="${3:-normal}"
    $NOTIFY && command -v notify-send &>/dev/null && \
        notify-send -u "$urgency" -i network-wireless "WiFi Sentinel: $title" "$body" || true
}

# ── Helpers ───────────────────────────────────────────────────────────────────
get_ssid() {
    nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || \
    iwgetid -r 2>/dev/null || echo "UNKNOWN"
}

get_gateway() {
    ip route show default | awk '/default/ {print $3; exit}'
}

get_gateway_mac() {
    local gw="$1"
    # Ping once to populate ARP cache, then read it
    ping -c1 -W1 "$gw" &>/dev/null || true
    ip neigh show "$gw" 2>/dev/null | awk '{print $5}' | head -1
}

oui_lookup() {
    local mac="${1^^}"  # uppercase
    local oui="${mac:0:8}"  # first 3 octets XX:XX:XX

    # Try local DB first (faster, offline)
    if [[ -f "$OUI_DB" ]]; then
        local normalized="${oui//:/-}"
        grep -i "^$normalized" "$OUI_DB" | head -1 | cut -f3 || true
    fi

    # Fall back to online API
    if command -v curl &>/dev/null; then
        curl -sf --max-time 5 "https://api.macvendors.com/$oui" 2>/dev/null || echo "Unknown"
    fi
}

is_trusted() {
    local ssid="$1"
    [[ -f "$TRUSTED_NETWORKS" ]] && grep -qxF "$ssid" "$TRUSTED_NETWORKS"
}

detect_captive_portal() {
    # Returns the redirect URL if a captive portal is detected, empty otherwise
    local redirect
    redirect=$(curl -sf --max-time 5 -o /dev/null -w '%{redirect_url}' \
        http://connectivitycheck.gstatic.com/generate_204 2>/dev/null || true)
    echo "$redirect"
}

check_cert() {
    local host="$1"
    local port="${2:-443}"
    # Returns cert info as key=value lines
    echo | timeout 5 openssl s_client -connect "$host:$port" -servername "$host" \
        2>/dev/null | openssl x509 -noout \
        -subject -issuer -dates -fingerprint 2>/dev/null || true
}

check_dns_hijack() {
    local assigned_dns
    assigned_dns=$(resolvectl status 2>/dev/null | grep 'DNS Servers' | awk '{print $3}' | head -1)
    [[ -z "$assigned_dns" ]] && assigned_dns=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -1)

    local via_google via_local
    via_google=$(dig +short +time=3 google.com @8.8.8.8 2>/dev/null | grep -v '^;' | sort | head -5)
    via_local=$(dig +short +time=3 google.com 2>/dev/null | grep -v '^;' | sort | head -5)

    echo "dns_server=$assigned_dns"
    if [[ -z "$via_google" || -z "$via_local" ]]; then
        echo "dns_hijack=unknown"
    elif [[ "$via_google" != "$via_local" ]]; then
        echo "dns_hijack=yes"
        echo "dns_google=$via_google"
        echo "dns_local=$via_local"
    else
        echo "dns_hijack=no"
    fi
}

score_risk() {
    # Accumulates a numeric risk score and returns it
    echo "$RISK_SCORE"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    local ssid
    ssid=$(get_ssid)

    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYN}  WiFi Sentinel — scanning: $ssid${NC}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "=== Scan start: SSID=$ssid ==="

    # Skip trusted networks
    if is_trusted "$ssid"; then
        good "Network '$ssid' is in your trusted list. Skipping."
        exit 0
    fi

    RISK_SCORE=0
    RISK_REASONS=()

    # ── Gateway & MAC ─────────────────────────────────────────────────────────
    local gateway mac vendor
    gateway=$(get_gateway)
    if [[ -z "$gateway" ]]; then
        warn "Could not determine default gateway."
        exit 1
    fi
    info "Gateway: $gateway"

    mac=$(get_gateway_mac "$gateway")
    info "Gateway MAC: ${mac:-not found}"

    if [[ -n "$mac" ]]; then
        vendor=$(oui_lookup "$mac")
        info "OUI Vendor: ${vendor:-unknown}"
        if [[ -z "$vendor" || "$vendor" == "Unknown" ]]; then
            warn "Gateway MAC has no known vendor — could be a cheap/DIY AP"
            RISK_SCORE=$((RISK_SCORE + 20))
            RISK_REASONS+=("Unknown MAC vendor")
        else
            good "MAC vendor identified: $vendor"
        fi
    fi

    # ── Captive Portal Detection ──────────────────────────────────────────────
    local portal_url
    portal_url=$(detect_captive_portal)

    if [[ -n "$portal_url" ]]; then
        info "Captive portal detected: $portal_url"
        local portal_host
        portal_host=$(echo "$portal_url" | awk -F/ '{print $3}' | cut -d: -f1)

        # ── Certificate Check ─────────────────────────────────────────────────
        info "Checking TLS certificate for $portal_host ..."
        local cert_info
        cert_info=$(check_cert "$portal_host")

        if [[ -z "$cert_info" ]]; then
            warn "Could not retrieve certificate from portal host."
            RISK_SCORE=$((RISK_SCORE + 15))
            RISK_REASONS+=("No cert retrievable from portal")
        else
            local subject issuer not_after
            subject=$(echo "$cert_info" | grep subject | sed 's/subject=//')
            issuer=$(echo  "$cert_info" | grep issuer  | sed 's/issuer=//')
            not_after=$(echo "$cert_info" | grep notAfter | sed 's/notAfter=//')

            info "Subject : $subject"
            info "Issuer  : $issuer"
            info "Expires : $not_after"

            # Self-signed: issuer == subject
            if [[ "$subject" == "$issuer" ]]; then
                warn "Certificate is SELF-SIGNED"
                RISK_SCORE=$((RISK_SCORE + 30))
                RISK_REASONS+=("Self-signed certificate")
            else
                good "Certificate has a distinct issuer (not self-signed)"
            fi

            # Cert issued to raw IP
            if echo "$subject" | grep -qE 'CN=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
                warn "Certificate issued to a raw IP address"
                RISK_SCORE=$((RISK_SCORE + 25))
                RISK_REASONS+=("Cert CN is a raw IP")
            fi

            # Expired
            if [[ -n "$not_after" ]]; then
                local expiry_epoch now_epoch
                expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo 0)
                now_epoch=$(date +%s)
                if (( expiry_epoch > 0 && expiry_epoch < now_epoch )); then
                    warn "Certificate is EXPIRED"
                    RISK_SCORE=$((RISK_SCORE + 20))
                    RISK_REASONS+=("Expired certificate")
                else
                    good "Certificate is not expired"
                fi
            fi
        fi
    else
        good "No captive portal detected."
    fi

    # ── DNS Hijack Check ──────────────────────────────────────────────────────
    info "Checking for DNS hijacking ..."
    local dns_result
    dns_result=$(check_dns_hijack)

    local dns_server dns_hijack
    dns_server=$(echo "$dns_result" | grep dns_server | cut -d= -f2)
    dns_hijack=$(echo "$dns_result" | grep dns_hijack | cut -d= -f2)

    info "Assigned DNS: ${dns_server:-unknown}"

    case "$dns_hijack" in
        yes)
            alert "DNS HIJACKING DETECTED — local DNS results differ from 8.8.8.8"
            RISK_SCORE=$((RISK_SCORE + 50))
            RISK_REASONS+=("DNS hijacking detected")
            ;;
        no)
            good "DNS is not being hijacked"
            ;;
        unknown)
            warn "Could not determine DNS hijacking status (no internet yet?)"
            ;;
    esac

    # ── Verdict ───────────────────────────────────────────────────────────────
    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYN}  VERDICT — Risk Score: $RISK_SCORE / 100${NC}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if (( RISK_SCORE == 0 )); then
        good "Network looks clean. No anomalies detected."
        notify "Clean" "Network '$ssid' passed all checks." normal
    elif (( RISK_SCORE < 30 )); then
        warn "Low-risk anomalies found on '$ssid':"
        for r in "${RISK_REASONS[@]}"; do echo -e "  ${YEL}•${NC} $r"; done
        warn "Probably lazy IT. Avoid sending sensitive data without a VPN."
        notify "Low Risk" "$ssid — ${RISK_REASONS[*]}" normal
    elif (( RISK_SCORE < 60 )); then
        alert "Moderate risk on '$ssid':"
        for r in "${RISK_REASONS[@]}"; do echo -e "  ${RED}•${NC} $r"; done
        alert "Use a VPN. Do not log in to anything on this network."
        notify "Moderate Risk" "$ssid — ${RISK_REASONS[*]}" critical
    else
        alert "HIGH RISK — possible rogue AP / evil twin on '$ssid':"
        for r in "${RISK_REASONS[@]}"; do echo -e "  ${RED}•${NC} $r"; done
        alert "DISCONNECT IMMEDIATELY. Use mobile data."
        notify "HIGH RISK — DISCONNECT" "$ssid — ${RISK_REASONS[*]}" critical
    fi

    echo ""
    log "=== Scan end: SSID=$ssid  score=$RISK_SCORE  reasons=${RISK_REASONS[*]:-none} ==="
}

main "$@"
