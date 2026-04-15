#!/usr/bin/env bash
# wifi-sentinel.sh — Automatic captive portal & rogue AP detector
# Runs on connect to any network not in your trusted list.

# -e  exit on any error
# -u  treat unset variables as errors
# -o pipefail  if any command in a pipe fails, the whole pipe fails
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
# BASH_SOURCE[0] is this script's path even when called via symlink or sourced.
# The cd/pwd pattern resolves it to an absolute path regardless of where you run from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUSTED_NETWORKS="$SCRIPT_DIR/trusted_networks.txt"
LOG_FILE="$SCRIPT_DIR/sentinel.log"
OUI_DB="$SCRIPT_DIR/oui.txt"           # optional local OUI db (see README)
NOTIFY=true                             # set false to disable desktop notifications
# ─────────────────────────────────────────────────────────────────────────────

# ANSI escape codes for terminal colours. NC = No Colour (reset).
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

# tee -a writes to stdout AND appends to the log file at the same time.
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
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

# ── Helpers ───────────────────────────────────────────────────────────────────
get_ssid() {
    # nmcli -t outputs terse (machine-readable) lines: "yes:MyNetwork"
    # grep '^yes' picks the active connection, cut extracts the SSID after the colon.
    # iwgetid is a fallback for systems without NetworkManager.
    nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || \
    iwgetid -r 2>/dev/null || echo "UNKNOWN"
}

get_gateway() {
    # Reads the kernel routing table and pulls out the default gateway IP.
    ip route show default | awk '/default/ {print $3; exit}'
}

get_gateway_mac() {
    local gw="$1"
    # The ARP cache is only populated after traffic reaches the gateway.
    # One ping ensures it's there before we try to read it.
    ping -c1 -W1 "$gw" &>/dev/null || true
    # 'ip neigh' shows the ARP table; field 5 is the MAC address.
    ip neigh show "$gw" 2>/dev/null | awk '{print $5}' | head -1
}

oui_lookup() {
    local mac="${1^^}"      # ^^ converts the string to uppercase
    local oui="${mac:0:8}"  # slice the first 8 characters = XX:XX:XX (3 octets)

    # Try local DB first (faster, offline)
    if [[ -f "$OUI_DB" ]]; then
        # The Wireshark manuf file uses dashes (AA-BB-CC), so replace colons.
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
    # -q  silent (no output, just exit code)
    # -x  match the whole line exactly (no partial matches)
    # -F  treat the pattern as a plain string, not a regex
    [[ -f "$TRUSTED_NETWORKS" ]] && grep -qxF "$ssid" "$TRUSTED_NETWORKS"
}

detect_captive_portal() {
    # Google's generate_204 endpoint normally returns HTTP 204 (no content).
    # If a captive portal intercepts the request it returns a redirect instead.
    # -w '%{redirect_url}' prints that redirect URL; if there's no redirect it's empty.
    local redirect
    redirect=$(curl -sf --max-time 5 -o /dev/null -w '%{redirect_url}' \
        http://connectivitycheck.gstatic.com/generate_204 2>/dev/null || true)
    echo "$redirect"
}

check_cert() {
    local host="$1"
    local port="${2:-443}"  # default to 443 if no port given
    # Two openssl commands piped together:
    #   s_client  opens a TLS connection and dumps the raw certificate
    #   x509      parses the cert and prints the requested fields
    # 'echo |' provides the empty input s_client needs to not hang waiting for stdin.
    # 'timeout 5' kills it if the host doesn't respond within 5 seconds.
    echo | timeout 5 openssl s_client -connect "$host:$port" -servername "$host" \
        2>/dev/null | openssl x509 -noout \
        -subject -issuer -dates -fingerprint 2>/dev/null || true
}

check_dns_hijack() {
    # Try systemd-resolved first, fall back to /etc/resolv.conf.
    local assigned_dns
    assigned_dns=$(resolvectl status 2>/dev/null | grep 'DNS Servers' | awk '{print $3}' | head -1)
    [[ -z "$assigned_dns" ]] && assigned_dns=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -1)

    # NXDOMAIN test: query a random domain that is guaranteed not to exist.
    # A legitimate DNS returns no answer (NXDOMAIN); a hijacking DNS returns an IP
    # so it can redirect you to a search/ad page. This avoids false positives from
    # CDN load balancing, where the same domain legitimately resolves to different
    # IPs depending on which resolver you ask.
    local canary="wifi-sentinel-canary-$(date +%s).invalid"
    local hijack_result
    hijack_result=$(dig +short +time=3 "$canary" 2>/dev/null | grep -v '^;' || true)

    echo "dns_server=$assigned_dns"
    if [[ -n "$hijack_result" ]]; then
        # Got an IP back for a non-existent domain — local DNS is redirecting queries.
        echo "dns_hijack=yes"
        echo "dns_redirect=$hijack_result"
    else
        echo "dns_hijack=no"
    fi
}

score_risk() {
    # Simple getter — RISK_SCORE is built up throughout main() via (( RISK_SCORE += N ))
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
    RISK_REASONS=()  # array — entries are appended with +=("reason text")

    # ── Gateway & MAC ─────────────────────────────────────────────────────────
    local gateway mac vendor
    gateway=$(get_gateway)
    if [[ -z "$gateway" ]]; then
        warn "Could not determine default gateway."
        exit 1
    fi
    info "Gateway: $gateway"

    mac=$(get_gateway_mac "$gateway")
    info "Gateway MAC: ${mac:-not found}"  # ${var:-fallback} prints fallback if var is empty

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
        # Parse just the hostname out of the URL (strip scheme and path).
        # awk splits on '/' to get the host:port part, cut drops any port number.
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

            # A self-signed cert has no separate CA — the subject signed itself.
            if [[ "$subject" == "$issuer" ]]; then
                warn "Certificate is SELF-SIGNED"
                RISK_SCORE=$((RISK_SCORE + 30))
                RISK_REASONS+=("Self-signed certificate")
            else
                good "Certificate has a distinct issuer (not self-signed)"
            fi

            # Legitimate TLS certs are issued to domain names, not raw IPs.
            if echo "$subject" | grep -qE 'CN=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
                warn "Certificate issued to a raw IP address"
                RISK_SCORE=$((RISK_SCORE + 25))
                RISK_REASONS+=("Cert CN is a raw IP")
            fi

            # Convert the cert's expiry string to a Unix timestamp and compare to now.
            if [[ -n "$not_after" ]]; then
                local expiry_epoch now_epoch
                # 'date -d' is GNU/Linux syntax; the second form is macOS/BSD fallback.
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

    # Parse the key=value output from check_dns_hijack
    local dns_server dns_hijack
    dns_server=$(echo "$dns_result" | grep dns_server | cut -d= -f2)
    dns_hijack=$(echo "$dns_result" | grep dns_hijack | cut -d= -f2)

    info "Assigned DNS: ${dns_server:-unknown}"

    case "$dns_hijack" in
        yes)
            alert "DNS HIJACKING DETECTED — local DNS is returning results for non-existent domains"
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
