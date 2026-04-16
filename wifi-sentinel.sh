#!/usr/bin/env bash
# wifi-sentinel.sh — Automatic captive portal & rogue AP detector
# Runs on every WiFi connect for networks not in your trusted list.

# -e  exit on any error
# -u  treat unset variables as errors
# -o pipefail  if any command in a pipe fails, the whole pipe fails
set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
# BASH_SOURCE[0] is this script's path even when called via symlink or sourced.
# The cd/pwd pattern resolves it to an absolute path regardless of where you run from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUSTED_NETWORKS="${TRUSTED_NETWORKS:-$SCRIPT_DIR/trusted_networks.txt}"
SCORE_HISTORY="${SCORE_HISTORY:-$SCRIPT_DIR/score_history.txt}"
LOG_FILE="$SCRIPT_DIR/sentinel.log"
OUI_DB="$SCRIPT_DIR/oui.txt"   # optional local OUI db (see README)

# ── Defaults (overridden by sentinel.conf, or by environment for testing) ────
NOTIFY=${NOTIFY:-true}
AUTO_TRUST=${AUTO_TRUST:-true}

# ── Load config and modules ───────────────────────────────────────────────────
[[ -f "$SCRIPT_DIR/sentinel.conf" ]] && source "$SCRIPT_DIR/sentinel.conf"

source "$SCRIPT_DIR/lib/logging.sh"
source "$SCRIPT_DIR/lib/trust.sh"
source "$SCRIPT_DIR/checks/gateway.sh"
source "$SCRIPT_DIR/checks/dns.sh"
source "$SCRIPT_DIR/checks/cert.sh"
source "$SCRIPT_DIR/checks/evil_twin.sh"

# ── Network identity ──────────────────────────────────────────────────────────
get_ssid() {
    # nmcli -t outputs terse (machine-readable) lines: "yes:MyNetwork"
    # grep '^yes' picks the active connection, cut extracts the SSID after the colon.
    # iwgetid is a fallback for systems without NetworkManager.
    nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || \
    iwgetid -r 2>/dev/null || echo "UNKNOWN"
}

get_bssid() {
    # The BSSID is the MAC address of the wireless access point (the radio).
    # Unlike the SSID (network name), it is unique per physical AP — two networks
    # can share an SSID but never a BSSID.
    nmcli -f ACTIVE,BSSID dev wifi 2>/dev/null | awk '/^yes/ {print $2}' || \
    iwgetid --ap -r 2>/dev/null || echo "UNKNOWN"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    local ssid bssid
    ssid=$(get_ssid)
    bssid=$(get_bssid)

    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYN}  WiFi Sentinel — scanning: $ssid${NC}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    log "=== Scan start: SSID=$ssid BSSID=$bssid ==="

    RISK_SCORE=0
    RISK_REASONS=()
    GATEWAY_MAC=""

    if is_trusted "$ssid" "$bssid"; then
        # Before skipping, verify the gateway MAC hasn't changed since we last trusted
        # this network — a change could mean an evil twin is pretending to be it.
        local gw gw_mac stored_mac
        gw=$(_get_gateway)
        gw_mac=$(_get_gateway_mac "$gw")
        stored_mac=$(get_stored_gateway_mac "$ssid" "$bssid")

        if [[ -n "$stored_mac" && -n "$gw_mac" && "${gw_mac^^}" != "${stored_mac^^}" ]]; then
            alert "Gateway MAC changed on trusted network '$ssid' (was $stored_mac, now ${gw_mac^^})"
            RISK_SCORE=$((RISK_SCORE + 40))
            RISK_REASONS+=("Gateway MAC changed since last visit")
            GATEWAY_MAC="$gw_mac"
            # Fall through to full scan — do not skip
        else
            good "Network '$ssid' is in your trusted list. Skipping."
            exit 0
        fi
    fi

    # ── Run checks ────────────────────────────────────────────────────────────
    check_gateway || exit 1   # fatal if no gateway — nothing else can run
    check_evil_twin "$ssid"
    check_tls_pinning
    check_https_downgrade
    check_portal
    check_dns
    check_dnssec

    # ── Score history ─────────────────────────────────────────────────────────
    # Record raw score before escalation so history reflects actual check results.
    local last_score
    last_score=$(get_last_score "$ssid" "$bssid")
    record_score "$ssid" "$bssid" "$RISK_SCORE"
    if [[ -n "$last_score" && "$last_score" == "0" && "$RISK_SCORE" -gt 0 ]]; then
        warn "Previously clean network now shows anomalies (last score: 0, current: $RISK_SCORE)"
        RISK_SCORE=$((RISK_SCORE + 20))
        RISK_REASONS+=("Previously clean — new anomalies detected since last visit")
    fi

    # ── Silent scan logic ─────────────────────────────────────────────────────
    # In dispatcher mode, suppress notifications only when the network scores 0
    # and has scored 0 before — genuinely clean and already seen.
    # Any score > 0 always notifies, regardless of history, so untrusted networks
    # (e.g. a coffee shop) keep alerting until explicitly added to the trusted list.
    # Terminal mode always shows full output regardless.
    local should_notify=true
    if [[ ! -t 0 && "$RISK_SCORE" -eq 0 && -n "$last_score" ]]; then
        should_notify=false
        log "Silent scan — score=0, previously clean — notification suppressed"
    fi

    # ── Verdict ───────────────────────────────────────────────────────────────
    echo ""
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYN}  VERDICT — Risk Score: $RISK_SCORE / 100${NC}"
    echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # _trust_from_notification fires an interactive notification with an
    # "Add to Trusted" button. If clicked, adds the network to the trusted list.
    # Respects should_notify — suppressed on silent scans.
    _trust_from_notification() {
        local title="$1" body="$2" urgency="${3:-normal}"
        "$should_notify" || return 0
        local action
        action=$(notify_interactive "$title" "$body" "$urgency")
        if [[ "$action" == "trust" && "$bssid" != "UNKNOWN" ]]; then
            add_to_trusted "$ssid" "$bssid" "${GATEWAY_MAC:-}"
            log "User trusted '$ssid' ($bssid) via notification (score=$RISK_SCORE)."
        fi
    }

    if (( RISK_SCORE == 0 )); then
        good "Network looks clean. No anomalies detected."
        if [[ "$bssid" != "UNKNOWN" ]]; then
            if [ -t 0 ]; then
                # Interactive (manual run): use terminal prompt.
                echo -e -n "\n${CYN}Add '$ssid' to trusted networks? [y/N] ${NC}"
                read -r response
                if [[ "$response" =~ ^[Yy]$ ]]; then
                    add_to_trusted "$ssid" "$bssid" "${GATEWAY_MAC:-}"
                    good "Added '$ssid' ($bssid) to trusted networks."
                    notify "Clean — Trusted" "Network '$ssid' passed all checks." normal
                else
                    notify "Clean" "Network '$ssid' passed all checks." normal
                fi
            else
                _trust_from_notification "Clean ✓" "Score 0 — Network '$ssid' passed all checks." normal
            fi
        else
            $should_notify && notify "Clean" "Network '$ssid' passed all checks." normal || true
        fi
    elif (( RISK_SCORE < 30 )); then
        warn "Low-risk anomalies found on '$ssid':"
        for r in "${RISK_REASONS[@]}"; do echo -e "  ${YEL}•${NC} $r"; done
        warn "Probably lazy IT. Avoid sending sensitive data without a VPN."
        _trust_from_notification "Low Risk" "Score $RISK_SCORE — $ssid — ${RISK_REASONS[*]}" normal
    elif (( RISK_SCORE < 60 )); then
        alert "Moderate risk on '$ssid':"
        for r in "${RISK_REASONS[@]}"; do echo -e "  ${RED}•${NC} $r"; done
        alert "Use a VPN. Do not log in to anything on this network."
        _trust_from_notification "Moderate Risk ⚠" "Score $RISK_SCORE — $ssid — ${RISK_REASONS[*]}" critical
    else
        alert "HIGH RISK — possible rogue AP / evil twin on '$ssid':"
        for r in "${RISK_REASONS[@]}"; do echo -e "  ${RED}•${NC} $r"; done
        alert "DISCONNECT IMMEDIATELY. Use mobile data."
        _trust_from_notification "HIGH RISK ✗" "Score $RISK_SCORE — $ssid — ${RISK_REASONS[*]}" critical
    fi

    echo ""
    log "=== Scan end: SSID=$ssid  score=$RISK_SCORE  reasons=${RISK_REASONS[*]:-none} ==="
}

main "$@"
