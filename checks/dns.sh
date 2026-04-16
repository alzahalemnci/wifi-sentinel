#!/usr/bin/env bash
# checks/dns.sh — DNS hijack detection
# Sourced by wifi-sentinel.sh. Modifies globals RISK_SCORE and RISK_REASONS.

# Public entry point — called by the main orchestrator.
check_dns() {
    info "Checking for DNS hijacking ..."

    # Try systemd-resolved first, fall back to /etc/resolv.conf.
    local assigned_dns
    assigned_dns=$(resolvectl status 2>/dev/null | grep 'DNS Servers' | awk '{print $3}' | head -1)
    [[ -z "$assigned_dns" ]] && \
        assigned_dns=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -1)
    info "Assigned DNS: ${assigned_dns:-unknown}"

    # NXDOMAIN test: query a random domain that is guaranteed not to exist.
    # A legitimate DNS returns no answer (NXDOMAIN); a hijacking DNS returns an IP
    # so it can redirect you to a search/ad page. This avoids false positives from
    # CDN load balancing, where the same domain legitimately resolves to different
    # IPs depending on which resolver you ask.
    local canary="wifi-sentinel-canary-$(date +%s).invalid"
    local hijack_result
    hijack_result=$(dig +short +time=3 "$canary" 2>/dev/null | grep -v '^;' || true)

    if [[ -n "$hijack_result" ]]; then
        # Got an IP back for a non-existent domain — local DNS is redirecting queries.
        alert "DNS HIJACKING DETECTED — local DNS is returning results for non-existent domains"
        RISK_SCORE=$((RISK_SCORE + 50))
        RISK_REASONS+=("DNS hijacking detected")
    else
        good "DNS is not being hijacked"
    fi
}
