#!/usr/bin/env bash
# checks/dns.sh — DNS hijack detection and DNSSEC validation
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
    # so it can redirect you to a search/ad page.
    local canary="wifi-sentinel-canary-$(date +%s).invalid"
    local local_result
    local_result=$(dig +short +time=3 "$canary" 2>/dev/null | grep -v '^;' || true)

    if [[ -z "$local_result" ]]; then
        good "DNS is not being hijacked"
        return
    fi

    # Local DNS returned something for a non-existent domain.
    # Cross-check against two independent public resolvers to rule out the
    # (extremely unlikely) case that someone actually registered our canary domain.
    local google_result cf_result
    google_result=$(dig +short +time=3 "$canary" @8.8.8.8  2>/dev/null | grep -v '^;' || true)
    cf_result=$(dig +short     +time=3 "$canary" @1.1.1.1  2>/dev/null | grep -v '^;' || true)

    if [[ -z "$google_result" && -z "$cf_result" ]]; then
        # Public resolvers return NXDOMAIN, but local doesn't — confirmed hijack.
        alert "DNS HIJACKING DETECTED — local DNS returns results for non-existent domains"
        RISK_SCORE=$((RISK_SCORE + 50))
        RISK_REASONS+=("DNS hijacking detected")
    else
        # Even public resolvers returned something — canary domain may have been registered.
        # Inconclusive; log it but don't score.
        warn "Local DNS returned a result for canary domain, but public resolvers did too — inconclusive"
        info "  Local: $local_result  |  8.8.8.8: $google_result  |  1.1.1.1: $cf_result"
    fi
}

# Public entry point — checks whether the local resolver performs DNSSEC validation.
# DNSSEC-aware resolvers set the AD (Authenticated Data) flag when a response has
# been cryptographically verified against the DNS chain of trust. A rogue DNS server
# cannot forge valid DNSSEC signatures, so it strips the AD flag — its absence is
# weak but meaningful signal. Scored low (+20) because many legitimate resolvers
# (including some ISPs and home routers) simply don't do DNSSEC validation.
check_dnssec() {
    info "Checking DNSSEC validation ..."

    if ! command -v dig &>/dev/null; then
        warn "dig not found — skipping DNSSEC check"
        return
    fi

    # cloudflare.com is reliably DNSSEC-signed and fast to resolve.
    # +dnssec requests the resolver include RRSIG records; the 'ad' flag in the
    # response header means the resolver itself validated the signatures.
    local response
    response=$(dig +dnssec +time=3 cloudflare.com 2>/dev/null || true)

    if [[ -z "$response" ]]; then
        warn "DNSSEC check skipped — could not reach resolver"
        return
    fi

    if echo "$response" | grep -q "flags:.*\bad\b"; then
        good "DNSSEC validated (AD flag set) — resolver is verifying signatures"
    else
        warn "DNSSEC not validated — resolver did not set AD flag"
        info "  This may indicate a rogue resolver stripping DNSSEC, or simply a resolver that does not validate."
        RISK_SCORE=$((RISK_SCORE + 20))
        RISK_REASONS+=("DNSSEC not validated by local resolver")
    fi
}
