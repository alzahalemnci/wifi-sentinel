#!/usr/bin/env bash
# checks/cert.sh — captive portal detection and TLS certificate analysis
# Sourced by wifi-sentinel.sh. Modifies globals RISK_SCORE and RISK_REASONS.

_detect_captive_portal() {
    # Google's generate_204 endpoint normally returns HTTP 204 (no content).
    # If a captive portal intercepts the request it returns a redirect instead.
    # -w '%{redirect_url}' prints that redirect URL; if there's no redirect it's empty.
    curl -sf --max-time 5 -o /dev/null -w '%{redirect_url}' \
        http://connectivitycheck.gstatic.com/generate_204 2>/dev/null || true
}

_fetch_cert() {
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

# Public entry point — called by the main orchestrator.
check_portal() {
    local portal_url
    portal_url=$(_detect_captive_portal)

    if [[ -z "$portal_url" ]]; then
        good "No captive portal detected."
        return
    fi

    info "Captive portal detected: $portal_url"

    # Parse just the hostname out of the URL (strip scheme and path).
    # awk splits on '/' to get the host:port part, cut drops any port number.
    local portal_host
    portal_host=$(echo "$portal_url" | awk -F/ '{print $3}' | cut -d: -f1)

    info "Checking TLS certificate for $portal_host ..."
    local cert_info
    cert_info=$(_fetch_cert "$portal_host")

    if [[ -z "$cert_info" ]]; then
        warn "Could not retrieve certificate from portal host."
        RISK_SCORE=$((RISK_SCORE + 15))
        RISK_REASONS+=("No cert retrievable from portal")
        return
    fi

    local subject issuer not_after
    subject=$(echo "$cert_info"  | grep subject  | sed 's/subject=//')
    issuer=$(echo "$cert_info"   | grep issuer   | sed 's/issuer=//')
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
        expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || \
            date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        if (( expiry_epoch > 0 && expiry_epoch < now_epoch )); then
            warn "Certificate is EXPIRED"
            RISK_SCORE=$((RISK_SCORE + 20))
            RISK_REASONS+=("Expired certificate")
        else
            good "Certificate is not expired"
        fi
    fi
}
