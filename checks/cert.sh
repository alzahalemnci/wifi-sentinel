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

# Public entry point — checks for TLS interception by validating google.com's
# certificate against the system CA bundle. A valid cert means no one is
# intercepting TLS. A failed validation means a proxy is presenting its own cert,
# which won't be trusted by the OS unless the attacker installed their CA — a
# strong indicator of a MITM attack on public/home WiFi.
check_tls_pinning() {
    info "Checking for TLS interception ..."

    local result verify_code
    result=$(echo | timeout 10 openssl s_client \
        -connect google.com:443 \
        -servername google.com \
        -verify 5 2>&1 || true)
    verify_code=$(echo "$result" | grep "Verify return code" | awk '{print $4}')

    case "$verify_code" in
        0)
            good "TLS certificate for google.com validates against system CA bundle"
            ;;
        "")
            warn "TLS pinning check skipped — could not reach google.com (no internet yet?)"
            ;;
        *)
            local reason
            reason=$(echo "$result" | grep "Verify return code" | grep -oP '\(\K[^)]+' || true)
            alert "TLS INTERCEPTION DETECTED — google.com cert fails CA validation: ${reason:-code $verify_code}"
            RISK_SCORE=$((RISK_SCORE + 60))
            RISK_REASONS+=("TLS interception detected — certificate fails CA validation")
            evidence_add "TLS Interception Detected" \
                "A connection to google.com failed certificate validation against your system's trusted CA store. Someone is intercepting your HTTPS traffic and presenting their own certificate. Your encrypted traffic is being read and possibly modified." \
                "  Verify return code : $verify_code\n  Reason            : ${reason:-unknown}"
            ;;
    esac
}

# Public entry point — checks whether plain HTTP requests to a known HTTPS site
# are served unencrypted instead of being redirected to HTTPS.
# A legitimate network returns HTTP 301/302 → https://. A MITM stripping TLS
# intercepts the connection and serves a 200 directly over HTTP so it can read
# and modify traffic before re-encrypting it toward the real server.
check_https_downgrade() {
    info "Checking for HTTPS downgrade attack ..."

    if ! command -v curl &>/dev/null; then
        warn "curl not found — skipping HTTPS downgrade check"
        return
    fi

    # -s silent, -I head-only, -L do NOT follow redirects (we want the raw response)
    # --max-time 5 prevents hanging on a captive portal that never responds
    local http_code
    http_code=$(curl -sI --max-time 5 --no-location http://google.com 2>/dev/null \
        | grep -i "^HTTP/" | awk '{print $2}' | head -1 || true)

    case "$http_code" in
        301|302|307|308)
            good "HTTP → HTTPS redirect in place (status $http_code) — no downgrade detected"
            ;;
        200)
            alert "HTTPS DOWNGRADE DETECTED — http://google.com served 200 OK without redirecting to HTTPS"
            RISK_SCORE=$((RISK_SCORE + 40))
            RISK_REASONS+=("HTTPS downgrade — HTTP request served without TLS redirect")
            evidence_add "HTTPS Downgrade Attack" \
                "A plain HTTP request to google.com returned 200 OK instead of a redirect to HTTPS. An attacker is stripping TLS — they intercept your HTTP request before it can upgrade to HTTPS, allowing them to read and modify all traffic in plaintext." \
                "  curl -sI http://google.com → HTTP/1.1 200 OK (expected 301 Moved Permanently)"
            ;;
        "")
            warn "HTTPS downgrade check skipped — could not reach google.com"
            ;;
        *)
            warn "HTTPS downgrade check — unexpected status code: $http_code"
            ;;
    esac
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
