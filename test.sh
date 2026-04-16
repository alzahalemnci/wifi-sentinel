#!/usr/bin/env bash
# test.sh — simulate attack conditions to verify wifi-sentinel detects them
# Run from the project directory: bash test.sh
# Each test restores state on exit — safe to run on a live machine.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# NOTIFY=false prevents notify-send --wait from blocking tests waiting for a click.
# wifi-sentinel.sh respects this env var via ${NOTIFY:-true} so it won't override it.
export NOTIFY=false
SENTINEL="$SCRIPT_DIR/wifi-sentinel.sh"
TRUSTED="$SCRIPT_DIR/trusted_networks.txt"
TRUSTED_BAK="$SCRIPT_DIR/trusted_networks.txt.testbak"
RESOLV_BAK="/tmp/resolv.conf.testbak"
HISTORY_TEST="/tmp/sentinel_score_history_test.txt"
EVIDENCE_TEST="/tmp/sentinel_evidence_test"

RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
YEL='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GRN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYN}[INFO]${NC} $*"; }
skip() { echo -e "${YEL}[SKIP]${NC} $*"; }

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

run_test() {
    local name="$1"
    local fn="$2"
    TESTS_RUN=$(( TESTS_RUN + 1 ))
    echo ""
    echo -e "${CYN}── $name ──${NC}"
    if "$fn"; then
        TESTS_PASSED=$(( TESTS_PASSED + 1 ))
    else
        TESTS_FAILED=$(( TESTS_FAILED + 1 ))
    fi
}

# ── Cleanup trap ──────────────────────────────────────────────────────────────
cleanup() {
    # Restore trusted_networks.txt if we backed it up
    if [[ -f "$TRUSTED_BAK" ]]; then
        mv "$TRUSTED_BAK" "$TRUSTED"
    fi
    # Restore /etc/resolv.conf if we backed it up
    if [[ -f "$RESOLV_BAK" ]]; then
        sudo cp "$RESOLV_BAK" /etc/resolv.conf
        rm -f "$RESOLV_BAK"
    fi
    # Kill any dnsmasq we started
    if [[ -n "${DNSMASQ_PID:-}" ]]; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
    fi
    rm -f "$HISTORY_TEST"
    rm -rf "$EVIDENCE_TEST"
}
trap cleanup EXIT

# ── Test: trusted network skip ────────────────────────────────────────────────
test_trusted_skip() {
    local ssid bssid
    ssid=$(nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || echo "UNKNOWN")
    bssid=$(nmcli -f ACTIVE,BSSID dev wifi 2>/dev/null | awk '/^yes/ {print $2}' || echo "UNKNOWN")

    if [[ "$ssid" == "UNKNOWN" || "$bssid" == "UNKNOWN" ]]; then
        skip "Not connected to WiFi — cannot test trusted skip"
        TESTS_SKIPPED=$(( TESTS_SKIPPED + 1 ))
        TESTS_RUN=$(( TESTS_RUN - 1 ))
        return 0
    fi

    cp "$TRUSTED" "$TRUSTED_BAK"
    echo "$ssid|$bssid" >> "$TRUSTED"

    local output
    output=$(bash "$SENTINEL" </dev/null 2>&1)
    mv "$TRUSTED_BAK" "$TRUSTED"

    if echo "$output" | grep -q "trusted list. Skipping"; then
        pass "Trusted network correctly skipped full scan"
    else
        fail "Expected skip message not found"
        echo "$output"
        return 1
    fi
}

# ── Test: gateway MAC change alert ────────────────────────────────────────────
test_gateway_mac_change() {
    local ssid bssid
    ssid=$(nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || echo "UNKNOWN")
    bssid=$(nmcli -f ACTIVE,BSSID dev wifi 2>/dev/null | awk '/^yes/ {print $2}' || echo "UNKNOWN")

    if [[ "$ssid" == "UNKNOWN" || "$bssid" == "UNKNOWN" ]]; then
        skip "Not connected to WiFi — cannot test MAC change"
        TESTS_SKIPPED=$(( TESTS_SKIPPED + 1 ))
        TESTS_RUN=$(( TESTS_RUN - 1 ))
        return 0
    fi

    cp "$TRUSTED" "$TRUSTED_BAK"
    # Add entry with a deliberately wrong gateway MAC
    echo "$ssid|$bssid|00:11:22:33:44:55" >> "$TRUSTED"

    local output
    output=$(TRUSTED_NETWORKS="$TRUSTED" bash "$SENTINEL" </dev/null 2>&1)
    mv "$TRUSTED_BAK" "$TRUSTED"

    if echo "$output" | grep -q "Gateway MAC changed"; then
        pass "Gateway MAC change correctly detected"
    else
        fail "Expected MAC change alert not found"
        echo "$output"
        return 1
    fi
}

# ── Test: DNS hijacking detection ─────────────────────────────────────────────
test_dns_hijack() {
    # Mock dig using a bash function exported to the subprocess.
    # Exported bash functions are inherited by child bash processes via BASH_FUNC_*
    # environment variables — no real DNS server or root access needed.
    #
    # Simulated behaviour:
    #   Local resolver (no @)  → returns 1.2.3.4 for any query (hijacking)
    #   Public resolvers (@8.8.8.8 / @1.1.1.1) → return nothing (NXDOMAIN)
    dig() {
        local args="$*"
        if [[ "$args" == *"@8.8.8.8"* ]] || [[ "$args" == *"@1.1.1.1"* ]]; then
            echo ""
        else
            echo "1.2.3.4"
        fi
    }
    export -f dig

    local output
    output=$(bash "$SENTINEL" </dev/null 2>&1) || true
    unset -f dig

    if echo "$output" | grep -q "DNS HIJACKING DETECTED"; then
        pass "DNS hijacking correctly detected"
    else
        fail "Expected DNS hijacking alert not found"
        echo "$output"
        return 1
    fi
}

# ── Test: clean network scores 0 ─────────────────────────────────────────────
test_clean_scan() {
    # Mock nmap and dig to give deterministic results regardless of the real
    # network state: no suspicious ports, and a resolver that validates DNSSEC.
    nmap() { echo ""; }
    export -f nmap
    dig() {
        local args="$*"
        if [[ "$args" == *"+dnssec"* ]]; then
            echo ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 1"
        else
            command dig "$@"
        fi
    }
    export -f dig

    local output
    output=$(bash "$SENTINEL" 2>&1) || true
    unset -f nmap
    unset -f dig

    if echo "$output" | grep -q "score=0"; then
        pass "Clean network scores 0"
    elif echo "$output" | grep -q "score=15"; then
        # Multiple APs on a mesh network is expected low-risk
        pass "Clean network scores low (mesh/multiple APs expected)"
    else
        fail "Unexpected score on known-clean network"
        echo "$output"
        return 1
    fi
}

# ── Test: suspicious gateway port ────────────────────────────────────────────
test_gateway_port_scan() {
    # Mock nmap to report telnet (port 23) open on the gateway.
    # Exported bash functions are inherited by child bash processes via BASH_FUNC_*
    # so no real nmap scan or root access is needed.
    nmap() {
        echo "23/tcp open  telnet"
    }
    export -f nmap

    local output
    output=$(bash "$SENTINEL" 2>&1) || true
    unset -f nmap

    if echo "$output" | grep -q "Telnet"; then
        pass "Suspicious gateway port (telnet) correctly detected"
    else
        fail "Expected gateway port alert not found"
        echo "$output"
        return 1
    fi
}

# ── Test: HTTPS downgrade detection ──────────────────────────────────────────
test_https_downgrade() {
    # Mock curl to simulate a MITM serving 200 OK over plain HTTP instead of
    # redirecting to HTTPS. Only intercept the HEAD request to google.com —
    # pass everything else through to avoid breaking other checks.
    curl() {
        local args="$*"
        if [[ "$args" == *"google.com"* ]]; then
            echo "HTTP/1.1 200 OK"
        else
            command curl "$@"
        fi
    }
    export -f curl

    local output
    output=$(bash "$SENTINEL" 2>&1) || true
    unset -f curl

    if echo "$output" | grep -q "HTTPS DOWNGRADE DETECTED"; then
        pass "HTTPS downgrade correctly detected"
    else
        fail "Expected HTTPS downgrade alert not found"
        echo "$output"
        return 1
    fi
}

# ── Test: DNSSEC not validated ────────────────────────────────────────────────
test_dnssec() {
    # Mock dig to return a response without the AD flag, simulating a resolver
    # that does not perform DNSSEC validation (or a rogue resolver stripping it).
    # Only intercept the DNSSEC query — pass canary/hijack queries through so
    # check_dns still runs cleanly.
    dig() {
        local args="$*"
        if [[ "$args" == *"+dnssec"* ]]; then
            echo ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1"
        else
            command dig "$@"
        fi
    }
    export -f dig

    local output
    output=$(bash "$SENTINEL" 2>&1) || true
    unset -f dig

    if echo "$output" | grep -q "DNSSEC not validated"; then
        pass "DNSSEC missing AD flag correctly detected"
    else
        fail "Expected DNSSEC warning not found"
        echo "$output"
        return 1
    fi
}

# ── Test: score history escalation ───────────────────────────────────────────
test_score_history() {
    local ssid bssid
    ssid=$(nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || echo "UNKNOWN")
    bssid=$(nmcli -f ACTIVE,BSSID dev wifi 2>/dev/null | awk '/^yes/ {print $2}' || echo "UNKNOWN")

    if [[ "$ssid" == "UNKNOWN" || "$bssid" == "UNKNOWN" ]]; then
        skip "Not connected to WiFi — cannot test score history"
        TESTS_SKIPPED=$(( TESTS_SKIPPED + 1 ))
        TESTS_RUN=$(( TESTS_RUN - 1 ))
        return 0
    fi

    # Seed history with a previous clean score of 0 for the current network.
    echo "$ssid|$bssid|$(date +%s)|0" > "$HISTORY_TEST"

    # Mock nmap to produce a finding (telnet open) so the current scan scores > 0.
    nmap() { echo "23/tcp open  telnet"; }
    export -f nmap

    local output
    output=$(SCORE_HISTORY="$HISTORY_TEST" bash "$SENTINEL" 2>&1) || true
    unset -f nmap

    if echo "$output" | grep -q "Previously clean"; then
        pass "Score history escalation correctly triggered"
    else
        fail "Expected score history escalation not found"
        echo "$output"
        return 1
    fi
}

# ── Test: silent scan (score unchanged, no notification) ──────────────────────
test_silent_scan() {
    local ssid bssid
    ssid=$(nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || echo "UNKNOWN")
    bssid=$(nmcli -f ACTIVE,BSSID dev wifi 2>/dev/null | awk '/^yes/ {print $2}' || echo "UNKNOWN")

    if [[ "$ssid" == "UNKNOWN" || "$bssid" == "UNKNOWN" ]]; then
        skip "Not connected to WiFi — cannot test silent scan"
        TESTS_SKIPPED=$(( TESTS_SKIPPED + 1 ))
        TESTS_RUN=$(( TESTS_RUN - 1 ))
        return 0
    fi

    # Seed history with score=0. Mock all checks clean so current scan also scores 0
    # — should trigger silent suppression.
    echo "$ssid|$bssid|$(date +%s)|0" > "$HISTORY_TEST"

    nmap() { echo ""; }
    export -f nmap
    dig() {
        [[ "$*" == *"+dnssec"* ]] && echo ";; flags: qr rd ra ad;" || command dig "$@"
    }
    export -f dig
    # Return a single AP for the evil twin check so the mesh doesn't score +15.
    # Pass all other nmcli calls through unchanged.
    export MOCK_SSID="$ssid" MOCK_BSSID="$bssid"
    nmcli() {
        [[ "$*" == *"SSID,BSSID"* ]] && echo "$MOCK_SSID  $MOCK_BSSID" || command nmcli "$@"
    }
    export -f nmcli

    local output
    output=$(SCORE_HISTORY="$HISTORY_TEST" bash "$SENTINEL" 2>&1) || true
    unset -f nmap
    unset -f dig
    unset -f nmcli

    if echo "$output" | grep -q "notification suppressed"; then
        pass "Silent scan correctly suppressed notification on unchanged score"
    else
        fail "Expected silent scan suppression not found"
        echo "$output"
        return 1
    fi
}

# ── Test: silent scan does not suppress when score > 0 ───────────────────────
# Covers both: score increased from 0, AND score unchanged but still > 0
# (e.g. a coffee shop that always scores 30 — should always notify until trusted)
test_silent_scan_notifies_on_risk() {
    local ssid bssid
    ssid=$(nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes' | cut -d: -f2 || echo "UNKNOWN")
    bssid=$(nmcli -f ACTIVE,BSSID dev wifi 2>/dev/null | awk '/^yes/ {print $2}' || echo "UNKNOWN")

    if [[ "$ssid" == "UNKNOWN" || "$bssid" == "UNKNOWN" ]]; then
        skip "Not connected to WiFi — cannot test silent scan with risk"
        TESTS_SKIPPED=$(( TESTS_SKIPPED + 1 ))
        TESTS_RUN=$(( TESTS_RUN - 1 ))
        return 0
    fi

    # Seed history with score=30 — same as what the mock will produce.
    # Score is unchanged but > 0, so notification must still fire.
    echo "$ssid|$bssid|$(date +%s)|30" > "$HISTORY_TEST"

    nmap() { echo "23/tcp open  telnet"; }
    export -f nmap

    local output
    output=$(SCORE_HISTORY="$HISTORY_TEST" bash "$SENTINEL" 2>&1) || true
    unset -f nmap

    if echo "$output" | grep -q "notification suppressed"; then
        fail "Silent scan incorrectly suppressed notification on risk score > 0"
        echo "$output"
        return 1
    else
        pass "Silent scan correctly notifies when score > 0 (even if unchanged)"
    fi
}

# ── Test: evidence dump written on high-risk scan ────────────────────────────
test_evidence_dump() {
    mkdir -p "$EVIDENCE_TEST"

    # Mock dig to simulate DNS hijacking — confirmed finding, score +50 → triggers dump.
    dig() {
        local args="$*"
        if [[ "$args" == *"@8.8.8.8"* ]] || [[ "$args" == *"@1.1.1.1"* ]]; then
            echo ""
        elif [[ "$args" == *"+dnssec"* ]]; then
            echo ";; flags: qr rd ra ad;"
        else
            echo "1.2.3.4"
        fi
    }
    export -f dig

    local output
    output=$(EVIDENCE_DIR="$EVIDENCE_TEST" bash "$SENTINEL" 2>&1) || true
    unset -f dig

    local report
    report=$(ls "$EVIDENCE_TEST"/evidence_*.txt 2>/dev/null | head -1)

    if [[ -z "$report" ]]; then
        fail "Evidence report file not created"
        echo "$output"
        return 1
    fi

    if grep -q "DNS Hijacking" "$report"; then
        pass "Evidence report created with correct finding"
    else
        fail "Evidence report missing expected finding"
        cat "$report"
        return 1
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYN}  wifi-sentinel test suite${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

run_test "Clean scan baseline"               test_clean_scan
run_test "Trusted network skip"              test_trusted_skip
run_test "Gateway MAC change alert"          test_gateway_mac_change
run_test "DNS hijacking detection"           test_dns_hijack
run_test "Gateway suspicious port scan"      test_gateway_port_scan
run_test "HTTPS downgrade detection"         test_https_downgrade
run_test "DNSSEC validation"                 test_dnssec
run_test "Score history escalation"          test_score_history
run_test "Silent scan (score 0, no change)"  test_silent_scan
run_test "Silent scan notifies on risk > 0"  test_silent_scan_notifies_on_risk
run_test "Evidence dump on high-risk scan"   test_evidence_dump

echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Results: ${GRN}$TESTS_PASSED passed${NC}  ${RED}$TESTS_FAILED failed${NC}  ${YEL}$TESTS_SKIPPED skipped${NC}  (${TESTS_RUN} run)"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

(( TESTS_FAILED == 0 ))
