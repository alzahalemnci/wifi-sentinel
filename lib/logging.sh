#!/usr/bin/env bash
# lib/logging.sh — terminal colours, log helpers, desktop notifications, evidence dump
# Sourced by wifi-sentinel.sh. Expects LOG_FILE, NOTIFY, and EVIDENCE_DIR to be set.

# ANSI escape codes for terminal colours. NC = No Colour (reset).
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
NC='\033[0m'

# tee -a writes to stdout AND appends to the log file at the same time.
log()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }
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

# ── Evidence accumulator ──────────────────────────────────────────────────────
# Checks call evidence_add() for each scored finding. evidence_dump() writes
# everything to a timestamped human-readable report file when the score warrants it.

EVIDENCE_FINDINGS=()

# evidence_add TITLE EXPLANATION RAW_OUTPUT
# Appends one formatted finding block to EVIDENCE_FINDINGS[].
evidence_add() {
    local title="$1" explanation="$2" raw="$3"
    EVIDENCE_FINDINGS+=("$(printf -- '--- %s ---\nWhat this means:\n  %s\n\nEvidence:\n%s' \
        "$title" "$explanation" "$raw")")
}

# evidence_dump SSID BSSID SCORE
# Writes all accumulated findings to EVIDENCE_DIR/evidence_TIMESTAMP_SSID.txt.
# Skips silently if there are no findings or EVIDENCE_DIR is not writable.
evidence_dump() {
    local ssid="$1" bssid="$2" score="$3"
    [[ ${#EVIDENCE_FINDINGS[@]} -eq 0 ]] && return 0
    [[ -d "$EVIDENCE_DIR" ]] || { warn "Evidence dir '$EVIDENCE_DIR' not found — skipping report"; return 0; }

    local timestamp safe_ssid outfile
    timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    safe_ssid="${ssid//[^a-zA-Z0-9_-]/_}"
    outfile="$EVIDENCE_DIR/evidence_${timestamp}_${safe_ssid}.txt"

    {
        echo "=== WiFi Sentinel Evidence Report ==="
        echo "Time    : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Network : $ssid"
        echo "BSSID   : $bssid"
        echo "Score   : $score / 100"
        echo ""
        for finding in "${EVIDENCE_FINDINGS[@]}"; do
            echo "$finding"
            echo ""
        done
    } > "$outfile" 2>/dev/null || { warn "Could not write evidence report to $outfile"; return 0; }

    log "Evidence report written: $outfile"
    info "Evidence report saved: $outfile"
}

notify_interactive() {
    local title="$1" body="$2" urgency="${3:-normal}"
    $NOTIFY && command -v notify-send &>/dev/null || { echo ""; return; }
    # --wait blocks until the notification is dismissed or an action is clicked.
    # --action adds a button; notify-send prints the action ID ("trust") if clicked,
    # or an empty string if the notification is dismissed without clicking.
    notify-send --wait \
        -u "$urgency" \
        -i network-wireless \
        --action="trust=Add to Trusted" \
        "WiFi Sentinel: $title" "$body" 2>/dev/null || echo ""
}
