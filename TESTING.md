# Testing Guide

## Running the automated tests

```bash
bash test.sh
```

Tests restore all state on exit (trusted_networks.txt, resolv.conf, background processes) so they are safe to run on a live machine.

---

## What is covered

| Check | How simulated | Automated |
|---|---|---|
| Clean scan baseline | Current network (nmap mocked to return no ports) | Yes |
| Trusted network skip | Inject fake entry into trusted_networks.txt | Yes |
| Gateway MAC change | Inject wrong MAC into trusted_networks.txt | Yes |
| DNS hijacking | Bash function mock via `export -f dig` | Yes |
| Gateway port fingerprint | Bash function mock via `export -f nmap` returning telnet | Yes |
| HTTPS downgrade detection | Bash function mock via `export -f curl` returning 200 OK | Yes |
| DNSSEC validation | Bash function mock via `export -f dig` returning response without AD flag | Yes |
| Score history escalation | Seed history file with score=0, mock nmap to produce a finding, verify escalation warning | Yes |

---

## Manual tests (testing debt)

These require physical setup and cannot be automated yet.

### Evil twin detection
**What to do:** Create a mobile hotspot on a second device with the exact same SSID as your current WiFi. Run the script while connected to the real network.  
**Expected result:** `[WARN] Multiple APs (2) are broadcasting SSID '...'` and score +15.  
**Debt:** No way to spin up a fake AP programmatically without `hostapd` and a second wireless interface.

### TLS interception (certificate pinning check)
**What to do:**
```bash
pip install mitmproxy
mitmproxy --mode transparent --listen-port 8080 &
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
bash wifi-sentinel.sh
# Cleanup:
sudo iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
```
**Expected result:** `[ALERT] TLS INTERCEPTION DETECTED` and score +60.  
**Debt:** Requires `mitmproxy` and iptables root access — can be scripted but involves more invasive system changes than the other tests.

### Captive portal detection + cert checks
**What to do:**
```bash
# Serve a redirect on port 8080
python3 -m http.server 8080 &
sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
bash wifi-sentinel.sh
# Cleanup:
sudo iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
```
**Expected result:** `[INFO] Captive portal detected`.  
**Debt:** The portal cert checks (self-signed, expired, raw IP) need a locally served HTTPS endpoint with a bad cert to fully exercise — not yet scripted.

### Unknown MAC vendor
**What to do:** No practical way to simulate without a second device with a spoofed MAC address acting as a gateway.  
**Debt:** Would require `macchanger` on a second interface or a VM configured as a gateway. Not yet scripted.

---

## Policy

Every new check added to the codebase must have a corresponding entry in this file — either a passing automated test or a documented manual procedure in the debt section with a note on what would be needed to automate it.
