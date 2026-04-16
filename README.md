# wifi-sentinel

Automatic WiFi security scanner for Linux. Runs on every WiFi connect, scores the network for suspicious behaviour, and fires a desktop notification only when something changes or gets worse.

## What it checks

| Check | Risk points |
|---|---|
| Gateway MAC has no known OUI vendor | +20 |
| Suspicious port open on gateway (telnet, SOCKS, VNC, RDP, C2 ports…) | +10–30 |
| Multiple APs broadcasting the same SSID (possible evil twin) | +15 |
| TLS interception — google.com cert fails CA validation | +60 |
| HTTPS downgrade — HTTP request served without redirect to HTTPS | +40 |
| Captive portal with no retrievable certificate | +15 |
| Self-signed certificate on captive portal | +30 |
| Certificate issued to a raw IP address | +25 |
| Expired certificate | +20 |
| DNS hijacking — local resolver returns results for non-existent domains | +50 |
| DNSSEC not validated by local resolver | +20 |
| Previously clean network now shows anomalies | +20 |

**Verdict thresholds:**
- **0** — clean, all checks passed
- **1–29** — low risk, probably lazy IT, use a VPN for anything sensitive
- **30–59** — moderate risk, do not log in to anything
- **60+** — high risk, possible evil-twin / rogue AP, disconnect immediately

## Smart notification behaviour

wifi-sentinel tracks scan scores in `score_history.txt`. When running automatically via the NetworkManager dispatcher:

- **First time on a network** — full notification regardless of score
- **Score unchanged or lower since last visit** — silent scan, result logged but no notification
- **Score increased since last visit** — notification fires
- **In trusted list** — scan skipped entirely (use this for networks you've accepted as-is)

When run manually from a terminal, full output always prints regardless of history.

## Dependencies

| Tool | Package (Debian/Ubuntu) | Package (Fedora/RHEL) |
|---|---|---|
| `openssl` | `openssl` | `openssl` |
| `curl` | `curl` | `curl` |
| `dig` | `dnsutils` | `bind-utils` |
| `nmap` | `nmap` | `nmap` |
| `notify-send` | `libnotify-bin` | `libnotify` |
| `nmcli` | `network-manager` | `NetworkManager` |

`nmcli` ships with NetworkManager, which is present on virtually all modern Linux desktops.

## Installation

```bash
git clone https://github.com/alzahalemnci/wifi-sentinel.git
cd wifi-sentinel
sudo bash install.sh
```

`install.sh` will:
1. Install missing dependencies via `apt-get` or `dnf`
2. Copy the project files to `/opt/wifi-sentinel/`
3. Install the NetworkManager dispatcher to `/etc/NetworkManager/dispatcher.d/99-wifi-sentinel` so the scan runs automatically on every WiFi connect
4. (Optional) Download the Wireshark OUI database for offline vendor lookups

### Updating

Pull the latest changes and re-run `install.sh` — it overwrites the installed files in place:

```bash
cd wifi-sentinel
git pull
sudo bash install.sh
```

### Manual run

```bash
bash wifi-sentinel.sh
```

## Configuration

Edit `/opt/wifi-sentinel/sentinel.conf`:

```bash
# Send desktop notifications (true/false)
NOTIFY=${NOTIFY:-true}
```

**Trusted networks** — edit `/opt/wifi-sentinel/trusted_networks.txt`. The sentinel skips these entirely, suppressing all alerts even if something changes:

```
MyHomeWiFi
WorkNetwork
MyHomeWiFi|AA:BB:CC:DD:EE:FF|11:22:33:44:55:66
```

Entries are added automatically when you click **Add to Trusted** on a notification, or you can add them manually in `SSID|BSSID|GATEWAY_MAC` format.

**OUI database** — `install.sh` downloads this automatically. To refresh it manually:

```bash
sudo curl -o /opt/wifi-sentinel/oui.txt https://www.wireshark.org/download/automated/data/manuf
```

## Log files

All scan results are written to `/opt/wifi-sentinel/sentinel.log`. Score history is in `score_history.txt`. Tail the log live with:

```bash
tail -f /opt/wifi-sentinel/sentinel.log
```

When running manually from the clone directory (before install), both files go to that directory instead.

## Testing

```bash
bash test.sh
```

Runs 10 automated tests covering all major checks. Safe to run on a live machine — all state is restored on exit. See [`TESTING.md`](TESTING.md) for details and manual testing procedures.
