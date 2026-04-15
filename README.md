# wifi-sentinel

Automatic captive portal and rogue AP detector for Linux. Runs on every WiFi connect, scores the network for suspicious behaviour, and fires a desktop notification if something looks off.

## What it checks

| Check | Risk points |
|---|---|
| Gateway MAC has no known OUI vendor | +20 |
| Captive portal with no retrievable certificate | +15 |
| Self-signed certificate | +30 |
| Certificate issued to a raw IP address | +25 |
| Expired certificate | +20 |
| DNS hijacking (local results differ from 8.8.8.8) | +50 |

**Verdict thresholds:**
- **0** — clean, all checks passed
- **1–29** — low risk, probably lazy IT, use a VPN for anything sensitive
- **30–59** — moderate risk, do not log in to anything
- **60+** — high risk, possible evil-twin / rogue AP, disconnect immediately

## Dependencies

| Tool | Package (Debian/Ubuntu) | Package (Fedora/RHEL) |
|---|---|---|
| `openssl` | `openssl` | `openssl` |
| `curl` | `curl` | `curl` |
| `dig` | `dnsutils` | `bind-utils` |
| `nmap` | `nmap` | `nmap` |
| `notify-send` | `libnotify-bin` | `libnotify` |
| `nmcli` | `network-manager` | `NetworkManager` |

Install everything at once:

```bash
# Debian / Ubuntu
sudo apt-get install -y openssl curl dnsutils nmap libnotify-bin

# Fedora / RHEL
sudo dnf install -y openssl curl bind-utils nmap libnotify
```

`nmcli` ships with NetworkManager, which is present on virtually all modern Linux desktops.

## Installation

```bash
git clone https://github.com/alzahalemnci/wifi-sentinel.git
cd wifi-sentinel
bash install.sh
```

`install.sh` will:
1. Install missing dependencies via `apt-get` or `dnf`
2. Make the scripts executable
3. Copy `dispatcher.sh` to `/etc/NetworkManager/dispatcher.d/99-wifi-sentinel` so the scan runs automatically on every WiFi connect
4. (Optional) Download the Wireshark OUI database for offline vendor lookups

### Manual run

```bash
bash wifi-sentinel.sh
```

## Configuration

**Trusted networks** — edit `trusted_networks.txt`, one SSID per line. The sentinel skips these entirely:

```
MyHomeWiFi
WorkNetwork
```

**Dispatcher path** — after cloning, open `dispatcher.sh` and update the two variables at the top to match your setup:

```bash
SENTINEL="/opt/wifi-sentinel/wifi-sentinel.sh"   # path to wifi-sentinel.sh
USER="your-username"                              # your Linux username
```

**Desktop notifications** — set `NOTIFY=false` at the top of `wifi-sentinel.sh` to disable them.

**OUI database** — for offline vendor lookups, run `install.sh` or download manually:

```bash
curl -o oui.txt https://www.wireshark.org/download/automated/data/manuf
```

`oui.txt` is gitignored — it's ~10 MB and user-generated.

## Log file

All scan results are written to `sentinel.log` in the project directory (also gitignored). Tail it live with:

```bash
tail -f sentinel.log
```

## Captive portal investigation

See [`captive_portal_investigation.md`](captive_portal_investigation.md) for a manual cheatsheet on inspecting suspicious portal certificates with `openssl` and `curl`.
