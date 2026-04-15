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

`nmcli` ships with NetworkManager, which is present on virtually all modern Linux desktops.

## Installation

```bash
git clone https://github.com/alzahalemnci/wifi-sentinel.git
cd wifi-sentinel
bash install.sh
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

**Trusted networks** — edit `/opt/wifi-sentinel/trusted_networks.txt`, one SSID per line. The sentinel skips these entirely:

```
MyHomeWiFi
WorkNetwork
```

**Desktop notifications** — set `NOTIFY=false` at the top of `wifi-sentinel.sh` to disable them.

**OUI database** — `install.sh` downloads this automatically. To refresh it manually after install:

```bash
sudo curl -o /opt/wifi-sentinel/oui.txt https://www.wireshark.org/download/automated/data/manuf
```

`oui.txt` is gitignored — it's ~10 MB and user-generated.

## Log file

All scan results are written to `/opt/wifi-sentinel/sentinel.log`. Tail it live with:

```bash
tail -f /opt/wifi-sentinel/sentinel.log
```

When running manually from the clone directory (before install), logs go to `sentinel.log` in that directory instead.

## Captive portal investigation

See [`captive_portal_investigation.md`](captive_portal_investigation.md) for a manual cheatsheet on inspecting suspicious portal certificates with `openssl` and `curl`.
