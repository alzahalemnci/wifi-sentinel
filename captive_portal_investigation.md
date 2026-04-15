# Captive Portal SSL Investigation Cheatsheet

Use this when you hit a public WiFi captive portal with invalid or self-signed SSL certs.
Goal: determine if it's a lazy-but-legit network or a rogue evil-twin / MITM setup.

---

## 1. Inspect the Certificate

```bash
# Full cert details
openssl s_client -connect <captive-portal-ip>:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text

# Quick summary
openssl s_client -connect <captive-portal-ip>:443 </dev/null 2>&1 | grep -E "subject|issuer|notBefore|notAfter"
```

**Red flags:**
- Issuer = Subject → self-signed
- CN is a raw IP, `router.local`, or random string
- Expired or very short validity
- No Subject Alternative Names (SANs)

---

## 2. Identify the Gateway and Portal

```bash
ip route show          # find default gateway IP
arp -n                 # get gateway MAC address
curl -vk https://<gateway-ip>   # -k skips cert check, -v shows response headers
```

Headers often reveal the vendor (Palo Alto, Cisco, Aruba, Fortinet, etc.).
Legitimate enterprise portals usually identify themselves.

---

## 3. MAC Address OUI Lookup

```bash
ip neigh show    # or: arp -a
curl https://api.macvendors.com/<first-3-octets-of-mac>
```

A MAC registered to a cheap/unknown vendor while the SSID claims to be a major
airport/hotel chain is a strong signal of a rogue AP.

---

## 4. Passive Network Recon

```bash
# Ping sweep your subnet — don't probe other clients
nmap -sn 192.168.x.0/24

# Check services on the gateway only
nmap -sV <gateway-ip>
```

---

## 5. Check for DNS Hijacking

```bash
# See what DNS server was assigned
resolvectl status
# or: cat /etc/resolv.conf

# Compare results — if they differ, DNS is being intercepted
dig google.com @8.8.8.8     # direct to Google DNS
dig google.com               # through assigned DNS
```

---

## Red Flags vs. Green Flags

| Signal                          | Verdict              |
|---------------------------------|----------------------|
| Self-signed cert, unknown org   | Suspicious           |
| Cert issued to a raw IP         | Suspicious           |
| Gateway MAC = unknown OUI       | Suspicious           |
| DNS hijacking all queries       | Active MITM          |
| No HSTS headers                 | Weak but common      |
| Known vendor in response headers| Likely legit         |
| OpenDNS / Cloudflare upstream   | Likely legit         |
| Cert just expired / neglected   | Lazy IT, not evil    |

---

## If It Looks Rogue

- Do not log in to anything — credentials will be captured
- Do not use the network for anything sensitive
- Report to venue staff immediately
- Use mobile data or a VPN instead
- Report to FTC (US): reportfraud.ftc.gov or your national cybercrime authority

---

## Common Legit Explanation

Many enterprise captive portals (Palo Alto, Cisco ISE, Aruba ClearPass) ship with
a default self-signed cert that IT never bothers replacing since it "works."
Combined with a known vendor fingerprint and clean DNS — it's almost always just
neglected cert hygiene, not malice.
