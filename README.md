# RouterOS 7 IPS v4.0

**Defensive Firewall / Lightweight IPS for MikroTik RouterOS 7**

![RouterOS](https://img.shields.io/badge/RouterOS-7.x-blue)
![IPv4](https://img.shields.io/badge/IP-v4%20%2B%20v6-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Status](https://img.shields.io/badge/status-baseline-orange)

> IPv4 + IPv6 · Threat Levels · Wired Event Hook · Profiles · DDoS/SYN separation

---

## 📖 Overview

A defensive firewall / lightweight IPS baseline for **MikroTik RouterOS 7**.  
Designed for cheap, RAW-first blocking, staged escalation, and profile-driven thresholds — **not** a payload-inspection IDS/IPS.

> ⚠️ For deep inspection (AV/DPI) use **Suricata**, **Zeek**, **Wazuh**, or **ClamAV** alongside this baseline.

---

## 🎯 Design Goals

Carried over from v3 — all still true:

- **RAW-first** cheap blocking before connection tracking where possible
- **Safe whitelist:** trusted hosts do **NOT** bypass spoof/malformed-packet checks
- Separate **SYN-flood detection** from **volumetric DDoS detection**
- **Profile-based thresholds** generated at import time
- **Threat levels L1..L5** with staged escalation
- **IPv4 and IPv6** protection
- **FastTrack** kept optional and **OFF by default** for IPS mode
- **No payload AV/DPI claim** — use Suricata/Zeek/Wazuh/ClamAV for deep inspection

---

## 🆕 Changelog vs v3.0

Fixes based on real findings from review, not cosmetics.

### 🐛 Bug Fixes

| Tag | Description |
|---|---|
| `BUG FIX` | **IPS-SCAN / IPS6-SCAN** never escalated past `L2-SUSPICIOUS`, and neither RAW nor FILTER ever blocked on L1/L2 membership. Net effect: a plain port scan (no malformed TCP flags) was logged forever and **never blocked** — only malformed-flag scans reached L3 and got dropped. **v4 adds the missing L2→L3 promotion rule** (same highest-stage-first pattern already used correctly in the brute-force engine), so a sustained scan now escalates to a real block within a few packets. |
| `BUG FIX` | **IPS-EVENT / IPS6-EVENT** chains were created but never jumped to (dead code, despite "event engine" being a stated design goal). **v4 wires them as a real central hook:** every RAW L3/L4/L5 block now jumps through `IPS-EVENT` first. By default it only runs a passthrough counter (visible in `/ip firewall filter print stats`), and it's the **one place** to add a custom action later (e.g. a webhook/Telegram alert script) without touching every individual rule. |

### ➕ Added

- **Fragment guard** is now a real gated, disabled-by-default rule (`ENABLE_FRAGMENT_GUARD`) instead of just a comment — v3 dropped it entirely with a text note. v4 makes it available but still **off by default** since it can affect legacy fragmented UDP/VoIP.
- **Threat-feed sync template** restored (was dropped in v3), kept explicitly **manual/disabled** since it depends on a feed URL and format only you can vet.

### 🧹 Cleanup

- Removed the placeholder add+remove trick used to "pre-create" dynamic address-lists. RouterOS creates them automatically on first use and can reference a not-yet-existing list name in a condition without error — the trick added complexity with no functional benefit.
- Removed a dead duplicate `forward established,related accept` rule in the FastTrack section — the baseline in Section 7 already terminates on that condition earlier, so the second copy could never be reached.

---

## ⚠️ Important — Read Before Deploying

1. **TEST IN SAFE MODE / MAINTENANCE WINDOW.**
2. Have **local console / MAC access** before changing firewall remotely.
3. Add real trusted/admin IPs to `IPS-EXEMPT` (and `MGMT-TRUSTED` if you plan to enable management lockdown) **before** enabling management rules.
4. Add WAN/LAN interfaces to the existing interface lists **before import**, OR replace the placeholders with your real interfaces.
5. This script is a **security baseline**. Existing firewall/NAT, VPN, IPv6 ND/DHCPv6, and service-specific rules must be reviewed together with it.
6. RouterOS firewall is **connection-state / rate / pattern based**. It is **not** a substitute for payload-inspection IDS/IPS (Suricata/Zeek) or AV/EDR.

---

## 🚀 Quick Start

```rsc
# 1. Open a safe-mode session
/system safe-mode

# 2. Add your trusted IPs to the exemption list
/ip firewall address-list add list=IPS-EXEMPT address=<YOUR-ADMIN-IP> comment="admin"

# 3. Add your interfaces to the WAN / LAN lists
/interface list member add list=WAN interface=<YOUR-WAN>
/interface list member add list=LAN interface=<YOUR-LAN>

# 4. Import the script
/import file-name=ips-v4.rsc

# 5. Verify counters
/ip firewall filter print stats
/ipv6 firewall filter print stats
```

---

## 🧩 Features at a Glance

| Feature | Status |
|---|---|
| RAW-first blocking (IPv4 + IPv6) | ✅ |
| Threat levels L1–L5 | ✅ |
| Profile-based thresholds | ✅ |
| SYN-flood vs DDoS separation | ✅ |
| Central event hook (`IPS-EVENT`) | ✅ |
| Fragment guard (opt-in) | ⚙️ `ENABLE_FRAGMENT_GUARD` |
| Threat-feed sync (manual) | ⚙️ Disabled by default |
| FastTrack | ⚙️ Off by default |
| Payload inspection / AV | ❌ Use external tools |

---

## 🛡️ Threat Levels

| Level | Meaning | Typical Action |
|---|---|---|
| **L1** | Info / first sighting | Log |
| **L2** | Suspicious | Log + counter |
| **L3** | Confirmed hostile | Drop via RAW + jump to `IPS-EVENT` |
| **L4** | Persistent attacker | Drop + address-list |
| **L5** | Severe / ongoing | Drop + escalate (long TTL) |

---

## 🔌 Extending the Event Hook

`IPS-EVENT` / `IPS6-EVENT` chains are the **single integration point** for custom reactions. Example: send a Telegram alert on any L3+ block without editing individual rules.

```rsc
/ip firewall filter
add chain=IPS-EVENT action=log log-prefix="IPS-EVENT:" comment="Custom hook"
# or a script call:
# add chain=IPS-EVENT action=script script=":log info \"blocked\"" ...
```

---

## 📄 License

MIT — see `LICENSE` for details.

---

## 🙏 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your branch (`git checkout -b feature/my-fix`)
3. Commit your changes
4. Push and open a PR

---

## ⭐ Support

If this project helped you, consider starring the repo ⭐ and sharing it with others.
