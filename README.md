# ============================================================================
# RouterOS 7 IPS v4.0
# Defensive Firewall / Lightweight IPS for MikroTik RouterOS 7
# IPv4 + IPv6 | Threat Levels | Wired Event Hook | Profiles | DDoS/SYN separation
# ============================================================================
#
# DESIGN GOALS (carried over from v3, all still true)
#  - RAW-first cheap blocking before connection tracking where possible
#  - Safe whitelist: trusted hosts do NOT bypass spoof/malformed-packet checks
#  - Separate SYN-flood detection from volumetric DDoS detection
#  - Profile-based thresholds generated at import time
#  - Threat levels L1..L5 with staged escalation
#  - IPv4 and IPv6 protection
#  - FastTrack kept optional and OFF by default for IPS mode
#  - No payload AV/DPI claim: use Suricata/Zeek/Wazuh/ClamAV for deep inspection
#
# CHANGELOG vs v3.0 (fixes real findings from review, not cosmetic)
#  [BUG FIX] IPS-SCAN / IPS6-SCAN never escalated past L2-SUSPICIOUS, and
#            neither RAW nor FILTER ever blocked on L1/L2 membership. Net
#            effect: a plain port scan (no malformed TCP flags) was logged
#            forever and NEVER blocked - only malformed-flag scans reached
#            L3 and got dropped. v4 adds the missing L2->L3 promotion rule
#            (same highest-stage-first pattern already used correctly in
#            the brute-force engine), so a sustained scan now escalates to
#            a real block within a few packets, same as every other engine.
#  [BUG FIX] IPS-EVENT / IPS6-EVENT chains were created but never jumped to
#            anywhere (dead code, despite "event engine" being a stated
#            design goal). v4 wires them as a real central hook: every RAW
#            L3/L4/L5 block now jumps through IPS-EVENT first. By default it
#            only runs a passthrough counter (visible in
#            `/ip firewall filter print stats`), and it's the ONE place to
#            add a custom action later (e.g. a script that sends a webhook/
#            Telegram alert) without touching every individual rule.
#  [ADDED]   Fragment guard is now a real gated, disabled-by-default rule
#            (ENABLE_FRAGMENT_GUARD) instead of just a comment - v3 dropped
#            it entirely with a text note; v4 makes it available but still
#            off by default since it can affect legacy fragmented UDP/VoIP.
#  [ADDED]   Threat-feed sync template restored (was dropped in v3), kept
#            explicitly manual/disabled since it depends on a feed URL and
#            format only you can vet.
#  [CLEANUP] Removed the placeholder add+remove trick used to "pre-create"
#            dynamic address-lists - RouterOS creates them automatically on
#            first use and can reference a not-yet-existing list name in a
#            condition without error, so the trick added complexity with no
#            functional benefit.
#  [CLEANUP] Removed a dead duplicate "forward established,related accept"
#            rule in the FastTrack section - the baseline in section 7
#            already terminates on that condition earlier, so the second
#            copy could never be reached.
#
# IMPORTANT
#  1) TEST IN SAFE MODE / MAINTENANCE WINDOW.
#  2) Have local console/MAC access before changing firewall remotely.
#  3) Add real trusted/admin IPs to IPS-EXEMPT (and MGMT-TRUSTED if you plan
#     to enable management lockdown) before enabling management rules.
#  4) Add WAN/LAN interfaces to the existing interface lists before import,
#     OR replace the placeholders below with your real interfaces.
#  5) This script is a security baseline. Existing firewall/NAT, VPN, IPv6
#     ND/DHCPv6 and service-specific rules must be reviewed together with it.
#  6) RouterOS firewall is connection-state/rate/pattern based. It is not a
#     substitute for payload-inspection IDS/IPS (Suricata/Zeek) or AV/EDR.
# ============================================================================
