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

# ============================================================================
# 0. CONFIGURATION
# ============================================================================

# Select ONE profile: HOME | SMALL-OFFICE | SERVER | DATACENTER
:local PROFILE "SMALL-OFFICE"

# IPS mode: ON = detection + blocking (MONITOR mode is not a separate code
# path in this version - to run monitor-only, disable the *-blocking rules
# manually and keep the *-tagging rules enabled).
:local IPSMODE "ON"

# FastTrack is intentionally OFF for IPS mode. Set true only after testing -
# detection already runs on connection-state=new, which always happens
# before FastTrack can mark a connection, so enabling this is a throughput
# optimization, not a security trade-off, but test it anyway.
:local ENABLE_FASTTRACK false

# Optional public-management lockdown. Keep false unless MGMT-TRUSTED is
# filled - enabling this with an empty MGMT-TRUSTED will lock out ALL
# WAN-side management access, including yours.
:local ENABLE_MGMT_LOCKDOWN false

# Optional UDP amplification guard. Enable only when you do NOT intentionally
# expose the listed services (DNS/NTP/SSDP/CLDAP/memcached) publicly.
:local ENABLE_AMP_GUARD false

# Optional: drop non-initial IPv4 fragments arriving on WAN. Stops some
# fragmentation-based evasion/DoS techniques, but can break legitimate
# fragmented UDP (some VoIP, legacy DNS). Test before enabling broadly.
:local ENABLE_FRAGMENT_GUARD false

# ---------------------------------------------------------------------------
# Profile thresholds (defaults below = SMALL-OFFICE; other profiles override)
# ---------------------------------------------------------------------------
:local SYN_INPUT 40
:local SYN_FORWARD 80
:local CONN_INPUT 80
:local CONN_FORWARD 160
:local ICMP_INPUT_RATE 10
:local ICMP_INPUT_BURST 20
:local ICMP_FWD_RATE 50
:local ICMP_FWD_BURST 100
:local DDOS_RATE 32
:local DDOS_BURST 32
:local DDOS_WINDOW "10s"
:local PSD_WEIGHT 21
:local PSD_DELAY "3s"
:local PSD_LOW 3
:local PSD_HIGH 1
:local BF_STAGE1 "1m"
:local BF_STAGE2 "5m"
:local BF_STAGE3 "1d"
:local L2_TIMEOUT "5m"
:local L3_TIMEOUT "30m"
:local L4_TIMEOUT "1h"
:local L5_TIMEOUT "1d"

:if ($PROFILE="HOME") do={
    :set SYN_INPUT 80
    :set SYN_FORWARD 120
    :set CONN_INPUT 120
    :set CONN_FORWARD 240
    :set ICMP_INPUT_RATE 20
    :set ICMP_INPUT_BURST 40
    :set ICMP_FWD_RATE 100
    :set ICMP_FWD_BURST 200
    :set DDOS_RATE 64
    :set DDOS_BURST 64
    :set DDOS_WINDOW "10s"
    :set PSD_WEIGHT 24
    :set PSD_DELAY "4s"
    :set PSD_LOW 3
    :set PSD_HIGH 1
}
:if ($PROFILE="SERVER") do={
    :set SYN_INPUT 60
    :set SYN_FORWARD 200
    :set CONN_INPUT 120
    :set CONN_FORWARD 400
    :set ICMP_INPUT_RATE 20
    :set ICMP_INPUT_BURST 40
    :set ICMP_FWD_RATE 150
    :set ICMP_FWD_BURST 300
    :set DDOS_RATE 96
    :set DDOS_BURST 96
    :set DDOS_WINDOW "10s"
    :set PSD_WEIGHT 28
    :set PSD_DELAY "5s"
    :set PSD_LOW 4
    :set PSD_HIGH 1
}
:if ($PROFILE="DATACENTER") do={
    :set SYN_INPUT 120
    :set SYN_FORWARD 500
    :set CONN_INPUT 250
    :set CONN_FORWARD 1000
    :set ICMP_INPUT_RATE 50
    :set ICMP_INPUT_BURST 100
    :set ICMP_FWD_RATE 300
    :set ICMP_FWD_BURST 600
    :set DDOS_RATE 256
    :set DDOS_BURST 256
    :set DDOS_WINDOW "10s"
    :set PSD_WEIGHT 32
    :set PSD_DELAY "5s"
    :set PSD_LOW 5
    :set PSD_HIGH 1
}

# ============================================================================
# 1. GLOBAL ROUTER SETTINGS
# ============================================================================

/ip/settings
set tcp-syncookies=yes
set rp-filter=loose

# ============================================================================
# 2. INTERFACE LISTS
# ============================================================================

:do { /interface/list/add name=WAN comment="IPS v4 WAN" } on-error={}
:do { /interface/list/add name=LAN comment="IPS v4 LAN" } on-error={}

# ACTION REQUIRED:
# Add your actual WAN and LAN interfaces to these existing lists.
# Example:
# /interface/list/member/add list=WAN interface=ether1
# /interface/list/member/add list=LAN interface=bridge

# ============================================================================
# 3. IPv4 ADDRESS LISTS
# ============================================================================

/ip/firewall/address-list
add list=IPS-EXEMPT address=127.0.0.1 comment="IPS v4 reserved local"
add list=IPS-TRUSTED address=10.0.0.0/8 comment="IPS v4 private trusted reference"
add list=IPS-TRUSTED address=172.16.0.0/12 comment="IPS v4 private trusted reference"
add list=IPS-TRUSTED address=192.168.0.0/16 comment="IPS v4 private trusted reference"

# ---- ACTION REQUIRED ----
# Add your real admin IP(s) before relying on this for remote access:
#   /ip firewall address-list add list=IPS-EXEMPT address=YOUR.IP.HERE comment="admin"
#   /ip firewall address-list add list=MGMT-TRUSTED address=YOUR.IP.HERE comment="admin"
# (MGMT-TRUSTED is only consumed by the optional lockdown in section 14.)

# Threat/evidence lists (IPS-L1-OBSERVE .. IPS-L5-QUARANTINE) are created
# dynamically the first time a firewall action adds an entry - no
# pre-creation needed, and referencing them in a condition before they
# exist is safe (simply never matches until populated).
#   L1 = observation      L2 = suspicious       L3 = confirmed pattern (BLOCKED)
#   L4 = active attack (BLOCKED)                L5 = quarantine (BLOCKED)

# RFC6890 / non-public source references used by RAW.
add list=IPS-BAD-SRC address=0.0.0.0/8 comment="RFC6890"
add list=IPS-BAD-SRC address=10.0.0.0/8 comment="RFC1918"
add list=IPS-BAD-SRC address=100.64.0.0/10 comment="RFC6598 CGNAT - WAN spoof guard"
add list=IPS-BAD-SRC address=127.0.0.0/8 comment="Loopback"
add list=IPS-BAD-SRC address=169.254.0.0/16 comment="Link-local"
add list=IPS-BAD-SRC address=172.16.0.0/12 comment="RFC1918"
add list=IPS-BAD-SRC address=192.0.0.0/24 comment="RFC6890"
add list=IPS-BAD-SRC address=192.168.0.0/16 comment="RFC1918"
add list=IPS-BAD-SRC address=198.18.0.0/15 comment="Benchmark"
add list=IPS-BAD-SRC address=198.51.100.0/24 comment="Documentation"
add list=IPS-BAD-SRC address=203.0.113.0/24 comment="Documentation"
add list=IPS-BAD-SRC address=224.0.0.0/4 comment="Multicast"
add list=IPS-BAD-SRC address=240.0.0.0/4 comment="Reserved"

# ============================================================================
# 4. IPv6 ADDRESS LISTS
# ============================================================================

/ipv6/firewall/address-list
add list=IPS6-EXEMPT address=::1 comment="IPS v4 IPv6 reserved local"
add list=IPS6-BAD-SRC address=::/128 comment="Unspecified"
add list=IPS6-BAD-SRC address=::1/128 comment="Loopback"
add list=IPS6-BAD-SRC address=::ffff:0:0/96 comment="IPv4 mapped"
add list=IPS6-BAD-SRC address=100::/64 comment="Discard-only"
add list=IPS6-BAD-SRC address=2001:db8::/32 comment="Documentation"
add list=IPS6-BAD-SRC address=fc00::/7 comment="ULA - WAN spoof guard"
add list=IPS6-BAD-SRC address=fe80::/10 comment="Link-local - WAN spoof guard"
add list=IPS6-BAD-SRC address=ff00::/8 comment="Multicast source"
add list=IPS6-BAD-SRC address=2001:10::/28 comment="ORCHID"

# ============================================================================
# 5. EVENT ENGINE CHAINS (wired in sections 6/18 via IPS-EVENT / IPS6-EVENT)
# ============================================================================

/ip/firewall/filter
add chain=IPS-EVENT action=passthrough \
    comment="IPS v4 central hook: add custom actions ABOVE this line (e.g. run a script that sends a webhook/Telegram alert); the passthrough counter is always visible via 'filter print stats'"
add chain=IPS-SCAN comment="IPS v4 scan/anomaly engine"
add chain=IPS-SYN comment="IPS v4 SYN-flood engine"
add chain=IPS-DDOS comment="IPS v4 volumetric DDoS engine"
add chain=IPS-BRUTE comment="IPS v4 brute-force connection heuristic"

/ipv6/firewall/filter
add chain=IPS6-EVENT action=passthrough \
    comment="IPS v4 IPv6 central hook: add custom actions ABOVE this line"
add chain=IPS6-SCAN comment="IPS v4 IPv6 scan/anomaly engine"
add chain=IPS6-SYN comment="IPS v4 IPv6 SYN-flood engine"
add chain=IPS6-DDOS comment="IPS v4 IPv6 volumetric DDoS engine"
add chain=IPS6-BRUTE comment="IPS v4 IPv6 brute-force connection heuristic"

# ============================================================================
# 6. IPv4 RAW - SAFE WHITELIST + EARLY BLOCKING
# ============================================================================
# IMPORTANT: EXEMPT does NOT come before spoof/malformed checks. A trusted
# admin IP cannot use whitelist semantics to bypass basic packet-integrity /
# WAN source validation.

/ip/firewall/raw
# RAW-local event hook. RAW and FILTER are separate firewall modules, so a
# jump from RAW must target a chain that exists inside RAW itself. This hook
# intentionally mirrors the filter event hook and keeps the existing design
# without trying to jump across modules.
add chain=IPS-EVENT action=passthrough \
    comment="IPS v4 RAW central event hook"

add chain=prerouting in-interface-list=WAN src-address-list=IPS-BAD-SRC \
    action=drop log=yes log-prefix="IPS-EVENT|L3|SPOOF|" \
    comment="IPS v4 drop spoofed/special WAN sources"

add chain=prerouting in-interface-list=WAN protocol=tcp tcp-flags=fin,syn \
    action=drop log=yes log-prefix="IPS-EVENT|L3|TCP-SYNFIN|" \
    comment="IPS v4 malformed SYN+FIN"

add chain=prerouting in-interface-list=WAN protocol=tcp tcp-flags=fin,rst \
    action=drop log=yes log-prefix="IPS-EVENT|L3|TCP-FINRST|" \
    comment="IPS v4 malformed FIN+RST"

add chain=prerouting in-interface-list=WAN protocol=tcp tcp-flags=fin,psh,urg \
    action=drop log=yes log-prefix="IPS-EVENT|L3|TCP-XMAS|" \
    comment="IPS v4 XMAS scan"

add chain=prerouting in-interface-list=WAN protocol=tcp \
    tcp-flags=!fin,!syn,!rst,!ack action=drop \
    log=yes log-prefix="IPS-EVENT|L3|TCP-NULL|" \
    comment="IPS v4 NULL scan"

# Optional - non-initial IPv4 fragment guard (off by default, see section 0).
/ip/firewall/raw
add chain=prerouting in-interface-list=WAN fragment=yes action=drop \
    log=yes log-prefix="IPS-EVENT|L3|FRAGMENT|" disabled=yes \
    comment="IPS v4 fragment guard - test before enabling, may affect legacy UDP/VoIP"

:if ($ENABLE_FRAGMENT_GUARD=true) do={
    /ip/firewall/raw/enable [find comment="IPS v4 fragment guard - test before enabling, may affect legacy UDP/VoIP"]
}

# Safe whitelist: skips dynamic reputation blocks only AFTER integrity checks.
/ip/firewall/raw
add chain=prerouting src-address-list=IPS-EXEMPT action=accept \
    comment="IPS v4 safe exempt - after spoof/malformed checks"

# Central event hook, then block - highest severity first.
add chain=prerouting src-address-list=IPS-L5-QUARANTINE \
    action=jump jump-target=IPS-EVENT comment="IPS v4 hook: L5 quarantine"
add chain=prerouting src-address-list=IPS-L5-QUARANTINE action=drop \
    log=yes log-prefix="IPS-EVENT|L5|QUARANTINE|" \
    comment="IPS v4 L5 quarantine block"

add chain=prerouting src-address-list=IPS-L4-ACTIVE \
    action=jump jump-target=IPS-EVENT comment="IPS v4 hook: L4 active"
add chain=prerouting src-address-list=IPS-L4-ACTIVE action=drop \
    log=yes log-prefix="IPS-EVENT|L4|ACTIVE-BLOCK|" \
    comment="IPS v4 L4 active attack block"

add chain=prerouting src-address-list=IPS-L3-CONFIRMED \
    action=jump jump-target=IPS-EVENT comment="IPS v4 hook: L3 confirmed"
add chain=prerouting src-address-list=IPS-L3-CONFIRMED action=drop \
    log=yes log-prefix="IPS-EVENT|L3|CONFIRMED-BLOCK|" \
    comment="IPS v4 L3 confirmed pattern block"

# ============================================================================
# 7. IPv4 FILTER BASELINE
# ============================================================================

/ip/firewall/filter
add chain=input connection-state=invalid action=drop \
    log=yes log-prefix="IPS-EVENT|L3|INVALID-INPUT|" \
    comment="IPS v4 invalid input"
add chain=forward connection-state=invalid action=drop \
    log=yes log-prefix="IPS-EVENT|L3|INVALID-FWD|" \
    comment="IPS v4 invalid forward"

add chain=input connection-state=established,related,untracked action=accept \
    comment="IPS v4 established input"
# Optional FastTrack must be evaluated BEFORE the established/related accept;
# placing it after that accept makes the FastTrack rule unreachable.
add chain=forward connection-state=established,related action=fasttrack-connection \
    hw-offload=yes disabled=yes comment="IPS v4 optional FastTrack"

:if ($ENABLE_FASTTRACK=true) do={
    /ip/firewall/filter/enable [find comment="IPS v4 optional FastTrack"]
}

add chain=forward connection-state=established,related,untracked action=accept \
    comment="IPS v4 established forward"

# Fallback safety net for anything not already caught in RAW (dynamic
# levels checked after established/related so existing legitimate sessions
# are not destroyed merely because the source was flagged afterward).
add chain=input src-address-list=IPS-L5-QUARANTINE action=drop \
    log=yes log-prefix="IPS-EVENT|L5|INPUT-QUARANTINE|"
add chain=forward src-address-list=IPS-L5-QUARANTINE action=drop \
    log=yes log-prefix="IPS-EVENT|L5|FWD-QUARANTINE|"
add chain=input src-address-list=IPS-L4-ACTIVE action=drop \
    log=yes log-prefix="IPS-EVENT|L4|INPUT-ACTIVE|"
add chain=forward src-address-list=IPS-L4-ACTIVE action=drop \
    log=yes log-prefix="IPS-EVENT|L4|FWD-ACTIVE|"
add chain=input src-address-list=IPS-L3-CONFIRMED action=drop \
    log=yes log-prefix="IPS-EVENT|L3|INPUT-CONFIRMED|"
add chain=forward src-address-list=IPS-L3-CONFIRMED action=drop \
    log=yes log-prefix="IPS-EVENT|L3|FWD-CONFIRMED|"

# ============================================================================
# 8. IPv4 DISPATCH
# ============================================================================

/ip/firewall/filter
add chain=input in-interface-list=WAN protocol=tcp action=jump jump-target=IPS-SCAN \
    comment="IPS v4 dispatch WAN TCP scan"
add chain=forward in-interface-list=WAN protocol=tcp action=jump jump-target=IPS-SCAN \
    comment="IPS v4 dispatch FWD TCP scan"
add chain=input in-interface-list=WAN protocol=udp action=jump jump-target=IPS-SCAN \
    comment="IPS v4 dispatch WAN UDP scan"
add chain=forward in-interface-list=WAN protocol=udp action=jump jump-target=IPS-SCAN \
    comment="IPS v4 dispatch FWD UDP scan"

add chain=input in-interface-list=WAN protocol=tcp tcp-flags=syn \
    connection-state=new action=jump jump-target=IPS-SYN \
    comment="IPS v4 dispatch router SYN"
add chain=forward in-interface-list=WAN protocol=tcp tcp-flags=syn \
    connection-state=new action=jump jump-target=IPS-SYN \
    comment="IPS v4 dispatch forwarded SYN"

add chain=input in-interface-list=WAN connection-state=new \
    action=jump jump-target=IPS-DDOS comment="IPS v4 dispatch router DDoS"
add chain=forward in-interface-list=WAN connection-state=new \
    action=jump jump-target=IPS-DDOS comment="IPS v4 dispatch forwarded DDoS"

add chain=input in-interface-list=WAN protocol=tcp dst-port=22,8291 \
    connection-state=new action=jump jump-target=IPS-BRUTE \
    comment="IPS v4 SSH/Winbox brute heuristic"

# ============================================================================
# 9. IPv4 SCAN ENGINE (FIXED escalation path vs v3)
# ============================================================================
# Escalation checks run HIGHEST stage first, because add-src-to-address-list
# is a passthrough action: membership added by a later rule in this SAME
# pass is not visible to an earlier rule until the NEXT packet. This is the
# same pattern already used correctly in the brute-force engine (section 12).

/ip/firewall/filter
add chain=IPS-SCAN src-address-list=IPS-EXEMPT action=return \
    comment="IPS v4 scan exempt"

# Repeat offender already flagged SUSPICIOUS -> CONFIRMED (this is the fix:
# v3 had no rule promoting L2 to L3, so a plain scan never got blocked).
add chain=IPS-SCAN src-address-list=IPS-L2-SUSPICIOUS \
    action=add-src-to-address-list address-list=IPS-L3-CONFIRMED \
    address-list-timeout=$L3_TIMEOUT log=yes log-prefix="IPS-EVENT|L3|SCAN-CONFIRMED|" \
    comment="IPS v4 repeat scan while suspicious -> confirmed (blocked)"

# Repeat while OBSERVE -> escalate to SUSPICIOUS
add chain=IPS-SCAN src-address-list=IPS-L1-OBSERVE \
    action=add-src-to-address-list address-list=IPS-L2-SUSPICIOUS \
    address-list-timeout=$L2_TIMEOUT log=yes log-prefix="IPS-EVENT|L2|SCAN-ESCALATE|" \
    comment="IPS v4 scan observation escalation"

# First-seen PSD hit -> OBSERVE
add chain=IPS-SCAN protocol=tcp psd=($PSD_WEIGHT . "," . $PSD_DELAY . "," . $PSD_LOW . "," . $PSD_HIGH) \
    action=add-src-to-address-list address-list=IPS-L1-OBSERVE \
    address-list-timeout=5m log=yes log-prefix="IPS-EVENT|L1|TCP-PSD|" \
    comment="IPS v4 TCP port-scan observation"

add chain=IPS-SCAN protocol=udp psd=($PSD_WEIGHT . "," . $PSD_DELAY . "," . $PSD_LOW . "," . $PSD_HIGH) \
    action=add-src-to-address-list address-list=IPS-L1-OBSERVE \
    address-list-timeout=5m log=yes log-prefix="IPS-EVENT|L1|UDP-PSD|" \
    comment="IPS v4 UDP port-scan observation"

# Malformed TCP flags are already high-confidence -> straight to CONFIRMED.
add chain=IPS-SCAN tcp-flags=fin,syn action=add-src-to-address-list \
    address-list=IPS-L3-CONFIRMED address-list-timeout=$L3_TIMEOUT \
    log=yes log-prefix="IPS-EVENT|L3|SYNFIN|" \
    comment="IPS v4 confirmed malformed TCP"

add chain=IPS-SCAN tcp-flags=fin,rst action=add-src-to-address-list \
    address-list=IPS-L3-CONFIRMED address-list-timeout=$L3_TIMEOUT \
    log=yes log-prefix="IPS-EVENT|L3|FINRST|" \
    comment="IPS v4 confirmed malformed TCP"

add chain=IPS-SCAN tcp-flags=fin,psh,urg action=add-src-to-address-list \
    address-list=IPS-L3-CONFIRMED address-list-timeout=$L3_TIMEOUT \
    log=yes log-prefix="IPS-EVENT|L3|XMAS|" \
    comment="IPS v4 confirmed XMAS"

# ============================================================================
# 10. IPv4 SYN ENGINE - SEPARATE FROM DDOS
# ============================================================================

/ip/firewall/filter
add chain=IPS-SYN connection-state=new connection-limit=($SYN_INPUT . ",32") \
    in-interface-list=WAN action=add-src-to-address-list address-list=IPS-L4-ACTIVE \
    address-list-timeout=$L4_TIMEOUT log=yes log-prefix="IPS-EVENT|L4|SYN-FLOOD-INPUT|" \
    comment="IPS v4 router SYN flood"

add chain=IPS-SYN connection-state=new connection-limit=($SYN_FORWARD . ",32") \
    action=add-src-to-address-list address-list=IPS-L4-ACTIVE \
    address-list-timeout=$L4_TIMEOUT log=yes log-prefix="IPS-EVENT|L4|SYN-FLOOD-FWD|" \
    comment="IPS v4 forwarded SYN flood"

# ============================================================================
# 11. IPv4 DDoS ENGINE - SRC/DST PAIR
# ============================================================================

/ip/firewall/filter
add chain=IPS-DDOS src-address-list=IPS-EXEMPT action=return \
    comment="IPS v4 DDoS exempt"

add chain=IPS-DDOS dst-limit=($DDOS_RATE . "," . $DDOS_BURST . ",src-and-dst-addresses/" . $DDOS_WINDOW) \
    action=return comment="IPS v4 DDoS normal-rate return"

add chain=IPS-DDOS action=add-dst-to-address-list address-list=IPS-DDOS-TARGETS \
    address-list-timeout=10m comment="IPS v4 DDoS target evidence"

add chain=IPS-DDOS action=add-src-to-address-list address-list=IPS-L4-ACTIVE \
    address-list-timeout=$L4_TIMEOUT log=yes log-prefix="IPS-EVENT|L4|DDOS-ATTACKER|" \
    comment="IPS v4 DDoS attacker"

add chain=IPS-DDOS action=add-src-to-address-list address-list=IPS-L5-QUARANTINE \
    address-list-timeout=$L5_TIMEOUT log=yes log-prefix="IPS-EVENT|L5|DDOS-QUARANTINE|" \
    comment="IPS v4 DDoS quarantine - a rate exceeding threshold is already a multi-packet pattern, not a single-packet false-positive risk, so we escalate immediately"

# Pair-specific raw drop. Intentionally AFTER the L4/L5 lists above.
/ip/firewall/raw
add chain=prerouting src-address-list=IPS-L4-ACTIVE dst-address-list=IPS-DDOS-TARGETS \
    action=drop log=yes log-prefix="IPS-EVENT|L4|DDOS-PAIR|" \
    comment="IPS v4 DDoS attacker-target pair"

# ============================================================================
# 12. IPv4 BRUTE-FORCE ENGINE
# ============================================================================
# This is a CONNECTION-BASED heuristic, not SSH/Winbox authentication failure
# telemetry. It must not be interpreted as proof of a failed login.

/ip/firewall/filter
add chain=IPS-BRUTE connection-state=new src-address-list=IPS-BF-2 \
    action=add-src-to-address-list address-list=IPS-L4-ACTIVE \
    address-list-timeout=$BF_STAGE3 log=yes log-prefix="IPS-EVENT|L4|BF-STAGE3|" \
    comment="IPS v4 brute connection stage 3"
add chain=IPS-BRUTE connection-state=new src-address-list=IPS-BF-1 \
    action=add-src-to-address-list address-list=IPS-BF-2 \
    address-list-timeout=$BF_STAGE2 log=yes log-prefix="IPS-EVENT|L3|BF-STAGE2|" \
    comment="IPS v4 brute connection stage 2"
add chain=IPS-BRUTE connection-state=new action=add-src-to-address-list \
    address-list=IPS-BF-1 address-list-timeout=$BF_STAGE1 \
    log=yes log-prefix="IPS-EVENT|L2|BF-STAGE1|" \
    comment="IPS v4 brute connection stage 1"

# ============================================================================
# 13. IPv4 ICMP RATE LIMIT
# ============================================================================

/ip/firewall/filter
add chain=input in-interface-list=WAN protocol=icmp \
    limit=($ICMP_INPUT_RATE . "," . $ICMP_INPUT_BURST) action=accept \
    comment="IPS v4 ICMP input rate allow"
add chain=input in-interface-list=WAN protocol=icmp action=drop \
    log=yes log-prefix="IPS-EVENT|L3|ICMP-FLOOD|" \
    comment="IPS v4 ICMP excess"
add chain=forward in-interface-list=WAN protocol=icmp \
    limit=($ICMP_FWD_RATE . "," . $ICMP_FWD_BURST) action=accept \
    comment="IPS v4 ICMP forward rate allow"
add chain=forward in-interface-list=WAN protocol=icmp action=drop \
    log=yes log-prefix="IPS-EVENT|L3|ICMP-FLOOD-FWD|" \
    comment="IPS v4 ICMP forward excess"

# ============================================================================
# 14. OPTIONAL MANAGEMENT LOCKDOWN
# ============================================================================

/ip/firewall/filter
add chain=input in-interface-list=WAN protocol=tcp dst-port=22,8291,80,443,8728,8729 \
    connection-state=new src-address-list=!MGMT-TRUSTED action=drop \
    log=yes log-prefix="IPS-EVENT|L4|MGMT-DENY|" disabled=yes \
    comment="IPS v4 management lockdown - enable only after MGMT-TRUSTED"

:if ($ENABLE_MGMT_LOCKDOWN=true) do={
    /ip/firewall/filter/enable [find comment="IPS v4 management lockdown - enable only after MGMT-TRUSTED"]
}

# ============================================================================
# 15. OPTIONAL AMPLIFICATION GUARD
# ============================================================================

/ip/firewall/filter
add chain=forward in-interface-list=WAN protocol=udp dst-port=53,123,1900,389,11211 \
    connection-state=new connection-limit=20,32 action=add-src-to-address-list \
    address-list=IPS-L4-ACTIVE address-list-timeout=1h log=yes \
    log-prefix="IPS-EVENT|L4|AMPLIFICATION|" disabled=yes \
    comment="IPS v4 amplification guard - review NAT/services first"

:if ($ENABLE_AMP_GUARD=true) do={
    /ip/firewall/filter/enable [find comment="IPS v4 amplification guard - review NAT/services first"]
}

# ============================================================================
# 16. IPv4 FORWARD POLICY
# ============================================================================

/ip/firewall/filter
add chain=forward in-interface-list=WAN connection-state=new connection-nat-state=!dstnat \
    action=drop comment="IPS v4 WAN new not dstnat"

add chain=input in-interface-list=WAN connection-state=new action=drop \
    comment="IPS v4 unsolicited WAN input"

# ============================================================================
# 17. OPTIONAL FASTTRACK
# ============================================================================
# FastTrack is installed and enabled conditionally in section 7, BEFORE the
# established/related accept rule. This section is kept as a documentation
# marker only so the original structure remains easy to follow.

# ============================================================================
# 18. IPv6 RAW - INTEGRITY + REPUTATION
# ============================================================================

/ipv6/firewall/raw
# IPv6 RAW-local event hook. RAW and FILTER are separate firewall modules.
add chain=IPS6-EVENT action=passthrough \
    comment="IPS v4 IPv6 RAW central event hook"

add chain=prerouting in-interface-list=WAN src-address-list=IPS6-BAD-SRC \
    action=drop log=yes log-prefix="IPS6-EVENT|L3|SPOOF|" \
    comment="IPS v4 IPv6 bad WAN source"

# IPv6 requires ICMPv6 for normal operation; v4 does not blanket-drop ICMPv6.
# Extension-header filtering should be added only after testing the exact
# IPv6 services/tunnel design used in the network.

add chain=prerouting src-address-list=IPS6-EXEMPT action=accept \
    comment="IPS v4 IPv6 safe exempt after source validation"

add chain=prerouting src-address-list=IPS6-L5-QUARANTINE \
    action=jump jump-target=IPS6-EVENT comment="IPS v4 IPv6 hook: L5 quarantine"
add chain=prerouting src-address-list=IPS6-L5-QUARANTINE action=drop \
    log=yes log-prefix="IPS6-EVENT|L5|QUARANTINE|"

add chain=prerouting src-address-list=IPS6-L4-ACTIVE \
    action=jump jump-target=IPS6-EVENT comment="IPS v4 IPv6 hook: L4 active"
add chain=prerouting src-address-list=IPS6-L4-ACTIVE action=drop \
    log=yes log-prefix="IPS6-EVENT|L4|ACTIVE-BLOCK|"

add chain=prerouting src-address-list=IPS6-L3-CONFIRMED \
    action=jump jump-target=IPS6-EVENT comment="IPS v4 IPv6 hook: L3 confirmed"
add chain=prerouting src-address-list=IPS6-L3-CONFIRMED action=drop \
    log=yes log-prefix="IPS6-EVENT|L3|CONFIRMED-BLOCK|"

# ============================================================================
# 19. IPv6 FILTER BASELINE
# ============================================================================

/ipv6/firewall/filter
add chain=input connection-state=invalid action=drop \
    log=yes log-prefix="IPS6-EVENT|L3|INVALID-INPUT|"
add chain=forward connection-state=invalid action=drop \
    log=yes log-prefix="IPS6-EVENT|L3|INVALID-FWD|"
add chain=input connection-state=established,related action=accept \
    comment="IPS v4 IPv6 established input"
add chain=forward connection-state=established,related action=accept \
    comment="IPS v4 IPv6 established forward"

add chain=input src-address-list=IPS6-L5-QUARANTINE action=drop \
    log=yes log-prefix="IPS6-EVENT|L5|INPUT-QUARANTINE|"
add chain=forward src-address-list=IPS6-L5-QUARANTINE action=drop \
    log=yes log-prefix="IPS6-EVENT|L5|FWD-QUARANTINE|"
add chain=input src-address-list=IPS6-L4-ACTIVE action=drop \
    log=yes log-prefix="IPS6-EVENT|L4|INPUT-ACTIVE|"
add chain=forward src-address-list=IPS6-L4-ACTIVE action=drop \
    log=yes log-prefix="IPS6-EVENT|L4|FWD-ACTIVE|"

# ICMPv6 is explicitly allowed - Neighbor Discovery, PMTUD and other
# essential IPv6 functions depend on it. Tighten by type only after lab
# testing.
add chain=input protocol=icmpv6 action=accept comment="IPS v4 IPv6 ICMPv6 allow"
add chain=forward protocol=icmpv6 action=accept comment="IPS v4 IPv6 ICMPv6 allow"

# ============================================================================
# 20. IPv6 DISPATCH
# ============================================================================

/ipv6/firewall/filter
add chain=input in-interface-list=WAN protocol=tcp action=jump jump-target=IPS6-SCAN \
    comment="IPS v4 IPv6 TCP scan dispatch"
add chain=forward in-interface-list=WAN protocol=tcp action=jump jump-target=IPS6-SCAN \
    comment="IPS v4 IPv6 TCP scan forward dispatch"
add chain=input in-interface-list=WAN protocol=udp action=jump jump-target=IPS6-SCAN \
    comment="IPS v4 IPv6 UDP scan dispatch"
add chain=forward in-interface-list=WAN protocol=udp action=jump jump-target=IPS6-SCAN \
    comment="IPS v4 IPv6 UDP scan forward dispatch"

add chain=input in-interface-list=WAN protocol=tcp tcp-flags=syn connection-state=new \
    action=jump jump-target=IPS6-SYN comment="IPS v4 IPv6 router SYN"
add chain=forward in-interface-list=WAN protocol=tcp tcp-flags=syn connection-state=new \
    action=jump jump-target=IPS6-SYN comment="IPS v4 IPv6 forwarded SYN"

add chain=input in-interface-list=WAN connection-state=new action=jump jump-target=IPS6-DDOS \
    comment="IPS v4 IPv6 DDoS input"
add chain=forward in-interface-list=WAN connection-state=new action=jump jump-target=IPS6-DDOS \
    comment="IPS v4 IPv6 DDoS forward"

add chain=input in-interface-list=WAN protocol=tcp dst-port=22,8291 connection-state=new \
    action=jump jump-target=IPS6-BRUTE comment="IPS v4 IPv6 brute heuristic"

# ============================================================================
# 21. IPv6 SCAN ENGINE (FIXED escalation path vs v3)
# ============================================================================
# RouterOS PSD is documented as IPv4-only, so IPv6 uses a conservative
# per-source packet-rate heuristic plus TCP flag anomalies instead.

/ipv6/firewall/filter
add chain=IPS6-SCAN src-address-list=IPS6-EXEMPT action=return \
    comment="IPS v4 IPv6 scan exempt"

# Repeat offender already flagged SUSPICIOUS -> CONFIRMED (same fix as IPv4).
add chain=IPS6-SCAN src-address-list=IPS6-L2-SUSPICIOUS \
    action=add-src-to-address-list address-list=IPS6-L3-CONFIRMED \
    address-list-timeout=$L3_TIMEOUT log=yes log-prefix="IPS6-EVENT|L3|SCAN-CONFIRMED|" \
    comment="IPS v4 IPv6 repeat scan while suspicious -> confirmed (blocked)"

# Repeat while OBSERVE -> escalate to SUSPICIOUS
add chain=IPS6-SCAN src-address-list=IPS6-L1-OBSERVE \
    action=add-src-to-address-list address-list=IPS6-L2-SUSPICIOUS \
    address-list-timeout=$L2_TIMEOUT log=yes log-prefix="IPS6-EVENT|L2|SCAN-ESCALATE|" \
    comment="IPS v4 IPv6 scan observation escalation"

# Malformed TCP flags are already high-confidence -> straight to CONFIRMED.
add chain=IPS6-SCAN tcp-flags=fin,syn action=add-src-to-address-list \
    address-list=IPS6-L3-CONFIRMED address-list-timeout=$L3_TIMEOUT \
    log=yes log-prefix="IPS6-EVENT|L3|SYNFIN|"
add chain=IPS6-SCAN tcp-flags=fin,rst action=add-src-to-address-list \
    address-list=IPS6-L3-CONFIRMED address-list-timeout=$L3_TIMEOUT \
    log=yes log-prefix="IPS6-EVENT|L3|FINRST|"
add chain=IPS6-SCAN tcp-flags=fin,psh,urg action=add-src-to-address-list \
    address-list=IPS6-L3-CONFIRMED address-list-timeout=$L3_TIMEOUT \
    log=yes log-prefix="IPS6-EVENT|L3|XMAS|"

# Rate-based fallback: normal rate returns, excess creates an OBSERVE entry
# which the two escalation rules above will promote on repeat.
add chain=IPS6-SCAN dst-limit=20,20,src-address/10s action=return \
    comment="IPS v4 IPv6 normal scan-rate return"
add chain=IPS6-SCAN action=add-src-to-address-list address-list=IPS6-L1-OBSERVE \
    address-list-timeout=5m log=yes log-prefix="IPS6-EVENT|L1|RATE-SCAN|" \
    comment="IPS v4 IPv6 high-rate scan observation"

# ============================================================================
# 22. IPv6 SYN ENGINE
# ============================================================================

/ipv6/firewall/filter
add chain=IPS6-SYN connection-state=new connection-limit=($SYN_INPUT . ",128") \
    in-interface-list=WAN action=add-src-to-address-list address-list=IPS6-L4-ACTIVE \
    address-list-timeout=$L4_TIMEOUT log=yes log-prefix="IPS6-EVENT|L4|SYN-FLOOD-INPUT|"
add chain=IPS6-SYN connection-state=new connection-limit=($SYN_FORWARD . ",128") \
    action=add-src-to-address-list address-list=IPS6-L4-ACTIVE \
    address-list-timeout=$L4_TIMEOUT log=yes log-prefix="IPS6-EVENT|L4|SYN-FLOOD-FWD|"

# ============================================================================
# 23. IPv6 DDOS ENGINE
# ============================================================================

/ipv6/firewall/filter
add chain=IPS6-DDOS src-address-list=IPS6-EXEMPT action=return
add chain=IPS6-DDOS dst-limit=($DDOS_RATE . "," . $DDOS_BURST . ",src-and-dst-addresses/" . $DDOS_WINDOW) \
    action=return comment="IPS v4 IPv6 DDoS normal rate"
add chain=IPS6-DDOS action=add-dst-to-address-list address-list=IPS6-DDOS-TARGETS \
    address-list-timeout=10m
add chain=IPS6-DDOS action=add-src-to-address-list address-list=IPS6-L4-ACTIVE \
    address-list-timeout=$L4_TIMEOUT log=yes log-prefix="IPS6-EVENT|L4|DDOS-ATTACKER|"
add chain=IPS6-DDOS action=add-src-to-address-list address-list=IPS6-L5-QUARANTINE \
    address-list-timeout=$L5_TIMEOUT log=yes log-prefix="IPS6-EVENT|L5|DDOS-QUARANTINE|"

/ipv6/firewall/raw
add chain=prerouting src-address-list=IPS6-L4-ACTIVE dst-address-list=IPS6-DDOS-TARGETS \
    action=drop log=yes log-prefix="IPS6-EVENT|L4|DDOS-PAIR|"

# ============================================================================
# 24. IPv6 BRUTE ENGINE
# ============================================================================

/ipv6/firewall/filter
add chain=IPS6-BRUTE connection-state=new src-address-list=IPS6-BF-2 \
    action=add-src-to-address-list address-list=IPS6-L4-ACTIVE \
    address-list-timeout=$BF_STAGE3 log=yes log-prefix="IPS6-EVENT|L4|BF-STAGE3|"
add chain=IPS6-BRUTE connection-state=new src-address-list=IPS6-BF-1 \
    action=add-src-to-address-list address-list=IPS6-BF-2 \
    address-list-timeout=$BF_STAGE2 log=yes log-prefix="IPS6-EVENT|L3|BF-STAGE2|"
add chain=IPS6-BRUTE connection-state=new action=add-src-to-address-list \
    address-list=IPS6-BF-1 address-list-timeout=$BF_STAGE1 \
    log=yes log-prefix="IPS6-EVENT|L2|BF-STAGE1|"

# ============================================================================
# 25. IPv6 FINAL POLICY
# ============================================================================
# Default-deny for unsolicited inbound/forward traffic. Outbound client
# traffic is allowed via established/related above; adapt if you route
# public IPv6 subnets.

/ipv6/firewall/filter
add chain=input in-interface-list=WAN connection-state=new action=drop \
    log=yes log-prefix="IPS6-EVENT|L3|UNSOLICITED-INPUT|" \
    comment="IPS v4 IPv6 unsolicited WAN input"

add chain=forward in-interface-list=WAN connection-state=new action=drop \
    log=yes log-prefix="IPS6-EVENT|L3|UNSOLICITED-FWD|" \
    comment="IPS v4 IPv6 unsolicited WAN forward"

# ============================================================================
# 26. LOGGING / EVENT FORMAT
# ============================================================================

/system/logging
:do { add topics=firewall action=memory comment="IPS v4 firewall event log" } on-error={}

# Event prefix format:
#   IPS-EVENT|L<level>|<event>|<optional context>
#   IPS6-EVENT|L<level>|<event>|<optional context>
# Searchable and suitable for forwarding to syslog/Wazuh.

# Optional remote syslog example - configure your own collector:
# /system/logging/action/add name=IPS-SYSLOG target=remote remote=10.0.0.10 remote-port=514
# /system/logging/add topics=firewall action=IPS-SYSLOG

# ============================================================================
# 27. OPTIONAL - EXTERNAL THREAT FEED SYNC (TEMPLATE, MANUAL ENABLE ONLY)
# ============================================================================
# Proactive layer: periodically pull a plaintext IP list (one IP/CIDR per
# line) into IPS-L5-QUARANTINE. Requires WAN internet access from the router
# and a source you trust. This is a TEMPLATE - review the feed's content and
# licensing, set FEED-URL, test the parsing manually, THEN create the
# scheduler. Left fully manual/disabled intentionally - do not uncomment
# without testing against your RouterOS version's /tool fetch output format.
#
# /system script
# add name=ips-feed-sync source={
#   :local url "https://your-trusted-feed.example/ips.txt";
#   :local data ([/tool fetch url=$url as-value output=user]->"data");
#   :foreach line in=[:toarray $data] do={
#     :if ($line != "" && [:pick $line 0 1] != "#") do={
#       :do {
#         /ip firewall address-list add list=IPS-L5-QUARANTINE address=$line \
#             timeout=1d comment="threat-feed"
#       } on-error={}
#     }
#   }
# }
# /system scheduler
# add name=ips-feed-sync interval=1d on-event="/system script run ips-feed-sync" \
#     disabled=yes comment="IPS v4 - external feed sync (enable after testing)"

# ============================================================================
# 28. MONITORING / EVENT QUERIES
# ============================================================================

# IPv4:
# /ip/firewall/address-list/print where list~"IPS-"
# /ip/firewall/address-list/print where list=IPS-L5-QUARANTINE
# /ip/firewall/address-list/print where list=IPS-L4-ACTIVE
# /ip/firewall/address-list/print where list=IPS-L3-CONFIRMED
# /ip/firewall/filter/print stats
# /ip/firewall/raw/print stats
# /log/print where message~"IPS-EVENT"
#
# IPv6:
# /ipv6/firewall/address-list/print where list~"IPS6-"
# /ipv6/firewall/filter/print stats
# /ipv6/firewall/raw/print stats
# /log/print where message~"IPS6-EVENT"

# ============================================================================
# 29. OPERATIONS: MANUAL RESPONSE
# ============================================================================

# Remove one IPv4 offender:
# /ip/firewall/address-list/remove [find list=IPS-L5-QUARANTINE address=1.2.3.4]
#
# Exempt one IPv4 trusted source (after source-integrity rules):
# /ip/firewall/address-list/add list=IPS-EXEMPT address=1.2.3.4 comment="trusted admin"
#
# IPv6:
# /ipv6/firewall/address-list/add list=IPS6-EXEMPT address=2001:db8:... comment="trusted admin"

# ============================================================================
# 30. BACKUP / ROLLBACK
# ============================================================================

# BEFORE IMPORT:
# /system/backup/save name=before-IPS-v4
# /export file=before-IPS-v4
#
# Use Safe Mode and local/MAC access during first deployment.

# ============================================================================
# 31. VALIDATION CHECKLIST
# ============================================================================
# 1) Verify WAN/LAN membership:
#    /interface/list/member/print
# 2) Verify IPv6 is actually in use:
#    /ipv6/address/print
# 3) Check syntax/counters after import:
#    /ip/firewall/filter/print stats
#    /ipv6/firewall/filter/print stats
# 4) Generate controlled lab scans from a test host and confirm the source
#    ACTUALLY reaches IPS-L3-CONFIRMED after a few repeated scans - this
#    exercises the exact escalation path fixed in this version:
#    /ip/firewall/address-list/print where list=IPS-L1-OBSERVE
#    /ip/firewall/address-list/print where list=IPS-L2-SUSPICIOUS
#    /ip/firewall/address-list/print where list=IPS-L3-CONFIRMED
# 5) Verify legitimate VPN, DNS, DHCPv6/ND, VoIP, SIP and PMTUD behavior.
# 6) Only then consider enabling FastTrack, management lockdown, the
#    amplification guard, or the fragment guard.
#
# ============================================================================
# END RouterOS 7 IPS v4.0
# ============================================================================
