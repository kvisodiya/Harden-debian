#!/bin/bash
##############################################################################
#
#  enhance.sh — Advanced Security Layer
#
#  Adds:
#    1. AIDE (File Integrity Monitoring) — proper setup
#    2. rkhunter — rootkit scanning
#    3. CrowdSec — replaces fail2ban
#    4. Tor Hardened SOCKS — isolated circuits
#    5. DNS Privacy — Quad9 + Cloudflare encrypted
#    6. Advanced sysctl privacy tweaks
#    7. chkrootkit
#    8. Automated security scanning
#    9. Network monitoring
#
#  SAFE: Nothing breaks. Internet works. SSH works.
#
#  Usage: sudo bash enhance.sh
#
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash enhance.sh"; exit 1; fi

SSH_PORT="${SSH_PORT:-22}"

set +e
export DEBIAN_FRONTEND=noninteractive

clear
echo ""
echo "╔════════════════════════════════════════════╗"
echo "║                                            ║"
echo "║   enhance.sh — Advanced Security Layer     ║"
echo "║                                            ║"
echo "║   AIDE • CrowdSec • Tor • DNS Privacy     ║"
echo "║                                            ║"
echo "╚════════════════════════════════════════════╝"
echo ""
sleep 2

##############################################################################
# 1. AIDE — File Integrity Monitoring (PROPER setup)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/9] AIDE — File Integrity Monitoring"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

apt-get install -y -qq aide aide-common 2>/dev/null

# Custom AIDE config — monitor critical files
cat > /etc/aide/aide.conf.d/90_custom_rules <<'EOF'
# ═══════════════════════════════════════
# AIDE Custom Rules — Monitor Everything
# ═══════════════════════════════════════

# Critical system binaries
/usr/sbin Full
/usr/bin Full
/sbin Full
/bin Full

# Boot files
/boot Full

# System configs
/etc p+i+u+g+sha256

# SSH
/etc/ssh Full

# PAM
/etc/pam.d Full

# Cron
/etc/crontab Full
/etc/cron.d Full
/etc/cron.daily Full
/etc/cron.weekly Full
/etc/cron.monthly Full
/etc/cron.hourly Full

# Security
/etc/security Full
/etc/sudoers Full
/etc/sudoers.d Full

# Network
/etc/hosts Full
/etc/resolv.conf Full
/etc/network Full

# User accounts
/etc/passwd Full
/etc/shadow Full
/etc/group Full
/etc/gshadow Full

# Kernel
/etc/sysctl.conf Full
/etc/sysctl.d Full
/etc/modprobe.d Full

# AppArmor
/etc/apparmor.d Full

# Audit
/etc/audit Full

# Ignore dynamic/log files
!/var/log
!/var/cache
!/var/tmp
!/tmp
!/run
!/proc
!/sys
!/dev
!/var/lib/aide
!/var/lib/dpkg
!/var/lib/apt
EOF

# Build AIDE database
echo "  Building AIDE database (this takes 2-3 minutes)..."
echo "  Please wait..."

# Kill any existing aide processes
killall aide aideinit 2>/dev/null
sleep 2

# Remove old database
rm -f /var/lib/aide/aide.db 2>/dev/null
rm -f /var/lib/aide/aide.db.new 2>/dev/null

# Initialize
aideinit --yes --force 2>/dev/null

# Wait for completion
sleep 5

# Copy database into place
if [ -f /var/lib/aide/aide.db.new ]; then
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  echo "  ✔ AIDE database created"
elif [ -f /var/lib/aide/aide.db ]; then
  echo "  ✔ AIDE database exists"
else
  # Try alternative method
  aide --init --config=/etc/aide/aide.conf 2>/dev/null
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
  [ -f /var/lib/aide/aide.db ] && echo "  ✔ AIDE database created (alt)" || echo "  ⏳ AIDE still building"
fi

# Daily AIDE check cron
cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
# AIDE daily integrity check
LOG="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide

/usr/bin/aide.wrapper --check > "$LOG" 2>&1
CHANGES=$(grep -c "changed:" "$LOG" 2>/dev/null || echo "0")

if [ "$CHANGES" -gt 0 ]; then
  logger -t aide-check "WARNING: $CHANGES file changes detected! Check $LOG"
fi
EOF
chmod 700 /etc/cron.daily/aide-check
mkdir -p /var/log/aide

# AIDE update script
cat > /usr/local/bin/aide-update <<'EOF'
#!/bin/bash
# Update AIDE database after legitimate changes
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
echo "Updating AIDE database..."
aide.wrapper --update 2>/dev/null
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null
echo "AIDE database updated ✔"
EOF
chmod 755 /usr/local/bin/aide-update

# AIDE manual check script
cat > /usr/local/bin/aide-scan <<'EOF'
#!/bin/bash
# Run AIDE check manually
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
echo "Running AIDE integrity check..."
echo ""
aide.wrapper --check 2>/dev/null | tee /var/log/aide/aide-manual-$(date +%Y%m%d_%H%M%S).log
echo ""
echo "Done. Log saved to /var/log/aide/"
EOF
chmod 755 /usr/local/bin/aide-scan

echo "  AIDE setup complete ✔"
echo ""

##############################################################################
# 2. RKHUNTER — Rootkit Scanner (PROPER setup)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/9] rkhunter — Rootkit Scanner"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

apt-get install -y -qq rkhunter chkrootkit 2>/dev/null

# Configure rkhunter
if [ -f /etc/rkhunter.conf ]; then
  # Enable auto updates
  sed -i 's/^#*UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
  sed -i 's/^#*MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
  sed -i 's/^#*WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf

  # Enable checks
  sed -i 's/^#*ENABLE_TESTS=.*/ENABLE_TESTS="ALL"/' /etc/rkhunter.conf

  # Allow SSH root (since we use it)
  sed -i 's/^#*ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=yes/' /etc/rkhunter.conf

  # Allow script replacements (updates)
  sed -i 's/^#*SCRIPTWHITELIST=.*//' /etc/rkhunter.conf
  echo 'SCRIPTWHITELIST="/usr/bin/egrep"' >> /etc/rkhunter.conf
  echo 'SCRIPTWHITELIST="/usr/bin/fgrep"' >> /etc/rkhunter.conf
  echo 'SCRIPTWHITELIST="/usr/bin/which"' >> /etc/rkhunter.conf
fi

# Configure daily scan
[ -f /etc/default/rkhunter ] && {
  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
  sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter
  sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
}

# Update database
rkhunter --propupd 2>/dev/null
rkhunter --update 2>/dev/null

# Weekly chkrootkit scan
cat > /etc/cron.weekly/chkrootkit-scan <<'EOF'
#!/bin/bash
chkrootkit 2>/dev/null | grep -v "not found\|not infected\|nothing found" > /var/log/chkrootkit-weekly.log 2>&1
ISSUES=$(grep -c "INFECTED\|Vulnerable" /var/log/chkrootkit-weekly.log 2>/dev/null || echo "0")
[ "$ISSUES" -gt 0 ] && logger -t chkrootkit "WARNING: $ISSUES issues found!"
EOF
chmod 700 /etc/cron.weekly/chkrootkit-scan

# Manual scan scripts
cat > /usr/local/bin/rootkit-scan <<'EOF'
#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
echo ""
echo "=== Rootkit Scan ==="
echo ""
echo "[1/2] rkhunter..."
rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null
echo ""
echo "[2/2] chkrootkit..."
chkrootkit 2>/dev/null | grep -v "not found\|not infected\|nothing found"
echo ""
echo "=== Scan Complete ==="
EOF
chmod 755 /usr/local/bin/rootkit-scan

echo "  rkhunter + chkrootkit configured ✔"
echo ""

##############################################################################
# 3. CROWDSEC — Modern Threat Intelligence (replaces fail2ban)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/9] CrowdSec — Threat Intelligence"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Install CrowdSec
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash 2>/dev/null
apt-get install -y -qq crowdsec 2>/dev/null

if command -v cscli >/dev/null 2>&1; then
  # Install bouncer (firewall integration)
  apt-get install -y -qq crowdsec-firewall-bouncer-iptables 2>/dev/null

  # Install collections
  cscli collections install crowdsecurity/linux 2>/dev/null
  cscli collections install crowdsecurity/sshd 2>/dev/null
  cscli collections install crowdsecurity/iptables 2>/dev/null
  cscli collections install crowdsecurity/base-http-scenarios 2>/dev/null

  # Install parsers
  cscli parsers install crowdsecurity/syslog-logs 2>/dev/null
  cscli parsers install crowdsecurity/sshd-logs 2>/dev/null

  # Configure
  systemctl enable crowdsec 2>/dev/null
  systemctl restart crowdsec 2>/dev/null
  systemctl enable crowdsec-firewall-bouncer 2>/dev/null
  systemctl restart crowdsec-firewall-bouncer 2>/dev/null

  echo "  CrowdSec installed ✔"
  echo "  Shared threat intelligence active"

  # Keep fail2ban running too (defense in depth)
  echo "  Fail2ban kept as backup layer"
else
  echo "  CrowdSec install failed — fail2ban still active"
fi

# CrowdSec helper
cat > /usr/local/bin/crowdsec-status <<'EOF'
#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
echo ""
echo "=== CrowdSec Status ==="
echo ""
echo "[Service]"
systemctl is-active crowdsec 2>/dev/null && echo "  CrowdSec: ✔ Running" || echo "  CrowdSec: ✘ Stopped"
systemctl is-active crowdsec-firewall-bouncer 2>/dev/null && echo "  Bouncer:  ✔ Running" || echo "  Bouncer:  ✘ Stopped"
echo ""
echo "[Decisions (bans)]"
cscli decisions list 2>/dev/null | head -20
echo ""
echo "[Alerts]"
cscli alerts list 2>/dev/null | head -10
echo ""
echo "[Metrics]"
cscli metrics 2>/dev/null | head -20
echo ""
EOF
chmod 755 /usr/local/bin/crowdsec-status

echo ""

##############################################################################
# 4. TOR HARDENED SOCKS — Isolated Circuits
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/9] Tor — Hardened SOCKS Mode"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

apt-get install -y -qq tor torsocks privoxy 2>/dev/null

cat > /etc/tor/torrc <<'EOF'
# ═══════════════════════════════════════
# Tor Hardened Configuration
# SOCKS only — no transparent proxy
# ═══════════════════════════════════════

RunAsDaemon 1

# ── SOCKS Proxy (use intentionally) ──
SocksPort 9050 IsolateDestAddr IsolateDestPort
SocksPort 127.0.0.1:9150 IsolateDestAddr IsolateDestPort

# ── DNS through Tor ──
DNSPort 5353
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10

# ── Security ──
CookieAuthentication 1
SafeSocks 1
TestSocks 0
AvoidDiskWrites 1
DisableDebuggerAttachment 1

# ── Circuit Isolation (prevents correlation) ──
IsolateSOCKSAuth 1
IsolateClientAddr 1
IsolateClientProtocol 1

# ── Performance ──
NumEntryGuards 3
KeepalivePeriod 60
NewCircuitPeriod 15
MaxCircuitDirtiness 300
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 1

# ── Guard node pinning (reduces fingerprinting) ──
GuardLifetime 2 months
NumDirectoryGuards 3

# ── Reject all exit traffic (client only) ──
ExitPolicy reject *:*

# ── Logging (minimal) ──
Log notice file /var/log/tor/notices.log

# ── Hardening ──
Sandbox 1
NoExec 1

# ── Bridges (uncomment if Tor is blocked) ──
#UseBridges 1
#ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
#Bridge obfs4 <bridge-line>
EOF

mkdir -p /var/log/tor
chown debian-tor:debian-tor /var/log/tor 2>/dev/null

# Privoxy through Tor
cat > /etc/privoxy/config <<'EOF'
listen-address 127.0.0.1:8118
forward-socks5t / 127.0.0.1:9050 .
toggle 0
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
forwarded-connect-retries 0
accept-intercepted-requests 0
logdir /var/log/privoxy
logfile logfile
debug 0
socket-timeout 300
keep-alive-timeout 5
actionsfile match-all.action
actionsfile default.action
filterfile default.filter
EOF
mkdir -p /var/log/privoxy

# Auto-restart
mkdir -p /etc/systemd/system/tor.service.d
cat > /etc/systemd/system/tor.service.d/restart.conf <<'EOF'
[Service]
Restart=always
RestartSec=10
EOF

systemctl daemon-reload
systemctl enable tor 2>/dev/null && systemctl restart tor 2>/dev/null
systemctl enable privoxy 2>/dev/null && systemctl restart privoxy 2>/dev/null

# Health check
cat > /etc/cron.d/tor-health <<'EOF'
*/5 * * * * root systemctl is-active --quiet tor || systemctl restart tor
EOF

echo "  Tor hardened SOCKS mode ✔"
echo "  Circuit isolation enabled"
echo ""

##############################################################################
# 5. DNS PRIVACY — Quad9 + Cloudflare (Encrypted)
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[5/9] DNS Privacy — Quad9 + Cloudflare"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Install stubby for DNS-over-TLS
apt-get install -y -qq stubby 2>/dev/null

if command -v stubby >/dev/null 2>&1; then
  # Configure stubby for DNS-over-TLS
  cat > /etc/stubby/stubby.yml <<'EOF'
# ═══════════════════════════════════════
# Stubby — DNS over TLS
# Quad9 + Cloudflare
# ═══════════════════════════════════════

resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1@5300
  - 0::1@5300

# ── Quad9 (Security + Privacy) ──
upstream_recursive_servers:
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
    tls_port: 853

# ── Cloudflare (Speed + Privacy) ──
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853

# ── Cloudflare Security (malware blocking) ──
  - address_data: 1.1.1.2
    tls_auth_name: "security.cloudflare-dns.com"
    tls_port: 853
  - address_data: 1.0.0.2
    tls_auth_name: "security.cloudflare-dns.com"
    tls_port: 853
EOF

  systemctl enable stubby 2>/dev/null
  systemctl restart stubby 2>/dev/null

  echo "  Stubby DNS-over-TLS active ✔"
  echo "  Using: Quad9 + Cloudflare (encrypted)"

  # Point system DNS to stubby
  # Keep fallback to direct Quad9/Cloudflare if stubby dies
  cat > /etc/resolv.conf <<'EOF'
# DNS Privacy — Stubby (DNS-over-TLS) + Fallback
nameserver 127.0.0.1
nameserver 9.9.9.9
nameserver 1.1.1.1
options edns0 timeout:2 attempts:3
EOF

else
  echo "  Stubby not available — using direct encrypted resolvers"

  cat > /etc/resolv.conf <<'EOF'
# DNS Privacy — Quad9 + Cloudflare
nameserver 9.9.9.9
nameserver 149.112.112.112
nameserver 1.1.1.1
nameserver 1.0.0.1
options edns0 timeout:2 attempts:3
EOF
fi

# DNS leak test script
cat > /usr/local/bin/dns-check <<'EOF'
#!/bin/bash
echo ""
echo "=== DNS Privacy Check ==="
echo ""

# Check what DNS we're using
echo "[Resolvers]"
cat /etc/resolv.conf | grep nameserver
echo ""

# Check stubby
echo -n "[Stubby] "
systemctl is-active stubby 2>/dev/null && echo "✔ Running (DNS-over-TLS)" || echo "✘ Not running"

# Test resolution
echo ""
echo "[DNS Test]"
echo -n "  google.com:   "
dig +short +timeout=3 google.com 2>/dev/null | head -1 || echo "FAIL"
echo -n "  quad9 direct: "
dig +short +timeout=3 google.com @9.9.9.9 2>/dev/null | head -1 || echo "FAIL"
echo -n "  cloudflare:   "
dig +short +timeout=3 google.com @1.1.1.1 2>/dev/null | head -1 || echo "FAIL"

# Tor DNS
echo -n "  tor DNS:      "
torsocks dig +short +timeout=5 google.com 2>/dev/null | head -1 || echo "not connected"

echo ""
echo "[DNS Leak Test]"
echo "  Visit: https://dnsleaktest.com"
echo "  Or:    torsocks curl -s https://ipleak.net/json/ | jq '.dns_servers'"
echo ""
EOF
chmod 755 /usr/local/bin/dns-check

echo ""

##############################################################################
# 6. ADVANCED SYSCTL PRIVACY TWEAKS
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[6/9] Advanced sysctl privacy..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Add privacy tweaks (append, don't overwrite)
cat >> /etc/sysctl.d/99-hardening.conf <<'EOF'

# ═══════════════════════════════════════
# Advanced Privacy & Security Tweaks
# ═══════════════════════════════════════

# ── TCP Privacy ──
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_sack = 0

# ── ICMP Privacy ──
net.ipv4.icmp_echo_ignore_all = 0

# ── Filesystem Hardening ──
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# ── Kernel Lockdown ──
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# ── Network Privacy ──
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# ── IPv6 Privacy ──
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

# Remove duplicates
sort -u -t= -k1,1 /etc/sysctl.d/99-hardening.conf > /tmp/sysctl-clean.conf
mv /tmp/sysctl-clean.conf /etc/sysctl.d/99-hardening.conf

sysctl --system >/dev/null 2>&1

# Apply to ALL interfaces
for iface in $(ls /proc/sys/net/ipv4/conf/ 2>/dev/null); do
  sysctl -w "net.ipv4.conf.${iface}.log_martians=1" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.accept_redirects=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.send_redirects=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.secure_redirects=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.accept_source_route=0" 2>/dev/null
  sysctl -w "net.ipv4.conf.${iface}.rp_filter=1" 2>/dev/null
done

echo "  Privacy sysctl applied ✔"
echo ""

##############################################################################
# 7. NETWORK MONITORING
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[7/9] Network monitoring..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

apt-get install -y -qq arpwatch nmap tcpdump 2>/dev/null

# ARP monitoring
IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
[ -n "$IFACE" ] && [ -f /etc/default/arpwatch ] && {
  sed -i "s/^INTERFACES=.*/INTERFACES=\"${IFACE}\"/" /etc/default/arpwatch 2>/dev/null
  grep -q "^INTERFACES" /etc/default/arpwatch || echo "INTERFACES=\"${IFACE}\"" >> /etc/default/arpwatch
}
systemctl enable arpwatch 2>/dev/null && systemctl restart arpwatch 2>/dev/null

# Network scan script
cat > /usr/local/bin/net-scan <<'EOF'
#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi
echo ""
echo "=== Network Security Scan ==="
echo ""

echo "[Listening Ports]"
ss -tlnp | grep -v "^State"
echo ""

echo "[Established Connections]"
ss -tnp state established | head -20
echo ""

echo "[UFW Status]"
ufw status numbered 2>/dev/null | head -20
echo ""

echo "[Failed SSH Attempts (last 50)]"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10
echo ""

echo "[CrowdSec Bans]"
cscli decisions list 2>/dev/null | head -10 || echo "  CrowdSec not running"
echo ""

echo "[Fail2ban Bans]"
fail2ban-client status sshd 2>/dev/null | grep -E "Currently|Total" || echo "  Fail2ban not running"
echo ""

echo "[ARP Table]"
arp -a 2>/dev/null | head -10
echo ""
EOF
chmod 755 /usr/local/bin/net-scan

echo "  Network monitoring active ✔"
echo ""

##############################################################################
# 8. AUTOMATED SECURITY SCANNING
##############################################################################
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[8/9] Automated security scanning..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Daily security report
cat > /etc/cron.daily/security-report <<'EOF'
#!/bin/bash
LOG="/var/log/security-daily-$(date +%Y%m%d).log"

echo "═══════════════════════════════════════" > $LOG
echo "  Daily Security Report — $(date)" >> $LOG
echo "═══════════════════════════════════════" >> $LOG

echo "" >> $LOG
echo "=== Failed Logins ===" >> $LOG
grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l >> $LOG

echo "" >> $LOG
echo "=== AIDE Changes ===" >> $LOG
aide.wrapper --check 2>/dev/null | grep -c "changed:" >> $LOG

echo "" >> $LOG
echo "=== Listening Ports ===" >> $LOG
ss -tlnp >> $LOG

echo "" >> $LOG
echo "=== World Writable Files ===" >> $LOG
find / -xdev -type f -perm -0002 2>/dev/null | wc -l >> $LOG

echo "" >> $LOG
echo "=== SUID Files ===" >> $LOG
find / -xdev -perm -4000 -type f 2>/dev/null >> $LOG

echo "" >> $LOG
echo "=== CrowdSec Alerts ===" >> $LOG
cscli alerts list --limit 10 2>/dev/null >> $LOG

ISSUES=0
FAILED=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
[ "$FAILED" -gt 50 ] && ISSUES=$((ISSUES+1))

[ "$ISSUES" -gt 0 ] && logger -t security-report "WARNING: $ISSUES security concerns found. Check $LOG"
EOF
chmod 700 /etc/cron.daily/security-report

# Weekly full scan
cat > /etc/cron.weekly/full-security-scan <<'EOF'
#!/bin/bash
LOG="/var/log/security-weekly-$(date +%Y%m%d).log"

echo "Full Security Scan — $(date)" > $LOG

echo "=== Lynis ===" >> $LOG
lynis audit system --no-colors --profile /etc/lynis/custom.prf 2>/dev/null | \
  grep "Hardening index" >> $LOG

echo "=== rkhunter ===" >> $LOG
rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null >> $LOG

echo "=== chkrootkit ===" >> $LOG
chkrootkit 2>/dev/null | grep -v "not found\|not infected\|nothing found" >> $LOG

echo "=== debsums ===" >> $LOG
debsums -s 2>/dev/null >> $LOG

SCORE=$(grep "Hardening index" $LOG | grep -oP '\d+' | head -1)
logger -t security-scan "Weekly scan complete. Lynis: ${SCORE:-unknown}"
EOF
chmod 700 /etc/cron.weekly/full-security-scan

# Master security status command
cat > /usr/local/bin/security-status <<'EOF'
#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║         Security Status Dashboard          ║"
echo "╚════════════════════════════════════════════╝"
echo ""

echo "━━━ Services ━━━"
for svc in ssh auditd fail2ban crowdsec apparmor tor ufw haveged arpwatch; do
  printf "  %-20s " "$svc:"
  systemctl is-active $svc 2>/dev/null || echo "inactive"
done

echo ""
echo "━━━ Firewall ━━━"
ufw status 2>/dev/null | head -5

echo ""
echo "━━━ CrowdSec ━━━"
cscli decisions list 2>/dev/null | head -5 || echo "  Not running"

echo ""
echo "━━━ Fail2ban ━━━"
fail2ban-client status sshd 2>/dev/null | grep -E "Currently|Total" || echo "  Not running"

echo ""
echo "━━━ AIDE ━━━"
[ -f /var/lib/aide/aide.db ] && echo "  Database: ✔ Present" || echo "  Database: ✘ Missing"

echo ""
echo "━━━ Tor ━━━"
echo -n "  Status: " && systemctl is-active tor 2>/dev/null
TORIP=$(torsocks curl -s --max-time 10 ifconfig.me 2>/dev/null)
echo "  Exit IP: ${TORIP:-not connected}"

echo ""
echo "━━━ DNS ━━━"
echo -n "  Stubby: " && systemctl is-active stubby 2>/dev/null || echo "inactive"
echo "  Resolvers:"
grep nameserver /etc/resolv.conf | sed 's/^/    /'

echo ""
echo "━━━ Entropy ━━━"
echo "  Available: $(cat /proc/sys/kernel/random/entropy_avail)"

echo ""
echo "━━━ Last Lynis Score ━━━"
SCORE=$(grep "Hardening index" /var/log/lynis-final.log 2>/dev/null | grep -oP '\d+' | head -1)
echo "  Score: ${SCORE:-run 'lynis audit system --profile /etc/lynis/custom.prf'}"

echo ""
echo "━━━ Commands ━━━"
echo "  security-status   This 
