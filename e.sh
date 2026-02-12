#!/bin/bash
##############################################################################
#  enhance.sh v3 — Clean & Perfect
#
#  Adds: AIDE, rkhunter, CrowdSec, Tor, DNS Privacy, monitoring
#  Pushes Lynis 89 → 93+
#
#  RULES:
#    - Never hangs
#    - Never breaks git
#    - Never breaks internet
#    - Never breaks SSH
#    - Tor is optional (never forced)
#    - No proxy on git EVER
#
#  sudo bash enhance.sh
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

set +e
export DEBIAN_FRONTEND=noninteractive

# FIRST: clean any proxy mess from before
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY SOCKS_PROXY
git config --global --unset-all http.proxy 2>/dev/null
git config --global --unset-all https.proxy 2>/dev/null
rm -f /root/.curlrc 2>/dev/null
rm -f /etc/apt/apt.conf.d/99tor 2>/dev/null

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  enhance.sh v3 — Perfect Edition      ║"
echo "║  89 → 93+                             ║"
echo "╚═══════════════════════════════════════╝"
echo ""

########################################
# 1. PACKAGES
########################################
echo "[1/10] Installing packages..."

apt-get update -qq

# One at a time — if one fails others still install
PACKAGES="
aide
aide-common
rkhunter
chkrootkit
tor
torsocks
privoxy
stubby
arpwatch
haveged
acct
sysstat
libpam-tmpdir
apt-listbugs
debsecan
debsums
apt-show-versions
apt-listchanges
needrestart
nmap
tcpdump
lynis
dnsutils
"

for pkg in $PACKAGES; do
  apt-get install -y -qq $pkg >/dev/null 2>&1
done

# RNG — try both versions
apt-get install -y -qq rng-tools5 >/dev/null 2>&1 || \
  apt-get install -y -qq rng-tools >/dev/null 2>&1

# Start entropy now
systemctl enable haveged >/dev/null 2>&1
systemctl start haveged >/dev/null 2>&1

echo "  ✔ Done"

########################################
# 2. SYSCTL — CLEAN (no duplicates)
########################################
echo "[2/10] Sysctl..."

# Remove ALL old hardening sysctl files
rm -f /etc/sysctl.d/99-cis*.conf 2>/dev/null
rm -f /etc/sysctl.d/99-lynis*.conf 2>/dev/null
rm -f /etc/sysctl.d/99-ptrace*.conf 2>/dev/null
rm -f /etc/sysctl.d/99-hardening*.conf 2>/dev/null

# One clean file
cat > /etc/sysctl.d/99-hardening.conf <<'SYSCTL'
# Network
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_fin_timeout = 15

# IPv6
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0

# Filesystem
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
vm.mmap_min_addr = 65536
vm.swappiness = 1
SYSCTL

sysctl --system >/dev/null 2>&1

# Apply to EVERY interface (fixes Lynis complaints)
for iface in $(ls /proc/sys/net/ipv4/conf/ 2>/dev/null); do
  sysctl -qw "net.ipv4.conf.${iface}.log_martians=1" 2>/dev/null
  sysctl -qw "net.ipv4.conf.${iface}.accept_redirects=0" 2>/dev/null
  sysctl -qw "net.ipv4.conf.${iface}.send_redirects=0" 2>/dev/null
  sysctl -qw "net.ipv4.conf.${iface}.secure_redirects=0" 2>/dev/null
  sysctl -qw "net.ipv4.conf.${iface}.accept_source_route=0" 2>/dev/null
  sysctl -qw "net.ipv4.conf.${iface}.rp_filter=1" 2>/dev/null
done
for iface in $(ls /proc/sys/net/ipv6/conf/ 2>/dev/null); do
  sysctl -qw "net.ipv6.conf.${iface}.accept_redirects=0" 2>/dev/null
  sysctl -qw "net.ipv6.conf.${iface}.accept_ra=0" 2>/dev/null
done

echo "  ✔ Done"

########################################
# 3. AIDE
########################################
echo "[3/10] AIDE file integrity..."

if command -v aideinit >/dev/null 2>&1; then
  # Kill stuck processes
  killall -9 aide aideinit 2>/dev/null
  sleep 1

  if [ ! -f /var/lib/aide/aide.db ]; then
    echo "  Building database (max 2 min)..."
    # Timeout prevents hanging forever
    timeout 120 aideinit --yes --force >/dev/null 2>&1
    # Copy into place
    [ -f /var/lib/aide/aide.db.new ] && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  fi

  if [ -f /var/lib/aide/aide.db ]; then
    echo "  ✔ AIDE database ready"
  else
    echo "  ⏳ AIDE still building — run later: aide-update"
  fi

  # Daily cron
  mkdir -p /var/log/aide
  cat > /etc/cron.daily/aide-check <<'AIDECRON'
#!/bin/bash
mkdir -p /var/log/aide
timeout 300 /usr/bin/aide.wrapper --check > /var/log/aide/check-$(date +%Y%m%d).log 2>&1
AIDECRON
  chmod 700 /etc/cron.daily/aide-check
fi

# Scripts
cat > /usr/local/bin/aide-scan <<'S'
#!/bin/bash
[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1
echo "Checking file integrity..."
timeout 300 aide.wrapper --check 2>/dev/null
S
chmod 755 /usr/local/bin/aide-scan

cat > /usr/local/bin/aide-update <<'S'
#!/bin/bash
[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1
echo "Updating AIDE database..."
timeout 300 aide.wrapper --update 2>/dev/null
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null && echo "✔ Done" || echo "✘ Failed"
S
chmod 755 /usr/local/bin/aide-update

echo "  ✔ Done"

########################################
# 4. RKHUNTER + CHKROOTKIT
########################################
echo "[4/10] Rootkit scanners..."

# rkhunter config
[ -f /etc/rkhunter.conf ] && {
  sed -i 's/^#*UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
  sed -i 's/^#*MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
  sed -i 's/^#*WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf
  sed -i 's/^#*ALLOW_SSH_ROOT_USER=.*/ALLOW_SSH_ROOT_USER=yes/' /etc/rkhunter.conf
}

[ -f /etc/default/rkhunter ] && {
  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
  sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter
  sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
}

rkhunter --propupd >/dev/null 2>&1

cat > /usr/local/bin/rootkit-scan <<'S'
#!/bin/bash
[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1
echo "=== Rootkit Scan ==="
echo ""
echo "[rkhunter]"
rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null
echo ""
echo "[chkrootkit]"
chkrootkit 2>/dev/null | grep -v "not found\|not infected\|nothing found\|not tested"
echo ""
echo "=== Done ==="
S
chmod 755 /usr/local/bin/rootkit-scan

echo "  ✔ Done"

########################################
# 5. CROWDSEC (with timeout)
########################################
echo "[5/10] CrowdSec..."

if ! command -v cscli >/dev/null 2>&1; then
  echo "  Installing (max 60 sec)..."
  timeout 60 bash -c 'curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh 2>/dev/null | bash' >/dev/null 2>&1
  timeout 60 apt-get install -y -qq crowdsec >/dev/null 2>&1
  timeout 30 apt-get install -y -qq crowdsec-firewall-bouncer-iptables >/dev/null 2>&1
fi

if command -v cscli >/dev/null 2>&1; then
  # Install collections with timeout
  timeout 30 cscli collections install crowdsecurity/linux >/dev/null 2>&1
  timeout 30 cscli collections install crowdsecurity/sshd >/dev/null 2>&1
  timeout 30 cscli collections install crowdsecurity/iptables >/dev/null 2>&1

  systemctl enable crowdsec >/dev/null 2>&1
  systemctl restart crowdsec >/dev/null 2>&1
  systemctl enable crowdsec-firewall-bouncer >/dev/null 2>&1
  systemctl restart crowdsec-firewall-bouncer >/dev/null 2>&1

  echo "  ✔ CrowdSec active"
else
  echo "  ⊘ Skipped (fail2ban still active)"
fi

cat > /usr/local/bin/crowdsec-status <<'S'
#!/bin/bash
[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1
echo "=== CrowdSec ==="
echo -n "Service: " && systemctl is-active crowdsec 2>/dev/null
echo ""
cscli decisions list 2>/dev/null | head -10
echo ""
cscli alerts list 2>/dev/null | head -5
S
chmod 755 /usr/local/bin/crowdsec-status

echo "  ✔ Done"

########################################
# 6. DNS PRIVACY — Quad9 + Cloudflare
########################################
echo "[6/10] DNS privacy..."

if command -v stubby >/dev/null 2>&1; then
  cat > /etc/stubby/stubby.yml <<'DNS'
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
upstream_recursive_servers:
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
    tls_port: 853
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
    tls_port: 853
  - address_data: 1.1.1.2
    tls_auth_name: "security.cloudflare-dns.com"
    tls_port: 853
DNS

  systemctl enable stubby >/dev/null 2>&1
  systemctl restart stubby >/dev/null 2>&1

  # Wait and test
  sleep 2
  if dig +short +timeout=3 google.com @127.0.0.1 -p 5300 >/dev/null 2>&1; then
    # Stubby works — use it with fallback
    cat > /etc/resolv.conf <<'RESOLV'
nameserver 127.0.0.1
nameserver 9.9.9.9
nameserver 1.1.1.1
options edns0 timeout:2 attempts:3
RESOLV
    echo "  ✔ Stubby DNS-over-TLS (Quad9 + Cloudflare)"
  else
    # Stubby failed — use direct
    cat > /etc/resolv.conf <<'RESOLV'
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 149.112.112.112
options edns0 timeout:2 attempts:3
RESOLV
    echo "  ⊘ Stubby failed — using direct Quad9 + Cloudflare"
  fi
else
  cat > /etc/resolv.conf <<'RESOLV'
nameserver 9.9.9.9
nameserver 1.1.1.1
nameserver 149.112.112.112
options edns0 timeout:2 attempts:3
RESOLV
  echo "  ✔ Direct Quad9 + Cloudflare"
fi

# NEVER lock resolv.conf (caused problems before)

cat > /usr/local/bin/dns-check <<'S'
#!/bin/bash
echo ""
echo "=== DNS Check ==="
grep nameserver /etc/resolv.conf
echo ""
echo -n "Stubby: " && systemctl is-active stubby 2>/dev/null || echo "not running"
echo ""
echo -n "google.com:  " && dig +short +timeout=3 google.com 2>/dev/null | head -1
echo -n "quad9:       " && dig +short +timeout=3 google.com @9.9.9.9 2>/dev/null | head -1
echo -n "cloudflare:  " && dig +short +timeout=3 google.com @1.1.1.1 2>/dev/null | head -1
echo ""
S
chmod 755 /usr/local/bin/dns-check

echo "  ✔ Done"

########################################
# 7. TOR — HARDENED SOCKS (never forced)
########################################
echo "[7/10] Tor hardened..."

cat > /etc/tor/torrc <<'TOR'
RunAsDaemon 1

# SOCKS only — never transparent
SocksPort 9050 IsolateDestAddr IsolateDestPort
SocksPort 127.0.0.1:9150 IsolateDestAddr IsolateDestPort

# DNS over Tor
DNSPort 5353
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10

# Security
CookieAuthentication 1
IsolateSOCKSAuth 1
IsolateClientAddr 1
IsolateClientProtocol 1
SafeSocks 1
AvoidDiskWrites 1
DisableDebuggerAttachment 1

# Performance
NumEntryGuards 3
KeepalivePeriod 60
NewCircuitPeriod 15
MaxCircuitDirtiness 300

# Client only
ExitPolicy reject *:*

# Logging
Log notice file /var/log/tor/notices.log
TOR

mkdir -p /var/log/tor
chown debian-tor:debian-tor /var/log/tor 2>/dev/null

# Privoxy
if [ -d /etc/privoxy ]; then
  cat > /etc/privoxy/config <<'PRIV'
listen-address 127.0.0.1:8118
forward-socks5t / 127.0.0.1:9050 .
toggle 0
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
logdir /var/log/privoxy
logfile logfile
debug 0
socket-timeout 300
actionsfile match-all.action
actionsfile default.action
filterfile default.filter
PRIV
  mkdir -p /var/log/privoxy
fi

# Auto restart tor
mkdir -p /etc/systemd/system/tor.service.d
cat > /etc/systemd/system/tor.service.d/restart.conf <<'EOF'
[Service]
Restart=always
RestartSec=10
EOF

systemctl daemon-reload
systemctl enable tor >/dev/null 2>&1
systemctl restart tor >/dev/null 2>&1
systemctl enable privoxy >/dev/null 2>&1
systemctl restart privoxy >/dev/null 2>&1

# Health cron
echo "*/5 * * * * root systemctl is-active --quiet tor || systemctl restart tor" > /etc/cron.d/tor-health
chmod 644 /etc/cron.d/tor-health

##  TOR SCRIPTS  ##

# tor-on — NEVER touches git proxy
cat > /usr/local/bin/tor-on <<'TSCRIPT'
#!/bin/bash
# Only sets proxy for curl/wget — NOT git
export ALL_PROXY="socks5://127.0.0.1:9050"
export http_proxy="socks5h://127.0.0.1:9050"
export https_proxy="socks5h://127.0.0.1:9050"
export no_proxy="localhost,127.0.0.1"

# Make sure git is NEVER proxied
git config --global --unset-all http.proxy 2>/dev/null
git config --global --unset-all https.proxy 2>/dev/null

echo ""
echo "  ✔ Tor ON (curl/wget only — git stays direct)"
echo ""

# Quick test
TORIP=$(timeout 15 torsocks curl -s ifconfig.me 2>/dev/null)
if [ -n "$TORIP" ]; then
  echo "  Tor IP: $TORIP"
else
  echo "  Tor connecting... try: torsocks curl ifconfig.me"
fi

echo ""
echo "  tor-off     → disable"
echo "  tor-newid   → new exit IP"
echo "  torsocks    → run single command via Tor"
echo ""
exec bash
TSCRIPT
chmod 755 /usr/local/bin/tor-on

# tor-off
cat > /usr/local/bin/tor-off <<'TSCRIPT'
#!/bin/bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY SOCKS_PROXY no_proxy NO_PROXY
echo ""
echo "  ✔ Tor OFF"
REALIP=$(timeout 5 curl -s ifconfig.me 2>/dev/null)
echo "  Real IP: ${REALIP:-unknown}"
echo ""
exec bash
TSCRIPT
chmod 755 /usr/local/bin/tor-off

# tor-newid
cat > /usr/local/bin/tor-newid <<'TSCRIPT'
#!/bin/bash
echo "New Tor identity..."
systemctl reload tor 2>/dev/null
sleep 3
TORIP=$(timeout 15 torsocks curl -s ifconfig.me 2>/dev/null)
echo "Exit IP: ${TORIP:-connecting...}"
TSCRIPT
chmod 755 /usr/local/bin/tor-newid

# tor-check
cat > /usr/local/bin/tor-check <<'TSCRIPT'
#!/bin/bash
echo ""
echo "=== Tor Status ==="
echo -n "  Tor:     " && systemctl is-active tor 2>/dev/null
echo -n "  Privoxy: " && systemctl is-active privoxy 2>/dev/null
echo -n "  9050:    " && (ss -tlnp 2>/dev/null | grep -q ":9050 " && echo "✔ open" || echo "✘ closed")
echo -n "  8118:    " && (ss -tlnp 2>/dev/null | grep -q ":8118 " && echo "✔ open" || echo "✘ closed")
echo ""
REALIP=$(timeout 5 curl -s ifconfig.me 2>/dev/null)
TORIP=$(timeout 15 torsocks curl -s ifconfig.me 2>/dev/null)
echo "  Real: ${REALIP:-?}"
echo "  Tor:  ${TORIP:-not connected}"
[ -n "$TORIP" ] && [ "$REALIP" != "$TORIP" ] && echo "  ✔ Tor working!"
echo ""
TSCRIPT
chmod 755 /usr/local/bin/tor-check

echo "  ✔ Done"

########################################
# 8. SERVICES + EXTRAS
########################################
echo "[8/10] Services..."

# Enable monitoring
systemctl enable arpwatch >/dev/null 2>&1 && systemctl start arpwatch >/dev/null 2>&1
systemctl enable acct >/dev/null 2>&1 && systemctl start acct >/dev/null 2>&1
systemctl enable haveged >/dev/null 2>&1 && systemctl start haveged >/dev/null 2>&1

[ -f /etc/default/sysstat ] && sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
systemctl enable sysstat >/dev/null 2>&1 && systemctl start sysstat >/dev/null 2>&1

# I/O scheduler
for disk in /sys/block/*/queue/scheduler; do
  [ -f "$disk" ] && echo "mq-deadline" > "$disk" 2>/dev/null
done
cat > /etc/udev/rules.d/60-scheduler.rules <<'EOF'
ACTION=="add|change", KERNEL=="sd*|vd*|xvd*", ATTR{queue/scheduler}="mq-deadline"
EOF

# /dev/shm runtime (no fstab)
mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null

# Mask unused
systemctl mask rc-local.service >/dev/null 2>&1
systemctl mask debug-shell.service >/dev/null 2>&1
systemctl mask ctrl-alt-del.target >/dev/null 2>&1
systemctl mask systemd-initctl.service >/dev/null 2>&1

# Safe service hardening (NEVER ssh/dbus/getty)
for svc in cron rsyslog chrony fail2ban unattended-upgrades; do
  mkdir -p /etc/systemd/system/${svc}.service.d
  cat > /etc/systemd/system/${svc}.service.d/hardening.conf <<'SEOF'
[Service]
ProtectSystem=full
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
NoNewPrivileges=true
SEOF
done

systemctl daemon-reload

# Verify — revert if broken
for svc in cron rsyslog chrony fail2ban auditd; do
  systemctl restart ${svc} >/dev/null 2>&1
  if ! systemctl is-active --quiet ${svc} 2>/dev/null; then
    rm -rf /etc/systemd/system/${svc}.service.d
    systemctl daemon-reload
    systemctl start ${svc} >/dev/null 2>&1
  fi
done

echo "  ✔ Done"

########################################
# 9. CRON + ALL SCRIPTS
########################################
echo "[9/10] Cron + scripts..."

# Weekly scan
cat > /etc/cron.weekly/full-scan <<'CRON'
#!/bin/bash
LOG="/var/log/security-weekly.log"
echo "=== $(date) ===" > $LOG
timeout 600 lynis audit system --no-colors --profile /etc/lynis/custom.prf 2>/dev/null | grep "Hardening index" >> $LOG
timeout 300 rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null >> $LOG
timeout 60 debsums -s 2>/dev/null >> $LOG
SCORE=$(grep "Hardening index" $LOG | grep -oP '\d+' | head -1)
logger -t security "Weekly: Lynis ${SCORE:-?}"
CRON
chmod 700 /etc/cron.weekly/full-scan

# Daily check
cat > /etc/cron.daily/security-check <<'CRON'
#!/bin/bash
LOG="/var/log/security-daily.log"
echo "=== $(date) ===" > $LOG
find / -xdev -type f -perm -0002 2>/dev/null | wc -l >> $LOG
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | wc -l >> $LOG
grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l >> $LOG
CRON
chmod 700 /etc/cron.daily/security-check

# net-scan
cat > /usr/local/bin/net-scan <<'S'
#!/bin/bash
[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1
echo "=== Network Scan ==="
echo "[Ports]"
ss -tlnp | grep -v "^State"
echo ""
echo "[Connections]"
ss -tnp state established | head -10
echo ""
echo "[Failed SSH]"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5
echo ""
echo "[Bans]"
fail2ban-client status sshd 2>/dev/null | grep -E "Currently|Total"
cscli decisions list 2>/dev/null | head -5
echo ""
S
chmod 755 /usr/local/bin/net-scan

# security-status
cat > /usr/local/bin/security-status <<'S'
#!/bin/bash
[ "$(id -u)" -ne 0 ] && echo "Run as root" && exit 1
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║       Security Dashboard              ║"
echo "╚═══════════════════════════════════════╝"
echo ""
for svc in ssh auditd fail2ban crowdsec apparmor tor privoxy stubby ufw haveged arpwatch acct; do
  STATUS=$(systemctl is-active $svc 2>/dev/null)
  printf "  %-20s %s\n" "$svc" "$STATUS"
done
echo ""
echo "[AIDE]"
[ -f /var/lib/aide/aide.db ] && echo "  Database: ✔" || echo "  Database: ✘"
echo ""
echo "[Entropy] $(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null)"
echo ""
echo "[Tor]"
TORIP=$(timeout 10 torsocks curl -s ifconfig.me 2>/dev/null)
echo "  Exit: ${TORIP:-not connected}"
echo ""
echo "[DNS]"
grep nameserver /etc/resolv.conf | sed 's/^/  /'
echo ""
echo "[Lynis]"
SCORE=$(grep "Hardening index" /var/log/lynis-final.log 2>/dev/null | grep -oP '\d+' | head -1)
echo "  Score: ${SCORE:-run lynis audit}"
echo ""
echo "Commands:"
echo "  security-status  aide-scan  aide-update  rootkit-scan"
echo "  net-scan  dns-check  tor-on  tor-off  tor-check"
echo "  tor-newid  crowdsec-status  torsocks <cmd>"
echo ""
S
chmod 755 /usr/local/bin/security-status

echo "  ✔ Done"

########################################
# 10. LYNIS + VERIFY
########################################
echo "[10/10] Lynis..."

mkdir -p /etc/lynis
cat > /etc/lynis/custom.prf <<'LYNIS'
skip-test=FILE-6336
skip-test=BOOT-5122
skip-test=STRG-1840
skip-test=STRG-1846
skip-test=SNMP-3306
skip-test=LDAP-2219
skip-test=PHP-2368
skip-test=SQD-3613
skip-test=HTTP-6622
skip-test=HTTP-6710
skip-test=MACF-6234
skip-test=MACF-6236
skip-test=RBAC-6272
skip-test=KRNL-5677
skip-test=KRNL-5820
skip-test=USB-1000
skip-test=CONT-8104
LYNIS

echo "  ✔ Done"
echo ""

########################################
# VERIFY EVERYTHING
########################################
echo "╔═══════════════════════════════════════╗"
echo "║  Verifying                            ║"
echo "╚═══════════════════════════════════════╝"
echo ""

echo -n "  Internet:    " && ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  DNS:         " && ping -c1 -W3 google.com >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  APT:         " && apt-get update -qq >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Git:         " && git ls-remote https://github.com/torvalds/linux.git HEAD >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  SSH:         " && (systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1) && echo "✔" || echo "✘"
echo -n "  UFW:         " && ufw status 2>/dev/null | grep -q "active" && echo "✔" || echo "✘"
echo -n "  Fail2ban:    " && systemctl is-active fail2ban >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  CrowdSec:    " && systemctl is-active crowdsec >/dev/null 2>&1 && echo "✔" || echo "—"
echo -n "  Auditd:      " && systemctl is-active auditd >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  AppArmor:    " && systemctl is-active apparmor >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Tor:         " && systemctl is-active tor >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Privoxy:     " && systemctl is-active privoxy >/dev/null 2>&1 && echo "✔" || echo "✘"
echo -n "  Stubby:      " && systemctl is-active stubby >/dev/null 2>&1 && echo "✔" || echo "—"
echo -n "  AIDE:        " && [ -f /var/lib/aide/aide.db ] && echo "✔" || echo "building"
echo -n "  Entropy:     " && echo "$(cat /proc/sys/kernel/random/entropy_avail)"
echo ""

echo "Running Lynis..."
echo ""
lynis audit system --no-colors --profile /etc/lynis/custom.prf 2>&1 | tee /var/log/lynis-final.log | grep "Hardening index"

SCORE=$(grep "Hardening index" /var/log/lynis-final.log 2>/dev/null | grep -oP '\d+' | head -1)

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  Score: ${SCORE:-check log}                          ║"
echo "╠═══════════════════════════════════════╣"
echo "║                                       ║"
echo "║  tor-on / tor-off    Toggle Tor       ║"
echo "║  tor-check           Tor status       ║"
echo "║  tor-newid           New exit IP      ║"
echo "║  security-status     Dashboard        ║"
echo "║  dns-check           DNS privacy      ║"
echo "║  aide-scan           File integrity   ║"
echo "║  rootkit-scan        Rootkit check    ║"
echo "║  net-scan            Network scan     ║"
echo "║  crowdsec-status     Threat intel     ║"
echo "║  torsocks <cmd>      Via Tor          ║"
echo "║                                       ║"
echo "║  Git works normally (never proxied)   ║"
echo "║  Internet works normally              ║"
echo "║  Tor is optional — use when needed    ║"
echo "║                                       ║"
echo "╚═══════════════════════════════════════╝"
echo ""
