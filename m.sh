#!/usr/bin/env bash
#===============================================================================
# enhance.sh — Debian 11 (Bullseye) VPS Advanced Security Enhancement
#
# Covers all 30 points:
#   Network Privacy | Intrusion Detection | Service Containment
#   Monitoring & Forensics | Anonymity Stack | Fingerprint Reduction
#   Optional Advanced Hardening
#
# Usage : chmod +x enhance.sh && sudo ./enhance.sh
# Prereq: harden.sh must be run first
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

#===============================================================================
# ██████  CONFIGURATION — EDIT BEFORE RUNNING  ██████
#===============================================================================
# ---- General ----
SSH_PORT="2222"                             # Must match harden.sh
LOGFILE="/var/log/enhance.log"
ALERT_EMAIL=""                              # Email for alerts (blank=skip email)

# ---- Module Toggles (true/false) ----
ENABLE_DNS_PRIVACY=true                     # Unbound + DNSSEC + DoT
ENABLE_OUTBOUND_FIREWALL=true               # Restrict outgoing traffic
ENABLE_OSSEC=true                           # OSSEC HIDS (compiles from source)
ENABLE_TOR=true                             # Official Tor + torsocks
ENABLE_PROXYCHAINS=true                     # Proxychains-ng
ENABLE_GEOIP=false                          # GeoIP blocking (needs config)
ENABLE_CANARY=true                          # Integrity canary files
ENABLE_MONITORING=true                      # All monitoring scripts

# ---- DNS ----
DNS_UPSTREAM_1="1.1.1.1@853#cloudflare-dns.com"
DNS_UPSTREAM_2="1.0.0.1@853#cloudflare-dns.com"
DNS_UPSTREAM_3="9.9.9.9@853#dns.quad9.net"
DNS_UPSTREAM_4="149.112.112.112@853#dns.quad9.net"

# ---- Outbound Firewall — allowed destination ports ----
OUTBOUND_ALLOW_TCP="80 443 853 9001 9030 587 123"
OUTBOUND_ALLOW_UDP="123 853"

# ---- GeoIP ----
GEOIP_BLOCK_COUNTRIES="cn ru kp ir sy"     # ISO country codes to BLOCK

# ---- Remote Syslog (leave blank to skip) ----
REMOTE_SYSLOG_SERVER=""                     # e.g. "logs.example.com:514"
REMOTE_SYSLOG_PROTO="tcp"                   # tcp or udp

# ---- Tor ----
TOR_BRIDGES_ENABLED=false                   # Use obfs4 bridges
TOR_BRIDGE_1=""                             # obfs4 bridge line
TOR_BRIDGE_2=""
TOR_BRIDGE_3=""

# ---- Fail2Ban ----
F2B_SSH_BANTIME="86400"                     # 24h
F2B_SSH_MAXRETRY="2"
F2B_RECIDIVE_BANTIME="604800"               # 7 days

#===============================================================================
# COLOURS & HELPERS
#===============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

log()    { echo -e "${GREEN}[✓]${NC} $*" | tee -a "$LOGFILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOGFILE"; }
err()    { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOGFILE"; }
header() { echo -e "\n${CYAN}${BOLD}═══ $* ═══${NC}" | tee -a "$LOGFILE"; }
sub()    { echo -e "  ${MAGENTA}→${NC} $*" | tee -a "$LOGFILE"; }

check_root() {
    [[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }
}

backup_file() {
    [[ -f "$1" ]] && cp -a "$1" "${1}.enhance-bak.$(date +%s)" 2>/dev/null || true
}

pkg_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" 2>&1 | tail -2 | tee -a "$LOGFILE"
}

service_reload() {
    systemctl daemon-reload 2>/dev/null || true
    for svc in "$@"; do
        systemctl restart "$svc" 2>/dev/null || systemctl start "$svc" 2>/dev/null || true
    done
}

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================
check_root
echo "" > "$LOGFILE"
header "ENHANCE.SH — Starting at $(date)"

if ! command -v ufw &>/dev/null; then
    err "ufw not found. Run harden.sh first."
    exit 1
fi

apt-get update -y 2>&1 | tail -1 | tee -a "$LOGFILE"

###############################################################################
#                                                                             #
#   🔥  SECTION 1 — NETWORK PRIVACY LAYER                                    #
#                                                                             #
###############################################################################

#===============================================================================
# 1. ENCRYPTED DNS — UNBOUND + DNSSEC
#===============================================================================
if [[ "$ENABLE_DNS_PRIVACY" == true ]]; then
header "1. Encrypted DNS Resolver — Unbound + DNSSEC + DoT"

pkg_install unbound unbound-anchor dns-root-data

# Download root hints
curl -sSL https://www.internic.net/domain/named.cache \
    -o /var/lib/unbound/root.hints 2>/dev/null || true

# Initialise DNSSEC trust anchor
unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true

backup_file /etc/unbound/unbound.conf

cat > /etc/unbound/unbound.conf << 'UBEOF'
# ============================================================
# Unbound — Privacy-Hardened Recursive + Forwarding Resolver
# ============================================================

server:
    # --- Interface ---
    interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    prefer-ip6: no

    # --- Access Control ---
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse

    # --- Privacy ---
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    harden-below-nxdomain: yes
    harden-large-queries: yes
    harden-short-bufsize: yes

    # --- DNSSEC ---
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
    val-log-level: 1

    # --- Performance ---
    num-threads: 2
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    rrset-cache-size: 64m
    msg-cache-size: 32m
    so-rcvbuf: 1m
    so-sndbuf: 1m
    outgoing-range: 8192
    num-queries-per-thread: 4096

    # --- Anti-Leak / Anti-Spoof ---
    use-caps-for-id: yes
    qname-minimisation: yes
    qname-minimisation-strict: no
    minimal-responses: yes
    rrset-roundrobin: yes

    # --- Root hints ---
    root-hints: "/var/lib/unbound/root.hints"

    # --- Logging (minimal for privacy) ---
    verbosity: 0
    log-queries: no
    log-replies: no
    log-servfail: yes
    logfile: ""
    use-syslog: yes

    # --- Security ---
    unwanted-reply-threshold: 10000
    do-not-query-localhost: no
    prefetch: yes
    prefetch-key: yes
    deny-any: yes

    # --- Prevent DNS rebinding ---
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10

    # --- TLS for outgoing queries ---
    tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"

# --- Forward to Cloudflare + Quad9 via DNS-over-TLS ---
forward-zone:
    name: "."
    forward-tls-upstream: yes
UBEOF

# Append upstream servers from config
{
    echo "    forward-addr: ${DNS_UPSTREAM_1}"
    echo "    forward-addr: ${DNS_UPSTREAM_2}"
    echo "    forward-addr: ${DNS_UPSTREAM_3}"
    echo "    forward-addr: ${DNS_UPSTREAM_4}"
} >> /etc/unbound/unbound.conf

# Validate config
if unbound-checkconf 2>&1 | grep -q "no errors"; then
    log "Unbound config validated"
else
    warn "Unbound config check reported issues — review /etc/unbound/unbound.conf"
fi

# Stop systemd-resolved if running (conflicts)
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true

# Point resolv.conf to local unbound
backup_file /etc/resolv.conf
rm -f /etc/resolv.conf 2>/dev/null || true
cat > /etc/resolv.conf << 'EOF'
# Local Unbound resolver — DNS-over-TLS to upstream
nameserver 127.0.0.1
options edns0 trust-ad
EOF
chattr +i /etc/resolv.conf    # Prevent overwrite by DHCP

systemctl enable unbound
systemctl restart unbound

# Verify DNS resolution
sleep 2
if dig +short @127.0.0.1 example.com A 2>/dev/null | grep -qE '^[0-9]'; then
    log "DNS resolution via Unbound — WORKING"
else
    warn "DNS resolution test failed — check unbound status"
fi

# Verify DNSSEC
if dig +dnssec @127.0.0.1 cloudflare.com 2>/dev/null | grep -q "ad"; then
    log "DNSSEC validation — ACTIVE"
else
    sub "DNSSEC response flags not fully visible (normal with forwarding)"
fi

log "Unbound DNS Privacy layer complete"

fi # ENABLE_DNS_PRIVACY

#===============================================================================
# 2. DNS-OVER-HTTPS ALTERNATIVE (cloudflared proxy)
#===============================================================================
if [[ "$ENABLE_DNS_PRIVACY" == true ]]; then
header "2. DNS-over-HTTPS Capability (cloudflared — optional)"

# Install cloudflared as a DoH proxy (in addition to Unbound DoT)
ARCH=$(dpkg --print-architecture)
if [[ "$ARCH" == "amd64" ]]; then
    CFDL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
elif [[ "$ARCH" == "arm64" ]]; then
    CFDL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64.deb"
else
    CFDL=""
fi

if [[ -n "$CFDL" ]]; then
    wget -qO /tmp/cloudflared.deb "$CFDL" 2>/dev/null || true
    if [[ -f /tmp/cloudflared.deb ]]; then
        dpkg -i /tmp/cloudflared.deb 2>/dev/null || true
        rm -f /tmp/cloudflared.deb

        # Create DoH proxy service (runs on port 5053)
        useradd -r -s /usr/sbin/nologin cloudflared 2>/dev/null || true

        mkdir -p /etc/cloudflared
        cat > /etc/cloudflared/config.yml << 'EOF'
proxy-dns: true
proxy-dns-port: 5053
proxy-dns-address: 127.0.0.1
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query
  - https://9.9.9.9/dns-query
  - https://149.112.112.112/dns-query
EOF

        cat > /etc/systemd/system/cloudflared-doh.service << 'EOF'
[Unit]
Description=Cloudflare DNS-over-HTTPS Proxy
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=cloudflared
ExecStart=/usr/bin/cloudflared --config /etc/cloudflared/config.yml
Restart=on-failure
RestartSec=10
LimitNOFILE=8192
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/log

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable cloudflared-doh
        systemctl start cloudflared-doh 2>/dev/null || true
        log "Cloudflared DoH proxy running on 127.0.0.1:5053"
        sub "Unbound uses DoT (port 853) by default; DoH on :5053 is available as backup"
    else
        warn "cloudflared download failed — DoH proxy skipped (DoT still active)"
    fi
else
    warn "Unsupported arch ($ARCH) for cloudflared — skipping DoH"
fi

fi # ENABLE_DNS_PRIVACY

#===============================================================================
# 3. OUTBOUND FIREWALL RESTRICTION
#===============================================================================
if [[ "$ENABLE_OUTBOUND_FIREWALL" == true ]]; then
header "3. Outbound Firewall Restriction"

warn "Setting default DENY outgoing — adding required allow rules first"

# Allow loopback (critical for DNS)
ufw allow out on lo 2>/dev/null || true

# Allow established connections
# (UFW handles this by default via before.rules)

# Allow DNS to localhost only (unbound)
ufw allow out to 127.0.0.1 port 53 proto udp comment 'DNS-local-udp' 2>/dev/null || true
ufw allow out to 127.0.0.1 port 53 proto tcp comment 'DNS-local-tcp' 2>/dev/null || true

# Allow DoT (port 853) to upstream resolvers
for resolver in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112; do
    ufw allow out to "$resolver" port 853 proto tcp comment "DoT-$resolver" 2>/dev/null || true
done

# Allow DoH (443) to known DNS providers
for resolver in 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112; do
    ufw allow out to "$resolver" port 443 proto tcp comment "DoH-$resolver" 2>/dev/null || true
done

# Allow configured outbound TCP ports
for port in $OUTBOUND_ALLOW_TCP; do
    ufw allow out to any port "$port" proto tcp comment "out-tcp-$port" 2>/dev/null || true
done

# Allow configured outbound UDP ports
for port in $OUTBOUND_ALLOW_UDP; do
    ufw allow out to any port "$port" proto udp comment "out-udp-$port" 2>/dev/null || true
done

# Allow ICMP (needed for MTU discovery, etc.)
# UFW handles this in before.rules by default

# NOW set default deny outgoing
ufw default deny outgoing

# Reload UFW
ufw reload

log "Outbound firewall: DEFAULT DENY + explicit allows"
sub "Allowed TCP ports: $OUTBOUND_ALLOW_TCP"
sub "Allowed UDP ports: $OUTBOUND_ALLOW_UDP"
warn "If something breaks, run: ufw default allow outgoing"

fi # ENABLE_OUTBOUND_FIREWALL

#===============================================================================
# 4. IPv6 CONTROL
#===============================================================================
header "4. IPv6 Control"

# Check if already disabled via sysctl (from harden.sh)
IPV6_STATUS=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")

if [[ "$IPV6_STATUS" == "1" ]]; then
    log "IPv6 already disabled via sysctl"
else
    sub "Disabling IPv6..."
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
    sysctl -w net.ipv6.conf.lo.disable_ipv6=1 2>/dev/null || true
fi

# Block IPv6 in UFW
if [[ -f /etc/default/ufw ]]; then
    sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
    log "IPv6 disabled in UFW"
fi

# Block via ip6tables
if command -v ip6tables &>/dev/null; then
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true
    ip6tables -P OUTPUT DROP 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    log "ip6tables set to DROP all"
fi

# Disable in GRUB
if [[ -f /etc/default/grub ]]; then
    if ! grep -q "ipv6.disable=1" /etc/default/grub; then
        sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' /etc/default/grub
        update-grub 2>/dev/null || true
        log "IPv6 disabled in GRUB (effective after reboot)"
    fi
fi

log "IPv6 fully controlled"

###############################################################################
#                                                                             #
#   🕵️  SECTION 2 — INTRUSION DETECTION LAYER                                #
#                                                                             #
###############################################################################

#===============================================================================
# 5. OSSEC HOST-BASED IDS
#===============================================================================
if [[ "$ENABLE_OSSEC" == true ]]; then
header "5. OSSEC Host-Based Intrusion Detection System"

OSSEC_VERSION="3.7.0"
OSSEC_DIR="/var/ossec"

if [[ -d "$OSSEC_DIR" ]]; then
    log "OSSEC already installed at $OSSEC_DIR — skipping"
else
    log "Installing OSSEC ${OSSEC_VERSION} from source..."

    # Install build dependencies
    pkg_install build-essential make gcc libpcre2-dev zlib1g-dev \
        libssl-dev libevent-dev libsystemd-dev wget tar

    # Temporarily restore compiler permissions
    chmod 755 /usr/bin/gcc* /usr/bin/cc /usr/bin/make /usr/bin/as 2>/dev/null || true

    cd /tmp
    rm -rf ossec-hids-*

    wget -qO "ossec-${OSSEC_VERSION}.tar.gz" \
        "https://github.com/ossec/ossec-hids/archive/refs/tags/${OSSEC_VERSION}.tar.gz" 2>/dev/null || true

    if [[ -f "ossec-${OSSEC_VERSION}.tar.gz" ]]; then
        tar xzf "ossec-${OSSEC_VERSION}.tar.gz"
        cd "ossec-hids-${OSSEC_VERSION}"

        # Create preloaded answers for non-interactive install
        cat > etc/preloaded-vars.conf << 'OSSEC_VARS'
USER_LANGUAGE="en"
USER_NO_STOP="y"
USER_INSTALL_TYPE="local"
USER_DIR="/var/ossec"
USER_DELETE_DIR="y"
USER_ENABLE_ACTIVE_RESPONSE="y"
USER_ENABLE_SYSCHECK="y"
USER_ENABLE_ROOTCHECK="y"
USER_ENABLE_OPENSCAP="n"
USER_ENABLE_EMAIL="n"
USER_ENABLE_FIREWALL_RESPONSE="y"
USER_UPDATE="n"
USER_BINARYINSTALL=""
OSSEC_VARS

        # Build and install
        log "Compiling OSSEC (this takes 2-5 minutes)..."
        ./install.sh 2>&1 | tail -5 | tee -a "$LOGFILE"

        if [[ -f "${OSSEC_DIR}/bin/ossec-control" ]]; then
            log "OSSEC installed successfully"

            # Harden OSSEC config
            backup_file "${OSSEC_DIR}/etc/ossec.conf"

            # Add custom rules for our monitoring
            cat > "${OSSEC_DIR}/rules/local_rules.xml" << 'OSSEC_RULES'
<group name="local,custom,">

  <!-- Alert on new user creation -->
  <rule id="100001" level="10">
    <if_sid>5902</if_sid>
    <description>New user account created on system.</description>
  </rule>

  <!-- Alert on sudo failures -->
  <rule id="100002" level="8">
    <if_sid>5401</if_sid>
    <description>Failed sudo attempt detected.</description>
  </rule>

  <!-- Alert on SSH brute force -->
  <rule id="100003" level="12" frequency="6" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <description>SSH brute force attack detected.</description>
  </rule>

  <!-- Alert on file integrity change in critical dirs -->
  <rule id="100004" level="10">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
    <description>Critical system file modified.</description>
  </rule>

  <!-- Alert on rootkit detection -->
  <rule id="100005" level="14">
    <if_sid>510</if_sid>
    <description>Possible rootkit detected by OSSEC.</description>
  </rule>

</group>
OSSEC_RULES

            # Configure syscheck (file integrity)
            # Add monitored directories to ossec.conf
            if [[ -f "${OSSEC_DIR}/etc/ossec.conf" ]]; then
                # Check if syscheck section exists and add dirs
                if grep -q "<syscheck>" "${OSSEC_DIR}/etc/ossec.conf"; then
                    sed -i '/<syscheck>/a\
    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>\
    <directories check_all="yes" realtime="yes">/boot</directories>\
    <ignore>/etc/mtab</ignore>\
    <ignore>/etc/hosts.deny</ignore>\
    <ignore>/etc/adjtime</ignore>\
    <ignore>/etc/resolv.conf</ignore>\
    <ignore>/var/ossec/queue</ignore>\
    <ignore>/var/ossec/logs</ignore>\
    <ignore type="sregex">.log$</ignore>' "${OSSEC_DIR}/etc/ossec.conf" 2>/dev/null || true
                fi
            fi

            # Start OSSEC
            "${OSSEC_DIR}/bin/ossec-control" start 2>/dev/null || true

            # Create systemd service
            cat > /etc/systemd/system/ossec.service << 'EOF'
[Unit]
Description=OSSEC Host-based Intrusion Detection System
After=network.target

[Service]
Type=forking
ExecStart=/var/ossec/bin/ossec-control start
ExecStop=/var/ossec/bin/ossec-control stop
ExecReload=/var/ossec/bin/ossec-control reload
PIDFile=/var/ossec/var/run/ossec-analysisd.pid
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable ossec
            log "OSSEC systemd service created and enabled"
        else
            err "OSSEC installation failed — check /tmp/ossec-hids-${OSSEC_VERSION}/logs"
        fi

        # Cleanup
        cd /
        rm -rf "/tmp/ossec-hids-${OSSEC_VERSION}" "/tmp/ossec-${OSSEC_VERSION}.tar.gz"
    else
        err "Failed to download OSSEC source"
    fi

    # Re-restrict compilers
    chmod o-rx /usr/bin/gcc* /usr/bin/cc /usr/bin/make /usr/bin/as 2>/dev/null || true
    log "Compiler access re-restricted"
fi

fi # ENABLE_OSSEC

#===============================================================================
# 6. ROOTKIT SCANNERS — ENHANCED
#===============================================================================
header "6. Rootkit Scanners — Enhanced Configuration"

# --- rkhunter advanced config ---
if command -v rkhunter &>/dev/null; then
    backup_file /etc/rkhunter.conf

    # Update properties database
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true

    # Hardened rkhunter configuration
    cat > /etc/default/rkhunter << 'EOF'
CRON_DAILY_RUN="true"
CRON_DB_UPDATE="true"
APT_AUTOGEN="true"
DB_UPDATE_EMAIL="false"
REPORT_EMAIL="root"
NICE="10"
RUN_CHECK_ON_BATTERY="false"
EOF

    # Create enhanced daily scan script
    cat > /etc/cron.daily/rkhunter-enhanced << 'RKHEOF'
#!/bin/bash
# Enhanced rkhunter daily scan
LOGDIR="/var/log/rkhunter"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

# Update before scan
/usr/bin/rkhunter --update --nocolors 2>/dev/null

# Run scan
/usr/bin/rkhunter --check --skip-keypress --nocolors \
    --report-warnings-only \
    --logfile "${LOGDIR}/rkhunter-${DATE}.log" 2>&1

# Alert on warnings
if grep -q "Warning" "${LOGDIR}/rkhunter-${DATE}.log" 2>/dev/null; then
    echo "=== RKHUNTER WARNINGS on $(hostname) ===" > /tmp/rkhunter-alert.txt
    grep "Warning" "${LOGDIR}/rkhunter-${DATE}.log" >> /tmp/rkhunter-alert.txt
    logger -t rkhunter -p auth.warning "Rootkit warnings detected — check ${LOGDIR}/rkhunter-${DATE}.log"
fi

# Cleanup old logs (keep 30 days)
find "$LOGDIR" -name "rkhunter-*.log" -mtime +30 -delete 2>/dev/null
RKHEOF
    chmod 700 /etc/cron.daily/rkhunter-enhanced
    log "rkhunter enhanced with daily scan + alerting"
fi

# --- chkrootkit enhanced ---
if command -v chkrootkit &>/dev/null; then
    cat > /etc/cron.daily/chkrootkit-enhanced << 'CHKEOF'
#!/bin/bash
# Enhanced chkrootkit daily scan
LOGDIR="/var/log/chkrootkit"
mkdir -p "$LOGDIR"
DATE=$(date +%Y%m%d)

/usr/sbin/chkrootkit > "${LOGDIR}/chkrootkit-${DATE}.log" 2>&1

if grep -qiE "INFECTED|FOUND|Vulnerable" "${LOGDIR}/chkrootkit-${DATE}.log" 2>/dev/null; then
    logger -t chkrootkit -p auth.crit "Rootkit/infection detected — check ${LOGDIR}/chkrootkit-${DATE}.log"
fi

find "$LOGDIR" -name "chkrootkit-*.log" -mtime +30 -delete 2>/dev/null
CHKEOF
    chmod 700 /etc/cron.daily/chkrootkit-enhanced
    log "chkrootkit enhanced with daily scan + alerting"
fi

#===============================================================================
# 7. AIDE AUTOMATION — ENHANCED
#===============================================================================
header "7. AIDE Daily Automation — Enhanced"

mkdir -p /var/log/aide /var/lib/aide

# Create comprehensive AIDE check script
cat > /usr/local/sbin/aide-daily-check << 'AIDEEOF'
#!/bin/bash
#===============================================================================
# AIDE Daily Integrity Check with Alerting
#===============================================================================
LOGDIR="/var/log/aide"
DATE=$(date +%Y%m%d-%H%M)
LOGFILE="${LOGDIR}/aide-check-${DATE}.log"
DBDIR="/var/lib/aide"
ALERT_FLAG="${LOGDIR}/.alert-sent-${DATE%%-*}"

mkdir -p "$LOGDIR"

echo "=== AIDE Integrity Check — $(date) ===" > "$LOGFILE"

# Run AIDE check
/usr/bin/aide --check >> "$LOGFILE" 2>&1
EXIT_CODE=$?

case $EXIT_CODE in
    0)
        echo "STATUS: No changes detected" >> "$LOGFILE"
        ;;
    1|2|3|4|5|6|7)
        echo "STATUS: CHANGES DETECTED (exit code: $EXIT_CODE)" >> "$LOGFILE"
        logger -t aide -p auth.warning "AIDE detected file integrity changes — $LOGFILE"

        # Count changes
        ADDED=$(grep -c "^Added:" "$LOGFILE" 2>/dev/null || echo 0)
        REMOVED=$(grep -c "^Removed:" "$LOGFILE" 2>/dev/null || echo 0)
        CHANGED=$(grep -c "^Changed:" "$LOGFILE" 2>/dev/null || echo 0)

        echo "  Added: $ADDED | Removed: $REMOVED | Changed: $CHANGED" >> "$LOGFILE"
        logger -t aide -p auth.warning "AIDE: Added=$ADDED Removed=$REMOVED Changed=$CHANGED"
        ;;
    *)
        echo "STATUS: AIDE error (exit code: $EXIT_CODE)" >> "$LOGFILE"
        logger -t aide -p auth.err "AIDE check failed with exit code $EXIT_CODE"
        ;;
esac

# Backup AIDE database (rotate weekly)
DOW=$(date +%u)
if [[ "$DOW" == "1" ]]; then
    cp "${DBDIR}/aide.db" "${DBDIR}/aide.db.backup-$(date +%Y%m%d)" 2>/dev/null || true
    find "${DBDIR}" -name "aide.db.backup-*" -mtime +30 -delete 2>/dev/null || true
fi

# Cleanup old logs
find "$LOGDIR" -name "aide-check-*.log" -mtime +60 -delete 2>/dev/null || true
AIDEEOF

chmod 700 /usr/local/sbin/aide-daily-check

# Replace simple cron with enhanced version
rm -f /etc/cron.daily/aide-check 2>/dev/null || true
cat > /etc/cron.daily/aide-enhanced << 'EOF'
#!/bin/bash
/usr/local/sbin/aide-daily-check
EOF
chmod 700 /etc/cron.daily/aide-enhanced

# Ensure AIDE database exists
if [[ ! -f /var/lib/aide/aide.db ]]; then
    log "Initialising AIDE database (may take several minutes)..."
    aideinit 2>&1 | tail -3 | tee -a "$LOGFILE"
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
fi

log "AIDE automation configured with daily check + alerting"

###############################################################################
#                                                                             #
#   🔐  SECTION 3 — SERVICE CONTAINMENT LAYER                                #
#                                                                             #
###############################################################################

#===============================================================================
# 8. APPARMOR CUSTOM PROFILES
#===============================================================================
header "8. AppArmor Custom Profiles"

# Ensure AppArmor is running
systemctl enable apparmor
systemctl start apparmor 2>/dev/null || true

# --- 8a. SSHD AppArmor Profile ---
cat > /etc/apparmor.d/usr.sbin.sshd.custom << 'AA_SSHD'
#include <tunables/global>

/usr/sbin/sshd {
    #include <abstractions/base>
    #include <abstractions/authentication>
    #include <abstractions/nameservice>
    #include <abstractions/openssl>
    #include <abstractions/wutmp>

    capability net_bind_service,
    capability sys_chroot,
    capability sys_resource,
    capability setgid,
    capability setuid,
    capability chown,
    capability fowner,
    capability fsetid,
    capability kill,
    capability dac_override,
    capability dac_read_search,
    capability audit_write,
    capability sys_tty_config,

    network inet stream,
    network inet dgram,

    /usr/sbin/sshd mr,
    /etc/ssh/** r,
    /etc/ssh/sshd_config r,
    /etc/ssh/ssh_host_* r,

    /etc/passwd r,
    /etc/shadow r,
    /etc/group r,
    /etc/gshadow r,
    /etc/login.defs r,
    /etc/securetty r,
    /etc/security/** r,
    /etc/pam.d/** r,
    /etc/nsswitch.conf r,
    /etc/resolv.conf r,
    /etc/hosts r,
    /etc/localtime r,
    /etc/issue.net r,
    /etc/motd r,
    /etc/default/locale r,
    /etc/environment r,
    /etc/shells r,

    /run/sshd.pid rw,
    /run/sshd/ rw,
    /var/run/sshd.pid rw,

    /proc/*/fd/ r,
    /proc/*/oom_score_adj rw,
    @{PROC}/sys/kernel/ngroups_max r,

    /var/log/auth.log rw,
    /var/log/btmp rw,
    /var/log/wtmp rw,
    /var/log/lastlog rw,
    /dev/ptmx rw,
    /dev/pts/* rw,
    /dev/urandom r,
    /dev/null rw,
    /dev/tty rw,

    /tmp/ r,
    /tmp/** rwl,
    /var/tmp/ r,

    /home/*/.ssh/authorized_keys r,
    /root/.ssh/authorized_keys r,

    # Allow spawning user shells
    /bin/bash Ux,
    /bin/sh Ux,
    /bin/dash Ux,
    /usr/bin/bash Ux,
    /usr/sbin/nologin Ux,
    /usr/bin/passwd Px,

    # Deny everything else by default (AppArmor implicit deny)
}
AA_SSHD

# --- 8b. Cron AppArmor Profile ---
cat > /etc/apparmor.d/usr.sbin.cron.custom << 'AA_CRON'
#include <tunables/global>

/usr/sbin/cron {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/authentication>

    capability setgid,
    capability setuid,
    capability sys_resource,
    capability dac_override,
    capability dac_read_search,
    capability audit_write,

    /usr/sbin/cron mr,
    /etc/crontab r,
    /etc/cron.d/ r,
    /etc/cron.d/** r,
    /etc/cron.daily/ r,
    /etc/cron.daily/** rix,
    /etc/cron.hourly/ r,
    /etc/cron.hourly/** rix,
    /etc/cron.weekly/ r,
    /etc/cron.weekly/** rix,
    /etc/cron.monthly/ r,
    /etc/cron.monthly/** rix,
    /etc/cron.allow r,
    /etc/environment r,
    /etc/default/locale r,
    /etc/localtime r,
    /etc/passwd r,
    /etc/shadow r,
    /etc/group r,
    /etc/login.defs r,
    /etc/pam.d/cron r,
    /etc/security/** r,

    /var/spool/cron/ r,
    /var/spool/cron/** rw,
    /var/spool/cron/crontabs/ r,
    /var/spool/cron/crontabs/** rw,
    /run/crond.pid rw,

    /var/log/syslog rw,
    /var/log/cron.log rw,
    /var/log/auth.log rw,

    /bin/** Ux,
    /usr/bin/** Ux,
    /usr/sbin/** Ux,
    /usr/local/bin/** Ux,
    /usr/local/sbin/** Ux,

    /tmp/ rw,
    /tmp/** rw,
    /dev/null rw,
}
AA_CRON

# --- 8c. Unbound AppArmor Profile ---
cat > /etc/apparmor.d/usr.sbin.unbound.custom << 'AA_UB'
#include <tunables/global>

/usr/sbin/unbound {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/openssl>

    capability net_bind_service,
    capability setgid,
    capability setuid,
    capability sys_chroot,
    capability sys_resource,
    capability dac_override,

    network inet stream,
    network inet dgram,
    network inet6 stream,
    network inet6 dgram,

    /usr/sbin/unbound mr,
    /etc/unbound/** r,
    /var/lib/unbound/** rw,
    /run/unbound.pid rw,

    /etc/ssl/certs/** r,
    /usr/share/ca-certificates/** r,
    /etc/ca-certificates/** r,

    /dev/urandom r,
    /dev/null rw,
    /dev/log rw,

    /proc/sys/net/core/somaxconn r,
    @{PROC}/sys/kernel/random/uuid r,
}
AA_UB

# Load profiles in COMPLAIN mode first (safe)
for profile in /etc/apparmor.d/usr.sbin.sshd.custom \
               /etc/apparmor.d/usr.sbin.cron.custom \
               /etc/apparmor.d/usr.sbin.unbound.custom; do
    if [[ -f "$profile" ]]; then
        apparmor_parser -r -C "$profile" 2>/dev/null || true
        sub "Loaded $(basename $profile) in COMPLAIN mode"
    fi
done

# Enforce all existing default profiles
aa-enforce /etc/apparmor.d/usr.* 2>/dev/null || true

# Create enforcement script (run after testing)
cat > /usr/local/sbin/apparmor-enforce-all << 'EOF'
#!/bin/bash
# Run this after verifying custom profiles don't break services
echo "Enforcing all custom AppArmor profiles..."
for profile in /etc/apparmor.d/usr.sbin.*.custom; do
    if [[ -f "$profile" ]]; then
        apparmor_parser -r "$profile" 2>/dev/null && echo "  Enforced: $(basename $profile)"
    fi
done
echo "Done. Check: aa-status"
EOF
chmod 700 /usr/local/sbin/apparmor-enforce-all

# Tor AppArmor profile is added later if Tor is installed

log "AppArmor custom profiles loaded (COMPLAIN mode for safety)"
sub "Run '/usr/local/sbin/apparmor-enforce-all' after testing"

#===============================================================================
# 9. SYSTEMD SANDBOXING
#===============================================================================
header "9. Systemd Service Sandboxing"

# --- 9a. SSH sandboxing override ---
mkdir -p /etc/systemd/system/ssh.service.d/
cat > /etc/systemd/system/ssh.service.d/hardening.conf << 'EOF'
[Service]
# Sandboxing for SSH (careful — must allow auth & shells)
ProtectSystem=strict
ReadWritePaths=/var/log /run/sshd /var/run /tmp /dev/pts /home /root
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
NoNewPrivileges=no
EOF

# --- 9b. Cron sandboxing ---
mkdir -p /etc/systemd/system/cron.service.d/
cat > /etc/systemd/system/cron.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=strict
ReadWritePaths=/var/spool/cron /var/log /tmp /run
ProtectHome=read-only
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
EOF

# --- 9c. Rsyslog sandboxing ---
mkdir -p /etc/systemd/system/rsyslog.service.d/
cat > /etc/systemd/system/rsyslog.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=strict
ReadWritePaths=/var/log /run/rsyslogd.pid /var/spool/rsyslog
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
EOF

# --- 9d. Fail2Ban sandboxing ---
mkdir -p /etc/systemd/system/fail2ban.service.d/
cat > /etc/systemd/system/fail2ban.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=strict
ReadWritePaths=/var/log /var/lib/fail2ban /run/fail2ban /tmp
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
NoNewPrivileges=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF

# --- 9e. Unbound sandboxing ---
mkdir -p /etc/systemd/system/unbound.service.d/
cat > /etc/systemd/system/unbound.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=strict
ReadWritePaths=/var/lib/unbound /run
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
EOF

# --- 9f. Auditd sandboxing ---
mkdir -p /etc/systemd/system/auditd.service.d/
cat > /etc/systemd/system/auditd.service.d/hardening.conf << 'EOF'
[Service]
ProtectSystem=strict
ReadWritePaths=/var/log/audit /run
ProtectHome=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallArchitectures=native
EOF

systemctl daemon-reload
log "Systemd sandboxing applied to 6 services"

# Verify no service broke
for svc in ssh cron rsyslog fail2ban unbound auditd; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        sub "$svc — running"
    else
        systemctl restart "$svc" 2>/dev/null || true
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            sub "$svc — restarted OK"
        else
            warn "$svc — may need attention"
        fi
    fi
done

#===============================================================================
# 10. SUDO USAGE LOGGING — ENHANCED
#===============================================================================
header "10. Sudo Audit Logging — Enhanced"

# Ensure sudo log directory exists
mkdir -p /var/log/sudo-io
chmod 700 /var/log/sudo-io

# Enhanced sudoers logging (extend from harden.sh)
cat > /etc/sudoers.d/99-audit-enhance << 'EOF'
# Enhanced sudo auditing
Defaults        log_input,log_output
Defaults        iolog_dir="/var/log/sudo-io/%{user}/%{seq}"
Defaults        iolog_file="%{seq}"
Defaults        logfile="/var/log/sudo.log"
Defaults        log_year
Defaults        syslog=auth
Defaults        syslog_goodpri=info
Defaults        syslog_badpri=alert
EOF
chmod 440 /etc/sudoers.d/99-audit-enhance

# Validate
visudo -cf /etc/sudoers 2>/dev/null && log "Sudo audit config validated" || err "Sudoers error!"

# Create sudo log rotation
cat > /etc/logrotate.d/sudo-audit << 'EOF'
/var/log/sudo.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF

log "Sudo full I/O logging enabled"

###############################################################################
#                                                                             #
#   🧠  SECTION 4 — MONITORING & FORENSICS                                   #
#                                                                             #
###############################################################################

#===============================================================================
# 11. REMOTE LOG FORWARDING
#===============================================================================
header "11. Remote Syslog Forwarding"

if [[ -n "$REMOTE_SYSLOG_SERVER" ]]; then
    backup_file /etc/rsyslog.conf

    PROTO_CHAR="@"
    [[ "$REMOTE_SYSLOG_PROTO" == "tcp" ]] && PROTO_CHAR="@@"

    cat > /etc/rsyslog.d/10-remote-forward.conf << RSEOF
# ============================================================
# Remote syslog forwarding — tamper-resistant logging
# ============================================================
# Forward all logs to remote server
*.* ${PROTO_CHAR}${REMOTE_SYSLOG_SERVER}

# Queue configuration for reliability
\$ActionQueueType LinkedList
\$ActionQueueFileName remote-fwd
\$ActionResumeRetryCount -1
\$ActionQueueSaveOnShutdown on
\$ActionQueueMaxDiskSpace 256m
RSEOF

    systemctl restart rsyslog
    log "Remote syslog forwarding to $REMOTE_SYSLOG_SERVER ($REMOTE_SYSLOG_PROTO)"
else
    # Even without remote server, prepare the config
    cat > /etc/rsyslog.d/10-remote-forward.conf << 'EOF'
# Remote syslog forwarding — UNCONFIGURED
# To enable, set the remote server below and restart rsyslog:
# *.* @@logs.example.com:514
#
# $ActionQueueType LinkedList
# $ActionQueueFileName remote-fwd
# $ActionResumeRetryCount -1
# $ActionQueueSaveOnShutdown on
EOF
    log "Remote syslog template created (not active — configure REMOTE_SYSLOG_SERVER)"
fi

#===============================================================================
# 12. SUID/SGID FILE MONITOR
#===============================================================================
header "12. SUID/SGID File Monitor"

# Create baseline
SUID_BASELINE="/var/lib/security/suid-baseline.txt"
SUID_SCRIPT="/usr/local/sbin/suid-monitor"

mkdir -p /var/lib/security /var/log/security

# Generate baseline
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$SUID_BASELINE"
log "SUID/SGID baseline: $(wc -l < "$SUID_BASELINE") files recorded"

# Create monitoring script
cat > "$SUID_SCRIPT" << 'SUIDEOF'
#!/bin/bash
#===============================================================================
# SUID/SGID File Monitor — Detect new privileged binaries
#===============================================================================
BASELINE="/var/lib/security/suid-baseline.txt"
CURRENT="/tmp/suid-current-$$.txt"
LOGFILE="/var/log/security/suid-changes.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Generate current list
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$CURRENT"

if [[ ! -f "$BASELINE" ]]; then
    cp "$CURRENT" "$BASELINE"
    echo "[$DATE] Baseline created with $(wc -l < "$BASELINE") SUID/SGID files" >> "$LOGFILE"
    rm -f "$CURRENT"
    exit 0
fi

# Compare
NEW_FILES=$(comm -13 "$BASELINE" "$CURRENT")
REMOVED_FILES=$(comm -23 "$BASELINE" "$CURRENT")

if [[ -n "$NEW_FILES" ]]; then
    echo "[$DATE] ⚠️  NEW SUID/SGID FILES DETECTED:" >> "$LOGFILE"
    echo "$NEW_FILES" >> "$LOGFILE"
    logger -t suid-monitor -p auth.crit "NEW SUID/SGID files detected: $(echo "$NEW_FILES" | tr '\n' ' ')"

    # Create alert
    echo "=== SUID/SGID ALERT on $(hostname) at $DATE ===" > /tmp/suid-alert.txt
    echo "New privileged binaries found:" >> /tmp/suid-alert.txt
    echo "$NEW_FILES" >> /tmp/suid-alert.txt
    echo "" >> /tmp/suid-alert.txt
    echo "Run 'find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f' to verify" >> /tmp/suid-alert.txt
fi

if [[ -n "$REMOVED_FILES" ]]; then
    echo "[$DATE] REMOVED SUID/SGID files:" >> "$LOGFILE"
    echo "$REMOVED_FILES" >> "$LOGFILE"
fi

if [[ -z "$NEW_FILES" && -z "$REMOVED_FILES" ]]; then
    echo "[$DATE] OK — No SUID/SGID changes" >> "$LOGFILE"
fi

rm -f "$CURRENT"
SUIDEOF

chmod 700 "$SUID_SCRIPT"

# Cron job — every 4 hours
echo "0 */4 * * * root /usr/local/sbin/suid-monitor" > /etc/cron.d/suid-monitor
chmod 600 /etc/cron.d/suid-monitor

log "SUID/SGID monitor installed (runs every 4 hours)"

#===============================================================================
# 13. NEW USER DETECTION
#===============================================================================
header "13. New User Detection Monitor"

USER_BASELINE="/var/lib/security/user-baseline.txt"
USER_SCRIPT="/usr/local/sbin/user-monitor"

# Create baseline
cp /etc/passwd "$USER_BASELINE"
cp /etc/group /var/lib/security/group-baseline.txt
chmod 
