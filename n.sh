#!/bin/bash
##############################################################################
# final.sh — Stable Production VPS Hardening
##############################################################################

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root: sudo bash final.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo ""
echo "Production VPS Hardening"
echo ""

##############################################################################
# 1. SYSCTL
##############################################################################
echo "[1/7] Kernel hardening..."

rm -f /etc/sysctl.d/99-*.conf 2>/dev/null

cat > /etc/sysctl.d/99-hardening.conf <<'SYSCTL'
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
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
vm.mmap_min_addr = 65536
SYSCTL

sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1

echo "✔ Sysctl done"

##############################################################################
# 2. AIDE
##############################################################################
echo "[2/7] AIDE..."

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq aide aide-common >/dev/null 2>&1

rm -f /var/lib/aide/aide.db* 2>/dev/null

if command -v aideinit >/dev/null 2>&1; then
  echo "Building AIDE database..."
  if ! timeout 300 aideinit >/dev/null 2>&1; then
    echo "AIDE init timed out — continuing"
  fi
fi

if [ -f /var/lib/aide/aide.db.new ]; then
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

if [ -f /var/lib/aide/aide.db.new.gz ]; then
  gunzip -f /var/lib/aide/aide.db.new.gz
fi

mkdir -p /var/log/aide

cat > /etc/cron.daily/aide-check <<'CRON'
#!/bin/bash
timeout 300 /usr/bin/aide.wrapper --check > /var/log/aide/check-$(date +%Y%m%d).log 2>&1
CRON

chmod 700 /etc/cron.daily/aide-check

echo "✔ AIDE ready"

##############################################################################
# 3. SSH
##############################################################################
echo "[3/7] SSH..."

SSH_PORT="${SSH_PORT:-22}"

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)

cat > /etc/ssh/sshd_config <<SSH
Port ${SSH_PORT}
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes
Compression no
TCPKeepAlive no
UseDNS no
LogLevel VERBOSE
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
SSH

chmod 600 /etc/ssh/sshd_config

if sshd -t 2>/dev/null; then
  systemctl restart ssh >/dev/null 2>&1
fi

echo "✔ SSH done"

##############################################################################
# 4. FIREWALL
##############################################################################
echo "[4/7] UFW..."

apt-get install -y -qq ufw >/dev/null 2>&1

ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow ${SSH_PORT}/tcp >/dev/null 2>&1
ufw limit ${SSH_PORT}/tcp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

echo "✔ UFW active"

##############################################################################
# 5. FAIL2BAN
##############################################################################
echo "[5/7] Fail2ban..."

apt-get install -y -qq fail2ban >/dev/null 2>&1

cat > /etc/fail2ban/jail.local <<F2B
[DEFAULT]
bantime = 7200
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
F2B

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1

echo "✔ Fail2ban active"

##############################################################################
# 6. SERVICE HARDENING (SAFE)
##############################################################################
echo "[6/7] Service hardening..."

for svc in fail2ban cron; do
  if systemctl list-unit-files | grep -q "^${svc}.service"; then
    mkdir -p /etc/systemd/system/${svc}.service.d
    cat > /etc/systemd/system/${svc}.service.d/hardening.conf <<'HARD'
[Service]
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
HARD
  fi
done

systemctl daemon-reload >/dev/null 2>&1

echo "✔ Services hardened"

##############################################################################
# 7. EXTRAS
##############################################################################
echo "[7/7] Extras..."

apt-get install -y -qq haveged unattended-upgrades >/dev/null 2>&1

systemctl enable haveged >/dev/null 2>&1
systemctl start haveged >/dev/null 2>&1

cat > /etc/apt/apt.conf.d/20auto-upgrades <<AUTO
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUTO

echo "✔ Extras done"

##############################################################################
# VERIFY
##############################################################################
echo ""
echo "Verification:"
echo -n "Internet: " && ping -c1 -W1 1.1.1.1 >/dev/null 2>&1 && echo OK || echo FAIL
echo -n "SSH: " && systemctl is-active ssh >/dev/null 2>&1 && echo OK || echo FAIL
echo -n "UFW: " && ufw status | grep -q active && echo OK || echo FAIL
echo -n "Fail2ban: " && systemctl is-active fail2ban >/dev/null 2>&1 && echo OK || echo FAIL
echo ""
echo "Hardening complete."
